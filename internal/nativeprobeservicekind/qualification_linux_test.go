//go:build linux && nativeprobeservicekind

// This is a disposable Kind network qualification, never a live controller.
// It is intentionally outside the default probe root enumerator/build.
package nativeprobeservicekind

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	neturl "net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	probe "github.com/dakasa-yggdrasil/yggdrasil-core/internal/nativeworkerprobe"
	"github.com/google/uuid"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

const fixtureNamespace = "native-probe-service-ci"
const runLabel = "yggdrasil.io/probe-service-ci-run"
const roleLabel = "yggdrasil.io/probe-service-ci-role"

func digest(raw []byte) string { h := sha256.Sum256(raw); return hex.EncodeToString(h[:]) }
func await(t *testing.T, ctx context.Context, description string, ready func() bool) {
	t.Helper()
	timer := time.NewTicker(100 * time.Millisecond)
	defer timer.Stop()
	for {
		if ready() {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal("bounded real Kind observation unavailable:", description)
		case <-timer.C:
		}
	}
}
func fixtureError(t *testing.T, operation string, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("Kind %s refused (reason=%s)", operation, apierrors.ReasonForError(err))
	}
}

type podLife struct {
	Name                           string    `json:"name"`
	UID                            types.UID `json:"uid"`
	IP, Node, ContainerID, ImageID string
	StartedAt                      time.Time
}

func life(p *corev1.Pod) (podLife, bool) {
	if p == nil || p.DeletionTimestamp != nil || len(p.Status.ContainerStatuses) != 1 {
		return podLife{}, false
	}
	s := p.Status.ContainerStatuses[0]
	if s.State.Running == nil || s.RestartCount != 0 || s.ContainerID == "" || s.ImageID == "" || len(p.Spec.Containers) != 1 || len(p.Spec.InitContainers) != 0 || len(p.Spec.Containers[0].Command) != 0 || len(p.Spec.Containers[0].Args) != 0 {
		return podLife{}, false
	}
	return podLife{p.Name, p.UID, p.Status.PodIP, p.Spec.NodeName, s.ContainerID, s.ImageID, s.State.Running.StartedAt.Time}, true
}
func privateKey(t *testing.T, k ed25519.PrivateKey) []byte {
	t.Helper()
	v, e := x509.MarshalPKCS8PrivateKey(k)
	if e != nil {
		t.Fatal("private fixture encoding failed")
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: v})
}

type fixtureCA struct {
	cert *x509.Certificate
	key  ed25519.PrivateKey
	pem  []byte
}

func newCA(t *testing.T) fixtureCA {
	t.Helper()
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now()
	c := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "disposable-kind-probe-only"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	raw, e := x509.CreateCertificate(rand.Reader, c, c, pub, key)
	if e != nil {
		t.Fatal(e)
	}
	c, e = x509.ParseCertificate(raw)
	if e != nil {
		t.Fatal(e)
	}
	return fixtureCA{c, key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw})}
}
func (c fixtureCA) leaf(t *testing.T, serial int64, ip string, usage x509.ExtKeyUsage) (tls.Certificate, []byte, []byte) {
	t.Helper()
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now()
	leaf := &x509.Certificate{SerialNumber: big.NewInt(serial), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(30 * time.Minute), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
	if ip != "" {
		leaf.IPAddresses = []net.IP{net.ParseIP(ip)}
	}
	raw, e := x509.CreateCertificate(rand.Reader, leaf, c.cert, pub, c.key)
	if e != nil {
		t.Fatal(e)
	}
	certPEM, keyPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw}), privateKey(t, key)
	pair, e := tls.X509KeyPair(certPEM, keyPEM)
	clear(keyPEM)
	if e != nil {
		t.Fatal(e)
	}
	return pair, certPEM, privateKey(t, key)
}
func clientFor(t *testing.T, ca fixtureCA, client tls.Certificate, ip, leafHash string) *http.Client {
	t.Helper()
	roots := x509.NewCertPool()
	roots.AddCert(ca.cert)
	tr := &http.Transport{Proxy: nil, DisableKeepAlives: true, TLSHandshakeTimeout: 2 * time.Second, ResponseHeaderTimeout: 3 * time.Second, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, Certificates: []tls.Certificate{client}, ServerName: ip, VerifyConnection: func(c tls.ConnectionState) error {
		if len(c.VerifiedChains) == 0 || len(c.PeerCertificates) == 0 || digest(c.PeerCertificates[0].Raw) != leafHash {
			return fmt.Errorf("fixture peer refused")
		}
		return nil
	}}}
	c := &http.Client{Transport: tr, Timeout: 4 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	t.Cleanup(c.CloseIdleConnections)
	return c
}
func call(ctx context.Context, c *http.Client, ip, path, method, source string) (probe.Report, error) {
	var out probe.Report
	r, e := http.NewRequestWithContext(ctx, method, "https://"+net.JoinHostPort(ip, "9446")+path, nil)
	if e != nil {
		return out, e
	}
	r.GetBody = nil
	r.Close = true
	response, e := c.Do(r)
	if response == nil || response.Body == nil {
		return out, fmt.Errorf("original probe call unavailable")
	}
	raw, re := io.ReadAll(io.LimitReader(response.Body, (256<<10)+1))
	ce := response.Body.Close()
	if e != nil || re != nil || ce != nil || ctx.Err() != nil || len(raw) > 256<<10 || len(response.Header.Values("X-Yggdrasil-Source-Commit")) != 1 || response.Header.Get("X-Yggdrasil-Source-Commit") != source {
		return out, fmt.Errorf("original probe response incomplete")
	}
	want := 200
	if method == http.MethodPost {
		want = 202
	}
	if response.StatusCode != want {
		return out, fmt.Errorf("original probe response refused")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&out) != nil || d.Decode(new(any)) != io.EOF {
		return out, fmt.Errorf("closed probe report refused")
	}
	return out, nil
}

// Failure-only audit: the first projection is the same original GET that
// failed. Later GETs are subsequent observations and cannot qualify that read.
// Deliberately omit Packet, Config, signing material and arbitrary error text.
func logFailedExchange(t *testing.T, ctx context.Context, original probe.Report, index int, phase, source string, lives []podLife, clients []*http.Client, configs []probe.Config, pubs []ed25519.PublicKey) {
	t.Helper()
	type row struct {
		Batch, Path, Address, RawSHA256 string
		Sequence, BytesLength           int
		At                              time.Time
	}
	type batch struct {
		State, ErrorClass                   string
		StartedAt, CompletedAt              *time.Time
		SentCount, ReceivedCount, EchoCount int
		Sent, Received, Echoed              []row
	}
	project := func(b probe.BatchReport) batch {
		rows := func(records []probe.DatagramRecord) []row {
			out := []row{}
			for _, r := range records {
				if len(out) == 16 {
					break
				}
				address := "invalid"
				if a, err := netip.ParseAddrPort(r.Address); err == nil && a.Addr().Is4() {
					address = a.String()
				}
				b, p := "invalid", "invalid"
				if r.Batch == "initial" || r.Batch == "final" {
					b = r.Batch
				}
				if r.Path == "pod" || r.Path == "service" {
					p = r.Path
				}
				sha := ""
				for sender := range configs {
					peer := 1 - sender
					if probe.VerifyPacket(r.Packet, configs[sender], pubs[sender], pubs[peer], false) || probe.VerifyPacket(r.Packet, configs[sender], pubs[sender], pubs[peer], true) {
						sha = digest(r.Packet)
						break
					}
				}
				out = append(out, row{b, p, address, sha, r.Sequence, len(r.Packet), r.ObservedAt})
			}
			return out
		}
		state, class := b.State, b.ErrorClass
		switch state {
		case "idle", "running", "complete", "failed", "unknown":
		default:
			state = "invalid"
		}
		switch class {
		case "", "datagram_deadline", "datagram_send_incomplete", "echo_send_incomplete", "datagram_replay", "receive_limit", "internal_failure":
		default:
			class = "invalid"
		}
		return batch{state, class, b.StartedAt, b.CompletedAt, len(b.Sent), len(b.Received), len(b.Echoed), rows(b.Sent), rows(b.Received), rows(b.Echoed)}
	}
	log := func(origin string, peer int, out probe.Report) {
		v := struct {
			Schema, Origin, Phase string
			Peer                  int
			ObservedAt            time.Time
			Initial, Final        batch
		}{"native_probe_service_failure_audit_v1", origin, phase, peer, out.ObservedAt, project(out.Initial), project(out.Final)}
		raw, err := json.Marshal(v)
		if err == nil && len(raw) <= 32<<10 {
			t.Logf("NATIVE_PROBE_SERVICE_FAILURE_AUDIT %s", raw)
		}
	}
	log("same_original_failed_get", index, original)
	for i := range lives {
		audit, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		out, err := call(audit, clients[i], lives[i].IP, probe.ReportPath, http.MethodGet, source)
		stop()
		if err != nil {
			t.Logf("NATIVE_PROBE_SERVICE_SUBSEQUENT_AUDIT_UNAVAILABLE peer=%d", i)
			continue
		}
		log("subsequent_get_not_original_qualification", i, out)
	}
}

func TestNativeProbeActualClusterIPReverseSNATEcho(t *testing.T) {
	if os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("REQUIRE_NATIVE_PROBE_SERVICE_KIND") != "true" {
		t.Fatal("this network qualification is GitHub disposable Kind only")
	}
	source, image := os.Getenv("NATIVE_PROBE_SERVICE_SOURCE"), os.Getenv("NATIVE_PROBE_SERVICE_IMAGE")
	if !regexp.MustCompile(`^[a-f0-9]{40}$`).MatchString(source) || !regexp.MustCompile(`^docker\.io/library/native-probe-service@sha256:[a-f0-9]{64}$`).MatchString(image) {
		t.Fatal("exact normal agent Source/image required")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Minute)
	defer cancel()
	config, e := rest.InClusterConfig()
	fixtureError(t, "in-cluster configuration", e)
	config.Proxy = func(*http.Request) (*neturl.URL, error) { return nil, nil }
	config.Timeout = 5 * time.Second
	client, e := kubernetes.NewForConfig(config)
	fixtureError(t, "typed client", e)
	namespace, e := client.CoreV1().Namespaces().Get(ctx, fixtureNamespace, metav1.GetOptions{})
	fixtureError(t, "namespace read", e)
	nodes, e := client.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	fixtureError(t, "node inventory", e)
	workers := []corev1.Node{}
	for _, n := range nodes.Items {
		if !strings.HasPrefix(n.Spec.ProviderID, "kind://") {
			t.Fatal("refusing a non-Kind node")
		}
		if _, control := n.Labels["node-role.kubernetes.io/control-plane"]; !control {
			workers = append(workers, n)
		}
	}
	if len(workers) != 2 {
		t.Fatal("exact two disposable workers required")
	}
	sort.Slice(workers, func(i, j int) bool { return workers[i].Name < workers[j].Name })
	run, attempt, pool := uuid.NewString(), uuid.NewString(), uuid.NewString()
	prefix := "nps-" + strings.ReplaceAll(run, "-", "")[:12]
	roles := []string{"floor", "candidate"}
	pods := make([]*corev1.Pod, 2)
	services := make([]*corev1.Service, 2)
	lives := make([]podLife, 2)
	configs := make([]probe.Config, 2)
	reports := make([]probe.Report, 2)
	secretReceipts := make([]struct {
		Name      string
		UID       types.UID
		CreatedAt metav1.Time
	}, 2)
	pubs := make([]ed25519.PublicKey, 2)
	keys := make([]ed25519.PrivateKey, 2)
	httpClients := make([]*http.Client, 2)
	defer func() {
		cleanup, done := context.WithTimeout(context.Background(), 15*time.Second)
		defer done()
		zero := int64(0)
		for _, p := range pods {
			if p != nil {
				uid := p.UID
				_ = client.CoreV1().Pods(fixtureNamespace).Delete(cleanup, p.Name, metav1.DeleteOptions{GracePeriodSeconds: &zero, Preconditions: &metav1.Preconditions{UID: &uid}})
			}
		}
		for _, s := range services {
			if s != nil {
				uid := s.UID
				_ = client.CoreV1().Services(fixtureNamespace).Delete(cleanup, s.Name, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid}})
			}
		}
	}()
	mode, group, uid := int32(0440), int64(65532), int64(65532)
	yes, no := true, false
	for i, role := range roles {
		labels := map[string]string{runLabel: run, roleLabel: role}
		family := corev1.IPFamilyPolicySingleStack
		services[i], e = client.CoreV1().Services(fixtureNamespace).Create(ctx, &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: prefix + "-" + role, Namespace: fixtureNamespace, Labels: labels}, Spec: corev1.ServiceSpec{Type: corev1.ServiceTypeClusterIP, Selector: labels, PublishNotReadyAddresses: true, IPFamilyPolicy: &family, IPFamilies: []corev1.IPFamily{corev1.IPv4Protocol}, Ports: []corev1.ServicePort{{Name: "probe-udp", Port: 9446, TargetPort: intstr.FromInt32(9446), Protocol: corev1.ProtocolUDP}}}}, metav1.CreateOptions{})
		fixtureError(t, "Service create", e)
		pods[i], e = client.CoreV1().Pods(fixtureNamespace).Create(ctx, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: prefix + "-" + role, Namespace: fixtureNamespace, Labels: labels}, Spec: corev1.PodSpec{NodeName: workers[i].Name, RestartPolicy: corev1.RestartPolicyNever, AutomountServiceAccountToken: &no, SecurityContext: &corev1.PodSecurityContext{RunAsNonRoot: &yes, RunAsUser: &uid, RunAsGroup: &group, FSGroup: &group, SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault}}, Containers: []corev1.Container{{Name: "probe", Image: image, ImagePullPolicy: corev1.PullNever, SecurityContext: &corev1.SecurityContext{AllowPrivilegeEscalation: &no, ReadOnlyRootFilesystem: &yes, Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}}}, Resources: corev1.ResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("10m"), corev1.ResourceMemory: resource.MustParse("16Mi")}, Limits: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("500m"), corev1.ResourceMemory: resource.MustParse("128Mi")}}, VolumeMounts: []corev1.VolumeMount{{Name: "material", MountPath: "/run/dakasa-native-worker-probe", ReadOnly: true}}}}, Volumes: []corev1.Volume{{Name: "material", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: prefix + "-" + role, Optional: &yes, DefaultMode: &mode}}}}}}, metav1.CreateOptions{})
		fixtureError(t, "normal agent Pod create", e)
	}
	podCIDR, serviceCIDR := netip.MustParsePrefix("10.244.0.0/16"), netip.MustParsePrefix("10.96.0.0/16")
	for i := range pods {
		index := i
		await(t, ctx, "real Pod sandbox and original normal process", func() bool {
			p, err := client.CoreV1().Pods(fixtureNamespace).Get(ctx, pods[index].Name, metav1.GetOptions{})
			if err != nil {
				return false
			}
			if len(p.Status.ContainerStatuses) == 1 && p.Status.ContainerStatuses[0].State.Terminated != nil {
				logTerminated(t, p)
				t.Fatalf("normal agent exited before material: code=%d", p.Status.ContainerStatuses[0].State.Terminated.ExitCode)
			}
			v, ok := life(p)
			if !ok {
				return false
			}
			ip, err := netip.ParseAddr(v.IP)
			if err != nil || !podCIDR.Contains(ip) || v.UID != pods[index].UID || v.Node != workers[index].Name || p.Spec.Containers[0].Image != image {
				t.Fatal("actual Pod identity differs")
			}
			lives[index] = v
			return true
		})
		ip, err := netip.ParseAddr(services[i].Spec.ClusterIP)
		if err != nil || !serviceCIDR.Contains(ip) {
			t.Fatal("actual single-stack Service address differs")
		}
	}
	endpointSlices := make([][]discoveryv1.EndpointSlice, 2)
	for i := range pods {
		index := i
		await(t, ctx, "actual Service EndpointSlice to exact PodUID", func() bool {
			rows, err := client.DiscoveryV1().EndpointSlices(fixtureNamespace).List(ctx, metav1.ListOptions{LabelSelector: discoveryv1.LabelServiceName + "=" + services[index].Name})
			if err != nil {
				return false
			}
			if !endpointsExact(rows.Items, services[index], pods[index], lives[index].IP) {
				return false
			}
			endpointSlices[index] = rows.Items
			return true
		})
	}
	ca := newCA(t)
	defer clear(ca.key)
	controller, _, controllerKey := ca.leaf(t, 2, "", x509.ExtKeyUsageClientAuth)
	defer clear(controllerKey)
	for i := range keys {
		pubs[i], keys[i], e = ed25519.GenerateKey(rand.Reader)
		fixtureError(t, "per-run key generation", e)
		defer clear(keys[i])
	}
	nonce := make([]byte, 32)
	if _, e = rand.Read(nonce); e != nil {
		t.Fatal("fixture entropy unavailable")
	}
	now := time.Now().UTC()
	hard := now.Add(3 * time.Minute)
	for i, role := range roles {
		peer := 1 - i
		c := probe.Config{Schema: probe.ConfigSchema, SourceCommit: source, Identity: probe.Identity{RunID: run, AttemptID: attempt, BirthSHA256: digest([]byte("disposable-Kind-network-only-no-native-birth")), PoolUID: pool, Role: role, Namespace: fixtureNamespace, NamespaceUID: string(namespace.UID), PodName: pods[i].Name, PodUID: string(pods[i].UID), PodIPv4: lives[i].IP, ServiceUID: string(services[i].UID), ServiceClusterIPv4: services[i].Spec.ClusterIP, NodeName: workers[i].Name, NodeUID: string(workers[i].UID)}, Peer: probe.Peer{PodUID: string(pods[peer].UID), NodeUID: string(workers[peer].UID), PodIPv4: lives[peer].IP, ServiceUID: string(services[peer].UID), ServiceClusterIPv4: services[peer].Spec.ClusterIP}, PodCIDR: podCIDR.String(), ServiceCIDR: serviceCIDR.String(), Nonce: base64.StdEncoding.EncodeToString(nonce), NotBefore: now.Add(-time.Second), HardNotAfter: hard, ControllerLeafSHA256: digest(controller.Certificate[0])}
		if role == "candidate" {
			c.Startup = &probe.StartupConfig{CoreSourceCommit: source, ImageDigest: "sha256:" + strings.Repeat("d", 64), WorkloadUID: string(pods[i].UID), ContainerName: "not-qualified-by-network-fixture", LaneRosterSHA256: strings.Repeat("e", 64)}
		}
		pair, certPEM, keyPEM := ca.leaf(t, int64(3+i), lives[i].IP, x509.ExtKeyUsageServerAuth)
		raw, err := json.Marshal(c)
		fixtureError(t, "public configuration encode", err)
		data := map[string][]byte{"config.json": raw, "server.crt": certPEM, "server.key": keyPEM, "controller-ca.crt": ca.pem, "signing.key": keys[i], "peer-signing.pub": pubs[peer]}
		if role == "candidate" {
			data["admission.key"] = bytes.Repeat([]byte{'c'}, 32)
		}
		secret, err := client.CoreV1().Secrets(fixtureNamespace).Create(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: prefix + "-" + role, Namespace: fixtureNamespace, Labels: map[string]string{runLabel: run, roleLabel: role}}, Immutable: &yes, Type: corev1.SecretTypeOpaque, Data: data}, metav1.CreateOptions{})
		fixtureError(t, "late actual-IP-bound private Secret create", err)
		secretUID := secret.UID
		secretName := secret.Name
		secretReceipts[i].Name, secretReceipts[i].UID, secretReceipts[i].CreatedAt = secret.Name, secret.UID, secret.CreationTimestamp
		t.Cleanup(func() {
			cleanup, done := context.WithTimeout(context.Background(), 5*time.Second)
			defer done()
			_ = client.CoreV1().Secrets(fixtureNamespace).Delete(cleanup, secretName, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &secretUID}})
		})
		clear(keyPEM)
		configs[i] = c
		httpClients[i] = clientFor(t, ca, controller, lives[i].IP, digest(pair.Certificate[0]))
	}
	setup, _ := json.Marshal(struct {
		Source         string
		ActualPods     []podLife
		SecretReceipts any
	}{source, lives, secretReceipts})
	t.Logf("NATIVE_PROBE_SERVICE_SETUP %s", setup)
	for i := range pods {
		index := i
		await(t, ctx, "actual normal bounded loader/mTLS server", func() bool {
			p, err := client.CoreV1().Pods(fixtureNamespace).Get(ctx, pods[index].Name, metav1.GetOptions{})
			if err != nil {
				return false
			}
			if len(p.Status.ContainerStatuses) == 1 && p.Status.ContainerStatuses[0].State.Terminated != nil {
				logTerminated(t, p)
				t.Fatalf("normal bounded loader/late projection failed: exit=%d", p.Status.ContainerStatuses[0].State.Terminated.ExitCode)
			}
			out, err := call(ctx, httpClients[index], lives[index].IP, probe.ReportPath, http.MethodGet, source)
			if err != nil {
				return false
			}
			raw, _ := json.Marshal(configs[index])
			if out.Schema != probe.ReportSchema || out.SourceCommit != source || out.ConfigSHA256 != digest(raw) || out.Identity != configs[index].Identity {
				t.Fatal("original normal process config/identity differs")
			}
			reports[index] = out
			return true
		})
	}
	for _, phase := range []struct {
		path, name string
	}{{probe.InitialPath, "initial"}, {probe.FinalPath, "final"}} {
		for i := range pods {
			if _, err := call(ctx, httpClients[i], lives[i].IP, phase.path, http.MethodPost, source); err != nil {
				t.Fatal("one original controlPOST incomplete; never retry")
			}
		}
		for i := range pods {
			index := i
			await(t, ctx, "finite signed "+phase.name, func() bool {
				out, err := call(ctx, httpClients[index], lives[index].IP, probe.ReportPath, http.MethodGet, source)
				if err != nil {
					return false
				}
				b := out.Initial
				if phase.name == "final" {
					b = out.Final
				}
				if b.State == "failed" || b.State == "unknown" {
					logFailedExchange(t, ctx, out, index, phase.name, source, lives, httpClients, configs, pubs)
					t.Fatal("real finite network exchange failed:", b.ErrorClass)
				}
				raw, _ := json.Marshal(configs[index])
				if out.SourceCommit != source || out.ConfigSHA256 != digest(raw) || out.Identity != configs[index].Identity || out.SigningPublicKey != base64.StdEncoding.EncodeToString(pubs[index]) {
					t.Fatal("original report identity changed")
				}
				reports[index] = out
				return b.State == "complete"
			})
		}
	}
	serviceSNAT := 0
	for i, report := range reports {
		peer := 1 - i
		for batchIndex, b := range []probe.BatchReport{report.Initial, report.Final} {
			want := 4
			if batchIndex == 1 {
				want = 2
			}
			if b.State != "complete" || b.StartedAt == nil || b.CompletedAt == nil || b.CompletedAt.Before(*b.StartedAt) || b.CompletedAt.Sub(*b.StartedAt) > probe.BatchDeadline || len(b.Sent) != want || len(b.Echoed) != want || len(b.Received) != 2*want {
				t.Fatal("normal fixed packet budget differs")
			}
			requests := map[string]probe.DatagramRecord{}
			seen := map[string]bool{}
			for _, r := range b.Received {
				if len(r.Packet) != probe.PayloadBytes || r.PayloadBytes != probe.PayloadBytes || r.PayloadSHA256 != digest(r.Packet) {
					t.Fatal("original signed datagram bytes differ")
				}
				address, err := netip.ParseAddrPort(r.Address)
				if err != nil || !address.Addr().Is4() || address.Port() == 0 || address.String() != r.Address {
					t.Fatal("actual UDP source unavailable")
				}
				echo := probe.VerifyPacket(r.Packet, configs[i], pubs[i], pubs[peer], true)
				request := probe.VerifyPacket(r.Packet, configs[peer], pubs[peer], pubs[i], false)
				if echo == request {
					t.Fatal("frame signature/source identity ambiguous")
				}
				if address.Port() != probe.Port && (!request || r.Packet[10] != 1) {
					t.Fatal("only a signed Service request may have a translated source port")
				}
				key := fmt.Sprintf("%t/%d/%d", echo, r.Packet[10], r.Packet[11])
				if seen[key] {
					t.Fatal("repeated original signed frame")
				}
				seen[key] = true
				batch := "initial"
				if batchIndex == 1 {
					batch = "final"
				}
				if r.Batch != batch || int(r.Packet[9]) != batchIndex || r.Sequence != int(r.Packet[11]) || r.ObservedAt.Before(*b.StartedAt) || r.ObservedAt.After(*b.CompletedAt) {
					t.Fatal("original datagram batch/lifetime differs")
				}
				if r.Path == "service" && r.Packet[10] != 1 || r.Path == "pod" && r.Packet[10] != 0 || r.Path != "service" && r.Path != "pod" {
					t.Fatal("signed path differs from evidence row")
				}
				if request {
					if address.Addr().String() != configs[i].Peer.PodIPv4 {
						t.Fatal("request widened beyond peer Pod source")
					}
					requests[fmt.Sprintf("%d/%d/%d", r.Packet[9], r.Packet[10], r.Packet[11])] = r
				} else if address.Addr().String() == configs[i].Peer.ServiceClusterIPv4 {
					if r.Path != "service" {
						t.Fatal("Pod echo claimed a Service source")
					}
					serviceSNAT++
				} else if address.Addr().String() != configs[i].Peer.PodIPv4 {
					t.Fatal("foreign echo accepted")
				}
			}
			for echoIndex, rows := range [][]probe.DatagramRecord{b.Sent, b.Echoed} {
				echo := echoIndex == 1
				sender, signer, echoer := configs[i], pubs[i], pubs[peer]
				if echo {
					sender, signer, echoer = configs[peer], pubs[peer], pubs[i]
				}
				seen := map[string]bool{}
				for _, r := range rows {
					if !probe.VerifyPacket(r.Packet, sender, signer, echoer, echo) || r.PayloadBytes != probe.PayloadBytes || r.PayloadSHA256 != digest(r.Packet) {
						t.Fatal("original outbound signed frame differs")
					}
					path := "pod"
					if r.Packet[10] == 1 {
						path = "service"
					}
					if int(r.Packet[9]) != batchIndex || r.Batch != []string{"initial", "final"}[batchIndex] || r.Path != path || r.Sequence != int(r.Packet[11]) || r.ObservedAt.Before(*b.StartedAt) || r.ObservedAt.After(*b.CompletedAt) {
						t.Fatal("original outbound signed selection or lifetime differs")
					}
					if echo {
						request, ok := requests[fmt.Sprintf("%d/%d/%d", r.Packet[9], r.Packet[10], r.Packet[11])]
						// Byte 8 (packet kind) and the final 64-byte echo signature are the
						// only differences from this exact original request.
						if !ok || r.Address != request.Address || r.ObservedAt.Before(request.ObservedAt) || !bytes.Equal(r.Packet[:8], request.Packet[:8]) || !bytes.Equal(r.Packet[9:len(r.Packet)-ed25519.SignatureSize], request.Packet[9:len(request.Packet)-ed25519.SignatureSize]) {
							t.Fatal("echo differs from its exact original request/return address")
						}
					} else {
						destination := configs[i].Peer.PodIPv4
						if r.Path == "service" {
							destination = configs[i].Peer.ServiceClusterIPv4
						}
						if r.Address != net.JoinHostPort(destination, "9446") {
							t.Fatal("original outbound path differs")
						}
					}
					key := fmt.Sprintf("%d/%d", r.Packet[10], r.Packet[11])
					if seen[key] {
						t.Fatal("duplicate outbound logical frame")
					}
					seen[key] = true
				}
			}
		}
		current, err := client.CoreV1().Pods(fixtureNamespace).Get(ctx, pods[i].Name, metav1.GetOptions{})
		fixtureError(t, "final Pod read", err)
		after, ok := life(current)
		if !ok || current.Spec.Containers[0].Image != image || after.Name != lives[i].Name || after.UID != lives[i].UID || after.IP != lives[i].IP || after.Node != lives[i].Node || after.ContainerID != lives[i].ContainerID || after.ImageID != lives[i].ImageID || !after.StartedAt.Equal(lives[i].StartedAt) {
			t.Fatal("normal process lifetime changed during original protocol")
		}
		service, err := client.CoreV1().Services(fixtureNamespace).Get(ctx, services[i].Name, metav1.GetOptions{})
		fixtureError(t, "final Service read", err)
		if service.UID != services[i].UID || service.DeletionTimestamp != nil || service.Spec.ClusterIP != services[i].Spec.ClusterIP {
			t.Fatal("Service lifetime changed")
		}
	}
	for i := range services {
		rows, err := client.DiscoveryV1().EndpointSlices(fixtureNamespace).List(ctx, metav1.ListOptions{LabelSelector: discoveryv1.LabelServiceName + "=" + services[i].Name})
		fixtureError(t, "final EndpointSlice read", err)
		if !endpointsExact(rows.Items, services[i], pods[i], lives[i].IP) {
			t.Fatal("actual endpoint ownership changed")
		}
	}
	if serviceSNAT == 0 {
		t.Fatal("real ClusterIP reverse-SNAT source was not observed; no Service proof")
	}
	public, _ := json.Marshal(struct {
		Schema, Source, Image                                      string
		ActualPods                                                 []podLife
		EndpointSlices                                             [][]discoveryv1.EndpointSlice
		Reports                                                    []probe.Report
		ServiceSourceEchoes                                        int
		Requests, Echoes                                           int
		NativeBirthQualified, StartupQualified, ReadinessQualified bool
	}{"native_probe_service_kind_public_v1", source, image, lives, endpointSlices, reports, serviceSNAT, 12, 12, false, false, false})
	t.Logf("NATIVE_PROBE_SERVICE_PROOF %s", public)
}

// A complete, one-endpoint slice joins the actual Service UID and Pod UID.
// The fixture never substitutes requested selectors for these native records.
func endpointsExact(rows []discoveryv1.EndpointSlice, service *corev1.Service, pod *corev1.Pod, ip string) bool {
	if len(rows) != 1 {
		return false
	}
	s := rows[0]
	if s.UID == "" || s.AddressType != discoveryv1.AddressTypeIPv4 || len(s.OwnerReferences) != 1 || s.OwnerReferences[0].UID != service.UID || s.OwnerReferences[0].Kind != "Service" || s.OwnerReferences[0].Name != service.Name || s.OwnerReferences[0].Controller == nil || !*s.OwnerReferences[0].Controller || len(s.Endpoints) != 1 || len(s.Ports) != 1 {
		return false
	}
	port := s.Ports[0]
	e := s.Endpoints[0]
	return port.Port != nil && *port.Port == 9446 && port.Protocol != nil && *port.Protocol == corev1.ProtocolUDP && e.TargetRef != nil && e.TargetRef.Kind == "Pod" && e.TargetRef.Namespace == fixtureNamespace && e.TargetRef.Name == pod.Name && e.TargetRef.UID == pod.UID && e.NodeName != nil && *e.NodeName == pod.Spec.NodeName && len(e.Addresses) == 1 && e.Addresses[0] == ip
}

// Termination messages and projected contents are intentionally excluded.
func logTerminated(t *testing.T, p *corev1.Pod) {
	t.Helper()
	for _, s := range p.Status.ContainerStatuses {
		if s.Name != "probe" || s.State.Terminated == nil {
			continue
		}
		v := s.State.Terminated
		raw, _ := json.Marshal(struct {
			Name, UID, Node       string
			ExitCode              int32
			StartedAt, FinishedAt metav1.Time
		}{p.Name, string(p.UID), p.Spec.NodeName, v.ExitCode, v.StartedAt, v.FinishedAt})
		t.Logf("NATIVE_PROBE_SERVICE_TERMINATED %s", raw)
	}
}
