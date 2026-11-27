package capacity

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

var errNativePrivateFactory = errors.New("HOLD: private Native bootstrap is unavailable or unqualified")

// NativeWorkerPrivateFactoryConfig is installed protected Source configuration,
// never a workflow input. No material value or caller URL is accepted here.
type NativeWorkerPrivateFactoryConfig struct {
	Execution           model.CapacityNativeWorkerExecutionProfile
	TemplateFile        string
	TemplateSHA256      string
	CLIFile             string
	CLISHA256           string
	CLIBytes            int64
	SystemBuildSource   string
	AgentTokenFile      string
	CAFile              string
	WireGuardMasterFile string
	ArtifactBucket      string
	ArtifactKey         string
	ArtifactVersionID   string
}

// NativeWorkerPrivateFactory is a copyable opaque handle. All copies share one
// private state and Close fence; formatting a value never exposes that state.
type NativeWorkerPrivateFactory struct {
	*nativeWorkerPrivateFactoryState
}

// Keep secrets, the executable and its mutex together behind the handle. The
// pointer is initialized once and never replaced during Prepare/Render/Close.
type nativeWorkerPrivateFactoryState struct {
	mu                sync.RWMutex
	closed            bool
	config            NativeWorkerPrivateFactoryConfig
	template          nativePrivateLaunch
	binary            *os.File
	master, token, ca []byte
	credentials       aws.CredentialsProvider
}

func (NativeWorkerPrivateFactory) String() string     { return "[private Native bootstrap factory]" }
func (f NativeWorkerPrivateFactory) GoString() string { return f.String() }
func (NativeWorkerPrivateFactory) MarshalJSON() ([]byte, error) {
	return []byte(`{"private_native_factory":"redacted"}`), nil
}

// These closed DTOs retain System LaunchBinding's exact declaration order.
// They are a wire mirror, not an import of System's internal module.
type nativePrivateLaunch struct {
	Schema            int                   `json:"schema"`
	Mode              string                `json:"mode"`
	SourceCommit      string                `json:"source_commit"`
	PoolID            string                `json:"pool_id"`
	PoolUID           string                `json:"pool_uid"`
	Registry          nativePrivateRegistry `json:"registry"`
	PolicyID          string                `json:"policy_id"`
	PolicySHA256      string                `json:"policy_sha256"`
	ExpectedPoolEpoch int64                 `json:"expected_pool_epoch"`
	IntentGeneration  int64                 `json:"intent_generation"`
	FencingToken      int64                 `json:"fencing_token"`
	ReservationID     string                `json:"reservation_id"`
	IntentSHA256      string                `json:"intent_sha256"`
	Provider          nativePrivateProvider `json:"provider"`
	Floor             nativePrivateFloor    `json:"floor"`
	Network           nativePrivateNetwork  `json:"network"`
	Operator          nativePrivateOperator `json:"operator"`
	Reserve           nativePrivateReserve  `json:"reserve"`
}
type nativePrivateRegistry struct {
	Kind      string `json:"kind"`
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	UID       string `json:"uid"`
}
type nativePrivateProvider struct {
	Kind              string `json:"kind"`
	AccountID         string `json:"account_id"`
	Region            string `json:"region"`
	Zone              string `json:"zone"`
	ImageID           string `json:"image_id"`
	NativeNetworkCIDR string `json:"native_network_cidr"`
}
type nativePrivateFloor struct {
	NodeName        string `json:"node_name"`
	NodeUID         string `json:"node_uid"`
	ProviderID      string `json:"provider_id"`
	ClusterUID      string `json:"cluster_uid"`
	APIEndpoint     string `json:"api_endpoint"`
	CASHA256        string `json:"ca_sha256"`
	NodeNetworkCIDR string `json:"node_network_cidr"`
}
type nativePrivateNetwork struct {
	Mode               string `json:"mode"`
	TransportCIDR      string `json:"transport_cidr"`
	WorkerIPv4         string `json:"worker_ipv4"`
	FloorPeerIPv4      string `json:"floor_peer_ipv4"`
	FloorPeerEndpoint  string `json:"floor_peer_endpoint"`
	FloorPeerPublicKey string `json:"floor_peer_public_key"`
	WorkerPublicKey    string `json:"worker_public_key"`
	PodCIDR            string `json:"pod_cidr"`
	ServiceCIDR        string `json:"service_cidr"`
}
type nativePrivateOperator struct {
	SourceCommit     string `json:"source_commit"`
	SHA256           string `json:"sha256"`
	Bytes            int64  `json:"bytes"`
	CapabilityRef    string `json:"capability_ref"`
	ExpectedHostname string `json:"expected_hostname"`
}
type nativePrivateReserve struct {
	KubeMilliCPU      int `json:"kube_milli_cpu"`
	KubeMemoryMiB     int `json:"kube_memory_mib"`
	SystemMilliCPU    int `json:"system_milli_cpu"`
	SystemMemoryMiB   int `json:"system_memory_mib"`
	EvictionMemoryMiB int `json:"eviction_memory_mib"`
}

// NewNativeWorkerPrivateFactory loads and pins real protected files once. It
// does not retrieve credentials, open a network connection or activate a port.
func NewNativeWorkerPrivateFactory(c NativeWorkerPrivateFactoryConfig, credentials aws.CredentialsProvider) (*NativeWorkerPrivateFactory, error) {
	if credentials != nil {
		value := reflect.ValueOf(credentials)
		switch value.Kind() {
		case reflect.Pointer, reflect.Interface, reflect.Func, reflect.Map, reflect.Slice:
			if value.IsNil() {
				return nil, errNativePrivateFactory
			}
		}
	}
	if credentials == nil || !marketID.MatchString(c.Execution.Profile) || !marketID.MatchString(c.Execution.BindingName) || !marketAdapterValid(c.Execution.Adapter) || !marketCommit.MatchString(c.Execution.SDKSourceCommit) || !marketSHA.MatchString(c.Execution.ScopeSHA256) || len(c.Execution.ExcludedIPv4) == 0 || !marketCommit.MatchString(c.SystemBuildSource) || c.Execution.BootstrapSourceCommit != c.SystemBuildSource || c.Execution.LaunchTemplateSHA256 != c.TemplateSHA256 || !marketSHA.MatchString(c.TemplateSHA256) || !marketSHA.MatchString(c.CLISHA256) || c.CLIBytes < 1 || c.CLIBytes > 512<<20 || !regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$`).MatchString(c.ArtifactBucket) || c.ArtifactVersionID == "" || c.ArtifactVersionID == "null" || len(c.ArtifactVersionID) > 2048 || c.ArtifactKey == "" || strings.HasPrefix(c.ArtifactKey, "/") || len(c.ArtifactKey) > 1024 {
		return nil, errNativePrivateFactory
	}
	for _, v := range c.ArtifactKey + c.ArtifactVersionID {
		if v < 32 || v == 127 {
			return nil, errNativePrivateFactory
		}
	}
	c.Execution.ExcludedIPv4 = slices.Clone(c.Execution.ExcludedIPv4)
	f := &NativeWorkerPrivateFactory{nativeWorkerPrivateFactoryState: &nativeWorkerPrivateFactoryState{config: c, credentials: credentials}}
	ok := false
	defer func() {
		if !ok {
			f.Close()
		}
	}()
	raw, e := nativePrivateReadFile(c.TemplateFile, 32768, false)
	if e != nil || nativePrivateSHA(raw) != c.TemplateSHA256 || DecodeNativeCapacity(raw, &f.template) != nil {
		return nil, errNativePrivateFactory
	}
	canonical, _ := json.Marshal(f.template)
	if !bytes.Equal(raw, canonical) || f.template.Schema != 1 || f.template.Mode != "native_k3s_worker_v1" || f.template.SourceCommit != c.SystemBuildSource || f.template.Operator.SourceCommit != c.SystemBuildSource || f.template.Operator.SHA256 != c.CLISHA256 || f.template.Operator.Bytes != c.CLIBytes || f.template.Operator.CapabilityRef != "native-private://operator-capability" || f.template.Operator.ExpectedHostname != c.ArtifactBucket+".s3.us-east-1.amazonaws.com" {
		return nil, errNativePrivateFactory
	}
	if f.master, e = nativePrivateReadFile(c.WireGuardMasterFile, 32, true); e != nil || len(f.master) != 32 || bytes.Equal(f.master, make([]byte, 32)) {
		return nil, errNativePrivateFactory
	}
	if f.token, e = nativePrivateReadFile(c.AgentTokenFile, 640, true); e != nil || !regexp.MustCompile(`^K10[a-f0-9]{64}::node:[^\s:]{16,512}$`).Match(f.token) {
		return nil, errNativePrivateFactory
	}
	if f.ca, e = nativePrivateReadFile(c.CAFile, 65536, false); e != nil || nativePrivateSHA(f.ca) != f.template.Floor.CASHA256 {
		return nil, errNativePrivateFactory
	}
	if !nativePrivateCAPEM(f.ca) {
		return nil, errNativePrivateFactory
	}
	if f.binary, e = nativePrivateOpenExecutable(c); e != nil {
		return nil, errNativePrivateFactory
	}
	ok = true
	return f, nil
}

func nativePrivateSHA(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func nativePrivateWipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
func nativePrivateCAPEM(raw []byte) bool {
	count := 0
	for len(bytes.TrimSpace(raw)) != 0 {
		if !bytes.HasPrefix(bytes.TrimSpace(raw), []byte("-----BEGIN CERTIFICATE-----")) {
			return false
		}
		b, rest := pem.Decode(raw)
		if b == nil || b.Type != "CERTIFICATE" || len(b.Headers) != 0 {
			return false
		}
		cert, e := x509.ParseCertificate(b.Bytes)
		if e != nil || !cert.IsCA {
			return false
		}
		count++
		raw = rest
	}
	return count > 0
}

func (f *NativeWorkerPrivateFactory) Close() error {
	if f == nil || f.nativeWorkerPrivateFactoryState == nil {
		return nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return nil
	}
	f.closed = true
	for _, b := range [][]byte{f.master, f.token, f.ca} {
		nativePrivateWipe(b)
	}
	f.master, f.token, f.ca = nil, nil, nil
	if f.binary != nil {
		e := f.binary.Close()
		f.binary = nil
		if e != nil {
			return errNativePrivateFactory
		}
	}
	return nil
}

// Prepare is pure after construction. It is safe inside the reservation Tx:
// no file read, credential retrieval, clock, randomness or WAN occurs here.
func (f *NativeWorkerPrivateFactory) Prepare(a model.CapacityNativeWorkerAttempt) (model.CapacityNativeWorkerLaunch, error) {
	if f == nil || f.nativeWorkerPrivateFactoryState == nil {
		return model.CapacityNativeWorkerLaunch{}, errNativePrivateFactory
	}
	f.mu.RLock()
	defer f.mu.RUnlock()
	prepared, key, e := f.prepare(a)
	defer nativePrivateWipe(key)
	return prepared, e
}

func (f *NativeWorkerPrivateFactory) prepare(a model.CapacityNativeWorkerAttempt) (model.CapacityNativeWorkerLaunch, []byte, error) {
	var empty model.CapacityNativeWorkerLaunch
	ip, e := netip.ParseAddr(a.OverlayIPv4)
	cidr, cidrErr := netip.ParsePrefix(a.Execution.OverlayCIDR)
	poolID, uidErr := uuid.Parse(a.PoolUID)
	if f.closed || len(f.master) != 32 || a.ID == uuid.Nil || a.PolicyID == uuid.Nil || uidErr != nil || poolID == uuid.Nil || poolID.String() != a.PoolUID || a.PoolEpoch < 1 || a.Generation < 1 || a.FencingToken < 1 || a.Domain == "" || a.Namespace == "" || a.Profile != f.config.Execution.Profile || !reflect.DeepEqual(a.Execution, f.config.Execution) || !marketSHA.MatchString(a.IntentSHA256) || !marketSHA.MatchString(strings.TrimPrefix(a.PolicyChecksum, "sha256:")) || e != nil || !ip.Is4() || !ip.IsPrivate() || ip.String() != a.OverlayIPv4 || cidrErr != nil || !cidr.Contains(ip) || slices.Contains(a.Execution.ExcludedIPv4, a.OverlayIPv4) || a.Registry.Kind != "Lease" || a.Registry.Namespace == "" || a.Registry.Name == "" || a.Registry.UID == "" {
		return empty, nil, errNativePrivateFactory
	}
	launch := f.template
	if a.Provider != launch.Provider.Kind || a.Provider == "aws" && a.Region != launch.Provider.Region || a.Provider == "hetzner" && (launch.Provider.Region != "eu-central" || a.Region != launch.Provider.Zone) || a.Provider != "aws" && a.Provider != "hetzner" {
		return empty, nil, errNativePrivateFactory
	}
	frame, _ := json.Marshal(struct {
		Domain    string
		Binding   string
		Scope     string
		Namespace string
		Pool      string
		Attempt   string
	}{"dakasa.native-worker.wireguard.v1/" + a.Domain, a.Execution.BindingName, a.Execution.ScopeSHA256, a.Namespace, a.PoolUID, a.ID.String()})
	mac := hmac.New(sha256.New, f.master)
	_, _ = mac.Write(frame)
	private := mac.Sum(nil)
	key, e := ecdh.X25519().NewPrivateKey(private)
	if e != nil {
		nativePrivateWipe(private)
		return empty, nil, errNativePrivateFactory
	}
	launch.PoolUID = a.PoolUID
	launch.Registry = nativePrivateRegistry{a.Registry.Kind, a.Registry.Namespace, a.Registry.Name, a.Registry.UID}
	launch.PolicyID = a.PolicyID.String()
	launch.PolicySHA256 = strings.TrimPrefix(a.PolicyChecksum, "sha256:")
	launch.ExpectedPoolEpoch = a.PoolEpoch
	launch.IntentGeneration = a.Generation
	launch.FencingToken = a.FencingToken
	launch.ReservationID = a.ID.String()
	launch.IntentSHA256 = a.IntentSHA256
	launch.Network.WorkerIPv4 = a.OverlayIPv4
	launch.Network.WorkerPublicKey = base64.StdEncoding.EncodeToString(key.PublicKey().Bytes())
	if launch.Network.WorkerPublicKey == launch.Network.FloorPeerPublicKey {
		nativePrivateWipe(private)
		return empty, nil, errNativePrivateFactory
	}
	raw, e := json.Marshal(launch)
	prepared := model.CapacityNativeWorkerLaunch{AttemptID: a.ID, PoolUID: a.PoolUID, PoolEpoch: a.PoolEpoch, Generation: a.Generation, FencingToken: a.FencingToken, OverlayIPv4: a.OverlayIPv4, TemplateSHA256: f.config.TemplateSHA256, PublicJSON: raw}
	if e != nil || ValidateNativeWorkerLaunch(a, prepared) != nil {
		nativePrivateWipe(private)
		return empty, nil, errNativePrivateFactory
	}
	return prepared, private, nil
}

// RenderNativeWorkerPrivateBootstrap accepts only the exact stored public launch.
// All private capability signing and real child execution happen before Redeem.
func (f *NativeWorkerPrivateFactory) RenderNativeWorkerPrivateBootstrap(ctx context.Context, a model.CapacityNativeWorkerAttempt, stored json.RawMessage, expires time.Time) ([]byte, error) {
	if f == nil || f.nativeWorkerPrivateFactoryState == nil || ctx == nil || ctx.Err() != nil {
		return nil, errNativePrivateFactory
	}
	f.mu.RLock()
	defer f.mu.RUnlock()
	if a.State != "reserved" || !expires.After(time.Now().UTC()) {
		return nil, errNativePrivateFactory
	}
	deadline := nativePrivateEarlier(expires, time.Now().Add(20*time.Second))
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	prepared, private, e := f.prepare(a)
	if e != nil {
		return nil, e
	}
	defer nativePrivateWipe(private)
	if !bytes.Equal(stored, prepared.PublicJSON) || nativePrivateSHA(stored) != a.LaunchSHA256 {
		return nil, errNativePrivateFactory
	}
	capability, e := f.capability(ctx, expires)
	if e != nil {
		return nil, errNativePrivateFactory
	}
	material, e := json.Marshal(struct {
		Schema int    `json:"schema"`
		Token  string `json:"agent_token"`
		Key    string `json:"wireguard_private_key"`
		CA     string `json:"ca_pem"`
	}{1, string(f.token), base64.StdEncoding.EncodeToString(private), string(f.ca)})
	if e != nil {
		return nil, errNativePrivateFactory
	}
	defer nativePrivateWipe(material)
	input, e := json.Marshal(struct {
		Schema   string          `json:"schema"`
		Launch   json.RawMessage `json:"launch"`
		SHA      string          `json:"launch_sha256"`
		Material json.RawMessage `json:"material"`
		URL      string          `json:"operator_capability_url"`
	}{"native_worker_private_render_v1", prepared.PublicJSON, a.LaunchSHA256, material, capability})
	if e != nil || len(input) > 256<<10 {
		return nil, errNativePrivateFactory
	}
	defer nativePrivateWipe(input)
	return nativePrivateExecute(ctx, f.binary, f.config, input, expires)
}

func (f *NativeWorkerPrivateFactory) capability(ctx context.Context, expires time.Time) (string, error) {
	creds, e := f.credentials.Retrieve(ctx)
	if e != nil || creds.AccessKeyID == "" || creds.SecretAccessKey == "" {
		return "", errNativePrivateFactory
	}
	now := time.Now().UTC()
	if creds.CanExpire && creds.Expires.Before(expires) {
		expires = creds.Expires
	}
	seconds := min(int64(900), int64(expires.Sub(now)/time.Second))
	if seconds < 1 {
		return "", errNativePrivateFactory
	}
	u := url.URL{Scheme: "https", Host: f.template.Operator.ExpectedHostname, Path: "/" + f.config.ArtifactKey}
	q := url.Values{"versionId": {f.config.ArtifactVersionID}, "X-Amz-Expires": {strconv.FormatInt(seconds, 10)}}
	u.RawQuery = q.Encode()
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if e != nil {
		return "", errNativePrivateFactory
	}
	req.Header.Set("x-amz-expected-bucket-owner", "153828470928")
	url, _, e := v4.NewSigner().PresignHTTP(ctx, creds, req, "UNSIGNED-PAYLOAD", "s3", "us-east-1", now, func(o *v4.SignerOptions) { o.DisableHeaderHoisting = true; o.DisableURIPathEscaping = true })
	if e != nil {
		return "", errNativePrivateFactory
	}
	return url, nil
}

var _ fmt.Stringer = (*NativeWorkerPrivateFactory)(nil)

func nativePrivateEarlier(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
