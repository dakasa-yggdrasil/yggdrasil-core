package capacity

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

type nativePrivateCredentialsFixture struct {
	calls int
	value aws.Credentials
	err   error
}

func (c *nativePrivateCredentialsFixture) Retrieve(context.Context) (aws.Credentials, error) {
	c.calls++
	return c.value, c.err
}

// The pure fixture does not pretend to be an executable or live factory. The
// separately tagged test must construct the real factory and run the actual CLI.
func nativePrivateFactoryFixture(t *testing.T, source string) (*NativeWorkerPrivateFactory, model.CapacityNativeWorkerAttempt) {
	t.Helper()
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "synthetic-private-factory-ci"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, e := x509.CreateCertificate(rand.Reader, cert, cert, pub, key)
	if e != nil {
		t.Fatal(e)
	}
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	floorKey, _ := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{8}, 32))
	template := nativePrivateLaunch{Schema: 1, Mode: "native_k3s_worker_v1", SourceCommit: source, PoolID: "ci-native-worker", Provider: nativePrivateProvider{Kind: "aws", AccountID: "153828470928", Region: "us-east-1", Zone: "us-east-1a", ImageID: "ami-11111111111111111", NativeNetworkCIDR: "10.90.0.0/24"}, Floor: nativePrivateFloor{NodeName: "ci-floor", NodeUID: "33333333-3333-4333-8333-333333333333", ProviderID: "hcloud://12345", ClusterUID: "44444444-4444-4444-8444-444444444444", APIEndpoint: "https://10.80.0.2:6443", CASHA256: nativePrivateSHA(ca), NodeNetworkCIDR: "10.80.0.0/24"}, Network: nativePrivateNetwork{Mode: "wireguard_routed_v1", TransportCIDR: "10.81.0.0/24", FloorPeerIPv4: "10.81.0.2", FloorPeerEndpoint: "203.0.113.2:51820", FloorPeerPublicKey: base64.StdEncoding.EncodeToString(floorKey.PublicKey().Bytes()), PodCIDR: "10.82.0.0/16", ServiceCIDR: "10.83.0.0/16"}, Operator: nativePrivateOperator{SourceCommit: source, SHA256: strings.Repeat("d", 64), Bytes: 12345, CapabilityRef: "native-private://operator-capability", ExpectedHostname: "ci-fixture.s3.us-east-1.amazonaws.com"}, Reserve: nativePrivateReserve{100, 128, 100, 128, 128}}
	raw, _ := json.Marshal(template)
	execution := model.CapacityNativeWorkerExecutionProfile{Profile: "aws-worker", Adapter: model.CapacityMarketAdapterBinding{ManifestID: "10000000-0000-4000-8000-000000000001", Version: 1, Checksum: strings.Repeat("b", 64), IntegrationTypeID: "10000000-0000-4000-8000-000000000002", TypeChecksum: strings.Repeat("c", 64)}, BindingName: "ci-workers", SDKSourceCommit: strings.Repeat("b", 40), ScopeSHA256: strings.Repeat("e", 64), EnsureCapability: "ensure_native_worker", ObserveCapability: "observe_native_worker", DestroyCapability: "destroy_native_worker", LaunchTemplateSHA256: nativePrivateSHA(raw), BootstrapSourceCommit: source, IPAMScope: "ci/workers", OverlayCIDR: "10.81.0.0/24", ExcludedIPv4: []string{"10.81.0.2"}}
	f := &NativeWorkerPrivateFactory{nativeWorkerPrivateFactoryState: &nativeWorkerPrivateFactoryState{template: template, master: bytes.Repeat([]byte{7}, 32), token: []byte("K10" + strings.Repeat("a", 64) + "::node:" + strings.Repeat("x", 32)), ca: ca, config: NativeWorkerPrivateFactoryConfig{Execution: execution, TemplateSHA256: execution.LaunchTemplateSHA256, CLISHA256: template.Operator.SHA256, CLIBytes: template.Operator.Bytes, SystemBuildSource: source, ArtifactBucket: "ci-fixture", ArtifactKey: "qualified/operator", ArtifactVersionID: "ci-source-version"}}}
	a := model.CapacityNativeWorkerAttempt{ID: uuid.MustParse("22222222-2222-4222-8222-222222222222"), PolicyID: uuid.MustParse("11111111-1111-4111-8111-111111111111"), PolicyChecksum: strings.Repeat("f", 64), Namespace: "ci-workers", Domain: "compute", PoolUID: "55555555-5555-4555-8555-555555555555", PoolEpoch: 1, Generation: 2, FencingToken: 3, Registry: model.CapacityNativePoolRegistryRef{Kind: "Lease", Namespace: "ci-workers", Name: "ci-registry", UID: "66666666-6666-4666-8666-666666666666"}, Profile: execution.Profile, Provider: "aws", Region: "us-east-1", Execution: execution, OverlayIPv4: "10.81.0.7", IntentSHA256: strings.Repeat("c", 64), State: "reserved"}
	return f, a
}

func TestNativePrivateFactoryPrepareIsDeterministicPureAndAuthorityBound(t *testing.T) {
	f, a := nativePrivateFactoryFixture(t, strings.Repeat("a", 40))
	defer f.Close()
	provider := &nativePrivateCredentialsFixture{}
	f.credentials = provider
	first, e := f.Prepare(a)
	if e != nil {
		t.Fatal(e)
	}
	second, e := f.Prepare(a)
	if e != nil || !bytes.Equal(first.PublicJSON, second.PublicJSON) || provider.calls != 0 {
		t.Fatal("pure preparation changed or retrieved credentials", e)
	}
	var base nativePrivateLaunch
	if json.Unmarshal(first.PublicJSON, &base) != nil {
		t.Fatal("invalid prepared launch")
	}
	for _, mode := range []string{"attempt", "domain", "namespace", "pool", "binding"} {
		copy := a
		owned := &NativeWorkerPrivateFactory{nativeWorkerPrivateFactoryState: &nativeWorkerPrivateFactoryState{config: f.config, template: f.template, master: append([]byte(nil), f.master...)}}
		owned.config.Execution.ExcludedIPv4 = append([]string(nil), f.config.Execution.ExcludedIPv4...)
		switch mode {
		case "attempt":
			copy.ID = uuid.New()
		case "domain":
			copy.Domain = "another-domain"
		case "namespace":
			copy.Namespace = "another-namespace"
		case "pool":
			copy.PoolUID = uuid.NewString()
		case "binding":
			copy.Execution.BindingName = "different-binding"
			owned.config.Execution.BindingName = copy.Execution.BindingName
		}
		prepared, e := owned.Prepare(copy)
		nativePrivateWipe(owned.master)
		var launch nativePrivateLaunch
		if e != nil || json.Unmarshal(prepared.PublicJSON, &launch) != nil || launch.Network.WorkerPublicKey == base.Network.WorkerPublicKey {
			t.Fatal("domain-separated key reused", mode, e)
		}
	}
	for _, mode := range []string{"scope", "source", "profile", "excluded-ip", "foreign-ip", "expired-authority"} {
		copy := a
		switch mode {
		case "scope":
			copy.Execution.ScopeSHA256 = strings.Repeat("0", 64)
		case "source":
			copy.Execution.BootstrapSourceCommit = strings.Repeat("0", 40)
		case "profile":
			copy.Profile = "caller-profile"
		case "excluded-ip":
			copy.OverlayIPv4 = "10.81.0.2"
		case "foreign-ip":
			copy.OverlayIPv4 = "10.99.0.7"
		case "expired-authority":
			copy.PoolEpoch = 0
		}
		if _, e := f.Prepare(copy); e == nil {
			t.Fatal("unbound preparation accepted", mode)
		}
	}
}

func TestNativePrivateFactoryHCloudRegionTranslationIsTemplateLocal(t *testing.T) {
	f, a := nativePrivateFactoryFixture(t, strings.Repeat("a", 40))
	defer f.Close()
	f.template.Provider = nativePrivateProvider{Kind: "hetzner", Region: "eu-central", Zone: "hel1", ImageID: "123456", NativeNetworkCIDR: "10.90.0.0/24"}
	a.Provider = "hetzner"
	a.Region = "hel1"
	prepared, e := f.Prepare(a)
	var launch nativePrivateLaunch
	if e != nil || json.Unmarshal(prepared.PublicJSON, &launch) != nil || launch.Provider.Region != "eu-central" || a.Region != "hel1" {
		t.Fatal("provider region leaked into market identity", e)
	}
	a.Region = "eu-central"
	if _, e = f.Prepare(a); e == nil {
		t.Fatal("invented market alias accepted")
	}
}

func TestNativePrivateFactorySignsOnlyFixedVersionOwnerAndBoundedDeadline(t *testing.T) {
	f, _ := nativePrivateFactoryFixture(t, strings.Repeat("a", 40))
	defer f.Close()
	provider := &nativePrivateCredentialsFixture{value: aws.Credentials{AccessKeyID: "CI_ACCESS", SecretAccessKey: "CI_PRIVATE", SessionToken: "CI_SESSION", CanExpire: true, Expires: time.Now().Add(70 * time.Second)}}
	f.credentials = provider
	value, e := f.capability(context.Background(), time.Now().Add(10*time.Minute))
	if e != nil {
		t.Fatal("real SigV4 signing refused", e)
	}
	u, e := url.Parse(value)
	q := u.Query()
	seconds, _ := time.ParseDuration(q.Get("X-Amz-Expires") + "s")
	if e != nil || u.Host != f.template.Operator.ExpectedHostname || u.Path != "/qualified/operator" || q.Get("versionId") != f.config.ArtifactVersionID || q.Get("X-Amz-SignedHeaders") != "host;x-amz-expected-bucket-owner" || q.Get("X-Amz-Algorithm") != "AWS4-HMAC-SHA256" || !strings.Contains(q.Get("X-Amz-Credential"), "/us-east-1/s3/aws4_request") || seconds <= 0 || seconds > 70*time.Second || provider.calls != 1 {
		t.Fatal("signed capability escaped fixed private bounds")
	}
	if _, e = f.capability(context.Background(), time.Now().Add(-time.Second)); e == nil {
		t.Fatal("expired command got a capability")
	}
	provider.value.Expires = time.Now().Add(-time.Second)
	if _, e = f.capability(context.Background(), time.Now().Add(time.Minute)); e == nil {
		t.Fatal("expired credentials got a capability")
	}
}

func TestNativePrivateFactoryCloseFencesConcurrentPrepareAndWipesOwnedMaterial(t *testing.T) {
	f, a := nativePrivateFactoryFixture(t, strings.Repeat("a", 40))
	handle := *f // Copies only the state pointer, never the mutex or private slices.
	master, token := f.master, f.token
	var group sync.WaitGroup
	for range 4 {
		group.Go(func() {
			for range 20 {
				_, _ = handle.Prepare(a)
			}
		})
	}
	if e := f.Close(); e != nil {
		t.Fatal(e)
	}
	group.Wait()
	if !bytes.Equal(master, make([]byte, len(master))) || !bytes.Equal(token, make([]byte, len(token))) {
		t.Fatal("owned material survived close")
	}
	if _, e := f.Prepare(a); e == nil {
		t.Fatal("closed factory prepared another launch")
	}
	if _, e := handle.Prepare(a); e == nil {
		t.Fatal("value copy escaped the shared close fence")
	}
	if e := handle.Close(); e != nil {
		t.Fatal("copied handle did not share idempotent close")
	}
	if e := f.Close(); e != nil {
		t.Fatal("close is not idempotent")
	}
	encoded, e := json.Marshal(f)
	if e != nil || strings.Contains(string(encoded), "CI_PRIVATE") || string(encoded) != `{"private_native_factory":"redacted"}` {
		t.Fatal("private factory marshaled material")
	}
}

func TestNativePrivateFactoryValueAndPointerRepresentationsRemainOpaque(t *testing.T) {
	f, _ := nativePrivateFactoryFixture(t, strings.Repeat("a", 40))
	defer f.Close()
	f.master = []byte("CI_PRIVATE_MASTER_VALUE_DO_NOT_FORMAT")
	f.token = []byte("CI_PRIVATE_TOKEN_VALUE_DO_NOT_FORMAT")
	f.ca = []byte("CI_PRIVATE_CA_VALUE_DO_NOT_FORMAT")
	f.credentials = &nativePrivateCredentialsFixture{value: aws.Credentials{AccessKeyID: "CI_PRIVATE_ACCESS_KEY", SecretAccessKey: "CI_PRIVATE_CREDENTIAL_VALUE_DO_NOT_FORMAT"}}
	for _, value := range []any{f, *f, NativeWorkerPrivateFactory{}, &NativeWorkerPrivateFactory{}} {
		for _, format := range []string{"%v", "%+v", "%#v"} {
			if got := fmt.Sprintf(format, value); got != "[private Native bootstrap factory]" {
				t.Fatal("factory representation exposed private state")
			}
		}
		raw, e := json.Marshal(value)
		if e != nil || string(raw) != `{"private_native_factory":"redacted"}` {
			t.Fatal("factory JSON representation exposed private state")
		}
	}
	var absent *NativeWorkerPrivateFactory
	for _, format := range []string{"%v", "%+v", "%#v"} {
		if got := fmt.Sprintf(format, absent); got != "<nil>" {
			t.Fatal("nil factory representation is not closed")
		}
	}
	if raw, e := json.Marshal(absent); e != nil || string(raw) != "null" {
		t.Fatal("nil factory JSON representation is not closed")
	}
}

func TestNativePrivateFactoryZeroAndNilHandlesRefuseWork(t *testing.T) {
	for _, f := range []*NativeWorkerPrivateFactory{nil, {}} {
		if _, e := f.Prepare(model.CapacityNativeWorkerAttempt{}); e != errNativePrivateFactory {
			t.Fatal("missing private state prepared a launch")
		}
		if _, e := f.RenderNativeWorkerPrivateBootstrap(context.Background(), model.CapacityNativeWorkerAttempt{}, nil, time.Now().Add(time.Minute)); e != errNativePrivateFactory {
			t.Fatal("missing private state rendered bootstrap")
		}
		if e := f.Close(); e != nil {
			t.Fatal("missing private state close is not safe")
		}
	}
}
