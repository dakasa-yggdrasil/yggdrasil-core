package message

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity/executoractivity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-sdk-go/rpc"
	"github.com/google/uuid"
)

type executorSDKTransport struct {
	t      *testing.T
	calls  int
	op     string
	output any
}

func (f *executorSDKTransport) Consume(rpc.ConsumerConfig) (rpc.Subscription, error) {
	f.t.Fatal("unexpected SDK consumer")
	return nil, nil
}
func (f *executorSDKTransport) Publish(context.Context, rpc.Request) error {
	f.t.Fatal("unexpected SDK publish")
	return nil
}
func (f *executorSDKTransport) Close() error { return nil }
func (f *executorSDKTransport) Request(ctx context.Context, r rpc.Request) (rpc.Reply, error) {
	f.calls++
	if _, ok := ctx.Deadline(); !ok {
		f.t.Fatal("unbounded RPC")
	}
	var request model.AdapterExecuteIntegrationRequest
	if err := json.Unmarshal(r.Body, &request); err != nil {
		f.t.Fatal(err)
	}
	if request.Operation != f.op || request.Capability != f.op || r.Endpoint != "adapter.execute" || len(request.Auth) != 0 || len(request.Metadata) != 0 || len(request.Integration.InstanceSpec.Credentials) != 0 {
		f.t.Fatal("foreign/writing SDK request", request.Operation, r.Endpoint)
	}
	raw, _ := json.Marshal(model.AdapterExecuteIntegrationResponse{Operation: f.op, Capability: f.op, Status: "observed", Output: f.output})
	return rpc.Reply{Body: raw, ContentType: "application/json"}, nil
}
func executorReadFixture(t *testing.T, provider, op string, output any) (executorAdapterReader, *executorSDKTransport) {
	t.Helper()
	iid, tid := uuid.New(), uuid.New()
	ts := model.IntegrationTypeManifestSpec{Provider: provider, Adapter: model.IntegrationAdapterSpec{Transport: "rabbitmq", Version: "1.0.0", TimeoutSeconds: 5, Queues: model.IntegrationAdapterQueue{Execute: "adapter.execute", Describe: "adapter.describe"}}, Capabilities: []string{"describe", "execute"}, CredentialSchema: model.IntegrationSchemaSpec{Mode: "inline"}, InstanceSchema: model.IntegrationSchemaSpec{Mode: "inline"}, ResourceTypes: []model.IntegrationResourceType{{Name: "resource", CanonicalPrefix: "thirdparty.test.resource", IdentityTemplate: "resource.{id}", DefaultActions: []string{op}}}, ActionCatalog: []model.IntegrationActionDefinition{{Name: op, ResourceTypes: []string{"resource"}, Idempotent: true}}, Discovery: model.IntegrationDiscoverySpec{Mode: "push"}, Normalization: model.IntegrationNormalizationSpec{ExternalIDPath: "id", FallbackResourcePrefix: "thirdparty.test.custom"}}
	is := model.IntegrationInstanceManifestSpec{TypeRef: model.ManifestSelector{Namespace: "global", Name: provider}, Status: "active", Discovery: model.IntegrationInstanceDiscoverySpec{Mode: "manual"}}
	a := capacityResolvedObservationAdapter{instance: model.Manifest{ID: iid, Kind: "integration_instance", Version: 1, Checksum: strings.Repeat("a", 64), Metadata: model.ManifestMetadata{Namespace: "global", Name: "fixed-reader", Active: true}}, typ: model.Manifest{ID: tid, Kind: "integration_type", Version: 1, Checksum: strings.Repeat("b", 64), Metadata: model.ManifestMetadata{Namespace: "global", Name: provider, Active: true}}, instanceSpec: is, typeSpec: ts}
	f := &executorSDKTransport{t: t, op: op, output: output}
	return executorAdapterReader{enabled: true, client: NewAdapterTransportClient(f), resolved: a, pin: model.CapacityObservationAdapterBinding{IntegrationInstanceID: iid.String(), IntegrationTypeID: tid.String(), InstanceChecksum: a.instance.Checksum, TypeChecksum: a.typ.Checksum}}, f
}

func TestExecutorSDKPowerReadsExistingContractButNeverClaimsAuthority(t *testing.T) {
	r := executoractivity.ExactResource{AccountID: "123456789012", Region: "us-east-1", InstanceID: "i-0123456789abcdef0", OwnershipBindingID: "operator-record"}
	reader, f := executorReadFixture(t, "aws", "observe_ec2_instance", map[string]any{"instance_id": r.InstanceID, "region": r.Region, "state": "running", "found": true, "private_ip": "192.0.2.1", "instance_type": "m7i.2xlarge"})
	b := executorPowerReadBridge{reader: reader, resource: r}
	d, err := b.DiagnosticEC2(context.Background())
	if err != nil || d.State != "running" || f.calls != 1 {
		t.Fatal(d, err, f.calls)
	}
	if snapshot, err := b.Observe(context.Background(), r); !errors.Is(err, errExecutorPowerObservation) || snapshot.BootID != "" {
		t.Fatal("invented power proof", snapshot, err)
	}
	before := f.calls
	for _, action := range []string{"start", "stop", "terminate"} {
		if !errors.Is(b.Execute(context.Background(), executoractivity.PowerCommand{Action: action, Resource: r}), capacity.ErrPowerLifecycleUnqualified) {
			t.Fatal("legacy power write admitted")
		}
	}
	if _, err = b.Settlement(context.Background(), executoractivity.PowerCommand{}); !errors.Is(err, capacity.ErrPowerLifecycleUnqualified) {
		t.Fatal(err)
	}
	if f.calls != before {
		t.Fatal("unqualified mutation reached SDK")
	}
}

func TestExecutorSDKReadsRefuseDisabledDriftInlineSecretsAndCancellation(t *testing.T) {
	for _, mode := range []string{"disabled", "pin", "catalog", "credentials", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			r, f := executorReadFixture(t, "aws", "observe_ec2_instance", map[string]any{})
			ctx := context.Background()
			switch mode {
			case "disabled":
				r.enabled = false
			case "pin":
				r.pin.InstanceChecksum = strings.Repeat("c", 64)
			case "catalog":
				r.resolved.typeSpec.ActionCatalog[0].Idempotent = false
			case "credentials":
				r.resolved.instanceSpec.Credentials = map[string]any{"dummy": "synthetic"}
			case "cancel":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if _, err := r.read(ctx, "observe_ec2_instance", nil); err == nil || f.calls != 0 {
				t.Fatal("unsafe read reached transport", err, f.calls)
			}
		})
	}
}

func TestExecutorSDKNativeAdmissionDoesNotBecomeJobCensus(t *testing.T) {
	at := time.Date(2026, 10, 16, 0, 0, 0, 0, time.UTC)
	req := model.AdapterObserveCapacityPodAdmissionRequest{BindingName: "fixed-worker", PodName: "worker", ExpectedPodUID: uuid.NewString(), ExpectedPodGeneration: 1, ExpectedContainerID: "containerd://fixed", ExpectedContainerStartedAt: at}
	output := model.AdapterCapacityPodAdmissionResponse{Operation: capacity.ObserveNativePodAdmission, Status: "observed", Observation: model.NativeTerminationObservation{BindingName: req.BindingName, PodName: req.PodName, PodGeneration: req.ExpectedPodGeneration, PodUID: req.ExpectedPodUID, ContainerID: req.ExpectedContainerID, StartedAt: &at}, Admission: model.NativeProcessAdmissionObservation{SchemaVersion: 2, PodUID: req.ExpectedPodUID, ProcessNonce: uuid.NewString(), State: "roots_open", ObservedAt: at}}
	reader, f := executorReadFixture(t, "kubernetes", capacity.ObserveNativePodAdmission, output)
	r := executoractivity.ExactResource{AccountID: "123456789012", Region: "us-east-1", InstanceID: "i-0123456789abcdef0", OwnershipBindingID: "operator-record"}
	b := executorWorkerReadBridge{reader: reader, resource: r, request: req}
	if _, err := b.DiagnosticAdmission(context.Background()); err != nil {
		t.Fatal(err)
	}
	state, err := b.Observe(context.Background(), r)
	if !errors.Is(err, errExecutorWorkerContract) || state.Complete || state.Ready || state.BootID != "" {
		t.Fatal("Pod/process frame became host/job proof", state, err)
	}
	before := f.calls
	if b.Close(context.Background(), r, 1) == nil || b.Open(context.Background(), r, 2) == nil || b.Admit(context.Background(), r, "job", 2, "boot") == nil {
		t.Fatal("unqualified worker write admitted")
	}
	if f.calls != before {
		t.Fatal("worker mutation reached SDK")
	}
}
