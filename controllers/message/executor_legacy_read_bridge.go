package message

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity/executoractivity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

var errExecutorWorkerContract = errors.New("native admission is not a qualified executor job census/admission protocol")
var errExecutorPowerObservation = errors.New("legacy EC2 observation lacks verified account ownership boot and original power receipt")

// This private bridge uses the real Core adapter client/SDK wire contract, not a
// parallel RPC API. Its resolved manifests must come from the existing protected
// resolver, and are checked against operator pins. No constructor is installed at
// boot. Reads default off; no write/grant/credential fallback is implemented.
type executorAdapterReader struct {
	enabled  bool
	client   AdapterTransportClient
	resolved capacityResolvedObservationAdapter
	pin      model.CapacityObservationAdapterBinding
}

func (r executorAdapterReader) read(ctx context.Context, operation string, input map[string]any) (model.AdapterExecuteIntegrationResponse, error) {
	var out model.AdapterExecuteIntegrationResponse
	if ctx == nil || ctx.Err() != nil {
		return out, fmt.Errorf("executor read context unavailable")
	}
	if !r.enabled || r.client == nil || (operation != "observe_ec2_instance" && operation != capacity.ObserveNativePodAdmission) {
		return out, fmt.Errorf("executor read bridge disabled or operation refused")
	}
	a, b := r.resolved, r.pin
	if a.instance.Kind != "integration_instance" || a.typ.Kind != "integration_type" || !a.instance.Metadata.Active || !a.typ.Metadata.Active || a.instance.ID.String() != b.IntegrationInstanceID || a.typ.ID.String() != b.IntegrationTypeID || a.instance.Checksum != b.InstanceChecksum || a.typ.Checksum != b.TypeChecksum || !capacity.ValidDigest(b.InstanceChecksum) || !capacity.ValidDigest(b.TypeChecksum) || !capacityNativeCatalogOperation(a.typeSpec, operation) {
		return out, fmt.Errorf("executor adapter identity/catalog changed")
	}
	idempotent := false
	for _, action := range a.typeSpec.ActionCatalog {
		if action.Name == operation {
			idempotent = action.Idempotent
		}
	}
	if !idempotent || len(a.instanceSpec.Credentials) != 0 {
		return out, fmt.Errorf("executor read requires declared idempotence and no inline credential transfer")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	request := model.AdapterExecuteIntegrationRequest{Operation: operation, Capability: operation, Input: input, Integration: model.AdapterExecuteIntegrationContext{Type: manifestReferenceFromRecord(a.typ), TypeSpec: a.typeSpec, Instance: manifestReferenceFromRecord(a.instance), InstanceSpec: a.instanceSpec}}
	if err := r.client.Call(ctx, integrationExecuteContract, a.typeSpec, a.instanceSpec, "execute", request, &out); err != nil {
		return model.AdapterExecuteIntegrationResponse{}, fmt.Errorf("executor adapter read failed")
	}
	if out.Operation != operation || out.Capability != operation || out.Status != "observed" {
		return model.AdapterExecuteIntegrationResponse{}, fmt.Errorf("executor adapter explicit read response required")
	}
	raw, err := json.Marshal(out.Output)
	if err != nil || len(raw) > 2<<20 {
		return model.AdapterExecuteIntegrationResponse{}, fmt.Errorf("executor adapter output exceeds bound")
	}
	return out, nil
}

type executorEC2Diagnostic struct {
	InstanceID string `json:"instance_id"`
	State      string `json:"state"`
	Region     string `json:"region"`
	Found      bool   `json:"found"`
}
type executorPowerReadBridge struct {
	reader   executorAdapterReader
	resource executoractivity.ExactResource
}

// DiagnosticEC2 returns only fields actually supplied by the existing adapter.
// No tags, account, boot ID, ownership receipt or timestamp are manufactured.
func (b executorPowerReadBridge) DiagnosticEC2(ctx context.Context) (executorEC2Diagnostic, error) {
	var out executorEC2Diagnostic
	if b.reader.resolved.typeSpec.Provider != "aws" || b.resource.InstanceID == "" || b.resource.Region == "" {
		return out, fmt.Errorf("fixed AWS read binding required")
	}
	r, err := b.reader.read(ctx, "observe_ec2_instance", map[string]any{"instance_id": b.resource.InstanceID, "region": b.resource.Region})
	if err != nil {
		return out, err
	}
	raw, _ := json.Marshal(r.Output)
	if err = json.Unmarshal(raw, &out); err != nil {
		return out, fmt.Errorf("EC2 observation shape refused")
	}
	if !out.Found || out.InstanceID != b.resource.InstanceID || out.Region != b.resource.Region {
		return executorEC2Diagnostic{}, fmt.Errorf("exact EC2 instance observation unavailable")
	}
	switch out.State {
	case "running", "stopped", "pending", "stopping":
	default:
		return executorEC2Diagnostic{}, fmt.Errorf("EC2 state unavailable")
	}
	return out, nil
}
func (b executorPowerReadBridge) Observe(ctx context.Context, r executoractivity.ExactResource) (executoractivity.PowerSnapshot, error) {
	if r != b.resource {
		return executoractivity.PowerSnapshot{}, fmt.Errorf("foreign power resource")
	}
	if _, err := b.DiagnosticEC2(ctx); err != nil {
		return executoractivity.PowerSnapshot{}, err
	}
	return executoractivity.PowerSnapshot{}, errExecutorPowerObservation
}
func (b executorPowerReadBridge) Execute(context.Context, executoractivity.PowerCommand) error {
	return capacity.ErrPowerLifecycleUnqualified
}
func (b executorPowerReadBridge) Settlement(context.Context, executoractivity.PowerCommand) (executoractivity.PowerSettlement, error) {
	return executoractivity.PowerSettlement{}, capacity.ErrPowerLifecycleUnqualified
}

type executorWorkerReadBridge struct {
	reader   executorAdapterReader
	resource executoractivity.ExactResource
	request  model.AdapterObserveCapacityPodAdmissionRequest
}

type executorNativeDiagnostic struct {
	PodUID, ContainerID, AdmissionState string
	ObservedAt                          time.Time
}

func (b executorWorkerReadBridge) DiagnosticAdmission(ctx context.Context) (executorNativeDiagnostic, error) {
	var out model.AdapterCapacityPodAdmissionResponse
	if b.request.BindingName == "" || b.request.PodName == "" || b.request.ExpectedPodGeneration < 1 || b.request.ExpectedRestartCount < 0 || b.request.ExpectedPodUID == "" || b.request.ExpectedContainerID == "" || b.request.ExpectedContainerStartedAt.IsZero() {
		return executorNativeDiagnostic{}, fmt.Errorf("fixed native worker lifetime required")
	}
	raw, _ := json.Marshal(b.request)
	var input map[string]any
	if err := json.Unmarshal(raw, &input); err != nil {
		return executorNativeDiagnostic{}, err
	}
	r, err := b.reader.read(ctx, capacity.ObserveNativePodAdmission, input)
	if err != nil {
		return executorNativeDiagnostic{}, err
	}
	if capacity.DecodeNativeCapacity(r.Output, &out) != nil || out.Operation != capacity.ObserveNativePodAdmission || out.Status != "observed" || out.Admission.PodUID != b.request.ExpectedPodUID || out.Observation.PodUID != b.request.ExpectedPodUID || out.Observation.PodName != b.request.PodName || out.Observation.BindingName != b.request.BindingName || out.Observation.PodGeneration != b.request.ExpectedPodGeneration || out.Observation.ContainerID != b.request.ExpectedContainerID || out.Observation.StartedAt == nil || !out.Observation.StartedAt.Equal(b.request.ExpectedContainerStartedAt) || out.Observation.RestartCount != b.request.ExpectedRestartCount {
		return executorNativeDiagnostic{}, fmt.Errorf("native worker observation refused")
	}
	return executorNativeDiagnostic{PodUID: out.Observation.PodUID, ContainerID: out.Observation.ContainerID, AdmissionState: out.Admission.State, ObservedAt: out.Admission.ObservedAt}, nil
}
func (b executorWorkerReadBridge) Observe(ctx context.Context, r executoractivity.ExactResource) (executoractivity.WorkerSnapshot, error) {
	if r != b.resource {
		return executoractivity.WorkerSnapshot{}, fmt.Errorf("foreign worker resource")
	}
	if _, err := b.DiagnosticAdmission(ctx); err != nil {
		return executoractivity.WorkerSnapshot{}, err
	}
	// roots_open/process nonce is not EC2 boot or a complete child/job census.
	return executoractivity.WorkerSnapshot{Resource: r, Complete: false, Ready: false}, errExecutorWorkerContract
}
func (b executorWorkerReadBridge) Close(context.Context, executoractivity.ExactResource, uint64) error {
	return errExecutorWorkerContract
}
func (b executorWorkerReadBridge) Open(context.Context, executoractivity.ExactResource, uint64) error {
	return errExecutorWorkerContract
}
func (b executorWorkerReadBridge) Admit(context.Context, executoractivity.ExactResource, string, uint64, string) error {
	return errExecutorWorkerContract
}

var _ executoractivity.PowerPort = executorPowerReadBridge{}
var _ executoractivity.WorkerPort = executorWorkerReadBridge{}
