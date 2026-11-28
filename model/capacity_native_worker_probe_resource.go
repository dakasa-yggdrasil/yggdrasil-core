package model

import (
	"encoding/json"
	"time"
)

const NativeWorkerProbeResourceContextSchema = "native_worker_probe_resource_context_v1"
const NativeWorkerProbeResourceBootstrapSchema = "native_worker_probe_resource_bootstrap_v1"
const NativeWorkerProbeResourcePermitSchema = "native_worker_probe_resource_permit_v1"
const NativeWorkerProbeResourceObservationSchema = "native_worker_probe_resource_observation_v1"
const NativeWorkerProbeRunLabel = "yggdrasil.io/native-worker-probe-run"
const NativeWorkerProbeSlotLabel = "yggdrasil.io/native-worker-probe-slot"
const NativeWorkerProbeAttemptLabel = "yggdrasil.io/native-worker-probe-attempt"
const NativeWorkerProbeAdmissionAnnotation = "yggdrasil.io/native-admission-v2"

// These are the entire public capability input. They select a protected
// journal target, never a manifest, endpoint, UID, credential or native command.
type NativeWorkerProbeResourceInput struct {
	BindingName string `json:"binding_name"`
	RunID       string `json:"run_id"`
	Slot        string `json:"slot"`
}

// This safe identity comes only from the fixed authenticated Core callback.
// Create has empty expected UID/RV; deletion requires its original exact UID/RV.
type NativeWorkerProbeResourceContext struct {
	Schema                  string    `json:"schema"`
	BindingName             string    `json:"binding_name"`
	RunID                   string    `json:"run_id"`
	AttemptID               string    `json:"attempt_id"`
	Slot                    string    `json:"slot"`
	CoreSourceCommit        string    `json:"core_source_commit"`
	SDKSourceCommit         string    `json:"sdk_source_commit"`
	SDKScopeSHA256          string    `json:"sdk_scope_sha256"`
	Namespace               string    `json:"namespace"`
	NamespaceUID            string    `json:"namespace_uid"`
	APIVersion              string    `json:"api_version"`
	Kind                    string    `json:"kind"`
	Name                    string    `json:"name"`
	ExpectedUID             string    `json:"expected_uid"`
	ExpectedResourceVersion string    `json:"expected_resource_version"`
	PublicTemplateSHA256    string    `json:"public_template_sha256"`
	State                   string    `json:"state"`
	NotAfter                time.Time `json:"not_after"`
	Op                      string    `json:"op"`
}

// Private bootstrap is TLS/RAM-only. Generic formatting/JSON cannot expose a
// Secret-bearing object. Only the authenticated callback uses MarshalPrivateJSON.
type NativeWorkerProbeResourceBootstrap struct {
	Schema     string                           `json:"schema"`
	Context    NativeWorkerProbeResourceContext `json:"context"`
	ObjectJSON json.RawMessage                  `json:"object_json"`
}

func (NativeWorkerProbeResourceBootstrap) String() string {
	return "[private Native probe resource bootstrap]"
}
func (b NativeWorkerProbeResourceBootstrap) GoString() string { return b.String() }
func (NativeWorkerProbeResourceBootstrap) MarshalJSON() ([]byte, error) {
	return []byte(`{"private_native_probe_bootstrap":"redacted"}`), nil
}
func (b NativeWorkerProbeResourceBootstrap) MarshalPrivateJSON() ([]byte, error) {
	type wire NativeWorkerProbeResourceBootstrap
	return json.Marshal(wire(b))
}

// The settlement token is 32 random bytes encoded as canonical unpadded base64url
// (43 characters). It is never a workflow input, event or general SDK output.
type NativeWorkerProbeResourcePermit struct {
	Schema          string                           `json:"schema"`
	Context         NativeWorkerProbeResourceContext `json:"context"`
	SettlementToken string                           `json:"settlement_token"`
}

func (NativeWorkerProbeResourcePermit) String() string {
	return "[private Native probe resource permit]"
}
func (p NativeWorkerProbeResourcePermit) GoString() string { return p.String() }
func (NativeWorkerProbeResourcePermit) MarshalJSON() ([]byte, error) {
	return []byte(`{"private_native_probe_permit":"redacted"}`), nil
}
func (p NativeWorkerProbeResourcePermit) MarshalPrivateJSON() ([]byte, error) {
	type wire NativeWorkerProbeResourcePermit
	return json.Marshal(wire(p))
}

// Raw original custody precedes interpretation, event and safe output. A Read,
// Close or cancellation failure preserves its captured prefix and false flag.
type NativeWorkerProbeResourceReceive struct {
	BindingName        string    `json:"binding_name"`
	RunID              string    `json:"run_id"`
	Slot               string    `json:"slot"`
	SettlementToken    string    `json:"settlement_token"`
	HTTPStatus         int       `json:"http_status"`
	CompletedAt        time.Time `json:"completed_at"`
	TransportCompleted bool      `json:"transport_completed"`
	OriginalReturn     []byte    `json:"original_return"`
}

func (NativeWorkerProbeResourceReceive) String() string {
	return "[private Native probe original return]"
}
func (r NativeWorkerProbeResourceReceive) GoString() string { return r.String() }
func (NativeWorkerProbeResourceReceive) MarshalJSON() ([]byte, error) {
	return []byte(`{"private_native_probe_original":"redacted"}`), nil
}
func (r NativeWorkerProbeResourceReceive) MarshalPrivateJSON() ([]byte, error) {
	type wire NativeWorkerProbeResourceReceive
	return json.Marshal(wire(r))
}
