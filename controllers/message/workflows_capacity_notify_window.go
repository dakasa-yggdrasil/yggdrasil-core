package message

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

const originalNotifyWindowMode = "core_original_bound_machine"
const originalNotifyWindowPath = "/internal-runtime/capacity-notify-window"
const originalNotifyWindowControlPath = originalNotifyWindowPath + "/control"
const originalNotifyWindowQuerySHA = "cb805c604ceeffb265368719082a2f9203dabb60fc0406e1378e64e6ba0180f1"
const originalNotifyWindowStatusRounds = 8
const originalNotifyCreationQuerySHA = "ad98fb64cf7fd8f528f53789f5d74cd414ae1548aed9ecf297b90b49b9a62ccd"
const originalNotifyPrivateObservation = "observe_capacity_pod_private_observation"

// Literal typed JSON order/tags mirror the ORIGINAL Notify WindowScope.
// The owning joint gate compares the actual original canonical encoder;
// map-sorted JSON, offset normalization or hash-in-preimage is not its ABI.
type OriginalNotifyWindowScope struct {
	CoreAuthority    *OriginalNotifyCoreBinding  `json:"core_authority,omitempty"`
	NativeRoster     *OriginalNotifyNativeRoster `json:"native_roster,omitempty"`
	TargetDeployment string                      `json:"target_deployment"`
	WindowID         string                      `json:"window_id"`
	Namespace        string                      `json:"namespace"`
	Environment      string                      `json:"environment"`
	Domain           string                      `json:"domain"`
	Dimension        string                      `json:"dimension"`
	PolicyID         string                      `json:"policy_id"`
	PolicyChecksum   string                      `json:"policy_checksum"`
	WorkflowID       string                      `json:"workflow_id"`
	WorkflowVersion  int                         `json:"workflow_version"`
	Generation       int64                       `json:"generation"`
	FencingToken     int64                       `json:"fencing_token"`
	LeaseOwner       string                      `json:"lease_owner"`
	LeaseExecutorID  string                      `json:"lease_executor_id"`
	LeaseExpiresAt   time.Time                   `json:"lease_expires_at"`
	Deadline         time.Time                   `json:"deadline"`
	ProbeCount       int                         `json:"probe_count"`
}

type OriginalNotifyCoreBinding struct {
	WorkflowChecksum   string `json:"workflow_checksum"`
	DispatchJobID      string `json:"dispatch_job_id"`
	DispatchFence      int64  `json:"dispatch_fence"`
	MachinePrincipalID string `json:"machine_principal_id"`
}

type OriginalNotifyNativeRoster struct {
	BindingName  string                         `json:"binding_name"`
	PublisherUID string                         `json:"publisher_pod_uid"`
	ReaderUID    string                         `json:"reader_pod_uid"`
	ConsumerUIDs []string                       `json:"consumer_pod_uids"`
	ManagedPods  []OriginalNotifyNativeIdentity `json:"managed_pods"`
}

type OriginalNotifyNativeIdentity struct {
	PodName          string    `json:"pod_name"`
	PodUID           string    `json:"pod_uid"`
	PodGeneration    int64     `json:"pod_generation"`
	ContainerID      string    `json:"container_id"`
	ContainerStart   time.Time `json:"container_started_at"`
	RestartCount     int32     `json:"restart_count"`
	ProcessNonce     string    `json:"process_nonce"`
	OriginGeneration int64     `json:"origin_generation"`
	ChallengeSHA256  string    `json:"challenge_sha256"`
	ImageDigest      string    `json:"image_digest"`
	LaneRosterSHA256 string    `json:"lane_roster_sha256"`
}

// This callback is installed only by the original RunOne private context.
// Scope input is source-built after current native reads and marker Commit ACK;
// no HTTP/workflow input or metadata can install a guard or mint permission.
type OriginalNotifyAuthorityFactory struct {
	// PrepareScope is PRIVATE source work: it captures the actual dispatch
	// fields/deadline once and performs no control, publication or Register.
	PrepareScope func(context.Context, model.Manifest, model.CapacityPolicySpec, model.CapacityIntent, OriginalNotifyNativeRoster) (OriginalNotifyWindowScope, error)
	// Register may run only after SAMEintent possible-start Commit ACK and
	// independently verifies that exact prepared scope and native marker.
	Register func(context.Context, model.Manifest, model.CapacityPolicySpec, model.CapacityIntent, OriginalNotifyWindowScope) (capacity.OriginalCanaryAuthorityToken, func(), func(context.Context) error, error)
}

func WithOriginalNotifyAuthorityFactory(ctx context.Context, factory OriginalNotifyAuthorityFactory) context.Context {
	if invocation := capacityDispatchInvocationFrom(ctx); invocation != nil {
		invocation.notifyFactory = factory
	}
	return ctx
}

type originalNotifyHTTPHeaders struct {
	coreBearer string
	scopeSHA   string
	controlKey string
	readKey    string
}

func (originalNotifyHTTPHeaders) String() string               { return "private original Notify headers" }
func (originalNotifyHTTPHeaders) GoString() string             { return "private original Notify headers" }
func (originalNotifyHTTPHeaders) MarshalJSON() ([]byte, error) { return []byte("null"), nil }
func (originalNotifyHTTPHeaders) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "private original Notify headers")
}

// One fixed PRODUCT HTTPS request. Original response Read and Close always
// return before acceptance; cancellation is never an early-return channel.
// The native supplier independently binds the actual participant before/after.
// This transport grants no infrastructure operation, readiness or certificate.
func originalNotifyHTTPRequest(parent context.Context, client *http.Client, endpoint, method string, request []byte, headers originalNotifyHTTPHeaders, expectedStatus, limit int) (raw []byte, result error) {
	refuse := func(causes ...error) error {
		return &opaqueAdapterError{public: errCapacityBoundAssessment, cause: errors.Join(append([]error{errCapacityBoundAssessment}, causes...)...)}
	}
	if parent == nil || nativeAdapterContext(parent) != nil || client == nil || limit < 1 || limit > 2<<20 || len(request) > 32<<10 {
		return nil, refuse(nativeAdapterContext(parent))
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || len(endpoint) > 2048 || (method != http.MethodGet && method != http.MethodPost) {
		return nil, refuse(err)
	}
	allowed := (method == http.MethodGet && (u.Path == originalNotifyWindowPath || u.Path == "/capacity/native/canary-authority")) || (method == http.MethodPost && u.Path == originalNotifyWindowControlPath)
	if !allowed || method == http.MethodGet && len(request) != 0 || method == http.MethodPost && len(request) == 0 {
		return nil, refuse()
	}
	owner, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	defer func() {
		if cause := errors.Join(nativeAdapterContext(owner), nativeAdapterContext(parent)); cause != nil {
			raw, result = nil, refuse(result, cause)
		}
	}()
	if strings.ContainsAny(headers.controlKey+headers.readKey, "\r\n\x00") || (u.Path != originalNotifyWindowPath && (!originalNotifySHA(headers.coreBearer) || !originalNotifySHA(headers.scopeSHA))) {
		return nil, refuse()
	}
	if u.Path == "/capacity/native/canary-authority" && (headers.controlKey != "" || headers.readKey != "") {
		return nil, refuse()
	}
	if method == http.MethodPost && (len(headers.controlKey) < 32 || len(headers.controlKey) > 4096 || headers.readKey != "") {
		return nil, refuse()
	}
	if u.Path == originalNotifyWindowPath && (len(headers.readKey) < 32 || len(headers.readKey) > 4096 || headers.controlKey != "" || headers.coreBearer != "" || headers.scopeSHA != "") {
		return nil, refuse()
	}
	req, err := http.NewRequestWithContext(owner, method, endpoint, bytes.NewReader(request))
	if err != nil {
		return nil, refuse(err)
	}
	if headers.coreBearer != "" {
		req.Header.Set("X-Capacity-Core-Authority", headers.coreBearer)
		req.Header.Set("X-Capacity-Participant-Window", headers.scopeSHA)
	}
	if headers.controlKey != "" {
		req.Header.Set("X-Capacity-Window-Control-Key", headers.controlKey)
	}
	if headers.readKey != "" {
		req.Header.Set("X-Capacity-Canary-Read-Key", headers.readKey)
	}
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/json")
	}
	fixedClient := *client
	fixedClient.Jar = nil
	fixedClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if err = errors.Join(nativeAdapterContext(owner), nativeAdapterContext(parent)); err != nil {
		return nil, refuse(err)
	}
	response, callErr := fixedClient.Do(req)
	if response == nil || response.Body == nil {
		return nil, refuse(callErr, nativeAdapterContext(owner), nativeAdapterContext(parent))
	}
	closeOriginal := func(causes ...error) error {
		return errors.Join(append(causes, response.Body.Close(), nativeAdapterContext(owner), nativeAdapterContext(parent))...)
	}
	if callErr != nil {
		return nil, refuse(closeOriginal(callErr))
	}
	if response.StatusCode != expectedStatus || response.TLS == nil || len(response.TLS.VerifiedChains) == 0 || response.Request == nil || response.Request.URL == nil || response.Request.URL.String() != endpoint || response.Request.Method != method {
		// Non200/authority drift must close the original body WITHOUT reading it.
		return nil, refuse(closeOriginal(errors.New("fixed product response refused")))
	}
	raw, readErr := io.ReadAll(io.LimitReader(response.Body, int64(limit)+1))
	joined := closeOriginal(readErr)
	if joined != nil || len(raw) > limit {
		return nil, refuse(joined)
	}
	return bytes.Clone(raw), nil
}

func originalNotifySHA(value string) bool {
	raw, err := hex.DecodeString(value)
	return err == nil && len(raw) == sha256.Size && hex.EncodeToString(raw) == value
}

func originalNotifyDigest(value any) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return capacity.BusinessCreationSHA256(raw), nil
}

func originalNotifyFalseFlags(flags map[string]*bool, names ...string) bool {
	if len(flags) != len(names) {
		return false
	}
	for _, name := range names {
		if value := flags[name]; value == nil || *value {
			return false
		}
	}
	return true
}

func originalNotifyControlAccepted(raw []byte) error {
	var reply struct {
		State  string `json:"state"`
		Lease  *bool  `json:"core_lease_verified"`
		ACK    *bool  `json:"broker_ack_known"`
		RTA    *bool  `json:"RTA_delivery_known"`
		Useful *bool  `json:"useful_all22_known"`
	}
	if capacity.DecodeBusinessJSON(raw, &reply) != nil || reply.State != "accepted" || reply.Lease == nil || *reply.Lease || reply.ACK == nil || *reply.ACK || reply.RTA == nil || *reply.RTA || reply.Useful == nil || *reply.Useful {
		return errCapacityBoundAssessment
	}
	return nil
}

// The initial complete native LIST and actual SDK admission produce identities.
// The operator profile selects names/roles/origins, never UID/nonce/readiness.
func originalNotifyRoster(ctx context.Context, p model.CapacityPolicySpec, call capacityBoundPrivateCall) (OriginalNotifyNativeRoster, error) {
	var result OriginalNotifyNativeRoster
	b := p.NativeNotifyWindowBinding
	if b == nil || p.HPAExecutionBinding == nil || call == nil {
		return result, errCapacityBoundAssessment
	}
	read := func(operation string, value any, out any) error {
		if err := capacityDispatchFence(ctx); err != nil {
			return err
		}
		input, err := boundPrivateMap(value)
		if err != nil {
			return err
		}
		status, err := call(b.Adapter, operation, input, out)
		if joined := errors.Join(err, capacityDispatchFence(ctx)); joined != nil {
			return joined
		}
		if status != "observed" {
			return errCapacityBoundAssessment
		}
		return nil
	}
	inventory := func() (model.AdapterCapacityPodAdmissionCandidatesResponse, error) {
		var out model.AdapterCapacityPodAdmissionCandidatesResponse
		err := read(capacity.ObserveNativePodAdmissionCandidates, map[string]any{"binding_name": b.NativeBindingName}, &out)
		if err != nil || capacity.NativeAdmissionCandidates(p, out, time.Now().UTC()) != nil || out.BindingName != b.NativeBindingName || out.Namespace != b.NativeNamespace || len(out.Unqualified) != 0 || len(out.Candidates) != len(b.Participants) {
			return out, errors.Join(errCapacityBoundAssessment, err)
		}
		return out, nil
	}
	before, err := inventory()
	if err != nil {
		return result, err
	}
	byName := map[string]model.NativeTerminationObservation{}
	for _, pod := range before.Candidates {
		if _, exists := byName[pod.PodName]; exists {
			return result, errCapacityBoundAssessment
		}
		byName[pod.PodName] = pod
	}
	result.BindingName = b.NativeBindingName
	for _, participant := range b.Participants {
		pod, exists := byName[participant.PodName]
		if !exists || pod.StartedAt == nil {
			return result, errCapacityBoundAssessment
		}
		var admission model.AdapterCapacityPodAdmissionResponse
		request := model.AdapterObserveCapacityPodAdmissionRequest{BindingName: b.NativeBindingName, PodName: pod.PodName, ExpectedPodUID: pod.PodUID, ExpectedPodGeneration: pod.PodGeneration, ExpectedContainerID: pod.ContainerID, ExpectedContainerStartedAt: *pod.StartedAt, ExpectedRestartCount: pod.RestartCount}
		if err := read(capacity.ObserveNativePodAdmission, request, &admission); err != nil {
			return result, err
		}
		frame := admission.Admission
		if capacity.NativeProcessAdmission(p, admission, time.Now().UTC()) != nil || frame.State != "roots_open" || frame.Challenge == nil || !admission.Observation.AdmissionReady || !originalNotifyPodSame(pod, admission.Observation) {
			return result, errCapacityBoundAssessment
		}
		identity := OriginalNotifyNativeIdentity{PodName: pod.PodName, PodUID: pod.PodUID, PodGeneration: pod.PodGeneration, ContainerID: pod.ContainerID, ContainerStart: *pod.StartedAt, RestartCount: pod.RestartCount, ProcessNonce: frame.ProcessNonce, OriginGeneration: frame.Challenge.IntentGeneration, ChallengeSHA256: frame.ChallengeSHA256, ImageDigest: frame.ImageDigest, LaneRosterSHA256: frame.LaneRosterSHA256}
		result.ManagedPods = append(result.ManagedPods, identity)
		if participant.Role == "publisher_reader" {
			result.PublisherUID, result.ReaderUID = pod.PodUID, pod.PodUID
		} else {
			result.ConsumerUIDs = append(result.ConsumerUIDs, pod.PodUID)
		}
	}
	after, err := inventory()
	if err != nil || after.WorkloadUID != before.WorkloadUID || after.WorkloadResourceVersion != before.WorkloadResourceVersion {
		return result, errors.Join(errCapacityBoundAssessment, err)
	}
	// The after LIST proves membership and identity only. Its candidates never
	// carry the admission readiness bit; each participant's readiness was
	// already required against its own admission frame above.
	for _, pod := range after.Candidates {
		original, exists := byName[pod.PodName]
		if !exists || !originalNotifyCandidateSame(original, pod) {
			return result, errCapacityBoundAssessment
		}
	}
	sort.Slice(result.ManagedPods, func(i, j int) bool { return result.ManagedPods[i].PodUID < result.ManagedPods[j].PodUID })
	sort.Strings(result.ConsumerUIDs)
	if len(result.ManagedPods) < 2 || len(result.ManagedPods) > 8 || result.PublisherUID == "" || len(result.ConsumerUIDs) != len(result.ManagedPods)-1 {
		return result, errCapacityBoundAssessment
	}
	return result, capacityDispatchFence(ctx)
}

// A membership LIST candidate (observe_capacity_pod_admission_candidates)
// never carries admission readiness; only a single-Pod admission read does.
// Identity and liveness stay exact here, without the readiness bit.
func originalNotifyCandidateSame(a, b model.NativeTerminationObservation) bool {
	return a.PodName == b.PodName && a.PodUID == b.PodUID && a.Namespace == b.Namespace && a.PodGeneration == b.PodGeneration && a.ContainerID == b.ContainerID && a.StartedAt != nil && b.StartedAt != nil && a.StartedAt.Equal(*b.StartedAt) && a.RestartCount == b.RestartCount && a.ImageDigest == b.ImageDigest && a.WorkloadUID == b.WorkloadUID && a.WorkloadResourceVersion == b.WorkloadResourceVersion && b.ContainerState == "running" && b.DeletionRequestedAt == nil && b.Protected
}

// The comparison against an admission frame keeps requiring its readiness.
func originalNotifyPodSame(a, b model.NativeTerminationObservation) bool {
	return originalNotifyCandidateSame(a, b) && b.AdmissionReady
}

func originalNotifySameRoster(a, b OriginalNotifyNativeRoster) bool {
	x, err := json.Marshal(a)
	y, other := json.Marshal(b)
	return err == nil && other == nil && bytes.Equal(x, y)
}

type originalNotifyRosterRead struct {
	InventoryBefore json.RawMessage   `json:"inventory_before"`
	Admissions      []json.RawMessage `json:"admissions"`
	InventoryAfter  json.RawMessage   `json:"inventory_after"`
}

type originalNotifyWindowReply struct {
	PoolPrerequisites   []originalNotifyPoolPrerequisite        `json:"native_pool_prerequisites,omitempty"`
	ParticipantReads    []json.RawMessage                       `json:"native_participant_reads,omitempty"`
	NativeRosterRead    *originalNotifyRosterRead               `json:"native_roster_read,omitempty"`
	Query               string                                  `json:"query_sha256"`
	AtomicSnapshot      *bool                                   `json:"atomic_snapshot"`
	Schema              string                                  `json:"schema_version"`
	Source              string                                  `json:"source_commit"`
	Scope               OriginalNotifyWindowScope               `json:"declared_scope"`
	Counter             int64                                   `json:"admission_counter"`
	ProducerReturned    *bool                                   `json:"producer_return_received"`
	Sealed              *bool                                   `json:"sealed"`
	Hold                *bool                                   `json:"hold"`
	CoreLeaseVerified   *bool                                   `json:"core_lease_verified"`
	BrokerCallbackKnown *bool                                   `json:"broker_callback_return_known"`
	BrokerACKKnown      *bool                                   `json:"broker_ack_known"`
	RTADeliveryKnown    *bool                                   `json:"RTA_delivery_known"`
	UsefulAll22Known    *bool                                   `json:"useful_all22_known"`
	PreparationBefore   model.NativeProcessAdmissionObservation `json:"preparation_before"`
	NativeRaw           []byte                                  `json:"native_snapshot_base64"`
	OriginalCreations   []model.CapacityBusinessCreationReply   `json:"original_creations"`
	PreparationAfter    model.NativeProcessAdmissionObservation `json:"preparation_after"`
}

type originalNotifyParticipantCall struct {
	MessageSHA                  string `json:"message_sha256"`
	BusinessReturnReceived      *bool  `json:"business_return_received"`
	BusinessReturnNil           *bool  `json:"business_return_nil"`
	ReceiptStoreReturnReceived  *bool  `json:"receipt_store_return_received"`
	ReceiptStoreReturnNil       *bool  `json:"receipt_store_return_nil"`
	FinalMarkerReturnReceived   *bool  `json:"final_marker_return_received"`
	FinalMarkerReturnNil        *bool  `json:"final_marker_return_nil"`
	OriginalOwnerReturnReceived *bool  `json:"original_owner_return_received"`
	OriginalOwnerReturnNil      *bool  `json:"original_owner_return_nil"`
	OriginalCauseFree           *bool  `json:"original_cause_free"`
}

type originalNotifyParticipantReply struct {
	PoolPrerequisites   []originalNotifyPoolPrerequisite        `json:"native_pool_prerequisites,omitempty"`
	Schema              string                                  `json:"schema_version"`
	Source              string                                  `json:"source_commit"`
	Query               string                                  `json:"query_sha256"`
	WindowSHA           string                                  `json:"window_sha256"`
	Scope               OriginalNotifyWindowScope               `json:"declared_scope"`
	Counter             int64                                   `json:"admission_counter"`
	Hold                *bool                                   `json:"hold"`
	CoreLeaseVerified   *bool                                   `json:"core_lease_verified"`
	BrokerCallbackKnown *bool                                   `json:"broker_callback_return_known"`
	BrokerACKKnown      *bool                                   `json:"broker_ack_known"`
	RTADeliveryKnown    *bool                                   `json:"RTA_delivery_known"`
	UsefulAll22Known    *bool                                   `json:"useful_all22_known"`
	PreparationBefore   model.NativeProcessAdmissionObservation `json:"preparation_before"`
	NativeRaw           []byte                                  `json:"native_snapshot_base64"`
	Calls               []originalNotifyParticipantCall         `json:"participant_calls"`
	PreparationAfter    model.NativeProcessAdmissionObservation `json:"preparation_after"`
}

type originalNotifyPrivateReply struct {
	Schema          string                                  `json:"schema_version"`
	Operation       string                                  `json:"operation"`
	Status          string                                  `json:"status"`
	Binding         string                                  `json:"binding_name"`
	Selector        string                                  `json:"selector_sha256"`
	PodBefore       originalNotifyPrivatePod                `json:"pod_before"`
	AdmissionBefore model.NativeProcessAdmissionObservation `json:"admission_before"`
	Body            []byte                                  `json:"body_base64"`
	BodySHA         string                                  `json:"body_sha256"`
	BodyBytes       int                                     `json:"body_bytes"`
	PodAfter        originalNotifyPrivatePod                `json:"pod_after"`
	AdmissionAfter  model.NativeProcessAdmissionObservation `json:"admission_after"`
	ObservedAt      time.Time                               `json:"observed_at"`
	Metadata        map[string]*bool                        `json:"metadata"`
}

// The standalone private Pod projection does not measure readiness. Retain
// its concrete FALSE wire member independently from the public ready-roster
// predicate. Missing/null is not a known default; no projection is rewritten.
type originalNotifyPrivatePod struct {
	model.NativeTerminationObservation
	AdmissionReady *bool `json:"admission_ready"`
}

func originalNotifyPrivateFrame(p model.CapacityPolicySpec, identity OriginalNotifyNativeIdentity, pod originalNotifyPrivatePod, frame model.NativeProcessAdmissionObservation) bool {
	if pod.AdmissionReady == nil || *pod.AdmissionReady {
		return false
	}
	original := pod.NativeTerminationObservation
	response := model.AdapterCapacityPodAdmissionResponse{Operation: capacity.ObserveNativePodAdmission, Status: "observed", Observation: original, Admission: frame}
	return capacity.NativeProcessAdmission(p, response, time.Now().UTC()) == nil && frame.State == "roots_open" && frame.Challenge != nil && frame.Challenge.IntentGeneration == identity.OriginGeneration && frame.ChallengeSHA256 == identity.ChallengeSHA256 && frame.ProcessNonce == identity.ProcessNonce && frame.LaneRosterSHA256 == identity.LaneRosterSHA256 && original.PodUID == identity.PodUID && original.PodName == identity.PodName && original.PodGeneration == identity.PodGeneration && original.ContainerID == identity.ContainerID && original.StartedAt != nil && original.StartedAt.Equal(identity.ContainerStart) && original.RestartCount == identity.RestartCount && original.ImageDigest == identity.ImageDigest && original.FinishedAt == nil && original.ExitCode == nil && original.Signal == nil && original.Receipt == nil && original.ReceiptSHA256 == ""
}

func originalNotifyPrivatePodSame(a, b originalNotifyPrivatePod) bool {
	return originalNotifyFalse(a.AdmissionReady, b.AdmissionReady) && a.PodName == b.PodName && a.PodUID == b.PodUID && a.Namespace == b.Namespace && a.PodGeneration == b.PodGeneration && a.ContainerID == b.ContainerID && a.StartedAt != nil && b.StartedAt != nil && a.StartedAt.Equal(*b.StartedAt) && a.RestartCount == b.RestartCount && a.ImageDigest == b.ImageDigest && a.WorkloadUID == b.WorkloadUID && a.WorkloadResourceVersion == b.WorkloadResourceVersion && a.PodResourceVersion == b.PodResourceVersion && b.ContainerState == "running" && b.State == "running" && b.DeletionRequestedAt == nil && b.Protected
}

func originalNotifyTrue(values ...*bool) bool {
	for _, value := range values {
		if value == nil || !*value {
			return false
		}
	}
	return true
}
func originalNotifyFalse(values ...*bool) bool {
	for _, value := range values {
		if value == nil || *value {
			return false
		}
	}
	return true
}

func originalNotifyScopeSame(a, b OriginalNotifyWindowScope) bool {
	x, e := json.Marshal(a)
	y, f := json.Marshal(b)
	return e == nil && f == nil && bytes.Equal(x, y)
}

func originalNotifyIdentity(roster OriginalNotifyNativeRoster, uid string) (OriginalNotifyNativeIdentity, bool) {
	for _, p := range roster.ManagedPods {
		if p.PodUID == uid {
			return p, true
		}
	}
	return OriginalNotifyNativeIdentity{}, false
}

func originalNotifyFrame(p model.CapacityPolicySpec, identity OriginalNotifyNativeIdentity, pod model.NativeTerminationObservation, frame model.NativeProcessAdmissionObservation) bool {
	response := model.AdapterCapacityPodAdmissionResponse{Operation: capacity.ObserveNativePodAdmission, Status: "observed", Observation: pod, Admission: frame}
	return capacity.NativeProcessAdmission(p, response, time.Now().UTC()) == nil && frame.State == "roots_open" && frame.Challenge != nil && frame.Challenge.IntentGeneration == identity.OriginGeneration && frame.ChallengeSHA256 == identity.ChallengeSHA256 && frame.ProcessNonce == identity.ProcessNonce && frame.LaneRosterSHA256 == identity.LaneRosterSHA256 && pod.PodUID == identity.PodUID && pod.PodName == identity.PodName && pod.PodGeneration == identity.PodGeneration && pod.ContainerID == identity.ContainerID && pod.StartedAt != nil && pod.StartedAt.Equal(identity.ContainerStart) && pod.RestartCount == identity.RestartCount && pod.ImageDigest == identity.ImageDigest && pod.AdmissionReady
}

// The original rolling producer supplies native SQL bytes, not a useful flag.
// Repeat independent SDK reads around the HTTP result; retain complete native
// roster witnesses rather than accepting the reported reader's name alone.
func originalNotifyRosterWitness(p model.CapacityPolicySpec, roster OriginalNotifyNativeRoster, raw *originalNotifyRosterRead) (map[string]model.AdapterCapacityPodAdmissionResponse, error) {
	result := map[string]model.AdapterCapacityPodAdmissionResponse{}
	if raw == nil || len(raw.Admissions) != len(roster.ManagedPods) {
		return result, errCapacityBoundAssessment
	}
	for _, snapshot := range []json.RawMessage{raw.InventoryBefore, raw.InventoryAfter} {
		var inv model.AdapterCapacityPodAdmissionCandidatesResponse
		if capacity.DecodeNativeCapacity(snapshot, &inv) != nil || capacity.NativeAdmissionCandidates(p, inv, time.Now().UTC()) != nil || len(inv.Unqualified) != 0 || len(inv.Candidates) != len(roster.ManagedPods) {
			return result, errCapacityBoundAssessment
		}
		seen := map[string]bool{}
		for _, pod := range inv.Candidates {
			identity, ok := originalNotifyIdentity(roster, pod.PodUID)
			if !ok || seen[pod.PodUID] || pod.PodName != identity.PodName || pod.PodGeneration != identity.PodGeneration || pod.ContainerID != identity.ContainerID || pod.StartedAt == nil || !pod.StartedAt.Equal(identity.ContainerStart) || pod.RestartCount != identity.RestartCount || pod.ImageDigest != identity.ImageDigest {
				return result, errCapacityBoundAssessment
			}
			seen[pod.PodUID] = true
		}
	}
	for _, snapshot := range raw.Admissions {
		var response model.AdapterCapacityPodAdmissionResponse
		if capacity.DecodeNativeCapacity(snapshot, &response) != nil {
			return result, errCapacityBoundAssessment
		}
		identity, ok := originalNotifyIdentity(roster, response.Observation.PodUID)
		if !ok || result[identity.PodUID].Operation != "" || !originalNotifyFrame(p, identity, response.Observation, response.Admission) {
			return result, errCapacityBoundAssessment
		}
		result[identity.PodUID] = response
	}
	return result, nil
}

type originalNotifySQLWindow struct {
	WindowSHA   string                    `json:"window_sha256"`
	Namespace   string                    `json:"namespace"`
	Environment string                    `json:"environment"`
	Domain      string                    `json:"domain"`
	Dimension   string                    `json:"dimension"`
	Counter     int64                     `json:"admission_counter"`
	Deployment  string                    `json:"target_deployment"`
	Source      string                    `json:"source_commit"`
	Scope       OriginalNotifyWindowScope `json:"declared_scope"`
	ProbeCount  int                       `json:"probe_count"`
	ExpiresAt   time.Time                 `json:"expires_at"`
}
type originalNotifySQLFence struct {
	Namespace   string `json:"namespace"`
	Environment string `json:"environment"`
	Domain      string `json:"domain"`
	Dimension   string `json:"dimension"`
	Generation  int64  `json:"generation"`
	Fencing     int64  `json:"fencing_token"`
	Counter     int64  `json:"admission_counter"`
	Unresolved  *bool  `json:"unresolved"`
	Erasure     *bool  `json:"erasure_unknown"`
}
type originalNotifySQLProbe struct {
	Message        string `json:"message_sha256"`
	WindowSHA      string `json:"window_sha256"`
	Ordinal        int    `json:"ordinal"`
	AttemptNonce   string `json:"attempt_nonce"`
	RequestBodySHA string `json:"request_body_sha256"`
	NativeBodySHA  string `json:"native_body_sha256"`
	BodyBytes      int    `json:"native_body_bytes"`
	Recipients     string `json:"recipient_sha256"`
	PodUID         string `json:"producer_pod_uid"`
	Process        string `json:"producer_process_nonce"`
	Origin         int64  `json:"producer_origin_generation"`
}
type originalNotifySQLCall struct {
	Message   string  `json:"message_sha256"`
	Operation string  `json:"operation"`
	PodUID    string  `json:"pod_uid"`
	Process   string  `json:"process_nonce"`
	Origin    int64   `json:"origin_generation"`
	Outcome   string  `json:"outcome"`
	XID       *string `json:"original_xid"`
	Elapsed   int64   `json:"elapsed_ns"`
}
type originalNotifySQLCensus struct {
	Window     *originalNotifySQLWindow `json:"window"`
	Fence      *originalNotifySQLFence  `json:"scope_fence"`
	Probes     []originalNotifySQLProbe `json:"probes"`
	Calls      []originalNotifySQLCall  `json:"calls"`
	ObservedAt time.Time                `json:"observed_at"`
}

func originalNotifyCensus(raw []byte, scope OriginalNotifyWindowScope, source, scopeSHA string, counter int64) (originalNotifySQLCensus, error) {
	var c originalNotifySQLCensus
	if capacity.DecodeBusinessJSON(raw, &c) != nil || c.Window == nil || c.Fence == nil || c.ObservedAt.IsZero() {
		return c, errCapacityBoundAssessment
	}
	w, f := c.Window, c.Fence
	if w.WindowSHA != scopeSHA || w.Source != source || w.ProbeCount != 1 || w.Counter != counter || !originalNotifyScopeSame(w.Scope, scope) || !w.ExpiresAt.Equal(scope.Deadline.Round(time.Microsecond)) || w.Namespace != scope.Namespace || w.Environment != scope.Environment || w.Domain != scope.Domain || w.Dimension != scope.Dimension || w.Deployment != scope.TargetDeployment || f.Namespace != scope.Namespace || f.Environment != scope.Environment || f.Domain != scope.Domain || f.Dimension != scope.Dimension || f.Generation != scope.Generation || f.Fencing != scope.FencingToken || f.Counter != counter || f.Unresolved == nil || !originalNotifyFalse(f.Erasure) || len(c.Probes) != 1 || len(c.Calls) > 5 {
		return c, errCapacityBoundAssessment
	}
	probe := c.Probes[0]
	if probe.WindowSHA != scopeSHA || probe.Ordinal != 1 || !capacity.NativeProcessNonce(probe.AttemptNonce) || !originalNotifySHA(probe.Message) || !originalNotifySHA(probe.RequestBodySHA) || !originalNotifySHA(probe.NativeBodySHA) || !originalNotifySHA(probe.Recipients) || probe.BodyBytes < 1 || probe.BodyBytes > 64<<10 || scope.NativeRoster == nil || probe.PodUID != scope.NativeRoster.PublisherUID {
		return c, errCapacityBoundAssessment
	}
	producer, ok := originalNotifyIdentity(*scope.NativeRoster, probe.PodUID)
	if !ok || producer.ProcessNonce != probe.Process || producer.OriginGeneration != probe.Origin {
		return c, errCapacityBoundAssessment
	}
	return c, nil
}

func originalNotifyCalls(c originalNotifySQLCensus, roster OriginalNotifyNativeRoster) (map[string]originalNotifySQLCall, error) {
	result := map[string]originalNotifySQLCall{}
	if len(c.Probes) != 1 || len(c.Calls) != 5 {
		return result, errCapacityBoundAssessment
	}
	for _, call := range c.Calls {
		identity, ok := originalNotifyIdentity(roster, call.PodUID)
		if !ok || call.Message != c.Probes[0].Message || call.Process != identity.ProcessNonce || call.Origin != identity.OriginGeneration || call.Elapsed < 0 || result[call.Operation].Operation != "" {
			return result, errCapacityBoundAssessment
		}
		switch call.Operation {
		case "publisher_call_started", "publisher_call_received":
			if call.PodUID != roster.PublisherUID {
				return result, errCapacityBoundAssessment
			}
		case "handler_call_started", "handler_call_received", "handler_receipt_store_return_received":
			if !sort.StringsAreSorted(roster.ConsumerUIDs) {
				return result, errCapacityBoundAssessment
			}
			index := sort.SearchStrings(roster.ConsumerUIDs, call.PodUID)
			if index == len(roster.ConsumerUIDs) || roster.ConsumerUIDs[index] != call.PodUID {
				return result, errCapacityBoundAssessment
			}
		default:
			return result, errCapacityBoundAssessment
		}
		if strings.HasSuffix(call.Operation, "started") {
			if call.Outcome != "started" {
				return result, errCapacityBoundAssessment
			}
		} else if call.Outcome != "nil" || call.XID == nil || *call.XID == "" {
			return result, errCapacityBoundAssessment
		}
		result[call.Operation] = call
	}
	for _, name := range []string{"publisher_call_started", "publisher_call_received", "handler_call_started", "handler_call_received", "handler_receipt_store_return_received"} {
		if result[name].Operation != name {
			return result, errCapacityBoundAssessment
		}
	}
	handler, received, marker := result["handler_call_started"], result["handler_call_received"], result["handler_receipt_store_return_received"]
	if handler.PodUID != received.PodUID || handler.Process != received.Process || handler.Origin != received.Origin || marker.PodUID != received.PodUID || marker.Process != received.Process || marker.Origin != received.Origin || *marker.XID != *received.XID || *result["publisher_call_received"].XID == *received.XID {
		return result, errCapacityBoundAssessment
	}
	return result, nil
}

// Original raw creation belongs to READER A; it is never rewritten into a
// consumer B admission envelope. Its SAME original business XID is joined to
// B's independently observed current process and actual return registry.
type originalNotifyCreationSnapshot struct {
	Schema          string    `json:"schema_version"`
	Database        string    `json:"database"`
	DatabaseOID     string    `json:"database_oid"`
	SystemID        string    `json:"system_identifier"`
	Recovery        *bool     `json:"in_recovery"`
	Track           string    `json:"track_commit_timestamp"`
	WitnessOID      string    `json:"witness_oid"`
	InboxOID        string    `json:"inbox_oid"`
	NotificationOID string    `json:"notification_oid"`
	StateOID        string    `json:"state_oid"`
	Observed        time.Time `json:"observed_at"`
	Witness         *struct {
		MessageSHA     string     `json:"message_sha256"`
		BodySHA        string     `json:"raw_body_sha256"`
		Source         string     `json:"source_commit"`
		Namespace      string     `json:"consumer_namespace"`
		PodUID         string     `json:"consumer_pod_uid"`
		Process        string     `json:"consumer_process_nonce"`
		BackendPID     int        `json:"backend_pid"`
		BackendStart   time.Time  `json:"backend_start"`
		XID            string     `json:"original_xid"`
		Recipients     string     `json:"recipient_sha256"`
		RecipientCount int        `json:"recipient_count"`
		Xmin           string     `json:"xmin"`
		Commit         *time.Time `json:"commit_at"`
	} `json:"witness"`
	Inbox *struct {
		ID     string     `json:"message_id"`
		Xmin   string     `json:"xmin"`
		Commit *time.Time `json:"commit_at"`
	} `json:"inbox"`
	Notifications []struct {
		ID     string     `json:"id"`
		Users  []string   `json:"user_ids"`
		Dedupe string     `json:"dedupe_key"`
		Xmin   string     `json:"xmin"`
		Commit *time.Time `json:"commit_at"`
		States []struct {
			NotificationID string     `json:"notification_id"`
			User           string     `json:"user_id"`
			OpenedAt       *time.Time `json:"opened_at"`
			Xmin           string     `json:"xmin"`
			Commit         *time.Time `json:"commit_at"`
		} `json:"states"`
	} `json:"notifications"`
}

func originalNotifyCreation(p model.CapacityPolicySpec, scope OriginalNotifyWindowScope, source string, c originalNotifySQLCensus, calls map[string]originalNotifySQLCall, creation model.CapacityBusinessCreationReply, admissions map[string]model.AdapterCapacityPodAdmissionResponse) error {
	call := calls["handler_call_received"]
	actor, ok := admissions[call.PodUID]
	reader, readerKnown := admissions[scope.NativeRoster.ReaderUID]
	readerIdentity, identityKnown := originalNotifyIdentity(*scope.NativeRoster, scope.NativeRoster.ReaderUID)
	if !ok || !readerKnown || !identityKnown || actor.Admission.ProcessNonce != call.Process || creation.Schema != "notify_capacity_creation_canary_response_v1" || creation.Source != source || creation.Query != originalNotifyCreationQuerySHA || !originalNotifyFrame(p, readerIdentity, reader.Observation, creation.PreparationBefore) || !originalNotifyFrame(p, readerIdentity, reader.Observation, creation.PreparationAfter) {
		return errCapacityBoundAssessment
	}
	var native originalNotifyCreationSnapshot
	if capacity.DecodeBusinessJSON(creation.NativeRaw, &native) != nil || native.Schema != "notify_capacity_creation_canary_read_v1" || native.Database == "" || native.DatabaseOID == "" || native.SystemID == "" || !originalNotifyFalse(native.Recovery) || native.Track != "on" || native.Observed.IsZero() || native.Witness == nil || native.Inbox == nil || len(native.Notifications) != 1 {
		return errCapacityBoundAssessment
	}
	seenOID := map[string]bool{}
	if !originalNotifyDecimal(native.DatabaseOID, 32) {
		return errCapacityBoundAssessment
	}
	for _, oid := range []string{native.WitnessOID, native.InboxOID, native.NotificationOID, native.StateOID} {
		if !originalNotifyDecimal(oid, 32) || seenOID[oid] {
			return errCapacityBoundAssessment
		}
		seenOID[oid] = true
	}
	if !originalNotifyDecimal(native.SystemID, 64) {
		return errCapacityBoundAssessment
	}
	w, inbox, n := native.Witness, native.Inbox, native.Notifications[0]
	probe := c.Probes[0]
	declared, _ := json.Marshal(scope)
	id := "capacity-window:" + capacity.BusinessCreationSHA256(append(bytes.Clone(declared), []byte(fmt.Sprintf("/%d/1", c.Window.Counter))...))
	if call.XID == nil || w.XID != *call.XID || !originalNotifyDecimal(w.XID, 32) || w.Commit == nil || w.Commit.IsZero() || w.Commit.After(native.Observed) || native.Observed.Sub(*w.Commit) > time.Duration(p.MaxEvidenceAgeSeconds)*time.Second || w.BackendPID < 1 || w.BackendStart.IsZero() || w.BackendStart.After(*w.Commit) {
		return errCapacityBoundAssessment
	}
	commit := func(xid string, at *time.Time) bool { return xid == w.XID && at != nil && at.Equal(*w.Commit) }
	if inbox.ID != id || w.MessageSHA != probe.Message || capacity.BusinessCreationSHA256([]byte(inbox.ID)) != probe.Message || w.BodySHA != probe.NativeBodySHA || w.Source != source || w.Namespace != p.NativeNotifyWindowBinding.NativeNamespace || w.PodUID != call.PodUID || w.Process != call.Process || w.Recipients != probe.Recipients || w.RecipientCount != 2 || !commit(w.Xmin, w.Commit) || !commit(inbox.Xmin, inbox.Commit) || n.Dedupe != inbox.ID || !capacity.NativeProcessNonce(n.ID) || !commit(n.Xmin, n.Commit) || len(n.Users) != 2 || len(n.States) != 2 || capacity.BusinessRecipientSHA256(n.Users) != probe.Recipients {
		return errCapacityBoundAssessment
	}
	if !capacity.NativeProcessNonce(n.Users[0]) || !capacity.NativeProcessNonce(n.Users[1]) || n.Users[0] == n.Users[1] {
		return errCapacityBoundAssessment
	}
	seenUsers := map[string]bool{}
	for _, state := range n.States {
		if seenUsers[state.User] || (state.User != n.Users[0] && state.User != n.Users[1]) || state.NotificationID != n.ID || !commit(state.Xmin, state.Commit) {
			return errCapacityBoundAssessment
		}
		seenUsers[state.User] = true
	}
	return nil
}

func originalNotifyDecimal(value string, bits int) bool {
	n, err := strconv.ParseUint(value, 10, bits)
	return err == nil && n > 0 && strconv.FormatUint(n, 10) == value
}

func originalNotifyParticipant(p model.CapacityPolicySpec, scope OriginalNotifyWindowScope, scopeSHA string, counter int64, census originalNotifySQLCensus, calls map[string]originalNotifySQLCall, raw originalNotifyPrivateReply) error {
	b := p.NativeNotifyWindowBinding
	identity, known := originalNotifyIdentity(*scope.NativeRoster, raw.PodBefore.PodUID)
	if !known || raw.Schema != "pod_private_observation_v1" || raw.Operation != originalNotifyPrivateObservation || raw.Status != "observed" || raw.Binding != b.PrivateBindingName || raw.Selector != scopeSHA || len(raw.Body) == 0 || len(raw.Body) > 1<<20 || raw.BodyBytes != len(raw.Body) || raw.BodySHA != capacity.BusinessCreationSHA256(raw.Body) || !capacity.Fresh(raw.ObservedAt, time.Now().UTC(), p.MaxEvidenceAgeSeconds) || !originalNotifyFalseFlags(raw.Metadata, "snapshot_atomic", "business_return_known", "broker_ack_known", "broker_callback_return_known", "core_lease_verified", "useful_capacity_known", "warm_resources_known", "physical_capacity_released") || !originalNotifyPrivateFrame(p, identity, raw.PodBefore, raw.AdmissionBefore) || !originalNotifyPrivateFrame(p, identity, raw.PodAfter, raw.AdmissionAfter) || !originalNotifyPrivatePodSame(raw.PodBefore, raw.PodAfter) {
		return errCapacityBoundAssessment
	}
	var status originalNotifyParticipantReply
	if capacity.DecodeBusinessJSON(raw.Body, &status) != nil || status.Schema != "notify_capacity_participant_original_status_v1" || status.Source != b.SourceCommit || status.Query != originalNotifyWindowQuerySHA || status.WindowSHA != scopeSHA || status.Counter != counter || !originalNotifyScopeSame(status.Scope, scope) || !originalNotifyFalse(status.Hold, status.CoreLeaseVerified, status.BrokerCallbackKnown, status.BrokerACKKnown, status.RTADeliveryKnown, status.UsefulAll22Known) || !originalNotifyPrivateFrame(p, identity, raw.PodBefore, status.PreparationBefore) || !originalNotifyPrivateFrame(p, identity, raw.PodAfter, status.PreparationAfter) {
		return errCapacityBoundAssessment
	}
	other, err := originalNotifyCensus(status.NativeRaw, scope, b.SourceCommit, scopeSHA, counter)
	if err != nil {
		return err
	}
	otherCalls, err := originalNotifyCalls(other, *scope.NativeRoster)
	if err != nil {
		return err
	}
	for name, call := range calls {
		a, e := json.Marshal(otherCalls[name])
		z, f := json.Marshal(call)
		if e != nil || f != nil || !bytes.Equal(a, z) {
			return errCapacityBoundAssessment
		}
	}
	if len(other.Probes) != len(census.Probes) || other.Probes[0] != census.Probes[0] {
		return errCapacityBoundAssessment
	}
	if err = originalNotifyPoolRoster(p, scope, scopeSHA, census.Probes[0].Message, identity, status.PoolPrerequisites); err != nil {
		return err
	}
	if identity.PodUID != calls["handler_call_received"].PodUID {
		if len(status.Calls) != 0 {
			return errCapacityBoundAssessment
		}
		return nil
	}
	if len(status.Calls) != 1 || status.Calls[0].MessageSHA != census.Probes[0].Message {
		return errCapacityBoundAssessment
	}
	call := status.Calls[0]
	if !originalNotifyTrue(call.BusinessReturnReceived, call.BusinessReturnNil, call.ReceiptStoreReturnReceived, call.ReceiptStoreReturnNil, call.FinalMarkerReturnReceived, call.FinalMarkerReturnNil, call.OriginalOwnerReturnReceived, call.OriginalOwnerReturnNil, call.OriginalCauseFree) {
		return errCapacityBoundAssessment
	}
	return nil
}

func originalNotifyReadComplete(ctx context.Context, p model.CapacityPolicySpec, scope OriginalNotifyWindowScope, scopeSHA string, raw []byte, call capacityBoundPrivateCall) (bool, error) {
	b := p.NativeNotifyWindowBinding
	var reply originalNotifyWindowReply
	if capacity.DecodeBusinessJSON(raw, &reply) != nil || reply.Schema != "notify_capacity_private_window_read_v2" || reply.Source != b.SourceCommit || reply.Query != originalNotifyWindowQuerySHA || !originalNotifyScopeSame(reply.Scope, scope) || reply.Counter < 1 || reply.ProducerReturned == nil || reply.Sealed == nil || reply.Hold == nil || !originalNotifyFalse(reply.AtomicSnapshot, reply.CoreLeaseVerified, reply.BrokerCallbackKnown, reply.BrokerACKKnown, reply.RTADeliveryKnown, reply.UsefulAll22Known) {
		return false, errCapacityBoundAssessment
	}
	if *reply.Hold || !*reply.ProducerReturned {
		return false, capacityDispatchFence(ctx)
	}
	admissions, err := originalNotifyRosterWitness(p, *scope.NativeRoster, reply.NativeRosterRead)
	if err != nil {
		return false, err
	}
	reader, ok := admissions[scope.NativeRoster.ReaderUID]
	identity, _ := originalNotifyIdentity(*scope.NativeRoster, scope.NativeRoster.ReaderUID)
	if !ok || !originalNotifyFrame(p, identity, reader.Observation, reply.PreparationBefore) || !originalNotifyFrame(p, identity, reader.Observation, reply.PreparationAfter) {
		return false, errCapacityBoundAssessment
	}
	census, err := originalNotifyCensus(reply.NativeRaw, scope, b.SourceCommit, scopeSHA, reply.Counter)
	if err != nil {
		return false, err
	}
	calls, err := originalNotifyCalls(census, *scope.NativeRoster)
	if err != nil || len(reply.OriginalCreations) != 1 || len(reply.ParticipantReads) != len(scope.NativeRoster.ConsumerUIDs) {
		return false, errors.Join(errCapacityBoundAssessment, err)
	}
	if err = originalNotifyCreation(p, scope, b.SourceCommit, census, calls, reply.OriginalCreations[0], admissions); err != nil {
		return false, err
	}
	if err = originalNotifyPoolRoster(p, scope, scopeSHA, census.Probes[0].Message, identity, reply.PoolPrerequisites); err != nil {
		return false, err
	}
	seen := map[string]bool{}
	for _, retained := range reply.ParticipantReads {
		var out originalNotifyPrivateReply
		// RawMessage retains literal JSON. []byte would become base64 in the
		// original DecodeNativeCapacity encoder and is not its wire contract.
		if capacity.DecodeNativeCapacity(retained, &out) != nil || seen[out.PodBefore.PodUID] {
			return false, errCapacityBoundAssessment
		}
		uid := out.PodBefore.PodUID
		index := sort.SearchStrings(scope.NativeRoster.ConsumerUIDs, uid)
		if index == len(scope.NativeRoster.ConsumerUIDs) || scope.NativeRoster.ConsumerUIDs[index] != uid || originalNotifyParticipant(p, scope, scopeSHA, reply.Counter, census, calls, out) != nil {
			return false, errCapacityBoundAssessment
		}
		seen[uid] = true
	}
	// GET-only independent original supplier reads; no body or marker is
	// caller proof, and replacing a participant cannot inherit a known return.
	for _, uid := range scope.NativeRoster.ConsumerUIDs {
		identity, _ := originalNotifyIdentity(*scope.NativeRoster, uid)
		input := map[string]any{"binding_name": b.PrivateBindingName, "pod_name": identity.PodName, "expected_pod_uid": identity.PodUID, "expected_pod_generation": identity.PodGeneration, "expected_container_id": identity.ContainerID, "expected_container_started_at": identity.ContainerStart, "expected_restart_count": identity.RestartCount, "expected_process_nonce": identity.ProcessNonce, "selector_sha256": scopeSHA}
		if err = capacityDispatchFence(ctx); err != nil {
			return false, err
		}
		var out originalNotifyPrivateReply
		status, readErr := call(b.Adapter, originalNotifyPrivateObservation, input, &out)
		if joined := errors.Join(readErr, capacityDispatchFence(ctx)); joined != nil {
			return false, joined
		}
		if status != "observed" || originalNotifyParticipant(p, scope, scopeSHA, reply.Counter, census, calls, out) != nil {
			return false, errCapacityBoundAssessment
		}
	}
	fresh, err := originalNotifyRoster(ctx, p, call)
	if err != nil || !originalNotifySameRoster(fresh, *scope.NativeRoster) {
		return false, errors.Join(errCapacityBoundAssessment, err)
	}
	return true, capacityDispatchFence(ctx)
}

func originalNotifyAuthorityAccepted(raw []byte, scope OriginalNotifyWindowScope, scopeSHA string, started time.Time) error {
	var reply capacity.OriginalCanaryAuthorityReply
	b := scope.CoreAuthority
	if b == nil || capacity.DecodeBusinessJSON(raw, &reply) != nil {
		return errCapacityBoundAssessment
	}
	expected := capacity.OriginalCanaryAuthorityScope{WindowID: scope.WindowID, ScopeSHA256: scopeSHA, PolicyID: scope.PolicyID, PolicyChecksum: scope.PolicyChecksum, WorkflowID: scope.WorkflowID, WorkflowChecksum: b.WorkflowChecksum, DispatchJobID: b.DispatchJobID, DispatchFence: b.DispatchFence, IntentGeneration: scope.Generation, IntentFence: scope.FencingToken, LeaseOwner: scope.LeaseOwner, ExecutorID: scope.LeaseExecutorID, MachinePrincipalID: b.MachinePrincipalID, Deadline: scope.Deadline}
	now := time.Now().UTC()
	if reply.Schema != capacity.OriginalCanaryAuthoritySchema || reply.Scope != expected || !reply.OriginalLiveLeaseVerified || !reply.CurrentMachineRBACVerified || reply.HumanSessionVerified || reply.UsefulCapacityKnown || reply.FullTransitionQualified || reply.ObservedAt.Before(started.Add(-time.Second)) || reply.ObservedAt.After(now.Add(time.Second)) || now.Sub(reply.ObservedAt) > 5*time.Second || !now.Before(scope.Deadline) {
		return errCapacityBoundAssessment
	}
	return nil
}

// The only useful hook executes inside the original live intent lease, BEFORE
// reservation completion. An optional binding is a finite prerequisite, not a
// capacity certificate. Any possible control/Commit with unknown return stays
// in the permanent marker; there is no arm replay, reconstructed bearer or
// late refreshed owner. A later invocation can only HOLD that uncertainty.
func runOriginalNotifyWindow(parent context.Context, store repository.CapacityStore, policy model.Manifest, p model.CapacityPolicySpec, intent model.CapacityIntent, call capacityBoundPrivateCall) (result error) {
	refuse := func(causes ...error) error {
		return &opaqueAdapterError{public: errCapacityBoundAssessment, cause: errors.Join(append([]error{errCapacityBoundAssessment}, causes...)...)}
	}
	if m := intent.OriginalNotifyWindow; m != nil && (m.State != "original_returns_observed" || m.OriginalReturnsObservedAt == nil || !originalNotifySHA(m.OriginalReturnsSHA256)) {
		return refuse()
	}
	if p.NativeNotifyWindowBinding == nil {
		return capacityDispatchFence(parent)
	}
	if !originalNotifyResourcesSupported(p) {
		return refuse()
	}
	b := p.NativeNotifyWindowBinding
	invocation := capacityDispatchInvocationFrom(parent)
	if invocation == nil || invocation.notifyFactory.PrepareScope == nil || invocation.notifyFactory.Register == nil || store.AdmissionOnly || call == nil || store.DB == nil || intent.LeaseExpiresAt == nil || b.Mode != originalNotifyWindowMode || b.ProbeCount != 1 || b.QuerySHA256 != originalNotifyWindowQuerySHA {
		return refuse()
	}
	if err := capacityDispatchFence(parent); err != nil {
		return refuse(err)
	}
	roster, err := originalNotifyRoster(parent, p, call)
	if err != nil {
		return refuse(err)
	}
	scope, err := invocation.notifyFactory.PrepareScope(parent, policy, p, intent, roster)
	if err != nil || scope.CoreAuthority == nil || scope.NativeRoster == nil || !originalNotifySameRoster(*scope.NativeRoster, roster) || scope.ProbeCount != 1 || scope.Deadline.After(*intent.LeaseExpiresAt) || !time.Now().Before(scope.Deadline) {
		return refuse(err)
	}
	owner, cancel := context.WithDeadline(parent, scope.Deadline)
	defer cancel()
	defer func() {
		if cause := errors.Join(capacityDispatchFence(owner), nativeAdapterContext(parent)); cause != nil {
			result = refuse(result, cause)
		}
	}()
	scopeSHA, err := originalNotifyDigest(scope)
	if err != nil {
		return refuse(err)
	}
	rosterSHA, err := originalNotifyDigest(roster)
	if err != nil {
		return refuse(err)
	}
	resolveKey := func(ref string) (string, error) {
		if cause := capacityDispatchFence(owner); cause != nil {
			return "", cause
		}
		value, e := repository.ResolveSecretRef(owner, store.DB, ref)
		key, ok := value.(string)
		if !ok || len(key) < 32 || len(key) > 4096 || strings.ContainsAny(key, "\r\n\x00") {
			return "", errors.Join(errCapacityBoundAssessment, e)
		}
		return key, errors.Join(e, capacityDispatchFence(owner))
	}
	controlKey, err := resolveKey(b.ControlKeyRef)
	if err != nil {
		return refuse(err)
	}
	readKey, err := resolveKey(b.ReadKeyRef)
	if err != nil || readKey == controlKey {
		return refuse(err)
	}
	marker := model.CapacityOriginalNotifyWindowMarker{Schema: "core_original_notify_window_marker_v1", State: "possible_start", WindowID: scope.WindowID, ScopeSHA256: scopeSHA, SourceCommit: b.SourceCommit, QuerySHA256: b.QuerySHA256, RosterSHA256: rosterSHA, PolicyID: scope.PolicyID, PolicyChecksum: scope.PolicyChecksum, WorkflowID: scope.WorkflowID, WorkflowChecksum: scope.CoreAuthority.WorkflowChecksum, DispatchJobID: scope.CoreAuthority.DispatchJobID, DispatchFence: scope.CoreAuthority.DispatchFence, IntentGeneration: scope.Generation, IntentFence: scope.FencingToken, LeaseOwner: scope.LeaseOwner, ExecutorID: scope.LeaseExecutorID, Deadline: scope.Deadline}
	// No registration or outbound control precedes actual original Commit ACK.
	intent, err = store.BeginOriginalNotifyWindow(owner, policy, intent, marker)
	if err != nil {
		return refuse(err)
	}
	token, revoke, current, err := invocation.notifyFactory.Register(owner, policy, p, intent, scope)
	if err != nil || revoke == nil || current == nil {
		if revoke != nil {
			revoke()
		}
		return refuse(err)
	}
	defer revoke()
	guard := func() error {
		if e := errors.Join(current(owner), capacityDispatchFence(owner), nativeAdapterContext(parent)); e != nil {
			return e
		}
		control, e := resolveKey(b.ControlKeyRef)
		if e != nil || control != controlKey {
			return errors.Join(errCapacityBoundAssessment, e)
		}
		read, e := resolveKey(b.ReadKeyRef)
		if e != nil || read != readKey {
			return errors.Join(errCapacityBoundAssessment, e)
		}
		return errors.Join(current(owner), capacityDispatchFence(owner), nativeAdapterContext(parent))
	}
	observeAuthority := func() error {
		if e := guard(); e != nil {
			return e
		}
		started := time.Now().UTC()
		raw, e := originalNotifyHTTPRequest(owner, http.DefaultClient, b.CoreAuthorityURL, http.MethodGet, nil, originalNotifyHTTPHeaders{coreBearer: token.HeaderValue(), scopeSHA: scopeSHA}, http.StatusOK, 16<<10)
		if e != nil {
			return e
		}
		return errors.Join(originalNotifyAuthorityAccepted(raw, scope, scopeSHA, started), guard())
	}
	control := func(participant model.CapacityNativeNotifyParticipant, operation string) error {
		if e := observeAuthority(); e != nil {
			return e
		}
		fresh, e := originalNotifyRoster(owner, p, call)
		if e != nil || !originalNotifySameRoster(fresh, roster) {
			return errors.Join(errCapacityBoundAssessment, e)
		}
		body := struct {
			Operation string                     `json:"operation"`
			Scope     *OriginalNotifyWindowScope `json:"scope,omitempty"`
		}{Operation: operation, Scope: &scope}
		if operation == "seal" {
			body.Scope = nil
		}
		request, e := json.Marshal(body)
		if e != nil {
			return e
		}
		raw, e := originalNotifyHTTPRequest(owner, http.DefaultClient, participant.Origin+originalNotifyWindowControlPath, http.MethodPost, request, originalNotifyHTTPHeaders{coreBearer: token.HeaderValue(), scopeSHA: scopeSHA, controlKey: controlKey}, http.StatusAccepted, 16<<10)
		if e != nil {
			return e
		}
		if e = errors.Join(originalNotifyControlAccepted(raw), guard()); e != nil {
			return e
		}
		fresh, e = originalNotifyRoster(owner, p, call)
		if e != nil || !originalNotifySameRoster(fresh, roster) {
			return errors.Join(errCapacityBoundAssessment, e)
		}
		return observeAuthority()
	}
	var publisher model.CapacityNativeNotifyParticipant
	// Join EVERY original B installation before A's single original arm.
	for _, participant := range b.Participants {
		if participant.Role == "publisher_reader" {
			publisher = participant
			continue
		}
		if err = control(participant, "participant_authority"); err != nil {
			return refuse(err)
		}
	}
	if publisher.PodName == "" {
		return refuse()
	}
	if err = control(publisher, "arm"); err != nil {
		return refuse(err)
	}
	var finalRaw []byte
	complete := false
	for round := 0; round < originalNotifyWindowStatusRounds-1; round++ {
		if err = observeAuthority(); err != nil {
			return refuse(err)
		}
		before, e := originalNotifyRoster(owner, p, call)
		if e != nil || !originalNotifySameRoster(before, roster) {
			return refuse(e)
		}
		raw, e := originalNotifyHTTPRequest(owner, http.DefaultClient, publisher.Origin+originalNotifyWindowPath, http.MethodGet, nil, originalNotifyHTTPHeaders{readKey: readKey}, http.StatusOK, 1<<20)
		if e != nil {
			return refuse(e)
		}
		complete, e = originalNotifyReadComplete(owner, p, scope, scopeSHA, raw, call)
		guardErr := guard()
		if e != nil || guardErr != nil {
			return refuse(e, guardErr)
		}
		if complete {
			finalRaw = bytes.Clone(raw)
			break
		}
		if round == originalNotifyWindowStatusRounds-2 {
			return refuse()
		}
		timer := time.NewTimer(250 * time.Millisecond)
		select {
		case <-owner.Done():
			timer.Stop()
			return refuse(nativeAdapterContext(owner), nativeAdapterContext(parent))
		case <-timer.C:
		}
	}
	if !complete {
		return refuse()
	}
	// ONE original seal joins the producer and native completion; its accepted
	// HTTP result alone still cannot stand in for B's original writer return.
	if err = control(publisher, "seal"); err != nil {
		return refuse(err)
	}
	raw, err := originalNotifyHTTPRequest(owner, http.DefaultClient, publisher.Origin+originalNotifyWindowPath, http.MethodGet, nil, originalNotifyHTTPHeaders{readKey: readKey}, http.StatusOK, 1<<20)
	if err != nil {
		return refuse(err)
	}
	complete, err = originalNotifyReadComplete(owner, p, scope, scopeSHA, raw, call)
	var final originalNotifyWindowReply
	guardErr := guard()
	if err != nil || !complete || capacity.DecodeBusinessJSON(raw, &final) != nil || !originalNotifyTrue(final.Sealed) || guardErr != nil {
		return refuse(err, guardErr)
	}
	// Retain only hashes of original joined observations; no credential/raw
	// private census leaves this invocation or becomes a capacity certificate.
	joinedSHA, e := originalNotifyDigest([]string{capacity.BusinessCreationSHA256(finalRaw), capacity.BusinessCreationSHA256(raw), scopeSHA, rosterSHA})
	if e != nil {
		return refuse(e)
	}
	if err = observeAuthority(); err != nil {
		return refuse(err)
	}
	if err = store.RecordOriginalNotifyWindowReturns(owner, policy, intent, scopeSHA, joinedSHA, time.Now().UTC()); err != nil {
		return refuse(err)
	}
	return guard()
}
