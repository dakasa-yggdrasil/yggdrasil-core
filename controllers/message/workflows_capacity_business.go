package message

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/manifest"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
	amqp "github.com/rabbitmq/amqp091-go"
)

var errCapacityBusinessObservation = errors.New("protected original creation canary refused")

// One fixed original ledger read; there is no new ledger, lease or grant.
// Retain the private original bytes so even a phase/owner/expiry mutation while
// a native Read/Close is held invalidates the whole observation.
func readCapacityBusinessIntent(ctx context.Context, db *sql.DB, policy model.Manifest, p model.CapacityPolicySpec) (model.CapacityIntent, []byte, error) {
	var intent model.CapacityIntent
	if nativeAdapterContext(ctx) != nil {
		return intent, nil, nativeAdapterContext(ctx)
	}
	rows, err := db.QueryContext(ctx, `SELECT substring(convert_to(intent::text,'UTF8') FROM 1 FOR 65537) FROM public.capacity_intents WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4`, policy.Metadata.Namespace, p.Environment, p.Domain, p.Dimension)
	if err != nil {
		return intent, nil, err
	}
	var raw []byte
	if !rows.Next() {
		err = errors.New("original intent absent")
	} else {
		err = rows.Scan(&raw)
	}
	if rows.Next() {
		err = errors.Join(err, errors.New("original intent ambiguous"))
	}
	joined := errors.Join(err, rows.Err(), rows.Close(), nativeAdapterContext(ctx))
	if joined != nil || len(raw) == 0 || len(raw) > 65536 || json.Unmarshal(raw, &intent) != nil {
		return intent, nil, errors.Join(errors.New("original bounded intent unresolved"), joined)
	}
	return intent, bytes.Clone(raw), nil
}

// Production uses the ordinary verified TLS trust chain. The private seam is
// only an HTTP client for real TLS/failure fixtures; it grants no source scope.
func executeCapacityBusinessWorkflowStep(parent context.Context, conn *amqp.Connection, db *sql.DB, ref model.ManifestReference, result model.WorkflowRunStepResult, input map[string]any) model.WorkflowRunStepResult {
	return executeCapacityBusinessWorkflowStepWithClient(parent, conn, db, ref, result, input, &http.Client{})
}

func executeCapacityBusinessWorkflowStepWithClient(parent context.Context, conn *amqp.Connection, db *sql.DB, ref model.ManifestReference, result model.WorkflowRunStepResult, input map[string]any, client *http.Client) (out model.WorkflowRunStepResult) {
	out = result
	out.Attempts, out.Status, out.Error, out.Metadata = 1, "failed", errCapacityBusinessObservation.Error(), nil
	if nativeAdapterContext(parent) != nil {
		out.FinishedAt = time.Now().UTC()
		return out
	}
	ctx, cancel := context.WithTimeout(parent, 90*time.Second)
	leaseCancel := func() {}
	defer func() { leaseCancel(); cancel() }()
	ctx = withNativeAdapterPolicy(ctx, parent)
	var originalLeaseDeadline time.Time
	defer func() {
		out.FinishedAt = time.Now().UTC()
		if errors.Join(nativeAdapterContext(ctx), nativeAdapterContext(parent)) != nil || !originalLeaseDeadline.IsZero() && !time.Now().Before(originalLeaseDeadline) {
			out.Status, out.Error, out.Metadata = "failed", errCapacityBusinessObservation.Error(), nil
		}
	}()
	var parsed struct {
		Policy      model.ManifestSelector `json:"policy"`
		BindingName string                 `json:"binding_name"`
	}
	if len(input) != 2 || input["policy"] == nil || input["binding_name"] == nil {
		return out
	}
	rawInput, encodeErr := json.Marshal(input)
	if db == nil || client == nil || result.Operation != "capacity.observe_original_creation_canary" || encodeErr != nil || capacity.DecodeBusinessJSON(rawInput, &parsed) != nil || parsed.Policy.ManifestID != "" || parsed.Policy.Version != nil || parsed.Policy.Namespace == "" || parsed.Policy.Name == "" || parsed.BindingName == "" {
		return out
	}
	executor, _ := ctx.Value(capacityInvocationKey{}).(string)
	if id, err := uuid.Parse(executor); err != nil || id == uuid.Nil || id.String() != executor {
		return out
	}
	policy, err := repository.ResolveManifest(ctx, db, "capacity_policy", parsed.Policy.Namespace, parsed.Policy.Name, nil, true)
	if err != nil {
		return out
	}
	p, err := manifest.ParseCapacityPolicySpec(policy.Spec)
	if err != nil || manifest.ValidateCapacityPolicySpec(p) != nil || capacity.ValidateBusinessCreationBinding(p) != nil || p.BusinessCreationBinding == nil || p.BusinessCreationBinding.Name != parsed.BindingName || ref.Kind != "workflow" || ref.Namespace != p.Workflow.Namespace || ref.Name != p.Workflow.Name {
		return out
	}
	wf, err := repository.ResolveManifest(ctx, db, "workflow", p.Workflow.Namespace, p.Workflow.Name, nil, true)
	if err != nil || wf.ID != ref.ID || wf.Version != ref.Version {
		return out
	}
	ws, err := manifest.ParseWorkflowSpec(wf.Spec)
	if err != nil || ws.Authorization == nil {
		return out
	}
	b := p.BusinessCreationBinding
	if !strings.HasPrefix(b.ReadTokenRef, "secret://"+policy.Metadata.Namespace+"/") {
		return out
	}
	store := repository.CapacityStore{DB: db, ExecutionEnabled: os.Getenv("YGGDRASIL_CAPACITY_EXECUTION_ENABLED") == "true", WorkflowID: wf.ID, ExecutorID: executor}
	intent, original, err := readCapacityBusinessIntent(ctx, db, policy, p)
	if err != nil || intent.PolicyID != policy.ID || intent.PolicyChecksum != policy.Checksum || intent.LeaseExecutorID != executor || intent.LeaseOwner == "" || intent.Generation < 1 || intent.FencingToken < 1 || intent.RecoveryOnly || intent.LeaseExpiresAt == nil || !intent.LeaseExpiresAt.After(time.Now()) {
		return out
	}
	// Copy the ORIGINAL lease deadline once. Native calls and their real
	// Read/Close/Commit returns cannot acquire a fresh90s budget after expiry.
	originalLeaseDeadline = *intent.LeaseExpiresAt
	ctx, leaseCancel = context.WithDeadline(ctx, originalLeaseDeadline)
	var boundToken string
	guard := func() error {
		if joined := errors.Join(nativeAdapterContext(ctx), nativeAdapterContext(parent)); joined != nil {
			return joined
		}
		currentPolicy, e := repository.ResolveManifest(ctx, db, "capacity_policy", parsed.Policy.Namespace, parsed.Policy.Name, nil, true)
		if e != nil || currentPolicy.ID != policy.ID || currentPolicy.Checksum != policy.Checksum {
			return errors.Join(errCapacityBusinessObservation, e)
		}
		currentWF, e := repository.ResolveManifest(ctx, db, "workflow", p.Workflow.Namespace, p.Workflow.Name, nil, true)
		if e != nil || currentWF.ID != wf.ID || currentWF.Checksum != wf.Checksum || currentWF.Version != wf.Version {
			return errors.Join(errCapacityBusinessObservation, e)
		}
		if e = preflightVMNodeCatalog(ctx, db, b.Adapter, []string{capacity.ObserveNativePodAdmission}); e != nil {
			return e
		}
		if boundToken != "" {
			value, e := repository.ResolveSecretRef(ctx, db, b.ReadTokenRef)
			current, ok := value.(string)
			if e != nil || !ok || current != boundToken {
				return errors.Join(errCapacityBusinessObservation, e)
			}
		}
		_, raw, e := readCapacityBusinessIntent(ctx, db, policy, p)
		if e != nil || !bytes.Equal(raw, original) {
			return errors.Join(errCapacityBusinessObservation, e)
		}
		joined := errors.Join(store.ValidateNativeObservationLease(ctx, policy, intent.Generation, intent.FencingToken, intent.LeaseOwner), nativeAdapterContext(ctx), nativeAdapterContext(parent))
		if !time.Now().Before(originalLeaseDeadline) {
			joined = errors.Join(joined, context.DeadlineExceeded)
		}
		return joined
	}
	// Both immutable instance/type catalogs and the original live lease are
	// checked BEFORE any resolver, health/Describe or separate read secret.
	if guard() != nil {
		return out
	}
	a, err := resolveCapacityObservationAdapterWithResolver(ctx, conn, db, b.Adapter, []string{capacity.ObserveNativePodAdmission}, resolveIntegrationInstance)
	if err != nil || guard() != nil {
		return out
	}
	credential, err := repository.ResolveSecretRef(ctx, db, b.ReadTokenRef)
	token, ok := credential.(string)
	if err != nil || !ok || len(token) < 32 || len(token) > 4096 || strings.ContainsAny(token, "\r\n") {
		return out
	}
	boundToken = token
	if guard() != nil {
		return out
	}
	readPod := func() (model.AdapterCapacityPodAdmissionResponse, error) {
		var pod model.AdapterCapacityPodAdmissionResponse
		if e := guard(); e != nil {
			return pod, e
		}
		r, e := executeIntegrationThroughResolvedWithPolicy(ctx, conn, model.ExecuteIntegrationRequest{Operation: capacity.ObserveNativePodAdmission, Capability: capacity.ObserveNativePodAdmission, Input: map[string]any{"binding_name": b.Pod.BindingName, "pod_name": b.Pod.PodName, "expected_pod_uid": b.Pod.ExpectedPodUID, "expected_pod_generation": b.Pod.ExpectedPodGeneration, "expected_container_id": b.Pod.ExpectedContainerID, "expected_container_started_at": b.Pod.ExpectedContainerStartedAt, "expected_restart_count": b.Pod.ExpectedRestartCount}}, a.instance, a.instanceSpec, a.typ, a.typeSpec, 65*time.Second, integrationExecutionPolicy{detailFreeErrors: true, safeError: errCapacityBusinessObservation, requireExplicitResponse: true, nativeHTTP: &nativeAdapterHTTPPolicy{limit: 2 << 20, parent: parent}})
		if e != nil || r.Status != "observed" || capacity.DecodeVMObservation(r.Output, &pod) != nil {
			return pod, errors.Join(errCapacityBusinessObservation, e)
		}
		return pod, guard()
	}
	before, err := readPod()
	if err != nil || before.Admission.Challenge == nil || before.Admission.Challenge.IntentGeneration != intent.Generation {
		return out
	}
	var reply model.CapacityBusinessCreationReply
	transport := &adapterTransportClient{httpClient: client}
	readCtx, done := context.WithTimeout(ctx, 65*time.Second)
	err = transport.callNativeHTTPJSON(readCtx, b.ReaderURL, nil, &reply, adapterCallPolicy{detailFreeErrors: true, native: &nativeAdapterHTTPPolicy{limit: capacity.BusinessCreationLimit, get: true, requireTLS: true, exactURL: b.ReaderURL, readToken: token, parent: parent}})
	joined := errors.Join(err, nativeAdapterContext(readCtx), nativeAdapterContext(ctx), nativeAdapterContext(parent))
	done()
	if joined != nil || guard() != nil {
		return out
	}
	after, err := readPod()
	if err != nil {
		return out
	}
	creation, err := capacity.JoinBusinessCreation(p, reply, before, after, time.Now().UTC())
	if err != nil || guard() != nil {
		return out
	}
	out.Metadata = map[string]any{"native_creation_canary_observed": true, "original_creation": creation, "preparation_observed": true, "original_caller_return_known": false, "useful_capacity_known": false, "bootstrap_completed_known": false, "routing_withdrawn_known": false, "business_drain_known": false, "provider_mutation_quiescence_known": false, "physical_capacity_released": false, "atomic_snapshot": false, "missing": []string{"original_caller_return", "bootstrap_completion", "broader_warmup", "route_lifecycle", "business_drain", "writer_retirement", "provider_quiescence"}}
	out.Status, out.Error = "succeeded", ""
	return out
}
