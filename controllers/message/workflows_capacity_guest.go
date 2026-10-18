package message

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"reflect"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/manifest"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
)

var errOriginalGuestStep = errors.New("protected original Guest source step unavailable; HOLD and recover by exact GET")

type guestOriginalProvider interface {
	Prepare(context.Context, int) error
	Create(context.Context, repository.CapacityStore, model.Manifest, model.CapacityMutationGrant, model.CapacityGuestOriginalProvisioningPreregistration) (model.CapacityMutationProof, error)
}

// The production source provider/registry is EMPTY. Only the separately
// compiled native qualification constructor may install its exact own realm.
var originalGuestSourceProvider guestOriginalProvider

type guestOriginalStepInput struct {
	Policy            model.ManifestSelector `json:"policy"`
	BindingName       string                 `json:"binding_name"`
	Slot              int                    `json:"slot"`
	Generation        int64                  `json:"generation"`
	FencingToken      int64                  `json:"fencing_token"`
	LeaseOwner        string                 `json:"lease_owner"`
	PreregistrationID string                 `json:"preregistration_id,omitempty"`
	RequestID         string                 `json:"request_id,omitempty"`
}

func guestOriginalOperation(operation string) bool {
	return operation == capacity.ProvisionOriginalGuestOperation || operation == capacity.RetireOriginalGuestOperation || operation == "capacity.qualify_original_guest_echo" || operation == "capacity.finish_original_guest_retirement"
}

func sourceGuestSecret(ctx context.Context, db *sql.DB, ref string) ([]byte, error) {
	value, err := repository.ResolveSecretRef(ctx, db, ref)
	text, ok := value.(string)
	if err != nil || !ok || len(text) < 1 || len(text) > 1<<20 {
		return nil, errOriginalGuestStep
	}
	return []byte(text), nil
}
func sourceGuestSigningKey(ctx context.Context, db *sql.DB, ref string) (ed25519.PrivateKey, error) {
	raw, err := sourceGuestSecret(ctx, db, ref)
	if err != nil {
		return nil, err
	}
	key, err := base64.StdEncoding.DecodeString(string(raw))
	if err != nil || len(key) != ed25519.PrivateKeySize || base64.StdEncoding.EncodeToString(key) != string(raw) {
		return nil, errOriginalGuestStep
	}
	return ed25519.PrivateKey(key), nil
}
func sourceGuestClient(ctx context.Context, db *sql.DB, member model.CapacityGuestRetirementMemberBinding) (*capacity.GuestOriginalHTTPClient, error) {
	ca, err := sourceGuestSecret(ctx, db, member.ServerCARef)
	if err != nil {
		return nil, err
	}
	crt, err := sourceGuestSecret(ctx, db, member.ClientCertificateRef)
	if err != nil {
		return nil, err
	}
	key, err := sourceGuestSecret(ctx, db, member.ClientKeyRef)
	if err != nil {
		return nil, err
	}
	return capacity.NewGuestOriginalHTTPClient(member, ca, crt, key)
}
func sourceGuestNonce() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw[:]), nil
}

// ACTUAL resolved step and its timeout precede reservation. Inputs supply no
// profile, native tuple, source identity, provider proof or context/deadline.
func executeCapacityGuestWorkflowStep(parent context.Context, db *sql.DB, workflowRef model.ManifestReference, step model.WorkflowStepSpec, result model.WorkflowRunStepResult, input map[string]any) model.WorkflowRunStepResult {
	result.Attempts = 1
	fail := func(predicate string) model.WorkflowRunStepResult {
		result.Status = "failed"
		result.Error = errOriginalGuestStep.Error()
		result.Metadata = map[string]any{"original_guest_refusal_predicate": predicate}
		result.FinishedAt = time.Now().UTC()
		return result
	}
	if db == nil || !guestOriginalOperation(result.Operation) || step.Use.Kind != "yggdrasil" || step.Use.Operation != result.Operation || step.TimeoutSeconds < 1 || step.TimeoutSeconds > 86400 || step.Retry.MaxAttempts > 1 || step.ForEach != nil {
		return fail("original-guest-step-01")
	}
	hostContext, cancelHost, hostRealm, err := originalHostStepContext(parent, workflowRef, step, result.Operation)
	if err != nil || (hostRealm == nil && originalGuestSourceProvider == nil) {
		return fail("original-guest-step-02")
	}
	defer cancelHost()
	if hostRealm != nil {
		parent = hostContext
	}
	ctx, cancel := context.WithTimeout(parent, time.Duration(step.TimeoutSeconds)*time.Second)
	defer cancel()
	if hostRealm == nil {
		limited, cancelSource, sourceErr := guestOriginalSourceLimit(ctx)
		if sourceErr != nil {
			return fail("original-guest-step-03")
		}
		ctx = limited
		defer cancelSource()
	}
	var parsed guestOriginalStepInput
	if capacity.DecodeVMObservation(input, &parsed) != nil || parsed.Policy.ManifestID != "" || parsed.Policy.Version != nil || parsed.Policy.Namespace == "" || parsed.Policy.Name == "" || parsed.BindingName == "" || parsed.Slot < 1 || parsed.Slot > 64 || parsed.Generation < 1 || parsed.FencingToken < 1 || parsed.LeaseOwner == "" {
		return fail("original-guest-step-04")
	}
	policy, err := repository.ResolveManifest(ctx, db, "capacity_policy", parsed.Policy.Namespace, parsed.Policy.Name, nil, true)
	if err != nil {
		return fail("original-guest-step-05")
	}
	p, err := manifest.ParseCapacityPolicySpec(policy.Spec)
	if err != nil || manifest.ValidateCapacityPolicySpec(p) != nil || p.GuestRetirementBinding == nil || p.GuestRetirementBinding.MutationBindingName != parsed.BindingName || workflowRef.Kind != "workflow" || workflowRef.Namespace != p.Workflow.Namespace || workflowRef.Name != p.Workflow.Name {
		return fail("original-guest-step-06")
	}
	wf, err := repository.ResolveManifest(ctx, db, "workflow", p.Workflow.Namespace, p.Workflow.Name, nil, true)
	if err != nil || wf.ID != workflowRef.ID || wf.Version != workflowRef.Version {
		return fail("original-guest-step-07")
	}
	wfs, err := manifest.ParseWorkflowSpec(wf.Spec)
	if err != nil || wfs.Authorization == nil {
		return fail("original-guest-step-08")
	}
	matched := false
	for _, approved := range wfs.Steps {
		matched = matched || reflect.DeepEqual(approved, step)
	}
	if !matched {
		return fail("original-guest-step-09")
	}
	b, err := capacity.VMObservationBinding(p, parsed.BindingName)
	if err != nil {
		return fail("original-guest-step-10")
	}
	provider := ""
	for _, profile := range p.Profiles {
		if profile.Name == b.ProfileName {
			provider = profile.Provider
		}
	}
	if !capacity.GuestOriginalProfileEnabled(p, *p.GuestRetirementBinding, provider) {
		return fail("original-guest-step-11")
	}
	var member model.CapacityGuestRetirementMemberBinding
	for _, candidate := range p.GuestRetirementBinding.Members {
		if candidate.Slot == parsed.Slot {
			member = candidate
		}
	}
	if member.Name == "" {
		return fail("original-guest-step-12")
	}
	executor, _ := ctx.Value(capacityInvocationKey{}).(string)
	store := repository.CapacityStore{DB: db, ExecutionEnabled: os.Getenv("YGGDRASIL_CAPACITY_EXECUTION_ENABLED") == "true", WorkflowID: wf.ID, ExecutorID: executor}
	if store.ValidateNativeObservationLease(ctx, policy, parsed.Generation, parsed.FencingToken, parsed.LeaseOwner) != nil {
		return fail("original-guest-step-13")
	}
	if hostRealm != nil {
		output, hostErr := executeOriginalHostFactoryStep(ctx, hostRealm, store, policy, wf, step, p, b, parsed)
		if hostErr != nil {
			return fail("original-guest-step-14")
		}
		raw, hostErr := json.Marshal(output)
		if hostErr != nil || json.Unmarshal(raw, &result.Metadata) != nil {
			return fail("original-guest-step-15")
		}
		result.Status = "succeeded"
		result.Error = ""
		result.FinishedAt = time.Now().UTC()
		return result
	}
	key, err := sourceGuestSigningKey(ctx, db, p.GuestRetirementBinding.IntentSigningKeyRef)
	if err != nil {
		return fail("original-guest-step-16")
	}
	var output any
	if result.Operation == "capacity.qualify_original_guest_echo" || result.Operation == "capacity.finish_original_guest_retirement" {
		output, err = sourceGuestQualificationStep(ctx, store, policy, p, parsed, key, result.Operation)
		if err != nil {
			return fail("original-guest-step-17")
		}
	} else if result.Operation == capacity.ProvisionOriginalGuestOperation {
		if parsed.PreregistrationID != "" {
			return fail("original-guest-step-18")
		}
		if originalGuestSourceProvider.Prepare(ctx, parsed.Slot) != nil {
			return fail("original-guest-step-19")
		}
		var projection *model.CapacityMutationSpecV1
		for _, slot := range b.Slots {
			if slot.Slot == parsed.Slot {
				projection = slot.DesiredSpec
			}
		}
		if projection == nil {
			return fail("original-guest-step-20")
		}
		body, err := json.Marshal(projection)
		if err != nil {
			return fail("original-guest-step-21")
		}
		nonce, err := sourceGuestNonce()
		if err != nil {
			return fail("original-guest-step-22")
		}
		store = store.WithOriginalGuestProvisioning(step, capacity.CurrentGuestCoreSource(), capacity.BusinessCreationSHA256([]byte(nonce)))
		grant, err := store.IssueMutation(ctx, policy, parsed.Generation, parsed.FencingToken, parsed.LeaseOwner, model.CapacityMutationIssue{BindingName: b.Name, DesiredSpec: body})
		if err != nil {
			return fail("original-guest-step-23")
		}
		pre, err := store.OriginalGuestProvisioning(ctx, grant.GrantID)
		if err != nil {
			return fail("original-guest-step-24")
		}
		original, cancelOriginal := context.WithDeadline(ctx, pre.OriginalDeadline)
		defer cancelOriginal()
		proof, err := originalGuestSourceProvider.Create(original, store, policy, grant, pre)
		if err != nil {
			return fail("original-guest-step-25")
		}
		witness, err := store.RecordGuestCreateWitness(original, pre.PreregistrationID, proof, key)
		if err != nil {
			return fail("original-guest-step-26")
		}
		if err = guestOriginalSourceWitnessed(original, grant, pre, witness); err != nil {
			return fail("original-guest-step-27")
		}
		ticker := time.NewTicker(50 * time.Millisecond)
		defer ticker.Stop()
		var receipt model.CapacityGuestOriginalProvisioningReceipt
		for {
			receipt, err = store.GuestProvisioningReceipt(original, member.ProvisionerClientPrincipal, pre.PreregistrationID, pre.NonceSHA256)
			if err == nil {
				break
			}
			if !errors.Is(err, sql.ErrNoRows) {
				return fail("original-guest-step-28")
			}
			select {
			case <-original.Done():
				return fail("original-guest-step-29")
			case <-ticker.C:
			}
		}
		// Confirm physical source membership only after the complete original
		// enrollment callback. This still grants no business readiness/canary.
		if _, err = store.ConfirmMutation(original, policy, parsed.Generation, parsed.FencingToken, parsed.LeaseOwner, proof); err != nil {
			return fail("original-guest-step-30")
		}
		if err = guestOriginalSourceEnrolled(original, grant, pre, receipt); err != nil {
			return fail("original-guest-step-31")
		}
		output = struct {
			Preregistration     model.CapacityGuestOriginalProvisioningPreregistration `json:"preregistration"`
			WitnessSHA256       string                                                 `json:"witness_sha256"`
			Receipt             model.CapacityGuestOriginalProvisioningReceipt         `json:"receipt"`
			UsefulCapacityKnown bool                                                   `json:"useful_capacity_known"`
		}{pre, capacity.GuestRetirementSHA(witness), receipt, false}
	} else {
		if _, err = uuid.Parse(parsed.PreregistrationID); err != nil {
			return fail("original-guest-step-32")
		}
		joinOriginalFloor, err := guestOriginalSourceBeforeRetirement(ctx, store, policy, p, parsed, key)
		if err != nil {
			return fail("original-guest-step-33")
		}
		defer joinOriginalFloor()
		nonce, err := sourceGuestNonce()
		if err != nil {
			return fail("original-guest-step-34")
		}
		store = store.WithOriginalGuestRetirement(step, capacity.CurrentGuestCoreSource())
		request, err := store.IssueGuestRetirement(ctx, policy, parsed.Generation, parsed.FencingToken, parsed.LeaseOwner, parsed.PreregistrationID, nonce, key)
		if err != nil {
			return fail("original-guest-step-35")
		}
		original, cancelOriginal := context.WithDeadline(ctx, request.Intent.OriginalDeadline)
		defer cancelOriginal()
		if err = store.ReserveGuestCaller(original, request); err != nil {
			return fail("original-guest-step-36")
		}
		client, err := sourceGuestClient(original, db, member)
		if err != nil {
			return fail("original-guest-step-37")
		}
		defer client.Close()
		body, err := json.Marshal(request)
		if err != nil {
			return fail("original-guest-step-38")
		}
		returned, callErr := client.Original(original, http.MethodPost, "/v1/retirement", body)
		floorJoinErr := joinOriginalFloor()
		var observed model.CapacityGuestRetirementObservation
		decoded := capacity.GuestOriginalHTTPDecode(returned, &observed) == nil
		// Only a closed authenticated protocol body is retained. Unknown body
		// bytes/errors/secrets remain hash/count/timestamp facts, never proof.
		persisted := false
		// The expected original enrollment is fetched by its scoped exact GET.
		retention, cancelRetention := context.WithTimeout(context.WithoutCancel(original), 5*time.Second)
		stored, loadErr := store.GuestRetirementOriginal(retention, member.ActorClientPrincipal, request.Intent.RequestID, capacity.GuestRetirementSHA(request.Intent))
		if loadErr == nil {
			persisted = decoded && capacity.GuestRetirementObservedReturnAuthentic(observed, stored.Receipt.Enrollment, request.Intent, observed.ObservedAt)
		}
		retained := repository.GuestOriginalCallerReturn{RequestID: request.Intent.RequestID, AttemptID: request.Intent.AttemptID, StartedAt: returned.StartedAt, DoStartedAt: returned.DoStartedAt, DriverReturnedAt: returned.DriverReturnedAt, PreflightFailed: returned.PreflightFailed, DoReturnedAt: returned.DoReturnedAt, ReadReturnedAt: returned.ReadReturnedAt, CloseReturnedAt: returned.CloseReturnedAt, OriginalDeadline: request.Intent.OriginalDeadline, ReceivedBodyBytes: returned.ReceivedBodyBytes, BodyPersisted: persisted, Status: returned.Status, ResponseSHA256: returned.ResponseSHA256, ResponseBodyScope: returned.ResponseBodyScope, RetainedPrefixBytes: returned.RetainedPrefixBytes, RetainedPrefixSHA256: returned.RetainedPrefixSHA256, DoFailed: returned.DoFailed, ReadFailed: returned.ReadFailed, CloseFailed: returned.CloseFailed, OriginalContextFailed: returned.OriginalContextFailed}
		if persisted {
			retained.Body = returned.Body
		}
		recordErr := store.RecordGuestCallerReturn(retention, retained)
		if persisted && recordErr == nil {
			recordErr = store.RecordGuestObservation(retention, request.Intent.RequestID, observed)
		}
		cancelRetention()
		if callErr != nil || floorJoinErr != nil || recordErr != nil || !persisted {
			return fail("original-guest-step-39")
		}
		output = struct {
			RequestID           string                                   `json:"request_id"`
			IntentSHA256        string                                   `json:"intent_sha256"`
			Observation         model.CapacityGuestRetirementObservation `json:"observation"`
			NativePoweroffKnown bool                                     `json:"native_poweroff_known"`
		}{request.Intent.RequestID, capacity.GuestRetirementSHA(request.Intent), observed, false}
	}
	raw, err := json.Marshal(output)
	if err != nil {
		return fail("original-guest-step-40")
	}
	if json.Unmarshal(raw, &result.Metadata) != nil {
		return fail("original-guest-step-41")
	}
	result.Status = "succeeded"
	result.Error = ""
	result.FinishedAt = time.Now().UTC()
	return result
}
