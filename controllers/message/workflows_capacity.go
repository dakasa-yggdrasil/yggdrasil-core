package message

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/manifest"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
)

type capacityInvocationKey struct{}

// The invocation identity is process-generated and lives in an unexported
// context key. Caller inputs and metadata cannot supply or restore it.
func newCapacityInvocationContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, capacityInvocationKey{}, uuid.NewString())
}

type capacityWorkflowInput struct {
	Policy        model.ManifestSelector          `json:"policy"`
	Assessment    model.CapacityAssessment        `json:"assessment"`
	Generation    int64                           `json:"generation"`
	FencingToken  int64                           `json:"fencing_token"`
	LeaseOwner    string                          `json:"lease_owner"`
	Phase         string                          `json:"phase"`
	Proof         model.CapacityTransitionProof   `json:"proof"`
	Mutation      model.CapacityMutationIssue     `json:"mutation"`
	MutationProof model.CapacityMutationProof     `json:"mutation_proof"`
	Compensation  model.CapacityCompensationIssue `json:"compensation"`
}

// Capacity operations are available only inside the exact protected workflow
// named by the policy. The existing authenticated dispatch/RBAC/policy pipeline
// remains the authority; no actorless scheduler or self-dispatch is introduced.
func executeCapacityWorkflowStep(ctx context.Context, db *sql.DB, workflowRef model.ManifestReference, result model.WorkflowRunStepResult, input map[string]any) model.WorkflowRunStepResult {
	result.Attempts = 1
	fail := func(err error) model.WorkflowRunStepResult {
		result.Error = err.Error()
		result.FinishedAt = time.Now().UTC()
		return result
	}
	data, err := json.Marshal(input)
	if err != nil {
		return fail(err)
	}
	var parsed capacityWorkflowInput
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&parsed); err != nil {
		return fail(fmt.Errorf("capacity input: %w", err))
	}
	recoveryOperation := result.Operation == "capacity.recover" || result.Operation == "capacity.renew_recovery" || result.Operation == "capacity.reconcile" || result.Operation == "capacity.confirm_mutation" || result.Operation == "capacity.record_slot" || result.Operation == "capacity.confirm_compensation"
	if parsed.Policy.ManifestID != "" || (!recoveryOperation && parsed.Policy.Version != nil) || (parsed.Policy.Version != nil && *parsed.Policy.Version < 1) || strings.TrimSpace(parsed.Policy.Namespace) == "" || strings.TrimSpace(parsed.Policy.Name) == "" {
		return fail(fmt.Errorf("capacity policy requires exact active logical namespace/name"))
	}
	policy, err := repository.ResolveManifest(ctx, db, "capacity_policy", parsed.Policy.Namespace, parsed.Policy.Name, parsed.Policy.Version, !recoveryOperation)
	if err != nil {
		return fail(err)
	}
	p, err := manifest.ParseCapacityPolicySpec(policy.Spec)
	if err != nil {
		return fail(err)
	}
	if workflowRef.Kind != "workflow" || workflowRef.Namespace != p.Workflow.Namespace || workflowRef.Name != p.Workflow.Name {
		return fail(fmt.Errorf("capacity policy does not authorize this workflow"))
	}
	wf, err := repository.ResolveManifest(ctx, db, "workflow", p.Workflow.Namespace, p.Workflow.Name, nil, true)
	if err != nil {
		return fail(err)
	}
	if wf.ID != workflowRef.ID || wf.Version != workflowRef.Version {
		return fail(fmt.Errorf("capacity requires the active workflow revision"))
	}
	spec, err := manifest.ParseWorkflowSpec(wf.Spec)
	if err != nil {
		return fail(err)
	}
	if spec.Authorization == nil {
		return fail(fmt.Errorf("capacity requires an authenticated, manifest-authorized workflow"))
	}
	executorID, _ := ctx.Value(capacityInvocationKey{}).(string)
	store := repository.CapacityStore{DB: db, ExecutionEnabled: os.Getenv("YGGDRASIL_CAPACITY_EXECUTION_ENABLED") == "true", WorkflowID: wf.ID, ExecutorID: executorID}
	var intent model.CapacityIntent
	var output any
	switch result.Operation {
	case "capacity.grant_compensation":
		output, err = store.IssueCompensation(ctx, policy, parsed.Compensation)
	case "capacity.confirm_compensation":
		output, err = store.ConfirmCompensation(ctx, policy, parsed.MutationProof)
	case "capacity.grant_mutation":
		output, err = store.IssueMutation(ctx, policy, parsed.Generation, parsed.FencingToken, parsed.LeaseOwner, parsed.Mutation)
	case "capacity.record_slot":
		err = store.RecordMutationSlot(ctx, policy, parsed.Generation, parsed.FencingToken, parsed.LeaseOwner, parsed.Mutation, parsed.MutationProof)
		output = map[string]any{"recorded": err == nil}
	case "capacity.confirm_mutation":
		output, err = store.ConfirmMutation(ctx, policy, parsed.Generation, parsed.FencingToken, parsed.LeaseOwner, parsed.MutationProof)
	case "capacity.assess":
		intent, err = store.Assess(ctx, policy, parsed.Assessment)
	case "capacity.observe":
		intent, err = store.Observe(ctx, policy)
	case "capacity.claim":
		intent, err = store.Claim(ctx, policy, parsed.Generation, parsed.Assessment)
	case "capacity.renew":
		intent, err = store.Renew(ctx, policy, parsed.Generation, parsed.FencingToken, parsed.LeaseOwner)
	case "capacity.advance":
		intent, err = store.Advance(ctx, policy, parsed.Generation, parsed.FencingToken, parsed.LeaseOwner, parsed.Phase, parsed.Proof)
	case "capacity.recover":
		intent, err = store.Recover(ctx, policy, parsed.Generation, parsed.Assessment)
	case "capacity.renew_recovery":
		intent, err = store.RenewRecovery(ctx, policy, parsed.Generation, parsed.FencingToken, parsed.LeaseOwner)
	case "capacity.reconcile":
		intent, err = store.Reconcile(ctx, policy, parsed.Generation, parsed.FencingToken, parsed.LeaseOwner, parsed.Phase, parsed.Proof)
	default:
		return fail(fmt.Errorf("unsupported capacity operation"))
	}
	if err != nil {
		return fail(err)
	}
	intent.LeaseExecutorID = ""
	if output == nil {
		output = intent
	}
	// Convert to plain JSON metadata so subsequent templates use the same map
	// representation as adapter responses. It stays within this protected run.
	data, err = json.Marshal(output)
	if err != nil {
		return fail(err)
	}
	var metadata map[string]any
	if err = json.Unmarshal(data, &metadata); err != nil {
		return fail(err)
	}
	result.Status, result.Error, result.Metadata = "succeeded", "", metadata
	result.FinishedAt = time.Now().UTC()
	return result
}
