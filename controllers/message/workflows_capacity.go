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
)

type capacityWorkflowInput struct {
	Policy       model.ManifestSelector        `json:"policy"`
	Assessment   model.CapacityAssessment      `json:"assessment"`
	Generation   int64                         `json:"generation"`
	FencingToken int64                         `json:"fencing_token"`
	LeaseOwner   string                        `json:"lease_owner"`
	Phase        string                        `json:"phase"`
	Proof        model.CapacityTransitionProof `json:"proof"`
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
	if parsed.Policy.ManifestID != "" || parsed.Policy.Version != nil || strings.TrimSpace(parsed.Policy.Namespace) == "" || strings.TrimSpace(parsed.Policy.Name) == "" {
		return fail(fmt.Errorf("capacity policy requires exact active logical namespace/name"))
	}
	policy, err := repository.ResolveManifest(ctx, db, "capacity_policy", parsed.Policy.Namespace, parsed.Policy.Name, nil, true)
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
	store := repository.CapacityStore{DB: db, ExecutionEnabled: os.Getenv("YGGDRASIL_CAPACITY_EXECUTION_ENABLED") == "true", WorkflowID: wf.ID}
	var intent model.CapacityIntent
	switch result.Operation {
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
	default:
		return fail(fmt.Errorf("unsupported capacity operation"))
	}
	if err != nil {
		return fail(err)
	}
	// Convert to plain JSON metadata so subsequent templates use the same map
	// representation as adapter responses. It stays within this protected run.
	data, err = json.Marshal(intent)
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
