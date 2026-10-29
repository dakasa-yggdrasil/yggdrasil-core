//go:build linux && nativequalification

package message

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	q "github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacitynativeqemu"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
)

// Verification consumes the same actual public workflow records and native
// source returns used by the producer. No direct IssueMutation, constructed
// context, third slot or generated successful native proof is used here.
func TestCapacityGuestOriginalWorkflowNativeReadsPostgres(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	path := os.Getenv("CAPACITY_GUEST_NATIVE_CORPUS_FILE")
	var c q.Corpus
	if os.Getenv("REQUIRE_CAPACITY_GUEST_NATIVE_CORPUS") != "true" { t.Fatal("owning original corpus is mandatory") }
	if _, err := q.ReadPrivate(ctx, path, &c); err != nil { t.Fatal("closed full corpus required", err) }
	if c.Schema != "core_original_guest_native_qemu_corpus_v1" || !q.PositiveCase(c.NativeCase) || c.NativeCase != os.Getenv("GUEST_ORIGINAL_NATIVE_CASE") || c.CaseOutcome != "ORIGINAL_PROTECTED_LIFECYCLE_JOINED" || !guestOriginalPinnedCoreSource(c.ActualCoreSourceCommit) || len(c.NativeResources) != 2 || len(c.OriginalPreregistrationIDs) != 2 || len(c.OriginalRunIDs) < 2 || len(c.OriginalRunIDs) > 8 {
		t.Fatal("current exact owning two-slot positive corpus required")
	}
	db, err := sql.Open("postgres", os.Getenv("DB_URL"))
	if err != nil { t.Fatal(err) }
	defer db.Close()
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly:true, Isolation:sql.LevelRepeatableRead})
	if err != nil { t.Fatal(err) }
	defer tx.Rollback()
	var rawPolicy []byte
	var policySHA, workflowSHA, workflowName string
	if err := tx.QueryRowContext(ctx, `SELECT p.spec,p.checksum,w.checksum,w.name FROM public.manifests p JOIN public.manifests w ON w.id=$2 WHERE p.id=$1 AND p.kind='capacity_policy' AND w.kind='workflow' AND p.namespace=$3 AND w.namespace=$3`, c.PolicyID,c.WorkflowID,c.Namespace).Scan(&rawPolicy,&policySHA,&workflowSHA,&workflowName); err != nil || policySHA != c.PolicyChecksum || workflowSHA != c.WorkflowChecksum { t.Fatal("actual same-DB manifest identity mismatch",err) }
	var policy model.CapacityPolicySpec
	if json.Unmarshal(rawPolicy,&policy) != nil || policy.GuestRetirementBinding == nil || capacity.ValidateGuestRetirementBinding(policy, policy.GuestRetirementBinding) != nil || policy.GuestRetirementBinding.CoreAuthoritySourceCommit != c.ActualCoreSourceCommit || policy.GuestRetirementBinding.GuestSourceCommit != c.GuestSourceCommit || policy.GuestRetirementBinding.ProfileManifestSHA256 != c.ProfileManifestSHA256 || policy.GuestRetirementBinding.EvidenceClass != "native_qemu_qualification" || policy.GuestRetirementBinding.ProfileManifest.ProductionCatalogSHA256 != "" { t.Fatal("owning qualification source/profile is not the registered actual source") }
	var public []guestActualPublicReturn
	if _, err := q.ReadPrivate(ctx,filepath.Join(filepath.Dir(path),"core-original-public-caller-returns.json"),&public); err != nil || len(public) < 4 || len(public) > 4096 { t.Fatal("full original typed public returns unavailable",err) }
	terminal := map[string]bool{}
	posts := 0
	for _, returned := range public {
		if returned.PreflightFailed || returned.DoFailed || returned.ReadFailed || returned.CloseFailed || returned.OriginalContextFailed || returned.BodyBytes < 1 || !capacity.ValidDigest(returned.BodySHA256) || returned.DoStartedAt.Before(returned.StartedAt) || returned.DoReturnedAt.Before(returned.DoStartedAt) || returned.ReadReturnedAt.Before(returned.DoReturnedAt) || returned.CloseReturnedAt.Before(returned.ReadReturnedAt) || returned.DriverReturnedAt.Before(returned.CloseReturnedAt) { t.Fatal("public transport original owner/read/close incomplete") }
		if returned.Method == "POST" && returned.Path == "/api/v1/workflow-runs" && returned.Status == 202 { posts++; continue }
		if returned.Method != "GET" || returned.Status != 200 { t.Fatal("unexpected actual public caller route/status") }
		for _, id := range c.OriginalRunIDs {
			if returned.Path == "/api/v1/workflow-runs/"+id && returned.WorkflowStatus == "succeeded" {
				if returned.WorkflowFailedStep != "" || returned.WorkflowPredicate != "" || returned.WorkflowErrorClass != "" || returned.WorkflowErrorBytes != 0 || returned.WorkflowErrorSHA256 != "" { t.Fatal("public success retained a contradictory workflow failure") }
				terminal[id] = true
			}
		}
	}
	if posts != len(c.OriginalRunIDs) || len(terminal) != len(c.OriginalRunIDs) { t.Fatal("each corpus run requires its actual POST202 and terminal GET200") }
	seen := map[string]bool{}
	created := map[string]bool{}
	for _, id := range c.OriginalRunIDs {
		parsed, err := uuid.Parse(id)
		if err != nil || seen[id] { t.Fatal("original run identities missing or duplicated") }
		seen[id] = true
		run, err := repository.GetWorkflowRun(ctx,db,parsed)
		var exact int
		if err != nil || run.ID != parsed || run.WorkflowNamespace != c.Namespace || run.WorkflowName != workflowName || run.Status != "succeeded" || run.Error != "" || run.StartedAt == nil || run.FinishedAt == nil || run.FinishedAt.Before(*run.StartedAt) || run.Result == nil || run.Result.Status != "succeeded" { t.Fatal("actual public run did not succeed with full result",err) }
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM (`+q.OriginalWorkflowIdentitySQL+`) exact_original`,id,c.WorkflowID).Scan(&exact); err != nil || exact != 1 { t.Fatal("public run belongs to another immutable workflow",err) }
		principal, ok := run.Metadata[repository.WorkflowRunCreatorMachinePrincipalMetadataKey].(string)
		if !ok || principal == "" { t.Fatal("original run lacks server-authored public machine principal") }
		mode, ok := run.Inputs["mode"].(string)
		if !ok || (mode != "baseline" && mode != "burst" && mode != "observe_reduction_demand" && mode != "retire") || len(run.Result.Steps) != 6 { t.Fatal("original public workflow mode/step set changed") }
		stepIDs := map[string]bool{}
		for _, step := range run.Result.Steps {
			if stepIDs[step.ID] || step.Error != "" { t.Fatal("duplicated or failed original workflow step") }
			stepIDs[step.ID] = true
			shouldRun := false
			switch step.ID {
			case "original_assess": shouldRun = true
			case "original_claim": shouldRun = mode != "observe_reduction_demand"
			case policy.GuestRetirementBinding.ProfileManifest.OriginalProvisioningStepID, "original_echo_qualified": shouldRun = mode == "baseline" || mode == "burst"
			case "original_burst_retire", "original_burst_native_off": shouldRun = mode == "retire"
			default: t.Fatal("unregistered step entered original workflow")
			}
			if !shouldRun {
				if step.Status != "skipped" { t.Fatal("original conditional branch did not skip") }
				continue
			}
			if step.Status != "succeeded" || step.StartedAt.IsZero() || step.FinishedAt.Before(step.StartedAt) { t.Fatal("selected actual workflow step failed or returned without lifecycle") }
			if step.Operation != capacity.ProvisionOriginalGuestOperation { continue }
			var output struct {
				Preregistration model.CapacityGuestOriginalProvisioningPreregistration `json:"preregistration"`
				WitnessSHA256 string `json:"witness_sha256"`
				Receipt model.CapacityGuestOriginalProvisioningReceipt `json:"receipt"`
				UsefulCapacityKnown bool `json:"useful_capacity_known"`
			}
			raw, err := json.Marshal(step.Metadata)
			flag, present := step.Metadata["useful_capacity_known"].(bool)
			if err != nil || capacity.DecodeGuestLifecycle(raw,&output) != nil || !present || flag || output.UsefulCapacityKnown || !capacity.ValidDigest(output.WitnessSHA256) { t.Fatal("native creation was promoted to useful readiness or lost source metadata") }
			pre := output.Preregistration
			if pre.Slot < 1 || pre.Slot > 2 || pre.PreregistrationID != c.OriginalPreregistrationIDs[pre.Slot-1] || pre.CoreSourceCommit != c.ActualCoreSourceCommit || pre.PolicyID != c.PolicyID || pre.PolicyChecksum != c.PolicyChecksum || pre.WorkflowID != c.WorkflowID || pre.WorkflowChecksum != c.WorkflowChecksum || pre.ProfileManifestSHA256 != c.ProfileManifestSHA256 || pre.OriginalWorkflowStepTimeoutSeconds != 600 || !pre.OriginalDeadline.After(pre.ReservedAt) || pre.OriginalDeadline.Sub(pre.ReservedAt) > 420*time.Second || pre.OriginalDeadline.After(pre.OriginalWorkflowContextDeadline) || created[pre.PreregistrationID] { t.Fatal("workflow output lost original source-owned two-slot identity/budget") }
			var storedWire []byte
			var consistent bool
			if err := tx.QueryRowContext(ctx, `SELECT original_wire,preregistration_record=convert_from(original_wire,'UTF8')::jsonb FROM public.capacity_vm_provisioning_preregistrations WHERE id=$1`,pre.PreregistrationID).Scan(&storedWire,&consistent); err != nil || !consistent || capacity.GuestRetirementSHA(pre) != capacity.BusinessCreationSHA256(storedWire) { t.Fatal("public workflow output differs from full original preregistration",err) }
			resource := c.NativeResources[pre.Slot-1]
			if resource.Slot != pre.Slot || output.Receipt.Enrollment.Statement.Tuple.ResourceID != resource.ResourceID || output.Receipt.Enrollment.Statement.Tuple.CreatedAt != resource.ResourceCreatedAt || capacity.GuestRetirementSHA(output.Receipt.Enrollment) != resource.EnrollmentSHA256 { t.Fatal("public output adopted another native resource") }
			created[pre.PreregistrationID] = true
		}
	}
	if len(created) != 2 { t.Fatal("both original public creation steps must exist exactly once") }
	for n, resource := range c.NativeResources {
		var applied struct {
			Schema string `json:"schema"`
			CoreSource string `json:"core_source"`
			Slot int `json:"slot"`
			GrantID string `json:"grant_id"`
			ResourceID string `json:"resource_id"`
			ProofSHA256 string `json:"proof_sha256"`
			Events int `json:"canonical_events"`
			Members int `json:"registered_members"`
		}
		if _, err := q.ReadPrivate(ctx,filepath.Join(q.SlotDirectory(filepath.Dir(path),n+1),"canonical-apply-contract.json"),&applied); err != nil { t.Fatal("original same-proof double confirmation contract missing",err) }
		var record struct { Proof *model.CapacityMutationProof `json:"proof"` }
		var grantID string
		var grantWire []byte
		if err := tx.QueryRowContext(ctx,`SELECT p.create_grant_id::text,g.grant_record FROM public.capacity_vm_provisioning_preregistrations p JOIN public.capacity_mutation_grants g ON g.id=p.create_grant_id WHERE p.id=$1 AND g.namespace=$2`,c.OriginalPreregistrationIDs[n],c.Namespace).Scan(&grantID,&grantWire); err != nil || json.Unmarshal(grantWire,&record) != nil || record.Proof == nil { t.Fatal("actual stored native confirmation absent",err) }
		if applied.Schema != "original_guest_canonical_apply_once_v1" || applied.CoreSource != c.ActualCoreSourceCommit || applied.Slot != n+1 || applied.GrantID != grantID || applied.ResourceID != resource.ResourceID || applied.Events != 1 || applied.Members != 1 || applied.ProofSHA256 != capacity.GuestRetirementSHA(*record.Proof) || record.Proof.ObservedCreationGrantID != grantID || record.Proof.ResourceID != resource.ResourceID || !record.Proof.OwnerVerified || !record.Proof.SpecVerified { t.Fatal("canonical once contract/proof does not join real two-slot workflow") }
		var events int
		if err := tx.QueryRowContext(ctx,`SELECT count(*) FROM public.event_log WHERE idempotency_key=$1 AND metadata->>'namespace'=$2`,"capacity-mutation/"+grantID,c.Namespace).Scan(&events); err != nil || events != 1 { t.Fatal("native confirmation duplicated or lost canonical event",err) }
	}
}

type guestActualPublicReturn struct {
	DoStartedAt           time.Time `json:"do_started_at"`
	DriverReturnedAt      time.Time `json:"driver_returned_at"`
	PreflightFailed       bool      `json:"preflight_failed"`
	DoFailed              bool      `json:"do_failed"`
	ReadFailed            bool      `json:"read_failed"`
	CloseFailed           bool      `json:"close_failed"`
	Method                string    `json:"method"`
	Path                  string    `json:"path"`
	StartedAt             time.Time `json:"started_at"`
	DoReturnedAt          time.Time `json:"do_returned_at"`
	ReadReturnedAt        time.Time `json:"read_returned_at"`
	CloseReturnedAt       time.Time `json:"close_returned_at"`
	Status                int       `json:"status"`
	BodySHA256            string    `json:"body_sha256"`
	BodyBytes             int       `json:"body_bytes"`
	OriginalContextFailed bool      `json:"original_context_failed"`
	WorkflowStatus        string    `json:"workflow_status"`
	WorkflowFailedStep    string    `json:"workflow_failed_step"`
	WorkflowPredicate     string    `json:"workflow_predicate"`
	WorkflowErrorClass    string    `json:"workflow_error_class"`
	WorkflowErrorBytes    int       `json:"workflow_error_bytes"`
	WorkflowErrorSHA256   string    `json:"workflow_error_sha256"`
}

// Test binaries are not VCS-stamped, so the corpus is bound to the Core pin
// the native job checked out instead of the build info revision.
func guestOriginalPinnedCoreSource(value string) bool {
	pin := os.Getenv("CORE_ORIGINAL_GUEST_NATIVE_SOURCE_COMMIT")
	if len(pin) != 40 || strings.Trim(pin, "0123456789abcdef") != "" {
		return false
	}
	return value == pin
}
