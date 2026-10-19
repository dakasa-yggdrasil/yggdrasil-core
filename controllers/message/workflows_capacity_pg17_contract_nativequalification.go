//go:build linux && nativequalification

package message

import (
	"context"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	q "github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacitynativeqemu"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"path/filepath"
)

// Assertion results are produced only after the actual original calls return.
// They identify bounded asserted properties, not equivalence of a whole test.
// No callback input or uploaded receipt can supply a successful assertion.
type PG17AssertionResult struct {
	Schema          string   `json:"schema"`
	CaseID          int      `json:"case_id"`
	OriginalTest    string   `json:"original_test"`
	SourceCase      string   `json:"source_case"`
	CoreSource      string   `json:"core_source"`
	PolicyID        string   `json:"policy_id"`
	WorkflowID      string   `json:"workflow_id"`
	Checks          []string `json:"checks"`
	EvidenceSHA256  []string `json:"evidence_sha256"`
	NativeQualified bool     `json:"native_qualified"`
}

var pg17OriginalNames = map[int]string{
	1:  "TestCapacityMutationCompensationPostgres/unprotected_failed_create",
	2:  "TestCapacityMutationCompensationPostgres/protected_failed_create_without_serving_membership",
	3:  "TestCapacityMutationCompensationPostgres/lost_create_reply_uses_separate_native_readback",
	4:  "TestCapacityMutationCompensationPostgres/protected_lost_create_reply",
	5:  "TestCapacityMutationFailedFloorRecoveryPostgres",
	6:  "TestCapacityMutationPostgres/paused_unredeemed_expiry_can_reconcile_without_native_fence",
	7:  "TestCapacityMutationPostgres/concurrent_issue_and_single_redemption",
	8:  "TestCapacityMutationPostgres/lost_reply_same_attempt_is_read_only",
	9:  "TestCapacityMutationPostgres/settlement_nonce_scope_pause_and_private_receipt",
	10: "TestCapacityMutationPostgres/unresolved_mutation_blocks_terminal_and_expiry_reissue",
	11: "TestCapacityMutationPostgres/native_action_cannot_replace_transport_settlement",
	12: "TestCapacityMutationPostgres/historical_recovery_confirms_after_pause",
	15: "TestCapacityMutationPostgres/policy_instance_type_and_executor_fences/policy",
	16: "TestCapacityMutationPostgres/policy_instance_type_and_executor_fences/instance",
	17: "TestCapacityMutationPostgres/policy_instance_type_and_executor_fences/type",
	19: "TestCapacityMutationNativeWorkflowPostgres/native_reads_confirm_once_without_readiness_claim",
	20: "TestCapacityMutationHTTPPostgres",
}

// Retain a closed bounded assertion family in the existing private custody
// directory. This creates no executor, admission, profile or Native credit.
func PG17RetainAssertions(ctx context.Context, realm *q.Realm, policy model.Manifest, workflowID string, slot int, family string, rows []PG17AssertionResult) error {
	if realm == nil || ctx.Err() != nil || workflowID == "" || len(rows) == 0 {
		return errOriginalGuestStep
	}
	switch family {
	case "compensation-eligibility", "compensation-pre-settlement", "compensation-confirm", "compensation-postloss-reissue", "failed-floor", "failed-floor-completed", "mutation-create", "mutation-confirm", "mutation-terminal", "mutation-historical", "source-fence", "native-workflow", "http-callback":
	default:
		return errOriginalGuestStep
	}
	seen := map[int]bool{}
	for _, row := range rows {
		name, ok := pg17OriginalNames[row.CaseID]
		if !ok || seen[row.CaseID] || row.Schema != "core_pg17_assertion_v1" || row.OriginalTest != name || row.SourceCase != realm.Request.NativeCase || row.CoreSource != capacity.CurrentGuestCoreSource() || row.PolicyID != policy.ID.String() || row.WorkflowID != workflowID || row.NativeQualified || len(row.Checks) == 0 || len(row.EvidenceSHA256) == 0 {
			return errOriginalGuestStep
		}
		seen[row.CaseID] = true
		checks := map[string]bool{}
		for _, check := range row.Checks {
			if len(check) < 1 || len(check) > 128 || check[0] < 'a' || check[0] > 'z' || checks[check] {
				return errOriginalGuestStep
			}
			for _, character := range check {
				if !(character >= 'a' && character <= 'z') && !(character >= '0' && character <= '9') && character != '_' {
					return errOriginalGuestStep
				}
			}
			checks[check] = true
		}
		for _, sha := range row.EvidenceSHA256 {
			if !capacity.ValidDigest(sha) {
				return errOriginalGuestStep
			}
		}
	}
	directory := realm.PrivateDirectory
	if slot != 0 {
		if slot < 1 || slot > 2 {
			return errOriginalGuestStep
		}
		directory = q.SlotDirectory(directory, slot)
	}
	_, err := q.Publish(ctx, filepath.Join(directory, "pg17-"+family+"-assertions.json"), rows)
	return err
}
