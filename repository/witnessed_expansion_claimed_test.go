package repository

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func testWitnessedExpansionClaimOnlyContinuation(t *testing.T) {
	t.Helper()
	_, a, oldEvents, now := witnessedPredelete107Unit(t)
	events := oldEvents[:2]
	claim := events[1]
	a.OriginalGeneration, a.OriginalFencingToken = claim.Generation, claim.FencingToken-1
	events[0].Generation, events[0].FencingToken = a.OriginalGeneration, a.OriginalFencingToken
	current := model.CapacityIntent{Generation: claim.Generation, FencingToken: claim.FencingToken, LeaseOwner: claim.LeaseOwner, LeaseExecutorID: claim.ExecutorID, LeaseExpiresAt: claim.LeaseExpiresAt, WitnessedUnenrolledExpansionCleanupID: a.ID, Decision: model.CapacityDecision{Reason: WitnessedUnenrolledExpansionCleanupMode}}
	type operands struct {
		Events  []WitnessedUnenrolledExpansionCleanupEvent
		Current model.CapacityIntent
	}
	raw := witnessedPredelete107Wire(t, operands{events, current})
	for _, fault := range []string{"complete", "requested_only", "wrong_schema", "wrong_admission", "wrong_child", "gap", "wrong_generation", "wrong_fence", "evidence", "future_record", "regressed_record", "missing_expiry", "lease_live", "current_owner", "current_executor", "current_expiry", "current_generation", "current_fence", "current_cleanup", "current_reason", "empty_run", "read_prefix", "returned_prefix", "issued_prefix", "possible_send_prefix", "repeated_closed", "duplicate_run", "previous_lease_live"} {
		var v operands
		if json.Unmarshal(raw, &v) != nil {
			t.Fatal("declared claim-only copy")
		}
		at := now
		switch fault {
		case "requested_only":
			v.Events = v.Events[:1]
		case "wrong_schema":
			v.Events[1].Schema = "foreign"
		case "wrong_admission":
			v.Events[1].CleanupID = "foreign"
		case "wrong_child":
			v.Events[1].ChildGrantID = "foreign"
		case "gap":
			v.Events[1].Sequence++
		case "wrong_generation":
			v.Events[0].Generation++
		case "wrong_fence":
			v.Events[0].FencingToken++
		case "evidence":
			v.Events[1].Evidence = json.RawMessage("{}")
		case "future_record":
			v.Events[1].RecordedAt = now.Add(time.Second)
		case "regressed_record":
			v.Events[1].RecordedAt = v.Events[0].RecordedAt.Add(-time.Second)
		case "missing_expiry":
			v.Events[1].LeaseExpiresAt = nil
		case "lease_live":
			at = *v.Events[1].LeaseExpiresAt
		case "current_owner":
			v.Current.LeaseOwner = "foreign"
		case "current_executor":
			v.Current.LeaseExecutorID = "foreign"
		case "current_expiry":
			x := v.Current.LeaseExpiresAt.Add(time.Second)
			v.Current.LeaseExpiresAt = &x
		case "current_generation":
			v.Current.Generation++
		case "current_fence":
			v.Current.FencingToken++
		case "current_cleanup":
			v.Current.WitnessedUnenrolledExpansionCleanupID = "foreign"
		case "current_reason":
			v.Current.Decision.Reason = "ordinary"
		case "empty_run":
			v.Events[1].RunID = ""
		case "read_prefix":
			v.Events[1].Stage = "inventory_prepared"
		case "returned_prefix":
			v.Events[1].Stage = "inventory_returned"
		case "issued_prefix":
			v.Events[1].Stage = "issued"
		case "possible_send_prefix":
			v.Events[1].Stage = "possible_send"
		case "repeated_closed", "duplicate_run", "previous_lease_live":
			next := v.Events[1]
			next.Sequence, next.FencingToken = 3, next.FencingToken+1
			next.RunID = "10000000-0000-4000-8000-000000000008"
			next.RecordedAt = next.LeaseExpiresAt.Add(time.Second)
			expires := next.RecordedAt.Add(time.Minute)
			next.LeaseExpiresAt = &expires
			if fault == "duplicate_run" {
				next.RunID = v.Events[1].RunID
			}
			if fault == "previous_lease_live" {
				next.RecordedAt = *v.Events[1].LeaseExpiresAt
			}
			v.Events = append(v.Events, next)
			v.Current.FencingToken, v.Current.LeaseExpiresAt = next.FencingToken, next.LeaseExpiresAt
		}
		last := v.Events[len(v.Events)-1]
		allowed := witnessedExpansionClaimOnlyContinuation(v.Events, last, a, v.Current, at)
		if allowed != (fault == "complete" || fault == "repeated_closed") {
			t.Fatal("closed read-free prefix classification", fault, allowed)
		}
	}
	// The old raw-read path remains separate; a claimed-only owner cannot
	// qualify an invented inventory by entering the 107 return predicate.
	p, a, full, at := witnessedPredelete107Unit(t)
	if witnessedExpansionPredeleteReturnContinuation(full[:2], full[1], a, p, at) {
		t.Fatal("claimed-only prefix became native inventory authority")
	}
}
