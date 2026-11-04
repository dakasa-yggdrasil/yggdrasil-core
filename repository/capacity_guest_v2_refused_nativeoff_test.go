package repository

import (
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// ADR-0092 pure predicates. The production shape: one closed caller 409 with
// 194 received bytes and no retained body, inside the original deadline.
func v2RefusedCallerFixture() (GuestOriginalCallerReturn, model.CapacityGuestRetirementIntentV2) {
	issued := time.Date(2026, 11, 2, 11, 20, 49, 380000000, time.UTC)
	var i model.CapacityGuestRetirementIntentV2
	i.RequestID, i.AttemptID, i.IssuedAt, i.OriginalDeadline = uuid.NewString(), uuid.NewString(), issued, issued.Add(30*time.Second)
	at := issued.Add(2 * time.Second)
	c := GuestOriginalCallerReturn{RequestID: i.RequestID, AttemptID: i.AttemptID, StartedAt: at, DoStartedAt: at, DoReturnedAt: at.Add(2 * time.Second), ReadReturnedAt: at.Add(2 * time.Second), CloseReturnedAt: at.Add(2 * time.Second), DriverReturnedAt: at.Add(2 * time.Second), OriginalDeadline: i.OriginalDeadline, Status: 409, Body: []byte{}, ReceivedBodyBytes: 194, ResponseBodyScope: capacity.GuestOriginalBodyCompleteRead, ResponseSHA256: strings.Repeat("a", 64), RetainedPrefixBytes: 194, RetainedPrefixSHA256: strings.Repeat("a", 64)}
	return c, i
}

func TestV2RefusedNativeOffCallerRefusalPredicate(t *testing.T) {
	c, i := v2RefusedCallerFixture()
	if !GuestOriginalCallerBodyFactsValid(c) || !v2RefusedCallerClosed(c, i) {
		t.Fatal("closed caller 409 without a retained body refused")
	}
	for name, mutate := range map[string]func(*GuestOriginalCallerReturn){
		"caller_200":          func(c *GuestOriginalCallerReturn) { c.Status = 200 },
		"informational":       func(c *GuestOriginalCallerReturn) { c.Status = 100 },
		"redirect":            func(c *GuestOriginalCallerReturn) { c.Status = 302 },
		"no_status":           func(c *GuestOriginalCallerReturn) { c.Status = 0 },
		"persisted_body":      func(c *GuestOriginalCallerReturn) { c.BodyPersisted = true; c.Body = []byte(`{}`) },
		"retained_bytes":      func(c *GuestOriginalCallerReturn) { c.Body = []byte(`{}`) },
		"preflight_failed":    func(c *GuestOriginalCallerReturn) { c.PreflightFailed = true },
		"do_failed":           func(c *GuestOriginalCallerReturn) { c.DoFailed = true },
		"read_failed":         func(c *GuestOriginalCallerReturn) { c.ReadFailed = true },
		"close_failed":        func(c *GuestOriginalCallerReturn) { c.CloseFailed = true },
		"context_failed":      func(c *GuestOriginalCallerReturn) { c.OriginalContextFailed = true },
		"after_deadline":      func(c *GuestOriginalCallerReturn) { c.DriverReturnedAt = i.OriginalDeadline },
		"foreign_attempt":     func(c *GuestOriginalCallerReturn) { c.AttemptID = uuid.NewString() },
		"foreign_request":     func(c *GuestOriginalCallerReturn) { c.RequestID = uuid.NewString() },
		"renewed_deadline":    func(c *GuestOriginalCallerReturn) { c.OriginalDeadline = c.OriginalDeadline.Add(time.Minute) },
		"started_before_send": func(c *GuestOriginalCallerReturn) { c.StartedAt = i.IssuedAt.Add(-time.Second) },
		"unread_body":         func(c *GuestOriginalCallerReturn) { c.ReadReturnedAt = time.Time{} },
	} {
		v := c
		mutate(&v)
		if v2RefusedCallerClosed(v, i) {
			t.Fatal("non-refusal caller return accepted", name)
		}
	}
}

func v2RefusedRunFixture(current model.CapacityIntent, pre string) []model.WorkflowRunStepResult {
	plan := map[string]any{"mode": "retire", "reason": "failed_installed_disposal", "slot": float64(1), "generation": float64(current.Generation), "fencing_token": float64(current.FencingToken), "lease_owner": current.LeaseOwner, "preregistration_id": pre}
	return []model.WorkflowRunStepResult{
		{ID: "plan-original-guest", Status: "succeeded", Metadata: plan},
		{ID: "provision-original-notify", Status: "skipped"},
		{ID: "refresh-original-membership", Status: "skipped"},
		{ID: "complete-original-provision", Status: "skipped"},
		{ID: "retire-original-guest", Status: "failed", Error: "protected original Guest source step unavailable; HOLD and recover by exact GET", Metadata: map[string]any{"original_guest_refusal_predicate": "original-production-retirement-v2-held"}},
		{ID: "finish-original-retirement", Status: "skipped"},
		{ID: "complete-original-retirement", Status: "skipped"},
	}
}

func TestV2RefusedNativeOffClaimRunPattern(t *testing.T) {
	current := model.CapacityIntent{Generation: 8, FencingToken: 21, LeaseOwner: "00e34a1a-5b50-4d61-bf9e-736503d20702"}
	pre := "b8076d1e-2e34-4acc-8ce1-14ef4a6adc8a"
	if !v2RefusedClaimRunSteps(v2RefusedRunFixture(current, pre), current, pre) {
		t.Fatal("production claim run 0b482d82 shape refused")
	}
	t.Run("later_slot_must_match_the_immutable_claim_baseline", func(t *testing.T) {
		for _, slot := range []int{2, 8} {
			later := current
			later.BaselineSnapshot.Units = slot
			steps := v2RefusedRunFixture(later, pre)
			steps[0].Metadata["slot"] = float64(slot)
			if !v2RefusedClaimRunSteps(steps, later, pre) {
				t.Fatal("exact later-slot claim refused", slot)
			}
			steps[0].Metadata["slot"] = float64(1)
			if v2RefusedClaimRunSteps(steps, later, pre) {
				t.Fatal("first member substituted for failed expansion tail", slot)
			}
		}
	})
	set := func(steps []model.WorkflowRunStepResult, id, status string) []model.WorkflowRunStepResult {
		for n := range steps {
			if steps[n].ID == id {
				steps[n].Status = status
			}
		}
		return steps
	}
	planField := func(key string, value any) []model.WorkflowRunStepResult {
		steps := v2RefusedRunFixture(current, pre)
		steps[0].Metadata[key] = value
		return steps
	}
	for name, steps := range map[string][]model.WorkflowRunStepResult{
		"advance_shape_retire_succeeded_finish_failed": set(set(v2RefusedRunFixture(current, pre), "retire-original-guest", "succeeded"), "finish-original-retirement", "failed"),
		"retire_succeeded":  set(v2RefusedRunFixture(current, pre), "retire-original-guest", "succeeded"),
		"finish_ran":        set(v2RefusedRunFixture(current, pre), "finish-original-retirement", "failed"),
		"plan_failed":       set(v2RefusedRunFixture(current, pre), "plan-original-guest", "failed"),
		"provision_ran":     set(v2RefusedRunFixture(current, pre), "provision-original-notify", "succeeded"),
		"six_steps":         v2RefusedRunFixture(current, pre)[:6],
		"duplicate_step":    append(v2RefusedRunFixture(current, pre)[:6], model.WorkflowRunStepResult{ID: "plan-original-guest", Status: "succeeded"}),
		"plan_hold":         planField("mode", "hold"),
		"plan_other_reason": planField("reason", "failed_installed_explicit_native_cleanup_pending"),
		"plan_other_slot":   planField("slot", float64(2)),
		"plan_other_gen":    planField("generation", float64(9)),
		"plan_other_fence":  planField("fencing_token", float64(22)),
		"plan_other_owner":  planField("lease_owner", uuid.NewString()),
		"plan_other_prereg": planField("preregistration_id", uuid.NewString()),
		"plan_without_metadata": func() []model.WorkflowRunStepResult {
			s := v2RefusedRunFixture(current, pre)
			s[0].Metadata = nil
			return s
		}(),
		// Adapter-style wrapping is not what the internal plan step writes.
		"plan_wrapped_under_output": func() []model.WorkflowRunStepResult {
			s := v2RefusedRunFixture(current, pre)
			s[0].Metadata = map[string]any{"output": s[0].Metadata}
			return s
		}(),
		"retire_legacy_v1_predicate": func() []model.WorkflowRunStepResult {
			s := v2RefusedRunFixture(current, pre)
			s[4].Metadata = map[string]any{"original_guest_refusal_predicate": "original-failed-installed-legacy-v1-held"}
			return s
		}(),
		"retire_preflight_predicate": func() []model.WorkflowRunStepResult {
			s := v2RefusedRunFixture(current, pre)
			s[4].Metadata = map[string]any{"original_guest_refusal_predicate": "original-guest-step-04"}
			return s
		}(),
		"retire_without_predicate": func() []model.WorkflowRunStepResult {
			s := v2RefusedRunFixture(current, pre)
			s[4].Metadata = nil
			return s
		}(),
		"retire_extra_metadata": func() []model.WorkflowRunStepResult {
			s := v2RefusedRunFixture(current, pre)
			s[4].Metadata["request_id"] = uuid.NewString()
			return s
		}(),
		"retire_other_error": func() []model.WorkflowRunStepResult {
			s := v2RefusedRunFixture(current, pre)
			s[4].Error = "adapter timeout"
			return s
		}(),
	} {
		if v2RefusedClaimRunSteps(steps, current, pre) {
			t.Fatal("foreign claim run pattern accepted", name)
		}
	}
	// The plan must name the CLAIMED epoch; a changed current never matches.
	moved := current
	moved.FencingToken++
	if v2RefusedClaimRunSteps(v2RefusedRunFixture(current, pre), moved, pre) {
		t.Fatal("claim run accepted for another fence")
	}
}
