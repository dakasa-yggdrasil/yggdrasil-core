//go:build linux && nativequalification

package repository

import (
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"testing"
	"time"
)

func TestPostlossEmptyOriginalReplyNeverBecomesAccepted(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	v := postlossReplyRead{Schema: "original_source_create_reply_v1", Class: "owning_reply_empty_eof_uncertain", BodySHA256: capacity.BusinessCreationSHA256(nil), ReadStartedAt: start, EOFReturnedAt: start.Add(time.Millisecond), CloseReturnedAt: start.Add(2 * time.Millisecond)}
	if !v.valid(start, start.Add(time.Second)) {
		t.Fatal("complete original empty read must retain uncertain class")
	}
	for _, mutate := range []func(*postlossReplyRead){func(v *postlossReplyRead) { v.Complete = true }, func(v *postlossReplyRead) { v.BodyBytes = 1 }, func(v *postlossReplyRead) { v.BodySHA256 = capacity.BusinessCreationSHA256([]byte("accepted")) }, func(v *postlossReplyRead) { v.ReadStartedAt = time.Time{} }, func(v *postlossReplyRead) { v.CloseReturnedAt = start.Add(2 * time.Second) }} {
		bad := v
		mutate(&bad)
		if bad.valid(start, start.Add(time.Second)) {
			t.Fatal("unknown/changed/original late reply admitted")
		}
	}
}
func TestPostlossChildReissueRequiresRealExpiredNeverRedeemedChild(t *testing.T) {
	at := time.Date(2026, 1, 1, 0, 1, 0, 0, time.UTC)
	old := capacityMutationRecord{Grant: model.CapacityMutationGrant{GrantID: "child-one", CompensationOf: "same-parent", State: "expired", ExpiresAt: at}, ExecutorID: "same-executor"}
	if !postlossUnusedExpiredChild(old, "same-parent", "same-executor", at) {
		t.Fatal("real expired unused child rejected")
	}
	if postlossUnusedExpiredChild(old, "same-parent", "same-executor", at.Add(-time.Nanosecond)) {
		t.Fatal("child lifetime renewed/short-circuited")
	}
	for _, mutate := range []func(*capacityMutationRecord){func(v *capacityMutationRecord) { v.Grant.State = "redeemed" }, func(v *capacityMutationRecord) { v.Grant.State = "issued" }, func(v *capacityMutationRecord) { v.AttemptID = "actual-attempt" }, func(v *capacityMutationRecord) {
		v.SettlementTokenSHA256 = capacity.BusinessCreationSHA256([]byte("actual"))
	}, func(v *capacityMutationRecord) { v.Settlement = &model.CapacityMutationSettleRequest{} }, func(v *capacityMutationRecord) { v.Proof = &model.CapacityMutationProof{} }, func(v *capacityMutationRecord) { v.Grant.CompensationOf = "foreign-parent" }, func(v *capacityMutationRecord) { v.ExecutorID = "foreign-executor" }, func(v *capacityMutationRecord) { v.Grant.ExpiresAt = time.Time{} }} {
		bad := old
		mutate(&bad)
		if postlossUnusedExpiredChild(bad, "same-parent", "same-executor", at) {
			t.Fatal("old effect/foreign/unknown child eligible for fresh attempt")
		}
	}
}
func TestPostlossSelectorsDoNotRequalifyOldUnknownLostReply(t *testing.T) {
	for _, c := range []string{"compensation_unprotected_lost_create_reply", "compensation_protected_lost_create_reply", "positive_original_lifecycle", "owned_provisioner_original", "canonical_failed_floor_recovery"} {
		if canonicalPostlossCase(c) {
			t.Fatalf("unqualified history relabelled: %s", c)
		}
	}
	if !canonicalPostlossCase("canonical_postloss_unprotected_failed_create_reissue") || !canonicalPostlossCase("canonical_postloss_protected_failed_create_reissue") {
		t.Fatal("closed new Source contract missing")
	}
}

func TestPostlossFreshReadCannotReuseOldFailureAsCurrentAuthority(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 2, 0, 0, time.UTC)
	sha := capacity.BusinessCreationSHA256([]byte("old-original-failure"))
	nonce := capacity.BusinessCreationSHA256([]byte("actual-new-challenge"))
	source := "0123456789012345678901234567890123456789"
	e := CanonicalSourceEligibility{NativeCase: "canonical_postloss_protected_failed_create_reissue", GuestSource: source, PreregistrationID: "same-pre", FailureSHA256: sha}
	b := SourceFailureCleanupBody{OriginalProvisioningDeadline: now.Add(time.Second)}
	fresh := CanonicalPostlossFreshFailureRead{Schema: "canonical_postloss_fresh_failure_read_v1", Scope: "READONLY_CURRENT_CENSUS_OLD_FAILURE_UNCHANGED_NOT_QUIESCENCE", NativeCase: e.NativeCase, SourceCommit: source, PreregistrationID: e.PreregistrationID, FailureSHA256: sha, ReadNonceSHA256: nonce, ReadStartedAt: now.Add(-time.Second), Census: model.CapacityGuestRetirementProtectedCensus{Schema: "guest_retirement_protected_cgroup_v1", Scope: "fixed_protected_cgroup_v2", SourceCommit: source, RawCensusSHA256: capacity.BusinessCreationSHA256([]byte("actual-current-empty-cgroup")), ObservedAt: now.Add(-500 * time.Millisecond)}, ReturnedAt: now, OriginalProvisioningDeadline: b.OriginalProvisioningDeadline}
	if !postlossFreshFailureMatches(fresh, e, b, nonce, now, 15) {
		t.Fatal("valid structural current read refused; signature separately required")
	}
	for _, mutate := range []func(*CanonicalPostlossFreshFailureRead){func(v *CanonicalPostlossFreshFailureRead) {
		v.FailureSHA256 = capacity.BusinessCreationSHA256([]byte("restamped-failure"))
	}, func(v *CanonicalPostlossFreshFailureRead) {
		v.ReadNonceSHA256 = capacity.BusinessCreationSHA256([]byte("old-challenge"))
	}, func(v *CanonicalPostlossFreshFailureRead) { v.PreregistrationID = "foreign-pre" }, func(v *CanonicalPostlossFreshFailureRead) { v.SourceCommit = "foreign-source" }, func(v *CanonicalPostlossFreshFailureRead) {
		v.Census.Processes = []model.CapacityGuestRetirementNativeProcess{{PID: 42}}
	}, func(v *CanonicalPostlossFreshFailureRead) { v.ReturnedAt = now.Add(-time.Minute) }, func(v *CanonicalPostlossFreshFailureRead) {
		v.OriginalProvisioningDeadline = now.Add(420 * time.Second)
	}, func(v *CanonicalPostlossFreshFailureRead) { v.Census.RawCensusSHA256 = "" }} {
		bad := fresh
		mutate(&bad)
		if postlossFreshFailureMatches(bad, e, b, nonce, now, 15) {
			t.Fatal("stale/foreign/changed failure or writer census accepted")
		}
	}
}
