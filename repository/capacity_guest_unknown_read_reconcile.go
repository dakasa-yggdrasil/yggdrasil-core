package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// This narrow source tuple identifies the historically deployed GET handler,
// its serialized Guest actor/runtime, and the fixed SELECT-only Notify reader.
// It is not a general exception for other sources, POSTs or incomplete bodies.
const (
	originalReadCoreSource   = "2de33bbca46000d86a6dc0d5162383a6128e3517"
	originalReadGuestSource  = "b50976579e128e9a418ae5209d2b2dfea0fc532b"
	originalReadNotifySource = "86dfa3fb24825123169c73c13fe9d9fc89a27e8e"
	originalReadQuerySHA256  = "621b160fc16e8f8e270a4a981ca407a48509c08836e48f82f02f2f0f667629a2"
)

func (s CapacityStore) previousInstalledCanariesVerifiedTx(ctx context.Context, tx *sql.Tx, policy model.Manifest, p model.CapacityPolicySpec, old model.CapacityIntent, stored guestOriginalStored, enrollment model.CapacityGuestRetirementEnrollment, now time.Time) ([]model.CapacityInstalledGuestPreviousCanary, error) {
	return previousInstalledCanariesWithReadVerifier(ctx, tx, policy, old, now, func(id string, row model.CapacityInstalledGuestPreviousCanary, _ []byte, original capacity.GuestOriginalHTTPReturn) error {
		return s.verifyHistoricalUnknownReadTx(ctx, tx, policy, p, old, stored, enrollment, now, id, row, original)
	})
}

func historicalUnknownReadTransport(row model.CapacityInstalledGuestPreviousCanary, original capacity.GuestOriginalHTTPReturn, now time.Time) bool {
	return row.Phase == "read" && row.PossibleSend && row.Outcome == "held" &&
		!original.PreflightFailed && original.DoFailed && !original.ReadFailed && !original.CloseFailed && original.OriginalContextFailed && original.Status == 0 && original.ResponseBodyScope == capacity.GuestOriginalBodyNoRead && original.CloseReturnedAt.IsZero() && len(original.Body) == 0 &&
		capacity.GuestOriginalHTTPBodyFactsValid(original.ResponseBodyScope, original.ReadReturnedAt, original.ReceivedBodyBytes, original.ResponseSHA256, original.RetainedPrefixBytes, original.RetainedPrefixSHA256, original.ReadFailed) &&
		!original.StartedAt.IsZero() && !original.DoStartedAt.Before(original.StartedAt) && !original.DoReturnedAt.Before(original.DoStartedAt) && !original.DriverReturnedAt.Before(original.DoReturnedAt) && !original.DriverReturnedAt.After(now)
}

// A possible GET stays an unknown historical effect. This validates the exact
// prior signed read, unique nonce, possible-send, parent publication and
// source identities; it neither replays the GET nor treats it as successful.
// New canary operations still require the existing current lease/fence, fresh
// signatures, actor/runtime lifetimes and the original serialized Guest gates.
func (s CapacityStore) verifyHistoricalUnknownReadTx(ctx context.Context, tx *sql.Tx, policy model.Manifest, p model.CapacityPolicySpec, old model.CapacityIntent, stored guestOriginalStored, enrollment model.CapacityGuestRetirementEnrollment, now time.Time, id string, row model.CapacityInstalledGuestPreviousCanary, original capacity.GuestOriginalHTTPReturn) error {
	if tx == nil || s.guestReconcile == nil || p.GuestRetirementBinding == nil || p.GuestNotifyCanaryBinding == nil || old.InstalledGuestReconcile == nil || old.InstalledGuestReconcile.Attempt != 1 || old.InstalledGuestReconcile.NewFence != old.FencingToken || !old.InstalledGuestReconcile.OriginalFailurePreserved || old.InstalledGuestReconcile.OriginalQuiescenceOrNoEffectClaimed || p.GuestRetirementBinding.GuestSourceCommit != originalReadGuestSource || p.GuestNotifyCanaryBinding.NotifySourceCommit != originalReadNotifySource || p.GuestNotifyCanaryBinding.QuerySHA256 != originalReadQuerySHA256 || !historicalUnknownReadTransport(row, original, now) {
		return ErrCapacityConflict
	}
	challenge, err := loadGuestNotifyChallengeTx(ctx, tx, id)
	if err != nil || challenge.ChallengeID != id || capacity.GuestNotifyCanaryPublication(challenge) || challenge.Schema != capacity.GuestNotifyCanaryChallengeSchema || challenge.Purpose != capacity.GuestNotifyCanaryReadPurpose || challenge.UsageClass != "initial_useful_membership" || challenge.PreregistrationID != stored.pre.PreregistrationID || challenge.PolicyID != policy.ID.String() || challenge.PolicyChecksum != policy.Checksum || challenge.WorkflowID != s.WorkflowID.String() || challenge.WorkflowChecksum != s.guestReconcile.workflow.Checksum || challenge.Generation != uint64(old.Generation) || challenge.Fence != uint64(old.FencingToken) || challenge.LeaseOwner != old.LeaseOwner || challenge.EnrollmentSHA256 != capacity.GuestRetirementSHA(enrollment) || !challenge.OriginalDeadline.Before(now) || original.DoStartedAt.After(challenge.OriginalDeadline) || original.DriverReturnedAt.Before(challenge.OriginalDeadline) {
		return ErrCapacityConflict
	}
	var executor, issuer, issuedSHA, challengeSHA string
	if err = tx.QueryRowContext(ctx, `SELECT c.executor_id,a.issuer_actual_source_commit,a.issued_wire_sha256,c.challenge_sha256 FROM public.capacity_guest_notify_canary_challenges c JOIN public.capacity_guest_authority_issues a ON a.issue_kind='canary_challenge' AND a.issue_id=c.id AND a.policy_id=c.policy_id AND a.workflow_id=c.workflow_id AND a.executor_id=c.executor_id WHERE c.id=$1`, id).Scan(&executor, &issuer, &issuedSHA, &challengeSHA); err != nil || executor != old.LeaseExecutorID || issuer != originalReadCoreSource || issuedSHA != challengeSHA {
		return ErrCapacityConflict
	}
	if err = verifyGuestAuthorityIssuerTx(ctx, tx, "canary_challenge", id, issuer, stored.binding, stored.pre); err != nil {
		return ErrCapacityConflict
	}
	var sendSHA string
	var sentAt, deadline time.Time
	if err = tx.QueryRowContext(ctx, `SELECT request_sha256,possible_send_at,original_deadline FROM public.capacity_guest_notify_canary_sends WHERE challenge_id=$1`, id).Scan(&sendSHA, &sentAt, &deadline); err != nil {
		return ErrCapacityConflict
	}
	if deadline.Sub(challenge.OriginalDeadline) > time.Microsecond || challenge.OriginalDeadline.Sub(deadline) > time.Microsecond || original.StartedAt.Before(sentAt.Add(-time.Microsecond)) || capacity.ValidateGuestNotifyCanaryChallenge(challenge, enrollment, sentAt) != nil {
		return ErrCapacityConflict
	}
	request, err := json.Marshal(model.CapacityGuestNotifyCanaryRequest{Challenge: challenge})
	if err != nil || sendSHA != capacity.BusinessCreationSHA256(request) {
		return ErrCapacityConflict
	}
	if _, _, err = loadGuestNotifyPublicationTx(ctx, tx, challenge, enrollment, p); err != nil {
		return ErrCapacityConflict
	}
	return nil
}
