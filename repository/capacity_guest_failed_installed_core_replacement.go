package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"regexp"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

const FailedInstalledCoreReplacementMode = "original_canary_core_bound_v1"

var failedInstalledCoreSource = regexp.MustCompile(`^[0-9a-f]{40}$`)

// Empty optional fields preserve canonical old wires and their strict barrier.
// A Core-bound admission names one already-current replacement implementation;
// it is neither an arbitrary future build nor a finding about the old cause.
func failedInstalledReplacementMarkerValid(r FailedInstalledGuestDisposal) bool {
	if r.ReplacementMode == "" {
		return r.OriginalFailedIssuerCoreSource == "" && r.ReplacementCoreSource == ""
	}
	return r.ReplacementMode == FailedInstalledCoreReplacementMode && r.RetirementMode == failedInstalledV2Mode &&
		failedInstalledCoreSource.MatchString(r.OriginalFailedIssuerCoreSource) && failedInstalledCoreSource.MatchString(r.ReplacementCoreSource) &&
		r.OriginalFailedIssuerCoreSource != r.ReplacementCoreSource && r.ReplacementCoreSource == r.ActualCoreSource
}

func failedInstalledReplacementPermitted(binding *model.CapacityGuestRetirementBinding, r FailedInstalledGuestDisposal, currentCore string) bool {
	if !failedInstalledReplacementMarkerValid(r) {
		return false
	}
	if failedInstalledReplacementChanged(binding, r.BlockedGuestSource, r.BlockedProfileSHA256) {
		return true
	}
	return binding != nil && r.ReplacementMode == FailedInstalledCoreReplacementMode &&
		currentCore == r.ReplacementCoreSource && currentCore != r.OriginalFailedIssuerCoreSource &&
		binding.GuestSourceCommit == r.BlockedGuestSource && binding.ProfileManifestSHA256 == r.BlockedProfileSHA256 &&
		binding.ProfileManifest.Profile == "notify-hetzner-elastic"
}

func failedInstalledOriginalCanaryFailure(raw []byte) bool {
	var result struct {
		Steps []model.WorkflowRunStepResult `json:"steps"`
	}
	if json.Unmarshal(raw, &result) != nil {
		return false
	}
	for _, step := range result.Steps {
		if step.ID == "complete-original-provision" {
			return step.Status == "failed" && step.Metadata["original_guest_reconcile_refusal_stage"] == "fresh_original_canary"
		}
	}
	return false
}

// Select the single held read and its accepted publication from the ORIGINAL
// acknowledged failed run, never a later disposal or installed-resume issuer.
// LEFT JOIN keeps a missing actual-issuer record visible as a refusal.
const failedInstalledOriginalCanaryIssuerQuery = `SELECT c.id::text,p.id::text,
 COALESCE(a.issuer_actual_source_commit,''),COALESCE(ap.issuer_actual_source_commit,''),
 COALESCE(a.executor_id,''),COALESCE(ap.executor_id,''),
 COALESCE(a.issued_wire_sha256,''),COALESCE(ap.issued_wire_sha256,'')
 FROM public.capacity_guest_notify_canary_challenges c
 JOIN public.capacity_guest_notify_canary_returns r ON r.challenge_id=c.id AND r.outcome='held'
 JOIN public.capacity_guest_notify_canary_sends sent ON sent.challenge_id=c.id
 JOIN public.capacity_guest_notify_canary_challenges p ON p.id=c.record_challenge_id AND p.phase='publish'
 JOIN public.capacity_guest_notify_canary_returns published ON published.challenge_id=p.id AND published.outcome='accepted'
 JOIN public.workflow_runs w ON w.id=$1 AND (w.workflow_id IS NULL OR w.workflow_id=$3) AND w.status='failed'
 LEFT JOIN public.capacity_guest_authority_issues a ON a.issue_kind='canary_challenge' AND a.issue_id=c.id
 LEFT JOIN public.capacity_guest_authority_issues ap ON ap.issue_kind='canary_challenge' AND ap.issue_id=p.id
 WHERE c.preregistration_id=$2 AND p.preregistration_id=$2 AND c.phase='read'
 AND c.policy_id=$4 AND p.policy_id=$4 AND c.workflow_id=$3 AND p.workflow_id=$3
 AND c.generation=$5 AND p.generation=$5 AND c.fence=$6 AND p.fence=$6
 AND c.executor_id=$7 AND p.executor_id=$7
 AND c.recorded_at>=w.created_at AND c.recorded_at<=w.finished_at
 AND p.recorded_at>=w.created_at AND p.recorded_at<=w.finished_at
 LIMIT 2`

func failedInstalledOriginalCanaryIssuerTx(ctx context.Context, tx *sql.Tx, p model.CapacityPolicySpec, stored guestOriginalStored, receipt model.CapacityGuestOriginalProvisioningReceipt, run string) (string, error) {
	pre := stored.pre
	rows, err := tx.QueryContext(ctx, failedInstalledOriginalCanaryIssuerQuery, run, pre.PreregistrationID, pre.WorkflowID, pre.PolicyID, pre.Generation, pre.Fence, pre.ExecutorID)
	if err != nil {
		return "", err
	}
	type issue struct{ read, publish, source, parentSource, executor, parentExecutor, sha, parentSHA string }
	var found []issue
	for rows.Next() {
		var v issue
		if err = rows.Scan(&v.read, &v.publish, &v.source, &v.parentSource, &v.executor, &v.parentExecutor, &v.sha, &v.parentSHA); err != nil {
			break
		}
		found = append(found, v)
	}
	rowErr, closeErr := rows.Err(), rows.Close()
	if err != nil {
		return "", err
	}
	if rowErr != nil {
		return "", rowErr
	}
	if closeErr != nil {
		return "", closeErr
	}
	if len(found) != 1 {
		return "", ErrCapacityConflict
	}
	v := found[0]
	if !failedInstalledCoreSource.MatchString(v.source) || v.source != v.parentSource || v.source == stored.binding.CoreAuthoritySourceCommit ||
		v.executor != pre.ExecutorID || v.parentExecutor != pre.ExecutorID {
		return "", ErrCapacityConflict
	}
	read, err := loadGuestNotifyPreflightTx(ctx, tx, v.read)
	if err != nil {
		return "", err
	}
	publish, err := loadGuestNotifyPreflightTx(ctx, tx, v.publish)
	if err != nil {
		return "", err
	}
	for _, c := range []model.CapacityGuestNotifyCanaryChallenge{read, publish} {
		if c.PreregistrationID != pre.PreregistrationID || c.PolicyID != pre.PolicyID || c.PolicyChecksum != pre.PolicyChecksum ||
			c.WorkflowID != pre.WorkflowID || c.WorkflowChecksum != pre.WorkflowChecksum || c.Generation != uint64(pre.Generation) || c.Fence != uint64(pre.Fence) ||
			c.ProfileManifestSHA256 != stored.binding.ProfileManifestSHA256 || c.Tuple != stored.witness.Tuple ||
			capacity.ValidateGuestNotifyCanaryPreflight(c, receipt.Enrollment, c.IssuedAt) != nil ||
			verifyGuestAuthorityIssuerTx(ctx, tx, "canary_challenge", c.ChallengeID, v.source, stored.binding, pre) != nil {
			return "", ErrCapacityConflict
		}
	}
	if v.sha != capacity.GuestRetirementSHA(read) || v.parentSHA != capacity.GuestRetirementSHA(publish) || !capacity.GuestNotifyCausalPair(publish, read) {
		return "", ErrCapacityConflict
	}
	return v.source, nil
}
