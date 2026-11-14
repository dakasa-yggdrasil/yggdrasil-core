package repository

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"reflect"
	"regexp"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

const installedReadinessHandoffSchema = "installed_readiness_exhausted_handoff_v1"
const installedReadinessHandoffRecordSchema = "installed_readiness_exhausted_handoff_record_v1"
const installedReadinessHandoffReason = "installed_readiness_exhausted_terminal_readonly_reconcile"

var installedReadinessHandoffSource = regexp.MustCompile(`^[a-f0-9]{40}$`)

// The record has no hash of the marker or successor wire: the marker names
// this record's digest, and both later wires are retained in separate columns.
// This keeps the immutable archive free of a circular hash dependency.
type installedReadinessHandoffRecord struct {
	Schema                              string    `json:"schema"`
	ID                                  string    `json:"id"`
	OriginalDispositionID               string    `json:"original_disposition_id"`
	Namespace                           string    `json:"namespace"`
	Environment                         string    `json:"environment"`
	Domain                              string    `json:"domain"`
	Dimension                           string    `json:"dimension"`
	PolicyID                            string    `json:"policy_id"`
	PolicyChecksum                      string    `json:"policy_checksum"`
	WorkflowID                          string    `json:"workflow_id"`
	WorkflowChecksum                    string    `json:"workflow_checksum"`
	ExhaustedGeneration                 int64     `json:"exhausted_generation"`
	ExhaustedFence                      int64     `json:"exhausted_fence"`
	ExhaustedAttempts                   int       `json:"exhausted_attempts"`
	SuccessorGeneration                 int64     `json:"successor_generation"`
	SuccessorFence                      int64     `json:"successor_fence"`
	SuccessorJobID                      string    `json:"successor_job_id"`
	SuccessorRunID                      string    `json:"successor_run_id"`
	SuccessorExecutorID                 string    `json:"successor_executor_id"`
	SuccessorLeaseOwner                 string    `json:"successor_lease_owner"`
	SuccessorLeaseExpiresAt             time.Time `json:"successor_lease_expires_at"`
	AdmittingCoreSource                 string    `json:"admitting_core_source"`
	OldIssuerCoreSource                 string    `json:"old_issuer_core_source"`
	Profile                             string    `json:"profile"`
	MembersCount                        int       `json:"members_count"`
	OriginalIntentSHA256                string    `json:"original_intent_sha256"`
	FailedJobsSHA256                    string    `json:"failed_jobs_sha256"`
	FailedRunsSHA256                    string    `json:"failed_runs_sha256"`
	PreviousCanariesSHA256              string    `json:"previous_canaries_sha256"`
	MembersSHA256                       string    `json:"members_sha256"`
	RecordedAt                          time.Time `json:"recorded_at"`
	OldGenerationOutcome                string    `json:"old_generation_outcome"`
	OriginalFailurePreserved            bool      `json:"original_failure_preserved"`
	OriginalQuiescenceOrNoEffectClaimed bool      `json:"original_quiescence_or_no_effect_claimed"`
	ProviderMutationsAuthorized         bool      `json:"provider_mutations_authorized"`
	ChildHandoffAllowed                 bool      `json:"child_handoff_allowed"`
}

type installedReadinessHandoffHistory struct {
	AuthorityMarkers []json.RawMessage `json:"authority_markers"`
	Challenges       []json.RawMessage `json:"challenges"`
	Returns          []json.RawMessage `json:"returns"`
	Sends            []json.RawMessage `json:"sends"`
}

type installedReadinessHandoffArchive struct {
	record                                installedReadinessHandoffRecord
	originalWire, intentWire, membersWire []byte
	markerWire, successorWire             []byte
}

func installedReadinessHandoffCandidate(old model.CapacityIntent, policy model.Manifest, p model.CapacityPolicySpec, now time.Time) bool {
	m := old.InstalledGuestReconcile
	return m != nil && old.InstalledReadinessHandoff == nil && old.FailedExpansionTerminalReconcile == nil && old.FailedUnwitnessedExpansionCleanupID == "" && old.FailedInstalledDisposal == nil && old.FailedServingDisposal == nil && old.RetirementForward == nil && old.OriginalNotifyWindow == nil && !old.RecoveryOnly && !old.FloorDegraded && (old.Phase == "preparing" || old.Phase == "prepared" || old.Phase == "canary") && old.PolicyID == policy.ID && old.PolicyChecksum == policy.Checksum && old.Generation > 0 && old.Generation < maxCapacityGeneration && old.FencingToken > 0 && old.FencingToken < maxCapacityGeneration && old.LeaseExpiresAt != nil && !old.LeaseExpiresAt.After(now) && old.Decision.Units >= 2 && old.Decision.Units >= p.Floor && old.Decision.Units <= p.Ceiling && old.Decision.Units <= 8 && m.Schema == "installed_original_guest_readiness_reconcile_v1" && m.Attempt == 3 && m.NewFence == old.FencingToken && m.OriginalFence > 0 && m.OriginalFence+3 == old.FencingToken && validCapacityExecutor(old.LeaseOwner) && old.LeaseExecutorID == m.NewExecutorID && validCapacityExecutor(m.NewExecutorID) && m.OriginalGeneration == old.Generation && m.InstalledProvisionTimeoutDispositionID != "" && m.OriginalFailurePreserved && !m.OriginalQuiescenceOrNoEffectClaimed && p.ExecutionEnabled && p.GuestRetirementBinding != nil && p.GuestNotifyReconcileBinding != nil && capacity.ValidateGuestNotifyReconcileBinding(p) == nil
}

func bindInstalledReadinessHandoff(s CapacityStore, m *model.CapacityInstalledReadinessHandoff) CapacityStore {
	s.installedReadinessHandoff = m
	source := *s.guestReconcile
	source.mode = "provision" // Private phase/canary authority; never a provider grant.
	s.guestReconcile = &source
	return s
}

func installedReadinessHandoffMarkerValid(m *model.CapacityInstalledReadinessHandoff, current model.CapacityIntent) bool {
	return m != nil && m.Schema == installedReadinessHandoffSchema && validCapacityExecutor(m.HandoffID) && capacity.ValidDigest(m.HandoffSHA256) && validCapacityExecutor(m.OriginalDispositionID) && m.ExhaustedGeneration > 0 && m.ExhaustedFence > 0 && m.ClaimGeneration == m.ExhaustedGeneration+1 && m.ClaimFence == m.ExhaustedFence+1 && current.Generation == m.ClaimGeneration && current.FencingToken == m.ClaimFence && validCapacityExecutor(m.RunID) && validCapacityExecutor(m.ExecutorID) && installedReadinessHandoffSource.MatchString(m.CoreSource)
}

func readInstalledReadinessHandoffTx(ctx context.Context, tx *sql.Tx, id string) (installedReadinessHandoffArchive, error) {
	var a installedReadinessHandoffArchive
	var digest string
	var valid bool
	err := tx.QueryRowContext(ctx, `SELECT original_wire,record_sha256,original_intent_wire,members_wire,marker_wire,successor_intent_wire,public.installed_readiness_handoff_valid(h) FROM public.capacity_installed_readiness_exhausted_handoffs h WHERE id=$1 FOR SHARE`, id).Scan(&a.originalWire, &digest, &a.intentWire, &a.membersWire, &a.markerWire, &a.successorWire, &valid)
	if err != nil {
		return a, err
	}
	if !valid || capacity.BusinessCreationSHA256(a.originalWire) != digest || json.Unmarshal(a.originalWire, &a.record) != nil || a.record.Schema != installedReadinessHandoffRecordSchema || a.record.ID != id {
		return a, ErrCapacityConflict
	}
	canonical, err := json.Marshal(a.record)
	if err != nil || !bytes.Equal(canonical, a.originalWire) {
		return a, ErrCapacityConflict
	}
	return a, nil
}

// All three authority markers are original producer wires, in attempt order.
// No missing/extra owner, unacknowledged result or partial old response is
// selected away by a favorable LIMIT or reconstructed as success.
func (s CapacityStore) installedReadinessHandoffHistoryTx(ctx context.Context, tx *sql.Tx, policy model.Manifest, p model.CapacityPolicySpec, old model.CapacityIntent, now time.Time) ([]byte, []byte, []byte, string, error) {
	m := old.InstalledGuestReconcile
	rows, err := tx.QueryContext(ctx, `SELECT to_jsonb(a)::text,decode(a.original_record->>'installed_reconcile_marker_base64','base64'),a.issuer_actual_source_commit FROM public.capacity_guest_authority_issues a WHERE a.issue_kind='installed_reconcile' AND a.policy_id=$1 AND a.workflow_id=$2 AND convert_from(decode(a.original_record->>'installed_reconcile_marker_base64','base64'),'UTF8')::jsonb->>'installed_provision_timeout_disposition_id'=$3 ORDER BY (convert_from(decode(a.original_record->>'installed_reconcile_marker_base64','base64'),'UTF8')::jsonb->>'attempt')::integer`, policy.ID, s.WorkflowID, m.InstalledProvisionTimeoutDispositionID)
	if err != nil {
		return nil, nil, nil, "", err
	}
	history := installedReadinessHandoffHistory{AuthorityMarkers: []json.RawMessage{}, Challenges: []json.RawMessage{}, Returns: []json.RawMessage{}, Sends: []json.RawMessage{}}
	markers := []model.CapacityInstalledGuestReconcile{}
	oldSource := ""
	for rows.Next() {
		var row, wire []byte
		var source string
		var marker model.CapacityInstalledGuestReconcile
		if err = rows.Scan(&row, &wire, &source); err != nil || len(markers) >= 3 || len(row) > 1<<20 || len(wire) > 1<<20 || json.Unmarshal(wire, &marker) != nil {
			rows.Close()
			return nil, nil, nil, "", ErrCapacityConflict
		}
		canonical, e := json.Marshal(marker)
		if e != nil || !bytes.Equal(canonical, wire) || !installedReadinessHandoffSource.MatchString(source) || source == capacity.CurrentGuestCoreSource() || oldSource != "" && oldSource != source || marker.Attempt != len(markers)+1 || marker.Schema != m.Schema || marker.InstalledProvisionTimeoutDispositionID != m.InstalledProvisionTimeoutDispositionID || marker.OriginalJobID != m.OriginalJobID || marker.OriginalRunID != m.OriginalRunID || marker.OriginalRunSHA256 != m.OriginalRunSHA256 || marker.OriginalGeneration != old.Generation || marker.OriginalFence != m.OriginalFence || marker.PreregistrationID != m.PreregistrationID || marker.NewFence != old.FencingToken-int64(2-len(markers)) || marker.PreviousFence != marker.NewFence-1 || !marker.OriginalFailurePreserved || marker.OriginalQuiescenceOrNoEffectClaimed {
			rows.Close()
			return nil, nil, nil, "", ErrCapacityConflict
		}
		oldSource = source
		markers = append(markers, marker)
		history.AuthorityMarkers = append(history.AuthorityMarkers, append(json.RawMessage(nil), row...))
	}
	rowErr, closeErr := rows.Err(), rows.Close()
	if rowErr != nil || closeErr != nil || len(markers) != 3 || !reflect.DeepEqual(markers[2], *m) {
		return nil, nil, nil, "", ErrCapacityConflict
	}
	jobs, runs := []json.RawMessage{}, []json.RawMessage{}
	for i, marker := range markers {
		if marker.NewRunID == s.OriginalRunID.String() || i == 0 && (marker.PreviousResumeRunID != "" || marker.PreviousResumeRunSHA256 != "") || i > 0 && (marker.PreviousResumeRunID != markers[i-1].NewRunID || marker.PreviousResumeRunSHA256 != capacity.BusinessCreationSHA256(runs[i-1])) {
			return nil, nil, nil, "", ErrCapacityConflict
		}
		wire, e := s.failedExpansionTerminalFailedRunTx(ctx, tx, policy, p, marker.NewRunID, now)
		if e != nil {
			return nil, nil, nil, "", e
		}
		if len(wire) > 8<<20 {
			return nil, nil, nil, "", ErrCapacityConflict
		}
		var job, result []byte
		if e = tx.QueryRowContext(ctx, `SELECT to_jsonb(j)::text,w.result FROM public.capacity_dispatch_jobs j JOIN public.workflow_runs w ON w.id=j.run_id WHERE j.run_id=$1 FOR SHARE OF j,w`, marker.NewRunID).Scan(&job, &result); e != nil || len(job) > 1<<20 || !failedInstalledResumeResult(result, old.Generation, marker.NewFence) {
			return nil, nil, nil, "", ErrCapacityConflict
		}
		var failed model.RunWorkflowResponse
		if json.Unmarshal(result, &failed) != nil {
			return nil, nil, nil, "", ErrCapacityConflict
		}
		stage := ""
		for _, step := range failed.Steps {
			if step.ID == "refresh-original-membership" {
				stage, _ = step.Metadata["original_guest_reconcile_refusal_stage"].(string)
			}
		}
		if stage != "advance_prepared" {
			return nil, nil, nil, "", ErrCapacityConflict
		}
		jobs, runs = append(jobs, json.RawMessage(job)), append(runs, json.RawMessage(wire))
	}
	for _, entry := range []struct{ key, table, order string }{{"challenges", "capacity_guest_notify_canary_challenges", "x.id"}, {"returns", "capacity_guest_notify_canary_returns", "x.challenge_id"}, {"sends", "capacity_guest_notify_canary_sends", "x.challenge_id"}} {
		q := `SELECT to_jsonb(x)::text FROM public.` + entry.table + ` x `
		if entry.key == "challenges" {
			q += `WHERE x.policy_id=$1 AND x.generation=$2 AND x.fence BETWEEN $3 AND $4 ORDER BY ` + entry.order
		} else {
			q += `JOIN public.capacity_guest_notify_canary_challenges c ON c.id=x.challenge_id WHERE c.policy_id=$1 AND c.generation=$2 AND c.fence BETWEEN $3 AND $4 ORDER BY ` + entry.order
		}
		r, e := tx.QueryContext(ctx, q, policy.ID, old.Generation, old.FencingToken-2, old.FencingToken)
		if e != nil {
			return nil, nil, nil, "", e
		}
		count, size := 0, 0
		for r.Next() {
			var wire []byte
			if e = r.Scan(&wire); e != nil {
				r.Close()
				return nil, nil, nil, "", e
			}
			count++
			size += len(wire)
			if count > 256 || size > 8<<20 {
				r.Close()
				return nil, nil, nil, "", ErrCapacityConflict
			}
			switch entry.key {
			case "challenges":
				history.Challenges = append(history.Challenges, json.RawMessage(wire))
			case "returns":
				history.Returns = append(history.Returns, json.RawMessage(wire))
			case "sends":
				history.Sends = append(history.Sends, json.RawMessage(wire))
			}
		}
		rowErr, closeErr = r.Err(), r.Close()
		if rowErr != nil || closeErr != nil {
			return nil, nil, nil, "", ErrCapacityConflict
		}
	}
	jw, e := json.Marshal(jobs)
	if e != nil {
		return nil, nil, nil, "", e
	}
	rw, e := json.Marshal(runs)
	if e != nil {
		return nil, nil, nil, "", e
	}
	cw, e := json.Marshal(history)
	if e != nil {
		return nil, nil, nil, "", e
	}
	if len(jw) > 3<<20 || len(rw) > 8<<20 || len(cw) > 8<<20 {
		return nil, nil, nil, "", ErrCapacityConflict
	}
	return jw, rw, cw, oldSource, nil
}

// TryClaimInstalledReadinessHandoff is a one-shot successor of the immutable
// exhausted M98 origin. It does not increase or reset InstalledGuestReconcile.
func (s CapacityStore) TryClaimInstalledReadinessHandoff(ctx context.Context, policy model.Manifest, assessment model.CapacityAssessment) (CapacityStore, model.CapacityIntent, bool, error) {
	var zero model.CapacityIntent
	if s.OriginalRunID == uuid.Nil {
		return s, zero, false, nil
	}
	if s.DB == nil {
		return s, zero, false, ErrCapacityConflict
	}
	p, err := parseCapacityPolicy(policy)
	if err != nil {
		return s, zero, false, err
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return s, zero, false, err
	}
	defer tx.Rollback()
	bound, next, eligible, err := s.tryClaimInstalledReadinessHandoffTx(ctx, tx, policy, p, assessment)
	if err != nil || !eligible {
		return bound, next, eligible, err
	}
	if !guestReconcileLive(ctx) {
		return s, next, false, ErrCapacityLease
	}
	if err = tx.Commit(); err != nil {
		return s, next, false, err
	}
	return bound, next, true, nil
}

// The same locked admission is used by the public transaction. Keeping its
// transaction explicit also permits rollback-only contract regression cases.
func (s CapacityStore) tryClaimInstalledReadinessHandoffTx(ctx context.Context, tx *sql.Tx, policy model.Manifest, p model.CapacityPolicySpec, assessment model.CapacityAssessment) (CapacityStore, model.CapacityIntent, bool, error) {
	var zero model.CapacityIntent
	if s.OriginalRunID == uuid.Nil {
		return s, zero, false, nil
	}
	if tx == nil || s.DB == nil || s.guestReconcile == nil || s.guestReconcile.step.Use.Operation != capacity.PlanOriginalGuestOperation || !validCapacityExecutor(s.ExecutorID) || !guestReconcileLive(ctx) {
		return s, zero, false, ErrCapacityConflict
	}
	var err error
	if _, err = tx.ExecContext(ctx, `SET LOCAL TIME ZONE 'UTC'`); err != nil {
		return s, zero, false, err
	}
	if err = lockMutationScope(ctx, tx, policy.Metadata.Namespace, p); err != nil {
		return s, zero, false, err
	}
	if err = lockRetirementForwardBindingsTx(ctx, tx, p.MutationBindings); err != nil {
		return s, zero, false, err
	}
	old, err := loadCapacityIntent(ctx, tx, policy.Metadata.Namespace, p, true)
	if errors.Is(err, sql.ErrNoRows) {
		return s, zero, false, nil
	}
	if err != nil {
		return s, old, false, err
	}
	var now time.Time
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return s, old, false, err
	}
	if !installedReadinessHandoffCandidate(old, policy, p, now) {
		return s, old, false, nil
	}
	var exists bool
	if err = tx.QueryRowContext(ctx, `SELECT to_regclass('public.capacity_installed_readiness_exhausted_handoffs') IS NOT NULL`).Scan(&exists); err != nil || !exists {
		return s, old, false, err
	}
	snapshot, err := capacity.GuestReconcileSnapshot(policy, p, s.guestReconcile.inventory, now)
	if err != nil || !reflect.DeepEqual(snapshot, assessment.Snapshot) {
		return s, old, false, ErrCapacityConflict
	}
	if s.ExecutorID == old.LeaseExecutorID || !s.ExecutionEnabled || !capacityProfileCurrent(p, old.Decision, now) || capacity.ValidateAssessment(p, assessment, now) != nil || assessment.Snapshot.Units != old.Decision.Units || assessment.Snapshot.Profile != old.Decision.Profile || !sameCapacityResourceIdentity(old.Assessment.Snapshot, assessment.Snapshot) {
		return s, old, false, ErrCapacityConflict
	}
	if err = s.guestReconcileSourceTx(ctx, tx, policy, p); err != nil {
		return s, old, false, err
	}
	if err = s.installedGuestDispatchRunTx(ctx, tx, policy, p, s.OriginalRunID, nil); err != nil {
		return s, old, false, err
	}
	var forbidden int
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_installed_readiness_exhausted_handoffs WHERE original_disposition_id=$1 OR namespace=$2 AND environment=$3 AND domain=$4 AND dimension=$5 AND (original_record->>'successor_generation')::bigint=$6`, old.InstalledGuestReconcile.InstalledProvisionTimeoutDispositionID, policy.Metadata.Namespace, p.Environment, p.Domain, p.Dimension, old.Generation).Scan(&forbidden); err != nil || forbidden != 0 {
		return s, old, false, ErrCapacityConflict
	}
	if pending, e := countUnresolvedCapacityGrantsTx(ctx, tx, policy.Metadata.Namespace, p); e != nil || pending != 0 {
		return s, old, false, ErrCapacityConflict
	}
	var busy bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM public.capacity_dispatch_jobs WHERE realm=$1 AND environment=$2 AND domain=$3 AND dimension=$4 AND run_id<>$5 AND (state IN('queued','started','unknown') OR state='returned' AND finalization_ack_at IS NULL)) OR EXISTS(SELECT 1 FROM public.capacity_guest_notify_canary_challenges WHERE policy_id=$6 AND original_deadline>=clock_timestamp())`, policy.Metadata.Namespace, p.Environment, p.Domain, p.Dimension, s.OriginalRunID, policy.ID).Scan(&busy); err != nil || busy {
		return s, old, false, ErrCapacityConflict
	}
	originJob, err := uuid.Parse(old.InstalledGuestReconcile.OriginalJobID)
	if err != nil {
		return s, old, false, ErrCapacityConflict
	}
	origin, err := readInstalledProvisionTimeoutDisposition(ctx, tx, originJob)
	if err != nil || origin.ID != old.InstalledGuestReconcile.InstalledProvisionTimeoutDispositionID {
		return s, old, false, ErrCapacityConflict
	}
	var originalIntent, memberWire, oldWire []byte
	if err = tx.QueryRowContext(ctx, `SELECT d.original_intent_wire,d.members_wire,i.intent::text FROM public.capacity_dispatch_installed_provision_timeout_dispositions d JOIN public.capacity_intents i ON i.namespace=$2 AND i.environment=$3 AND i.domain=$4 AND i.dimension=$5 WHERE d.id=$1`, origin.ID, policy.Metadata.Namespace, p.Environment, p.Domain, p.Dimension).Scan(&originalIntent, &memberWire, &oldWire); err != nil {
		return s, old, false, err
	}
	var original model.CapacityIntent
	if json.Unmarshal(originalIntent, &original) != nil {
		return s, old, false, ErrCapacityConflict
	}
	currentMembers, _, err := installedProvisionTimeoutMembersTx(ctx, tx, policy, p, original)
	if err != nil || !installedProvisionTimeoutRecordedMembersEqual(origin.Members, currentMembers) {
		return s, old, false, ErrCapacityConflict
	}
	members, err := s.guestReconcileMembersTx(ctx, tx, policy, p, now, true)
	if err != nil || len(members) != old.Decision.Units || !installedProvisionTimeoutMembersEqual(origin, members) {
		return s, old, false, ErrCapacityConflict
	}
	jw, rw, cw, oldSource, err := s.installedReadinessHandoffHistoryTx(ctx, tx, policy, p, old, now)
	if err != nil {
		return s, old, false, err
	}
	var jobID string
	var dispatchExpiry time.Time
	if err = tx.QueryRowContext(ctx, `SELECT j.id::text,j.lease_expires_at FROM public.capacity_dispatch_jobs j JOIN public.workflow_runs w ON w.id=j.run_id WHERE j.run_id=$1 AND j.state='started' AND j.lease_expires_at>clock_timestamp() AND w.status='running' AND w.finished_at IS NULL FOR SHARE OF j,w`, s.OriginalRunID).Scan(&jobID, &dispatchExpiry); err != nil {
		return s, old, false, err
	}
	next := old
	next.Generation++
	next.FencingToken++
	next.Phase = "preparing"
	next.InstalledGuestReconcile = nil
	next.Assessment, next.BaselineSnapshot, next.UpdatedAt = assessment, assessment.Snapshot, now.UTC()
	next.Decision.Action, next.Decision.Reason, next.Decision.ExecutionPermitted = "hold", installedReadinessHandoffReason, false
	next.LeaseOwner, next.LeaseExecutorID = uuid.NewString(), s.ExecutorID
	expires := now.UTC().Add(time.Duration(min(p.LeaseSeconds, 90)) * time.Second)
	if dispatchExpiry.Before(expires) {
		expires = dispatchExpiry.UTC()
	}
	if !expires.After(now) {
		return s, old, false, ErrCapacityLease
	}
	next.LeaseExpiresAt = &expires
	r := installedReadinessHandoffRecord{Schema: installedReadinessHandoffRecordSchema, ID: uuid.NewString(), OriginalDispositionID: origin.ID, Namespace: policy.Metadata.Namespace, Environment: p.Environment, Domain: p.Domain, Dimension: p.Dimension, PolicyID: policy.ID.String(), PolicyChecksum: policy.Checksum, WorkflowID: s.WorkflowID.String(), WorkflowChecksum: s.guestReconcile.workflow.Checksum, ExhaustedGeneration: old.Generation, ExhaustedFence: old.FencingToken, ExhaustedAttempts: 3, SuccessorGeneration: next.Generation, SuccessorFence: next.FencingToken, SuccessorJobID: jobID, SuccessorRunID: s.OriginalRunID.String(), SuccessorExecutorID: s.ExecutorID, SuccessorLeaseOwner: next.LeaseOwner, SuccessorLeaseExpiresAt: expires, AdmittingCoreSource: capacity.CurrentGuestCoreSource(), OldIssuerCoreSource: oldSource, Profile: old.Decision.Profile, MembersCount: len(members), OriginalIntentSHA256: capacity.BusinessCreationSHA256(oldWire), FailedJobsSHA256: capacity.BusinessCreationSHA256(jw), FailedRunsSHA256: capacity.BusinessCreationSHA256(rw), PreviousCanariesSHA256: capacity.BusinessCreationSHA256(cw), MembersSHA256: capacity.BusinessCreationSHA256(memberWire), RecordedAt: now.UTC(), OldGenerationOutcome: "exhausted_failed", OriginalFailurePreserved: true}
	archive, err := json.Marshal(r)
	if err != nil {
		return s, old, false, err
	}
	m := &model.CapacityInstalledReadinessHandoff{Schema: installedReadinessHandoffSchema, HandoffID: r.ID, HandoffSHA256: capacity.BusinessCreationSHA256(archive), OriginalDispositionID: origin.ID, ExhaustedGeneration: old.Generation, ExhaustedFence: old.FencingToken, ClaimGeneration: next.Generation, ClaimFence: next.FencingToken, RunID: s.OriginalRunID.String(), ExecutorID: s.ExecutorID, CoreSource: capacity.CurrentGuestCoreSource()}
	next.InstalledReadinessHandoff = m
	markerWire, err := json.Marshal(m)
	if err != nil {
		return s, old, false, err
	}
	successorWire, err := json.Marshal(next)
	if err != nil {
		return s, old, false, err
	}
	total := len(archive) + len(oldWire) + len(jw) + len(rw) + len(cw) + len(memberWire) + len(markerWire) + len(successorWire)
	if total > 16<<20 {
		return s, old, false, ErrCapacityConflict
	}
	if err = s.recordGuestAuthorityIssueTx(ctx, tx, policy, p, *p.GuestRetirementBinding, "installed_readiness_handoff", s.OriginalRunID.String(), capacity.BusinessCreationSHA256(markerWire)); err != nil {
		return s, old, false, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_installed_readiness_exhausted_handoffs(id,original_disposition_id,namespace,environment,domain,dimension,original_wire,original_record,record_sha256,original_intent_wire,failed_jobs_wire,failed_runs_wire,previous_canaries_wire,members_wire,marker_wire,successor_intent_wire,successor_job_id,successor_run_id,recorded_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)`, r.ID, origin.ID, r.Namespace, r.Environment, r.Domain, r.Dimension, archive, string(archive), m.HandoffSHA256, oldWire, jw, rw, cw, memberWire, markerWire, successorWire, jobID, s.OriginalRunID, now.UTC())
	if err != nil {
		return s, old, false, err
	}
	bound := bindInstalledReadinessHandoff(s, m)
	if err = bound.guardInstalledReadinessHandoffTransitionTx(ctx, tx, policy, p, &old, &next, now); err != nil {
		return s, old, false, err
	}
	if err = persistRetirementForwardIntentTx(ctx, tx, old, next, "installed-readiness-handoff:"+r.ID); err != nil {
		return s, old, false, err
	}
	if !guestReconcileLive(ctx) {
		return s, old, false, ErrCapacityLease
	}
	return bound, next, true, nil
}

// Only the winning actual run can obtain private canary/phase authority.
func (s CapacityStore) OriginalGuestInstalledReadinessHandoffEpoch(ctx context.Context, policy model.Manifest) (CapacityStore, model.CapacityIntent, bool, error) {
	var current model.CapacityIntent
	if s.DB == nil || s.guestReconcile == nil || s.OriginalRunID == uuid.Nil || !guestReconcileLive(ctx) {
		return s, current, false, ErrCapacityConflict
	}
	p, err := parseCapacityPolicy(policy)
	if err != nil {
		return s, current, false, err
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return s, current, false, err
	}
	defer tx.Rollback()
	if err = lockMutationScope(ctx, tx, policy.Metadata.Namespace, p); err != nil {
		return s, current, false, err
	}
	current, err = loadCapacityIntent(ctx, tx, policy.Metadata.Namespace, p, true)
	if err != nil {
		return s, current, false, err
	}
	m := current.InstalledReadinessHandoff
	if m == nil {
		return s, current, false, nil
	}
	if s.guestReconcile.step.Use.Operation != capacity.CompleteOriginalGuestOperation || !installedReadinessHandoffMarkerValid(m, current) || m.RunID != s.OriginalRunID.String() || m.ExecutorID != s.ExecutorID || m.CoreSource != capacity.CurrentGuestCoreSource() {
		return s, current, false, ErrCapacityConflict
	}
	bound := bindInstalledReadinessHandoff(s, m)
	var now time.Time
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return s, current, false, err
	}
	if err = bound.checkLease(p, policy, &current, current.Generation, current.FencingToken, current.LeaseOwner, now); err != nil {
		return s, current, false, err
	}
	if err = bound.guestReconcileSourceTx(ctx, tx, policy, p); err != nil {
		return s, current, false, err
	}
	if err = bound.installedGuestDispatchRunTx(ctx, tx, policy, p, s.OriginalRunID, nil); err != nil {
		return s, current, false, err
	}
	a, err := readInstalledReadinessHandoffTx(ctx, tx, m.HandoffID)
	if err != nil || a.record.SuccessorRunID != m.RunID || capacity.BusinessCreationSHA256(a.originalWire) != m.HandoffSHA256 {
		return s, current, false, ErrCapacityConflict
	}
	if err = tx.Commit(); err != nil {
		return s, current, false, err
	}
	return bound, current, true, nil
}

// Historical provenance is checked separately from current private ownership.
// A later ordinary assessment drops the marker only from a genuinely
// promoted, unleased epoch. The immutable archive remains; pending retries
// and writes that retain an already completed marker remain refused.
func (s CapacityStore) guardInstalledReadinessHandoffTransitionTx(ctx context.Context, tx *sql.Tx, policy model.Manifest, p model.CapacityPolicySpec, previous, next *model.CapacityIntent, now time.Time) error {
	if previous == nil || previous.InstalledReadinessHandoff == nil {
		if next == nil || next.InstalledReadinessHandoff == nil {
			return nil
		}
		m := next.InstalledReadinessHandoff
		if previous == nil || !installedReadinessHandoffMarkerValid(m, *next) || s.installedReadinessHandoff == nil || *s.installedReadinessHandoff != *m || m.RunID != s.OriginalRunID.String() || m.ExecutorID != s.ExecutorID || m.CoreSource != capacity.CurrentGuestCoreSource() {
			return ErrCapacityConflict
		}
		a, err := readInstalledReadinessHandoffTx(ctx, tx, m.HandoffID)
		if err != nil {
			return err
		}
		wire, err := json.Marshal(next)
		if err != nil || !bytes.Equal(wire, a.successorWire) || capacity.BusinessCreationSHA256(a.originalWire) != m.HandoffSHA256 {
			return ErrCapacityConflict
		}
		return nil
	}
	m := previous.InstalledReadinessHandoff
	if !installedReadinessHandoffMarkerValid(m, *previous) || next == nil {
		return ErrCapacityConflict
	}
	a, err := readInstalledReadinessHandoffTx(ctx, tx, m.HandoffID)
	if err != nil || capacity.BusinessCreationSHA256(a.originalWire) != m.HandoffSHA256 {
		return ErrCapacityConflict
	}
	stable := previous.Phase == "promoted" && previous.LeaseOwner == "" && previous.LeaseExecutorID == "" && previous.LeaseExpiresAt == nil
	if next.InstalledReadinessHandoff == nil {
		if !stable || (next.Generation != previous.Generation && next.Generation != previous.Generation+1) || next.FencingToken != previous.FencingToken || next.LeaseOwner != "" || next.LeaseExecutorID != "" || next.LeaseExpiresAt != nil || next.InstalledGuestReconcile != nil || (next.Generation == previous.Generation && next.Phase != "hold" && next.Phase != "promoted") || (next.Generation == previous.Generation+1 && next.Phase != "proposed") {
			return ErrCapacityConflict
		}
		return nil
	}
	if *next.InstalledReadinessHandoff != *m || next.Generation != previous.Generation || next.FencingToken != previous.FencingToken {
		return ErrCapacityConflict
	}
	if stable {
		return ErrCapacityConflict
	}
	if s.installedReadinessHandoff == nil || *s.installedReadinessHandoff != *m || m.RunID != s.OriginalRunID.String() || m.ExecutorID != s.ExecutorID || m.CoreSource != capacity.CurrentGuestCoreSource() || previous.LeaseExpiresAt == nil || !previous.LeaseExpiresAt.After(now) || previous.LeaseOwner != a.record.SuccessorLeaseOwner || previous.LeaseExecutorID != m.ExecutorID {
		return ErrCapacityConflict
	}
	if next.Phase == "promoted" {
		if next.LeaseOwner != "" || next.LeaseExecutorID != "" || next.LeaseExpiresAt != nil {
			return ErrCapacityConflict
		}
	} else if next.LeaseOwner != previous.LeaseOwner || next.LeaseExecutorID != previous.LeaseExecutorID || next.LeaseExpiresAt == nil || !next.LeaseExpiresAt.Equal(*previous.LeaseExpiresAt) {
		return ErrCapacityConflict
	}
	return nil
}
