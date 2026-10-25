package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"reflect"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

type FailedInstalledGuestRetirementRead struct {
	Policy         model.Manifest
	Spec           model.CapacityPolicySpec
	Current        model.CapacityIntent
	Original       GuestRetirementOriginalV2
	LegacyOriginal *GuestRetirementOriginal
}

// This grants only a new bounded provider GET after the owning Guest write
// and its actual workflow return have closed. It cannot renew a Guest nonce,
// issue another retirement, authorize DELETE or extend the old write deadline.
func loadFailedInstalledRetirementReadTx(ctx context.Context, tx *sql.Tx, id, preID, admissionID string) (FailedInstalledGuestRetirementRead, error) {
	var out FailedInstalledGuestRetirementRead
	r, _, err := loadFailedInstalledDisposalTx(ctx, tx, admissionID, "claimed")
	if err != nil {
		return out, err
	}
	if r.PreregistrationID != preID || r.ClaimedIntent == nil {
		return out, ErrCapacityConflict
	}
	out.Policy.ID = r.OriginalIntent.PolicyID
	out.Policy.Kind = "capacity_policy"
	var active bool
	if err = tx.QueryRowContext(ctx, `SELECT namespace,name,version,checksum,spec,active FROM public.manifests WHERE id=$1 AND kind='capacity_policy' FOR SHARE`, out.Policy.ID).Scan(&out.Policy.Metadata.Namespace, &out.Policy.Metadata.Name, &out.Policy.Version, &out.Policy.Checksum, &out.Policy.Spec, &active); err != nil || !active || out.Policy.Checksum != r.OriginalIntent.PolicyChecksum {
		return out, ErrCapacityConflict
	}
	out.Spec, err = parseCapacityPolicy(out.Policy)
	if err != nil {
		return out, err
	}
	if err = lockMutationScope(ctx, tx, r.Namespace, out.Spec); err != nil {
		return out, err
	}
	out.Current, err = loadCapacityIntent(ctx, tx, r.Namespace, out.Spec, true)
	if err != nil {
		return out, err
	}
	r, err = effectiveFailedInstalledClaimTx(ctx, tx, r, out.Current)
	if err != nil {
		return out, err
	}
	m := out.Current.FailedInstalledDisposal
	if m == nil || m.ID != admissionID || m.Stage != "claimed" || m.PreregistrationID != preID || !reflect.DeepEqual(out.Current, *r.ClaimedIntent) {
		return out, ErrCapacityConflict
	}
	var raw, result []byte
	var now time.Time
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return out, err
	}
	// A failed finish with an acknowledged return cannot retain an active
	// original publisher. Unknown/unacknowledged outcomes remain held.
	pre, err := loadGuestOriginalTx(ctx, tx, preID)
	if err != nil {
		return out, err
	}
	workflowID, e := uuid.Parse(pre.pre.WorkflowID)
	if e != nil {
		return out, ErrCapacityConflict
	}
	if err = tx.QueryRowContext(ctx, installedGuestPreviousFailedRunQuery, m.RunID, workflowID, now).Scan(&raw, &result); err != nil {
		return out, err
	}
	var run struct {
		Workflow model.ManifestReference       `json:"workflow"`
		Status   string                        `json:"status"`
		Steps    []model.WorkflowRunStepResult `json:"steps"`
	}
	if json.Unmarshal(result, &run) != nil || run.Status != "failed" || len(run.Steps) != 7 {
		return out, ErrCapacityConflict
	}
	var retirementRequest string
	statuses := map[string]string{}
	for _, step := range run.Steps {
		statuses[step.ID] = step.Status
		if step.ID == "retire-original-guest" {
			retirementRequest, _ = step.Metadata["request_id"].(string)
		}
	}
	if statuses["plan-original-guest"] != "succeeded" || statuses["retire-original-guest"] != "succeeded" || statuses["finish-original-retirement"] != "failed" || statuses["provision-original-notify"] != "skipped" || statuses["complete-original-provision"] != "skipped" || statuses["refresh-original-membership"] != "skipped" || statuses["complete-original-retirement"] != "skipped" || !validCapacityExecutor(retirementRequest) || id != "" && retirementRequest != id {
		return out, ErrCapacityConflict
	}
	var workflow string
	var executor string
	if r.RetirementMode == failedInstalledLegacyV1Mode {
		legacy, e := loadGuestRetirementTx(ctx, tx, retirementRequest)
		if e != nil || !failedInstalledLegacyJoin(r, legacy, out.Spec) {
			return out, ErrCapacityConflict
		}
		out.LegacyOriginal = &legacy
		workflow, executor = legacy.Request.Intent.WorkflowID, legacy.ExecutorID
		if _, e = guestQuiescentProofTx(ctx, tx, legacy); e != nil {
			return out, e
		}
	} else {
		out.Original, err = loadGuestRetirementV2Tx(ctx, tx, retirementRequest, true)
		if err != nil {
			return out, err
		}
		i := out.Original.Request.Intent
		if i.PreregistrationID != preID || i.PolicyID != out.Policy.ID.String() || i.PolicyChecksum != out.Policy.Checksum || i.Generation != uint64(out.Current.Generation) || i.Fence != uint64(out.Current.FencingToken) || i.LeaseOwner != out.Current.LeaseOwner || out.Original.ExecutorID != out.Current.LeaseExecutorID {
			return out, ErrCapacityConflict
		}
		workflow, executor = i.WorkflowID, out.Original.ExecutorID
		if _, err = guestQuiescentProofV2Tx(ctx, tx, out.Original); err != nil {
			return out, err
		}
	}
	store := CapacityStore{WorkflowID: uuid.MustParse(workflow), ExecutorID: executor}
	valid, err := store.failedInstalledDisposalActiveTx(ctx, tx, out.Policy, out.Spec, out.Current, 1, now)
	if err != nil || !valid {
		return out, ErrCapacityConflict
	}
	// Validate the real scheduler envelope/result, including optional NULL FK.
	var wf model.Manifest
	wf.ID = store.WorkflowID
	if err = tx.QueryRowContext(ctx, `SELECT namespace,name,version,checksum FROM public.manifests WHERE id=$1 AND kind='workflow'`, wf.ID).Scan(&wf.Metadata.Namespace, &wf.Metadata.Name, &wf.Version, &wf.Checksum); err != nil {
		return out, err
	}
	store.guestReconcile = &guestReconcileSource{workflow: wf}
	if err = store.installedGuestDispatchRunTx(ctx, tx, out.Policy, out.Spec, uuid.MustParse(m.RunID), result); err != nil {
		return out, err
	}
	return out, nil
}

func (s CapacityStore) FailedInstalledGuestRetirementForReadonly(ctx context.Context, preID, admissionID string) (FailedInstalledGuestRetirementRead, error) {
	var out FailedInstalledGuestRetirementRead
	if s.DB == nil || !validCapacityExecutor(preID) || !validCapacityExecutor(admissionID) {
		return out, ErrCapacityConflict
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	return loadFailedInstalledRetirementReadTx(ctx, tx, "", preID, admissionID)
}

func failedInstalledPoweroffReadonlyTx(ctx context.Context, tx *sql.Tx, stored GuestRetirementOriginalV2) (FailedInstalledGuestRetirementRead, error) {
	var id string
	err := tx.QueryRowContext(ctx, `SELECT id::text FROM public.capacity_guest_failed_installed_disposals WHERE preregistration_id=$1 AND stage='claimed'`, stored.Preregistration.PreregistrationID).Scan(&id)
	if err != nil {
		return FailedInstalledGuestRetirementRead{}, err
	}
	return loadFailedInstalledRetirementReadTx(ctx, tx, stored.Request.Intent.RequestID, stored.Preregistration.PreregistrationID, id)
}

func (s CapacityStore) AdvanceFailedInstalledGuestCleanup(ctx context.Context, preID, admissionID string) (FailedInstalledGuestDisposal, error) {
	var empty FailedInstalledGuestDisposal
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return empty, err
	}
	defer tx.Rollback()
	read, err := loadFailedInstalledRetirementReadTx(ctx, tx, "", preID, admissionID)
	if err != nil {
		return empty, err
	}
	var now time.Time
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return empty, err
	}
	if read.LegacyOriginal != nil {
		r, _, e := loadFailedInstalledDisposalTx(ctx, tx, admissionID, "claimed")
		if e != nil {
			return empty, e
		}
		r, e = effectiveFailedInstalledClaimTx(ctx, tx, r, read.Current)
		if e != nil {
			return empty, e
		}
		if r.NativePoweroffSHA256, e = failedInstalledLegacyOffTx(ctx, tx, r, *read.LegacyOriginal, read.Spec, true); e != nil {
			return empty, e
		}
		r, e = finishFailedInstalledCleanupTx(ctx, tx, r, read.Current, read.LegacyOriginal.Request.Intent.RequestID, now)
		if e != nil {
			return empty, e
		}
		if e = tx.Commit(); e != nil {
			return empty, e
		}
		return r, nil
	}
	b, err := capacity.VMObservationBinding(read.Spec, read.Original.Binding.MutationBindingName)
	if err != nil {
		return empty, err
	}
	if err = guestNativePoweroffV2Tx(ctx, tx, read.Original, read.Spec, b, now); err != nil {
		return empty, err
	}
	r, _, err := loadFailedInstalledDisposalTx(ctx, tx, admissionID, "claimed")
	if err != nil {
		return empty, err
	}
	if err = tx.QueryRowContext(ctx, `SELECT observation_sha256 FROM public.capacity_guest_original_native_poweroff_reads WHERE intent_id=$1 AND original_record->>'schema'='original_core_guest_native_poweroff_read_return_v2' ORDER BY recorded_at DESC,id DESC LIMIT 1`, read.Original.Request.Intent.RequestID).Scan(&r.NativePoweroffSHA256); err != nil {
		return empty, err
	}
	r.Stage = "quiescent"
	r.RetirementRequestID = read.Original.Request.Intent.RequestID
	if _, err = insertFailedInstalledDisposalTx(ctx, tx, r); err != nil {
		return empty, err
	}
	next := read.Current
	marker := *next.FailedInstalledDisposal
	marker.Stage = "quiescent"
	next.FailedInstalledDisposal = &marker
	next.Phase = "failed_installed_cleanup_pending"
	next.LeaseOwner = ""
	next.LeaseExecutorID = ""
	next.LeaseExpiresAt = nil
	next.UpdatedAt = now
	if err = persistFailedInstalledDisposalIntentTx(ctx, tx, read.Current, next); err != nil {
		return empty, err
	}
	if err = tx.Commit(); err != nil {
		return empty, err
	}
	return r, nil
}
