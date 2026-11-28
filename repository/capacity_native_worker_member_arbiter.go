package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// Every caller already holds the existing dimension arbiter and locks the
// Attempt first. This check is deliberately absent for the legacy nil binding.
func nativeMemberGrowthAllowedTx(ctx context.Context, tx *sql.Tx, p model.CapacityPolicySpec, a model.CapacityNativeWorkerAttempt) error {
	if p.NativeWorkerLifecycleBinding == nil || p.NativeWorkerLifecycleBinding.Members == nil {
		return nil
	}
	var blocked bool
	if e := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM public.capacity_native_worker_member_plans WHERE attempt_id=$1 AND kind='retirement' AND state NOT IN ('settled','cancelled'))`, a.ID).Scan(&blocked); e != nil {
		return e
	}
	if blocked {
		return ErrCapacityConflict
	}
	return nil
}

// Mode comes from append-only admission custody, not the caller or a lost taint.
// An unresolved exposed admission/release right cannot be called never-admitted.
func nativeMemberModeTx(ctx context.Context, tx *sql.Tx, a model.CapacityNativeWorkerAttempt) (string, string, error) {
	if a.Physical == nil {
		return "", "", errNativeMember
	}
	rows, e := tx.QueryContext(ctx, `SELECT CASE WHEN octet_length(record::text)<=2097152 THEN record END FROM public.capacity_native_worker_phase_permits WHERE attempt_id=$1 ORDER BY issued_at,id FOR UPDATE`, a.ID)
	if e != nil {
		return "", "", e
	}
	defer rows.Close()
	mode, receipt := "never_admitted", ""
	for rows.Next() {
		var raw []byte
		var r nativeWorkerPhaseRecord
		if rows.Scan(&raw) != nil || json.Unmarshal(raw, &r) != nil {
			return "", "", errNativeMember
		}
		if r.Context.Action != "admit_registry" && r.Context.Action != "release_quarantine" {
			continue
		}
		if r.Context.PhaseState == "issued" || r.Context.PhaseState == "no_effect" {
			continue
		}
		if r.Context.PhaseState != "observed" || r.Context.AttemptID != a.ID || r.Context.Node.CreationProofSHA256 != a.BirthSHA256 || r.Context.Node.ProviderID != a.Physical.ProviderID || r.Context.Node.UID != a.NodeUID || r.Context.Admission.ReceiptSHA256 == "" {
			return "", "", errNativeMember
		}
		if receipt != "" && receipt != r.Context.Admission.ReceiptSHA256 {
			return "", "", errNativeMember
		}
		mode, receipt = "admitted", r.Context.Admission.ReceiptSHA256
	}
	return mode, receipt, rows.Err()
}

// Retirement cancels only rights which have NEVER been exposed. Unknown Bind
// and probe sends remain an in-flight fence regardless of elapsed time. Probe
// cleanup/delete/receive continue through their original separate owned ports.
func nativeMemberRetirementFenceTx(ctx context.Context, tx *sql.Tx, p model.Manifest, a model.CapacityNativeWorkerAttempt, now time.Time) error {
	if e := abortFenceAdmissionTx(ctx, tx, a, now); e != nil {
		return e
	}
	rows, e := tx.QueryContext(ctx, `SELECT CASE WHEN octet_length(record::text)<=8388608 THEN record END FROM public.capacity_native_worker_member_permits WHERE attempt_id=$1 AND action='bind_pod' AND state NOT IN('preparing','no_effect','observed','member_absent') ORDER BY id FOR UPDATE`, a.ID)
	if e != nil {
		return e
	}
	var cancelled []nativeMemberRecord
	for rows.Next() {
		var raw []byte
		var r nativeMemberRecord
		if rows.Scan(&raw) != nil || nativeMemberDecode(raw, &r) != nil {
			rows.Close()
			return errNativeMember
		}
		if r.State != "issued" || r.Original != nil || r.SettlementTokenSHA256 != "" {
			rows.Close()
			return ErrCapacityConflict
		}
		cancelled = append(cancelled, r)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	var probe []byte
	e = tx.QueryRowContext(ctx, `SELECT CASE WHEN octet_length(record::text)<=50331648 THEN record END FROM public.capacity_native_worker_readiness_runs WHERE attempt_id=$1 FOR UPDATE`, a.ID).Scan(&probe)
	if e == nil {
		var r nativeReadinessRun
		if capacity.DecodeNativeReadinessJournalJSON(probe, &r) != nil || !r.Closed {
			return ErrCapacityConflict
		}
	} else if e != sql.ErrNoRows {
		return e
	}
	for _, r := range cancelled {
		r.State = "no_effect"
		r.Revision++
		if e = nativeMemberWriteTx(ctx, tx, p, r, false, now); e != nil {
			return e
		}
	}
	return nil
}
