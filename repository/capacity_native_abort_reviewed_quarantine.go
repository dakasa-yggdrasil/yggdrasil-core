package repository

import (
	"context"
	"database/sql"
	"reflect"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// Caller owns the existing scope, intent and global target UID locks. Receipt
// enumeration is independent of HOT rows and includes orphaned receipts. Every
// reference must still identify its full original quarantine custody, not just
// a matching count or a previously accepted digest.
func nativeReviewedAbortQuarantinesTx(ctx context.Context, tx *sql.Tx, policy model.Manifest, p model.CapacityPolicySpec, b model.CapacityNativeAbortBinding, ownIssued bool) (model.CapacityNativeUnsettledCounts, error) {
	var out model.CapacityNativeUnsettledCounts
	if b.ReviewedQuarantines == nil {
		return out, ErrCapacityConflict
	}
	rows, err := tx.QueryContext(ctx, `SELECT q.command_id,q.subject_uid,q.record_sha256 FROM public.capacity_native_abort_quarantines q LEFT JOIN public.capacity_native_command_identities i ON i.id=q.command_id WHERE (q.namespace=$1 AND q.environment=$2 AND q.domain=$3 AND q.dimension=$4) OR (i.namespace=$1 AND i.environment=$2 AND i.domain=$3 AND i.dimension=$4) ORDER BY q.command_id FOR SHARE OF q`, policy.Metadata.Namespace, p.Environment, p.Domain, p.Dimension)
	if err != nil {
		return out, err
	}
	var actual []model.CapacityNativeAbortQuarantineReference
	for rows.Next() {
		var ref model.CapacityNativeAbortQuarantineReference
		if rows.Scan(&ref.CommandID, &ref.SubjectUID, &ref.RecordSHA256) != nil {
			rows.Close()
			return out, ErrCapacityConflict
		}
		actual = append(actual, ref)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return out, err
	}
	if !reflect.DeepEqual(actual, b.ReviewedQuarantines.Receipts) {
		return out, ErrCapacityConflict
	}
	for _, ref := range actual {
		id, e := uuid.Parse(ref.CommandID)
		if e != nil {
			return out, ErrCapacityConflict
		}
		valid, e := nativeAbortQuarantineValidated(ctx, tx, policy, p, id)
		if e != nil || !valid {
			return out, ErrCapacityConflict
		}
	}
	// This existing helper independently validates every referenced receipt's
	// complete parent/child/request/result-seed identity and absence of all ACKs.
	out, err = nativeActiveUnsettledTx(ctx, tx, policy, p, b.PodUID)
	if err != nil {
		return out, err
	}
	n, self := int64(len(actual)), int64(0)
	if ownIssued {
		self = 1
	}
	if out != (model.CapacityNativeUnsettledCounts{RawUnsettled: n + self, Quarantined: n, ActiveUnsettled: self}) {
		return out, ErrCapacityConflict
	}
	return out, nil
}

// Redemption already loaded and validated the immutable, still-issued own
// command under FOR UPDATE. Only its one identity and HOT row may have appeared
// since the proof's six-zero baseline; no other global target history is legal.
func nativeReviewedAbortRedemptionTx(ctx context.Context, tx *sql.Tx, policy model.Manifest, p model.CapacityPolicySpec, b model.CapacityNativeAbortBinding, c model.CapacityNativeCommand) error {
	// The JSON proof alone cannot establish which SQL row contributes the one
	// active count. Bind the locked own row's complete indexed identity/state.
	var own int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_native_commands WHERE id=$1 AND namespace=$2 AND environment=$3 AND domain=$4 AND dimension=$5 AND generation=$6 AND operation=$7 AND subject_uid=$8 AND phase=$9 AND sequence=$10 AND state='issued' AND authority_token_sha256=$11`, c.CommandID, c.Namespace, c.Environment, c.Domain, c.Dimension, c.IntentGeneration, c.Operation, b.PodUID, c.Phase, c.Sequence, c.AuthorityTokenSHA256).Scan(&own); err != nil {
		return err
	}
	if own != 1 {
		return ErrCapacityConflict
	}
	if _, err := nativeReviewedAbortQuarantinesTx(ctx, tx, policy, p, b, true); err != nil {
		return err
	}
	z, err := nativeAbortZeroHistory(ctx, tx, b.PodUID)
	if err != nil {
		return err
	}
	if z != (model.CapacityNativeAbortZeroHistory{CommandIdentities: 1, HotCommands: 1}) {
		return ErrCapacityConflict
	}
	return nil
}
