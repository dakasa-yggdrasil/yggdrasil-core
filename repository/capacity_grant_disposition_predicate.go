package repository

import (
	"context"
	"database/sql"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// A linked disposition (ADR-0069, 0073, 0074, 0077, 0083) is the terminal,
// independently read closure of one accepted original create lifetime: its
// native resource and owned auxiliaries were authenticated absent (or its
// create authenticated as denied). The grant itself keeps state 'settled'
// forever because the pointer guards forbid any rewrite. Every projection of
// pending or unresolved mutation authority therefore excludes a disposed grant
// with this exact predicate; it never releases an undisposed settlement.
const capacityGrantUndisposedSQL = `original_disposition_id IS NULL AND failed_original_disposition_id IS NULL AND native_denied_disposition_id IS NULL AND enrolled_failed_disposition_id IS NULL`

const capacityUnresolvedGrantsSQL = `SELECT count(*) FROM public.capacity_mutation_grants WHERE ` + capacityGrantUndisposedSQL + ` AND NOT(grant_record ? 'authority_kind') AND namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4 AND state IN ('issued','redeemed','settled','compensating')`

// Counts legacy (non-authority) grants of one physical dimension that still
// hold provider mutation authority. The caller holds the dimension lock.
func countUnresolvedCapacityGrantsTx(ctx context.Context, tx *sql.Tx, namespace string, p model.CapacityPolicySpec) (int, error) {
	var unresolved int
	err := tx.QueryRowContext(ctx, capacityUnresolvedGrantsSQL, namespace, p.Environment, p.Domain, p.Dimension).Scan(&unresolved)
	return unresolved, err
}
