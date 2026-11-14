package repository

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/dakasa-yggdrasil/yggdrasil-core/manifest"
	"github.com/google/uuid"
)

// ErrCapacityPolicyPublicationConflict leaves the existing catalog pin intact.
// A new manifest ID is a pin change even when its checksum is unchanged.
var ErrCapacityPolicyPublicationConflict = errors.New("capacity policy publication conflicts with an active dispatch or changed catalog")

type capacityPolicyPublicationRow struct {
	ID       uuid.UUID
	Version  int
	Active   bool
	Spec     json.RawMessage
	Checksum string
}

func capacityPolicyPublicationRows(ctx context.Context, tx *sql.Tx, namespace, name string, lock bool) ([]capacityPolicyPublicationRow, error) {
	query := `SELECT id,version,active,spec,checksum FROM public.manifests WHERE kind='capacity_policy' AND namespace=$1 AND name=$2 ORDER BY id`
	if lock {
		query += ` FOR UPDATE`
	}
	rows, err := tx.QueryContext(ctx, query, namespace, name)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []capacityPolicyPublicationRow
	for rows.Next() {
		var row capacityPolicyPublicationRow
		if err := rows.Scan(&row.ID, &row.Version, &row.Active, &row.Spec, &row.Checksum); err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

func capacityPolicyPublicationScope(namespace string, raw json.RawMessage) ([4]string, bool, error) {
	var scope [4]string
	if len(raw) == 0 {
		raw = json.RawMessage(`{}`)
	}
	p, err := manifest.ParseCapacityPolicySpec(raw)
	if err != nil {
		return scope, false, err
	}
	// Legacy/default-off repository documents have no dispatch dimension.
	// They cannot erase the discovered scope of an existing active version.
	if p.Environment == "" && p.Domain == "" && p.Dimension == "" {
		return scope, false, nil
	}
	scope = [4]string{namespace, p.Environment, p.Domain, p.Dimension}
	for _, value := range scope {
		if value == "" || strings.TrimSpace(value) != value || strings.ContainsAny(value, "\x00\r\n") {
			return scope, false, fmt.Errorf("invalid capacity policy publication scope")
		}
	}
	return scope, true, nil
}

// guardCapacityPolicyPublicationTx takes the existing dispatch locks BEFORE
// catalog row locks. Discovery is optimistic: any intervening catalog change
// refuses this transaction instead of acquiring an undiscovered scope late.
// Hard deletion includes historical scopes because it removes those pins too.
func guardCapacityPolicyPublicationTx(ctx context.Context, tx *sql.Tx, namespace, name string, incoming *json.RawMessage, deleteAll bool, expectedID uuid.UUID) error {
	// Serialize this logical catalog identity even before its first row exists.
	// The explicit three-string namespace is distinct from dispatch's four-string
	// scope. Enqueue/disposition never need it, so scope -> catalog cannot cycle.
	logicalKey, _ := json.Marshal([]string{"capacity-policy-publication", namespace, name})
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, string(logicalKey)); err != nil {
		return err
	}
	before, err := capacityPolicyPublicationRows(ctx, tx, namespace, name, false)
	if err != nil {
		return err
	}
	scopes := make(map[string][4]string)
	add := func(raw json.RawMessage) error {
		scope, present, err := capacityPolicyPublicationScope(namespace, raw)
		if err == nil && present {
			key, _ := json.Marshal(scope) // Same compact four-string wire as EnqueueCapacityDispatch.
			scopes[string(key)] = scope
		}
		return err
	}
	found := expectedID == uuid.Nil
	for _, row := range before {
		found = found || row.ID == expectedID
		if row.Active || deleteAll {
			if err := add(row.Spec); err != nil {
				return ErrCapacityPolicyPublicationConflict
			}
		}
	}
	if !found {
		return ErrCapacityPolicyPublicationConflict
	}
	var incomingErr error
	if incoming != nil {
		incomingErr = add(*incoming)
	}
	keys := make([]string, 0, len(scopes))
	for key := range scopes {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, key); err != nil {
			return err
		}
	}
	for _, key := range keys {
		scope := scopes[key]
		var busy uuid.UUID
		err := tx.QueryRowContext(ctx, `SELECT id FROM public.capacity_dispatch_jobs WHERE realm=$1 AND environment=$2 AND domain=$3 AND dimension=$4 AND (state IN ('queued','started','unknown') OR (state='returned' AND finalization_ack_at IS NULL)) FOR UPDATE`, scope[0], scope[1], scope[2], scope[3]).Scan(&busy)
		if err == nil {
			return ErrCapacityPolicyPublicationConflict
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
	}
	if _, err := capacityPolicyPublicationRows(ctx, tx, namespace, name, true); err != nil {
		return err
	}
	after, err := capacityPolicyPublicationRows(ctx, tx, namespace, name, false)
	if err != nil {
		return err
	}
	beforeWire, err := json.Marshal(before)
	if err != nil {
		return err
	}
	afterWire, err := json.Marshal(after)
	if err != nil {
		return err
	}
	if !bytes.Equal(beforeWire, afterWire) {
		return ErrCapacityPolicyPublicationConflict
	}
	if incomingErr != nil {
		return fmt.Errorf("invalid capacity policy publication scope: %w", incomingErr)
	}
	return nil
}
