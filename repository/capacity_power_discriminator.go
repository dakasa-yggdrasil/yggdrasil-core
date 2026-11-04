package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
)

// Legacy VM consumers must not silently decode power grants/adoptions as zero
// VM records. Preserve the old untagged format and reject every other authority.
func rejectNonVMAuthority(raw []byte) error {
	var head map[string]json.RawMessage
	if err := json.Unmarshal(raw, &head); err != nil {
		return err
	}
	for k := range head {
		if strings.EqualFold(k, "authority_kind") {
			return fmt.Errorf("VM ledger rejects explicit foreign authority")
		}
	}
	return nil
}
func (r *capacityMutationRecord) UnmarshalJSON(raw []byte) error {
	if err := rejectNonVMAuthority(raw); err != nil {
		return err
	}
	type legacy capacityMutationRecord
	return json.Unmarshal(raw, (*legacy)(r))
}
func (r *capacityResourceSlot) UnmarshalJSON(raw []byte) error {
	if err := rejectNonVMAuthority(raw); err != nil {
		return err
	}
	type legacy capacityResourceSlot
	return json.Unmarshal(raw, (*legacy)(r))
}

// Same instance lock as adoption: no late legacy destructive claim can acquire
// write authority for an adopted EC2. Non-EC2 paths retain their existing behavior.
func guardExecutorPowerAdoption(ctx context.Context, tx *sql.Tx, id string) error {
	if !strings.HasPrefix(id, "i-") || len(id) != 19 {
		return nil
	}
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "capacity-power-instance/"+id); err != nil {
		return err
	}
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_resource_slots WHERE slot_record->>'authority_kind'='ec2_operator_adoption_v1' AND slot_record->'resource'->>'instance_id'=$1`, id).Scan(&count); err != nil {
		return err
	}
	if count != 0 {
		return ErrCapacityConflict
	}
	return nil
}
