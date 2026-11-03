//go:build linux && nativequalification && postlossdump

package repository

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// A same-source LAB snapshot is inspected in a disposable PostgreSQL cluster.
// The original source observation time is used for the historical join, not as
// a current lease or fresh authority. Every altered row is rolled back.
func TestPostlossPendingSnapshotTransactions(t *testing.T) {
	if os.Getenv("CAPACITY_POSTLOSS_PENDING_DUMP_TEST") != "true" || os.Getenv("DB_URL") == "" {
		t.Fatal("explicit isolated pending snapshot required")
	}
	db := guestOriginalPostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	var socket bool
	if err := db.QueryRowContext(ctx, `SELECT inet_server_addr() IS NULL`).Scan(&socket); err != nil || !socket {
		t.Fatal("Unix socket required")
	}
	rows, err := db.QueryContext(ctx, `SELECT g.grant_record,c.proof_wire,c.recorded_at,p.id::text FROM public.capacity_mutation_grants g JOIN public.capacity_vm_provisioning_preregistrations p ON p.create_grant_id=g.id JOIN public.capacity_canonical_postloss_confirmations c ON c.preregistration_id=p.id WHERE g.grant_record->'grant'->>'state'='settled' AND g.grant_record->'settlement'->>'outcome'='uncertain'`)
	if err != nil {
		t.Fatal("pending source records unavailable")
	}
	var raw, proofRaw []byte
	var recorded time.Time
	var preID string
	count := 0
	for rows.Next() {
		if rows.Scan(&raw, &proofRaw, &recorded, &preID) != nil {
			t.Fatal("pending source record unreadable")
		}
		count++
	}
	if rows.Err() != nil || rows.Close() != nil || count != 1 {
		t.Fatal("exactly one pending source record required")
	}
	var parent capacityMutationRecord
	var proof model.CapacityMutationProof
	if json.Unmarshal(raw, &parent) != nil || json.Unmarshal(proofRaw, &proof) != nil {
		t.Fatal("pending record malformed")
	}
	var policy model.Manifest
	if db.QueryRowContext(ctx, `SELECT id,namespace,name,checksum,spec FROM public.manifests WHERE id=$1`, parent.PolicyID).Scan(&policy.ID, &policy.Metadata.Namespace, &policy.Metadata.Name, &policy.Checksum, &policy.Spec) != nil {
		t.Fatal("policy unavailable")
	}
	var spec model.CapacityPolicySpec
	if json.Unmarshal(policy.Spec, &spec) != nil {
		t.Fatal("policy malformed")
	}
	store := CapacityStore{DB: db, WorkflowID: parent.WorkflowID, ExecutorID: parent.ExecutorID}
	nativeCase := "canonical_postloss_unprotected_failed_create_reissue"
	if parent.Grant.Slot == 1 {
		nativeCase = "canonical_postloss_protected_failed_create_reissue"
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal("isolated transaction unavailable")
	}
	defer tx.Rollback()
	stored, err := loadGuestOriginalTx(ctx, tx, preID)
	if err != nil || stored.binding.CoreAuthoritySourceCommit != capacity.CurrentGuestCoreSource() {
		t.Fatal("snapshot source mismatch")
	}
	check := func(p model.CapacityMutationProof) error {
		return store.verifyCanonicalPostlossPendingTx(ctx, tx, stored, policy, spec, nativeCase, parent.Grant, p, recorded)
	}
	if err = check(proof); err != nil {
		t.Fatal("same-source pending join rejected at retained observation")
	}
	bad := proof
	bad.ResourceID = "foreign"
	if check(bad) == nil {
		t.Fatal("foreign proof accepted")
	}
	scenarios := []struct {
		name string
		sql  string
		args []any
	}{
		{"event", `INSERT INTO public.event_log(event_id,type,aggregate_type,aggregate_id,payload,idempotency_key) VALUES ($1,'test','test','test','{}'::jsonb,$2)`, []any{uuid.New(), "capacity-mutation/" + parent.Grant.GrantID}},
		{"foreign_member", `INSERT INTO public.capacity_resource_slots(integration_instance_id,scope_checksum,profile_name,slot,namespace,environment,domain,dimension,resource_id,slot_record) SELECT $1,scope_checksum,profile_name,$2,namespace,environment,domain,dimension,'foreign-test','{}'::jsonb FROM public.capacity_resource_slots WHERE namespace=$3 AND resource_id<>'' LIMIT 1`, []any{uuid.New(), parent.Grant.Slot, policy.Metadata.Namespace}},
		{"settlement", `UPDATE public.capacity_mutation_grants SET grant_record=jsonb_set(grant_record,'{settlement,resource_id}',to_jsonb('foreign'::text),true) WHERE id=$1`, []any{parent.Grant.GrantID}},
		{"lease", `UPDATE public.capacity_intents SET intent=jsonb_set(intent,'{lease_owner}',to_jsonb('00000000-0000-0000-0000-000000000000'::text),true) WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4`, []any{policy.Metadata.Namespace, spec.Environment, spec.Domain, spec.Dimension}},
	}
	for _, tc := range scenarios {
		t.Run(tc.name, func(t *testing.T) {
			if _, e := tx.ExecContext(ctx, `SAVEPOINT pending_negative`); e != nil {
				t.Fatal("savepoint failed")
			}
			result, e := tx.ExecContext(ctx, tc.sql, tc.args...)
			if e != nil {
				t.Fatal("negative fixture mutation refused")
			}
			n, e := result.RowsAffected()
			if e != nil || n != 1 {
				t.Fatal("negative fixture mutation not unique")
			}
			if check(proof) == nil {
				t.Fatal("negative pending snapshot accepted")
			}
			if _, e = tx.ExecContext(ctx, `ROLLBACK TO SAVEPOINT pending_negative`); e != nil {
				t.Fatal("negative fixture rollback failed")
			}
		})
	}
	if err = check(proof); err != nil {
		t.Fatal("negative cases damaged baseline")
	}
}
