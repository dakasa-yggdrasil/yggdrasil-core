//go:build linux && nativequalification && postlossdump

package repository

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// Read-only replay of retained LAB evidence, only against a Unix-socket PG
// explicitly restored for this test. It neither creates evidence nor proves
// the later completion of that historical QEMU run.
func TestPostlossConfirmedRetainedDump(t *testing.T) {
	if os.Getenv("CAPACITY_POSTLOSS_DUMP_TEST") != "true" || os.Getenv("DB_URL") == "" {
		t.Fatal("explicit isolated dump and DB_URL required")
	}
	db := guestOriginalPostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	var socket bool
	if err := db.QueryRowContext(ctx, `SELECT inet_server_addr() IS NULL`).Scan(&socket); err != nil || !socket {
		t.Fatal("isolated Unix-socket PostgreSQL required")
	}
	rows, err := db.QueryContext(ctx, `SELECT grant_record FROM public.capacity_mutation_grants WHERE grant_record->'grant'->>'state'='confirmed' AND grant_record->'settlement'->>'outcome'='uncertain'`)
	if err != nil {
		t.Fatal("cannot read qualifying grants")
	}
	defer rows.Close()
	var raw []byte
	count := 0
	for rows.Next() {
		if err := rows.Scan(&raw); err != nil {
			t.Fatal("cannot decode original grant")
		}
		count++
	}
	if rows.Err() != nil || count != 1 {
		t.Fatal("expected exactly one original uncertain confirmed grant")
	}
	var parent capacityMutationRecord
	if json.Unmarshal(raw, &parent) != nil || parent.Proof == nil {
		t.Fatal("original confirmation proof missing")
	}
	var policy model.Manifest
	if err = db.QueryRowContext(ctx, `SELECT id, namespace, name, checksum, spec FROM public.manifests WHERE id=$1`, parent.PolicyID).Scan(&policy.ID, &policy.Metadata.Namespace, &policy.Metadata.Name, &policy.Checksum, &policy.Spec); err != nil {
		t.Fatal("original policy unavailable")
	}
	var spec model.CapacityPolicySpec
	if json.Unmarshal(policy.Spec, &spec) != nil {
		t.Fatal("original policy malformed")
	}
	store := CapacityStore{DB: db, WorkflowID: parent.WorkflowID}
	nativeCase := "canonical_postloss_unprotected_failed_create_reissue"
	if parent.Grant.Slot == 1 {
		nativeCase = "canonical_postloss_protected_failed_create_reissue"
	}
	proof := *parent.Proof
	if err := store.VerifyCanonicalPostlossConfirmed(ctx, policy, spec, nativeCase, parent.Grant, proof); err != nil {
		t.Fatal("original stored postloss join rejected")
	}
	mutations := []func(*model.CapacityMutationProof){
		func(p *model.CapacityMutationProof) { p.GrantID = "00000000-0000-0000-0000-000000000000" },
		func(p *model.CapacityMutationProof) { p.ResourceID = "foreign" },
		func(p *model.CapacityMutationProof) { p.ResourceCreatedAt = "2000-01-01T00:00:00Z" },
		func(p *model.CapacityMutationProof) { p.Slot = 3 - p.Slot },
		func(p *model.CapacityMutationProof) { p.ObservedAt = p.ObservedAt.Add(time.Second) },
		func(p *model.CapacityMutationProof) { p.ReceiptRef = "foreign" },
	}
	for _, mutate := range mutations {
		bad := proof
		mutate(&bad)
		if store.VerifyCanonicalPostlossConfirmed(ctx, policy, spec, nativeCase, parent.Grant, bad) == nil {
			t.Fatal("altered proof accepted")
		}
	}
	other := "canonical_postloss_protected_failed_create_reissue"
	if parent.Grant.Slot == 1 {
		other = "canonical_postloss_unprotected_failed_create_reissue"
	}
	if store.VerifyCanonicalPostlossConfirmed(ctx, policy, spec, other, parent.Grant, proof) == nil {
		t.Fatal("foreign source case accepted")
	}
}
