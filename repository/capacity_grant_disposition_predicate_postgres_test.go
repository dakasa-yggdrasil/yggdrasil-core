package repository

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// Regression for the production gen10 Guest refresh: an original whose real
// disposition was recorded stays 'settled' forever, and must stop counting as
// unresolved authority, while an undisposed 'settled' grant keeps counting.
func TestCountUnresolvedCapacityGrantsPostgresExcludesDisposedOriginal(t *testing.T) {
	db := originalDispositionPG(t)
	f := originalDispositionPGFixture(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var p model.CapacityPolicySpec
	if err := json.Unmarshal(f.policy.Spec, &p); err != nil {
		t.Fatal(err)
	}
	count := func() int {
		t.Helper()
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback() }()
		n, err := countUnresolvedCapacityGrantsTx(ctx, tx, f.policy.Metadata.Namespace, p)
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	if n := count(); n != 1 {
		t.Fatal("undisposed settled original must hold authority", n)
	}
	owner, err := f.store.BeginOriginalCreateDisposition(ctx, f.pre.OriginalCreateGrantID, "isolated-test-operator")
	if err != nil {
		t.Fatal("Begin", err)
	}
	result, err := f.store.CompleteOriginalCreateDisposition(ctx, owner, f.native(t, owner.Candidate()))
	if err != nil {
		t.Fatal("Complete", err)
	}
	var state, pointer string
	if err = db.QueryRow(`SELECT state,original_disposition_id::text FROM public.capacity_mutation_grants WHERE id=$1`, result.GrantID).Scan(&state, &pointer); err != nil || state != "settled" || pointer != result.ID {
		t.Fatal("disposed original must stay settled with its pointer", state, pointer, err)
	}
	if n := count(); n != 0 {
		t.Fatal("only a disposed original exists", n)
	}
	// A second settled legacy grant of the same dimension without any pointer.
	if _, err = db.Exec(`INSERT INTO public.capacity_mutation_grants(id,namespace,environment,domain,dimension,generation,integration_instance_id,scope_checksum,profile_name,slot,state,grant_record,expires_at) SELECT $2,namespace,environment,domain,dimension,2,integration_instance_id,scope_checksum,profile_name,2,'settled','{}',clock_timestamp()+interval '1 minute' FROM public.capacity_mutation_grants WHERE id=$1`, result.GrantID, uuid.NewString()); err != nil {
		t.Fatal(err)
	}
	if n := count(); n != 1 {
		t.Fatal("exactly the undisposed settled grant must count", n)
	}
}
