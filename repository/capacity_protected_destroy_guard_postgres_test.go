package repository

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// Both qualification checkpoints invoke this same repository API. Repeating
// the real PostgreSQL transaction proves exact refusal and no granted mutation.
func TestProtectedDestroyGuardPostgres(t *testing.T) {
	f := mutationPostgresFixture(t, false)
	var spec model.CapacityMutationSpecV1
	if err := json.Unmarshal(f.plans[1].DesiredSpec, &spec); err != nil {
		t.Fatal(err)
	}
	spec.Capability = f.binding.DestroyCapability
	spec.ExpectedResourceID = "protected-resource"
	spec.ExpectedResourceCreatedAt = f.created
	wire, err := json.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	issue := model.CapacityMutationIssue{BindingName: f.binding.Name, DesiredSpec: wire}
	for i := 0; i < 2; i++ {
		if _, err := f.store.IssueMutation(context.Background(), f.policy, f.intent.Generation, f.intent.FencingToken, f.intent.LeaseOwner, issue); !errors.Is(err, capacity.ErrProtectedMutationDestroy) {
			t.Fatalf("checkpoint %d did not reach the protected guard: %v", i, err)
		}
	}
	var grants int
	if err := f.db.QueryRowContext(context.Background(), `SELECT count(*) FROM public.capacity_mutation_grants WHERE namespace=$1`, f.policy.Metadata.Namespace).Scan(&grants); err != nil || grants != 0 {
		t.Fatalf("protected rejection changed grants: count=%d err=%v", grants, err)
	}
}
