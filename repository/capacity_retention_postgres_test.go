package repository

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
)

func TestCapacityIntentRetentionPostgres(t *testing.T) {
	db, policy, assessment := capacityPostgresFixture(t)
	ctx := context.Background()
	store := CapacityStore{DB: db, ExecutionEnabled: true, ExecutorID: uuid.NewString()}
	intent, err := store.Assess(ctx, policy, assessment)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := store.Claim(ctx, policy, intent.Generation, assessment)
	if err != nil {
		t.Fatal(err)
	}
	// Keep an unfinished live generation and its private lease as authoritative
	// state. Synthetic older event history belongs only to this fixture scope.
	if _, err = db.ExecContext(ctx, `UPDATE public.capacity_intents SET intent=jsonb_set(intent,'{generation}','4'::jsonb) WHERE namespace=$1`, policy.Metadata.Namespace); err != nil {
		t.Fatal(err)
	}
	var before string
	if err = db.QueryRowContext(ctx, `SELECT intent::text FROM public.capacity_intents WHERE namespace=$1`, policy.Metadata.Namespace).Scan(&before); err != nil {
		t.Fatal(err)
	}
	insert := func(generation int, dimension, receipt string, old bool) {
		t.Helper()
		days := 0
		if old {
			days = 91
		}
		_, err := db.ExecContext(ctx, `INSERT INTO public.capacity_intent_events(namespace,environment,domain,dimension,generation,fencing_token,phase,receipt_ref,recorded_at) VALUES($1,'production','api',$2,$3,1,'preparing',$4,clock_timestamp()-($5::integer*INTERVAL '1 day'))`, policy.Metadata.Namespace, dimension, generation, receipt, days)
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, record := range []struct {
		generation         int
		dimension, receipt string
		old                bool
	}{
		{0, "replicas", "old0", true}, {1, "replicas", "old1", true}, {2, "replicas", "old2", true},
		{3, "replicas", "previous", true}, {4, "replicas", "current", true}, {5, "replicas", "future", true},
		{1, "replicas", "recent", false}, {0, "orphan", "orphan", true},
	} {
		insert(record.generation, record.dimension, record.receipt, record.old)
	}
	n, err := PruneCapacityEvents(ctx, db, 90, 2)
	if err != nil || n != 2 {
		t.Fatal("bounded historical batch", n, err)
	}
	for i := 0; i < 60; i++ {
		insert(0, "replicas", fmt.Sprintf("parallel-%d", i), true)
	}
	var wg sync.WaitGroup
	var deleted atomic.Int64
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			n, err := PruneCapacityEvents(ctx, db, 90, 3)
			if err != nil || n > 3 {
				t.Errorf("concurrent bounded prune=%d,err=%v", n, err)
				return
			}
			deleted.Add(n)
		}()
	}
	wg.Wait()
	for {
		n, err := PruneCapacityEvents(ctx, db, 90, 3)
		if err != nil || n > 3 {
			t.Fatal("remaining bounded prune", n, err)
		}
		deleted.Add(n)
		if n == 0 {
			break
		}
	}
	if deleted.Load() != 61 {
		t.Fatal("replica pruning duplicated or skipped eligible history", deleted.Load())
	}
	for _, receipt := range []string{"previous", "current", "future", "recent", "orphan"} {
		var count int
		if err := db.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_intent_events WHERE namespace=$1 AND receipt_ref=$2`, policy.Metadata.Namespace, receipt).Scan(&count); err != nil || count != 1 {
			t.Fatal("protected event history removed", receipt, count, err)
		}
	}
	var after string
	if err := db.QueryRowContext(ctx, `SELECT intent::text FROM public.capacity_intents WHERE namespace=$1`, policy.Metadata.Namespace).Scan(&after); err != nil || after != before {
		t.Fatal("retention changed authority or live lease", err)
	}
	if lease.LeaseOwner == "" || lease.FencingToken == 0 {
		t.Fatal("fixture failed to retain actual private lease")
	}
	for _, bounds := range [][2]int{{29, 1}, {3651, 1}, {90, 0}, {90, 1001}} {
		if _, err := PruneCapacityEvents(ctx, db, bounds[0], bounds[1]); err == nil {
			t.Fatal("invalid retention bounds accepted", bounds)
		}
	}
}
