package httpapi

import (
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
)

// ADR-0090: the owner wait is bounded and never fabricates a return; a late
// report stays on the buffered channel for the detached finalizer.
func TestCapacityDispatchOwnerAwaitNeverInventsReturn(t *testing.T) {
	returns := make(chan capacityDispatchOwnedReturn, 1)
	started := time.Now()
	owned, overdue := awaitCapacityDispatchReturn(returns, time.Now().Add(50*time.Millisecond))
	if !overdue || owned.panicked || owned.runErr != nil || !owned.returnedAt.IsZero() || owned.response.Status != "" {
		t.Fatal("overdue owner invented a return", owned)
	}
	if time.Since(started) > 5*time.Second {
		t.Fatal("owner wait was not bounded")
	}
	// The executor's late single report never blocks and is kept for the
	// detached finalizer.
	late := capacityDispatchOwnedReturn{response: model.RunWorkflowResponse{Status: "failed"}, returnedAt: time.Now().UTC()}
	select {
	case returns <- late:
	default:
		t.Fatal("executor report blocked")
	}
	if got := <-returns; got.response.Status != "failed" || !got.returnedAt.Equal(late.returnedAt) {
		t.Fatal("late report changed", got)
	}
	returns <- late
	owned, overdue = awaitCapacityDispatchReturn(returns, time.Now().Add(time.Hour))
	if overdue || owned.response.Status != "failed" || !owned.returnedAt.Equal(late.returnedAt) {
		t.Fatal("a reported return was not delivered", owned, overdue)
	}
	panicked := capacityDispatchOwnedReturn{panicked: true}
	returns <- panicked
	if owned, overdue = awaitCapacityDispatchReturn(returns, time.Now().Add(time.Hour)); overdue || !owned.panicked || !owned.returnedAt.IsZero() {
		t.Fatal("a panic was reported as a return", owned)
	}
}

func TestCapacityDispatchPendingFinalizationBoundedAndSecretFree(t *testing.T) {
	s := &CapacityDispatchService{}
	jobs := make([]uuid.UUID, 0, maxCapacityDispatchPendingReturns+1)
	for i := 0; i <= maxCapacityDispatchPendingReturns; i++ {
		id := uuid.New()
		jobs = append(jobs, id)
		s.deferFinalization(&capacityDispatchPendingFinalization{job: repository.CapacityDispatchJob{CapacityDispatchEnvelope: repository.CapacityDispatchEnvelope{JobID: id}}})
	}
	if len(s.pending) != maxCapacityDispatchPendingReturns {
		t.Fatal("pending observed returns are unbounded", len(s.pending))
	}
	for _, p := range s.pending {
		if p.next.IsZero() {
			t.Fatal("pending return is retried without backoff")
		}
	}
	s.record(capacityDispatchExecutorOverdue, jobs[0])
	events := s.DrainEvents()
	if len(events) != 2 || events[0].Category != capacityDispatchPendingDropped || events[0].JobID != jobs[maxCapacityDispatchPendingReturns] ||
		events[1].Category != capacityDispatchExecutorOverdue || events[1].JobID != jobs[0] {
		t.Fatal("finalization events lost or reordered", events)
	}
	if again := s.DrainEvents(); len(again) != 0 {
		t.Fatal("drained events were kept", again)
	}
	for i := 0; i < maxCapacityDispatchEvents+10; i++ {
		s.record(repository.CapacityDispatchFinishWriteRetry, jobs[0])
	}
	if events := s.DrainEvents(); len(events) != maxCapacityDispatchEvents {
		t.Fatal("event buffer is unbounded", len(events))
	}
	var nilService *CapacityDispatchService
	if nilService.DrainEvents() != nil {
		t.Fatal("nil service drained events")
	}
}
