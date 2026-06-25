package reactors

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

type mockCaller struct {
	called int
}

func (m *mockCaller) Call(ctx context.Context, instanceID, capability string, payload []byte) error {
	m.called++
	return nil
}

func TestRunnerSingleTick_EmptyBatch(t *testing.T) {
	r := &Runner{
		DB:       nil,
		Interval: time.Second,
		Caller:   &mockCaller{},
	}
	r.claimBatch = func(ctx context.Context, limit int) ([]ClaimedReaction, error) {
		return nil, nil
	}
	if err := r.tickOnce(context.Background()); err != nil {
		t.Fatalf("tickOnce: %v", err)
	}
}

func TestRunnerDefaults(t *testing.T) {
	r := &Runner{}
	r.defaults()
	if r.Interval == 0 || r.BatchSize == 0 || r.Parallelism == 0 || r.StuckThreshold == 0 {
		t.Fatalf("defaults not set: %+v", r)
	}
	_ = uuid.New
}

// TestRunnerTickSkipsWhenBrokerUnavailable asserts that when BrokerAvailable
// returns false the runner skips the tick entirely — no reactions are claimed,
// no dispatches are attempted, and the rows remain in 'pending' for replay.
func TestRunnerTickSkipsWhenBrokerUnavailable(t *testing.T) {
	caller := &mockCaller{}
	claimed := false

	r := &Runner{
		DB:       nil,
		Interval: time.Second,
		Caller:   caller,
		BrokerAvailable: func() bool { return false },
	}
	r.claimBatch = func(ctx context.Context, limit int) ([]ClaimedReaction, error) {
		claimed = true
		return []ClaimedReaction{
			{
				ID:                    uuid.New(),
				EventID:               uuid.New(),
				EventType:             "test.event",
				IntegrationInstanceID: uuid.New(),
				Capability:            "on_something",
				Attempt:               0,
			},
		}, nil
	}

	if err := r.tickOnce(context.Background()); err != nil {
		t.Fatalf("tickOnce: unexpected error: %v", err)
	}
	if claimed {
		t.Error("claimBatch was called — reactions should not be claimed when broker is unavailable")
	}
	if caller.called > 0 {
		t.Errorf("Caller.Call was invoked %d times — should be 0 when broker is unavailable", caller.called)
	}
}
