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
