package manifestsync

import (
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

// resetNotifyChannelForTest is a test-only helper that resets the package
// notify channel so each test starts from a clean buffer.
func resetNotifyChannelForTest(t *testing.T) {
	t.Helper()
	notifyMu.Lock()
	defer notifyMu.Unlock()
	notifyCh = make(chan uuid.UUID, notifyBufferSize)
}

func TestNotify_DeliversToReceiver(t *testing.T) {
	resetNotifyChannelForTest(t)

	id := uuid.New()
	Notify(id)

	select {
	case got := <-NotifyChannel():
		assert.Equal(t, id, got)
	default:
		t.Fatalf("expected typeID on channel, got nothing")
	}
}

func TestNotify_NonBlockingWhenBufferFull(t *testing.T) {
	resetNotifyChannelForTest(t)

	// Fill the buffer to capacity.
	for i := 0; i < cap(NotifyChannel()); i++ {
		Notify(uuid.New())
	}

	// This call MUST NOT block — it returns immediately with the signal dropped.
	done := make(chan struct{})
	go func() {
		Notify(uuid.New())
		close(done)
	}()

	select {
	case <-done:
		// good — non-blocking semantic verified
	case <-time.After(100 * time.Millisecond):
		t.Fatalf("Notify blocked when buffer was full — must drop silently")
	}
}

func TestNotify_NilUUIDIsAccepted(t *testing.T) {
	resetNotifyChannelForTest(t)
	Notify(uuid.Nil) // must not panic; consumer is responsible for validation
	// Verify it was enqueued
	select {
	case got := <-NotifyChannel():
		assert.Equal(t, uuid.Nil, got)
	default:
		t.Fatalf("expected nil uuid on channel")
	}
}

// _ used to keep sync import alive in tests that may reference it
var _ = sync.Mutex{}
