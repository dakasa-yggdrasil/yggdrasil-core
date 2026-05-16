package manifestsync

import (
	"sync"

	"github.com/google/uuid"
)

const notifyBufferSize = 128

var (
	notifyMu sync.Mutex
	notifyCh = make(chan uuid.UUID, notifyBufferSize)
)

// Notify enqueues an integration_type ID for re-sync by the runner.
// Non-blocking: if the buffer is full, the signal is silently dropped.
// The cron safety-net (1h) covers any dropped signals — this channel is a
// fast-path nudge, not the source of truth.
//
// Callers (e.g. controllers/message/integration_describe.go) MUST tolerate
// dropped signals and never treat Notify as transactional.
func Notify(typeID uuid.UUID) {
	notifyMu.Lock()
	ch := notifyCh
	notifyMu.Unlock()

	select {
	case ch <- typeID:
	default:
		// buffer full → drop; cron will catch
	}
}

// NotifyChannel returns the channel of signaled type IDs for the runner
// to consume. Returned as bidirectional (rather than receive-only) so the
// same chan can be passed to tests that drain it.
func NotifyChannel() chan uuid.UUID {
	notifyMu.Lock()
	defer notifyMu.Unlock()
	return notifyCh
}
