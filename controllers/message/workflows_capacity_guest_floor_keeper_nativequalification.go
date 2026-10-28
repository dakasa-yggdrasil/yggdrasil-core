//go:build linux && nativequalification

package message

import (
	"context"
	"sync"
	"time"
)

// Stop scheduling new probes and join the original in-flight probe. A normal
// stop cannot cancel a probe that may already hold a durable challenge. The
// retirement caller's original deadline bounds that wait; when it expires we
// cancel the same probe, still join it, and propagate the original deadline.
func startOriginalFloorKeeper(parent context.Context, ticks <-chan time.Time, stopTicker func(), probe func(context.Context) error) func(context.Context) error {
	original, cancel := context.WithCancel(parent)
	stop := make(chan struct{})
	returned := make(chan error, 1)
	var stateMu sync.Mutex
	stopping := false
	go func() {
		defer stopTicker()
		for {
			select {
			case <-original.Done():
				returned <- original.Err()
				return
			case <-stop:
				returned <- nil
				return
			case _, ok := <-ticks:
				if !ok {
					returned <- errOriginalGuestStep
					return
				}
				stateMu.Lock()
				if stopping {
					stateMu.Unlock()
					returned <- nil
					return
				}
				stateMu.Unlock()
				if err := original.Err(); err != nil {
					returned <- err
					return
				}
				if err := probe(original); err != nil {
					returned <- err
					return
				}
			}
		}
	}()
	var once sync.Once
	var joined error
	return func(deadline context.Context) error {
		once.Do(func() {
			stateMu.Lock()
			stopping = true
			close(stop)
			stateMu.Unlock()
			select {
			case joined = <-returned:
				cancel()
				if joined == nil && deadline.Err() != nil {
					joined = deadline.Err()
				}
			case <-deadline.Done():
				cancel()
				joined = <-returned
				if joined == nil {
					joined = deadline.Err()
				}
			}
		})
		return joined
	}
}
