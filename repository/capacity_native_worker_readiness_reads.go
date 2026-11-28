package repository

import (
	"context"
	"encoding/json"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
)

type nativeReadinessReadOriginal struct {
	Status      int       `json:"status"`
	Complete    bool      `json:"complete"`
	CompletedAt time.Time `json:"completed_at"`
	Original    []byte    `json:"original"`
}

func (nativeReadinessReadOriginal) MarshalJSON() ([]byte, error) {
	return []byte(`{"private_native_readiness_read":"redacted"}`), nil
}

func nativeReadinessReadSlot(slot string) bool {
	switch slot {
	case "floor_report_initial", "candidate_report_initial", "floor_report_final", "candidate_report_final", "startup_before", "startup_after":
		return true
	}
	return false
}

// Each fixed GET result is encrypted before decoding. A later GET replaces the
// latest pointer only; the SQL trigger retains EVERY original revision in the
// immutable private event archive. This map cannot authorize a network send.
func (s *nativeReadinessRunJournal) captureRead(ctx context.Context, r nativeReadinessRun, slot string, status int, raw []byte, complete bool) (nativeReadinessRun, error) {
	if !nativeReadinessReadSlot(slot) || len(raw) > 256<<10 {
		return nativeReadinessRun{}, errNativeReadinessRun
	}
	type wire nativeReadinessReadOriginal
	body, err := json.Marshal(wire{Status: status, Complete: complete, CompletedAt: time.Now().UTC(), Original: raw})
	defer clear(body)
	if err != nil {
		return nativeReadinessRun{}, errNativeReadinessRun
	}
	return s.edit(ctx, r, nil, func(current *nativeReadinessRun, _ time.Time) error {
		if current.PendingProof != nil {
			return errNativeReadinessRun
		}
		nonce, sealed, err := s.cryptPurpose(*current, "read/"+slot, nil, body, true)
		if err != nil {
			return err
		}
		if current.Reads == nil {
			current.Reads = map[string]*nativeReadinessCipher{}
		}
		current.Reads[slot] = &nativeReadinessCipher{Nonce: nonce, Ciphertext: sealed}
		return nil
	})
}

func (s *nativeReadinessRunJournal) readOriginal(r nativeReadinessRun, slot string) (nativeReadinessReadOriginal, error) {
	var zero nativeReadinessReadOriginal
	if s == nil || s.key == nil || !nativeReadinessReadSlot(slot) {
		return zero, errNativeReadinessRun
	}
	s.key.mu.RLock()
	defer s.key.mu.RUnlock()
	c := r.Reads[slot]
	if s.key.closed || c == nil {
		return zero, errNativeReadinessRun
	}
	_, raw, err := s.cryptPurpose(r, "read/"+slot, c.Nonce, c.Ciphertext, false)
	defer clear(raw)
	if err != nil || capacity.DecodeNativeCapacity(json.RawMessage(raw), &zero) != nil {
		return nativeReadinessReadOriginal{}, errNativeReadinessRun
	}
	return zero, nil
}
