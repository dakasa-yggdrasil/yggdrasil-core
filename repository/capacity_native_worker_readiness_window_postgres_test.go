package repository

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

func TestNativeReadinessPostgresNewRunBudgetRefusesBeforeKeysOrResourceEffects(t *testing.T) {
	for _, ttl := range []time.Duration{179999 * time.Millisecond, 300 * time.Second} {
		t.Run(ttl.String(), func(t *testing.T) {
			f, a, producer, _ := nativeReadinessComposedFixture(t, nativeReadinessComposedOptions{NoOpen: true, QuoteTTL: ttl})
			s := producer.state.journal
			var originalCommand []byte
			if err := f.db.QueryRowContext(t.Context(), `SELECT record FROM public.capacity_native_worker_command_contexts WHERE attempt_id=$1`, a.ID).Scan(&originalCommand); err != nil {
				t.Fatal(err)
			}
			var command nativeWorkerCommandContext
			if json.Unmarshal(originalCommand, &command) != nil {
				t.Fatal("original command fixture missing")
			}
			generated := 0
			r, keys, err := s.open(t.Context(), a, func(uuid.UUID, time.Time, time.Time) ([]byte, error) {
				generated++
				return bytes.Repeat([]byte{7}, 256), nil
			})
			clear(keys)
			if ttl < nativeReadinessMinimumRun {
				if err == nil || generated != 0 || r.ID != uuid.Nil {
					t.Fatal("insufficient original time generated keys or admitted a run")
				}
			} else if err != nil || generated != 1 || r.ID == uuid.Nil || r.NotAfter.Sub(r.CreatedAt) < nativeReadinessMinimumRun || r.NotAfter.Sub(r.CreatedAt) > nativeReadinessMaximumRun || r.NotAfter.After(command.ExpiresAt) || r.NotAfter.After(a.QualificationValidUntil) {
				t.Fatal("sufficient original authority was widened or not retained", err)
			}
			var runs, events int
			if err := f.db.QueryRowContext(t.Context(), `SELECT (SELECT count(*) FROM public.capacity_native_worker_readiness_runs),(SELECT count(*) FROM public.capacity_native_worker_readiness_events)`).Scan(&runs, &events); err != nil {
				t.Fatal(err)
			}
			if ttl < nativeReadinessMinimumRun && (runs != 0 || events != 0) || ttl >= nativeReadinessMinimumRun && (runs != 1 || events != 1 || len(r.Effects) != 0) {
				t.Fatal("new-run threshold had resource/history effects before its admission")
			}
			var after []byte
			if err := f.db.QueryRowContext(t.Context(), `SELECT record FROM public.capacity_native_worker_command_contexts WHERE attempt_id=$1`, a.ID).Scan(&after); err != nil || !bytes.Equal(after, originalCommand) {
				t.Fatal("diagnostic budget rewrote the immutable original command", err)
			}
			// The original parent remains the actual Claim, never extended by this
			// diagnostic choice; receiving/cleanup after expiry has separate roots.
			var parent model.CapacityIntent
			if err := f.db.QueryRowContext(t.Context(), `SELECT intent FROM public.capacity_intents WHERE namespace=$1`, a.Namespace).Scan((*nativeIntentScan)(&parent)); err != nil || parent.LeaseExpiresAt == nil || ttl >= nativeReadinessMinimumRun && r.NotAfter.After(*parent.LeaseExpiresAt) {
				t.Fatal("diagnostic window escaped the original parent", err)
			}
		})
	}
}
