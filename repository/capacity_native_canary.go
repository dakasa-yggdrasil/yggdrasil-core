package repository

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

const originalNotifyWindowMarkerSchema = "core_original_notify_window_marker_v1"

var errOriginalNotifyWindow = errors.New("original Notify window unresolved")

type originalNotifyWindowStoreError struct{ cause error }

func (originalNotifyWindowStoreError) Error() string    { return errOriginalNotifyWindow.Error() }
func (originalNotifyWindowStoreError) GoString() string { return errOriginalNotifyWindow.Error() }
func (e originalNotifyWindowStoreError) Unwrap() error  { return e.cause }
func (originalNotifyWindowStoreError) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, errOriginalNotifyWindow.Error())
}

func originalNotifyStoreRefusal(causes ...error) error {
	return originalNotifyWindowStoreError{errors.Join(append([]error{errOriginalNotifyWindow}, causes...)...)}
}

func originalNotifyStoreContext(ctx context.Context) error {
	if ctx == nil {
		return errOriginalNotifyWindow
	}
	err := errors.Join(ctx.Err(), context.Cause(ctx))
	if deadline, ok := ctx.Deadline(); !ok || !time.Now().Before(deadline) {
		err = errors.Join(err, context.DeadlineExceeded)
	}
	return err
}

func originalNotifyMarkerSHA(value string) bool {
	b, err := hex.DecodeString(value)
	return err == nil && len(b) == 32 && hex.EncodeToString(b) == value
}

func originalNotifyMarkerUUID(value string) bool {
	u, err := uuid.Parse(value)
	return err == nil && u != uuid.Nil && u.String() == value
}

func originalNotifyMarkerSource(value string) bool {
	b, err := hex.DecodeString(value)
	return err == nil && len(b) == 20 && hex.EncodeToString(b) == value
}

func originalNotifyMarkerMatches(m model.CapacityOriginalNotifyWindowMarker, p model.Manifest, current model.CapacityIntent, store CapacityStore, now time.Time) bool {
	return m.Schema == originalNotifyWindowMarkerSchema && originalNotifyMarkerUUID(m.WindowID) &&
		originalNotifyMarkerSHA(m.ScopeSHA256) && originalNotifyMarkerSHA(m.RosterSHA256) && originalNotifyMarkerSHA(m.QuerySHA256) &&
		originalNotifyMarkerSource(m.SourceCommit) &&
		m.PolicyID == p.ID.String() && m.PolicyChecksum == p.Checksum && m.WorkflowID == store.WorkflowID.String() && originalNotifyMarkerSHA(m.WorkflowChecksum) &&
		originalNotifyMarkerUUID(m.DispatchJobID) && m.DispatchFence > 0 &&
		m.IntentGeneration == current.Generation && m.IntentFence == current.FencingToken &&
		m.LeaseOwner == current.LeaseOwner && m.ExecutorID == current.LeaseExecutorID && m.ExecutorID == store.ExecutorID &&
		current.LeaseExpiresAt != nil && m.Deadline.After(now) && !m.Deadline.After(*current.LeaseExpiresAt)
}

// BeginOriginalNotifyWindow is one durable possible-start, under the ORIGINAL
// intent lock/owner/executor/epoch. Only its actual Commit return can permit
// registration or one control call. An unacknowledged Commit is never retried.
func (s CapacityStore) BeginOriginalNotifyWindow(ctx context.Context, policy model.Manifest, intent model.CapacityIntent, marker model.CapacityOriginalNotifyWindowMarker) (model.CapacityIntent, error) {
	var observed model.CapacityIntent
	if err := originalNotifyStoreContext(ctx); err != nil {
		return observed, originalNotifyStoreRefusal(err)
	}
	err := s.mutationTransaction(ctx, policy, false, intent.Generation, intent.FencingToken, intent.LeaseOwner, func(tx *sql.Tx, p model.CapacityPolicySpec, current model.CapacityIntent, now time.Time) error {
		if p.NativeNotifyWindowBinding == nil || marker.State != "possible_start" || !marker.PossibleStartAt.IsZero() || marker.OriginalReturnsSHA256 != "" || marker.OriginalReturnsObservedAt != nil || !originalNotifyMarkerMatches(marker, policy, current, s, now) || marker.SourceCommit != p.NativeNotifyWindowBinding.SourceCommit || marker.QuerySHA256 != p.NativeNotifyWindowBinding.QuerySHA256 {
			return errOriginalNotifyWindow
		}
		if old := current.OriginalNotifyWindow; old != nil {
			// A later epoch cannot release an UNKNOWN original. Even a known
			// return never permits the same original job/window to publish twice.
			if old.State != "original_returns_observed" || old.OriginalReturnsObservedAt == nil || !originalNotifyMarkerSHA(old.OriginalReturnsSHA256) || old.WindowID == marker.WindowID || old.DispatchJobID == marker.DispatchJobID || marker.IntentFence <= old.IntentFence || marker.IntentGeneration < old.IntentGeneration {
				return errOriginalNotifyWindow
			}
		}
		if err := originalNotifyStoreContext(ctx); err != nil {
			return err
		}
		marker.PossibleStartAt = now
		current.OriginalNotifyWindow = &marker
		current.UpdatedAt = now
		raw, err := json.Marshal(current)
		if err != nil {
			return err
		}
		result, err := tx.ExecContext(ctx, `UPDATE public.capacity_intents SET intent=$5,updated_at=$6 WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4`, current.Namespace, p.Environment, p.Domain, p.Dimension, raw, now)
		if err != nil {
			return err
		}
		count, err := result.RowsAffected()
		if err != nil || count != 1 {
			return errors.Join(errOriginalNotifyWindow, err)
		}
		if err := originalNotifyStoreContext(ctx); err != nil {
			return err
		}
		observed = current
		return nil
	})
	if joined := errors.Join(err, originalNotifyStoreContext(ctx)); joined != nil {
		return model.CapacityIntent{}, originalNotifyStoreRefusal(joined)
	}
	return observed, nil
}

// ObserveOriginalNotifyWindow is GET-only after the first possible-start. It
// validates the SAME live lease and marker, and cannot create send permission.
func (s CapacityStore) ObserveOriginalNotifyWindow(ctx context.Context, policy model.Manifest, intent model.CapacityIntent, scopeSHA string) (model.CapacityOriginalNotifyWindowMarker, error) {
	var result model.CapacityOriginalNotifyWindowMarker
	if err := originalNotifyStoreContext(ctx); err != nil {
		return result, originalNotifyStoreRefusal(err)
	}
	err := s.mutationTransaction(ctx, policy, false, intent.Generation, intent.FencingToken, intent.LeaseOwner, func(_ *sql.Tx, _ model.CapacityPolicySpec, current model.CapacityIntent, now time.Time) error {
		m := current.OriginalNotifyWindow
		if m == nil || m.ScopeSHA256 != scopeSHA || !originalNotifyMarkerMatches(*m, policy, current, s, now) || m.PossibleStartAt.IsZero() || (m.State != "possible_start" && m.State != "original_returns_observed") {
			return errOriginalNotifyWindow
		}
		result = *m
		return originalNotifyStoreContext(ctx)
	})
	if joined := errors.Join(err, originalNotifyStoreContext(ctx)); joined != nil {
		return model.CapacityOriginalNotifyWindowMarker{}, originalNotifyStoreRefusal(joined)
	}
	return result, nil
}

// RecordOriginalNotifyWindowReturns retains observations only after all
// original source calls/reads return. The caller supplies a PRIVATE source
// join; no HTTP/workflow input is accepted here. Complete still needs its own
// current lease/claim/authorization fences and this actual final Commit ACK.
func (s CapacityStore) RecordOriginalNotifyWindowReturns(ctx context.Context, policy model.Manifest, intent model.CapacityIntent, scopeSHA, returnsSHA string, joinedAt time.Time) error {
	if !originalNotifyMarkerSHA(returnsSHA) || joinedAt.IsZero() || joinedAt.After(time.Now().UTC()) || originalNotifyStoreContext(ctx) != nil {
		return originalNotifyStoreRefusal(originalNotifyStoreContext(ctx))
	}
	err := s.mutationTransaction(ctx, policy, false, intent.Generation, intent.FencingToken, intent.LeaseOwner, func(tx *sql.Tx, p model.CapacityPolicySpec, current model.CapacityIntent, now time.Time) error {
		m := current.OriginalNotifyWindow
		// joinedAt and the captured deadline belong to the original Go owner.
		// PossibleStartAt is native PostgreSQL time: no inferred PG/Go offset
		// or cross-clock timestamp ordering supplies a return certificate.
		if m == nil || m.State != "possible_start" || m.ScopeSHA256 != scopeSHA || !originalNotifyMarkerMatches(*m, policy, current, s, now) || !joinedAt.Before(m.Deadline) {
			return errOriginalNotifyWindow
		}
		next := *m
		next.State, next.OriginalReturnsSHA256 = "original_returns_observed", returnsSHA
		next.OriginalReturnsObservedAt = &joinedAt
		current.OriginalNotifyWindow, current.UpdatedAt = &next, now
		raw, err := json.Marshal(current)
		if err != nil {
			return err
		}
		if err := originalNotifyStoreContext(ctx); err != nil {
			return err
		}
		result, err := tx.ExecContext(ctx, `UPDATE public.capacity_intents SET intent=$5,updated_at=$6 WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4`, current.Namespace, p.Environment, p.Domain, p.Dimension, raw, now)
		if err != nil {
			return err
		}
		count, err := result.RowsAffected()
		if err != nil || count != 1 {
			return errors.Join(errOriginalNotifyWindow, err)
		}
		return originalNotifyStoreContext(ctx)
	})
	if joined := errors.Join(err, originalNotifyStoreContext(ctx)); joined != nil {
		return originalNotifyStoreRefusal(joined)
	}
	return nil
}
