package repository

import (
	"context"
	"encoding/json"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// Exact known UID plus a fresh complete independent GET is closure. A DELETE
// ACK, callback204, unknown create or expired timer is never absence evidence.
func (s *nativeReadinessProducerState) recordAbsence(ctx context.Context, r nativeReadinessRun, slot string, o model.NativeWorkerProbeResourceObservation) (nativeReadinessRun, error) {
	i, exists := nativeReadinessEffectIndex(r, slot)
	if !exists {
		return nativeReadinessRun{}, errNativeReadinessRun
	}
	e := r.Effects[i]
	if !nativeReadinessObjectKind(e.Kind) || e.UID == "" || e.PrivateOriginal == nil || e.Context == nil || o.Found || nativeReadinessObservationHeader(r, s.pins, o, slot, e.UID, time.Now().UTC()) != nil {
		return nativeReadinessRun{}, errNativeReadinessRun
	}
	c := *e.Context
	if e.DeleteContext != nil {
		c = *e.DeleteContext
	} else {
		c.Op, c.State, c.ExpectedUID, c.ExpectedResourceVersion = "delete", "absent", e.UID, e.ResourceVersion
		raw, err := s.journal.privateRequest(r, slot)
		defer clear(raw)
		if err != nil {
			return nativeReadinessRun{}, err
		}
		sha, err := capacity.NativeWorkerProbePublicTemplateSHA(c, raw)
		if err != nil {
			return nativeReadinessRun{}, err
		}
		c.PublicTemplateSHA256 = sha
	}
	event, err := s.journal.resourceEvent(r, c, e.UID, "destroyed", "independent_absence")
	if err != nil {
		return nativeReadinessRun{}, err
	}
	raw, err := json.Marshal(o)
	defer clear(raw)
	if err != nil {
		return nativeReadinessRun{}, err
	}
	return s.journal.editEvent(ctx, r, nil, &event, func(current *nativeReadinessRun, now time.Time) error {
		i, ok := nativeReadinessEffectIndex(*current, slot)
		if !ok || o.ObservedAt.After(now) || now.Sub(o.ObservedAt) >= s.pins.MaxAge {
			return errNativeReadinessRun
		}
		x := &current.Effects[i]
		if x.UID != e.UID || x.PrivateOriginal == nil || x.State == "requested" || x.State == "send_started" || x.State == "received" || x.State == "absent" {
			return errNativeReadinessRun
		}
		nonce, sealed, err := s.journal.cryptPurpose(*current, "absence/"+slot, nil, raw, true)
		if err != nil {
			return err
		}
		c.State = "absent"
		x.DeleteContext = &c
		x.OperationExpiresAt = c.NotAfter
		x.State, x.EvidenceSHA256, x.ObservedAt = "absent", o.EvidenceSHA256, o.ObservedAt
		x.PrivateAbsence = &nativeReadinessCipher{Nonce: nonce, Ciphertext: sealed}
		return nil
	})
}

func (s *nativeReadinessProducerState) cleanup(ctx context.Context, a model.CapacityNativeWorkerAttempt, r nativeReadinessRun) (nativeReadinessRun, error) {
	var held bool
	// Remove the running processes before their keys and networking. The fixed
	// list never includes the real floor Node/worker or any business object.
	for _, slot := range []string{"candidate_pod", "floor_pod", "candidate_service", "floor_service", "candidate_secret", "floor_secret", "admission_secret", "network_policy"} {
		latest, err := s.journal.read(ctx, a.ID)
		if err != nil {
			return r, err
		}
		r = latest
		i, exists := nativeReadinessEffectIndex(r, slot)
		if !exists {
			continue
		}
		e := r.Effects[i]
		if e.State == "absent" {
			continue
		}
		if e.UID == "" {
			held = true
			continue
		}
		o, err := s.observe(ctx, a, r, slot)
		if err != nil {
			held = true
			continue
		}
		if !o.Found {
			r, err = s.recordAbsence(ctx, r, slot, o)
			if err != nil {
				return r, err
			}
			continue
		}
		if e.State == "observed" {
			c := *e.Context
			c.Op = "delete"
			c.ExpectedUID, c.ExpectedResourceVersion = o.Resource.UID, o.Resource.ResourceVersion
			original, err := s.journal.privateRequest(r, slot)
			if err != nil {
				return r, err
			}
			c.PublicTemplateSHA256, err = capacity.NativeWorkerProbePublicTemplateSHA(c, original)
			clear(original)
			if err != nil {
				return r, err
			}
			r, err = s.journal.beginDeleteResource(ctx, r, c)
			if err != nil {
				return r, err
			}
			_ = s.ports.Mutate(ctx, s.config.Binding.ResourceWriter, capacity.DestroyNativeWorkerProbeResource, model.NativeWorkerProbeResourceInput{BindingName: s.config.Binding.ResourceWriter.Name, RunID: r.ID.String(), Slot: slot})
			// A returned error still consumed this sole invocation. Never resend.
		}
		deadline := time.NewTimer(20 * time.Second)
		tick := time.NewTicker(200 * time.Millisecond)
		closed := false
		for !closed {
			latest, err = s.journal.read(ctx, a.ID)
			if err != nil {
				deadline.Stop()
				tick.Stop()
				return r, err
			}
			r = latest
			o, err = s.observe(ctx, a, r, slot)
			if err == nil && !o.Found {
				r, err = s.recordAbsence(ctx, r, slot, o)
				if err != nil {
					deadline.Stop()
					tick.Stop()
					return r, err
				}
				closed = true
				break
			}
			select {
			case <-ctx.Done():
				deadline.Stop()
				tick.Stop()
				return r, errNativeReadinessRun
			case <-deadline.C:
				tick.Stop()
				return r, errNativeReadinessRun
			case <-tick.C:
			}
		}
		deadline.Stop()
		tick.Stop()
	}
	if held {
		return r, errNativeReadinessRun
	}
	return r, nil
}
