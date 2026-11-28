package repository

import (
	"context"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

func nativeReadinessRequestPurpose(slot string) string { return "request/" + slot }

// The whole exact private object is archived in the same transaction that
// establishes requested. A process restart cannot reconstruct a different
// Secret, patch or Pod under the original public template hash.
func (s *nativeReadinessRunJournal) beginPrivateRequest(ctx context.Context, a model.CapacityNativeWorkerAttempt, r nativeReadinessRun, slot, publicTemplate string, raw []byte, resourceContext *model.NativeWorkerProbeResourceContext, startupOrigin *nativeReadinessOriginalStartupOrigin) (nativeReadinessRun, error) {
	name, kind, ok := nativeReadinessSlot(r, slot)
	if !ok || !nativeReadinessSHA(publicTemplate) || len(raw) == 0 || len(raw) > 256<<10 {
		return nativeReadinessRun{}, errNativeReadinessRun
	}
	if nativeReadinessObjectKind(kind) || kind == "StartupChallenge" {
		if resourceContext == nil || resourceContext.RunID != r.ID.String() || resourceContext.AttemptID != a.ID.String() || resourceContext.CoreSourceCommit != r.Identity.SourceCommit || resourceContext.Slot != slot || resourceContext.Name != name || resourceContext.Namespace != r.Identity.Namespace || resourceContext.PublicTemplateSHA256 != publicTemplate || !resourceContext.NotAfter.Equal(r.NotAfter) || resourceContext.State != "requested" {
			return nativeReadinessRun{}, errNativeReadinessRun
		}
	}
	if (kind == "StartupChallenge") != (startupOrigin != nil) {
		return nativeReadinessRun{}, errNativeReadinessRun
	}
	return s.edit(ctx, r, &a, func(current *nativeReadinessRun, now time.Time) error {
		if len(current.Effects) >= 13 {
			return errNativeReadinessRun
		}
		if _, exists := nativeReadinessEffectIndex(*current, slot); exists {
			return errNativeReadinessRun
		}
		nonce, body, err := s.cryptPurpose(*current, nativeReadinessRequestPurpose(slot), nil, raw, true)
		if err != nil {
			return err
		}
		var own *model.NativeWorkerProbeResourceContext
		if resourceContext != nil {
			copy := *resourceContext
			own = &copy
		}
		current.Effects = append(current.Effects, nativeReadinessEffect{Name: name, Kind: kind, TemplateSHA256: publicTemplate, State: "requested", ObservedAt: now, OperationExpiresAt: current.NotAfter, Context: own, StartupOrigin: startupOrigin, PrivateRequest: &nativeReadinessCipher{Nonce: nonce, Ciphertext: body}})
		return nil
	})
}

// Deletion receives its own finite cleanup context without changing the
// immutable creation request, original token purpose or original lifetime.
func (s *nativeReadinessRunJournal) beginDeleteResource(ctx context.Context, r nativeReadinessRun, c model.NativeWorkerProbeResourceContext) (nativeReadinessRun, error) {
	name, kind, ok := nativeReadinessSlot(r, c.Slot)
	if !ok || !nativeReadinessObjectKind(kind) || c.RunID != r.ID.String() || c.AttemptID != r.Identity.AttemptID.String() || c.CoreSourceCommit != r.Identity.SourceCommit || c.Name != name || c.Namespace != r.Identity.Namespace || c.Op != "delete" || c.ExpectedUID == "" || c.ExpectedResourceVersion == "" || !nativeReadinessSHA(c.PublicTemplateSHA256) {
		return nativeReadinessRun{}, errNativeReadinessRun
	}
	return s.edit(ctx, r, nil, func(current *nativeReadinessRun, now time.Time) error {
		i, exists := nativeReadinessEffectIndex(*current, c.Slot)
		if !exists {
			return errNativeReadinessRun
		}
		e := &current.Effects[i]
		if e.State != "observed" || e.UID != c.ExpectedUID || e.PrivateOriginal == nil || e.Context == nil || e.DeleteContext != nil || e.DeleteTokenSHA256 != "" {
			return errNativeReadinessRun
		}
		c.State, c.NotAfter = "delete_requested", now.Add(20*time.Second)
		e.State, e.ObservedAt = c.State, now
		e.OperationExpiresAt, e.SettlementTokenSHA256 = c.NotAfter, ""
		e.DeleteContext = &c
		return nil
	})
}

func nativeReadinessResourceContext(r nativeReadinessRun, slot string) (model.NativeWorkerProbeResourceContext, error) {
	i, ok := nativeReadinessEffectIndex(r, slot)
	if !ok {
		return model.NativeWorkerProbeResourceContext{}, errNativeReadinessRun
	}
	e := r.Effects[i]
	context := e.Context
	if e.State == "delete_requested" || e.State == "delete_started" || e.State == "delete_received" || e.State == "delete_acknowledged" || e.State == "absent" {
		context = e.DeleteContext
	}
	if context == nil || context.RunID != r.ID.String() || context.Slot != slot || context.NotAfter.IsZero() || !context.NotAfter.Equal(e.OperationExpiresAt) {
		return model.NativeWorkerProbeResourceContext{}, errNativeReadinessRun
	}
	out := *context
	out.State = e.State
	if out.State == "delete_acknowledged" {
		out.State = "delete_received"
	}
	if e.State == "observed" {
		if e.UID == "" || e.ResourceVersion == "" {
			return model.NativeWorkerProbeResourceContext{}, errNativeReadinessRun
		}
		out.ExpectedUID, out.ExpectedResourceVersion = e.UID, e.ResourceVersion
	}
	return out, nil
}

func (s *nativeReadinessRunJournal) privateRequest(r nativeReadinessRun, slot string) ([]byte, error) {
	if s == nil || s.key == nil {
		return nil, errNativeReadinessRun
	}
	s.key.mu.RLock()
	defer s.key.mu.RUnlock()
	i, ok := nativeReadinessEffectIndex(r, slot)
	if s.key.closed || !ok || r.Effects[i].PrivateRequest == nil {
		return nil, errNativeReadinessRun
	}
	c := r.Effects[i].PrivateRequest
	_, raw, err := s.cryptPurpose(r, nativeReadinessRequestPurpose(slot), c.Nonce, c.Ciphertext, false)
	return raw, err
}

func (s *nativeReadinessRunJournal) original(r nativeReadinessRun, slot string, deletion bool) ([]byte, error) {
	if s == nil || s.key == nil {
		return nil, errNativeReadinessRun
	}
	s.key.mu.RLock()
	defer s.key.mu.RUnlock()
	i, ok := nativeReadinessEffectIndex(r, slot)
	if s.key.closed || !ok {
		return nil, errNativeReadinessRun
	}
	e := r.Effects[i]
	operation, token, c := "create", e.CreateTokenSHA256, e.PrivateOriginal
	if e.Kind == "StartupChallenge" {
		operation = "startup_patch"
	}
	if deletion {
		operation, token, c = "delete", e.DeleteTokenSHA256, e.PrivateDeleteOriginal
	}
	if c == nil || !nativeReadinessSHA(token) {
		return nil, errNativeReadinessRun
	}
	_, raw, err := s.cryptPurpose(r, "original/"+operation+"/"+slot+"/"+token, c.Nonce, c.Ciphertext, false)
	return raw, err
}

// The callback knows only its Source-closed run ID. The private row still has
// to match this producer's immutable policy/checksum/namespace/Source/scope.
func (s *nativeReadinessRunJournal) readRun(ctx context.Context, id uuid.UUID) (nativeReadinessRun, error) {
	if s == nil || s.key == nil || ctx == nil || ctx.Err() != nil || id == uuid.Nil {
		return nativeReadinessRun{}, errNativeReadinessRun
	}
	var attempt uuid.UUID
	if err := s.db.QueryRowContext(ctx, `SELECT attempt_id FROM public.capacity_native_worker_readiness_runs WHERE id=$1 AND record#>>'{identity,policy_id}'=$2 AND record#>>'{identity,policy_checksum}'=$3 AND record#>>'{identity,namespace}'=$4`, id, s.policy.ID.String(), s.policy.Checksum, s.policy.Metadata.Namespace).Scan(&attempt); err != nil {
		return nativeReadinessRun{}, errNativeReadinessRun
	}
	r, err := s.read(ctx, attempt)
	if err != nil || r.ID != id {
		return nativeReadinessRun{}, errNativeReadinessRun
	}
	return r, nil
}
