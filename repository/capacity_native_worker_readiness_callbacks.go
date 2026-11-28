package repository

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// Authentication is performed by the dedicated listener before reading a body.
// This backend independently closes selectors over its own immutable journal;
// it accepts neither a resource object nor a permission from the HTTP caller.
type nativeReadinessBackend struct {
	journal *nativeReadinessRunJournal
	binding model.CapacityNativeWorkerProbeResourceBinding
}

func (b nativeReadinessBackend) selected(ctx context.Context, in model.NativeWorkerProbeResourceInput) (nativeReadinessRun, error) {
	id, err := uuid.Parse(in.RunID)
	if b.journal == nil || in.BindingName != b.binding.Name || err != nil || id == uuid.Nil || id.String() != in.RunID {
		return nativeReadinessRun{}, errNativeReadinessRun
	}
	r, err := b.journal.readRun(ctx, id)
	if err != nil {
		return nativeReadinessRun{}, err
	}
	c, err := nativeReadinessResourceContext(r, in.Slot)
	if err != nil || c.BindingName != b.binding.Name || c.SDKSourceCommit != b.binding.SourceCommit || c.SDKScopeSHA256 != b.binding.ScopeSHA256 || c.CoreSourceCommit != b.journal.source {
		return nativeReadinessRun{}, errNativeReadinessRun
	}
	return r, nil
}

func (b nativeReadinessBackend) Read(ctx context.Context, in model.NativeWorkerProbeResourceInput) (model.NativeWorkerProbeResourceContext, error) {
	r, err := b.selected(ctx, in)
	if err != nil {
		return model.NativeWorkerProbeResourceContext{}, err
	}
	return nativeReadinessResourceContext(r, in.Slot)
}

func (b nativeReadinessBackend) Bootstrap(ctx context.Context, in model.NativeWorkerProbeResourceInput) (model.NativeWorkerProbeResourceBootstrap, error) {
	var zero model.NativeWorkerProbeResourceBootstrap
	r, err := b.selected(ctx, in)
	if err != nil || r.Closed || !time.Now().Before(r.NotAfter) {
		return zero, errNativeReadinessRun
	}
	c, err := nativeReadinessResourceContext(r, in.Slot)
	if err != nil || c.State != "requested" || c.Op == "delete" {
		return zero, errNativeReadinessRun
	}
	raw, err := b.journal.privateRequest(r, in.Slot)
	if err != nil {
		return zero, err
	}
	return model.NativeWorkerProbeResourceBootstrap{Schema: model.NativeWorkerProbeResourceBootstrapSchema, Context: c, ObjectJSON: raw}, nil
}

func (b nativeReadinessBackend) Redeem(ctx context.Context, in model.NativeWorkerProbeResourceInput) (model.NativeWorkerProbeResourcePermit, error) {
	var zero model.NativeWorkerProbeResourcePermit
	r, err := b.selected(ctx, in)
	if err != nil || r.Closed {
		return zero, errNativeReadinessRun
	}
	// A creation right is revalidated from the actual stored Attempt and parent
	// command/lease inside journal.redeem's transaction, never from Read output.
	var raw []byte
	var a model.CapacityNativeWorkerAttempt
	if b.journal.db.QueryRowContext(ctx, `SELECT attempt FROM public.capacity_native_worker_attempts WHERE id=$1 AND policy_id=$2 AND namespace=$3`, r.Identity.AttemptID, r.Identity.PolicyID, r.Identity.Namespace).Scan(&raw) != nil || capacity.DecodeNativeCapacity(json.RawMessage(raw), &a) != nil {
		return zero, errNativeReadinessRun
	}
	next, token, err := b.journal.redeem(ctx, a, r, in.Slot)
	if err != nil {
		return zero, err
	}
	c, err := nativeReadinessResourceContext(next, in.Slot)
	if err != nil {
		// A consumed permit is never restored or returned with a different frame.
		return zero, err
	}
	return model.NativeWorkerProbeResourcePermit{Schema: model.NativeWorkerProbeResourcePermitSchema, Context: c, SettlementToken: token}, nil
}

func nativeReadinessReceiveContext(r nativeReadinessRun, slot, token string) (model.NativeWorkerProbeResourceContext, bool, error) {
	i, ok := nativeReadinessEffectIndex(r, slot)
	hash, valid := nativeReadinessTokenSHA(token)
	if !ok || !valid {
		return model.NativeWorkerProbeResourceContext{}, false, errNativeReadinessRun
	}
	e := r.Effects[i]
	creation := nativeReadinessSHA(e.CreateTokenSHA256) && subtle.ConstantTimeCompare([]byte(hash), []byte(e.CreateTokenSHA256)) == 1
	deletion := nativeReadinessSHA(e.DeleteTokenSHA256) && subtle.ConstantTimeCompare([]byte(hash), []byte(e.DeleteTokenSHA256)) == 1
	if creation == deletion || creation && e.Context == nil || deletion && e.DeleteContext == nil {
		return model.NativeWorkerProbeResourceContext{}, false, errNativeReadinessRun
	}
	if deletion {
		return *e.DeleteContext, true, nil
	}
	return *e.Context, false, nil
}

func (b nativeReadinessBackend) Receive(ctx context.Context, original model.NativeWorkerProbeResourceReceive) error {
	in := model.NativeWorkerProbeResourceInput{BindingName: original.BindingName, RunID: original.RunID, Slot: original.Slot}
	r, err := b.selected(ctx, in)
	if err != nil {
		return err
	}
	c, deletion, err := nativeReadinessReceiveContext(r, in.Slot, original.SettlementToken)
	if err != nil {
		return err
	}
	// Retried receiving can only match the identical previously retained bytes.
	// It cannot reopen a closed run or replace an earlier partial return.
	if r.Closed {
		return b.journal.sameOriginal(r, original, deletion)
	}
	index, exists := nativeReadinessEffectIndex(r, in.Slot)
	if !exists {
		return errNativeReadinessRun
	}
	effect := r.Effects[index]
	if (!deletion && effect.PrivateOriginal != nil && effect.State != "received" && effect.State != "send_started") || (deletion && effect.PrivateDeleteOriginal != nil && effect.State != "delete_received" && effect.State != "delete_started") {
		return b.journal.sameOriginal(r, original, deletion)
	}
	r, err = b.journal.captureOriginal(ctx, r, original)
	if err != nil {
		return err
	}
	expected, err := b.journal.privateRequest(r, in.Slot)
	defer clear(expected)
	if err != nil {
		return nil // The original is already privately custodied, not qualified.
	}
	var candidate []byte
	if c.Op == "startup_patch" {
		wire, err := b.journal.original(r, "candidate_pod", false)
		defer clear(wire)
		var create model.NativeWorkerProbeResourceReceive
		if err != nil || capacity.DecodeNativeCapacity(json.RawMessage(wire), &create) != nil {
			return nil
		}
		candidate = create.OriginalReturn
		defer clear(candidate)
	}
	index, exists = nativeReadinessEffectIndex(r, in.Slot)
	if !exists {
		return nil
	}
	accepted, err := nativeReadinessQualifyOriginal(c, expected, candidate, original, r.CreatedAt, time.Now().UTC(), r.Effects[index].StartupOrigin)
	if err != nil {
		// Custody has already committed. Incomplete/error returns stay received,
		// unavailable for readiness and never a reason for another mutation.
		return nil
	}
	// This endpoint acknowledges custody only. If the qualification/event Tx
	// fails, Read remains received/unknown; it cannot report observed until the
	// real atomic transaction succeeds during GET-only recovery.
	_ = b.journal.acceptOriginal(ctx, r, c, accepted)
	return nil
}

func (s *nativeReadinessRunJournal) sameOriginal(r nativeReadinessRun, original model.NativeWorkerProbeResourceReceive, deletion bool) error {
	old, err := s.original(r, original.Slot, deletion)
	defer clear(old)
	want, e := original.MarshalPrivateJSON()
	defer clear(want)
	if err != nil || e != nil || subtle.ConstantTimeCompare(old, want) != 1 {
		return errNativeReadinessRun
	}
	return nil
}

func (s *nativeReadinessRunJournal) acceptOriginal(ctx context.Context, r nativeReadinessRun, c model.NativeWorkerProbeResourceContext, accepted nativeReadinessOriginalAcceptance) error {
	i, ok := nativeReadinessEffectIndex(r, c.Slot)
	if !ok || accepted.UID == "" || !nativeReadinessSHA(accepted.SafeEvidenceSHA256) {
		return errNativeReadinessRun
	}
	e := r.Effects[i]
	// A duplicate complete original is idempotent, including after deletion has
	// begun. Receiving cannot regress the latest operation or its actual RV.
	if c.Op != "delete" && e.UID == accepted.UID && e.PrivateOriginal != nil && e.EvidenceSHA256 != "" && e.State != "received" {
		return nil
	}
	if c.Op == "delete" && e.PrivateDeleteOriginal != nil && (e.State == "delete_acknowledged" || e.State == "absent") {
		return nil
	}
	event, err := s.resourceEvent(r, c, accepted.UID, "ensured", accepted.EventType)
	if err != nil {
		return err
	}
	var emit *NativeWorkerProbeResourceEvent
	if c.Op != "delete" {
		emit = &event
	}
	_, err = s.editEvent(ctx, r, nil, emit, func(current *nativeReadinessRun, now time.Time) error {
		index, ok := nativeReadinessEffectIndex(*current, c.Slot)
		if !ok {
			return errNativeReadinessRun
		}
		x := &current.Effects[index]
		if c.Op == "delete" {
			if x.State != "delete_received" || x.PrivateDeleteOriginal == nil || x.UID != accepted.UID {
				return errNativeReadinessRun
			}
			// Safe native ACK only. The original known UID/RV stays available for
			// independent GET closure; a Status response supplies no new RV.
			x.State = "delete_acknowledged"
		} else {
			if x.State != "received" || x.PrivateOriginal == nil || !nativeReadinessResourceVersion(accepted.ResourceVersion) || x.UID != "" {
				return errNativeReadinessRun
			}
			x.UID, x.ResourceVersion, x.State = accepted.UID, accepted.ResourceVersion, "observed"
		}
		x.EvidenceSHA256, x.ObservedAt = accepted.SafeEvidenceSHA256, now
		return nil
	})
	return err
}

func nativeReadinessEmitEvent(ctx context.Context, tx *sql.Tx, e NativeWorkerProbeResourceEvent) error {
	raw, err := json.Marshal(e)
	var payload map[string]interface{}
	if err != nil || json.Unmarshal(raw, &payload) != nil || e.EventID == "" {
		return errNativeReadinessRun
	}
	_, _, verb, ok := ParseIntegrationMutationEventType(e.Type)
	if !ok || e.InstanceID == "" {
		return errNativeReadinessRun
	}
	_, err = EmitEvent(ctx, tx, model.EmitEventRequest{Type: e.Type, SchemaVersion: "v1", AggregateType: "native_worker_probe_resource", AggregateID: e.RunID + "/" + e.Slot, IdempotencyKey: e.EventID, Payload: map[string]interface{}{"provider": "kubernetes", "resource": "native_worker_probe_resource", "verb": verb, "resource_id": e.UID, "instance_id": e.InstanceID, "observed": payload}})
	return err
}

func (s *nativeReadinessRunJournal) resourceEvent(r nativeReadinessRun, c model.NativeWorkerProbeResourceContext, uid, verb, phase string) (NativeWorkerProbeResourceEvent, error) {
	p, err := parseCapacityPolicy(s.policy)
	if err != nil || p.NativeWorkerLifecycleBinding == nil || p.NativeWorkerLifecycleBinding.ReadinessProducer == nil || (verb != "ensured" && verb != "destroyed") {
		return NativeWorkerProbeResourceEvent{}, errNativeReadinessRun
	}
	b := p.NativeWorkerLifecycleBinding.ReadinessProducer.ResourceWriter
	if b.Name != c.BindingName || b.ScopeSHA256 != c.SDKScopeSHA256 || b.SourceCommit != c.SDKSourceCommit {
		return NativeWorkerProbeResourceEvent{}, errNativeReadinessRun
	}
	return NativeWorkerProbeResourceEvent{EventID: r.ID.String() + "/" + c.Slot + "/" + c.Op + "/" + uid + "/" + verb, Type: "kubernetes.native_worker_probe_resource." + verb, Namespace: c.Namespace, RunID: c.RunID, AttemptID: c.AttemptID, Slot: c.Slot, Operation: c.Op, APIVersion: c.APIVersion, Kind: c.Kind, Name: c.Name, UID: uid, InstanceID: b.Adapter.ManifestID, Phase: phase}, nil
}
