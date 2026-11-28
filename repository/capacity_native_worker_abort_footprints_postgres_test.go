package repository

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// This port is intentionally synthetic. It isolates the real Store/Goose
// transaction and append-only history; provider shape qualification is covered
// separately by the concrete runtime, pure Core receiver and SDK CI roots.
type abortFootprintPGRuntime struct {
	*abortPGRuntime
	attach   bool
	last     *model.CapacityNativeWorkerResourceFootprint
	volumeID string
}

func (r *abortFootprintPGRuntime) ObserveAbort(ctx context.Context, p model.Manifest, a model.CapacityNativeWorkerAttempt) (model.CapacityNativeWorkerAbortObservation, error) {
	o, err := r.abortPGRuntime.ObserveAbort(ctx, p, a)
	if err == nil && r.attach {
		r.last = &model.CapacityNativeWorkerResourceFootprint{Schema: "native_worker_resource_footprint_v1", Provider: "aws", ObservedAt: o.ObservedAt, Requested: model.CapacityNativeWorkerObservationRequest{AttemptID: a.ID.String(), ResourceID: a.Physical.ResourceID, LaunchSHA256: a.LaunchSHA256}, AWS: &model.CapacityNativeWorkerAWSResourceFootprint{RootVolume: model.CapacityNativeWorkerCleanupVolume{ResourceID: "vol-0123456789abcdef0"}}, EvidenceSHA256: strings.Repeat("7", 64)}
		o.ResourceFootprint = r.last
		if r.volumeID != "" {
			r.last.AWS.RootVolume.ResourceID = r.volumeID
		}
	}
	return o, err
}

func TestNativeAbortFootprintRedeemComparesHistoryAfterMutableObservationWasCleared(t *testing.T) {
	f, store, base, authority, _, _ := nativeWorkerAbortPGFixture(t, 30)
	runtime := &abortFootprintPGRuntime{abortPGRuntime: base, attach: true}
	store.Runtime = runtime
	a := abortPGChild(t, f, store, authority)
	permit, err := store.Begin(t.Context(), f.policy, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	runtime.attach = false
	if _, err = store.Reconcile(t.Context(), f.policy, permit.PermitID, abortPGCaller(a)); err != nil {
		t.Fatal(err)
	}
	if r := abortPGStored(t, f, permit.PermitID); r.Context.State != "issued" || r.Observation.ResourceFootprint != nil {
		t.Fatal("fixture did not clear only mutable latest observation")
	}
	runtime.attach = true
	runtime.volumeID = "vol-11111111111111111"
	if _, err = store.Redeem(t.Context(), f.policy, permit.PermitID, abortPGCaller(a)); err == nil {
		t.Fatal("replacement resource set acquired a one-send permission after observation overwrite")
	}
	if r := abortPGStored(t, f, permit.PermitID); r.Context.State != "issued" || r.TokenSHA256 != "" {
		t.Fatal("failed drift check retained a mutation bearer")
	}
	runtime.volumeID = ""
	if send, err := store.Redeem(t.Context(), f.policy, permit.PermitID, abortPGCaller(a)); err != nil || !send.MutationPermitted {
		t.Fatal("exact original resource set lost its valid one-send right", err)
	}
}

func TestNativeAbortFootprintCommitsOnRedeemAfterUnknownBeginAndSurvivesLatestOverwrite(t *testing.T) {
	f, store, base, authority, _, _ := nativeWorkerAbortPGFixture(t, 30)
	runtime := &abortFootprintPGRuntime{abortPGRuntime: base}
	store.Runtime = runtime
	a := abortPGChild(t, f, store, authority)
	base.node = "unknown"
	permit, err := store.Begin(t.Context(), f.policy, a.ID)
	if err != nil {
		t.Fatal("unknown Begin must retain quarantine without send permission", err)
	}
	base.node = ""
	runtime.attach = true
	send, err := store.Redeem(t.Context(), f.policy, permit.PermitID, abortPGCaller(a))
	if err != nil || !send.MutationPermitted {
		t.Fatal("fresh first snapshot was not committed with one-send permission", err)
	}
	stored := abortPGStored(t, f, permit.PermitID)
	if stored.Revision != 2 || stored.Observation == nil || stored.Observation.ResourceFootprint == nil || stored.Observation.ResourceFootprint.AWS.RootVolume.ResourceID != "vol-0123456789abcdef0" {
		t.Fatal("first present snapshot missing from actual Redeem event")
	}
	// Mutating the Go producer after return cannot change committed custody.
	runtime.last.AWS.RootVolume.ResourceID = "vol-11111111111111111"
	runtime.attach = false
	if _, err = store.Reconcile(t.Context(), f.policy, permit.PermitID, abortPGCaller(a)); err != nil {
		t.Fatal("later honest observation", err)
	}
	latest := abortPGStored(t, f, permit.PermitID)
	if latest.Observation == nil || latest.Observation.ResourceFootprint != nil {
		t.Fatal("fixture did not exercise latest Observation overwrite")
	}
	current, err := store.Workers.Read(t.Context(), f.policy, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	fp, err := nativeAbortCommittedResourceFootprint(t.Context(), f.db, f.policy, current, base.SourceCommit())
	if err != nil || fp == nil || fp.AWS.RootVolume.ResourceID != "vol-0123456789abcdef0" {
		t.Fatal("GET-only receiving trusted mutable latest observation or lost revision2 origin", err)
	}
	if _, err = f.db.ExecContext(t.Context(), `UPDATE public.capacity_native_worker_abort_events SET record=jsonb_set(record,'{observation,resource_footprint,aws,root_volume,resource_id}','"vol-11111111111111111"') WHERE permit_id=$1 AND revision=2`, permit.PermitID); err == nil {
		t.Fatal("append-only custody accepted historical resource replacement")
	}
	changed := f.policy
	changed.Checksum = strings.Repeat("0", 64)
	if _, err = nativeAbortCommittedResourceFootprint(t.Context(), f.db, changed, current, base.SourceCommit()); err == nil {
		t.Fatal("different policy checksum borrowed historical cleanup origin")
	}
	var raw []byte
	if err = f.db.QueryRowContext(t.Context(), `SELECT record FROM public.capacity_native_worker_abort_events WHERE permit_id=$1 AND revision=2`, permit.PermitID).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var original nativeWorkerAbortRecord
	if json.Unmarshal(raw, &original) != nil || original.Observation.ResourceFootprint.AWS.RootVolume.ResourceID != "vol-0123456789abcdef0" {
		t.Fatal("original history changed")
	}
}
