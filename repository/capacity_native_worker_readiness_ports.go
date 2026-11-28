package repository

import (
	"context"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// NativeWorkerReadinessPorts are installed only by protected Core composition.
// They resolve the exact current catalogue and their own mTLS transport; neither
// a workflow nor a callback request supplies a URL, credential or object.
// The producer already runs under Workers' read fence: none of these callbacks
// may reenter that Workers owner or its runtime getter.
type NativeWorkerReadinessPorts struct {
	Mutate func(context.Context, model.CapacityNativeWorkerProbeResourceBinding, string, model.NativeWorkerProbeResourceInput) error
	Read   func(context.Context, model.CapacityNativeWorkerProbeResourceBinding, model.NativeWorkerProbeResourceInput) (model.NativeWorkerProbeResourceObservation, error)
	Phase  capacity.NativeWorkerPhaseReadFunc
}

// NativeWorkerProbeResourceEvent is emitted by the authenticated Core receiver
// only after original private custody and full expected-object qualification.
// EventID is deterministic for this run/slot/op/UID. The ordinary event stream
// persists it atomically with qualification using its durable dedup key. No
// SDK event bearer or parallel event emitter is required.
type NativeWorkerProbeResourceEvent struct {
	EventID    string `json:"event_id"`
	Type       string `json:"type"`
	Namespace  string `json:"namespace"`
	RunID      string `json:"run_id"`
	AttemptID  string `json:"attempt_id"`
	Slot       string `json:"slot"`
	Operation  string `json:"operation"`
	APIVersion string `json:"api_version"`
	Kind       string `json:"kind"`
	Name       string `json:"name"`
	UID        string `json:"uid"`
	InstanceID string `json:"instance_id"`
	Phase      string `json:"phase"`
}
