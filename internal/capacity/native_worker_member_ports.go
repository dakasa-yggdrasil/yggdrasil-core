package capacity

import (
	"context"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// These ports are installed by the protected owner. No workflow can install a
// callback, choose its URL, mint its observations or supply a mutation target.
type NativeWorkerMemberReadFunc func(context.Context, model.CapacityNativeWorkerMemberEndpoint, model.CapacityNativeWorkerMemberSelectors) (model.CapacityNativeWorkerMemberObservation, error)
type NativeWorkerMemberWriteFunc func(context.Context, model.CapacityNativeWorkerMemberEndpoint, model.CapacityNativeWorkerMemberSelectors) error
type NativeWorkerAllocatorFenceReadFunc func(context.Context, model.CapacityNativeWorkerMemberEndpoint, model.CapacityNativeWorkerMemberSelectors) (model.CapacityNativeWorkerAllocatorFenceObservation, error)
type NativeWorkerPlacementBootstrapReadFunc func(context.Context, model.CapacityNativeWorkerAttempt) (model.CapacityNativeWorkerPlacementBootstrapObservation, error)

// Installation facts are protected input, never values copied from a read
// response. A new guard installation invalidates the old pins and canaries.
// ConfigMap parameters are an immutable audit mirror of Source literals in
// the VAP, not a dynamic paramRef whose cache miss could deny legacy traffic.
type NativeWorkerMemberAuthority struct {
	FenceObjects          []model.CapacityNativeWorkerFenceObject
	Enforcement           []model.CapacityNativeWorkerFenceEnforcement
	LegacyControllers     []model.CapacityNativeWorkerLegacyController
	WorkloadContracts     []string
	WorkloadLineage       map[string][]model.CapacityNativeWorkerMemberController
	SystemSourceCommit    string
	KubeletVersion        string
	AgentConfigPath       string
	ConfiguredKubeletArgs []string
}

// Facts have an effective expiry which is capped by EVERY original observation
// used, including the guest and effective configuration reads. A fresh outer
// GET does not make an old packet, bootstrap or installer fact fresh again.
type NativeWorkerMemberFacts struct {
	Observation model.CapacityNativeWorkerMemberObservation
	Bootstrap   model.CapacityNativeWorkerPlacementBootstrapObservation
	Fence       model.CapacityNativeWorkerAllocatorFenceObservation
	ValidUntil  time.Time
	Physical    *NativeWorkerMemberPhysicalFact
	Absence     *model.CapacityNativeWorkerAbortObservation
}

// Safe current facts from the existing sealed qualifier. Historical raw return
// hashes and acceptance credentials are deliberately absent from this carrier.
type NativeWorkerMemberPhysicalFact struct {
	Physical                                  model.CapacityNativeWorkerPhysical
	Adapter                                   model.CapacityMarketAdapterBinding
	SourceCommit, ScopeSHA256, EvidenceSHA256 string
	ObservedAt                                time.Time
}

// Admitted-provider destruction intentionally has no implementation or fallback
// in this vertical. Abort v1 remains strictly pre-admission. Do not satisfy this
// missing port with an ACK, a bool, a fixture or the old destroy operation.
