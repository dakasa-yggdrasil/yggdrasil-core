package capacity

import (
	"context"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// NativeWorkerLifecycleRead is private Go evidence from one fresh sealed read.
// BirthRequestIDs remain the historical acceptance/witness identities. The
// current request identity is separate; a missing HCloud HTTP ID stays empty.
// This carrier grants no transition and is never decoded from workflow input.
type NativeWorkerLifecycleRead struct {
	Adapter                                           model.CapacityMarketAdapterBinding
	Physical                                          model.CapacityNativeWorkerPhysical
	ObservedAt                                        time.Time
	SourceCommit, ScopeSHA256, EvidenceSHA256         string
	CurrentRequestID                                  string
	BirthOriginalRequestID, BirthIndependentRequestID string
	OriginalReturnSHA256                              string
	HCloudWitness                                     *model.CapacityNativeWorkerHCloudWitness
}

func (NativeWorkerLifecycleRead) String() string     { return "[private Native lifecycle read]" }
func (r NativeWorkerLifecycleRead) GoString() string { return r.String() }

func (NativeWorkerLifecycleRead) MarshalJSON() ([]byte, error) {
	return []byte(`{"private_native_lifecycle_read":"redacted"}`), nil
}

// ReadLifecycleACK does not call an actor or synthesize an acknowledged state.
// The same callback result is retained which the sealed qualifier checked.
func (q *NativeWorkerACKQualifier) ReadLifecycleACK(ctx context.Context, a model.CapacityNativeWorkerAttempt, launch []byte, original model.CapacityNativeWorkerOriginalReturn) (NativeWorkerLifecycleRead, error) {
	var zero NativeWorkerLifecycleRead
	if q == nil || q.read == nil || ctx == nil || ctx.Err() != nil {
		return zero, errNativePhysical
	}
	var captured model.CapacityNativeWorkerPhysicalObservation
	count := 0
	bound := *q
	bound.read = func(c context.Context, b model.CapacityNativeWorkerPhysicalReadBinding, in model.CapacityNativeWorkerObservationRequest) (model.CapacityNativeWorkerPhysicalObservation, error) {
		count++
		v, err := q.read(c, b, in)
		if err != nil {
			return v, err
		}
		captured, err = cloneNativeTransportRead(v)
		return captured, err
	}
	qualified, err := bound.qualify(ctx, a, launch, original, true)
	if err != nil || count != 1 || ctx.Err() != nil {
		return zero, errNativePhysical
	}
	out := NativeWorkerLifecycleRead{Adapter: captured.Adapter, Physical: qualified.IndependentCurrent, ObservedAt: captured.ObservedAt,
		SourceCommit: captured.SourceCommit, ScopeSHA256: captured.BindingScopeSHA256, EvidenceSHA256: captured.EvidenceSHA256,
		BirthOriginalRequestID: qualified.OriginalRequestID, BirthIndependentRequestID: qualified.IndependentRequestID,
		OriginalReturnSHA256: nativePrivateSHA(original.Wire)}
	if a.Provider == "hetzner" {
		if captured.HCloud == nil || a.HCloudWitness == nil {
			return zero, errNativePhysical
		}
		h := captured.HCloud
		if len(h.Reads) != 7 {
			return zero, errNativePhysical
		}
		out.ObservedAt, out.SourceCommit, out.ScopeSHA256, out.EvidenceSHA256 = h.ObservedAt, h.SourceCommit, h.BindingScopeSHA256, h.EvidenceSHA256
		out.CurrentRequestID = h.Reads[6].RequestID
		out.Adapter = h.Adapter
		out.BirthOriginalRequestID = a.HCloudWitness.Acceptance.RequestID
		out.BirthIndependentRequestID = a.HCloudWitness.Observation.Reads[len(a.HCloudWitness.Observation.Reads)-1].RequestID
		out.HCloudWitness = CloneNativeWorkerHCloudWitness(a.HCloudWitness)
	} else {
		if len(captured.Reads) != 7 {
			return zero, errNativePhysical
		}
		out.CurrentRequestID = captured.Reads[6].RequestID
	}
	if out.Physical != *a.Physical || !ValidDigest(out.EvidenceSHA256) || !ValidDigest(out.OriginalReturnSHA256) {
		return zero, errNativePhysical
	}
	return out, nil
}
