package capacity

import (
	"context"
	"encoding/json"
	"net/netip"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// NativeWorkerTransportObservation is a Go-only sealed reobservation. It is
// neither an original acceptance nor network/readiness/admission permission.
// Its transport address and freshness come from the same independently read
// provider response which the existing sealed-birth qualifier validated.
type NativeWorkerTransportObservation struct {
	Physical              model.CapacityNativeWorkerPhysical
	ObservedAt            time.Time
	EvidenceSHA256        string
	SourceCommit          string
	ScopeSHA256           string
	TransportEndpointIPv4 string
}

// ReobserveTransportACK retains current transport facts which ReobserveACK's
// physical-only ABI deliberately omits. It performs exactly the same one fresh
// independent read and all existing original/launch/sealed identity checks.
// An absent public endpoint stays unavailable, even when an older physical-only
// caller can legitimately reobserve that provider response.
func (q *NativeWorkerACKQualifier) ReobserveTransportACK(ctx context.Context, a model.CapacityNativeWorkerAttempt, launch []byte, original model.CapacityNativeWorkerOriginalReturn) (NativeWorkerTransportObservation, error) {
	var zero NativeWorkerTransportObservation
	if q == nil || q.read == nil {
		return zero, errNativePhysical
	}
	var captured model.CapacityNativeWorkerPhysicalObservation
	readCount := 0
	bound := *q
	bound.read = func(c context.Context, b model.CapacityNativeWorkerPhysicalReadBinding, in model.CapacityNativeWorkerObservationRequest) (model.CapacityNativeWorkerPhysicalObservation, error) {
		readCount++
		v, err := q.read(c, b, in)
		if err != nil {
			return model.CapacityNativeWorkerPhysicalObservation{}, err
		}
		captured, err = cloneNativeTransportRead(v)
		return captured, err
	}
	qualified, err := bound.qualify(ctx, a, launch, original, true)
	if err != nil || readCount != 1 || ctx.Err() != nil {
		return zero, errNativePhysical
	}
	out := NativeWorkerTransportObservation{Physical: qualified.IndependentCurrent,
		ObservedAt: captured.ObservedAt, EvidenceSHA256: captured.EvidenceSHA256,
		SourceCommit: captured.SourceCommit, ScopeSHA256: captured.BindingScopeSHA256,
		TransportEndpointIPv4: captured.TransportEndpointIPv4}
	if a.Provider == "hetzner" {
		if captured.HCloud == nil {
			return zero, errNativePhysical
		}
		h := captured.HCloud
		out.ObservedAt, out.EvidenceSHA256 = h.ObservedAt, h.EvidenceSHA256
		out.SourceCommit, out.ScopeSHA256 = h.SourceCommit, h.BindingScopeSHA256
		out.TransportEndpointIPv4 = h.TransportEndpointIPv4
	}
	ip, err := netip.ParseAddr(out.TransportEndpointIPv4)
	if err != nil || !ip.Is4() || ip.String() != out.TransportEndpointIPv4 || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return zero, errNativePhysical
	}
	return out, nil
}

// The HCloud carrier is intentionally json:"-" on the AWS DTO. Clone it
// separately rather than silently losing it through an AWS wire roundtrip.
// All decoder and provider checks still run against the complete copied read.
func cloneNativeTransportRead(v model.CapacityNativeWorkerPhysicalObservation) (model.CapacityNativeWorkerPhysicalObservation, error) {
	h := v.HCloud
	v.HCloud = nil
	raw, err := json.Marshal(v)
	var out model.CapacityNativeWorkerPhysicalObservation
	if err != nil || len(raw) > 2<<20 || DecodeNativeCapacity(json.RawMessage(raw), &out) != nil {
		return out, errNativePhysical
	}
	if h != nil {
		raw, err = json.Marshal(h)
		var hcloudCopy model.CapacityNativeWorkerHCloudPhysicalObservation
		if err != nil || len(raw) > 2<<20 || DecodeNativeCapacity(json.RawMessage(raw), &hcloudCopy) != nil {
			return model.CapacityNativeWorkerPhysicalObservation{}, errNativePhysical
		}
		out.HCloud = &hcloudCopy
	}
	return out, nil
}
