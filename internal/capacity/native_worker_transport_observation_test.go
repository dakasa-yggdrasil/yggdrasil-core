package capacity

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func nativeTransportFixture(t *testing.T, provider string) (model.CapacityPolicySpec, model.CapacityNativeWorkerAttempt, []byte, model.CapacityNativeWorkerOriginalReturn, model.CapacityNativeWorkerPhysicalObservation) {
	t.Helper()
	var p model.CapacityPolicySpec
	var a model.CapacityNativeWorkerAttempt
	var launch []byte
	var original model.CapacityNativeWorkerOriginalReturn
	var read model.CapacityNativeWorkerPhysicalObservation
	var now time.Time
	if provider == "hetzner" {
		p, a, launch, original, read, now = nativeHCloudPhysicalFixture(t)
	} else {
		p, a, launch, original, read, now = nativePhysicalFixture(t)
		read.TransportEndpointIPv4 = "203.0.113.8"
		sealNativePhysicalFixture(&read)
	}
	ack, err := PureNativePhysicalQualify(a, launch, original, read, p.NativeWorkerLifecycleBinding.PhysicalObservers[0], 30, now)
	if err != nil {
		t.Fatal("existing real-shape original/read fixture refused", err)
	}
	a.State, a.Physical, a.BirthSHA256 = "registered", &ack.IndependentCurrent, strings.Repeat("e", 64)
	a.HCloudWitness = CloneNativeWorkerHCloudWitness(ack.HCloudWitness)
	return p, a, launch, original, read
}

func TestNativeTransportUsesOneValidatedReadAndPreservesSealedState(t *testing.T) {
	for _, provider := range []string{"aws", "hetzner"} {
		t.Run(provider, func(t *testing.T) {
			p, a, launch, original, read := nativeTransportFixture(t, provider)
			before, _ := json.Marshal(a)
			calls := 0
			q, err := NewNativeWorkerACKQualifier(p, func(_ context.Context, b model.CapacityNativeWorkerPhysicalReadBinding, in model.CapacityNativeWorkerObservationRequest) (model.CapacityNativeWorkerPhysicalObservation, error) {
				calls++
				if !reflect.DeepEqual(b, p.NativeWorkerLifecycleBinding.PhysicalObservers[0]) || in != (model.CapacityNativeWorkerObservationRequest{BindingName: b.BindingName, AttemptID: a.ID.String(), ResourceID: a.Physical.ResourceID, LaunchSHA256: a.LaunchSHA256}) {
					t.Fatal("current read lost original protected binding or stored target")
				}
				return read, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			got, err := q.ReobserveTransportACK(t.Context(), a, launch, original)
			b := p.NativeWorkerLifecycleBinding.PhysicalObservers[0]
			observed, evidence := read.ObservedAt, read.EvidenceSHA256
			if read.HCloud != nil {
				observed, evidence = read.HCloud.ObservedAt, read.HCloud.EvidenceSHA256
			}
			after, _ := json.Marshal(a)
			if err != nil || calls != 1 || got.Physical != *a.Physical || got.TransportEndpointIPv4 != "203.0.113.8" || !got.ObservedAt.Equal(observed) || got.EvidenceSHA256 != evidence || got.SourceCommit != b.SourceCommit || got.ScopeSHA256 != b.ScopeSHA256 || !bytes.Equal(before, after) {
				t.Fatal("fresh transport did not come from the same sealed identity/read", err, calls)
			}
			// A copied local qualifier must not replace the original reader or
			// change its physical-only ABI. This is an explicit separate call.
			physical, err := q.ReobserveACK(t.Context(), a, launch, original)
			if err != nil || calls != 2 || physical != *a.Physical {
				t.Fatal("new read port changed the original qualifier", err)
			}
		})
	}
}

func TestNativeTransportRequiresPublicEndpointAndKeepsAllOriginalGuards(t *testing.T) {
	for _, provider := range []string{"aws", "hetzner"} {
		for _, fault := range []string{"unsealed", "launch", "partialOriginal", "source", "scope", "privateEndpoint", "cancelled"} {
			t.Run(provider+"/"+fault, func(t *testing.T) {
				p, a, launch, original, read := nativeTransportFixture(t, provider)
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				wantReads := 0
				switch fault {
				case "unsealed":
					a.Physical, a.BirthSHA256 = nil, ""
				case "launch":
					launch = append(bytes.Clone(launch), '\n')
				case "partialOriginal":
					original.CaptureComplete = false
				case "source", "scope", "privateEndpoint":
					wantReads = 1
					if read.HCloud != nil {
						switch fault {
						case "source":
							read.HCloud.SourceCommit = strings.Repeat("f", 40)
						case "scope":
							read.HCloud.BindingScopeSHA256 = strings.Repeat("f", 64)
						case "privateEndpoint":
							read.HCloud.TransportEndpointIPv4 = read.HCloud.Physical.NativeIPv4
							read.HCloud.PrimaryIPs[0].IP = read.HCloud.Physical.NativeIPv4
						}
						sealNativeHCloudFixture(read.HCloud)
					} else {
						switch fault {
						case "source":
							read.SourceCommit = strings.Repeat("f", 40)
						case "scope":
							read.BindingScopeSHA256 = strings.Repeat("f", 64)
						case "privateEndpoint":
							read.TransportEndpointIPv4 = read.Physical.NativeIPv4
						}
						sealNativePhysicalFixture(&read)
					}
				case "cancelled":
					cancel()
				}
				calls := 0
				q, err := NewNativeWorkerACKQualifier(p, func(context.Context, model.CapacityNativeWorkerPhysicalReadBinding, model.CapacityNativeWorkerObservationRequest) (model.CapacityNativeWorkerPhysicalObservation, error) {
					calls++
					return read, nil
				})
				if err != nil {
					t.Fatal(err)
				}
				if _, err = q.ReobserveTransportACK(ctx, a, launch, original); err == nil || calls != wantReads {
					t.Fatal("transport port bypassed original sealed receiving", err, calls, wantReads)
				}
			})
		}
	}
	p, a, launch, original, read := nativeTransportFixture(t, "aws")
	read.TransportEndpointIPv4 = "" // The earlier optional AWS wire is still valid.
	sealNativePhysicalFixture(&read)
	calls := 0
	q, err := NewNativeWorkerACKQualifier(p, func(context.Context, model.CapacityNativeWorkerPhysicalReadBinding, model.CapacityNativeWorkerObservationRequest) (model.CapacityNativeWorkerPhysicalObservation, error) {
		calls++
		return read, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = q.ReobserveTransportACK(t.Context(), a, launch, original); err == nil || calls != 1 {
		t.Fatal("missing public transport address became an invented endpoint")
	}
	if got, err := q.ReobserveACK(t.Context(), a, launch, original); err != nil || got != *a.Physical || calls != 2 {
		t.Fatal("optional transport changed the existing physical-only ABI", err)
	}
}

func TestNativeTransportCopiesCarrierAndPublicEvidenceKeepsRawOriginalPrivate(t *testing.T) {
	p, a, launch, original, read, now := nativeHCloudPhysicalFixture(t)
	b := p.NativeWorkerLifecycleBinding.PhysicalObservers[0]
	ack, err := PureNativePhysicalQualify(a, launch, original, read, b, 30, now)
	if err != nil {
		t.Fatal(err)
	}
	// Both the original Go observation and the public witness must retain the
	// original privacy boundary. OriginalReturnSHA256 is already json:"-".
	for _, value := range []any{ack, ack.HCloudWitness} {
		wire, err := json.Marshal(value)
		if err != nil || bytes.Contains(wire, []byte(nativePrivateSHA(original.Wire))) || bytes.Contains(wire, []byte("root_password")) || bytes.Contains(wire, []byte("CI-only-private-original-password")) {
			t.Fatal("original observation/witness serialization disclosed private custody")
		}
	}
	copy, err := cloneNativeTransportRead(read)
	if err != nil || copy.HCloud == nil || !reflect.DeepEqual(copy, read) {
		t.Fatal("internal HCloud carrier was lost through the AWS wire", err)
	}
	copy.HCloud.PrimaryIPs[0].IP = "203.0.113.9"
	copy.HCloud.Reads[0].Operation = "changed-copy"
	if read.HCloud.PrimaryIPs[0].IP != "203.0.113.8" || read.HCloud.Reads[0].Operation != "GET /networks/{id}" {
		t.Fatal("copied read retained mutable producer-owned storage")
	}
}
