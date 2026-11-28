package capacity

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func TestNativeLifecycleReadKeepsCurrentReadSeparateFromHistoricalBirth(t *testing.T) {
	for _, provider := range []string{"aws", "hetzner"} {
		t.Run(provider, func(t *testing.T) {
			p, a, launch, original, read := nativeTransportFixture(t, provider)
			before, _ := json.Marshal(a)
			currentID := "current-http-read"
			if provider == "hetzner" {
				read.HCloud.Reads[6].RequestID = currentID
				read.HCloud.Reads[6].RequestIDObserved = true
				sealNativeHCloudFixture(read.HCloud)
			} else {
				read.Reads[6].RequestID = currentID
				sealNativePhysicalFixture(&read)
			}
			calls := 0
			q, err := NewNativeWorkerACKQualifier(p, func(_ context.Context, b model.CapacityNativeWorkerPhysicalReadBinding, in model.CapacityNativeWorkerObservationRequest) (model.CapacityNativeWorkerPhysicalObservation, error) {
				calls++
				if b.Adapter != p.NativeWorkerLifecycleBinding.PhysicalObservers[0].Adapter || in.AttemptID != a.ID.String() || in.ResourceID != a.Physical.ResourceID || in.LaunchSHA256 != a.LaunchSHA256 {
					t.Fatal("unbound current read")
				}
				return read, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			got, err := q.ReadLifecycleACK(t.Context(), a, launch, original)
			after, _ := json.Marshal(a)
			if err != nil || calls != 1 || got.Physical != *a.Physical || got.CurrentRequestID != currentID || got.OriginalReturnSHA256 != nativePrivateSHA(original.Wire) || !bytes.Equal(before, after) {
				t.Fatal("sealed lifecycle read did not retain one actual current read", err, calls)
			}
			if provider == "hetzner" {
				if got.HCloudWitness == nil || got.HCloudWitness.EvidenceSHA256 != a.HCloudWitness.EvidenceSHA256 || got.BirthIndependentRequestID != a.HCloudWitness.Observation.Reads[6].RequestID || got.BirthIndependentRequestID == got.CurrentRequestID {
					t.Fatal("fresh read relabeled historical witness")
				}
				got.HCloudWitness.Observation.Physical.ResourceID = "mutated-copy"
				if a.HCloudWitness.Observation.Physical.ResourceID == "mutated-copy" || read.HCloud.Physical.ResourceID == "mutated-copy" {
					t.Fatal("private carrier aliases original witness")
				}
			}
			wire, _ := json.Marshal(got)
			if bytes.Contains(wire, []byte(got.OriginalReturnSHA256)) || bytes.Contains(wire, []byte(currentID)) {
				t.Fatal("private read facts serialized")
			}
		})
	}
}
