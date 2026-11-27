package capacity

import (
	"math"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func nativePoolFixture(now time.Time) (model.CapacityNativeWorkerPoolBinding, *model.CapacityNativeWorkerPoolObservation) {
	b := model.CapacityNativeWorkerPoolBinding{Mode: "native_worker_pool_v1", Name: "native-surplus", SourceCommit: "0123456789012345678901234567890123456789", Adapter: marketTestAdapter(), RealmUID: marketTestUUID(10), PoolUID: marketTestUUID(11), Owner: "capacity-pool", MaxAgeSeconds: 60, ExpectedPoolEpoch: 7, RegistryRef: model.CapacityNativePoolRegistryRef{Kind: "Lease", Namespace: "infra", Name: "native-pool-owner", UID: marketTestUUID(12)}, Profiles: []model.CapacityNativeWorkerProfileBinding{{Profile: "hcloud", Provider: "hcloud", ProviderIDPrefix: "hcloud://", PhysicalSpecSHA256: marketTestSHA("d"), RegistrationBindingSHA: marketTestSHA("e"), MinAllocatableMilliCPU: 2_000, MinAllocatableMemory: 4 << 30}}, ProtectedNodes: []model.CapacityNativeProtectedNode{{NodeUID: marketTestUUID(13), ProviderID: "hcloud://protected-floor"}}}
	o := &model.CapacityNativeWorkerPoolObservation{Schema: b.Mode, SourceCommit: b.SourceCommit, Adapter: b.Adapter, RealmUID: b.RealmUID, PoolUID: b.PoolUID, Owner: b.Owner, CurrentProfile: "hcloud", OwnerEpoch: b.ExpectedPoolEpoch, RegistryRef: b.RegistryRef, OwnerResourceUID: b.RegistryRef.UID, OwnerResourceVersion: "123", CollectionResourceVersion: "456", EvidenceSHA256: marketTestSHA("f"), ObservedAt: now, Complete: true, Nodes: []model.CapacityNativeWorkerNode{{NodeUID: marketTestUUID(14), NodeResourceVersion: "789", ProviderID: "hcloud://123456", Provider: "hcloud", Profile: "hcloud", PoolUID: b.PoolUID, RegistrationEpoch: b.ExpectedPoolEpoch, RegistrationBindingSHA256: b.Profiles[0].RegistrationBindingSHA, PhysicalSpecSHA256: b.Profiles[0].PhysicalSpecSHA256, CurrentRegistration: true, CapacityPolicyID: marketTestUUID(15), IntentGeneration: 2, FencingToken: 3, RegistrationReceiptSHA256: marketTestSHA("a"), Ready: true, SchedulingAdmitted: true, AdmissionReceiptSHA256: marketTestSHA("b"), AdmissionRegistryUID: b.RegistryRef.UID, AdmissionRegistryResourceVersion: "123", ReadyObservedAt: now, AllocatableMilliCPU: 4_000, AllocatableMemoryBytes: 8 << 30}}}
	return b, o
}

func TestNativeWorkerPoolCountsActualOwnedNodesAndAllowsZero(t *testing.T) {
	now := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	b, o := nativePoolFixture(now)
	s, err := SummarizeNativeWorkerPool(b, o, b.ExpectedPoolEpoch, now)
	if err != nil || s.RegisteredUnits != 1 || s.ReadyUnits != 1 || s.AllocatableMilliCPU != 4_000 || s.AllocatableMemoryBytes != 8<<30 {
		t.Fatalf("exact node roster not counted: %+v %v", s, err)
	}
	o.Nodes[0].Ready = false
	s, err = SummarizeNativeWorkerPool(b, o, b.ExpectedPoolEpoch, now)
	if err != nil || s.RegisteredUnits != 1 || s.ReadyUnits != 0 || s.AllocatableMilliCPU != 0 {
		t.Fatalf("unready became usable or vanished from registration: %+v %v", s, err)
	}
	o.Nodes[0].Ready = true
	o.Nodes[0].SchedulingAdmitted = false
	s, err = SummarizeNativeWorkerPool(b, o, b.ExpectedPoolEpoch, now)
	if err != nil || s.RegisteredUnits != 1 || s.ReadyUnits != 0 {
		t.Fatalf("quarantined Ready worker became useful: %+v %v", s, err)
	}
	o.Nodes = []model.CapacityNativeWorkerNode{}
	s, err = SummarizeNativeWorkerPool(b, o, b.ExpectedPoolEpoch, now)
	if err != nil || s.RegisteredUnits != 0 || s.ReadyUnits != 0 {
		t.Fatalf("empty surplus pool fabricated a paid unit: %+v %v", s, err)
	}
}

func TestNativeWorkerPoolProviderNameDoesNotInventProviderIDScheme(t *testing.T) {
	now := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct{ provider, prefix, id string }{
		{"hetzner", "hcloud://", "hcloud://177895230"},
		{"aws", "aws:///", "aws:///us-east-1a/i-0123456789abcdef0"},
	} {
		b, o := nativePoolFixture(now)
		b.Profiles[0].Provider = tc.provider
		b.Profiles[0].ProviderIDPrefix = tc.prefix
		o.Nodes[0].Provider = tc.provider
		o.Nodes[0].ProviderID = tc.id
		if s, err := SummarizeNativeWorkerPool(b, o, b.ExpectedPoolEpoch, now); err != nil || s.ReadyUnits != 1 {
			t.Fatalf("explicit %s scheme binding refused: %+v %v", tc.provider, s, err)
		}
	}
}

func TestNativeWorkerPoolRejectsWrongEpochFloorIdentityAndStaleReady(t *testing.T) {
	now := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name   string
		mutate func(*model.CapacityNativeWorkerPoolBinding, *model.CapacityNativeWorkerPoolObservation)
	}{
		{"incomplete", func(b *model.CapacityNativeWorkerPoolBinding, o *model.CapacityNativeWorkerPoolObservation) {
			o.Complete = false
		}},
		{"caller_epoch", func(b *model.CapacityNativeWorkerPoolBinding, o *model.CapacityNativeWorkerPoolObservation) {
			o.OwnerEpoch++
		}},
		{"registry_uid", func(b *model.CapacityNativeWorkerPoolBinding, o *model.CapacityNativeWorkerPoolObservation) {
			o.RegistryRef.UID = marketTestUUID(99)
		}},
		{"registry_kind", func(b *model.CapacityNativeWorkerPoolBinding, o *model.CapacityNativeWorkerPoolObservation) {
			b.RegistryRef.Kind = "Secret"
		}},
		{"registry_namespace", func(b *model.CapacityNativeWorkerPoolBinding, o *model.CapacityNativeWorkerPoolObservation) {
			b.RegistryRef.Namespace = "wrong.namespace"
		}},
		{"wrong_owner_uid", func(b *model.CapacityNativeWorkerPoolBinding, o *model.CapacityNativeWorkerPoolObservation) {
			o.OwnerResourceUID = marketTestUUID(99)
		}},
		{"wrong_realm", func(b *model.CapacityNativeWorkerPoolBinding, o *model.CapacityNativeWorkerPoolObservation) {
			o.RealmUID = marketTestUUID(99)
		}},
		{"wrong_source", func(b *model.CapacityNativeWorkerPoolBinding, o *model.CapacityNativeWorkerPoolObservation) {
			o.SourceCommit = "1123456789012345678901234567890123456789"
		}},
		{"missing_source", func(b *model.CapacityNativeWorkerPoolBinding, o *model.CapacityNativeWorkerPoolObservation) {
			b.SourceCommit = ""
		}},
		{"wrong_type", func(b *model.CapacityNativeWorkerPoolBinding, o *model.CapacityNativeWorkerPoolObservation) {
			o.Adapter.IntegrationTypeID = marketTestUUID(99)
		}},
		{"stale_collection", func(b *model.CapacityNativeWorkerPoolBinding, o *model.CapacityNativeWorkerPoolObservation) {
			o.ObservedAt = now.Add(-61 * time.Second)
		}},
		{"future_collection", func(b *model.CapacityNativeWorkerPoolBinding, o *model.CapacityNativeWorkerPoolObservation) {
			o.ObservedAt = now.Add(time.Second)
		}},
		{"stale_ready", func(b *model.CapacityNativeWorkerPoolBinding, o *model.CapacityNativeWorkerPoolObservation) {
			o.Nodes[0].ReadyObservedAt = now.Add(-61 * time.Second)
		}},
		{"floor_uid", func(b *model.CapacityNativeWorkerPoolBinding, o *model.CapacityNativeWorkerPoolObservation) {
			o.Nodes[0].NodeUID = b.ProtectedNodes[0].NodeUID
		}},
		{"floor_provider", func(b *model.CapacityNativeWorkerPoolBinding, o *model.CapacityNativeWorkerPoolObservation) {
			o.Nodes[0].ProviderID = b.ProtectedNodes[0].ProviderID
		}},
		{"provider_prefix", func(b *model.CapacityNativeWorkerPoolBinding, o *model.CapacityNativeWorkerPoolObservation) {
			o.Nodes[0].ProviderID = "aws:///us-east-1/i-a"
		}},
		{"duplicate_node", func(b *model.CapacityNativeWorkerPoolBinding, o *model.CapacityNativeWorkerPoolObservation) {
			o.Nodes = append(o.Nodes, o.Nodes[0])
		}},
		{"duplicate_physical", func(b *model.CapacityNativeWorkerPoolBinding, o *model.CapacityNativeWorkerPoolObservation) {
			n := o.Nodes[0]
			n.NodeUID = marketTestUUID(99)
			o.Nodes = append(o.Nodes, n)
		}},
		{"registration_stale_epoch", func(b *model.CapacityNativeWorkerPoolBinding, o *model.CapacityNativeWorkerPoolObservation) {
			o.Nodes[0].RegistrationEpoch--
		}},
		{"registration_absent", func(b *model.CapacityNativeWorkerPoolBinding, o *model.CapacityNativeWorkerPoolObservation) {
			o.Nodes[0].CurrentRegistration = false
		}},
		{"registration_policy_missing", func(b *model.CapacityNativeWorkerPoolBinding, o *model.CapacityNativeWorkerPoolObservation) {
			o.Nodes[0].CapacityPolicyID = ""
		}},
		{"registration_fence_missing", func(b *model.CapacityNativeWorkerPoolBinding, o *model.CapacityNativeWorkerPoolObservation) {
			o.Nodes[0].FencingToken = 0
		}},
		{"registration_receipt_missing", func(b *model.CapacityNativeWorkerPoolBinding, o *model.CapacityNativeWorkerPoolObservation) {
			o.Nodes[0].RegistrationReceiptSHA256 = ""
		}},
		{"admission_receipt_missing", func(b *model.CapacityNativeWorkerPoolBinding, o *model.CapacityNativeWorkerPoolObservation) {
			o.Nodes[0].AdmissionReceiptSHA256 = ""
		}},
		{"admission_wrong_registry", func(b *model.CapacityNativeWorkerPoolBinding, o *model.CapacityNativeWorkerPoolObservation) {
			o.Nodes[0].AdmissionRegistryUID = marketTestUUID(99)
		}},
		{"admission_stale_registry", func(b *model.CapacityNativeWorkerPoolBinding, o *model.CapacityNativeWorkerPoolObservation) {
			o.Nodes[0].AdmissionRegistryResourceVersion = "stale"
		}},
		{"unqualified_physical", func(b *model.CapacityNativeWorkerPoolBinding, o *model.CapacityNativeWorkerPoolObservation) {
			o.Nodes[0].PhysicalSpecSHA256 = marketTestSHA("b")
		}},
		{"insufficient_allocatable", func(b *model.CapacityNativeWorkerPoolBinding, o *model.CapacityNativeWorkerPoolObservation) {
			o.Nodes[0].AllocatableMilliCPU = 1_000
		}},
		{"wrong_registry_profile", func(b *model.CapacityNativeWorkerPoolBinding, o *model.CapacityNativeWorkerPoolObservation) {
			o.CurrentProfile = "undeclared"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, o := nativePoolFixture(now)
			tc.mutate(&b, o)
			if _, err := SummarizeNativeWorkerPool(b, o, 7, now); err == nil {
				t.Fatal("unowned/unqualified worker counted")
			}
		})
	}
}

func TestNativeWorkerPoolRejectsEchoedEpochAndArithmeticOverflow(t *testing.T) {
	now := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	b, o := nativePoolFixture(now)
	o.OwnerEpoch = 8
	if _, err := SummarizeNativeWorkerPool(b, o, 8, now); err == nil {
		t.Fatal("observation's own epoch accepted as authority")
	}
	b, o = nativePoolFixture(now)
	n := o.Nodes[0]
	n.NodeUID = marketTestUUID(99)
	n.ProviderID = "hcloud://999999"
	o.Nodes = append(o.Nodes, n)
	o.Nodes[0].AllocatableMilliCPU = math.MaxInt64
	if _, err := SummarizeNativeWorkerPool(b, o, 7, now); err == nil {
		t.Fatal("allocatable CPU overflow accepted")
	}
}
