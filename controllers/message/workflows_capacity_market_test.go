package message

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

func TestProtectedWorkerMarketCollectorKeepsHealthyProviderOnIndependentFailure(t *testing.T) {
	for _, fault := range []string{"collector_unavailable", "collector_contract_refused"} {
		t.Run(fault, func(t *testing.T) {
			now := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
			sha := func(s string) string { return strings.Repeat(s, 64) }
			adapter := model.CapacityMarketAdapterBinding{ManifestID: uuid.NewString(), Version: 3, Checksum: sha("a"), IntegrationTypeID: uuid.NewString(), TypeChecksum: sha("b")}
			b := &model.CapacityNativeWorkerPoolBinding{Mode: "native_worker_pool_v1", Name: "workers", SourceCommit: strings.Repeat("a", 40), Adapter: adapter, RealmUID: uuid.NewString(), PoolUID: uuid.NewString(), Owner: "pool-owner", MaxAgeSeconds: 60, ExpectedPoolEpoch: 1, RegistryRef: model.CapacityNativePoolRegistryRef{Kind: "Lease", Namespace: "infra", Name: "workers", UID: uuid.NewString()}, Profiles: []model.CapacityNativeWorkerProfileBinding{}, ProtectedNodes: []model.CapacityNativeProtectedNode{{NodeUID: uuid.NewString(), ProviderID: "hcloud://1"}}}
			p := model.CapacityPolicySpec{Currency: "USD", TargetIdentity: "native/workers", Owner: b.Owner, Profiles: []model.CapacityProfile{{Name: "hcloud"}, {Name: "aws"}}, NativeWorkerPoolBinding: b, MarketBinding: &model.CapacityMarketBinding{HorizonSeconds: 60, MaxQuoteAgeSeconds: 60, Profiles: []model.CapacityMarketProfileBinding{}}}
			for _, name := range []string{"hcloud", "aws"} {
				b.Profiles = append(b.Profiles, model.CapacityNativeWorkerProfileBinding{Profile: name, Provider: name, ProviderIDPrefix: name + "://", PhysicalSpecSHA256: sha("a"), RegistrationBindingSHA: sha("c"), MinAllocatableMilliCPU: 1000, MinAllocatableMemory: 1 << 30})
				p.MarketBinding.Profiles = append(p.MarketBinding.Profiles, model.CapacityMarketProfileBinding{Profile: name, Provider: name, Region: "region", Adapter: adapter})
			}
			o := model.CapacityNativeWorkerPoolObservation{Schema: b.Mode, SourceCommit: b.SourceCommit, Adapter: adapter, RealmUID: b.RealmUID, PoolUID: b.PoolUID, Owner: b.Owner, CurrentProfile: "hcloud", OwnerEpoch: 1, RegistryRef: b.RegistryRef, OwnerResourceUID: b.RegistryRef.UID, OwnerResourceVersion: "1", CollectionResourceVersion: "2", EvidenceSHA256: sha("d"), ObservedAt: now, Complete: true, Nodes: []model.CapacityNativeWorkerNode{}}
			var calls []string
			read := func(actual model.CapacityObservationAdapterBinding, op string, input map[string]any, out any) (string, error) {
				if actual != marketObservationAdapter(adapter) {
					t.Fatal("unbound adapter selected")
				}
				if len(input) != 1 {
					t.Fatal("caller-selected fields reached a protected collector")
				}
				calls = append(calls, op+":"+input["binding_name"].(string))
				if op == capacity.ObserveNativeWorkerPool {
					*out.(*model.CapacityNativeWorkerPoolObservation) = o
					return "observed", nil
				}
				if input["binding_name"] == "aws" {
					if fault == "collector_unavailable" {
						return "", errors.New("independent provider read unavailable")
					}
					*out.(*model.CapacityMarketProfileQuote) = model.CapacityMarketProfileQuote{Currency: "EUR", Profile: "aws", Provider: "aws", Region: "region", Adapter: adapter, ObservedAt: now, ValidUntil: now.Add(time.Minute)}
					return "observed", nil
				}
				*out.(*model.CapacityMarketProfileQuote) = model.CapacityMarketProfileQuote{Currency: "USD", Profile: "hcloud", Provider: "hcloud", Region: "region", Adapter: adapter, ObservedAt: now, ValidUntil: now.Add(time.Minute)}
				return "observed", nil
			}
			pool, market, err := observeCapacityWorkerMarket(p, read, now)
			if err != nil || pool == nil || len(market.Profiles) != 1 || len(market.Unavailable) != 1 || market.Unavailable[0].Profile != "aws" || market.Unavailable[0].Reason != fault {
				t.Fatalf("one provider failure erased healthy quote: %+v %v", market, err)
			}
			want := []string{capacity.ObserveNativeWorkerPool + ":workers", capacity.ObserveComputeOffer + ":hcloud", capacity.ObserveComputeOffer + ":aws"}
			if !reflect.DeepEqual(calls, want) {
				t.Fatalf("unexpected/unbound/retried provider reads: %v", calls)
			}
			if version, ok := capacityMarketAdapterVersion(p, marketObservationAdapter(adapter)); !ok || version != 3 {
				t.Fatalf("numeric revision was not bound: %d %v", version, ok)
			}
		})
	}
}
