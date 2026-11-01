//go:build labqualification && !nativequalification

package message

import (
	"context"
	"errors"
	"time"

	"encoding/json"
	"github.com/dakasa-yggdrasil/yggdrasil-sdk-go/rpc"
	"os"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/manifest"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

func TestLabOriginalGuestSupplierExactPairs(t *testing.T) {
	cases := []struct{ name, fixture, provider, source, instanceID, instanceChecksum, typeID, typeChecksum, version, queue string }{
		{"aws", "testdata/lab_aws_supplier_type.json", "aws", "57fcec882c31ad958d92556de9e9789fc95b8970", "bf14f99f-5de3-4314-a462-db85fa973f3c", "32638e487fd58c64aff23d20990e8e2f243762c60b2d918d1f19d344df723beb", "c7547c2f-1fb5-424b-bb7b-03d99f98328c", "75344b44769a8a9089da8fc13d2217ce6c58fa0234cd8fa77af514d379d855ce", "1.65.5", "yggdrasil.adapter.aws"},
		{"hetzner", "testdata/lab_hetzner_supplier_type.json", "hetzner", "bcd65615c8704e0fd1f5d60875f80180b35f9599", "73bbf97c-e6c5-44ff-aaf3-0cb868ae764a", "5893366ae4d8791eb41402c1dbb7050dffe5717f6763aa091c688cecfa635b50", "8b3ccd73-a5d8-4544-ae8f-f2d9ee356df1", "fbaa33a618963333f68b8991a7548a6550f713c3543f112cd7e4f33275304dc7", "0.3.5", "yggdrasil.adapter.hetzner"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := os.ReadFile(tc.fixture)
			if err != nil {
				t.Fatal(err)
			}
			var envelope model.ManifestDocument
			typeSpec := json.RawMessage(raw)
			if tc.provider == "aws" {
				if err = json.Unmarshal(raw, &envelope); err != nil {
					t.Fatal(err)
				}
				typeSpec = envelope.Spec
			}
			ts, err := manifest.ParseIntegrationTypeSpec(typeSpec)
			if err != nil {
				t.Fatal(err)
			}
			typ := model.Manifest{ID: uuid.MustParse(tc.typeID), Checksum: tc.typeChecksum, Spec: typeSpec}
			raw, err = os.ReadFile("testdata/lab_" + tc.provider + "_supplier_instance.json")
			if err != nil {
				t.Fatal(err)
			}
			var instDoc model.ManifestDocument
			if err = json.Unmarshal(raw, &instDoc); err != nil {
				t.Fatal(err)
			}
			instance := model.Manifest{ID: uuid.MustParse(tc.instanceID), Checksum: tc.instanceChecksum, Spec: instDoc.Spec}
			instanceSpec, err := manifest.ParseIntegrationInstanceSpec(instance.Spec)
			if err != nil {
				t.Fatal(err)
			}
			if !originalGuestSupplierSourceConfigFor(tc.provider, instanceSpec, tc.source) {
				t.Fatal("source config before hydration")
			}
			instanceSpec.Credentials = map[string]any{"synthetic": "only-for-test"}
			if !originalGuestSupplierSourceConfigFor(tc.provider, instanceSpec, tc.source) {
				t.Fatal("source config after hydration")
			}
			if originalGuestSupplierSourceConfigFor(tc.provider, instanceSpec, "0000000000000000000000000000000000000000") {
				t.Fatal("foreign source config")
			}
			if !labOriginalGuestSupplierApproved(tc.provider, tc.source, instance, typ, ts) {
				t.Fatal("exact LAB pair refused")
			}
			t.Run("foreign_source", func(t *testing.T) {
				if labOriginalGuestSupplierApproved(tc.provider, "0000000000000000000000000000000000000000", instance, typ, ts) {
					t.Fatal("foreign source")
				}
			})
			t.Run("foreign_instance", func(t *testing.T) {
				x := instance
				x.ID = uuid.New()
				if labOriginalGuestSupplierApproved(tc.provider, tc.source, x, typ, ts) {
					t.Fatal("foreign instance")
				}
			})
			t.Run("foreign_checksum", func(t *testing.T) {
				x := typ
				x.Checksum = "foreign"
				if labOriginalGuestSupplierApproved(tc.provider, tc.source, instance, x, ts) {
					t.Fatal("foreign catalog")
				}
			})
			t.Run("modified_catalog", func(t *testing.T) {
				x := ts
				x.Adapter.Queues.Execute = "foreign"
				if labOriginalGuestSupplierApproved(tc.provider, tc.source, instance, typ, x) {
					t.Fatal("foreign queue")
				}
			})
			t.Run("modified_raw_spec", func(t *testing.T) {
				x := typ
				x.Spec = []byte(`{}`)
				if labOriginalGuestSupplierApproved(tc.provider, tc.source, instance, x, ts) {
					t.Fatal("foreign raw spec")
				}
			})
			t.Run("forged_persisted_spec_with_matching_typed_view", func(t *testing.T) {
				var obj map[string]any
				if err := json.Unmarshal(typ.Spec, &obj); err != nil {
					t.Fatal(err)
				}
				obj["unexpected_field"] = "foreign"
				changed, err := json.Marshal(obj)
				if err != nil {
					t.Fatal(err)
				}
				x := typ
				x.Spec = changed
				changedTS, err := manifest.ParseIntegrationTypeSpec(changed)
				if err != nil {
					t.Fatal(err)
				}
				if labOriginalGuestSupplierApproved(tc.provider, tc.source, instance, x, changedTS) {
					t.Fatal("changed full spec")
				}
			})
			t.Run("forged_instance_spec", func(t *testing.T) {
				x := instance
				x.Spec = []byte(`{}`)
				if labOriginalGuestSupplierApproved(tc.provider, tc.source, x, typ, ts) {
					t.Fatal("changed instance spec")
				}
			})
			t.Run("foreign_provider", func(t *testing.T) {
				if labOriginalGuestSupplierApproved("unsupported", tc.source, instance, typ, ts) {
					t.Fatal("foreign provider")
				}
			})
		})
	}
}

type labOnceTransport struct {
	calls   int
	failure error
	body    []byte
}

func (f *labOnceTransport) Consume(rpc.ConsumerConfig) (rpc.Subscription, error) {
	return nil, errors.New("unexpected consume")
}
func (f *labOnceTransport) Publish(context.Context, rpc.Request) error {
	return errors.New("unexpected publish")
}
func (f *labOnceTransport) Close() error { return nil }
func (f *labOnceTransport) Request(_ context.Context, _ rpc.Request) (rpc.Reply, error) {
	f.calls++
	return rpc.Reply{Body: f.body}, f.failure
}

// In-memory only: a lost or malformed broker reply is never retried by the
// bounded original RPC call. It does not prove broker/provider exactly-once.
func TestLabOriginalSupplierBrokerCallDoesNotReplay(t *testing.T) {
	for _, tc := range []struct {
		name    string
		body    []byte
		failure error
	}{
		{"lost_reply", nil, errors.New("uncertain original return")},
		{"malformed_reply", []byte(`{`), nil},
		{"complete_reply", []byte(`{"status":"succeeded"}`), nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			f := &labOnceTransport{body: tc.body, failure: tc.failure}
			policy := &nativeAdapterHTTPPolicy{limit: 2 << 20, parent: ctx}
			bounded := &nativeBoundedRPC{Transport: f, policy: policy}
			var response map[string]any
			err := callRPCWithPolicy(ctx, bounded, "yggdrasil.adapter.aws.execute", map[string]any{"operation": "ensure_ec2_instance"}, &response, adapterCallPolicy{native: policy, detailFreeErrors: true})
			if f.calls != 1 {
				t.Fatalf("got %d sends", f.calls)
			}
			if (err == nil) != (tc.name == "complete_reply") {
				t.Fatalf("unexpected result: %v", err)
			}
		})
	}
}
