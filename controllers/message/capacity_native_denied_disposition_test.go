//go:build !nativequalification

package message

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
	"os"
	"strings"
	"testing"
)

func TestNativeDeniedObserverFutureSourceRefusesBeforeHydration(t *testing.T) {
	if nativeDeniedObserverSourceReady("") || nativeDeniedObserverSourceReady(originalCreateDispositionAWSObserverSource) || nativeDeniedObserverSourceReady("future-not-published") {
		t.Fatal("unpublished or historical creator admitted as new observer")
	}
	if !nativeDeniedObserverSourceReady(nativeDeniedAWSObserverSource) {
		t.Fatal("published observer digest refused")
	}
	c := model.CapacityNativeDeniedCandidate{Request: model.CapacityNativeDeniedReadRequest{OriginalAdapterSourceCommit: originalCreateDispositionAWSObserverSource}}
	for _, source := range []string{"", "future-not-published", originalCreateDispositionAWSObserverSource} {
		touched := false
		d := nativeDeniedResolverReads{
			historical: func(context.Context, string, string) (model.Manifest, error) {
				touched = true
				return model.Manifest{}, errors.New("unexpected historical read")
			},
			current: func(context.Context, string, string) (model.Manifest, error) {
				touched = true
				return model.Manifest{}, errors.New("unexpected current read")
			},
			hydrate: func(context.Context, *model.IntegrationInstanceManifestSpec) error {
				touched = true
				return errors.New("unexpected hydration")
			},
			validate: func(model.IntegrationInstanceManifestSpec, model.IntegrationTypeManifestSpec) error {
				touched = true
				return errors.New("unexpected validation")
			},
			handshake: func(context.Context, model.Manifest, model.Manifest, model.IntegrationInstanceManifestSpec, model.IntegrationTypeManifestSpec) error {
				touched = true
				return errors.New("unexpected handshake")
			},
		}
		if _, err := resolveNativeDeniedObserverWith(context.Background(), c, source, d); err == nil || touched {
			t.Fatal("invalid observer source reached an operand read", source, err, touched)
		}
	}
	if _, e := RecordNativeDeniedDisposition(context.Background(), nil, nil, "grant", "job", "issuer"); e == nil {
		t.Fatal("missing publication or effects dependencies")
	}
	if _, e := resolveNativeDeniedObserver(context.Background(), nil, nil, model.CapacityNativeDeniedCandidate{}); e == nil {
		t.Fatal("future observer consumed historical fields")
	}
}

// Exercise the actual owning resolver seam with full authentic historical
// catalogue and Source-derived expected successor; no database or credentials.
func TestNativeDeniedHistoricalEnvelopeWithCurrentLiveCatalog(t *testing.T) {
	oldRaw, e := os.ReadFile("../../repository/testdata/capacity_aws_denied_historical_1654_type_spec.json")
	if e != nil {
		t.Fatal(e)
	}
	newRaw, e := os.ReadFile("../../repository/testdata/capacity_aws_denied_source_expected_1655_type_spec.json")
	if e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{"exact", "foreign_live_version", "foreign_input_example", "foreign_action", "inactive_live", "inactive_IID", "foreign_historical_checksum", "hydrate_source_swap", "handshake_error"} {
		t.Run(name, func(t *testing.T) {
			old := model.Manifest{ID: uuid.New(), Kind: "integration_type", Metadata: model.ManifestMetadata{Namespace: "global", Name: "aws", Active: false}, Version: 10, Checksum: strings.Repeat("a", 64), Spec: append([]byte(nil), oldRaw...)}
			live := model.Manifest{ID: uuid.New(), Kind: "integration_type", Metadata: model.ManifestMetadata{Namespace: "global", Name: "aws", Active: true}, Version: 11, Checksum: strings.Repeat("b", 64), Spec: append([]byte(nil), newRaw...)}
			is := model.IntegrationInstanceManifestSpec{TypeRef: model.ManifestSelector{ManifestID: old.ID.String()}, Config: map[string]any{"original_capacity": map[string]any{"mode": "original_aws_ec2_capacity_v1", "adapter_source_commit": originalCreateDispositionAWSObserverSource}}}
			body, _ := json.Marshal(is)
			im := model.Manifest{ID: uuid.New(), Kind: "integration_instance", Metadata: model.ManifestMetadata{Namespace: "test", Name: "original", Active: true}, Version: 1, Checksum: strings.Repeat("c", 64), Spec: body}
			c := model.CapacityNativeDeniedCandidate{Original: model.CapacityOriginalCreateDispositionCandidate{Binding: model.CapacityMutationBinding{IntegrationInstanceID: im.ID.String(), IntegrationChecksum: im.Checksum, IntegrationTypeID: old.ID.String(), IntegrationTypeChecksum: old.Checksum}}, Request: model.CapacityNativeDeniedReadRequest{OriginalAdapterSourceCommit: originalCreateDispositionAWSObserverSource}}
			if name == "inactive_live" {
				live.Metadata.Active = false
			}
			if name == "inactive_IID" {
				im.Metadata.Active = false
			}
			if name == "foreign_historical_checksum" {
				old.Checksum = strings.Repeat("f", 64)
			}
			if name == "foreign_live_version" || name == "foreign_input_example" || name == "foreign_action" {
				var m map[string]any
				if json.Unmarshal(live.Spec, &m) != nil {
					t.Fatal("fixture")
				}
				switch name {
				case "foreign_live_version":
					m["adapter"].(map[string]any)["version"] = "1.65.6"
				case "foreign_input_example":
					m["action_catalog"].([]any)[0].(map[string]any)["input_example"] = map[string]any{"force": true}
				case "foreign_action":
					m["action_catalog"].([]any)[0].(map[string]any)["idempotent"] = false
				}
				live.Spec, _ = json.Marshal(m)
			}
			hydrated, validated, described := false, false, false
			d := nativeDeniedResolverReads{
				historical: func(_ context.Context, kind, id string) (model.Manifest, error) {
					if kind == "integration_instance" && id == im.ID.String() {
						return im, nil
					}
					if kind == "integration_type" && id == old.ID.String() {
						return old, nil
					}
					return model.Manifest{}, errors.New("foreign")
				},
				current: func(_ context.Context, ns, name string) (model.Manifest, error) {
					if ns != old.Metadata.Namespace || name != old.Metadata.Name {
						t.Fatal("foreign logical catalog")
					}
					return live, nil
				},
				hydrate: func(_ context.Context, v *model.IntegrationInstanceManifestSpec) error {
					hydrated = true
					if name == "hydrate_source_swap" {
						v.Config["original_capacity"].(map[string]any)["adapter_source_commit"] = strings.Repeat("f", 40)
					}
					return nil
				},
				validate: func(v model.IntegrationInstanceManifestSpec, ts model.IntegrationTypeManifestSpec) error {
					validated = true
					if ts.Adapter.Version != "1.65.4" || !originalGuestSupplierSourceConfigFor("aws", v, originalCreateDispositionAWSObserverSource) {
						t.Fatal("relabelled historical input")
					}
					return nil
				},
				handshake: func(_ context.Context, gotI, gotT model.Manifest, v model.IntegrationInstanceManifestSpec, ts model.IntegrationTypeManifestSpec) error {
					described = true
					if gotI.ID != im.ID || gotT.ID != live.ID || ts.Adapter.Version != "1.65.5" || !originalGuestSupplierSourceConfigFor("aws", v, originalCreateDispositionAWSObserverSource) {
						t.Fatal("legacy Describe or new config alias")
					}
					if name == "handshake_error" {
						return errors.New("no authentic live Describe")
					}
					return nil
				},
			}
			got, e := resolveNativeDeniedObserverWith(context.Background(), c, strings.Repeat("e", 40), d)
			if name == "exact" {
				if e != nil || !hydrated || !validated || !described || got.typeSpec.Adapter.Version != "1.65.4" || got.typ.ID != old.ID || got.currentType.ID != live.ID {
					t.Fatal("historical execute/current Describe seam", e)
				}
			} else {
				if e == nil {
					t.Fatal("foreign boundary accepted", name)
				}
				if name != "hydrate_source_swap" && name != "handshake_error" && hydrated {
					t.Fatal("private hydration preceded public catalog refusal")
				}
			}
		})
	}
}
