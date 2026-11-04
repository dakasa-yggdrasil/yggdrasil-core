//go:build !nativequalification

package message

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/manifest"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

func TestOriginalGuestSupplierPinsPublicAdapterSource(t *testing.T) {
	for _, name := range []string{"exact", "missing", "foreign", "malformed", "workflow_input"} {
		t.Run(name, func(t *testing.T) {
			source := strings.Repeat("a", 40)
			config := map[string]any{"original_create_source_commit": source}
			spec := model.IntegrationInstanceManifestSpec{Config: map[string]any{"fleet": config}}
			switch name {
			case "missing":
				delete(config, "original_create_source_commit")
			case "foreign":
				config["original_create_source_commit"] = strings.Repeat("b", 40)
			case "malformed":
				source = "head"
			case "workflow_input":
				spec.Config = map[string]any{"original_create_source_commit": source}
			}
			if originalGuestSupplierSourceConfig(spec, source) != (name == "exact") {
				t.Fatal("adapter source pin admission mismatch")
			}
		})
	}
}

func TestProductionOriginalGuestWitnessRefusesUnsupportedSources(t *testing.T) {
	for _, provider := range []string{"unsupported-provider", "native-qemu", ""} {
		if repository.OriginalGuestCreateWitnessProviderEnabled(provider) {
			t.Fatalf("production gained an unimplemented original create witness: %q", provider)
		}
	}
}

func TestOriginalGuestSupplierRequiresActualClosedCatalog(t *testing.T) {
	raw, err := os.ReadFile("../../repository/testdata/capacity_hetzner_type_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var original model.Manifest
	if err = json.Unmarshal(raw, &original); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"original", "slot_candidate", "provider", "transport", "version", "ensure_not_idempotent", "missing_observation", "duplicate_action"} {
		t.Run(name, func(t *testing.T) {
			ts, err := manifest.ParseIntegrationTypeSpec(original.Spec)
			if err != nil {
				t.Fatal(err)
			}
			switch name {
			case "slot_candidate":
				ts.Adapter.Version = "0.2.0"
			case "provider":
				ts.Provider = "aws"
			case "transport":
				ts.Adapter.Transport = "http_json"
			case "version":
				ts.Adapter.Version = "0.1.1"
			case "ensure_not_idempotent":
				for n := range ts.ActionCatalog {
					if ts.ActionCatalog[n].Name == "ensure_server" {
						ts.ActionCatalog[n].Idempotent = false
					}
				}
			case "missing_observation":
				for n := range ts.ActionCatalog {
					if ts.ActionCatalog[n].Name == "observe_server_action" {
						ts.ActionCatalog[n].Name = "unreviewed_observation"
					}
				}
			case "duplicate_action":
				for _, a := range ts.ActionCatalog {
					if a.Name == "ensure_server" {
						ts.ActionCatalog = append(ts.ActionCatalog, a)
						break
					}
				}
			}
			if originalGuestSupplierCatalog(ts) != (name == "original" || name == "slot_candidate") {
				t.Fatalf("unexpected catalog admission for %s", name)
			}
		})
	}
}

func TestOriginalGuestReceiptJoinsOmittedEmptyActionLists(t *testing.T) {
	for _, kind := range []string{"omitted_receipt_empty_return", "empty_receipt_omitted_return", "exact_ordered", "foreign_action", "foreign_next", "reversed_order", "duplicate_next", "duplicate_main", "empty_next", "uncertain", "incomplete"} {
		t.Run(kind, func(t *testing.T) {
			r := model.CapacityMutationReceipt{Outcome: "accepted", TransportCompleted: true, ActionID: "original-action"}
			next := []string{}
			switch kind {
			case "empty_receipt_omitted_return":
				r.NextActionIDs = []string{}
				next = nil
			case "exact_ordered":
				r.NextActionIDs = []string{"original-next", "original-last"}
				next = []string{"original-next", "original-last"}
			case "foreign_action":
				r.ActionID = "foreign"
			case "foreign_next":
				next = []string{"foreign"}
			case "reversed_order":
				r.NextActionIDs = []string{"one", "two"}
				next = []string{"two", "one"}
			case "duplicate_next":
				r.NextActionIDs = []string{"one", "one"}
				next = []string{"one", "one"}
			case "duplicate_main":
				r.NextActionIDs = []string{r.ActionID}
				next = []string{r.ActionID}
			case "empty_next":
				r.NextActionIDs = []string{""}
				next = []string{""}
			case "uncertain":
				r.Outcome = "uncertain"
			case "incomplete":
				r.TransportCompleted = false
			}
			// Actual receipt JSON omitempty drops empty arrays. The owning query's
			// append(nil,list...) projection likewise produces nil when empty.
			raw, err := json.Marshal(r)
			if err != nil {
				t.Fatal(err)
			}
			var projected model.CapacityMutationReceipt
			if json.Unmarshal(raw, &projected) != nil {
				t.Fatal("receipt codec")
			}
			projected.NextActionIDs = append([]string(nil), projected.NextActionIDs...)
			want := kind == "omitted_receipt_empty_return" || kind == "empty_receipt_omitted_return" || kind == "exact_ordered"
			if originalGuestReceiptActionJoin(projected, "original-action", next) != want {
				t.Fatal("original action identity join mismatch", kind)
			}
		})
	}
}
