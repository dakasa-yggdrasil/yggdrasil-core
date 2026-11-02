package repository

import (
	"context"
	"encoding/json"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

func testFailedInstalledDisposalBoundaries(t *testing.T) {
	t.Run("legacy548_exact_original_contract_only", testFailedInstalledLegacyV1Scope)
	t.Run("scheduled_terminal_handoff", testFailedInstalledDisposalTerminalHandoff)
	now := time.Now().UTC()
	expired := now.Add(-time.Second)
	policy := model.Manifest{ID: uuid.New(), Checksum: "original"}
	p := model.CapacityPolicySpec{Floor: 1, GuestNotifyReconcileBinding: &model.CapacityGuestNotifyReconcileBinding{}, GuestRetirementBinding: &model.CapacityGuestRetirementBinding{EvidenceClass: "owned_provisioner_original"}}
	base := model.CapacityIntent{PolicyID: policy.ID, PolicyChecksum: policy.Checksum, Phase: "preparing", Generation: 6, FencingToken: 13, LeaseExpiresAt: &expired, Decision: model.CapacityDecision{Units: 1}, Assessment: model.CapacityAssessment{Snapshot: model.CapacitySnapshot{Units: 1}}}
	for _, name := range []string{"exact_failed_first", "live_lease", "missing_lease", "promoted", "foreign_policy", "foreign_checksum", "other_member", "recovery", "degraded", "already_requested", "overflow"} {
		t.Run(name, func(t *testing.T) {
			old := base
			switch name {
			case "live_lease":
				live := now.Add(time.Second)
				old.LeaseExpiresAt = &live
			case "missing_lease":
				old.LeaseExpiresAt = nil
			case "promoted":
				old.Phase = "promoted"
			case "foreign_policy":
				old.PolicyID = uuid.New()
			case "foreign_checksum":
				old.PolicyChecksum = "other"
			case "other_member":
				old.Assessment.Snapshot.Units = 2
			case "recovery":
				old.RecoveryOnly = true
			case "degraded":
				old.FloorDegraded = true
			case "already_requested":
				old.FailedInstalledDisposal = &model.CapacityFailedInstalledDisposal{}
			case "overflow":
				old.FencingToken = maxCapacityGeneration
			}
			if failedInstalledDisposalCandidate(old, p, policy, now) != (name == "exact_failed_first") {
				t.Fatal("unrelated/live/useful epoch eligible")
			}
		})
	}
	for _, name := range []string{"zero_useful", "accepted_read_or_promotion", "another_native", "another_active_epoch", "unexpired_canary", "unresolved_provider"} {
		t.Run(name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			mock.ExpectBegin()
			tx, _ := db.Begin()
			defer tx.Rollback()
			counts := []int{0, 0, 0, 0, 0}
			for i, n := range []string{"accepted_read_or_promotion", "another_native", "another_active_epoch", "unexpired_canary", "unresolved_provider"} {
				if name == n {
					counts[i] = 1
				}
			}
			mock.ExpectQuery("SELECT").WillReturnRows(sqlmock.NewRows([]string{"useful", "other", "active", "open", "pending"}).AddRow(counts[0], counts[1], counts[2], counts[3], counts[4]))
			r := FailedInstalledGuestDisposal{PreregistrationID: uuid.NewString(), OriginalIntent: base}
			if (failedInstalledZeroUsefulTx(context.Background(), tx, r, now, "") == nil) != (name == "zero_useful") {
				t.Fatal("caller flag replaced zero useful proof")
			}
			if err = mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
	t.Run("CAS_refuses_changed_epoch", func(t *testing.T) {
		db, mock, err := sqlmock.New()
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		mock.ExpectBegin()
		tx, _ := db.Begin()
		defer tx.Rollback()
		next := base
		next.FailedInstalledDisposal = &model.CapacityFailedInstalledDisposal{ID: uuid.NewString(), Stage: "requested"}
		mock.ExpectExec("UPDATE public.capacity_intents").WillReturnResult(sqlmock.NewResult(0, 0))
		if persistFailedInstalledDisposalIntentTx(context.Background(), tx, base, next) == nil {
			t.Fatal("concurrent epoch overwritten")
		}
		if err = mock.ExpectationsWereMet(); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("replacement_needs_both_new_Source_and_new_profile", func(t *testing.T) {
		for _, kind := range []string{"same_contract", "only_profile_changed", "only_Source_changed", "both_changed", "missing_binding"} {
			b := &model.CapacityGuestRetirementBinding{GuestSourceCommit: "old-source", ProfileManifestSHA256: "old-profile"}
			switch kind {
			case "only_profile_changed":
				b.ProfileManifestSHA256 = "new-profile"
			case "only_Source_changed":
				b.GuestSourceCommit = "new-source"
			case "both_changed":
				b.GuestSourceCommit = "new-source"
				b.ProfileManifestSHA256 = "new-profile"
			case "missing_binding":
				b = nil
			}
			if failedInstalledReplacementChanged(b, "old-source", "old-profile") != (kind == "both_changed") {
				t.Fatal("old defect reactivated by policy name/version only", kind)
			}
		}
	})
	t.Run("internal_sparse_intent_and_exact_raw_run_are_storage_not_Guest_wire", func(t *testing.T) {
		r := FailedInstalledGuestDisposal{Schema: "failed_installed_guest_disposal_v1", OriginalIntent: base, OriginalRun: "{ \"id\": \"original\", \"result\": {\"ACK\":true} }\n", LastFailedRun: "{ \"status\": \"failed\" }", BusinessEffectsPreserved: true}
		wire, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		var got FailedInstalledGuestDisposal
		if decodeFailedInstalledDisposal(wire, &got) != nil || got.OriginalRun != r.OriginalRun || got.LastFailedRun != r.LastFailedRun {
			t.Fatal("original raw bytes normalized or sparse internal intent refused")
		}
	})

	t.Run("new_kind_preserves_old_outcomes", func(t *testing.T) {
		r := FailedInstalledGuestDisposal{Schema: "failed_installed_guest_disposal_v1", BusinessEffectsPreserved: true, OriginalIntent: base, OriginalRun: string(`{"status":"failed","ACK":true}`), LastFailedRun: string(`{"status":"failed","HTTP":409}`)}
		raw, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		var copy FailedInstalledGuestDisposal
		if json.Unmarshal(raw, &copy) != nil || string(copy.OriginalRun) != string(r.OriginalRun) || string(copy.LastFailedRun) != string(r.LastFailedRun) || !copy.BusinessEffectsPreserved {
			t.Fatal("original outcomes rewritten")
		}
	})
}

func testFailedInstalledLegacyV1Scope(t *testing.T) {
	for _, provider := range []string{"aws", "hetzner"} {
		raw, err := os.ReadFile("../internal/capacity/testdata/original-notify-" + provider + "-production-contract.json")
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"exact548", "foreign_key", "changed_catalog", "changed_native_origin", "wrong_authority", "no_actual_issuer", "new_Guest_stays_V2"} {
			t.Run(provider+"/"+name, func(t *testing.T) {
				var p model.CapacityPolicySpec
				if capacity.DecodeNativeCapacity(json.RawMessage(raw), &p) != nil {
					t.Fatal("actual complete historical contract fixture")
				}
				b := p.GuestRetirementBinding
				b.CoreAuthoritySourceCommit = capacity.GuestD11ProtocolAuthority
				issuer := "c8d9b7c0d13ae8ef22a8f088ee7a7628f0148a6a"
				switch name {
				case "foreign_key":
					b.IntentSigningKeyRef = "secret://foreign/key#value"
				case "changed_catalog":
					b.ProfileManifest.ProductionCatalogSHA256 = strings.Repeat("a", 64)
				case "changed_native_origin":
					b.Members[0].Origin = "https://foreign.invalid:9447"
				case "wrong_authority":
					b.CoreAuthoritySourceCommit = strings.Repeat("b", 40)
				case "no_actual_issuer":
					issuer = ""
				case "new_Guest_stays_V2":
					b.GuestSourceCommit = strings.Repeat("c", 40)
				}
				want := ""
				if name == "exact548" {
					want = failedInstalledLegacyV1Mode
				}
				if name == "new_Guest_stays_V2" {
					want = failedInstalledV2Mode
				}
				if got := failedInstalledRetirementModeForIssuer(p, *b, issuer); got != want {
					t.Fatalf("legacy fallback escaped exact original548 contract: %s", got)
				}
				// No decoder or mode selection may rewrite the actual/wire identities.
				if issuer == capacity.GuestD11ProtocolAuthority {
					t.Fatal("issuer forged as old authority")
				}
			})
		}
	}
	t.Run("no_private_native_owner", func(t *testing.T) {
		store := CapacityStore{}
		if store.RecordFailedInstalledGuestLegacyNativeRead(context.Background(), nil, FailedInstalledLegacyNativeReturn{}) == nil {
			t.Fatal("caller supplied native read")
		}
	})
}

func testFailedInstalledDisposalTerminalHandoff(t *testing.T) {
	for _, stage := range []string{"absent", "requested", "claimed", "quiescent", "terminal", "unknown"} {
		t.Run(stage, func(t *testing.T) {
			var marker *model.CapacityFailedInstalledDisposal
			if stage != "absent" {
				marker = &model.CapacityFailedInstalledDisposal{Stage: stage}
			}
			requested, err := failedInstalledDisposalClaimRequested(marker)
			if requested != (stage == "requested") || (err != nil) != (stage == "claimed" || stage == "quiescent" || stage == "unknown") {
				t.Fatal("scheduler terminal remained a pending disposal or active disposal escaped", stage, requested, err)
			}
		})
	}
}
