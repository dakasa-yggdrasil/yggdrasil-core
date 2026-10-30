package repository

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// Actual PG78 storage, scope queries and CAS. Synthetic preregistration rows
// are explicitly unqualified and cannot satisfy admission or V2 retirement.
// No successful Guest runtime, business effect or provider absence is seeded.
func testFailedInstalledDisposalPostgres(t *testing.T) {
	db, policy := d12AuthorityLocalFixture(t)
	ctx := context.Background()
	t.Run("append_only_closed_ledger_and_preserved_originals", func(t *testing.T) {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		f := guestOriginalStorageRecords(t)
		guestOriginalStoragePre(t, tx, ctx, f, f.wire, f.wire, f.pre.OriginalDeadline)
		r := FailedInstalledGuestDisposal{Schema: "failed_installed_guest_disposal_v1", ID: uuid.NewString(), Stage: "requested", Namespace: policy.Metadata.Namespace, Environment: "production", Domain: "notify", Dimension: "storage-disposal-only", PreregistrationID: f.pre.PreregistrationID, Issuer: "source-test", ActualCoreSource: strings.Repeat("a", 40), OriginalRun: string(`{"status":"failed","known_ACK":true}`), LastFailedRun: string(`{"status":"failed","HTTP409":true}`), InstallationSHA256: strings.Repeat("b", 64), EnrollmentSHA256: strings.Repeat("c", 64), BlockedGuestSource: strings.Repeat("d", 40), BlockedProfileSHA256: strings.Repeat("e", 64), BusinessEffectsPreserved: true, RetirementMode: failedInstalledV2Mode}
		sha, err := insertFailedInstalledDisposalTx(ctx, tx, r)
		if err != nil {
			t.Fatal(err)
		}
		got, digest, err := loadFailedInstalledDisposalTx(ctx, tx, r.ID, "requested")
		if err != nil || sha != digest || string(got.OriginalRun) != string(r.OriginalRun) || string(got.LastFailedRun) != string(r.LastFailedRun) {
			t.Fatal("original acknowledged failures not retained", err)
		}
		// These are explicitly storage-only records, not signed Guest quiescence.
		// The backend cannot qualify them as native absence without the real chain.
		claim := r
		claim.Stage = "claimed"
		claim.AdmissionSHA256 = sha
		claim.ClaimedIntent = &model.CapacityIntent{Generation: 6, FencingToken: 15}
		if _, err = insertFailedInstalledDisposalTx(ctx, tx, claim); err != nil {
			t.Fatal("claim lineage", err)
		}
		q := claim
		q.Stage = "quiescent"
		q.RetirementRequestID = uuid.NewString()
		q.NativePoweroffSHA256 = strings.Repeat("f", 64)
		if _, err = insertFailedInstalledDisposalTx(ctx, tx, q); err != nil {
			t.Fatal("versioned quiescent storage", err)
		}
		terminal := q
		terminal.Stage = "terminal"
		terminal.TerminalIssuer = "storage-only"
		terminal.Observation = &model.CapacityOriginalCreateDispositionObservation{}
		terminal.ObservationSHA256 = strings.Repeat("a", 64)
		if _, err = insertFailedInstalledDisposalTx(ctx, tx, terminal); err != nil {
			t.Fatal("terminal storage lineage", err)
		}
		if _, _, _, err = loadFailedInstalledQuiescentTx(ctx, tx, r.PreregistrationID, r.ID, ""); err == nil {
			t.Fatal("storage-only records qualified a Guest/native terminal")
		}

		for _, query := range []string{`UPDATE public.capacity_guest_failed_installed_disposals SET original_record='{}'::jsonb WHERE id=$1`, `DELETE FROM public.capacity_guest_failed_installed_disposals WHERE id=$1`} {
			guestOriginalExpectedSQLRefusal(t, tx, ctx, query, r.ID)
		}
		raw, _ := json.Marshal(r)
		for _, name := range []string{"missing_schema", "unknown_key", "null_credit", "nonzero_credit", "effects_erased", "missing_mode", "unknown_mode", "legacy_mode_for_other_Source"} {
			t.Run(name, func(t *testing.T) {
				var v map[string]any
				_ = json.Unmarshal(raw, &v)
				fresh := guestOriginalStorageRecords(t)
				guestOriginalStoragePre(t, tx, ctx, fresh, fresh.wire, fresh.wire, fresh.pre.OriginalDeadline)
				v["preregistration_id"] = fresh.pre.PreregistrationID
				v["id"] = uuid.NewString()
				switch name {
				case "missing_schema":
					delete(v, "schema")
				case "unknown_key":
					v["resource_absent"] = true
				case "null_credit":
					v["useful_capacity_before"] = nil
				case "nonzero_credit":
					v["useful_capacity_before"] = 1
				case "missing_mode":
					delete(v, "retirement_mode")
				case "unknown_mode":
					v["retirement_mode"] = "force_quiescent"
				case "legacy_mode_for_other_Source":
					v["retirement_mode"] = failedInstalledLegacyV1Mode
				case "effects_erased":
					v["business_effects_preserved"] = false
				}
				wire, _ := json.Marshal(v)
				guestOriginalExpectedSQLRefusal(t, tx, ctx, `INSERT INTO public.capacity_guest_failed_installed_disposals(id,stage,namespace,environment,domain,dimension,preregistration_id,original_wire,original_record,record_sha256) VALUES($1,'requested',$2,$3,$4,$5,$6,$7,$8::jsonb,$9)`, v["id"], r.Namespace, r.Environment, r.Domain, r.Dimension, v["preregistration_id"], wire, string(wire), capacity.BusinessCreationSHA256(wire))
			})
		}
	})
	t.Run("replacement_gate_still_blocks_old_or_unapproved_Guest", func(t *testing.T) {
		tx, e := db.BeginTx(ctx, nil)
		if e != nil {
			t.Fatal(e)
		}
		defer tx.Rollback()
		f := guestOriginalStorageRecords(t)
		guestOriginalStoragePre(t, tx, ctx, f, f.wire, f.wire, f.pre.OriginalDeadline)
		r := FailedInstalledGuestDisposal{Schema: "failed_installed_guest_disposal_v1", ID: uuid.NewString(), Stage: "requested", Namespace: policy.Metadata.Namespace, Environment: "production", Domain: "notify", Dimension: "terminal-replacement-only", PreregistrationID: f.pre.PreregistrationID, Issuer: "storage-test", ActualCoreSource: strings.Repeat("a", 40), OriginalRun: `{"status":"failed"}`, LastFailedRun: `{"status":"failed"}`, InstallationSHA256: strings.Repeat("b", 64), EnrollmentSHA256: strings.Repeat("c", 64), BlockedGuestSource: strings.Repeat("d", 40), BlockedProfileSHA256: strings.Repeat("e", 64), BusinessEffectsPreserved: true, RetirementMode: failedInstalledV2Mode}
		sha, e := insertFailedInstalledDisposalTx(ctx, tx, r)
		if e != nil {
			t.Fatal(e)
		}
		r.Stage = "claimed"
		r.AdmissionSHA256 = sha
		r.ClaimedIntent = &model.CapacityIntent{Generation: 6, FencingToken: 15}
		if _, e = insertFailedInstalledDisposalTx(ctx, tx, r); e != nil {
			t.Fatal(e)
		}
		r.Stage = "quiescent"
		r.RetirementRequestID = uuid.NewString()
		r.NativePoweroffSHA256 = strings.Repeat("f", 64)
		if _, e = insertFailedInstalledDisposalTx(ctx, tx, r); e != nil {
			t.Fatal(e)
		}
		r.Stage = "terminal"
		r.TerminalIssuer = "storage-test"
		r.Observation = &model.CapacityOriginalCreateDispositionObservation{}
		r.ObservationSHA256 = strings.Repeat("a", 64)
		if _, e = insertFailedInstalledDisposalTx(ctx, tx, r); e != nil {
			t.Fatal(e)
		}
		p := model.CapacityPolicySpec{Environment: r.Environment, Domain: r.Domain, Dimension: r.Dimension, GuestNotifyReconcileBinding: &model.CapacityGuestNotifyReconcileBinding{}}
		for _, kind := range []string{"same_old", "only_Source_changed", "only_profile_changed", "both_changed_but_unapproved"} {
			t.Run(kind, func(t *testing.T) {
				b := &model.CapacityGuestRetirementBinding{GuestSourceCommit: r.BlockedGuestSource, ProfileManifestSHA256: r.BlockedProfileSHA256}
				if kind == "only_Source_changed" || kind == "both_changed_but_unapproved" {
					b.GuestSourceCommit = strings.Repeat("f", 40)
				}
				if kind == "only_profile_changed" || kind == "both_changed_but_unapproved" {
					b.ProfileManifestSHA256 = strings.Repeat("a", 64)
				}
				p.GuestRetirementBinding = b
				if requireFailedInstalledReplacementTx(ctx, tx, policy, p) == nil {
					t.Fatal("terminal bypassed exact changed Source+profile and full compiled approval", kind)
				}
			})
		}
	})
	t.Run("terminal_handoff_allows_ordinary_assessment_generation7", func(t *testing.T) {
		// A storage/phase seam, not a fabricated production Guest approval. The
		// separate test above exercises the actual Guest replacement gate in PG.
		db, policy, a := capacityPostgresFixture(t)
		var p model.CapacityPolicySpec
		if json.Unmarshal(policy.Spec, &p) != nil {
			t.Fatal("fixture policy")
		}
		a.Snapshot.Units = 0
		old := model.CapacityIntent{Namespace: policy.Metadata.Namespace, PolicyName: policy.Metadata.Name, Environment: p.Environment, Domain: p.Domain, Dimension: p.Dimension, PolicyID: policy.ID, PolicyChecksum: policy.Checksum, Generation: 6, FencingToken: 15, Phase: "disposed_failed_installed", FailedInstalledDisposal: &model.CapacityFailedInstalledDisposal{ID: uuid.NewString(), Stage: "terminal"}, Assessment: a}
		before, _ := json.Marshal(old)
		if _, e := db.ExecContext(ctx, `INSERT INTO public.capacity_intents(namespace,environment,domain,dimension,intent) VALUES($1,$2,$3,$4,$5::jsonb)`, old.Namespace, old.Environment, old.Domain, old.Dimension, string(before)); e != nil {
			t.Fatal(e)
		}
		requested, e := failedInstalledDisposalClaimRequested(old.FailedInstalledDisposal)
		if e != nil || requested {
			t.Fatal("scheduler did not reach ordinary assessment")
		}
		next, e := (CapacityStore{DB: db, ExecutionEnabled: true}).Assess(ctx, policy, a)
		if e != nil || next.Generation != 7 || next.Phase != "proposed" || next.FailedInstalledDisposal != nil {
			t.Fatal("completed disposal permanently froze original generation", next.Generation, next.Phase, e)
		}
		var stored []byte
		if e = db.QueryRowContext(ctx, `SELECT intent FROM public.capacity_intents WHERE namespace=$1 AND dimension=$2`, old.Namespace, old.Dimension).Scan(&stored); e != nil {
			t.Fatal(e)
		}
		var got model.CapacityIntent
		if json.Unmarshal(stored, &got) != nil || got.Generation != 7 {
			t.Fatal("generation7 proposal was not persisted")
		}
	})

	t.Run("floor_exception_does_not_credit_previous_promotion", func(t *testing.T) {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		r := FailedInstalledGuestDisposal{PreregistrationID: uuid.NewString(), Namespace: policy.Metadata.Namespace, Environment: "production", Domain: "notify", Dimension: "zero-useful-only", OriginalIntent: model.CapacityIntent{Generation: 6}}
		if err = failedInstalledZeroUsefulTx(ctx, tx, r, time.Now().UTC(), ""); err != nil {
			t.Fatal("empty native storage query", err)
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_intent_events(namespace,environment,domain,dimension,generation,fencing_token,phase,receipt_ref) VALUES($1,$2,$3,$4,6,11,'promoted','declared-storage-only')`, r.Namespace, r.Environment, r.Domain, r.Dimension)
		if err != nil {
			t.Fatal(err)
		}
		if failedInstalledZeroUsefulTx(ctx, tx, r, time.Now().UTC(), "") == nil {
			t.Fatal("previous useful phase bypassed protected floor")
		}
	})
	t.Run("CAS_event_rollback_and_stale_epoch", func(t *testing.T) {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		old := model.CapacityIntent{Namespace: policy.Metadata.Namespace, Environment: "production", Domain: "notify", Dimension: "disposal-CAS-only", Generation: 6, FencingToken: 13, Phase: "preparing"}
		raw, _ := json.Marshal(old)
		_, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_intents(namespace,environment,domain,dimension,intent) VALUES($1,$2,$3,$4,$5::jsonb)`, old.Namespace, old.Environment, old.Domain, old.Dimension, string(raw))
		if err != nil {
			t.Fatal(err)
		}
		next := old
		next.FailedInstalledDisposal = &model.CapacityFailedInstalledDisposal{ID: uuid.NewString(), Stage: "requested"}
		if _, err = tx.ExecContext(ctx, `SAVEPOINT disposal_cas`); err != nil {
			t.Fatal(err)
		}
		if err = persistFailedInstalledDisposalIntentTx(ctx, tx, old, next); err != nil {
			t.Fatal(err)
		}
		if persistFailedInstalledDisposalIntentTx(ctx, tx, old, next) == nil {
			t.Fatal("same old epoch claimed twice")
		}
		if _, err = tx.ExecContext(ctx, `ROLLBACK TO SAVEPOINT disposal_cas`); err != nil {
			t.Fatal(err)
		}
		var current []byte
		var events int
		if err = tx.QueryRowContext(ctx, `SELECT intent FROM public.capacity_intents WHERE namespace=$1 AND dimension=$2`, old.Namespace, old.Dimension).Scan(&current); err != nil {
			t.Fatal(err)
		}
		var got model.CapacityIntent
		if json.Unmarshal(current, &got) != nil || got.FailedInstalledDisposal != nil {
			t.Fatal("rollback left authority")
		}
		if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_intent_events WHERE namespace=$1 AND dimension=$2`, old.Namespace, old.Dimension).Scan(&events); err != nil || events != 0 {
			t.Fatal("rollback left disposal event", err)
		}
	})
}
