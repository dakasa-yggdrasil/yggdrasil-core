package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// Declared native read records exercise the actual owning validator and real
// isolated SQL component. They supply no AWS execution or enrollment authority.
func witnessedUnenrolledAWSObservation(t *testing.T, c model.CapacityOriginalCreateDispositionCandidate) model.CapacityOriginalCreateDispositionObservation {
	t.Helper()
	_, o, _ := enrolledFailedAWSObservationFixture(t)
	o.Profile, o.Slot, o.GrantID, o.AttemptID = c.Request.Profile, c.Request.Slot, c.Request.GrantID, c.Request.AttemptID
	o.RequestSHA256, o.ResourceID, o.ResourceCreatedAt = c.Request.RequestSHA256, c.Request.ExpectedResourceID, c.Request.ExpectedResourceCreatedAt
	o.NativeReads[1].ResourceID = o.ResourceID
	enrolledFailedRecloseNativeBody(&o.NativeReads[2], enrolledFailedProjectedEvent(o.NativeReads[2].ResourceID, c.Request.OriginalCreateActionID, false))
	return o
}

func TestWitnessedUnenrolledAWSObservationBoundaries(t *testing.T) {
	c, o, now := enrolledFailedAWSObservationFixture(t)
	for _, name := range []string{"valid", "foreign_ami", "foreign_account", "birth", "creator", "observer", "partial_aux", "native_present", "missing_native_body", "raw_cloudtrail"} {
		t.Run(name, func(t *testing.T) {
			x := cloneDispositionObservation(o)
			switch name {
			case "foreign_ami":
				x.NativeReads[3].ResourceID = "ami-fffffffffffffffff"
			case "foreign_account":
				x.NativeReads[0].ResourceID = "999999999999"
			case "birth":
				created, err := time.Parse(time.RFC3339Nano, c.Request.ExpectedResourceCreatedAt)
				if err != nil {
					t.Fatal(err)
				}
				x.ResourceCreatedAt = created.Add(time.Second).Format(time.RFC3339Nano)
			case "creator":
				x.OriginalAdapterSourceCommit = originalDispositionAWS1653OriginalSource
			case "observer":
				x.AdapterSourceCommit = strings.Repeat("e", 40)
			case "partial_aux":
				x.AuxiliaryResources[0].Absent = false
			case "native_present":
				x.ResourceState, x.ResourceAbsenceComplete = "running", false
			case "missing_native_body":
				x.NativeReads[0].ResponseBodyBase64 = ""
			case "raw_cloudtrail":
				x.NativeReads[2].ResponseRepresentation = "raw_http_body_v1"
			}
			err := validateWitnessedUnenrolledAWSObservation(c, x, "ami-0123456789abcdef0", "123456789012", o.ObservationStartedAt, now, 30*time.Second)
			if (err == nil) != (name == "valid") {
				t.Fatal("witnessed unenrolled AWS proof boundary", name, err)
			}
		})
	}
}

func TestWitnessedUnenrolledAWSFailedOriginalPostgresWholeLifecycle(t *testing.T) {
	db := originalDispositionPG(t)
	for _, explicit := range []bool{false, true} {
		name := "owning_omitted_false_and_empty"
		flag, resources := "", ""
		if explicit {
			name, flag, resources = "explicit_false_and_empty_compatible", "false", "[]"
		}
		t.Run(name, func(t *testing.T) {
			f := enrolledFailedAWSOriginalPGFixture(t, db, flag, resources)
			ctx, stop := context.WithTimeout(context.Background(), 15*time.Second)
			defer stop()
			owner, err := f.store.BeginFailedOriginalDisposition(ctx, f.pre.OriginalCreateGrantID, f.jobID.String(), "collaborator:"+uuid.NewString())
			if err != nil {
				t.Fatal("Begin modern AWS", err)
			}
			c := owner.Candidate()
			if c.Request.OriginalAuxiliaryInventoryComplete || len(c.Request.AuxiliaryResources) != 0 || c.Request.OriginalCreateActionID != f.record.Settlement.ActionID {
				t.Fatal("original unknown-AUX/action rewritten")
			}
			o := witnessedUnenrolledAWSObservation(t, c)
			r, err := f.store.CompleteFailedOriginalDisposition(ctx, owner, o)
			if err != nil {
				t.Fatal("Complete modern AWS through migration82", err)
			}
			read, err := f.store.ReadFailedOriginalDisposition(ctx, r.GrantID)
			if err != nil || originalDispositionJSONSHA(read) != originalDispositionJSONSHA(r) {
				t.Fatal("GET reconciliation", err)
			}
			var grant, run, witness, state string
			var ack sql.NullTime
			if err = db.QueryRow(`SELECT grant_record::text FROM public.capacity_mutation_grants WHERE id=$1`, r.GrantID).Scan(&grant); err != nil || grant != f.rawGrant {
				t.Fatal("accepted original modified", err)
			}
			if err = db.QueryRow(`SELECT to_jsonb(w)::text FROM public.workflow_runs w WHERE id=$1`, f.runID).Scan(&run); err != nil || run != f.originalRun {
				t.Fatal("failed original return modified", err)
			}
			if err = db.QueryRow(`SELECT witness_sha256 FROM public.capacity_guest_original_create_witnesses WHERE preregistration_id=$1`, f.pre.PreregistrationID).Scan(&witness); err != nil || witness != capacity.GuestRetirementSHA(f.witness) {
				t.Fatal("witness modified", err)
			}
			if err = db.QueryRow(`SELECT state,finalization_ack_at FROM public.capacity_dispatch_jobs WHERE id=$1`, f.jobID).Scan(&state, &ack); err != nil || state != "failed_disposed" || ack.Valid {
				t.Fatal("unknown ACK rewritten", err)
			}
			if !r.OriginalWitnessPreserved || !r.OriginalAcceptedUnchanged || !r.OriginalUnknownACKPreserved || r.HistoricalWriterStartState != "unknown" || r.ServingOrBusinessOrSavingsAuthority {
				t.Fatal("administrative accounting relabelled runtime")
			}
			if _, err = f.store.CompleteFailedOriginalDisposition(ctx, owner, o); err == nil {
				t.Fatal("owner replay admitted")
			}
			if _, err = f.store.BeginFailedOriginalDisposition(ctx, r.GrantID, f.jobID.String(), r.Issuer); err == nil {
				t.Fatal("witnessed terminal reopened")
			}
			var p model.CapacityPolicySpec
			_ = json.Unmarshal(f.policy.Spec, &p)
			tx, err := db.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			if requireOriginalDispositionSuccessorTx(ctx, tx, f.policy.Metadata.Namespace, p, f.record.Binding, 1, r.ClosedGeneration, r.ClosedFencingToken) == nil {
				t.Fatal("old generation/fence reused")
			}
			if err = requireOriginalDispositionSuccessorTx(ctx, tx, f.policy.Metadata.Namespace, p, f.record.Binding, 1, r.ClosedGeneration+1, r.ClosedFencingToken+1); err != nil {
				t.Fatal("fresh ordinary generation held", err)
			}
		})
	}
}

func TestWitnessedUnenrolledAWSFailedOriginalPostgresStateGuards(t *testing.T) {
	db := originalDispositionPG(t)
	for _, name := range []string{"enrollment", "installation", "ACK_changed"} {
		t.Run(name, func(t *testing.T) {
			f := enrolledFailedAWSOriginalPGFixture(t, db, "", "")
			ctx, stop := context.WithTimeout(context.Background(), 10*time.Second)
			defer stop()
			owner, err := f.store.BeginFailedOriginalDisposition(ctx, f.pre.OriginalCreateGrantID, f.jobID.String(), "collaborator:"+uuid.NewString())
			if err != nil {
				t.Fatal("Begin", err)
			}
			o := witnessedUnenrolledAWSObservation(t, owner.Candidate())
			switch name {
			case "enrollment":
				// Reuse the complete declared local enrollment representation;
				// no production signature or native authority is claimed.
				enrolledFailedSQLRecordFromFixture(t, db, f)
			case "installation":
				witnessedUnenrolledDeclaredInstallation(t, db, f)
			case "ACK_changed":
				_, err = db.Exec(`UPDATE public.capacity_dispatch_jobs SET state='returned',finalization_ack_at=clock_timestamp() WHERE id=$1`, f.jobID)
				if err == nil {
					t.Fatal("manufactured ACK bypassed original-owner guard")
				}
				var ack sql.NullTime
				var state string
				if readErr := db.QueryRow(`SELECT state,finalization_ack_at FROM public.capacity_dispatch_jobs WHERE id=$1`, f.jobID).Scan(&state, &ack); readErr != nil || state != "unknown" || ack.Valid {
					t.Fatal("refused ACK changed original history", readErr)
				}
				return
			}
			if err != nil {
				t.Fatal("declared local conflicting history", err)
			}
			if _, err = f.store.CompleteFailedOriginalDisposition(ctx, owner, o); err == nil {
				t.Fatal("changed/enrolled history accepted", name)
			}
			var n int
			if err = db.QueryRow(`SELECT count(*) FROM public.capacity_failed_original_dispositions WHERE grant_id=$1`, f.pre.OriginalCreateGrantID).Scan(&n); err != nil || n != 0 {
				t.Fatal("partial terminal survived", err)
			}
		})
	}
}

func TestWitnessedUnenrolledAWSMigration82NativeGuards(t *testing.T) {
	db := originalDispositionPG(t)
	for _, name := range []string{"valid", "foreign_ami", "foreign_account", "birth", "observer", "native_present", "partial_aux", "missing_body", "raw_cloudtrail"} {
		t.Run(name, func(t *testing.T) {
			f := enrolledFailedAWSOriginalPGFixture(t, db, "", "")
			ctx, stop := context.WithTimeout(context.Background(), 10*time.Second)
			defer stop()
			tx, err := db.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			r, s := migration73Record(t, ctx, tx, f)
			r.Observation = witnessedUnenrolledAWSObservation(t, s.candidate)
			o := &r.Observation
			switch name {
			case "foreign_ami":
				o.NativeReads[3].ResourceID = "ami-fffffffffffffffff"
			case "foreign_account":
				o.NativeReads[0].ResourceID = "999999999999"
			case "birth":
				o.ResourceCreatedAt = time.Now().UTC().Format(time.RFC3339Nano)
			case "observer":
				o.AdapterSourceCommit = strings.Repeat("e", 40)
			case "native_present":
				o.ResourceState, o.ResourceAbsenceComplete = "running", false
			case "partial_aux":
				o.AuxiliaryResources = o.AuxiliaryResources[:1]
			case "missing_body":
				o.NativeReads[0].ResponseBodyBase64 = ""
			case "raw_cloudtrail":
				o.NativeReads[2].ResponseRepresentation = "raw_http_body_v1"
			}
			err = migration73Insert(tx, r)
			if name == "valid" {
				if err != nil {
					t.Fatal("real migration82 insert", err)
				}
				migration73Projections(t, tx, r, s, "none")
				if _, err = tx.Exec(`SET CONSTRAINTS ALL IMMEDIATE`); err != nil {
					t.Fatal("unchanged atomic foreign-key closure", err)
				}
			} else if err == nil {
				t.Fatal("SQL bypass accepted malformed native proof", name)
			}
		})
	}
}

// Complete DECLARED storage, not a native/signature authority. Schema69 owns
// the real enrollment FK and immutable wire/hash/time columns in the full DB.
func witnessedUnenrolledDeclaredInstallation(t *testing.T, db *sql.DB, f failedOriginalFixture) {
	t.Helper()
	_, enrolled := enrolledFailedSQLRecordFromFixture(t, db, f)
	confirmation := model.CapacityGuestOriginalInstallationConfirmation{Schema: capacity.GuestOriginalInstallationSchema, PreregistrationID: f.pre.PreregistrationID, OriginalReceiptSHA256: enrolled.OriginalReceiptSHA256, EnrollmentSHA256: enrolled.OriginalEnrollmentSHA256, InstalledAt: f.pre.ReservedAt.Add(6 * time.Second), AdmittedAt: f.pre.ReservedAt.Add(7 * time.Second), Signature: strings.Repeat("A", 88)}
	wire, err := json.Marshal(confirmation)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`INSERT INTO public.capacity_guest_original_installations(preregistration_id,original_wire,confirmation_sha256,recorded_at) VALUES($1,$2,$3,$4)`, f.pre.PreregistrationID, wire, capacity.GuestRetirementSHA(confirmation), confirmation.AdmittedAt); err != nil {
		t.Fatal(err)
	}
}
