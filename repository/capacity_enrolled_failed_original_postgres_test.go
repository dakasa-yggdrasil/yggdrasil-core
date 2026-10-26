package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
	"strings"
	"testing"
	"time"
)

func enrolledFailedPG(t *testing.T) *sql.DB { t.Helper(); return originalDispositionPG(t) }

// DECLARED SQL representation fixture only. Its placeholder signature-shaped
// strings are NOT valid signatures: the Go Begin path must refuse it. Separate
// pure owning tests exercise actual signed registration/enrollment validation.
func enrolledFailedSQLRecord(t *testing.T, db *sql.DB) (failedOriginalFixture, model.CapacityEnrolledFailedOriginalDisposition) {
	t.Helper()
	return enrolledFailedSQLRecordFromFixture(t, db, failedOriginalPGFixture(t, db))
}
func enrolledFailedSQLRecordFromFixture(t *testing.T, db *sql.DB, f failedOriginalFixture) (failedOriginalFixture, model.CapacityEnrolledFailedOriginalDisposition) {
	t.Helper()
	at := f.pre.ReservedAt.Add(5 * time.Second)
	enrollment := map[string]any{"statement": map[string]any{"tuple": f.witness.Tuple}, "signature": strings.Repeat("A", 88)}
	registration := map[string]any{"result": map[string]any{"schema": "original_guest_protected_provisioning_v2", "tuple": f.witness.Tuple, "preregistration_id": f.pre.PreregistrationID, "original_create_grant_id": f.pre.OriginalCreateGrantID, "original_create_attempt_id": f.record.AttemptID, "profile_manifest_sha256": f.pre.ProfileManifestSHA256, "preregistration_nonce_sha256": f.pre.NonceSHA256, "admission_opened": false, "production_clock": map[string]any{}}, "enrollment_statement": enrollment["statement"], "signature": strings.Repeat("A", 88)}
	reg, _ := json.Marshal(registration)
	enr, _ := json.Marshal(enrollment)
	regSHA, enrSHA := originalDispositionDigest(reg), originalDispositionDigest(enr)
	receipt, _ := json.Marshal(map[string]any{"preregistration_id": f.pre.PreregistrationID, "recorded_at": at, "enrollment": enrollment, "original_provisioning_sha256": regSHA})
	if _, err := db.Exec(`INSERT INTO public.capacity_vm_original_enrollments(preregistration_id,resource_tuple_sha256,enrollment_sha256,original_provisioning_sha256,enrollment_record,recorded_at,registration_wire,receipt_wire) VALUES($1,$2,$3,$4,$5::jsonb,$6,$7,$8)`, f.pre.PreregistrationID, originalDispositionJSONSHA(f.witness.Tuple), enrSHA, regSHA, string(enr), at, reg, receipt); err != nil {
		t.Fatal(err)
	}
	var now time.Time
	var binding []byte
	if err := db.QueryRow(`SELECT clock_timestamp(),binding_wire FROM public.capacity_vm_provisioning_preregistrations WHERE id=$1`, f.pre.PreregistrationID).Scan(&now, &binding); err != nil {
		t.Fatal(err)
	}
	c := model.CapacityOriginalCreateDispositionCandidate{Request: model.CapacityOriginalCreateDispositionReadRequest{OriginalAuxiliaryInventoryComplete: f.record.Settlement.AuxiliaryInventoryComplete, Profile: f.record.Binding.ProfileName, Slot: 1, GrantID: f.pre.OriginalCreateGrantID, AttemptID: f.record.AttemptID, RequestSHA256: f.record.Grant.RequestSHA256, ExpectedResourceID: f.record.Settlement.ResourceID, ExpectedResourceCreatedAt: f.record.Settlement.ResourceCreatedAt, OriginalAdapterSourceCommit: f.record.Binding.OriginalProviderSourceCommit, AuxiliaryResources: f.record.Settlement.AuxiliaryResources}}
	o := f.absent(t, c)
	o.AdapterSourceCommit = enrolledFailedHetznerCreator
	if f.record.EventProvider == "aws" {
		c.Request.OriginalCreateActionID = f.record.Settlement.ActionID
		_, o, _ = enrolledFailedAWSObservationFixture(t)
		o.Profile, o.Slot, o.GrantID, o.AttemptID = c.Request.Profile, c.Request.Slot, c.Request.GrantID, c.Request.AttemptID
		o.RequestSHA256, o.ResourceID, o.ResourceCreatedAt = c.Request.RequestSHA256, c.Request.ExpectedResourceID, c.Request.ExpectedResourceCreatedAt
		o.NativeReads[1].ResourceID = o.ResourceID
		enrolledFailedRecloseNativeBody(&o.NativeReads[2], enrolledFailedProjectedEvent(o.NativeReads[2].ResourceID, c.Request.OriginalCreateActionID, false))
	}
	r := model.CapacityEnrolledFailedOriginalDisposition{Schema: model.EnrolledFailedOriginalDispositionSchema, ID: uuid.NewString(), GrantID: f.pre.OriginalCreateGrantID, PreregistrationID: f.pre.PreregistrationID, JobID: f.jobID.String(), RunID: f.runID.String(), Issuer: "collaborator:" + uuid.NewString(), OriginalGrantSHA256: originalDispositionDigest([]byte(f.rawGrant)), OriginalPreregistrationSHA256: originalDispositionJSONSHA(f.pre), OriginalWitnessSHA256: originalDispositionJSONSHA(f.witness), OriginalDispatchSHA256: originalDispositionDigest([]byte(f.originalDispatch)), OriginalRunSHA256: originalDispositionDigest([]byte(f.originalRun)), OriginalBindingSHA256: originalDispositionDigest(binding), OriginalRegistrationSHA256: regSHA, OriginalReceiptSHA256: originalDispositionDigest(receipt), OriginalEnrollmentSHA256: enrSHA, ClosedGeneration: f.intent.Generation, ClosedFencingToken: f.intent.FencingToken + 1, RecordedAt: now.UTC(), Observation: o, OriginalAcceptedUnchanged: true, OriginalWitnessPreserved: true, OriginalUnknownACKPreserved: true, OriginalEnrollmentPreserved: true, HistoricalWriterStartState: "unknown"}
	return f, r
}
func insertEnrolledFailedSQL(tx *sql.Tx, r model.CapacityEnrolledFailedOriginalDisposition) error {
	raw, e := json.Marshal(r)
	if e != nil {
		return e
	}
	return insertEnrolledFailedSQLWire(tx, r, raw)
}
func insertEnrolledFailedSQLWire(tx *sql.Tx, r model.CapacityEnrolledFailedOriginalDisposition, raw []byte) error {
	_, e := tx.Exec(`INSERT INTO public.capacity_enrolled_failed_original_dispositions(id,grant_id,preregistration_id,job_id,run_id,original_grant_sha256,original_preregistration_sha256,original_witness_sha256,original_dispatch_sha256,original_run_sha256,original_registration_sha256,original_receipt_sha256,original_enrollment_sha256,disposition_sha256,original_wire,disposition_record,recorded_at,closed_generation,closed_fencing_token)VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16::jsonb,$17,$18,$19)`, r.ID, r.GrantID, r.PreregistrationID, r.JobID, r.RunID, r.OriginalGrantSHA256, r.OriginalPreregistrationSHA256, r.OriginalWitnessSHA256, r.OriginalDispatchSHA256, r.OriginalRunSHA256, r.OriginalRegistrationSHA256, r.OriginalReceiptSHA256, r.OriginalEnrollmentSHA256, originalDispositionDigest(raw), raw, string(raw), r.RecordedAt, r.ClosedGeneration, r.ClosedFencingToken)
	return e
}
func linkEnrolledFailedSQL(t *testing.T, tx *sql.Tx, f failedOriginalFixture, r model.CapacityEnrolledFailedOriginalDisposition, omit string) {
	t.Helper()
	if omit != "grant" {
		if _, e := tx.Exec(`UPDATE public.capacity_mutation_grants SET enrolled_failed_disposition_id=$2 WHERE id=$1`, r.GrantID, r.ID); e != nil {
			t.Fatal(e)
		}
	}
	if omit != "job" {
		if _, e := tx.Exec(`UPDATE public.capacity_dispatch_jobs SET state='enrolled_failed_disposed',enrolled_failed_disposition_id=$2,updated_at=clock_timestamp() WHERE id=$1`, r.JobID, r.ID); e != nil {
			t.Fatal(e)
		}
	}
	if omit != "intent" {
		i := f.intent
		i.Phase = "reconciled_failed_floor"
		i.FloorDegraded = true
		i.RecoveryOnly = false
		i.Decision.ExecutionPermitted = false
		i.FencingToken = r.ClosedFencingToken
		i.LeaseOwner = ""
		i.LeaseExecutorID = ""
		i.LeaseExpiresAt = nil
		raw, _ := json.Marshal(i)
		if _, e := tx.Exec(`UPDATE public.capacity_intents SET intent=$5::jsonb WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4`, i.Namespace, i.Environment, i.Domain, i.Dimension, string(raw)); e != nil {
			t.Fatal(e)
		}
	}
}
func TestEnrolledFailedDispositionPostgresAtomicLinksAndSuccessorFence(t *testing.T) {
	db := enrolledFailedPG(t)
	for _, omit := range []string{"grant", "job", "intent", "none"} {
		t.Run(omit, func(t *testing.T) {
			f, r := enrolledFailedSQLRecord(t, db)
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			// A SQL shape is not a valid signed producer: Go refuses before native I/O.
			if _, e := f.store.BeginEnrolledFailedOriginalDisposition(ctx, r.GrantID, r.JobID, r.Issuer); e == nil {
				t.Fatal("signature-shaped SQL fixture acquired Go authority")
			}
			tx, e := db.BeginTx(ctx, nil)
			if e != nil {
				t.Fatal(e)
			}
			defer tx.Rollback()
			// clock_timestamp must be sampled inside the exact insert transaction.
			if e = tx.QueryRow(`SELECT clock_timestamp()`).Scan(&r.RecordedAt); e != nil {
				t.Fatal(e)
			}
			if e = insertEnrolledFailedSQL(tx, r); e != nil {
				t.Fatal("insert", e)
			}
			linkEnrolledFailedSQL(t, tx, f, r, omit)
			_, e = tx.Exec(`SET CONSTRAINTS ALL IMMEDIATE`)
			if (e == nil) != (omit == "none") {
				t.Fatalf("atomic closure %s: %v", omit, e)
			}
			if omit == "none" {
				var p model.CapacityPolicySpec
				_ = json.Unmarshal(f.policy.Spec, &p)
				if requireOriginalDispositionSuccessorTx(ctx, tx, f.policy.Metadata.Namespace, p, f.record.Binding, 1, r.ClosedGeneration, r.ClosedFencingToken) == nil {
					t.Fatal("old generation/fence reused")
				}
				if e = requireOriginalDispositionSuccessorTx(ctx, tx, f.policy.Metadata.Namespace, p, f.record.Binding, 1, r.ClosedGeneration+1, r.ClosedFencingToken+1); e != nil {
					t.Fatal("fresh successor fence refused", e)
				}
				var grant, run, witness string
				var ack sql.NullTime
				if e = tx.QueryRow(`SELECT grant_record::text FROM public.capacity_mutation_grants WHERE id=$1`, r.GrantID).Scan(&grant); e != nil || grant != f.rawGrant {
					t.Fatal("accepted create changed", e)
				}
				if e = tx.QueryRow(`SELECT to_jsonb(w)::text FROM public.workflow_runs w WHERE id=$1`, r.RunID).Scan(&run); e != nil || run != f.originalRun {
					t.Fatal("failed run changed", e)
				}
				if e = tx.QueryRow(`SELECT witness_sha256 FROM public.capacity_guest_original_create_witnesses WHERE preregistration_id=$1`, r.PreregistrationID).Scan(&witness); e != nil || witness != r.OriginalWitnessSHA256 {
					t.Fatal("witness changed", e)
				}
				if e = tx.QueryRow(`SELECT finalization_ack_at FROM public.capacity_dispatch_jobs WHERE id=$1`, r.JobID).Scan(&ack); e != nil || ack.Valid {
					t.Fatal("ACK invented", e)
				}
			}
		})
	}
}
func TestEnrolledFailedDispositionPostgresClosedForgeryBoundaries(t *testing.T) {
	db := enrolledFailedPG(t)
	enrolledFailedAWSContractBoundaries(t, db)
	for _, name := range []string{"registration_hash", "receipt_hash", "enrollment_hash", "quiescence", "serving", "writer_never_started", "missing_interval", "missing_native_body", "deleted_interval", "deleted_native_body", "aux_alias", "missing_aux_read", "old_fence", "enrollment_not_preserved"} {
		t.Run(name, func(t *testing.T) {
			f, r := enrolledFailedSQLRecord(t, db)
			_ = f
			switch name {
			case "registration_hash":
				r.OriginalRegistrationSHA256 = strings.Repeat("0", 64)
			case "receipt_hash":
				r.OriginalReceiptSHA256 = strings.Repeat("0", 64)
			case "enrollment_hash":
				r.OriginalEnrollmentSHA256 = strings.Repeat("0", 64)
			case "quiescence":
				r.GuestQuiescenceProved = true
			case "serving":
				r.InstallationOrServingAuthority = true
			case "writer_never_started":
				r.HistoricalWriterStartState = "never_started"
			case "missing_interval":
				r.Observation.ObservationStartedAt = time.Time{}
				r.Observation.ObservedAt = time.Time{}
			case "missing_native_body":
				r.Observation.NativeReads[0].ResponseBodyBase64 = ""
				r.Observation.NativeReads[0].ResponseSHA256 = ""
				r.Observation.NativeReads[0].ResponseBytes = 0
			case "aux_alias":
				r.Observation.AuxiliaryResources[0].ID = "foreign"
			case "missing_aux_read":
				r.Observation.NativeReads = r.Observation.NativeReads[:1]
			case "old_fence":
				r.ClosedFencingToken--
			case "enrollment_not_preserved":
				r.OriginalEnrollmentPreserved = false
			}
			tx, e := db.Begin()
			if e != nil {
				t.Fatal(e)
			}
			defer tx.Rollback()
			if e = tx.QueryRow(`SELECT clock_timestamp()`).Scan(&r.RecordedAt); e != nil {
				t.Fatal(e)
			}
			wire, _ := json.Marshal(r)
			if name == "deleted_interval" || name == "deleted_native_body" {
				var v map[string]any
				_ = json.Unmarshal(wire, &v)
				ob := v["observation"].(map[string]any)
				if name == "deleted_interval" {
					delete(ob, "observation_started_at")
					delete(ob, "observed_at")
				} else {
					read := ob["native_reads"].([]any)[0].(map[string]any)
					delete(read, "response_body_base64")
					delete(read, "response_sha256")
					delete(read, "response_bytes")
				}
				wire, _ = json.Marshal(v)
			}
			if e = insertEnrolledFailedSQLWire(tx, r, wire); e == nil {
				t.Fatal("reclosed forged SQL terminal accepted", name)
			}
		})
	}
}

func enrolledFailedAWSContractBoundaries(t *testing.T, db *sql.DB) {
	t.Helper()
	for _, name := range []string{"valid_distinct_event_and_request", "valid_explicit_false_and_empty_aux", "flag_null", "flag_string", "flag_object", "aux_null", "aux_string", "aux_object", "aux_nonempty", "raw_userdata", "canonical_userdata", "projected_userdata", "duplicate_private_request_parameters", "duplicate_outer_response", "event_record_alias", "request_alias", "foreign_page_event", "duplicate_request", "state_deleted", "state_null", "state_object"} {
		t.Run("AWS/"+name, func(t *testing.T) {
			flag, aux := "", ""
			switch name {
			case "valid_explicit_false_and_empty_aux":
				flag, aux = "false", "[]"
			case "flag_null":
				flag = "null"
			case "flag_string":
				flag = `"false"`
			case "flag_object":
				flag = "{}"
			case "aux_null":
				aux = "null"
			case "aux_string":
				aux = `"[]"`
			case "aux_object":
				aux = "{}"
			case "aux_nonempty":
				aux = `[{"kind":"aws_ebs_volume","id":"vol-0123456789abcdef0","requires_absence":true}]`
			}
			f, r := enrolledFailedSQLRecordFromFixture(t, db, enrolledFailedAWSOriginalPGFixture(t, db, flag, aux))
			eventID, requestID := r.Observation.NativeReads[2].ResourceID, f.record.Settlement.ActionID
			if eventID == requestID {
				t.Fatal("fixture must keep EventID distinct from RequestID")
			}
			guard := "CloudTrail event/request identity"
			if strings.HasPrefix(name, "flag_") || strings.HasPrefix(name, "aux_") {
				guard = "exact expired witnessed accepted original"
			}
			if name == "request_alias" {
				requestID = eventID
			}
			body := enrolledFailedProjectedEvent(eventID, requestID, name == "raw_userdata" || name == "canonical_userdata" || name == "projected_userdata")
			if name == "projected_userdata" {
				guard = "truthful closed userdata-omitted CloudTrail projection"
			}
			if name == "duplicate_private_request_parameters" || name == "duplicate_outer_response" {
				body = enrolledFailedDuplicateProjection(eventID, requestID, name == "duplicate_outer_response")
				guard = "unique-key CloudTrail JSON"
			}
			var projection map[string]any
			_ = json.Unmarshal(body, &projection)
			page := projection["response"].(map[string]any)
			rows := page["Events"].([]any)
			switch name {
			case "raw_userdata", "canonical_userdata":
				guard = "sanitized CloudTrail projection"
				body, _ = json.Marshal(page)
				r.Observation.NativeReads[2].ResponseRepresentation = "raw_http_body_v1"
				if name == "canonical_userdata" {
					r.Observation.NativeReads[2].ResponseRepresentation = "canonical_provider_SDK_result_v1"
				}
			case "event_record_alias":
				r.Observation.NativeReads[2].ResourceID = requestID
			case "foreign_page_event":
				rows[0].(map[string]any)["EventId"] = uuid.NewString()
				body, _ = json.Marshal(projection)
			case "duplicate_request":
				page["Events"] = append(rows, rows[0])
				body, _ = json.Marshal(projection)
			}
			enrolledFailedRecloseNativeBody(&r.Observation.NativeReads[2], body)
			tx, e := db.Begin()
			if e != nil {
				t.Fatal(e)
			}
			defer tx.Rollback()
			if e = tx.QueryRow(`SELECT clock_timestamp()`).Scan(&r.RecordedAt); e != nil {
				t.Fatal(e)
			}
			wire, _ := json.Marshal(r)
			if strings.HasPrefix(name, "state_") {
				guard = "separate complete readonly native absence"
				var v map[string]any
				_ = json.Unmarshal(wire, &v)
				ob := v["observation"].(map[string]any)
				switch name {
				case "state_deleted":
					delete(ob, "resource_state")
				case "state_null":
					ob["resource_state"] = nil
				case "state_object":
					ob["resource_state"] = map[string]any{"state": "absent"}
				}
				wire, _ = json.Marshal(v)
			}
			e = insertEnrolledFailedSQLWire(tx, r, wire)
			if strings.HasPrefix(name, "valid_") {
				if e != nil {
					t.Fatal("distinct original EventID/RequestID must join", e)
				}
				linkEnrolledFailedSQL(t, tx, f, r, "none")
				if _, e = tx.Exec(`SET CONSTRAINTS ALL IMMEDIATE`); e != nil {
					t.Fatal("complete AWS atomic links", e)
				}
			} else if e == nil || !strings.Contains(e.Error(), guard) {
				t.Fatal("reclosed AWS outer wire must reach its specific SQL guard", name, e)
			}
		})
	}
}

// DECLARED AWS history for the new SQL76 contract. It is constructed before
// witness/enrollment insertion; no immutable historical row is rewritten.
// As in the H SQL fixture, signature-shaped enrollment is not Go authority.
func enrolledFailedAWSOriginalPGFixture(t *testing.T, db *sql.DB, auxiliaryFlag, auxiliaryResources string) failedOriginalFixture {
	t.Helper()
	f := originalDispositionPGFixturePrepared(t, db, func(f *dispositionPGFixture) {
		f.record.EventProvider = "aws"
		f.record.Binding.OriginalProviderSourceCommit = enrolledFailedAWSCreator
		f.record.Binding.EnsureCapability = "ensure_ec2_instance"
		f.record.Binding.DestroyCapability = "terminate_ec2_instance"
		f.record.Binding.Slots[0].DesiredSpec.Capability = "ensure_ec2_instance"
		requestSHA := originalDispositionJSONSHA(f.record.Binding.Slots[0].DesiredSpec)
		f.record.Binding.Slots[0].DesiredSpecSHA256 = requestSHA
		f.record.Grant.Capability, f.record.Grant.RequestSHA256 = "ensure_ec2_instance", requestSHA
		f.pre.OriginalCreateRequestSHA256 = requestSHA
		f.record.Settlement.RequestSHA256 = requestSHA
		o := f.record.Settlement.OriginalProviderCreateReturn
		o.Schema, o.Provider, o.AdapterSourceCommit = "aws_original_run_instances_return_v1", "aws", enrolledFailedAWSCreator
		o.RequestSHA256, o.ResourceID, o.ResponseStatus = requestSHA, "i-0123456789abcdef0", 200
		o.ActionID = uuid.NewString()
		f.record.Settlement.ActionID = o.ActionID
		f.record.Settlement.ResourceID = o.ResourceID
		f.record.Settlement.AuxiliaryResources = []model.CapacityMutationAuxiliaryResource{}
		f.record.Settlement.AuxiliaryInventoryComplete = false
		var p model.CapacityPolicySpec
		if json.Unmarshal(f.policy.Spec, &p) != nil {
			t.Fatal("fixture policy")
		}
		p.Profiles[0].Provider = "aws"
		policyRaw, _ := json.Marshal(p)
		f.policy.Spec = policyRaw
		grantRaw, _ := json.Marshal(f.record)
		// Preserve the real owning c34 omitempty shape in the default positive.
		// Compatibility/forgery cases change only the DECLARED SQL representation
		// before witness insertion; no old immutable or production row is rewritten.
		var grantFields, settlementFields map[string]json.RawMessage
		if err := json.Unmarshal(grantRaw, &grantFields); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(grantFields["settlement"], &settlementFields); err != nil {
			t.Fatal(err)
		}
		if _, present := settlementFields["auxiliary_inventory_complete"]; present {
			t.Fatal("owning false inventory flag must remain omitted")
		}
		if _, present := settlementFields["auxiliary_resources"]; present {
			t.Fatal("owning empty auxiliary slice must remain omitted")
		}
		if auxiliaryFlag != "" {
			settlementFields["auxiliary_inventory_complete"] = json.RawMessage(auxiliaryFlag)
		}
		if auxiliaryResources != "" {
			settlementFields["auxiliary_resources"] = json.RawMessage(auxiliaryResources)
		}
		if auxiliaryFlag != "" || auxiliaryResources != "" {
			grantFields["settlement"], _ = json.Marshal(settlementFields)
			grantRaw, _ = json.Marshal(grantFields)
		}
		f.initialGrantRaw = grantRaw
	})
	o := f.record.Settlement.OriginalProviderCreateReturn
	requestSHA := f.record.Grant.RequestSHA256
	var p model.CapacityPolicySpec
	if json.Unmarshal(f.policy.Spec, &p) != nil {
		t.Fatal("prepared AWS policy")
	}
	start := f.pre.ReservedAt.Add(-time.Second)
	finish := f.pre.OriginalDeadline.Add(time.Second)
	jobID, runID := uuid.New(), uuid.New()
	e := CapacityDispatchEnvelope{Protocol: CapacityDispatchProtocol, JobID: jobID, RunID: runID, Realm: f.policy.Metadata.Namespace, Environment: p.Environment, Domain: p.Domain, Dimension: p.Dimension, SourceTick: start.Format(time.RFC3339Nano), Policy: CapacityDispatchManifestPin{ID: f.policy.ID, Namespace: f.policy.Metadata.Namespace, Name: f.policy.Metadata.Name, Version: 1, Checksum: f.policy.Checksum}, Workflow: CapacityDispatchManifestPin{ID: f.record.WorkflowID, Namespace: f.policy.Metadata.Namespace, Name: "original", Version: 1, Checksum: f.pre.WorkflowChecksum}, RBAC: CapacityDispatchManifestPin{ID: uuid.New(), Namespace: f.policy.Metadata.Namespace, Name: "isolated-rbac", Version: 1, Checksum: strings.Repeat("9", 64)}, MachinePrincipalID: "isolated-terminal-test", PrincipalSHA256: strings.Repeat("8", 64), BindingSHA256: strings.Repeat("7", 64), Inputs: map[string]any{}, Metadata: map[string]any{}}
	e.Inputs = map[string]any{"policy": map[string]any{"namespace": e.Policy.Namespace, "name": e.Policy.Name}}
	e.Metadata = map[string]any{WorkflowRunCreatorMachinePrincipalMetadataKey: e.MachinePrincipalID, "triggered_by": "workflow_scheduler", "manifest_id": e.Workflow.ID.String(), "scheduled_for": e.SourceTick}
	e.InputsSHA256, e.MetadataSHA256, _ = CapacityDispatchEnvelopeHashes(e)
	envelope, err := encodeCapacityDispatchEnvelope(e)
	if err != nil {
		t.Fatal(err)
	}
	result := capacityDispatchResponse(e, "failed")
	result.StartedAt, result.FinishedAt = start, finish
	result.Steps = []model.WorkflowRunStepResult{{ID: "plan-original-guest", Status: "succeeded", Metadata: map[string]any{"generation": f.record.Generation, "fencing_token": f.record.FencingToken, "lease_owner": f.record.LeaseOwner}}, {ID: f.pre.OriginalWorkflowStepID, Status: "failed", Error: "original Guest reconciliation held", Metadata: map[string]any{"original_guest_refusal_predicate": "original-guest-step-29"}}}
	resultRaw, _ := json.Marshal(result)
	inputsRaw, _ := json.Marshal(e.Inputs)
	metadataRaw, _ := json.Marshal(e.Metadata)
	observed := f.pre.ReservedAt.Add(3 * time.Second)
	w := model.CapacityGuestOriginalCreateWitness{Schema: capacity.GuestCreateWitnessSchema, BindingName: f.pre.BindingName, PreregistrationID: f.pre.PreregistrationID, PreregistrationNonceSHA256: f.pre.NonceSHA256, OriginalCreateGrantID: f.pre.OriginalCreateGrantID, OriginalCreateAttemptID: f.record.AttemptID, OriginalCreateRequestSHA256: requestSHA, OriginalCreateSettlementSHA256: capacity.GuestRetirementSHA(*f.record.Settlement), ProfileManifestSHA256: f.pre.ProfileManifestSHA256, BootstrapSHA256: f.binding.ProfileManifest.BootstrapSHA256, CoreSourceCommit: f.pre.CoreSourceCommit, OriginalDeadline: f.pre.OriginalDeadline, OriginalCreateReturnedAt: f.pre.ReservedAt.Add(2 * time.Second), ObservedAt: observed, Tuple: model.CapacityGuestNativeTuple{Provider: "aws", InstanceID: f.record.Binding.IntegrationInstanceID, InstanceChecksum: f.record.Binding.IntegrationChecksum, TypeID: f.record.Binding.IntegrationTypeID, TypeChecksum: f.record.Binding.IntegrationTypeChecksum, ScopeChecksum: f.record.Binding.ScopeChecksum, Profile: f.record.Binding.ProfileName, Slot: 1, ResourceID: o.ResourceID, CreatedAt: o.ResourceCreatedAt}}
	w.ProviderNativeIdentity = &model.CapacityGuestProviderNativeIdentity{Schema: capacity.GuestProviderNativeIdentitySchema, Provider: "aws", ResourceID: o.ResourceID, ResourceCreatedAt: o.ResourceCreatedAt, Region: "us-east-1", TypeID: "m6a.large", ImageID: "ami-0123456789abcdef0", Hostname: "isolated-original", ObservedAt: observed, AdapterSourceCommit: enrolledFailedAWSCreator}
	// Complete the DECLARED AWS native-realm fixture before first insertion.
	w.ProviderNativeIdentity.Location = "us-east-1"
	w.ProviderNativeIdentity.Zone = "us-east-1a"
	w.ProviderNativeIdentity.AccountID = "123456789012"
	witnessRaw, _ := json.Marshal(w)
	must := func(query string, args ...any) {
		t.Helper()
		if _, err := db.Exec(query, args...); err != nil {
			t.Fatal(err)
		}
	}
	must(`INSERT INTO public.capacity_guest_original_create_witnesses(preregistration_id,original_wire,witness_sha256,original_record,original_create_attempt_id,recorded_at,resource_tuple_sha256) VALUES($1,$2,$3,$4::jsonb,$5,$6,$7)`, f.pre.PreregistrationID, witnessRaw, capacity.GuestRetirementSHA(w), string(witnessRaw), f.record.AttemptID, observed, capacity.GuestRetirementSHA(w.Tuple))
	// The owning insertWorkflowRun stores the selector and omits workflow_id.
	// Keep the actual historical NULL instead of improving the old row.
	must(`INSERT INTO public.workflow_runs(id,status,workflow_namespace,workflow_name,workflow_version,started_at,finished_at,result,error,inputs,metadata) VALUES($1,'failed',$2,'original',1,$3,$4,$5::jsonb,'original deadline elapsed',$6::jsonb,$7::jsonb)`, runID, f.policy.Metadata.Namespace, start, finish, string(resultRaw), string(inputsRaw), string(metadataRaw))
	// A DECLARED original tuple exercises the real database guards. This
	// fixture supplies no native execution and never fabricates a late ACK.
	must(`INSERT INTO public.capacity_dispatch_jobs(id,run_id,protocol,realm,environment,domain,dimension,source_tick,envelope,envelope_sha256,state,lease_owner,fencing_token,lease_expires_at,started_at,returned_at,return_status,return_error,finalization_error) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'unknown',$11,1,$12,$13,$14,'failed','original deadline elapsed','original deadline elapsed')`, jobID, runID, e.Protocol, e.Realm, e.Environment, e.Domain, e.Dimension, e.SourceTick, string(envelope), capacityDispatchSHA(envelope), uuid.New(), f.pre.OriginalDeadline, start, finish)
	var rawGrant, rawDispatch, rawRun string
	if err = db.QueryRow(`SELECT grant_record::text FROM public.capacity_mutation_grants WHERE id=$1`, f.pre.OriginalCreateGrantID).Scan(&rawGrant); err != nil {
		t.Fatal(err)
	}
	if err = db.QueryRow(`SELECT to_jsonb(j)::text FROM public.capacity_dispatch_jobs j WHERE id=$1`, jobID).Scan(&rawDispatch); err != nil {
		t.Fatal(err)
	}
	if err = db.QueryRow(`SELECT to_jsonb(w)::text FROM public.workflow_runs w WHERE id=$1`, runID).Scan(&rawRun); err != nil {
		t.Fatal(err)
	}
	f.rawGrant = rawGrant
	return failedOriginalFixture{f, jobID, runID, w, rawDispatch, rawRun}
}
