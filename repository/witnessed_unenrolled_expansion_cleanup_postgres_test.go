//go:build recoveryfixture && !nativequalification

package repository

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/pressly/goose/v3"
)

// This private tail of the existing recovery-fixture root declares provider,
// Guest and HTTP DTOs. Only the production store, SQL, dispatch, callback and
// canary seams execute in CI. It supplies no provider/SSH/Guest execution or
// clean-cycle evidence and never changes the historical M94/M95 fixtures.
type witnessedCleanup106Fixture struct {
	DB               *sql.DB
	Policy, Workflow model.Manifest
	Spec             model.CapacityPolicySpec
	private          *failedServingFixture
	job              CapacityDispatchJob
	pre              model.CapacityGuestOriginalProvisioningPreregistration
	witness          model.CapacityGuestOriginalCreateWitness
	registration     model.CapacityGuestOriginalProvisioningRegistration
	receipt          model.CapacityGuestOriginalProvisioningReceipt
	installation     model.CapacityGuestOriginalInstallationConfirmation
	parent           capacityMutationRecord
	intent           model.CapacityIntent
	base             map[string][]json.RawMessage
}

// TestWitnessedUnenrolledExpansionCleanupPostgres owns the unchanged M106
// regression in its own CI process, including its real 300-second Guest claim.
func TestWitnessedUnenrolledExpansionCleanupPostgres(t *testing.T) {
	witnessedCleanup106PostgresRegression(t)
}

func witnessedCleanup106PostgresRegression(t *testing.T) {
	t.Helper()
	base := newFailedServingFixtureHistory(t, "hetzner", true)
	migrations := filepath.Join(failedServingRepositoryRoot(t), "db/migrations")
	if err := goose.UpToContext(context.Background(), base.db, migrations, 105); err != nil {
		t.Fatal(err)
	}
	before := installedReadinessCatalog(t, base.db)
	if err := goose.UpToContext(context.Background(), base.db, migrations, 106); err != nil {
		t.Fatal("M106 actual Up", err)
	}
	after := installedReadinessCatalog(t, base.db)
	put := witnessedCleanup106Put(t)
	put("M106-PG-BEFORE105-CATALOG.original.json", before)
	put("M106-PG-AFTER106-CATALOG.original.json", after)
	witnessedCleanup106Catalog(t, base.db, before, after, put)
	witnessedCleanup106OldGoose(t, base.db, migrations, put)
	f := witnessedCleanup106Current(t, base)
	// Current Source really captured and exhausted its ORIGINAL dispatch context.
	// The unchanged public HZN profile budget is 420s; the real Guest dispatch 300s claim
	// clips it through GuestOriginalProvisioningDeadline, without clock rewriting.
	put("M106-CURRENT-SOURCE-PRODUCER-WITNESS.PUBLIC.json", failedServingWire(t, map[string]any{
		"schema": "witnessed_cleanup106_current_source_fixture_v1", "fixture_only": true,
		"workflow_result_fixture_declared": true, "full_workflow_execution_claimed": false,
		"SDK_and_Guest_DTOs_declared": true, "provider_or_Guest_executed": false,
		"real_enqueue_claim_start_finish_UNKNOWN": true, "original_ACK_absent": true,
		"unchanged_profile_420_seconds": true, "original_context_clipped_by_real_300_second_claim": true,
		"original_300_second_context_naturally_expired": true, "originals": json.RawMessage(witnessedCleanup106Originals(t, f)),
	}))
	witnessedCleanup106AdmissionNegatives(t, f, put)
	f.base = witnessedCleanup106Rows(t, f.DB)
	// Each race starts from a separately declared exact copy of this immutable
	// failed history; none backdates or alters the current producer's originals.
	for _, kind := range []string{"enrollment", "installation"} {
		for _, writerFirst := range []bool{true, false} {
			r := witnessedCleanup106Clone(t, f, migrations)
			witnessedCleanup106CallbackRace(t, r, kind, writerFirst, put)
			if err := r.DB.Close(); err != nil {
				t.Fatal(err)
			}
		}
	}
	witnessedCleanup106RepeatableRead(t, f, migrations, put)
	witnessedCleanup106ClaimLockOrder(t, f, migrations, put)
	witnessedCleanup106TwoRequesters(t, f, put)
	a, _, err := (CapacityStore{DB: f.DB}).ReadWitnessedUnenrolledExpansionCleanup(context.Background(), f.pre.OriginalCreateGrantID)
	if err != nil {
		t.Fatal(err)
	}
	witnessedCleanup106Immutable(t, f, a)
	witnessedCleanup106Native(t, f, a, put)
	witnessedCleanup106Down(t, f.DB, migrations, put)
	witnessedCleanup106EmptyDown(t, migrations, put)
}

func witnessedCleanup106Put(t *testing.T) func(string, []byte) {
	t.Helper()
	dir := os.Getenv("PREACTION_PLAN_LOGS")
	if !filepath.IsAbs(dir) {
		t.Fatal("owned M106 evidence directory required")
	}
	return func(name string, raw []byte) {
		t.Helper()
		if len(raw) == 0 || len(raw) > 16<<20 || filepath.Base(name) != name {
			t.Fatal("bounded whole M106 artifact", name)
		}
		f, err := os.OpenFile(filepath.Join(dir, name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal(err)
		}
		n, we := f.Write(append(append([]byte(nil), raw...), '\n'))
		ce := f.Close()
		if we != nil || ce != nil || n != len(raw)+1 {
			t.Fatal("whole M106 artifact", name, n, we, ce)
		}
	}
}

func witnessedCleanup106Current(t *testing.T, base *failedServingFixture) *witnessedCleanup106Fixture {
	t.Helper()
	f := &witnessedCleanup106Fixture{DB: base.db, Policy: base.policy, Workflow: base.workflow, Spec: base.p, private: base}
	f.job = witnessedCleanup106InitialStart(t, base)
	if f.job.StartedAt == nil || f.job.LeaseExpiresAt == nil {
		t.Fatal("real original start/lease required")
	}
	ctx, cancel := context.WithDeadline(context.Background(), *f.job.LeaseExpiresAt)
	defer cancel()
	b := f.Spec.MutationBindings[0]
	pre := base.pre
	pre.PreregistrationID, pre.OriginalCreateGrantID = uuid.NewString(), uuid.NewString()
	pre.Slot = 2
	pre.BindingName = f.Spec.GuestRetirementBinding.Members[1].Name
	pre.NonceSHA256 = capacity.BusinessCreationSHA256([]byte(uuid.NewString()))
	pre.OriginalCreateRequestSHA256 = b.Slots[1].DesiredSpecSHA256
	pre.Generation, pre.Fence = base.intent.Generation+1, base.intent.FencingToken+1
	pre.LeaseOwner, pre.ExecutorID = uuid.NewString(), base.store.ExecutorID
	pre.ReservedAt = time.Now().UTC()
	step := base.step(t, "provision-original-notify")
	pre.OriginalWorkflowStepID, pre.OriginalWorkflowStepTimeoutSeconds = step.ID, step.TimeoutSeconds
	pre.OriginalWorkflowContextDeadline = *f.job.LeaseExpiresAt
	var err error
	pre.OriginalDeadline, err = capacity.GuestOriginalProvisioningDeadline(ctx, f.Spec.GuestRetirementBinding.ProfileManifest, step, pre.ReservedAt)
	if err != nil || !capacity.GuestOriginalProvisioningDeadlineMatches(pre, f.Spec.GuestRetirementBinding.ProfileManifest) || !pre.OriginalDeadline.Equal(*f.job.LeaseExpiresAt) || f.Spec.GuestRetirementBinding.ProfileManifest.OriginalProvisioningBudgetSeconds != 420 {
		t.Fatal("original clipped provisioning deadline", err)
	}
	attempt := uuid.NewString()
	birth := pre.ReservedAt.Format(time.RFC3339Nano)
	stamp := pre.ReservedAt.Add(time.Millisecond).Format(time.RFC3339Nano)
	sdk := &model.CapacityOriginalProviderCreateReturn{Schema: "hetzner_original_create_return_v1", Provider: "hetzner", AdapterSourceCommit: b.OriginalProviderSourceCommit, GrantID: pre.OriginalCreateGrantID, AttemptID: attempt, RequestSHA256: pre.OriginalCreateRequestSHA256, ResourceID: "174243512", ResourceCreatedAt: birth, ActionID: "92", NextActionIDs: []string{}, CalledAt: pre.ReservedAt.Format(time.RFC3339Nano), ReturnedAt: stamp, ContextDeadline: pre.OriginalDeadline.Format(time.RFC3339Nano), ResponseStatus: 201, ResponseBodySHA256: strings.Repeat("a", 64), ResponseBytes: 2}
	settle := model.CapacityMutationSettleRequest{GrantID: pre.OriginalCreateGrantID, AttemptID: attempt, RequestSHA256: pre.OriginalCreateRequestSHA256, Outcome: "accepted", TransportCompleted: true, ResourceID: sdk.ResourceID, ResourceCreatedAt: birth, ActionID: sdk.ActionID, NextActionIDs: []string{}, AuxiliaryResources: []model.CapacityMutationAuxiliaryResource{{Kind: "primary_ip", ID: "162672124", RequiresAbsence: true}, {Kind: "primary_ip", ID: "162672125", RequiresAbsence: true}}, AuxiliaryInventoryComplete: true, OriginalProviderCreateReturn: sdk, ObservedAt: stamp}
	grant := model.CapacityMutationGrant{GrantID: pre.OriginalCreateGrantID, BindingName: b.Name, IntegrationInstanceID: b.IntegrationInstanceID, ScopeChecksum: b.ScopeChecksum, ProfileName: b.ProfileName, Slot: 2, Capability: b.EnsureCapability, RequestSHA256: pre.OriginalCreateRequestSHA256, ExpiresAt: pre.OriginalDeadline, State: "settled"}
	f.pre = pre
	f.parent = capacityMutationRecord{Grant: grant, Binding: b, PolicyID: f.Policy.ID, PolicyChecksum: f.Policy.Checksum, WorkflowID: f.Workflow.ID, Generation: pre.Generation, FencingToken: pre.Fence, LeaseOwner: pre.LeaseOwner, ExecutorID: pre.ExecutorID, CreatedAt: pre.ReservedAt, AttemptID: attempt, Settlement: &settle, EventProvider: "hetzner", EventResource: "server"}
	f.witness, f.registration, f.receipt = capacity.RecoveryFixtureCompensationRegistration(t, f.Spec, *f.Spec.GuestRetirementBinding, pre, settle)
	f.installation = witnessedCleanup106Installation(t, f)
	base.exec(t, `INSERT INTO capacity_mutation_grants(id,namespace,environment,domain,dimension,generation,integration_instance_id,scope_checksum,profile_name,slot,state,grant_record,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,2,'settled',$10::jsonb,$11)`, grant.GrantID, f.Policy.Metadata.Namespace, f.Spec.Environment, f.Spec.Domain, f.Spec.Dimension, pre.Generation, b.IntegrationInstanceID, b.ScopeChecksum, b.ProfileName, string(failedServingWire(t, f.parent)), pre.OriginalDeadline)
	base.exec(t, `INSERT INTO capacity_vm_provisioning_preregistrations(id,create_grant_id,nonce_sha256,profile_manifest_sha256,preregistration_record,original_deadline,created_at,original_wire,binding_wire) VALUES($1,$2,$3,$4,$5::jsonb,$6,$7,$8,$9)`, pre.PreregistrationID, grant.GrantID, pre.NonceSHA256, pre.ProfileManifestSHA256, string(failedServingWire(t, pre)), pre.OriginalDeadline, pre.ReservedAt, failedServingWire(t, pre), failedServingWire(t, *f.Spec.GuestRetirementBinding))
	w := f.witness
	base.exec(t, `INSERT INTO capacity_guest_original_create_witnesses(preregistration_id,original_create_attempt_id,resource_tuple_sha256,witness_sha256,original_wire,original_record,recorded_at) VALUES($1,$2,$3,$4,$5,$6::jsonb,$7)`, pre.PreregistrationID, w.OriginalCreateAttemptID, capacity.GuestRetirementSHA(w.Tuple), capacity.GuestRetirementSHA(w), failedServingWire(t, w), string(failedServingWire(t, w)), w.ObservedAt)
	f.intent = base.intent
	f.intent.Generation, f.intent.FencingToken = pre.Generation, pre.Fence
	f.intent.Phase = "preparing"
	f.intent.LeaseOwner, f.intent.LeaseExecutorID = pre.LeaseOwner, pre.ExecutorID
	f.intent.LeaseExpiresAt = &pre.OriginalDeadline
	f.intent.BaselineSnapshot = f.intent.Assessment.Snapshot
	f.intent.Decision.Action, f.intent.Decision.Reason = "expand", "scale_up"
	f.intent.Decision.Units, f.intent.Decision.ExecutionPermitted = 2, true
	f.intent.UpdatedAt = pre.ReservedAt
	base.exec(t, `UPDATE capacity_intents SET intent=$2::jsonb WHERE namespace=$1`, f.Policy.Metadata.Namespace, string(failedServingWire(t, f.intent)))
	// The only wait uses the original immutable context captured above.
	<-ctx.Done()
	if !errors.Is(ctx.Err(), context.DeadlineExceeded) {
		t.Fatal("original context did not expire naturally")
	}
	finished := time.Now().UTC()
	r := supersededHTTPResult(t, f.job, pre.Generation, pre.Fence, pre.ReservedAt, finished)
	r.Metadata = map[string]any{}
	for k, v := range f.job.Metadata {
		r.Metadata[k] = v
	}
	r.Metadata["failed_step"] = "provision-original-notify"
	for i := range r.Steps {
		s := &r.Steps[i]
		s.Metadata = map[string]any{}
		s.Status, s.Attempts = "skipped", 0
		s.Error = `workflow aborted after step "provision-original-notify" failed`
		if i == 0 {
			s.Status, s.Attempts, s.Error = "succeeded", 1, ""
			s.Metadata = map[string]any{"mode": "prepare", "slot": 2, "generation": pre.Generation, "fencing_token": pre.Fence, "lease_owner": pre.LeaseOwner}
		}
		if i == 1 {
			s.Status, s.Attempts, s.Error = "failed", 1, "original Guest reconciliation held"
			s.Metadata = map[string]any{"original_guest_refusal_predicate": "original-guest-step-29"}
		}
	}
	if err = FinishCapacityDispatch(context.Background(), f.DB, f.job, r, finished, context.DeadlineExceeded); !errors.Is(err, ErrCapacityDispatchUnknown) {
		t.Fatal("M106 real expired Finish must retain UNKNOWN", err)
	}
	f.job, err = readCapacityDispatchJob(context.Background(), f.DB, f.job.JobID, false)
	if err != nil || f.job.State != "unknown" || f.job.FinalizationAckAt != nil {
		t.Fatal("M106 immutable UNKNOWN/noACK", err)
	}
	return f
}

func witnessedCleanup106Installation(t *testing.T, f *witnessedCleanup106Fixture) model.CapacityGuestOriginalInstallationConfirmation {
	t.Helper()
	at := f.receipt.RecordedAt.Add(time.Millisecond)
	c := model.CapacityGuestOriginalInstallationConfirmation{Schema: capacity.GuestInstallationV2Schema, PreregistrationID: f.pre.PreregistrationID, OriginalReceiptSHA256: capacity.GuestRetirementSHA(f.receipt), EnrollmentSHA256: capacity.GuestRetirementSHA(f.receipt.Enrollment), InstalledAt: at, AdmittedAt: at.Add(time.Millisecond), ProductionClock: &model.CapacityGuestProductionInstallationClockV2{Schema: capacity.GuestInstallationClockV2Schema, OriginalProvisioningClockSHA256: capacity.GuestRetirementSHA(*f.registration.Result.ProductionClock), OriginalReceiptReadStartedMonotonicNS: int64(111 * time.Second), OriginalReceiptReadReturnedMonotonicNS: int64(112 * time.Second), OriginalReceiptReadReturnedAt: at, InstalledMonotonicNS: int64(113 * time.Second), AdmittedMonotonicNS: int64(114 * time.Second), OriginalConfirmationPreparedMonotonicNS: int64(115 * time.Second)}}
	var err error
	c.Signature, err = capacity.GuestLifecycleSignature(failedServingKey('p'), c)
	if err != nil || capacity.GuestOriginalInstallationV2(f.pre, f.receipt, c, failedServingPublic(failedServingKey('p')), *f.registration.Result.ProductionClock, at.Add(2*time.Millisecond)) != nil {
		t.Fatal("declared authentic late installation operand", err)
	}
	return c
}

func witnessedCleanup106InitialStart(t *testing.T, f *failedServingFixture) CapacityDispatchJob {
	t.Helper()
	pin := func(m model.Manifest) CapacityDispatchManifestPin {
		return CapacityDispatchManifestPin{ID: m.ID, Namespace: m.Metadata.Namespace, Name: m.Metadata.Name, Version: m.Version, Checksum: m.Checksum}
	}
	rbac := CapacityDispatchManifestPin{ID: uuid.New(), Namespace: f.policy.Metadata.Namespace, Name: "failed-serving-unit-rbac", Version: 1, Checksum: capacityDispatchSHA([]byte("declared-M106-rbac"))}
	f.exec(t, `INSERT INTO manifests(id,api_version,kind,namespace,name,version,checksum,spec,active) VALUES($1,'v1','rbac',$2,$3,1,$4,'{}'::jsonb,true)`, rbac.ID, rbac.Namespace, rbac.Name, rbac.Checksum)
	e := CapacityDispatchEnvelope{Protocol: CapacityDispatchProtocol, JobID: uuid.New(), RunID: uuid.New(), Realm: f.policy.Metadata.Namespace, Environment: f.p.Environment, Domain: f.p.Domain, Dimension: f.p.Dimension, SourceTick: time.Now().UTC().Format(time.RFC3339Nano), Policy: pin(f.policy), Workflow: pin(f.workflow), RBAC: rbac, MachinePrincipalID: "capacity-controller", PrincipalSHA256: capacityDispatchSHA([]byte("declared-M106-principal")), BindingSHA256: capacityDispatchSHA([]byte("declared-M106-binding"))}
	e.Inputs = map[string]any{"policy": map[string]any{"namespace": f.policy.Metadata.Namespace, "name": f.policy.Metadata.Name}}
	e.Metadata = map[string]any{WorkflowRunCreatorMachinePrincipalMetadataKey: e.MachinePrincipalID, "triggered_by": "workflow_scheduler", "manifest_id": e.Workflow.ID.String(), "scheduled_for": e.SourceTick, "capacity_dispatch_job_id": e.JobID.String(), "capacity_dispatch_protocol": e.Protocol}
	var err error
	e.InputsSHA256, e.MetadataSHA256, err = CapacityDispatchEnvelopeHashes(e)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := f.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	j, merged, err := EnqueueCapacityDispatch(context.Background(), tx, e)
	if err != nil || merged {
		t.Fatal("actual original M106 enqueue", err, merged)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	j, err = ClaimCapacityDispatch(context.Background(), f.db, e.Realm, e.Environment, uuid.New(), 30*time.Second)
	if err != nil || j.JobID != e.JobID {
		t.Fatal("actual original M106 claim", err)
	}
	j, err = StartCapacityDispatch(context.Background(), f.db, j)
	if err != nil {
		t.Fatal(err)
	}
	return j
}

func witnessedCleanup106Originals(t *testing.T, f *witnessedCleanup106Fixture) []byte {
	t.Helper()
	var raw []byte
	err := f.DB.QueryRow(`SELECT jsonb_build_object('job',to_jsonb(j),'run',to_jsonb(w),'parent',to_jsonb(g),'preregistration',to_jsonb(p),'witness',to_jsonb(c),'S1',(SELECT to_jsonb(s) FROM capacity_resource_slots s WHERE namespace=$2 AND slot=1))::text FROM capacity_dispatch_jobs j JOIN workflow_runs w ON w.id=j.run_id JOIN capacity_mutation_grants g ON g.id=$3 JOIN capacity_vm_provisioning_preregistrations p ON p.create_grant_id=g.id JOIN capacity_guest_original_create_witnesses c ON c.preregistration_id=p.id WHERE j.id=$1`, f.job.JobID, f.Policy.Metadata.Namespace, f.pre.OriginalCreateGrantID).Scan(&raw)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func witnessedCleanup106Rows(t *testing.T, db *sql.DB) map[string][]json.RawMessage {
	t.Helper()
	rows := supersededHTTPBaseRows(t, db)
	for _, table := range []string{"workflow_runs", "capacity_dispatch_jobs", "capacity_dispatch_wakes", "capacity_guest_authority_issues", "capacity_guest_notify_canary_challenges", "capacity_guest_notify_canary_nonces", "capacity_guest_notify_canary_sends", "capacity_guest_notify_canary_returns"} {
		var raw []byte
		if err := db.QueryRow(`SELECT COALESCE(jsonb_agg(to_jsonb(t)),'[]'::jsonb)::text FROM public.` + pq.QuoteIdentifier(table) + ` t`).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		var values []json.RawMessage
		if json.Unmarshal(raw, &values) != nil {
			t.Fatal("whole declared source rows", table)
		}
		rows[table] = values
	}
	return rows
}

func witnessedCleanup106Clone(t *testing.T, f *witnessedCleanup106Fixture, migrations string) *witnessedCleanup106Fixture {
	t.Helper()
	db := failedServingDB(t)
	if err := goose.UpToContext(context.Background(), db, migrations, 105); err != nil {
		t.Fatal(err)
	}
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	tables := append(append([]string(nil), supersededHTTPBaseTables...), "workflow_runs", "capacity_dispatch_jobs", "capacity_dispatch_wakes", "capacity_guest_authority_issues", "capacity_guest_notify_canary_challenges", "capacity_guest_notify_canary_nonces", "capacity_guest_notify_canary_sends", "capacity_guest_notify_canary_returns")
	for _, table := range tables {
		for _, raw := range f.base[table] {
			if _, err = tx.Exec(`INSERT INTO public.`+pq.QuoteIdentifier(table)+` SELECT (jsonb_populate_record(NULL::public.`+pq.QuoteIdentifier(table)+`,$1::jsonb)).*`, string(raw)); err != nil {
				t.Fatal("declared immutable clone before M106 Up", table, err)
			}
		}
	}
	if _, err = tx.Exec(`SELECT setval(pg_get_serial_sequence('capacity_intent_events','id'),COALESCE((SELECT max(id) FROM capacity_intent_events),1),EXISTS(SELECT 1 FROM capacity_intent_events))`); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err = goose.UpToContext(context.Background(), db, migrations, 106); err != nil {
		t.Fatal(err)
	}
	out := *f
	out.DB = db
	clone := *f.private
	clone.db = db
	out.private = &clone
	return &out
}

func witnessedCleanup106LateInsert(t *testing.T, f *witnessedCleanup106Fixture, kind string) (string, []any) {
	t.Helper()
	if kind == "enrollment" {
		return `INSERT INTO capacity_vm_original_enrollments(preregistration_id,resource_tuple_sha256,enrollment_sha256,original_provisioning_sha256,enrollment_record,recorded_at,registration_wire,receipt_wire) VALUES($1,$2,$3,$4,$5::jsonb,$6,$7,$8)`, []any{f.pre.PreregistrationID, capacity.GuestRetirementSHA(f.receipt.Enrollment.Statement.Tuple), capacity.GuestRetirementSHA(f.receipt.Enrollment), f.receipt.OriginalProvisioningSHA256, string(failedServingWire(t, f.receipt.Enrollment)), f.receipt.RecordedAt, failedServingWire(t, f.registration), failedServingWire(t, f.receipt)}
	}
	if kind == "installation" {
		return `INSERT INTO capacity_guest_original_installations(preregistration_id,original_wire,confirmation_sha256,recorded_at) VALUES($1,$2,$3,$4)`, []any{f.pre.PreregistrationID, failedServingWire(t, f.installation), capacity.GuestRetirementSHA(f.installation), f.installation.AdmittedAt}
	}
	t.Fatal("closed callback kind")
	return "", nil
}

func witnessedCleanup106PeerDB(t *testing.T, db *sql.DB) *sql.DB {
	t.Helper()
	var name string
	if err := db.QueryRow(`SELECT current_database()`).Scan(&name); err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(os.Getenv("FAILED_SERVING_FIXTURE_ADMIN_URL"))
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + name
	peer, err := sql.Open("postgres", u.String())
	if err != nil {
		t.Fatal(err)
	}
	peer.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = peer.Close() })
	return peer
}

func witnessedCleanup106AdmissionNegatives(t *testing.T, f *witnessedCleanup106Fixture, put func(string, []byte)) {
	t.Helper()
	original := witnessedCleanup106Originals(t, f)
	store := CapacityStore{DB: f.DB}
	for _, ids := range [][2]string{{uuid.NewString(), f.job.JobID.String()}, {f.pre.OriginalCreateGrantID, uuid.NewString()}} {
		if _, err := store.RequestWitnessedUnenrolledExpansionCleanup(context.Background(), ids[0], ids[1], "collaborator:"+uuid.NewString()); err == nil {
			t.Fatal("foreign identity admitted")
		}
	}
	// Both enrollment and installation are authentic signed DECLARED historical
	// rows. The direct production eligibility seam must see each same-tx fault;
	// rolled-back faults never replace an archived original or fake an ACK.
	for _, kind := range []string{"enrollment", "installation"} {
		tx, err := f.DB.Begin()
		if err != nil {
			t.Fatal(err)
		}
		if kind == "installation" {
			q, a := witnessedCleanup106LateInsert(t, f, "enrollment")
			if _, err = tx.Exec(q, a...); err != nil {
				_ = tx.Rollback()
				t.Fatal("authentic enrollment prerequisite", err)
			}
		}
		q, a := witnessedCleanup106LateInsert(t, f, kind)
		if _, err = tx.Exec(q, a...); err != nil {
			_ = tx.Rollback()
			t.Fatal("declared callback must reach eligibility", kind, err)
		}
		_, err = store.witnessedExpansionSnapshotTx(context.Background(), tx, f.pre.OriginalCreateGrantID, f.job.JobID.String())
		if err == nil {
			_ = tx.Rollback()
			t.Fatal("enrolled/installed failed tail admitted", kind)
		}
		if err = tx.Rollback(); err != nil {
			t.Fatal(err)
		}
	}
	if !bytes.Equal(original, witnessedCleanup106Originals(t, f)) {
		t.Fatal("refusal changed originals")
	}
	put("M106-ADMISSION-NEGATIVES.PUBLIC.json", failedServingWire(t, map[string]any{"schema": "witnessed_cleanup106_admission_refusals_v1", "foreign_grant_refused": true, "foreign_job_refused": true, "authentic_enrollment_refused": true, "authentic_installation_refused": true, "rolled_back_originals_exact": true, "fixture_only": true}))
}

func witnessedCleanup106CallbackRace(t *testing.T, f *witnessedCleanup106Fixture, kind string, writerFirst bool, put func(string, []byte)) {
	t.Helper()
	ctx, stop := context.WithTimeout(context.Background(), 10*time.Second)
	defer stop()
	// Writer-first installation has its authentic enrollment prerequisite. In
	// admission-first order the same signed installation is ONLY a declared raw
	// storage attempt: it must be refused by M106, never claimed as Guest success.
	if kind == "installation" && writerFirst {
		q, a := witnessedCleanup106LateInsert(t, f, "enrollment")
		if _, err := f.DB.ExecContext(ctx, q, a...); err != nil {
			t.Fatal(err)
		}
	}
	q, args := witnessedCleanup106LateInsert(t, f, kind)
	peer := witnessedCleanup106PeerDB(t, f.DB)
	var pid int
	if err := peer.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
		t.Fatal(err)
	}
	if writerFirst {
		tx, err := peer.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		if _, err = tx.ExecContext(ctx, q, args...); err != nil {
			t.Fatal("authentic first callback", kind, err)
		}
		result := make(chan error, 1)
		go func() {
			_, e := (CapacityStore{DB: f.DB}).RequestWitnessedUnenrolledExpansionCleanup(ctx, f.pre.OriginalCreateGrantID, f.job.JobID.String(), "collaborator:"+uuid.NewString())
			result <- e
		}()
		nonceAcquire105WaitBlocked(t, ctx, f.DB, 0, pid)
		if err = tx.Commit(); err != nil {
			t.Fatal(err)
		}
		if err = <-result; err == nil {
			t.Fatal("committed callback ignored", kind)
		}
	} else {
		// Force the real Request transaction to own the scope lock, then wait on
		// its events INSERT. No production callback or lock seam is replaced.
		holder, err := f.DB.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer holder.Rollback()
		if _, err = holder.ExecContext(ctx, `LOCK TABLE capacity_witnessed_unenrolled_expansion_cleanup_events IN SHARE MODE`); err != nil {
			t.Fatal(err)
		}
		operator := witnessedCleanup106PeerDB(t, f.DB)
		var opPID int
		if err = operator.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&opPID); err != nil {
			t.Fatal(err)
		}
		admitted := make(chan error, 1)
		written := make(chan error, 1)
		go func() {
			_, e := (CapacityStore{DB: operator}).RequestWitnessedUnenrolledExpansionCleanup(ctx, f.pre.OriginalCreateGrantID, f.job.JobID.String(), "collaborator:"+uuid.NewString())
			admitted <- e
		}()
		nonceAcquire105WaitBlocked(t, ctx, f.DB, opPID, 0)
		go func() { _, e := peer.ExecContext(ctx, q, args...); written <- e }()
		nonceAcquire105WaitBlocked(t, ctx, f.DB, pid, opPID)
		if err = holder.Commit(); err != nil {
			t.Fatal(err)
		}
		if err = <-admitted; err != nil {
			t.Fatal("first admission", err)
		}
		var pg *pq.Error
		if err = <-written; !errors.As(err, &pg) || pg.Code != "P0001" || pg.Message != "witnessed unenrolled expansion callback is permanently closed" {
			t.Fatal("late callback escaped permanent closure", kind, err)
		}
	}
	put("M106-CALLBACK-RACE-"+strings.ToUpper(kind)+map[bool]string{true: "-WRITER-FIRST", false: "-ADMISSION-FIRST"}[writerFirst]+".PUBLIC.json", failedServingWire(t, map[string]any{"schema": "witnessed_cleanup106_backend_callback_race_v1", "kind": kind, "writer_first": writerFirst, "installation_storage_operand_declared": kind == "installation", "installation_existing_enrollment": kind == "installation" && writerFirst, "actual_blocking_observed": true, "original_ACK_unchanged": true, "fixture_only": true}))
}

func witnessedCleanup106TwoRequesters(t *testing.T, f *witnessedCleanup106Fixture, put func(string, []byte)) {
	t.Helper()
	ctx, stop := context.WithTimeout(context.Background(), 10*time.Second)
	defer stop()
	var wg sync.WaitGroup
	type answer struct {
		a   WitnessedUnenrolledExpansionCleanup
		err error
	}
	answers := make(chan answer, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a, e := (CapacityStore{DB: f.DB}).RequestWitnessedUnenrolledExpansionCleanup(ctx, f.pre.OriginalCreateGrantID, f.job.JobID.String(), "collaborator:"+uuid.NewString())
			answers <- answer{a, e}
		}()
	}
	wg.Wait()
	close(answers)
	success, conflict := 0, 0
	for a := range answers {
		if a.err == nil {
			success++
			if a.a.ChildGrantID == a.a.GrantID || a.a.Slot != 2 || a.a.SurvivorCount != 1 {
				t.Fatal("separate child/floor", a.a)
			}
		} else if errors.Is(a.err, ErrCapacityConflict) {
			conflict++
		} else {
			t.Fatal(a.err)
		}
	}
	if success != 1 || conflict != 1 {
		t.Fatal("two real requesters", success, conflict)
	}
	var admissions, events, children int
	if err := f.DB.QueryRow(`SELECT (SELECT count(*) FROM capacity_witnessed_unenrolled_expansion_cleanups),(SELECT count(*) FROM capacity_witnessed_unenrolled_expansion_cleanup_events),(SELECT count(*) FROM capacity_mutation_grants WHERE grant_record ? 'witnessed_unenrolled_expansion_cleanup_id')`).Scan(&admissions, &events, &children); err != nil || admissions != 1 || events != 1 || children != 0 {
		t.Fatal("one requested admission only", err, admissions, events, children)
	}
	put("M106-TWO-REQUESTERS.PUBLIC.json", failedServingWire(t, map[string]any{"schema": "witnessed_cleanup106_two_real_requesters_v1", "admitted": success, "conflicts": conflict, "admissions": admissions, "events": events, "child_grants": children, "provider_calls": 0, "fixture_only": true}))
}

func witnessedCleanup106Immutable(t *testing.T, f *witnessedCleanup106Fixture, a WitnessedUnenrolledExpansionCleanup) {
	t.Helper()
	for _, q := range []string{`UPDATE capacity_witnessed_unenrolled_expansion_cleanups SET recorded_at=recorded_at+interval '1 microsecond' WHERE id=$1`, `DELETE FROM capacity_witnessed_unenrolled_expansion_cleanups WHERE id=$1`, `UPDATE capacity_witnessed_unenrolled_expansion_cleanup_events SET stage='terminal' WHERE cleanup_id=$1`, `DELETE FROM capacity_witnessed_unenrolled_expansion_cleanup_events WHERE cleanup_id=$1`} {
		_, err := f.DB.Exec(q, a.ID)
		var pg *pq.Error
		if !errors.As(err, &pg) || pg.Code != "P0001" || !strings.Contains(pg.Message, "immutable") {
			t.Fatal("immutable106 trigger required", err)
		}
	}
	// A known admission UUID and reserved child ID in arbitrary JSON do not
	// establish the private claim/read/floor chain or earn an index exemption.
	bad := f.parent
	bad.WitnessedUnenrolledExpansionCleanupID = a.ID
	bad.AttemptID = ""
	bad.Settlement = nil
	bad.Proof = nil
	bad.CreatedAt = time.Now().UTC()
	bad.Grant = model.CapacityMutationGrant{GrantID: a.ChildGrantID, BindingName: bad.Binding.Name, IntegrationInstanceID: bad.Binding.IntegrationInstanceID, ScopeChecksum: bad.Binding.ScopeChecksum, ProfileName: bad.Binding.ProfileName, Slot: 2, Capability: bad.Binding.DestroyCapability, ExpectedResourceID: a.ResourceID, ExpectedResourceCreatedAt: a.ResourceCreatedAt, RequestSHA256: strings.Repeat("f", 64), State: "issued", ExpiresAt: bad.CreatedAt.Add(5 * time.Second)}
	_, err := f.DB.Exec(`INSERT INTO capacity_mutation_grants(id,namespace,environment,domain,dimension,generation,integration_instance_id,scope_checksum,profile_name,slot,state,grant_record,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,2,'issued',$10::jsonb,$11)`, a.ChildGrantID, a.Namespace, a.Environment, a.Domain, a.Dimension, a.OriginalGeneration, bad.Binding.IntegrationInstanceID, bad.Binding.ScopeChecksum, bad.Binding.ProfileName, string(failedServingWire(t, bad)), bad.Grant.ExpiresAt)
	var pg *pq.Error
	if !errors.As(err, &pg) || pg.Code != "P0001" {
		t.Fatal("JSON marker spoof must reach independent M106 claim guard", err)
	}
}

func witnessedCleanup106Catalog(t *testing.T, db *sql.DB, before, after []byte, put func(string, []byte)) {
	t.Helper()
	var b, a map[string]json.RawMessage
	if json.Unmarshal(before, &b) != nil || json.Unmarshal(after, &a) != nil {
		t.Fatal("whole actual106 catalogs")
	}
	if len(b) != len(a) || !bytes.Equal(b["server_version_num"], a["server_version_num"]) {
		t.Fatal("complete same-PG catalogs required")
	}
	var bh, ah string
	var oldHistory, newHistory []map[string]any
	if json.Unmarshal(b["history_wire"], &bh) != nil || json.Unmarshal(a["history_wire"], &ah) != nil || json.Unmarshal([]byte(bh), &oldHistory) != nil || json.Unmarshal([]byte(ah), &newHistory) != nil || len(newHistory) != len(oldHistory)+1 || !reflect.DeepEqual(oldHistory, newHistory[:len(oldHistory)]) || oldHistory[len(oldHistory)-1]["version_id"] != float64(105) || newHistory[len(oldHistory)]["version_id"] != float64(106) || newHistory[len(oldHistory)]["is_applied"] != true {
		t.Fatal("sole actual106 whole-history append")
	}
	var priorFunctions, nextFunctions []map[string]any
	if json.Unmarshal(b["functions"], &priorFunctions) != nil || json.Unmarshal(a["functions"], &nextFunctions) != nil {
		t.Fatal("whole function catalogs")
	}
	key := func(v map[string]any) string { return v["name"].(string) + "(" + v["arguments"].(string) + ")" }
	by := map[string]map[string]any{}
	for _, v := range nextFunctions {
		by[key(v)] = v
	}
	changed, added := []string{}, []string{}
	for _, v := range priorFunctions {
		next, ok := by[key(v)]
		if !ok {
			t.Fatal("removed historical function", key(v))
		}
		if !reflect.DeepEqual(v, next) {
			changed = append(changed, v["name"].(string))
		}
		delete(by, key(v))
	}
	for _, v := range by {
		added = append(added, v["name"].(string))
	}
	sort.Strings(added)
	sort.Strings(changed)
	want := []string{"guard_witnessed_expansion_callback106", "guard_witnessed_expansion_dispatch_ownership106", "guard_witnessed_expansion_job_insert106", "guard_witnessed_expansion_workflow106", "guard_witnessed_unenrolled_expansion_cleanup", "guard_witnessed_unenrolled_expansion_cleanup_event", "guard_witnessed_unenrolled_expansion_cleanup_grant", "guard_witnessed_unenrolled_expansion_cleanup_intent", "immutable_witnessed_unenrolled_expansion_cleanup", "initialize_witnessed_expansion_dispatch106", "require_witnessed_expansion_dispatch_ownership106", "require_witnessed_expansion_links106", "witnessed_expansion_absence_read_valid106", "witnessed_expansion_dispatch_marker_present106", "witnessed_unenrolled_expansion_parent_valid106", "witnessed_unenrolled_expansion_terminal_valid106"}
	sort.Strings(want)
	if !reflect.DeepEqual(added, want) || !reflect.DeepEqual(changed, []string{"guard_capacity_dispatch_job", "retirement_forward_continuation_quiet"}) {
		t.Fatal("exact M106 additive/legacy function delta", added, changed)
	}
	// Each whole retained row is compared, not just its name or deparse body.
	// Only the explicitly versioned state/lifecycle CHECKs and physical indexes
	// can replace old rows; every historical table column and trigger stays exact.
	newTables := map[string]int{"capacity_witnessed_unenrolled_expansion_cleanups": 16, "capacity_witnessed_unenrolled_expansion_cleanup_events": 9, "capacity_witnessed_unenrolled_expansion_dispatch_ownership": 4}
	for _, field := range []string{"columns", "constraints", "triggers", "indexes"} {
		var old, next []map[string]any
		if json.Unmarshal(b[field], &old) != nil || json.Unmarshal(a[field], &next) != nil {
			t.Fatal(field)
		}
		id := func(v map[string]any) string { return v["table"].(string) + "/" + v["name"].(string) }
		rows := map[string]map[string]any{}
		for _, v := range next {
			rows[id(v)] = v
		}
		for _, v := range old {
			k := id(v)
			n, ok := rows[k]
			allowed := field == "constraints" && (k == "capacity_mutation_grants/capacity_mutation_grants_state_check" || k == "capacity_dispatch_jobs/capacity_dispatch_jobs_state_v12_check" || k == "capacity_dispatch_jobs/capacity_dispatch_jobs_lifecycle_v12_check") || field == "indexes" && (k == "capacity_dispatch_jobs/capacity_dispatch_active_scope_idx" || k == "capacity_mutation_grants/capacity_mutation_grants_open_slot_idx")
			if !allowed && (!ok || !reflect.DeepEqual(v, n)) {
				t.Fatal("changed unrelated whole historical catalog row", field, k)
			}
			delete(rows, k)
		}
		counts := map[string]int{}
		for k, v := range rows {
			table := v["table"].(string)
			_, newTable := newTables[table]
			if field == "columns" {
				if !newTable || v["default"] != nil || v["identity"] != "" || v["generated"] != "" {
					t.Fatal("unexpected/default/generated column", k)
				}
				counts[table]++
			}
			if field == "constraints" && !newTable && k != "capacity_dispatch_jobs/capacity_dispatch_jobs_state_v13_check" && k != "capacity_dispatch_jobs/capacity_dispatch_jobs_lifecycle_v13_check" {
				t.Fatal("extra constraint", k)
			}
			if field == "indexes" {
				if v["valid"] != true || v["ready"] != true {
					t.Fatal("invalid index", k)
				}
				if !newTable && k != "capacity_dispatch_jobs/capacity_witnessed_expansion_active_scope106_idx" {
					t.Fatal("extra index", k)
				}
			}
			if field == "triggers" && !strings.HasSuffix(v["name"].(string), "106") {
				t.Fatal("unexpected trigger", k)
			}
		}
		if field == "columns" && !reflect.DeepEqual(counts, newTables) {
			t.Fatal("exact new16+9+4 columns", counts)
		}
	}
	var version int64
	if err := db.QueryRow(`SELECT max(version_id) FROM goose_db_version WHERE is_applied`).Scan(&version); err != nil || version != 106 {
		t.Fatal("current106", version, err)
	}
	var indexesLive bool
	if err := db.QueryRow(`SELECT count(*)=3 AND bool_and(i.indisvalid AND i.indisready AND i.indislive AND i.indisunique) FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname IN('capacity_dispatch_active_scope_idx','capacity_witnessed_expansion_active_scope106_idx','capacity_mutation_grants_open_slot_idx')`).Scan(&indexesLive); err != nil || !indexesLive {
		t.Fatal("exact three valid/ready/live physical uniqueness guards", err)
	}
	var ddl []byte
	if err := db.QueryRow(`SELECT jsonb_build_object('functions',(SELECT jsonb_agg(jsonb_build_object('name',p.proname,'arguments',pg_get_function_identity_arguments(p.oid),'definition',pg_get_functiondef(p.oid)) ORDER BY p.proname,pg_get_function_identity_arguments(p.oid)) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public' AND p.proname LIKE '%witnessed%'),'constraints',(SELECT jsonb_agg(jsonb_build_object('table',r.relname,'name',c.conname,'definition',pg_get_constraintdef(c.oid,false),'validated',c.convalidated) ORDER BY r.relname,c.conname) FROM pg_constraint c JOIN pg_class r ON r.oid=c.conrelid WHERE r.relname LIKE 'capacity_witnessed%'),'indexes',(SELECT jsonb_agg(jsonb_build_object('table',r.relname,'name',c.relname,'definition',pg_get_indexdef(x.indexrelid),'valid',x.indisvalid,'ready',x.indisready) ORDER BY r.relname,c.relname) FROM pg_index x JOIN pg_class r ON r.oid=x.indrelid JOIN pg_class c ON c.oid=x.indexrelid WHERE r.relname IN('capacity_witnessed_unenrolled_expansion_cleanups','capacity_witnessed_unenrolled_expansion_cleanup_events','capacity_dispatch_jobs')))::text`).Scan(&ddl); err != nil {
		t.Fatal(err)
	}
	put("M106-PG-CHECK-DEPARSE.RESULT.PUBLIC.json", failedServingWire(t, map[string]any{"schema": "witnessed_cleanup106_actual_pg_catalog_v1", "version": version, "before105_sha256": capacity.BusinessCreationSHA256(before), "after106_sha256": capacity.BusinessCreationSHA256(after), "functions_added": added, "functions_changed": changed, "new_table_columns": newTables, "all_retained_catalog_rows_exact_except_explicit106_replacements": true, "sole_history_append": true, "actual_deparse": json.RawMessage(ddl), "fixture_only": true}))
}

func witnessedCleanup106Down(t *testing.T, db *sql.DB, migrations string, put func(string, []byte)) {
	t.Helper()
	before := installedReadinessCatalog(t, db)
	err := goose.DownContext(context.Background(), db, migrations)
	if err == nil || !strings.Contains(err.Error(), "used witnessed unenrolled expansion cleanup is permanent provenance") {
		t.Fatal("used106 Down must refuse", err)
	}
	if !bytes.Equal(before, installedReadinessCatalog(t, db)) {
		t.Fatal("used Down changed whole catalog/history")
	}
	put("M106-USED-DOWN-REFUSAL.PUBLIC.json", failedServingWire(t, map[string]any{"schema": "witnessed_cleanup106_used_down_refusal_v1", "whole_catalog_and_history_unchanged": true, "fixture_only": true}))
}

func witnessedCleanup106EmptyDown(t *testing.T, migrations string, put func(string, []byte)) {
	t.Helper()
	db := failedServingDB(t)
	if err := goose.UpToContext(context.Background(), db, migrations, 105); err != nil {
		t.Fatal(err)
	}
	before := installedReadinessCatalog(t, db)
	if err := goose.UpToContext(context.Background(), db, migrations, 106); err != nil {
		t.Fatal(err)
	}
	if err := goose.DownContext(context.Background(), db, migrations); err != nil {
		t.Fatal("unused106 Down", err)
	}
	after := installedReadinessCatalog(t, db)
	var b, a map[string]json.RawMessage
	if json.Unmarshal(before, &b) != nil || json.Unmarshal(after, &a) != nil {
		t.Fatal("unused Down catalog")
	}
	delete(b, "history_wire")
	delete(a, "history_wire")
	if !reflect.DeepEqual(b, a) {
		t.Fatal("unused106 Down did not restore whole105 schema")
	}
	var version int64
	if err := db.QueryRow(`SELECT max(version_id) FROM goose_db_version WHERE is_applied`).Scan(&version); err != nil || version != 105 {
		t.Fatal("unused Down history", version, err)
	}
	put("M106-EMPTY-DOWN-BEFORE105.original.json", before)
	put("M106-EMPTY-DOWN-AFTER105.original.json", after)
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
}

func witnessedCleanup106Canaries(t *testing.T, f *witnessedCleanup106Fixture, store CapacityStore, current model.CapacityIntent, usage string) {
	t.Helper()
	waitCtx, stopWait := context.WithTimeout(context.Background(), 7*time.Second)
	delay, err := store.WitnessedExpansionPublicationDelay(waitCtx, f.Policy, f.private.pre.PreregistrationID)
	if err != nil || delay > 6*time.Second {
		stopWait()
		t.Fatal("actual bounded PG publication gap", delay, err)
	}
	if delay > 0 {
		timer := time.NewTimer(delay + time.Millisecond)
		select {
		case <-waitCtx.Done():
			timer.Stop()
			stopWait()
			t.Fatal("original PG gap wait", waitCtx.Err())
		case <-timer.C:
		}
	}
	stopWait()
	ctx, stop := context.WithTimeout(context.Background(), 4*time.Second)
	defer stop()
	key := failedServingKey('c')
	e := f.private.receipt.Enrollment
	members, err := store.GuestNotifyFloorMembers(ctx, f.Policy, current.Generation, current.FencingToken, current.LeaseOwner, 2)
	if err != nil || len(members) != 1 || members[0].Slot != 1 {
		t.Fatal("actual onlyS1 floor selection with desiredN2 retained", members, err)
	}
	probe := func(c model.CapacityGuestNotifyCanaryChallenge, pub *capacity.GuestNotifyPublicationReply) *capacity.GuestNotifyPublicationReply {
		c = capacity.RecoveryFixtureCanaryNonce(t, c, e)
		at := time.Now().UTC()
		nonceReturn := cleanupNativeHTTP(t, c.GuestNonce, at)
		if err := store.FinalizeGuestNotifyCanaryNonce(ctx, f.Policy, current.Generation, current.FencingToken, current.LeaseOwner, c, nonceReturn); err != nil {
			t.Fatal(err)
		}
		if err := store.ReserveGuestNotifyCanarySend(ctx, f.Policy, current.Generation, current.FencingToken, current.LeaseOwner, c); err != nil {
			t.Fatal(err)
		}
		response, facts := capacity.RecoveryFixtureCanaryResponse(t, f.Spec, c, e, pub)
		returned := cleanupNativeHTTP(t, response, response.OriginalReadStartedAt.Add(-time.Millisecond))
		time.Sleep(max(0, time.Until(returned.DriverReturnedAt)) + time.Millisecond)
		if _, err := store.RecordGuestNotifyCanaryReturn(ctx, f.Policy, current.Generation, current.FencingToken, current.LeaseOwner, c, returned); err != nil {
			t.Fatal("real source-owned survivor return", err)
		}
		return facts
	}
	pub, err := store.IssueGuestNotifyCanaryPublication(ctx, f.Policy, current.Generation, current.FencingToken, current.LeaseOwner, members[0].PreregistrationID, usage, key)
	if err != nil {
		t.Fatal(err)
	}
	facts := probe(pub, nil)
	read, err := store.IssueGuestNotifyCanaryRead(ctx, f.Policy, current.Generation, current.FencingToken, current.LeaseOwner, members[0].PreregistrationID, usage, pub.ChallengeID, key)
	if err != nil {
		t.Fatal(err)
	}
	probe(read, facts)
}

func witnessedCleanup106Start(t *testing.T, f *witnessedCleanup106Fixture) CapacityDispatchJob {
	t.Helper()
	e := witnessedCleanup106Next(t, f)
	// A caller cannot supply its own reserved selector, even if its UUID is real.
	spoof := e
	spoof.WitnessedUnenrolledExpansionCleanupID = uuid.NewString()
	tx, err := f.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = EnqueueCapacityDispatch(context.Background(), tx, spoof)
	_ = tx.Rollback()
	if !errors.Is(err, ErrCapacityDispatchEnvelope) {
		t.Fatal("caller marker reached admission", err)
	}
	tx, err = f.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	j, merged, err := EnqueueCapacityDispatch(context.Background(), tx, e)
	if err != nil || merged || j.JobID != e.JobID || j.WitnessedUnenrolledExpansionCleanupID == "" {
		t.Fatal("new typed successor requires internally derived marker", err, merged, j)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	j, err = ClaimCapacityDispatch(context.Background(), f.DB, e.Realm, e.Environment, uuid.New(), 30*time.Second)
	if err != nil || j.JobID != e.JobID {
		t.Fatal("real child dispatch claim", err, j)
	}
	j, err = StartCapacityDispatch(context.Background(), f.DB, j)
	if err != nil {
		t.Fatal(err)
	}
	f.private.store.OriginalRunID = j.RunID
	f.private.store.ExecutorID = uuid.NewString()
	return j
}

func witnessedCleanup106Next(t *testing.T, f *witnessedCleanup106Fixture) CapacityDispatchEnvelope {
	t.Helper()
	e := f.job.CapacityDispatchEnvelope
	e.JobID, e.RunID = uuid.New(), uuid.New()
	e.WitnessedUnenrolledExpansionCleanupID = ""
	e.SourceTick = time.Now().UTC().Format(time.RFC3339Nano)
	e.Metadata = map[string]any{}
	for k, v := range f.job.Metadata {
		e.Metadata[k] = v
	}
	e.Metadata["scheduled_for"], e.Metadata["capacity_dispatch_job_id"] = e.SourceTick, e.JobID.String()
	var err error
	e.InputsSHA256, e.MetadataSHA256, err = CapacityDispatchEnvelopeHashes(e)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// Direct storage operands below test independent SQL guards, never a public
// marker-supplying caller. The positive Native lane uses only public Enqueue.
func witnessedCleanup106InsertDispatch(t *testing.T, ctx context.Context, tx *sql.Tx, e CapacityDispatchEnvelope) error {
	t.Helper()
	raw, err := encodeCapacityDispatchEnvelope(e)
	if err != nil {
		return err
	}
	v := e.Workflow.Version
	if err = InsertWorkflowRunTx(ctx, tx, e.RunID, model.ManifestSelector{Namespace: e.Workflow.Namespace, Name: e.Workflow.Name, Version: &v}, e.Inputs, e.Metadata); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO capacity_dispatch_jobs(id,run_id,protocol,realm,environment,domain,dimension,source_tick,envelope,envelope_sha256) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, e.JobID, e.RunID, e.Protocol, e.Realm, e.Environment, e.Domain, e.Dimension, e.SourceTick, string(raw), capacityDispatchSHA(raw))
	return err
}

func witnessedCleanup106RepeatableRead(t *testing.T, f *witnessedCleanup106Fixture, migrations string, put func(string, []byte)) {
	t.Helper()
	ctx, stop := context.WithTimeout(context.Background(), 10*time.Second)
	defer stop()
	// A snapshot taken before real admission must not authorize an ordinary
	// INSERT after admission has changed the existing capacity_intents row.
	r := witnessedCleanup106Clone(t, f, migrations)
	stale, err := r.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	var snapshot string
	if err = stale.QueryRowContext(ctx, `SELECT intent::text FROM capacity_intents WHERE namespace=$1`, r.Policy.Metadata.Namespace).Scan(&snapshot); err != nil {
		t.Fatal(err)
	}
	a, err := (CapacityStore{DB: r.DB}).RequestWitnessedUnenrolledExpansionCleanup(ctx, r.pre.OriginalCreateGrantID, r.job.JobID.String(), "collaborator:"+uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = EnqueueCapacityDispatch(ctx, stale, witnessedCleanup106Next(t, r))
	var pg *pq.Error
	if !errors.As(err, &pg) || pg.Code != "40001" {
		_ = stale.Rollback()
		t.Fatal("stale pre-admission RR must serialize", err)
	}
	_ = stale.Rollback()
	if err = r.DB.Close(); err != nil {
		t.Fatal(err)
	}
	// Two RR storage transactions see the SAME existing ownership revision.
	// The first complete INSERT commits its real ownership CAS; the second
	// must abort 40001, not rely on a snapshot that cannot see the first child.
	r = witnessedCleanup106Clone(t, f, migrations)
	a, err = (CapacityStore{DB: r.DB}).RequestWitnessedUnenrolledExpansionCleanup(ctx, r.pre.OriginalCreateGrantID, r.job.JobID.String(), "collaborator:"+uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	first, err := r.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	defer first.Rollback()
	second, err := r.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	defer second.Rollback()
	for _, tx := range []*sql.Tx{first, second} {
		var revision int
		if err = tx.QueryRowContext(ctx, `SELECT revision FROM capacity_witnessed_unenrolled_expansion_dispatch_ownership WHERE cleanup_id=$1`, a.ID).Scan(&revision); err != nil || revision != 0 {
			t.Fatal("same pre-child RR ownership", revision, err)
		}
	}
	e := witnessedCleanup106Next(t, r)
	e.WitnessedUnenrolledExpansionCleanupID = a.ID
	if err = witnessedCleanup106InsertDispatch(t, ctx, first, e); err != nil {
		t.Fatal("first canonical typed storage INSERT", err)
	}
	if err = first.Commit(); err != nil {
		t.Fatal(err)
	}
	e = witnessedCleanup106Next(t, r)
	e.WitnessedUnenrolledExpansionCleanupID = a.ID
	err = witnessedCleanup106InsertDispatch(t, ctx, second, e)
	if !errors.As(err, &pg) || pg.Code != "40001" {
		_ = second.Rollback()
		t.Fatal("stale ownership RR must serialize", err)
	}
	_ = second.Rollback()
	if err = r.DB.Close(); err != nil {
		t.Fatal(err)
	}
	put("M106-REPEATABLE-READ-OWNERSHIP.PUBLIC.json", failedServingWire(t, map[string]any{"schema": "witnessed_cleanup106_real_repeatable_read_v1", "pre_admission_snapshot_then_admission_40001": true, "same_ownership_snapshot_then_first_child_CAS_40001": true, "legacy_UNKNOWN_index_not_bypassed": true, "fixture_only": true}))
}

func witnessedCleanup106ClaimLockOrder(t *testing.T, f *witnessedCleanup106Fixture, migrations string, put func(string, []byte)) {
	t.Helper()
	r := witnessedCleanup106Clone(t, f, migrations)
	ctx, stop := context.WithTimeout(context.Background(), 7*time.Second)
	defer stop()
	a, err := (CapacityStore{DB: r.DB}).RequestWitnessedUnenrolledExpansionCleanup(ctx, r.pre.OriginalCreateGrantID, r.job.JobID.String(), "collaborator:"+uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	e := witnessedCleanup106Next(t, r)
	tx, err := r.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	queued, merged, err := EnqueueCapacityDispatch(ctx, tx, e)
	if err != nil || merged || queued.WitnessedUnenrolledExpansionCleanupID != a.ID {
		_ = tx.Rollback()
		t.Fatal(err, merged)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	// The holder represents Enqueue's existing Scope -> job order. Genuine
	// Claim/Start must finish while Scope is held: they already own the job row
	// and an unchanged busy identity must never try to acquire Scope afterwards.
	holder, err := r.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Rollback()
	if err = lockMutationScope(ctx, holder, r.Policy.Metadata.Namespace, r.Spec); err != nil {
		t.Fatal(err)
	}
	j, err := ClaimCapacityDispatch(ctx, r.DB, e.Realm, e.Environment, uuid.New(), 30*time.Second)
	if err != nil || j.JobID != queued.JobID {
		t.Fatal("Claim inverted job->Scope", err)
	}
	j, err = StartCapacityDispatch(ctx, r.DB, j)
	if err != nil {
		t.Fatal("Start inverted job->Scope", err)
	}
	peer := witnessedCleanup106PeerDB(t, r.DB)
	var pid int
	if err = peer.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
		t.Fatal(err)
	}
	type answer struct {
		j      CapacityDispatchJob
		merged bool
		err    error
	}
	done := make(chan answer, 1)
	next := witnessedCleanup106Next(t, r)
	go func() {
		tx, e := peer.BeginTx(ctx, nil)
		if e != nil {
			done <- answer{err: e}
			return
		}
		defer tx.Rollback()
		job, m, e := EnqueueCapacityDispatch(ctx, tx, next)
		if e == nil {
			e = tx.Commit()
		}
		done <- answer{job, m, e}
	}()
	nonceAcquire105WaitBlocked(t, ctx, r.DB, pid, 0)
	if err = holder.Commit(); err != nil {
		t.Fatal(err)
	}
	got := <-done
	if got.err != nil || !got.merged || got.j.JobID != j.JobID {
		t.Fatal("coalescing after genuine claim must not deadlock", got)
	}
	for _, marker := range []string{uuid.NewString(), ""} {
		bad := j.CapacityDispatchEnvelope
		bad.WitnessedUnenrolledExpansionCleanupID = marker
		raw, e := encodeCapacityDispatchEnvelope(bad)
		if e != nil {
			t.Fatal(e)
		}
		_, e = r.DB.ExecContext(ctx, `UPDATE capacity_dispatch_jobs SET envelope=$2,envelope_sha256=$3 WHERE id=$1`, j.JobID, string(raw), capacityDispatchSHA(raw))
		var p *pq.Error
		if !errors.As(e, &p) || p.Code != "P0001" {
			t.Fatal("changed marker/envelope exploited busy identity shortcut", e)
		}
	}
	put("M106-CLAIM-ENQUEUE-LOCK-ORDER.PUBLIC.json", failedServingWire(t, map[string]any{"schema": "witnessed_cleanup106_real_claim_enqueue_lock_order_v1", "real_claim_and_start_complete_while_scope_held": true, "enqueue_scope_block_observed": true, "same_child_coalesced": true, "marker_mutations_refused": 2, "fixture_only": true}))
	if err = r.DB.Close(); err != nil {
		t.Fatal(err)
	}
}

func witnessedCleanup106Inventory(t *testing.T, f *witnessedCleanup106Fixture, a WitnessedUnenrolledExpansionCleanup, target bool) model.CapacityVMFleetInventory {
	t.Helper()
	inv := capacity.RecoveryFixtureInventory(t, f.Spec, f.private.reg, time.Now().UTC())
	if target {
		m := inv.Members[0]
		m.Slot = 2
		m.Protected = false
		m.DesiredSpec = *f.Spec.MutationBindings[0].Slots[1].DesiredSpec
		m.RequestSHA256 = f.Spec.MutationBindings[0].Slots[1].DesiredSpecSHA256
		m.Server.ID, m.Server.CreatedAt, m.Server.Name = a.ResourceID, a.ResourceCreatedAt, m.DesiredSpec.NativeName
		m.Server.Labels = map[string]string{}
		for k, v := range inv.Members[0].Server.Labels {
			m.Server.Labels[k] = v
		}
		m.Server.Labels["yggdrasil.io/slot"], m.Server.Labels["yggdrasil.io/intent"] = "2", a.GrantID
		inv.Members = append(inv.Members, m)
		inv.MissingSlots = []int{3, 4, 5, 6, 7, 8}
	}
	return inv
}

func witnessedCleanup106InventoryReturn(t *testing.T, f *witnessedCleanup106Fixture, a WitnessedUnenrolledExpansionCleanup, read WitnessedExpansionRead) WitnessedExpansionReadReturn {
	t.Helper()
	at := time.Now().UTC()
	plan, err := witnessedExpansionDestroyPlan(f.Spec, a)
	if err != nil {
		t.Fatal(err)
	}
	var desired model.CapacityMutationSpecV1
	if json.Unmarshal(plan.CanonicalSpec, &desired) != nil {
		t.Fatal("exact dry-run destroy request")
	}
	inv := witnessedCleanup106Inventory(t, f, a, true)
	server := inv.Members[1].Server
	server.AuxiliaryInventoryComplete = true
	return WitnessedExpansionReadReturn{Schema: "witnessed_unenrolled_expansion_native_return_v1", Read: read, ReadWire: failedServingWire(t, read), Status: "dry_run", Plan: &model.CapacityVMFleetPlan{DesiredSpec: desired, RequestSHA256: plan.RequestSHA256, Server: &server, ObservedAt: at.Format(time.RFC3339Nano)}, StartedAtCore: at, ReturnedAtCore: at}
}

func witnessedCleanup106Settle(t *testing.T, f *witnessedCleanup106Fixture, store CapacityStore, grant model.CapacityMutationGrant) model.CapacityMutationReceipt {
	t.Helper()
	ctx, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	callback := CapacityStore{DB: f.DB, ExecutionEnabled: true}
	b := f.Spec.MutationBindings[0]
	nonce := uuid.NewString()
	req := model.CapacityMutationRedeemRequest{GrantID: grant.GrantID, Capability: grant.Capability, IntegrationInstanceID: grant.IntegrationInstanceID, ScopeChecksum: grant.ScopeChecksum, ProfileName: grant.ProfileName, Slot: grant.Slot, RequestSHA256: grant.RequestSHA256, ExpectedResourceID: grant.ExpectedResourceID, ExpectedResourceCreatedAt: grant.ExpectedResourceCreatedAt, AttemptID: uuid.NewString(), SettlementTokenSHA256: capacity.BusinessCreationSHA256([]byte(nonce))}
	permit, err := callback.RedeemMutation(ctx, b.AdapterPrincipalID, req)
	if err != nil || permit.Mode != "write_once" || permit.CompensationOf != "" {
		t.Fatal("one real ordinary DELETE redemption", err, permit)
	}
	if again, e := callback.RedeemMutation(ctx, b.AdapterPrincipalID, req); e == nil && again.Mode == "write_once" {
		t.Fatal("second write permit")
	}
	at := time.Now().UTC()
	stamp := at.Format(time.RFC3339Nano)
	settle := model.CapacityMutationSettleRequest{GrantID: grant.GrantID, AttemptID: req.AttemptID, RequestSHA256: grant.RequestSHA256, Outcome: "accepted", TransportCompleted: true, ResourceID: grant.ExpectedResourceID, ResourceCreatedAt: grant.ExpectedResourceCreatedAt, ActionID: "93", NextActionIDs: []string{}, AuxiliaryResources: append([]model.CapacityMutationAuxiliaryResource(nil), f.parent.Settlement.AuxiliaryResources...), AuxiliaryInventoryComplete: true, ObservedAt: stamp}
	// HZN's existing ordinary writer does not emit the AWS-only SDK destroy
	// wrapper. This DTO is declared; real Redeem/Settle and immutable receipt run.
	if _, err = callback.SettleMutation(ctx, b.AdapterPrincipalID, nonce, settle); err != nil {
		t.Fatal("real ordinary HZN settlement", err)
	}
	receipt, found, err := store.WitnessedExpansionDestroyReceipt(ctx, f.Policy)
	if err != nil || !found || receipt.Grant.State != "settled" {
		t.Fatal("real linked child receipt", err, found)
	}
	return receipt
}

func witnessedCleanup106Absence(t *testing.T, f *witnessedCleanup106Fixture, read WitnessedExpansionRead, receipt model.CapacityMutationReceipt, pending bool) WitnessedExpansionReadReturn {
	t.Helper()
	// Reuse only the existing provider-DTO factory; no old forward admission,
	// authority, fixture run or AWS observer wrapper is used by this lane.
	dto := &GuestRetirementForwardRecoveryFixture{Spec: f.Spec, t: t}
	o, at := dto.nativeAbsenceObservation(receipt)
	if pending {
		o.AuxiliaryResources[0].Absent = false
		o.BillableResourcesAbsent = false
		o.RetirementComplete = false
		o.BillingExposure = nil
		o.HoldReasons = []string{"native_billable_resources_present"}
	}
	return WitnessedExpansionReadReturn{Schema: "witnessed_unenrolled_expansion_native_return_v1", Read: read, ReadWire: failedServingWire(t, read), Status: "observed", Receipt: &receipt, ReceiptWire: failedServingWire(t, receipt), Observation: &o, StartedAtCore: at, ReturnedAtCore: at}
}

func witnessedCleanup106Native(t *testing.T, f *witnessedCleanup106Fixture, a WitnessedUnenrolledExpansionCleanup, put func(string, []byte)) {
	t.Helper()
	before := witnessedCleanup106Originals(t, f)
	childJob := witnessedCleanup106Start(t, f)
	ctx, stop := context.WithTimeout(context.Background(), 25*time.Second)
	defer stop()
	plan := f.private.store.WithOriginalGuestReconcile(f.Workflow, f.private.step(t, "plan-original-guest"), capacity.CurrentGuestCoreSource(), "", "", model.CapacityVMFleetInventory{}, model.CapacityMetricRangeObservation{})
	owned, current, same, found, err := plan.TryClaimWitnessedExpansionCleanup(ctx, f.Policy)
	if err != nil || !found || same.ID != a.ID || current.Generation != a.OriginalGeneration || current.FencingToken != a.OriginalFencingToken+1 || current.LeaseOwner == "" || current.LeaseOwner == f.intent.LeaseOwner {
		t.Fatal("distinct Source-authenticated cleanup owner", err, found, current)
	}
	if owned.witnessedExpansionOwner == nil {
		t.Fatal("private owner missing")
	}
	step := f.private.step(t, "retire-original-guest")
	store, _, found, err := f.private.store.WithOriginalGuestNotifyCanary(step, capacity.CurrentGuestCoreSource()).BindWitnessedExpansionCleanup(ctx, f.Policy, current.Generation, current.FencingToken, current.LeaseOwner)
	if err != nil || !found {
		t.Fatal("actual retire-source Bind", err)
	}
	if _, err = store.IssueWitnessedExpansionDestroy(ctx, f.Policy); err == nil {
		t.Fatal("DELETE without inventory/floor")
	}
	if err = store.RefreshWitnessedExpansionSurvivors(ctx, f.Policy, witnessedCleanup106Inventory(t, f, a, true)); err != nil {
		t.Fatal("fresh S1 and exact witnessed S2", err)
	}
	witnessedCleanup106Canaries(t, f, store, current, "before_retirement_floor")
	for _, fault := range []string{"locked", "foreign", "unknown_inventory", "open_context"} {
		read, e := store.PrepareWitnessedExpansionRead(ctx, f.Policy, "inventory")
		if e != nil {
			t.Fatal(e)
		}
		r := witnessedCleanup106InventoryReturn(t, f, a, read)
		switch fault {
		case "locked":
			r.Plan.Server.Locked = true
		case "foreign":
			r.Plan.Server.ID = "174243599"
		case "unknown_inventory":
			r.Plan.Server.AuxiliaryInventoryComplete = false
		case "open_context":
			r.OriginalContextFailed = true
		}
		if _, _, e = store.RecordWitnessedExpansionRead(ctx, f.Policy, r); e == nil {
			t.Fatal("invalid native dry-run qualified", fault)
		}
	}
	read, err := store.PrepareWitnessedExpansionRead(ctx, f.Policy, "inventory")
	if err != nil {
		t.Fatal(err)
	}
	if _, pending, e := store.RecordWitnessedExpansionRead(ctx, f.Policy, witnessedCleanup106InventoryReturn(t, f, a, read)); e != nil || pending {
		t.Fatal("exact native dry-run", e, pending)
	}
	grant, err := store.IssueWitnessedExpansionDestroy(ctx, f.Policy)
	if err != nil || grant.GrantID != a.ChildGrantID || grant.CompensationOf != "" {
		t.Fatal("one separately owned ordinary DELETE", err, grant)
	}
	if _, err = store.IssueWitnessedExpansionDestroy(ctx, f.Policy); err == nil {
		t.Fatal("second child issuance")
	}
	if err = store.MarkWitnessedExpansionPossibleSend(ctx, f.Policy); err != nil {
		t.Fatal(err)
	}
	if err = store.MarkWitnessedExpansionPossibleSend(ctx, f.Policy); err == nil {
		t.Fatal("possible_send replay")
	}
	receipt := witnessedCleanup106Settle(t, f, store, grant)
	finishStep := f.private.step(t, "finish-original-retirement")
	finish, _, found, err := f.private.store.WithOriginalGuestNotifyCanary(finishStep, capacity.CurrentGuestCoreSource()).BindWitnessedExpansionCleanup(ctx, f.Policy, current.Generation, current.FencingToken, current.LeaseOwner)
	if err != nil || !found {
		t.Fatal("actual finish-source Bind", err)
	}
	absenceRefusals := []string{"duplicate_primary_ip_ID", "observation_chronology", "missing_billing_exposure", "reported_call_failure", "failed_status", "at_original_read_deadline"}
	for _, fault := range absenceRefusals {
		read, err = finish.PrepareWitnessedExpansionRead(ctx, f.Policy, "absence")
		if err != nil {
			t.Fatal(err)
		}
		bad := witnessedCleanup106Absence(t, f, read, receipt, false)
		switch fault {
		case "duplicate_primary_ip_ID":
			bad.Observation.AuxiliaryResources[1].ID = bad.Observation.AuxiliaryResources[0].ID
		case "observation_chronology":
			bad.Observation.ObservedAt = bad.StartedAtCore.Add(-time.Nanosecond).Format(time.RFC3339Nano)
		case "missing_billing_exposure":
			bad.Observation.BillingExposure = nil
		case "reported_call_failure":
			bad.CallFailed = true
		case "failed_status":
			bad.Status = "failed"
		case "at_original_read_deadline":
			bad.ReturnedAtCore = read.OriginalDeadlineCore
		}
		if _, _, e := finish.RecordWitnessedExpansionRead(ctx, f.Policy, bad); e == nil {
			t.Fatal("invalid actual Go content channel qualified", fault)
		}
	}
	read, err = finish.PrepareWitnessedExpansionRead(ctx, f.Policy, "absence")
	if err != nil {
		t.Fatal(err)
	}
	if _, pending, e := finish.RecordWitnessedExpansionRead(ctx, f.Policy, witnessedCleanup106Absence(t, f, read, receipt, true)); e != nil || !pending {
		t.Fatal("paid auxiliary remains Pending", e, pending)
	}
	if _, err = finish.CompleteWitnessedExpansionCleanup(ctx, f.Policy); err == nil {
		t.Fatal("Pending mistaken for complete")
	}
	if err = finish.RefreshWitnessedExpansionSurvivors(ctx, f.Policy, witnessedCleanup106Inventory(t, f, a, false)); err != nil {
		t.Fatal("pending child preserves S1 refresh", err)
	}
	continuedStore, continuedIntent, continuedJob, continuedContext, continuedStop := witnessedCleanup106Continue(t, f, a, current, childJob, finish, receipt, ctx)
	stop()
	finish, current, childJob, ctx, stop = continuedStore, continuedIntent, continuedJob, continuedContext, continuedStop
	defer stop()
	read, err = finish.PrepareWitnessedExpansionRead(ctx, f.Policy, "absence")
	if err != nil {
		t.Fatal(err)
	}
	if proof, pending, e := finish.RecordWitnessedExpansionRead(ctx, f.Policy, witnessedCleanup106Absence(t, f, read, receipt, false)); e != nil || pending || !proof.ResourceAbsent {
		t.Fatal("complete exact HZN absence", e, pending, proof)
	}
	if _, err = finish.CompleteWitnessedExpansionCleanup(ctx, f.Policy); err == nil {
		t.Fatal("no fresh after-floor")
	}
	witnessedCleanup106Canaries(t, f, finish, current, "after_retirement_floor")
	terminal, err := finish.CompleteWitnessedExpansionCleanup(ctx, f.Policy)
	if err != nil || terminal.Decision.Units != 1 || terminal.Phase != "hold" || terminal.LeaseOwner != "" || terminal.LeaseExpiresAt != nil {
		t.Fatal("complete only failed expansion at floor1", err, terminal)
	}
	var valid bool
	var raw []byte
	if err = f.DB.QueryRow(`SELECT j.state='witnessed_unenrolled_expansion_disposed' AND j.finalization_ack_at IS NULL AND w.status='failed' AND g.state='witnessed_unenrolled_cleanup_closed' AND public.witnessed_unenrolled_expansion_terminal_valid106(j.id),jsonb_build_object('job',to_jsonb(j),'run',to_jsonb(w),'parent',to_jsonb(g),'admission',(SELECT to_jsonb(a) FROM capacity_witnessed_unenrolled_expansion_cleanups a WHERE a.id=$2),'events',(SELECT jsonb_agg(to_jsonb(e) ORDER BY sequence) FROM capacity_witnessed_unenrolled_expansion_cleanup_events e WHERE cleanup_id=$2))::text FROM capacity_dispatch_jobs j JOIN workflow_runs w ON w.id=j.run_id JOIN capacity_mutation_grants g ON g.id=$3 WHERE j.id=$1`, f.job.JobID, a.ID, a.GrantID).Scan(&valid, &raw); err != nil || !valid {
		t.Fatal("typed terminal/failed originals", err, valid)
	}
	// Only original terminal state+updated_at and grant state may differ. Whole
	// original ACK/error/envelope/SDK/witness/preregistration remain exact.
	var old, now map[string]json.RawMessage
	if json.Unmarshal(before, &old) != nil || json.Unmarshal(witnessedCleanup106Originals(t, f), &now) != nil {
		t.Fatal("whole originals")
	}
	for _, key := range []string{"run", "preregistration", "witness"} {
		if !bytes.Equal(old[key], now[key]) {
			t.Fatal("immutable original changed", key)
		}
	}
	for _, key := range []string{"job", "parent"} {
		var x, y map[string]json.RawMessage
		_ = json.Unmarshal(old[key], &x)
		_ = json.Unmarshal(now[key], &y)
		delete(x, "state")
		delete(y, "state")
		delete(x, "updated_at")
		delete(y, "updated_at")
		if key == "parent" {
			var gx, gy map[string]json.RawMessage
			_ = json.Unmarshal(x["grant_record"], &gx)
			_ = json.Unmarshal(y["grant_record"], &gy)
			var px, py map[string]json.RawMessage
			_ = json.Unmarshal(gx["grant"], &px)
			_ = json.Unmarshal(gy["grant"], &py)
			delete(px, "state")
			delete(py, "state")
			if !reflect.DeepEqual(px, py) {
				t.Fatal("original grant authority changed")
			}
			delete(gx, "grant")
			delete(gy, "grant")
			if !reflect.DeepEqual(gx, gy) {
				t.Fatal("original SDK/settlement changed")
			}
			delete(x, "grant_record")
			delete(y, "grant_record")
		}
		if !reflect.DeepEqual(x, y) {
			t.Fatal("original row changed beyond typed terminal", key)
		}
	}
	var s1Before, s1After map[string]json.RawMessage
	if json.Unmarshal(old["S1"], &s1Before) != nil || json.Unmarshal(now["S1"], &s1After) != nil {
		t.Fatal("whole S1 original/current rows")
	}
	var slotBefore, slotAfter map[string]json.RawMessage
	if json.Unmarshal(s1Before["slot_record"], &slotBefore) != nil || json.Unmarshal(s1After["slot_record"], &slotAfter) != nil {
		t.Fatal("whole S1 physical slot")
	}
	for _, k := range []string{"observed_at", "receipt_ref"} {
		delete(slotBefore, k)
		delete(slotAfter, k)
	}
	if !reflect.DeepEqual(slotBefore, slotAfter) {
		t.Fatal("cleanup changed S1 physical/create/enrollment tuple")
	}
	for _, k := range []string{"slot_record", "revision", "updated_at"} {
		delete(s1Before, k)
		delete(s1After, k)
	}
	if !reflect.DeepEqual(s1Before, s1After) {
		t.Fatal("cleanup changed S1 storage identity")
	}
	started, err := readCapacityDispatchJob(ctx, f.DB, childJob.JobID, false)
	if err != nil || started.State != "started" {
		t.Fatal("typed child must remain valid STARTED after parent disposed", err, started.State)
	}
	// The disposed parent no longer occupies the legacy index. The separate
	// marked child still does: a direct legacy INSERT must hit the independent
	// cross-class guard instead of escaping between the two physical indexes.
	legacy, err := f.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = witnessedCleanup106InsertDispatch(t, ctx, legacy, witnessedCleanup106Next(t, f))
	var legacyPG *pq.Error
	if !errors.As(err, &legacyPG) || legacyPG.Code != "23505" || legacyPG.Constraint != "capacity_dispatch_active_scope_idx" {
		_ = legacy.Rollback()
		t.Fatal("legacy INSERT escaped STARTED child after parent disposal", err)
	}
	if err = legacy.Rollback(); err != nil {
		t.Fatal(err)
	}
	if _, err = (CapacityStore{DB: f.DB}).RequestWitnessedUnenrolledExpansionCleanup(ctx, a.GrantID, a.JobID, "collaborator:"+uuid.NewString()); err == nil {
		t.Fatal("terminal admission replay")
	}
	put("M106-NATIVE-DECLARED-FIXTURE-WITNESS.PUBLIC.json", failedServingWire(t, map[string]any{"schema": "witnessed_cleanup106_real_store_declared_native_v1", "fixture_only": true, "native_provider_HTTP_Guest_execution_claimed": false, "real_store_dispatch_claim_bind_canary_redeem_settle_terminal": true, "one_ordinary_child": true, "no_compensation": true, "paid_auxiliary_pending_preserved": true, "fresh_before_and_after_S1_floor": true, "four_inventory_refusals": true, "distinct_two_primary_ip_positive": true, "absence_content_refusals": absenceRefusals, "real_original_read_deadline_failed_custody": true, "real_failed_ACK_then_natural_private_lease_expiry": true, "fresh_owner_read_same_child_no_DELETE_replay": true, "child_STARTED_after_parent_disposed": true, "legacy_insert_after_parent_disposed_blocked": true, "original_ACK_absent": true, "whole_terminal": json.RawMessage(raw)}))
}

func witnessedCleanup106Continue(t *testing.T, f *witnessedCleanup106Fixture, a WitnessedUnenrolledExpansionCleanup, current model.CapacityIntent, oldJob CapacityDispatchJob, finish CapacityStore, receipt model.CapacityMutationReceipt, original context.Context) (CapacityStore, model.CapacityIntent, CapacityDispatchJob, context.Context, context.CancelFunc) {
	t.Helper()
	read, err := finish.PrepareWitnessedExpansionRead(original, f.Policy, "absence")
	if err != nil {
		t.Fatal(err)
	}
	readContext, readStop := context.WithDeadline(original, read.OriginalDeadlineCore)
	started := time.Now().UTC()
	<-readContext.Done()
	readStop()
	if !errors.Is(readContext.Err(), context.DeadlineExceeded) {
		t.Fatal("original finite native read must expire")
	}
	raw := WitnessedExpansionReadReturn{Schema: "witnessed_unenrolled_expansion_native_return_v1", Read: read, ReadWire: failedServingWire(t, read), Receipt: &receipt, ReceiptWire: failedServingWire(t, receipt), StartedAtCore: started, ReturnedAtCore: time.Now().UTC(), CallFailed: true, OriginalContextFailed: true}
	retain, retainStop := context.WithTimeout(context.Background(), 5*time.Second)
	_, _, err = finish.RecordWitnessedExpansionRead(retain, f.Policy, raw)
	retainStop()
	if err == nil {
		t.Fatal("failed original read became positive absence")
	}
	_, events, err := (CapacityStore{DB: f.DB}).ReadWitnessedUnenrolledExpansionCleanup(context.Background(), a.GrantID)
	if err != nil || len(events) < 3 || events[len(events)-1].Stage != "absence_returned" {
		t.Fatal("failed raw return must remain archived", err)
	}
	var storedRaw WitnessedExpansionReadReturn
	if json.Unmarshal(events[len(events)-1].Evidence, &storedRaw) != nil || !reflect.DeepEqual(storedRaw, raw) {
		t.Fatal("failed-read custody changed")
	}
	var child capacityMutationRecord
	var childWire []byte
	if err = f.DB.QueryRow(`SELECT grant_record FROM capacity_mutation_grants WHERE id=$1`, a.ChildGrantID).Scan(&childWire); err != nil || json.Unmarshal(childWire, &child) != nil {
		t.Fatal("same original accepted child", err)
	}
	claim, ok := latestWitnessedExpansionClaim(events)
	if !ok || !witnessedExpansionDeadlineReturnContinuation(events, claim, a, child, f.Spec, time.Now().UTC()) {
		t.Fatal("qualified HZN Pending/deadline suffix must be recognized without AWS SDK")
	}
	failedAt := time.Now().UTC()
	response := supersededHTTPResult(t, oldJob, current.Generation, current.FencingToken, *oldJob.StartedAt, failedAt)
	response.Metadata = map[string]any{}
	for k, v := range oldJob.Metadata {
		response.Metadata[k] = v
	}
	response.Metadata["failed_step"] = "finish-original-retirement"
	for i := range response.Steps {
		response.Steps[i].Metadata = map[string]any{}
		response.Steps[i].Status = "skipped"
		response.Steps[i].Attempts = 0
	}
	response.Steps[0].Status, response.Steps[0].Attempts = "succeeded", 1
	response.Steps[2].Status, response.Steps[2].Attempts = "succeeded", 1
	response.Steps[5].Status, response.Steps[5].Attempts, response.Steps[5].Error = "failed", 1, "declared original native read returned deadline failure"
	declaredFailure := errors.New("declared original native read failed")
	err = FinishCapacityDispatch(context.Background(), f.DB, oldJob, response, failedAt, declaredFailure)
	if !errors.Is(err, declaredFailure) || errors.Is(err, ErrCapacityDispatchUnknown) || errors.Is(err, ErrCapacityDispatchFinalizationPending) || errors.Is(err, ErrCapacityDispatchClaim) {
		t.Fatal("real failed cleanup ACK before its lease expiry", err)
	}
	closed, err := readCapacityDispatchJob(context.Background(), f.DB, oldJob.JobID, false)
	if err != nil || closed.State != "returned" || closed.FinalizationAckAt == nil {
		t.Fatal("real closed old owner/failed ACK", err, closed.State)
	}
	if current.LeaseExpiresAt == nil {
		t.Fatal("old private lease required")
	}
	if wait := time.Until(*current.LeaseExpiresAt); wait > 0 {
		timer := time.NewTimer(wait + time.Millisecond)
		<-timer.C
	}
	job := witnessedCleanup106Start(t, f)
	if job.LeaseExpiresAt == nil {
		t.Fatal("fresh run's own original deadline required")
	}
	ctx, stop := context.WithDeadline(context.Background(), *job.LeaseExpiresAt)
	plan := f.private.store.WithOriginalGuestReconcile(f.Workflow, f.private.step(t, "plan-original-guest"), capacity.CurrentGuestCoreSource(), "", "", model.CapacityVMFleetInventory{}, model.CapacityMetricRangeObservation{})
	_, next, same, found, err := plan.TryClaimWitnessedExpansionCleanup(ctx, f.Policy)
	if err != nil || !found || same.ID != a.ID || next.FencingToken != current.FencingToken+1 || next.LeaseOwner == current.LeaseOwner || next.LeaseExecutorID == current.LeaseExecutorID {
		stop()
		t.Fatal("new private owner of SAME child", err, found)
	}
	store, _, found, err := f.private.store.WithOriginalGuestNotifyCanary(f.private.step(t, "finish-original-retirement"), capacity.CurrentGuestCoreSource()).BindWitnessedExpansionCleanup(ctx, f.Policy, next.Generation, next.FencingToken, next.LeaseOwner)
	if err != nil || !found {
		stop()
		t.Fatal("fresh finish-source continuation Bind", err)
	}
	if _, err = store.IssueWitnessedExpansionDestroy(ctx, f.Policy); err == nil {
		stop()
		t.Fatal("continuation replayed DELETE")
	}
	if err = store.MarkWitnessedExpansionPossibleSend(ctx, f.Policy); err == nil {
		stop()
		t.Fatal("continuation replayed possible_send")
	}
	if again, found, e := store.WitnessedExpansionDestroyReceipt(ctx, f.Policy); e != nil || !found || !reflect.DeepEqual(again, receipt) {
		stop()
		t.Fatal("continuation changed accepted child", e, found)
	}
	if err = store.RefreshWitnessedExpansionSurvivors(ctx, f.Policy, witnessedCleanup106Inventory(t, f, a, false)); err != nil {
		stop()
		t.Fatal("continuation refreshes only existing S1", err)
	}
	return store, next, job, ctx, stop
}

func witnessedCleanup106OldGoose(t *testing.T, db *sql.DB, migrations string, put func(string, []byte)) {
	t.Helper()
	oldDir := t.TempDir()
	entries, err := os.ReadDir(migrations)
	if err != nil {
		t.Fatal(err)
	}
	versions := map[int]bool{}
	files := []map[string]any{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		if len(e.Name()) < 6 || e.Name()[5] != '_' {
			t.Fatal("canonical migration filename", e.Name())
		}
		n, err := strconv.Atoi(e.Name()[:5])
		if err != nil {
			t.Fatal(err)
		}
		if n > 104 {
			continue
		}
		if versions[n] || n < 1 || n == 40 {
			t.Fatal("exact old migration roster", e.Name())
		}
		versions[n] = true
		raw, err := os.ReadFile(filepath.Join(migrations, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(oldDir, e.Name()), raw, 0600); err != nil {
			t.Fatal(err)
		}
		copied, err := os.ReadFile(filepath.Join(oldDir, e.Name()))
		if err != nil || !bytes.Equal(raw, copied) {
			t.Fatal("exact old Goose Source copy", e.Name(), err)
		}
		files = append(files, map[string]any{"path": e.Name(), "bytes": len(raw), "sha256": capacity.BusinessCreationSHA256(raw)})
	}
	if len(versions) != 103 {
		t.Fatal("103 exact Source migrations through104 required", len(versions))
	}
	for n := 1; n <= 104; n++ {
		if n != 40 && !versions[n] {
			t.Fatal("missing original migration", n)
		}
	}
	before := installedReadinessCatalog(t, db)
	put("M106-OLD-GOOSE104-BEFORE106.original.json", before)
	// This is the unchanged production Goose Up library path with the exact
	// old image's migration directory, not a claim to boot the old image here.
	if err = goose.UpContext(context.Background(), db, oldDir); err != nil {
		t.Fatal("old Goose directory must no-op on complete DB106", err)
	}
	after := installedReadinessCatalog(t, db)
	put("M106-OLD-GOOSE104-AFTER106.original.json", after)
	if !bytes.Equal(before, after) {
		t.Fatal("old Goose changed whole DB106 history/catalog")
	}
	put("M106-OLD-GOOSE104-DIRECTORY-NOOP.PUBLIC.json", failedServingWire(t, map[string]any{"schema": "witnessed_cleanup106_old_goose_directory_noop_v1", "local_migration_files": files, "local_max": 104, "database_schema": 106, "whole_catalog_and_history_before_sha256": capacity.BusinessCreationSHA256(before), "whole_catalog_and_history_after_sha256": capacity.BusinessCreationSHA256(after), "whole_equal": true, "old_image_boot_claimed": false, "fixture_only": true}))
}
