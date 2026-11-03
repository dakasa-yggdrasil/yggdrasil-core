//go:build recoveryfixture && !nativequalification

package repository

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/manifest"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/pressly/goose/v3"
)

// One fixture owns all process-scoped test registry changes until TB
// cleanup. Focused tests do not run fixtures in parallel or leak this process
// to the production/default/nativequalification builds.
var failedServingFixtureMutex sync.Mutex

// These are signed, explicitly tagged test operands in an isolated database.
// They exercise production repository/FK/trigger behavior. They are never live
// Guest/process/provider authority, and no cloud or application is contacted.
type failedServingFixture struct {
	db               *sql.DB
	p                model.CapacityPolicySpec
	policy, workflow model.Manifest
	steps            []model.WorkflowStepSpec
	store            CapacityStore
	pre              model.CapacityGuestOriginalProvisioningPreregistration
	reg              model.CapacityGuestOriginalProvisioningRegistration
	receipt          model.CapacityGuestOriginalProvisioningReceipt
	installed        model.CapacityGuestOriginalInstallationConfirmation
	intent           model.CapacityIntent
}

func failedServingWire(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func failedServingDB(t *testing.T) *sql.DB { t.Helper(); return failedServingDBAtSchema(t, 90) }

// Only the historical index89 proof uses89; operational/new recovery fixtures
// always use current90. No caller/env can select an arbitrary old schema.
func failedServingDBAtSchema(t *testing.T, target int64) *sql.DB {
	t.Helper()
	if target != 89 && target != 90 {
		t.Fatal("closed fixture schema89 or90 required")
	}
	if !strings.HasSuffix(filepath.Base(os.Args[0]), ".test") || os.Getenv("CAPACITY_RECOVERY_FIXTURE_ONLY") != "true" {
		t.Fatal("explicit disposable fixture gate required")
	}
	u, err := url.Parse(os.Getenv("FAILED_SERVING_FIXTURE_ADMIN_URL"))
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") || u.Path != "/postgres" {
		t.Fatal("explicit fixture admin URL required")
	}
	host, socket := u.Hostname(), u.Query().Get("host")
	if host != "127.0.0.1" && host != "localhost" && host != "::1" && !(host == "" && strings.HasPrefix(socket, "/")) {
		t.Fatal("remote PostgreSQL refused")
	}
	want, err := strconv.Atoi(os.Getenv("FAILED_SERVING_TEST_PG_MAJOR"))
	if err != nil || (want != 16 && want != 17) {
		t.Fatal("explicit PostgreSQL16/17 fixture major required")
	}
	admin, err := sql.Open("postgres", u.String())
	if err != nil {
		t.Fatal(err)
	}
	var addr string
	var major int
	if err = admin.QueryRow(`SELECT COALESCE(inet_server_addr()::text,'unix'),current_setting('server_version_num')::int/10000`).Scan(&addr, &major); err != nil || !failedServingLocalServer(host, addr) || major != want {
		_ = admin.Close()
		t.Fatal("actual local fixture PostgreSQL identity/major differs", err)
	}
	name := "failed_serving_fixture_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err = admin.Exec("CREATE DATABASE " + pq.QuoteIdentifier(name)); err != nil {
		_ = admin.Close()
		t.Fatal(err)
	}
	u.Path = "/" + name
	db, err := sql.Open("postgres", u.String())
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(6)
	t.Cleanup(func() {
		_ = db.Close()
		if _, e := admin.Exec("DROP DATABASE " + pq.QuoteIdentifier(name) + " WITH (FORCE)"); e != nil {
			t.Error("disposable failed-serving database cleanup", e)
		}
		_ = admin.Close()
	})
	var actualName string
	if err = db.QueryRow(`SELECT current_database()`).Scan(&actualName); err != nil || actualName != name || !strings.HasPrefix(actualName, "failed_serving_fixture_") {
		t.Fatal("new disposable database identity differs", err)
	}
	if err = goose.SetDialect("postgres"); err != nil {
		t.Fatal(err)
	}
	migrations := filepath.Join(failedServingRepositoryRoot(t), "db", "migrations")
	if target == 89 {
		err = goose.UpTo(db, migrations, 89)
	} else {
		err = goose.Up(db, migrations)
	}
	if err != nil {
		t.Fatal("production migrations", err)
	}
	version, err := goose.GetDBVersion(db)
	if err != nil || version != target {
		t.Fatal("exact closed fixture schema required", target, version, err)
	}
	return db
}

func (f *failedServingFixture) exec(t *testing.T, query string, args ...any) {
	t.Helper()
	if _, err := f.db.Exec(query, args...); err != nil {
		t.Fatal("failed-serving original fixture", err)
	}
}

func (f *failedServingFixture) step(t *testing.T, id string) model.WorkflowStepSpec {
	t.Helper()
	var found model.WorkflowStepSpec
	count := 0
	for _, step := range f.steps {
		if step.ID == id {
			found = step
			count++
		}
	}
	if count != 1 {
		t.Fatal("one exact owning original workflow step required", id, count)
	}
	return found
}

func (f *failedServingFixture) inventory(t *testing.T, empty bool) model.CapacityVMFleetInventory {
	t.Helper()
	inv := capacity.RecoveryFixtureInventory(t, f.p, f.reg, time.Now().UTC())
	if empty {
		inv.Members = []model.CapacityVMFleetInventoryMember{}
		inv.MissingSlots = []int{1, 2, 3, 4, 5, 6, 7, 8}
	}
	return inv
}

func (f *failedServingFixture) rawIntent(t *testing.T) []byte {
	t.Helper()
	var raw []byte
	if err := f.db.QueryRow(`SELECT intent::text FROM public.capacity_intents WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4`, f.policy.Metadata.Namespace, f.p.Environment, f.p.Domain, f.p.Dimension).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	return raw
}

func (f *failedServingFixture) request(t *testing.T) model.CapacityFailedServingGuestDisposalRequest {
	t.Helper()
	raw := f.rawIntent(t)
	var current model.CapacityIntent
	if json.Unmarshal(raw, &current) != nil {
		t.Fatal("actual complete intent")
	}
	return model.CapacityFailedServingGuestDisposalRequest{PreregistrationID: f.pre.PreregistrationID, PolicyID: f.policy.ID.String(), PolicyChecksum: f.policy.Checksum, Generation: current.Generation, FencingToken: current.FencingToken, IntentSHA256: capacity.BusinessCreationSHA256(raw)}
}

func failedServingKey(ch byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed([]byte(strings.Repeat(string(ch), 32)))
}

func failedServingPublic(key ed25519.PrivateKey) string {
	return base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
}

func newFailedServingFixture(t *testing.T, provider string) *failedServingFixture {
	t.Helper()
	return newFailedServingFixtureHistory(t, provider, false)
}

func newFailedServingFixtureHistory(t *testing.T, provider string, historical bool) *failedServingFixture {
	t.Helper()
	return newFailedServingFixtureLease(t, provider, historical, 30)
}

// Select the declared lease before any initial signed policy/catalog state.
// This is fixture construction, never a rewrite of an admitted original.
func newFailedServingFixtureLease(t *testing.T, provider string, historical bool, leaseSeconds int) *failedServingFixture {
	t.Helper()
	if leaseSeconds != 30 && leaseSeconds != 300 {
		t.Fatal("closed declared fixture lease")
	}
	if !strings.HasSuffix(filepath.Base(os.Args[0]), ".test") || os.Getenv("CAPACITY_RECOVERY_FIXTURE_ONLY") != "true" {
		t.Fatal("explicit test process and fixture gate required")
	}
	actualSource := capacity.CurrentGuestCoreSource()
	if len(actualSource) != 40 || actualSource != os.Getenv("SOURCE_COMMIT") {
		t.Fatal("exact clean native test build metadata required; CI must use -buildvcs=true")
	}
	failedServingFixtureMutex.Lock()
	t.Cleanup(failedServingFixtureMutex.Unlock)
	capacity.RecoveryFixtureApprovalScope(t)
	p, binding, reg, receipt, installed, settlement := failedServingOperands(t, provider)
	p.LeaseSeconds = leaseSeconds
	f := &failedServingFixture{db: failedServingDB(t), p: p, reg: reg, receipt: receipt, installed: installed}
	f.pre = reg.Result.ProductionClock.Authority.Preregistration
	f.policy = model.Manifest{ID: uuid.MustParse(f.pre.PolicyID), Kind: "capacity_policy", Checksum: f.pre.PolicyChecksum, Version: 1, Metadata: model.ManifestMetadata{Namespace: "dakasa-production", Name: "notify-" + provider + "-elastic-capacity", Active: true}, Spec: failedServingWire(t, p)}
	steps, err := capacity.OriginalGuestReconcileGraph(f.policy, p)
	if err != nil {
		t.Fatal("actual owning source graph", err)
	}
	f.steps = steps
	enabled, no := true, false
	wfs := model.WorkflowManifestSpec{Trigger: model.WorkflowTriggerSpec{Mode: "schedule", Enabled: &enabled, Schedule: &model.WorkflowScheduleTriggerSpec{CronExpression: "* * * * *", CatchupPolicy: "skip"}}, Authorization: &model.WorkflowAuthorizationSpec{RBAC: model.ManifestSelector{Namespace: "dakasa-production", Name: "failed-serving-unit-rbac"}}, DispatchMode: "async", InputSchema: model.WorkflowInputSchemaSpec{Required: []string{"policy"}, AdditionalProperties: &no, Properties: map[string]model.IntegrationSchemaProperty{"policy": {Type: "object"}}}, Steps: steps}
	f.workflow = model.Manifest{ID: uuid.MustParse(f.pre.WorkflowID), Kind: "workflow", Checksum: f.pre.WorkflowChecksum, Version: 1, Metadata: model.ManifestMetadata{Namespace: p.Workflow.Namespace, Name: p.Workflow.Name, Active: true}, Spec: failedServingWire(t, wfs)}
	for _, m := range []model.Manifest{f.policy, f.workflow} {
		f.exec(t, `INSERT INTO public.manifests(id,api_version,kind,namespace,name,version,checksum,spec,active) VALUES($1,'v1',$2,$3,$4,1,$5,$6::jsonb,true)`, m.ID, m.Kind, m.Metadata.Namespace, m.Metadata.Name, m.Checksum, string(m.Spec))
	}
	mutation := p.MutationBindings[0]
	// A complete DECLARED catalog, so normal mutation/event APIs validate the
	// provider/resource/action contract. This is not a hydrated live catalog or
	// proof that the fixture transport/version is the production adapter.
	typeSpec := failedServingTypeSpec(provider, mutation)
	if err := manifest.ValidateIntegrationTypeSpec(typeSpec); err != nil {
		t.Fatal("declared provider catalog invalid", err)
	}
	f.exec(t, `INSERT INTO public.manifests(id,api_version,kind,namespace,name,version,checksum,spec,active) VALUES($1,'v1','integration_type','failed-serving-fixture',$2,1,$3,$4::jsonb,true)`, mutation.IntegrationTypeID, "source-"+provider, mutation.IntegrationTypeChecksum, string(failedServingWire(t, typeSpec)))
	instance := failedServingWire(t, map[string]any{"type_ref": map[string]any{"manifest_id": mutation.IntegrationTypeID}})
	f.exec(t, `INSERT INTO public.manifests(id,api_version,kind,namespace,name,version,checksum,spec,active) VALUES($1,'v1','integration_instance','failed-serving-fixture',$2,1,$3,$4::jsonb,true)`, mutation.IntegrationInstanceID, "source-"+provider, mutation.IntegrationChecksum, string(instance))
	tx, err := f.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	_, err = tx.Exec(`INSERT INTO public.capacity_mutation_grants(id,namespace,environment,domain,dimension,generation,integration_instance_id,scope_checksum,profile_name,slot,state,grant_record,expires_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,1,'settled','{}'::jsonb,$10,$11)`, f.pre.OriginalCreateGrantID, f.policy.Metadata.Namespace, p.Environment, p.Domain, p.Dimension, f.pre.Generation, mutation.IntegrationInstanceID, mutation.ScopeChecksum, mutation.ProfileName, f.pre.OriginalDeadline, f.pre.ReservedAt)
	if err != nil {
		t.Fatal(err)
	}
	_, err = tx.Exec(`INSERT INTO public.capacity_vm_provisioning_preregistrations(id,create_grant_id,nonce_sha256,profile_manifest_sha256,preregistration_record,original_deadline,created_at,original_wire,binding_wire) VALUES($1,$2,$3,$4,$5::jsonb,$6,$7,$8,$9)`, f.pre.PreregistrationID, f.pre.OriginalCreateGrantID, f.pre.NonceSHA256, f.pre.ProfileManifestSHA256, string(failedServingWire(t, f.pre)), f.pre.OriginalDeadline, f.pre.ReservedAt, failedServingWire(t, f.pre), failedServingWire(t, binding))
	if err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	witness := reg.Result.ProductionClock.Authority.CreateWitness
	originalProof := &model.CapacityMutationProof{GrantID: f.pre.OriginalCreateGrantID, BindingName: mutation.Name, Slot: 1, ResourceID: witness.Tuple.ResourceID, ResourceCreatedAt: witness.Tuple.CreatedAt, RequestSHA256: f.pre.OriginalCreateRequestSHA256, ObservedAt: witness.ObservedAt, ReceiptRef: "declared-signed-original-native-read", OwnerVerified: true, SpecVerified: true, ObservedCreationGrantID: f.pre.OriginalCreateGrantID, ProviderNativeIdentity: witness.ProviderNativeIdentity}
	if provider == "aws" {
		originalProof.AWSInstanceLifecycle = &model.CapacityAWSInstanceLifecycle{Schema: "aws_original_request_and_instance_status_v1", RequestID: settlement.ActionID, EC2State: "running", SystemStatus: "ok", InstanceStatus: "ok", ObservedAt: witness.ObservedAt}
	} else {
		originalProof.ActionIDs = []string{settlement.ActionID}
		originalProof.ActionsTerminal = true
		originalProof.ActionsSuccessful = true
	}
	created := capacityMutationRecord{PolicyID: f.policy.ID, PolicyChecksum: f.policy.Checksum, WorkflowID: f.workflow.ID, Binding: mutation, Generation: f.pre.Generation, FencingToken: f.pre.Fence, ExecutorID: f.pre.ExecutorID, LeaseOwner: f.pre.LeaseOwner, AttemptID: settlement.AttemptID, Grant: model.CapacityMutationGrant{GrantID: f.pre.OriginalCreateGrantID, BindingName: mutation.Name, IntegrationInstanceID: mutation.IntegrationInstanceID, ScopeChecksum: mutation.ScopeChecksum, ProfileName: mutation.ProfileName, Slot: 1, Capability: mutation.EnsureCapability, RequestSHA256: f.pre.OriginalCreateRequestSHA256, State: "confirmed", ExpiresAt: f.pre.OriginalDeadline}, CreatedAt: f.pre.ReservedAt, Settlement: &settlement, Proof: originalProof}
	f.exec(t, `UPDATE public.capacity_mutation_grants SET namespace=$2,environment=$3,domain=$4,dimension=$5,generation=$6,integration_instance_id=$7,scope_checksum=$8,profile_name=$9,slot=1,state='confirmed',grant_record=$10::jsonb WHERE id=$1`, f.pre.OriginalCreateGrantID, f.policy.Metadata.Namespace, p.Environment, p.Domain, p.Dimension, f.pre.Generation, mutation.IntegrationInstanceID, mutation.ScopeChecksum, mutation.ProfileName, string(failedServingWire(t, created)))
	f.exec(t, `INSERT INTO public.capacity_guest_original_create_witnesses(preregistration_id,original_create_attempt_id,resource_tuple_sha256,witness_sha256,original_wire,original_record,recorded_at) VALUES($1,$2,$3,$4,$5,$6::jsonb,$7)`, f.pre.PreregistrationID, witness.OriginalCreateAttemptID, capacity.GuestRetirementSHA(witness.Tuple), capacity.GuestRetirementSHA(witness), failedServingWire(t, witness), string(failedServingWire(t, witness)), witness.ObservedAt)
	f.exec(t, `INSERT INTO public.capacity_vm_original_enrollments(preregistration_id,resource_tuple_sha256,enrollment_sha256,original_provisioning_sha256,enrollment_record,recorded_at,registration_wire,receipt_wire) VALUES($1,$2,$3,$4,$5::jsonb,$6,$7,$8)`, f.pre.PreregistrationID, capacity.GuestRetirementSHA(receipt.Enrollment.Statement.Tuple), capacity.GuestRetirementSHA(receipt.Enrollment), receipt.OriginalProvisioningSHA256, string(failedServingWire(t, receipt.Enrollment)), receipt.RecordedAt, failedServingWire(t, reg), failedServingWire(t, receipt))
	f.exec(t, `INSERT INTO public.capacity_guest_original_installations(preregistration_id,original_wire,confirmation_sha256,recorded_at) VALUES($1,$2,$3,$4)`, f.pre.PreregistrationID, failedServingWire(t, installed), capacity.GuestRetirementSHA(installed), receipt.RecordedAt.Add(time.Second))
	tx, err = f.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if historical {
		now = f.pre.ReservedAt.Add(10 * time.Minute)
	}
	slot := capacityResourceSlot{BindingName: mutation.Name, ProfileName: mutation.ProfileName, DesiredSpecSHA256: mutation.Slots[0].DesiredSpecSHA256, ResourceID: witness.Tuple.ResourceID, ResourceCreatedAt: witness.Tuple.CreatedAt, ObservedAt: now, ReceiptRef: "declared-failed-serving-source-fixture"}
	if err = saveMutationSlot(context.Background(), tx, f.policy.Metadata.Namespace, p, mutation, 1, slot); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	snapshot, err := capacity.GuestReconcileSnapshot(f.policy, p, capacity.RecoveryFixtureInventory(t, p, reg, now), now)
	if err != nil {
		t.Fatal("actual complete source inventory content", err)
	}
	baseline := snapshot
	baseline.Units = 0
	f.intent = model.CapacityIntent{Namespace: f.policy.Metadata.Namespace, PolicyName: f.policy.Metadata.Name, PolicyID: f.policy.ID, PolicyChecksum: f.policy.Checksum, Environment: p.Environment, Domain: p.Domain, Dimension: p.Dimension, Generation: f.pre.Generation, FencingToken: f.pre.Fence, Phase: "promoted", Decision: model.CapacityDecision{Action: "hold", Reason: "within_bounds", Profile: mutation.ProfileName, Units: 1, Floor: 1}, BaselineSnapshot: baseline, Assessment: model.CapacityAssessment{Snapshot: snapshot}, UpdatedAt: now}
	f.exec(t, `INSERT INTO public.capacity_intents(namespace,environment,domain,dimension,intent) VALUES($1,$2,$3,$4,$5::jsonb)`, f.policy.Metadata.Namespace, p.Environment, p.Domain, p.Dimension, string(failedServingWire(t, f.intent)))
	f.exec(t, `INSERT INTO public.capacity_intent_events(namespace,environment,domain,dimension,generation,fencing_token,phase,receipt_ref) VALUES($1,$2,$3,$4,$5,$6,'promoted','declared-source-fixture-promoted-history')`, f.policy.Metadata.Namespace, p.Environment, p.Domain, p.Dimension, f.intent.Generation, f.intent.FencingToken)
	f.store = CapacityStore{DB: f.db, ExecutionEnabled: true, WorkflowID: f.workflow.ID, ExecutorID: uuid.NewString()}
	if historical {
		// Initial declared storage chronology. No immutable original is edited;
		// the source-generated historical canary rows are inserted below. The
		// normal fixture above separately exercises actual nonce/send/return APIs.
		old := f.pre.ReservedAt.Add(10 * time.Minute)
		f.exec(t, `UPDATE public.capacity_mutation_grants SET updated_at=$2 WHERE id=$1`, f.pre.OriginalCreateGrantID, old)
		f.exec(t, `UPDATE public.capacity_resource_slots SET updated_at=$2 WHERE namespace=$1`, f.policy.Metadata.Namespace, old)
		f.exec(t, `UPDATE public.capacity_intents SET updated_at=$2 WHERE namespace=$1`, f.policy.Metadata.Namespace, old)
		f.exec(t, `UPDATE public.capacity_intent_events SET recorded_at=$2 WHERE namespace=$1`, f.policy.Metadata.Namespace, old)
		f.seedHistoricalAcceptedRead(t, f.pre.ReservedAt.Add(30*time.Minute))
		return f
	}
	f.acceptMaintenanceCanary(t)
	// Make these accepted originals historical using their actual deadline,
	// rather than rewriting any nonce, original return, row or source clock.
	var remaining float64
	if err = f.db.QueryRow(`SELECT GREATEST(0,EXTRACT(EPOCH FROM(max(original_deadline)-clock_timestamp()))) FROM public.capacity_guest_notify_canary_challenges WHERE preregistration_id=$1`, f.pre.PreregistrationID).Scan(&remaining); err != nil || remaining > 6 {
		t.Fatal("bounded historical canary closure", remaining, err)
	}
	if remaining > 0 {
		time.Sleep(time.Duration(remaining*float64(time.Second)) + 5*time.Millisecond)
	}
	return f
}

func (f *failedServingFixture) offPlan(t *testing.T) model.CapacityVMFleetPlan {
	t.Helper()
	plan := capacity.RecoveryFixtureNativeOffPlan(t, f.p, f.pre, f.reg.Result.Tuple)
	if f.p.Profiles[0].Provider == "aws" {
		plan.DesiredSpec.Capability = "observe_ec2_instance"
		plan.RequestSHA256 = f.p.MutationBindings[0].Slots[0].DesiredSpecSHA256
		plan.Server.Status = "stopped"
	}
	return plan
}

func failedServingAbsence(t *testing.T, owner *FailedServingGuestOwner) model.CapacityOriginalCreateDispositionObservation {
	t.Helper()
	return failedServingAbsenceCandidate(t, owner.Candidate(), owner.Spec())
}

func failedServingAbsenceCandidate(t *testing.T, c model.CapacityOriginalCreateDispositionCandidate, p model.CapacityPolicySpec) model.CapacityOriginalCreateDispositionObservation {
	t.Helper()
	r := c.Request
	provider := p.Profiles[0].Provider
	now := time.Now().UTC()
	basis, source, mainKind := "original_accepted_auxiliary_inventory_v1", enrolledFailedHetznerCreator, "server"
	if provider == "aws" {
		basis, source, mainKind = "aws_original_enrolled_failed_create_owned_auxiliary_absence_v1", EnrolledFailedAWSObserverSource(), "aws_ec2_instance"
	}
	o := model.CapacityOriginalCreateDispositionObservation{Schema: model.OriginalCreateDispositionObservationSchema, InventoryBasis: basis, Provider: provider, Profile: r.Profile, Slot: r.Slot, GrantID: r.GrantID, AttemptID: r.AttemptID, RequestSHA256: r.RequestSHA256, ResourceID: r.ExpectedResourceID, ResourceCreatedAt: r.ExpectedResourceCreatedAt, OriginalAdapterSourceCommit: r.OriginalAdapterSourceCommit, AdapterSourceCommit: source, ResourceState: "absent", ResourceAbsenceComplete: true, AuxiliaryInventoryComplete: true, SharedResourcesPreserved: true, AuxiliaryResources: []model.CapacityVMAuxiliaryObservation{}, NativeReads: []model.CapacityOriginalCreateDispositionNativeRead{}, ObservationStartedAt: now}
	if provider == "aws" && !r.OriginalAuxiliaryInventoryComplete {
		return failedServingAWSAdjunctAbsence(t, c, o, now)
	}
	resources := []model.CapacityMutationAuxiliaryResource{{Kind: mainKind, ID: r.ExpectedResourceID}}
	resources = append(resources, r.AuxiliaryResources...)
	for i, a := range resources {
		body := []byte(`{"error":{"code":"not_found","message":"declared provider fixture"}}`)
		called := now.Add(time.Duration(i) * time.Microsecond)
		returned := called.Add(time.Nanosecond)
		o.NativeReads = append(o.NativeReads, model.CapacityOriginalCreateDispositionNativeRead{Operation: "GetExactOriginal", ResourceKind: a.Kind, ResourceID: a.ID, Status: 404, ResponseSHA256: capacity.BusinessCreationSHA256(body), ResponseBytes: int64(len(body)), ResponseBodyBase64: base64.StdEncoding.EncodeToString(body), ResponseRepresentation: "raw_http_body_v1", CalledAt: called, ReturnedAt: returned})
		if i > 0 {
			o.AuxiliaryResources = append(o.AuxiliaryResources, model.CapacityVMAuxiliaryObservation{Kind: a.Kind, ID: a.ID, Absent: true, ObservedAt: returned.Format(time.RFC3339Nano)})
		}
	}
	o.ObservedAt = now.Add(time.Duration(len(resources)) * time.Microsecond)
	return o
}

// Declared public six-read DTOs, including the lossy userdata-omitted CloudTrail
// projection. The production observer owns SDK authentication/content; this
// fixture exercises the Core's exact original RequestID/auxiliary custody join.
func failedServingAWSAdjunctAbsence(t *testing.T, c model.CapacityOriginalCreateDispositionCandidate, o model.CapacityOriginalCreateDispositionObservation, now time.Time) model.CapacityOriginalCreateDispositionObservation {
	t.Helper()
	snapshot, eni, eventID := "snap-00000000000000123", "eni-00000000000000123", uuid.NewString()
	event := failedServingWire(t, map[string]any{"eventID": eventID, "requestID": c.Request.OriginalCreateActionID, "requestParameters": map[string]any{"clientToken": c.Request.AttemptID}})
	trail := failedServingWire(t, map[string]any{"schema": "cloudtrail_lookup_events_userdata_omitted_projection_v1", "original_http_body_retained": false, "original_http_body_hashed": false, "original_eof_and_close": true, "user_data_fields_removed": 1, "response": map[string]any{"Events": []map[string]any{{"EventId": eventID, "CloudTrailEvent": string(event)}}}})
	reads := []struct {
		op, kind, id   string
		status         int
		body           []byte
		representation string
	}{
		{"GetCallerIdentity", "aws_account", "153828470928", 200, []byte(`{"Account":"153828470928"}`), "canonical_provider_SDK_result_v1"},
		{"DescribeInstances", "aws_ec2_instance", c.Request.ExpectedResourceID, 400, []byte(`<Response><Errors><Error><Code>InvalidInstanceID.NotFound</Code></Error></Errors></Response>`), "raw_http_body_v1"},
		{"LookupEvents", "aws_cloudtrail_event", eventID, 200, trail, "cloudtrail_lookup_events_userdata_omitted_projection_v1"},
		{"DescribeImages", "aws_ami", "ami-00000000000000123", 200, []byte(`{"Images":[{"ImageId":"ami-00000000000000123","BlockDeviceMappings":[{"Ebs":{"SnapshotId":"snap-00000000000000123"}}]}]}`), "canonical_provider_SDK_result_v1"},
		{"DescribeVolumes", "aws_ebs_snapshot_descendants", snapshot, 200, []byte(`{"Volumes":[]}`), "canonical_provider_SDK_result_v1"},
		{"DescribeNetworkInterfaces", "aws_network_interface", eni, 400, []byte(`<Response><Errors><Error><Code>InvalidNetworkInterfaceID.NotFound</Code></Error></Errors></Response>`), "raw_http_body_v1"},
	}
	for i, r := range reads {
		at := now.Add(time.Duration(i) * time.Microsecond)
		o.NativeReads = append(o.NativeReads, model.CapacityOriginalCreateDispositionNativeRead{Operation: r.op, ResourceKind: r.kind, ResourceID: r.id, Status: r.status, ResponseSHA256: capacity.BusinessCreationSHA256(r.body), ResponseBytes: int64(len(r.body)), ResponseBodyBase64: base64.StdEncoding.EncodeToString(r.body), ResponseRepresentation: r.representation, CalledAt: at, ReturnedAt: at.Add(time.Nanosecond)})
	}
	o.ObservedAt = now.Add(7 * time.Microsecond)
	o.AuxiliaryResources = []model.CapacityVMAuxiliaryObservation{{Kind: "aws_ebs_snapshot_descendants", ID: snapshot, Absent: true, ObservedAt: o.ObservedAt.Format(time.RFC3339Nano)}, {Kind: "aws_network_interface", ID: eni, Absent: true, ObservedAt: o.ObservedAt.Format(time.RFC3339Nano)}}
	return o
}

func (f *failedServingFixture) preserved(t *testing.T) map[string]string {
	t.Helper()
	queries := map[string]string{
		"preregistration": `SELECT row_to_json(t)::text FROM public.capacity_vm_provisioning_preregistrations t WHERE id=$1`,
		"witness":         `SELECT row_to_json(t)::text FROM public.capacity_guest_original_create_witnesses t WHERE preregistration_id=$1`,
		"enrollment":      `SELECT row_to_json(t)::text FROM public.capacity_vm_original_enrollments t WHERE preregistration_id=$1`,
		"installation":    `SELECT row_to_json(t)::text FROM public.capacity_guest_original_installations t WHERE preregistration_id=$1`,
		"challenges":      `SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY t.id),'[]'::jsonb)::text FROM public.capacity_guest_notify_canary_challenges t WHERE preregistration_id=$1`,
		"nonces":          `SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY t.challenge_id),'[]'::jsonb)::text FROM public.capacity_guest_notify_canary_nonces t WHERE challenge_id IN(SELECT id FROM public.capacity_guest_notify_canary_challenges WHERE preregistration_id=$1)`,
		"sends":           `SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY t.challenge_id),'[]'::jsonb)::text FROM public.capacity_guest_notify_canary_sends t WHERE challenge_id IN(SELECT id FROM public.capacity_guest_notify_canary_challenges WHERE preregistration_id=$1)`,
		"returns":         `SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY t.challenge_id),'[]'::jsonb)::text FROM public.capacity_guest_notify_canary_returns t WHERE challenge_id IN(SELECT id FROM public.capacity_guest_notify_canary_challenges WHERE preregistration_id=$1)`,
	}
	out := map[string]string{}
	for name, query := range queries {
		var raw []byte
		if err := f.db.QueryRow(query, f.pre.PreregistrationID).Scan(&raw); err != nil {
			t.Fatal("original preservation", name, err)
		}
		out[name] = capacity.BusinessCreationSHA256(raw)
	}
	var grant, promoted []byte
	if err := f.db.QueryRow(`SELECT row_to_json(t)::text FROM public.capacity_mutation_grants t WHERE id=$1`, f.pre.OriginalCreateGrantID).Scan(&grant); err != nil {
		t.Fatal(err)
	}
	if err := f.db.QueryRow(`SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY t.id),'[]'::jsonb)::text FROM public.capacity_intent_events t WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4 AND phase='promoted' AND generation=$5`, f.policy.Metadata.Namespace, f.p.Environment, f.p.Domain, f.p.Dimension, f.pre.Generation).Scan(&promoted); err != nil {
		t.Fatal(err)
	}
	out["original_create_grant"], out["historical_promoted_events"] = capacity.BusinessCreationSHA256(grant), capacity.BusinessCreationSHA256(promoted)
	return out
}

func (f *failedServingFixture) acceptMaintenanceCanary(t *testing.T) {
	t.Helper()
	ctx, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	step := f.step(t, "refresh-original-membership")
	store := f.store.WithOriginalGuestReconcile(f.workflow, step, capacity.CurrentGuestCoreSource(), "refresh", "", f.inventory(t, false), model.CapacityMetricRangeObservation{}).WithOriginalGuestNotifyCanary(step, capacity.CurrentGuestCoreSource())
	generation, fence, owner, err := store.GuestNotifyMaintenanceEpoch(ctx, f.policy, f.pre.PreregistrationID)
	if err != nil {
		t.Fatal("actual maintenance epoch", err)
	}
	probe := func(challenge model.CapacityGuestNotifyCanaryChallenge, publication *capacity.GuestNotifyPublicationReply) *capacity.GuestNotifyPublicationReply {
		challenge = capacity.RecoveryFixtureCanaryNonce(t, challenge, f.receipt.Enrollment)
		nonce := failedServingHTTP(t, challenge.GuestNonce, time.Now().UTC())
		if e := store.FinalizeGuestNotifyCanaryNonce(ctx, f.policy, generation, fence, owner, challenge, nonce); e != nil {
			t.Fatal("real nonce finalization", e)
		}
		if e := store.ReserveGuestNotifyCanarySend(ctx, f.policy, generation, fence, owner, challenge); e != nil {
			t.Fatal("real canary reservation", e)
		}
		response, facts := capacity.RecoveryFixtureCanaryResponse(t, f.p, challenge, f.receipt.Enrollment, publication)
		returned := failedServingHTTP(t, response, response.OriginalReadStartedAt.Add(-time.Millisecond))
		if delay := time.Until(returned.DriverReturnedAt) + time.Millisecond; delay > 0 {
			time.Sleep(delay)
		}
		if _, e := store.RecordGuestNotifyCanaryReturn(ctx, f.policy, generation, fence, owner, challenge, returned); e != nil {
			t.Fatal("actual accepted canary storage path", e)
		}
		return facts
	}
	publication, err := store.IssueGuestNotifyCanaryPublication(ctx, f.policy, generation, fence, owner, f.pre.PreregistrationID, "steady_useful_membership", failedServingKey('c'))
	if err != nil {
		t.Fatal("actual historical publication", err)
	}
	facts := probe(publication, nil)
	read, err := store.IssueGuestNotifyCanaryRead(ctx, f.policy, generation, fence, owner, f.pre.PreregistrationID, "steady_useful_membership", publication.ChallengeID, failedServingKey('c'))
	if err != nil {
		t.Fatal("actual historical read", err)
	}
	probe(read, facts)
}

// Initial construction of declared historical operands, before any signature
// or database row is made. The whole itinerary moves together; no production
// history or stored clock is edited to manufacture an expired authority.
func failedServingHistoricalOperand[T any](t *testing.T, value T) T {
	t.Helper()
	var decoded any
	if json.Unmarshal(failedServingWire(t, value), &decoded) != nil {
		t.Fatal("declared historical operand")
	}
	var shift func(any) any
	shift = func(value any) any {
		switch v := value.(type) {
		case string:
			if at, err := time.Parse(time.RFC3339Nano, v); err == nil && !at.IsZero() {
				return at.Add(-2 * time.Hour).Format(time.RFC3339Nano)
			}
		case []any:
			for i := range v {
				v[i] = shift(v[i])
			}
		case map[string]any:
			for k := range v {
				v[k] = shift(v[k])
			}
		}
		return value
	}
	var out T
	if json.Unmarshal(failedServingWire(t, shift(decoded)), &out) != nil {
		t.Fatal("declared historical operand shape")
	}
	return out
}

// Reuse only the declared test clock/process itinerary. Each provider gets its
// own actual b509 contract, tuple, native identity, original settlement and all
// freshly rederived signatures/hashes. No Hetzner record is labelled as AWS.
func failedServingOperands(t *testing.T, provider string) (model.CapacityPolicySpec, model.CapacityGuestRetirementBinding, model.CapacityGuestOriginalProvisioningRegistration, model.CapacityGuestOriginalProvisioningReceipt, model.CapacityGuestOriginalInstallationConfirmation, model.CapacityMutationSettleRequest) {
	t.Helper()
	_, _, reg, receipt, installed := capacity.RecoveryFixtureInstalledSlot(t, 1)
	reg = failedServingHistoricalOperand(t, reg)
	receipt = failedServingHistoricalOperand(t, receipt)
	installed = failedServingHistoricalOperand(t, installed)
	if provider != "aws" && provider != "hetzner" {
		t.Fatal("closed fixture provider")
	}
	raw, err := os.ReadFile(filepath.Join(failedServingRepositoryRoot(t), "internal", "capacity", "testdata", "b509-notify-"+provider+"-production-contract.json"))
	if err != nil {
		t.Fatal(err)
	}
	var p model.CapacityPolicySpec
	if err = json.Unmarshal(raw, &p); err != nil || p.GuestRetirementBinding == nil || p.Profiles[0].Provider != provider {
		t.Fatal("actual provider-specific public contract fixture", err)
	}
	b := *p.GuestRetirementBinding
	b.ProvisionerPublicKey, b.EnrollmentIssuerPublicKey = failedServingPublic(failedServingKey('p')), failedServingPublic(failedServingKey('i'))
	p.GuestRetirementBinding = &b
	p.ExecutionEnabled, p.LeaseSeconds = true, 30
	p.GuestNotifyCanaryBinding.RecipientSHA256 = capacity.BusinessRecipientSHA256([]string{"77777777-7777-4777-8777-777777777777", "88888888-8888-4888-8888-888888888888"})
	p.GuestNotifyCanaryBinding.MinimumPublicationIntervalSeconds = 5
	mutation := p.MutationBindings[0]
	clock := *reg.Result.ProductionClock
	pre := clock.Authority.Preregistration
	// A noninitial birth epoch lets the negative corpus distinguish a future
	// birth from a merely malformed generation-zero request.
	pre.Generation, pre.Fence = 2, 2
	pre.BindingName, pre.ProfileManifestSHA256, pre.CoreSourceCommit = b.Members[0].Name, b.ProfileManifestSHA256, b.CoreAuthoritySourceCommit
	pre.OriginalWorkflowStepID = b.ProfileManifest.OriginalProvisioningStepID
	pre.OriginalCreateRequestSHA256 = mutation.Slots[0].DesiredSpecSHA256
	witness := clock.Authority.CreateWitness
	witness.BindingName, witness.ProfileManifestSHA256, witness.CoreSourceCommit = pre.BindingName, b.ProfileManifestSHA256, pre.CoreSourceCommit
	witness.OriginalCreateRequestSHA256 = pre.OriginalCreateRequestSHA256
	witness.BootstrapSHA256 = capacity.GuestProfileBootstrapSHA(b.ProfileManifest, 1)
	tuple := model.CapacityGuestNativeTuple{Provider: provider, InstanceID: mutation.IntegrationInstanceID, InstanceChecksum: mutation.IntegrationChecksum, TypeID: mutation.IntegrationTypeID, TypeChecksum: mutation.IntegrationTypeChecksum, ScopeChecksum: mutation.ScopeChecksum, ProfileChecksum: mutation.Slots[0].DesiredSpec.ProfileChecksum, Profile: mutation.ProfileName, Slot: 1, ResourceID: "123", CreatedAt: witness.Tuple.CreatedAt}
	if provider == "aws" {
		tuple.ResourceID = "i-00000000000000123"
	}
	witness.Tuple = tuple
	identity := &model.CapacityGuestProviderNativeIdentity{Schema: capacity.GuestProviderNativeIdentitySchema, Provider: provider, ResourceID: tuple.ResourceID, ResourceCreatedAt: tuple.CreatedAt, Region: "us-east", Location: "ash", TypeID: "22", ImageID: "33", Hostname: "declared-source-fixture", ObservedAt: witness.ObservedAt, AdapterSourceCommit: mutation.OriginalProviderSourceCommit}
	if provider == "aws" {
		identity.Region, identity.Location, identity.Zone = "us-east-1", "us-east-1", "us-east-1a"
		identity.AccountID, identity.TypeID, identity.ImageID = "153828470928", "t3.small", "ami-00000000000000123"
	}
	witness.ProviderNativeIdentity = identity
	action := "77"
	schema, status := "hetzner_original_create_return_v1", 201
	aux := []model.CapacityMutationAuxiliaryResource{{Kind: "ssh_key", ID: "901", RequiresAbsence: true}}
	if provider == "aws" {
		action, schema, status = "10000000-0000-4000-8000-000000000008", "aws_original_run_instances_return_v1", 200
		// The actual enrolled AWS creator did not attest auxiliary inventory.
		// Preserve that false and exercise the dedicated six-read adjunct lane.
		aux = []model.CapacityMutationAuxiliaryResource{}
	}
	providerReturn := &model.CapacityOriginalProviderCreateReturn{Schema: schema, Provider: provider, AdapterSourceCommit: mutation.OriginalProviderSourceCommit, GrantID: pre.OriginalCreateGrantID, AttemptID: witness.OriginalCreateAttemptID, RequestSHA256: pre.OriginalCreateRequestSHA256, ResourceID: tuple.ResourceID, ResourceCreatedAt: tuple.CreatedAt, ActionID: action, NextActionIDs: []string{}, CalledAt: pre.ReservedAt.Format(time.RFC3339Nano), ReturnedAt: witness.OriginalCreateReturnedAt.Format(time.RFC3339Nano), ContextDeadline: pre.OriginalDeadline.Format(time.RFC3339Nano), ResponseStatus: status, ResponseBodySHA256: strings.Repeat("a", 64), ResponseBytes: 2}
	settlement := model.CapacityMutationSettleRequest{GrantID: pre.OriginalCreateGrantID, AttemptID: witness.OriginalCreateAttemptID, RequestSHA256: pre.OriginalCreateRequestSHA256, Outcome: "accepted", TransportCompleted: true, ResourceID: tuple.ResourceID, ResourceCreatedAt: tuple.CreatedAt, ActionID: action, NextActionIDs: []string{}, AuxiliaryResources: aux, AuxiliaryInventoryComplete: true, OriginalProviderCreateReturn: providerReturn, ObservedAt: witness.ObservedAt.Format(time.RFC3339Nano)}
	if provider == "aws" {
		settlement.AuxiliaryInventoryComplete = false
	}
	grant := model.CapacityMutationGrant{GrantID: pre.OriginalCreateGrantID, BindingName: mutation.Name, IntegrationInstanceID: mutation.IntegrationInstanceID, ScopeChecksum: mutation.ScopeChecksum, ProfileName: mutation.ProfileName, Slot: 1, Capability: mutation.EnsureCapability, RequestSHA256: pre.OriginalCreateRequestSHA256, ExpiresAt: pre.OriginalDeadline, State: "confirmed"}
	validateReturn := capacity.ValidateOriginalHetznerCreateReturn
	if provider == "aws" {
		validateReturn = capacity.ValidateOriginalAWSCreateReturn
	}
	if _, err = validateReturn(mutation, grant, witness.OriginalCreateAttemptID, settlement, pre.ReservedAt, receipt.RecordedAt); err != nil {
		t.Fatal("declared original provider return must match its actual schema", err)
	}
	witness.OriginalCreateSettlementSHA256 = capacity.GuestRetirementSHA(settlement)
	witness.Signature = ""
	witness.Signature, err = capacity.GuestLifecycleSignature(failedServingKey('c'), witness)
	if err != nil {
		t.Fatal(err)
	}
	clock.Authority.BindingName, clock.Authority.Profile, clock.Authority.Preregistration, clock.Authority.CreateWitness = pre.BindingName, b.ProfileManifest, pre, witness
	clock.Authority.Signature = ""
	clock.Authority.Signature, err = capacity.GuestLifecycleSignature(failedServingKey('c'), clock.Authority)
	if err != nil {
		t.Fatal(err)
	}
	r := &reg.Result
	r.BindingName, r.SourceClass, r.ProvisionerSourceCommit, r.ProfileManifestSHA256 = pre.BindingName, b.EvidenceClass, b.ProvisionerSourceCommit, b.ProfileManifestSHA256
	r.OriginalCreateSettlementSHA256, r.Tuple, r.ProductionClock = witness.OriginalCreateSettlementSHA256, tuple, &clock
	r.Actor.SourceCommit, r.Actor.BinarySHA256 = b.ProfileManifest.ActorSourceCommit, b.ProfileManifest.ActorBinarySHA256
	r.Runtime.SourceCommit, r.Runtime.BinarySHA256 = b.ProfileManifest.OwnerSourceCommit, b.ProfileManifest.OwnerBinarySHA256
	r.Writers[0].ID, r.Writers[0].Lifetime.SourceCommit, r.Writers[0].Lifetime.BinarySHA256 = b.ProfileManifest.Writers[0].ID, b.ProfileManifest.Writers[0].SourceCommit, b.ProfileManifest.Writers[0].BinarySHA256
	r.WriterRosterSHA256 = capacity.GuestRetirementSHA(r.Writers)
	r.BootstrapOriginalJournal.Tuple, r.BootstrapOriginalJournal.UserDataSHA256, r.BootstrapOriginalJournal.PayloadSHA256 = tuple, witness.BootstrapSHA256, b.ProfileManifest.BootstrapPayloadSHA256
	r.BootstrapOriginalJournal.OwnerSourceCommit, r.BootstrapOriginalJournal.OwnerBinarySHA256 = b.ProfileManifest.BootstrapOwnerSourceCommit, b.ProfileManifest.BootstrapOwnerBinarySHA256
	r.BootstrapOriginalObservation.Journal, r.BootstrapOriginalObservation.JournalSHA256 = r.BootstrapOriginalJournal, capacity.GuestRetirementSHA(r.BootstrapOriginalJournal)
	r.BootstrapOriginalObservation.UserDataSHA256 = witness.BootstrapSHA256
	r.BootstrapOriginalObservation.ReaderSourceCommit, r.BootstrapOriginalObservation.ReaderBinarySHA256 = b.ProfileManifest.BootstrapOwnerSourceCommit, b.ProfileManifest.BootstrapReaderBinarySHA256
	r.ProtectedCensus.SourceCommit = r.Runtime.SourceCommit
	r.WriterPlacements[0].Writer, r.WriterPlacements[0].DefinitionSHA256, r.WriterPlacements[0].ProtectedCgroup = r.Writers[0], capacity.GuestRetirementSHA(b.ProfileManifest.Writers[0]), b.ProfileManifest.ProtectedCgroup
	r.WriterPlacements[0].Census = r.ProtectedCensus
	e := &reg.EnrollmentStatement
	e.BindingName, e.SourceClass, e.ProvisionerSourceCommit, e.Tuple = r.BindingName, r.SourceClass, r.ProvisionerSourceCommit, tuple
	e.Actor, e.Runtime, e.Writers, e.WriterRosterSHA256 = r.Actor, r.Runtime, r.Writers, r.WriterRosterSHA256
	e.OriginalNativeResultSHA256, e.OriginalProvisioningClockSHA256 = capacity.GuestRetirementSHA(*r), capacity.GuestRetirementSHA(clock)
	e.RuntimeCommandSHA256, e.PoweroffCommandSHA256, e.CoreAuthoritySourceCommit = b.ProfileManifest.RuntimeClientCommandSHA256, b.ProfileManifest.PoweroffCommandSHA256, b.CoreAuthoritySourceCommit
	reg.Signature = ""
	reg.Signature, err = capacity.GuestLifecycleSignature(failedServingKey('p'), reg)
	if err != nil {
		t.Fatal(err)
	}
	receipt.OriginalProvisioningSHA256, receipt.Enrollment.Statement = capacity.GuestRetirementSHA(reg), *e
	receipt.Enrollment.Signature, err = capacity.GuestLifecycleSignature(failedServingKey('i'), receipt.Enrollment.Statement)
	if err != nil {
		t.Fatal(err)
	}
	installed.OriginalReceiptSHA256, installed.EnrollmentSHA256 = capacity.GuestRetirementSHA(receipt), capacity.GuestRetirementSHA(receipt.Enrollment)
	installed.ProductionClock.OriginalProvisioningClockSHA256 = capacity.GuestRetirementSHA(clock)
	installed.Signature = ""
	installed.Signature, err = capacity.GuestLifecycleSignature(failedServingKey('p'), installed)
	if err != nil {
		t.Fatal(err)
	}
	if err = capacity.RegisterRecoveryFixtureApproval(p, b, provider); err != nil {
		t.Fatal(err)
	}
	if err = capacity.GuestProductionProvisioningClockV2(p, b, b.Members[0], clock, failedServingPublic(failedServingKey('c')), receipt.RecordedAt); err != nil {
		t.Fatal("provider-specific original clock", err)
	}
	if err = capacity.GuestOriginalRegistration(p, b, b.Members[0], witness, reg, receipt.RecordedAt); err != nil {
		t.Fatal("provider-specific signed original registration", err)
	}
	if err = capacity.GuestRetirementEnrollment(p, b, b.Members[0], receipt.Enrollment, receipt.RecordedAt); err != nil {
		t.Fatal("provider-specific signed enrollment", err)
	}
	if err = capacity.GuestOriginalInstallationV2(pre, receipt, installed, b.ProvisionerPublicKey, clock, receipt.RecordedAt.Add(time.Second)); err != nil {
		t.Fatal("provider-specific signed installation", err)
	}
	return p, b, reg, receipt, installed, settlement
}

// This additional fixture tests immutable historical storage, not a native
// Guest execution. Normal lifecycle tests separately produce accepted reads
// through the actual source nonce/send/return APIs. Here historical originals
// are inserted once, with normal FK/trigger enforcement, never replica mode.
func (f *failedServingFixture) historicalChallenge(t *testing.T, at time.Time) model.CapacityGuestNotifyCanaryChallenge {
	t.Helper()
	_, c, _, _ := capacity.RecoveryFixtureCausal(t, f.p, f.reg, f.receipt, uint64(f.pre.Fence), GuestNotifyMaintenanceOwner(f.store.ExecutorID), at)
	c.ChallengeID = uuid.NewString()
	c.RecordChallengeID = c.ChallengeID
	c.NonceSHA256 = capacity.BusinessCreationSHA256([]byte("historical:" + c.ChallengeID))
	c.UsageClass = "steady_useful_membership"
	c.GuestNonce.ChallengeID = c.ChallengeID
	c.GuestNonce.PreflightSHA256 = capacity.GuestNotifyPreflightSHA(c)
	c.GuestNonce.NonceSHA256 = capacity.BusinessCreationSHA256([]byte("guest-historical:" + c.ChallengeID))
	c.GuestNonce.Signature = ""
	var err error
	c.GuestNonce.Signature, err = capacity.GuestLifecycleSignature(failedServingKey('o'), c.GuestNonce)
	if err != nil {
		t.Fatal(err)
	}
	c.Signature = ""
	c.Signature, err = capacity.GuestLifecycleSignature(failedServingKey('c'), c)
	if err != nil {
		t.Fatal(err)
	}
	if err = capacity.ValidateGuestNotifyCanaryChallenge(c, f.receipt.Enrollment, at.Add(time.Millisecond)); err != nil {
		t.Fatal("signed historical challenge operand", err)
	}
	return c
}

func (f *failedServingFixture) insertHistoricalChallenge(t *testing.T, c model.CapacityGuestNotifyCanaryChallenge, phase string) {
	t.Helper()
	wire := failedServingWire(t, c)
	f.exec(t, `INSERT INTO public.capacity_guest_notify_canary_challenges(id,preregistration_id,record_challenge_id,phase,policy_id,workflow_id,generation,fence,executor_id,lease_owner,challenge_sha256,nonce_sha256,original_wire,original_record,original_deadline,recorded_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14::jsonb,$15,$16)`, c.ChallengeID, f.pre.PreregistrationID, c.RecordChallengeID, phase, f.policy.ID, f.workflow.ID, c.Generation, c.Fence, f.store.ExecutorID, c.LeaseOwner, capacity.GuestRetirementSHA(c), c.NonceSHA256, wire, string(wire), c.OriginalDeadline, c.IssuedAt)
}

func (f *failedServingFixture) seedHistoricalAcceptedRead(t *testing.T, at time.Time) {
	t.Helper()
	pub := f.historicalChallenge(t, at)
	f.insertHistoricalChallenge(t, pub, "publish")
	read := pub
	read.Schema = capacity.GuestNotifyCanaryChallengeSchema
	read.Purpose = capacity.GuestNotifyCanaryReadPurpose
	read.ChallengeID = uuid.NewString()
	read.RecordChallengeID = pub.ChallengeID
	read.NonceSHA256 = capacity.BusinessCreationSHA256([]byte("historical-read:" + read.ChallengeID))
	read.IssuedAt = at.Add(500 * time.Millisecond)
	read.GuestNonce.Phase = "read"
	read.GuestNonce.ChallengeID = read.ChallengeID
	read.GuestNonce.PreflightSHA256 = capacity.GuestNotifyPreflightSHA(read)
	read.GuestNonce.Signature = ""
	read.GuestNonce.Signature, _ = capacity.GuestLifecycleSignature(failedServingKey('o'), read.GuestNonce)
	read.Signature = ""
	read.Signature, _ = capacity.GuestLifecycleSignature(failedServingKey('c'), read)
	f.insertHistoricalChallenge(t, read, "read")
	// Explicit opaque declared storage operand. This does not attest that an
	// application/provider was contacted or that an old remote effect ended.
	wire := []byte(`{"declared_historical_accepted_read_fixture":true}`)
	f.exec(t, `INSERT INTO public.capacity_guest_notify_canary_returns(challenge_id,outcome,return_sha256,original_wire,original_transport,recorded_at) VALUES($1,'accepted',$2,$3,'{"declared_storage_only":true}'::jsonb,$4)`, read.ChallengeID, capacity.BusinessCreationSHA256(wire), wire, at.Add(time.Second))
}

func failedServingLocalServer(host, addr string) bool {
	if addr == "unix" {
		return true
	}
	ip := net.ParseIP(strings.SplitN(addr, "/", 2)[0])
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || (host != "" && ip.IsPrivate())
}

func failedServingHTTP(t *testing.T, body any, at time.Time) capacity.GuestOriginalHTTPReturn {
	t.Helper()
	wire := failedServingWire(t, body)
	sha := capacity.BusinessCreationSHA256(wire)
	return capacity.GuestOriginalHTTPReturn{StartedAt: at, DoStartedAt: at.Add(time.Millisecond), DoReturnedAt: at.Add(51 * time.Millisecond), ReadReturnedAt: at.Add(52 * time.Millisecond), CloseReturnedAt: at.Add(53 * time.Millisecond), DriverReturnedAt: at.Add(54 * time.Millisecond), Status: 200, Body: wire, ReceivedBodyBytes: len(wire), ResponseSHA256: sha, ResponseBodyScope: capacity.GuestOriginalBodyCompleteRead, RetainedPrefixBytes: len(wire), RetainedPrefixSHA256: sha}
}

// FailedServingRecoveryFixture contains declared Source-test operands only.
// Its builder has no native/cloud authority and is absent from both release
// and nativequalification packages. Every database is newly created and owned
// until TB cleanup; no caller may supply an existing database to this type.
type FailedServingRecoveryFixture struct {
	DB           *sql.DB
	Store        CapacityStore
	Policy       model.Manifest
	Workflow     model.Manifest
	Spec         model.CapacityPolicySpec
	Pre          model.CapacityGuestOriginalProvisioningPreregistration
	Registration model.CapacityGuestOriginalProvisioningRegistration
	Receipt      model.CapacityGuestOriginalProvisioningReceipt
	private      *failedServingFixture
	t            *testing.T
}

func NewFailedServingRecoveryFixture(tb testing.TB, provider string) *FailedServingRecoveryFixture {
	tb.Helper()
	if !strings.HasSuffix(filepath.Base(os.Args[0]), ".test") || os.Getenv("CAPACITY_RECOVERY_FIXTURE_ONLY") != "true" {
		tb.Fatal("explicit test process and fixture gate required")
	}
	t, ok := tb.(*testing.T)
	if !ok {
		tb.Fatal("test fixture requires owning *testing.T")
	}
	f := newFailedServingFixture(t, provider)
	return &FailedServingRecoveryFixture{DB: f.db, Store: f.store, Policy: f.policy, Workflow: f.workflow, Spec: f.p, Pre: f.pre, Registration: f.reg, Receipt: f.receipt, private: f, t: t}
}
func (f *FailedServingRecoveryFixture) Request() model.CapacityFailedServingGuestDisposalRequest {
	return f.private.request(f.t)
}
func (f *FailedServingRecoveryFixture) Inventory(empty bool) model.CapacityVMFleetInventory {
	return f.private.inventory(f.t, empty)
}
func (f *FailedServingRecoveryFixture) NativeOffPlan() model.CapacityVMFleetPlan {
	return f.private.offPlan(f.t)
}
func (f *FailedServingRecoveryFixture) Absence(c model.CapacityOriginalCreateDispositionCandidate) model.CapacityOriginalCreateDispositionObservation {
	return failedServingAbsenceCandidate(f.t, c, f.private.p)
}
func (f *FailedServingRecoveryFixture) OriginalIntentWire() []byte { return f.private.rawIntent(f.t) }

func failedServingRepositoryRoot(t *testing.T) string {
	t.Helper()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("fixture source path unavailable")
	}
	return filepath.Dir(filepath.Dir(source))
}

func failedServingTypeSpec(provider string, b model.CapacityMutationBinding) model.IntegrationTypeManifestSpec {
	resource := "server"
	if provider == "aws" {
		resource = "ec2_instance"
	}
	return model.IntegrationTypeManifestSpec{
		Provider:     provider,
		Adapter:      model.IntegrationAdapterSpec{Transport: "rabbitmq", Version: "0.1.0", TimeoutSeconds: 65, Queues: model.IntegrationAdapterQueue{Describe: "declared.fixture.describe", Execute: "declared.fixture.execute"}},
		Capabilities: []string{"describe", "execute"}, CredentialSchema: model.IntegrationSchemaSpec{Mode: "none"}, InstanceSchema: model.IntegrationSchemaSpec{Mode: "none"},
		ResourceTypes: []model.IntegrationResourceType{{Name: resource, CanonicalPrefix: "thirdparty." + provider + "." + resource, IdentityTemplate: resource + ".{id}", DefaultActions: []string{b.EnsureCapability, b.DestroyCapability}}},
		ActionCatalog: []model.IntegrationActionDefinition{{Name: b.EnsureCapability, ResourceTypes: []string{resource}, Idempotent: true}, {Name: b.DestroyCapability, ResourceTypes: []string{resource}, Idempotent: true}},
		Discovery:     model.IntegrationDiscoverySpec{Mode: "push", Cursor: "none"}, Normalization: model.IntegrationNormalizationSpec{ExternalIDPath: "id", FallbackResourcePrefix: "thirdparty." + provider + ".custom"},
		Execution: model.IntegrationExecutionSpec{SupportsDryRun: true, IdempotentActions: []string{b.EnsureCapability, b.DestroyCapability}},
	}
}
