//go:build recoveryfixture && !nativequalification

package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	manifestengine "github.com/dakasa-yggdrasil/yggdrasil-core/manifest"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/pressly/goose/v3"
)

// These are declared signed operands in isolated PG16/17 databases, never
// provider observations. Every original is inserted once; natural time, actual
// dispatch writers and the production M98 guards decide admission.
type installedTimeoutFixture struct {
	db                *sql.DB
	p                 model.CapacityPolicySpec
	binding           model.CapacityGuestRetirementBinding
	policy, workflow  model.Manifest
	steps             []model.WorkflowStepSpec
	pre               []model.CapacityGuestOriginalProvisioningPreregistration
	reg               []model.CapacityGuestOriginalProvisioningRegistration
	receipts          []model.CapacityGuestOriginalProvisioningReceipt
	installed         []model.CapacityGuestOriginalInstallationConfirmation
	intent            model.CapacityIntent
	original          CapacityDispatchEnvelope
	job               CapacityDispatchJob
	rbac              CapacityDispatchManifestPin
	historicalGrantID string
}

func installedTimeoutWire(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func (f *installedTimeoutFixture) exec(t *testing.T, q string, args ...any) {
	t.Helper()
	if _, err := f.db.Exec(q, args...); err != nil {
		t.Fatal("declared installed timeout fixture", err)
	}
}
func installedTimeoutPin(m model.Manifest) CapacityDispatchManifestPin {
	return CapacityDispatchManifestPin{ID: m.ID, Namespace: m.Metadata.Namespace, Name: m.Metadata.Name, Version: m.Version, Checksum: m.Checksum}
}
func (f *installedTimeoutFixture) envelope(t *testing.T) CapacityDispatchEnvelope {
	t.Helper()
	e := CapacityDispatchEnvelope{Protocol: CapacityDispatchProtocol, JobID: uuid.New(), RunID: uuid.New(), Realm: f.policy.Metadata.Namespace, Environment: f.p.Environment, Domain: f.p.Domain, Dimension: f.p.Dimension, SourceTick: time.Now().UTC().Format(time.RFC3339Nano), Policy: installedTimeoutPin(f.policy), Workflow: installedTimeoutPin(f.workflow), RBAC: f.rbac, MachinePrincipalID: "capacity-controller", PrincipalSHA256: capacityDispatchSHA([]byte("declared-principal")), BindingSHA256: capacityDispatchSHA([]byte("declared-binding"))}
	e.Inputs = map[string]any{"policy": map[string]any{"namespace": f.policy.Metadata.Namespace, "name": f.policy.Metadata.Name}}
	e.Metadata = map[string]any{WorkflowRunCreatorMachinePrincipalMetadataKey: e.MachinePrincipalID, "triggered_by": "workflow_scheduler", "manifest_id": f.workflow.ID.String(), "scheduled_for": e.SourceTick, "capacity_dispatch_job_id": e.JobID.String(), "capacity_dispatch_protocol": e.Protocol}
	var err error
	e.InputsSHA256, e.MetadataSHA256, err = CapacityDispatchEnvelopeHashes(e)
	if err != nil {
		t.Fatal(err)
	}
	return e
}
func (f *installedTimeoutFixture) enqueue(e CapacityDispatchEnvelope) (CapacityDispatchJob, bool, error) {
	tx, err := f.db.BeginTx(context.Background(), nil)
	if err != nil {
		return CapacityDispatchJob{}, false, err
	}
	defer tx.Rollback()
	j, coalesced, err := EnqueueCapacityDispatch(context.Background(), tx, e)
	if err != nil {
		return j, coalesced, err
	}
	return j, coalesced, tx.Commit()
}

func (f *installedTimeoutFixture) seedMember(t *testing.T, i int, omitInstallation bool) {
	t.Helper()
	pre, reg, receipt := f.pre[i], f.reg[i], f.receipts[i]
	witness := reg.Result.ProductionClock.Authority.CreateWitness
	tx, err := f.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	g := guestOriginalStorageFixture{pre: pre, binding: f.binding, wire: installedTimeoutWire(t, pre), bindingWire: installedTimeoutWire(t, f.binding)}
	guestOriginalStoragePre(t, tx, context.Background(), g, g.wire, g.wire, pre.OriginalDeadline)
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	mutation := f.p.MutationBindings[0]
	settlement := capacity.RecoveryFixtureInstalledTimeoutSettlement(pre, mutation, witness.Tuple, witness.OriginalCreateAttemptID)
	created := capacityMutationRecord{PolicyID: f.policy.ID, PolicyChecksum: f.policy.Checksum, WorkflowID: f.workflow.ID, Binding: mutation, Generation: pre.Generation, FencingToken: pre.Fence, ExecutorID: pre.ExecutorID, LeaseOwner: pre.LeaseOwner, AttemptID: witness.OriginalCreateAttemptID, Grant: model.CapacityMutationGrant{GrantID: pre.OriginalCreateGrantID, BindingName: mutation.Name, IntegrationInstanceID: mutation.IntegrationInstanceID, ScopeChecksum: mutation.ScopeChecksum, ProfileName: mutation.ProfileName, Slot: pre.Slot, Capability: mutation.EnsureCapability, RequestSHA256: pre.OriginalCreateRequestSHA256, State: "confirmed", ExpiresAt: pre.OriginalDeadline}, Settlement: &settlement, Proof: &model.CapacityMutationProof{Slot: pre.Slot, ResourceID: witness.Tuple.ResourceID, ResourceCreatedAt: witness.Tuple.CreatedAt}}
	f.exec(t, "UPDATE public.capacity_mutation_grants SET namespace=$2,environment=$3,domain=$4,dimension=$5,generation=$6,integration_instance_id=$7,scope_checksum=$8,profile_name=$9,slot=$10,state='confirmed',grant_record=$11::jsonb WHERE id=$1", pre.OriginalCreateGrantID, f.policy.Metadata.Namespace, f.p.Environment, f.p.Domain, f.p.Dimension, pre.Generation, mutation.IntegrationInstanceID, mutation.ScopeChecksum, mutation.ProfileName, pre.Slot, string(installedTimeoutWire(t, created)))
	f.exec(t, "INSERT INTO public.capacity_guest_original_create_witnesses(preregistration_id,original_create_attempt_id,resource_tuple_sha256,witness_sha256,original_wire,original_record,recorded_at)VALUES($1,$2,$3,$4,$5,$6::jsonb,$7)", pre.PreregistrationID, witness.OriginalCreateAttemptID, capacity.GuestRetirementSHA(witness.Tuple), capacity.GuestRetirementSHA(witness), installedTimeoutWire(t, witness), string(installedTimeoutWire(t, witness)), witness.ObservedAt)
	f.exec(t, "INSERT INTO public.capacity_vm_original_enrollments(preregistration_id,resource_tuple_sha256,enrollment_sha256,original_provisioning_sha256,enrollment_record,recorded_at,registration_wire,receipt_wire)VALUES($1,$2,$3,$4,$5::jsonb,$6,$7,$8)", pre.PreregistrationID, capacity.GuestRetirementSHA(receipt.Enrollment.Statement.Tuple), capacity.GuestRetirementSHA(receipt.Enrollment), receipt.OriginalProvisioningSHA256, string(installedTimeoutWire(t, receipt.Enrollment)), receipt.RecordedAt, installedTimeoutWire(t, reg), installedTimeoutWire(t, receipt))
	if !omitInstallation {
		confirmation := f.installed[i]
		f.exec(t, "INSERT INTO public.capacity_guest_original_installations(preregistration_id,original_wire,confirmation_sha256,recorded_at)VALUES($1,$2,$3,$4)", pre.PreregistrationID, installedTimeoutWire(t, confirmation), capacity.GuestRetirementSHA(confirmation), receipt.RecordedAt.Add(time.Second))
	}
	tx, err = f.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	slot := capacityResourceSlot{BindingName: mutation.Name, ProfileName: mutation.ProfileName, DesiredSpecSHA256: mutation.Slots[i].DesiredSpecSHA256, ResourceID: witness.Tuple.ResourceID, ResourceCreatedAt: witness.Tuple.CreatedAt, ObservedAt: time.Now().UTC(), ReceiptRef: "declared-installed-timeout-fixture"}
	if err = saveMutationSlot(context.Background(), tx, f.policy.Metadata.Namespace, f.p, mutation, i+1, slot); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func installedTimeoutDB(t *testing.T) *sql.DB {
	t.Helper()
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
		t.Fatal("explicit PG16/17 fixture major required")
	}
	adminURL := u.String()
	openAdmin := func() *sql.DB {
		admin, x := sql.Open("postgres", adminURL)
		if x != nil {
			t.Fatal(x)
		}
		admin.SetMaxOpenConns(1)
		admin.SetMaxIdleConns(1)
		var address string
		var major int
		if x = admin.QueryRow("SELECT COALESCE(inet_server_addr()::text,'unix'),current_setting('server_version_num')::int/10000").Scan(&address, &major); x != nil || !failedServingLocalServer(host, address) || major != want {
			admin.Close()
			t.Fatal("actual isolated PostgreSQL identity/major differs", x)
		}
		return admin
	}
	admin := openAdmin()
	name := "failed_serving_fixture_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err = admin.Exec("CREATE DATABASE " + pq.QuoteIdentifier(name)); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	if err = admin.Close(); err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + name
	db, err := sql.Open("postgres", u.String())
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	t.Cleanup(func() {
		if e := db.Close(); e != nil {
			t.Error("work database close", e)
		}
		cleanup := openAdmin()
		if _, e := cleanup.Exec("DROP DATABASE " + pq.QuoteIdentifier(name) + " WITH (FORCE)"); e != nil {
			t.Error("disposable database cleanup", e)
		}
		if e := cleanup.Close(); e != nil {
			t.Error("cleanup admin close", e)
		}
	})
	var actual string
	if err = db.QueryRow("SELECT current_database()").Scan(&actual); err != nil || actual != name || !strings.HasPrefix(actual, "failed_serving_fixture_") {
		t.Fatal("owned UUID database identity differs", err)
	}
	if err = goose.SetDialect("postgres"); err != nil {
		t.Fatal(err)
	}
	if err = goose.UpToContext(context.Background(), db, filepath.Join(failedServingRepositoryRoot(t), "db", "migrations"), 93); err != nil {
		t.Fatal("actual closed93 fixture prefix", err)
	}
	version, err := goose.GetDBVersion(db)
	if err != nil || version != 93 {
		t.Fatal("exact closed93 fixture prefix required", version, err)
	}
	return db
}

func installedTimeoutCatalog(t *testing.T, db *sql.DB) []byte {
	t.Helper()
	const query = "SELECT jsonb_build_object('server_version_num',current_setting('server_version_num')::int,'history_wire',(SELECT json_agg(row_to_json(g) ORDER BY id)::text FROM public.goose_db_version g),'functions',(SELECT jsonb_agg(jsonb_build_object('name',p.proname,'arguments',pg_get_function_identity_arguments(p.oid),'definition',pg_get_functiondef(p.oid)) ORDER BY p.proname,pg_get_function_identity_arguments(p.oid)) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public' AND p.prokind='f'),'constraints',(SELECT jsonb_agg(jsonb_build_object('table',r.relname,'name',c.conname,'kind',c.contype,'validated',c.convalidated,'definition',pg_get_constraintdef(c.oid,false)) ORDER BY r.relname,c.conname) FROM pg_constraint c JOIN pg_class r ON r.oid=c.conrelid JOIN pg_namespace n ON n.oid=r.relnamespace WHERE n.nspname='public' AND r.relname IN('capacity_dispatch_jobs','capacity_dispatch_installed_provision_timeout_dispositions','capacity_guest_retirement_forwards','capacity_guest_retirement_forward_reads','capacity_intents','capacity_guest_authority_issues','workflow_runs')),'triggers',(SELECT jsonb_agg(jsonb_build_object('table',r.relname,'name',g.tgname,'enabled',g.tgenabled,'definition',pg_get_triggerdef(g.oid,false)) ORDER BY r.relname,g.tgname) FROM pg_trigger g JOIN pg_class r ON r.oid=g.tgrelid JOIN pg_namespace n ON n.oid=r.relnamespace WHERE n.nspname='public' AND NOT g.tgisinternal AND r.relname IN('capacity_dispatch_jobs','capacity_dispatch_installed_provision_timeout_dispositions','capacity_guest_retirement_forwards','capacity_guest_retirement_forward_reads','capacity_intents','capacity_guest_authority_issues','workflow_runs')),'columns',(SELECT jsonb_agg(jsonb_build_object('table',r.relname,'name',a.attname,'number',a.attnum,'type',format_type(a.atttypid,a.atttypmod),'not_null',a.attnotnull) ORDER BY r.relname,a.attnum) FROM pg_attribute a JOIN pg_class r ON r.oid=a.attrelid JOIN pg_namespace n ON n.oid=r.relnamespace WHERE n.nspname='public' AND a.attnum>0 AND NOT a.attisdropped AND r.relname IN('capacity_dispatch_jobs','capacity_dispatch_installed_provision_timeout_dispositions')))::text"
	var raw []byte
	if err := db.QueryRow(query).Scan(&raw); err != nil {
		t.Fatal("complete actual PG schema catalog", err)
	}
	return raw
}

func installedTimeoutCatalogArtifact(t *testing.T, db *sql.DB, before []byte) {
	t.Helper()
	after := installedTimeoutCatalog(t, db)
	type function struct {
		Name       string
		Arguments  string
		Definition string
	}
	type row map[string]any
	type catalog struct {
		Version     int        `json:"server_version_num"`
		History     string     `json:"history_wire"`
		Functions   []function `json:"functions"`
		Constraints []row      `json:"constraints"`
		Triggers    []row      `json:"triggers"`
		Columns     []row      `json:"columns"`
	}
	var old, next catalog
	if json.Unmarshal(before, &old) != nil || json.Unmarshal(after, &next) != nil || old.Version != next.Version || (next.Version/10000 != 16 && next.Version/10000 != 17) {
		t.Fatal("actual PG16/17 before97 andafter98 catalog required")
	}
	var previous, current []map[string]any
	if json.Unmarshal([]byte(old.History), &previous) != nil || json.Unmarshal([]byte(next.History), &current) != nil || len(current) != len(previous)+1 || !reflect.DeepEqual(previous, current[:len(previous)]) || current[len(previous)]["version_id"] != float64(98) || current[len(previous)]["is_applied"] != true {
		t.Fatal("migration98 did not solely append to whole97 history")
	}
	functions := map[string]function{}
	for _, fn := range next.Functions {
		functions[fn.Name+"("+fn.Arguments+")"] = fn
	}
	changed := []string{}
	for _, fn := range old.Functions {
		got, ok := functions[fn.Name+"("+fn.Arguments+")"]
		if !ok {
			t.Fatal("migration98 removed prior public function", fn.Name)
		}
		if got != fn {
			if fn.Name != "guard_capacity_dispatch_job" {
				t.Fatal("migration98 rewrote unrelated prior function", fn.Name)
			}
			changed = append(changed, fn.Name)
		}
	}
	validAdded := false
	for _, fn := range next.Functions {
		if fn.Name == "installed_provision_timeout_valid" && fn.Definition != "" {
			validAdded = true
		}
	}
	if !validAdded {
		t.Fatal("actual typed M98 predicate not deparsed")
	}
	historical := func(rows []row) []row {
		out := []row{}
		for _, r := range rows {
			if r["table"] != "capacity_dispatch_jobs" && r["table"] != "capacity_dispatch_installed_provision_timeout_dispositions" {
				out = append(out, r)
			}
		}
		return out
	}
	if !reflect.DeepEqual(historical(old.Constraints), historical(next.Constraints)) {
		t.Fatal("M98 changed historical Root97 intent/authority/retirement constraints")
	}
	triggerByName := map[string]row{}
	for _, r := range next.Triggers {
		triggerByName[r["table"].(string)+"/"+r["name"].(string)] = r
	}
	for _, r := range old.Triggers {
		if !reflect.DeepEqual(r, triggerByName[r["table"].(string)+"/"+r["name"].(string)]) {
			t.Fatal("M98 rewrote historical trigger", r["name"])
		}
	}
	dispatch := func(rows []row) map[string]row {
		out := map[string]row{}
		for _, r := range rows {
			if r["table"] == "capacity_dispatch_jobs" {
				out[r["name"].(string)] = r
			}
		}
		return out
	}
	oldDispatch, newDispatch := dispatch(old.Constraints), dispatch(next.Constraints)
	for _, name := range []string{"capacity_dispatch_jobs_state_v9_check", "capacity_dispatch_jobs_lifecycle_v9_check"} {
		if oldDispatch[name] == nil || newDispatch[name] != nil {
			t.Fatal("old dispatch predicate replacement mismatch", name)
		}
		delete(oldDispatch, name)
	}
	for _, name := range []string{"capacity_dispatch_jobs_state_v10_check", "capacity_dispatch_jobs_lifecycle_v10_check"} {
		if newDispatch[name] == nil || newDispatch[name]["validated"] != true {
			t.Fatal("new dispatch predicate missing or unvalidated", name)
		}
		delete(newDispatch, name)
	}
	if !reflect.DeepEqual(oldDispatch, newDispatch) {
		t.Fatal("M98 changed unrelated dispatch constraints")
	}
	newConstraints, newColumns := 0, 0
	for _, r := range next.Constraints {
		if r["validated"] != true {
			t.Fatal("unvalidated schema98 constraint", r["name"])
		}
		if r["table"] == "capacity_dispatch_installed_provision_timeout_dispositions" {
			newConstraints++
		}
	}
	for _, r := range next.Columns {
		if r["table"] == "capacity_dispatch_installed_provision_timeout_dispositions" {
			newColumns++
		}
	}
	if newConstraints == 0 || newColumns != 10 {
		t.Fatal("exact new typed10-column table andvalidated predicates required", newColumns, newConstraints)
	}
	logs := os.Getenv("INSTALLED_TIMEOUT_LOGS")
	if logs == "" {
		return
	}
	put := func(name string, b []byte) map[string]any {
		p := filepath.Join(logs, name)
		f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			t.Fatal(err)
		}
		n, err := f.Write(b)
		if err != nil || n != len(b) {
			f.Close()
			t.Fatal("complete catalog original", n, err)
		}
		if err = f.Sync(); err != nil {
			f.Close()
			t.Fatal(err)
		}
		if err = f.Close(); err != nil {
			t.Fatal(err)
		}
		return map[string]any{"path": p, "sha256": capacity.BusinessCreationSHA256(b), "bytes": len(b)}
	}
	beforeRef := put("M98-PG-BEFORE97-CATALOG.original.json", before)
	afterRef := put("M98-PG-AFTER98-CATALOG.original.json", after)
	files, err := filepath.Glob(filepath.Join(failedServingRepositoryRoot(t), "db", "migrations", "00098_*.sql"))
	if err != nil || len(files) != 1 {
		t.Fatal("exact sole migration98 source", files, err)
	}
	sql, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	artifact := map[string]any{"schema": "installed_provision_timeout_schema98_pg_catalog_v1", "source_commit": capacity.CurrentGuestCoreSource(), "postgres_major": next.Version / 10000, "fixture_only": true, "native_authority": false, "before97_ref": beforeRef, "after98_ref": afterRef, "migration98_sha256": capacity.BusinessCreationSHA256(sql), "history_sole98_append": true, "old_public_functions_changed": changed, "historical97_constraints_and_triggers_unchanged": true, "new_table_columns": newColumns, "all_observed_constraints_validated": true}
	put("M98-PG-CHECK-DEPARSE.RESULT.PUBLIC.json", append(installedTimeoutWire(t, artifact), '\n'))
}

func installedTimeoutHistoricalFixture(t *testing.T, db *sql.DB, namespace, environment, domain, dimension string) dispositionPGFixture {
	t.Helper()
	ctx := context.Background()
	at := time.Now().UTC().Truncate(time.Second).Add(-2 * time.Hour)
	grantID, preID, policyID, wfID, instance, attempt := uuid.NewString(), uuid.NewString(), uuid.New(), uuid.New(), uuid.NewString(), uuid.NewString()
	ns := namespace
	profile := model.CapacityGuestProtectedProfileManifest{Schema: "original_guest_protected_profile_v1", Profile: "original", MutationBinding: "original", BootstrapSHA256: strings.Repeat("a", 64), OriginalProvisioningBudgetSeconds: 60, OriginalProvisioningStepID: "provision-original", Writers: []model.CapacityGuestProtectedWriterDefinition{}}
	desired := model.CapacityMutationSpecV1{SchemaVersion: "1", Capability: "ensure_ec2_instance", IntegrationInstanceID: instance, ScopeChecksum: strings.Repeat("b", 64), ProfileName: "original", Slot: 1, BootstrapSHA256: profile.BootstrapSHA256}
	requestSHA := originalDispositionJSONSHA(desired)
	binding := model.CapacityMutationBinding{OriginalProviderSourceCommit: strings.Repeat("c", 40), Name: "original", IntegrationInstanceID: instance, ScopeChecksum: desired.ScopeChecksum, ProfileName: "original", EnsureCapability: "ensure_ec2_instance", DestroyCapability: "terminate_ec2_instance", ProtectedSlots: 2, MaxSlots: 2, Slots: []model.CapacityMutationSlotBinding{{Slot: 1, DesiredSpecSHA256: requestSHA, DesiredSpec: &desired}}}
	guest := model.CapacityGuestRetirementBinding{MutationBindingName: binding.Name, CoreAuthoritySourceCommit: strings.Repeat("d", 40), ProfileManifest: profile, ProfileManifestSHA256: capacity.GuestRetirementSHA(profile), Members: []model.CapacityGuestRetirementMemberBinding{{Name: "original-member", Slot: 1}}}
	p := model.CapacityPolicySpec{Environment: environment, Domain: domain, Dimension: dimension, Floor: 2, Ceiling: 2, MaxEvidenceAgeSeconds: 30, GuestRetirementBinding: &guest, Profiles: []model.CapacityProfile{{Name: "original", Provider: "aws"}}}
	policyRaw, _ := json.Marshal(p)
	policy := model.Manifest{ID: policyID, Kind: "capacity_policy", Metadata: model.ManifestMetadata{Namespace: ns, Name: "original"}, Checksum: strings.Repeat("e", 64), Spec: policyRaw}
	wfSHA := strings.Repeat("f", 64)
	pre := model.CapacityGuestOriginalProvisioningPreregistration{Schema: capacity.GuestPreregistrationSchema, PreregistrationID: preID, BindingName: "original-member", OriginalCreateGrantID: grantID, OriginalCreateRequestSHA256: requestSHA, NonceSHA256: originalDispositionDigest([]byte(preID)), ProfileManifestSHA256: guest.ProfileManifestSHA256, PolicyID: policyID.String(), PolicyChecksum: policy.Checksum, WorkflowID: wfID.String(), WorkflowChecksum: wfSHA, OriginalWorkflowStepID: profile.OriginalProvisioningStepID, OriginalWorkflowStepTimeoutSeconds: 60, OriginalWorkflowContextDeadline: at.Add(time.Minute), CoreSourceCommit: guest.CoreAuthoritySourceCommit, Generation: 1, Fence: 1, LeaseOwner: uuid.NewString(), ExecutorID: uuid.NewString(), Slot: 1, OriginalDeadline: at.Add(time.Minute), ReservedAt: at}
	created := at.Add(time.Second).Format(time.RFC3339Nano)
	g := model.CapacityMutationGrant{GrantID: grantID, BindingName: binding.Name, IntegrationInstanceID: instance, ScopeChecksum: binding.ScopeChecksum, ProfileName: binding.ProfileName, Slot: 1, Capability: binding.EnsureCapability, RequestSHA256: requestSHA, State: "settled", ExpiresAt: pre.OriginalDeadline}
	original := &model.CapacityOriginalProviderCreateReturn{Schema: "aws_original_run_instances_return_v1", Provider: "aws", AdapterSourceCommit: binding.OriginalProviderSourceCommit, GrantID: grantID, AttemptID: attempt, RequestSHA256: requestSHA, ResourceID: "i-" + preID, ResourceCreatedAt: created, ActionID: "request-" + attempt, NextActionIDs: []string{}, CalledAt: at.Format(time.RFC3339Nano), ReturnedAt: at.Add(2 * time.Second).Format(time.RFC3339Nano), ContextDeadline: pre.OriginalDeadline.Format(time.RFC3339Nano), ResponseStatus: 200, ResponseBodySHA256: strings.Repeat("1", 64), ResponseBytes: 100}
	settlement := &model.CapacityMutationSettleRequest{OriginalProviderCreateReturn: original, GrantID: grantID, AttemptID: attempt, RequestSHA256: requestSHA, Outcome: "accepted", TransportCompleted: true, ResourceID: original.ResourceID, ResourceCreatedAt: created, ActionID: original.ActionID, NextActionIDs: []string{}, ObservedAt: at.Add(2 * time.Second).Format(time.RFC3339Nano), AuxiliaryResources: []model.CapacityMutationAuxiliaryResource{{Kind: "aws_ebs_volume", ID: "vol-" + preID, RequiresAbsence: true}, {Kind: "aws_network_interface", ID: "eni-" + preID, RequiresAbsence: true}}, AuxiliaryInventoryComplete: true}
	record := capacityMutationRecord{Grant: g, Binding: binding, PolicyID: policyID, PolicyChecksum: policy.Checksum, WorkflowID: wfID, Generation: 1, FencingToken: 1, LeaseOwner: pre.LeaseOwner, ExecutorID: pre.ExecutorID, CreatedAt: at, AttemptID: attempt, Settlement: settlement, EventProvider: "aws"}
	snapshot := model.CapacitySnapshot{Units: 0, Profile: "original", ObservedAt: at}
	intent := model.CapacityIntent{Namespace: ns, PolicyName: "original", PolicyID: policyID, PolicyChecksum: policy.Checksum, Environment: p.Environment, Domain: p.Domain, Dimension: p.Dimension, Generation: 1, FencingToken: 1, Phase: "preparing", LeaseOwner: pre.LeaseOwner, LeaseExecutorID: pre.ExecutorID, LeaseExpiresAt: &pre.OriginalDeadline, BaselineSnapshot: snapshot, Assessment: model.CapacityAssessment{Snapshot: snapshot}, Decision: model.CapacityDecision{Reason: "protected_floor_recovery", Profile: "original", Units: 2, Floor: 2, ExecutionPermitted: true}}
	f := dispositionPGFixture{db: db, store: CapacityStore{DB: db}, record: record, pre: pre, binding: guest, policy: policy, intent: intent, ctx: ctx}
	record, pre, guest, policy, intent = f.record, f.pre, f.binding, f.policy, f.intent
	g, binding = record.Grant, record.Binding
	policyRaw = policy.Spec
	if err := json.Unmarshal(policyRaw, &p); err != nil {
		t.Fatal("declared prepared policy", err)
	}
	must := func(q string, a ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q, a...); err != nil {
			t.Fatal(err)
		}
	}
	must(`INSERT INTO public.manifests(id,api_version,kind,namespace,name,version,checksum,spec,active) VALUES($1,'v1','capacity_policy',$2,'original',1,$3,$4::jsonb,false)`, policyID, ns, policy.Checksum, string(policyRaw))
	must(`INSERT INTO public.manifests(id,api_version,kind,namespace,name,version,checksum,spec,active) VALUES($1,'v1','workflow',$2,'original',1,$3,'{}'::jsonb,true)`, wfID, ns, wfSHA)
	raw, _ := json.Marshal(record)
	if len(f.initialGrantRaw) != 0 {
		raw = append([]byte(nil), f.initialGrantRaw...)
	}
	must(`INSERT INTO public.capacity_mutation_grants(id,namespace,environment,domain,dimension,generation,integration_instance_id,scope_checksum,profile_name,slot,state,grant_record,expires_at) VALUES($1,$2,$3,$4,$5,1,$6,$7,$8,1,'settled',$9::jsonb,$10)`, grantID, ns, p.Environment, p.Domain, p.Dimension, instance, binding.ScopeChecksum, binding.ProfileName, string(raw), g.ExpiresAt)
	preRaw, _ := json.Marshal(pre)
	bindingRaw, _ := json.Marshal(guest)
	must(`INSERT INTO public.capacity_vm_provisioning_preregistrations(id,create_grant_id,nonce_sha256,profile_manifest_sha256,preregistration_record,original_deadline,created_at,original_wire,binding_wire) VALUES($1,$2,$3,$4,$5::jsonb,$6,$7,$8,$9)`, preID, grantID, pre.NonceSHA256, pre.ProfileManifestSHA256, string(preRaw), pre.OriginalDeadline, pre.ReservedAt, preRaw, bindingRaw)
	intentRaw, _ := json.Marshal(intent)
	must(`INSERT INTO public.capacity_intents(namespace,environment,domain,dimension,intent,updated_at) VALUES($1,$2,$3,$4,$5::jsonb,$6)`, ns, p.Environment, p.Domain, p.Dimension, string(intentRaw), at)
	var rawGrant string
	if err := db.QueryRow(`SELECT grant_record::text FROM public.capacity_mutation_grants WHERE id=$1`, grantID).Scan(&rawGrant); err != nil {
		t.Fatal(err)
	}
	f.rawGrant = rawGrant
	return f
}
func newInstalledTimeoutFixture(t *testing.T, n int, variant string) *installedTimeoutFixture {
	t.Helper()
	capacity.RecoveryFixtureApprovalScope(t)
	f := &installedTimeoutFixture{db: installedTimeoutDB(t), pre: make([]model.CapacityGuestOriginalProvisioningPreregistration, n), reg: make([]model.CapacityGuestOriginalProvisioningRegistration, n), receipts: make([]model.CapacityGuestOriginalProvisioningReceipt, n), installed: make([]model.CapacityGuestOriginalInstallationConfirmation, n)}
	if err := goose.UpToContext(context.Background(), f.db, failedServingRepositoryRoot(t)+"/db/migrations", 97); err != nil {
		t.Fatal("actual schema97 predecessor", err)
	}
	var before97 []byte
	if n == 8 {
		before97 = installedTimeoutCatalog(t, f.db)
	}
	if err := goose.UpToContext(context.Background(), f.db, failedServingRepositoryRoot(t)+"/db/migrations", 98); err != nil {
		t.Fatal("actual schema98", err)
	}
	if before97 != nil {
		installedTimeoutCatalogArtifact(t, f.db, before97)
	}
	if n == 8 {
		h := installedTimeoutHistoricalFixture(t, f.db, "dakasa-production", "production", "notify", "original_notify_hetzner_vm_members")
		historyCtx, cancelHistory := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancelHistory()
		owner, e := h.store.BeginOriginalCreateDisposition(historyCtx, h.pre.OriginalCreateGrantID, "declared-historical-owner")
		if e != nil {
			t.Fatal("genuine historical disposition Begin", e)
		}
		closed, e := h.store.CompleteOriginalCreateDisposition(historyCtx, owner, h.native(t, owner.Candidate()))
		if e != nil {
			t.Fatal("genuine historical disposition Complete", e)
		}
		var state, pointer string
		if e = f.db.QueryRow("SELECT state,original_disposition_id::text FROM public.capacity_mutation_grants WHERE id=$1", closed.GrantID).Scan(&state, &pointer); e != nil || state != "settled" || pointer != closed.ID {
			t.Fatal("genuine terminal SETTLED history", state, pointer, e)
		}
		f.historicalGrantID = closed.GrantID
	}
	if variant == "concurrent_wakes" {
		f.db.SetMaxOpenConns(2)
		f.db.SetMaxIdleConns(2)
	}
	historyAt := time.Now().UTC().Add(-60 * time.Second).Truncate(time.Microsecond)
	p, b, r, receipt, installed := capacity.RecoveryFixtureInstalledSlotDuring(t, 1, historyAt, historyAt.Add(420*time.Second))
	f.p, f.binding = p, b
	f.p.ExecutionEnabled, f.p.LeaseSeconds = true, 300
	if err := capacity.RegisterRecoveryFixtureApproval(f.p, b, "hetzner"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n-1; i++ {
		_, _, f.reg[i], f.receipts[i], f.installed[i] = capacity.RecoveryFixtureInstalledSlotDuring(t, i+1, historyAt, historyAt.Add(420*time.Second))
		f.pre[i] = f.reg[i].Result.ProductionClock.Authority.Preregistration
	}
	f.reg[0], f.receipts[0], f.installed[0] = r, receipt, installed
	f.pre[0] = r.Result.ProductionClock.Authority.Preregistration
	pre := f.pre[0]
	f.policy = model.Manifest{ID: uuid.MustParse(pre.PolicyID), Kind: "capacity_policy", Checksum: pre.PolicyChecksum, Version: 1, Metadata: model.ManifestMetadata{Namespace: "dakasa-production", Name: "installed-timeout-unit", Active: true}, Spec: installedTimeoutWire(t, f.p)}
	var err error
	f.steps, err = capacity.OriginalGuestReconcileGraph(f.policy, f.p)
	if err != nil {
		t.Fatal(err)
	}
	enabled, no := true, false
	wfSpec := model.WorkflowManifestSpec{Trigger: model.WorkflowTriggerSpec{Mode: "schedule", Enabled: &enabled, Schedule: &model.WorkflowScheduleTriggerSpec{CronExpression: "* * * * *", CatchupPolicy: "skip"}}, Authorization: &model.WorkflowAuthorizationSpec{RBAC: model.ManifestSelector{Namespace: "dakasa-production", Name: "unit-rbac"}}, DispatchMode: "async", InputSchema: model.WorkflowInputSchemaSpec{Required: []string{"policy"}, AdditionalProperties: &no, Properties: map[string]model.IntegrationSchemaProperty{"policy": {Type: "object"}}}, Steps: f.steps}
	f.workflow = model.Manifest{ID: uuid.MustParse(pre.WorkflowID), Kind: "workflow", Checksum: pre.WorkflowChecksum, Version: 1, Metadata: model.ManifestMetadata{Namespace: f.p.Workflow.Namespace, Name: f.p.Workflow.Name, Active: true}, Spec: installedTimeoutWire(t, wfSpec)}
	for _, m := range []model.Manifest{f.policy, f.workflow} {
		f.exec(t, "INSERT INTO public.manifests(id,api_version,kind,namespace,name,version,checksum,spec,active)VALUES($1,'v1',$2,$3,$4,1,$5,$6::jsonb,true)", m.ID, m.Kind, m.Metadata.Namespace, m.Metadata.Name, m.Checksum, string(m.Spec))
	}
	mutation := f.p.MutationBindings[0]
	f.exec(t, "INSERT INTO public.manifests(id,api_version,kind,namespace,name,version,checksum,spec,active)VALUES($1,'v1','integration_type','test-recovery','unit-type',1,$2,'{}'::jsonb,true)", mutation.IntegrationTypeID, mutation.IntegrationTypeChecksum)
	f.exec(t, "INSERT INTO public.manifests(id,api_version,kind,namespace,name,version,checksum,spec,active)VALUES($1,'v1','integration_instance','test-recovery','unit-instance',1,$2,$3::jsonb,true)", mutation.IntegrationInstanceID, mutation.IntegrationChecksum, string(installedTimeoutWire(t, map[string]any{"type_ref": map[string]any{"manifest_id": mutation.IntegrationTypeID}})))
	f.rbac = CapacityDispatchManifestPin{ID: uuid.New(), Namespace: f.policy.Metadata.Namespace, Name: "unit-rbac", Version: 1, Checksum: capacityDispatchSHA([]byte("declared-rbac"))}
	f.exec(t, "INSERT INTO public.manifests(id,api_version,kind,namespace,name,version,checksum,spec,active)VALUES($1,'v1','rbac',$2,$3,1,$4,'{}'::jsonb,true)", f.rbac.ID, f.rbac.Namespace, f.rbac.Name, f.rbac.Checksum)
	for i := 0; i < n-1; i++ {
		f.seedMember(t, i, false)
	}
	f.original = f.envelope(t)
	queued, coalesced, err := f.enqueue(f.original)
	if err != nil || coalesced || queued.JobID != f.original.JobID {
		t.Fatal("new original dispatch", coalesced, err)
	}
	f.job, err = ClaimCapacityDispatch(context.Background(), f.db, f.original.Realm, f.original.Environment, uuid.New(), 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	f.job, err = StartCapacityDispatch(context.Background(), f.db, f.job)
	if err != nil {
		t.Fatal(err)
	}
	if f.job.StartedAt == nil || f.job.LeaseExpiresAt == nil || f.job.LeaseExpiresAt.Sub(*f.job.StartedAt) < 4*time.Minute {
		t.Fatal("production original300s context must remain intact")
	}
	reserved := time.Now().UTC().Truncate(time.Microsecond)
	_, _, f.reg[n-1], f.receipts[n-1], f.installed[n-1] = capacity.RecoveryFixtureInstalledSlotDuring(t, n, reserved, *f.job.LeaseExpiresAt)
	selected := f.reg[n-1].Result.ProductionClock.Authority.Preregistration
	f.pre[n-1] = selected
	now := time.Now().UTC()
	snapshot, err := capacity.GuestReconcileSnapshot(f.policy, f.p, f.inventory(t, n-1, now), now)
	if err != nil {
		t.Fatal(err)
	}
	f.intent = model.CapacityIntent{Namespace: f.policy.Metadata.Namespace, PolicyName: f.policy.Metadata.Name, PolicyID: f.policy.ID, PolicyChecksum: f.policy.Checksum, Environment: f.p.Environment, Domain: f.p.Domain, Dimension: f.p.Dimension, Generation: selected.Generation, FencingToken: selected.Fence, Phase: "preparing", LeaseOwner: selected.LeaseOwner, LeaseExecutorID: selected.ExecutorID, LeaseExpiresAt: f.job.LeaseExpiresAt, Decision: model.CapacityDecision{Action: "expand", ExecutionPermitted: true, Profile: mutation.ProfileName, Units: n, Floor: 1}, BaselineSnapshot: snapshot, Assessment: model.CapacityAssessment{Snapshot: snapshot}, UpdatedAt: now}
	if variant == "live_original_lease" {
		expiry := f.job.LeaseExpiresAt.Add(5 * time.Second)
		f.intent.LeaseExpiresAt = &expiry
	}
	if variant == "current_epoch_changed" {
		f.intent.Generation++
	}
	if f.historicalGrantID != "" {
		// Declared initial current epoch after a real closed historical disposition.
		// Only the mutable intent changes; all historical originals remain exact.
		f.exec(t, "UPDATE public.capacity_intents SET intent=$5::jsonb,updated_at=$6 WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4", f.policy.Metadata.Namespace, f.p.Environment, f.p.Domain, f.p.Dimension, string(installedTimeoutWire(t, f.intent)), now)
	} else {
		f.exec(t, "INSERT INTO public.capacity_intents(namespace,environment,domain,dimension,intent,updated_at)VALUES($1,$2,$3,$4,$5::jsonb,$6)", f.policy.Metadata.Namespace, f.p.Environment, f.p.Domain, f.p.Dimension, string(installedTimeoutWire(t, f.intent)), now)
	}
	// No future storage timestamp: wait for the actual signed installation time.
	time.Sleep(time.Until(f.receipts[n-1].RecordedAt.Add(time.Second)) + time.Millisecond)
	f.seedMember(t, n-1, variant == "missing_or_foreign_installation")
	return f
}

func (f *installedTimeoutFixture) response(t *testing.T, stage string, returnedAt time.Time) model.RunWorkflowResponse {
	t.Helper()
	r := capacityDispatchResponse(f.original, "failed")
	r.StartedAt = *f.job.StartedAt
	r.FinishedAt = returnedAt
	selected := f.pre[len(f.pre)-1]
	var workflowSpec model.WorkflowManifestSpec
	if err := json.Unmarshal(f.workflow.Spec, &workflowSpec); err != nil {
		t.Fatal(err)
	}
	ordered, err := manifestengine.WorkflowExecutionOrder(workflowSpec)
	if err != nil {
		t.Fatal(err)
	}
	completed := false
	for _, spec := range ordered {
		skipAt := f.receipts[len(f.pre)-1].RecordedAt.Add(time.Second)
		if completed {
			skipAt = r.FinishedAt
		}
		step := model.WorkflowRunStepResult{ID: spec.ID, Kind: strings.ToLower(strings.TrimSpace(spec.Use.Kind)), Operation: manifestengine.NormalizeWorkflowStepOperation(spec), Capability: manifestengine.NormalizeWorkflowStepCapability(spec), Status: "skipped", StartedAt: skipAt, FinishedAt: skipAt}
		switch spec.ID {
		case "plan-original-guest":
			step.Status, step.Attempts = "succeeded", 1
			step.StartedAt = *f.job.StartedAt
			step.FinishedAt = selected.ReservedAt
			step.Metadata = map[string]any{"mode": "provision", "generation": selected.Generation, "fencing_token": selected.Fence, "lease_owner": selected.LeaseOwner, "slot": selected.Slot, "preregistration_id": ""}
		case "provision-original-notify":
			step.Status, step.Attempts = "succeeded", 1
			step.StartedAt = selected.ReservedAt
			step.FinishedAt = f.receipts[len(f.pre)-1].RecordedAt.Add(time.Second)
			step.Metadata = map[string]any{"preregistration": selected}
		case "retire-original-guest", "refresh-original-membership":
			step.Metadata = map[string]any{"condition": spec.Condition, "skip_reason": "condition"}
		case "complete-original-provision":
			completed = true
			step.Status, step.Attempts, step.Error = "failed", 1, "original Guest reconciliation held"
			step.StartedAt = f.receipts[len(f.pre)-1].RecordedAt.Add(time.Second)
			step.FinishedAt = r.FinishedAt
			step.Metadata = map[string]any{"original_guest_reconcile_refusal_stage": stage}
		}
		r.Steps = append(r.Steps, step)
	}
	return r
}
func (f *installedTimeoutFixture) finish(t *testing.T, stage string, late bool) {
	t.Helper()
	if late {
		time.Sleep(time.Until(*f.job.LeaseExpiresAt) + 2*time.Millisecond)
	}
	var runErr error
	if late {
		runErr = context.DeadlineExceeded
	}
	returnedAt := time.Now().UTC().Truncate(time.Microsecond)
	err := FinishCapacityDispatch(context.Background(), f.db, f.job, f.response(t, stage, returnedAt), returnedAt, runErr)
	if late && !errors.Is(err, ErrCapacityDispatchUnknown) || !late && err != nil {
		t.Fatal("genuine original finalization", err)
	}
}
func (f *installedTimeoutFixture) preserved(t *testing.T) map[string]string {
	t.Helper()
	rows := map[string]string{}
	for _, table := range []string{"capacity_mutation_grants", "capacity_vm_provisioning_preregistrations", "capacity_guest_original_create_witnesses", "capacity_vm_original_enrollments", "capacity_guest_original_installations", "capacity_guest_notify_canary_challenges", "capacity_guest_notify_canary_sends", "capacity_guest_notify_canary_returns", "capacity_vm_retirement_intents", "capacity_vm_retirement_delete_bindings", "capacity_original_create_dispositions"} {
		var wire string
		if err := f.db.QueryRow("SELECT COALESCE(jsonb_agg(to_jsonb(x) ORDER BY to_jsonb(x)::text)::text,'[]') FROM public." + table + " x").Scan(&wire); err != nil {
			t.Fatal(err)
		}
		rows[table] = wire
	}
	var run string
	if err := f.db.QueryRow("SELECT row_to_json(w)::text FROM public.workflow_runs w WHERE id=$1", f.original.RunID).Scan(&run); err != nil {
		t.Fatal(err)
	}
	rows["original_run"] = run
	return rows
}
func (f *installedTimeoutFixture) inventory(t *testing.T, count int, now time.Time) model.CapacityVMFleetInventory {
	t.Helper()
	inv := capacity.RecoveryFixtureInventory(t, f.p, f.reg[0], now)
	first := inv.Members[0]
	inv.Members = nil
	inv.MissingSlots = nil
	for i, reg := range f.reg[:count] {
		member := first
		member.Slot, member.Protected = i+1, i+1 <= f.p.MutationBindings[0].ProtectedSlots
		member.DesiredSpec = *f.p.MutationBindings[0].Slots[i].DesiredSpec
		member.RequestSHA256 = f.p.MutationBindings[0].Slots[i].DesiredSpecSHA256
		member.Server.ID, member.Server.CreatedAt, member.Server.Name = reg.Result.Tuple.ResourceID, reg.Result.Tuple.CreatedAt, member.DesiredSpec.NativeName
		member.Server.Labels = map[string]string{"yggdrasil.io/owner": f.p.Owner, "yggdrasil.io/scope": forwardFixtureVMLabelDigest(f.p.MutationBindings[0].ScopeChecksum), "yggdrasil.io/spec": forwardFixtureVMLabelDigest(member.DesiredSpec.ProfileChecksum), "yggdrasil.io/profile": f.p.MutationBindings[0].ProfileName, "yggdrasil.io/slot": string(rune('0' + i + 1))}
		inv.Members = append(inv.Members, member)
	}
	for i := count + 1; i <= 8; i++ {
		inv.MissingSlots = append(inv.MissingSlots, i)
	}
	return inv
}

func (f *installedTimeoutFixture) resume(t *testing.T, newJob CapacityDispatchJob, typed bool) model.CapacityIntent {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	now := time.Now().UTC()
	inv := f.inventory(t, len(f.reg), now)
	snapshot, err := capacity.GuestReconcileSnapshot(f.policy, f.p, inv, now)
	if err != nil {
		t.Fatal(err)
	}
	assessment := model.CapacityAssessment{Snapshot: snapshot}
	store := CapacityStore{DB: f.db, ExecutionEnabled: true, WorkflowID: f.workflow.ID, OriginalRunID: newJob.RunID, ExecutorID: uuid.NewString(), guestReconcile: &guestReconcileSource{workflow: f.workflow, step: f.steps[0], source: capacity.CurrentGuestCoreSource(), inventory: inv}}
	got, eligible, err := store.TryResumeInstalledGuest(ctx, f.policy, assessment)
	if err != nil || !eligible {
		t.Fatal("fresh read-only installed resume", eligible, err)
	}
	if got.Generation != f.intent.Generation || got.FencingToken != f.intent.FencingToken+1 || got.LeaseOwner == f.intent.LeaseOwner || got.InstalledGuestReconcile == nil || (got.InstalledGuestReconcile.InstalledProvisionTimeoutDispositionID != "") != typed {
		t.Fatal("resume did not retain typed origin and fresh owner")
	}
	_, duplicate, err := store.TryResumeInstalledGuest(ctx, f.policy, assessment)
	if err != nil || duplicate {
		t.Fatal("live new lease duplicated recovery", duplicate, err)
	}
	return got
}

func (f *installedTimeoutFixture) sqlProofVectors(t *testing.T) {
	t.Helper()
	var recordRaw, dispatchRaw, runRaw, intentRaw, membersRaw []byte
	if err := f.db.QueryRow("SELECT original_record::text,original_dispatch_wire,original_run_wire,original_intent_wire,members_wire FROM public.capacity_dispatch_installed_provision_timeout_dispositions WHERE job_id=$1", f.original.JobID).Scan(&recordRaw, &dispatchRaw, &runRaw, &intentRaw, &membersRaw); err != nil {
		t.Fatal(err)
	}
	clone := func(raw []byte) map[string]any {
		var v map[string]any
		if err := json.Unmarshal(raw, &v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	check := func(label string, r map[string]any, d, w, i, m []byte, want bool) {
		var valid bool
		err := f.db.QueryRow("SELECT public.installed_provision_timeout_valid($1::jsonb,$2::bytea,$3::bytea,$4::bytea,$5::bytea)", string(installedTimeoutWire(t, r)), d, w, i, m).Scan(&valid)
		if err != nil || valid != want {
			t.Fatalf("M98 real immutable proof %s: valid=%v want=%v err=%v", label, valid, want, err)
		}
	}
	check("whole original", clone(recordRaw), dispatchRaw, runRaw, intentRaw, membersRaw, true)

	var workflowSpec model.WorkflowManifestSpec
	if err := json.Unmarshal(f.workflow.Spec, &workflowSpec); err != nil {
		t.Fatal(err)
	}
	checkResult := func(label string, run map[string]any, want bool) {
		got := installedProvisionTimeoutResult(installedTimeoutWire(t, run["result"]), f.pre[len(f.pre)-1], f.intent, f.original.Workflow, workflowSpec)
		if got != want {
			t.Fatalf("original conditional-skip result %s: got=%v want=%v", label, got, want)
		}
	}
	checkResult("authentic conditional skips", clone(runRaw), true)
	for _, vector := range []struct {
		step  int
		fault string
	}{
		{2, "condition"}, {3, "condition"}, {2, "reason"}, {3, "reason"},
		{2, "extra"}, {3, "extra"}, {2, "empty"}, {3, "empty"},
		{5, "extra"}, {6, "extra"},
	} {
		modified := clone(runRaw)
		result := modified["result"].(map[string]any)
		step := result["steps"].([]any)[vector.step].(map[string]any)
		metadata, _ := step["metadata"].(map[string]any)
		if metadata == nil {
			metadata = map[string]any{}
		}
		step["metadata"] = metadata
		switch vector.fault {
		case "condition":
			metadata["condition"] = "{{ steps.plan-original-guest.metadata.mode }} == provision"
		case "reason":
			metadata["skip_reason"] = "other"
		case "extra":
			metadata["extra"] = true
		case "empty":
			step["metadata"] = map[string]any{}
		}
		label := step["id"].(string) + " " + vector.fault
		checkResult(label, modified, false)
		changed := installedTimeoutWire(t, modified)
		record := clone(recordRaw)
		record["original_run_sha256"] = capacity.BusinessCreationSHA256(changed)
		check("resealed conditional skip "+label, record, dispatchRaw, changed, intentRaw, membersRaw, false)
	}
	for _, field := range []string{"schema", "original_dispatch_sha256", "original_run_sha256", "original_intent_sha256", "members_sha256", "policy_checksum"} {
		r := clone(recordRaw)
		r[field] = "foreign"
		check("changed "+field, r, dispatchRaw, runRaw, intentRaw, membersRaw, false)
	}
	r := clone(recordRaw)
	delete(r, "executor_id")
	check("missing required executor", r, dispatchRaw, runRaw, intentRaw, membersRaw, false)
	r = clone(recordRaw)
	r["extra_authority"] = true
	check("extra proof field", r, dispatchRaw, runRaw, intentRaw, membersRaw, false)
	r = clone(recordRaw)
	r["generation"] = true
	check("boolean is not generation", r, dispatchRaw, runRaw, intentRaw, membersRaw, false)
	for _, field := range []string{"policy_id", "job_id", "run_id", "lease_owner", "executor_id", "preregistration_id", "create_grant_id"} {
		r := clone(recordRaw)
		r[field] = uuid.NewString()
		check("foreign "+field, r, dispatchRaw, runRaw, intentRaw, membersRaw, false)
	}
	// Reseal the exact modified raw domain, so these vectors must fail on
	// semantic joins rather than a superficial enclosing hash mismatch.
	d := clone(dispatchRaw)
	d["finalization_ack_at"] = time.Now().UTC().Format(time.RFC3339Nano)
	changed := installedTimeoutWire(t, d)
	r = clone(recordRaw)
	r["original_dispatch_sha256"] = capacity.BusinessCreationSHA256(changed)
	check("resealed fabricated original ACK", r, changed, runRaw, intentRaw, membersRaw, false)
	d = clone(dispatchRaw)
	d["state"] = "returned"
	changed = installedTimeoutWire(t, d)
	r = clone(recordRaw)
	r["original_dispatch_sha256"] = capacity.BusinessCreationSHA256(changed)
	check("resealed original no longer unknown", r, changed, runRaw, intentRaw, membersRaw, false)
	w := clone(runRaw)
	result := w["result"].(map[string]any)
	for _, raw := range result["steps"].([]any) {
		step := raw.(map[string]any)
		if step["id"] == "complete-original-provision" {
			step["metadata"] = map[string]any{"original_guest_reconcile_refusal_stage": "fresh_original_canary"}
		}
	}
	changed = installedTimeoutWire(t, w)
	r = clone(recordRaw)
	r["original_run_sha256"] = capacity.BusinessCreationSHA256(changed)
	check("resealed different failed source stage", r, dispatchRaw, changed, intentRaw, membersRaw, false)
	i := clone(intentRaw)
	i["fencing_token"] = float64(f.intent.FencingToken + 1)
	changed = installedTimeoutWire(t, i)
	r = clone(recordRaw)
	r["original_intent_sha256"] = capacity.BusinessCreationSHA256(changed)
	check("resealed changed current fence", r, dispatchRaw, runRaw, changed, membersRaw, false)
	var members []map[string]any
	if err := json.Unmarshal(membersRaw, &members); err != nil {
		t.Fatal(err)
	}
	members[0]["installation_sha256"] = strings.Repeat("f", 64)
	changed = installedTimeoutWire(t, members)
	r = clone(recordRaw)
	r["members"] = members
	r["members_sha256"] = capacity.BusinessCreationSHA256(changed)
	check("resealed foreign immutable installation", r, dispatchRaw, runRaw, intentRaw, changed, false)
	if err := json.Unmarshal(membersRaw, &members); err != nil {
		t.Fatal(err)
	}
	members = append(members, members[0])
	changed = installedTimeoutWire(t, members)
	r = clone(recordRaw)
	r["members"] = members
	r["members_sha256"] = capacity.BusinessCreationSHA256(changed)
	check("resealed duplicate member", r, dispatchRaw, runRaw, intentRaw, changed, false)
	if err := json.Unmarshal(membersRaw, &members); err != nil {
		t.Fatal(err)
	}
	members = members[:len(members)-1]
	changed = installedTimeoutWire(t, members)
	r = clone(recordRaw)
	r["members"] = members
	r["members_sha256"] = capacity.BusinessCreationSHA256(changed)
	check("resealed omitted member", r, dispatchRaw, runRaw, intentRaw, changed, false)
	if err := json.Unmarshal(membersRaw, &members); err != nil {
		t.Fatal(err)
	}
	members[0], members[1] = members[1], members[0]
	changed = installedTimeoutWire(t, members)
	r = clone(recordRaw)
	r["members"] = members
	r["members_sha256"] = capacity.BusinessCreationSHA256(changed)
	check("resealed reordered current roster", r, dispatchRaw, runRaw, intentRaw, changed, false)
	// SQL storage protects the receipt itself independently of the Go writer.
	tx, err := f.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	_, err = tx.Exec("UPDATE public.capacity_dispatch_installed_provision_timeout_dispositions SET recorded_at=recorded_at+interval '1 second' WHERE job_id=$1", f.original.JobID)
	_ = tx.Rollback()
	var pg *pq.Error
	if !errors.As(err, &pg) || string(pg.Code) != "P0001" || pg.Message != "installed timeout disposition is immutable" {
		t.Fatal("immutable terminal receipt UPDATE refused for wrong reason", err)
	}
	tx, err = f.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	_, err = tx.Exec("DELETE FROM public.capacity_dispatch_installed_provision_timeout_dispositions WHERE job_id=$1", f.original.JobID)
	_ = tx.Rollback()
	pg = nil
	if !errors.As(err, &pg) || string(pg.Code) != "P0001" || pg.Message != "installed timeout disposition is immutable" {
		t.Fatal("immutable terminal receipt DELETE refused for wrong reason", err)
	}
}

func (f *installedTimeoutFixture) undisposedHistoricalBoundary(t *testing.T) {
	t.Helper()
	if f.historicalGrantID == "" {
		t.Fatal("real historical disposition required")
	}
	tx, err := f.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	// Existing legacy-grant fixture pattern: a new settled original with no
	// closure holds authority. Both this row and its coalesced wake roll back.
	_, err = tx.Exec("INSERT INTO public.capacity_mutation_grants(id,namespace,environment,domain,dimension,generation,integration_instance_id,scope_checksum,profile_name,slot,state,grant_record,expires_at) SELECT $2,namespace,environment,domain,dimension,generation,integration_instance_id,scope_checksum,profile_name,slot,'settled','{}'::jsonb,clock_timestamp()+interval '1 minute' FROM public.capacity_mutation_grants WHERE id=$1", f.historicalGrantID, uuid.NewString())
	if err != nil {
		t.Fatal("declared unresolved original", err)
	}
	next := f.envelope(t)
	got, merged, err := EnqueueCapacityDispatch(context.Background(), tx, next)
	if err != nil || !merged || got.JobID != f.job.JobID {
		t.Fatal("undisposed settled original did not retain unknown job", merged, err)
	}
	var receipts int
	if err = tx.QueryRow("SELECT count(*) FROM public.capacity_dispatch_installed_provision_timeout_dispositions").Scan(&receipts); err != nil || receipts != 0 {
		t.Fatal("unresolved original admitted terminal receipt", receipts, err)
	}
	if err = tx.Rollback(); err != nil {
		t.Fatal(err)
	}
}

func TestInstalledProvisionTimeoutRecoveryPostgres(t *testing.T) {
	for _, name := range []string{"two_members", "eight_members", "live_original_lease", "wrong_failure_stage", "current_epoch_changed", "missing_or_foreign_installation", "concurrent_wakes", "old_ACK_origin"} {
		t.Run(name, func(t *testing.T) {
			n := 2
			if name == "eight_members" {
				n = 8
			}
			f := newInstalledTimeoutFixture(t, n, name)
			if name == "live_original_lease" {
				e := f.envelope(t)
				j, coalesced, err := f.enqueue(e)
				if err != nil || !coalesced || j.JobID != f.job.JobID {
					t.Fatal("live original was not retained", coalesced, err)
				}
				var count int
				if err = f.db.QueryRow("SELECT count(*) FROM public.capacity_dispatch_installed_provision_timeout_dispositions").Scan(&count); err != nil || count != 0 {
					t.Fatal("live original acquired terminal receipt", count, err)
				}
				f.finish(t, "source_assessment", true)
				if !time.Now().Before(*f.intent.LeaseExpiresAt) {
					t.Fatal("fixture missed genuine live intent lease boundary")
				}
				pending := f.envelope(t)
				j, coalesced, err = f.enqueue(pending)
				if err != nil || !coalesced || j.JobID != f.job.JobID {
					t.Fatal("unknown original with live intent lease was not retained", coalesced, err)
				}
				if err = f.db.QueryRow("SELECT count(*) FROM public.capacity_dispatch_installed_provision_timeout_dispositions").Scan(&count); err != nil || count != 0 {
					t.Fatal("unexpired original intent acquired terminal receipt", count, err)
				}
				return
			}
			stage := "source_assessment"
			if name == "wrong_failure_stage" {
				stage = "fresh_original_canary"
			}
			if name == "concurrent_wakes" {
				for count := 1; count < MaxCapacityDispatchPendingWakes; count++ {
					wake := f.envelope(t)
					got, merged, x := f.enqueue(wake)
					if x != nil || !merged || got.JobID != f.job.JobID {
						t.Fatal("original pending wake accumulation", merged, x)
					}
				}
				_, _, x := f.enqueue(f.envelope(t))
				if !errors.Is(x, ErrCapacityDispatchSaturated) {
					t.Fatal("unchanged pending wake cap not enforced before closure", x)
				}
			}
			f.finish(t, stage, name != "old_ACK_origin")
			if name == "old_ACK_origin" {
				time.Sleep(time.Until(*f.intent.LeaseExpiresAt) + 2*time.Millisecond)
			}
			if name == "eight_members" {
				f.undisposedHistoricalBoundary(t)
			}
			before := f.preserved(t)
			if name == "old_ACK_origin" {
				var count int
				rows, err := f.db.Query(installedGuestOriginalFailedRunQuery, f.workflow.ID, f.pre[n-1].PreregistrationID, time.Now().UTC(), uuid.New())
				if err != nil {
					t.Fatal(err)
				}
				for rows.Next() {
					count++
				}
				err = rows.Err()
				rows.Close()
				if err != nil || count != 1 {
					t.Fatal("old acknowledged original path changed", count, err)
				}
			}
			e := f.envelope(t)
			var j CapacityDispatchJob
			var coalesced bool
			var err error
			if name == "concurrent_wakes" {
				type answer struct {
					job    CapacityDispatchJob
					merged bool
					err    error
				}
				replies := make(chan answer, 4)
				candidates := map[uuid.UUID]CapacityDispatchEnvelope{}
				var wg sync.WaitGroup
				for i := 0; i < 4; i++ {
					wake := f.envelope(t)
					candidates[wake.JobID] = wake
					wg.Add(1)
					go func() { defer wg.Done(); got, merged, x := f.enqueue(wake); replies <- answer{got, merged, x} }()
				}
				wg.Wait()
				close(replies)
				fresh := 0
				joined := []uuid.UUID{}
				for answer := range replies {
					if answer.err != nil {
						t.Fatal("concurrent terminal admission", answer.err)
					}
					joined = append(joined, answer.job.JobID)
					if !answer.merged {
						fresh++
						j = answer.job
						e = candidates[j.JobID]
					}
				}
				if fresh != 1 || j.JobID == uuid.Nil {
					t.Fatal("concurrent wakes did not create exactlyone fresh plan", fresh)
				}
				for _, id := range joined {
					if id != j.JobID {
						t.Fatal("concurrent wake selected foreign or historical job", id)
					}
				}
			} else {
				j, coalesced, err = f.enqueue(e)
			}
			negative := name == "wrong_failure_stage" || name == "current_epoch_changed" || name == "missing_or_foreign_installation"
			if negative {
				if err != nil || !coalesced || j.JobID != f.job.JobID {
					t.Fatal("ineligible unknown original was not retained", coalesced, err)
				}
				var count int
				if err = f.db.QueryRow("SELECT count(*) FROM public.capacity_dispatch_installed_provision_timeout_dispositions").Scan(&count); err != nil || count != 0 {
					t.Fatal("ineligible original acquired terminal receipt", count, err)
				}
				if !reflect.DeepEqual(before, f.preserved(t)) {
					t.Fatal("refused disposition changed original evidence")
				}
				return
			}
			if err != nil || coalesced || j.JobID != e.JobID || j.RunID != e.RunID {
				t.Fatal("new distinct queued plan unavailable", coalesced, err)
			}
			if name == "old_ACK_origin" {
				var count int
				if err = f.db.QueryRow("SELECT count(*) FROM public.capacity_dispatch_installed_provision_timeout_dispositions").Scan(&count); err != nil || count != 0 {
					t.Fatal("old ACK relabeled as unknown disposition", count, err)
				}
			}
			if name != "old_ACK_origin" {
				disposition, err := ReadCapacityDispatchInstalledProvisionTimeoutDisposition(context.Background(), f.db, f.original.JobID)
				if err != nil || disposition.JobID != f.original.JobID.String() || disposition.RunID != f.original.RunID.String() || len(disposition.Members) != n {
					t.Fatal("immutable typed disposition", disposition, err)
				}
				if name == "two_members" {
					f.sqlProofVectors(t)
				}
				old, err := readCapacityDispatchJob(context.Background(), f.db, f.original.JobID, false)
				var originalReturnStatus string
				statusErr := f.db.QueryRow("SELECT COALESCE(return_status,'') FROM public.capacity_dispatch_jobs WHERE id=$1", f.original.JobID).Scan(&originalReturnStatus)
				if err != nil || statusErr != nil || old.State != CapacityDispatchInstalledProvisionTimeoutState || old.FinalizationAckAt != nil || old.ReturnedAt == nil || originalReturnStatus != "failed" {
					t.Fatal("historical unknown return or absent ACK rewritten", old.State, err, statusErr)
				}
			}
			claimed, err := ClaimCapacityDispatch(context.Background(), f.db, e.Realm, e.Environment, uuid.New(), 30*time.Second)
			if err != nil || claimed.JobID != j.JobID {
				t.Fatal("new claim", err)
			}
			started, err := StartCapacityDispatch(context.Background(), f.db, claimed)
			if err != nil {
				t.Fatal(err)
			}
			f.resume(t, started, name != "old_ACK_origin")
			if !reflect.DeepEqual(before, f.preserved(t)) {
				t.Fatal("readiness recovery changed original/provider/Guest evidence")
			}
			var receipts int
			wantReceipts := 1
			if name == "old_ACK_origin" {
				wantReceipts = 0
			}
			if err = f.db.QueryRow("SELECT count(*) FROM public.capacity_dispatch_installed_provision_timeout_dispositions").Scan(&receipts); err != nil || receipts != wantReceipts {
				t.Fatal("terminal receipt was not unique", receipts, err)
			}
		})
	}
}
