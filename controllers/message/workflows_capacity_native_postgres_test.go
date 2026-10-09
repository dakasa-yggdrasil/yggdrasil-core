package message

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/manifest"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
)

func capacityNativeFixture(t *testing.T, input any) map[string]any {
	return capacitySourceFixture(t, "CAPACITY_NATIVE_FIXTURE_BINARY", "TestCapacityCoreNativeFixtureProducer", input)
}

func capacitySourceFixture(t *testing.T, binaryEnv, rootTest string, input any) map[string]any {
	t.Helper()
	binary := os.Getenv(binaryEnv)
	if binary == "" {
		t.Fatal("remote real-adapter fixture binary is required")
	}
	dir := t.TempDir()
	in, out := filepath.Join(dir, "input.json"), filepath.Join(dir, "output.json")
	raw, err := json.Marshal(input)
	if err != nil || os.WriteFile(in, raw, 0600) != nil {
		t.Fatal("fixture input could not be written", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, "-test.run=^"+rootTest+"$", "-test.count=1")
	cmd.Env = append(os.Environ(), "CAPACITY_NATIVE_INPUT_FILE="+in, "CAPACITY_NATIVE_OUTPUT_FILE="+out)
	if logs, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("reviewed native fixture producer failed: %v %s", err, logs)
	}
	raw, err = os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	if err = json.Unmarshal(raw, &value); err != nil {
		t.Fatal(err)
	}
	return value
}

// The native SDK is a separately compiled exact-source fixture, not a fake
// capability registry. The protected operation performs actual HTTP transport,
// Describe verification and durable PostgreSQL authority checks.
func TestCapacityMutationNativeWorkflowPostgres(t *testing.T) {
	dsn := os.Getenv("DB_URL")
	if dsn == "" {
		if os.Getenv("REQUIRE_CAPACITY_POSTGRES") == "true" {
			t.Fatal("capacity native PostgreSQL gate requires DB_URL")
		}
		t.Skip("remote PostgreSQL native bridge gate")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	ctx := newCapacityInvocationContext(context.Background())
	ns := "capacity-native-" + uuid.NewString()
	t.Cleanup(func() {
		for _, table := range []string{"event_log", "capacity_mutation_grants", "capacity_resource_slots", "capacity_intent_events", "capacity_intents", "manifests"} {
			query := `DELETE FROM public.` + table + ` WHERE namespace=$1`
			if table == "event_log" {
				query = `DELETE FROM public.event_log WHERE metadata->>'namespace'=$1`
			}
			if _, err := db.ExecContext(context.Background(), query, ns); err != nil {
				t.Error(err)
			}
		}
		db.Close()
	})
	iid, tid := uuid.New(), uuid.New()
	seed := capacityNativeFixture(t, map[string]any{"mode": "seed", "instance_id": iid.String(), "type_id": tid.String()})
	var typeSpec model.IntegrationTypeManifestSpec
	var describe model.AdapterDescribeResponse
	seedRaw, _ := json.Marshal(seed["describe"])
	if err := json.Unmarshal(seedRaw, &typeSpec); err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(seedRaw, &describe); err != nil {
		t.Fatal(err)
	}
	// Only the IO route changes for the local CI fixture. Every action/resource,
	// schema and version is copied from the reviewed real Describe producer.
	typeSpec.Adapter.Transport = "http_json"
	typeSpec.Adapter.Queues = model.IntegrationAdapterQueue{}
	typeSpec.Adapter.Endpoints = model.IntegrationAdapterRoute{Describe: "/describe", Execute: "/execute"}
	// HTTP transport requires its fixed operator URL to be schema-declared.
	// This IO-only property does not alter any native action or fleet config.
	typeSpec.InstanceSchema.Properties["base_url"] = model.IntegrationSchemaProperty{Type: "string"}
	describe.Adapter, describe.InstanceSchema = typeSpec.Adapter, typeSpec.InstanceSchema
	if err = manifest.ValidateIntegrationTypeSpec(typeSpec); err != nil {
		t.Fatal("real Describe fixture must be registration-valid", err)
	}
	var members []map[string]any
	baselineCreated := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano)
	for slot := 1; slot <= 2; slot++ {
		members = append(members, map[string]any{"slot": slot, "id": 100 + slot, "created_at": baselineCreated, "grant_id": uuid.NewString()})
	}
	mode := "inventory"
	var receipt model.CapacityMutationReceipt
	nativeCreated := ""
	rpcCalls, describeCalls := 0, 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/describe" {
			describeCalls++
			json.NewEncoder(w).Encode(describe)
			return
		}
		if r.URL.Path != "/execute" || r.Method != http.MethodPost {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		rpcCalls++
		var request model.AdapterExecuteIntegrationRequest
		if json.NewDecoder(r.Body).Decode(&request) != nil || !strings.HasPrefix(request.Operation, "observe_") || request.Capability != request.Operation || len(request.Auth) != 0 || len(request.Metadata) != 0 {
			t.Error("protected observer widened its native request")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		value := capacityNativeFixture(t, map[string]any{"mode": mode, "request": request, "receipt": receipt, "members": members, "native_created_at": nativeCreated})
		if value["error"] != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		json.NewEncoder(w).Encode(value)
	}))
	t.Cleanup(server.Close)
	create := func(id uuid.UUID, kind, name string, spec any) model.Manifest {
		t.Helper()
		raw, err := json.Marshal(spec)
		if err != nil {
			t.Fatal(err)
		}
		checksum := fmt.Sprintf("%x", sha256.Sum256(raw))
		// Explicit UUIDs let the separate native fixture bind the exact stored
		// manifest-version identity. No fake stable logical identity is added.
		if _, err = db.ExecContext(ctx, `INSERT INTO public.manifests(id,api_version,kind,namespace,name,version,active,spec,checksum) VALUES($1,'yggdrasil.io/v1alpha1',$2,$3,$4,1,true,$5::jsonb,$6)`, id, kind, ns, name, raw, checksum); err != nil {
			t.Fatal(err)
		}
		m, err := repository.GetManifestByID(ctx, db, id)
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	ty := create(tid, "integration_type", "native-vm-type", typeSpec)
	config := seed["config"].(map[string]any)
	config["base_url"] = server.URL
	instance := create(iid, "integration_instance", "native-vm", model.IntegrationInstanceManifestSpec{TypeRef: model.ManifestSelector{ManifestID: tid.String()}, Status: "active", Config: config, Credentials: seed["credentials"].(map[string]any)})
	wf := create(uuid.New(), "workflow", "native-scale", model.WorkflowManifestSpec{Trigger: model.WorkflowTriggerSpec{Mode: "manual"}, Authorization: &model.WorkflowAuthorizationSpec{RBAC: model.ManifestSelector{Namespace: ns, Name: "capacity-rbac"}}, Steps: []model.WorkflowStepSpec{{ID: "inventory", Use: model.WorkflowStepUseSpec{Kind: "yggdrasil", Operation: "capacity.observe_vm_inventory"}}}})
	ref := manifestReferenceFromRecord(wf)
	var slots []model.CapacityMutationSlotBinding
	raw, _ := json.Marshal(seed["slots"])
	if err = json.Unmarshal(raw, &slots); err != nil || len(slots) != 4 {
		t.Fatal("native approved projections absent", err)
	}
	b := model.CapacityMutationBinding{Name: "native-vm", IntegrationInstanceID: iid.String(), IntegrationChecksum: instance.Checksum, IntegrationTypeID: tid.String(), IntegrationTypeChecksum: ty.Checksum, AdapterPrincipalID: "fleet-adapter", ScopeChecksum: slots[0].DesiredSpec.ScopeChecksum, ProfileName: "workers", EnsureCapability: "ensure_server", DestroyCapability: "destroy_server", ProtectedSlots: 1, MaxSlots: 4, Slots: slots}
	now := time.Now().UTC()
	p := model.CapacityPolicySpec{Environment: "production", Domain: "vm-workers", Dimension: "nodes", TargetIdentity: "fleet/native-vm", Owner: "capacity-native", Workflow: model.ManifestSelector{Namespace: ns, Name: wf.Metadata.Name}, Currency: "EUR", Floor: 1, Ceiling: 4, Step: 2, MaxEvidenceAgeSeconds: 60, MaxSampleGapSeconds: 30, MinSamples: 3, DownHoldSeconds: 60, LeaseSeconds: 120, ExecutionEnabled: true, Signals: []model.CapacitySignalRule{{Name: "load", SourceIdentity: "prom/queue", Unit: "ratio", UpAbove: .8, DownBelow: .3}}, Profiles: []model.CapacityProfile{{Name: "workers", Provider: "hetzner", Region: "nbg1", MinUnits: 1, MaxUnits: 4, UnitMonthlyCostMinor: 100, QuoteValidUntil: now.Add(time.Hour), ValidationValidUntil: now.Add(time.Hour), ValidationRef: "fixture:capacity-qualification-is-separate"}}, MutationBindings: []model.CapacityMutationBinding{b}}
	policy := create(uuid.New(), "capacity_policy", "workers", p)
	executor, _ := ctx.Value(capacityInvocationKey{}).(string)
	store := repository.CapacityStore{DB: db, ExecutionEnabled: true, WorkflowID: wf.ID, ExecutorID: executor}
	input := func() map[string]any {
		return map[string]any{"policy": map[string]any{"namespace": ns, "name": "workers"}, "binding_name": b.Name}
	}
	run := func(c context.Context, op string, value map[string]any) model.WorkflowRunStepResult {
		return executeCapacityNativeWorkflowStep(c, nil, db, ref, model.WorkflowRunStepResult{Kind: "yggdrasil", Operation: op, Status: "failed"}, value)
	}
	count := func() int {
		var n int
		if err := db.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_resource_slots WHERE namespace=$1`, ns).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	t.Run("readonly_real_adapter_inventory_has_no_authority", func(t *testing.T) {
		t.Setenv("YGGDRASIL_CAPACITY_EXECUTION_ENABLED", "false")
		got := run(ctx, "capacity.observe_vm_inventory", input())
		if got.Status != "succeeded" || got.Metadata["native_members"] != float64(2) || got.Metadata["useful_capacity_known"] != false || got.Metadata["registered"] != float64(0) || count() != 0 {
			t.Fatalf("read-only source became authority: %+v", got)
		}
	})
	t.Run("caller_scope_proof_and_unprotected_workflow_are_refused", func(t *testing.T) {
		before := rpcCalls
		for _, field := range []string{"proof", "complete", "warm_ready", "integration", "capability", "owner", "url"} {
			value := input()
			value[field] = true
			if run(ctx, "capacity.observe_vm_inventory", value).Status == "succeeded" {
				t.Fatal("caller assertion accepted", field)
			}
		}
		wrong := ref
		wrong.ID = uuid.New()
		got := executeCapacityNativeWorkflowStep(ctx, nil, db, wrong, model.WorkflowRunStepResult{Kind: "yggdrasil", Operation: "capacity.observe_vm_inventory", Status: "failed"}, input())
		if got.Status == "succeeded" || rpcCalls != before {
			t.Fatal("wrong protected workflow reached adapter")
		}
	})
	t.Run("native_collision_refuses_entire_inventory", func(t *testing.T) {
		mode = "collision"
		defer func() { mode = "inventory" }()
		if run(ctx, "capacity.observe_vm_inventory", input()).Status == "succeeded" || count() != 0 {
			t.Fatal("native drift gained coverage")
		}
	})
	load := .9
	a := model.CapacityAssessment{Snapshot: model.CapacitySnapshot{TargetIdentity: p.TargetIdentity, ResourceUID: "fleet-uid", ResourceVersion: "1", WorkloadUID: "workers-uid", WorkloadResourceVersion: "1", Owner: p.Owner, Profile: b.ProfileName, Units: 2, ObservedAt: now}, Evidence: []model.CapacityEvidence{{Name: "load", SourceIdentity: "prom/queue", Unit: "ratio", RequireData: true, Matched: true, DataState: "present", Value: &load, RangeMin: &load, RangeMax: &load, SourceSampledAt: now, WindowStart: now.Add(-time.Minute), WindowEnd: now, Samples: 10, CoverageComplete: true, MaxGapSeconds: 15}}}
	intent, err := store.Assess(ctx, policy, a)
	if err != nil {
		t.Fatal(err)
	}
	intent, err = store.Claim(ctx, policy, intent.Generation, a)
	if err != nil {
		t.Fatal(err)
	}
	leased := func() map[string]any {
		v := input()
		v["generation"], v["fencing_token"], v["lease_owner"] = intent.Generation, intent.FencingToken, intent.LeaseOwner
		return v
	}
	t.Setenv("YGGDRASIL_CAPACITY_EXECUTION_ENABLED", "true")
	t.Run("complete_inventory_registers_through_existing_lease", func(t *testing.T) {
		got := run(ctx, "capacity.record_vm_inventory", leased())
		if got.Status != "succeeded" || got.Metadata["registered"] != float64(2) || count() != 2 {
			t.Fatalf("registration failed: %+v", got)
		}
		before := rpcCalls
		if run(newCapacityInvocationContext(context.Background()), "capacity.record_vm_inventory", leased()).Status == "succeeded" || rpcCalls != before {
			t.Fatal("another invocation borrowed native registration lease")
		}
	})
	issue := func(slot int) model.CapacityMutationGrant {
		raw, _ := json.Marshal(slots[slot-1].DesiredSpec)
		g, e := store.IssueMutation(ctx, policy, intent.Generation, intent.FencingToken, intent.LeaseOwner, model.CapacityMutationIssue{BindingName: b.Name, DesiredSpec: raw})
		if e != nil {
			t.Fatal(e)
		}
		return g
	}
	settle := func(g model.CapacityMutationGrant, known bool) {
		nonce := strings.Repeat("a", 64)
		sum := sha256.Sum256([]byte(nonce))
		r := model.CapacityMutationRedeemRequest{GrantID: g.GrantID, AttemptID: uuid.NewString(), SettlementTokenSHA256: fmt.Sprintf("%x", sum), Capability: g.Capability, IntegrationInstanceID: g.IntegrationInstanceID, ScopeChecksum: g.ScopeChecksum, ProfileName: g.ProfileName, Slot: g.Slot, RequestSHA256: g.RequestSHA256}
		reply, e := store.RedeemMutation(ctx, b.AdapterPrincipalID, r)
		if e != nil || reply.Mode != "write_once" {
			t.Fatal("fixture redemption failed", e, reply)
		}
		nativeCreated = time.Now().UTC().Format(time.RFC3339Nano)
		s := model.CapacityMutationSettleRequest{GrantID: g.GrantID, AttemptID: r.AttemptID, RequestSHA256: g.RequestSHA256, Outcome: "uncertain", TransportCompleted: true, ObservedAt: time.Now().UTC().Format(time.RFC3339Nano)}
		if known {
			s.Outcome = "accepted"
			s.ResourceID = "100"
			s.ResourceCreatedAt = nativeCreated
			s.ActionID = "500"
			s.AuxiliaryInventoryComplete = true
			s.AuxiliaryResources = []model.CapacityMutationAuxiliaryResource{{Kind: "primary_ip", ID: "101", RequiresAbsence: true}}
		}
		if _, e = store.SettleMutation(ctx, b.AdapterPrincipalID, nonce, s); e != nil {
			t.Fatal(e)
		}
		receipt, e = store.NativeMutationReceipt(ctx, policy, b, g.GrantID)
		if e != nil {
			t.Fatal(e)
		}
	}
	t.Run("native_reads_confirm_once_without_readiness_claim", func(t *testing.T) {
		g := issue(3)
		settle(g, true)
		mode = "confirm"
		v := leased()
		v["grant_id"] = g.GrantID
		got := run(ctx, "capacity.confirm_native_mutation", v)
		if got.Status != "succeeded" || count() != 3 || got.Metadata["useful_capacity_known"] != false {
			t.Fatalf("native confirmation failed: %+v", got)
		}
		receipt, err = store.NativeMutationReceipt(ctx, policy, b, g.GrantID)
		if err != nil {
			t.Fatal(err)
		}
		if got = run(ctx, "capacity.confirm_native_mutation", v); got.Status != "succeeded" {
			t.Fatalf("readback replay failed: %+v", got)
		}
		var events int
		if err = db.QueryRowContext(ctx, `SELECT count(*) FROM public.event_log WHERE metadata->>'namespace'=$1`, ns).Scan(&events); err != nil || events != 1 {
			t.Fatal("native confirmation duplicated/missed canonical effect", events, err)
		}
		members = append(members, map[string]any{"slot": 3, "id": 100, "created_at": nativeCreated, "grant_id": g.GrantID})
	})
	t.Run("lost_failed_creation_is_explicit_unresolved_member", func(t *testing.T) {
		g := issue(4)
		settle(g, false)
		mode = "failed"
		v := input()
		v["parent_grant_id"], v["slot"] = g.GrantID, 4
		got := run(ctx, "capacity.observe_failed_vm_creation", v)
		if got.Status != "succeeded" {
			t.Fatalf("lost failed native readback failed: %+v", got)
		}
		raw, _ := json.Marshal(got.Metadata["mutation_proof"])
		var proof model.CapacityMutationProof
		json.Unmarshal(raw, &proof)
		if proof.ResourceID != "104" || proof.SpecVerified || !proof.CompensationIdentityVerified || !proof.ActionHistoryComplete || !proof.ActionsFailed || count() != 3 {
			t.Fatal("failed lifetime became physical/registered capacity", proof)
		}
		mode = "failed_inventory"
		got = run(ctx, "capacity.observe_vm_inventory", v)
		if got.Status != "succeeded" || got.Metadata["native_members"] != float64(4) || len(got.Metadata["mutation_proofs"].([]any)) != 3 || count() != 3 {
			t.Fatalf("unresolved member was dropped or counted as registered: %+v", got)
		}
		v = leased()
		v["parent_grant_id"], v["slot"] = g.GrantID, 4
		got = run(ctx, "capacity.record_vm_inventory", v)
		if got.Status != "succeeded" || got.Metadata["registered"] != float64(3) || count() != 3 {
			t.Fatalf("failed member altered serving ledger: %+v", got)
		}
		var state string
		if err = db.QueryRowContext(ctx, `SELECT state FROM public.capacity_mutation_grants WHERE id=$1`, g.GrantID).Scan(&state); err != nil || state != "settled" {
			t.Fatal("observer freed uncertain reserve", state, err)
		}
	})
	t.Run("paused_instance_and_old_type_refuse_current_reads", func(t *testing.T) {
		before := rpcCalls
		if _, err = db.ExecContext(ctx, `UPDATE public.manifests SET active=false WHERE id=$1`, iid); err != nil {
			t.Fatal(err)
		}
		if run(ctx, "capacity.observe_vm_inventory", input()).Status == "succeeded" || rpcCalls != before {
			t.Fatal("paused exact instance reached native API")
		}
		if _, err = db.ExecContext(ctx, `UPDATE public.manifests SET active=true WHERE id=$1`, iid); err != nil {
			t.Fatal(err)
		}
		if _, err = db.ExecContext(ctx, `UPDATE public.manifests SET checksum=$2 WHERE id=$1`, tid, strings.Repeat("0", 64)); err != nil {
			t.Fatal(err)
		}
		if run(ctx, "capacity.observe_vm_inventory", input()).Status == "succeeded" {
			t.Fatal("type revision drift accepted")
		}
	})
	t.Run("native_catalog_refuses_before_private_hydration", func(t *testing.T) {
		var bad model.IntegrationTypeManifestSpec
		raw, _ := json.Marshal(typeSpec)
		json.Unmarshal(raw, &bad)
		for i := range bad.ActionCatalog {
			if bad.ActionCatalog[i].Name == "observe_fleet_inventory" {
				bad.ActionCatalog[i].Category = "permission"
			}
		}
		typeRaw, _ := json.Marshal(bad)
		typeDigest := fmt.Sprintf("%x", sha256.Sum256(typeRaw))
		var spec model.IntegrationInstanceManifestSpec
		json.Unmarshal(instance.Spec, &spec)
		spec.CredentialsRef = "capacity-test://must-not-hydrate"
		instanceRaw, _ := json.Marshal(spec)
		instanceDigest := fmt.Sprintf("%x", sha256.Sum256(instanceRaw))
		if _, err = db.ExecContext(ctx, `UPDATE public.manifests SET spec=$2::jsonb,checksum=$3 WHERE id=$1`, tid, typeRaw, typeDigest); err != nil {
			t.Fatal(err)
		}
		if _, err = db.ExecContext(ctx, `UPDATE public.manifests SET spec=$2::jsonb,checksum=$3,active=true WHERE id=$1`, iid, instanceRaw, instanceDigest); err != nil {
			t.Fatal(err)
		}
		var nativePolicy model.CapacityPolicySpec
		json.Unmarshal(policy.Spec, &nativePolicy)
		nativePolicy.MutationBindings[0].IntegrationChecksum = instanceDigest
		nativePolicy.MutationBindings[0].IntegrationTypeChecksum = typeDigest
		badPolicy := create(uuid.New(), "capacity_policy", "native-catalog-denied", nativePolicy)
		before, beforeDescribe := rpcCalls, describeCalls
		value := map[string]any{"policy": map[string]any{"namespace": ns, "name": badPolicy.Metadata.Name}, "binding_name": b.Name}
		if run(ctx, "capacity.observe_vm_inventory", value).Status == "succeeded" || rpcCalls != before || describeCalls != beforeDescribe {
			t.Fatal("native invalid capability reached private transport")
		}
	})
}
