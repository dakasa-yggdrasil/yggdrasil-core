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
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/manifest"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
	amqp "github.com/rabbitmq/amqp091-go"
)

func TestCapacityMutationBoundAssessmentPostgres(t *testing.T) {
	dsn := os.Getenv("DB_URL")
	if dsn == "" {
		if os.Getenv("REQUIRE_CAPACITY_POSTGRES") == "true" {
			t.Fatal("bound source PostgreSQL gate requires DB_URL")
		}
		t.Skip("remote bound source gate")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	ctx := newCapacityInvocationContext(context.Background())
	ns := "capacity-bound-" + uuid.NewString()
	t.Cleanup(func() {
		for _, table := range []string{"capacity_intent_events", "capacity_intents", "manifests"} {
			if _, err := db.ExecContext(context.Background(), `DELETE FROM public.`+table+` WHERE namespace=$1`, ns); err != nil {
				t.Error(err)
			}
		}
		db.Close()
	})
	var mu sync.Mutex
	mode := "complete"
	calls, describes := 0, 0
	setMode := func(value string) { mu.Lock(); mode = value; mu.Unlock() }
	getCalls := func() int { mu.Lock(); defer mu.Unlock(); return calls }
	getDescribes := func() int { mu.Lock(); defer mu.Unlock(); return describes }
	metricAPI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		selected := mode
		mu.Unlock()
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/query_range" || r.ParseForm() != nil {
			t.Error("native range query route changed")
			w.WriteHeader(400)
			return
		}
		query := r.Form.Get("query")
		if query != "fixed-pressure" && query != "min(timestamp(fixed-source))" {
			t.Error("native query escaped approved binding")
			w.WriteHeader(400)
			return
		}
		start, _ := strconv.ParseInt(r.Form.Get("start"), 10, 64)
		end, _ := strconv.ParseInt(r.Form.Get("end"), 10, 64)
		if end-start != 60 || r.Form.Get("step") != "15" {
			t.Error("native range grid changed")
		}
		points := [][]any{}
		for at := start; at <= end; at += 15 {
			value := "0.9"
			if query == "min(timestamp(fixed-source))" {
				sample := at
				if selected == "stale" {
					sample -= 120
				}
				value = strconv.FormatInt(sample, 10)
			} else if selected == "non_finite" {
				value = "NaN"
			}
			points = append(points, []any{float64(at), value})
		}
		series := []any{map[string]any{"metric": map[string]string{"service": "api"}, "values": points}}
		if selected == "missing" {
			series = []any{}
		}
		if selected == "cardinality" {
			series = append(series, series[0])
		}
		json.NewEncoder(w).Encode(map[string]any{"status": "success", "data": map[string]any{"resultType": "matrix", "result": series}})
	}))
	t.Cleanup(metricAPI.Close)
	metricConfig := map[string]any{"prometheus_url": metricAPI.URL, "evidence_bindings": map[string]any{"api-pressure": map[string]any{"name": "load", "source_identity": "prom/api", "unit": "ratio", "value_query": "fixed-pressure", "source_timestamp_query": "min(timestamp(fixed-source))", "expected_labels": map[string]string{"service": "api"}, "window_seconds": 60, "step_seconds": 15, "max_source_age_seconds": 30, "max_gap_seconds": 15, "min_samples": 3}}}
	seedRequest := model.AdapterExecuteIntegrationRequest{Operation: capacity.ObserveMetricRange, Capability: capacity.ObserveMetricRange, Input: map[string]any{"binding": "api-pressure"}, Integration: model.AdapterExecuteIntegrationContext{InstanceSpec: model.IntegrationInstanceManifestSpec{Config: metricConfig}}}
	metricSeed := capacitySourceFixture(t, "CAPACITY_METRIC_FIXTURE_BINARY", "TestCapacityCoreMetricSourceFixtureProducer", map[string]any{"mode": "seed", "request": seedRequest})
	hpaSeed := capacitySourceFixture(t, "CAPACITY_HPA_FIXTURE_BINARY", "TestCapacityCoreHPASourceFixtureProducer", map[string]any{"mode": "seed"})
	var metricType, hpaType model.IntegrationTypeManifestSpec
	var metricDescribe, hpaDescribe model.AdapterDescribeResponse
	decode := func(value any, out any) {
		t.Helper()
		raw, _ := json.Marshal(value)
		if err := json.Unmarshal(raw, out); err != nil {
			t.Fatal(err)
		}
	}
	decode(metricSeed["describe"], &metricType)
	decode(metricSeed["describe"], &metricDescribe)
	decode(hpaSeed["describe"], &hpaType)
	decode(hpaSeed["describe"], &hpaDescribe)
	ioRoute := func(ts *model.IntegrationTypeManifestSpec, desc *model.AdapterDescribeResponse) {
		ts.Adapter.Transport = "http_json"
		ts.Adapter.Queues = model.IntegrationAdapterQueue{}
		ts.Adapter.Endpoints = model.IntegrationAdapterRoute{Describe: "/describe", Execute: "/execute"}
		ts.InstanceSchema.Properties["base_url"] = model.IntegrationSchemaProperty{Type: "string"}
		desc.Adapter, desc.InstanceSchema = ts.Adapter, ts.InstanceSchema
		if manifest.ValidateIntegrationTypeSpec(*ts) != nil {
			t.Fatal("actual source registry is invalid")
		}
	}
	ioRoute(&metricType, &metricDescribe)
	ioRoute(&hpaType, &hpaDescribe)
	adapterServer := func(desc model.AdapterDescribeResponse, binaryEnv, rootTest string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/describe" {
				mu.Lock()
				describes++
				mu.Unlock()
				json.NewEncoder(w).Encode(desc)
				return
			}
			if r.Method != http.MethodPost || r.URL.Path != "/execute" {
				w.WriteHeader(404)
				return
			}
			mu.Lock()
			calls++
			selected := mode
			mu.Unlock()
			var request model.AdapterExecuteIntegrationRequest
			if json.NewDecoder(r.Body).Decode(&request) != nil || !strings.HasPrefix(request.Operation, "observe_") || request.Capability != request.Operation || len(request.Auth) != 0 || len(request.Metadata) != 0 {
				t.Error("fixed source request authority changed")
				w.WriteHeader(400)
				return
			}
			value := capacitySourceFixture(t, binaryEnv, rootTest, map[string]any{"mode": selected, "request": request})
			if value["error"] != nil {
				w.WriteHeader(503)
				return
			}
			json.NewEncoder(w).Encode(value)
		}))
	}
	metricServer := adapterServer(metricDescribe, "CAPACITY_METRIC_FIXTURE_BINARY", "TestCapacityCoreMetricSourceFixtureProducer")
	t.Cleanup(metricServer.Close)
	hpaServer := adapterServer(hpaDescribe, "CAPACITY_HPA_FIXTURE_BINARY", "TestCapacityCoreHPASourceFixtureProducer")
	t.Cleanup(hpaServer.Close)
	create := func(kind, name string, spec any) model.Manifest {
		t.Helper()
		raw, _ := json.Marshal(spec)
		m, err := repository.CreateManifestVersion(ctx, db, model.ManifestDocument{APIVersion: "yggdrasil.io/v1alpha1", Kind: kind, Metadata: model.ManifestMetadataInput{Namespace: ns, Name: name}, Spec: raw}, fmt.Sprintf("%x", sha256.Sum256(raw)))
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	mt := create("integration_type", "range-source", metricType)
	kt := create("integration_type", "hpa-source", hpaType)
	metricConfig["base_url"] = metricServer.URL
	mi := create("integration_instance", "range", model.IntegrationInstanceManifestSpec{TypeRef: model.ManifestSelector{ManifestID: mt.ID.String()}, Status: "active", Config: metricConfig})
	hpaConfig := hpaSeed["config"].(map[string]any)
	hpaConfig["base_url"] = hpaServer.URL
	ki := create("integration_instance", "cluster", model.IntegrationInstanceManifestSpec{TypeRef: model.ManifestSelector{ManifestID: kt.ID.String()}, Status: "active", Config: hpaConfig})
	wf := create("workflow", "assess-pods", model.WorkflowManifestSpec{Trigger: model.WorkflowTriggerSpec{Mode: "manual"}, Authorization: &model.WorkflowAuthorizationSpec{RBAC: model.ManifestSelector{Namespace: ns, Name: "capacity-rbac"}}, Steps: []model.WorkflowStepSpec{{ID: "assess", Use: model.WorkflowStepUseSpec{Kind: "yggdrasil", Operation: "capacity.assess_bound"}}}})
	ref := manifestReferenceFromRecord(wf)
	binding := func(instance, typ model.Manifest) model.CapacityObservationAdapterBinding {
		return model.CapacityObservationAdapterBinding{IntegrationInstanceID: instance.ID.String(), InstanceChecksum: instance.Checksum, IntegrationTypeID: typ.ID.String(), TypeChecksum: typ.Checksum}
	}
	fingerprint := metricSeed["output"].(map[string]any)["binding_sha256"].(string)
	now := time.Now().UTC()
	p := model.CapacityPolicySpec{Environment: "production", Domain: "api", Dimension: capacity.ReservedPodEnvelopeUnit, TargetIdentity: "cluster/platform/api-hpa", Owner: "capacity-owner", Workflow: model.ManifestSelector{Namespace: ns, Name: wf.Metadata.Name}, Currency: "USD", Floor: 2, Ceiling: 20, Step: 2, MaxEvidenceAgeSeconds: 60, MinSamples: 3, MaxSampleGapSeconds: 30, DownHoldSeconds: 60, LeaseSeconds: 120, Signals: []model.CapacitySignalRule{{Name: "load", SourceIdentity: "prom/api", Unit: "ratio", UpAbove: .8, DownBelow: .3}}, Profiles: []model.CapacityProfile{{Name: "pods", Provider: "kubernetes", Region: "cluster", MinUnits: 2, MaxUnits: 20, UnitMonthlyCostMinor: 100, QuoteValidUntil: now.Add(time.Hour), ValidationValidUntil: now.Add(time.Hour), ValidationRef: "fixture:reserved-envelope-not-readiness"}}}
	p.AssessmentBinding = &model.CapacityBoundAssessmentBinding{Snapshot: model.CapacityHPAMinimumBinding{Mode: capacity.HPAMinimumSnapshotMode, Unit: capacity.ReservedPodEnvelopeUnit, Adapter: binding(ki, kt), Namespace: "platform", HPAName: "api-hpa", HPAUID: "hpa-uid", WorkloadName: "api", WorkloadUID: "workload-uid", Owner: p.Owner, Profile: "pods", ProtectedFloor: 2, MaximumReplicas: 20}, Signals: []model.CapacityMetricSignalBinding{{Name: "load", Adapter: binding(mi, mt), BindingName: "api-pressure", BindingSHA256: fingerprint}}}
	if err = manifest.ValidateCapacityPolicySpec(p); err != nil {
		t.Fatal(err)
	}
	policy := create("capacity_policy", "pods", p)
	input := func() map[string]any {
		return map[string]any{"policy": map[string]any{"namespace": ns, "name": "pods"}}
	}
	run := func(op string) model.WorkflowRunStepResult {
		return executeCapacityBoundWorkflowStep(ctx, nil, db, ref, model.WorkflowRunStepResult{Kind: "yggdrasil", Operation: op, Status: "failed"}, input())
	}
	t.Setenv("YGGDRASIL_CAPACITY_EXECUTION_ENABLED", "true") // Declared shadow mode still cannot claim.
	t.Run("actual_metric_and_hpa_producers_measure_only_reserved_minimum", func(t *testing.T) {
		got := run("capacity.observe_bound_assessment")
		if got.Status != "succeeded" {
			t.Fatalf("bound sources failed: %+v", got)
		}
		var receipt model.CapacityBoundAssessmentReceipt
		decode(got.Metadata, &receipt)
		if receipt.Assessment.Snapshot.Units != 2 || receipt.Unit != capacity.ReservedPodEnvelopeUnit || receipt.UsefulCapacityKnown || receipt.ExecutionEnabled || receipt.AtomicSnapshot || len(receipt.Assessment.Evidence) != 1 || receipt.Assessment.Evidence[0].Value == nil || *receipt.Assessment.Evidence[0].Value != .9 {
			t.Fatal("reserved pods became useful/VM capacity", receipt)
		}
		got = run("capacity.assess_bound")
		if got.Status != "succeeded" {
			t.Fatalf("bound assess failed: %+v", got)
		}
		decode(got.Metadata, &receipt)
		if receipt.Intent == nil || receipt.Intent.Decision.Action != "expand" || receipt.Intent.Decision.Units != 4 || receipt.Intent.Decision.ExecutionPermitted || receipt.Intent.Assessment.Snapshot.ResourceVersion != "10" || receipt.Intent.Assessment.Snapshot.WorkloadResourceVersion != "30" {
			t.Fatal("source intent lost unit/revision or enabled execution", receipt)
		}
	})
	t.Run("missing_stale_cardinality_and_nonfinite_sources_hold_without_zero", func(t *testing.T) {
		for _, quality := range []string{"missing", "stale", "cardinality", "non_finite"} {
			setMode(quality)
			got := run("capacity.assess_bound")
			if got.Status != "succeeded" {
				t.Fatalf("quality state lost diagnostic hold (%s): %+v", quality, got)
			}
			var receipt model.CapacityBoundAssessmentReceipt
			decode(got.Metadata, &receipt)
			if receipt.Intent == nil || receipt.Intent.Decision.Action != "hold" || receipt.Intent.Decision.ExecutionPermitted || receipt.Assessment.Evidence[0].CoverageComplete {
				t.Fatal("bad source approved", quality, receipt)
			}
			if quality == "missing" && receipt.Assessment.Evidence[0].Value != nil {
				t.Fatal("missing source became zero")
			}
		}
		setMode("complete")
	})
	t.Run("caller_assessment_and_old_actuation_paths_are_blocked", func(t *testing.T) {
		before := getCalls()
		for _, op := range []string{"capacity.assess", "capacity.claim", "capacity.advance", "capacity.recover", "capacity.reconcile"} {
			got := executeCapacityWorkflowStep(ctx, db, ref, model.WorkflowRunStepResult{Kind: "yggdrasil", Operation: op, Status: "failed"}, input())
			if got.Status == "succeeded" {
				t.Fatal("caller path reinterpreted bound pods", op)
			}
		}
		value := input()
		value["assessment"] = model.CapacityAssessment{}
		got := executeCapacityBoundWorkflowStep(ctx, nil, db, ref, model.WorkflowRunStepResult{Kind: "yggdrasil", Operation: "capacity.assess_bound", Status: "failed"}, value)
		if got.Status == "succeeded" || getCalls() != before {
			t.Fatal("caller evidence reached native producer")
		}
	})
	t.Run("foreign_uid_missing_rv_and_wrong_hash_refuse", func(t *testing.T) {
		for _, bad := range []string{"foreign_hpa", "missing_rv"} {
			setMode(bad)
			if run("capacity.assess_bound").Status == "succeeded" {
				t.Fatal("foreign/incomplete HPA accepted", bad)
			}
		}
		setMode("complete")
		p.AssessmentBinding.Signals[0].BindingSHA256 = strings.Repeat("f", 64)
		create("capacity_policy", "pods", p)
		if run("capacity.assess_bound").Status == "succeeded" {
			t.Fatal("different operator signal fingerprint accepted")
		}
		p.AssessmentBinding.Signals[0].BindingSHA256 = fingerprint
		policy = create("capacity_policy", "pods", p)
	})
	t.Run("shadow_binding_rejects_vm_units_and_profile_migration", func(t *testing.T) {
		copyPolicy := p
		copyPolicy.ExecutionEnabled = true
		if manifest.ValidateCapacityPolicySpec(copyPolicy) == nil {
			t.Fatal("bound shadow execution enabled")
		}
		copyPolicy = p
		copyPolicy.MutationBindings = []model.CapacityMutationBinding{{Name: "vm"}}
		if manifest.ValidateCapacityPolicySpec(copyPolicy) == nil {
			t.Fatal("VM membership mixed with HPA min")
		}
		copyPolicy = p
		copyPolicy.Profiles = append(append([]model.CapacityProfile{}, p.Profiles...), p.Profiles[0])
		if manifest.ValidateCapacityPolicySpec(copyPolicy) == nil {
			t.Fatal("unqualified profile migration enabled")
		}
	})
	t.Run("catalog_refusal_precedes_private_hydration_and_describe", func(t *testing.T) {
		for _, kind := range []string{"missing", "permission_alias", "missing_second_required_action"} {
			raw, _ := json.Marshal(metricType)
			var bad model.IntegrationTypeManifestSpec
			decode(json.RawMessage(raw), &bad)
			switch kind {
			case "permission_alias":
				for i := range bad.ActionCatalog {
					if bad.ActionCatalog[i].Name == capacity.ObserveMetricRange {
						bad.ActionCatalog[i].Category = "permission"
					}
				}
			case "missing":
				var actions []model.IntegrationActionDefinition
				for _, a := range bad.ActionCatalog {
					if a.Name != capacity.ObserveMetricRange {
						actions = append(actions, a)
					}
				}
				bad.ActionCatalog = actions
			}
			ty := create("integration_type", "rejected-type-"+kind, bad)
			inst := create("integration_instance", "rejected-instance-"+kind, model.IntegrationInstanceManifestSpec{TypeRef: model.ManifestSelector{ManifestID: ty.ID.String()}, Status: "active", CredentialsRef: "capacity-test://must-not-hydrate", Config: metricConfig})
			rev := binding(inst, ty)
			privateCalls := 0
			before, beforeDescribe := getCalls(), getDescribes()
			private := func(context.Context, *amqp.Connection, *sql.DB, model.ManifestSelector) (model.Manifest, model.IntegrationInstanceManifestSpec, model.Manifest, model.IntegrationTypeManifestSpec, error) {
				privateCalls++
				return model.Manifest{}, model.IntegrationInstanceManifestSpec{}, model.Manifest{}, model.IntegrationTypeManifestSpec{}, fmt.Errorf("private hydration sentinel reached")
			}
			ops := []string{capacity.ObserveMetricRange}
			if kind == "missing_second_required_action" {
				ops = append(ops, capacity.VMObserveAction)
			}
			if _, err := resolveCapacityObservationAdapterWithResolver(ctx, nil, db, rev, ops, private); err == nil || privateCalls != 0 || getCalls() != before || getDescribes() != beforeDescribe {
				t.Fatal("invalid catalog reached private resolution", kind, err, privateCalls)
			}
			if kind != "missing_second_required_action" {
				if _, err := resolveCapacityObservationAdapter(ctx, nil, db, rev, capacity.ObserveMetricRange); err == nil || getCalls() != before || getDescribes() != beforeDescribe {
					t.Fatal("production resolver reached invalid transport", kind, err)
				}
			}
		}
	})
	t.Run("mutator_category_refusal_precedes_private_hydration", func(t *testing.T) {
		for index, operation := range []string{capacity.EnsureBoundHPAEnvelope, capacity.EnsureNativePodDrain, capacity.DestroyNativePodProtection} {
			for _, category := range []string{"permission", "unknown"} {
				raw, _ := json.Marshal(metricType)
				var bad model.IntegrationTypeManifestSpec
				decode(json.RawMessage(raw), &bad)
				if len(bad.ResourceTypes) == 0 {
					t.Fatal("actual source resource catalog missing")
				}
				resource := bad.ResourceTypes[0].Name
				bad.ResourceTypes[0].DefaultActions = append(bad.ResourceTypes[0].DefaultActions, operation)
				bad.ActionCatalog = append(bad.ActionCatalog, model.IntegrationActionDefinition{Name: operation, ResourceTypes: []string{resource}, Category: category, Idempotent: false})
				name := fmt.Sprintf("reject-mutator-%d-%s", index, category)
				ty := create("integration_type", name, bad)
				inst := create("integration_instance", name, model.IntegrationInstanceManifestSpec{TypeRef: model.ManifestSelector{ManifestID: ty.ID.String()}, Status: "active", CredentialsRef: "capacity-test://must-not-hydrate", Config: metricConfig})
				privateCalls := 0
				private := func(context.Context, *amqp.Connection, *sql.DB, model.ManifestSelector) (model.Manifest, model.IntegrationInstanceManifestSpec, model.Manifest, model.IntegrationTypeManifestSpec, error) {
					privateCalls++
					return model.Manifest{}, model.IntegrationInstanceManifestSpec{}, model.Manifest{}, model.IntegrationTypeManifestSpec{}, fmt.Errorf("private hydration sentinel reached")
				}
				before, describeBefore := getCalls(), getDescribes()
				if _, err := resolveCapacityObservationAdapterWithResolver(ctx, nil, db, binding(inst, ty), []string{operation}, private); err == nil || privateCalls != 0 || getCalls() != before || getDescribes() != describeBefore {
					t.Fatal("non-capability mutator reached private transport", operation, category, err)
				}
			}
		}
	})
	t.Run("inactive_instance_and_type_revision_refuse_without_source_calls", func(t *testing.T) {
		before := getCalls()
		if _, err = db.ExecContext(ctx, `UPDATE public.manifests SET active=false WHERE id=$1`, mi.ID); err != nil {
			t.Fatal(err)
		}
		if run("capacity.assess_bound").Status == "succeeded" || getCalls() != before {
			t.Fatal("inactive source reached remote native")
		}
		if _, err = db.ExecContext(ctx, `UPDATE public.manifests SET active=true WHERE id=$1`, mi.ID); err != nil {
			t.Fatal(err)
		}
		if _, err = db.ExecContext(ctx, `UPDATE public.manifests SET checksum=$2 WHERE id=$1`, mt.ID, strings.Repeat("0", 64)); err != nil {
			t.Fatal(err)
		}
		if run("capacity.assess_bound").Status == "succeeded" || getCalls() != before {
			t.Fatal("type revision drift reached native")
		}
	})
	_ = policy // Stored policy revisions are resolved internally by logical name.
}
