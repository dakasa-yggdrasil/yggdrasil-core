package addons

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/controllers/httpapi"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/manifest"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
	amqp "github.com/rabbitmq/amqp091-go"
	"go.uber.org/zap"
)

type dispatchSchedulerFixture struct {
	db       *sql.DB
	broker   *amqp.Connection
	service  *httpapi.CapacityDispatchService
	workflow model.Manifest
	policy   model.CapacityPolicySpec
	schedule *model.WorkflowScheduleTriggerSpec
	now      time.Time
	create   func(kind, name string, spec any) model.Manifest
}

type dispatchSchedulerOptions struct {
	brokerRequired          bool
	controllerBindingAbsent bool
	configureServer         func(*testing.T)
}

func newDispatchSchedulerFixture(t *testing.T, brokerRequired bool) dispatchSchedulerFixture {
	t.Helper()
	return newDispatchSchedulerFixtureConfigured(t, dispatchSchedulerOptions{brokerRequired: brokerRequired})
}

func newDispatchSchedulerFixtureConfigured(t *testing.T, options dispatchSchedulerOptions) dispatchSchedulerFixture {
	t.Helper()
	dsn := os.Getenv("DB_URL")
	if dsn == "" {
		if os.Getenv("REQUIRE_CAPACITY_POSTGRES") == "true" || os.Getenv("REQUIRE_CAPACITY_DISPATCH_POSTGRES") == "true" {
			t.Fatal("DB_URL required by capacity scheduler PostgreSQL gate")
		}
		t.Skip("original scheduler PostgreSQL integration runs in CI")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(12)
	realm := "dispatch-scheduler-" + uuid.NewString()
	now := time.Now().UTC().Truncate(time.Minute)
	create := func(kind, name string, spec any) model.Manifest {
		raw, marshalErr := json.Marshal(spec)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		m, createErr := repository.CreateManifestVersion(context.Background(), db, model.ManifestDocument{APIVersion: "yggdrasil.io/v1alpha1", Kind: kind, Metadata: model.ManifestMetadataInput{Namespace: realm, Name: name}, Spec: raw}, fmt.Sprintf("%x", sha256.Sum256(raw)))
		if createErr != nil {
			t.Fatal(createErr)
		}
		return m
	}
	create("rbac", "dispatch", model.RBACManifestSpec{Roles: []model.RBACRole{{Name: "controller", Rules: []model.RBACRule{{Effect: "allow", Resources: []string{"workflow:" + realm + ":pressure"}, Actions: []string{"run"}}}}}, Bindings: []model.RBACBinding{{Name: "operator-controller", Subjects: []model.RBACSubject{{Type: "service", ID: "dispatch-ci"}}, Roles: []string{"controller"}}}})
	enabled := true
	schedule := &model.WorkflowScheduleTriggerSpec{CronExpression: "* * * * *", Timezone: "UTC", StartAt: now.Add(-2 * time.Minute).Format(time.RFC3339)}
	wf := create("workflow", "pressure", model.WorkflowManifestSpec{Trigger: model.WorkflowTriggerSpec{Mode: "schedule", Enabled: &enabled, Schedule: schedule}, Authorization: &model.WorkflowAuthorizationSpec{RBAC: model.ManifestSelector{Namespace: realm, Name: "dispatch"}}, Steps: []model.WorkflowStepSpec{{ID: "capacity", Use: model.WorkflowStepUseSpec{Kind: "yggdrasil", Operation: "capacity.execute_bound"}, With: map[string]any{"policy": map[string]any{"namespace": realm, "name": "pods"}}}}})
	// Valid operator scope, intentionally absent native source catalog. The
	// original executor must actually return typed failure; this fixture does
	// not certify successful useful capacity or fabricate native observations.
	adapter := model.CapacityObservationAdapterBinding{IntegrationInstanceID: uuid.NewString(), IntegrationTypeID: uuid.NewString(), InstanceChecksum: strings.Repeat("a", 64), TypeChecksum: strings.Repeat("b", 64)}
	p := model.CapacityPolicySpec{Environment: "ci", Domain: "scheduler", Dimension: capacity.ReservedPodEnvelopeUnit, TargetIdentity: "fixture/platform/api", Owner: "capacity-ci", Workflow: model.ManifestSelector{Namespace: realm, Name: "pressure"}, Currency: "USD", Floor: 2, Ceiling: 4, Step: 1, MaxEvidenceAgeSeconds: 180, MinSamples: 3, MaxSampleGapSeconds: 30, DownHoldSeconds: 60, LeaseSeconds: 120, ExecutionEnabled: true, Profiles: []model.CapacityProfile{{Name: "pods", Provider: "kubernetes", Region: "fixture-only", MinUnits: 2, MaxUnits: 4, QuoteValidUntil: now.Add(time.Hour), ValidationValidUntil: now.Add(time.Hour), ValidationRef: "fixture:scope-only"}}, Signals: []model.CapacitySignalRule{{Name: "pressure", SourceIdentity: "fixture/pressure", Unit: "ratio", UpAbove: .8, DownBelow: .3}}, AssessmentBinding: &model.CapacityBoundAssessmentBinding{Snapshot: model.CapacityHPAMinimumBinding{Mode: capacity.HPAMinimumSnapshotMode, Unit: capacity.ReservedPodEnvelopeUnit, Adapter: adapter, Namespace: "platform", HPAName: "api", HPAUID: "fixture-hpa", WorkloadName: "api", WorkloadUID: "fixture-workload", Owner: "capacity-ci", Profile: "pods", ProtectedFloor: 2, MaximumReplicas: 4}, Signals: []model.CapacityMetricSignalBinding{{Name: "pressure", Adapter: adapter, BindingName: "pressure", BindingSHA256: strings.Repeat("c", 64)}}}, HPAExecutionBinding: &model.CapacityHPAExecutionBinding{AdapterPrincipalID: "fixture-adapter", Mode: capacity.HPALifetimeExecutionMode, PodTerminationBinding: "api-native", BirthGuardBinding: "api-birth", BirthGuardSHA256: strings.Repeat("d", 64), ContainerName: "api", ImageDigest: "sha256:" + strings.Repeat("e", 64), Lanes: []string{"listener"}, ProjectionDirectory: "/native", AdmissionMode: "process_v2", AdmissionPort: 8080, AdmissionWorkflow: model.ManifestSelector{Namespace: realm, Name: "admit"}}, ControllerBinding: &model.CapacityControllerBinding{Mode: repository.CapacityDispatchProtocol, MachinePrincipalID: "dispatch-ci", DispatchLeaseSeconds: 90}}
	if options.controllerBindingAbsent {
		p.ControllerBinding = nil
	}
	if err := manifest.ValidateCapacityPolicySpec(p); err != nil {
		t.Fatal(err)
	}
	create("capacity_policy", "pods", p)
	t.Setenv("YGGDRASIL_ENV", "development")
	t.Setenv("YGGDRASIL_CAPACITY_DISPATCH_ENABLED", "true")
	t.Setenv("YGGDRASIL_CAPACITY_EXECUTION_ENABLED", "true")
	for _, key := range []string{"YGGDRASIL_DIRECTORY_MACHINE_PRINCIPALS_JSON", "YGGDRASIL_EVENT_PUBLISHER_PRINCIPALS_JSON", "YGGDRASIL_CAPACITY_MUTATION_PRINCIPALS_JSON", "YGGDRASIL_WORKFLOW_RUN_TOKEN", "YGGDRASIL_WORKFLOW_RUN_SCOPED_TOKENS_JSON", "YGGDRASIL_WORKFLOW_RUN_LEGACY_ENABLED", "YGGDRASIL_EVENT_PUBLISH_TOKEN", "YGGDRASIL_DEPLOY_TOKEN", "YGGDRASIL_AUTH_ADMIN_TOKEN", "YGGDRASIL_WORKFLOW_DISPATCH_LOCK_JSON"} {
		t.Setenv(key, "")
		if err := os.Unsetenv(key); err != nil {
			t.Fatal(err)
		}
	}
	inventory, err := json.Marshal([]map[string]any{{"principal_id": "dispatch-ci", "status": "active", "expires_at": time.Now().UTC().Add(time.Hour), "rotation_id": "ci-scheduler", "rotated_at": time.Now().UTC().Add(-time.Hour), "token_sha256": fmt.Sprintf("%x", sha256.Sum256([]byte("ci-scheduler-fixture-credential"))), "allowed_workflows": []map[string]string{{"namespace": realm, "name": "pressure"}}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("YGGDRASIL_WORKFLOW_MACHINE_PRINCIPALS_JSON", string(inventory))
	var conn *amqp.Connection
	t.Setenv("BROKER_URL", "")
	if options.brokerRequired {
		url := os.Getenv("CAPACITY_DISPATCH_BROKER_URL")
		if url == "" {
			t.Fatal("actual CI RabbitMQ required by CAPACITY_DISPATCH_BROKER_URL")
		}
		conn, err = amqp.Dial(url)
		if err != nil {
			t.Fatal(err)
		}
		t.Setenv("BROKER_URL", url)
	}
	if options.configureServer != nil {
		options.configureServer(t)
	}
	var service *httpapi.CapacityDispatchService
	if _, err = httpapi.New("capacity-scheduler-ci", db, conn, zap.NewNop(), httpapi.WithCapacityDispatchServiceReceiver(func(received *httpapi.CapacityDispatchService) { service = received })); err != nil || service == nil {
		t.Fatalf("actual server-owned service unavailable: %v", err)
	}
	t.Cleanup(func() {
		for _, query := range []string{`DELETE FROM public.capacity_dispatch_wakes WHERE realm=$1`, `DELETE FROM public.capacity_dispatch_jobs WHERE realm=$1`, `DELETE FROM public.workflow_runs WHERE workflow_namespace=$1`, `DELETE FROM public.workflow_schedule_state WHERE workflow_manifest_id IN (SELECT id FROM public.manifests WHERE namespace=$1)`, `DELETE FROM public.manifests WHERE namespace=$1`} {
			if _, err := db.ExecContext(context.Background(), query, realm); err != nil {
				t.Error(err)
			}
		}
		if conn != nil {
			if err := conn.Close(); err != nil {
				t.Error(err)
			}
		}
		if err := db.Close(); err != nil {
			t.Error(err)
		}
	})
	return dispatchSchedulerFixture{db: db, broker: conn, service: service, workflow: wf, policy: p, schedule: schedule, now: now, create: create}
}

func (f dispatchSchedulerFixture) tick(t *testing.T, now time.Time) error {
	t.Helper()
	ctx := withCapacitySchedulerService(context.Background(), f.service)
	return processScheduledWorkflow(ctx, f.db, f.broker, zap.NewNop(), f.workflow.ID.String(), f.workflow.Metadata.Namespace, f.workflow.Metadata.Name, f.schedule, now)
}

// Verify refusal before any cron transaction or goroutine can own a run.
func (f dispatchSchedulerFixture) assertRefusedTick(t *testing.T, ownerAvailable bool) {
	t.Helper()
	ctx := context.Background()
	if ownerAvailable {
		ctx = withCapacitySchedulerService(ctx, f.service)
	}
	if err := processScheduledWorkflow(ctx, f.db, f.broker, zap.NewNop(), f.workflow.ID.String(), f.workflow.Metadata.Namespace, f.workflow.Metadata.Name, f.schedule, f.now); err == nil {
		t.Fatal("protected graph used actorless legacy cron after delegation refusal")
	}
	for _, query := range []string{`SELECT count(*) FROM public.capacity_dispatch_jobs WHERE realm=$1`, `SELECT count(*) FROM public.capacity_dispatch_wakes WHERE realm=$1`, `SELECT count(*) FROM public.workflow_runs WHERE workflow_namespace=$1`} {
		var count int
		if err := f.db.QueryRowContext(t.Context(), query, f.workflow.Metadata.Namespace).Scan(&count); err != nil || count != 0 {
			t.Fatalf("refused protected cron admitted source: count=%d err=%v", count, err)
		}
	}
	state, err := repository.GetWorkflowScheduleState(t.Context(), f.db, f.workflow.ID.String())
	if err != nil || !state.LastFiredAt.IsZero() {
		t.Fatal("delegation refusal consumed original due tick", err)
	}
	assertDispatchNoNativeAuthority(t, f.db, f.workflow.Metadata.Namespace)
}

func (f dispatchSchedulerFixture) matchingEventTrigger(t *testing.T) (eventTriggerWorkflow, model.Event) {
	t.Helper()
	spec, err := manifest.ParseWorkflowSpec(f.workflow.Spec)
	if err != nil || spec.Trigger.Mode != "event" || spec.Trigger.Event == nil {
		t.Fatal("event fixture has no original reactive trigger", err)
	}
	payload := validManifestCreatedPayloadForTrigger(f.workflow.Metadata.Name)
	payload["manifest_id"] = f.workflow.ID.String()
	payload["kind"] = "workflow"
	payload["namespace"] = f.workflow.Metadata.Namespace
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := f.db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	eventID, err := repository.EmitEvent(t.Context(), tx, model.EmitEventRequest{
		Type: "manifest.created", SchemaVersion: "v1", AggregateType: "manifest", AggregateID: f.workflow.ID.String(),
		Actor: &model.EventActor{Type: "system", ID: "capacity-scheduler-ci"}, Payload: payload,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := f.db.ExecContext(context.Background(), `DELETE FROM public.event_log WHERE event_id=$1 OR (type='workflow.event.matched' AND aggregate_id=$2 AND payload->>'matched_event_id'=$3)`, eventID, f.workflow.ID.String(), eventID.String()); err != nil {
			t.Error(err)
		}
	})
	return eventTriggerWorkflow{manifestID: f.workflow.ID.String(), namespace: f.workflow.Metadata.Namespace, name: f.workflow.Metadata.Name, trigger: spec.Trigger.Event}, model.Event{EventID: eventID, Type: "manifest.created", SchemaVersion: "v1", AggregateType: "manifest", AggregateID: f.workflow.ID.String(), Payload: raw}
}

// A capacity event must stay available to its private admission owner. The
// generic match marker would consume that event before any protected job exists.
func (f dispatchSchedulerFixture) assertRefusedMatchedTrigger(t *testing.T) {
	t.Helper()
	trigger, event := f.matchingEventTrigger(t)
	for _, owner := range []string{"private_owner_present", "private_owner_absent"} {
		t.Run(owner, func(t *testing.T) {
			ctx := t.Context()
			if owner == "private_owner_present" {
				ctx = withCapacitySchedulerService(ctx, f.service)
			}
			rec := &recordingDispatcher{}
			if err := processMatchedTrigger(ctx, f.db, f.broker, zap.NewNop(), rec.dispatch, trigger, event); err == nil {
				t.Fatal("protected capacity event entered actorless legacy reactive dispatch")
			}
			if len(rec.calls) != 0 {
				t.Fatalf("protected event invoked the legacy dispatcher: calls=%d", len(rec.calls))
			}
			matched, err := repository.HasWorkflowEventMatched(ctx, f.db, trigger.manifestID, event.EventID.String())
			if err != nil || matched {
				t.Fatal("protected event consumed its generic dedup marker before private admission", err)
			}
			for _, query := range []string{`SELECT count(*) FROM public.capacity_dispatch_jobs WHERE realm=$1`, `SELECT count(*) FROM public.capacity_dispatch_wakes WHERE realm=$1`, `SELECT count(*) FROM public.workflow_runs WHERE workflow_namespace=$1`} {
				var count int
				if err := f.db.QueryRowContext(ctx, query, f.workflow.Metadata.Namespace).Scan(&count); err != nil || count != 0 {
					t.Fatalf("refused protected event admitted source: count=%d err=%v", count, err)
				}
			}
			assertDispatchNoNativeAuthority(t, f.db, f.workflow.Metadata.Namespace)
		})
	}
}

func (f dispatchSchedulerFixture) enqueue(t *testing.T) repository.CapacityDispatchJob {
	t.Helper()
	prepared, err := f.service.PrepareScheduledTick(context.Background(), f.workflow.ID, f.now)
	if err != nil || prepared == nil {
		t.Fatalf("original operator admission refused: %v", err)
	}
	tx, err := f.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	job, dedup, err := prepared.Enqueue(context.Background(), tx)
	if err != nil || dedup {
		t.Fatalf("original admission: dedup=%t err=%v", dedup, err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	return job
}

func (f dispatchSchedulerFixture) readJob(t *testing.T, id uuid.UUID) (state string, started, returned sql.NullTime) {
	t.Helper()
	if err := f.db.QueryRow(`SELECT state,started_at,returned_at FROM public.capacity_dispatch_jobs WHERE id=$1`, id).Scan(&state, &started, &returned); err != nil {
		t.Fatal(err)
	}
	return state, started, returned
}

func TestCapacityDispatchSchedulerPostgres(t *testing.T) {
	if cut := os.Getenv("CAPACITY_DISPATCH_TEST_CHILD_CUT"); cut != "" {
		capacityDispatchActualChild(t, cut)
		return
	}
	t.Run("original_cron_tick_queued_without_broker", func(t *testing.T) {
		f := newDispatchSchedulerFixture(t, false)
		if err := f.tick(t, f.now); err != nil {
			t.Fatal(err)
		}
		var jobID, runID uuid.UUID
		var protocol, state string
		if err := f.db.QueryRow(`SELECT id,run_id,protocol,state FROM public.capacity_dispatch_jobs WHERE realm=$1`, f.workflow.Metadata.Namespace).Scan(&jobID, &runID, &protocol, &state); err != nil || protocol != repository.CapacityDispatchProtocol || state != "queued" {
			t.Fatalf("broker loss consumed original wake: state=%s err=%v", state, err)
		}
		run, err := repository.GetWorkflowRun(context.Background(), f.db, runID)
		schedule, scheduleErr := repository.GetWorkflowScheduleState(context.Background(), f.db, f.workflow.ID.String())
		if err != nil || scheduleErr != nil || run.Status != "pending" || run.StartedAt != nil || schedule.LastFiredAt.IsZero() || run.Metadata[repository.WorkflowRunCreatorMachinePrincipalMetadataKey] != "dispatch-ci" {
			t.Fatalf("original tick/run/principal not durable: run=%s err=%v %v", run.Status, err, scheduleErr)
		}
		if ran, _ := f.service.RunOne(context.Background(), f.workflow.Metadata.Namespace, f.policy.Environment); ran {
			t.Fatal("missing actual broker invoked workflow")
		}
		if got, started, returned := f.readJob(t, jobID); got != "queued" || started.Valid || returned.Valid {
			t.Fatal("broker refusal manufactured original start/return")
		}
	})
	t.Run("default_off_binding_never_legacy_fallback", func(t *testing.T) {
		f := newDispatchSchedulerFixture(t, false)
		t.Setenv("YGGDRASIL_CAPACITY_DISPATCH_ENABLED", "false")
		if err := f.tick(t, f.now); err == nil {
			t.Fatal("disabled bound capacity silently used actorless legacy dispatch")
		}
		for _, query := range []string{`SELECT count(*) FROM public.capacity_dispatch_jobs WHERE realm=$1`, `SELECT count(*) FROM public.workflow_runs WHERE workflow_namespace=$1`} {
			var count int
			if err := f.db.QueryRow(query, f.workflow.Metadata.Namespace).Scan(&count); err != nil || count != 0 {
				t.Fatalf("disabled gate admitted source: count=%d err=%v", count, err)
			}
		}
		state, err := repository.GetWorkflowScheduleState(context.Background(), f.db, f.workflow.ID.String())
		if err != nil || !state.LastFiredAt.IsZero() {
			t.Fatal("disabled gate consumed tick", err)
		}
	})
	t.Run("private_owner_absent_binding_never_legacy_fallback", func(t *testing.T) {
		f := newDispatchSchedulerFixture(t, true)
		err := processScheduledWorkflow(context.Background(), f.db, f.broker, zap.NewNop(), f.workflow.ID.String(), f.workflow.Metadata.Namespace, f.workflow.Metadata.Name, f.schedule, f.now)
		if err == nil {
			t.Fatal("missing private admission owner used legacy dispatcher")
		}
		var count int
		if err := f.db.QueryRow(`SELECT count(*) FROM public.workflow_runs WHERE workflow_namespace=$1`, f.workflow.Metadata.Namespace).Scan(&count); err != nil || count != 0 {
			t.Fatal("owner refusal inserted original run", err)
		}
		state, err := repository.GetWorkflowScheduleState(context.Background(), f.db, f.workflow.ID.String())
		if err != nil || !state.LastFiredAt.IsZero() {
			t.Fatal("owner refusal consumed original cron tick", err)
		}
	})
	t.Run("paused_policy_never_legacy_fallback", func(t *testing.T) {
		f := newDispatchSchedulerFixture(t, true)
		if _, err := f.db.ExecContext(t.Context(), `UPDATE public.manifests SET active=false WHERE kind='capacity_policy' AND namespace=$1`, f.workflow.Metadata.Namespace); err != nil {
			t.Fatal(err)
		}
		if err := f.tick(t, f.now); err == nil {
			t.Fatal("paused configured policy routed into legacy dispatcher")
		}
		var count int
		if err := f.db.QueryRow(`SELECT count(*) FROM public.workflow_runs WHERE workflow_namespace=$1`, f.workflow.Metadata.Namespace).Scan(&count); err != nil || count != 0 {
			t.Fatal("paused original catalog inserted fallback run", err)
		}
	})
	t.Run("removed_binding_never_legacy_fallback", func(t *testing.T) {
		for _, refusal := range []string{"process_off", "absent_inventory", "denied_rbac"} {
			t.Run(refusal, func(t *testing.T) {
				options := dispatchSchedulerOptions{brokerRequired: true}
				if refusal == "absent_inventory" {
					options.configureServer = func(t *testing.T) {
						if err := os.Unsetenv("YGGDRASIL_WORKFLOW_MACHINE_PRINCIPALS_JSON"); err != nil {
							t.Fatal(err)
						}
					}
				}
				f := newDispatchSchedulerFixtureConfigured(t, options)
				// Publish the same manual-capable policy; ONLY delegation changes.
				p := f.policy
				p.ControllerBinding = nil
				if err := manifest.ValidateCapacityPolicySpec(p); err != nil {
					t.Fatal("manual protected policy must remain valid", err)
				}
				f.create("capacity_policy", "pods", p)
				switch refusal {
				case "process_off":
					t.Setenv("YGGDRASIL_CAPACITY_DISPATCH_ENABLED", "false")
				case "denied_rbac":
					f.create("rbac", "dispatch", model.RBACManifestSpec{Roles: []model.RBACRole{{Name: "controller", Rules: []model.RBACRule{{Effect: "deny", Resources: []string{"workflow:" + f.workflow.Metadata.Namespace + ":pressure"}, Actions: []string{"run"}}}}}, Bindings: []model.RBACBinding{{Name: "operator-controller", Subjects: []model.RBACSubject{{Type: "service", ID: "dispatch-ci"}}, Roles: []string{"controller"}}}})
				}
				f.assertRefusedTick(t, true)
			})
		}
	})
	t.Run("initially_absent_binding_never_legacy_fallback", func(t *testing.T) {
		f := newDispatchSchedulerFixtureConfigured(t, dispatchSchedulerOptions{brokerRequired: true, controllerBindingAbsent: true})
		f.assertRefusedTick(t, true)
	})
	t.Run("unbound_normalized_capacity_graph_never_legacy_fallback", func(t *testing.T) {
		for _, form := range []string{"operation_normalized", "capability_fallback"} {
			t.Run(form, func(t *testing.T) {
				f := newDispatchSchedulerFixtureConfigured(t, dispatchSchedulerOptions{brokerRequired: true, controllerBindingAbsent: true})
				spec, err := manifest.ParseWorkflowSpec(f.workflow.Spec)
				if err != nil {
					t.Fatal(err)
				}
				spec.Steps[0].Use.Kind = " Yggdrasil "
				if form == "operation_normalized" {
					spec.Steps[0].Use.Operation = " CAPACITY.EXECUTE_BOUND "
				} else {
					spec.Steps[0].Use.Operation = ""
					spec.Steps[0].Use.Capability = "capacity.execute_bound"
				}
				f.workflow = f.create("workflow", "pressure", spec)
				f.assertRefusedTick(t, true)
				f.assertRefusedTick(t, false)
			})
		}
	})
	t.Run("tombstoned_or_purged_binding_never_legacy_fallback", func(t *testing.T) {
		for _, state := range []string{"tombstoned_without_binding", "purged_policy"} {
			t.Run(state, func(t *testing.T) {
				f := newDispatchSchedulerFixture(t, true)
				p := f.policy
				p.ControllerBinding = nil
				current := f.create("capacity_policy", "pods", p)
				if state == "tombstoned_without_binding" {
					if count, err := repository.MarkManifestInactiveByID(t.Context(), f.db, current.ID); err != nil || count != 1 {
						t.Fatal("original tombstone not recorded", err)
					}
				} else if count, err := repository.HardDeleteManifestByID(t.Context(), f.db, current.ID); err != nil || count != 2 {
					t.Fatal("original logical policy not purged", err)
				}
				f.assertRefusedTick(t, true)
				f.assertRefusedTick(t, false)
			})
		}
	})
	t.Run("private_owner_absent_removed_binding_never_legacy_fallback", func(t *testing.T) {
		f := newDispatchSchedulerFixture(t, true)
		p := f.policy
		p.ControllerBinding = nil
		f.create("capacity_policy", "pods", p)
		f.assertRefusedTick(t, false)
	})
	t.Run("unrelated_legacy_cron_retains_original_dispatch", func(t *testing.T) {
		f := newDispatchSchedulerFixture(t, true)
		enabled := true
		spec := model.WorkflowManifestSpec{Trigger: model.WorkflowTriggerSpec{Mode: "schedule", Enabled: &enabled, Schedule: f.schedule}, Steps: []model.WorkflowStepSpec{{ID: "ordinary", Use: model.WorkflowStepUseSpec{Kind: "yggdrasil", Operation: "assert"}, With: map[string]any{"equal": []any{map[string]any{"name": "same", "actual": "ordinary", "expected": "ordinary"}}}}}}
		f.workflow = f.create("workflow", "ordinary", spec)
		t.Setenv("YGGDRASIL_CAPACITY_DISPATCH_ENABLED", "false")
		if err := f.tick(t, f.now); err != nil {
			t.Fatal("unrelated legacy cron refused", err)
		}
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()
		var runID uuid.UUID
		if err := f.db.QueryRowContext(ctx, `SELECT id FROM public.workflow_runs WHERE workflow_namespace=$1 AND workflow_name='ordinary'`, f.workflow.Metadata.Namespace).Scan(&runID); err != nil {
			t.Fatal("original legacy cron did not insert its run", err)
		}
		for {
			run, err := repository.GetWorkflowRun(ctx, f.db, runID)
			if err != nil {
				t.Fatal(err)
			}
			if run.FinishedAt != nil {
				if run.Status != "succeeded" || run.Result == nil || run.Result.Status != "succeeded" || len(run.Result.Steps) != 1 || run.Result.Steps[0].Operation != "assert" || run.Metadata[repository.WorkflowRunCreatorMachinePrincipalMetadataKey] != nil {
					t.Fatalf("ordinary original run changed semantics: status=%s", run.Status)
				}
				break
			}
			select {
			case <-ctx.Done():
				t.Fatal("original legacy goroutine did not return", ctx.Err())
			case <-time.After(10 * time.Millisecond):
			}
		}
		var count int
		if err := f.db.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_dispatch_jobs WHERE realm=$1`, f.workflow.Metadata.Namespace).Scan(&count); err != nil || count != 0 {
			t.Fatal("ordinary cron was converted into capacity dispatch", err)
		}
		state, err := repository.GetWorkflowScheduleState(ctx, f.db, f.workflow.ID.String())
		if err != nil || state.LastFiredAt.IsZero() {
			t.Fatal("ordinary original tick was not consumed", err)
		}
	})
	t.Run("original_scheduler_null_version_completion_wakes_fixed_demand", func(t *testing.T) {
		f := newDispatchSchedulerFixture(t, true)
		enabled := true
		// This ordinary source proves the scheduler's real persistence shape.
		// The HTTP demand cases separately execute the compiled metric source;
		// neither the assert output nor this event is capacity evidence.
		spec := model.WorkflowManifestSpec{Trigger: model.WorkflowTriggerSpec{Mode: "schedule", Enabled: &enabled, Schedule: f.schedule}, Steps: []model.WorkflowStepSpec{{ID: "ordinary", Use: model.WorkflowStepUseSpec{Kind: "yggdrasil", Operation: "assert"}, With: map[string]any{"equal": []any{map[string]any{"name": "same", "actual": "ordinary", "expected": "ordinary"}}}}}}
		source := f.create("workflow", "scheduled-demand-source", spec)
		p := f.policy
		binding := *p.ControllerBinding
		binding.DemandSource = &model.CapacityDemandSourceBinding{Mode: "core_workflow_completion_v1", ManifestID: source.ID.String(), Namespace: source.Metadata.Namespace, Name: source.Metadata.Name, Version: source.Version, Checksum: source.Checksum, MaxAgeSeconds: 60}
		p.ControllerBinding = &binding
		if err := manifest.ValidateCapacityPolicySpec(p); err != nil {
			t.Fatal("fixed original demand policy invalid", err)
		}
		f.create("capacity_policy", "pods", p)
		scope := repository.CapacityDemandScope{Realm: source.Metadata.Namespace, Environment: p.Environment, Domain: p.Domain, Dimension: p.Dimension, SourceWorkflowID: source.ID, MaxAgeSeconds: binding.DemandSource.MaxAgeSeconds}
		cursorID, err := scope.CursorID()
		if err != nil || len(cursorID) != 64 {
			t.Fatal("fixed original cursor exceeds native schema", err)
		}
		t.Cleanup(func() {
			if _, err := f.db.ExecContext(context.Background(), `DELETE FROM public.event_log WHERE type='workflow.run.completed' AND aggregate_type='workflow_run' AND payload->'workflow_ref'->>'id'=$1`, source.ID.String()); err != nil {
				t.Error(err)
			}
			if _, err := f.db.ExecContext(context.Background(), `DELETE FROM public.workflow_event_trigger_state WHERE id=$1`, cursorID); err != nil {
				t.Error(err)
			}
		})
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()
		owner := withCapacitySchedulerService(ctx, f.service)
		if err := processScheduledWorkflow(owner, f.db, f.broker, zap.NewNop(), source.ID.String(), source.Metadata.Namespace, source.Metadata.Name, f.schedule, f.now); err != nil {
			t.Fatal("original scheduler refused its ordinary source", err)
		}
		var eventID uuid.UUID
		// The original scheduler owns Insert/MarkRunning/RunWorkflow/Finalize
		// and its separate emitter TX. This is readback, not a return join for
		// that legacy goroutine, which exposes no join handle.
		for {
			err := f.db.QueryRowContext(ctx, `SELECT event_id FROM public.event_log WHERE type='workflow.run.completed' AND idempotency_key=aggregate_id AND payload->'workflow_ref'->>'id'=$1`, source.ID.String()).Scan(&eventID)
			if err == nil {
				break
			}
			if !errors.Is(err, sql.ErrNoRows) {
				t.Fatal("original completion readback unresolved", err)
			}
			select {
			case <-ctx.Done():
				t.Fatal("original scheduled completion did not commit", ctx.Err())
			case <-time.After(10 * time.Millisecond):
			}
		}
		event, err := repository.ReadCapacityDemandEvent(ctx, f.db, eventID)
		if err != nil || event.SourceWorkflow.ID != source.ID || event.SourceWorkflow.Version != source.Version || event.SourceWorkflow.Checksum != source.Checksum {
			t.Fatal("actual scheduler result/catalog binding refused", err)
		}
		run, err := repository.GetWorkflowRun(ctx, f.db, event.RunID)
		if err != nil || run.WorkflowVersion != nil || run.Status != "succeeded" || run.Result == nil || run.Result.Workflow.ID != source.ID || run.Result.Workflow.Version != source.Version || run.Metadata["manifest_id"] != source.ID.String() || run.Metadata["triggered_by"] != "workflow_scheduler" || run.FinishedAt == nil || len(run.Result.Steps) != 1 || run.Result.Steps[0].Operation != "assert" {
			t.Fatal("original scheduler NULL version or stored response changed", err)
		}
		// Original private RunPass admits the wake and actually invokes its
		// bounded executor. Missing native catalog must remain a refusal.
		if err := f.service.RunPass(ctx); err == nil {
			t.Fatal("source completion became unobserved capacity")
		}
		var jobID uuid.UUID
		if err := f.db.QueryRowContext(ctx, `SELECT id FROM public.capacity_dispatch_jobs WHERE realm=$1`, source.Metadata.Namespace).Scan(&jobID); err != nil {
			t.Fatal("actual scheduler completion did not admit its fixed dimension", err)
		}
		job, err := repository.ReadCapacityDispatchJob(ctx, f.db, jobID)
		if err != nil || job.Metadata["source_event_id"] != eventID.String() || job.Metadata["source_run_id"] != event.RunID.String() || job.Metadata["source_workflow_id"] != source.ID.String() || job.SourceTick != "event:"+eventID.String() || job.StartedAt == nil || job.ReturnedAt == nil || len(job.Inputs) != 1 {
			t.Fatal("native admission lost original source/return identity", err)
		}
		cursor, err := repository.ReadCapacityDemandCursor(ctx, f.db, scope)
		var wakes int
		if err != nil || cursor != fmt.Sprint(event.Sequence) || f.db.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_dispatch_wakes WHERE realm=$1 AND source_tick=$2`, source.Metadata.Namespace, "event:"+eventID.String()).Scan(&wakes) != nil || wakes != 1 {
			t.Fatal("original wake/cursor transaction not retained", err)
		}
		if err := f.service.RunPass(ctx); err != nil {
			t.Fatal("already-consumed scheduler completion replayed", err)
		}
		var jobs int
		if f.db.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_dispatch_jobs WHERE realm=$1`, source.Metadata.Namespace).Scan(&jobs) != nil || jobs != 1 || f.db.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_dispatch_wakes WHERE realm=$1`, source.Metadata.Namespace).Scan(&wakes) != nil || wakes != 1 {
			t.Fatal("second pass replaced an original demand obligation")
		}
		assertDispatchNoNativeAuthority(t, f.db, source.Metadata.Namespace)
	})
	t.Run("unrelated_legacy_event_retains_original_dispatch", func(t *testing.T) {
		f := newDispatchSchedulerFixture(t, true)
		enabled := true
		spec := model.WorkflowManifestSpec{Trigger: model.WorkflowTriggerSpec{Mode: "event", Enabled: &enabled, Event: &model.WorkflowEventTriggerSpec{Types: []string{"manifest.created"}, DefaultInputs: map[string]any{"ordinary_default": "retained"}}}, Steps: []model.WorkflowStepSpec{{ID: "ordinary", Use: model.WorkflowStepUseSpec{Kind: "yggdrasil", Operation: "assert"}, With: map[string]any{"equal": []any{map[string]any{"name": "same", "actual": "ordinary", "expected": "ordinary"}}}}}}
		f.workflow = f.create("workflow", "ordinary-event", spec)
		trigger, event := f.matchingEventTrigger(t)
		t.Setenv("YGGDRASIL_CAPACITY_DISPATCH_ENABLED", "false")
		rec := &recordingDispatcher{}
		dispatch := func(ctx context.Context, db *sql.DB, conn *amqp.Connection, runID uuid.UUID, req model.RunWorkflowRequest) {
			rec.dispatch(ctx, db, conn, runID, req)
			dispatchAsyncWorkflowRunBackground(ctx, db, conn, runID, req)
		}
		for attempt := 0; attempt < 2; attempt++ {
			if err := processMatchedTrigger(t.Context(), f.db, f.broker, zap.NewNop(), dispatch, trigger, event); err != nil {
				t.Fatal("unrelated legacy event refused", err)
			}
		}
		if len(rec.calls) != 1 {
			t.Fatalf("ordinary reactive dispatch changed idempotency: calls=%d", len(rec.calls))
		}
		got := rec.calls[0]
		inputEvent, ok := got.Req.Inputs["event"].(map[string]any)
		if got.Req.Workflow.Namespace != f.workflow.Metadata.Namespace || got.Req.Workflow.Name != "ordinary-event" || got.Req.Metadata["triggered_by"] != "workflow_event_triggers" || got.Req.Metadata["matched_event_id"] != event.EventID.String() || !ok || inputEvent["name"] != "ordinary-event" || got.Req.Inputs["ordinary_default"] != "retained" {
			t.Fatal("ordinary reactive selector, metadata or inputs changed")
		}
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()
		for {
			run, err := repository.GetWorkflowRun(ctx, f.db, got.RunID)
			if err != nil {
				t.Fatal(err)
			}
			if run.FinishedAt != nil {
				if run.Status != "succeeded" || run.Result == nil || run.Result.Status != "succeeded" || len(run.Result.Steps) != 1 || run.Result.Steps[0].Operation != "assert" || run.Metadata[repository.WorkflowRunCreatorMachinePrincipalMetadataKey] != nil {
					t.Fatalf("ordinary reactive original run changed semantics: status=%s", run.Status)
				}
				break
			}
			select {
			case <-ctx.Done():
				t.Fatal("original legacy reactive goroutine did not return", ctx.Err())
			case <-time.After(10 * time.Millisecond):
			}
		}
		for _, check := range []struct {
			query string
			want  int
		}{
			{`SELECT count(*) FROM public.workflow_runs WHERE workflow_namespace=$1`, 1},
			{`SELECT count(*) FROM public.capacity_dispatch_jobs WHERE realm=$1`, 0},
			{`SELECT count(*) FROM public.capacity_dispatch_wakes WHERE realm=$1`, 0},
		} {
			var count int
			if err := f.db.QueryRowContext(ctx, check.query, f.workflow.Metadata.Namespace).Scan(&count); err != nil || count != check.want {
				t.Fatalf("ordinary reactive persistence changed: count=%d want=%d err=%v", count, check.want, err)
			}
		}
		var matches int
		if err := f.db.QueryRowContext(ctx, `SELECT count(*) FROM public.event_log WHERE type='workflow.event.matched' AND aggregate_id=$1 AND payload->>'matched_event_id'=$2`, trigger.manifestID, event.EventID.String()).Scan(&matches); err != nil || matches != 1 {
			t.Fatalf("ordinary event lost original dedup marker: matches=%d err=%v", matches, err)
		}
		assertDispatchNoNativeAuthority(t, f.db, f.workflow.Metadata.Namespace)
	})
	t.Run("unrelated_legacy_event_degraded_broker_retains_original_match", func(t *testing.T) {
		for _, state := range []string{"nil_broker", "closed_broker"} {
			t.Run(state, func(t *testing.T) {
				f := newDispatchSchedulerFixture(t, false)
				enabled := true
				spec := model.WorkflowManifestSpec{Trigger: model.WorkflowTriggerSpec{Mode: "event", Enabled: &enabled, Event: &model.WorkflowEventTriggerSpec{Types: []string{"manifest.created"}}}, Steps: []model.WorkflowStepSpec{{ID: "ordinary", Use: model.WorkflowStepUseSpec{Kind: "yggdrasil", Operation: "assert"}, With: map[string]any{"equal": []any{map[string]any{"name": "same", "actual": "ordinary", "expected": "ordinary"}}}}}}
				f.workflow = f.create("workflow", "ordinary-event-degraded", spec)
				trigger, event := f.matchingEventTrigger(t)
				var conn *amqp.Connection
				if state == "closed_broker" {
					conn = brokerForTriggerTest(t)
					if err := conn.Close(); err != nil {
						t.Fatal("close original connection before degraded event dispatch", err)
					}
				}
				rec := &recordingDispatcher{}
				for attempt := 0; attempt < 2; attempt++ {
					if err := processMatchedTrigger(t.Context(), f.db, conn, zap.NewNop(), rec.dispatch, trigger, event); err != nil {
						t.Fatal("ordinary event lost original degraded broker behavior", err)
					}
				}
				if len(rec.calls) != 0 {
					t.Fatalf("degraded event invoked legacy dispatcher: calls=%d", len(rec.calls))
				}
				var matches int
				if err := f.db.QueryRowContext(t.Context(), `SELECT count(*) FROM public.event_log WHERE type='workflow.event.matched' AND aggregate_id=$1 AND payload->>'matched_event_id'=$2`, trigger.manifestID, event.EventID.String()).Scan(&matches); err != nil || matches != 1 {
					t.Fatalf("degraded ordinary event lost original retained match: matches=%d err=%v", matches, err)
				}
				for _, query := range []string{`SELECT count(*) FROM public.capacity_dispatch_jobs WHERE realm=$1`, `SELECT count(*) FROM public.capacity_dispatch_wakes WHERE realm=$1`, `SELECT count(*) FROM public.workflow_runs WHERE workflow_namespace=$1`} {
					var count int
					if err := f.db.QueryRowContext(t.Context(), query, f.workflow.Metadata.Namespace).Scan(&count); err != nil || count != 0 {
						t.Fatalf("degraded ordinary event manufactured execution: count=%d err=%v", count, err)
					}
				}
				assertDispatchNoNativeAuthority(t, f.db, f.workflow.Metadata.Namespace)
			})
		}
	})
	t.Run("configured_capacity_event_binding_refused_before_legacy_dedup", func(t *testing.T) {
		f := newDispatchSchedulerFixture(t, true)
		enabled := true
		// The configured binding protects its workflow independently of step
		// classification; replacing the graph cannot escape the private owner.
		spec := model.WorkflowManifestSpec{Trigger: model.WorkflowTriggerSpec{Mode: "event", Enabled: &enabled, Event: &model.WorkflowEventTriggerSpec{Types: []string{"manifest.created"}}}, Steps: []model.WorkflowStepSpec{{ID: "ordinary", Use: model.WorkflowStepUseSpec{Kind: "yggdrasil", Operation: "assert"}}}}
		f.workflow = f.create("workflow", "pressure", spec)
		f.assertRefusedMatchedTrigger(t)
	})
	t.Run("unbound_capacity_event_graph_refused_before_legacy_dedup", func(t *testing.T) {
		for _, form := range []string{"operation_canonical", "operation_normalized", "capability_fallback"} {
			t.Run(form, func(t *testing.T) {
				f := newDispatchSchedulerFixtureConfigured(t, dispatchSchedulerOptions{brokerRequired: true, controllerBindingAbsent: true})
				spec, err := manifest.ParseWorkflowSpec(f.workflow.Spec)
				if err != nil {
					t.Fatal(err)
				}
				spec.Trigger = model.WorkflowTriggerSpec{Mode: "event", Enabled: spec.Trigger.Enabled, Event: &model.WorkflowEventTriggerSpec{Types: []string{"manifest.created"}}}
				if form != "operation_canonical" {
					spec.Steps[0].Use.Kind = " Yggdrasil "
					if form == "operation_normalized" {
						spec.Steps[0].Use.Operation = " CAPACITY.EXECUTE_BOUND "
					} else {
						spec.Steps[0].Use.Operation = ""
						spec.Steps[0].Use.Capability = "capacity.execute_bound"
					}
				}
				f.workflow = f.create("workflow", "pressure", spec)
				f.assertRefusedMatchedTrigger(t)
			})
		}
	})
	t.Run("removed_tombstoned_or_purged_capacity_event_binding_refused_before_legacy_dedup", func(t *testing.T) {
		for _, state := range []string{"removed_binding", "tombstoned_without_binding", "purged_policy"} {
			t.Run(state, func(t *testing.T) {
				f := newDispatchSchedulerFixture(t, true)
				spec, err := manifest.ParseWorkflowSpec(f.workflow.Spec)
				if err != nil {
					t.Fatal(err)
				}
				spec.Trigger = model.WorkflowTriggerSpec{Mode: "event", Enabled: spec.Trigger.Enabled, Event: &model.WorkflowEventTriggerSpec{Types: []string{"manifest.created"}}}
				f.workflow = f.create("workflow", "pressure", spec)
				p := f.policy
				p.ControllerBinding = nil
				current := f.create("capacity_policy", "pods", p)
				switch state {
				case "tombstoned_without_binding":
					if count, err := repository.MarkManifestInactiveByID(t.Context(), f.db, current.ID); err != nil || count != 1 {
						t.Fatal("original event policy tombstone not recorded", err)
					}
				case "purged_policy":
					if count, err := repository.HardDeleteManifestByID(t.Context(), f.db, current.ID); err != nil || count != 2 {
						t.Fatal("original event logical policy not purged", err)
					}
				}
				f.assertRefusedMatchedTrigger(t)
			})
		}
	})
	t.Run("generic_cleaner_cannot_release_started_dispatch", func(t *testing.T) {
		f := newDispatchSchedulerFixture(t, false)
		original := f.enqueue(t)
		claimed, err := repository.ClaimCapacityDispatch(t.Context(), f.db, original.Realm, original.Environment, uuid.New(), time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		started, err := repository.StartCapacityDispatch(t.Context(), f.db, claimed)
		if err != nil {
			t.Fatal(err)
		}
		// Make only the original run old enough for the actual generic cleaner.
		// Its separately immutable dispatch start/deadline is unchanged.
		if _, err := f.db.ExecContext(t.Context(), `UPDATE public.workflow_runs SET started_at=clock_timestamp()-interval '2 hours' WHERE id=$1`, original.RunID); err != nil {
			t.Fatal(err)
		}
		if _, err := cleanupStaleWorkflowRuns(t.Context(), f.db, time.Hour); err != nil {
			t.Fatal(err)
		}
		run, err := repository.GetWorkflowRun(t.Context(), f.db, original.RunID)
		state, observedStart, observedReturn := f.readJob(t, original.JobID)
		if err != nil || run.Status != "running" || state != "started" || !observedStart.Valid || observedReturn.Valid || !observedStart.Time.Equal(*started.StartedAt) {
			t.Fatal("generic cleaner manufactured return/release", err)
		}
		if _, err := repository.ClaimCapacityDispatch(t.Context(), f.db, original.Realm, original.Environment, uuid.New(), time.Minute); !errors.Is(err, repository.ErrCapacityDispatchClaim) {
			t.Fatal("generic cleanup permitted second invocation", err)
		}
	})
	t.Run("owned_service_prestart_resume_actual_failed_return", func(t *testing.T) {
		f := newDispatchSchedulerFixture(t, true)
		original := f.enqueue(t)
		first, err := repository.ClaimCapacityDispatch(context.Background(), f.db, original.Realm, original.Environment, uuid.New(), time.Second)
		if err != nil {
			t.Fatal(err)
		}
		time.Sleep(time.Until(*first.LeaseExpiresAt) + 20*time.Millisecond)
		if ran, err := f.service.RunOne(context.Background(), original.Realm, original.Environment); !ran || err == nil {
			t.Fatal("owned original worker must retain actual typed source failure", err)
		}
		state, started, returned := f.readJob(t, original.JobID)
		run, err := repository.GetWorkflowRun(context.Background(), f.db, original.RunID)
		if err != nil || state != "returned" || !started.Valid || !returned.Valid || run.Status != "failed" || run.Result == nil || run.Result.Status != "failed" || len(run.Result.Steps) != 1 || run.Result.Steps[0].Operation != "capacity.execute_bound" {
			t.Fatalf("original typed failure was replaced by success/wrapper: state=%s run=%s err=%v", state, run.Status, err)
		}
		assertDispatchNoNativeAuthority(t, f.db, original.Realm)
	})
	t.Run("started_expiry_new_tick_hold", func(t *testing.T) {
		f := newDispatchSchedulerFixture(t, true)
		original := f.enqueue(t)
		claimed, err := repository.ClaimCapacityDispatch(context.Background(), f.db, original.Realm, original.Environment, uuid.New(), time.Second)
		if err != nil {
			t.Fatal(err)
		}
		started, err := repository.StartCapacityDispatch(context.Background(), f.db, claimed)
		if err != nil {
			t.Fatal(err)
		}
		time.Sleep(time.Until(*started.LeaseExpiresAt) + 20*time.Millisecond)
		if ran, _ := f.service.RunOne(context.Background(), original.Realm, original.Environment); ran {
			t.Fatal("elapsed possible-start invoked original workflow twice")
		}
		if err := f.tick(t, f.now.Add(time.Minute)); err != nil {
			t.Fatal(err)
		}
		var count int
		if err := f.db.QueryRow(`SELECT count(*) FROM public.workflow_runs WHERE workflow_namespace=$1`, original.Realm).Scan(&count); err != nil || count != 1 {
			t.Fatalf("new tick released active original run: count=%d err=%v", count, err)
		}
		if state, observedStart, observedReturn := f.readJob(t, original.JobID); state != "started" || !observedStart.Valid || observedReturn.Valid {
			t.Fatal("new wake invented original return/quiescence")
		}
		assertDispatchNoNativeAuthority(t, f.db, original.Realm)
	})
	t.Run("actual_child_failstop", func(t *testing.T) {
		for _, cut := range []string{"before_started", "after_started_before_invoke"} {
			t.Run(cut, func(t *testing.T) {
				f := newDispatchSchedulerFixture(t, true)
				original := f.enqueue(t)
				executable, err := os.Executable()
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				child := exec.CommandContext(ctx, executable, "-test.run=^TestCapacityDispatchSchedulerPostgres$", "-test.count=1")
				child.Env = append(os.Environ(), "CAPACITY_DISPATCH_TEST_CHILD_CUT="+cut, "CAPACITY_DISPATCH_TEST_CHILD_JOB="+original.JobID.String())
				pipe, err := child.StdoutPipe()
				if err != nil {
					t.Fatal(err)
				}
				child.Stderr = os.Stderr
				if err := child.Start(); err != nil {
					t.Fatal(err)
				}
				defer func() { _ = child.Process.Kill() }()
				var receipt dispatchChildReceipt
				if err := json.NewDecoder(pipe).Decode(&receipt); err != nil || receipt.PID != child.Process.Pid || receipt.JobID != original.JobID || receipt.Cut != cut || receipt.LeaseExpiresAt.IsZero() {
					t.Fatalf("actual child ready receipt missing: %+v %v", receipt, err)
				}
				if err := child.Process.Kill(); err != nil {
					t.Fatal(err)
				}
				waitErr := child.Wait()
				var exitErr *exec.ExitError
				if !errors.As(waitErr, &exitErr) || child.ProcessState == nil || child.ProcessState.Pid() != receipt.PID || child.ProcessState.Success() {
					t.Fatal("actual child fail-stop Wait was not observed", waitErr)
				}
				t.Logf("actual child Start PID=%d cut=%s; native Wait=%s", receipt.PID, receipt.Cut, child.ProcessState.String())
				time.Sleep(time.Until(receipt.LeaseExpiresAt) + 20*time.Millisecond)
				ran, err := f.service.RunOne(context.Background(), original.Realm, original.Environment)
				state, started, returned := f.readJob(t, original.JobID)
				if cut == "before_started" {
					if !ran || state != "returned" || !started.Valid || !returned.Valid {
						t.Fatalf("before-start crash could not resume original: ran=%t state=%s err=%v", ran, state, err)
					}
				} else if ran || state != "started" || !started.Valid || returned.Valid {
					t.Fatalf("after-start zero-invocation fixture granted replay: ran=%t state=%s err=%v", ran, state, err)
				}
				assertDispatchNoNativeAuthority(t, f.db, original.Realm)
			})
		}
	})
}

func assertDispatchNoNativeAuthority(t *testing.T, db *sql.DB, realm string) {
	t.Helper()
	for _, table := range []string{"capacity_intents", "capacity_mutation_grants", "capacity_native_commands"} {
		var count int
		if err := db.QueryRow(`SELECT count(*) FROM public.`+table+` WHERE namespace=$1`, realm).Scan(&count); err != nil || count != 0 {
			t.Fatalf("absent catalog produced native authority: table=%s count=%d err=%v", table, count, err)
		}
	}
}

type dispatchChildReceipt struct {
	PID            int       `json:"pid"`
	Cut            string    `json:"cut"`
	JobID          uuid.UUID `json:"job_id"`
	LeaseExpiresAt time.Time `json:"lease_expires_at"`
}

func capacityDispatchActualChild(t *testing.T, cut string) {
	t.Helper()
	if cut != "before_started" && cut != "after_started_before_invoke" {
		t.Fatal("unknown fail-stop cut")
	}
	db, err := sql.Open("postgres", os.Getenv("DB_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	id, err := uuid.Parse(os.Getenv("CAPACITY_DISPATCH_TEST_CHILD_JOB"))
	if err != nil {
		t.Fatal(err)
	}
	var raw string
	if err := db.QueryRow(`SELECT envelope FROM public.capacity_dispatch_jobs WHERE id=$1`, id).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var e repository.CapacityDispatchEnvelope
	if err := json.Unmarshal([]byte(raw), &e); err != nil {
		t.Fatal(err)
	}
	job, err := repository.ClaimCapacityDispatch(context.Background(), db, e.Realm, e.Environment, uuid.New(), time.Second)
	if err != nil || job.JobID != id {
		t.Fatal("actual child claim refused", err)
	}
	if cut == "after_started_before_invoke" {
		job, err = repository.StartCapacityDispatch(context.Background(), db, job)
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := json.NewEncoder(os.Stdout).Encode(dispatchChildReceipt{PID: os.Getpid(), Cut: cut, JobID: id, LeaseExpiresAt: *job.LeaseExpiresAt}); err != nil {
		t.Fatal(err)
	}
	// Parent observes Start/PID/ready then a real signal and Wait. This child
	// never crosses original RunWorkflow; a possible-start cut still holds.
	select {}
}
