package message

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
)

func TestCapacityWorkflowPostgres(t *testing.T) {
	dsn := os.Getenv("DB_URL")
	if dsn == "" {
		if os.Getenv("REQUIRE_CAPACITY_POSTGRES") == "true" {
			t.Fatal("capacity PostgreSQL gate requires DB_URL")
		}
		t.Skip("remote PostgreSQL gate")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	ns := "capacity-workflow-" + uuid.NewString()
	ctx := context.Background()
	t.Cleanup(func() {
		for _, q := range []string{`DELETE FROM public.capacity_intent_events WHERE namespace=$1`, `DELETE FROM public.capacity_intents WHERE namespace=$1`, `DELETE FROM public.manifests WHERE namespace=$1`} {
			if _, err := db.ExecContext(ctx, q, ns); err != nil {
				t.Error(err)
			}
		}
		db.Close()
	})
	create := func(kind, name string, spec any) model.Manifest {
		t.Helper()
		data, err := json.Marshal(spec)
		if err != nil {
			t.Fatal(err)
		}
		m, err := repository.CreateManifestVersion(ctx, db, model.ManifestDocument{APIVersion: "yggdrasil.io/v1alpha1", Kind: kind, Metadata: model.ManifestMetadataInput{Namespace: ns, Name: name}, Spec: data}, uuid.NewString())
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	wfSpec := model.WorkflowManifestSpec{Trigger: model.WorkflowTriggerSpec{Mode: "manual"}, Authorization: &model.WorkflowAuthorizationSpec{RBAC: model.ManifestSelector{Namespace: ns, Name: "capacity-rbac"}}, Steps: []model.WorkflowStepSpec{{ID: "observe", Use: model.WorkflowStepUseSpec{Kind: "yggdrasil", Operation: "capacity.observe"}}}}
	wf := create("workflow", "scale", wfSpec)
	ref := model.ManifestReference{ID: wf.ID, Kind: "workflow", Namespace: ns, Name: "scale", Version: wf.Version}
	now := time.Now().UTC()
	p := model.CapacityPolicySpec{Environment: "production", Domain: "api", Dimension: "replicas", TargetIdentity: "cluster/ns/api", Owner: "capacity-api", Workflow: model.ManifestSelector{Namespace: ns, Name: "scale"}, Currency: "USD", Floor: 2, Ceiling: 20, Step: 2, MaxEvidenceAgeSeconds: 60, MaxSampleGapSeconds: 30, MinSamples: 3, DownHoldSeconds: 60, LeaseSeconds: 10, Signals: []model.CapacitySignalRule{{Name: "load", SourceIdentity: "prom/api", Unit: "ratio", UpAbove: 0.8, DownBelow: 0.3}}, Profiles: []model.CapacityProfile{{Name: "base", Provider: "provider", Region: "region", MinUnits: 2, MaxUnits: 20, UnitMonthlyCostMinor: 100, QuoteValidUntil: now.Add(time.Hour), ValidationValidUntil: now.Add(time.Hour), ValidationRef: "receipt:validated"}}}
	create("capacity_policy", "api", p)
	v := 0.9
	a := model.CapacityAssessment{Snapshot: model.CapacitySnapshot{TargetIdentity: p.TargetIdentity, ResourceUID: "hpa-1", WorkloadUID: "deployment-1", WorkloadResourceVersion: "10", ResourceVersion: "1", Owner: p.Owner, Profile: "base", Units: 4, ObservedAt: now}, Evidence: []model.CapacityEvidence{{Name: "load", SourceIdentity: "prom/api", Unit: "ratio", RequireData: true, Matched: true, DataState: "present", Value: &v, RangeMin: &v, RangeMax: &v, SourceSampledAt: now, WindowStart: now.Add(-time.Minute), WindowEnd: now, Samples: 10, CoverageComplete: true, MaxGapSeconds: 15}}}
	input := map[string]any{"policy": map[string]any{"namespace": ns, "name": "api"}, "assessment": a}
	base := model.WorkflowRunStepResult{Kind: "yggdrasil", Operation: "capacity.assess", Status: "failed"}
	t.Run("exact_active_protected_workflow", func(t *testing.T) {
		result := executeCapacityWorkflowStep(ctx, db, ref, base, input)
		if result.Status != "succeeded" || result.Metadata["phase"] != "proposed" {
			t.Fatalf("%+v", result)
		}
		wrong := ref
		wrong.Name = "other"
		result = executeCapacityWorkflowStep(ctx, db, wrong, base, input)
		if result.Status == "succeeded" {
			t.Fatal("another workflow assessed policy")
		}
		old := ref
		old.ID = uuid.New()
		result = executeCapacityWorkflowStep(ctx, db, old, base, input)
		if result.Status == "succeeded" {
			t.Fatal("old revision assessed policy")
		}
	})
	t.Run("shadow_claim_is_blocked", func(t *testing.T) {
		t.Setenv("YGGDRASIL_CAPACITY_EXECUTION_ENABLED", "false")
		claim := base
		claim.Operation = "capacity.claim"
		copyInput := map[string]any{"policy": input["policy"], "assessment": a, "generation": 1}
		result := executeCapacityWorkflowStep(ctx, db, ref, claim, copyInput)
		if result.Status == "succeeded" {
			t.Fatal("shadow acquired execution lease")
		}
	})
	t.Run("actorless_dispatch_is_blocked", func(t *testing.T) {
		_, err := RunWorkflowFromUnauthenticatedChannel(ctx, nil, db, model.RunWorkflowRequest{Workflow: model.ManifestSelector{Namespace: ns, Name: "scale"}})
		if !errors.Is(err, ErrWorkflowAuthenticatedActorRequired) {
			t.Fatalf("actorless channel: %v", err)
		}
	})
	t.Run("unprotected_runtime_is_blocked", func(t *testing.T) {
		wfSpec.Authorization = nil
		unprotected := create("workflow", "scale", wfSpec)
		unprotectedRef := model.ManifestReference{ID: unprotected.ID, Kind: "workflow", Namespace: ns, Name: "scale", Version: unprotected.Version}
		result := executeCapacityWorkflowStep(ctx, db, unprotectedRef, base, input)
		if result.Status == "succeeded" {
			t.Fatal("unprotected runtime assessed policy")
		}
	})
}
