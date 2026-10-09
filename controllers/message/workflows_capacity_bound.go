package message

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/manifest"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	amqp "github.com/rabbitmq/amqp091-go"
)

var errCapacityBoundAssessment = fmt.Errorf("protected bound capacity assessment refused")

func capacityBoundOperation(op string) bool {
	return op == "capacity.observe_bound_assessment" || op == "capacity.assess_bound" || op == "capacity.execute_bound" || op == "capacity.admit_bound"
}

type capacityResolvedObservationAdapter struct {
	instance     model.Manifest
	instanceSpec model.IntegrationInstanceManifestSpec
	typ          model.Manifest
	typeSpec     model.IntegrationTypeManifestSpec
}

type capacityPrivateObservationResolver func(context.Context, *amqp.Connection, *sql.DB, model.ManifestSelector) (model.Manifest, model.IntegrationInstanceManifestSpec, model.Manifest, model.IntegrationTypeManifestSpec, error)

func resolveCapacityObservationAdapter(ctx context.Context, conn *amqp.Connection, db *sql.DB, b model.CapacityObservationAdapterBinding, operation string) (capacityResolvedObservationAdapter, error) {
	return resolveCapacityObservationAdapterWithResolver(ctx, conn, db, b, []string{operation}, resolveIntegrationInstance)
}

// A private dependency seam lets remote PostgreSQL fixtures prove that a bad
// catalog never reaches secret hydration, health or live Describe at all.
func resolveCapacityObservationAdapterWithResolver(ctx context.Context, conn *amqp.Connection, db *sql.DB, b model.CapacityObservationAdapterBinding, operations []string, resolvePrivate capacityPrivateObservationResolver) (capacityResolvedObservationAdapter, error) {
	var out capacityResolvedObservationAdapter
	im, err := resolveManifestForKind(ctx, db, "integration_instance", b.IntegrationInstanceID, "", "", nil)
	if err != nil || im.Kind != "integration_instance" || !im.Metadata.Active || im.ID.String() != b.IntegrationInstanceID || im.Checksum != b.InstanceChecksum {
		return out, errCapacityBoundAssessment
	}
	is, err := manifest.ParseIntegrationInstanceSpec(im.Spec)
	if err != nil {
		return out, errCapacityBoundAssessment
	}
	tm, err := resolveManifestForKind(ctx, db, "integration_type", is.TypeRef.ManifestID, is.TypeRef.Namespace, is.TypeRef.Name, is.TypeRef.Version)
	if err != nil || tm.Kind != "integration_type" || !tm.Metadata.Active || tm.ID.String() != b.IntegrationTypeID || tm.Checksum != b.TypeChecksum {
		return out, errCapacityBoundAssessment
	}
	rawType, err := manifest.ParseIntegrationTypeSpec(tm.Spec)
	if err != nil || manifest.ValidateIntegrationTypeSpec(rawType) != nil || len(operations) == 0 {
		return out, errCapacityBoundAssessment
	}
	for _, operation := range operations {
		if !capacityBoundCatalogOperation(rawType, operation) {
			return out, errCapacityBoundAssessment
		}
	}
	im, is, tm, ts, err := resolvePrivate(ctx, conn, db, model.ManifestSelector{ManifestID: b.IntegrationInstanceID})
	if err != nil || im.Kind != "integration_instance" || im.ID.String() != b.IntegrationInstanceID || !im.Metadata.Active || im.Checksum != b.InstanceChecksum || tm.Kind != "integration_type" || tm.ID.String() != b.IntegrationTypeID || !tm.Metadata.Active || tm.Checksum != b.TypeChecksum || manifest.ValidateIntegrationTypeSpec(ts) != nil {
		return out, errCapacityBoundAssessment
	}
	return capacityResolvedObservationAdapter{im, is, tm, ts}, nil
}

func executeCapacityBoundWorkflowStep(ctx context.Context, conn *amqp.Connection, db *sql.DB, workflowRef model.ManifestReference, result model.WorkflowRunStepResult, input map[string]any) model.WorkflowRunStepResult {
	result.Attempts = 1
	fail := func() model.WorkflowRunStepResult {
		result.Error = errCapacityBoundAssessment.Error()
		result.FinishedAt = time.Now().UTC()
		return result
	}
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	var parsed struct {
		Policy model.ManifestSelector `json:"policy"`
	}
	if db == nil || !capacityBoundOperation(result.Operation) || capacity.DecodeNativeCapacity(input, &parsed) != nil || parsed.Policy.ManifestID != "" || parsed.Policy.Version != nil || parsed.Policy.Namespace == "" || parsed.Policy.Name == "" {
		return fail()
	}
	policy, err := repository.ResolveManifest(ctx, db, "capacity_policy", parsed.Policy.Namespace, parsed.Policy.Name, nil, true)
	if err != nil {
		return fail()
	}
	p, err := manifest.ParseCapacityPolicySpec(policy.Spec)
	admissionOnly := result.Operation == "capacity.admit_bound"
	expectedWorkflow := p.Workflow
	if admissionOnly && p.HPAExecutionBinding != nil {
		expectedWorkflow = p.HPAExecutionBinding.AdmissionWorkflow
	}
	if err != nil || manifest.ValidateCapacityPolicySpec(p) != nil || p.AssessmentBinding == nil || workflowRef.Kind != "workflow" || workflowRef.Namespace != expectedWorkflow.Namespace || workflowRef.Name != expectedWorkflow.Name {
		return fail()
	}
	wf, err := repository.ResolveManifest(ctx, db, "workflow", expectedWorkflow.Namespace, expectedWorkflow.Name, nil, true)
	if err != nil || wf.ID != workflowRef.ID || wf.Version != workflowRef.Version {
		return fail()
	}
	spec, err := manifest.ParseWorkflowSpec(wf.Spec)
	if err != nil || spec.Authorization == nil {
		return fail()
	}
	resolved := map[model.CapacityObservationAdapterBinding]capacityResolvedObservationAdapter{}
	read := func(binding model.CapacityObservationAdapterBinding, op string, fixed map[string]any, out any) (string, error) {
		a, ok := resolved[binding]
		if !ok {
			required := []string{op}
			if p.HPAExecutionBinding != nil && p.ExecutionEnabled && p.HPAExecutionBinding.Mode == capacity.HPALifetimeExecutionMode && binding == p.AssessmentBinding.Snapshot.Adapter && op != capacity.ObserveCurrentBirthGuard {
				required = append(required, capacity.ObserveCurrentBirthGuard)
			}
			a, err = resolveCapacityObservationAdapter(ctx, conn, db, binding, required...)
			if err != nil {
				return "", err
			}
			resolved[binding] = a
		}
		if !capacityBoundCatalogOperation(a.typeSpec, op) {
			return "", errCapacityBoundAssessment
		}
		r, e := executeIntegrationThroughResolvedWithPolicy(ctx, conn, model.ExecuteIntegrationRequest{Operation: op, Capability: op, Input: fixed}, a.instance, a.instanceSpec, a.typ, a.typeSpec, 35*time.Second, integrationExecutionPolicy{detailFreeErrors: true, safeError: errCapacityBoundAssessment, requireExplicitResponse: true})
		if e != nil || capacity.DecodeNativeCapacity(r.Output, out) != nil {
			return "", errCapacityBoundAssessment
		}
		return r.Status, nil
	}
	b := p.AssessmentBinding
	if admissionOnly {
		if p.HPAExecutionBinding == nil || p.HPAExecutionBinding.Mode != capacity.HPALifetimeExecutionMode || !p.ExecutionEnabled || os.Getenv("YGGDRASIL_CAPACITY_ADMISSION_ENABLED") != "true" {
			return fail()
		}
		var hpa model.CapacityHPAEnvelopeResponse
		status, err := read(b.Snapshot.Adapter, capacity.ObserveHPAEnvelope, map[string]any{"namespace": b.Snapshot.Namespace, "hpa_name": b.Snapshot.HPAName}, &hpa)
		if err != nil || status != "observed" {
			return fail()
		}
		executor, _ := ctx.Value(capacityInvocationKey{}).(string)
		store := repository.CapacityStore{DB: db, ExecutionEnabled: true, AdmissionOnly: true, WorkflowID: wf.ID, ExecutorID: executor}
		intent, err := runCapacityBoundExecution(ctx, store, policy, p, model.CapacityIntent{}, model.CapacityAssessment{}, hpa, read)
		if err != nil {
			return fail()
		}
		intent.LeaseOwner, intent.LeaseExecutorID = "", ""
		var membership model.AdapterCapacityPodAdmissionCandidatesResponse
		status, err = read(b.Snapshot.Adapter, capacity.ObserveNativePodAdmissionCandidates, map[string]any{"binding_name": p.HPAExecutionBinding.PodTerminationBinding}, &membership)
		if err != nil || status != "observed" || capacity.NativeAdmissionCandidates(p, membership, time.Now().UTC()) != nil {
			return fail()
		}
		result.Metadata = map[string]any{"mode": "native_candidate_admission_v2", "intent": intent, "unqualified_baseline_lifetimes": membership.Unqualified, "pressure_execution_enabled": false, "useful_capacity_known": false, "warm_resources_known": false}
		result.Status, result.Error, result.FinishedAt = "succeeded", "", time.Now().UTC()
		return result
	}
	assessment := model.CapacityAssessment{}
	for _, binding := range b.Signals {
		var metric model.CapacityMetricRangeObservation
		status, e := read(binding.Adapter, capacity.ObserveMetricRange, map[string]any{"binding": binding.BindingName}, &metric)
		if e != nil || status != "succeeded" {
			return fail()
		}
		evidence, e := capacity.BoundMetricEvidence(p, binding, metric, time.Now().UTC())
		if e != nil {
			return fail()
		}
		assessment.Evidence = append(assessment.Evidence, evidence)
	}
	var hpa model.CapacityHPAEnvelopeResponse
	status, err := read(b.Snapshot.Adapter, capacity.ObserveHPAEnvelope, map[string]any{"namespace": b.Snapshot.Namespace, "hpa_name": b.Snapshot.HPAName}, &hpa)
	if err != nil || status != "observed" {
		return fail()
	}
	assessment.Snapshot, err = capacity.BoundHPASnapshot(p, hpa, time.Now().UTC())
	if err != nil {
		return fail()
	}
	// A source may become stale while later reads run. The policy's planner
	// checks the complete assembled window at the moment of assessment.
	receipt := model.CapacityBoundAssessmentReceipt{Mode: b.Snapshot.Mode, Unit: b.Snapshot.Unit, Assessment: assessment}
	if result.Operation == "capacity.assess_bound" || result.Operation == "capacity.execute_bound" {
		executor, _ := ctx.Value(capacityInvocationKey{}).(string)
		store := repository.CapacityStore{DB: db, ExecutionEnabled: result.Operation == "capacity.execute_bound" && os.Getenv("YGGDRASIL_CAPACITY_EXECUTION_ENABLED") == "true", WorkflowID: wf.ID, ExecutorID: executor}
		intent, e := store.Assess(ctx, policy, assessment)
		if e != nil {
			return fail()
		}
		if result.Operation == "capacity.execute_bound" {
			if p.HPAExecutionBinding == nil || !p.ExecutionEnabled || !store.ExecutionEnabled {
				return fail()
			}
			intent, e = runCapacityBoundExecution(ctx, store, policy, p, intent, assessment, hpa, read)
			if e != nil {
				return fail()
			}
			receipt.ExecutionEnabled = true
		}
		intent.LeaseOwner, intent.LeaseExecutorID = "", ""
		receipt.Intent = &intent
	}
	raw, err := json.Marshal(receipt)
	if err != nil || json.Unmarshal(raw, &result.Metadata) != nil {
		return fail()
	}
	result.Status, result.Error, result.FinishedAt = "succeeded", "", time.Now().UTC()
	return result
}

func capacityBoundCatalogOperation(ts model.IntegrationTypeManifestSpec, operation string) bool {
	if capacityNativeCatalogOperation(ts, operation) {
		return true
	}
	if operation != capacity.EnsureBoundHPAEnvelope && operation != capacity.EnsureNativePodDrain && operation != capacity.DestroyNativePodProtection {
		return false
	}
	for _, capability := range ts.Capabilities {
		if capability == "execute" {
			for _, action := range ts.ActionCatalog {
				if action.Name == operation && !action.Idempotent && (action.Category == "" || action.Category == "capability") {
					for _, resource := range ts.ResourceTypes {
						for _, kind := range action.ResourceTypes {
							if kind == resource.Name {
								for _, allowed := range resource.DefaultActions {
									if allowed == operation {
										return true
									}
								}
							}
						}
					}
				}
			}
		}
	}
	return false
}
