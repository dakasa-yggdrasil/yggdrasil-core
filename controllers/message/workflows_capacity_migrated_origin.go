package message

import (
	"context"
	"database/sql"
	"os"
	"reflect"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/manifest"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
	amqp "github.com/rabbitmq/amqp091-go"
)

type capacityMigratedOriginStepInput struct {
	Binding      model.CapacityMigratedNativeOriginBinding `json:"binding"`
	Confirmation string                                    `json:"confirmation"`
}

func migratedOriginHumanInput(parent context.Context, operation string, input map[string]any) (capacityMigratedOriginStepInput, error) {
	var in capacityMigratedOriginStepInput
	human, _ := parent.Value(executorPowerOperatorKey{}).(string)
	if operation != capacity.RetireMigratedNativeOrigin || capacity.DecodeNativeCapacity(input, &in) != nil || human == "" || human != in.Binding.OperatorID || in.Confirmation == "" || in.Confirmation != in.Binding.Confirmation {
		return in, errCapacityBoundAssessment
	}
	return in, nil
}

func migratedOriginLiteralWorkflow(w model.WorkflowManifestSpec, b model.CapacityMigratedNativeOriginBinding) bool {
	if w.Authorization == nil || w.Trigger.Mode != "manual" || w.DispatchMode != "sync" || len(w.Steps) != 1 {
		return false
	}
	s := w.Steps[0]
	var literal model.CapacityMigratedNativeOriginBinding
	return s.Use.Kind == "yggdrasil" && s.Use.Operation == capacity.RetireMigratedNativeOrigin && s.Use.InstanceRef == nil && s.Use.ProviderRef == nil && s.Use.Family == "" && s.Use.Capability == "" && s.Condition == "" && s.ForEach == nil && len(s.DependsOn) == 0 && s.TimeoutSeconds == 90 && s.Retry.MaxAttempts == 1 && s.Retry.BackoffSeconds == 0 && len(s.With) == 2 && s.With["confirmation"] == "{{ inputs.confirmation }}" && capacity.DecodeNativeCapacity(s.With["binding"], &literal) == nil && reflect.DeepEqual(literal, b)
}

// A protected named-human administrative operation, with only native GETs.
// Source measurements are explicitly attested administrative facts; Target
// observations are collected here, never accepted from execution input.
func executeCapacityMigratedNativeOriginStep(parent context.Context, conn *amqp.Connection, db *sql.DB, ref model.ManifestReference, result model.WorkflowRunStepResult, input map[string]any) model.WorkflowRunStepResult {
	result.Attempts = 1
	fail := func(err error) model.WorkflowRunStepResult {
		capacityDispatchCause(parent, err)
		result.Status, result.Error, result.Metadata = "failed", "protected migrated native origin retirement refused", nil
		result.FinishedAt = time.Now().UTC()
		return result
	}
	in, inputErr := migratedOriginHumanInput(parent, result.Operation, input)
	human := in.Binding.OperatorID
	if db == nil || inputErr != nil || os.Getenv("YGGDRASIL_CAPACITY_EXECUTION_ENABLED") != "true" {
		return fail(errCapacityBoundAssessment)
	}
	ctx, cancel := context.WithTimeout(parent, 90*time.Second)
	defer cancel()
	ctx, err := activateCapacityReleaseRecovery(ctx)
	if err != nil {
		return fail(err)
	}
	wf, err := repository.GetManifestByID(ctx, db, ref.ID)
	if err != nil || wf.Kind != "workflow" || !wf.Metadata.Active || wf.Version != ref.Version || wf.Metadata.Namespace != ref.Namespace || wf.Metadata.Name != ref.Name {
		return fail(errCapacityBoundAssessment)
	}
	ws, err := manifest.ParseWorkflowSpec(wf.Spec)
	if err != nil || !migratedOriginLiteralWorkflow(ws, in.Binding) {
		return fail(errCapacityBoundAssessment)
	}
	id, err := uuid.Parse(in.Binding.PolicyID)
	if err != nil {
		return fail(err)
	}
	policy, err := repository.GetManifestByID(ctx, db, id)
	if err != nil || policy.Kind != "capacity_policy" || !policy.Metadata.Active || policy.Metadata.Namespace != wf.Metadata.Namespace {
		return fail(errCapacityBoundAssessment)
	}
	p, err := manifest.ParseCapacityPolicySpec(policy.Spec)
	if err != nil || manifest.ValidateCapacityPolicySpec(p) != nil || capacity.ValidateMigratedNativeOriginBinding(policy, p, in.Binding) != nil {
		return fail(errCapacityBoundAssessment)
	}
	ops := []string{capacity.ObserveCurrentBirthGuard, capacity.ObserveHPAEnvelope, capacity.ObserveNativePodAdmissionCandidates}
	a, err := resolveCapacityObservationAdapterWithResolver(ctx, conn, db, p.AssessmentBinding.Snapshot.Adapter, ops, resolveIntegrationInstance)
	if err != nil {
		return fail(err)
	}
	read := func(op string, fixed map[string]any, out any) error {
		if e := capacityDispatchFence(ctx); e != nil {
			return e
		}
		native, e := capacityDispatchNativePolicy(ctx)
		if e != nil || native == nil || a.typeSpec.Adapter.Transport != "http_json" || !capacityBoundCatalogOperation(a.typeSpec, op) {
			return errCapacityBoundAssessment
		}
		owned := *native
		r, e := executeIntegrationThroughResolvedWithPolicy(ctx, conn, model.ExecuteIntegrationRequest{Operation: op, Capability: op, Input: fixed}, a.instance, a.instanceSpec, a.typ, a.typeSpec, 35*time.Second, integrationExecutionPolicy{detailFreeErrors: true, safeError: errCapacityBoundAssessment, requireExplicitResponse: true, nativeHTTP: &owned})
		if e != nil {
			return capacityDispatchCause(ctx, e)
		}
		if e = capacityDispatchFence(ctx); e != nil {
			return e
		}
		if r.Status != "observed" {
			return errCapacityBoundAssessment
		}
		return capacity.DecodeNativeCapacity(r.Output, out)
	}
	var evidence model.CapacityMigratedNativeTargetEvidence
	if err = read(ops[0], map[string]any{"binding_name": p.HPAExecutionBinding.BirthGuardBinding}, &evidence.BirthGuard); err != nil {
		return fail(err)
	}
	if err = read(ops[1], map[string]any{"namespace": p.AssessmentBinding.Snapshot.Namespace, "hpa_name": p.AssessmentBinding.Snapshot.HPAName}, &evidence.HPA); err != nil {
		return fail(err)
	}
	if err = read(ops[2], map[string]any{"binding_name": p.HPAExecutionBinding.PodTerminationBinding}, &evidence.Candidates); err != nil {
		return fail(err)
	}
	executor, _ := ctx.Value(capacityInvocationKey{}).(string)
	store := repository.CapacityStore{DB: db, ExecutionEnabled: true, WorkflowID: wf.ID, ExecutorID: executor, ExecutorPowerOperator: human}
	if err = store.RetireMigratedNativeOrigin(ctx, policy, in.Binding, evidence); err != nil {
		return fail(err)
	}
	result.Status, result.Error, result.FinishedAt = "succeeded", "", time.Now().UTC()
	result.Metadata = map[string]any{"disposition": "migrated_origin_administratively_retired_not_sdk_joined", "pod_uid": in.Binding.PodUID, "origin_policy_id": in.Binding.OriginPolicyID, "policy_id": policy.ID.String(), "original_admitted_checkpoint_preserved": true, "original_confirmed_commands_preserved": true, "permanent_old_uid_denied": true, "source_evidence_class": capacity.MigratedSourceFenceClass, "sdk_lane_witness": false, "original_sdk_joined": false, "original_native_release_confirmed": false, "useful_capacity_known": false, "physical_capacity_released": false}
	return result
}
