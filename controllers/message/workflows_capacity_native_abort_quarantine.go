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

type capacityNativeAbortQuarantineStepInput struct {
	Binding      model.CapacityNativeAbortQuarantineBinding `json:"binding"`
	Confirmation string                                     `json:"confirmation"`
}

// Separate protected human operation. It performs only an authenticated native
// GET followed by an append-only administrative classification; no native send.
func executeCapacityNativeAbortQuarantineStep(parent context.Context, conn *amqp.Connection, db *sql.DB, ref model.ManifestReference, result model.WorkflowRunStepResult, input map[string]any) model.WorkflowRunStepResult {
	result.Attempts = 1
	fail := func(err error) model.WorkflowRunStepResult {
		capacityDispatchCause(parent, err)
		result.Status, result.Error, result.Metadata = "failed", "protected native uncertain-abort quarantine refused", nil
		result.FinishedAt = time.Now().UTC()
		return result
	}
	var in capacityNativeAbortQuarantineStepInput
	human, _ := parent.Value(executorPowerOperatorKey{}).(string)
	if db == nil || result.Operation != capacity.QuarantineUncertainNativeBirth || capacity.DecodeNativeCapacity(input, &in) != nil || human == "" || human != in.Binding.Native.OperatorID || in.Confirmation != in.Binding.Confirmation || os.Getenv("YGGDRASIL_CAPACITY_EXECUTION_ENABLED") != "true" {
		return fail(errCapacityBoundAssessment)
	}
	ctx, cancel := context.WithTimeout(parent, 90*time.Second)
	defer cancel()
	var err error
	ctx, err = activateCapacityReleaseRecovery(ctx)
	if err != nil {
		return fail(err)
	}
	wf, err := repository.GetManifestByID(ctx, db, ref.ID)
	if err != nil || wf.Kind != "workflow" || !wf.Metadata.Active || wf.Version != ref.Version || wf.Metadata.Namespace != ref.Namespace || wf.Metadata.Name != ref.Name {
		return fail(errCapacityBoundAssessment)
	}
	ws, err := manifest.ParseWorkflowSpec(wf.Spec)
	if err != nil || ws.Authorization == nil || ws.Trigger.Mode != "manual" || ws.DispatchMode != "sync" || len(ws.Steps) != 1 {
		return fail(errCapacityBoundAssessment)
	}
	step := ws.Steps[0]
	var literal model.CapacityNativeAbortQuarantineBinding
	if step.Use.Kind != "yggdrasil" || step.Use.Operation != capacity.QuarantineUncertainNativeBirth || step.Use.InstanceRef != nil || step.Use.ProviderRef != nil || step.Use.Family != "" || step.Use.Capability != "" || step.Condition != "" || step.ForEach != nil || len(step.DependsOn) != 0 || step.TimeoutSeconds != 90 || step.Retry.MaxAttempts > 1 || step.Retry.BackoffSeconds != 0 || len(step.With) != 2 || capacity.DecodeNativeCapacity(step.With["binding"], &literal) != nil || !reflect.DeepEqual(literal, in.Binding) {
		return fail(errCapacityBoundAssessment)
	}
	id, err := uuid.Parse(in.Binding.Native.PolicyID)
	if err != nil {
		return fail(err)
	}
	policy, err := repository.GetManifestByID(ctx, db, id)
	if err != nil || policy.Kind != "capacity_policy" || !policy.Metadata.Active {
		return fail(errCapacityBoundAssessment)
	}
	p, err := manifest.ParseCapacityPolicySpec(policy.Spec)
	if err != nil || manifest.ValidateCapacityPolicySpec(p) != nil || capacity.ValidateNativeAbortQuarantineBinding(policy, p, in.Binding) != nil {
		return fail(errCapacityBoundAssessment)
	}
	a, err := resolveCapacityObservationAdapterWithResolver(ctx, conn, db, in.Binding.Native.Adapter, []string{capacity.ObserveNativeUnregisteredTerminal}, resolveIntegrationInstance)
	if err != nil {
		return fail(err)
	}
	invoke := func(op string, fixed any, out any) (string, error) {
		if e := capacityDispatchFence(ctx); e != nil {
			return "", e
		}
		native, e := capacityDispatchNativePolicy(ctx)
		if e != nil || native == nil || a.typeSpec.Adapter.Transport != "http_json" {
			return "", errCapacityBoundAssessment
		}
		owned := *native
		fields, e := nativeAbortPrivateInput(op, fixed, "")
		if e != nil {
			return "", e
		}
		defer delete(fields, "authority_token")
		r, e := executeIntegrationThroughResolvedWithPolicy(ctx, conn, model.ExecuteIntegrationRequest{Operation: op, Capability: op, Input: fields}, a.instance, a.instanceSpec, a.typ, a.typeSpec, 35*time.Second, integrationExecutionPolicy{detailFreeErrors: true, safeError: errCapacityBoundAssessment, requireExplicitResponse: true, nativeHTTP: &owned})
		if e != nil {
			return "", capacityDispatchCause(ctx, e)
		}
		if e = capacityDispatchFence(ctx); e != nil {
			return "", e
		}
		if e = capacity.DecodeNativeCapacity(r.Output, out); e != nil {
			return "", e
		}
		return r.Status, nil
	}
	executor, _ := ctx.Value(capacityInvocationKey{}).(string)
	store := repository.CapacityStore{DB: db, ExecutionEnabled: true, WorkflowID: wf.ID, ExecutorID: executor, ExecutorPowerOperator: human}
	observeReq := model.AdapterObserveCapacityPodUnregisteredTerminalRequest{BindingName: in.Binding.Native.BindingName, PodName: in.Binding.Native.PodName, ExpectedPodUID: in.Binding.Native.PodUID}
	var observed model.AdapterCapacityPodUnregisteredTerminalResponse
	status, err := invoke(capacity.ObserveNativeUnregisteredTerminal, observeReq, &observed)
	if err != nil || status != "observed" || observed.Operation != capacity.ObserveNativeUnregisteredTerminal || capacity.ValidateNativeAbortQuarantineAbsence(p, in.Binding.Native, observed, time.Now().UTC()) != nil {
		return fail(errCapacityBoundAssessment)
	}
	counts, err := store.QuarantineNativeUncertainAbort(ctx, policy, in.Binding, observed)
	if err != nil {
		return fail(err)
	}
	result.Status, result.Error, result.FinishedAt = "succeeded", "", time.Now().UTC()
	result.Metadata = map[string]any{"disposition": "uncertain_abort_administratively_quarantined", "parent_command_id": in.Binding.ParentCommandID, "command_id": in.Binding.CommandID, "pod_uid": in.Binding.Native.PodUID, "policy_id": policy.ID.String(), "generation": in.Binding.Native.Generation, "raw_uncertain_preserved": true, "original_adapter_result_present": false, "original_caller_acknowledged": false, "native_unsettled": counts, "sdk_lane_witness": false, "useful_capacity_known": false, "physical_capacity_released": false}
	return result
}
