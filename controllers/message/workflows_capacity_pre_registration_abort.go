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

const capacityAbortNativeBirthOperation = "capacity.abort_native_birth"

// Separate protected human operation. No ordinary policy field, controller
// input or adapter response enables this administrative disposition.
func executeCapacityPreRegistrationAbortStep(parent context.Context, conn *amqp.Connection, db *sql.DB, ref model.ManifestReference, result model.WorkflowRunStepResult, input map[string]any) model.WorkflowRunStepResult {
	result.Attempts = 1
	fail := func(err error) model.WorkflowRunStepResult {
		capacityDispatchCause(parent, err)
		result.Status, result.Error, result.Metadata = "failed", "protected native pre-registration abort refused", nil
		result.FinishedAt = time.Now().UTC()
		return result
	}
	var in struct {
		Binding      model.CapacityNativeAbortBinding `json:"binding"`
		Confirmation string                           `json:"confirmation"`
	}
	human, _ := parent.Value(executorPowerOperatorKey{}).(string)
	if db == nil || result.Operation != capacityAbortNativeBirthOperation || capacity.DecodeNativeCapacity(input, &in) != nil || human == "" || human != in.Binding.OperatorID || in.Confirmation != in.Binding.Confirmation || os.Getenv("YGGDRASIL_CAPACITY_EXECUTION_ENABLED") != "true" {
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
	if err != nil || ws.Authorization == nil || ws.Trigger.Mode != "manual" || len(ws.Steps) != 1 {
		return fail(errCapacityBoundAssessment)
	}
	step := ws.Steps[0]
	var literal model.CapacityNativeAbortBinding
	if step.Use.Kind != "yggdrasil" || step.Use.Operation != capacityAbortNativeBirthOperation || step.Use.InstanceRef != nil || step.Use.ProviderRef != nil || step.Use.Family != "" || step.Use.Capability != "" || step.Condition != "" || step.ForEach != nil || len(step.DependsOn) != 0 || step.Retry.MaxAttempts > 1 || step.Retry.BackoffSeconds != 0 || len(step.With) != 2 || capacity.DecodeNativeCapacity(step.With["binding"], &literal) != nil || !reflect.DeepEqual(literal, in.Binding) {
		return fail(errCapacityBoundAssessment)
	}
	id, err := uuid.Parse(in.Binding.PolicyID)
	if err != nil {
		return fail(err)
	}
	policy, err := repository.GetManifestByID(ctx, db, id)
	if err != nil || policy.Kind != "capacity_policy" || !policy.Metadata.Active {
		return fail(errCapacityBoundAssessment)
	}
	p, err := manifest.ParseCapacityPolicySpec(policy.Spec)
	if err != nil || manifest.ValidateCapacityPolicySpec(p) != nil || capacity.ValidateNativeAbortBinding(policy, p, in.Binding) != nil {
		return fail(errCapacityBoundAssessment)
	}
	a, err := resolveCapacityObservationAdapterWithResolver(ctx, conn, db, in.Binding.Adapter, []string{capacity.ObserveNativeUnregisteredTerminal, capacity.DestroyNativeUnregisteredProtection}, resolveIntegrationInstance)
	if err != nil {
		return fail(err)
	}
	invoke := func(op string, fixed any, out any, original *bool) (string, error) {
		if e := capacityDispatchFence(ctx); e != nil {
			return "", e
		}
		native, e := capacityDispatchNativePolicy(ctx)
		if e != nil || native == nil || a.typeSpec.Adapter.Transport != "http_json" {
			return "", errCapacityBoundAssessment
		}
		owned := *native
		if original != nil {
			owned.originalReturn = func(joined bool) { *original = joined }
		}
		fields, e := boundPrivateMap(fixed)
		if e != nil {
			return "", e
		}
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
	intent, err := store.ResumeNativePreRegistrationAbort(ctx, policy, in.Binding)
	if err != nil {
		return fail(err)
	}
	observeReq := model.AdapterObserveCapacityPodUnregisteredTerminalRequest{BindingName: in.Binding.BindingName, PodName: in.Binding.PodName, ExpectedPodUID: in.Binding.PodUID}
	var observed model.AdapterCapacityPodUnregisteredTerminalResponse
	status, err := invoke(capacity.ObserveNativeUnregisteredTerminal, observeReq, &observed, nil)
	if err != nil || status != "observed" || observed.Operation != capacity.ObserveNativeUnregisteredTerminal || capacity.ValidateNativeAbortObservation(p, in.Binding, observed.Observation, time.Now().UTC(), true) != nil {
		return fail(errCapacityBoundAssessment)
	}
	command, token, err := store.IssueNativePreRegistrationAbort(ctx, policy, intent, in.Binding, observed.Observation)
	if err != nil {
		return fail(err)
	}
	var request model.AdapterDestroyCapacityPodUnregisteredProtectionRequest
	if capacity.DecodeNativeCapacity(command.Request, &request) != nil {
		return fail(errCapacityBoundAssessment)
	}
	request.AuthorityToken = token
	var response model.AdapterCapacityPodUnregisteredTerminalResponse
	joined := false
	status, err = invoke(capacity.DestroyNativeUnregisteredProtection, request, &response, &joined)
	request.AuthorityToken, token = "", ""
	if err != nil || !joined || status != "aborted_before_admission" || response.Status != status || response.Operation != capacity.DestroyNativeUnregisteredProtection || response.Metadata["command_id"] != command.CommandID.String() || response.Metadata["mutation_event_retained"] != true {
		_ = store.MarkNativeCommandUncertain(ctx, command.CommandID)
		return fail(errCapacityBoundAssessment)
	}
	var fresh model.AdapterCapacityPodUnregisteredTerminalResponse
	status, err = invoke(capacity.ObserveNativeUnregisteredTerminal, observeReq, &fresh, nil)
	if err != nil || status != "observed" {
		_ = store.MarkNativeCommandUncertain(ctx, command.CommandID)
		return fail(errCapacityBoundAssessment)
	}
	if err = store.ConfirmNativePreRegistrationAbort(ctx, policy, intent, command.CommandID, fresh, joined); err != nil {
		return fail(err)
	}
	if err = store.ArchiveNativePreRegistrationAbort(ctx, policy, intent, command.CommandID); err != nil {
		return fail(err)
	}
	result.Status, result.Error, result.FinishedAt = "succeeded", "", time.Now().UTC()
	result.Metadata = map[string]any{"disposition": "abort_before_admission", "command_id": command.CommandID.String(), "pod_uid": in.Binding.PodUID, "policy_id": policy.ID.String(), "generation": intent.Generation, "fencing_token": intent.FencingToken, "lease_expires_at": intent.LeaseExpiresAt, "sdk_lane_witness": false, "useful_capacity_known": false, "physical_capacity_released": false}
	return result
}
