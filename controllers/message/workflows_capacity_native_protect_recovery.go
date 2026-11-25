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

type capacityNativeProtectRecoveryInput struct {
	Binding      model.CapacityUnredeemedProtectRecoveryBinding `json:"binding"`
	Confirmation string                                         `json:"confirmation"`
}

// The human authorizes one stored child; the caller supplies neither a native
// observation nor a credential. The installed adapter and worker wire stay the
// ordinary protect protocol. Opening roots remains a separate normal admission.
func executeCapacityUnredeemedProtectRecoveryStep(parent context.Context, conn *amqp.Connection, db *sql.DB, ref model.ManifestReference, result model.WorkflowRunStepResult, input map[string]any) model.WorkflowRunStepResult {
	result.Attempts = 1
	fail := func(err error) model.WorkflowRunStepResult {
		capacityDispatchCause(parent, err)
		result.Status, result.Error, result.Metadata = "failed", "protected one-use native protect recovery refused", nil
		result.FinishedAt = time.Now().UTC()
		return result
	}
	var in capacityNativeProtectRecoveryInput
	human, _ := parent.Value(executorPowerOperatorKey{}).(string)
	if db == nil || result.Operation != capacity.RecoverUnredeemedNativeProtect || capacity.DecodeNativeCapacity(input, &in) != nil || human == "" || human != in.Binding.OperatorID || in.Confirmation != in.Binding.Confirmation || os.Getenv("YGGDRASIL_CAPACITY_EXECUTION_ENABLED") != "true" || os.Getenv("YGGDRASIL_CAPACITY_ADMISSION_ENABLED") != "true" {
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
	if err != nil || ws.Authorization == nil || ws.Trigger.Mode != "manual" || ws.DispatchMode != "sync" || len(ws.Steps) != 1 {
		return fail(errCapacityBoundAssessment)
	}
	step := ws.Steps[0]
	var literal model.CapacityUnredeemedProtectRecoveryBinding
	if step.Use.Kind != "yggdrasil" || step.Use.Operation != capacity.RecoverUnredeemedNativeProtect || step.Use.InstanceRef != nil || step.Use.ProviderRef != nil || step.Use.Family != "" || step.Use.Capability != "" || step.Condition != "" || step.ForEach != nil || len(step.DependsOn) != 0 || step.TimeoutSeconds != 90 || step.Retry.MaxAttempts != 1 || step.Retry.BackoffSeconds != 0 || len(step.With) != 2 || capacity.DecodeNativeCapacity(step.With["binding"], &literal) != nil || !reflect.DeepEqual(literal, in.Binding) {
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
	if err != nil || manifest.ValidateCapacityPolicySpec(p) != nil || capacity.ValidateUnredeemedProtectRecoveryBinding(policy, p, in.Binding) != nil {
		return fail(errCapacityBoundAssessment)
	}
	a, err := resolveCapacityObservationAdapterWithResolver(ctx, conn, db, p.AssessmentBinding.Snapshot.Adapter, []string{capacity.ObserveNativePodAdmission, capacity.EnsureNativePodDrain, capacity.ObserveNativePodTermination}, resolveIntegrationInstance)
	if err != nil {
		return fail(err)
	}
	invoke := func(op string, fixed any, out any, joined *bool, token string) error {
		if e := capacityDispatchFence(ctx); e != nil {
			return e
		}
		native, e := capacityDispatchNativePolicy(ctx)
		if e != nil || native == nil || a.typeSpec.Adapter.Transport != "http_json" {
			return errCapacityBoundAssessment
		}
		owned := *native
		if joined != nil {
			owned.originalReturn = func(done bool) { *joined = done }
		}
		fields, e := boundPrivateMap(fixed)
		if e != nil {
			return e
		}
		if token != "" {
			fields["authority_token"] = token
		}
		defer delete(fields, "authority_token")
		r, e := executeIntegrationThroughResolvedWithPolicy(ctx, conn, model.ExecuteIntegrationRequest{Operation: op, Capability: op, Input: fields}, a.instance, a.instanceSpec, a.typ, a.typeSpec, 35*time.Second, integrationExecutionPolicy{detailFreeErrors: true, safeError: errCapacityBoundAssessment, requireExplicitResponse: true, nativeHTTP: &owned})
		if e != nil {
			return capacityDispatchCause(ctx, e)
		}
		if e = capacityDispatchFence(ctx); e != nil {
			return e
		}
		return capacity.DecodeNativeCapacity(r.Output, out)
	}
	executor, _ := ctx.Value(capacityInvocationKey{}).(string)
	store := repository.CapacityStore{DB: db, ExecutionEnabled: true, AdmissionOnly: true, WorkflowID: wf.ID, ExecutorID: executor, ExecutorPowerOperator: human}
	cp, err := store.UnredeemedProtectRecoveryTarget(ctx, policy, in.Binding)
	if err != nil {
		return fail(err)
	}
	bootReq := model.AdapterObserveCapacityPodAdmissionRequest{BindingName: p.HPAExecutionBinding.PodTerminationBinding, PodName: cp.PodName, ExpectedPodUID: cp.PodUID, ExpectedPodGeneration: cp.PodGeneration, ExpectedContainerID: cp.ContainerID, ExpectedContainerStartedAt: cp.ContainerStartedAt, ExpectedRestartCount: cp.RestartCount}
	var boot model.AdapterCapacityPodAdmissionResponse
	if err = invoke(capacity.ObserveNativePodAdmission, bootReq, &boot, nil, ""); err != nil {
		return fail(err)
	}
	intent, child, token, err := store.IssueUnredeemedProtectRecovery(ctx, policy, in.Binding, boot)
	if err != nil {
		return fail(err)
	}
	var request model.AdapterEnsureCapacityPodDrainRequest
	if capacity.DecodeNativeCapacity(child.Request, &request) != nil {
		return fail(errCapacityBoundAssessment)
	}
	joined := false
	var reply map[string]any
	callErr := invoke(capacity.EnsureNativePodDrain, request, &reply, &joined, token)
	if !joined {
		_, _ = store.SettleUnredeemedProtectRecovery(ctx, policy, intent, child, nil)
		return fail(errCapacityBoundAssessment)
	}
	// A failed original reply does not authorize a resend. Atomic revocation
	// settles an unused token; an actual redeemed mutation needs real readback.
	observe, err := boundPodObservationRequest(p, cp)
	if err != nil {
		return fail(err)
	}
	var after model.AdapterCapacityPodTerminationResponse
	readErr := invoke(capacity.ObserveNativePodTermination, observe, &after, nil, "")
	var readback *model.AdapterCapacityPodTerminationResponse
	if readErr == nil {
		readback = &after
	}
	refused, err := store.SettleUnredeemedProtectRecovery(ctx, policy, intent, child, readback)
	if err != nil || refused {
		return fail(errCapacityBoundAssessment)
	}
	_ = callErr // Durable redemption plus qualified readback settle a lost reply.
	result.Status, result.Error, result.FinishedAt = "succeeded", "", time.Now().UTC()
	result.Metadata = map[string]any{"disposition": "one_unredeemed_protect_child_confirmed", "command_id": child.CommandID.String(), "policy_id": policy.ID.String(), "pod_uid": cp.PodUID, "generation": intent.Generation, "fencing_token": intent.FencingToken, "ordinary_admission_required": true, "sdk_lane_witness": false, "physical_capacity_released": false}
	return result
}
