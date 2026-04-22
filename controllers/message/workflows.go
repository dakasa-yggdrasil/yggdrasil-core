package message

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	manifestengine "github.com/dakasa-yggdrasil/yggdrasil-core/manifest"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
	amqp "github.com/rabbitmq/amqp091-go"
	"go.uber.org/zap"
)

const (
	queueWorkflowDispatch      = "yggdrasil-core.workflow.dispatch"
	queueWorkflowRun           = "yggdrasil-core.workflow.run"
	defaultWorkflowStepTimeout = 20 * time.Second
)

func workflowConsumers(conn *amqp.Connection, db *sql.DB, logger *zap.Logger) []ConsumerConfig {
	return []ConsumerConfig{
		{
			Queue:   queueWorkflowDispatch,
			Timeout: 20 * time.Second,
			QoS:     10,
			Handler: workflowDispatchHandler(conn, db, logger),
		},
		{
			Queue:   queueWorkflowRun,
			Timeout: 60 * time.Second,
			QoS:     5,
			Handler: workflowRunHandler(conn, db, logger),
		},
	}
}

func workflowDispatchHandler(conn *amqp.Connection, db *sql.DB, logger *zap.Logger) ConsumerHandler {
	return func(ctx context.Context, d amqp.Delivery) error {
		var req model.DispatchWorkflowRequest
		if err := json.Unmarshal(d.Body, &req); err != nil {
			return replyFailure(ctx, conn, d, "bad_request", err, logger)
		}

		req = normalizeWorkflowDispatchRequest(req)
		if err := validateWorkflowDispatchRequest(req); err != nil {
			return replyFailure(ctx, conn, d, "bad_request", err, logger)
		}

		instanceManifest, instanceSpec, typeManifest, typeSpec, err := resolveIntegrationInstance(ctx, conn, db, req.Runner)
		if err != nil {
			return replyFailure(ctx, conn, d, integrationAwareErrorCode(err, "dispatch_failed"), err, logger)
		}

		response, err := dispatchWorkflowThroughIntegration(ctx, conn, req, instanceManifest, instanceSpec, typeManifest, typeSpec, 0)
		if err != nil {
			return replyFailure(ctx, conn, d, "dispatch_failed", err, logger)
		}

		return replySuccess(ctx, conn, d, response, logger)
	}
}

func workflowRunHandler(conn *amqp.Connection, db *sql.DB, logger *zap.Logger) ConsumerHandler {
	return func(ctx context.Context, d amqp.Delivery) error {
		var req model.RunWorkflowRequest
		if err := json.Unmarshal(d.Body, &req); err != nil {
			return replyFailure(ctx, conn, d, "bad_request", err, logger)
		}

		response, err := RunWorkflow(ctx, conn, db, req)
		if err != nil {
			code := integrationAwareErrorCode(err, "workflow_run_failed")
			if manifestLookupErrorCode(err) != "internal_error" {
				code = manifestLookupErrorCode(err)
			} else if strings.Contains(strings.ToLower(strings.TrimSpace(err.Error())), "required") ||
				strings.Contains(strings.ToLower(strings.TrimSpace(err.Error())), "invalid") ||
				strings.Contains(strings.ToLower(strings.TrimSpace(err.Error())), "unsupported") ||
				strings.Contains(strings.ToLower(strings.TrimSpace(err.Error())), "validation") {
				code = "bad_request"
			}
			return replyFailure(ctx, conn, d, code, err, logger)
		}

		// Emit workflow.run.completed event (best-effort, post-execution).
		// Workflow runs are not transactional with the core DB; they involve
		// external integration calls. The event is emitted in its own tx
		// after the run finishes. On emit failure, log and continue.
		emitWorkflowRunCompletedEvent(ctx, db, logger, response)

		return replySuccess(ctx, conn, d, response, logger)
	}
}

// emitWorkflowRunCompletedEvent records a workflow run completion in the
// core event stream. Best-effort: failures are logged but do not affect the
// caller response. Called after RunWorkflow returns successfully (workflow
// status may still be "failed" if a step failed — the event captures that).
func emitWorkflowRunCompletedEvent(
	ctx context.Context,
	db *sql.DB,
	logger *zap.Logger,
	response model.RunWorkflowResponse,
) {
	runID := uuid.NewString()
	payload := map[string]interface{}{
		"workflow_ref": map[string]interface{}{
			"id":        response.Workflow.ID.String(),
			"name":      response.Workflow.Name,
			"namespace": response.Workflow.Namespace,
			"version":   response.Workflow.Version,
		},
		"run_id":       runID,
		"status":       response.Status,
		"started_at":   response.StartedAt.Format(time.RFC3339),
		"finished_at":  response.FinishedAt.Format(time.RFC3339),
		"step_count":   len(response.Steps),
		"triggered_by": "manual",
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		if logger != nil {
			logger.Warn("emit workflow.run.completed: begin tx failed", zap.Error(err))
		}
		return
	}
	defer tx.Rollback()

	if _, err := repository.EmitEvent(ctx, tx, model.EmitEventRequest{
		Type:          "workflow.run.completed",
		SchemaVersion: "v1",
		AggregateType: "workflow_run",
		AggregateID:   runID,
		Payload:       payload,
	}); err != nil {
		if logger != nil {
			logger.Warn("emit workflow.run.completed: emit failed", zap.Error(err))
		}
		return
	}

	if err := tx.Commit(); err != nil {
		if logger != nil {
			logger.Warn("emit workflow.run.completed: commit failed", zap.Error(err))
		}
	}
}

// RunWorkflow executes one stored workflow definition directly from an in-process caller.
func RunWorkflow(
	ctx context.Context,
	conn *amqp.Connection,
	db *sql.DB,
	req model.RunWorkflowRequest,
) (model.RunWorkflowResponse, error) {
	req = normalizeRunWorkflowRequest(req)
	if err := validateRunWorkflowRequest(req); err != nil {
		return model.RunWorkflowResponse{}, err
	}

	workflowManifest, spec, err := resolveWorkflowManifestSpec(ctx, db, req.Workflow)
	if err != nil {
		return model.RunWorkflowResponse{}, err
	}

	if err := manifestengine.ValidateWorkflowSpec(spec); err != nil {
		return model.RunWorkflowResponse{}, err
	}
	mergedInputs := manifestengine.MergeWorkflowInputs(spec, req.Inputs)
	if err := manifestengine.ValidateWorkflowInputs(spec, mergedInputs); err != nil {
		return model.RunWorkflowResponse{}, err
	}
	req.Inputs = mergedInputs

	return runWorkflow(ctx, conn, db, workflowManifest, spec, req)
}

func resolveWorkflowManifestSpec(ctx context.Context, db *sql.DB, selector model.ManifestSelector) (model.Manifest, model.WorkflowManifestSpec, error) {
	workflowManifest, err := resolveManifestForKind(ctx, db, "workflow", selector.ManifestID, selector.Namespace, selector.Name, selector.Version)
	if err != nil {
		return model.Manifest{}, model.WorkflowManifestSpec{}, err
	}

	spec, err := manifestengine.ParseWorkflowSpec(workflowManifest.Spec)
	if err != nil {
		return model.Manifest{}, model.WorkflowManifestSpec{}, fmt.Errorf("parse workflow spec: %w", err)
	}

	return workflowManifest, spec, nil
}

func runWorkflow(
	ctx context.Context,
	conn *amqp.Connection,
	db *sql.DB,
	workflowManifest model.Manifest,
	spec model.WorkflowManifestSpec,
	req model.RunWorkflowRequest,
) (model.RunWorkflowResponse, error) {
	orderedSteps, err := manifestengine.WorkflowExecutionOrder(spec)
	if err != nil {
		return model.RunWorkflowResponse{}, err
	}

	workflowRef := manifestReferenceFromRecord(workflowManifest)
	startedAt := time.Now().UTC()
	response := model.RunWorkflowResponse{
		Workflow:  workflowRef,
		Status:    "succeeded",
		Metadata:  cloneAuthorizationInput(req.Metadata),
		StartedAt: startedAt,
	}

	executionCtx := manifestengine.WorkflowExecutionContext{
		Inputs:   req.Inputs,
		Metadata: req.Metadata,
		Auth:     req.Auth,
		Workflow: workflowRef,
		Steps:    map[string]model.WorkflowRunStepResult{},
	}

	for index, step := range orderedSteps {
		result := executeWorkflowStep(ctx, conn, db, workflowRef, step, executionCtx, req)
		response.Steps = append(response.Steps, result)
		executionCtx.Steps[result.ID] = result

		// A condition-skipped step is recorded as "skipped" but the workflow
		// keeps running. Only a truly failed step aborts the run.
		if result.Status == "failed" {
			response.Status = "failed"
			response.FinishedAt = result.FinishedAt
			response.Steps = append(response.Steps, skipWorkflowSteps(orderedSteps[index+1:], result.ID)...)
			if response.Metadata == nil {
				response.Metadata = map[string]any{}
			}
			response.Metadata["failed_step"] = result.ID
			return response, nil
		}
	}

	response.FinishedAt = time.Now().UTC()
	return response, nil
}

func executeWorkflowStep(
	ctx context.Context,
	conn *amqp.Connection,
	db *sql.DB,
	workflowRef model.ManifestReference,
	step model.WorkflowStepSpec,
	executionCtx manifestengine.WorkflowExecutionContext,
	req model.RunWorkflowRequest,
) model.WorkflowRunStepResult {
	stepID := normalizeWorkflowStepID(step.ID)
	result := model.WorkflowRunStepResult{
		ID:         stepID,
		Kind:       strings.ToLower(strings.TrimSpace(step.Use.Kind)),
		Operation:  manifestengine.NormalizeWorkflowStepOperation(step),
		Capability: manifestengine.NormalizeWorkflowStepCapability(step),
		Status:     "failed",
		StartedAt:  time.Now().UTC(),
	}

	// Condition gate: skip the step when Condition evaluates to false.
	// A condition that fails to render fails the step fail-loud so
	// broken workflows surface the mistake immediately.
	if strings.TrimSpace(step.Condition) != "" {
		run, err := manifestengine.EvaluateWorkflowStepCondition(step.Condition, executionCtx)
		if err != nil {
			result.Error = err.Error()
			result.Attempts = 1
			result.FinishedAt = time.Now().UTC()
			return result
		}
		if !run {
			result.Status = "skipped"
			result.Attempts = 0
			result.Metadata = map[string]any{
				"skip_reason": "condition",
				"condition":   step.Condition,
			}
			result.FinishedAt = time.Now().UTC()
			return result
		}
	}

	renderedInput, err := renderWorkflowStepInput(step, executionCtx)
	if err != nil {
		result.Error = err.Error()
		result.Attempts = 1
		result.FinishedAt = time.Now().UTC()
		return result
	}

	// Branch on step kind: product steps have their own execution path that
	// dispatches to the in-process product handlers (apply, observe, etc.)
	// rather than going through an integration adapter.
	if result.Kind == "product" {
		return executeProductWorkflowStep(ctx, conn, db, workflowRef, step, result, renderedInput)
	}

	var (
		instanceManifest model.Manifest
		instanceSpec     model.IntegrationInstanceManifestSpec
		typeManifest     model.Manifest
		typeSpec         model.IntegrationTypeManifestSpec
	)
	if step.Use.InstanceRef != nil {
		instanceManifest, instanceSpec, typeManifest, typeSpec, err = resolveIntegrationInstance(ctx, conn, db, *step.Use.InstanceRef)
	} else {
		instanceManifest, instanceSpec, typeManifest, typeSpec, err = resolveIntegrationByFamily(
			ctx, conn, db, step.Use.Family, step.Use.Operation, step.Use.ProviderRef,
		)
	}
	if err != nil {
		result.Error = err.Error()
		result.Attempts = 1
		result.FinishedAt = time.Now().UTC()
		return result
	}
	result.IntegrationInstance = manifestReferencePointer(manifestReferenceFromRecord(instanceManifest))
	result.IntegrationType = manifestReferencePointer(manifestReferenceFromRecord(typeManifest))

	maxAttempts := workflowStepAttempts(step)
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		result.Attempts = attempt

		switch result.Operation {
		case model.WorkflowDispatchOperation:
			dispatchReq := buildWorkflowDispatchStepRequest(workflowRef, step, renderedInput, req)
			dispatchResp, err := dispatchWorkflowThroughIntegration(
				ctx,
				conn,
				dispatchReq,
				instanceManifest,
				instanceSpec,
				typeManifest,
				typeSpec,
				workflowStepTimeout(step, typeSpec),
			)
			if err == nil {
				result.Status = "succeeded"
				result.Metadata = mergeStringAnyMaps(dispatchResp.Metadata, map[string]any{
					"adapter_status": dispatchResp.Status,
					"workflow":       dispatchResp.Workflow,
				})
				result.FinishedAt = time.Now().UTC()
				return result
			}

			result.Error = err.Error()
		default:
			executeReq := model.ExecuteIntegrationRequest{
				Integration: *step.Use.InstanceRef,
				Operation:   result.Operation,
				Capability:  result.Capability,
				Input:       cloneAuthorizationInput(renderedInput),
				Auth:        workflowDispatchAuthToMap(req.Auth),
				Metadata: map[string]any{
					"workflow": workflowRef,
					"step_id":  result.ID,
					"source":   "workflow.run",
				},
			}

			executeResp, err := executeIntegrationThroughResolved(
				ctx,
				conn,
				executeReq,
				instanceManifest,
				instanceSpec,
				typeManifest,
				typeSpec,
				workflowStepTimeout(step, typeSpec),
			)
			if err == nil {
				result.Status = normalizeWorkflowIntegrationStatus(executeResp.Status)
				result.Metadata = mergeStringAnyMaps(executeResp.Metadata, map[string]any{
					"integration_status": executeResp.Status,
					"output":             executeResp.Output,
				})
				if result.Status == "succeeded" {
					result.FinishedAt = time.Now().UTC()
					return result
				}

				result.Error = fmt.Sprintf("integration returned status %q", executeResp.Status)
			} else {
				result.Error = err.Error()
			}
		}

		if attempt >= maxAttempts {
			break
		}

		if err := sleepWithContext(ctx, workflowStepBackoff(step)); err != nil {
			result.Error = err.Error()
			break
		}
	}

	result.FinishedAt = time.Now().UTC()
	return result
}

func skipWorkflowSteps(steps []model.WorkflowStepSpec, failedStepID string) []model.WorkflowRunStepResult {
	if len(steps) == 0 {
		return nil
	}

	now := time.Now().UTC()
	results := make([]model.WorkflowRunStepResult, 0, len(steps))
	for _, step := range steps {
		results = append(results, model.WorkflowRunStepResult{
			ID:         normalizeWorkflowStepID(step.ID),
			Kind:       strings.ToLower(strings.TrimSpace(step.Use.Kind)),
			Operation:  manifestengine.NormalizeWorkflowStepOperation(step),
			Capability: manifestengine.NormalizeWorkflowStepCapability(step),
			Status:     "skipped",
			Error:      fmt.Sprintf("workflow aborted after step %q failed", failedStepID),
			StartedAt:  now,
			FinishedAt: now,
		})
	}

	return results
}

func buildWorkflowDispatchStepRequest(
	workflowRef model.ManifestReference,
	step model.WorkflowStepSpec,
	input map[string]any,
	req model.RunWorkflowRequest,
) model.DispatchWorkflowRequest {
	metadata := mergeStringAnyMaps(req.Metadata, workflowInputMap(input["metadata"]))
	if metadata == nil {
		metadata = map[string]any{}
	}
	metadata["workflow_manifest"] = map[string]any{
		"namespace": workflowRef.Namespace,
		"name":      workflowRef.Name,
		"version":   workflowRef.Version,
	}
	metadata["workflow_step"] = normalizeWorkflowStepID(step.ID)

	return normalizeWorkflowDispatchRequest(model.DispatchWorkflowRequest{
		Runner:     *step.Use.InstanceRef,
		Operation:  manifestengine.NormalizeWorkflowStepOperation(step),
		Capability: manifestengine.NormalizeWorkflowStepCapability(step),
		Workflow: model.WorkflowDispatchSpec{
			ComponentID: workflowInputString(input["component_id"]),
			Repository:  workflowInputString(input["repository"]),
			Workflow:    workflowInputString(input["workflow"]),
			Ref:         workflowInputString(input["ref"]),
			Inputs:      workflowInputMap(input["inputs"]),
			Metadata:    metadata,
		},
		Auth: req.Auth,
	})
}

func renderWorkflowStepInput(step model.WorkflowStepSpec, executionCtx manifestengine.WorkflowExecutionContext) (map[string]any, error) {
	rendered, err := manifestengine.RenderWorkflowInput(step.With, executionCtx)
	if err != nil {
		return nil, err
	}
	if rendered == nil {
		return map[string]any{}, nil
	}

	scope, ok := rendered.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("workflow step %q rendered a non-object payload", step.ID)
	}
	return scope, nil
}

func workflowInputMap(value any) map[string]any {
	typed, ok := value.(map[string]any)
	if !ok || typed == nil {
		return map[string]any{}
	}
	return cloneAuthorizationInput(typed)
}

func workflowInputString(value any) string {
	if value == nil {
		return ""
	}
	return strings.TrimSpace(fmt.Sprint(value))
}

func workflowStepAttempts(step model.WorkflowStepSpec) int {
	if step.Retry.MaxAttempts > 0 {
		return step.Retry.MaxAttempts
	}
	return 1
}

func workflowStepBackoff(step model.WorkflowStepSpec) time.Duration {
	if step.Retry.BackoffSeconds <= 0 {
		return 0
	}
	return time.Duration(step.Retry.BackoffSeconds) * time.Second
}

func workflowStepTimeout(step model.WorkflowStepSpec, typeSpec model.IntegrationTypeManifestSpec) time.Duration {
	if step.TimeoutSeconds > 0 {
		return time.Duration(step.TimeoutSeconds) * time.Second
	}
	if typeSpec.Adapter.TimeoutSeconds > 0 {
		return time.Duration(typeSpec.Adapter.TimeoutSeconds) * time.Second
	}
	return defaultWorkflowStepTimeout
}

func sleepWithContext(ctx context.Context, duration time.Duration) error {
	if duration <= 0 {
		return nil
	}

	timer := time.NewTimer(duration)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func dispatchWorkflowThroughIntegration(
	ctx context.Context,
	conn *amqp.Connection,
	req model.DispatchWorkflowRequest,
	instanceManifest model.Manifest,
	instanceSpec model.IntegrationInstanceManifestSpec,
	typeManifest model.Manifest,
	typeSpec model.IntegrationTypeManifestSpec,
	timeoutOverride time.Duration,
) (model.DispatchWorkflowResponse, error) {
	request := model.ExecuteIntegrationRequest{
		Operation:  req.Operation,
		Capability: req.Capability,
		Input: map[string]any{
			"component_id": req.Workflow.ComponentID,
			"repository":   req.Workflow.Repository,
			"workflow":     req.Workflow.Workflow,
			"ref":          req.Workflow.Ref,
			"inputs":       cloneAuthorizationInput(req.Workflow.Inputs),
			"metadata":     cloneAuthorizationInput(req.Workflow.Metadata),
		},
		Auth: workflowDispatchAuthToMap(req.Auth),
		Metadata: map[string]any{
			"source": "workflow.dispatch",
		},
	}

	response, err := executeIntegrationThroughResolved(
		ctx,
		conn,
		request,
		instanceManifest,
		instanceSpec,
		typeManifest,
		typeSpec,
		timeoutOverride,
	)
	if err != nil {
		return model.DispatchWorkflowResponse{}, err
	}

	workflow := req.Workflow
	renderedWorkflow := workflowDispatchSpecFromOutput(response.Output)
	if workflowDispatchSpecProvided(renderedWorkflow) {
		workflow = mergeWorkflowDispatchSpec(workflow, renderedWorkflow)
	}

	status := normalizeDispatchExecutionStatus(response.Status)
	if status == "" {
		status = "dispatched"
	}

	return model.DispatchWorkflowResponse{
		Operation:       req.Operation,
		Status:          status,
		Runner:          manifestReferenceFromRecord(instanceManifest),
		IntegrationType: manifestReferenceFromRecord(typeManifest),
		Workflow:        workflow,
		Metadata:        response.Metadata,
	}, nil
}

func workflowDispatchSpecProvided(spec model.WorkflowDispatchSpec) bool {
	return strings.TrimSpace(spec.Repository) != "" ||
		strings.TrimSpace(spec.Workflow) != "" ||
		strings.TrimSpace(spec.Ref) != "" ||
		strings.TrimSpace(spec.ComponentID) != "" ||
		len(spec.Inputs) > 0 ||
		len(spec.Metadata) > 0
}

func workflowDispatchSpecFromOutput(value any) model.WorkflowDispatchSpec {
	output, ok := value.(map[string]any)
	if !ok || output == nil {
		return model.WorkflowDispatchSpec{}
	}

	return model.WorkflowDispatchSpec{
		ComponentID: workflowInputString(output["component_id"]),
		Repository:  workflowInputString(output["repository"]),
		Workflow:    workflowInputString(output["workflow"]),
		Ref:         workflowInputString(output["ref"]),
		Inputs:      workflowInputMap(output["inputs"]),
		Metadata:    workflowInputMap(output["metadata"]),
	}
}

func mergeWorkflowDispatchSpec(base model.WorkflowDispatchSpec, override model.WorkflowDispatchSpec) model.WorkflowDispatchSpec {
	if strings.TrimSpace(override.ComponentID) != "" {
		base.ComponentID = override.ComponentID
	}
	if strings.TrimSpace(override.Repository) != "" {
		base.Repository = override.Repository
	}
	if strings.TrimSpace(override.Workflow) != "" {
		base.Workflow = override.Workflow
	}
	if strings.TrimSpace(override.Ref) != "" {
		base.Ref = override.Ref
	}
	if len(override.Inputs) > 0 {
		base.Inputs = override.Inputs
	}
	if len(override.Metadata) > 0 {
		base.Metadata = override.Metadata
	}
	return base
}

func normalizeDispatchExecutionStatus(status string) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "", "ok", "done", "completed", "success", "succeeded":
		return "dispatched"
	default:
		return strings.TrimSpace(status)
	}
}

func workflowDispatchAuthToMap(auth model.WorkflowDispatchAuth) map[string]any {
	if strings.TrimSpace(auth.Token) == "" {
		return map[string]any{}
	}
	return map[string]any{
		"token": strings.TrimSpace(auth.Token),
	}
}

func normalizeWorkflowIntegrationStatus(status string) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "", "ok", "done", "completed", "dispatched", "succeeded", "success":
		return "succeeded"
	default:
		return "failed"
	}
}

func normalizeRunWorkflowRequest(req model.RunWorkflowRequest) model.RunWorkflowRequest {
	req.Auth.Token = strings.TrimSpace(req.Auth.Token)
	if req.Inputs == nil {
		req.Inputs = map[string]any{}
	}
	if req.Metadata == nil {
		req.Metadata = map[string]any{}
	}
	return req
}

func validateRunWorkflowRequest(req model.RunWorkflowRequest) error {
	if !manifestSelectorProvided(&req.Workflow) {
		return fmt.Errorf("workflow requires manifest_id or name")
	}
	return nil
}

func normalizeWorkflowDispatchRequest(req model.DispatchWorkflowRequest) model.DispatchWorkflowRequest {
	req.Operation = strings.TrimSpace(req.Operation)
	if req.Operation == "" {
		req.Operation = model.WorkflowDispatchOperation
	}

	req.Capability = strings.TrimSpace(req.Capability)
	if req.Capability == "" {
		req.Capability = req.Operation
	}

	req.Workflow.Repository = strings.TrimSpace(req.Workflow.Repository)
	req.Workflow.Workflow = strings.TrimSpace(req.Workflow.Workflow)
	req.Workflow.Ref = strings.TrimSpace(req.Workflow.Ref)
	req.Workflow.ComponentID = strings.TrimSpace(req.Workflow.ComponentID)
	req.Auth.Token = strings.TrimSpace(req.Auth.Token)

	if req.Workflow.Inputs == nil {
		req.Workflow.Inputs = map[string]any{}
	}
	if req.Workflow.Metadata == nil {
		req.Workflow.Metadata = map[string]any{}
	}

	return req
}

func validateWorkflowDispatchRequest(req model.DispatchWorkflowRequest) error {
	if strings.TrimSpace(req.Runner.ManifestID) == "" && strings.TrimSpace(req.Runner.Name) == "" {
		return fmt.Errorf("workflow runner requires manifest_id or name")
	}
	if strings.TrimSpace(req.Workflow.Repository) == "" {
		return fmt.Errorf("workflow repository is required")
	}
	if strings.TrimSpace(req.Workflow.Workflow) == "" {
		return fmt.Errorf("workflow name is required")
	}

	return nil
}

func mergeStringAnyMaps(base map[string]any, extra map[string]any) map[string]any {
	if len(base) == 0 && len(extra) == 0 {
		return nil
	}

	merged := map[string]any{}
	for key, value := range base {
		merged[key] = value
	}
	for key, value := range extra {
		merged[key] = value
	}

	return merged
}

func normalizeWorkflowStepID(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

// executeProductWorkflowStep runs a workflow step with use.kind = "product".
// Supported operations: materialize, installation.reconcile, installation.apply,
// installation.observe, installation.uninstall, installation_state.discover.
//
// The step's with.product_ref identifies the target Product, and optional
// with.target_overrides redirect specific components to different integration
// instances at runtime (Gap 3 of the product audit).
func executeProductWorkflowStep(
	ctx context.Context,
	conn *amqp.Connection,
	db *sql.DB,
	workflowRef model.ManifestReference,
	step model.WorkflowStepSpec,
	result model.WorkflowRunStepResult,
	renderedInput map[string]any,
) model.WorkflowRunStepResult {
	result.Attempts = 1

	operation := strings.ToLower(strings.TrimSpace(step.Use.Operation))

	productRef, err := parseProductRefFromStepInput(renderedInput)
	if err != nil {
		result.Error = fmt.Sprintf("product step with.product_ref: %v", err)
		result.FinishedAt = time.Now().UTC()
		return result
	}

	targetOverrides, err := parseTargetOverridesFromStepInput(renderedInput)
	if err != nil {
		result.Error = fmt.Sprintf("product step with.target_overrides: %v", err)
		result.FinishedAt = time.Now().UTC()
		return result
	}

	productManifest, spec, err := resolveProductManifestSpec(ctx, db, productRef)
	if err != nil {
		result.Error = fmt.Sprintf("resolve product: %v", err)
		result.FinishedAt = time.Now().UTC()
		return result
	}

	if err := validateTargetOverrides(targetOverrides, spec); err != nil {
		result.Error = err.Error()
		result.FinishedAt = time.Now().UTC()
		return result
	}

	logger := zap.NewNop()
	executor := newProductTargetExecutor(conn, db, logger).withTargetOverrides(targetOverrides)

	switch operation {
	case "installation.apply":
		applyResults, err := executor.applyProduct(ctx, productManifest, spec)
		if err != nil {
			result.Error = fmt.Sprintf("apply: %v", err)
			result.FinishedAt = time.Now().UTC()
			return result
		}
		emitProductInstallationAppliedEvent(ctx, db, logger, productManifest, spec, applyResults, targetOverrides)
		result.Status = "succeeded"
		result.Metadata = map[string]any{
			"product_ref":        manifestReferenceFromRecord(productManifest),
			"components_applied": len(applyResults),
		}
		if len(targetOverrides) > 0 {
			result.Metadata["target_overrides_used"] = len(targetOverrides)
		}

	case "installation.observe":
		observeResults, err := executor.observeProduct(ctx, productManifest, spec)
		if err != nil {
			result.Error = fmt.Sprintf("observe: %v", err)
			result.FinishedAt = time.Now().UTC()
			return result
		}
		result.Status = "succeeded"
		result.Metadata = map[string]any{
			"product_ref":         manifestReferenceFromRecord(productManifest),
			"components_observed": len(observeResults),
		}

	case "installation.uninstall":
		uninstallResults, err := executor.uninstallProduct(ctx, productManifest, spec)
		if err != nil {
			result.Error = fmt.Sprintf("uninstall: %v", err)
			result.FinishedAt = time.Now().UTC()
			return result
		}
		emitProductInstallationUninstalledEvent(ctx, db, logger, productManifest, spec, uninstallResults, targetOverrides)
		result.Status = "succeeded"
		result.Metadata = map[string]any{
			"product_ref":            manifestReferenceFromRecord(productManifest),
			"components_uninstalled": len(uninstallResults),
		}
		if len(targetOverrides) > 0 {
			result.Metadata["target_overrides_used"] = len(targetOverrides)
		}

	case "materialize", "installation.reconcile", "installation_state.discover":
		// These operations exist at the RPC level but are not yet wired into
		// the workflow step executor. Reject with a clear error so callers
		// know they need to wait for a future core release (or use direct
		// RPC dispatch instead of a workflow step).
		result.Error = fmt.Sprintf("product step operation %q not yet supported in workflow executor (use direct RPC)", operation)
		result.FinishedAt = time.Now().UTC()
		return result

	default:
		result.Error = fmt.Sprintf("unsupported product step operation %q", operation)
		result.FinishedAt = time.Now().UTC()
		return result
	}

	result.FinishedAt = time.Now().UTC()
	_ = workflowRef
	return result
}

// parseProductRefFromStepInput extracts a ManifestSelector from the step's
// with.product_ref field. Accepts both object form (with namespace/name) and
// is strict about type: returns an error if product_ref is missing or has
// the wrong shape.
func parseProductRefFromStepInput(input map[string]any) (model.ManifestSelector, error) {
	raw, ok := input["product_ref"]
	if !ok {
		return model.ManifestSelector{}, fmt.Errorf("product_ref is required")
	}
	refMap, ok := raw.(map[string]any)
	if !ok {
		return model.ManifestSelector{}, fmt.Errorf("product_ref must be an object, got %T", raw)
	}

	ref := model.ManifestSelector{}
	if id, ok := refMap["id"].(string); ok {
		ref.ManifestID = id
	}
	if namespace, ok := refMap["namespace"].(string); ok {
		ref.Namespace = namespace
	}
	if name, ok := refMap["name"].(string); ok {
		ref.Name = name
	}
	if version, ok := refMap["version"].(float64); ok {
		v := int(version)
		ref.Version = &v
	}

	if ref.ManifestID == "" && (ref.Name == "" || ref.Namespace == "") {
		return model.ManifestSelector{}, fmt.Errorf("product_ref requires id OR (namespace + name)")
	}

	return ref, nil
}

// parseTargetOverridesFromStepInput extracts the optional target_overrides
// map from the step's with field. Returns an empty map if not present.
// Each override must be a map with integration_instance_ref (with name +
// optional namespace) and optional top-level namespace.
func parseTargetOverridesFromStepInput(input map[string]any) (map[string]model.TargetOverride, error) {
	raw, ok := input["target_overrides"]
	if !ok {
		return nil, nil
	}
	rawMap, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("target_overrides must be an object, got %T", raw)
	}

	overrides := make(map[string]model.TargetOverride, len(rawMap))
	for key, value := range rawMap {
		valueMap, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("target_overrides[%q] must be an object", key)
		}

		override := model.TargetOverride{}

		refRaw, ok := valueMap["integration_instance_ref"]
		if !ok {
			return nil, fmt.Errorf("target_overrides[%q].integration_instance_ref is required", key)
		}
		refMap, ok := refRaw.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("target_overrides[%q].integration_instance_ref must be an object", key)
		}
		if name, ok := refMap["name"].(string); ok {
			override.IntegrationInstanceRef.Name = name
		}
		if namespace, ok := refMap["namespace"].(string); ok {
			override.IntegrationInstanceRef.Namespace = namespace
		}
		if override.IntegrationInstanceRef.Name == "" {
			return nil, fmt.Errorf("target_overrides[%q].integration_instance_ref.name is required", key)
		}

		if ns, ok := valueMap["namespace"].(string); ok {
			override.Namespace = ns
		}

		if imageRaw, ok := valueMap["image_overrides"]; ok {
			imageMap, ok := imageRaw.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("target_overrides[%q].image_overrides must be an object", key)
			}
			if len(imageMap) > 0 {
				override.ImageOverrides = make(map[string]string, len(imageMap))
				for originalRef, replacement := range imageMap {
					replacementStr, ok := replacement.(string)
					if !ok {
						return nil, fmt.Errorf("target_overrides[%q].image_overrides[%q] must be a string", key, originalRef)
					}
					override.ImageOverrides[originalRef] = replacementStr
				}
			}
		}

		overrides[key] = override
	}

	return overrides, nil
}
