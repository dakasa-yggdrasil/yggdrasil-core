package message

import (
	"context"
	"database/sql"
	"errors"
	"regexp"
	"strings"

	manifestengine "github.com/dakasa-yggdrasil/yggdrasil-core/manifest"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

const (
	supportsSensitiveOutputPathsMetadataKey = "supports_sensitive_output_paths"
	sensitiveOutputSinkMetadataKey          = "sensitive_output_sink"
	sensitiveInputLeaseMetadataKey          = "sensitive_input_lease"

	sensitiveOutputLeaseVersion     = "v1"
	sensitiveOutputLeaseMode        = "transient_next_step"
	sensitiveOutputSinkFamily       = "secrets-management"
	sensitiveOutputSinkOperation    = "ensure_secret"
	sensitiveOutputSinkInputPath    = "secret.generation.manual.value"
	sensitiveOutputSinkSecretIDPath = "secret.secret_id"
	sensitiveOutputSinkStrategyPath = "secret.generation.strategy"
)

var (
	errSensitiveOutputContract = errors.New("sensitive_output_contract_violation")
	errSensitiveOutputProducer = errors.New("sensitive_output_producer_failed")
	errSensitiveOutputSink     = errors.New("sensitive_output_sink_failed")

	sensitiveWorkflowTemplatePattern = regexp.MustCompile(`{{\s*([^{}]+?)\s*}}`)
	sensitiveOutputPathPattern       = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
)

// sensitiveOutputPlan is derived by the Core from one statically eligible
// producer/sink pair. It contains no provider output and is never serialized.
type sensitiveOutputPlan struct {
	producerStepID      string
	sinkStepID          string
	sourcePath          string
	inputPath           string
	sinkInstanceID      string
	sinkInstanceVersion int
	sinkTypeID          string
	sinkTypeVersion     int
}

// sensitiveOutputLease is the only runtime object allowed to retain a
// provider-generated secret between workflow steps. It is deliberately private,
// local to one run, and absent from every JSON-facing model.
type sensitiveOutputLease struct {
	producerStepID      string
	sinkStepID          string
	sourcePath          string
	inputPath           string
	sinkInstanceID      string
	sinkInstanceVersion int
	sinkTypeID          string
	sinkTypeVersion     int
	value               string
}

type workflowStepExecutionSecurity struct {
	producerPlan *sensitiveOutputPlan
	inputLease   *sensitiveOutputLease
}

func (lease *sensitiveOutputLease) clear() {
	if lease == nil {
		return
	}
	lease.value = ""
}

func runWithSensitiveOutputLease(
	lease *sensitiveOutputLease,
	run func() ([]model.WorkflowRunStepResult, string),
) ([]model.WorkflowRunStepResult, string) {
	defer lease.clear()
	return run()
}

func failWorkflowWithUnconsumedSensitiveOutput(
	response model.RunWorkflowResponse,
	lease *sensitiveOutputLease,
) model.RunWorkflowResponse {
	if lease == nil {
		return response
	}
	failedStepID := lease.producerStepID
	lease.clear()
	response.Status = "failed"
	if response.Metadata == nil {
		response.Metadata = map[string]any{}
	}
	response.Metadata["failed_step"] = failedStepID
	response.Metadata["error"] = errSensitiveOutputContract.Error()
	return response
}

func (lease *sensitiveOutputLease) accepts(step model.WorkflowStepSpec) bool {
	if lease == nil {
		return false
	}
	return normalizeWorkflowStepID(step.ID) == lease.sinkStepID &&
		strings.EqualFold(strings.TrimSpace(step.Use.Kind), "integration") &&
		manifestengine.NormalizeWorkflowStepOperation(step) == sensitiveOutputSinkOperation &&
		manifestengine.NormalizeWorkflowStepCapability(step) == sensitiveOutputSinkOperation &&
		strings.TrimSpace(step.Condition) == "" && step.ForEach == nil
}

func (plan *sensitiveOutputPlan) producerMetadata() map[string]any {
	if plan == nil {
		return nil
	}
	return map[string]any{
		supportsSensitiveOutputPathsMetadataKey: true,
		sensitiveOutputSinkMetadataKey: map[string]any{
			"version":             sensitiveOutputLeaseVersion,
			"mode":                sensitiveOutputLeaseMode,
			"producer_step_id":    plan.producerStepID,
			"step_id":             plan.sinkStepID,
			"family":              sensitiveOutputSinkFamily,
			"operation":           sensitiveOutputSinkOperation,
			"input_path":          plan.inputPath,
			"source_output_paths": []string{plan.sourcePath},
		},
	}
}

func (lease *sensitiveOutputLease) sinkMetadata() map[string]any {
	if lease == nil {
		return nil
	}
	return map[string]any{
		sensitiveInputLeaseMetadataKey: map[string]any{
			"version":        sensitiveOutputLeaseVersion,
			"mode":           sensitiveOutputLeaseMode,
			"source_step_id": lease.producerStepID,
			"input_paths":    []string{lease.inputPath},
		},
	}
}

// authorizeSensitiveOutputPlan issues a producer handshake only after the
// complete static pair is valid and the sink resolves to the canonical secret
// management family. Resolution errors intentionally withhold the handshake;
// guarded producers then fail before provider mutation.
func authorizeSensitiveOutputPlan(
	ctx context.Context,
	db *sql.DB,
	orderedSteps []model.WorkflowStepSpec,
	index int,
	executionCtx manifestengine.WorkflowExecutionContext,
) *sensitiveOutputPlan {
	plan := deriveSensitiveOutputPlan(orderedSteps, index)
	if plan == nil {
		return nil
	}

	sink := orderedSteps[index+1]
	if !sensitiveOutputSinkSecretIDResolvable(sink, executionCtx) {
		return nil
	}
	resolvedUse, err := renderWorkflowStepUse(sink.Use, executionCtx)
	if err != nil {
		return nil
	}

	instanceManifest, typeManifest, typeSpec, err := resolveSensitiveOutputSinkReadOnly(ctx, db, resolvedUse)
	if err != nil || !isSensitiveOutputSinkType(typeSpec) {
		return nil
	}
	plan.sinkInstanceID = instanceManifest.ID.String()
	plan.sinkInstanceVersion = instanceManifest.Version
	plan.sinkTypeID = typeManifest.ID.String()
	plan.sinkTypeVersion = typeManifest.Version
	return plan
}

func resolveSensitiveOutputSinkReadOnly(
	ctx context.Context,
	db *sql.DB,
	use model.WorkflowStepUseSpec,
) (model.Manifest, model.Manifest, model.IntegrationTypeManifestSpec, error) {
	if db == nil {
		return model.Manifest{}, model.Manifest{}, model.IntegrationTypeManifestSpec{}, errors.New("database connection is required")
	}
	if use.InstanceRef != nil {
		instanceManifest, err := resolveManifestForKind(
			ctx,
			db,
			"integration_instance",
			use.InstanceRef.ManifestID,
			use.InstanceRef.Namespace,
			use.InstanceRef.Name,
			use.InstanceRef.Version,
		)
		if err != nil || !strings.EqualFold(instanceManifest.Kind, "integration_instance") || !instanceManifest.Metadata.Active {
			return model.Manifest{}, model.Manifest{}, model.IntegrationTypeManifestSpec{}, errors.New("sensitive output sink instance could not be resolved")
		}
		instanceSpec, err := manifestengine.ParseIntegrationInstanceSpec(instanceManifest.Spec)
		if err != nil || normalizeIntegrationInstanceDeclaredStatus(instanceSpec.Status) != "active" {
			return model.Manifest{}, model.Manifest{}, model.IntegrationTypeManifestSpec{}, errors.New("sensitive output sink instance is not active")
		}
		typeManifest, err := resolveManifestForKind(
			ctx,
			db,
			"integration_type",
			instanceSpec.TypeRef.ManifestID,
			instanceSpec.TypeRef.Namespace,
			instanceSpec.TypeRef.Name,
			instanceSpec.TypeRef.Version,
		)
		if err != nil || !strings.EqualFold(typeManifest.Kind, "integration_type") || !typeManifest.Metadata.Active {
			return model.Manifest{}, model.Manifest{}, model.IntegrationTypeManifestSpec{}, errors.New("sensitive output sink type could not be resolved")
		}
		typeSpec, err := manifestengine.ParseIntegrationTypeSpec(typeManifest.Spec)
		return instanceManifest, typeManifest, typeSpec, err
	}

	typeManifest, typeSpec, err := resolveProviderForFamily(
		ctx,
		db,
		use.Family,
		use.Operation,
		use.ProviderRef,
	)
	if err != nil {
		return model.Manifest{}, model.Manifest{}, model.IntegrationTypeManifestSpec{}, err
	}
	instanceManifest, instanceSpec, err := resolveActiveInstanceForProvider(ctx, db, typeManifest)
	if err != nil || normalizeIntegrationInstanceDeclaredStatus(instanceSpec.Status) != "active" {
		return model.Manifest{}, model.Manifest{}, model.IntegrationTypeManifestSpec{}, errors.New("sensitive output sink instance is not active")
	}
	return instanceManifest, typeManifest, typeSpec, nil
}

func deriveSensitiveOutputPlan(orderedSteps []model.WorkflowStepSpec, index int) *sensitiveOutputPlan {
	if index < 0 || index+1 >= len(orderedSteps) {
		return nil
	}

	producer := orderedSteps[index]
	sink := orderedSteps[index+1]
	producerID := normalizeWorkflowStepID(producer.ID)
	sinkID := normalizeWorkflowStepID(sink.ID)
	producerOperation := manifestengine.NormalizeWorkflowStepOperation(producer)
	producerCapability := manifestengine.NormalizeWorkflowStepCapability(producer)
	sinkOperation := manifestengine.NormalizeWorkflowStepOperation(sink)
	sinkCapability := manifestengine.NormalizeWorkflowStepCapability(sink)
	if producerID == "" || sinkID == "" ||
		!strings.EqualFold(strings.TrimSpace(producer.Use.Kind), "integration") ||
		producerOperation == "" || producerOperation == model.WorkflowDispatchOperation ||
		producerCapability != producerOperation ||
		workflowStepAttempts(producer) != 1 ||
		strings.TrimSpace(producer.Condition) != "" || producer.ForEach != nil ||
		!strings.EqualFold(strings.TrimSpace(sink.Use.Kind), "integration") ||
		sinkOperation != sensitiveOutputSinkOperation || sinkCapability != sinkOperation ||
		strings.TrimSpace(sink.Condition) != "" || sink.ForEach != nil {
		return nil
	}

	if len(sink.DependsOn) != 1 || normalizeWorkflowStepID(sink.DependsOn[0]) != producerID {
		return nil
	}
	strategy, ok := workflowStringAtPath(sink.With, strings.Split(sensitiveOutputSinkStrategyPath, "."))
	if !ok || strategy != "manual" {
		return nil
	}
	secretID, ok := workflowStringAtPath(sink.With, strings.Split(sensitiveOutputSinkSecretIDPath, "."))
	if !ok || strings.TrimSpace(secretID) == "" {
		return nil
	}

	rawTemplate, ok := workflowStringAtPath(sink.With, strings.Split(sensitiveOutputSinkInputPath, "."))
	if !ok {
		return nil
	}
	sourcePath, ok := exactSensitiveOutputSource(rawTemplate, producerID)
	if !ok {
		return nil
	}

	reference := "steps." + producerID + ".metadata.output." + sourcePath
	if countSensitiveOutputReferences(orderedSteps, reference) != 1 {
		return nil
	}

	return &sensitiveOutputPlan{
		producerStepID: producerID,
		sinkStepID:     sinkID,
		sourcePath:     sourcePath,
		inputPath:      sensitiveOutputSinkInputPath,
	}
}

func sensitiveOutputSinkSecretIDResolvable(
	step model.WorkflowStepSpec,
	executionCtx manifestengine.WorkflowExecutionContext,
) bool {
	raw, ok := workflowStringAtPath(step.With, strings.Split(sensitiveOutputSinkSecretIDPath, "."))
	if !ok {
		return false
	}
	rendered, err := manifestengine.RenderWorkflowInput(raw, executionCtx)
	if err != nil {
		return false
	}
	secretID, ok := rendered.(string)
	if !ok || secretID == "" || secretID != strings.TrimSpace(secretID) {
		return false
	}
	return !strings.Contains(secretID, "{{") && !strings.Contains(secretID, "}}")
}

func isSensitiveOutputSinkType(typeSpec model.IntegrationTypeManifestSpec) bool {
	return typeSpec.FamilyRef != nil &&
		strings.EqualFold(strings.TrimSpace(typeSpec.FamilyRef.Name), sensitiveOutputSinkFamily) &&
		containsFold(typeSpec.ImplementedOperations, sensitiveOutputSinkOperation)
}

func (lease *sensitiveOutputLease) matchesResolvedSink(instanceManifest, typeManifest model.Manifest) bool {
	if lease == nil || lease.sinkInstanceID == "" || lease.sinkTypeID == "" {
		return false
	}
	return strings.EqualFold(instanceManifest.ID.String(), lease.sinkInstanceID) &&
		instanceManifest.Version == lease.sinkInstanceVersion &&
		strings.EqualFold(typeManifest.ID.String(), lease.sinkTypeID) &&
		typeManifest.Version == lease.sinkTypeVersion
}

func exactSensitiveOutputSource(rawTemplate, producerStepID string) (string, bool) {
	trimmed := strings.TrimSpace(rawTemplate)
	matches := sensitiveWorkflowTemplatePattern.FindAllStringSubmatch(trimmed, -1)
	if len(matches) != 1 || strings.TrimSpace(matches[0][0]) != trimmed {
		return "", false
	}

	parts := strings.Split(strings.TrimSpace(matches[0][1]), ".")
	if len(parts) != 5 || parts[0] != "steps" || parts[1] != producerStepID ||
		parts[2] != "metadata" || parts[3] != "output" {
		return "", false
	}
	// V1 authorizes one top-level output path only. Splitting into five parts
	// catches a nested or derived path before any secret exists.
	if parts[4] == "" || !sensitiveOutputPathPattern.MatchString(parts[4]) {
		return "", false
	}
	return parts[4], true
}

func workflowStringAtPath(root map[string]any, segments []string) (string, bool) {
	var current any = root
	for _, segment := range segments {
		object, ok := current.(map[string]any)
		if !ok {
			return "", false
		}
		current, ok = object[segment]
		if !ok {
			return "", false
		}
	}
	value, ok := current.(string)
	return value, ok
}

func countSensitiveOutputReferences(steps []model.WorkflowStepSpec, reference string) int {
	reference, ok := canonicalWorkflowTemplatePath(reference)
	if !ok {
		return 0
	}
	count := 0
	for _, step := range steps {
		for _, path := range workflowTemplatePathsInStep(step) {
			path, ok = canonicalWorkflowTemplatePath(path)
			if !ok {
				continue
			}
			if path == reference || strings.HasPrefix(path, reference+".") || strings.HasPrefix(reference, path+".") {
				count++
			}
		}
	}
	return count
}

func canonicalWorkflowTemplatePath(path string) (string, bool) {
	parts := strings.Split(strings.TrimSpace(path), ".")
	for index, part := range parts {
		parts[index] = strings.TrimSpace(part)
		if parts[index] == "" {
			return "", false
		}
	}
	return strings.Join(parts, "."), true
}

func workflowTemplatePathsInStep(step model.WorkflowStepSpec) []string {
	paths := workflowTemplatePathsInValue(step.With)
	for _, value := range []string{
		step.Condition,
		step.Use.Family,
		step.Use.Operation,
		step.Use.Capability,
	} {
		paths = append(paths, workflowTemplatePathsInString(value)...)
	}
	if step.ForEach != nil {
		paths = append(paths, workflowTemplatePathsInString(step.ForEach.Items)...)
	}
	for _, selector := range []*model.ManifestSelector{step.Use.InstanceRef, step.Use.ProviderRef} {
		if selector == nil {
			continue
		}
		paths = append(paths, workflowTemplatePathsInString(selector.ManifestID)...)
		paths = append(paths, workflowTemplatePathsInString(selector.Namespace)...)
		paths = append(paths, workflowTemplatePathsInString(selector.Name)...)
	}
	return paths
}

func workflowTemplatePathsInValue(value any) []string {
	var paths []string
	switch typed := value.(type) {
	case map[string]any:
		for key, item := range typed {
			paths = append(paths, workflowTemplatePathsInString(key)...)
			paths = append(paths, workflowTemplatePathsInValue(item)...)
		}
	case []any:
		for _, item := range typed {
			paths = append(paths, workflowTemplatePathsInValue(item)...)
		}
	case []string:
		for _, item := range typed {
			paths = append(paths, workflowTemplatePathsInString(item)...)
		}
	case string:
		paths = append(paths, workflowTemplatePathsInString(typed)...)
	}
	return paths
}

func workflowTemplatePathsInString(value string) []string {
	matches := sensitiveWorkflowTemplatePattern.FindAllStringSubmatch(value, -1)
	paths := make([]string, 0, len(matches))
	for _, match := range matches {
		if len(match) == 2 {
			paths = append(paths, strings.TrimSpace(match[1]))
		}
	}
	return paths
}

func secureSensitiveProducerResult(
	result model.WorkflowRunStepResult,
	plan *sensitiveOutputPlan,
) (model.WorkflowRunStepResult, *sensitiveOutputLease) {
	rawPaths, declared := result.Metadata["sensitive_output_paths"]
	if plan != nil && result.Status != "succeeded" {
		return sensitiveOutputProducerFailure(result), nil
	}
	if !declared {
		if plan != nil {
			if output, ok := result.Metadata["output"].(map[string]any); ok {
				if _, sourcePresent := output[plan.sourcePath]; sourcePresent {
					return sensitiveOutputContractFailure(result), nil
				}
			}
		}
		return result, nil
	}
	if plan == nil || result.Status != "succeeded" {
		return sensitiveOutputContractFailure(result), nil
	}

	paths, ok := strictSensitiveOutputPaths(rawPaths)
	if !ok || len(paths) != 1 || paths[0] != plan.sourcePath {
		return sensitiveOutputContractFailure(result), nil
	}
	output, ok := result.Metadata["output"].(map[string]any)
	if !ok {
		return sensitiveOutputContractFailure(result), nil
	}
	value, ok := output[plan.sourcePath].(string)
	if !ok || value == "" {
		return sensitiveOutputContractFailure(result), nil
	}

	safe := redactSensitiveWorkflowStepResult(result)
	if metadata, ok := redactWorkflowSensitiveValue(safe.Metadata, value).(map[string]any); ok {
		safe.Metadata = metadata
	} else {
		return sensitiveOutputContractFailure(result), nil
	}
	safe.Error = ""
	return safe, &sensitiveOutputLease{
		producerStepID:      plan.producerStepID,
		sinkStepID:          plan.sinkStepID,
		sourcePath:          plan.sourcePath,
		inputPath:           plan.inputPath,
		sinkInstanceID:      plan.sinkInstanceID,
		sinkInstanceVersion: plan.sinkInstanceVersion,
		sinkTypeID:          plan.sinkTypeID,
		sinkTypeVersion:     plan.sinkTypeVersion,
		value:               value,
	}
}

func sensitiveOutputProducerFailure(result model.WorkflowRunStepResult) model.WorkflowRunStepResult {
	result.Status = "failed"
	result.Error = errSensitiveOutputProducer.Error()
	result.Metadata = map[string]any{
		"output":                           redactedWorkflowOutputValue,
		"sensitive_output_redacted":        true,
		"sensitive_output_redaction_scope": "output",
	}
	return result
}

func strictSensitiveOutputPaths(raw any) ([]string, bool) {
	var values []string
	switch typed := raw.(type) {
	case []string:
		values = append([]string(nil), typed...)
	case []any:
		values = make([]string, 0, len(typed))
		for _, item := range typed {
			value, ok := item.(string)
			if !ok {
				return nil, false
			}
			values = append(values, value)
		}
	default:
		return nil, false
	}
	if len(values) == 0 {
		return nil, false
	}

	seen := make(map[string]struct{}, len(values))
	for index, value := range values {
		trimmed := strings.TrimSpace(value)
		if value != trimmed || trimmed == "" || !sensitiveOutputPathPattern.MatchString(trimmed) {
			return nil, false
		}
		if _, duplicated := seen[trimmed]; duplicated {
			return nil, false
		}
		seen[trimmed] = struct{}{}
		values[index] = trimmed
	}
	return values, true
}

func sensitiveOutputContractFailure(result model.WorkflowRunStepResult) model.WorkflowRunStepResult {
	result.Status = "failed"
	result.Error = errSensitiveOutputContract.Error()
	result.Metadata = map[string]any{
		"output":                              redactedWorkflowOutputValue,
		"sensitive_output_redacted":           true,
		"sensitive_output_redaction_scope":    "output",
		"sensitive_output_contract_violation": true,
	}
	return result
}

func renderSensitiveOutputSinkInput(
	step model.WorkflowStepSpec,
	executionCtx manifestengine.WorkflowExecutionContext,
	lease *sensitiveOutputLease,
) (map[string]any, error) {
	if lease == nil || !lease.accepts(step) || lease.value == "" {
		return nil, errSensitiveOutputSink
	}

	overlayCtx := executionCtx
	overlayCtx.Steps = make(map[string]model.WorkflowRunStepResult, len(executionCtx.Steps))
	for id, stepResult := range executionCtx.Steps {
		overlayCtx.Steps[id] = stepResult
	}
	source, ok := overlayCtx.Steps[lease.producerStepID]
	if !ok {
		return nil, errSensitiveOutputSink
	}
	source.Metadata = cloneWorkflowResultMap(source.Metadata)
	output, ok := source.Metadata["output"].(map[string]any)
	if !ok {
		return nil, errSensitiveOutputSink
	}
	output = cloneWorkflowResultMap(output)
	output[lease.sourcePath] = lease.value
	source.Metadata["output"] = output
	overlayCtx.Steps[lease.producerStepID] = source
	defer func() { output[lease.sourcePath] = redactedWorkflowOutputValue }()

	rendered, err := renderWorkflowStepInput(step, overlayCtx)
	if err != nil {
		return nil, errSensitiveOutputSink
	}
	leaf, ok := workflowValueAtPath(rendered, strings.Split(lease.inputPath, "."))
	strategy, strategyOK := workflowValueAtPath(rendered, strings.Split(sensitiveOutputSinkStrategyPath, "."))
	secretID, secretIDOK := workflowValueAtPath(rendered, strings.Split(sensitiveOutputSinkSecretIDPath, "."))
	if !ok || leaf != lease.value || countWorkflowStringValue(rendered, lease.value) != 1 ||
		!strategyOK || strategy != "manual" || !secretIDOK || secretID == "" ||
		secretID != strings.TrimSpace(secretID) || strings.Contains(secretID, "{{") || strings.Contains(secretID, "}}") {
		clearSensitiveRenderedInput(rendered, lease.value)
		return nil, errSensitiveOutputSink
	}
	return rendered, nil
}

func workflowValueAtPath(root map[string]any, segments []string) (string, bool) {
	value, ok := workflowStringAtPath(root, segments)
	return value, ok
}

func countWorkflowStringValue(value any, target string) int {
	count := 0
	switch typed := value.(type) {
	case map[string]any:
		for key, item := range typed {
			count += strings.Count(key, target)
			count += countWorkflowStringValue(item, target)
		}
	case []any:
		for _, item := range typed {
			count += countWorkflowStringValue(item, target)
		}
	case []string:
		for _, item := range typed {
			count += strings.Count(item, target)
		}
	case string:
		count += strings.Count(typed, target)
	}
	return count
}

func redactWorkflowSensitiveValue(value any, target string) any {
	switch typed := value.(type) {
	case map[string]any:
		redacted := make(map[string]any, len(typed))
		for key, item := range typed {
			redactedKey := strings.ReplaceAll(key, target, redactedWorkflowOutputValue)
			redacted[redactedKey] = redactWorkflowSensitiveValue(item, target)
		}
		return redacted
	case []any:
		redacted := make([]any, len(typed))
		for index, item := range typed {
			redacted[index] = redactWorkflowSensitiveValue(item, target)
		}
		return redacted
	case []string:
		redacted := append([]string(nil), typed...)
		for index, item := range redacted {
			redacted[index] = strings.ReplaceAll(item, target, redactedWorkflowOutputValue)
		}
		return redacted
	case string:
		return strings.ReplaceAll(typed, target, redactedWorkflowOutputValue)
	}
	return value
}

func clearSensitiveRenderedInput(input map[string]any, value string) {
	if input == nil || value == "" {
		return
	}
	redacted, ok := redactWorkflowSensitiveValue(input, value).(map[string]any)
	if !ok {
		return
	}
	for key := range input {
		delete(input, key)
	}
	for key, item := range redacted {
		input[key] = item
	}
}

func sensitiveOutputSinkReceipt() map[string]any {
	return map[string]any{
		"integration_status":            "succeeded",
		"sensitive_input_persisted":     true,
		"sensitive_input_lease_version": sensitiveOutputLeaseVersion,
	}
}

func secureSensitiveOutputSinkResponse(
	result model.WorkflowRunStepResult,
	response model.ExecuteIntegrationResponse,
) (model.WorkflowRunStepResult, bool) {
	if !sensitiveOutputSinkStatusSucceeded(response.Status) {
		result.Status = "failed"
		result.Error = errSensitiveOutputSink.Error()
		result.Metadata = nil
		return result, false
	}
	result.Status = "succeeded"
	result.Error = ""
	result.Metadata = sensitiveOutputSinkReceipt()
	return result, true
}

func sensitiveOutputSinkStatusSucceeded(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "created", "updated", "unchanged":
		return true
	default:
		return false
	}
}

func validateReservedIntegrationMetadata(metadata map[string]any) error {
	for key := range metadata {
		switch strings.ToLower(strings.TrimSpace(key)) {
		case supportsSensitiveOutputPathsMetadataKey, sensitiveOutputSinkMetadataKey, sensitiveInputLeaseMetadataKey:
			return errors.New("integration metadata contains a workflow-runtime-reserved key")
		}
	}
	return nil
}
