package message

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	manifestengine "github.com/dakasa-yggdrasil/yggdrasil-core/manifest"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

const sensitiveLeaseTestCanary = "whsec_CANARY_DO_NOT_PERSIST_20260905_core"

func TestDeriveSensitiveOutputPlanAcceptsOnlyImmediateExactSingleConsumer(t *testing.T) {
	steps := sensitiveLeaseTestSteps()
	plan := deriveSensitiveOutputPlan(steps, 0)
	if plan == nil {
		t.Fatal("expected eligible adjacent producer/sink pair")
	}
	if plan.producerStepID != "provision-webhook" || plan.sinkStepID != "persist-webhook-secret" ||
		plan.sourcePath != "secret" || plan.inputPath != sensitiveOutputSinkInputPath {
		t.Fatalf("unexpected plan: %#v", plan)
	}

	wantMetadata := map[string]any{
		supportsSensitiveOutputPathsMetadataKey: true,
		sensitiveOutputSinkMetadataKey: map[string]any{
			"version":             "v1",
			"mode":                "transient_next_step",
			"producer_step_id":    "provision-webhook",
			"step_id":             "persist-webhook-secret",
			"family":              "secrets-management",
			"operation":           "ensure_secret",
			"input_path":          "secret.generation.manual.value",
			"source_output_paths": []string{"secret"},
		},
	}
	if got := plan.producerMetadata(); !reflect.DeepEqual(got, wantMetadata) {
		t.Fatalf("producer metadata = %#v, want %#v", got, wantMetadata)
	}
}

func TestDeriveSensitiveOutputPlanWithholdsHandshakeForInvalidShapes(t *testing.T) {
	forEach := &model.WorkflowForEachSpec{Items: "{{ inputs.items }}", As: "item"}
	tests := map[string]func([]model.WorkflowStepSpec) []model.WorkflowStepSpec{
		"interposed step": func(steps []model.WorkflowStepSpec) []model.WorkflowStepSpec {
			unrelated := model.WorkflowStepSpec{
				ID:        "unrelated",
				DependsOn: []string{"provision-webhook"},
				Use: model.WorkflowStepUseSpec{
					Kind:        "integration",
					Operation:   "observe_resource",
					InstanceRef: &model.ManifestSelector{Name: "observer", Namespace: "test"},
				},
			}
			return []model.WorkflowStepSpec{steps[0], unrelated, steps[1]}
		},
		"missing exact dependency": func(steps []model.WorkflowStepSpec) []model.WorkflowStepSpec {
			steps[1].DependsOn = nil
			return steps
		},
		"extra dependency": func(steps []model.WorkflowStepSpec) []model.WorkflowStepSpec {
			steps[1].DependsOn = []string{"provision-webhook", "other"}
			return steps
		},
		"wrong operation": func(steps []model.WorkflowStepSpec) []model.WorkflowStepSpec {
			steps[1].Use.Operation = "read_secret"
			return steps
		},
		"wrong producer capability": func(steps []model.WorkflowStepSpec) []model.WorkflowStepSpec {
			steps[0].Use.Capability = "observe_webhook_endpoint"
			return steps
		},
		"wrong sink capability": func(steps []model.WorkflowStepSpec) []model.WorkflowStepSpec {
			steps[1].Use.Capability = "read_secret"
			return steps
		},
		"wrong input path": func(steps []model.WorkflowStepSpec) []model.WorkflowStepSpec {
			steps[1].With = map[string]any{"value": sensitiveLeaseTemplate()}
			return steps
		},
		"missing secret id": func(steps []model.WorkflowStepSpec) []model.WorkflowStepSpec {
			delete(steps[1].With["secret"].(map[string]any), "secret_id")
			return steps
		},
		"missing manual strategy": func(steps []model.WorkflowStepSpec) []model.WorkflowStepSpec {
			delete(steps[1].With["secret"].(map[string]any)["generation"].(map[string]any), "strategy")
			return steps
		},
		"wrong generation strategy": func(steps []model.WorkflowStepSpec) []model.WorkflowStepSpec {
			steps[1].With["secret"].(map[string]any)["generation"].(map[string]any)["strategy"] = "random_string"
			return steps
		},
		"concatenated template": func(steps []model.WorkflowStepSpec) []model.WorkflowStepSpec {
			setSensitiveLeaseInput(steps[1].With, "prefix-"+sensitiveLeaseTemplate())
			return steps
		},
		"nested output path": func(steps []model.WorkflowStepSpec) []model.WorkflowStepSpec {
			setSensitiveLeaseInput(steps[1].With, "{{ steps.provision-webhook.metadata.output.secret.value }}")
			return steps
		},
		"producer condition": func(steps []model.WorkflowStepSpec) []model.WorkflowStepSpec {
			steps[0].Condition = "true"
			return steps
		},
		"producer retry": func(steps []model.WorkflowStepSpec) []model.WorkflowStepSpec {
			steps[0].Retry.MaxAttempts = 2
			return steps
		},
		"sink condition": func(steps []model.WorkflowStepSpec) []model.WorkflowStepSpec {
			steps[1].Condition = "true"
			return steps
		},
		"producer for_each": func(steps []model.WorkflowStepSpec) []model.WorkflowStepSpec {
			steps[0].ForEach = forEach
			return steps
		},
		"sink for_each": func(steps []model.WorkflowStepSpec) []model.WorkflowStepSpec {
			steps[1].ForEach = forEach
			return steps
		},
		"second consumer": func(steps []model.WorkflowStepSpec) []model.WorkflowStepSpec {
			steps = append(steps, model.WorkflowStepSpec{
				ID:        "leak",
				DependsOn: []string{"persist-webhook-secret"},
				Use: model.WorkflowStepUseSpec{
					Kind:        "integration",
					Operation:   "send",
					InstanceRef: &model.ManifestSelector{Name: "other", Namespace: "test"},
				},
				With: map[string]any{"body": sensitiveLeaseTemplate()},
			})
			return steps
		},
		"ancestor consumer": func(steps []model.WorkflowStepSpec) []model.WorkflowStepSpec {
			steps[1].With["all_output"] = "{{ steps.provision-webhook.metadata.output }}"
			return steps
		},
		"root ancestor consumer": func(steps []model.WorkflowStepSpec) []model.WorkflowStepSpec {
			steps[1].With["all_steps"] = "{{ steps }}"
			return steps
		},
		"spaced equivalent consumer": func(steps []model.WorkflowStepSpec) []model.WorkflowStepSpec {
			steps[1].With["copy"] = "{{ steps . provision-webhook . metadata . output . secret }}"
			return steps
		},
	}

	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			if plan := deriveSensitiveOutputPlan(mutate(sensitiveLeaseTestSteps()), 0); plan != nil {
				t.Fatalf("invalid pair issued handshake: %#v", plan)
			}
		})
	}
}

func TestSensitiveOutputSinkFamilyUsesResolvedTypeNotInstanceName(t *testing.T) {
	wrongFamily := model.IntegrationTypeManifestSpec{
		FamilyRef: &model.ManifestSelector{Name: "payments"},
	}
	if isSensitiveOutputSinkType(wrongFamily) {
		t.Fatal("instance naming must not establish the sink family")
	}

	rightFamily := model.IntegrationTypeManifestSpec{
		FamilyRef:             &model.ManifestSelector{Name: "secrets-management"},
		ImplementedOperations: []string{sensitiveOutputSinkOperation},
	}
	if !isSensitiveOutputSinkType(rightFamily) {
		t.Fatal("resolved secrets-management type should be eligible")
	}

	missingOperation := model.IntegrationTypeManifestSpec{
		FamilyRef:             &model.ManifestSelector{Name: "secrets-management"},
		ImplementedOperations: []string{"read_secret"},
	}
	if isSensitiveOutputSinkType(missingOperation) {
		t.Fatal("sink type without ensure_secret implementation must not be eligible")
	}
}

func TestSensitiveOutputSinkSecretIDMustResolveBeforeHandshake(t *testing.T) {
	ctx := manifestengine.WorkflowExecutionContext{Inputs: map[string]any{"secret_id": "stripe/webhook"}}
	step := sensitiveLeaseTestSteps()[1]
	step.With["secret"].(map[string]any)["secret_id"] = "{{ inputs.secret_id }}"
	if !sensitiveOutputSinkSecretIDResolvable(step, ctx) {
		t.Fatal("concrete rendered secret_id was rejected")
	}

	for name, value := range map[string]string{
		"missing input":       "{{ inputs.missing }}",
		"downstream template": "{{ service }}",
		"padded":              " stripe/webhook ",
		"empty":               "",
	} {
		t.Run(name, func(t *testing.T) {
			candidate := sensitiveLeaseTestSteps()[1]
			candidate.With["secret"].(map[string]any)["secret_id"] = value
			if sensitiveOutputSinkSecretIDResolvable(candidate, ctx) {
				t.Fatalf("unsafe secret_id %q was accepted", value)
			}
		})
	}
}

func TestAuthorizeSensitiveOutputPlanRejectsLookalikeInstanceUsingReadOnlyCatalogResolution(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("open sqlmock: %v", err)
	}
	defer db.Close()

	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	columns := []string{
		"id", "api_version", "kind", "namespace", "name", "version", "active",
		"description", "labels", "spec", "checksum", "created_at", "updated_at",
	}
	mock.ExpectQuery(`FROM public\.manifests\s+WHERE kind = \$1 AND namespace = \$2 AND name = \$3`).
		WithArgs("integration_instance", "test", "secrets-management-prod").
		WillReturnRows(sqlmock.NewRows(columns).AddRow(
			"11111111-1111-4111-8111-111111111111",
			"yggdrasil.dakasa.io/v1alpha1",
			"integration_instance",
			"test",
			"secrets-management-prod",
			1,
			true,
			"",
			[]byte(`{}`),
			[]byte(`{"type_ref":{"namespace":"global","name":"payments"},"status":"active","discovery":{"enabled":false}}`),
			"checksum-instance",
			now,
			now,
		))
	mock.ExpectQuery(`FROM public\.manifests\s+WHERE kind = \$1 AND namespace = \$2 AND name = \$3`).
		WithArgs("integration_type", "global", "payments").
		WillReturnRows(sqlmock.NewRows(columns).AddRow(
			"22222222-2222-4222-8222-222222222222",
			"yggdrasil.dakasa.io/v1alpha1",
			"integration_type",
			"global",
			"payments",
			1,
			true,
			"",
			[]byte(`{}`),
			[]byte(`{"provider":"fake","family_ref":{"name":"payments"}}`),
			"checksum-type",
			now,
			now,
		))

	steps := sensitiveLeaseTestSteps()
	steps[1].Use.Family = ""
	steps[1].Use.InstanceRef = &model.ManifestSelector{
		Name:      "secrets-management-prod",
		Namespace: "test",
	}
	plan := authorizeSensitiveOutputPlan(
		context.Background(),
		db,
		steps,
		0,
		manifestengine.WorkflowExecutionContext{Steps: map[string]model.WorkflowRunStepResult{}},
	)
	if plan != nil {
		t.Fatalf("lookalike instance issued handshake: %#v", plan)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("catalog resolution performed an unexpected query or write: %v", err)
	}
}

func TestAuthorizeSensitiveOutputPlanPinsReadOnlyResolvedSinkIdentity(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("open sqlmock: %v", err)
	}
	defer db.Close()

	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	columns := []string{
		"id", "api_version", "kind", "namespace", "name", "version", "active",
		"description", "labels", "spec", "checksum", "created_at", "updated_at",
	}
	mock.ExpectQuery(`FROM public\.manifests\s+WHERE kind = \$1 AND namespace = \$2 AND name = \$3`).
		WithArgs("integration_instance", "test", "secrets-management-prod").
		WillReturnRows(sqlmock.NewRows(columns).AddRow(
			"33333333-3333-4333-8333-333333333333",
			"yggdrasil.dakasa.io/v1alpha1",
			"integration_instance",
			"test",
			"secrets-management-prod",
			7,
			true,
			"",
			[]byte(`{}`),
			[]byte(`{"type_ref":{"namespace":"global","name":"aws-secrets-management"},"status":"active","discovery":{"enabled":false}}`),
			"checksum-instance",
			now,
			now,
		))
	mock.ExpectQuery(`FROM public\.manifests\s+WHERE kind = \$1 AND namespace = \$2 AND name = \$3`).
		WithArgs("integration_type", "global", "aws-secrets-management").
		WillReturnRows(sqlmock.NewRows(columns).AddRow(
			"44444444-4444-4444-8444-444444444444",
			"yggdrasil.dakasa.io/v1alpha1",
			"integration_type",
			"global",
			"aws-secrets-management",
			11,
			true,
			"",
			[]byte(`{}`),
			[]byte(`{"provider":"aws","family_ref":{"name":"secrets-management"},"implemented_operations":["ensure_secret"]}`),
			"checksum-type",
			now,
			now,
		))

	steps := sensitiveLeaseTestSteps()
	steps[1].Use.Family = ""
	steps[1].Use.InstanceRef = &model.ManifestSelector{
		Name:      "secrets-management-prod",
		Namespace: "test",
	}
	plan := authorizeSensitiveOutputPlan(
		context.Background(),
		db,
		steps,
		0,
		manifestengine.WorkflowExecutionContext{Steps: map[string]model.WorkflowRunStepResult{}},
	)
	if plan == nil {
		t.Fatal("expected eligible read-only sink authorization")
	}
	if plan.sinkInstanceID != "33333333-3333-4333-8333-333333333333" || plan.sinkInstanceVersion != 7 ||
		plan.sinkTypeID != "44444444-4444-4444-8444-444444444444" || plan.sinkTypeVersion != 11 {
		t.Fatalf("authorization did not pin resolved identity: %#v", plan)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("catalog authorization performed an unexpected query or write: %v", err)
	}
}

func TestSecureSensitiveProducerResultCreatesPrivateLeaseAndStoresOnlyRedactedResult(t *testing.T) {
	plan := deriveSensitiveOutputPlan(sensitiveLeaseTestSteps(), 0)
	raw := model.WorkflowRunStepResult{
		ID:     "provision-webhook",
		Status: "succeeded",
		Error:  "unexpected echo " + sensitiveLeaseTestCanary,
		Metadata: map[string]any{
			"output": map[string]any{
				"id":     "we_123",
				"secret": sensitiveLeaseTestCanary,
			},
			"sensitive_output_paths": []any{"secret"},
			"accidental_echo":        "prefix-" + sensitiveLeaseTestCanary,
		},
	}

	safe, lease := secureSensitiveProducerResult(raw, plan)
	if lease == nil || lease.value != sensitiveLeaseTestCanary {
		t.Fatalf("lease = %#v, want private canary", lease)
	}
	assertJSONExcludesCanary(t, safe)
	output := safe.Metadata["output"].(map[string]any)
	if output["id"] != "we_123" || output["secret"] != redactedWorkflowOutputValue {
		t.Fatalf("safe producer output = %#v", output)
	}
	if safe.Metadata["accidental_echo"] != "prefix-"+redactedWorkflowOutputValue {
		t.Fatalf("metadata echo was not redacted: %#v", safe.Metadata)
	}
	if safe.Error != "" {
		t.Fatalf("successful producer retained an error: %q", safe.Error)
	}

	ctx := manifestengine.WorkflowExecutionContext{
		Steps: map[string]model.WorkflowRunStepResult{"provision-webhook": safe},
	}
	resolved, err := manifestengine.RenderWorkflowInput(sensitiveLeaseTemplate(), ctx)
	if err != nil {
		t.Fatalf("render redacted context: %v", err)
	}
	if resolved != redactedWorkflowOutputValue {
		t.Fatalf("general workflow context resolved %q, want redaction", resolved)
	}

	sink := sensitiveLeaseTestSteps()[1]
	rendered, err := renderSensitiveOutputSinkInput(sink, ctx, lease)
	if err != nil {
		t.Fatalf("render leased sink input: %v", err)
	}
	if got, ok := workflowValueAtPath(rendered, strings.Split(sensitiveOutputSinkInputPath, ".")); !ok || got != sensitiveLeaseTestCanary {
		t.Fatalf("leased sink value = %q, %v", got, ok)
	}
	clearSensitiveRenderedInput(rendered, lease.value)
	assertJSONExcludesCanary(t, rendered)
	assertJSONExcludesCanary(t, lease.sinkMetadata())
	assertJSONExcludesCanary(t, sensitiveOutputSinkReceipt())
}

func TestSensitiveOutputLeasePinsResolvedSinkIdentityAndVersion(t *testing.T) {
	instanceID := uuid.MustParse("33333333-3333-4333-8333-333333333333")
	typeID := uuid.MustParse("44444444-4444-4444-8444-444444444444")
	plan := deriveSensitiveOutputPlan(sensitiveLeaseTestSteps(), 0)
	plan.sinkInstanceID = instanceID.String()
	plan.sinkInstanceVersion = 7
	plan.sinkTypeID = typeID.String()
	plan.sinkTypeVersion = 11

	_, lease := secureSensitiveProducerResult(model.WorkflowRunStepResult{
		ID:     "provision-webhook",
		Status: "succeeded",
		Metadata: map[string]any{
			"output":                 map[string]any{"secret": sensitiveLeaseTestCanary},
			"sensitive_output_paths": []any{"secret"},
		},
	}, plan)
	if lease == nil {
		t.Fatal("expected lease")
	}
	if !lease.matchesResolvedSink(
		model.Manifest{ID: instanceID, Version: 7},
		model.Manifest{ID: typeID, Version: 11},
	) {
		t.Fatal("lease rejected the exact preauthorized sink")
	}
	for name, manifests := range map[string][2]model.Manifest{
		"instance id": {
			{ID: uuid.New(), Version: 7},
			{ID: typeID, Version: 11},
		},
		"instance version": {
			{ID: instanceID, Version: 8},
			{ID: typeID, Version: 11},
		},
		"type id": {
			{ID: instanceID, Version: 7},
			{ID: uuid.New(), Version: 11},
		},
		"type version": {
			{ID: instanceID, Version: 7},
			{ID: typeID, Version: 12},
		},
	} {
		t.Run(name, func(t *testing.T) {
			if lease.matchesResolvedSink(manifests[0], manifests[1]) {
				t.Fatal("lease accepted a sink changed after preauthorization")
			}
		})
	}
}

func TestSecureSensitiveProducerResultFailsClosedForMalformedDeclarations(t *testing.T) {
	plan := deriveSensitiveOutputPlan(sensitiveLeaseTestSteps(), 0)
	tests := map[string]func(map[string]any){
		"scalar":           func(metadata map[string]any) { metadata["sensitive_output_paths"] = "secret" },
		"empty":            func(metadata map[string]any) { metadata["sensitive_output_paths"] = []any{} },
		"duplicate":        func(metadata map[string]any) { metadata["sensitive_output_paths"] = []any{"secret", "secret"} },
		"extra":            func(metadata map[string]any) { metadata["sensitive_output_paths"] = []any{"secret", "other"} },
		"non string":       func(metadata map[string]any) { metadata["sensitive_output_paths"] = []any{42} },
		"wrong path":       func(metadata map[string]any) { metadata["sensitive_output_paths"] = []any{"other"} },
		"padded path":      func(metadata map[string]any) { metadata["sensitive_output_paths"] = []any{" secret "} },
		"nested path":      func(metadata map[string]any) { metadata["sensitive_output_paths"] = []any{"secret.value"} },
		"missing output":   func(metadata map[string]any) { delete(metadata, "output") },
		"unresolvable":     func(metadata map[string]any) { metadata["output"] = map[string]any{"other": sensitiveLeaseTestCanary} },
		"non string value": func(metadata map[string]any) { metadata["output"] = map[string]any{"secret": 42} },
	}

	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			metadata := map[string]any{
				"output":                 map[string]any{"secret": sensitiveLeaseTestCanary},
				"sensitive_output_paths": []any{"secret"},
				"echo":                   sensitiveLeaseTestCanary,
			}
			mutate(metadata)
			safe, lease := secureSensitiveProducerResult(model.WorkflowRunStepResult{
				ID:       "provision-webhook",
				Status:   "succeeded",
				Metadata: metadata,
			}, plan)
			if lease != nil {
				t.Fatalf("malformed declaration created lease: %#v", lease)
			}
			if safe.Status != "failed" || safe.Error != errSensitiveOutputContract.Error() {
				t.Fatalf("safe result = %#v", safe)
			}
			assertJSONExcludesCanary(t, safe)
		})
	}
}

func TestSecureSensitiveProducerResultRequiresCoreIssuedPlan(t *testing.T) {
	safe, lease := secureSensitiveProducerResult(model.WorkflowRunStepResult{
		ID:     "producer",
		Status: "succeeded",
		Metadata: map[string]any{
			"output":                 map[string]any{"secret": sensitiveLeaseTestCanary},
			"sensitive_output_paths": []any{"secret"},
		},
	}, nil)
	if lease != nil || safe.Status != "failed" {
		t.Fatalf("unplanned sensitive output was accepted: safe=%#v lease=%#v", safe, lease)
	}
	assertJSONExcludesCanary(t, safe)
}

func TestSecureSensitiveProducerResultRejectsAuthorizedSourceWithoutDeclaration(t *testing.T) {
	plan := deriveSensitiveOutputPlan(sensitiveLeaseTestSteps(), 0)
	safe, lease := secureSensitiveProducerResult(model.WorkflowRunStepResult{
		ID:     "provision-webhook",
		Status: "succeeded",
		Error:  "echo " + sensitiveLeaseTestCanary,
		Metadata: map[string]any{
			"output": map[string]any{
				"id":     "we_123",
				"secret": sensitiveLeaseTestCanary,
			},
			"another_echo": sensitiveLeaseTestCanary,
		},
	}, plan)
	if lease != nil || safe.Status != "failed" || safe.Error != errSensitiveOutputContract.Error() {
		t.Fatalf("undeclared authorized source was accepted: safe=%#v lease=%#v", safe, lease)
	}
	assertJSONExcludesCanary(t, safe)
}

func TestSecureSensitiveProducerResultKeepsOrdinaryNoSourceResponseCompatible(t *testing.T) {
	plan := deriveSensitiveOutputPlan(sensitiveLeaseTestSteps(), 0)
	original := model.WorkflowRunStepResult{
		ID:     "provision-webhook",
		Status: "succeeded",
		Metadata: map[string]any{
			"output": map[string]any{"id": "we_existing"},
		},
	}
	safe, lease := secureSensitiveProducerResult(original, plan)
	if lease != nil || !reflect.DeepEqual(safe, original) {
		t.Fatalf("ordinary source-free response changed: safe=%#v lease=%#v", safe, lease)
	}
}

func TestSecureSensitiveProducerResultMakesEveryAuthorizedFailureDetailFree(t *testing.T) {
	plan := deriveSensitiveOutputPlan(sensitiveLeaseTestSteps(), 0)
	safe, lease := secureSensitiveProducerResult(model.WorkflowRunStepResult{
		ID:     "provision-webhook",
		Status: "failed",
		Error:  "provider reflected " + sensitiveLeaseTestCanary,
		Metadata: map[string]any{
			"output": map[string]any{"diagnostic": sensitiveLeaseTestCanary},
			"trace":  sensitiveLeaseTestCanary,
		},
	}, plan)
	if lease != nil || safe.Status != "failed" || safe.Error != errSensitiveOutputProducer.Error() {
		t.Fatalf("authorized producer failure was not sanitized: safe=%#v lease=%#v", safe, lease)
	}
	assertJSONExcludesCanary(t, safe)
}

func TestRenderSensitiveOutputSinkInputRejectsAnySecondPlacement(t *testing.T) {
	plan := deriveSensitiveOutputPlan(sensitiveLeaseTestSteps(), 0)
	safe, lease := secureSensitiveProducerResult(model.WorkflowRunStepResult{
		ID:     "provision-webhook",
		Status: "succeeded",
		Metadata: map[string]any{
			"output":                 map[string]any{"secret": sensitiveLeaseTestCanary},
			"sensitive_output_paths": []any{"secret"},
		},
	}, plan)
	ctx := manifestengine.WorkflowExecutionContext{Steps: map[string]model.WorkflowRunStepResult{"provision-webhook": safe}}
	sink := sensitiveLeaseTestSteps()[1]
	sink.With["leak"] = sensitiveLeaseTemplate()

	rendered, err := renderSensitiveOutputSinkInput(sink, ctx, lease)
	if !errors.Is(err, errSensitiveOutputSink) {
		t.Fatalf("error = %v, want generic sink failure", err)
	}
	if rendered != nil {
		t.Fatalf("unsafe rendered input escaped: %#v", rendered)
	}
	if strings.Contains(err.Error(), sensitiveLeaseTestCanary) {
		t.Fatalf("error leaked canary: %v", err)
	}
}

func TestSecureSensitiveOutputSinkResponseDiscardsEchoedOutputAndMetadata(t *testing.T) {
	result, succeeded := secureSensitiveOutputSinkResponse(
		model.WorkflowRunStepResult{ID: "persist-webhook-secret", Status: "failed"},
		model.ExecuteIntegrationResponse{
			Status: "created",
			Output: map[string]any{
				"value": sensitiveLeaseTestCanary,
			},
			Metadata: map[string]any{
				"another_echo": sensitiveLeaseTestCanary,
			},
		},
	)
	if !succeeded || result.Status != "succeeded" {
		t.Fatalf("safe sink result = %#v, succeeded=%v", result, succeeded)
	}
	assertJSONExcludesCanary(t, result)
	if !reflect.DeepEqual(result.Metadata, sensitiveOutputSinkReceipt()) {
		t.Fatalf("sink metadata = %#v, want fixed receipt", result.Metadata)
	}
	for _, status := range []string{"created", "updated", "unchanged"} {
		if !sensitiveOutputSinkStatusSucceeded(status) {
			t.Fatalf("persisting status %q was rejected", status)
		}
	}

	failed, succeeded := secureSensitiveOutputSinkResponse(
		model.WorkflowRunStepResult{ID: "persist-webhook-secret"},
		model.ExecuteIntegrationResponse{Status: sensitiveLeaseTestCanary},
	)
	if succeeded || failed.Status != "failed" || failed.Error != errSensitiveOutputSink.Error() {
		t.Fatalf("unsafe status was not sanitized: %#v", failed)
	}
	assertJSONExcludesCanary(t, failed)

	for _, status := range []string{
		"", "ok", "done", "completed", "succeeded", "success", "applied", "ensured",
		"already_exists", "not_found", "absent", "deleted", "simulated", "dry_run", "noop",
	} {
		t.Run(status, func(t *testing.T) {
			got, ok := secureSensitiveOutputSinkResponse(
				model.WorkflowRunStepResult{ID: "persist-webhook-secret"},
				model.ExecuteIntegrationResponse{Status: status},
			)
			if ok || got.Status != "failed" || got.Error != errSensitiveOutputSink.Error() {
				t.Fatalf("non-persisting status %q was accepted: %#v", status, got)
			}
		})
	}
}

func TestRunWithSensitiveOutputLeaseClearsOnSuccessAndPanic(t *testing.T) {
	lease := &sensitiveOutputLease{value: sensitiveLeaseTestCanary}
	runWithSensitiveOutputLease(lease, func() ([]model.WorkflowRunStepResult, string) {
		return nil, ""
	})
	if lease.value != "" {
		t.Fatalf("lease retained value after success: %q", lease.value)
	}

	cancelledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	cancelledLease := &sensitiveOutputLease{value: sensitiveLeaseTestCanary}
	runWithSensitiveOutputLease(cancelledLease, func() ([]model.WorkflowRunStepResult, string) {
		<-cancelledCtx.Done()
		return []model.WorkflowRunStepResult{{Status: "failed", Error: errSensitiveOutputSink.Error()}}, "sink"
	})
	if cancelledLease.value != "" {
		t.Fatalf("lease retained value after cancellation: %q", cancelledLease.value)
	}

	panicLease := &sensitiveOutputLease{value: sensitiveLeaseTestCanary}
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("expected test panic")
			}
		}()
		runWithSensitiveOutputLease(panicLease, func() ([]model.WorkflowRunStepResult, string) {
			panic("synthetic panic without secret")
		})
	}()
	if panicLease.value != "" {
		t.Fatalf("lease retained value after panic: %q", panicLease.value)
	}
}

func TestFailWorkflowWithUnconsumedSensitiveOutputIsGenericAndClearsLease(t *testing.T) {
	lease := &sensitiveOutputLease{
		producerStepID: "provision-webhook",
		value:          sensitiveLeaseTestCanary,
	}
	response := failWorkflowWithUnconsumedSensitiveOutput(model.RunWorkflowResponse{Status: "succeeded"}, lease)
	if response.Status != "failed" || response.Metadata["failed_step"] != "provision-webhook" ||
		response.Metadata["error"] != errSensitiveOutputContract.Error() {
		t.Fatalf("response = %#v", response)
	}
	if lease.value != "" {
		t.Fatalf("unconsumed lease retained value: %q", lease.value)
	}
	assertJSONExcludesCanary(t, response)
}

func sensitiveLeaseTestSteps() []model.WorkflowStepSpec {
	return []model.WorkflowStepSpec{
		{
			ID: "provision-webhook",
			Use: model.WorkflowStepUseSpec{
				Kind:        "integration",
				Operation:   "provision_webhook_endpoint",
				InstanceRef: &model.ManifestSelector{Name: "stripe", Namespace: "test"},
			},
		},
		{
			ID:        "persist-webhook-secret",
			DependsOn: []string{"provision-webhook"},
			Use: model.WorkflowStepUseSpec{
				Kind:      "integration",
				Family:    "secrets-management",
				Operation: "ensure_secret",
			},
			With: map[string]any{
				"secret": map[string]any{
					"secret_id": "stripe/webhook",
					"generation": map[string]any{
						"strategy": "manual",
						"manual": map[string]any{
							"value": sensitiveLeaseTemplate(),
						},
					},
				},
			},
		},
	}
}

func setSensitiveLeaseInput(input map[string]any, value string) {
	input["secret"].(map[string]any)["generation"].(map[string]any)["manual"].(map[string]any)["value"] = value
}

func sensitiveLeaseTemplate() string {
	return "{{ steps.provision-webhook.metadata.output.secret }}"
}

func assertJSONExcludesCanary(t *testing.T, value any) {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal value: %v", err)
	}
	if strings.Contains(string(raw), sensitiveLeaseTestCanary) {
		t.Fatalf("serialized value leaked canary: %s", raw)
	}
}
