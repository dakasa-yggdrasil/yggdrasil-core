package message

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

func TestValidateExecuteIntegrationRequestRejectsWorkflowRuntimeMetadata(t *testing.T) {
	for _, key := range []string{
		supportsSensitiveOutputPathsMetadataKey,
		sensitiveOutputSinkMetadataKey,
		sensitiveInputLeaseMetadataKey,
		" SENSITIVE_OUTPUT_SINK ",
	} {
		t.Run(strings.TrimSpace(key), func(t *testing.T) {
			req := normalizeExecuteIntegrationRequest(model.ExecuteIntegrationRequest{
				Integration: model.ManifestSelector{Name: "stripe", Namespace: "test"},
				Operation:   "provision_webhook_endpoint",
				Metadata:    map[string]any{key: map[string]any{"forged": sensitiveLeaseTestCanary}},
			})
			if err := validateExecuteIntegrationRequest(req); err == nil {
				t.Fatalf("reserved metadata key %q was accepted", key)
			} else if strings.Contains(err.Error(), sensitiveLeaseTestCanary) {
				t.Fatalf("validation error leaked input: %v", err)
			}
		})
	}
}

func TestValidateExecuteIntegrationRequestKeepsOrdinaryMetadataCompatible(t *testing.T) {
	req := normalizeExecuteIntegrationRequest(model.ExecuteIntegrationRequest{
		Integration: model.ManifestSelector{Name: "stripe", Namespace: "test"},
		Operation:   "observe_balance",
		Metadata: map[string]any{
			"source":          "console",
			"idempotency_key": "request-123",
		},
	})
	if err := validateExecuteIntegrationRequest(req); err != nil {
		t.Fatalf("ordinary metadata rejected: %v", err)
	}
}

func TestExecuteIntegrationRejectsForgedLeaseBeforeResolution(t *testing.T) {
	_, err := ExecuteIntegration(context.Background(), nil, nil, model.ExecuteIntegrationRequest{
		Integration: model.ManifestSelector{Name: "stripe", Namespace: "test"},
		Operation:   "provision_webhook_endpoint",
		Metadata: map[string]any{
			sensitiveOutputSinkMetadataKey: map[string]any{"forged": true},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "workflow-runtime-reserved") {
		t.Fatalf("forged lease reached resolution: %v", err)
	}
}

func TestDirectIntegrationResponseCannotReturnDeclaredSensitiveOutput(t *testing.T) {
	inner, err := json.Marshal(model.AdapterExecuteIntegrationResponse{
		Operation:  "recover_webhook_destination_secret",
		Capability: "recover_webhook_destination_secret",
		Status:     "succeeded",
		Output: map[string]any{
			"secret": sensitiveLeaseTestCanary,
		},
		Metadata: map[string]any{
			"sensitive_output_paths": []string{"secret"},
		},
	})
	if err != nil {
		t.Fatalf("marshal adapter response: %v", err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"content_type": "application/json",
			"body":         base64.StdEncoding.EncodeToString(inner),
		})
	}))
	defer server.Close()

	instanceManifest, instanceSpec, typeManifest, typeSpec := sensitiveExecutionTestManifests(server.URL)
	response, err := executeIntegrationThroughResolved(
		context.Background(),
		nil,
		model.ExecuteIntegrationRequest{
			Integration: model.ManifestSelector{Name: "didit", Namespace: "test"},
			Operation:   "recover_webhook_destination_secret",
			Capability:  "recover_webhook_destination_secret",
		},
		instanceManifest,
		instanceSpec,
		typeManifest,
		typeSpec,
		0,
	)
	if !errors.Is(err, errSensitiveOutputContract) {
		t.Fatalf("direct sensitive response error = %v", err)
	}
	assertJSONExcludesCanary(t, response)
	if strings.Contains(err.Error(), sensitiveLeaseTestCanary) {
		t.Fatalf("direct sensitive response error leaked canary: %v", err)
	}
}

func TestSensitiveSinkHTTPErrorDropsAdapterBody(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		http.Error(w, "provider reflected "+sensitiveLeaseTestCanary, http.StatusBadGateway)
	}))
	defer server.Close()

	instanceManifest, instanceSpec, typeManifest, typeSpec := sensitiveExecutionTestManifests(server.URL)
	_, err := executeIntegrationThroughResolvedWithPolicy(
		context.Background(),
		nil,
		model.ExecuteIntegrationRequest{
			Integration: model.ManifestSelector{Name: "secrets", Namespace: "test"},
			Operation:   sensitiveOutputSinkOperation,
			Capability:  sensitiveOutputSinkOperation,
			Input: map[string]any{
				"secret": map[string]any{
					"generation": map[string]any{
						"manual": map[string]any{"value": sensitiveLeaseTestCanary},
					},
				},
			},
		},
		instanceManifest,
		instanceSpec,
		typeManifest,
		typeSpec,
		0,
		integrationExecutionPolicy{detailFreeErrors: true},
	)
	if requests != 1 {
		t.Fatalf("HTTP adapter calls = %d, want 1", requests)
	}
	if err == nil || err.Error() != errSensitiveOutputSink.Error() {
		t.Fatalf("error = %v, want stable detail-free error", err)
	}
	if strings.Contains(err.Error(), sensitiveLeaseTestCanary) {
		t.Fatalf("HTTP error leaked adapter body: %v", err)
	}
}

func TestSensitiveProducerHTTPErrorDropsAdapterBody(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		http.Error(w, "provider reflected "+sensitiveLeaseTestCanary, http.StatusBadGateway)
	}))
	defer server.Close()

	instanceManifest, instanceSpec, typeManifest, typeSpec := sensitiveExecutionTestManifests(server.URL)
	_, err := executeIntegrationThroughResolvedWithPolicy(
		context.Background(),
		nil,
		model.ExecuteIntegrationRequest{
			Integration: model.ManifestSelector{Name: "stripe", Namespace: "test"},
			Operation:   "provision_webhook_endpoint",
			Capability:  "provision_webhook_endpoint",
		},
		instanceManifest,
		instanceSpec,
		typeManifest,
		typeSpec,
		0,
		integrationExecutionPolicy{
			detailFreeErrors: true,
			safeError:        errSensitiveOutputProducer,
		},
	)
	if requests != 1 {
		t.Fatalf("HTTP adapter calls = %d, want 1", requests)
	}
	if err == nil || err.Error() != errSensitiveOutputProducer.Error() {
		t.Fatalf("error = %v, want stable detail-free producer error", err)
	}
	if strings.Contains(err.Error(), sensitiveLeaseTestCanary) {
		t.Fatalf("HTTP producer error leaked adapter body: %v", err)
	}
}

func TestSensitiveSinkAMQPEnvelopeDropsAdapterMessage(t *testing.T) {
	body, err := json.Marshal(rpcEnvelope{
		OK: false,
		Error: &rpcError{
			Code:    "backend_error",
			Message: "provider reflected " + sensitiveLeaseTestCanary,
		},
	})
	if err != nil {
		t.Fatalf("marshal RPC envelope: %v", err)
	}
	rawErr := decodeRPCBody(body, &model.AdapterExecuteIntegrationResponse{})
	if rawErr == nil || !strings.Contains(rawErr.Error(), sensitiveLeaseTestCanary) {
		t.Fatalf("test fixture did not exercise reflected RPC message: %v", rawErr)
	}

	transportErr := decodeRPCBodyWithPolicy(
		body,
		&model.AdapterExecuteIntegrationResponse{},
		adapterCallPolicy{detailFreeErrors: true},
	)
	if transportErr == nil || transportErr.Error() != errAdapterCallFailed.Error() {
		t.Fatalf("detail-free RPC decode error = %v", transportErr)
	}
	if strings.Contains(transportErr.Error(), sensitiveLeaseTestCanary) {
		t.Fatalf("RPC decoder leaked adapter message: %v", transportErr)
	}

	safeErr := (integrationExecutionPolicy{detailFreeErrors: true}).sanitizeError(rawErr)
	if safeErr == nil || safeErr.Error() != errSensitiveOutputSink.Error() {
		t.Fatalf("sanitized error = %v", safeErr)
	}
	if strings.Contains(safeErr.Error(), sensitiveLeaseTestCanary) {
		t.Fatalf("AMQP error leaked adapter message: %v", safeErr)
	}
}

func TestDetailFreeRPCRejectsMalformedFailureShapes(t *testing.T) {
	for name, body := range map[string]string{
		"false envelope":             `{"ok":false}`,
		"string error":               `{"error":"` + sensitiveLeaseTestCanary + `"}`,
		"mixed malformed envelope":   `{"ok":false,"error":"` + sensitiveLeaseTestCanary + `"}`,
		"false envelope with status": `{"ok":false,"status":"created"}`,
	} {
		t.Run(name, func(t *testing.T) {
			err := decodeRPCBodyWithPolicy(
				[]byte(body),
				&model.AdapterExecuteIntegrationResponse{},
				adapterCallPolicy{detailFreeErrors: true},
			)
			if err == nil || err.Error() != errAdapterCallFailed.Error() {
				t.Fatalf("malformed response error = %v", err)
			}
			if strings.Contains(err.Error(), sensitiveLeaseTestCanary) {
				t.Fatalf("malformed response leaked canary: %v", err)
			}
		})
	}
}

func TestSensitiveSinkRequiresExplicitResponseEvidence(t *testing.T) {
	inner, err := json.Marshal(rpcEnvelope{OK: true, Data: json.RawMessage(`{}`)})
	if err != nil {
		t.Fatalf("marshal empty success envelope: %v", err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"content_type": "application/json",
			"body":         base64.StdEncoding.EncodeToString(inner),
		})
	}))
	defer server.Close()

	instanceManifest, instanceSpec, typeManifest, typeSpec := sensitiveExecutionTestManifests(server.URL)
	_, err = executeIntegrationThroughResolvedWithPolicy(
		context.Background(),
		nil,
		model.ExecuteIntegrationRequest{
			Integration: model.ManifestSelector{Name: "secrets", Namespace: "test"},
			Operation:   sensitiveOutputSinkOperation,
			Capability:  sensitiveOutputSinkOperation,
			Input: map[string]any{
				"secret": map[string]any{
					"secret_id": "stripe/webhook",
					"generation": map[string]any{
						"strategy": "manual",
						"manual":   map[string]any{"value": sensitiveLeaseTestCanary},
					},
				},
			},
		},
		instanceManifest,
		instanceSpec,
		typeManifest,
		typeSpec,
		0,
		integrationExecutionPolicy{
			detailFreeErrors:        true,
			safeError:               errSensitiveOutputSink,
			requireExplicitResponse: true,
		},
	)
	if err == nil || err.Error() != errSensitiveOutputSink.Error() {
		t.Fatalf("empty sink success error = %v", err)
	}
	if strings.Contains(err.Error(), sensitiveLeaseTestCanary) {
		t.Fatalf("empty sink success error leaked canary: %v", err)
	}
}

func sensitiveExecutionTestManifests(baseURL string) (
	model.Manifest,
	model.IntegrationInstanceManifestSpec,
	model.Manifest,
	model.IntegrationTypeManifestSpec,
) {
	typeManifest := model.Manifest{
		ID:      uuid.New(),
		Kind:    "integration_type",
		Version: 1,
		Metadata: model.ManifestMetadata{
			Name:      "secrets-management",
			Namespace: "global",
		},
	}
	instanceManifest := model.Manifest{
		ID:      uuid.New(),
		Kind:    "integration_instance",
		Version: 1,
		Metadata: model.ManifestMetadata{
			Name:      "secrets",
			Namespace: "test",
		},
	}
	typeSpec := model.IntegrationTypeManifestSpec{
		Provider:              "secrets-management",
		FamilyRef:             &model.ManifestSelector{Name: sensitiveOutputSinkFamily},
		ImplementedOperations: []string{sensitiveOutputSinkOperation},
		Adapter: model.IntegrationAdapterSpec{
			Transport: "http_json",
			Version:   "1.0.0",
			Endpoints: model.IntegrationAdapterRoute{Execute: "/execute"},
		},
		Capabilities:     []string{"execute"},
		CredentialSchema: model.IntegrationSchemaSpec{Mode: "inline"},
		InstanceSchema:   model.IntegrationSchemaSpec{Mode: "inline"},
		ResourceTypes:    []model.IntegrationResourceType{},
		Discovery:        model.IntegrationDiscoverySpec{Mode: "none"},
		Normalization: model.IntegrationNormalizationSpec{
			ExternalIDPath:         "id",
			FallbackResourcePrefix: "secret",
		},
	}
	instanceSpec := model.IntegrationInstanceManifestSpec{
		TypeRef: model.ManifestSelector{Name: typeManifest.Metadata.Name, Namespace: typeManifest.Metadata.Namespace},
		Config:  map[string]any{"base_url": baseURL},
	}
	return instanceManifest, instanceSpec, typeManifest, typeSpec
}
