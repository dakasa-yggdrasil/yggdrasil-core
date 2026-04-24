package message

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"sync"
	"time"

	manifestengine "github.com/dakasa-yggdrasil/yggdrasil-core/manifest"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	amqp "github.com/rabbitmq/amqp091-go"
	rpcamqp "github.com/dakasa-yggdrasil/yggdrasil-core/internal/rpc/amqp"
)

const integrationDescribeCacheTTL = 30 * time.Second

var (
	integrationDescribeContract = rpcContractSpec{
		Family:      "integration-adapter/v1",
		RequestDef:  "adapterDescribeRequest",
		ResponseDef: "adapterDescribeResponse",
		Label:       "integration describe",
	}

	integrationDescribeCacheMu sync.RWMutex
	integrationDescribeCache   = map[string]time.Time{}
)

func verifyResolvedIntegrationType(
	ctx context.Context,
	conn *amqp.Connection,
	db *sql.DB,
	instanceManifest model.Manifest,
	typeManifest model.Manifest,
	instanceSpec model.IntegrationInstanceManifestSpec,
	typeSpec model.IntegrationTypeManifestSpec,
) error {
	channel := adapterQueueForCapability(typeSpec.Adapter.Queues, "describe")
	endpoint := adapterEndpointForCapability(typeSpec.Adapter.Endpoints, "describe")
	stateDetails := integrationDescribeStateDetails(instanceManifest, typeManifest, typeSpec, channel, endpoint)

	if db == nil {
		return fmt.Errorf("database connection is required to verify integration describe handshake")
	}

	if channel == "" && endpoint == "" {
		err := fmt.Errorf(
			"integration type %s/%s has no describe route",
			typeManifest.Metadata.Namespace,
			typeManifest.Metadata.Name,
		)
		return failIntegrationDescribeHandshake(ctx, db, instanceManifest, typeManifest, model.IntegrationRuntimeStatusContractMismatch, err, stateDetails)
	}

	cacheKey := integrationDescribeCacheKey(instanceManifest, typeManifest, typeSpec, instanceSpec)
	if integrationDescribeRecentlyVerified(cacheKey) {
		return nil
	}

	if err := verifyIntegrationTransportConnectivity(ctx, conn, db, instanceManifest, typeManifest, instanceSpec, typeSpec); err != nil {
		return err
	}

	timeout := time.Duration(typeSpec.Adapter.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 15 * time.Second
	}

	rpcCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	request := model.AdapterDescribeRequest{
		Provider:        strings.TrimSpace(typeSpec.Provider),
		ExpectedVersion: strings.TrimSpace(typeSpec.Adapter.Version),
	}

	var response model.AdapterDescribeResponse
	transport := NewAdapterTransportClient(rpcamqp.New(conn))
	if err := transport.Call(rpcCtx, integrationDescribeContract, typeSpec, instanceSpec, "describe", request, &response); err != nil {
		wrappedErr := fmt.Errorf(
			"describe integration type %s/%s through transport %q: %w",
			typeManifest.Metadata.Namespace,
			typeManifest.Metadata.Name,
			typeSpec.Adapter.Transport,
			err,
		)
		details := cloneAuthorizationInput(stateDetails)
		if liveDetails := integrationDescribeLiveDetails(response); len(liveDetails) > 0 {
			details["live_contract"] = liveDetails
		}
		return failIntegrationDescribeHandshake(
			ctx,
			db,
			instanceManifest,
			typeManifest,
			integrationDescribeFailureStatus(wrappedErr),
			wrappedErr,
			details,
		)
	}

	liveSpec := integrationTypeSpecFromDescribeResponse(response)
	if liveDetails := integrationDescribeLiveDetails(response); len(liveDetails) > 0 {
		stateDetails["live_contract"] = liveDetails
	}
	if err := manifestengine.ValidateIntegrationTypeSpec(liveSpec); err != nil {
		wrappedErr := fmt.Errorf(
			"live describe contract for integration type %s/%s is invalid: %w",
			typeManifest.Metadata.Namespace,
			typeManifest.Metadata.Name,
			err,
		)
		return failIntegrationDescribeHandshake(ctx, db, instanceManifest, typeManifest, model.IntegrationRuntimeStatusInvalidResponse, wrappedErr, stateDetails)
	}

	if err := compareIntegrationTypeSpec(typeSpec, liveSpec); err != nil {
		wrappedErr := fmt.Errorf(
			"integration type %s/%s does not match live adapter describe contract: %w",
			typeManifest.Metadata.Namespace,
			typeManifest.Metadata.Name,
			err,
		)
		return failIntegrationDescribeHandshake(ctx, db, instanceManifest, typeManifest, model.IntegrationRuntimeStatusContractMismatch, wrappedErr, stateDetails)
	}

	if _, err := repository.UpsertIntegrationRuntimeState(
		ctx,
		db,
		instanceManifest,
		typeManifest,
		model.IntegrationRuntimeCheckKindDescribeHandshake,
		model.IntegrationRuntimeStatusHealthy,
		fmt.Sprintf(
			"describe handshake healthy for %s/%s",
			typeManifest.Metadata.Namespace,
			typeManifest.Metadata.Name,
		),
		stateDetails,
	); err != nil {
		return fmt.Errorf(
			"record describe handshake state for integration type %s/%s: %w",
			typeManifest.Metadata.Namespace,
			typeManifest.Metadata.Name,
			err,
		)
	}

	markIntegrationDescribeVerified(cacheKey)
	return nil
}

func verifyIntegrationTransportConnectivity(
	ctx context.Context,
	conn *amqp.Connection,
	db *sql.DB,
	instanceManifest model.Manifest,
	typeManifest model.Manifest,
	instanceSpec model.IntegrationInstanceManifestSpec,
	typeSpec model.IntegrationTypeManifestSpec,
) error {
	details := integrationTransportConnectivityStateDetails(instanceManifest, typeManifest, typeSpec)
	message, liveDetails, err := checkIntegrationTransportConnectivity(ctx, conn, instanceSpec, typeSpec)
	for key, value := range liveDetails {
		details[key] = value
	}
	if err != nil {
		status := model.IntegrationRuntimeStatusUnreachable
		if strings.Contains(strings.ToLower(strings.TrimSpace(err.Error())), "unsupported") ||
			strings.Contains(strings.ToLower(strings.TrimSpace(err.Error())), "required") {
			status = model.IntegrationRuntimeStatusContractMismatch
		}
		return failIntegrationRuntimeCheck(
			ctx,
			db,
			instanceManifest,
			typeManifest,
			model.IntegrationRuntimeCheckKindTransportConnectivity,
			status,
			err,
			details,
		)
	}

	if _, err := repository.UpsertIntegrationRuntimeState(
		ctx,
		db,
		instanceManifest,
		typeManifest,
		model.IntegrationRuntimeCheckKindTransportConnectivity,
		model.IntegrationRuntimeStatusHealthy,
		message,
		details,
	); err != nil {
		return fmt.Errorf(
			"record transport connectivity state for integration instance %s/%s: %w",
			instanceManifest.Metadata.Namespace,
			instanceManifest.Metadata.Name,
			err,
		)
	}
	return nil
}

func checkIntegrationTransportConnectivity(
	ctx context.Context,
	conn *amqp.Connection,
	instanceSpec model.IntegrationInstanceManifestSpec,
	typeSpec model.IntegrationTypeManifestSpec,
) (string, map[string]any, error) {
	switch strings.ToLower(strings.TrimSpace(typeSpec.Adapter.Transport)) {
	case "http_json":
		return checkHTTPJSONTransportConnectivity(ctx, instanceSpec, typeSpec)
	case "rabbitmq":
		return checkRabbitMQTransportConnectivity(conn, typeSpec)
	default:
		return "", nil, fmt.Errorf("integration transport %q is unsupported", typeSpec.Adapter.Transport)
	}
}

func checkHTTPJSONTransportConnectivity(
	ctx context.Context,
	instanceSpec model.IntegrationInstanceManifestSpec,
	typeSpec model.IntegrationTypeManifestSpec,
) (string, map[string]any, error) {
	baseURL, err := adapterBaseURL(instanceSpec)
	if err != nil {
		return "", nil, err
	}

	targetURL := baseURL
	healthEndpoint := adapterEndpointForCapability(typeSpec.Adapter.Endpoints, "health")
	if healthEndpoint != "" {
		targetURL, err = resolveAdapterEndpointURL(baseURL, healthEndpoint)
		if err != nil {
			return "", nil, err
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return "", nil, fmt.Errorf("build connectivity request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", map[string]any{"target_url": targetURL}, fmt.Errorf("call connectivity endpoint %q: %w", targetURL, err)
	}
	defer func() { _ = resp.Body.Close() }()

	details := map[string]any{
		"target_url":   targetURL,
		"status_code":  resp.StatusCode,
		"health_route": strings.TrimSpace(healthEndpoint),
	}
	if resp.StatusCode >= http.StatusInternalServerError {
		return "", details, fmt.Errorf("connectivity endpoint %q returned %d", targetURL, resp.StatusCode)
	}

	return fmt.Sprintf("transport connectivity healthy via %s", targetURL), details, nil
}

func checkRabbitMQTransportConnectivity(
	conn *amqp.Connection,
	typeSpec model.IntegrationTypeManifestSpec,
) (string, map[string]any, error) {
	queue := firstNonEmpty(
		strings.TrimSpace(typeSpec.Adapter.Queues.Health),
		strings.TrimSpace(typeSpec.Adapter.Queues.Describe),
		strings.TrimSpace(typeSpec.Adapter.Queues.Execute),
		strings.TrimSpace(typeSpec.Adapter.Queues.Read),
		strings.TrimSpace(typeSpec.Adapter.Queues.Discover),
		strings.TrimSpace(typeSpec.Adapter.Queues.Sync),
	)
	if queue == "" {
		return "", nil, fmt.Errorf("adapter queue is required for rabbitmq transport connectivity")
	}
	if conn == nil {
		return "", map[string]any{"queue": queue}, fmt.Errorf("rabbitmq connection is not configured")
	}

	channel, err := conn.Channel()
	if err != nil {
		return "", map[string]any{"queue": queue}, fmt.Errorf("open rabbitmq channel: %w", err)
	}
	defer func() { _ = channel.Close() }()

	//nolint:staticcheck // QueueInspect is deprecated but the replacement (passive QueueDeclare) has different semantics we don't need here.
	if _, err := channel.QueueInspect(queue); err != nil {
		return "", map[string]any{"queue": queue}, fmt.Errorf("inspect rabbitmq queue %q: %w", queue, err)
	}

	return fmt.Sprintf("transport connectivity healthy through queue %s", queue), map[string]any{"queue": queue}, nil
}

func integrationDescribeStateDetails(
	instanceManifest model.Manifest,
	typeManifest model.Manifest,
	typeSpec model.IntegrationTypeManifestSpec,
	queue string,
	endpoint string,
) map[string]any {
	details := map[string]any{
		"integration_type": manifestReferenceFromRecord(typeManifest),
		"provider":         strings.TrimSpace(typeSpec.Provider),
		"adapter_version":  strings.TrimSpace(typeSpec.Adapter.Version),
		"queue":            strings.TrimSpace(queue),
		"endpoint":         strings.TrimSpace(endpoint),
		"transport":        strings.TrimSpace(typeSpec.Adapter.Transport),
	}
	if instanceManifest.Kind == "integration_instance" {
		details["integration_instance"] = manifestReferenceFromRecord(instanceManifest)
	}
	return details
}

func integrationTransportConnectivityStateDetails(
	instanceManifest model.Manifest,
	typeManifest model.Manifest,
	typeSpec model.IntegrationTypeManifestSpec,
) map[string]any {
	details := map[string]any{
		"integration_type": manifestReferenceFromRecord(typeManifest),
		"provider":         strings.TrimSpace(typeSpec.Provider),
		"adapter_version":  strings.TrimSpace(typeSpec.Adapter.Version),
		"transport":        strings.TrimSpace(typeSpec.Adapter.Transport),
	}
	if instanceManifest.Kind == "integration_instance" {
		details["integration_instance"] = manifestReferenceFromRecord(instanceManifest)
	}
	return details
}

func integrationDescribeLiveDetails(response model.AdapterDescribeResponse) map[string]any {
	if strings.TrimSpace(response.Provider) == "" &&
		strings.TrimSpace(response.Adapter.Version) == "" &&
		len(response.Capabilities) == 0 &&
		len(response.ResourceTypes) == 0 &&
		len(response.ActionCatalog) == 0 {
		return nil
	}

	liveSpec := normalizeIntegrationTypeSpecForComparison(integrationTypeSpecFromDescribeResponse(response))
	return map[string]any{
		"provider":          liveSpec.Provider,
		"adapter":           liveSpec.Adapter,
		"capabilities":      liveSpec.Capabilities,
		"credential_schema": liveSpec.CredentialSchema,
		"instance_schema":   liveSpec.InstanceSchema,
		"resource_types":    liveSpec.ResourceTypes,
		"action_catalog":    liveSpec.ActionCatalog,
		"discovery":         liveSpec.Discovery,
		"normalization":     liveSpec.Normalization,
		"execution":         liveSpec.Execution,
		"extensions":        liveSpec.Extensions,
	}
}

func integrationDescribeFailureStatus(err error) string {
	if err == nil {
		return model.IntegrationRuntimeStatusUnreachable
	}

	message := strings.ToLower(strings.TrimSpace(err.Error()))
	switch {
	case strings.Contains(message, "validate integration describe response"),
		strings.Contains(message, "live describe contract"):
		return model.IntegrationRuntimeStatusInvalidResponse
	case strings.Contains(message, "does not match live adapter describe contract"),
		strings.Contains(message, "has no describe route"),
		strings.Contains(message, "validate integration describe request"):
		return model.IntegrationRuntimeStatusContractMismatch
	default:
		return model.IntegrationRuntimeStatusUnreachable
	}
}

func failIntegrationDescribeHandshake(
	ctx context.Context,
	db *sql.DB,
	instanceManifest model.Manifest,
	typeManifest model.Manifest,
	status string,
	cause error,
	details map[string]any,
) error {
	if cause == nil {
		return nil
	}

	if db == nil {
		return cause
	}

	recordedDetails := cloneAuthorizationInput(details)
	recordedDetails["error"] = cause.Error()
	if _, err := repository.UpsertIntegrationRuntimeState(
		ctx,
		db,
		instanceManifest,
		typeManifest,
		model.IntegrationRuntimeCheckKindDescribeHandshake,
		status,
		cause.Error(),
		recordedDetails,
	); err != nil {
		return fmt.Errorf(
			"%w (also failed to record integration runtime state: %v)",
			cause,
			err,
		)
	}

	return cause
}

func failIntegrationRuntimeCheck(
	ctx context.Context,
	db *sql.DB,
	instanceManifest model.Manifest,
	typeManifest model.Manifest,
	checkKind string,
	status string,
	cause error,
	details map[string]any,
) error {
	if cause == nil {
		return nil
	}
	if db == nil {
		return cause
	}

	recordedDetails := cloneAuthorizationInput(details)
	recordedDetails["error"] = cause.Error()
	if _, err := repository.UpsertIntegrationRuntimeState(
		ctx,
		db,
		instanceManifest,
		typeManifest,
		checkKind,
		status,
		cause.Error(),
		recordedDetails,
	); err != nil {
		return fmt.Errorf("%w (also failed to record integration runtime state: %v)", cause, err)
	}
	return cause
}

func integrationTypeSpecFromDescribeResponse(response model.AdapterDescribeResponse) model.IntegrationTypeManifestSpec {
	return model.IntegrationTypeManifestSpec{
		Provider:         response.Provider,
		Adapter:          response.Adapter,
		Capabilities:     response.Capabilities,
		CredentialSchema: response.CredentialSchema,
		InstanceSchema:   response.InstanceSchema,
		ResourceTypes:    response.ResourceTypes,
		ActionCatalog:    response.ActionCatalog,
		Discovery:        response.Discovery,
		Normalization:    response.Normalization,
		Execution:        response.Execution,
		Extensions:       response.Extensions,
	}
}

func compareIntegrationTypeSpec(expected model.IntegrationTypeManifestSpec, actual model.IntegrationTypeManifestSpec) error {
	expected = normalizeIntegrationTypeSpecForComparison(expected)
	actual = normalizeIntegrationTypeSpecForComparison(actual)

	if expected.Provider != actual.Provider {
		return fmt.Errorf("provider mismatch: expected %q, got %q", expected.Provider, actual.Provider)
	}
	if !reflect.DeepEqual(expected.Adapter, actual.Adapter) {
		return formatContractMismatch("adapter", expected.Adapter, actual.Adapter)
	}
	if !reflect.DeepEqual(expected.Capabilities, actual.Capabilities) {
		return formatContractMismatch("capabilities", expected.Capabilities, actual.Capabilities)
	}
	if !reflect.DeepEqual(expected.CredentialSchema, actual.CredentialSchema) {
		return formatContractMismatch("credential_schema", expected.CredentialSchema, actual.CredentialSchema)
	}
	if !reflect.DeepEqual(expected.InstanceSchema, actual.InstanceSchema) {
		return formatContractMismatch("instance_schema", expected.InstanceSchema, actual.InstanceSchema)
	}
	if !reflect.DeepEqual(expected.ResourceTypes, actual.ResourceTypes) {
		return formatContractMismatch("resource_types", expected.ResourceTypes, actual.ResourceTypes)
	}
	if !reflect.DeepEqual(expected.ActionCatalog, actual.ActionCatalog) {
		return formatContractMismatch("action_catalog", expected.ActionCatalog, actual.ActionCatalog)
	}
	if !reflect.DeepEqual(expected.Discovery, actual.Discovery) {
		return formatContractMismatch("discovery", expected.Discovery, actual.Discovery)
	}
	if !reflect.DeepEqual(expected.Normalization, actual.Normalization) {
		return formatContractMismatch("normalization", expected.Normalization, actual.Normalization)
	}
	if !reflect.DeepEqual(expected.Execution, actual.Execution) {
		return formatContractMismatch("execution", expected.Execution, actual.Execution)
	}
	if !reflect.DeepEqual(expected.Extensions, actual.Extensions) {
		return formatContractMismatch("extensions", expected.Extensions, actual.Extensions)
	}

	return nil
}

func normalizeIntegrationTypeSpecForComparison(spec model.IntegrationTypeManifestSpec) model.IntegrationTypeManifestSpec {
	spec.Provider = normalizeIntegrationToken(spec.Provider)
	spec.CredentialPolicy = model.IntegrationCredentialPolicySpec{}
	spec.GuardianSupport = model.IntegrationGuardianSupportSpec{}
	spec.Adapter = normalizeIntegrationAdapterSpec(spec.Adapter)
	spec.Capabilities = normalizeIntegrationTokens(spec.Capabilities)
	spec.CredentialSchema = normalizeIntegrationSchemaSpec(spec.CredentialSchema)
	spec.InstanceSchema = normalizeIntegrationSchemaSpec(spec.InstanceSchema)
	spec.ResourceTypes = normalizeIntegrationResourceTypes(spec.ResourceTypes)
	spec.ActionCatalog = normalizeIntegrationActionCatalog(spec.ActionCatalog)
	spec.Discovery = model.IntegrationDiscoverySpec{
		Mode:             normalizeIntegrationToken(spec.Discovery.Mode),
		Cursor:           normalizeIntegrationToken(spec.Discovery.Cursor),
		SupportsWebhooks: spec.Discovery.SupportsWebhooks,
	}
	spec.Normalization = model.IntegrationNormalizationSpec{
		ExternalIDPath:         strings.TrimSpace(spec.Normalization.ExternalIDPath),
		NamePath:               strings.TrimSpace(spec.Normalization.NamePath),
		OwnerPath:              strings.TrimSpace(spec.Normalization.OwnerPath),
		FallbackResourcePrefix: strings.TrimSpace(spec.Normalization.FallbackResourcePrefix),
	}
	spec.Execution = model.IntegrationExecutionSpec{
		SupportsDryRun:    spec.Execution.SupportsDryRun,
		IdempotentActions: normalizeIntegrationTokens(spec.Execution.IdempotentActions),
	}
	return spec
}

func normalizeIntegrationAdapterSpec(spec model.IntegrationAdapterSpec) model.IntegrationAdapterSpec {
	return model.IntegrationAdapterSpec{
		Transport: normalizeIntegrationToken(spec.Transport),
		Version:   strings.TrimSpace(spec.Version),
		Queues: model.IntegrationAdapterQueue{
			Describe: strings.TrimSpace(spec.Queues.Describe),
			Discover: strings.TrimSpace(spec.Queues.Discover),
			Read:     strings.TrimSpace(spec.Queues.Read),
			Execute:  strings.TrimSpace(spec.Queues.Execute),
			Sync:     strings.TrimSpace(spec.Queues.Sync),
			Health:   strings.TrimSpace(spec.Queues.Health),
		},
		Endpoints: model.IntegrationAdapterRoute{
			Describe: strings.TrimSpace(spec.Endpoints.Describe),
			Discover: strings.TrimSpace(spec.Endpoints.Discover),
			Read:     strings.TrimSpace(spec.Endpoints.Read),
			Execute:  strings.TrimSpace(spec.Endpoints.Execute),
			Sync:     strings.TrimSpace(spec.Endpoints.Sync),
			Health:   strings.TrimSpace(spec.Endpoints.Health),
		},
		TimeoutSeconds: spec.TimeoutSeconds,
	}
}

func normalizeIntegrationSchemaSpec(spec model.IntegrationSchemaSpec) model.IntegrationSchemaSpec {
	spec.Mode = normalizeIntegrationToken(spec.Mode)
	spec.Required = normalizeIntegrationTokens(spec.Required)

	if len(spec.Properties) == 0 {
		return spec
	}

	properties := make(map[string]model.IntegrationSchemaProperty, len(spec.Properties))
	for name, property := range spec.Properties {
		properties[normalizeIntegrationToken(name)] = model.IntegrationSchemaProperty{
			Type:        normalizeIntegrationToken(property.Type),
			Description: strings.TrimSpace(property.Description),
			Secret:      property.Secret,
			Enum:        property.Enum,
			Default:     property.Default,
		}
	}
	spec.Properties = properties
	return spec
}

func normalizeIntegrationResourceTypes(resourceTypes []model.IntegrationResourceType) []model.IntegrationResourceType {
	if len(resourceTypes) == 0 {
		return nil
	}

	normalized := make([]model.IntegrationResourceType, 0, len(resourceTypes))
	for _, resourceType := range resourceTypes {
		normalized = append(normalized, model.IntegrationResourceType{
			Name:             normalizeIntegrationToken(resourceType.Name),
			CanonicalPrefix:  strings.TrimSpace(resourceType.CanonicalPrefix),
			IdentityTemplate: strings.TrimSpace(resourceType.IdentityTemplate),
			Discoverable:     resourceType.Discoverable,
			DefaultActions:   normalizeIntegrationTokens(resourceType.DefaultActions),
		})
	}

	slices.SortFunc(normalized, func(a model.IntegrationResourceType, b model.IntegrationResourceType) int {
		return strings.Compare(a.Name, b.Name)
	})
	return normalized
}

func normalizeIntegrationActionCatalog(actions []model.IntegrationActionDefinition) []model.IntegrationActionDefinition {
	if len(actions) == 0 {
		return nil
	}

	normalized := make([]model.IntegrationActionDefinition, 0, len(actions))
	for _, action := range actions {
		normalized = append(normalized, model.IntegrationActionDefinition{
			Name:          normalizeIntegrationToken(action.Name),
			Description:   strings.TrimSpace(action.Description),
			ResourceTypes: normalizeIntegrationTokens(action.ResourceTypes),
			Idempotent:    action.Idempotent,
		})
	}

	slices.SortFunc(normalized, func(a model.IntegrationActionDefinition, b model.IntegrationActionDefinition) int {
		return strings.Compare(a.Name, b.Name)
	})
	return normalized
}

func normalizeIntegrationTokens(values []string) []string {
	if len(values) == 0 {
		return nil
	}

	normalized := make([]string, 0, len(values))
	for _, value := range values {
		token := normalizeIntegrationToken(value)
		if token != "" {
			normalized = append(normalized, token)
		}
	}
	slices.Sort(normalized)
	return normalized
}

func normalizeIntegrationToken(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func formatContractMismatch(label string, expected any, actual any) error {
	expectedJSON, _ := json.Marshal(expected)
	actualJSON, _ := json.Marshal(actual)
	return fmt.Errorf("%s mismatch: expected %s, got %s", label, expectedJSON, actualJSON)
}

func integrationDescribeCacheKey(
	instanceManifest model.Manifest,
	typeManifest model.Manifest,
	typeSpec model.IntegrationTypeManifestSpec,
	instanceSpec model.IntegrationInstanceManifestSpec,
) string {
	instanceID := "global"
	instanceChecksum := ""
	if instanceManifest.Kind == "integration_instance" {
		instanceID = instanceManifest.ID.String()
		instanceChecksum = instanceManifest.Checksum
	}
	return strings.Join([]string{
		instanceID,
		instanceChecksum,
		typeManifest.ID.String(),
		typeManifest.Checksum,
		strings.TrimSpace(typeSpec.Adapter.Transport),
		strings.TrimSpace(typeSpec.Adapter.Version),
		strings.TrimSpace(typeSpec.Adapter.Queues.Health),
		strings.TrimSpace(typeSpec.Adapter.Queues.Describe),
		strings.TrimSpace(typeSpec.Adapter.Endpoints.Health),
		strings.TrimSpace(typeSpec.Adapter.Endpoints.Describe),
		strings.TrimSpace(fmt.Sprint(instanceSpec.Config["base_url"])),
	}, ":")
}

func integrationDescribeRecentlyVerified(cacheKey string) bool {
	integrationDescribeCacheMu.RLock()
	verifiedAt, ok := integrationDescribeCache[cacheKey]
	integrationDescribeCacheMu.RUnlock()
	if !ok {
		return false
	}
	return time.Since(verifiedAt) < integrationDescribeCacheTTL
}

func markIntegrationDescribeVerified(cacheKey string) {
	integrationDescribeCacheMu.Lock()
	integrationDescribeCache[cacheKey] = time.Now().UTC()
	integrationDescribeCacheMu.Unlock()
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	return ""
}
