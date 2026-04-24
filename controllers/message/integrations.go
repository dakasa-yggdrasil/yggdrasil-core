package message

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	amqp "github.com/rabbitmq/amqp091-go"
	"go.uber.org/zap"
	"github.com/dakasa-yggdrasil/yggdrasil-sdk-go/rpc"
	rpcamqp "github.com/dakasa-yggdrasil/yggdrasil-sdk-go/rpc/amqp"
)

const (
	queueIntegrationExecute            = "yggdrasil-core.integration.execute"
	queueIntegrationStatusGet          = "yggdrasil-core.integration.status.get"
	queueIntegrationStatusList         = "yggdrasil-core.integration.status.list"
	queueIntegrationInstanceHealthGet  = "yggdrasil-core.integration.instance_health.get"
	queueIntegrationInstanceHealthList = "yggdrasil-core.integration.instance_health.list"
	queueIntegrationCatalogGet         = "yggdrasil-core.integration.catalog.get"
	queueIntegrationCatalogList        = "yggdrasil-core.integration.catalog.list"
	queueCatalogDiscover               = "yggdrasil-core.catalog.discover"
)

func integrationConsumers(conn *amqp.Connection, db *sql.DB, logger *zap.Logger) []ConsumerConfig {
	return []ConsumerConfig{
		{
			Queue:   queueIntegrationExecute,
			Timeout: 30 * time.Second,
			QoS:     10,
			Handler: integrationExecuteHandler(conn, db, logger),
		},
		{
			Queue:   queueIntegrationStatusGet,
			Timeout: 10 * time.Second,
			QoS:     10,
			Handler: integrationStatusGetHandler(conn, db, logger),
		},
		{
			Queue:   queueIntegrationStatusList,
			Timeout: 10 * time.Second,
			QoS:     10,
			Handler: integrationStatusListHandler(conn, db, logger),
		},
		{
			Queue:   queueIntegrationInstanceHealthGet,
			Timeout: 10 * time.Second,
			QoS:     10,
			Handler: integrationInstanceHealthGetHandler(conn, db, logger),
		},
		{
			Queue:   queueIntegrationInstanceHealthList,
			Timeout: 10 * time.Second,
			QoS:     10,
			Handler: integrationInstanceHealthListHandler(conn, db, logger),
		},
		{
			Queue:   queueIntegrationCatalogGet,
			Timeout: 10 * time.Second,
			QoS:     10,
			Handler: integrationCatalogGetHandler(conn, db, logger),
		},
		{
			Queue:   queueIntegrationCatalogList,
			Timeout: 10 * time.Second,
			QoS:     10,
			Handler: integrationCatalogListHandler(conn, db, logger),
		},
		{
			Queue:   queueCatalogDiscover,
			Timeout: 30 * time.Second,
			QoS:     10,
			Handler: catalogDiscoverHandler(conn, db, logger),
		},
	}
}

func integrationExecuteHandler(conn *amqp.Connection, db *sql.DB, logger *zap.Logger) ConsumerHandler {
	return func(ctx context.Context, d rpc.Delivery) error {
		var req model.ExecuteIntegrationRequest
		if err := json.Unmarshal(d.Body, &req); err != nil {
			return replyFailure(ctx, d, "bad_request", err, logger)
		}

		req = normalizeExecuteIntegrationRequest(req)
		if err := validateExecuteIntegrationRequest(req); err != nil {
			return replyFailure(ctx, d, "bad_request", err, logger)
		}

		response, err := executeIntegrationRequest(ctx, conn, db, req, 0)
		if err != nil {
			return replyFailure(ctx, d, integrationAwareErrorCode(err, "integration_execute_failed"), err, logger)
		}

		return replySuccess(ctx, d, response, logger)
	}
}

func integrationStatusGetHandler(conn *amqp.Connection, db *sql.DB, logger *zap.Logger) ConsumerHandler {
	return func(ctx context.Context, d rpc.Delivery) error {
		var req model.GetIntegrationRuntimeStateRequest
		if err := json.Unmarshal(d.Body, &req); err != nil {
			return replyFailure(ctx, d, "bad_request", err, logger)
		}

		if strings.TrimSpace(req.CheckKind) == "" {
			req.CheckKind = model.IntegrationRuntimeCheckKindDescribeHandshake
		}

		state, err := repository.GetIntegrationRuntimeState(ctx, db, req.IntegrationInstance, req.CheckKind)
		if err != nil {
			return replyFailure(ctx, d, integrationRuntimeStateErrorCode(err), err, logger)
		}

		return replySuccess(ctx, d, map[string]any{"state": state}, logger)
	}
}

func integrationStatusListHandler(conn *amqp.Connection, db *sql.DB, logger *zap.Logger) ConsumerHandler {
	return func(ctx context.Context, d rpc.Delivery) error {
		req := model.ListIntegrationRuntimeStatesRequest{}
		if len(bytesTrimSpace(d.Body)) > 0 {
			if err := json.Unmarshal(d.Body, &req); err != nil {
				return replyFailure(ctx, d, "bad_request", err, logger)
			}
		}

		states, err := repository.ListIntegrationRuntimeStates(ctx, db, req)
		if err != nil {
			return replyFailure(ctx, d, integrationRuntimeStateErrorCode(err), err, logger)
		}

		return replySuccess(ctx, d, map[string]any{"states": states}, logger)
	}
}

func integrationInstanceHealthGetHandler(conn *amqp.Connection, db *sql.DB, logger *zap.Logger) ConsumerHandler {
	return func(ctx context.Context, d rpc.Delivery) error {
		var req model.GetIntegrationInstanceHealthRequest
		if err := json.Unmarshal(d.Body, &req); err != nil {
			return replyFailure(ctx, d, "bad_request", err, logger)
		}

		health, err := getIntegrationInstanceHealth(ctx, db, req.IntegrationInstance, req.CheckKind)
		if err != nil {
			return replyFailure(ctx, d, integrationInstanceHealthErrorCode(err), err, logger)
		}

		return replySuccess(ctx, d, map[string]any{"health": health}, logger)
	}
}

func integrationInstanceHealthListHandler(conn *amqp.Connection, db *sql.DB, logger *zap.Logger) ConsumerHandler {
	return func(ctx context.Context, d rpc.Delivery) error {
		req := model.ListIntegrationInstanceHealthRequest{}
		if len(bytesTrimSpace(d.Body)) > 0 {
			if err := json.Unmarshal(d.Body, &req); err != nil {
				return replyFailure(ctx, d, "bad_request", err, logger)
			}
		}

		items, err := listIntegrationInstanceHealth(ctx, db, req)
		if err != nil {
			return replyFailure(ctx, d, integrationInstanceHealthErrorCode(err), err, logger)
		}

		return replySuccess(ctx, d, map[string]any{"items": items}, logger)
	}
}

func integrationCatalogGetHandler(conn *amqp.Connection, db *sql.DB, logger *zap.Logger) ConsumerHandler {
	return func(ctx context.Context, d rpc.Delivery) error {
		var req model.GetIntegrationCatalogEntryRequest
		if err := json.Unmarshal(d.Body, &req); err != nil {
			return replyFailure(ctx, d, "bad_request", err, logger)
		}

		entry, err := getIntegrationCatalogEntry(ctx, db, req)
		if err != nil {
			return replyFailure(ctx, d, integrationCatalogErrorCode(err), err, logger)
		}

		return replySuccess(ctx, d, map[string]any{"entry": entry}, logger)
	}
}

func integrationCatalogListHandler(conn *amqp.Connection, db *sql.DB, logger *zap.Logger) ConsumerHandler {
	return func(ctx context.Context, d rpc.Delivery) error {
		req := model.ListIntegrationCatalogRequest{}
		if len(bytesTrimSpace(d.Body)) > 0 {
			if err := json.Unmarshal(d.Body, &req); err != nil {
				return replyFailure(ctx, d, "bad_request", err, logger)
			}
		}

		domains, err := integrationCatalogList(ctx, db, req)
		if err != nil {
			return replyFailure(ctx, d, integrationCatalogErrorCode(err), err, logger)
		}

		return replySuccess(ctx, d, map[string]any{"domains": domains}, logger)
	}
}

func catalogDiscoverHandler(conn *amqp.Connection, db *sql.DB, logger *zap.Logger) ConsumerHandler {
	return func(ctx context.Context, d rpc.Delivery) error {
		req := model.DiscoverCatalogRequest{}
		if len(bytesTrimSpace(d.Body)) > 0 {
			if err := json.Unmarshal(d.Body, &req); err != nil {
				return replyFailure(ctx, d, "bad_request", err, logger)
			}
		}

		response, err := discoverCatalog(ctx, conn, db, req)
		if err != nil {
			return replyFailure(ctx, d, integrationAwareErrorCode(err, "catalog_discover_failed"), err, logger)
		}

		return replySuccess(ctx, d, response, logger)
	}
}

func executeIntegrationRequest(
	ctx context.Context,
	conn *amqp.Connection,
	db *sql.DB,
	req model.ExecuteIntegrationRequest,
	timeoutOverride time.Duration,
) (model.ExecuteIntegrationResponse, error) {
	instanceManifest, instanceSpec, typeManifest, typeSpec, err := resolveIntegrationInstance(ctx, conn, db, req.Integration)
	if err != nil {
		return model.ExecuteIntegrationResponse{}, err
	}

	return executeIntegrationThroughResolved(ctx, conn, req, instanceManifest, instanceSpec, typeManifest, typeSpec, timeoutOverride)
}

func executeIntegrationThroughResolved(
	ctx context.Context,
	conn *amqp.Connection,
	req model.ExecuteIntegrationRequest,
	instanceManifest model.Manifest,
	instanceSpec model.IntegrationInstanceManifestSpec,
	typeManifest model.Manifest,
	typeSpec model.IntegrationTypeManifestSpec,
	timeoutOverride time.Duration,
) (model.ExecuteIntegrationResponse, error) {
	timeout := defaultWorkflowStepTimeout
	if typeSpec.Adapter.TimeoutSeconds > 0 {
		timeout = time.Duration(typeSpec.Adapter.TimeoutSeconds) * time.Second
	}
	if timeoutOverride > 0 {
		timeout = timeoutOverride
	}

	rpcCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	request := model.AdapterExecuteIntegrationRequest{
		Operation:  req.Operation,
		Capability: req.Capability,
		Input:      cloneAuthorizationInput(req.Input),
		Auth:       cloneAuthorizationInput(req.Auth),
		Metadata:   cloneAuthorizationInput(req.Metadata),
		Integration: model.AdapterExecuteIntegrationContext{
			Type:         manifestReferenceFromRecord(typeManifest),
			TypeSpec:     typeSpec,
			Instance:     manifestReferenceFromRecord(instanceManifest),
			InstanceSpec: instanceSpec,
		},
	}

	var response model.AdapterExecuteIntegrationResponse
	transport := NewAdapterTransportClient(rpcamqp.New(conn))
	if err := transport.Call(rpcCtx, integrationExecuteContract, typeSpec, instanceSpec, "execute", request, &response); err != nil {
		return model.ExecuteIntegrationResponse{}, fmt.Errorf("call integration execute transport %q: %w", typeSpec.Adapter.Transport, err)
	}

	if operation := strings.TrimSpace(response.Operation); operation != "" && operation != req.Operation {
		return model.ExecuteIntegrationResponse{}, fmt.Errorf("unexpected adapter operation %q", response.Operation)
	}
	if capability := strings.TrimSpace(response.Capability); capability != "" && capability != req.Capability {
		return model.ExecuteIntegrationResponse{}, fmt.Errorf("unexpected adapter capability %q", response.Capability)
	}

	status := strings.TrimSpace(response.Status)
	if status == "" {
		status = "succeeded"
	}

	return model.ExecuteIntegrationResponse{
		Operation:           req.Operation,
		Capability:          req.Capability,
		Status:              status,
		IntegrationInstance: manifestReferenceFromRecord(instanceManifest),
		IntegrationType:     manifestReferenceFromRecord(typeManifest),
		Output:              response.Output,
		Metadata:            response.Metadata,
	}, nil
}

func normalizeExecuteIntegrationRequest(req model.ExecuteIntegrationRequest) model.ExecuteIntegrationRequest {
	req.Operation = strings.ToLower(strings.TrimSpace(req.Operation))
	req.Capability = strings.ToLower(strings.TrimSpace(req.Capability))
	if req.Operation == "" {
		req.Operation = req.Capability
	}
	if req.Capability == "" {
		req.Capability = req.Operation
	}
	if req.Input == nil {
		req.Input = map[string]any{}
	}
	if req.Auth == nil {
		req.Auth = map[string]any{}
	}
	if req.Metadata == nil {
		req.Metadata = map[string]any{}
	}
	return req
}

func validateExecuteIntegrationRequest(req model.ExecuteIntegrationRequest) error {
	if strings.TrimSpace(req.Integration.ManifestID) == "" &&
		strings.TrimSpace(req.Integration.Name) == "" {
		return fmt.Errorf("integration instance selector is required")
	}
	if strings.TrimSpace(req.Operation) == "" && strings.TrimSpace(req.Capability) == "" {
		return fmt.Errorf("integration operation or capability is required")
	}
	return nil
}

func integrationRuntimeStateErrorCode(err error) string {
	if errors.Is(err, repository.ErrIntegrationRuntimeStateNotFound) || errors.Is(err, repository.ErrManifestNotFound) {
		return "not_found"
	}
	if strings.Contains(strings.ToLower(err.Error()), "integration type") || strings.Contains(strings.ToLower(err.Error()), "manifest") {
		return "bad_request"
	}
	return "internal_error"
}

func integrationCatalogErrorCode(err error) string {
	if errors.Is(err, repository.ErrManifestNotFound) {
		return "not_found"
	}
	message := strings.ToLower(strings.TrimSpace(err.Error()))
	if strings.Contains(message, "domain") || strings.Contains(message, "section") || strings.Contains(message, "entry") {
		return "bad_request"
	}
	return manifestLookupErrorCode(err)
}
