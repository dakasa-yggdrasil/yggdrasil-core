package message

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	contractdocs "github.com/dakasa-yggdrasil/yggdrasil-core/docs/contracts"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	amqp "github.com/rabbitmq/amqp091-go"
)

// ErrAdapterTransportUnavailable is returned when the configured adapter transport cannot be reached.
var ErrAdapterTransportUnavailable = errors.New("adapter transport is unavailable")

// AdapterTransportClient executes one adapter contract call through the transport declared by integration_type.
type AdapterTransportClient interface {
	Call(
		ctx context.Context,
		contract rpcContractSpec,
		typeSpec model.IntegrationTypeManifestSpec,
		instanceSpec model.IntegrationInstanceManifestSpec,
		capability string,
		request any,
		response any,
	) error
}

type adapterTransportClient struct {
	rabbitmq   *amqp.Connection
	httpClient *http.Client
}

// NewAdapterTransportClient builds the transport client used by the core to reach integrations.
func NewAdapterTransportClient(rabbitmq *amqp.Connection) AdapterTransportClient {
	return &adapterTransportClient{
		rabbitmq:   rabbitmq,
		httpClient: &http.Client{},
	}
}

func (c *adapterTransportClient) Call(
	ctx context.Context,
	contract rpcContractSpec,
	typeSpec model.IntegrationTypeManifestSpec,
	instanceSpec model.IntegrationInstanceManifestSpec,
	capability string,
	request any,
	response any,
) error {
	if err := contractdocs.Validate(contract.Family, contract.RequestDef, request); err != nil {
		return fmt.Errorf("validate %s request: %w", contract.Label, err)
	}

	transport := strings.ToLower(strings.TrimSpace(typeSpec.Adapter.Transport))
	switch transport {
	case "rabbitmq":
		queue := adapterQueueForCapability(typeSpec.Adapter.Queues, capability)
		if queue == "" {
			return fmt.Errorf("adapter queue for capability %q is required", capability)
		}
		if c.rabbitmq == nil {
			return fmt.Errorf("%w: rabbitmq connection is not configured", ErrAdapterTransportUnavailable)
		}
		if err := callRabbitRPC(ctx, c.rabbitmq, queue, request, response); err != nil {
			return err
		}
	case "http_json":
		endpoint := adapterEndpointForCapability(typeSpec.Adapter.Endpoints, capability)
		if endpoint == "" {
			return fmt.Errorf("adapter endpoint for capability %q is required", capability)
		}
		if err := c.callHTTPJSON(ctx, endpoint, instanceSpec, request, response); err != nil {
			return err
		}
	default:
		return fmt.Errorf("integration transport %q is unsupported", typeSpec.Adapter.Transport)
	}

	if response != nil && contract.ResponseDef != "" {
		if err := contractdocs.Validate(contract.Family, contract.ResponseDef, response); err != nil {
			return fmt.Errorf("validate %s response: %w", contract.Label, err)
		}
	}
	return nil
}

func (c *adapterTransportClient) callHTTPJSON(
	ctx context.Context,
	endpoint string,
	instanceSpec model.IntegrationInstanceManifestSpec,
	request any,
	response any,
) error {
	baseURL, err := adapterBaseURL(instanceSpec)
	if err != nil {
		return err
	}

	targetURL, err := resolveAdapterEndpointURL(baseURL, endpoint)
	if err != nil {
		return err
	}

	body, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("marshal http adapter request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build http adapter request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	httpResp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("%w: call http adapter endpoint %q: %v", ErrAdapterTransportUnavailable, targetURL, err)
	}
	defer func() { _ = httpResp.Body.Close() }()

	responseBody, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return fmt.Errorf("read http adapter response: %w", err)
	}

	if httpResp.StatusCode >= http.StatusBadRequest {
		message := strings.TrimSpace(string(responseBody))
		if message == "" {
			message = http.StatusText(httpResp.StatusCode)
		}
		return fmt.Errorf("http adapter endpoint %q returned %d: %s", targetURL, httpResp.StatusCode, message)
	}

	return decodeRPCBody(responseBody, response)
}

func adapterQueueForCapability(queues model.IntegrationAdapterQueue, capability string) string {
	switch strings.ToLower(strings.TrimSpace(capability)) {
	case "describe":
		return strings.TrimSpace(queues.Describe)
	case "discover":
		return strings.TrimSpace(queues.Discover)
	case "read":
		return strings.TrimSpace(queues.Read)
	case "execute":
		return strings.TrimSpace(queues.Execute)
	case "sync":
		return strings.TrimSpace(queues.Sync)
	case "health":
		return strings.TrimSpace(queues.Health)
	default:
		return ""
	}
}

func adapterEndpointForCapability(endpoints model.IntegrationAdapterRoute, capability string) string {
	switch strings.ToLower(strings.TrimSpace(capability)) {
	case "describe":
		return strings.TrimSpace(endpoints.Describe)
	case "discover":
		return strings.TrimSpace(endpoints.Discover)
	case "read":
		return strings.TrimSpace(endpoints.Read)
	case "execute":
		return strings.TrimSpace(endpoints.Execute)
	case "sync":
		return strings.TrimSpace(endpoints.Sync)
	case "health":
		return strings.TrimSpace(endpoints.Health)
	default:
		return ""
	}
}

func adapterBaseURL(instanceSpec model.IntegrationInstanceManifestSpec) (string, error) {
	raw, _ := instanceSpec.Config["base_url"].(string)
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("integration instance config.base_url is required for http_json transport")
	}

	parsed, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("parse integration base_url: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", fmt.Errorf("integration base_url must use http or https")
	}
	if parsed.Host == "" {
		return "", fmt.Errorf("integration base_url host is required")
	}
	return strings.TrimRight(parsed.String(), "/"), nil
}

func resolveAdapterEndpointURL(baseURL string, endpoint string) (string, error) {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return "", fmt.Errorf("adapter endpoint is required")
	}

	base, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("parse adapter base url: %w", err)
	}
	rel, err := url.Parse(endpoint)
	if err != nil {
		return "", fmt.Errorf("parse adapter endpoint: %w", err)
	}
	return base.ResolveReference(rel).String(), nil
}
