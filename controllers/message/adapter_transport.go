package message

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	contractdocs "github.com/dakasa-yggdrasil/yggdrasil-core/docs/contracts"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-sdk-go/rpc"
)

// ErrAdapterTransportUnavailable is returned when the configured adapter transport cannot be reached.
var ErrAdapterTransportUnavailable = errors.New("adapter transport is unavailable")

var errAdapterCallFailed = errors.New("adapter_call_failed")

type adapterCallPolicy struct {
	detailFreeErrors bool
	// Set only by protected source-owned observers. Ordinary calls retain
	// their original transport behavior when this private policy is absent.
	native *nativeAdapterHTTPPolicy
}

// Private protected-observer scope also reaches the ORIGINAL resolver's
// health/Describe transport. No public input can install this context key.
type nativeAdapterPolicyKey struct{}

func withNativeAdapterPolicy(ctx, parent context.Context) context.Context {
	ownerDeadline, _ := ctx.Deadline()
	var parentDeadline time.Time
	if parent != nil {
		parentDeadline, _ = parent.Deadline()
	}
	return context.WithValue(ctx, nativeAdapterPolicyKey{}, adapterCallPolicy{detailFreeErrors: true, native: &nativeAdapterHTTPPolicy{limit: 2 << 20, parent: parent, ownerDeadline: ownerDeadline, parentDeadline: parentDeadline}})
}

type nativeAdapterHTTPPolicy struct {
	limit          int64
	get            bool
	requireTLS     bool
	exactURL       string
	readToken      string
	parent         context.Context
	ownerDeadline  time.Time
	parentDeadline time.Time
	guest          *capacityGuestHTTPPolicy
}

// Installed only by the protected original Guest consumer after operator
// catalog/secret/lease checks. No capability input can select an auth header,
// origin, decoder or TLS option.
type capacityGuestHTTPPolicy struct {
	baseURL string
	bearer  string
}

func withCapacityGuestHTTPPolicy(ctx, parent context.Context, g *capacityGuestHTTPPolicy) context.Context {
	ownerDeadline, _ := ctx.Deadline()
	parentDeadline, _ := parent.Deadline()
	return context.WithValue(ctx, nativeAdapterPolicyKey{}, adapterCallPolicy{detailFreeErrors: true, native: &nativeAdapterHTTPPolicy{limit: capacity.GuestBootstrapLimit, requireTLS: true, parent: parent, ownerDeadline: ownerDeadline, parentDeadline: parentDeadline, guest: g}})
}

func capacityGuestPolicy(ctx context.Context) *capacityGuestHTTPPolicy {
	if p, ok := ctx.Value(nativeAdapterPolicyKey{}).(adapterCallPolicy); ok && p.native != nil {
		return p.native.guest
	}
	return nil
}

type opaqueAdapterError struct{ public, cause error }

func (e *opaqueAdapterError) Error() string              { return e.public.Error() }
func (e *opaqueAdapterError) Unwrap() []error            { return []error{e.public, e.cause} }
func (e *opaqueAdapterError) GoString() string           { return e.Error() }
func (e *opaqueAdapterError) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, e.Error()) }
func nativeAdapterContext(ctx context.Context) error {
	if ctx == nil {
		return errors.New("native adapter owner missing")
	}
	err := errors.Join(ctx.Err(), context.Cause(ctx))
	if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
		err = errors.Join(err, context.DeadlineExceeded)
	}
	if policy, ok := ctx.Value(nativeAdapterPolicyKey{}).(adapterCallPolicy); ok && policy.native != nil {
		for _, deadline := range []time.Time{policy.native.ownerDeadline, policy.native.parentDeadline} {
			if !deadline.IsZero() && !time.Now().Before(deadline) {
				err = errors.Join(err, context.DeadlineExceeded)
			}
		}
	}
	return err
}

func (policy adapterCallPolicy) contextError(ctx context.Context) error {
	err := nativeAdapterContext(ctx)
	if policy.native != nil {
		if policy.native.parent != nil {
			err = errors.Join(err, nativeAdapterContext(policy.native.parent))
		}
		for _, deadline := range []time.Time{policy.native.ownerDeadline, policy.native.parentDeadline} {
			if !deadline.IsZero() && !time.Now().Before(deadline) {
				err = errors.Join(err, context.DeadlineExceeded)
			}
		}
	}
	return err
}

func (policy adapterCallPolicy) sanitizeError(err error) error {
	if err != nil && policy.detailFreeErrors {
		if policy.native != nil {
			return &opaqueAdapterError{public: errAdapterCallFailed, cause: err}
		}
		return errAdapterCallFailed
	}
	return err
}

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
	rpcTransport rpc.Transport
	httpClient   *http.Client
}

// NewAdapterTransportClient builds the transport client used by the
// core to reach integrations. Takes a generic rpc.Transport; the
// caller wires AMQP, HTTP, or any future backend behind that
// interface. The httpClient is kept distinct because http_json
// integrations still dial adapter URLs directly (they don't route
// through the core's rpc transport).
func NewAdapterTransportClient(transport rpc.Transport) AdapterTransportClient {
	return newAdapterTransportClient(transport)
}

func newAdapterTransportClient(transport rpc.Transport) *adapterTransportClient {
	return &adapterTransportClient{
		rpcTransport: transport,
		httpClient:   &http.Client{},
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
	var policy adapterCallPolicy
	if ctx != nil {
		policy, _ = ctx.Value(nativeAdapterPolicyKey{}).(adapterCallPolicy)
	}
	return c.callWithPolicy(ctx, contract, typeSpec, instanceSpec, capability, request, response, policy)
}

func (c *adapterTransportClient) callWithPolicy(
	ctx context.Context,
	contract rpcContractSpec,
	typeSpec model.IntegrationTypeManifestSpec,
	instanceSpec model.IntegrationInstanceManifestSpec,
	capability string,
	request any,
	response any,
	policy adapterCallPolicy,
) error {
	if policy.native != nil && ctx != nil {
		copy := *policy.native
		if d, ok := ctx.Deadline(); ok && (copy.ownerDeadline.IsZero() || d.Before(copy.ownerDeadline)) {
			copy.ownerDeadline = d
		}
		if copy.parent != nil {
			if d, ok := copy.parent.Deadline(); ok && (copy.parentDeadline.IsZero() || d.Before(copy.parentDeadline)) {
				copy.parentDeadline = d
			}
		}
		policy.native = &copy
	}
	if policy.native != nil && policy.contextError(ctx) != nil {
		return policy.sanitizeError(policy.contextError(ctx))
	}
	if err := contractdocs.Validate(contract.Family, contract.RequestDef, request); err != nil {
		if policy.detailFreeErrors {
			return policy.sanitizeError(err)
		}
		return fmt.Errorf("validate %s request: %w", contract.Label, err)
	}

	transport := strings.ToLower(strings.TrimSpace(typeSpec.Adapter.Transport))
	switch transport {
	case "rabbitmq":
		queue := adapterQueueForCapability(typeSpec.Adapter.Queues, capability)
		if queue == "" {
			return fmt.Errorf("adapter queue for capability %q is required", capability)
		}
		if c.rpcTransport == nil {
			err := fmt.Errorf("%w: rpc transport is not configured", ErrAdapterTransportUnavailable)
			return policy.sanitizeError(err)
		}
		rpcTransport := c.rpcTransport
		if policy.native != nil {
			if policy.native.get || policy.native.requireTLS {
				return policy.sanitizeError(errors.New("private native HTTPS reader cannot use broker RPC"))
			}
			rpcTransport = &nativeBoundedRPC{Transport: rpcTransport, policy: policy.native}
		}
		if err := callRPCWithPolicy(ctx, rpcTransport, queue, request, response, policy); err != nil {
			return policy.sanitizeError(err)
		}
	case "http_json":
		endpoint := adapterEndpointForCapability(typeSpec.Adapter.Endpoints, capability)
		if endpoint == "" {
			return fmt.Errorf("adapter endpoint for capability %q is required", capability)
		}
		if err := c.callHTTPJSONWithPolicy(ctx, endpoint, instanceSpec, request, response, policy); err != nil {
			return policy.sanitizeError(err)
		}
	default:
		return fmt.Errorf("integration transport %q is unsupported", typeSpec.Adapter.Transport)
	}

	if response != nil && contract.ResponseDef != "" {
		if err := contractdocs.Validate(contract.Family, contract.ResponseDef, response); err != nil {
			if policy.detailFreeErrors {
				return policy.sanitizeError(err)
			}
			return fmt.Errorf("validate %s response: %w", contract.Label, err)
		}
	}
	if policy.native != nil && policy.contextError(ctx) != nil {
		return policy.sanitizeError(policy.contextError(ctx))
	}
	return nil
}

// The broker SDK owns its original Request return and buffering. This fence
// caps decode/acceptance after that actual return; it makes no streaming-memory
// or HTTP Body.Close claim for the broker transport.
type nativeBoundedRPC struct {
	rpc.Transport
	policy *nativeAdapterHTTPPolicy
}

func (n *nativeBoundedRPC) Request(ctx context.Context, request rpc.Request) (rpc.Reply, error) {
	var empty rpc.Reply
	if n == nil || n.Transport == nil || n.policy == nil || n.policy.limit < 1 || n.policy.limit > 8<<20 || nativeAdapterContext(ctx) != nil {
		return empty, errors.Join(errors.New("fixed native broker owner required"), nativeAdapterContext(ctx))
	}
	deadline, _ := ctx.Deadline()
	reply, err := n.Transport.Request(ctx, request)
	joined := errors.Join(err, adapterCallPolicy{native: n.policy}.contextError(ctx))
	if n.policy.parent != nil {
		joined = errors.Join(joined, nativeAdapterContext(n.policy.parent))
	}
	if !deadline.IsZero() && !time.Now().Before(deadline) {
		joined = errors.Join(joined, context.DeadlineExceeded)
	}
	if joined != nil || int64(len(reply.Body)) > n.policy.limit {
		return empty, errors.Join(errors.New("bounded original broker return required"), joined)
	}
	return reply, nil
}

func (c *adapterTransportClient) callHTTPJSONWithPolicy(
	ctx context.Context,
	endpoint string,
	instanceSpec model.IntegrationInstanceManifestSpec,
	request any,
	response any,
	policy adapterCallPolicy,
) error {
	baseURL, err := adapterBaseURL(instanceSpec)
	if err != nil {
		return policy.sanitizeError(err)
	}

	targetURL, err := resolveAdapterEndpointURL(baseURL, endpoint)
	if err != nil {
		return policy.sanitizeError(err)
	}
	if policy.native != nil {
		return c.callNativeHTTPJSON(ctx, targetURL, request, response, policy)
	}

	body, err := json.Marshal(request)
	if err != nil {
		if policy.detailFreeErrors {
			return policy.sanitizeError(err)
		}
		return fmt.Errorf("marshal http adapter request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewReader(body))
	if err != nil {
		if policy.detailFreeErrors {
			return policy.sanitizeError(err)
		}
		return fmt.Errorf("build http adapter request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	httpResp, err := c.httpClient.Do(httpReq)
	if err != nil {
		if policy.detailFreeErrors {
			return policy.sanitizeError(err)
		}
		return fmt.Errorf("%w: call http adapter endpoint %q: %v", ErrAdapterTransportUnavailable, targetURL, err)
	}
	defer func() { _ = httpResp.Body.Close() }()

	responseBody, err := io.ReadAll(httpResp.Body)
	if err != nil {
		if policy.detailFreeErrors {
			return policy.sanitizeError(err)
		}
		return fmt.Errorf("read http adapter response: %w", err)
	}

	if httpResp.StatusCode >= http.StatusBadRequest {
		if policy.detailFreeErrors {
			return policy.sanitizeError(errors.New("http adapter returned non-success status"))
		}
		message := strings.TrimSpace(string(responseBody))
		if message == "" {
			message = http.StatusText(httpResp.StatusCode)
		}
		return fmt.Errorf("http adapter endpoint %q returned %d: %s", targetURL, httpResp.StatusCode, message)
	}

	// SDK HTTP transport wraps the adapter's reply in an envelope
	// `{content_type, body}` where body is base64-encoded JSON. Peel
	// that off here so decodeRPCBody sees the inner `{ok, data, ...}`
	// envelope the adapter actually produced.
	inner, err := unwrapSDKHTTPEnvelope(responseBody)
	if err != nil {
		if policy.detailFreeErrors {
			return policy.sanitizeError(err)
		}
		return fmt.Errorf("unwrap adapter http envelope: %w", err)
	}
	return decodeRPCBodyWithPolicy(inner, response, policy)
}

// One original call, Read and actual Close; no retry, caller header map or
// refreshed deadline. Private response bodies never become public error text.
func (c *adapterTransportClient) callNativeHTTPJSON(ctx context.Context, target string, request, response any, policy adapterCallPolicy) error {
	n := policy.native
	fail := func(err error) error { return &opaqueAdapterError{public: errAdapterCallFailed, cause: err} }
	if c == nil || c.httpClient == nil || n == nil || n.limit < 1 || n.limit > 8<<20 || nativeAdapterContext(ctx) != nil {
		return fail(errors.Join(errors.New("closed native response policy required"), nativeAdapterContext(ctx)))
	}
	deadline, hasDeadline := ctx.Deadline()
	var parentDeadline time.Time
	if n.parent != nil {
		parentDeadline, _ = n.parent.Deadline()
	}
	fence := func() error {
		err := policy.contextError(ctx)
		if hasDeadline && !time.Now().Before(deadline) {
			err = errors.Join(err, context.DeadlineExceeded)
		}
		if n.parent != nil {
			err = errors.Join(err, nativeAdapterContext(n.parent))
		}
		if !parentDeadline.IsZero() && !time.Now().Before(parentDeadline) {
			err = errors.Join(err, context.DeadlineExceeded)
		}
		return err
	}
	if fence() != nil {
		return fail(fence())
	}
	u, err := url.Parse(target)
	guest := n.guest
	privateBindingValid := n.exactURL == target && len(n.readToken) >= 32 && len(n.readToken) <= 4096 && !strings.ContainsAny(n.readToken, "\r\n")
	if guest != nil {
		privateBindingValid = len(guest.bearer) >= 32 && len(guest.bearer) <= 4096 && !strings.ContainsAny(guest.bearer, "\r\n") && (target == guest.baseURL+"/rpc/describe" || target == guest.baseURL+"/rpc/execute" || n.get && target == guest.baseURL+"/healthz")
	}
	if err != nil || u.User != nil || u.Fragment != "" || u.Host == "" || n.requireTLS && (u.Scheme != "https" || !privateBindingValid) {
		return fail(errors.New("fixed native transport binding refused"))
	}
	method := http.MethodPost
	var body []byte
	if n.get {
		method = http.MethodGet
	} else {
		body, err = json.Marshal(request)
		if err != nil {
			return fail(err)
		}
		if guest != nil && len(body) > capacity.GuestBootstrapLimit {
			return fail(errors.New("bounded original Guest request required"))
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(body))
	if err != nil {
		return fail(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if n.requireTLS {
		if guest != nil {
			req.GetBody = nil
			req.Header.Set("Authorization", "Bearer "+guest.bearer)
		} else {
			req.Header.Set("X-Capacity-Canary-Read-Key", n.readToken)
		}
	}
	client := *c.httpClient
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return errors.New("native redirect refused") }
	reply, callErr := client.Do(req)
	var raw []byte
	var readErr, closeErr, shapeErr error
	if reply == nil || reply.Body == nil {
		shapeErr = errors.New("native response absent")
	} else {
		valid := callErr == nil && fence() == nil && reply.StatusCode == http.StatusOK && reply.Request != nil && reply.Request.URL != nil && reply.Request.URL.String() == target && reply.Request.Method == method
		if n.requireTLS {
			valid = valid && reply.TLS != nil && reply.TLS.Version >= tls.VersionTLS12 && len(reply.TLS.VerifiedChains) > 0
		}
		if valid {
			raw, readErr = io.ReadAll(io.LimitReader(reply.Body, n.limit+1))
		} else {
			shapeErr = errors.New("fixed native response refused")
		}
		closeErr = reply.Body.Close()
	}
	joined := errors.Join(callErr, shapeErr, readErr, closeErr, fence())
	if joined != nil || int64(len(raw)) > n.limit {
		return fail(errors.Join(errors.New("bounded complete native response required"), joined))
	}
	if guest != nil && n.get {
		if target != guest.baseURL+"/healthz" || response != nil {
			return fail(errors.New("fixed Guest connectivity read required"))
		}
	} else if guest != nil && target == guest.baseURL+"/rpc/execute" {
		typed, ok := response.(*model.AdapterExecuteIntegrationResponse)
		if !ok {
			return fail(errors.New("original typed Guest reply required"))
		}
		err = capacity.DecodeGuestBootstrapReply(raw, typed)
	} else if guest != nil && target == guest.baseURL+"/rpc/describe" {
		// Validate the SAME raw public catalog before optional typed fields can
		// erase nulls or malformed shapes during remarshal. No projected fixture
		// or extra request can substitute for the original HTTP Read/Close.
		if _, ok := response.(*model.AdapterDescribeResponse); !ok {
			return fail(errors.New("original typed Guest catalog required"))
		}
		err = contractdocs.Validate(integrationDescribeContract.Family, integrationDescribeContract.ResponseDef, json.RawMessage(raw))
		if err == nil {
			err = decodeRPCBodyWithPolicy(raw, response, policy)
		}
	} else if n.get {
		err = capacity.DecodeBusinessJSON(raw, response)
	} else {
		var inner []byte
		inner, err = unwrapSDKHTTPEnvelope(raw)
		if err == nil {
			err = decodeRPCBodyWithPolicy(inner, response, policy)
		}
	}
	if err = errors.Join(err, fence()); err != nil {
		return fail(err)
	}
	return nil
}

// unwrapSDKHTTPEnvelope peels the {content_type, body} wrapper that
// the yggdrasil-sdk-go HTTP transport emits around adapter replies.
// If the payload does not look like the SDK envelope (zero-byte or
// missing the well-known fields), it is returned unchanged — AMQP
// replies and custom transports are already in the inner shape.
func unwrapSDKHTTPEnvelope(raw []byte) ([]byte, error) {
	if len(bytesTrimSpace(raw)) == 0 {
		return raw, nil
	}
	var envelope struct {
		ContentType string `json:"content_type"`
		Body        []byte `json:"body"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		// Not an SDK envelope — pass through so older transports
		// that don't wrap still work.
		return raw, nil
	}
	if envelope.Body == nil {
		return raw, nil
	}
	return envelope.Body, nil
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
