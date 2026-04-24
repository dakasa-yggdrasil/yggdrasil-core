package message

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/rpc"
)

type rpcEnvelope struct {
	OK    bool            `json:"ok"`
	Data  json.RawMessage `json:"data,omitempty"`
	Error *rpcError       `json:"error,omitempty"`
}

// callRPC performs an RPC round-trip through a rpc.Transport: JSON-
// marshals the request, dispatches to the endpoint, awaits the reply,
// then decodes the rpcEnvelope wrapper into response. Used by every
// core consumer that needs to talk to another core consumer (or to an
// external RPC endpoint over the same transport).
//
// Replaces the AMQP-specific callRabbitRPC; the difference is purely
// the transport layer — the request/response body shape is unchanged.
func callRPC(ctx context.Context, transport rpc.Transport, endpoint string, request any, response any) error {
	if transport == nil {
		return fmt.Errorf("rpc: transport is nil")
	}

	body, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("rpc: encode request for %s: %w", endpoint, err)
	}

	reply, err := transport.Request(ctx, rpc.Request{
		Endpoint:    endpoint,
		Body:        body,
		ContentType: "application/json",
	})
	if err != nil {
		return err
	}
	return decodeRPCBody(reply.Body, response)
}

func decodeRPCBody(body []byte, response any) error {
	if len(bytesTrimSpace(body)) == 0 {
		return fmt.Errorf("rpc response body is empty")
	}

	var envelope rpcEnvelope
	if err := json.Unmarshal(body, &envelope); err == nil {
		if envelope.Error != nil {
			return fmt.Errorf("%s: %s", envelope.Error.Code, envelope.Error.Message)
		}
		if len(envelope.Data) > 0 {
			if response == nil {
				return nil
			}
			return json.Unmarshal(envelope.Data, response)
		}
		if envelope.OK {
			return nil
		}
	}

	if response == nil {
		return nil
	}
	return json.Unmarshal(body, response)
}
