package message

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/dakasa-yggdrasil/yggdrasil-sdk-go/rpc"
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
	return callRPCWithPolicy(ctx, transport, endpoint, request, response, adapterCallPolicy{})
}

func callRPCWithPolicy(
	ctx context.Context,
	transport rpc.Transport,
	endpoint string,
	request any,
	response any,
	policy adapterCallPolicy,
) error {
	if transport == nil {
		return policy.sanitizeError(fmt.Errorf("rpc: transport is nil"))
	}

	body, err := json.Marshal(request)
	if err != nil {
		if policy.detailFreeErrors {
			return policy.sanitizeError(err)
		}
		return fmt.Errorf("rpc: encode request for %s: %w", endpoint, err)
	}

	reply, err := transport.Request(ctx, rpc.Request{
		Endpoint:    endpoint,
		Body:        body,
		ContentType: "application/json",
	})
	if err != nil {
		return policy.sanitizeError(err)
	}
	return decodeRPCBodyWithPolicy(reply.Body, response, policy)
}

func decodeRPCBody(body []byte, response any) error {
	return decodeRPCBodyWithPolicy(body, response, adapterCallPolicy{})
}

func decodeRPCBodyWithPolicy(body []byte, response any, policy adapterCallPolicy) error {
	if len(bytesTrimSpace(body)) == 0 {
		return policy.sanitizeError(fmt.Errorf("rpc response body is empty"))
	}
	if policy.detailFreeErrors {
		return decodeRPCBodyDetailFree(body, response, policy)
	}

	var envelope rpcEnvelope
	if err := json.Unmarshal(body, &envelope); err == nil {
		if envelope.Error != nil {
			if policy.detailFreeErrors {
				return policy.sanitizeError(errors.New("rpc adapter returned failure"))
			}
			return fmt.Errorf("%s: %s", envelope.Error.Code, envelope.Error.Message)
		}
		if len(envelope.Data) > 0 {
			if response == nil {
				return nil
			}
			if err := json.Unmarshal(envelope.Data, response); err != nil {
				return policy.sanitizeError(err)
			}
			return nil
		}
		if envelope.OK {
			return nil
		}
	}

	if response == nil {
		return nil
	}
	if err := json.Unmarshal(body, response); err != nil {
		return policy.sanitizeError(err)
	}
	return nil
}

func decodeRPCBodyDetailFree(body []byte, response any, policy adapterCallPolicy) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil {
		return policy.sanitizeError(err)
	}
	_, hasOK := fields["ok"]
	_, hasData := fields["data"]
	_, hasError := fields["error"]
	if hasOK || hasData || hasError {
		var envelope rpcEnvelope
		if err := strictJSONUnmarshal(body, &envelope); err != nil {
			return policy.sanitizeError(err)
		}
		if envelope.Error != nil || !envelope.OK {
			return policy.sanitizeError(errors.New("rpc adapter returned failure"))
		}
		if len(envelope.Data) == 0 || response == nil {
			return nil
		}
		return policy.sanitizeError(strictJSONUnmarshal(envelope.Data, response))
	}

	if response == nil {
		return nil
	}
	return policy.sanitizeError(strictJSONUnmarshal(body, response))
}

func strictJSONUnmarshal(body []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}

	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("json response contains trailing data")
		}
		return err
	}
	return nil
}
