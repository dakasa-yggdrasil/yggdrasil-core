//go:build nativequalification

package capacityqualification

import "errors"

// ReadDiagnostic contains only a closed stage label. It carries no request,
// response, resource identity, timestamp, error text, or credential material.
type ReadDiagnostic struct {
	Schema string `json:"schema"`
	Origin string `json:"origin"`
	Stage  string `json:"stage"`
}

func NewReadDiagnostic(origin, stage string) (ReadDiagnostic, error) {
	allowed := map[string]map[string]bool{
		"client":   {"catalog": true, "transport": true, "status": true, "decode": true, "contract_request": true, "transport_setup": true, "rpc_marshal": true, "rpc_roundtrip": true, "rpc_response": true, "contract_response": true, "operation": true, "capability": true, "explicit_status": true, "context": true},
		"consumer": {"envelope": true, "ordinal": true, "callee": true, "metadata": true, "request_publish": true, "response_encode": true, "response_publish": true, "reply_ack": true, "return_publish": true},
		"callee":   {"scope": true, "policy": true, "input": true, "slot_type": true, "slot": true, "keys": true, "realm": true, "prereg_query": true, "prereg_compare": true, "original": true, "binding": true, "ids": true, "instance": true, "type": true, "receipt": true, "expected": true, "native_read": true, "native_identity": true, "approved": true, "publish": true, "action": true, "context": true},
	}
	if !allowed[origin][stage] {
		return ReadDiagnostic{}, errors.New("closed qualification read diagnostic required")
	}
	return ReadDiagnostic{Schema: "pg17_native_read_failure_v1", Origin: origin, Stage: stage}, nil
}
