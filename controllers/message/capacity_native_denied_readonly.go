//go:build !nativequalification

package message

import (
	"context"
	"encoding/json"
	"reflect"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// A dedicated observer publication is required. The normal 1.65.5 adapter,
// normal current type/IID, IAM, inventories and historical creator are separate.
// Root binds the real independently published compiler source before CI/deploy.
const nativeDeniedReadonlySource = "836ef8b0a864c07761d1f5e59d11a14d03ebf823"
const nativeDeniedReadonlyVersion = "1.65.6"
const nativeDeniedReadonlyProvider = "aws-native-denied-readonly"
const nativeDeniedReadonlyOrigin = "http://integration-aws-native-denied-readonly.dakasa.svc.cluster.local:8081"
const nativeDeniedReadonlyDescribeSchema = "aws_native_authorization_denied_readonly_describe_v1"

type nativeDeniedReadonlyDescription struct {
	Schema                      string `json:"schema"`
	Provider                    string `json:"provider"`
	Version                     string `json:"version"`
	SourceCommit                string `json:"source_commit"`
	Transport                   string `json:"transport"`
	DescribeEndpoint            string `json:"describe_endpoint"`
	ExecuteEndpoint             string `json:"execute_endpoint"`
	Operation                   string `json:"operation"`
	RequestSchema               string `json:"request_schema"`
	OriginalAdapterVersion      string `json:"original_adapter_version"`
	OriginalAdapterSourceCommit string `json:"original_adapter_source_commit"`
	NativeMutations             int    `json:"native_mutations"`
	NormalAdapterOperations     bool   `json:"normal_adapter_operations"`
	AMQPRegistered              bool   `json:"AMQP_registered"`
}

func nativeDeniedReadonlySourceReady(source string) bool {
	return nativeDeniedObserverSourceReady(source) && source != nativeDeniedAWSObserverSource
}

func expectedNativeDeniedReadonlyDescription(source string) nativeDeniedReadonlyDescription {
	return nativeDeniedReadonlyDescription{Schema: nativeDeniedReadonlyDescribeSchema, Provider: nativeDeniedReadonlyProvider, Version: nativeDeniedReadonlyVersion, SourceCommit: source, Transport: "http_json", DescribeEndpoint: "/rpc/describe", ExecuteEndpoint: "/rpc/execute", Operation: originalCreateDispositionOperation, RequestSchema: "aws_original_authorization_denied_read_request_v1", OriginalAdapterVersion: "1.65.4", OriginalAdapterSourceCommit: originalCreateDispositionAWSObserverSource, NativeMutations: 0, NormalAdapterOperations: false, AMQPRegistered: false}
}

// Compare every raw JSON key, including mandatory false/zero values, before a
// typed projection can erase omissions. The dedicated role is never a normal
// integration_type or an assertion that old config has a new creator Source.
func validateNativeDeniedReadonlyDescription(raw []byte, source string) error {
	var typed nativeDeniedReadonlyDescription
	if !nativeDeniedReadonlySourceReady(source) || capacity.DecodeGuestLifecycle(raw, &typed) != nil || typed != expectedNativeDeniedReadonlyDescription(source) {
		return errOriginalCreateDisposition
	}
	expected, err := json.Marshal(expectedNativeDeniedReadonlyDescription(source))
	var a, b map[string]any
	if err != nil || json.Unmarshal(raw, &a) != nil || json.Unmarshal(expected, &b) != nil || !reflect.DeepEqual(a, b) {
		return errOriginalCreateDisposition
	}
	return nil
}

func describeNativeDeniedReadonly(ctx context.Context, source string) error {
	if ctx == nil || !nativeDeniedReadonlySourceReady(source) {
		return errOriginalCreateDisposition
	}
	rpcCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	request := struct {
		Provider             string `json:"provider"`
		ExpectedVersion      string `json:"expected_version"`
		ExpectedSourceCommit string `json:"expected_source_commit"`
	}{nativeDeniedReadonlyProvider, nativeDeniedReadonlyVersion, source}
	var raw json.RawMessage
	client := newAdapterTransportClient(nil)
	if client.callNativeHTTPJSON(rpcCtx, nativeDeniedReadonlyOrigin+"/rpc/describe", request, &raw, adapterCallPolicy{detailFreeErrors: true, native: &nativeAdapterHTTPPolicy{limit: 8192, parent: ctx}}) != nil {
		return errOriginalCreateDisposition
	}
	return validateNativeDeniedReadonlyDescription(raw, source)
}

// Keep the original immutable manifests/type/config in the execute envelope.
// Only transport destination changes to the separately described HTTP reader.
func nativeDeniedReadonlyEnvelope(observer nativeDeniedResolvedObserver, fixed map[string]any) (any, error) {
	// The full raw historical/current catalogs have already been compared by
	// resolveNativeDeniedObserver. Project ONLY the published AWS protocol DTO
	// for execution, as the old AWS handler did on decode. Core-only credential
	// policy, guardian/UI/family metadata and action InputSchema are not part of
	// that DTO. This is not a relaxed whole-catalog or input validation rule.
	wire, err := nativeDeniedHistoricalAWSWireType(observer.typeSpec)
	if err != nil {
		return nil, err
	}
	return struct {
		Operation   string         `json:"operation"`
		Capability  string         `json:"capability"`
		Input       map[string]any `json:"input"`
		Integration struct {
			Type         model.ManifestReference               `json:"type"`
			TypeSpec     map[string]any                        `json:"type_spec"`
			Instance     model.ManifestReference               `json:"instance"`
			InstanceSpec model.IntegrationInstanceManifestSpec `json:"instance_spec"`
		} `json:"integration"`
	}{Operation: originalCreateDispositionOperation, Capability: originalCreateDispositionOperation, Input: cloneAuthorizationInput(fixed), Integration: struct {
		Type         model.ManifestReference               `json:"type"`
		TypeSpec     map[string]any                        `json:"type_spec"`
		Instance     model.ManifestReference               `json:"instance"`
		InstanceSpec model.IntegrationInstanceManifestSpec `json:"instance_spec"`
	}{manifestReferenceFromRecord(observer.typ), wire, manifestReferenceFromRecord(observer.instance), observer.instanceSpec}}, nil
}

func nativeDeniedHistoricalAWSWireType(spec model.IntegrationTypeManifestSpec) (map[string]any, error) {
	raw, err := json.Marshal(spec)
	var source map[string]any
	if err != nil || json.Unmarshal(raw, &source) != nil {
		return nil, errOriginalCreateDisposition
	}
	selectFields := func(input map[string]any, names ...string) map[string]any {
		out := make(map[string]any)
		for _, name := range names {
			if value, exists := input[name]; exists {
				out[name] = value
			}
		}
		return out
	}
	out := selectFields(source, "provider", "adapter", "capabilities", "credential_schema", "instance_schema", "resource_types", "action_catalog", "discovery", "normalization", "execution", "extensions")
	adapter, ok := source["adapter"].(map[string]any)
	if !ok {
		return nil, errOriginalCreateDisposition
	}
	projectedAdapter := selectFields(adapter, "transport", "version", "queues", "endpoints", "timeout_seconds")
	if value, exists := adapter["endpoints"]; exists {
		endpoints, ok := value.(map[string]any)
		if !ok {
			return nil, errOriginalCreateDisposition
		}
		projectedAdapter["endpoints"] = selectFields(endpoints, "describe", "execute")
	}
	out["adapter"] = projectedAdapter
	for _, name := range []string{"credential_schema", "instance_schema"} {
		schema, ok := source[name].(map[string]any)
		if !ok {
			return nil, errOriginalCreateDisposition
		}
		projectedSchema := selectFields(schema, "mode", "required", "properties")
		if value, exists := schema["properties"]; exists {
			properties, ok := value.(map[string]any)
			if !ok {
				return nil, errOriginalCreateDisposition
			}
			projectedProperties := make(map[string]any, len(properties))
			for key, value := range properties {
				property, ok := value.(map[string]any)
				if !ok {
					return nil, errOriginalCreateDisposition
				}
				projectedProperties[key] = selectFields(property, "type", "description", "secret", "enum", "default")
			}
			projectedSchema["properties"] = projectedProperties
		}
		out[name] = projectedSchema
	}
	if value, exists := source["action_catalog"]; exists {
		actions, ok := value.([]any)
		if !ok {
			return nil, errOriginalCreateDisposition
		}
		projectedActions := make([]any, len(actions))
		for i, value := range actions {
			action, ok := value.(map[string]any)
			if !ok {
				return nil, errOriginalCreateDisposition
			}
			projectedActions[i] = selectFields(action, "name", "description", "resource_types", "idempotent", "category")
		}
		out["action_catalog"] = projectedActions
	}
	return out, nil
}

func executeNativeDeniedReadonly(ctx context.Context, observer nativeDeniedResolvedObserver, fixed map[string]any) (model.AdapterExecuteIntegrationResponse, error) {
	var reply model.AdapterExecuteIntegrationResponse
	if ctx == nil || !nativeDeniedReadonlySourceReady(nativeDeniedReadonlySource) || len(fixed) != 11 || fixed["schema"] != "aws_original_authorization_denied_read_request_v1" {
		return reply, errOriginalCreateDisposition
	}
	rpcCtx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	request, err := nativeDeniedReadonlyEnvelope(observer, fixed)
	if err != nil {
		return reply, err
	}
	client := newAdapterTransportClient(nil)
	if client.callNativeHTTPJSON(rpcCtx, nativeDeniedReadonlyOrigin+"/rpc/execute", request, &reply, adapterCallPolicy{detailFreeErrors: true, native: &nativeAdapterHTTPPolicy{limit: 2 << 20, parent: ctx}}) != nil || reply.Operation != originalCreateDispositionOperation || reply.Capability != originalCreateDispositionOperation || reply.Status != "observed" {
		return model.AdapterExecuteIntegrationResponse{}, errOriginalCreateDisposition
	}
	return reply, nil
}
