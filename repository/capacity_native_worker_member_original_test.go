package repository

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

const memberOriginalPrivateCanary = "private-configz-canary-órgão-🔐"

// A synthetic fragment of the actual K3s1.34.6 configz shape, not a cluster
// observation. Configz legitimately omits TypeMeta; unrelated API fields are
// extensible and may contain private values which must not become diagnostics.
func memberOriginalConfigzFixture() map[string]any {
	return map[string]any{"kubeletconfig": map[string]any{
		"enableServer": true, "enableDebuggingHandlers": true, "port": 10250,
		"authorization":  map[string]any{"mode": "Webhook", "webhook": map[string]any{"cacheAuthorizedTTL": "5m0s"}},
		"authentication": map[string]any{"x509": map[string]any{"clientCAFile": "/var/lib/rancher/k3s/agent/client-ca.crt"}, "anonymous": map[string]any{"enabled": false}, "webhook": map[string]any{"enabled": true}},
		"featureGates":   map[string]any{"KubeletFineGrainedAuthz": true},
		"staticPodPath":  "", "staticPodURL": "", "readOnlyPort": 0,
		"unrelatedPrivateConfig": map[string]any{"opaqueCredential": memberOriginalPrivateCanary},
	}}
}

func memberOriginalJSON(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal("cannot encode synthetic original fixture")
	}
	return raw
}

func TestNativeMemberOriginalConfigzSourceShapeAndPrivateProjection(t *testing.T) {
	for _, variation := range []string{"TypeMeta_absent", "TypeMeta_present", "omitted_default_fields", "Unicode_values_ASCII_extensions"} {
		t.Run(variation, func(t *testing.T) {
			root := memberOriginalConfigzFixture()
			config := root["kubeletconfig"].(map[string]any)
			switch variation {
			case "TypeMeta_present":
				config["apiVersion"], config["kind"] = "kubelet.config.k8s.io/v1beta1", "KubeletConfiguration"
			case "omitted_default_fields":
				delete(config, "staticPodPath")
				delete(config, "staticPodURL")
				delete(config, "featureGates")
				delete(config["authentication"].(map[string]any), "anonymous")
			case "Unicode_values_ASCII_extensions":
				root["futureEnvelopeField"] = map[string]any{"message": "configuração válida 日本語"}
				config["newRuntimeField"] = []any{"ação", map[string]any{"nestedASCII": "λ"}}
				config["authorization"].(map[string]any)["futureOption"] = "extensão"
				config["authentication"].(map[string]any)["x509"].(map[string]any)["futureOption"] = "証明書"
			}
			raw := memberOriginalJSON(t, root)
			before := append([]byte(nil), raw...)
			path, url, err := nativeMemberConfigzProjection(raw)
			if err != nil || path != "" || url != "" {
				t.Fatal("actual configz shape or legitimate extension refused")
			}
			if !bytes.Equal(raw, before) {
				t.Fatal("private projection modified original custody")
			}
		})
	}
	// The parser reports a producer that exists; it never normalizes it into
	// absence. verifyConfigz separately requires BOTH returned values empty.
	for _, key := range []string{"staticPodPath", "staticPodURL"} {
		root := memberOriginalConfigzFixture()
		value := "/etc/kubernetes/manifests"
		if key == "staticPodURL" {
			value = "https://fixed.invalid/static-pods"
		}
		root["kubeletconfig"].(map[string]any)[key] = value
		path, url, err := nativeMemberConfigzProjection(memberOriginalJSON(t, root))
		if err != nil || key == "staticPodPath" && path != value || key == "staticPodURL" && url != value || path == "" && url == "" {
			t.Fatal("an actual static producer was erased by projection")
		}
	}
}

func TestNativeMemberOriginalConfigzRejectsAmbiguityAndUnsafeFacts(t *testing.T) {
	for _, fault := range []string{"server_missing", "server_false", "server_null", "debugging_false", "debugging_type", "port_wrong", "port_string", "port_fraction", "port_null", "authz_missing", "authz_mode", "authz_alias", "authn_null", "x509_missing", "CA_empty", "CA_null", "CA_type", "anonymous_enabled", "anonymous_null", "anonymous_enabled_null", "anonymous_alias", "gate_false", "gate_null", "gate_alias", "gates_null", "apiVersion_wrong", "apiVersion_null", "kind_wrong", "path_null", "path_type", "url_null", "url_type", "Unicode_outer", "Unicode_config", "Unicode_authz", "Unicode_authn", "Unicode_x509", "Unicode_gate"} {
		t.Run(fault, func(t *testing.T) {
			root := memberOriginalConfigzFixture()
			config := root["kubeletconfig"].(map[string]any)
			authn := config["authentication"].(map[string]any)
			x509 := authn["x509"].(map[string]any)
			switch fault {
			case "server_missing":
				delete(config, "enableServer")
			case "server_false":
				config["enableServer"] = false
			case "server_null":
				config["enableServer"] = nil
			case "debugging_false":
				config["enableDebuggingHandlers"] = false
			case "debugging_type":
				config["enableDebuggingHandlers"] = "true"
			case "port_wrong":
				config["port"] = 10255
			case "port_string":
				config["port"] = "10250"
			case "port_fraction":
				config["port"] = 10250.5
			case "port_null":
				config["port"] = nil
			case "authz_missing":
				delete(config, "authorization")
			case "authz_mode":
				config["authorization"].(map[string]any)["mode"] = "AlwaysAllow"
			case "authz_alias":
				config["authorization"].(map[string]any)["Mode"] = "Webhook"
			case "authn_null":
				config["authentication"] = nil
			case "x509_missing":
				delete(authn, "x509")
			case "CA_empty":
				x509["clientCAFile"] = ""
			case "CA_null":
				x509["clientCAFile"] = nil
			case "CA_type":
				x509["clientCAFile"] = []string{"/trusted/ca"}
			case "anonymous_enabled":
				authn["anonymous"].(map[string]any)["enabled"] = true
			case "anonymous_null":
				authn["anonymous"] = nil
			case "anonymous_enabled_null":
				authn["anonymous"].(map[string]any)["enabled"] = nil
			case "anonymous_alias":
				authn["anonymous"].(map[string]any)["Enabled"] = false
			case "gate_false":
				config["featureGates"].(map[string]any)["KubeletFineGrainedAuthz"] = false
			case "gate_null":
				config["featureGates"].(map[string]any)["KubeletFineGrainedAuthz"] = nil
			case "gate_alias":
				config["featureGates"].(map[string]any)["kubeletFineGrainedAuthz"] = true
			case "gates_null":
				config["featureGates"] = nil
			case "apiVersion_wrong":
				config["apiVersion"] = "v1"
			case "apiVersion_null":
				config["apiVersion"] = nil
			case "kind_wrong":
				config["kind"] = "Pod"
			case "path_null":
				config["staticPodPath"] = nil
			case "path_type":
				config["staticPodPath"] = true
			case "url_null":
				config["staticPodURL"] = nil
			case "url_type":
				config["staticPodURL"] = 123
			case "Unicode_outer":
				root["Kubeletconfig"] = config
			case "Unicode_config":
				config["enableſerver"] = true
			case "Unicode_authz":
				config["authorization"].(map[string]any)["mοde"] = "Webhook"
			case "Unicode_authn":
				authn["x５０９"] = x509
			case "Unicode_x509":
				x509["clientCAKile"] = "/trusted/ca"
			case "Unicode_gate":
				config["featureGates"].(map[string]any)["KubeletFineGrainedAuthz"] = true
			}
			path, url, err := nativeMemberConfigzProjection(memberOriginalJSON(t, root))
			if err != errNativeMember || path != "" || url != "" {
				t.Fatal("unsafe configz fact was accepted or exposed a non-private diagnostic")
			}
		})
	}
	valid := string(memberOriginalJSON(t, memberOriginalConfigzFixture()))
	for name, raw := range map[string][]byte{
		"empty_object": []byte(`{}`), "missing_config": []byte(`{"other":{}}`), "null_outer": []byte(`null`), "array_outer": []byte(`[]`), "null_config": []byte(`{"kubeletconfig":null}`), "wrong_config_type": []byte(`{"kubeletconfig":[]}`),
		"duplicate_outer":     []byte(`{"kubeletconfig":{},"kubeletconfig":{}}`),
		"duplicate_selected":  []byte(strings.Replace(valid, `"port":10250`, `"port":10250,"port":10250`, 1)),
		"duplicate_extension": []byte(strings.Replace(valid, `"readOnlyPort":0`, `"extra":{"a":1,"a":2},"readOnlyPort":0`, 1)),
		"trailing_object":     []byte(valid + ` {}`), "truncated": []byte(valid[:len(valid)-1]),
		"bound": bytes.Repeat([]byte(" "), model.CapacityNativeWorkerMemberMaxOriginalBytes+1),
	} {
		t.Run(name, func(t *testing.T) {
			path, url, err := nativeMemberConfigzProjection(raw)
			if err != errNativeMember || path != "" || url != "" {
				t.Fatal("ambiguous private configz was accepted or leaked its parser diagnostic")
			}
		})
	}
}

func memberOriginalStatus(code int) map[string]any {
	reason := "Conflict"
	if code == 422 {
		reason = "Invalid"
	}
	if code == 429 {
		reason = "TooManyRequests"
	}
	return map[string]any{"apiVersion": "v1", "kind": "Status", "metadata": map[string]any{}, "status": "Failure", "message": "atomic JSON patch test rejected — configuração", "reason": reason, "details": map[string]any{"kind": "nodes", "name": "nw-original", "causes": []any{map[string]any{"reason": "FieldValueInvalid", "field": "metadata.resourceVersion"}}}, "code": code}
}

func memberOriginalCapture(code int, raw []byte) model.CapacityNativeWorkerMemberReceive {
	// Caller/context authentication and token custody are separate Store gates.
	// This fixture tests only classification of the already captured return.
	return model.CapacityNativeWorkerMemberReceive{Schema: model.CapacityNativeWorkerMemberReceiveSchema, BindingName: "fixed-member-write", HTTPStatus: code, OriginalReturn: raw, CaptureComplete: true, TransportCompleted: true}
}

func TestNativeMemberOriginalNoEffectOnlyAtomicCordonStatus(t *testing.T) {
	for _, code := range []int{409, 422} {
		status := memberOriginalStatus(code)
		o := memberOriginalCapture(code, memberOriginalJSON(t, status))
		if !nativeMemberDefinitiveNoEffect(model.CapacityNativeWorkerMemberContext{Action: "cordon"}, o) {
			t.Fatal("complete native atomic patch rejection stayed ambiguous", code)
		}
		for _, action := range []string{"evict_pod", "bind_pod", "delete_node", "retire_registry", "provider_destroy", "CORDON", ""} {
			if nativeMemberDefinitiveNoEffect(model.CapacityNativeWorkerMemberContext{Action: action}, o) {
				t.Fatal("non-atomic action released uncertainty from Status alone", action, code)
			}
		}
		delete(status, "details")
		if !nativeMemberDefinitiveNoEffect(model.CapacityNativeWorkerMemberContext{Action: "cordon"}, memberOriginalCapture(code, memberOriginalJSON(t, status))) {
			t.Fatal("legitimate absent Status details refused")
		}
		status["details"] = nil
		if !nativeMemberDefinitiveNoEffect(model.CapacityNativeWorkerMemberContext{Action: "cordon"}, memberOriginalCapture(code, memberOriginalJSON(t, status))) {
			t.Fatal("legitimate null Status details refused")
		}
	}
	if nativeMemberDefinitiveNoEffect(model.CapacityNativeWorkerMemberContext{Action: "evict_pod"}, memberOriginalCapture(429, memberOriginalJSON(t, memberOriginalStatus(429)))) {
		t.Fatal("PDB rejection was mistaken for definitive no effect")
	}
}

func TestNativeMemberOriginalNoEffectCaptureAndFramingStayUnknown(t *testing.T) {
	c := model.CapacityNativeWorkerMemberContext{Action: "cordon"}
	valid := memberOriginalJSON(t, memberOriginalStatus(409))
	for _, fault := range []string{"partial_capture", "unclosed_transport", "body_read", "body_close", "context_cancelled", "deadline", "HTTP_200", "HTTP_429", "HTTP_zero"} {
		t.Run(fault, func(t *testing.T) {
			o := memberOriginalCapture(409, valid)
			switch fault {
			case "partial_capture":
				o.CaptureComplete = false
			case "unclosed_transport":
				o.TransportCompleted = false
			case "body_read":
				o.ErrorClass = "body_read_failed"
			case "body_close":
				o.ErrorClass = "body_close_failed"
			case "context_cancelled":
				o.ErrorClass = "caller_context_cancelled"
			case "deadline":
				o.ErrorClass = "caller_deadline_exceeded"
			case "HTTP_200":
				o.HTTPStatus = 200
			case "HTTP_429":
				o.HTTPStatus = 429
			case "HTTP_zero":
				o.HTTPStatus = 0
			}
			if nativeMemberDefinitiveNoEffect(c, o) {
				t.Fatal("incomplete/private capture error released the one-send right")
			}
		})
	}
	for _, fault := range []string{"missing_metadata", "null_metadata", "array_metadata", "string_metadata", "wrong_api", "wrong_kind", "success", "wrong_reason", "wrong_code", "code_type", "invalid_details", "alias", "unknown_envelope"} {
		t.Run(fault, func(t *testing.T) {
			status := memberOriginalStatus(409)
			switch fault {
			case "missing_metadata":
				delete(status, "metadata")
			case "null_metadata":
				status["metadata"] = nil
			case "array_metadata":
				status["metadata"] = []any{}
			case "string_metadata":
				status["metadata"] = memberOriginalPrivateCanary
			case "wrong_api":
				status["apiVersion"] = "v2"
			case "wrong_kind":
				status["kind"] = "Node"
			case "success":
				status["status"] = "Success"
			case "wrong_reason":
				status["reason"] = "Invalid"
			case "wrong_code":
				status["code"] = 422
			case "code_type":
				status["code"] = "409"
			case "invalid_details":
				status["details"] = []any{}
			case "alias":
				status["Kind"] = status["kind"]
				delete(status, "kind")
			case "unknown_envelope":
				status["provider_error"] = memberOriginalPrivateCanary
			}
			if nativeMemberDefinitiveNoEffect(c, memberOriginalCapture(409, memberOriginalJSON(t, status))) {
				t.Fatal("non-native Status envelope became definitive no effect")
			}
		})
	}
	for name, raw := range map[string][]byte{
		"empty": nil, "empty_object": []byte(`{}`), "null": []byte(`null`),
		"trailing":           append(append([]byte(nil), valid...), []byte(` {}`)...),
		"truncated":          valid[:len(valid)-1],
		"duplicate_status":   []byte(strings.Replace(string(valid), `"status":"Failure"`, `"status":"Failure","status":"Failure"`, 1)),
		"duplicate_metadata": []byte(strings.Replace(string(valid), `"metadata":{}`, `"metadata":{"x":1,"x":2}`, 1)),
	} {
		t.Run(name, func(t *testing.T) {
			if nativeMemberDefinitiveNoEffect(c, memberOriginalCapture(409, raw)) {
				t.Fatal("ambiguous original framing released uncertainty")
			}
		})
	}
}
