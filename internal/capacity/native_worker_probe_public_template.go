package capacity

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"

	model "github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// This projection is shared by the private Source producer and SDK. It binds
// safe structure/identities without publishing a digest of key material, env
// literal values or the process challenge. It is not mutation authority and
// never replaces validation of the complete private object against its binding.
type nativeProbePublicTemplate struct {
	Schema     string `json:"schema"`
	Op         string `json:"op"`
	APIVersion string `json:"api_version"`
	Kind       string `json:"kind"`
	Namespace  string `json:"namespace"`
	Name       string `json:"name"`
	Object     any    `json:"object"`
}

func NativeWorkerProbePublicTemplateSHA(c model.NativeWorkerProbeResourceContext, raw []byte) (string, error) {
	if len(raw) == 0 || len(raw) > 256<<10 {
		return "", errNativeProbeResourceTemplate
	}
	var projection any
	if c.Op == "startup_patch" {
		var steps []struct {
			Op    string          `json:"op"`
			Path  string          `json:"path"`
			Value json.RawMessage `json:"value"`
		}
		if DecodeNativeProbeResourceJSON(raw, &steps) != nil || len(steps) != 3 || steps[0].Op != "test" || steps[0].Path != "/metadata/uid" || steps[1].Op != "test" || steps[1].Path != "/metadata/resourceVersion" || steps[2].Op != "add" || steps[2].Path != "/metadata/annotations/yggdrasil.io~1native-admission-v2" {
			return "", errNativeProbeResourceTemplate
		}
		steps[2].Value = json.RawMessage(`""`)
		projection = steps
	} else {
		var members map[string]json.RawMessage
		if DecodeNativeProbeResourceJSON(raw, &members) != nil {
			return "", errNativeProbeResourceTemplate
		}
		for key := range members {
			if key != "apiVersion" && key != "kind" && key != "metadata" && key != "spec" && key != "data" && key != "type" && key != "immutable" {
				return "", errNativeProbeResourceTemplate
			}
		}
		var object map[string]any
		d := json.NewDecoder(bytes.NewReader(raw))
		d.UseNumber()
		if d.Decode(&object) != nil || object == nil {
			return "", errNativeProbeResourceTemplate
		}
		metadata, ok := object["metadata"].(map[string]any)
		if !ok {
			return "", errNativeProbeResourceTemplate
		}
		for key := range metadata {
			if key != "name" && key != "namespace" && key != "labels" && key != "annotations" {
				return "", errNativeProbeResourceTemplate
			}
		}
		if annotations, ok := metadata["annotations"].(map[string]any); ok {
			for key := range annotations {
				if key == model.NativeWorkerProbeAdmissionAnnotation {
					annotations[key] = ""
				} else {
					delete(annotations, key)
				}
			}
		}
		if object["kind"] == "Secret" {
			data, ok := object["data"].(map[string]any)
			if !ok {
				return "", errNativeProbeResourceTemplate
			}
			for key, value := range data {
				if _, ok := value.(string); !ok {
					return "", errNativeProbeResourceTemplate
				}
				data[key] = ""
			}
		}
		if spec, ok := object["spec"].(map[string]any); ok {
			for _, field := range []string{"containers", "initContainers"} {
				containers, _ := spec[field].([]any)
				for _, value := range containers {
					container, ok := value.(map[string]any)
					if !ok {
						return "", errNativeProbeResourceTemplate
					}
					env, _ := container["env"].([]any)
					for _, value := range env {
						variable, ok := value.(map[string]any)
						if !ok {
							return "", errNativeProbeResourceTemplate
						}
						if _, exists := variable["value"]; exists {
							variable["value"] = ""
						}
					}
				}
			}
		}
		projection = object
	}
	wire, e := json.Marshal(nativeProbePublicTemplate{Schema: "native_worker_probe_public_template_v1", Op: c.Op, APIVersion: c.APIVersion, Kind: c.Kind, Namespace: c.Namespace, Name: c.Name, Object: projection})
	if e != nil {
		return "", errNativeProbeResourceTemplate
	}
	return nativeProbeTemplateHash(wire), nil
}

func NativeWorkerProbeResourceName(run, slot string) (api, kind, name string, ok bool) {
	if !marketUUID.MatchString(run) || strings.ReplaceAll(run, "-", "") == strings.Repeat("0", 32) {
		return "", "", "", false
	}
	suffix := ""
	switch slot {
	case "floor_pod":
		api, kind, suffix = "v1", "Pod", "fp"
	case "candidate_pod", "startup_challenge":
		api, kind, suffix = "v1", "Pod", "cp"
	case "floor_service":
		api, kind, suffix = "v1", "Service", "fs"
	case "candidate_service":
		api, kind, suffix = "v1", "Service", "cs"
	case "admission_secret":
		api, kind, suffix = "v1", "Secret", "as"
	case "floor_secret":
		api, kind, suffix = "v1", "Secret", "fc"
	case "candidate_secret":
		api, kind, suffix = "v1", "Secret", "cc"
	case "network_policy":
		api, kind, suffix = "networking.k8s.io/v1", "NetworkPolicy", "np"
	default:
		return "", "", "", false
	}
	return api, kind, "nwp-" + strings.ReplaceAll(run, "-", "")[:20] + "-" + suffix, true
}

func nativeProbeTemplateHash(raw []byte) string {
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}
