package message

import (
	"strconv"
	"strings"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

const redactedWorkflowOutputValue = "[REDACTED]"

// redactSensitiveWorkflowStepResult removes adapter-declared one-time secrets
// from every durable or externally returned workflow representation while the
// original result remains available in the in-memory execution context for a
// following secret-store step.
//
// Adapters declare paths relative to metadata.output using
// metadata.sensitive_output_paths. Paths may be dot-delimited or JSON Pointer
// strings. If the declaration is malformed or a path cannot be resolved, the
// entire output is redacted fail-closed.
func redactSensitiveWorkflowStepResult(result model.WorkflowRunStepResult) model.WorkflowRunStepResult {
	paths, declared := workflowSensitiveOutputPaths(result.Metadata)
	if !declared {
		return result
	}

	metadata := cloneWorkflowResultMap(result.Metadata)
	output, hasOutput := metadata["output"]
	if !hasOutput || len(paths) == 0 {
		metadata["output"] = redactedWorkflowOutputValue
		metadata["sensitive_output_redacted"] = true
		metadata["sensitive_output_redaction_scope"] = "output"
		result.Metadata = metadata
		return result
	}

	for _, path := range paths {
		var ok bool
		output, ok = redactWorkflowOutputPath(output, path)
		if !ok {
			metadata["output"] = redactedWorkflowOutputValue
			metadata["sensitive_output_redacted"] = true
			metadata["sensitive_output_redaction_scope"] = "output"
			result.Metadata = metadata
			return result
		}
	}

	metadata["output"] = output
	metadata["sensitive_output_redacted"] = true
	metadata["sensitive_output_redaction_scope"] = "paths"
	result.Metadata = metadata
	return result
}

func workflowSensitiveOutputPaths(metadata map[string]any) ([]string, bool) {
	if metadata == nil {
		return nil, false
	}
	raw, declared := metadata["sensitive_output_paths"]
	if !declared {
		return nil, false
	}

	switch value := raw.(type) {
	case string:
		path := strings.TrimSpace(value)
		if path == "" {
			return nil, true
		}
		return []string{path}, true
	case []string:
		paths := make([]string, 0, len(value))
		for _, path := range value {
			path = strings.TrimSpace(path)
			if path == "" {
				return nil, true
			}
			paths = append(paths, path)
		}
		return paths, true
	case []any:
		paths := make([]string, 0, len(value))
		for _, item := range value {
			path, ok := item.(string)
			if !ok || strings.TrimSpace(path) == "" {
				return nil, true
			}
			paths = append(paths, strings.TrimSpace(path))
		}
		return paths, true
	default:
		return nil, true
	}
}

func redactWorkflowOutputPath(output any, rawPath string) (any, bool) {
	segments, ok := workflowOutputPathSegments(rawPath)
	if !ok || len(segments) == 0 {
		return nil, false
	}
	return redactWorkflowOutputSegments(output, segments)
}

func workflowOutputPathSegments(rawPath string) ([]string, bool) {
	path := strings.TrimSpace(rawPath)
	if path == "" {
		return nil, false
	}
	if strings.HasPrefix(path, "/") {
		rawSegments := strings.Split(strings.TrimPrefix(path, "/"), "/")
		segments := make([]string, 0, len(rawSegments))
		for _, rawSegment := range rawSegments {
			segment, ok := decodeWorkflowJSONPointerSegment(rawSegment)
			if !ok || segment == "" {
				return nil, false
			}
			segments = append(segments, segment)
		}
		return segments, true
	}

	path = strings.TrimPrefix(path, "output.")
	segments := strings.Split(path, ".")
	for _, segment := range segments {
		if strings.TrimSpace(segment) == "" {
			return nil, false
		}
	}
	return segments, true
}

// decodeWorkflowJSONPointerSegment implements RFC 6901 escaping and rejects
// any bare or unknown '~' sequence. Treating malformed pointers as literal map
// keys could make an adapter believe a secret was covered while the core and
// adapter disagree about which field the declaration identifies.
func decodeWorkflowJSONPointerSegment(segment string) (string, bool) {
	var decoded strings.Builder
	decoded.Grow(len(segment))
	for index := 0; index < len(segment); index++ {
		if segment[index] != '~' {
			decoded.WriteByte(segment[index])
			continue
		}
		if index+1 >= len(segment) {
			return "", false
		}
		index++
		switch segment[index] {
		case '0':
			decoded.WriteByte('~')
		case '1':
			decoded.WriteByte('/')
		default:
			return "", false
		}
	}
	return decoded.String(), true
}

func redactWorkflowOutputSegments(current any, segments []string) (any, bool) {
	if len(segments) == 0 {
		return redactedWorkflowOutputValue, true
	}

	switch value := current.(type) {
	case map[string]any:
		child, exists := value[segments[0]]
		if !exists {
			return current, false
		}
		redactedChild, ok := redactWorkflowOutputSegments(child, segments[1:])
		if !ok {
			return current, false
		}
		value[segments[0]] = redactedChild
		return value, true
	case []any:
		index, err := strconv.Atoi(segments[0])
		if err != nil || index < 0 || index >= len(value) {
			return current, false
		}
		redactedChild, ok := redactWorkflowOutputSegments(value[index], segments[1:])
		if !ok {
			return current, false
		}
		value[index] = redactedChild
		return value, true
	default:
		return current, false
	}
}

func cloneWorkflowResultMap(value map[string]any) map[string]any {
	if value == nil {
		return nil
	}
	cloned := make(map[string]any, len(value))
	for key, item := range value {
		cloned[key] = cloneWorkflowResultValue(item)
	}
	return cloned
}

func cloneWorkflowResultValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		return cloneWorkflowResultMap(typed)
	case []any:
		cloned := make([]any, len(typed))
		for index, item := range typed {
			cloned[index] = cloneWorkflowResultValue(item)
		}
		return cloned
	case []string:
		return append([]string(nil), typed...)
	default:
		return value
	}
}
