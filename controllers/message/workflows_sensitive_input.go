package message

import "github.com/dakasa-yggdrasil/yggdrasil-core/model"

const redactedWorkflowInputValue = "[REDACTED]"

// redactSensitiveWorkflowInputs creates the representation safe to persist in
// workflow_runs.inputs. The execution request remains untouched so templates
// can consume the original value during the current process lifetime.
//
// Secret marks values that are credentials; Sensitive marks values that must
// be concealed from operators even when they are not credentials. Either
// classification is sufficient to exclude the value from durable evidence.
func redactSensitiveWorkflowInputs(spec model.WorkflowManifestSpec, inputs map[string]any) map[string]any {
	redacted := cloneWorkflowResultMap(inputs)
	for name, property := range spec.InputSchema.Properties {
		if !property.Secret && !property.Sensitive {
			continue
		}
		if _, exists := redacted[name]; exists {
			redacted[name] = redactedWorkflowInputValue
		}
	}
	return redacted
}
