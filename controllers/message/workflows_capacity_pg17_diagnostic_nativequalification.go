//go:build linux && nativequalification

package message

import (
	"errors"
	"regexp"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// These fixed predicates contain no request fields and are emitted only by the
// native qualification binary. Production errors retain their generic form.
type pg17Diagnostic string

func (d pg17Diagnostic) Error() string      { return "native qualification assertion failed" }
func pg17ConfirmFailure(stage string) error { return pg17Diagnostic(stage) }
func nativeQualificationFailure(result *model.WorkflowRunStepResult, stage string) {
	if result.Metadata == nil {
		result.Metadata = map[string]any{}
	}
	result.Metadata["qualification_native_failure"] = stage
}
func pg17NativeResultFailure(result model.WorkflowRunStepResult) error {
	if stage, ok := result.Metadata["qualification_native_failure"].(string); ok && regexp.MustCompile(`^native-(?:0[1-9]|[12][0-9]|3[01])$`).MatchString(stage) {
		return pg17ConfirmFailure(stage)
	}
	return pg17ConfirmFailure("check-03")
}
func guestPG17ConfirmFailurePredicate(err error) string {
	var stage pg17Diagnostic
	if errors.As(err, &stage) && regexp.MustCompile(`^(?:check-0[1-6]|native-(?:0[1-9]|[12][0-9]|3[01]))$`).MatchString(string(stage)) {
		return "pg17-confirm-" + string(stage)
	}
	return "pg17-original-workflow-confirm"
}
