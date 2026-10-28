//go:build !linux || !nativequalification

package message

import (
	"errors"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"testing"
)

func TestNativeQualificationDiagnosticAbsent(t *testing.T) {
	var r model.WorkflowRunStepResult
	nativeQualificationFailure(&r, "native-01")
	if r.Metadata != nil {
		t.Fatal("production result changed")
	}
	if guestPG17ConfirmFailurePredicate(errors.New("secret")) != "pg17-original-workflow-confirm" {
		t.Fatal("production failure changed")
	}
}
