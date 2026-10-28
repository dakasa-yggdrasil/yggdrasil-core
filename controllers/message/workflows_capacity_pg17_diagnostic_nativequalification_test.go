//go:build linux && nativequalification

package message

import (
	"errors"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func TestPG17DiagnosticClosedPredicates(t *testing.T) {
	var r model.WorkflowRunStepResult
	nativeQualificationFailure(&r, "native-12")
	for _, tc := range []struct {
		err  error
		want string
	}{
		{pg17NativeResultFailure(r), "pg17-confirm-native-12"},
		{pg17ConfirmFailure("check-02"), "pg17-confirm-check-02"},
		{pg17ConfirmFailure("native-12\nsecret"), "pg17-original-workflow-confirm"},
		{errors.New("secret"), "pg17-original-workflow-confirm"},
	} {
		if got := guestPG17ConfirmFailurePredicate(tc.err); got != tc.want {
			t.Errorf("got %q want %q", got, tc.want)
		}
	}
	r.Metadata["qualification_native_failure"] = "secret"
	if got := guestPG17ConfirmFailurePredicate(pg17NativeResultFailure(r)); got != "pg17-confirm-check-03" {
		t.Fatal(got)
	}
}
