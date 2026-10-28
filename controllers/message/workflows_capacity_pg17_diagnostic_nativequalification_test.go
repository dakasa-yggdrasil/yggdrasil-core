//go:build linux && nativequalification

package message

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/lib/pq"
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
		{pg17ConfirmFailure("proof-join"), "pg17-confirm-proof-join"},
		{pg17ConfirmFailure("guest-slot-one"), "pg17-confirm-guest-slot-one"},
		{pg17ConfirmFailure("guest-conflict"), "pg17-confirm-guest-conflict"},
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

func TestQualificationInstallationReadErrorClasses(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want string
	}{
		{fmt.Errorf("wrapped: %w", repository.ErrCapacityLease), "confirmation_lease_invalid"},
		{repository.ErrCapacityDisabled, "confirmation_disabled"}, {context.Canceled, "confirmation_context_cancelled"}, {context.DeadlineExceeded, "confirmation_context_deadline"}, {sql.ErrTxDone, "confirmation_transaction_closed"},
		{&pq.Error{Code: "40P01", Message: "private"}, "confirmation_sql_deadlock"}, {&pq.Error{Code: "40001", Message: "private"}, "confirmation_sql_serialization"}, {&pq.Error{Code: "57014", Message: "private"}, "confirmation_sql_cancelled"}, {&pq.Error{Code: "XXXXX", Message: "private"}, "confirmation_sql_other"}, {errors.New("private"), "confirmation_read_error"},
	} {
		if got := guestInstallationFailureState(tc.err); got != tc.want {
			t.Fatalf("got %q want %q", got, tc.want)
		}
	}
}
