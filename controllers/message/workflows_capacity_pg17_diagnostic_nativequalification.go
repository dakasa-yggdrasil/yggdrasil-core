//go:build linux && nativequalification

package message

import (
	"context"
	"database/sql"
	"errors"

	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/lib/pq"
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
	if errors.As(err, &stage) && regexp.MustCompile(`^(?:check-0[1-6]|proof-join|guest-slot-one|guest-conflict|native-(?:0[1-9]|[12][0-9]|3[01]))$`).MatchString(string(stage)) {
		return "pg17-confirm-" + string(stage)
	}
	return "pg17-original-workflow-confirm"
}

type pg17ReadDiagnosticContextKey struct{}

func guestPG17ReadDiagnosticContext(ctx context.Context, workflowOperation, capability string) context.Context {
	if originalGuestNativeRealm == nil || workflowOperation != "capacity.confirm_native_mutation" || (capability != "observe_servers" && capability != "observe_server_action") {
		return ctx
	}
	return context.WithValue(ctx, pg17ReadDiagnosticContextKey{}, true)
}
func guestPG17TransportStage(ctx context.Context, stage string) {
	if ctx != nil && ctx.Value(pg17ReadDiagnosticContextKey{}) == true && originalGuestNativeRealm != nil {
		_ = originalGuestNativeRealm.RecordPG17ReadDiagnostic(ctx, "client", stage)
	}
}

// Diagnostics are best-effort, emitted only in the isolated positive fixture.
func guestPG17ReadClientDiagnostic(ctx context.Context, workflowOperation, capability, stage string) {
	if originalGuestNativeRealm == nil || workflowOperation != "capacity.confirm_native_mutation" || (capability != "observe_servers" && capability != "observe_server_action") {
		return
	}
	_ = originalGuestNativeRealm.RecordPG17ReadDiagnostic(ctx, "client", stage)
}

// Diagnostic states are fixed vocabulary and never expose database errors.
func guestInstallationFailureState(err error) string {
	switch {
	case errors.Is(err, repository.ErrCapacityLease):
		return "confirmation_lease_invalid"
	case errors.Is(err, repository.ErrCapacityDisabled):
		return "confirmation_disabled"
	case errors.Is(err, context.Canceled):
		return "confirmation_context_cancelled"
	case errors.Is(err, context.DeadlineExceeded):
		return "confirmation_context_deadline"
	case errors.Is(err, sql.ErrTxDone):
		return "confirmation_transaction_closed"
	}
	var pg *pq.Error
	if errors.As(err, &pg) {
		switch string(pg.Code) {
		case "40P01":
			return "confirmation_sql_deadlock"
		case "40001":
			return "confirmation_sql_serialization"
		case "57014":
			return "confirmation_sql_cancelled"
		default:
			return "confirmation_sql_other"
		}
	}
	return "confirmation_read_error"
}
