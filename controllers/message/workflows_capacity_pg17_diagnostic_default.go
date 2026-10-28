//go:build !linux || !nativequalification

package message

import (
	"context"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func nativeQualificationFailure(*model.WorkflowRunStepResult, string) {}
func guestPG17ConfirmFailurePredicate(error) string                   { return "pg17-original-workflow-confirm" }

func guestInstallationFailureState(error) string { return "confirmation_read_error" }

func guestPG17ReadClientDiagnostic(_ context.Context, _, _, _ string) {}

func guestPG17ReadDiagnosticContext(ctx context.Context, _, _ string) context.Context { return ctx }
func guestPG17TransportStage(_ context.Context, _ string)                             {}
