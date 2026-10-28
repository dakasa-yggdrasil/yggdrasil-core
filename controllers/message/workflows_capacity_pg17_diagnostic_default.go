//go:build !linux || !nativequalification

package message

import "github.com/dakasa-yggdrasil/yggdrasil-core/model"

func nativeQualificationFailure(*model.WorkflowRunStepResult, string) {}
func guestPG17ConfirmFailurePredicate(error) string                   { return "pg17-original-workflow-confirm" }

func guestInstallationFailureState(error) string { return "confirmation_read_error" }
