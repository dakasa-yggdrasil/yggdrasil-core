//go:build linux && nativequalification

package message

import (
	"context"
	"path/filepath"

	q "github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacitynativeqemu"
)

// Failure-only historical observation; it never changes the original result,
// creates authority or asserts that an unobserved stage was not reached.
func retainPG17TerminalGuardFailure(ctx context.Context, runErr error, stage string) {
	if runErr == nil || originalGuestNativeRealm == nil || ctx.Err() != nil {
		return
	}
	selected := originalGuestNativeRealm.Request.NativeCase
	if selected != "source_live_unredeemed_abort" && selected != "source_live_unresolved_terminal" {
		return
	}
	switch stage {
	case "entry", "contract_read", "contract_join", "grant_read", "intent_read", "intent_join", "physical_read", "physical_join", "abort_state", "abort_contract_read", "abort_contract_join", "unresolved_state", "unresolved_replay_read", "unresolved_replay_join", "unresolved_contract_read", "unresolved_contract_join", "retention":
	default:
		return
	}
	_, _ = q.Publish(ctx, filepath.Join(originalGuestNativeRealm.PrivateDirectory, "pg17-source-terminal-guard-diagnostic.json"), struct {
		Schema         string `json:"schema"`
		Case           string `json:"case"`
		Stage          string `json:"stage"`
		Classification string `json:"classification"`
		Scope          string `json:"scope"`
	}{"core_pg17_source_terminal_guard_diagnostic_v1", selected, stage, "UNKNOWN_FAILURE_NOT_AUTHORITY", "failure_observation_only_not_authority"})
}
