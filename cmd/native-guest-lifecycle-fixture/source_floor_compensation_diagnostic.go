//go:build linux && nativequalification

package main

import (
	"context"
	"path/filepath"
	"time"

	q "github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacitynativeqemu"
)

// A failure-only closed observation. Absence is UNKNOWN, never authority.
func (f *fixture) retainSourceFloorCompensationFailure(ctx context.Context, stage string, runErr *error) {
	if runErr == nil || *runErr == nil || f.request.NativeCase != "source_live_failed_floor_recovery" {
		return
	}
	switch stage {
	case "begin", "preregistration", "witness", "source_client", "source_refusal", "source_refusal_pending", "source_refusal_transport", "source_refusal_status", "source_refusal_validate", "source_refusal_record", "source_refusal_publish", "enrollment", "baseline_client", "baseline_probe", "prepare_cleanup", "prepare_input", "prepare_native", "prepare_receipt", "prepare_outcome", "prepare_members", "prepare_events", "prepare_policy", "prepare_lease", "prepare_intent", "prepare_deadline", "prepare_directory", "prepare_host_identity", "prepare_encoding", "cleanup_tables", "authority_encode", "authority_insert", "authority_readback", "cleanup_lease", "authority_publish", "after_authority":
	default:
		return
	}
	diagnostic, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	_, _ = q.Publish(diagnostic, filepath.Join(f.private, "core-source-floor-compensation-failure-stage.json"), struct {
		Schema string `json:"schema"`
		Case   string `json:"case"`
		Stage  string `json:"stage"`
		Scope  string `json:"scope"`
	}{"source_floor_compensation_failure_stage_v1", f.request.NativeCase, stage, "failure_only_observation_not_authority"})
}
