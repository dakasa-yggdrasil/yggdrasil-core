//go:build linux && nativequalification

package main

import (
	"context"
	"path/filepath"
	"time"

	q "github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacitynativeqemu"
)

// An original failed observation, not proof of authorization or absence.
func (f *fixture) retainHeldHelloFailure(ctx context.Context, stage string, runErr *error) {
	if runErr == nil || *runErr == nil || f.request.NativeCase != "held_hello_original_deadline" {
		return
	}
	switch stage {
	case "begin", "preregistration", "witness", "source_client", "source_refusal", "source_refusal_pending", "source_refusal_transport", "source_refusal_status", "source_refusal_validate", "source_refusal_decode", "source_refusal_identity", "source_refusal_signature", "source_refusal_owners", "source_refusal_probe", "source_refusal_journal", "source_refusal_case", "source_refusal_census", "source_refusal_record", "source_refusal_publish", "fresh_native", "creator_hash", "native_publish", "native_preregistration", "native_record", "baseline_client", "baseline_probe", "retirement_count", "destroy_count", "corpus", "corpus_publish":
	default:
		return
	}
	diagnostic, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	_, _ = q.Publish(diagnostic, filepath.Join(f.private, "core-held-hello-failure-stage.json"), struct {
		Schema string `json:"schema"`
		Case   string `json:"case"`
		Stage  string `json:"stage"`
		Scope  string `json:"scope"`
	}{"held_hello_failure_stage_v1", f.request.NativeCase, stage, "failure_only_observation_not_authority"})
}
