//go:build linux && nativequalification

package main

import (
	"context"
	"path/filepath"
	"time"

	q "github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacitynativeqemu"
)

// Failure-only qualification observation. It grants no authority and never
// replaces the original error; an absent file is UNKNOWN.
func (f *fixture) retainCanonicalChildFailure(ctx context.Context, stage string, runErr *error) {
	if runErr == nil || *runErr == nil {
		return
	}
	switch f.request.NativeCase {
	case "canonical_compensation_unprotected_failed_create", "canonical_compensation_protected_failed_create":
	default:
		return
	}
	switch stage {
	case "begin", "prepare_child", "eligibility", "unresolved_parent", "issue_children", "foreign_issue", "unredeemed_check", "unresolved_child", "redeem_child", "redeemed_checks", "read_eligibility", "publish_eligibility", "publish_child_authority", "publish_cleanup_authority", "after_cleanup_authority":
	default:
		return
	}
	diagnostic, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	_, _ = q.Publish(diagnostic, filepath.Join(f.private, "core-canonical-child-failure-stage.json"), struct {
		Schema string `json:"schema"`
		Case   string `json:"case"`
		Stage  string `json:"stage"`
		Scope  string `json:"scope"`
	}{"canonical_child_failure_stage_v1", f.request.NativeCase, stage, "failure_only_observation_not_authority"})
}
