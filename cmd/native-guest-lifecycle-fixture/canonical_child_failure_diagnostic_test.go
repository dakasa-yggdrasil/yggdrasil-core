//go:build linux && nativequalification

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	q "github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacitynativeqemu"
)

func TestCanonicalChildFailureStageClosed(t *testing.T) {
	for _, tc := range []struct {
		name, nativeCase, stage string
		failed, retain          bool
	}{
		{"original_failure", "canonical_compensation_unprotected_failed_create", "unresolved_parent", true, true},
		{"protected_failure", "canonical_compensation_protected_failed_create", "redeem_child", true, true},
		{"success", "canonical_compensation_unprotected_failed_create", "unresolved_parent", false, false},
		{"foreign_case", "canonical_failed_floor_recovery", "unresolved_parent", true, false},
		{"arbitrary_stage", "canonical_compensation_unprotected_failed_create", "secret", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &fixture{private: t.TempDir()}
			f.request.NativeCase = tc.nativeCase
			var runErr error
			if tc.failed {
				runErr = errors.New("original private error")
			}
			original := runErr
			f.retainCanonicalChildFailure(context.Background(), tc.stage, &runErr)
			if runErr != original {
				t.Fatal("original result changed")
			}
			path := filepath.Join(f.private, "core-canonical-child-failure-stage.json")
			if !tc.retain {
				if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("unexpected diagnostic")
				}
				return
			}
			var got struct {
				Schema string `json:"schema"`
				Case   string `json:"case"`
				Stage  string `json:"stage"`
				Scope  string `json:"scope"`
			}
			if _, err := q.ReadPrivate(context.Background(), path, &got); err != nil || got.Schema != "canonical_child_failure_stage_v1" || got.Case != tc.nativeCase || got.Stage != tc.stage || got.Scope != "failure_only_observation_not_authority" {
				t.Fatal("closed failure observation missing")
			}
			f.retainCanonicalChildFailure(context.Background(), "issue_children", &runErr)
			var retained struct {
				Schema string `json:"schema"`
				Case   string `json:"case"`
				Stage  string `json:"stage"`
				Scope  string `json:"scope"`
			}
			if _, err := q.ReadPrivate(context.Background(), path, &retained); err != nil || retained.Stage != tc.stage || runErr != original {
				t.Fatal("earlier observation replaced or original error changed")
			}
		})
	}
}
