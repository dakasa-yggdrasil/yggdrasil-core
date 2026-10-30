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

func TestHeldHelloFailureStageClosed(t *testing.T) {
	for _, tc := range []struct {
		name, nativeCase, stage string
		failed, retain          bool
	}{
		{"pending", "held_hello_original_deadline", "source_refusal_pending", true, true},
		{"lease", "held_hello_original_deadline", "source_refusal_validate", true, true},
		{"success", "held_hello_original_deadline", "witness", false, false},
		{"foreign_case", "held_probe_body_original_deadline", "witness", true, false},
		{"arbitrary_stage", "held_hello_original_deadline", "secret", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &fixture{private: t.TempDir()}
			f.request.NativeCase = tc.nativeCase
			var runErr error
			if tc.failed {
				runErr = errors.New("private original error")
			}
			original := runErr
			f.retainHeldHelloFailure(context.Background(), tc.stage, &runErr)
			if runErr != original {
				t.Fatal("original result changed")
			}
			path := filepath.Join(f.private, "core-held-hello-failure-stage.json")
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
			if _, err := q.ReadPrivate(context.Background(), path, &got); err != nil || got.Schema != "held_hello_failure_stage_v1" || got.Case != tc.nativeCase || got.Stage != tc.stage || got.Scope != "failure_only_observation_not_authority" {
				t.Fatal("closed failure observation missing")
			}
		})
	}
}
