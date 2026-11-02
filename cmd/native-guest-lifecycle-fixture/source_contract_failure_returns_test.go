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

func TestSourceContractFailureRetainsPublicReturns(t *testing.T) {
	for _, tc := range []struct {
		name string
		call func(*fixture, context.Context) error
	}{
		{"fence", (*fixture).runOriginalSourceFenceCaller},
		{"recovery", (*fixture).runOriginalRecoveryContractCaller},
		{"terminal", (*fixture).runOriginalTerminalCaller},
		{"live_partial", (*fixture).runOriginalLivePartialCaller},
		{"historical_confirm", (*fixture).runOriginalHistoricalConfirmCaller},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &fixture{private: t.TempDir(), publicReturns: []originalPublicReturn{{Method: "POST", Path: "/api/v1/workflow-runs", WorkflowStatus: "failed"}}}
			f.request.NativeCase = "positive_original_lifecycle"
			err := tc.call(f, context.Background())
			if !errors.Is(err, q.ErrOriginalUnknown) {
				t.Fatalf("original refusal changed: %v", err)
			}
			var returns []originalPublicReturn
			_, err = q.ReadPrivate(context.Background(), filepath.Join(f.private, "core-original-public-caller-failure-returns.json"), &returns)
			if err != nil || len(returns) != 1 || returns[0].Method != "POST" || returns[0].WorkflowStatus != "failed" {
				t.Fatalf("original public return projection not retained: %v", err)
			}
		})
	}
	t.Run("success_does_not_publish", func(t *testing.T) {
		f := &fixture{private: t.TempDir()}
		var runErr error
		f.retainSourceCallerFailure(context.Background(), &runErr)
		if runErr != nil {
			t.Fatalf("success changed: %v", runErr)
		}
		if _, err := os.Lstat(filepath.Join(f.private, "core-original-public-caller-failure-returns.json")); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("success published failure evidence: %v", err)
		}
	})
	t.Run("publication_error_preserves_original", func(t *testing.T) {
		f := &fixture{private: filepath.Join(t.TempDir(), "missing")}
		runErr := q.ErrOriginalUnknown
		f.retainSourceCallerFailure(context.Background(), &runErr)
		if runErr != q.ErrOriginalUnknown {
			t.Fatalf("original error changed after failed diagnostic publication: %v", runErr)
		}
	})
}
