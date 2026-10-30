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

	for _, tc := range []struct {
		nativeCase, stage string
		err               error
		want              bool
	}{
		{"source_contract_unresolved_expiry", "contract_read_and_identity", q.ErrOriginalUnknown, true},
		{"source_contract_unredeemed_expiry_recovery", "grant_state", q.ErrOriginalUnknown, true},
		{"source_contract_unresolved_expiry", "grant_state", nil, false},
		{"positive_original_lifecycle", "grant_state", q.ErrOriginalUnknown, false},
		{"source_contract_unresolved_expiry", "secret arbitrary input", q.ErrOriginalUnknown, false},
	} {
		f := &fixture{private: t.TempDir()}
		f.request.NativeCase = tc.nativeCase
		f.retainRecoveryGuardFailure(context.Background(), tc.err, tc.stage)
		path := filepath.Join(f.private, "core-source-recovery-guard-diagnostic.json")
		if !tc.want {
			if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("unexpected failure projection")
			}
			continue
		}
		var got struct {
			Schema string `json:"schema"`
			Case   string `json:"case"`
			Stage  string `json:"stage"`
			Scope  string `json:"scope"`
		}
		if _, err := q.ReadPrivate(context.Background(), path, &got); err != nil || got.Schema != "core_source_recovery_guard_diagnostic_v1" || got.Case != tc.nativeCase || got.Stage != tc.stage || got.Scope != "failure_observation_only_not_authority" {
			t.Fatal("incorrect failure-only guard projection")
		}
	}
}
