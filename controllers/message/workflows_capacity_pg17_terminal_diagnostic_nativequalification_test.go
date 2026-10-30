//go:build linux && nativequalification

package message

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	q "github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacitynativeqemu"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

func TestPG17TerminalGuardDiagnostic(t *testing.T) {
	previous := originalGuestNativeRealm
	t.Cleanup(func() { originalGuestNativeRealm = previous })
	for _, mode := range []string{"entry", "contract_read", "unresolved", "retention", "other_case", "success", "unknown_stage", "canceled", "publish_failure"} {
		t.Run(mode, func(t *testing.T) {
			directory := t.TempDir()
			nativeCase := "source_live_unredeemed_abort"
			if mode == "unresolved" {
				nativeCase = "source_live_unresolved_terminal"
			}
			if mode == "other_case" {
				nativeCase = "positive_original_lifecycle"
			}
			if mode == "publish_failure" {
				directory = filepath.Join(directory, "missing")
			}
			originalGuestNativeRealm = &q.Realm{PrivateDirectory: directory, Request: q.SourceRequest{NativeCase: nativeCase}}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "canceled" {
				cancel()
			}
			stage := "entry"
			var originalErr error
			switch mode {
			case "entry", "unresolved", "other_case":
				_, originalErr = guestPG17MutationAfterTerminal(ctx, repository.CapacityStore{}, model.Manifest{}, model.CapacityPolicySpec{}, model.CapacityMutationBinding{}, guestOriginalStepInput{}, model.CapacityMutationGrant{}, model.CapacityGuestOriginalProvisioningPreregistration{}, nil)
				if !errors.Is(originalErr, errOriginalGuestStep) {
					t.Fatal("original invalid-contract refusal changed")
				}
			case "contract_read":
				stage = "contract_read"
				_, originalErr = guestPG17MutationAfterTerminal(ctx, repository.CapacityStore{}, model.Manifest{}, model.CapacityPolicySpec{}, model.CapacityMutationBinding{}, guestOriginalStepInput{}, model.CapacityMutationGrant{}, model.CapacityGuestOriginalProvisioningPreregistration{}, q.SourceTerminalContract{})
				if originalErr == nil {
					t.Fatal("missing original contract was accepted")
				}
			case "retention", "unknown_stage", "canceled", "publish_failure":
				stage = "retention"
				if mode == "unknown_stage" {
					stage = "private untrusted input"
				}
				originalErr = errOriginalGuestStep
				retainPG17TerminalGuardFailure(ctx, originalErr, stage)
				if originalErr != errOriginalGuestStep {
					t.Fatal("diagnostic changed the original error")
				}
			case "success":
				retainPG17TerminalGuardFailure(ctx, nil, "entry")
			}
			path := filepath.Join(directory, "pg17-source-terminal-guard-diagnostic.json")
			if mode == "other_case" || mode == "success" || mode == "unknown_stage" || mode == "canceled" || mode == "publish_failure" {
				if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("unexpected failure diagnostic")
				}
				return
			}
			var fact struct {
				Schema         string `json:"schema"`
				Case           string `json:"case"`
				Stage          string `json:"stage"`
				Classification string `json:"classification"`
				Scope          string `json:"scope"`
			}
			if _, err := q.ReadPrivate(context.Background(), path, &fact); err != nil || fact.Schema != "core_pg17_source_terminal_guard_diagnostic_v1" || fact.Case != nativeCase || fact.Stage != stage || fact.Classification != "UNKNOWN_FAILURE_NOT_AUTHORITY" || fact.Scope != "failure_observation_only_not_authority" {
				t.Fatal("incorrect closed failure diagnostic")
			}
		})
	}
}
