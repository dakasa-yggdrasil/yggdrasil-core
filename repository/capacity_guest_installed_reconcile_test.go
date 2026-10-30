package repository

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

func TestInstalledGuestResumeDoesNotAdoptLiveOrAlreadyResumedEpoch(t *testing.T) {
	t.Run("failed_installed_disposal_boundaries", testFailedInstalledDisposalBoundaries)
	if os.Getenv("D12_LOCAL_PG17_DSN") != "" || os.Getenv("D12_SOURCE_CI_PG17_DSN") != "" {
		t.Run("failed_installed_disposal_PG78", testFailedInstalledDisposalPostgres)
	}
	now := time.Now().UTC()
	expired := now.Add(-time.Second)
	policy := model.Manifest{ID: uuid.New(), Checksum: "old-policy"}
	p := model.CapacityPolicySpec{Floor: 1, Ceiling: 8}
	base := model.CapacityIntent{PolicyID: policy.ID, PolicyChecksum: policy.Checksum, Generation: 6, FencingToken: 11, Phase: "preparing", LeaseExpiresAt: &expired, Decision: model.CapacityDecision{Units: 1}}
	for _, name := range []string{"expired_installed_candidate", "live", "no_lease_history", "already_resumed", "wrong_policy", "wrong_checksum", "recovery_only", "degraded", "promoted", "zero_generation", "zero_fence", "overflow_fence"} {
		t.Run(name, func(t *testing.T) {
			old := base
			switch name {
			case "live":
				at := now.Add(time.Second)
				old.LeaseExpiresAt = &at
			case "no_lease_history":
				old.LeaseExpiresAt = nil
			case "already_resumed":
				old.InstalledGuestReconcile = &model.CapacityInstalledGuestReconcile{}
			case "wrong_policy":
				old.PolicyID = uuid.New()
			case "wrong_checksum":
				old.PolicyChecksum = "different"
			case "recovery_only":
				old.RecoveryOnly = true
			case "degraded":
				old.FloorDegraded = true
			case "promoted":
				old.Phase = "promoted"
			case "zero_generation":
				old.Generation = 0
			case "zero_fence":
				old.FencingToken = 0
			case "overflow_fence":
				old.FencingToken = maxCapacityGeneration
			}
			if installedGuestResumeCandidate(&old, p, policy, now) != (name == "expired_installed_candidate") {
				t.Fatal("live, foreign, repeated or invalid original became eligible")
			}
		})
	}
}

func TestInstalledGuestPreviousHeldPublicationRemainsHeldAndUnknownRemainsUnknown(t *testing.T) {
	now := time.Now().UTC()
	old := model.CapacityIntent{Generation: 6, FencingToken: 11}
	policy := model.Manifest{ID: uuid.New()}
	for _, name := range []string{"closed_held409", "unknown_original", "no_send", "unexpired", "incomplete_return"} {
		t.Run(name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			mock.ExpectBegin()
			tx, _ := db.Begin()
			deadline := now.Add(-time.Minute)
			send := true
			outcome := "held"
			var transport []byte
			if name == "closed_held409" || name == "incomplete_return" {
				r := capacity.GuestOriginalHTTPReturn{Status: 409, ResponseBodyScope: capacity.GuestOriginalBodyCompleteRead, CloseReturnedAt: now.Add(-2 * time.Minute), DriverReturnedAt: now.Add(-2 * time.Minute)}
				if name == "incomplete_return" {
					r.ReadFailed = true
				}
				transport, _ = json.Marshal(r)
			}
			if name == "unknown_original" {
				outcome = ""
			}
			if name == "no_send" {
				send = false
				outcome = ""
			}
			if name == "unexpired" {
				deadline = now.Add(time.Second)
			}
			mock.ExpectQuery("SELECT c.id::text,c.phase").WithArgs(policy.ID, old.Generation, old.FencingToken).WillReturnRows(sqlmock.NewRows([]string{"id", "phase", "deadline", "send", "outcome", "transport", "return_sha"}).AddRow(uuid.NewString(), "publish", deadline, send, outcome, transport, ""))
			rows, got := previousInstalledCanariesTx(context.Background(), tx, policy, old, now)
			if name == "unexpired" || name == "incomplete_return" {
				if got == nil {
					t.Fatal("live/incomplete old operation admitted")
				}
			} else {
				if got != nil || len(rows) != 1 {
					t.Fatal(got)
				}
				if name == "closed_held409" && (rows[0].Outcome != "held" || rows[0].ClosedHTTPStatus != 409 || !rows[0].PossibleSend) {
					t.Fatal("held409 rewritten")
				}
				if name != "closed_held409" && rows[0].Outcome != "unknown" {
					t.Fatal("unknown original relabeled as success/no effect")
				}
			}
			mock.ExpectRollback()
			_ = tx.Rollback()
			if err = mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestInstalledGuestResumeBoundedFreshAttemptsAndPendingPhase(t *testing.T) {
	now := time.Now().UTC()
	expired := now.Add(-time.Minute)
	policy := model.Manifest{ID: uuid.New(), Checksum: "p"}
	p := model.CapacityPolicySpec{Floor: 1, Ceiling: 8}
	for _, attempt := range []int{1, 2, 3} {
		for _, phase := range []string{"preparing", "prepared", "canary", "promoted"} {
			old := model.CapacityIntent{PolicyID: policy.ID, PolicyChecksum: policy.Checksum, Generation: 6, FencingToken: int64(11 + attempt), Phase: phase, LeaseExpiresAt: &expired, Decision: model.CapacityDecision{Units: 1}, InstalledGuestReconcile: &model.CapacityInstalledGuestReconcile{Schema: "installed_original_guest_readiness_reconcile_v1", Attempt: attempt, OriginalGeneration: 6, OriginalFence: 11, NewFence: int64(11 + attempt), NewRunID: uuid.NewString(), OriginalFailurePreserved: true}}
			want := attempt < 3 && phase != "promoted"
			if installedGuestResumeCandidate(&old, p, policy, now) != want {
				t.Fatal("bounded retry or terminal phase lost", attempt, phase)
			}
		}
	}
}

func TestInstalledGuestResumeRequiresDistinctAcknowledgedRefreshShape(t *testing.T) {
	steps := []model.WorkflowRunStepResult{}
	for _, id := range []string{"plan-original-guest", "provision-original-notify", "retire-original-guest", "refresh-original-membership", "complete-original-provision", "finish-original-retirement", "complete-original-retirement"} {
		status := "skipped"
		if id == "plan-original-guest" {
			status = "succeeded"
		}
		if id == "refresh-original-membership" {
			status = "failed"
		}
		step := model.WorkflowRunStepResult{ID: id, Status: status}
		if id == "plan-original-guest" {
			step.Metadata = map[string]any{"mode": "refresh", "reason": "installed_original_readiness_reconcile", "generation": 6, "fencing_token": 12}
		}
		steps = append(steps, step)
	}
	raw, _ := json.Marshal(map[string]any{"status": "failed", "steps": steps})
	if !failedInstalledResumeResult(raw, 6, 12) || failedInstalledResumeResult(raw, 6, 11) {
		t.Fatal("last refresh joined wrong epoch")
	}
	steps[3].Status = "succeeded"
	raw, _ = json.Marshal(map[string]any{"status": "failed", "steps": steps})
	if failedInstalledResumeResult(raw, 6, 12) {
		t.Fatal("successful refresh treated as failed retry permission")
	}
}
