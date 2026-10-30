//go:build linux && nativequalification

package main

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
)

// Exercise the actual fixture store through the real transactional lease gate.
// The SQL driver controls time and rows; it does not stand in for the gate.
func TestSourceFailureCleanupFixtureStoreLease(t *testing.T) {
	for _, tc := range []struct {
		name, env string
		want      error
	}{
		{"enabled", "true", nil},
		{"disabled", "false", repository.ErrCapacityDisabled},
		{"unset_value", "", repository.ErrCapacityDisabled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("YGGDRASIL_CAPACITY_EXECUTION_ENABLED", tc.env)
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
			p := model.CapacityPolicySpec{Environment: "lab", Domain: "ai", Dimension: "executor", TargetIdentity: "fixed-lab", Owner: "lab-owner", Workflow: model.ManifestSelector{Namespace: "ops", Name: "lab-executor"}, Currency: "USD", Floor: 1, Ceiling: 1, Step: 1, MaxEvidenceAgeSeconds: 30, MinSamples: 1, MaxSampleGapSeconds: 10, DownHoldSeconds: 10, LeaseSeconds: 30, ExecutionEnabled: true,
				Signals:                 []model.CapacitySignalRule{{Name: "tasks", SourceIdentity: "fixed-sensor", Unit: "count", UpAbove: 1, DownBelow: 0}},
				Profiles:                []model.CapacityProfile{{Name: "lab", Provider: "aws", Region: "us-east-1", MinUnits: 1, MaxUnits: 1, ValidationRef: "source-only", QuoteValidUntil: now.Add(time.Hour), ValidationValidUntil: now.Add(time.Hour)}},
				ExecutorActivityBinding: &model.CapacityExecutorActivityBinding{Mode: "executor_activity_v1", LeaseTTLSeconds: 90, IdleAfterSeconds: 600, MaxObservationAgeSeconds: 30, MaxTasks: 10000}}
			spec, err := json.Marshal(p)
			if err != nil {
				t.Fatal(err)
			}
			policy := model.Manifest{ID: uuid.New(), Kind: "capacity_policy", Checksum: "policy-checksum", Metadata: model.ManifestMetadata{Namespace: "ops", Name: "lab"}, Spec: spec}
			f := &fixture{db: db}
			f.workflow.ID = uuid.New()
			parent, executor, owner := uuid.NewString(), uuid.NewString(), "fixture-owner"
			recordWire, err := json.Marshal(struct {
				Grant          model.CapacityMutationGrant   `json:"grant"`
				Binding        model.CapacityMutationBinding `json:"binding"`
				PolicyID       uuid.UUID                     `json:"policy_id"`
				PolicyChecksum string                        `json:"policy_checksum"`
				WorkflowID     uuid.UUID                     `json:"workflow_id"`
				Generation     int64                         `json:"generation"`
				FencingToken   int64                         `json:"fencing_token"`
				LeaseOwner     string                        `json:"lease_owner"`
				ExecutorID     string                        `json:"executor_id"`
				CreatedAt      time.Time                     `json:"created_at"`
				EventProvider  string                        `json:"event_provider"`
				EventResource  string                        `json:"event_resource"`
			}{model.CapacityMutationGrant{GrantID: parent, State: "settled"}, model.CapacityMutationBinding{Slots: []model.CapacityMutationSlotBinding{}}, policy.ID, policy.Checksum, f.workflow.ID, 2, 3, owner, executor, now, "fixture", ""})
			if err != nil {
				t.Fatal(err)
			}
			expiry := now.Add(time.Minute)
			intentWire, err := json.Marshal(model.CapacityIntent{PolicyID: policy.ID, PolicyChecksum: policy.Checksum, Generation: 2, FencingToken: 3, Phase: "preparing", LeaseOwner: owner, LeaseExecutorID: executor, LeaseExpiresAt: &expiry})
			if err != nil {
				t.Fatal(err)
			}
			mock.ExpectBegin()
			mock.ExpectQuery(`SELECT clock_timestamp\(\)`).WillReturnRows(sqlmock.NewRows([]string{"now"}).AddRow(now))
			mock.ExpectQuery(`SELECT checksum,active FROM public.manifests`).WithArgs(policy.ID).WillReturnRows(sqlmock.NewRows([]string{"checksum", "active"}).AddRow(policy.Checksum, true))
			mock.ExpectQuery(`SELECT grant_record FROM public.capacity_mutation_grants`).WithArgs(parent).WillReturnRows(sqlmock.NewRows([]string{"grant_record"}).AddRow(recordWire))
			mock.ExpectQuery(`SELECT intent FROM public.capacity_intents`).WithArgs(policy.Metadata.Namespace, p.Environment, p.Domain, p.Dimension).WillReturnRows(sqlmock.NewRows([]string{"intent"}).AddRow(intentWire))
			if tc.want == nil {
				mock.ExpectCommit()
			} else {
				mock.ExpectRollback()
			}
			err = f.sourceFailureCleanupStore().CheckSourceFailureCleanupLease(context.Background(), policy, parent)
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
