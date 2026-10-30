//go:build linux && nativequalification

package repository

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

func TestSourceFailureCleanupLeaseExecutionGate(t *testing.T) {
	for _, tc := range []struct {
		name    string
		enabled bool
		expired bool
		want    error
	}{
		{"disabled", false, false, ErrCapacityDisabled},
		{"enabled_valid", true, false, nil},
		{"enabled_expired", true, true, ErrCapacityLease},
		{"enabled_wrong_fence", true, false, ErrCapacityConflict},
		{"enabled_wrong_executor", true, false, ErrCapacityLease},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			policy := executorActivityRepositoryPolicy(t)
			var p model.CapacityPolicySpec
			if err := json.Unmarshal(policy.Spec, &p); err != nil {
				t.Fatal(err)
			}
			now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
			expiry := now.Add(time.Minute)
			if tc.expired {
				expiry = now.Add(-time.Second)
			}
			workflow := uuid.New()
			parent := uuid.NewString()
			executor := uuid.NewString()
			owner := "fixture-owner"
			record := capacityMutationRecord{Grant: model.CapacityMutationGrant{GrantID: parent, State: "settled"}, Binding: model.CapacityMutationBinding{Slots: []model.CapacityMutationSlotBinding{}}, PolicyID: policy.ID, PolicyChecksum: policy.Checksum, WorkflowID: workflow, Generation: 2, FencingToken: 3, LeaseOwner: owner, ExecutorID: executor}
			recordWire, err := json.Marshal(record)
			if err != nil {
				t.Fatal(err)
			}
			intent := model.CapacityIntent{PolicyID: policy.ID, PolicyChecksum: policy.Checksum, Generation: 2, FencingToken: 3, Phase: "preparing", LeaseOwner: owner, LeaseExecutorID: executor, LeaseExpiresAt: &expiry}
			if tc.name == "enabled_wrong_fence" {
				intent.FencingToken++
			}
			if tc.name == "enabled_wrong_executor" {
				intent.LeaseExecutorID = uuid.NewString()
			}
			intentWire, err := json.Marshal(intent)
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
			store := CapacityStore{DB: db, WorkflowID: workflow, ExecutionEnabled: tc.enabled}
			err = store.CheckSourceFailureCleanupLease(context.Background(), policy, parent)
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
