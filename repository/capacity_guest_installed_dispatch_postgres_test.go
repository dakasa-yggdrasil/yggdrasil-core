package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// Invoked by the existing installed-resume PostgreSQL root in the Source CI.
// It uses the actual scheduler writer/dispatch lifecycle, which leaves the
// optional workflow_id NULL. These synthetic storage records are not native
// enrollment, readiness or permission to mutate a provider.
func testInstalledGuestDispatchWorkflowIdentityPostgres(t *testing.T) {
	for _, name := range []string{"started_NULL", "returned_NULL", "foreign_optional_workflow_id", "foreign_envelope_workflow", "foreign_envelope_policy", "foreign_result_workflow", "foreign_result_version", "unacknowledged_return"} {
		t.Run(name, func(t *testing.T) {
			// Enforce the same owned, isolated Unix-only PG17 fixture as the
			// parent root, before creating any rows or opening another fixture.
			_, _ = d12AuthorityLocalFixture(t)
			db, envelope := capacityDispatchPostgresFixture(t)
			ctx := context.Background()
			envelope.Metadata["capacity_dispatch_job_id"] = envelope.JobID.String()
			envelope.Metadata["capacity_dispatch_protocol"] = envelope.Protocol
			var err error
			envelope.InputsSHA256, envelope.MetadataSHA256, err = CapacityDispatchEnvelopeHashes(envelope)
			if err != nil {
				t.Fatal(err)
			}
			capacityDispatchEnqueueFixture(t, db, envelope)
			job := capacityDispatchClaimFixture(t, db, envelope, 30*time.Second)
			job, err = StartCapacityDispatch(ctx, db, job)
			if err != nil {
				t.Fatal(err)
			}
			var optional uuid.NullUUID
			if err = db.QueryRowContext(ctx, `SELECT workflow_id FROM public.workflow_runs WHERE id=$1`, envelope.RunID).Scan(&optional); err != nil || optional.Valid {
				t.Fatal("actual scheduler writer no longer reproduces NULL workflow_id", err)
			}
			workflow := model.Manifest{ID: envelope.Workflow.ID, Version: envelope.Workflow.Version, Checksum: envelope.Workflow.Checksum, Metadata: model.ManifestMetadata{Namespace: envelope.Workflow.Namespace, Name: envelope.Workflow.Name}}
			policy := model.Manifest{ID: envelope.Policy.ID, Version: envelope.Policy.Version, Checksum: envelope.Policy.Checksum, Metadata: model.ManifestMetadata{Namespace: envelope.Policy.Namespace, Name: envelope.Policy.Name}}
			p := model.CapacityPolicySpec{Environment: envelope.Environment, Domain: envelope.Domain, Dimension: envelope.Dimension}
			store := CapacityStore{WorkflowID: workflow.ID, guestReconcile: &guestReconcileSource{workflow: workflow}}
			var result []byte
			preID := uuid.NewString()
			if name != "started_NULL" {
				response := capacityDispatchResponse(envelope, "failed")
				for _, id := range []string{"plan-original-guest", "provision-original-notify", "retire-original-guest", "refresh-original-membership", "complete-original-provision", "finish-original-retirement", "complete-original-retirement"} {
					step := model.WorkflowRunStepResult{ID: id, Status: "skipped"}
					if id == "plan-original-guest" || id == "provision-original-notify" {
						step.Status = "succeeded"
					}
					if id == "provision-original-notify" {
						step.Metadata = map[string]any{"preregistration": map[string]any{"preregistration_id": preID}}
					}
					if id == "complete-original-provision" {
						step.Status = "failed"
					}
					response.Steps = append(response.Steps, step)
				}
				if name == "unacknowledged_return" {
					err = FinishCapacityDispatch(ctx, db, job, response, time.Now().UTC(), nil, func(context.Context) error { return errors.New("ACK deliberately absent") })
					if err == nil {
						t.Fatal("missing ACK unexpectedly finalized")
					}
				} else if err = FinishCapacityDispatch(ctx, db, job, response, time.Now().UTC(), nil); err != nil {
					t.Fatal(err)
				}
				if err = db.QueryRowContext(ctx, `SELECT result FROM public.workflow_runs WHERE id=$1`, envelope.RunID).Scan(&result); err != nil {
					t.Fatal(err)
				}
				if name == "foreign_result_workflow" || name == "foreign_result_version" {
					if name == "foreign_result_workflow" {
						response.Workflow.ID = uuid.New()
					} else {
						response.Workflow.Version++
					}
					result, _ = json.Marshal(response)
				}
			}
			if name == "foreign_optional_workflow_id" {
				if _, err = db.ExecContext(ctx, `UPDATE public.workflow_runs SET workflow_id=$2 WHERE id=$1`, envelope.RunID, envelope.Policy.ID); err != nil {
					t.Fatal(err)
				}
			}
			if name == "foreign_envelope_workflow" {
				store.WorkflowID = uuid.New()
				store.guestReconcile.workflow.ID = store.WorkflowID
			}
			if name == "foreign_envelope_policy" {
				policy.ID = uuid.New()
			}
			var before, after string
			if err = db.QueryRowContext(ctx, `SELECT row_to_json(w)::text FROM public.workflow_runs w WHERE id=$1`, envelope.RunID).Scan(&before); err != nil {
				t.Fatal(err)
			}
			tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			got := store.installedGuestDispatchRunTx(ctx, tx, policy, p, envelope.RunID, result)
			positive := name == "started_NULL" || name == "returned_NULL"
			if (got == nil) != positive {
				t.Fatalf("exact original scheduler identity: %s: %v", name, got)
			}
			if name == "returned_NULL" {
				rows, queryErr := tx.QueryContext(ctx, installedGuestOriginalFailedRunQuery, envelope.Workflow.ID, preID, time.Now().UTC(), uuid.New())
				if queryErr != nil {
					t.Fatal(queryErr)
				}
				count := 0
				for rows.Next() {
					count++
				}
				queryErr = rows.Err()
				_ = rows.Close()
				if queryErr != nil || count != 1 {
					t.Fatal("production failed-original selection lost NULL scheduler row", count, queryErr)
				}
				var wire, last []byte
				if err = tx.QueryRowContext(ctx, installedGuestPreviousFailedRunQuery, envelope.RunID, envelope.Workflow.ID, time.Now().UTC()).Scan(&wire, &last); err != nil || string(last) != string(result) {
					t.Fatal("production retry selection lost original NULL scheduler row", err)
				}
			}
			if err = db.QueryRowContext(ctx, `SELECT row_to_json(w)::text FROM public.workflow_runs w WHERE id=$1`, envelope.RunID).Scan(&after); err != nil || before != after {
				t.Fatal("identity qualification rewrote historical workflow row", err)
			}
		})
	}
}
