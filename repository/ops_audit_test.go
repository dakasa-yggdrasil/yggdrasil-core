package repository_test

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
)

func opsAuditTestDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("DB_URL")
	if dsn == "" {
		t.Skip("DB_URL not set; skipping ops audit integration test")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.Ping(); err != nil {
		t.Fatalf("ping db: %v", err)
	}
	return db
}

func TestRecordOpsAuditEvent_Roundtrip(t *testing.T) {
	db := opsAuditTestDB(t)
	ctx := context.Background()
	collabID := uuid.New()
	corr := "corr_" + uuid.NewString()

	ev := model.OpsAuditEvent{
		Actor:               "user:" + collabID.String(),
		ActorCollaboratorID: &collabID,
		ActorSessionID:      "sess_abc",
		Action:              "ops.workflows.retry",
		TargetKind:          "workflow_run",
		TargetID:            "11111111-1111-1111-1111-111111111111",
		ResultStatus:        "success",
		CorrelationID:       corr,
		RequestBody:         map[string]any{"reason": "fix"},
		Result:              map[string]any{"new_run_id": "22222222-2222-2222-2222-222222222222"},
	}
	if err := repository.RecordOpsAuditEvent(ctx, db, ev); err != nil {
		t.Fatalf("record: %v", err)
	}

	got, err := repository.ListOpsAuditEvents(ctx, db, model.ListOpsAuditEventsFilter{
		CorrelationID: corr,
		Limit:         10,
	})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 row, got %d", len(got))
	}
	if got[0].Action != "ops.workflows.retry" {
		t.Errorf("action mismatch: %q", got[0].Action)
	}
	if got[0].ResultStatus != "success" {
		t.Errorf("status mismatch: %q", got[0].ResultStatus)
	}
	if time.Since(got[0].CreatedAt) > time.Minute {
		t.Errorf("created_at too far in past: %v", got[0].CreatedAt)
	}
}
