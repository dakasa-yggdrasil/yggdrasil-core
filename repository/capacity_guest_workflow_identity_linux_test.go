//go:build linux && nativequalification

package repository_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	q "github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacitynativeqemu"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
)

// Uses the actual idempotent writer and terminal result representation. The
// namespace is unique to this fixture; no production records are touched.
func TestOriginalWorkflowIdentityPublicWriterPostgres(t *testing.T) {
	ctx := context.Background()
	db := guestOriginalPostgres(t)
	ns := "identity-" + uuid.NewString()
	doc := model.ManifestDocument{APIVersion: "v1", Kind: "workflow", Metadata: model.ManifestMetadataInput{Namespace: ns, Name: "original"}, Spec: json.RawMessage(`{}`)}
	manifest, err := repository.CreateManifestVersion(ctx, db, doc, "test-checksum")
	if err != nil {
		t.Fatal(err)
	}
	runID := uuid.New()
	t.Cleanup(func() {
		if _, err := db.ExecContext(ctx, `DELETE FROM public.workflow_runs WHERE id=$1`, runID); err != nil {
			t.Error(err)
		}
		if _, err := db.ExecContext(ctx, `DELETE FROM public.manifests WHERE id=$1`, manifest.ID); err != nil {
			t.Error(err)
		}
	})
	got, duplicate, err := repository.InsertWorkflowRunIdempotent(ctx, db, runID, model.ManifestSelector{Namespace: ns, Name: "original"}, nil, map[string]any{"idempotency_key": uuid.NewString()})
	if err != nil || duplicate || got != runID {
		t.Fatal("original public writer failed", err)
	}
	var storedWorkflowID sql.NullString
	var storedVersion sql.NullInt64
	if err := db.QueryRowContext(ctx, `SELECT workflow_id::text, workflow_version FROM public.workflow_runs WHERE id=$1`, runID).Scan(&storedWorkflowID, &storedVersion); err != nil || storedWorkflowID.Valid || storedVersion.Valid {
		t.Fatal("public writer did not retain the expected nullable selector", err)
	}
	ref := model.ManifestReference{ID: manifest.ID, Kind: "workflow", Namespace: ns, Name: "original", Version: manifest.Version}
	result := model.RunWorkflowResponse{Workflow: ref, Status: "succeeded", StartedAt: time.Now().UTC(), FinishedAt: time.Now().UTC()}
	if err := repository.FinalizeWorkflowRun(ctx, db, runID, "succeeded", result, "", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	assert := func(want bool) {
		t.Helper()
		var status string
		err := db.QueryRowContext(ctx, q.OriginalWorkflowIdentitySQL, runID, manifest.ID).Scan(&status)
		if want && (err != nil || status != "succeeded") {
			t.Fatalf("expected original identity, status=%s err=%v", status, err)
		}
		if !want && err != sql.ErrNoRows {
			t.Fatalf("mismatched identity accepted, status=%s err=%v", status, err)
		}
	}
	assert(true)
	for _, field := range []string{"id", "kind", "namespace", "name", "version"} {
		t.Run("result_"+field, func(t *testing.T) {
			changed := result
			switch field {
			case "id":
				changed.Workflow.ID = uuid.New()
			case "kind":
				changed.Workflow.Kind = "capacity_policy"
			case "namespace":
				changed.Workflow.Namespace += "-wrong"
			case "name":
				changed.Workflow.Name += "-wrong"
			case "version":
				changed.Workflow.Version++
			}
			if err := repository.FinalizeWorkflowRun(ctx, db, runID, "succeeded", changed, "", time.Now().UTC()); err != nil {
				t.Fatal(err)
			}
			assert(false)
			if err := repository.FinalizeWorkflowRun(ctx, db, runID, "succeeded", result, "", time.Now().UTC()); err != nil {
				t.Fatal(err)
			}
		})
	}
	for _, tc := range []struct {
		column string
		value  any
	}{{"workflow_id", uuid.New()}, {"workflow_version", manifest.Version + 1}, {"workflow_namespace", ns + "-wrong"}, {"workflow_name", "wrong"}} {
		t.Run("selector_"+tc.column, func(t *testing.T) {
			if _, err := db.ExecContext(ctx, fmt.Sprintf(`UPDATE public.workflow_runs SET %s=$2 WHERE id=$1`, tc.column), runID, tc.value); err != nil {
				t.Fatal(err)
			}
			assert(false)
			var original any
			switch tc.column {
			case "workflow_namespace":
				original = ns
			case "workflow_name":
				original = "original"
			default:
				original = nil
			}
			if _, err := db.ExecContext(ctx, fmt.Sprintf(`UPDATE public.workflow_runs SET %s=$2 WHERE id=$1`, tc.column), runID, original); err != nil {
				t.Fatal(err)
			}
		})
	}
	assert(true)
}
