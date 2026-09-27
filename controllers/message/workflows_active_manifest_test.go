package message

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
)

const activeWorkflowSpec = `{"trigger":{"mode":"manual"},"steps":[{"id":"observe","use":{"kind":"integration","instance_ref":{"namespace":"dakasa","name":"example"},"operation":"observe_state"}}]}`

func TestResolveActiveWorkflowManifestSpecRejectsInactiveManifestID(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	manifestID := uuid.New()
	mock.ExpectQuery(`(?s)FROM public\.manifests\s+WHERE id = \$1`).
		WithArgs(manifestID).
		WillReturnRows(workflowManifestRows(manifestID, 7, false))

	_, _, err = ResolveActiveWorkflowManifestSpec(context.Background(), db, model.ManifestSelector{
		ManifestID: manifestID.String(),
	})
	if !errors.Is(err, repository.ErrManifestNotFound) {
		t.Fatalf("error = %v, want ErrManifestNotFound for inactive manifest_id", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestResolveActiveWorkflowManifestSpecRejectsActiveNonWorkflowManifestID(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	manifestID := uuid.New()
	mock.ExpectQuery(`(?s)FROM public\.manifests\s+WHERE id = \$1`).
		WithArgs(manifestID).
		WillReturnRows(manifestRowsForKind(manifestID, "policy", 8, true))

	_, _, err = ResolveActiveWorkflowManifestSpec(context.Background(), db, model.ManifestSelector{
		ManifestID: manifestID.String(),
	})
	if !errors.Is(err, repository.ErrManifestNotFound) {
		t.Fatalf("error = %v, want ErrManifestNotFound for non-workflow manifest_id", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestResolveActiveWorkflowManifestSpecKeepsExactActivePins(t *testing.T) {
	for _, test := range []struct {
		name     string
		selector func(uuid.UUID, int) model.ManifestSelector
		expect   func(sqlmock.Sqlmock, uuid.UUID, int)
	}{
		{
			name: "manifest id",
			selector: func(id uuid.UUID, _ int) model.ManifestSelector {
				return model.ManifestSelector{ManifestID: id.String()}
			},
			expect: func(mock sqlmock.Sqlmock, id uuid.UUID, version int) {
				mock.ExpectQuery(`(?s)FROM public\.manifests\s+WHERE id = \$1`).
					WithArgs(id).
					WillReturnRows(manifestRowsForKind(id, "WoRkFlOw", version, true))
			},
		},
		{
			name: "logical version",
			selector: func(_ uuid.UUID, version int) model.ManifestSelector {
				return model.ManifestSelector{Namespace: "dakasa", Name: "lifecycle", Version: &version}
			},
			expect: func(mock sqlmock.Sqlmock, id uuid.UUID, version int) {
				mock.ExpectQuery(`(?s)FROM public\.manifests\s+WHERE kind = \$1 AND namespace = \$2 AND name = \$3\s+AND version = \$4 AND active = TRUE`).
					WithArgs("workflow", "dakasa", "lifecycle", version).
					WillReturnRows(workflowManifestRows(id, version, true))
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = db.Close() })

			manifestID := uuid.New()
			const version = 8
			test.expect(mock, manifestID, version)

			manifestRecord, _, err := ResolveActiveWorkflowManifestSpec(
				context.Background(),
				db,
				test.selector(manifestID, version),
			)
			if err != nil {
				t.Fatalf("ResolveActiveWorkflowManifestSpec error: %v", err)
			}
			if manifestRecord.ID != manifestID || manifestRecord.Version != version || !manifestRecord.Metadata.Active {
				t.Fatalf("resolved manifest = %#v, want active id=%s version=%d", manifestRecord, manifestID, version)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestResolveActiveWorkflowManifestSpecRejectsInactiveExplicitVersion(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	version := 7
	mock.ExpectQuery(`(?s)FROM public\.manifests\s+WHERE kind = \$1 AND namespace = \$2 AND name = \$3\s+AND version = \$4 AND active = TRUE`).
		WithArgs("workflow", "dakasa", "lifecycle", version).
		WillReturnRows(sqlmock.NewRows(workflowManifestColumns()))

	_, _, err = ResolveActiveWorkflowManifestSpec(context.Background(), db, model.ManifestSelector{
		Namespace: "dakasa",
		Name:      "lifecycle",
		Version:   &version,
	})
	if !errors.Is(err, repository.ErrManifestNotFound) {
		t.Fatalf("error = %v, want ErrManifestNotFound for inactive version", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func workflowManifestRows(id uuid.UUID, version int, active bool) *sqlmock.Rows {
	return manifestRowsForKind(id, "workflow", version, active)
}

func manifestRowsForKind(id uuid.UUID, kind string, version int, active bool) *sqlmock.Rows {
	now := time.Now().UTC()
	return sqlmock.NewRows(workflowManifestColumns()).AddRow(
		id,
		"yggdrasil.io/v1alpha1",
		kind,
		"dakasa",
		"lifecycle",
		version,
		active,
		"",
		[]byte(`{}`),
		[]byte(activeWorkflowSpec),
		"sha256:test",
		now,
		now,
	)
}

func workflowManifestColumns() []string {
	return []string{
		"id", "api_version", "kind", "namespace", "name", "version", "active",
		"description", "labels", "spec", "checksum", "created_at", "updated_at",
	}
}
