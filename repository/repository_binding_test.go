package repository

import (
	"context"
	"errors"
	"regexp"
	"testing"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
)

func TestFindBindingByRepositoryReturnsBinding(t *testing.T) {
	t.Parallel()

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New error: %v", err)
	}
	defer db.Close()

	mock.ExpectQuery(regexp.QuoteMeta(`
		SELECT namespace, name, COALESCE(description, ''), spec
		FROM public.manifests
		WHERE kind = 'repository_binding'
		  AND active = TRUE
		  AND spec->>'repository' = $1
		LIMIT 1
	`)).
		WithArgs("dakasa-co/dakasa-app-identities-api").
		WillReturnRows(sqlmock.NewRows([]string{"namespace", "name", "description", "spec"}).
			AddRow("dakasa", "dakasa-app-identities", "binding for identities", []byte(`{
				"component_kind": "product",
				"component_name": "dakasa-app",
				"component_namespace": "dakasa",
				"repository": "dakasa-co/dakasa-app-identities-api",
				"default_branch": "main",
				"automation": {"observe": true, "allow_dispatch_workflow": true},
				"deploy": {
					"workflow_kind": "yggdrasil",
					"workflow_ref": {"namespace": "dakasa", "name": "deploy-via-kustomize-source"},
					"default_inputs": {"git_url": "{{ push.repository.clone_url }}"},
					"branch_filter": ["main"]
				}
			}`)))

	binding, err := FindBindingByRepository(context.Background(), db, "dakasa-co/dakasa-app-identities-api")
	if err != nil {
		t.Fatalf("FindBindingByRepository error: %v", err)
	}
	if binding.Metadata.Namespace != "dakasa" || binding.Metadata.Name != "dakasa-app-identities" {
		t.Fatalf("unexpected metadata: %+v", binding.Metadata)
	}
	if binding.Spec.Repository != "dakasa-co/dakasa-app-identities-api" {
		t.Fatalf("unexpected spec.repository: %q", binding.Spec.Repository)
	}
	if binding.Spec.Deploy == nil {
		t.Fatal("expected Deploy block to be parsed")
	}
	if binding.Spec.Deploy.WorkflowKind != "yggdrasil" {
		t.Fatalf("unexpected workflow_kind: %q", binding.Spec.Deploy.WorkflowKind)
	}
	if binding.Spec.Deploy.WorkflowRef == nil ||
		binding.Spec.Deploy.WorkflowRef.Name != "deploy-via-kustomize-source" {
		t.Fatalf("unexpected WorkflowRef: %+v", binding.Spec.Deploy.WorkflowRef)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestFindBindingByRepositoryReturnsErrBindingNotFoundOnNoRows(t *testing.T) {
	t.Parallel()

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New error: %v", err)
	}
	defer db.Close()

	mock.ExpectQuery(`SELECT namespace, name, COALESCE\(description, ''\), spec`).
		WithArgs("unknown/repo").
		WillReturnRows(sqlmock.NewRows([]string{"namespace", "name", "description", "spec"}))

	_, err = FindBindingByRepository(context.Background(), db, "unknown/repo")
	if !errors.Is(err, ErrBindingNotFound) {
		t.Fatalf("expected ErrBindingNotFound, got %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestFindBindingByRepositoryDecodeFailureWraps(t *testing.T) {
	t.Parallel()

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New error: %v", err)
	}
	defer db.Close()

	mock.ExpectQuery(`SELECT namespace, name, COALESCE\(description, ''\), spec`).
		WithArgs("acme/widget").
		WillReturnRows(sqlmock.NewRows([]string{"namespace", "name", "description", "spec"}).
			AddRow("global", "widget", "", []byte(`not-valid-json`)))

	_, err = FindBindingByRepository(context.Background(), db, "acme/widget")
	if err == nil {
		t.Fatal("expected decode error, got nil")
	}
}
