package reconciler

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

const sensitiveSentinel = "DO_NOT_LOG_secret_name_or_value"

// Diagnostic classification must never render an error, even by accident.
type noStringError struct{}

func (noStringError) Error() string { panic("error text must not be evaluated") }

type diagnosticMaterializer struct{}

func (diagnosticMaterializer) Owns() string { return "secrets" }
func (diagnosticMaterializer) Materialize(context.Context, KubeTarget, any) error {
	return nil
}
func (diagnosticMaterializer) Reconcile(context.Context, KubeTarget, *sql.DB) (ReconcileResult, error) {
	result := ReconcileResult{Kind: "secrets"}
	result.recordError(stageGet, k8serrors.NewForbidden(schema.GroupResource{Resource: "secrets"}, sensitiveSentinel, errors.New(sensitiveSentinel)))
	return result, nil
}

func TestEngineEmitsSanitizedPassDiagnostics(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	pool := &KubeClientPool{remotes: make(map[string]*cachedTarget)}
	pool.SetLocal(KubeTarget{Client: fake.NewSimpleClientset()})
	core, logs := observer.New(zap.InfoLevel)
	engine := NewEngine(pool, db, zap.New(core), diagnosticMaterializer{})
	engine.runFullReconcile(context.Background())
	entries := logs.FilterMessage("reconcile pass").All()
	if len(entries) != 1 || entries[0].ContextMap()["error_get_forbidden"] != int64(1) {
		t.Fatal("expected fixed error counter in reconcile pass log")
	}
	fields, err := json.Marshal(entries[0].ContextMap())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(fields), sensitiveSentinel) {
		t.Fatal("reconcile pass log contains sensitive marker")
	}
}

func TestClassifyReconcileError(t *testing.T) {
	resource := schema.GroupResource{Resource: "secrets"}
	tests := []struct {
		name string
		err  error
		want reconcileErrorClass
	}{
		{"forbidden", k8serrors.NewForbidden(resource, sensitiveSentinel, errors.New(sensitiveSentinel)), classForbidden},
		{"not found", k8serrors.NewNotFound(resource, sensitiveSentinel), classNotFound},
		{"bad request", k8serrors.NewBadRequest(sensitiveSentinel), classInvalid},
		{"conflict", k8serrors.NewConflict(resource, sensitiveSentinel, errors.New(sensitiveSentinel)), classConflict},
		{"timeout", fmt.Errorf("%s: %w", sensitiveSentinel, context.DeadlineExceeded), classTimeout},
		{"unavailable", k8serrors.NewServiceUnavailable(sensitiveSentinel), classUnavailable},
		{"other", errors.New(sensitiveSentinel), classOther},
		{"no error formatting", noStringError{}, classOther},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := classifyReconcileError(tt.err); got != tt.want {
				t.Fatalf("class = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestManifestDiagnosticsCoverDatabaseAndApply(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	cols := []string{"id", "api_version", "kind", "namespace", "name", "version", "active", "description", "labels", "spec", "checksum", "created_at", "updated_at"}
	for i, kind := range manifestManagedKinds {
		query := mock.ExpectQuery("FROM public.manifests").WithArgs(kind)
		switch i {
		case 0:
			query.WillReturnError(errors.New(sensitiveSentinel))
		case 1:
			now := time.Now()
			query.WillReturnRows(sqlmock.NewRows(cols).AddRow(uuid.New().String(), "v1", kind, "dakasa", sensitiveSentinel, 1, true, "", []byte("{}"), []byte("{}"), "", now, now))
		default:
			query.WillReturnRows(sqlmock.NewRows(cols))
		}
	}
	client := fake.NewSimpleClientset()
	client.PrependReactor("create", "configmaps", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, k8serrors.NewForbidden(schema.GroupResource{Resource: "configmaps"}, sensitiveSentinel, errors.New(sensitiveSentinel))
	})
	result, err := (&ManifestMaterializer{}).Reconcile(context.Background(), KubeTarget{Client: client}, db)
	if err != nil {
		t.Fatal(err)
	}
	if result.Errors != 2 || result.diagnostics[stageList][classOther] != 1 || result.diagnostics[stageApply][classForbidden] != 1 {
		t.Fatalf("unexpected manifest diagnostics: %+v", result.diagnostics)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
	core, logs := observer.New(zap.InfoLevel)
	zap.New(core).Info("reconcile pass", result.diagnostics.fields()...)
	fields, err := json.Marshal(logs.All()[0].ContextMap())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(fields), sensitiveSentinel) {
		t.Fatal("manifest diagnostics contain sensitive marker")
	}
}

func TestSecretDiagnosticsAreCountsOnly(t *testing.T) {
	client := fake.NewSimpleClientset(&corev1.Secret{ObjectMeta: metav1.ObjectMeta{
		Namespace: "dakasa", Name: "stale", Annotations: map[string]string{AnnotationVersion: "1"},
	}})
	resource := schema.GroupResource{Resource: "secrets"}
	client.PrependReactor("get", "secrets", func(action k8stesting.Action) (bool, runtime.Object, error) {
		if action.(k8stesting.GetAction).GetName() == sensitiveSentinel {
			return true, nil, k8serrors.NewForbidden(resource, sensitiveSentinel, errors.New(sensitiveSentinel))
		}
		return false, nil, nil
	})
	client.PrependReactor("create", "secrets", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, k8serrors.NewBadRequest(sensitiveSentinel)
	})
	client.PrependReactor("update", "secrets", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, k8serrors.NewConflict(resource, sensitiveSentinel, errors.New(sensitiveSentinel))
	})
	secrets := []model.ManagedSecret{
		{Namespace: "dakasa", Name: sensitiveSentinel, Version: 1, Data: map[string]string{"value": sensitiveSentinel}},
		{Namespace: "dakasa", Name: "missing", Version: 1},
		{Namespace: "dakasa", Name: "stale", Version: 2},
	}
	result := (&SecretMaterializer{}).reconcileSecretList(context.Background(), KubeTarget{Client: client}, secrets)
	if result.Errors != 3 || result.diagnostics[stageGet][classForbidden] != 1 || result.diagnostics[stageCreate][classInvalid] != 1 || result.diagnostics[stageUpdate][classConflict] != 1 {
		t.Fatalf("unexpected aggregate diagnostics: %+v", result.diagnostics)
	}

	core, logs := observer.New(zap.InfoLevel)
	zap.New(core).Info("reconcile pass", result.diagnostics.fields()...)
	fields, err := json.Marshal(logs.All()[0].ContextMap())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(fields), sensitiveSentinel) {
		t.Fatalf("diagnostic fields contain sensitive marker")
	}
	for _, field := range []string{"error_get_forbidden", "error_create_invalid", "error_update_conflict"} {
		if logs.All()[0].ContextMap()[field] != int64(1) {
			t.Errorf("missing fixed counter %s", field)
		}
	}

	// Adding internal diagnostics must not change the serialized status API.
	status, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(status), "diagnostics") || strings.Contains(string(status), sensitiveSentinel) {
		t.Fatal("private diagnostics leaked into status JSON")
	}
	var statusFields map[string]json.RawMessage
	if err := json.Unmarshal(status, &statusFields); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"Kind", "Created", "Updated", "Skipped", "Errors", "Duration", "Timestamp"} {
		if _, ok := statusFields[key]; !ok {
			t.Fatalf("status field %s missing", key)
		}
	}
	if len(statusFields) != 7 {
		t.Fatalf("status JSON gained fields: %v", statusFields)
	}
}
