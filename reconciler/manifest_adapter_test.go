package reconciler

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func newManifest(kind, namespace, name string, version int, spec map[string]any) model.Manifest {
	specJSON, _ := json.Marshal(spec)
	return model.Manifest{
		ID:         uuid.New(),
		APIVersion: "yggdrasil.io/v1alpha1",
		Kind:       kind,
		Version:    version,
		Metadata: model.ManifestMetadata{
			Name:      name,
			Namespace: namespace,
			Active:    true,
			Labels:    map[string]string{},
		},
		Spec: json.RawMessage(specJSON),
	}
}

func TestManifestMaterializer_Materialize_CreatesConfigMap(t *testing.T) {
	controlPlaneProjectionAfterLostNotification(t)
	client := fake.NewSimpleClientset()
	target := KubeTarget{Name: "local", Client: client, IsLocal: true}

	manifest := newManifest("workflow", "dakasa", "bootstrap-validation", 1, map[string]any{
		"steps": []string{"validate", "deploy"},
	})

	m := &ManifestMaterializer{}
	if err := m.Materialize(context.Background(), target, manifest); err != nil {
		t.Fatalf("Materialize returned error: %v", err)
	}

	cm, err := client.CoreV1().ConfigMaps("dakasa").Get(
		context.Background(), "ygg-workflow-bootstrap-validation", metav1.GetOptions{},
	)
	if err != nil {
		t.Fatalf("expected ConfigMap to exist: %v", err)
	}

	// Verify labels
	if cm.Labels[LabelManagedBy] != LabelManagedByValue {
		t.Errorf("label %s = %q, want %q", LabelManagedBy, cm.Labels[LabelManagedBy], LabelManagedByValue)
	}
	if cm.Labels[AnnotationKind] != "workflow" {
		t.Errorf("label %s = %q, want %q", AnnotationKind, cm.Labels[AnnotationKind], "workflow")
	}

	// Verify annotations
	if cm.Annotations[AnnotationVersion] != "1" {
		t.Errorf("annotation version = %q, want %q", cm.Annotations[AnnotationVersion], "1")
	}
	if cm.Annotations[AnnotationSourceNS] != "dakasa" {
		t.Errorf("annotation source-ns = %q, want %q", cm.Annotations[AnnotationSourceNS], "dakasa")
	}
	if cm.Annotations[AnnotationSourceName] != "bootstrap-validation" {
		t.Errorf("annotation source-name = %q, want %q", cm.Annotations[AnnotationSourceName], "bootstrap-validation")
	}
	if cm.Annotations[AnnotationLastSynced] == "" {
		t.Error("expected last-synced annotation to be set")
	}

	// Verify data key
	if _, ok := cm.Data["manifest.json"]; !ok {
		t.Fatal("expected manifest.json key in ConfigMap data")
	}

	var parsed map[string]any
	if err := json.Unmarshal([]byte(cm.Data["manifest.json"]), &parsed); err != nil {
		t.Fatalf("manifest.json is not valid JSON: %v", err)
	}
}

// No reactive notification is delivered. The ordinary sweep must recover the
// committed control_plane version and remain idempotent on its next pass.
func controlPlaneProjectionAfterLostNotification(t *testing.T) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	old := newManifest("control_plane", "dakasa", "yggdrasil", 8, map[string]any{"image": "registry/source@old", "replicas": 1, "extra_env_from": []any{map[string]any{"secretRef": map[string]any{"name": "preserved-auth-reference"}}}})
	current := old
	current.Version = 9
	var spec map[string]any
	if json.Unmarshal(old.Spec, &spec) != nil {
		t.Fatal("old control plane unavailable")
	}
	spec["image"] = "registry/source@current"
	current.Spec, _ = json.Marshal(spec)
	client := fake.NewSimpleClientset()
	target := KubeTarget{Name: "local", Client: client, IsLocal: true}
	m := &ManifestMaterializer{}
	if err := m.Materialize(t.Context(), target, old); err != nil {
		t.Fatal(err)
	}
	for pass := 0; pass < 2; pass++ {
		for _, kind := range manifestManagedKinds {
			rows := sqlmock.NewRows([]string{"id", "api_version", "kind", "namespace", "name", "version", "active", "description", "labels", "spec", "checksum", "created_at", "updated_at"})
			if kind == "control_plane" {
				rows.AddRow(current.ID, current.APIVersion, current.Kind, current.Metadata.Namespace, current.Metadata.Name, current.Version, true, "", []byte(`{}`), []byte(current.Spec), "source-current", time.Now(), time.Now())
			}
			mock.ExpectQuery("FROM public.manifests").WithArgs(kind).WillReturnRows(rows)
		}
		result, err := m.Reconcile(t.Context(), target, db)
		if err != nil || result.Errors != 0 || (pass == 0 && result.Updated != 1) || (pass == 1 && result.Skipped != 1) {
			t.Fatal("committed projection was lost or replayed", result, err)
		}
	}
	cm, err := client.CoreV1().ConfigMaps("dakasa").Get(t.Context(), manifestConfigMapName(current), metav1.GetOptions{})
	if err != nil || cm.Annotations[AnnotationVersion] != "9" || cm.Data["manifest.json"] != string(current.Spec) {
		t.Fatal("whole current projection differs", err)
	}
	for _, action := range client.Actions() {
		if action.GetResource().Resource != "configmaps" {
			t.Fatal("projection sweep acquired non-ConfigMap mutation", action.GetResource())
		}
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestManifestMaterializer_Materialize_UpdatesExisting(t *testing.T) {
	existing := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ygg-rbac-platform-admin",
			Namespace: "dakasa",
			Labels: map[string]string{
				LabelManagedBy: LabelManagedByValue,
				AnnotationKind: "rbac",
			},
			Annotations: map[string]string{
				AnnotationVersion:    "1",
				AnnotationSourceNS:   "dakasa",
				AnnotationSourceName: "platform-admin",
				AnnotationLastSynced: "2026-01-01T00:00:00Z",
			},
		},
		Data: map[string]string{
			"manifest.json": `{"roles":[]}`,
		},
	}

	client := fake.NewSimpleClientset(existing)
	target := KubeTarget{Name: "local", Client: client, IsLocal: true}

	manifest := newManifest("rbac", "dakasa", "platform-admin", 2, map[string]any{
		"roles": []map[string]any{{"name": "admin"}},
	})

	m := &ManifestMaterializer{}
	if err := m.Materialize(context.Background(), target, manifest); err != nil {
		t.Fatalf("Materialize returned error: %v", err)
	}

	cm, err := client.CoreV1().ConfigMaps("dakasa").Get(
		context.Background(), "ygg-rbac-platform-admin", metav1.GetOptions{},
	)
	if err != nil {
		t.Fatalf("expected ConfigMap to exist: %v", err)
	}

	if cm.Annotations[AnnotationVersion] != "2" {
		t.Errorf("annotation version = %q, want %q", cm.Annotations[AnnotationVersion], "2")
	}

	var parsed map[string]any
	if err := json.Unmarshal([]byte(cm.Data["manifest.json"]), &parsed); err != nil {
		t.Fatalf("manifest.json is not valid JSON: %v", err)
	}
	roles, ok := parsed["roles"].([]any)
	if !ok || len(roles) != 1 {
		t.Errorf("expected 1 role in updated spec, got %v", parsed["roles"])
	}
}

func TestManifestMaterializer_Materialize_SkipsUpToDate(t *testing.T) {
	existing := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ygg-surface-dashboard",
			Namespace: "dakasa",
			Labels: map[string]string{
				LabelManagedBy: LabelManagedByValue,
				AnnotationKind: "surface",
			},
			Annotations: map[string]string{
				AnnotationVersion:    "3",
				AnnotationSourceNS:   "dakasa",
				AnnotationSourceName: "dashboard",
				AnnotationLastSynced: "2026-04-01T00:00:00Z",
			},
		},
		Data: map[string]string{
			"manifest.json": `{"layout":"grid"}`,
		},
	}

	client := fake.NewSimpleClientset(existing)
	target := KubeTarget{Name: "local", Client: client, IsLocal: true}

	manifest := newManifest("surface", "dakasa", "dashboard", 3, map[string]any{
		"layout": "grid",
	})

	m := &ManifestMaterializer{}
	if err := m.Materialize(context.Background(), target, manifest); err != nil {
		t.Fatalf("Materialize returned error: %v", err)
	}

	cm, err := client.CoreV1().ConfigMaps("dakasa").Get(
		context.Background(), "ygg-surface-dashboard", metav1.GetOptions{},
	)
	if err != nil {
		t.Fatalf("expected ConfigMap to exist: %v", err)
	}

	// Should remain unchanged — no update happened.
	if cm.Annotations[AnnotationLastSynced] != "2026-04-01T00:00:00Z" {
		t.Errorf("expected last-synced to remain unchanged, got %q", cm.Annotations[AnnotationLastSynced])
	}
}

func TestManifestMaterializer_Materialize_DefaultsNamespace(t *testing.T) {
	client := fake.NewSimpleClientset()
	target := KubeTarget{Name: "local", Client: client, IsLocal: true}

	manifest := newManifest("guardian_policy", "", "rate-limit", 1, map[string]any{
		"rules": []string{},
	})

	m := &ManifestMaterializer{}
	if err := m.Materialize(context.Background(), target, manifest); err != nil {
		t.Fatalf("Materialize returned error: %v", err)
	}

	// Should be created in "dakasa" namespace by default.
	_, err := client.CoreV1().ConfigMaps("dakasa").Get(
		context.Background(), "ygg-guardian-policy-rate-limit", metav1.GetOptions{},
	)
	if err != nil {
		t.Fatalf("expected ConfigMap in dakasa namespace: %v", err)
	}
}

func TestManifestMaterializer_Materialize_RejectsWrongType(t *testing.T) {
	client := fake.NewSimpleClientset()
	target := KubeTarget{Name: "local", Client: client, IsLocal: true}

	m := &ManifestMaterializer{}
	err := m.Materialize(context.Background(), target, "not-a-manifest")
	if err == nil {
		t.Fatal("expected error for wrong type")
	}
}

func TestManifestMaterializer_Owns(t *testing.T) {
	m := &ManifestMaterializer{}
	if got := m.Owns(); got != "manifests" {
		t.Errorf("Owns() = %q, want %q", got, "manifests")
	}
}
