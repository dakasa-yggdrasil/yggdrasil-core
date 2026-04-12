package reconciler

import (
	"context"
	"encoding/json"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestProductMaterializer_Materialize_CreatesConfigMap(t *testing.T) {
	client := fake.NewSimpleClientset()
	target := KubeTarget{Name: "local", Client: client, IsLocal: true}

	manifest := newManifest("product", "dakasa", "payments-platform", 1, map[string]any{
		"components": []map[string]any{
			{"name": "api", "kustomize": "deploy/api"},
			{"name": "worker", "kustomize": "deploy/worker"},
		},
	})

	m := &ProductMaterializer{}
	if err := m.Materialize(context.Background(), target, manifest); err != nil {
		t.Fatalf("Materialize returned error: %v", err)
	}

	cm, err := client.CoreV1().ConfigMaps("dakasa").Get(
		context.Background(), "ygg-product-payments-platform", metav1.GetOptions{},
	)
	if err != nil {
		t.Fatalf("expected ConfigMap to exist: %v", err)
	}

	// Verify labels
	if cm.Labels[LabelManagedBy] != LabelManagedByValue {
		t.Errorf("label %s = %q, want %q", LabelManagedBy, cm.Labels[LabelManagedBy], LabelManagedByValue)
	}
	if cm.Labels[AnnotationKind] != "product" {
		t.Errorf("label %s = %q, want %q", AnnotationKind, cm.Labels[AnnotationKind], "product")
	}

	// Verify annotations
	if cm.Annotations[AnnotationVersion] != "1" {
		t.Errorf("annotation version = %q, want %q", cm.Annotations[AnnotationVersion], "1")
	}
	if cm.Annotations[AnnotationSourceName] != "payments-platform" {
		t.Errorf("annotation source-name = %q, want %q", cm.Annotations[AnnotationSourceName], "payments-platform")
	}

	// Verify data
	var parsed map[string]any
	if err := json.Unmarshal([]byte(cm.Data["manifest.json"]), &parsed); err != nil {
		t.Fatalf("manifest.json is not valid JSON: %v", err)
	}
	components, ok := parsed["components"].([]any)
	if !ok || len(components) != 2 {
		t.Errorf("expected 2 components in spec, got %v", parsed["components"])
	}
}

func TestProductMaterializer_Materialize_UpdatesExisting(t *testing.T) {
	existing := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ygg-product-auth-service",
			Namespace: "dakasa",
			Labels: map[string]string{
				LabelManagedBy: LabelManagedByValue,
				AnnotationKind: "product",
			},
			Annotations: map[string]string{
				AnnotationVersion:    "1",
				AnnotationSourceNS:   "dakasa",
				AnnotationSourceName: "auth-service",
				AnnotationLastSynced: "2026-01-01T00:00:00Z",
			},
		},
		Data: map[string]string{
			"manifest.json": `{"components":[]}`,
		},
	}

	client := fake.NewSimpleClientset(existing)
	target := KubeTarget{Name: "local", Client: client, IsLocal: true}

	manifest := newManifest("product", "dakasa", "auth-service", 2, map[string]any{
		"components": []map[string]any{
			{"name": "gateway", "kustomize": "deploy/gateway"},
		},
	})

	m := &ProductMaterializer{}
	if err := m.Materialize(context.Background(), target, manifest); err != nil {
		t.Fatalf("Materialize returned error: %v", err)
	}

	cm, err := client.CoreV1().ConfigMaps("dakasa").Get(
		context.Background(), "ygg-product-auth-service", metav1.GetOptions{},
	)
	if err != nil {
		t.Fatalf("expected ConfigMap to exist: %v", err)
	}

	if cm.Annotations[AnnotationVersion] != "2" {
		t.Errorf("annotation version = %q, want %q", cm.Annotations[AnnotationVersion], "2")
	}
}

func TestProductMaterializer_Materialize_SkipsUpToDate(t *testing.T) {
	existing := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ygg-product-billing",
			Namespace: "dakasa",
			Labels: map[string]string{
				LabelManagedBy: LabelManagedByValue,
				AnnotationKind: "product",
			},
			Annotations: map[string]string{
				AnnotationVersion:    "5",
				AnnotationSourceNS:   "dakasa",
				AnnotationSourceName: "billing",
				AnnotationLastSynced: "2026-04-01T00:00:00Z",
			},
		},
		Data: map[string]string{
			"manifest.json": `{"components":[{"name":"api"}]}`,
		},
	}

	client := fake.NewSimpleClientset(existing)
	target := KubeTarget{Name: "local", Client: client, IsLocal: true}

	manifest := newManifest("product", "dakasa", "billing", 5, map[string]any{
		"components": []map[string]any{{"name": "api"}},
	})

	m := &ProductMaterializer{}
	if err := m.Materialize(context.Background(), target, manifest); err != nil {
		t.Fatalf("Materialize returned error: %v", err)
	}

	cm, err := client.CoreV1().ConfigMaps("dakasa").Get(
		context.Background(), "ygg-product-billing", metav1.GetOptions{},
	)
	if err != nil {
		t.Fatalf("expected ConfigMap to exist: %v", err)
	}

	// Should remain unchanged — no write happened.
	if cm.Annotations[AnnotationLastSynced] != "2026-04-01T00:00:00Z" {
		t.Errorf("expected last-synced to remain unchanged, got %q", cm.Annotations[AnnotationLastSynced])
	}
}

func TestProductMaterializer_Materialize_DefaultsNamespace(t *testing.T) {
	client := fake.NewSimpleClientset()
	target := KubeTarget{Name: "local", Client: client, IsLocal: true}

	manifest := newManifest("product", "", "infra-tools", 1, map[string]any{
		"components": []string{},
	})

	m := &ProductMaterializer{}
	if err := m.Materialize(context.Background(), target, manifest); err != nil {
		t.Fatalf("Materialize returned error: %v", err)
	}

	_, err := client.CoreV1().ConfigMaps("dakasa").Get(
		context.Background(), "ygg-product-infra-tools", metav1.GetOptions{},
	)
	if err != nil {
		t.Fatalf("expected ConfigMap in dakasa namespace: %v", err)
	}
}

func TestProductMaterializer_Materialize_RejectsWrongType(t *testing.T) {
	client := fake.NewSimpleClientset()
	target := KubeTarget{Name: "local", Client: client, IsLocal: true}

	m := &ProductMaterializer{}
	err := m.Materialize(context.Background(), target, "not-a-manifest")
	if err == nil {
		t.Fatal("expected error for wrong type")
	}
}

func TestProductMaterializer_Owns(t *testing.T) {
	m := &ProductMaterializer{}
	if got := m.Owns(); got != "products" {
		t.Errorf("Owns() = %q, want %q", got, "products")
	}
}
