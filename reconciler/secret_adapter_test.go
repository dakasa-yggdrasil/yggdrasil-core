package reconciler

import (
	"context"
	"strconv"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestSecretMaterializer_Materialize_CreatesNewSecret(t *testing.T) {
	client := fake.NewSimpleClientset()
	target := KubeTarget{Name: "local", Client: client, IsLocal: true}

	ms := model.ManagedSecret{
		Namespace: "payments",
		Name:      "stripe-api-key",
		Status:    "active",
		Version:   1,
		Data: map[string]string{
			"API_KEY":    "sk_test_123",
			"API_SECRET": "whsec_456",
		},
	}

	m := &SecretMaterializer{}
	if err := m.Materialize(context.Background(), target, ms); err != nil {
		t.Fatalf("Materialize returned error: %v", err)
	}

	secret, err := client.CoreV1().Secrets("payments").Get(context.Background(), "stripe-api-key", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("expected K8s Secret to exist: %v", err)
	}

	// Verify data
	if string(secret.Data["API_KEY"]) != "sk_test_123" {
		t.Errorf("API_KEY = %q, want %q", string(secret.Data["API_KEY"]), "sk_test_123")
	}
	if string(secret.Data["API_SECRET"]) != "whsec_456" {
		t.Errorf("API_SECRET = %q, want %q", string(secret.Data["API_SECRET"]), "whsec_456")
	}

	// Verify labels
	if secret.Labels[LabelManagedBy] != LabelManagedByValue {
		t.Errorf("label %s = %q, want %q", LabelManagedBy, secret.Labels[LabelManagedBy], LabelManagedByValue)
	}

	// Verify annotations
	if secret.Annotations[AnnotationVersion] != "1" {
		t.Errorf("annotation %s = %q, want %q", AnnotationVersion, secret.Annotations[AnnotationVersion], "1")
	}
	if secret.Annotations[AnnotationSourceNS] != "payments" {
		t.Errorf("annotation %s = %q, want %q", AnnotationSourceNS, secret.Annotations[AnnotationSourceNS], "payments")
	}
	if secret.Annotations[AnnotationSourceName] != "stripe-api-key" {
		t.Errorf("annotation %s = %q, want %q", AnnotationSourceName, secret.Annotations[AnnotationSourceName], "stripe-api-key")
	}
	if secret.Annotations[AnnotationLastSynced] == "" {
		t.Error("expected last-synced annotation to be set")
	}
}

func TestSecretMaterializer_Materialize_UpdatesExistingSecret(t *testing.T) {
	existing := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "db-creds",
			Namespace: "backend",
			Labels: map[string]string{
				LabelManagedBy: LabelManagedByValue,
			},
			Annotations: map[string]string{
				AnnotationVersion:    "1",
				AnnotationSourceNS:   "backend",
				AnnotationSourceName: "db-creds",
				AnnotationLastSynced: "2026-01-01T00:00:00Z",
			},
		},
		Data: map[string][]byte{
			"PASSWORD": []byte("old-password"),
		},
	}

	client := fake.NewSimpleClientset(existing)
	target := KubeTarget{Name: "local", Client: client, IsLocal: true}

	ms := model.ManagedSecret{
		Namespace: "backend",
		Name:      "db-creds",
		Status:    "active",
		Version:   2,
		Data: map[string]string{
			"PASSWORD": "new-password",
			"HOST":     "db.example.com",
		},
	}

	m := &SecretMaterializer{}
	if err := m.Materialize(context.Background(), target, ms); err != nil {
		t.Fatalf("Materialize returned error: %v", err)
	}

	secret, err := client.CoreV1().Secrets("backend").Get(context.Background(), "db-creds", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("expected K8s Secret to exist: %v", err)
	}

	if string(secret.Data["PASSWORD"]) != "new-password" {
		t.Errorf("PASSWORD = %q, want %q", string(secret.Data["PASSWORD"]), "new-password")
	}
	if string(secret.Data["HOST"]) != "db.example.com" {
		t.Errorf("HOST = %q, want %q", string(secret.Data["HOST"]), "db.example.com")
	}
	if secret.Annotations[AnnotationVersion] != "2" {
		t.Errorf("annotation %s = %q, want %q", AnnotationVersion, secret.Annotations[AnnotationVersion], "2")
	}
}

func TestSecretMaterializer_Materialize_SkipsUpToDate(t *testing.T) {
	existing := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "cache-creds",
			Namespace: "infra",
			Labels: map[string]string{
				LabelManagedBy: LabelManagedByValue,
			},
			Annotations: map[string]string{
				AnnotationVersion:    "5",
				AnnotationSourceNS:   "infra",
				AnnotationSourceName: "cache-creds",
				AnnotationLastSynced: "2026-04-01T00:00:00Z",
			},
		},
		Data: map[string][]byte{
			"REDIS_URL": []byte("redis://host:6379"),
		},
	}

	client := fake.NewSimpleClientset(existing)
	target := KubeTarget{Name: "local", Client: client, IsLocal: true}

	ms := model.ManagedSecret{
		Namespace: "infra",
		Name:      "cache-creds",
		Status:    "active",
		Version:   5,
		Data: map[string]string{
			"REDIS_URL": "redis://host:6379",
		},
	}

	m := &SecretMaterializer{}
	if err := m.Materialize(context.Background(), target, ms); err != nil {
		t.Fatalf("Materialize returned error: %v", err)
	}

	secret, err := client.CoreV1().Secrets("infra").Get(context.Background(), "cache-creds", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("expected K8s Secret to exist: %v", err)
	}

	// The last-synced annotation should NOT have been updated (no write happened).
	if secret.Annotations[AnnotationLastSynced] != "2026-04-01T00:00:00Z" {
		t.Errorf("expected last-synced to remain unchanged, got %q", secret.Annotations[AnnotationLastSynced])
	}
	if secret.Annotations[AnnotationVersion] != "5" {
		t.Errorf("expected version to remain 5, got %q", secret.Annotations[AnnotationVersion])
	}
}

func TestSecretMaterializer_Materialize_UsesMetadataOverride(t *testing.T) {
	client := fake.NewSimpleClientset()
	target := KubeTarget{Name: "local", Client: client, IsLocal: true}

	ms := model.ManagedSecret{
		Namespace: "global",
		Name:      "stripe-keys",
		Status:    "active",
		Version:   1,
		Data: map[string]string{
			"STRIPE_KEY": "sk_live_xxx",
		},
		Metadata: map[string]any{
			"materialize": map[string]any{
				"namespace": "dakasa",
				"name":      "enterprise-payments-api-secrets",
			},
		},
	}

	m := &SecretMaterializer{}
	if err := m.Materialize(context.Background(), target, ms); err != nil {
		t.Fatalf("Materialize returned error: %v", err)
	}

	// Should NOT exist at global/stripe-keys
	_, err := client.CoreV1().Secrets("global").Get(context.Background(), "stripe-keys", metav1.GetOptions{})
	if err == nil {
		t.Error("expected K8s Secret NOT to be created at global/stripe-keys")
	}

	// Should exist at dakasa/enterprise-payments-api-secrets
	secret, err := client.CoreV1().Secrets("dakasa").Get(context.Background(), "enterprise-payments-api-secrets", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("expected K8s Secret at dakasa/enterprise-payments-api-secrets: %v", err)
	}

	if string(secret.Data["STRIPE_KEY"]) != "sk_live_xxx" {
		t.Errorf("STRIPE_KEY = %q, want %q", string(secret.Data["STRIPE_KEY"]), "sk_live_xxx")
	}

	// Source annotations should point back to the original managed secret
	if secret.Annotations[AnnotationSourceNS] != "global" {
		t.Errorf("source-ns = %q, want %q", secret.Annotations[AnnotationSourceNS], "global")
	}
	if secret.Annotations[AnnotationSourceName] != "stripe-keys" {
		t.Errorf("source-name = %q, want %q", secret.Annotations[AnnotationSourceName], "stripe-keys")
	}
}

func TestSecretMaterializer_MarkRevoked(t *testing.T) {
	existing := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "old-api-key",
			Namespace: "services",
			Labels: map[string]string{
				LabelManagedBy: LabelManagedByValue,
			},
			Annotations: map[string]string{
				AnnotationVersion:    "3",
				AnnotationSourceNS:   "services",
				AnnotationSourceName: "old-api-key",
				AnnotationLastSynced: "2026-03-01T00:00:00Z",
			},
		},
		Data: map[string][]byte{
			"TOKEN": []byte("expired-token"),
		},
	}

	client := fake.NewSimpleClientset(existing)
	target := KubeTarget{Name: "local", Client: client, IsLocal: true}

	ms := model.ManagedSecret{
		Namespace: "services",
		Name:      "old-api-key",
		Status:    "revoked",
		Version:   3,
		Data:      map[string]string{},
	}

	m := &SecretMaterializer{}
	if err := m.Materialize(context.Background(), target, ms); err != nil {
		t.Fatalf("Materialize returned error: %v", err)
	}

	secret, err := client.CoreV1().Secrets("services").Get(context.Background(), "old-api-key", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("expected K8s Secret to still exist: %v", err)
	}

	if secret.Annotations[AnnotationStatus] != "revoked" {
		t.Errorf("annotation %s = %q, want %q", AnnotationStatus, secret.Annotations[AnnotationStatus], "revoked")
	}
	if secret.Annotations[AnnotationRevokedAt] == "" {
		t.Error("expected revoked-at annotation to be set")
	}

	// Verify version annotation is preserved as a string
	if secret.Annotations[AnnotationVersion] != strconv.Itoa(ms.Version) {
		t.Errorf("annotation %s = %q, want %q", AnnotationVersion, secret.Annotations[AnnotationVersion], strconv.Itoa(ms.Version))
	}
}

func TestSecretMaterializer_Owns(t *testing.T) {
	m := &SecretMaterializer{}
	if got := m.Owns(); got != "secrets" {
		t.Errorf("Owns() = %q, want %q", got, "secrets")
	}
}
