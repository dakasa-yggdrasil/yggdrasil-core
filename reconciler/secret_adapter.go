package reconciler

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// SecretMaterializer converts model.ManagedSecret into Kubernetes Secrets.
type SecretMaterializer struct{}

// Owns returns the resource kind this materializer manages.
func (m *SecretMaterializer) Owns() string {
	return "secrets"
}

// Materialize creates, updates, or marks a Kubernetes Secret to match the
// given ManagedSecret. If the managed secret status is "revoked" or
// "disabled", the existing K8s Secret is annotated but not deleted.
func (m *SecretMaterializer) Materialize(ctx context.Context, target KubeTarget, resource any) error {
	secret, ok := resource.(model.ManagedSecret)
	if !ok {
		return fmt.Errorf("SecretMaterializer: expected model.ManagedSecret, got %T", resource)
	}

	if secret.Status == "revoked" || secret.Status == "disabled" {
		return m.markSecret(ctx, target, secret)
	}

	ns, name := resolveTargetLocation(secret)

	existing, err := target.Client.CoreV1().Secrets(ns).Get(ctx, name, metav1.GetOptions{})
	if k8serrors.IsNotFound(err) {
		return m.createSecret(ctx, target, secret, ns, name)
	}
	if err != nil {
		return fmt.Errorf("get secret %s/%s: %w", ns, name, err)
	}

	// Skip if already up-to-date.
	if existing.Annotations[AnnotationVersion] == strconv.Itoa(secret.Version) {
		return nil
	}

	return m.updateSecret(ctx, target, secret, existing)
}

// Reconcile lists all active managed secrets from the database and reconciles
// each against the corresponding Kubernetes Secret, materializing when needed.
func (m *SecretMaterializer) Reconcile(ctx context.Context, target KubeTarget, db *sql.DB) (ReconcileResult, error) {
	if db == nil {
		return ReconcileResult{Kind: "secrets", Timestamp: time.Now()}, nil
	}

	secrets, err := repository.ListManagedSecrets(ctx, db, model.ListManagedSecretsRequest{
		Status: "active",
	})
	if err != nil {
		return ReconcileResult{}, err
	}

	return m.reconcileSecretList(ctx, target, secrets), nil
}

// reconcileSecretList iterates a list of managed secrets, comparing each
// against the corresponding Kubernetes Secret and materializing when needed.
func (m *SecretMaterializer) reconcileSecretList(ctx context.Context, target KubeTarget, secrets []model.ManagedSecret) ReconcileResult {
	start := time.Now()
	result := ReconcileResult{
		Kind:      "secrets",
		Timestamp: start,
	}

	for _, secret := range secrets {
		ns, name := resolveTargetLocation(secret)

		existing, err := target.Client.CoreV1().Secrets(ns).Get(ctx, name, metav1.GetOptions{})
		if k8serrors.IsNotFound(err) {
			if mErr := m.createSecret(ctx, target, secret, ns, name); mErr != nil {
				result.Errors++
			} else {
				result.Created++
			}
			continue
		}
		if err != nil {
			result.Errors++
			continue
		}

		// Compare the version annotation with the managed secret version.
		existingVersion := existing.Annotations[AnnotationVersion]
		if existingVersion == strconv.Itoa(secret.Version) {
			result.Skipped++
			continue
		}

		if mErr := m.updateSecret(ctx, target, secret, existing); mErr != nil {
			result.Errors++
		} else {
			result.Updated++
		}
	}

	result.Duration = time.Since(start)
	return result
}

// createSecret builds and creates a new Kubernetes Secret.
func (m *SecretMaterializer) createSecret(ctx context.Context, target KubeTarget, secret model.ManagedSecret, ns, name string) error {
	k8sSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   ns,
			Labels:      map[string]string{LabelManagedBy: LabelManagedByValue},
			Annotations: buildAnnotations(secret),
		},
		Data: toSecretData(secret.Data),
	}

	_, err := target.Client.CoreV1().Secrets(ns).Create(ctx, k8sSecret, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("create secret %s/%s: %w", ns, name, err)
	}
	return nil
}

// updateSecret overwrites data and merges annotations on an existing K8s Secret.
func (m *SecretMaterializer) updateSecret(ctx context.Context, target KubeTarget, secret model.ManagedSecret, existing *corev1.Secret) error {
	existing.Data = toSecretData(secret.Data)

	annotations := buildAnnotations(secret)
	if existing.Annotations == nil {
		existing.Annotations = make(map[string]string)
	}
	for k, v := range annotations {
		existing.Annotations[k] = v
	}

	_, err := target.Client.CoreV1().Secrets(existing.Namespace).Update(ctx, existing, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("update secret %s/%s: %w", existing.Namespace, existing.Name, err)
	}
	return nil
}

// markSecret annotates an existing K8s Secret with status and revoked-at
// without deleting it.
func (m *SecretMaterializer) markSecret(ctx context.Context, target KubeTarget, secret model.ManagedSecret) error {
	ns, name := resolveTargetLocation(secret)

	existing, err := target.Client.CoreV1().Secrets(ns).Get(ctx, name, metav1.GetOptions{})
	if k8serrors.IsNotFound(err) {
		// Nothing to mark — the K8s Secret was never materialized.
		return nil
	}
	if err != nil {
		return fmt.Errorf("get secret %s/%s for marking: %w", ns, name, err)
	}

	if existing.Annotations == nil {
		existing.Annotations = make(map[string]string)
	}
	existing.Annotations[AnnotationStatus] = secret.Status
	existing.Annotations[AnnotationVersion] = strconv.Itoa(secret.Version)
	if secret.Status == "revoked" {
		existing.Annotations[AnnotationRevokedAt] = time.Now().UTC().Format(time.RFC3339)
	}

	_, err = target.Client.CoreV1().Secrets(ns).Update(ctx, existing, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("mark secret %s/%s: %w", ns, name, err)
	}
	return nil
}

// resolveTargetLocation returns the namespace and name where the K8s Secret
// should be written. If the ManagedSecret metadata contains a
// "materialize" override, those values are used instead.
func resolveTargetLocation(secret model.ManagedSecret) (ns, name string) {
	ns = secret.Namespace
	name = secret.Name

	mat, ok := secret.Metadata["materialize"]
	if !ok {
		return ns, name
	}

	matMap, ok := mat.(map[string]any)
	if !ok {
		return ns, name
	}

	if v, ok := matMap["namespace"].(string); ok && v != "" {
		ns = v
	}
	if v, ok := matMap["name"].(string); ok && v != "" {
		name = v
	}
	return ns, name
}

// resolveTargetName returns the target cluster name from metadata or "local".
func resolveTargetName(secret model.ManagedSecret) string {
	mat, ok := secret.Metadata["materialize"]
	if !ok {
		return "local"
	}
	matMap, ok := mat.(map[string]any)
	if !ok {
		return "local"
	}
	if v, ok := matMap["target"].(string); ok && v != "" {
		return v
	}
	return "local"
}

// buildAnnotations returns the standard set of annotations for a managed secret.
func buildAnnotations(secret model.ManagedSecret) map[string]string {
	return map[string]string{
		AnnotationVersion:    strconv.Itoa(secret.Version),
		AnnotationSourceNS:   secret.Namespace,
		AnnotationSourceName: secret.Name,
		AnnotationLastSynced: time.Now().UTC().Format(time.RFC3339),
	}
}

// toSecretData converts a string map to the []byte map expected by K8s.
func toSecretData(data map[string]string) map[string][]byte {
	out := make(map[string][]byte, len(data))
	for k, v := range data {
		out[k] = []byte(v)
	}
	return out
}
