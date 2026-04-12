package reconciler

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ProductMaterializer converts Yggdrasil product manifests into Kubernetes
// ConfigMaps. Products represent deployable service groups. For now they are
// materialized as ConfigMaps so they are visible in K8s; actual Kustomize
// deployment is deferred to a future enhancement.
type ProductMaterializer struct{}

// Owns returns the resource kind this materializer manages.
func (m *ProductMaterializer) Owns() string {
	return "products"
}

// Materialize creates or updates a ConfigMap for the given product manifest.
func (m *ProductMaterializer) Materialize(ctx context.Context, target KubeTarget, resource any) error {
	manifest, ok := resource.(model.Manifest)
	if !ok {
		return fmt.Errorf("ProductMaterializer: expected model.Manifest, got %T", resource)
	}

	ns := productNamespace(manifest)
	name := productConfigMapName(manifest)

	specJSON, err := json.Marshal(manifest.Spec)
	if err != nil {
		return fmt.Errorf("marshal product spec: %w", err)
	}

	labels := map[string]string{
		LabelManagedBy: LabelManagedByValue,
		AnnotationKind: "product",
	}
	annotations := productAnnotations(manifest)

	existing, err := target.Client.CoreV1().ConfigMaps(ns).Get(ctx, name, metav1.GetOptions{})
	if k8serrors.IsNotFound(err) {
		cm := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:        name,
				Namespace:   ns,
				Labels:      labels,
				Annotations: annotations,
			},
			Data: map[string]string{
				"manifest.json": string(specJSON),
			},
		}
		_, cErr := target.Client.CoreV1().ConfigMaps(ns).Create(ctx, cm, metav1.CreateOptions{})
		if cErr != nil {
			return fmt.Errorf("create product configmap %s/%s: %w", ns, name, cErr)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("get product configmap %s/%s: %w", ns, name, err)
	}

	// Skip if already up-to-date.
	if existing.Annotations[AnnotationVersion] == strconv.Itoa(manifest.Version) {
		return nil
	}

	// Update existing ConfigMap.
	existing.Labels = labels
	if existing.Annotations == nil {
		existing.Annotations = make(map[string]string)
	}
	for k, v := range annotations {
		existing.Annotations[k] = v
	}
	if existing.Data == nil {
		existing.Data = make(map[string]string)
	}
	existing.Data["manifest.json"] = string(specJSON)

	_, err = target.Client.CoreV1().ConfigMaps(ns).Update(ctx, existing, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("update product configmap %s/%s: %w", ns, name, err)
	}
	return nil
}

// Reconcile lists active product manifests from the database and reconciles
// each against the corresponding ConfigMap.
func (m *ProductMaterializer) Reconcile(ctx context.Context, target KubeTarget, db *sql.DB) (ReconcileResult, error) {
	if db == nil {
		return ReconcileResult{Kind: "products", Timestamp: time.Now()}, nil
	}

	start := time.Now()
	result := ReconcileResult{
		Kind:      "products",
		Timestamp: start,
	}

	manifests, err := repository.ListManifests(ctx, db, model.ListManifestFilters{
		Kind:       "product",
		ActiveOnly: true,
	})
	if err != nil {
		return ReconcileResult{}, err
	}

	for _, manifest := range manifests {
		ns := productNamespace(manifest)
		name := productConfigMapName(manifest)

		existing, err := target.Client.CoreV1().ConfigMaps(ns).Get(ctx, name, metav1.GetOptions{})
		if k8serrors.IsNotFound(err) {
			if mErr := m.Materialize(ctx, target, manifest); mErr != nil {
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

		if existing.Annotations[AnnotationVersion] == strconv.Itoa(manifest.Version) {
			result.Skipped++
			continue
		}

		if mErr := m.Materialize(ctx, target, manifest); mErr != nil {
			result.Errors++
		} else {
			result.Updated++
		}
	}

	result.Duration = time.Since(start)
	return result, nil
}

// productConfigMapName returns the ConfigMap name for a product:
// ygg-product-{name}
func productConfigMapName(manifest model.Manifest) string {
	return fmt.Sprintf("ygg-product-%s", manifest.Metadata.Name)
}

// productNamespace returns the namespace where the product ConfigMap should
// live. Defaults to "dakasa" if the manifest has no namespace.
func productNamespace(manifest model.Manifest) string {
	if manifest.Metadata.Namespace != "" {
		return manifest.Metadata.Namespace
	}
	return "dakasa"
}

// productAnnotations returns the standard annotation set for a product ConfigMap.
func productAnnotations(manifest model.Manifest) map[string]string {
	return map[string]string{
		AnnotationVersion:    strconv.Itoa(manifest.Version),
		AnnotationSourceNS:   manifest.Metadata.Namespace,
		AnnotationSourceName: manifest.Metadata.Name,
		AnnotationLastSynced: time.Now().UTC().Format(time.RFC3339),
	}
}
