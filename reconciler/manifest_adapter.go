package reconciler

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// manifestManagedKinds lists the manifest kinds that ManifestMaterializer
// reconciles into ConfigMaps. Products have their own materializer; internal
// kinds like event, remediation_bundle, and remediation_contract are skipped.
var manifestManagedKinds = []string{
	"integration_instance",
	"workflow",
	"guardian_policy",
	"rbac",
	"surface",
}

// ManifestMaterializer converts Yggdrasil manifests into Kubernetes ConfigMaps.
type ManifestMaterializer struct{}

// Owns returns the resource kind this materializer manages.
func (m *ManifestMaterializer) Owns() string {
	return "manifests"
}

// Materialize creates or updates a ConfigMap for the given manifest.
func (m *ManifestMaterializer) Materialize(ctx context.Context, target KubeTarget, resource any) error {
	manifest, ok := resource.(model.Manifest)
	if !ok {
		return fmt.Errorf("ManifestMaterializer: expected model.Manifest, got %T", resource)
	}

	ns := manifestNamespace(manifest)
	name := manifestConfigMapName(manifest)

	specJSON, err := json.Marshal(manifest.Spec)
	if err != nil {
		return fmt.Errorf("marshal manifest spec: %w", err)
	}

	labels := map[string]string{
		LabelManagedBy: LabelManagedByValue,
		AnnotationKind: manifest.Kind,
	}
	annotations := manifestAnnotations(manifest)

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
			return fmt.Errorf("create configmap %s/%s: %w", ns, name, cErr)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("get configmap %s/%s: %w", ns, name, err)
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
		return fmt.Errorf("update configmap %s/%s: %w", ns, name, err)
	}
	return nil
}

// Reconcile lists active manifests for each managed kind from the database
// and reconciles each against the corresponding ConfigMap.
func (m *ManifestMaterializer) Reconcile(ctx context.Context, target KubeTarget, db *sql.DB) (ReconcileResult, error) {
	if db == nil {
		return ReconcileResult{Kind: "manifests", Timestamp: time.Now()}, nil
	}

	start := time.Now()
	result := ReconcileResult{
		Kind:      "manifests",
		Timestamp: start,
	}

	for _, kind := range manifestManagedKinds {
		manifests, err := repository.ListManifests(ctx, db, model.ListManifestFilters{
			Kind:       kind,
			ActiveOnly: true,
		})
		if err != nil {
			result.Errors++
			continue
		}

		for _, manifest := range manifests {
			ns := manifestNamespace(manifest)
			name := manifestConfigMapName(manifest)

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
	}

	result.Duration = time.Since(start)
	return result, nil
}

// manifestConfigMapName returns the ConfigMap name for a manifest:
// ygg-{kind}-{name}, with underscores replaced by hyphens (K8s DNS naming rules).
func manifestConfigMapName(manifest model.Manifest) string {
	kind := strings.ReplaceAll(manifest.Kind, "_", "-")
	return fmt.Sprintf("ygg-%s-%s", kind, manifest.Metadata.Name)
}

// manifestNamespace returns the namespace where the ConfigMap should live.
// Defaults to "dakasa" if the manifest has no namespace.
func manifestNamespace(manifest model.Manifest) string {
	if manifest.Metadata.Namespace != "" {
		return manifest.Metadata.Namespace
	}
	return "dakasa"
}

// manifestAnnotations returns the standard annotation set for a manifest ConfigMap.
func manifestAnnotations(manifest model.Manifest) map[string]string {
	return map[string]string{
		AnnotationVersion:    strconv.Itoa(manifest.Version),
		AnnotationSourceNS:   manifest.Metadata.Namespace,
		AnnotationSourceName: manifest.Metadata.Name,
		AnnotationLastSynced: time.Now().UTC().Format(time.RFC3339),
	}
}
