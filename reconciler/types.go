package reconciler

import (
	"context"
	"database/sql"
	"time"

	"k8s.io/client-go/kubernetes"
)

// Materializer converts a Yggdrasil resource into Kubernetes objects.
type Materializer interface {
	Materialize(ctx context.Context, target KubeTarget, resource any) error
	Reconcile(ctx context.Context, target KubeTarget, db *sql.DB) (ReconcileResult, error)
	Owns() string
}

// ReconcileEvent is a generic event that triggers reactive materialization
// for a specific resource kind.
type ReconcileEvent struct {
	Kind     string
	Resource any
}

// KubeTarget represents a Kubernetes cluster that the reconciler can write to.
type KubeTarget struct {
	Name    string
	Client  kubernetes.Interface
	IsLocal bool
}

// ReconcileResult summarizes one reconciliation pass.
type ReconcileResult struct {
	Kind      string
	Created   int
	Updated   int
	Skipped   int
	Errors    int
	Duration  time.Duration
	Timestamp time.Time
}

// Labels and annotations applied to managed K8s resources.
const (
	LabelManagedBy       = "yggdrasil.io/managed-by"
	LabelManagedByValue  = "yggdrasil-core"
	AnnotationVersion    = "yggdrasil.io/secret-version"
	AnnotationSourceNS   = "yggdrasil.io/source-namespace"
	AnnotationSourceName = "yggdrasil.io/source-name"
	AnnotationLastSynced = "yggdrasil.io/last-synced"
	AnnotationStatus     = "yggdrasil.io/status"
	AnnotationRevokedAt  = "yggdrasil.io/revoked-at"
	AnnotationKind       = "yggdrasil.io/kind"
)
