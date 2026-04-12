# Reconciler Secret Materializer — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a reconciliation engine to yggdrasil-core that materializes managed secrets as Kubernetes native Secrets, with reactive push on write and periodic reconcile loop.

**Architecture:** New `reconciler/` package with a generic `Materializer` interface. `SecretMaterializer` is the first concrete adapter. A `KubeClientPool` manages local (in-cluster) and remote (kubeconfig from managed secrets) clients. The reconciler registers as an addon (priority 40) and hooks into the existing HTTP API handlers for secret create/update/revoke.

**Tech Stack:** Go 1.25, k8s.io/client-go, k8s.io/api, k8s.io/apimachinery. Existing: PostgreSQL (lib/pq), zap logger, addons registry.

**Spec:** `docs/superpowers/specs/2026-04-12-reconciler-secret-materializer-design.md`

---

## File Map

| File | Action | Responsibility |
|------|--------|----------------|
| `reconciler/types.go` | Create | Materializer interface, KubeTarget, ReconcileResult, constants |
| `reconciler/kubeclient.go` | Create | KubeClientPool — local InCluster + remote from managed secrets |
| `reconciler/secret_adapter.go` | Create | SecretMaterializer — implements Materializer for K8s Secrets |
| `reconciler/secret_adapter_test.go` | Create | Unit tests with fake k8s client |
| `reconciler/loop.go` | Create | Engine — periodic reconcile goroutine + event channel |
| `reconciler/loop_test.go` | Create | Unit tests for reconcile loop logic |
| `addons/reconciler.go` | Create | Addon bootstrap (priority 40) — creates Engine, starts loop |
| `controllers/httpapi/server.go` | Modify | Add reconciler field to Server, wire into secret handlers, add materialize endpoints |
| `controllers/httpapi/reconciler_handlers.go` | Create | HTTP handlers for materialize/status endpoints |
| `controllers/httpapi/reconciler_handlers_test.go` | Create | Handler unit tests |
| `go.mod` | Modify | Add k8s.io/client-go, k8s.io/api, k8s.io/apimachinery |
| `platform/kube/clusterrole.yaml` | Create | RBAC ClusterRole + ClusterRoleBinding for secrets |

---

### Task 1: Add Kubernetes client-go dependencies

**Files:**
- Modify: `go.mod`

- [ ] **Step 1: Add k8s dependencies**

```bash
cd /Users/dakasa/projects/yggdrasil/yggdrasil-core
go get k8s.io/client-go@latest k8s.io/api@latest k8s.io/apimachinery@latest
```

- [ ] **Step 2: Verify build still compiles**

```bash
go build ./...
```

Expected: no errors (deps added but not yet used).

- [ ] **Step 3: Commit**

```bash
git add go.mod go.sum
git commit -m "🔧 Add k8s client-go dependencies for reconciler"
```

---

### Task 2: Create reconciler types

**Files:**
- Create: `reconciler/types.go`

- [ ] **Step 1: Create the types file**

```go
package reconciler

import (
	"context"
	"time"

	"k8s.io/client-go/kubernetes"
)

// Materializer converts a Yggdrasil resource into Kubernetes objects.
type Materializer interface {
	Materialize(ctx context.Context, target KubeTarget, resource any) error
	Reconcile(ctx context.Context, target KubeTarget) (ReconcileResult, error)
	Owns() string
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
	LabelManagedBy          = "yggdrasil.io/managed-by"
	LabelManagedByValue     = "yggdrasil-core"
	AnnotationVersion       = "yggdrasil.io/secret-version"
	AnnotationSourceNS      = "yggdrasil.io/source-namespace"
	AnnotationSourceName    = "yggdrasil.io/source-name"
	AnnotationLastSynced    = "yggdrasil.io/last-synced"
	AnnotationStatus        = "yggdrasil.io/status"
	AnnotationRevokedAt     = "yggdrasil.io/revoked-at"
)
```

- [ ] **Step 2: Verify it compiles**

```bash
go build ./reconciler/...
```

- [ ] **Step 3: Commit**

```bash
git add reconciler/types.go
git commit -m "✨ Add reconciler types — Materializer interface, KubeTarget, constants"
```

---

### Task 3: Create KubeClientPool

**Files:**
- Create: `reconciler/kubeclient.go`

- [ ] **Step 1: Create the KubeClientPool**

```go
package reconciler

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"go.uber.org/zap"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// KubeClientPool manages Kubernetes clients for local and remote clusters.
type KubeClientPool struct {
	db     *sql.DB
	logger *zap.Logger

	mu      sync.RWMutex
	local   *KubeTarget
	remotes map[string]*cachedTarget
}

type cachedTarget struct {
	target    KubeTarget
	expiresAt time.Time
}

const remoteCacheTTL = 5 * time.Minute

// NewKubeClientPool initializes the pool. If inCluster is true, the local
// target is created from the pod's ServiceAccount. If false (tests), local
// is nil and must be set manually.
func NewKubeClientPool(db *sql.DB, logger *zap.Logger, inCluster bool) (*KubeClientPool, error) {
	pool := &KubeClientPool{
		db:      db,
		logger:  logger,
		remotes: make(map[string]*cachedTarget),
	}

	if inCluster {
		config, err := rest.InClusterConfig()
		if err != nil {
			return nil, fmt.Errorf("in-cluster config: %w", err)
		}
		client, err := kubernetes.NewForConfig(config)
		if err != nil {
			return nil, fmt.Errorf("in-cluster client: %w", err)
		}
		pool.local = &KubeTarget{
			Name:    "local",
			Client:  client,
			IsLocal: true,
		}
		logger.Info("kube client pool initialized", zap.String("local", "in-cluster"))
	}

	return pool, nil
}

// Local returns the in-cluster target.
func (p *KubeClientPool) Local() (*KubeTarget, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.local == nil {
		return nil, fmt.Errorf("local kube target not available")
	}
	return p.local, nil
}

// SetLocal overrides the local target (used in tests).
func (p *KubeClientPool) SetLocal(target KubeTarget) {
	p.mu.Lock()
	defer p.mu.Unlock()
	target.IsLocal = true
	target.Name = "local"
	p.local = &target
}

// Target returns the KubeTarget for the given name. "local" returns the
// in-cluster client. Anything else looks up a managed secret named
// "global/kubeconfig-{name}" and builds a client from it.
func (p *KubeClientPool) Target(ctx context.Context, name string) (*KubeTarget, error) {
	if name == "" || name == "local" {
		return p.Local()
	}

	p.mu.RLock()
	cached, ok := p.remotes[name]
	p.mu.RUnlock()
	if ok && time.Now().Before(cached.expiresAt) {
		return &cached.target, nil
	}

	secret, err := repository.GetManagedSecret(ctx, p.db, model.GetManagedSecretRequest{
		Namespace: "global",
		Name:      "kubeconfig-" + name,
	})
	if err != nil {
		return nil, fmt.Errorf("resolve kubeconfig for target %q: %w", name, err)
	}

	kubeconfig, ok := secret.Data["kubeconfig"]
	if !ok {
		return nil, fmt.Errorf("managed secret global/kubeconfig-%s has no 'kubeconfig' key", name)
	}

	config, err := clientcmd.RESTConfigFromKubeConfig([]byte(kubeconfig))
	if err != nil {
		return nil, fmt.Errorf("parse kubeconfig for target %q: %w", name, err)
	}

	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("build client for target %q: %w", name, err)
	}

	target := KubeTarget{
		Name:    name,
		Client:  client,
		IsLocal: false,
	}

	p.mu.Lock()
	p.remotes[name] = &cachedTarget{target: target, expiresAt: time.Now().Add(remoteCacheTTL)}
	p.mu.Unlock()

	p.logger.Info("remote kube target cached", zap.String("target", name))
	return &target, nil
}
```

- [ ] **Step 2: Verify it compiles**

```bash
go build ./reconciler/...
```

- [ ] **Step 3: Commit**

```bash
git add reconciler/kubeclient.go
git commit -m "✨ Add KubeClientPool — local InCluster + remote from managed secrets"
```

---

### Task 4: Create SecretMaterializer with tests (TDD)

**Files:**
- Create: `reconciler/secret_adapter_test.go`
- Create: `reconciler/secret_adapter.go`

- [ ] **Step 1: Write the failing tests**

```go
package reconciler

import (
	"context"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestSecretMaterializer_Materialize_CreatesNewSecret(t *testing.T) {
	client := fake.NewSimpleClientset()
	target := KubeTarget{Name: "local", Client: client, IsLocal: true}

	m := &SecretMaterializer{}

	secret := model.ManagedSecret{
		Namespace: "dakasa",
		Name:      "dakasa-hall-secrets",
		Status:    "active",
		Version:   1,
		Data:      map[string]string{"DATABASE_URL": "postgres://host/db", "API_KEY": "sk_test_123"},
	}

	err := m.Materialize(context.Background(), target, secret)
	if err != nil {
		t.Fatalf("Materialize() error = %v", err)
	}

	k8sSecret, err := client.CoreV1().Secrets("dakasa").Get(context.Background(), "dakasa-hall-secrets", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("K8s secret not created: %v", err)
	}

	if string(k8sSecret.Data["DATABASE_URL"]) != "postgres://host/db" {
		t.Errorf("DATABASE_URL = %q, want %q", string(k8sSecret.Data["DATABASE_URL"]), "postgres://host/db")
	}
	if string(k8sSecret.Data["API_KEY"]) != "sk_test_123" {
		t.Errorf("API_KEY = %q, want %q", string(k8sSecret.Data["API_KEY"]), "sk_test_123")
	}
	if k8sSecret.Labels[LabelManagedBy] != LabelManagedByValue {
		t.Errorf("label %s = %q, want %q", LabelManagedBy, k8sSecret.Labels[LabelManagedBy], LabelManagedByValue)
	}
	if k8sSecret.Annotations[AnnotationVersion] != "1" {
		t.Errorf("annotation version = %q, want %q", k8sSecret.Annotations[AnnotationVersion], "1")
	}
}

func TestSecretMaterializer_Materialize_UpdatesExistingSecret(t *testing.T) {
	existing := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "dakasa-hall-secrets",
			Namespace: "dakasa",
			Labels:    map[string]string{LabelManagedBy: LabelManagedByValue},
			Annotations: map[string]string{
				AnnotationVersion:    "1",
				AnnotationSourceNS:   "dakasa",
				AnnotationSourceName: "dakasa-hall-secrets",
			},
		},
		Data: map[string][]byte{"DATABASE_URL": []byte("old-value")},
	}
	client := fake.NewSimpleClientset(existing)
	target := KubeTarget{Name: "local", Client: client, IsLocal: true}

	m := &SecretMaterializer{}

	secret := model.ManagedSecret{
		Namespace: "dakasa",
		Name:      "dakasa-hall-secrets",
		Status:    "active",
		Version:   2,
		Data:      map[string]string{"DATABASE_URL": "new-value"},
	}

	err := m.Materialize(context.Background(), target, secret)
	if err != nil {
		t.Fatalf("Materialize() error = %v", err)
	}

	k8sSecret, _ := client.CoreV1().Secrets("dakasa").Get(context.Background(), "dakasa-hall-secrets", metav1.GetOptions{})
	if string(k8sSecret.Data["DATABASE_URL"]) != "new-value" {
		t.Errorf("DATABASE_URL = %q, want %q", string(k8sSecret.Data["DATABASE_URL"]), "new-value")
	}
	if k8sSecret.Annotations[AnnotationVersion] != "2" {
		t.Errorf("annotation version = %q, want %q", k8sSecret.Annotations[AnnotationVersion], "2")
	}
}

func TestSecretMaterializer_Materialize_SkipsUpToDate(t *testing.T) {
	existing := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-secret",
			Namespace: "dakasa",
			Labels:    map[string]string{LabelManagedBy: LabelManagedByValue},
			Annotations: map[string]string{
				AnnotationVersion:    "5",
				AnnotationSourceNS:   "dakasa",
				AnnotationSourceName: "my-secret",
			},
		},
		Data: map[string][]byte{"KEY": []byte("value")},
	}
	client := fake.NewSimpleClientset(existing)
	target := KubeTarget{Name: "local", Client: client, IsLocal: true}

	m := &SecretMaterializer{}

	secret := model.ManagedSecret{
		Namespace: "dakasa",
		Name:      "my-secret",
		Status:    "active",
		Version:   5,
		Data:      map[string]string{"KEY": "value"},
	}

	err := m.Materialize(context.Background(), target, secret)
	if err != nil {
		t.Fatalf("Materialize() error = %v", err)
	}

	// Secret should still be version 5 — no update needed
	k8sSecret, _ := client.CoreV1().Secrets("dakasa").Get(context.Background(), "my-secret", metav1.GetOptions{})
	if k8sSecret.Annotations[AnnotationVersion] != "5" {
		t.Errorf("should not have updated, version = %s", k8sSecret.Annotations[AnnotationVersion])
	}
}

func TestSecretMaterializer_Materialize_UsesMetadataOverride(t *testing.T) {
	client := fake.NewSimpleClientset()
	target := KubeTarget{Name: "local", Client: client, IsLocal: true}

	m := &SecretMaterializer{}

	secret := model.ManagedSecret{
		Namespace: "global",
		Name:      "stripe-keys",
		Status:    "active",
		Version:   1,
		Data:      map[string]string{"STRIPE_API_KEY": "sk_live_xxx"},
		Metadata: map[string]any{
			"materialize": map[string]any{
				"namespace": "dakasa",
				"name":      "enterprise-payments-api-secrets",
			},
		},
	}

	err := m.Materialize(context.Background(), target, secret)
	if err != nil {
		t.Fatalf("Materialize() error = %v", err)
	}

	// Should be created in the override namespace/name
	k8sSecret, err := client.CoreV1().Secrets("dakasa").Get(context.Background(), "enterprise-payments-api-secrets", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("K8s secret not created at override location: %v", err)
	}
	if string(k8sSecret.Data["STRIPE_API_KEY"]) != "sk_live_xxx" {
		t.Errorf("STRIPE_API_KEY mismatch")
	}
	if k8sSecret.Annotations[AnnotationSourceNS] != "global" {
		t.Errorf("source namespace should be 'global', got %q", k8sSecret.Annotations[AnnotationSourceNS])
	}
}

func TestSecretMaterializer_MarkRevoked(t *testing.T) {
	existing := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "old-secret",
			Namespace: "dakasa",
			Labels:    map[string]string{LabelManagedBy: LabelManagedByValue},
			Annotations: map[string]string{
				AnnotationVersion:    "1",
				AnnotationSourceNS:   "dakasa",
				AnnotationSourceName: "old-secret",
			},
		},
		Data: map[string][]byte{"KEY": []byte("value")},
	}
	client := fake.NewSimpleClientset(existing)
	target := KubeTarget{Name: "local", Client: client, IsLocal: true}

	m := &SecretMaterializer{}

	secret := model.ManagedSecret{
		Namespace: "dakasa",
		Name:      "old-secret",
		Status:    "revoked",
		Version:   2,
	}

	err := m.Materialize(context.Background(), target, secret)
	if err != nil {
		t.Fatalf("Materialize() error = %v", err)
	}

	k8sSecret, _ := client.CoreV1().Secrets("dakasa").Get(context.Background(), "old-secret", metav1.GetOptions{})
	if k8sSecret.Annotations[AnnotationStatus] != "revoked" {
		t.Errorf("status annotation = %q, want 'revoked'", k8sSecret.Annotations[AnnotationStatus])
	}
	if k8sSecret.Annotations[AnnotationRevokedAt] == "" {
		t.Error("revoked-at annotation should be set")
	}
}

func TestSecretMaterializer_Owns(t *testing.T) {
	m := &SecretMaterializer{}
	if m.Owns() != "secrets" {
		t.Errorf("Owns() = %q, want 'secrets'", m.Owns())
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
go test ./reconciler/... -v -count=1
```

Expected: FAIL — `SecretMaterializer` not defined.

- [ ] **Step 3: Implement SecretMaterializer**

```go
package reconciler

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// SecretMaterializer materializes Yggdrasil managed secrets as K8s Secrets.
type SecretMaterializer struct{}

func (m *SecretMaterializer) Owns() string { return "secrets" }

func (m *SecretMaterializer) Materialize(ctx context.Context, target KubeTarget, resource any) error {
	secret, ok := resource.(model.ManagedSecret)
	if !ok {
		return fmt.Errorf("expected model.ManagedSecret, got %T", resource)
	}

	k8sNS, k8sName := resolveTargetLocation(secret)

	if secret.Status == "revoked" || secret.Status == "disabled" {
		return m.markSecret(ctx, target, k8sNS, k8sName, secret)
	}

	existing, err := target.Client.CoreV1().Secrets(k8sNS).Get(ctx, k8sName, metav1.GetOptions{})
	if k8serrors.IsNotFound(err) {
		return m.createSecret(ctx, target, k8sNS, k8sName, secret)
	}
	if err != nil {
		return fmt.Errorf("get k8s secret %s/%s: %w", k8sNS, k8sName, err)
	}

	existingVersion := existing.Annotations[AnnotationVersion]
	if existingVersion == strconv.Itoa(secret.Version) {
		return nil // up to date
	}

	return m.updateSecret(ctx, target, existing, secret)
}

func (m *SecretMaterializer) Reconcile(ctx context.Context, target KubeTarget) (ReconcileResult, error) {
	// Implemented in Task 5 (loop.go calls this with the full secret list)
	return ReconcileResult{Kind: "secrets", Timestamp: time.Now()}, nil
}

func (m *SecretMaterializer) createSecret(ctx context.Context, target KubeTarget, ns, name string, secret model.ManagedSecret) error {
	k8sSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   ns,
			Labels:      map[string]string{LabelManagedBy: LabelManagedByValue},
			Annotations: buildAnnotations(secret),
		},
		Type: corev1.SecretTypeOpaque,
		Data: toSecretData(secret.Data),
	}

	_, err := target.Client.CoreV1().Secrets(ns).Create(ctx, k8sSecret, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("create k8s secret %s/%s: %w", ns, name, err)
	}
	return nil
}

func (m *SecretMaterializer) updateSecret(ctx context.Context, target KubeTarget, existing *corev1.Secret, secret model.ManagedSecret) error {
	existing.Data = toSecretData(secret.Data)
	existing.Annotations = mergeAnnotations(existing.Annotations, buildAnnotations(secret))

	_, err := target.Client.CoreV1().Secrets(existing.Namespace).Update(ctx, existing, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("update k8s secret %s/%s: %w", existing.Namespace, existing.Name, err)
	}
	return nil
}

func (m *SecretMaterializer) markSecret(ctx context.Context, target KubeTarget, ns, name string, secret model.ManagedSecret) error {
	existing, err := target.Client.CoreV1().Secrets(ns).Get(ctx, name, metav1.GetOptions{})
	if k8serrors.IsNotFound(err) {
		return nil // nothing to mark
	}
	if err != nil {
		return fmt.Errorf("get k8s secret for marking %s/%s: %w", ns, name, err)
	}

	if existing.Labels[LabelManagedBy] != LabelManagedByValue {
		return nil // not ours
	}

	if existing.Annotations == nil {
		existing.Annotations = map[string]string{}
	}
	existing.Annotations[AnnotationStatus] = secret.Status
	existing.Annotations[AnnotationRevokedAt] = time.Now().UTC().Format(time.RFC3339)

	_, err = target.Client.CoreV1().Secrets(ns).Update(ctx, existing, metav1.UpdateOptions{})
	return err
}

func resolveTargetLocation(secret model.ManagedSecret) (ns, name string) {
	ns = secret.Namespace
	name = secret.Name

	mat, ok := secret.Metadata["materialize"]
	if !ok {
		return
	}

	matMap, ok := mat.(map[string]any)
	if !ok {
		return
	}

	if v, ok := matMap["namespace"].(string); ok && v != "" {
		ns = v
	}
	if v, ok := matMap["name"].(string); ok && v != "" {
		name = v
	}
	return
}

func resolveTargetName(secret model.ManagedSecret) string {
	if mat, ok := secret.Metadata["materialize"]; ok {
		if matMap, ok := mat.(map[string]any); ok {
			if v, ok := matMap["target"].(string); ok && v != "" {
				return v
			}
		}
	}
	return "local"
}

func buildAnnotations(secret model.ManagedSecret) map[string]string {
	return map[string]string{
		AnnotationVersion:    strconv.Itoa(secret.Version),
		AnnotationSourceNS:   secret.Namespace,
		AnnotationSourceName: secret.Name,
		AnnotationLastSynced: time.Now().UTC().Format(time.RFC3339),
	}
}

func mergeAnnotations(existing, incoming map[string]string) map[string]string {
	merged := make(map[string]string, len(existing)+len(incoming))
	for k, v := range existing {
		merged[k] = v
	}
	for k, v := range incoming {
		merged[k] = v
	}
	return merged
}

func toSecretData(data map[string]string) map[string][]byte {
	out := make(map[string][]byte, len(data))
	for k, v := range data {
		out[k] = []byte(v)
	}
	return out
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
go test ./reconciler/... -v -count=1
```

Expected: all 6 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add reconciler/secret_adapter.go reconciler/secret_adapter_test.go
git commit -m "✨ Add SecretMaterializer — creates/updates/marks K8s Secrets from managed secrets"
```

---

### Task 5: Create reconciliation Engine and loop

**Files:**
- Create: `reconciler/loop.go`
- Create: `reconciler/loop_test.go`

- [ ] **Step 1: Write failing test**

```go
package reconciler

import (
	"context"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestEngine_ReconcileSecrets_CreatesMissing(t *testing.T) {
	client := fake.NewSimpleClientset()
	pool := &KubeClientPool{remotes: make(map[string]*cachedTarget)}
	pool.SetLocal(KubeTarget{Client: client})

	secrets := []model.ManagedSecret{
		{Namespace: "dakasa", Name: "svc-a", Status: "active", Version: 1, Data: map[string]string{"KEY": "val"}},
		{Namespace: "dakasa", Name: "svc-b", Status: "active", Version: 1, Data: map[string]string{"KEY": "val"}},
	}

	engine := NewEngine(pool, nil, nil)
	result := engine.reconcileSecretList(context.Background(), secrets)

	if result.Created != 2 {
		t.Errorf("Created = %d, want 2", result.Created)
	}

	_, err := client.CoreV1().Secrets("dakasa").Get(context.Background(), "svc-a", metav1.GetOptions{})
	if err != nil {
		t.Errorf("svc-a not created: %v", err)
	}
	_, err = client.CoreV1().Secrets("dakasa").Get(context.Background(), "svc-b", metav1.GetOptions{})
	if err != nil {
		t.Errorf("svc-b not created: %v", err)
	}
}

func TestEngine_ReconcileSecrets_SkipsUpToDate(t *testing.T) {
	client := fake.NewSimpleClientset()
	pool := &KubeClientPool{remotes: make(map[string]*cachedTarget)}
	pool.SetLocal(KubeTarget{Client: client})

	secrets := []model.ManagedSecret{
		{Namespace: "dakasa", Name: "svc-a", Status: "active", Version: 1, Data: map[string]string{"KEY": "val"}},
	}

	engine := NewEngine(pool, nil, nil)

	// First pass: create
	r1 := engine.reconcileSecretList(context.Background(), secrets)
	if r1.Created != 1 {
		t.Fatalf("first pass Created = %d, want 1", r1.Created)
	}

	// Second pass: skip
	r2 := engine.reconcileSecretList(context.Background(), secrets)
	if r2.Skipped != 1 {
		t.Errorf("second pass Skipped = %d, want 1", r2.Skipped)
	}
	if r2.Created != 0 || r2.Updated != 0 {
		t.Errorf("second pass should have 0 creates/updates, got %d/%d", r2.Created, r2.Updated)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
go test ./reconciler/... -run TestEngine -v -count=1
```

Expected: FAIL — `NewEngine` not defined.

- [ ] **Step 3: Implement Engine and loop**

```go
package reconciler

import (
	"context"
	"database/sql"
	"os"
	"strconv"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"go.uber.org/zap"
)

// Engine runs the reconciliation loop and dispatches materialization events.
type Engine struct {
	pool      *KubeClientPool
	db        *sql.DB
	logger    *zap.Logger
	secrets   *SecretMaterializer
	eventCh   chan model.ManagedSecret
	lastResult ReconcileResult
}

// NewEngine creates a new reconciler engine.
func NewEngine(pool *KubeClientPool, db *sql.DB, logger *zap.Logger) *Engine {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &Engine{
		pool:    pool,
		db:      db,
		logger:  logger,
		secrets: &SecretMaterializer{},
		eventCh: make(chan model.ManagedSecret, 64),
	}
}

// MaterializeSecret pushes one secret reactively (called from HTTP handlers).
func (e *Engine) MaterializeSecret(ctx context.Context, secret model.ManagedSecret) error {
	targetName := resolveTargetName(secret)
	target, err := e.pool.Target(ctx, targetName)
	if err != nil {
		e.logger.Warn("materialize: resolve target failed", zap.String("target", targetName), zap.Error(err))
		return err
	}
	return e.secrets.Materialize(ctx, *target, secret)
}

// NotifyChange queues a secret for reactive materialization (non-blocking).
func (e *Engine) NotifyChange(secret model.ManagedSecret) {
	select {
	case e.eventCh <- secret:
	default:
		e.logger.Warn("reconciler event channel full, dropping event",
			zap.String("secret", secret.Namespace+"/"+secret.Name))
	}
}

// LastResult returns the result of the most recent reconciliation pass.
func (e *Engine) LastResult() ReconcileResult { return e.lastResult }

// Run starts the reconciliation loop. Blocks until ctx is cancelled.
func (e *Engine) Run(ctx context.Context) {
	interval := reconcileInterval()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	e.logger.Info("reconciler loop started", zap.Duration("interval", interval))

	for {
		select {
		case <-ctx.Done():
			e.logger.Info("reconciler loop stopped")
			return

		case secret := <-e.eventCh:
			if err := e.MaterializeSecret(ctx, secret); err != nil {
				e.logger.Error("reactive materialize failed",
					zap.String("secret", secret.Namespace+"/"+secret.Name),
					zap.Error(err))
			} else {
				e.logger.Info("reactive materialize ok",
					zap.String("secret", secret.Namespace+"/"+secret.Name),
					zap.Int("version", secret.Version))
			}

		case <-ticker.C:
			e.runFullReconcile(ctx)
		}
	}
}

func (e *Engine) runFullReconcile(ctx context.Context) {
	if e.db == nil {
		return
	}

	secrets, err := repository.ListManagedSecrets(ctx, e.db, model.ListManagedSecretsRequest{Status: "active"})
	if err != nil {
		e.logger.Error("reconcile: list secrets failed", zap.Error(err))
		return
	}

	result := e.reconcileSecretList(ctx, secrets)
	e.lastResult = result

	if result.Created > 0 || result.Updated > 0 || result.Errors > 0 {
		e.logger.Info("reconcile pass complete",
			zap.Int("created", result.Created),
			zap.Int("updated", result.Updated),
			zap.Int("skipped", result.Skipped),
			zap.Int("errors", result.Errors),
			zap.Duration("duration", result.Duration))
	}
}

func (e *Engine) reconcileSecretList(ctx context.Context, secrets []model.ManagedSecret) ReconcileResult {
	start := time.Now()
	result := ReconcileResult{Kind: "secrets", Timestamp: start}

	for _, secret := range secrets {
		targetName := resolveTargetName(secret)
		target, err := e.pool.Target(ctx, targetName)
		if err != nil {
			result.Errors++
			continue
		}

		k8sNS, k8sName := resolveTargetLocation(secret)
		existing, err := target.Client.CoreV1().Secrets(k8sNS).Get(ctx, k8sName, metav1.GetOptions{})

		if err != nil {
			// Not found — create
			if err := e.secrets.Materialize(ctx, *target, secret); err != nil {
				result.Errors++
			} else {
				result.Created++
			}
			continue
		}

		existingVersion := existing.Annotations[AnnotationVersion]
		if existingVersion == strconv.Itoa(secret.Version) {
			result.Skipped++
			continue
		}

		if err := e.secrets.Materialize(ctx, *target, secret); err != nil {
			result.Errors++
		} else {
			result.Updated++
		}
	}

	result.Duration = time.Since(start)
	return result
}

func reconcileInterval() time.Duration {
	raw := os.Getenv("RECONCILE_INTERVAL")
	if raw == "" {
		return 60 * time.Second
	}
	seconds, err := strconv.Atoi(raw)
	if err != nil || seconds < 5 {
		return 60 * time.Second
	}
	return time.Duration(seconds) * time.Second
}
```

Note: add the missing import to loop.go:

```go
import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
go test ./reconciler/... -v -count=1
```

Expected: all 8 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add reconciler/loop.go reconciler/loop_test.go
git commit -m "✨ Add reconciler Engine — periodic loop + reactive event channel"
```

---

### Task 6: Create reconciler addon

**Files:**
- Create: `addons/reconciler.go`

- [ ] **Step 1: Create the addon**

```go
package addons

import (
	"context"
	"os"
	"strings"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/runtime"
	"github.com/dakasa-yggdrasil/yggdrasil-core/reconciler"
	"go.uber.org/zap"
)

func init() {
	Register("reconciler", bootstrapReconciler, 40)
}

func bootstrapReconciler(ctx context.Context, app *runtime.ServiceApp) error {
	db, ok := Postgres(app)
	if !ok {
		return nil // reconciler is optional if postgres is not available
	}

	logger, _ := Logger(app)
	if logger == nil {
		logger = zap.NewNop()
	}

	enabled := strings.ToLower(os.Getenv("RECONCILE_ENABLED"))
	if enabled == "false" || enabled == "0" {
		logger.Info("reconciler disabled via RECONCILE_ENABLED")
		return nil
	}

	inCluster := strings.ToLower(os.Getenv("KUBE_IN_CLUSTER")) != "false"

	pool, err := reconciler.NewKubeClientPool(db, logger, inCluster)
	if err != nil {
		logger.Warn("reconciler: kube client pool failed, running without reconciler", zap.Error(err))
		return nil // non-fatal — yggdrasil still works, just no materialization
	}

	engine := reconciler.NewEngine(pool, db, logger)

	loopCtx, cancelLoop := context.WithCancel(context.Background())
	go engine.Run(loopCtx)

	app.SetResource("reconciler", engine)
	app.RegisterCloser(func(context.Context) error {
		cancelLoop()
		return nil
	})

	logger.Info("reconciler addon started")
	return nil
}

// Reconciler returns the shared engine when the addon is installed.
func Reconciler(app *runtime.ServiceApp) (*reconciler.Engine, bool) {
	resource, ok := app.Resource("reconciler")
	if !ok {
		return nil, false
	}
	engine, ok := resource.(*reconciler.Engine)
	return engine, ok
}
```

- [ ] **Step 2: Verify it compiles**

```bash
go build ./...
```

- [ ] **Step 3: Commit**

```bash
git add addons/reconciler.go
git commit -m "✨ Add reconciler addon — bootstraps Engine at priority 40"
```

---

### Task 7: Wire reconciler into HTTP API

**Files:**
- Create: `controllers/httpapi/reconciler_handlers.go`
- Modify: `controllers/httpapi/server.go`

- [ ] **Step 1: Create reconciler HTTP handlers**

```go
package httpapi

import (
	"net/http"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/reconciler"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

func (s *Server) handleMaterializeOne(w http.ResponseWriter, r *http.Request) {
	if s.reconciler == nil {
		writeJSON(w, http.StatusServiceUnavailable, errorResponse{Error: "reconciler not available"})
		return
	}

	ns := r.PathValue("namespace")
	name := r.PathValue("name")

	secret, err := repository.GetManagedSecret(r.Context(), s.db, model.GetManagedSecretRequest{
		Namespace: ns,
		Name:      name,
	})
	if err != nil {
		writeMappedError(w, err)
		return
	}

	if err := s.reconciler.MaterializeSecret(r.Context(), secret); err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"materialized": true,
		"secret":       model.BuildManagedSecretView(secret, false),
	})
}

func (s *Server) handleMaterializeAll(w http.ResponseWriter, r *http.Request) {
	if s.reconciler == nil {
		writeJSON(w, http.StatusServiceUnavailable, errorResponse{Error: "reconciler not available"})
		return
	}

	secrets, err := repository.ListManagedSecrets(r.Context(), s.db, model.ListManagedSecretsRequest{
		Status: "active",
	})
	if err != nil {
		writeMappedError(w, err)
		return
	}

	var results []map[string]any
	errCount := 0
	for _, secret := range secrets {
		if err := s.reconciler.MaterializeSecret(r.Context(), secret); err != nil {
			results = append(results, map[string]any{
				"secret": secret.Namespace + "/" + secret.Name,
				"error":  err.Error(),
			})
			errCount++
		} else {
			results = append(results, map[string]any{
				"secret":       secret.Namespace + "/" + secret.Name,
				"materialized": true,
			})
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"total":   len(secrets),
		"errors":  errCount,
		"results": results,
	})
}

func (s *Server) handleReconcilerStatus(w http.ResponseWriter, r *http.Request) {
	if s.reconciler == nil {
		writeJSON(w, http.StatusServiceUnavailable, errorResponse{Error: "reconciler not available"})
		return
	}

	result := s.reconciler.LastResult()
	writeJSON(w, http.StatusOK, map[string]any{
		"last_reconcile": map[string]any{
			"kind":      result.Kind,
			"created":   result.Created,
			"updated":   result.Updated,
			"skipped":   result.Skipped,
			"errors":    result.Errors,
			"duration":  result.Duration.String(),
			"timestamp": result.Timestamp,
		},
	})
}

// materializeAfterWrite calls the reconciler reactively after a secret write.
// Errors are logged but do not fail the HTTP response (the DB write already succeeded).
func (s *Server) materializeAfterWrite(secret model.ManagedSecret) {
	if s.reconciler == nil {
		return
	}
	s.reconciler.NotifyChange(secret)
}
```

- [ ] **Step 2: Modify server.go — add reconciler field and wire endpoints**

In `server.go`, add the `reconciler` field to the `Server` struct:

```go
// Server exposes the synchronous HTTP surface of yggdrasil-core.
type Server struct {
	serviceName string
	db          *sql.DB
	rabbitmq    *amqp.Connection
	logger      *zap.Logger
	reconciler  *reconciler.Engine
}
```

Update the `New` function signature to accept an optional reconciler:

```go
func New(serviceName string, db *sql.DB, conn *amqp.Connection, logger *zap.Logger, opts ...ServerOption) (http.Handler, error) {
```

Add options pattern:

```go
// ServerOption configures the HTTP server.
type ServerOption func(*Server)

// WithReconciler attaches a reconciler engine to the server.
func WithReconciler(engine *reconciler.Engine) ServerOption {
	return func(s *Server) {
		s.reconciler = engine
	}
}
```

Apply options in `New`:

```go
server := &Server{
	serviceName: serviceName,
	db:          db,
	rabbitmq:    conn,
	logger:      logger,
}
for _, opt := range opts {
	opt(server)
}
```

Register new routes (add after the existing secrets routes):

```go
mux.HandleFunc("POST /api/v1/secrets/{namespace}/{name}/materialize", server.handleMaterializeOne)
mux.HandleFunc("POST /api/v1/secrets/materialize-all", server.handleMaterializeAll)
mux.HandleFunc("GET /api/v1/reconciler/status", server.handleReconcilerStatus)
// console mirrors
mux.HandleFunc("POST /api/v1/console/secrets/{namespace}/{name}/materialize", server.handleMaterializeOne)
mux.HandleFunc("POST /api/v1/console/secrets/materialize-all", server.handleMaterializeAll)
mux.HandleFunc("GET /api/v1/console/reconciler/status", server.handleReconcilerStatus)
```

- [ ] **Step 3: Hook materializeAfterWrite into existing handlers**

In `handleManagedSecretCreate` (line ~486), after the successful upsert, add:

```go
secret, err := repository.UpsertManagedSecret(r.Context(), s.db, req)
if err != nil {
	writeMappedError(w, err)
	return
}

s.materializeAfterWrite(secret) // ← ADD THIS LINE

writeJSON(w, http.StatusCreated, map[string]any{
```

In `handleManagedSecretRotate` (line ~504), after the successful rotate:

```go
s.materializeAfterWrite(secret) // ← ADD after rotate succeeds
```

In `handleManagedSecretDisable` and `handleManagedSecretRevoke`, same pattern:

```go
s.materializeAfterWrite(secret) // ← ADD after disable/revoke succeeds
```

- [ ] **Step 4: Update addons/http.go to pass reconciler option**

In `addons/http.go`, update `bootstrapHTTP` to pass the reconciler if available:

```go
func bootstrapHTTP(_ context.Context, app *runtime.ServiceApp) error {
	db, ok := Postgres(app)
	if !ok {
		return fmt.Errorf("postgres addon is not available")
	}

	conn, _ := RabbitMQ(app)
	logger, _ := Logger(app)
	if logger == nil {
		logger = zap.NewNop()
	}

	var opts []httpapi.ServerOption
	if engine, ok := Reconciler(app); ok {
		opts = append(opts, httpapi.WithReconciler(engine))
	}

	handler, err := httpapi.New(app.ServiceName, db, conn, logger, opts...)
```

- [ ] **Step 5: Verify it compiles and tests pass**

```bash
go build ./...
go test ./... -count=1
```

- [ ] **Step 6: Commit**

```bash
git add controllers/httpapi/reconciler_handlers.go controllers/httpapi/server.go addons/http.go
git commit -m "✨ Wire reconciler into HTTP API — materialize endpoints + reactive hooks"
```

---

### Task 8: Add RBAC manifest

**Files:**
- Create: `platform/kube/reconciler-rbac.yaml`

- [ ] **Step 1: Create RBAC manifest**

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: yggdrasil-reconciler
  labels:
    app: yggdrasil
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get", "list", "create", "update", "patch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: yggdrasil-reconciler
  labels:
    app: yggdrasil
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: yggdrasil-reconciler
subjects:
  - kind: ServiceAccount
    name: yggdrasil
    namespace: dakasa
```

- [ ] **Step 2: Commit**

```bash
git add platform/kube/reconciler-rbac.yaml
git commit -m "🔧 Add RBAC ClusterRole for Yggdrasil secret reconciler"
```

---

### Task 9: Build, deploy, and verify on EC2

**Files:**
- None (operational)

- [ ] **Step 1: Build new yggdrasil-core image on EC2**

```bash
ssh -i ~/.ssh/dakasa-validation.pem ubuntu@54.233.17.68
cd ~/yggdrasil/yggdrasil-core
git pull origin main
docker build -t yggdrasil-core:latest .
docker save yggdrasil-core:latest | sudo k3s ctr images import -
```

- [ ] **Step 2: Apply RBAC**

```bash
sudo k3s kubectl apply -f platform/kube/reconciler-rbac.yaml
```

- [ ] **Step 3: Create ServiceAccount if missing**

```bash
sudo k3s kubectl create serviceaccount yggdrasil -n dakasa --dry-run=client -o yaml | sudo k3s kubectl apply -f -
```

- [ ] **Step 4: Restart yggdrasil deployment**

```bash
sudo k3s kubectl rollout restart deployment/yggdrasil -n dakasa
sudo k3s kubectl rollout status deployment/yggdrasil -n dakasa --timeout=60s
```

- [ ] **Step 5: Verify reconciler is running**

```bash
curl -s http://localhost:9080/api/v1/reconciler/status | python3 -m json.tool
```

Expected: `{"last_reconcile": {"kind": "secrets", ...}}`

- [ ] **Step 6: Test end-to-end — create a managed secret and verify K8s Secret appears**

```bash
# Create managed secret via API
curl -s -X POST http://localhost:9080/api/v1/secrets \
  -H "Content-Type: application/json" \
  -d '{"name":"test-reconciler","namespace":"dakasa","data":{"HELLO":"world"}}'

# Verify K8s Secret was created
sudo k3s kubectl get secret test-reconciler -n dakasa -o yaml
```

Expected: K8s Secret exists with `data.HELLO: d29ybGQ=` (base64 of "world") and label `yggdrasil.io/managed-by: yggdrasil-core`.

- [ ] **Step 7: Clean up test secret**

```bash
curl -s -X POST http://localhost:9080/api/v1/secrets/dakasa/test-reconciler/revoke \
  -H "Content-Type: application/json" -d '{}'
sudo k3s kubectl delete secret test-reconciler -n dakasa
```
