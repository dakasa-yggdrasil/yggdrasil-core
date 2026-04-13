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
// target is created from the pod's ServiceAccount.
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

	// Check-lock-check: first read with RLock, then write with Lock if stale.
	p.mu.RLock()
	cached, ok := p.remotes[name]
	p.mu.RUnlock()
	if ok && time.Now().Before(cached.expiresAt) {
		return &cached.target, nil
	}

	// Acquire write lock and re-check (another goroutine may have refreshed).
	p.mu.Lock()
	cached, ok = p.remotes[name]
	if ok && time.Now().Before(cached.expiresAt) {
		p.mu.Unlock()
		return &cached.target, nil
	}
	p.mu.Unlock()

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
