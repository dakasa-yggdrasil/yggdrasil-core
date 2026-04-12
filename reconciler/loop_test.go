package reconciler

import (
	"context"
	"testing"

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

	mat := &SecretMaterializer{}
	_ = NewEngine(pool, nil, nil, mat)
	target, _ := pool.Local()

	result := mat.reconcileSecretList(context.Background(), *target, secrets)

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

	mat := &SecretMaterializer{}
	_ = NewEngine(pool, nil, nil, mat)
	target, _ := pool.Local()

	r1 := mat.reconcileSecretList(context.Background(), *target, secrets)
	if r1.Created != 1 {
		t.Fatalf("first pass Created = %d, want 1", r1.Created)
	}

	r2 := mat.reconcileSecretList(context.Background(), *target, secrets)
	if r2.Skipped != 1 {
		t.Errorf("second pass Skipped = %d, want 1", r2.Skipped)
	}
	if r2.Created != 0 || r2.Updated != 0 {
		t.Errorf("second pass should have 0 creates/updates, got %d/%d", r2.Created, r2.Updated)
	}
}

func TestNewEngine_RegistersMaterializers(t *testing.T) {
	pool := &KubeClientPool{remotes: make(map[string]*cachedTarget)}

	mat := &SecretMaterializer{}
	engine := NewEngine(pool, nil, nil, mat)

	if len(engine.materializers) != 1 {
		t.Errorf("materializers count = %d, want 1", len(engine.materializers))
	}
	if _, ok := engine.materializers["secrets"]; !ok {
		t.Error("expected 'secrets' materializer to be registered")
	}
}

func TestEngine_LastResults(t *testing.T) {
	pool := &KubeClientPool{remotes: make(map[string]*cachedTarget)}

	engine := NewEngine(pool, nil, nil, &SecretMaterializer{})

	results := engine.LastResults()
	if len(results) != 0 {
		t.Errorf("initial LastResults should be empty, got %d", len(results))
	}

	// LastResult should return zero value when no reconcile has run.
	lr := engine.LastResult()
	if lr.Kind != "" {
		t.Errorf("initial LastResult kind = %q, want empty", lr.Kind)
	}
}
