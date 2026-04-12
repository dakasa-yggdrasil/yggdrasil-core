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

	r1 := engine.reconcileSecretList(context.Background(), secrets)
	if r1.Created != 1 {
		t.Fatalf("first pass Created = %d, want 1", r1.Created)
	}

	r2 := engine.reconcileSecretList(context.Background(), secrets)
	if r2.Skipped != 1 {
		t.Errorf("second pass Skipped = %d, want 1", r2.Skipped)
	}
	if r2.Created != 0 || r2.Updated != 0 {
		t.Errorf("second pass should have 0 creates/updates, got %d/%d", r2.Created, r2.Updated)
	}
}
