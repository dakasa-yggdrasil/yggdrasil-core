package reconciler

import (
	"context"
	"reflect"
	"strconv"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func unmanagedSecretLabels() map[string]map[string]string {
	return map[string]map[string]string{
		"no labels":       nil,
		"missing owner":   {"other.example/owner": "another-controller"},
		"different owner": {LabelManagedBy: "another-controller"},
	}
}

func unmanagedSecret(labels map[string]string, version int) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "target-namespace",
			Name:      "target-secret",
			Labels:    labels,
			Annotations: map[string]string{
				AnnotationVersion:          strconv.Itoa(version),
				"other.example/annotation": "preserve",
			},
		},
		Data: map[string][]byte{"existing": []byte("preserve-existing-value")},
	}
}

func managedSecretWithTargetOverride(status string) model.ManagedSecret {
	return model.ManagedSecret{
		Namespace: "source-namespace",
		Name:      "source-secret",
		Status:    status,
		Version:   2,
		Data:      map[string]string{"replacement": "never-copy-to-unmanaged-target"},
		Metadata: map[string]any{
			"materialize": map[string]any{
				"namespace": "target-namespace",
				"name":      "target-secret",
			},
		},
	}
}

// Return the original pointer to detect even an in-memory change that is not
// followed by an API Update. The regular fake client would return a deep copy.
func clientReturningOriginalSecret(t *testing.T, existing *corev1.Secret) *fake.Clientset {
	t.Helper()
	client := fake.NewSimpleClientset()
	client.PrependReactor("get", "secrets", func(action k8stesting.Action) (bool, runtime.Object, error) {
		if action.GetNamespace() != existing.Namespace || action.(k8stesting.GetAction).GetName() != existing.Name {
			t.Fatal("materializer did not use the resolved target")
		}
		return true, existing, nil
	})
	return client
}

func assertUnmanagedSecretUntouched(t *testing.T, client *fake.Clientset, existing, before *corev1.Secret) {
	t.Helper()
	if !reflect.DeepEqual(existing, before) {
		t.Fatal("unmanaged target was mutated in memory")
	}
	for _, action := range client.Actions() {
		if action.GetVerb() != "get" {
			t.Fatalf("unmanaged target received a %s action", action.GetVerb())
		}
	}
}

func TestSecretMaterializerRefusesUnmanagedTargets(t *testing.T) {
	for owner, labels := range unmanagedSecretLabels() {
		for _, version := range []int{1, 2} {
			for _, status := range []string{"active", "disabled", "revoked"} {
				t.Run(owner+"/version-"+strconv.Itoa(version)+"/"+status, func(t *testing.T) {
					existing := unmanagedSecret(labels, version)
					before := existing.DeepCopy()
					client := clientReturningOriginalSecret(t, existing)
					err := (&SecretMaterializer{}).Materialize(context.Background(), KubeTarget{Client: client}, managedSecretWithTargetOverride(status))
					if err != errSecretTargetNotManaged || err.Error() != "secret target is not managed by yggdrasil-core" {
						t.Fatal("expected the fixed ownership refusal without resource names or values")
					}
					assertUnmanagedSecretUntouched(t, client, existing, before)
				})
			}
		}
	}
}

func TestSecretReconcileRefusesUnmanagedTargetsBeforeVersionSkip(t *testing.T) {
	for owner, labels := range unmanagedSecretLabels() {
		for _, version := range []int{1, 2} {
			t.Run(owner+"/version-"+strconv.Itoa(version), func(t *testing.T) {
				existing := unmanagedSecret(labels, version)
				before := existing.DeepCopy()
				client := clientReturningOriginalSecret(t, existing)
				result := (&SecretMaterializer{}).reconcileSecretList(context.Background(), KubeTarget{Client: client}, []model.ManagedSecret{managedSecretWithTargetOverride("active")})
				if result.Errors != 1 || result.Created != 0 || result.Updated != 0 || result.Skipped != 0 || result.diagnostics[stageUpdate][classOther] != 1 {
					t.Fatal("unmanaged target must report one ownership error and no convergence")
				}
				assertUnmanagedSecretUntouched(t, client, existing, before)
			})
		}
	}
}

func TestSecretUpdateRefusesUnmanagedTargetsBeforeMutation(t *testing.T) {
	for owner, labels := range unmanagedSecretLabels() {
		t.Run(owner, func(t *testing.T) {
			existing := unmanagedSecret(labels, 1)
			before := existing.DeepCopy()
			client := fake.NewSimpleClientset()
			err := (&SecretMaterializer{}).updateSecret(context.Background(), KubeTarget{Client: client}, managedSecretWithTargetOverride("active"), existing)
			if err != errSecretTargetNotManaged {
				t.Fatal("expected ownership refusal from the update helper")
			}
			assertUnmanagedSecretUntouched(t, client, existing, before)
			if len(client.Actions()) != 0 {
				t.Fatal("refused update helper must not call Kubernetes")
			}
		})
	}
}

func TestSecretMaterializerDoesNotAllocateAnnotationsOnUnmanagedTarget(t *testing.T) {
	for _, status := range []string{"disabled", "revoked"} {
		t.Run(status, func(t *testing.T) {
			existing := unmanagedSecret(nil, 1)
			existing.Annotations = nil
			before := existing.DeepCopy()
			client := clientReturningOriginalSecret(t, existing)
			if err := (&SecretMaterializer{}).Materialize(context.Background(), KubeTarget{Client: client}, managedSecretWithTargetOverride(status)); err != errSecretTargetNotManaged {
				t.Fatal("expected ownership refusal before allocating annotations")
			}
			assertUnmanagedSecretUntouched(t, client, existing, before)
		})
	}
}

func TestSecretMaterializerMarksOwnedDisabledSecret(t *testing.T) {
	existing := unmanagedSecret(map[string]string{LabelManagedBy: LabelManagedByValue}, 1)
	client := fake.NewSimpleClientset(existing)
	if err := (&SecretMaterializer{}).Materialize(context.Background(), KubeTarget{Client: client}, managedSecretWithTargetOverride("disabled")); err != nil {
		t.Fatal(err)
	}
	actual, err := client.CoreV1().Secrets(existing.Namespace).Get(context.Background(), existing.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(actual.Data, existing.Data) || actual.Annotations[AnnotationStatus] != "disabled" || actual.Annotations[AnnotationVersion] != "2" || actual.Annotations[AnnotationRevokedAt] != "" {
		t.Fatal("owned disabled Secret should retain its data and receive only lifecycle annotations")
	}
}

func TestSecretMaterializerMarkMissingSecretRemainsNoOp(t *testing.T) {
	for _, status := range []string{"disabled", "revoked"} {
		t.Run(status, func(t *testing.T) {
			client := fake.NewSimpleClientset()
			if err := (&SecretMaterializer{}).Materialize(context.Background(), KubeTarget{Client: client}, managedSecretWithTargetOverride(status)); err != nil {
				t.Fatal(err)
			}
			if len(client.Actions()) != 1 || client.Actions()[0].GetVerb() != "get" {
				t.Fatal("marking an absent Secret must not create or update it")
			}
		})
	}
}

func TestSecretReconcileOwnedTargetsStillCreateUpdateAndSkip(t *testing.T) {
	owned := func(name string, version int) *corev1.Secret {
		s := unmanagedSecret(map[string]string{LabelManagedBy: LabelManagedByValue}, version)
		s.Name = name
		return s
	}
	client := fake.NewSimpleClientset(owned("current", 2), owned("stale", 1))
	secrets := []model.ManagedSecret{
		{Namespace: "target-namespace", Name: "current", Status: "active", Version: 2},
		{Namespace: "target-namespace", Name: "stale", Status: "active", Version: 2, Data: map[string]string{"replacement": "new"}},
		{Namespace: "target-namespace", Name: "missing", Status: "active", Version: 2, Data: map[string]string{"new": "created"}},
	}
	result := (&SecretMaterializer{}).reconcileSecretList(context.Background(), KubeTarget{Client: client}, secrets)
	if result.Errors != 0 || result.Created != 1 || result.Updated != 1 || result.Skipped != 1 {
		t.Fatal("owned targets lost create/update/skip behavior")
	}
	for _, name := range []string{"stale", "missing"} {
		s, err := client.CoreV1().Secrets("target-namespace").Get(context.Background(), name, metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if s.Labels[LabelManagedBy] != LabelManagedByValue || s.Annotations[AnnotationVersion] != "2" {
			t.Fatal("materialized target lost its owner label or converged version")
		}
	}
}
