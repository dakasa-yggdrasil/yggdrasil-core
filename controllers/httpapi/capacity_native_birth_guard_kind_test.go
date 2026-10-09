package httpapi

// These helpers run only in the mandatory remote native KinD gate. They import
// the pinned private guard's real renderer/binary, not a self-acknowledgement.
import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

func nativeBirthRoster(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile(os.Getenv("CAPACITY_BIRTH_GUARD_ROSTER"))
	var profile struct {
		Functions []struct {
			Name string `json:"name"`
		} `json:"functions"`
	}
	if err != nil || json.Unmarshal(raw, &profile) != nil || len(profile.Functions) != 22 {
		t.Fatal("pinned private guard source roster is required")
	}
	names, seen := []string{}, map[string]bool{}
	for _, function := range profile.Functions {
		if function.Name == "" || seen[function.Name] {
			t.Fatal("private source roster identity differs")
		}
		seen[function.Name] = true
		names = append(names, function.Name)
	}
	return names
}

func nativeBirthSHA(value any) string {
	raw, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%x", sha256.Sum256(raw))
}

func nativeBirthTLS(t *testing.T, realm string) ([]byte, []byte, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "isolated native birth CI CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "capacity-native-admission"}, DNSNames: []string{"capacity-native-admission." + realm + ".svc", "capacity-native-admission." + realm + ".svc.cluster.local"}, NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	certDER, err := x509.CreateCertificate(rand.Reader, cert, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
}

func nativeBirthTyped(t *testing.T, value any, target any) {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil || json.Unmarshal(raw, target) != nil {
		t.Fatal("actual native typed projection unavailable")
	}
}

func nativeInstallBirthGuard(t *testing.T, ctx context.Context, realm, workload, workloadUID, image string) (map[string]any, string) {
	t.Helper()
	binary, guardImage := os.Getenv("CAPACITY_BIRTH_GUARD_BINARY"), os.Getenv("NATIVE_BIRTH_GUARD_IMAGE")
	if binary == "" || guardImage == "" {
		t.Fatal("actual pinned guard renderer and OCI manifest required")
	}
	principal := "system:serviceaccount:" + realm + ":capacity-native-adapter"
	units := []map[string]any{}
	for _, name := range nativeBirthRoster(t) {
		uid := workloadUID
		if name != workload {
			nativeKindApply(t, ctx, map[string]any{"apiVersion": "apps/v1", "kind": "Deployment", "metadata": map[string]any{"name": name, "namespace": realm}, "spec": map[string]any{"replicas": 0, "selector": map[string]any{"matchLabels": map[string]string{"app": name}}, "template": map[string]any{"metadata": map[string]any{"labels": map[string]string{"app": name}}, "spec": map[string]any{"containers": []map[string]any{{"name": "api", "image": image}}}}}})
			uid = nativeKindGet(t, ctx, "-n", realm, "get", "deployment", name, "-o", "json")["metadata"].(map[string]any)["uid"].(string)
		}
		units = append(units, map[string]any{"name": name, "deployment_uid": uid, "container": "api", "image": image, "projection_dir": "/native", "projection_volume": "native", "admission_secret": "native-admission-key", "admission_key": "key"})
	}
	config := map[string]any{"schema": 1, "enabled": true, "namespace": realm, "adapter_principal": principal, "units": units, "resources": map[string]string{"cpu": "50m", "memory": "32Mi", "limit_cpu": "200m", "limit_memory": "128Mi"}}
	ca, cert, key := nativeBirthTLS(t, realm)
	nativeKindApply(t, ctx, map[string]any{"apiVersion": "v1", "kind": "Secret", "metadata": map[string]any{"name": "capacity-native-admission-tls", "namespace": realm}, "type": "kubernetes.io/tls", "data": map[string]string{"tls.crt": base64.StdEncoding.EncodeToString(cert), "tls.key": base64.StdEncoding.EncodeToString(key)}})
	path := filepath.Join(t.TempDir(), "guard-config.json")
	raw, _ := json.Marshal(config)
	if os.WriteFile(path, raw, 0600) != nil {
		t.Fatal("fixed guard config write failed")
	}
	command := exec.CommandContext(ctx, binary, "-mode=admission-plan", "-admission-config="+path, "-webhook-image="+guardImage, "-webhook-ca-bundle="+base64.StdEncoding.EncodeToString(ca))
	raw, err := command.Output()
	var plan struct {
		Items []map[string]any `json:"items"`
	}
	if err != nil || json.Unmarshal(raw, &plan) != nil || len(plan.Items) < 8 {
		t.Fatal("actual pinned guard renderer refused")
	}
	for _, object := range plan.Items {
		nativeKindApply(t, ctx, object)
	}
	t.Cleanup(func() {
		_ = exec.Command("kubectl", "delete", "mutatingwebhookconfiguration", "capacity-native-mutate", "--ignore-not-found").Run()
		_ = exec.Command("kubectl", "delete", "validatingwebhookconfiguration", "capacity-native-validate", "--ignore-not-found").Run()
	})
	nativeKindCommand(t, ctx, "-n", realm, "rollout", "status", "deployment/capacity-native-admission", "--timeout=120s")
	nativeKindAwait(t, ctx, func() bool {
		endpoints := nativeKindGet(t, ctx, "-n", realm, "get", "endpoints", "capacity-native-admission", "-o", "json")
		// The pinned adapter contract observes the still-served core/v1
		// Endpoints graph. This readiness wait projects only that native JSON;
		// it does not replace the adapter's complete endpoint ownership checks.
		var ep struct {
			Subsets []struct {
				Addresses         []json.RawMessage `json:"addresses"`
				NotReadyAddresses []json.RawMessage `json:"notReadyAddresses"`
			} `json:"subsets"`
		}
		nativeBirthTyped(t, endpoints, &ep)
		count := 0
		for _, subset := range ep.Subsets {
			count += len(subset.Addresses)
			if len(subset.NotReadyAddresses) > 0 {
				return false
			}
		}
		return count == 2
	})
	nativeKindCommand(t, ctx, "label", "namespace", realm, "yggdrasil.io/capacity-native-admission=schema2", "--overwrite")
	var mutating admissionv1.MutatingWebhookConfiguration
	nativeBirthTyped(t, nativeKindGet(t, ctx, "get", "mutatingwebhookconfiguration", "capacity-native-mutate", "-o", "json"), &mutating)
	var validating admissionv1.ValidatingWebhookConfiguration
	nativeBirthTyped(t, nativeKindGet(t, ctx, "get", "validatingwebhookconfiguration", "capacity-native-validate", "-o", "json"), &validating)
	var service corev1.Service
	nativeBirthTyped(t, nativeKindGet(t, ctx, "-n", realm, "get", "service", "capacity-native-admission", "-o", "json"), &service)
	var cm corev1.ConfigMap
	nativeBirthTyped(t, nativeKindGet(t, ctx, "-n", realm, "get", "configmap", "capacity-native-admission", "-o", "json"), &cm)
	var deployment appsv1.Deployment
	deploymentObject := nativeKindGet(t, ctx, "-n", realm, "get", "deployment", "capacity-native-admission", "-o", "json")
	nativeBirthTyped(t, deploymentObject, &deployment)
	var sa corev1.ServiceAccount
	nativeBirthTyped(t, nativeKindGet(t, ctx, "-n", realm, "get", "serviceaccount", "capacity-native-admission", "-o", "json"), &sa)
	namespace := nativeKindGet(t, ctx, "get", "namespace", realm, "-o", "json")["metadata"].(map[string]any)
	pin := func(name, uid string, value any) map[string]any {
		return map[string]any{"name": name, "uid": uid, "sha256": nativeBirthSHA(value)}
	}
	binding := map[string]any{"binding_name": "api-birth", "namespace": realm, "namespace_uid": namespace["uid"], "namespace_label_key": "yggdrasil.io/capacity-native-admission", "namespace_label": "schema2", "workload_name": workload, "workload_uid": workloadUID, "workload_container": "api", "workload_image": image, "adapter_principal": principal, "mutating": pin(mutating.Name, string(mutating.UID), mutating.Webhooks), "validating": pin(validating.Name, string(validating.UID), validating.Webhooks), "service": pin(service.Name, string(service.UID), service.Spec), "configmap": pin(cm.Name, string(cm.UID), map[string]any{"data": cm.Data, "binary_data": cm.BinaryData, "immutable": cm.Immutable}), "deployment": map[string]any{"name": deployment.Name, "uid": string(deployment.UID), "sha256": nativeBirthDeploymentProjection(t, ctx, deploymentObject)}, "service_account": sa.Name, "service_account_uid": string(sa.UID), "guard_container": "guard", "guard_image": guardImage, "ca_bundle_sha256": fmt.Sprintf("%x", sha256.Sum256(ca)), "minimum_backends": 2}
	return binding, nativeBirthAdapterKubeconfig(t, ctx, realm)
}

func nativeBirthAdapterKubeconfig(t *testing.T, ctx context.Context, realm string) string {
	t.Helper()
	const name = "capacity-native-adapter"
	nativeKindApply(t, ctx, map[string]any{"apiVersion": "v1", "kind": "ServiceAccount", "metadata": map[string]any{"name": name, "namespace": realm}})
	nativeKindApply(t, ctx, map[string]any{"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role", "metadata": map[string]any{"name": name, "namespace": realm}, "rules": []map[string]any{{"apiGroups": []string{"", "apps", "autoscaling"}, "resources": []string{"pods", "pods/status", "pods/proxy", "replicasets", "deployments", "horizontalpodautoscalers", "services", "endpoints", "configmaps", "serviceaccounts"}, "verbs": []string{"get", "list", "patch", "update"}}}})
	nativeKindApply(t, ctx, map[string]any{"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding", "metadata": map[string]any{"name": name, "namespace": realm}, "subjects": []map[string]any{{"kind": "ServiceAccount", "name": name, "namespace": realm}}, "roleRef": map[string]string{"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": name}})
	clusterName := name + "-" + realm
	nativeKindApply(t, ctx, map[string]any{"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRole", "metadata": map[string]any{"name": clusterName}, "rules": []map[string]any{{"apiGroups": []string{""}, "resources": []string{"namespaces"}, "resourceNames": []string{realm}, "verbs": []string{"get"}}, {"apiGroups": []string{"admissionregistration.k8s.io"}, "resources": []string{"mutatingwebhookconfigurations", "validatingwebhookconfigurations"}, "resourceNames": []string{"capacity-native-mutate", "capacity-native-validate"}, "verbs": []string{"get"}}}})
	nativeKindApply(t, ctx, map[string]any{"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRoleBinding", "metadata": map[string]any{"name": clusterName}, "subjects": []map[string]any{{"kind": "ServiceAccount", "name": name, "namespace": realm}}, "roleRef": map[string]string{"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": clusterName}})
	t.Cleanup(func() {
		_ = exec.Command("kubectl", "delete", "clusterrole,clusterrolebinding", clusterName, "--ignore-not-found").Run()
	})
	// Capture the native ephemeral credential privately; never put it in arguments,
	// JSON qualification output, errors or durable operator configuration.
	token, err := exec.CommandContext(ctx, "kubectl", "-n", realm, "create", "token", name, "--duration=20m").Output()
	if err != nil || len(token) < 32 {
		t.Fatal("native scoped CI principal credential unavailable")
	}
	raw, err := exec.CommandContext(ctx, "kubectl", "config", "view", "--raw", "--flatten", "-o", "json").Output()
	if err != nil {
		t.Fatal("native private cluster transport read failed")
	}
	original, err := clientcmd.Load(raw)
	if err != nil || original.Contexts[original.CurrentContext] == nil {
		t.Fatal("native cluster transport unavailable")
	}
	current := original.Contexts[original.CurrentContext]
	cluster := original.Clusters[current.Cluster]
	if cluster == nil {
		t.Fatal("native cluster transport missing")
	}
	isolated := clientcmdapi.NewConfig()
	isolated.Clusters["native"] = cluster
	isolated.AuthInfos["native"] = &clientcmdapi.AuthInfo{Token: string(bytes.TrimSpace(token))}
	isolated.Contexts["native"] = &clientcmdapi.Context{Cluster: "native", AuthInfo: "native", Namespace: realm}
	isolated.CurrentContext = "native"
	path := filepath.Join(t.TempDir(), "native-adapter.kubeconfig")
	private, err := clientcmd.Write(*isolated)
	if err != nil || os.WriteFile(path, private, 0600) != nil {
		t.Fatal("scoped native transport write failed")
	}
	return path
}

func nativeBirthBaseline(t *testing.T, ctx context.Context, realm, image string) map[string]any {
	t.Helper()
	items := nativeKindGet(t, ctx, "-n", realm, "get", "pods", "-l", "app=native-core", "-o", "json")["items"].([]any)
	result := map[string]any{}
	for _, item := range items {
		var pod corev1.Pod
		nativeBirthTyped(t, item, &pod)
		if len(pod.Spec.Containers) != 1 || pod.Spec.Containers[0].Image != image || len(pod.Status.ContainerStatuses) != 1 || pod.Status.ContainerStatuses[0].State.Running == nil || pod.DeletionTimestamp != nil {
			t.Fatal("actual original baseline is incomplete")
		}
		cs := pod.Status.ContainerStatuses[0]
		result[pod.Name] = []any{string(pod.UID), cs.ContainerID, cs.ImageID, cs.State.Running.StartedAt.UTC(), cs.RestartCount, pod.Spec.Containers[0].Image}
	}
	if len(result) != 3 {
		t.Fatal("exact three original native lifetimes required")
	}
	return result
}

func nativeBirthCheckBaseline(t *testing.T, ctx context.Context, realm string, before map[string]any) {
	t.Helper()
	for name, tuple := range before {
		var pod corev1.Pod
		nativeBirthTyped(t, nativeKindGet(t, ctx, "-n", realm, "get", "pod", name, "-o", "json"), &pod)
		if len(pod.Status.ContainerStatuses) != 1 || len(pod.Spec.Containers) != 1 || pod.Status.ContainerStatuses[0].State.Running == nil || pod.DeletionTimestamp != nil {
			t.Fatal("original native lifetime was lost")
		}
		cs := pod.Status.ContainerStatuses[0]
		current := []any{string(pod.UID), cs.ContainerID, cs.ImageID, cs.State.Running.StartedAt.UTC(), cs.RestartCount, pod.Spec.Containers[0].Image}
		if !reflect.DeepEqual(tuple, current) {
			t.Fatal("original native process tuple changed")
		}
	}
}

// Use the production observer's exact typed projection. Core's newer Kubernetes
// SDK uses omitzero for Template.Metadata.CreationTimestamp; the adapter's pinned
// SDK retains the explicit null. Dropping the digest guard would hide drift.
func nativeBirthDeploymentProjection(t *testing.T, ctx context.Context, object map[string]any) string {
	t.Helper()
	binary := os.Getenv("CAPACITY_BIRTH_PROJECTION_BINARY")
	if binary == "" {
		t.Fatal("exact adapter projection producer required")
	}
	dir := t.TempDir()
	input, output := filepath.Join(dir, "native-deployment.json"), filepath.Join(dir, "projection.json")
	raw, err := json.Marshal(object)
	if err != nil || os.WriteFile(input, raw, 0600) != nil {
		t.Fatal("native Deployment projection input unavailable")
	}
	command := exec.CommandContext(ctx, binary, "-test.run=^TestCapacityCoreBirthProjectionProducer$")
	command.Env = append(os.Environ(), "CAPACITY_NATIVE_INPUT_FILE="+input, "CAPACITY_NATIVE_OUTPUT_FILE="+output)
	if err = command.Run(); err != nil {
		t.Fatal("actual adapter projection producer refused")
	}
	raw, err = os.ReadFile(output)
	var result struct {
		SchemaVersion int    `json:"schema_version"`
		SHA256        string `json:"deployment_spec_sha256"`
	}
	if err != nil || json.Unmarshal(raw, &result) != nil || result.SchemaVersion != 1 || len(result.SHA256) != 64 {
		t.Fatal("exact native projection result unavailable")
	}
	return result.SHA256
}
