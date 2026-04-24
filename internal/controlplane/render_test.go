package controlplane

import (
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func baseSpec() model.ControlPlaneManifestSpec {
	return model.ControlPlaneManifestSpec{
		Image:    "ghcr.io/dakasa-yggdrasil/yggdrasil-core:v1.0.0",
		Replicas: 2,
		Postgres: model.ControlPlanePostgresSpec{
			Mode: "bundled",
			Bundled: &model.ControlPlanePostgresBundledSpec{
				Storage: "32Gi",
			},
		},
		Kubernetes: model.ControlPlaneKubernetesSpec{
			Namespace: "yggdrasil",
			ClusterRef: model.ManifestSelector{
				Namespace: "global",
				Name:      "kubernetes-prod",
			},
		},
	}
}

// findObject returns the first rendered object with the given kind+name.
// The renderer emits unstructured map[string]any, so walking the tree
// with type assertions is the least-bad option for assertions. A helper
// keeps the tests readable.
func findObject(t *testing.T, objects []map[string]any, kind, name string) map[string]any {
	t.Helper()
	for _, obj := range objects {
		if obj["kind"] != kind {
			continue
		}
		metadata, _ := obj["metadata"].(map[string]any)
		if metadata == nil {
			continue
		}
		if metadata["name"] == name {
			return obj
		}
	}
	return nil
}

func TestRenderMinimalBundledPostgresHTTPOnly(t *testing.T) {
	bundle, err := Render(baseSpec())
	if err != nil {
		t.Fatalf("Render error: %v", err)
	}

	// Namespace + Postgres Secret/StatefulSet/Service in infra.
	if got, want := len(bundle.InfraObjects), 4; got != want {
		t.Fatalf("InfraObjects count = %d, want %d", got, want)
	}
	if findObject(t, bundle.InfraObjects, "Namespace", "yggdrasil") == nil {
		t.Error("missing Namespace in infra_objects")
	}
	if findObject(t, bundle.InfraObjects, "StatefulSet", postgresStatefulSet) == nil {
		t.Error("missing Postgres StatefulSet in infra_objects")
	}

	// Core Secret + Deployment + Service.
	if got, want := len(bundle.CoreObjects), 3; got != want {
		t.Fatalf("CoreObjects count = %d, want %d", got, want)
	}
	if findObject(t, bundle.CoreObjects, "Deployment", coreDeploymentName) == nil {
		t.Error("missing core Deployment")
	}

	// WaitTargets: bundled postgres + core Deployment.
	if got, want := len(bundle.WaitTargets), 2; got != want {
		t.Fatalf("WaitTargets count = %d, want %d", got, want)
	}
}

func TestRenderAMQPBundledAppendsRabbitMQAndCoreEnvFrom(t *testing.T) {
	spec := baseSpec()
	spec.Transports = []model.ControlPlaneTransport{{
		Kind:    "amqp",
		Mode:    "bundled",
		Bundled: &model.ControlPlaneTransportBundledSpec{Storage: "4Gi"},
	}}

	bundle, err := Render(spec)
	if err != nil {
		t.Fatalf("Render error: %v", err)
	}

	if findObject(t, bundle.InfraObjects, "StatefulSet", amqpStatefulSet) == nil {
		t.Error("missing RabbitMQ StatefulSet")
	}
	if findObject(t, bundle.InfraObjects, "Service", amqpServiceName) == nil {
		t.Error("missing RabbitMQ Service")
	}
	if findObject(t, bundle.InfraObjects, "Secret", amqpSecretName) == nil {
		t.Error("missing RabbitMQ Secret")
	}

	// Core Deployment must pull envFrom the RabbitMQ Secret (so the
	// core boots with BROKER_URL set from the bundled broker).
	deployment := findObject(t, bundle.CoreObjects, "Deployment", coreDeploymentName)
	if deployment == nil {
		t.Fatal("missing core Deployment")
	}
	envSources := extractEnvFromSources(t, deployment)
	if !containsSecretRef(envSources, amqpSecretName) {
		t.Errorf("core Deployment envFrom missing %q (got %#v)", amqpSecretName, envSources)
	}
}

func TestRenderAMQPExternalPullsSecretRefIntoCoreEnvFrom(t *testing.T) {
	spec := baseSpec()
	spec.Transports = []model.ControlPlaneTransport{{
		Kind: "amqp",
		Mode: "external",
		External: &model.ControlPlaneTransportConfigSpec{
			URLRef: "secret://yggdrasil-amqp-url/url",
		},
	}}

	bundle, err := Render(spec)
	if err != nil {
		t.Fatalf("Render error: %v", err)
	}

	// No RabbitMQ workload.
	if findObject(t, bundle.InfraObjects, "StatefulSet", amqpStatefulSet) != nil {
		t.Error("expected no RabbitMQ StatefulSet when transport.mode=external")
	}

	deployment := findObject(t, bundle.CoreObjects, "Deployment", coreDeploymentName)
	envSources := extractEnvFromSources(t, deployment)
	if !containsSecretRef(envSources, "yggdrasil-amqp-url") {
		t.Errorf("core Deployment envFrom missing external AMQP Secret ref (got %#v)", envSources)
	}
}

func TestRenderExternalPostgresSkipsStatefulSetAndWiresSecretRef(t *testing.T) {
	spec := baseSpec()
	spec.Postgres = model.ControlPlanePostgresSpec{
		Mode: "external",
		External: &model.ControlPlanePostgresExternalSpec{
			Host:        "db.example.com",
			Database:    "yggdrasil",
			Username:    "yggdrasil",
			PasswordRef: "secret://yggdrasil-db/password",
		},
	}

	bundle, err := Render(spec)
	if err != nil {
		t.Fatalf("Render error: %v", err)
	}

	// Only Namespace in infra — Postgres is external.
	if got, want := len(bundle.InfraObjects), 1; got != want {
		t.Fatalf("InfraObjects count = %d, want %d (external postgres should emit no infra workload)", got, want)
	}

	// WaitTargets: core only (no bundled postgres wait).
	if got, want := len(bundle.WaitTargets), 1; got != want {
		t.Fatalf("WaitTargets count = %d, want %d", got, want)
	}
	if bundle.WaitTargets[0].Phase != phaseCore {
		t.Errorf("expected only core wait target, got %#v", bundle.WaitTargets)
	}

	deployment := findObject(t, bundle.CoreObjects, "Deployment", coreDeploymentName)
	envSources := extractEnvFromSources(t, deployment)
	if !containsSecretRef(envSources, "yggdrasil-db") {
		t.Errorf("core Deployment envFrom missing external postgres Secret ref (got %#v)", envSources)
	}
}

func TestRenderIngressOnlyWhenEnabled(t *testing.T) {
	spec := baseSpec()
	bundle, err := Render(spec)
	if err != nil {
		t.Fatalf("Render error: %v", err)
	}
	if findObject(t, bundle.CoreObjects, "Ingress", coreIngressName) != nil {
		t.Error("Ingress should be omitted when ingress.enabled=false")
	}

	spec.Ingress = model.ControlPlaneIngressSpec{
		Enabled:       true,
		Host:          "yggdrasil.example.com",
		ClassName:     "nginx",
		TLSSecretName: "yggdrasil-tls",
	}
	bundle, err = Render(spec)
	if err != nil {
		t.Fatalf("Render error: %v", err)
	}
	ingress := findObject(t, bundle.CoreObjects, "Ingress", coreIngressName)
	if ingress == nil {
		t.Fatal("Ingress should be rendered when ingress.enabled=true")
	}
	ingressSpec, _ := ingress["spec"].(map[string]any)
	if got := ingressSpec["ingressClassName"]; got != "nginx" {
		t.Errorf("ingressClassName = %v, want nginx", got)
	}
}

func TestRenderResourcesApplyToCoreContainer(t *testing.T) {
	spec := baseSpec()
	spec.Resources = model.ControlPlaneResourcesSpec{
		Requests: model.ControlPlaneResourceClaim{CPU: "200m", Memory: "256Mi"},
		Limits:   model.ControlPlaneResourceClaim{CPU: "1", Memory: "1Gi"},
	}
	bundle, err := Render(spec)
	if err != nil {
		t.Fatalf("Render error: %v", err)
	}
	deployment := findObject(t, bundle.CoreObjects, "Deployment", coreDeploymentName)
	container := coreContainer(t, deployment)
	resources, _ := container["resources"].(map[string]any)
	if resources == nil {
		t.Fatal("expected container.resources to be rendered")
	}
	requests, _ := resources["requests"].(map[string]any)
	if requests["cpu"] != "200m" || requests["memory"] != "256Mi" {
		t.Errorf("unexpected requests: %#v", requests)
	}
}

func TestRenderRejectsUnsupportedTransportKind(t *testing.T) {
	spec := baseSpec()
	spec.Transports = []model.ControlPlaneTransport{{
		Kind: "kafka",
		Mode: "external",
		External: &model.ControlPlaneTransportConfigSpec{
			BootstrapServersRef: "secret://kafka-bootstrap/servers",
		},
	}}
	if _, err := Render(spec); err == nil {
		t.Fatal("expected kafka transport to be rejected by renderer (not yet wired by deploy workflow)")
	}
}

func TestRenderRejectsMissingBasics(t *testing.T) {
	cases := map[string]func(*model.ControlPlaneManifestSpec){
		"empty namespace": func(s *model.ControlPlaneManifestSpec) { s.Kubernetes.Namespace = "" },
		"empty image":     func(s *model.ControlPlaneManifestSpec) { s.Image = "" },
		"zero replicas":   func(s *model.ControlPlaneManifestSpec) { s.Replicas = 0 },
	}
	for name, mutator := range cases {
		t.Run(name, func(t *testing.T) {
			spec := baseSpec()
			mutator(&spec)
			if _, err := Render(spec); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

// coreContainer drills into a Deployment and returns the first
// container map in pod.spec.containers, failing the test on any
// structural surprise.
func coreContainer(t *testing.T, deployment map[string]any) map[string]any {
	t.Helper()
	if deployment == nil {
		t.Fatal("nil deployment")
	}
	spec, _ := deployment["spec"].(map[string]any)
	template, _ := spec["template"].(map[string]any)
	podSpec, _ := template["spec"].(map[string]any)
	containers, _ := podSpec["containers"].([]any)
	if len(containers) == 0 {
		t.Fatal("no containers in Deployment pod spec")
	}
	container, _ := containers[0].(map[string]any)
	if container == nil {
		t.Fatal("container is not a map")
	}
	return container
}

func extractEnvFromSources(t *testing.T, deployment map[string]any) []map[string]any {
	t.Helper()
	container := coreContainer(t, deployment)
	envFrom, _ := container["envFrom"].([]any)
	out := make([]map[string]any, 0, len(envFrom))
	for _, src := range envFrom {
		if m, ok := src.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

func containsSecretRef(sources []map[string]any, name string) bool {
	for _, src := range sources {
		secretRef, _ := src["secretRef"].(map[string]any)
		if secretRef == nil {
			continue
		}
		if secretRef["name"] == name {
			return true
		}
	}
	return false
}

func TestRenderPostgresInheritSkipsInfraAndEnvFrom(t *testing.T) {
	spec := baseSpec()
	spec.Postgres = model.ControlPlanePostgresSpec{Mode: "inherit"}

	bundle, err := Render(spec)
	if err != nil {
		t.Fatalf("Render error: %v", err)
	}

	// Only the Namespace should be in infra (no Postgres StatefulSet/Secret/Service).
	if got, want := len(bundle.InfraObjects), 1; got != want {
		t.Fatalf("InfraObjects count = %d, want %d (only Namespace)", got, want)
	}
	if findObject(t, bundle.InfraObjects, "StatefulSet", postgresStatefulSet) != nil {
		t.Error("Postgres StatefulSet must not render in inherit mode")
	}

	// WaitTargets should only include the core Deployment (no Postgres wait).
	if got, want := len(bundle.WaitTargets), 1; got != want {
		t.Fatalf("WaitTargets count = %d, want %d (core only)", got, want)
	}
	if bundle.WaitTargets[0].Kind != "Deployment" {
		t.Errorf("WaitTargets[0].Kind = %q, want Deployment", bundle.WaitTargets[0].Kind)
	}

	// Core Deployment must not reference yggdrasil-postgres Secret in envFrom.
	core := findObject(t, bundle.CoreObjects, "Deployment", coreDeploymentName)
	if core == nil {
		t.Fatal("missing core Deployment")
	}
	containers := mustPodContainers(t, core)
	envFrom, _ := containers[0]["envFrom"].([]any)
	for _, raw := range envFrom {
		entry, _ := raw.(map[string]any)
		secretRef, _ := entry["secretRef"].(map[string]any)
		if secretRef != nil && secretRef["name"] == postgresSecretName {
			t.Errorf("envFrom must not reference %s in inherit mode", postgresSecretName)
		}
	}
}

func mustPodContainers(t *testing.T, deployment map[string]any) []map[string]any {
	t.Helper()
	spec, _ := deployment["spec"].(map[string]any)
	template, _ := spec["template"].(map[string]any)
	podSpec, _ := template["spec"].(map[string]any)
	rawContainers, _ := podSpec["containers"].([]any)
	out := make([]map[string]any, 0, len(rawContainers))
	for _, raw := range rawContainers {
		if c, ok := raw.(map[string]any); ok {
			out = append(out, c)
		}
	}
	return out
}

func TestRenderNameOverride(t *testing.T) {
	spec := baseSpec()
	spec.Name = "yggdrasil"
	spec.Postgres = model.ControlPlanePostgresSpec{Mode: "inherit"}

	bundle, err := Render(spec)
	if err != nil {
		t.Fatalf("Render error: %v", err)
	}

	if findObject(t, bundle.CoreObjects, "Deployment", "yggdrasil") == nil {
		t.Error("core Deployment must be named 'yggdrasil' when spec.name=yggdrasil")
	}
	if findObject(t, bundle.CoreObjects, "Service", "yggdrasil") == nil {
		t.Error("core Service must be named 'yggdrasil' when spec.name=yggdrasil")
	}
	if findObject(t, bundle.CoreObjects, "Secret", "yggdrasil") == nil {
		t.Error("core Secret must be named 'yggdrasil' when spec.name=yggdrasil")
	}
	if findObject(t, bundle.CoreObjects, "Deployment", "yggdrasil-core") != nil {
		t.Error("default 'yggdrasil-core' name must not appear when spec.name is set")
	}

	if len(bundle.WaitTargets) != 1 || bundle.WaitTargets[0].Name != "yggdrasil" {
		t.Errorf("WaitTargets[0].Name = %v, want yggdrasil", bundle.WaitTargets)
	}
}

func TestRenderNameDefaultsToYggdrasilCore(t *testing.T) {
	spec := baseSpec()
	spec.Postgres = model.ControlPlanePostgresSpec{Mode: "inherit"}
	bundle, err := Render(spec)
	if err != nil {
		t.Fatalf("Render error: %v", err)
	}
	if findObject(t, bundle.CoreObjects, "Deployment", coreDeploymentName) == nil {
		t.Errorf("default name must remain %q when spec.name is empty", coreDeploymentName)
	}
}

func TestRenderImagePullSecretsAndPullPolicy(t *testing.T) {
	spec := baseSpec()
	spec.Postgres = model.ControlPlanePostgresSpec{Mode: "inherit"}
	spec.ImagePullSecrets = []string{"ghcr-pull", "ecr-pull"}
	spec.PullPolicy = "IfNotPresent"

	bundle, err := Render(spec)
	if err != nil {
		t.Fatalf("Render error: %v", err)
	}

	core := findObject(t, bundle.CoreObjects, "Deployment", coreDeploymentName)
	if core == nil {
		t.Fatal("missing core Deployment")
	}

	podSpec := mustPodSpec(t, core)
	secrets, _ := podSpec["imagePullSecrets"].([]any)
	if got, want := len(secrets), 2; got != want {
		t.Fatalf("imagePullSecrets count = %d, want %d", got, want)
	}
	first, _ := secrets[0].(map[string]any)
	if first["name"] != "ghcr-pull" {
		t.Errorf("imagePullSecrets[0].name = %v, want ghcr-pull", first["name"])
	}

	containers := mustPodContainers(t, core)
	if containers[0]["imagePullPolicy"] != "IfNotPresent" {
		t.Errorf("imagePullPolicy = %v, want IfNotPresent", containers[0]["imagePullPolicy"])
	}
}

func mustPodSpec(t *testing.T, deployment map[string]any) map[string]any {
	t.Helper()
	spec, _ := deployment["spec"].(map[string]any)
	template, _ := spec["template"].(map[string]any)
	podSpec, _ := template["spec"].(map[string]any)
	return podSpec
}

func TestRenderExtraEnvFrom(t *testing.T) {
	spec := baseSpec()
	spec.Postgres = model.ControlPlanePostgresSpec{Mode: "inherit"}
	spec.ExtraEnvFrom = []model.ControlPlaneEnvFrom{
		{SecretRef: &model.ControlPlaneLocalObjectRef{Name: "yggdrasil-secrets"}},
		{ConfigMapRef: &model.ControlPlaneLocalObjectRef{Name: "yggdrasil-config"}},
	}

	bundle, err := Render(spec)
	if err != nil {
		t.Fatalf("Render error: %v", err)
	}

	core := findObject(t, bundle.CoreObjects, "Deployment", coreDeploymentName)
	containers := mustPodContainers(t, core)
	envFrom, _ := containers[0]["envFrom"].([]any)

	// Expect at least 3 entries: core Secret + yggdrasil-secrets + yggdrasil-config.
	// Exact count depends on what the render path adds in inherit mode (coreSecret only).
	hasSecret := false
	hasCM := false
	for _, raw := range envFrom {
		entry, _ := raw.(map[string]any)
		if sr, _ := entry["secretRef"].(map[string]any); sr != nil && sr["name"] == "yggdrasil-secrets" {
			hasSecret = true
		}
		if cm, _ := entry["configMapRef"].(map[string]any); cm != nil && cm["name"] == "yggdrasil-config" {
			hasCM = true
		}
	}
	if !hasSecret {
		t.Error("envFrom missing yggdrasil-secrets secretRef")
	}
	if !hasCM {
		t.Error("envFrom missing yggdrasil-config configMapRef")
	}
}
