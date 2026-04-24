// Package controlplane renders a ControlPlaneManifestSpec into a bundle
// of Kubernetes objects suitable for the integration-kubernetes adapter
// (declarative_apply) to persist and observe.
//
// This is where the schema → objects mapping lives, and it is the same
// function a future K8s operator would invoke from its reconcile loop.
// Keep the output shape (map[string]any) in sync with the unstructured
// envelope the adapter expects; structs would force a dependency on
// kubernetes-go types that the core does not otherwise need.
package controlplane

import (
	"fmt"
	"strings"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// RenderedBundle groups the objects produced from one
// ControlPlaneManifestSpec by their reconciliation phase:
//
//   - InfraObjects — namespace, Postgres, transport backends. Must
//     reconcile and become ready before CoreObjects are applied.
//   - CoreObjects — the yggdrasil-core Secret, Deployment, Service,
//     optional Ingress. Depends on infra being reachable.
//   - WaitTargets — workload references the workflow uses with
//     observe_objects to gate further steps on readiness. Only
//     populated for objects that need explicit readiness verification
//     (bundled Postgres, bundled transport backends, core Deployment).
type RenderedBundle struct {
	InfraObjects []map[string]any `json:"infra_objects"`
	CoreObjects  []map[string]any `json:"core_objects"`
	WaitTargets  []WaitTarget     `json:"wait_targets"`
}

// WaitTarget names one workload the deploy workflow should wait on
// before moving past the phase it belongs to.
type WaitTarget struct {
	Phase     string `json:"phase"`
	Namespace string `json:"namespace"`
	Kind      string `json:"kind"`
	Name      string `json:"name"`
}

const (
	phaseInfra = "infra"
	phaseCore  = "core"

	coreLabelKey   = "app.kubernetes.io/part-of"
	coreLabelValue = "yggdrasil"

	coreSecretName     = "yggdrasil-core"
	coreDeploymentName = "yggdrasil-core"
	coreServiceName    = "yggdrasil-core"
	coreIngressName    = "yggdrasil-core"
	coreHTTPPortName   = "http"
	coreHTTPPort       = 9080

	postgresSecretName     = "yggdrasil-postgres"
	postgresStatefulSet    = "yggdrasil-postgres"
	postgresServiceName    = "yggdrasil-postgres"
	postgresImageDefault   = "postgres:16-alpine"
	postgresDBDefault      = "yggdrasil"
	postgresUserDefault    = "yggdrasil"
	postgresPort           = 5432
	postgresDataMountPath  = "/var/lib/postgresql/data"
	postgresDataVolumeName = "data"

	amqpSecretName     = "yggdrasil-rabbitmq"
	amqpStatefulSet    = "yggdrasil-rabbitmq"
	amqpServiceName    = "yggdrasil-rabbitmq"
	amqpImageDefault   = "rabbitmq:3.13-management-alpine"
	amqpUserDefault    = "yggdrasil"
	amqpAMQPPort       = 5672
	amqpMgmtPort       = 15672
	amqpDataMountPath  = "/var/lib/rabbitmq"
	amqpDataVolumeName = "data"
)

// resourceNameOrDefault picks spec.Name when set, else the hard-coded
// default. Kept deliberately unexported and passed into each renderer
// helper explicitly so the tests can still assert against the default
// constants via the helpers' named-arg variants.
func resourceNameOrDefault(spec model.ControlPlaneManifestSpec, fallback string) string {
	if name := strings.TrimSpace(spec.Name); name != "" {
		return name
	}
	return fallback
}

// Render translates spec into the concrete Kubernetes objects that make
// up a yggdrasil-core deployment. The spec is assumed to have been
// validated via manifest.ValidateControlPlaneSpec beforehand; the
// renderer performs only a best-effort shape check and trusts the
// validator for field-level correctness.
func Render(spec model.ControlPlaneManifestSpec) (*RenderedBundle, error) {
	namespace := strings.TrimSpace(spec.Kubernetes.Namespace)
	if namespace == "" {
		return nil, fmt.Errorf("control_plane render requires kubernetes.namespace")
	}
	if strings.TrimSpace(spec.Image) == "" {
		return nil, fmt.Errorf("control_plane render requires spec.image")
	}
	if spec.Replicas <= 0 {
		return nil, fmt.Errorf("control_plane render requires spec.replicas > 0")
	}

	bundle := &RenderedBundle{
		InfraObjects: []map[string]any{renderNamespace(namespace)},
	}

	coreEnvSources := []map[string]any{}

	switch strings.ToLower(strings.TrimSpace(spec.Postgres.Mode)) {
	case "bundled":
		secret, set, svc := renderBundledPostgres(namespace, spec.Postgres.Bundled)
		bundle.InfraObjects = append(bundle.InfraObjects, secret, set, svc)
		bundle.WaitTargets = append(bundle.WaitTargets, WaitTarget{
			Phase: phaseInfra, Namespace: namespace, Kind: "StatefulSet", Name: postgresStatefulSet,
		})
		coreEnvSources = append(coreEnvSources, envFromSecret(postgresSecretName))
	case "external":
		// envFrom is appended below, after the core Secret entry, to preserve
		// ordering (core Secret first, external Postgres Secret second).
	case "inherit":
		// nothing to render; caller supplies DB_* via spec.ExtraEnvFrom.
	}

	for _, transport := range spec.Transports {
		kind := strings.ToLower(strings.TrimSpace(transport.Kind))
		if kind != "amqp" {
			return nil, fmt.Errorf("control_plane render: transport %q is declared in the spec but not yet supported by the deploy workflow", transport.Kind)
		}
		if strings.EqualFold(transport.Mode, "bundled") {
			secret, set, svc := renderBundledRabbitMQ(namespace, transport.Bundled)
			bundle.InfraObjects = append(bundle.InfraObjects, secret, set, svc)
			bundle.WaitTargets = append(bundle.WaitTargets, WaitTarget{
				Phase: phaseInfra, Namespace: namespace, Kind: "StatefulSet", Name: amqpStatefulSet,
			})
			coreEnvSources = append(coreEnvSources, envFromSecret(amqpSecretName))
		}
		// External mode: no workload to render. The workflow wires
		// BROKER_URL via the user-provided Secret ref directly in the
		// core Secret's envFrom block (see renderCoreSecret).
	}

	coreName := resourceNameOrDefault(spec, coreDeploymentName)

	coreSecret := renderCoreSecret(namespace, coreName, spec)
	bundle.CoreObjects = append(bundle.CoreObjects, coreSecret)
	coreEnvSources = append(coreEnvSources, envFromSecret(coreName))

	if strings.EqualFold(spec.Postgres.Mode, "external") {
		coreEnvSources = append(coreEnvSources, envFromExternalPostgresSecret(spec.Postgres.External))
	}
	for _, transport := range spec.Transports {
		if strings.EqualFold(transport.Kind, "amqp") && strings.EqualFold(transport.Mode, "external") {
			if extName := externalTransportSecretName(transport.External); extName != "" {
				coreEnvSources = append(coreEnvSources, envFromSecret(extName))
			}
		}
	}

	for _, entry := range spec.ExtraEnvFrom {
		switch {
		case entry.SecretRef != nil && strings.TrimSpace(entry.SecretRef.Name) != "":
			coreEnvSources = append(coreEnvSources, envFromSecret(entry.SecretRef.Name))
		case entry.ConfigMapRef != nil && strings.TrimSpace(entry.ConfigMapRef.Name) != "":
			coreEnvSources = append(coreEnvSources, envFromConfigMap(entry.ConfigMapRef.Name))
		}
	}

	bundle.CoreObjects = append(bundle.CoreObjects,
		renderCoreDeployment(namespace, coreName, spec, coreEnvSources),
		renderCoreService(namespace, coreName),
	)
	bundle.WaitTargets = append(bundle.WaitTargets, WaitTarget{
		Phase: phaseCore, Namespace: namespace, Kind: "Deployment", Name: coreName,
	})

	if spec.Ingress.Enabled {
		bundle.CoreObjects = append(bundle.CoreObjects, renderIngress(namespace, coreName, spec.Ingress))
	}

	return bundle, nil
}
