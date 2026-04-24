package controlplane

import (
	"fmt"
	"strings"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// renderNamespace produces the Namespace object. Its only purpose is
// making `kubectl apply -f` idempotent — real clusters usually already
// have the target namespace, and declarative_apply is a no-op in that
// case.
func renderNamespace(namespace string) map[string]any {
	return map[string]any{
		"apiVersion": "v1",
		"kind":       "Namespace",
		"metadata": map[string]any{
			"name":   namespace,
			"labels": baseLabels(""),
		},
	}
}

func renderBundledPostgres(namespace string, spec *model.ControlPlanePostgresBundledSpec) (map[string]any, map[string]any, map[string]any) {
	image := postgresImageDefault
	if spec != nil && strings.TrimSpace(spec.Image) != "" {
		image = spec.Image
	}
	storage := "32Gi"
	if spec != nil && strings.TrimSpace(spec.Storage) != "" {
		storage = spec.Storage
	}

	secret := map[string]any{
		"apiVersion": "v1",
		"kind":       "Secret",
		"metadata": map[string]any{
			"name":      postgresSecretName,
			"namespace": namespace,
			"labels":    baseLabels("postgres"),
		},
		"type": "Opaque",
		"stringData": map[string]any{
			"POSTGRES_USER":     postgresUserDefault,
			"POSTGRES_DB":       postgresDBDefault,
			"POSTGRES_PASSWORD": generatedPlaceholderPassword("postgres"),
			"DB_HOST":           postgresServiceName,
			"DB_PORT":           fmt.Sprintf("%d", postgresPort),
			"DB_NAME":           postgresDBDefault,
			"DB_USER":           postgresUserDefault,
			"DB_PASSWORD":       generatedPlaceholderPassword("postgres"),
		},
	}

	set := map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "StatefulSet",
		"metadata": map[string]any{
			"name":      postgresStatefulSet,
			"namespace": namespace,
			"labels":    baseLabels("postgres"),
		},
		"spec": map[string]any{
			"serviceName": postgresServiceName,
			"replicas":    1,
			"selector":    map[string]any{"matchLabels": baseLabels("postgres")},
			"template": map[string]any{
				"metadata": map[string]any{"labels": baseLabels("postgres")},
				"spec": map[string]any{
					"containers": []any{
						map[string]any{
							"name":    "postgres",
							"image":   image,
							"envFrom": []any{envFromSecret(postgresSecretName)},
							"ports": []any{
								map[string]any{"name": "postgres", "containerPort": postgresPort},
							},
							"volumeMounts": []any{
								map[string]any{"name": postgresDataVolumeName, "mountPath": postgresDataMountPath},
							},
							"readinessProbe": map[string]any{
								"exec": map[string]any{"command": []any{"pg_isready", "-U", postgresUserDefault, "-d", postgresDBDefault}},
							},
						},
					},
				},
			},
			"volumeClaimTemplates": []any{
				map[string]any{
					"metadata": map[string]any{"name": postgresDataVolumeName},
					"spec": map[string]any{
						"accessModes": []any{"ReadWriteOnce"},
						"resources": map[string]any{
							"requests": map[string]any{"storage": storage},
						},
					},
				},
			},
		},
	}

	svc := map[string]any{
		"apiVersion": "v1",
		"kind":       "Service",
		"metadata": map[string]any{
			"name":      postgresServiceName,
			"namespace": namespace,
			"labels":    baseLabels("postgres"),
		},
		"spec": map[string]any{
			"selector":  baseLabels("postgres"),
			"ports":     []any{map[string]any{"name": "postgres", "port": postgresPort, "targetPort": postgresPort}},
			"clusterIP": "None",
		},
	}

	return secret, set, svc
}

func renderBundledRabbitMQ(namespace string, spec *model.ControlPlaneTransportBundledSpec) (map[string]any, map[string]any, map[string]any) {
	image := amqpImageDefault
	if spec != nil && strings.TrimSpace(spec.Image) != "" {
		image = spec.Image
	}
	storage := "4Gi"
	if spec != nil && strings.TrimSpace(spec.Storage) != "" {
		storage = spec.Storage
	}

	secret := map[string]any{
		"apiVersion": "v1",
		"kind":       "Secret",
		"metadata": map[string]any{
			"name":      amqpSecretName,
			"namespace": namespace,
			"labels":    baseLabels("rabbitmq"),
		},
		"type": "Opaque",
		"stringData": map[string]any{
			"RABBITMQ_DEFAULT_USER": amqpUserDefault,
			"RABBITMQ_DEFAULT_PASS": generatedPlaceholderPassword("amqp"),
			"BROKER_URL":            fmt.Sprintf("amqp://%s:%s@%s:%d/", amqpUserDefault, generatedPlaceholderPassword("amqp"), amqpServiceName, amqpAMQPPort),
		},
	}

	set := map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "StatefulSet",
		"metadata": map[string]any{
			"name":      amqpStatefulSet,
			"namespace": namespace,
			"labels":    baseLabels("rabbitmq"),
		},
		"spec": map[string]any{
			"serviceName": amqpServiceName,
			"replicas":    1,
			"selector":    map[string]any{"matchLabels": baseLabels("rabbitmq")},
			"template": map[string]any{
				"metadata": map[string]any{"labels": baseLabels("rabbitmq")},
				"spec": map[string]any{
					"containers": []any{
						map[string]any{
							"name":    "rabbitmq",
							"image":   image,
							"envFrom": []any{envFromSecret(amqpSecretName)},
							"ports": []any{
								map[string]any{"name": "amqp", "containerPort": amqpAMQPPort},
								map[string]any{"name": "mgmt", "containerPort": amqpMgmtPort},
							},
							"volumeMounts": []any{
								map[string]any{"name": amqpDataVolumeName, "mountPath": amqpDataMountPath},
							},
							"readinessProbe": map[string]any{
								"exec": map[string]any{"command": []any{"rabbitmq-diagnostics", "check_running"}},
							},
						},
					},
				},
			},
			"volumeClaimTemplates": []any{
				map[string]any{
					"metadata": map[string]any{"name": amqpDataVolumeName},
					"spec": map[string]any{
						"accessModes": []any{"ReadWriteOnce"},
						"resources": map[string]any{
							"requests": map[string]any{"storage": storage},
						},
					},
				},
			},
		},
	}

	svc := map[string]any{
		"apiVersion": "v1",
		"kind":       "Service",
		"metadata": map[string]any{
			"name":      amqpServiceName,
			"namespace": namespace,
			"labels":    baseLabels("rabbitmq"),
		},
		"spec": map[string]any{
			"selector": baseLabels("rabbitmq"),
			"ports": []any{
				map[string]any{"name": "amqp", "port": amqpAMQPPort, "targetPort": amqpAMQPPort},
				map[string]any{"name": "mgmt", "port": amqpMgmtPort, "targetPort": amqpMgmtPort},
			},
		},
	}

	return secret, set, svc
}

// renderCoreSecret emits only the values the core needs that are not
// already provided by another substrate's Secret (postgres / rabbitmq
// bundled secrets, or external user-provided secrets referenced via
// the core's envFrom list).
func renderCoreSecret(namespace string, spec model.ControlPlaneManifestSpec) map[string]any {
	data := map[string]any{
		"PORT": fmt.Sprintf("%d", coreHTTPPort),
	}
	if ref := strings.TrimSpace(spec.Bootstrap.AdminCredentialsRef); ref != "" {
		// Bootstrap admin is sourced via a secret reference; the
		// deploy workflow mounts that Secret through envFrom on the
		// core Deployment (see renderCoreDeployment), so the core
		// Secret only needs to carry the toggle that tells first-run
		// bootstrap to fire.
		data["YGGDRASIL_BOOTSTRAP_ENABLED"] = "true"
	}
	return map[string]any{
		"apiVersion": "v1",
		"kind":       "Secret",
		"metadata": map[string]any{
			"name":      coreSecretName,
			"namespace": namespace,
			"labels":    baseLabels("core"),
		},
		"type":       "Opaque",
		"stringData": data,
	}
}

func renderCoreDeployment(namespace string, spec model.ControlPlaneManifestSpec, envFromSources []map[string]any) map[string]any {
	container := map[string]any{
		"name":    "yggdrasil-core",
		"image":   spec.Image,
		"envFrom": anySlice(envFromSources),
		"ports": []any{
			map[string]any{"name": coreHTTPPortName, "containerPort": coreHTTPPort},
		},
		"readinessProbe": map[string]any{
			"httpGet": map[string]any{"path": "/readyz", "port": coreHTTPPortName},
		},
		"livenessProbe": map[string]any{
			"httpGet": map[string]any{"path": "/healthz", "port": coreHTTPPortName},
		},
	}
	if r := renderResources(spec.Resources); r != nil {
		container["resources"] = r
	}

	podSpec := map[string]any{
		"containers": []any{container},
	}
	if sa := strings.TrimSpace(spec.Kubernetes.ServiceAccount); sa != "" {
		podSpec["serviceAccountName"] = sa
	}

	return map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata": map[string]any{
			"name":      coreDeploymentName,
			"namespace": namespace,
			"labels":    baseLabels("core"),
		},
		"spec": map[string]any{
			"replicas": spec.Replicas,
			"selector": map[string]any{"matchLabels": baseLabels("core")},
			"template": map[string]any{
				"metadata": map[string]any{"labels": baseLabels("core")},
				"spec":     podSpec,
			},
		},
	}
}

func renderCoreService(namespace string) map[string]any {
	return map[string]any{
		"apiVersion": "v1",
		"kind":       "Service",
		"metadata": map[string]any{
			"name":      coreServiceName,
			"namespace": namespace,
			"labels":    baseLabels("core"),
		},
		"spec": map[string]any{
			"selector": baseLabels("core"),
			"ports": []any{
				map[string]any{"name": coreHTTPPortName, "port": coreHTTPPort, "targetPort": coreHTTPPortName},
			},
		},
	}
}

func renderIngress(namespace string, ingress model.ControlPlaneIngressSpec) map[string]any {
	rule := map[string]any{
		"host": ingress.Host,
		"http": map[string]any{
			"paths": []any{
				map[string]any{
					"path":     "/",
					"pathType": "Prefix",
					"backend": map[string]any{
						"service": map[string]any{
							"name": coreServiceName,
							"port": map[string]any{"name": coreHTTPPortName},
						},
					},
				},
			},
		},
	}
	spec := map[string]any{"rules": []any{rule}}
	if cls := strings.TrimSpace(ingress.ClassName); cls != "" {
		spec["ingressClassName"] = cls
	}
	if tls := strings.TrimSpace(ingress.TLSSecretName); tls != "" {
		spec["tls"] = []any{
			map[string]any{
				"hosts":      []any{ingress.Host},
				"secretName": tls,
			},
		}
	}

	return map[string]any{
		"apiVersion": "networking.k8s.io/v1",
		"kind":       "Ingress",
		"metadata": map[string]any{
			"name":      coreIngressName,
			"namespace": namespace,
			"labels":    baseLabels("core"),
		},
		"spec": spec,
	}
}

func renderResources(resources model.ControlPlaneResourcesSpec) map[string]any {
	out := map[string]any{}
	if claim := resourceClaim(resources.Requests); claim != nil {
		out["requests"] = claim
	}
	if claim := resourceClaim(resources.Limits); claim != nil {
		out["limits"] = claim
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func resourceClaim(claim model.ControlPlaneResourceClaim) map[string]any {
	out := map[string]any{}
	if cpu := strings.TrimSpace(claim.CPU); cpu != "" {
		out["cpu"] = cpu
	}
	if mem := strings.TrimSpace(claim.Memory); mem != "" {
		out["memory"] = mem
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func envFromSecret(secretName string) map[string]any {
	return map[string]any{
		"secretRef": map[string]any{"name": secretName},
	}
}

// envFromExternalPostgresSecret mounts the user-provided Postgres
// password Secret into the core via envFrom. The secret ref uses the
// `secret://name/key` convention; we only use the `name` segment here
// — the key mapping is for the core's credentials resolver, which is
// a separate concern from pod env wiring.
func envFromExternalPostgresSecret(external *model.ControlPlanePostgresExternalSpec) map[string]any {
	if external == nil {
		return nil
	}
	if name := secretRefName(external.PasswordRef); name != "" {
		return envFromSecret(name)
	}
	return nil
}

func externalTransportSecretName(external *model.ControlPlaneTransportConfigSpec) string {
	if external == nil {
		return ""
	}
	for _, ref := range []string{external.URLRef, external.CredentialsRef, external.BootstrapServersRef} {
		if name := secretRefName(ref); name != "" {
			return name
		}
	}
	return ""
}

// secretRefName extracts the Kubernetes Secret name segment from a
// `secret://<name>/<key>` or `secret://<name>` reference. Anything that
// is not a secret:// URI is ignored (we won't fabricate Secret names
// from arbitrary strings).
func secretRefName(ref string) string {
	ref = strings.TrimSpace(ref)
	const prefix = "secret://"
	if !strings.HasPrefix(ref, prefix) {
		return ""
	}
	rest := strings.TrimPrefix(ref, prefix)
	if idx := strings.IndexByte(rest, '/'); idx >= 0 {
		rest = rest[:idx]
	}
	return rest
}

func baseLabels(component string) map[string]any {
	labels := map[string]any{coreLabelKey: coreLabelValue}
	if component != "" {
		labels["app.kubernetes.io/component"] = component
	}
	return labels
}

func anySlice(in []map[string]any) []any {
	out := make([]any, 0, len(in))
	for _, item := range in {
		if item == nil {
			continue
		}
		out = append(out, item)
	}
	return out
}

// generatedPlaceholderPassword returns a deterministic placeholder that
// the deploy workflow replaces with a real random value before the
// Secret is applied. Keeping the renderer pure (no randomness) is what
// makes the output diffable and testable; random generation is the
// workflow engine's job, not the renderer's.
func generatedPlaceholderPassword(label string) string {
	return fmt.Sprintf("__GENERATE__:%s", label)
}
