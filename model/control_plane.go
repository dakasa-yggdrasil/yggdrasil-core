package model

// ControlPlaneManifestSpec declares a desired yggdrasil-core deployment. A
// seed core reconciles this spec by dispatching the
// `yggdrasil.deploy-control-plane` workflow, which composes the
// integration-kubernetes and integration-schema-migrations adapters to
// apply the concrete objects (Deployments, Services, Secrets,
// transport backends, Postgres, Ingress) in the target cluster.
//
// The HTTP rpc.Transport is always-on and implicit — it is never
// declared in `transports`. Additional transports (e.g. AMQP, Kafka,
// NATS, gRPC) are opt-in via the Transports slice; each plug-in
// documents its expected `extra` keys.
type ControlPlaneManifestSpec struct {
	Image      string                     `json:"image"`
	Replicas   int                        `json:"replicas"`
	Resources  ControlPlaneResourcesSpec  `json:"resources,omitempty"`
	Postgres   ControlPlanePostgresSpec   `json:"postgres"`
	Ingress    ControlPlaneIngressSpec    `json:"ingress,omitempty"`
	Transports []ControlPlaneTransport    `json:"transports,omitempty"`
	Kubernetes ControlPlaneKubernetesSpec `json:"kubernetes"`
	Bootstrap  ControlPlaneBootstrapSpec  `json:"bootstrap,omitempty"`
}

// ControlPlaneResourcesSpec maps to Kubernetes resource requests/limits
// for the control-plane pods.
type ControlPlaneResourcesSpec struct {
	Requests ControlPlaneResourceClaim `json:"requests,omitempty"`
	Limits   ControlPlaneResourceClaim `json:"limits,omitempty"`
}

// ControlPlaneResourceClaim is a single cpu/memory claim.
type ControlPlaneResourceClaim struct {
	CPU    string `json:"cpu,omitempty"`
	Memory string `json:"memory,omitempty"`
}

// ControlPlanePostgresSpec chooses how the control-plane reaches
// Postgres. Exactly one of Bundled / External must be populated per the
// Mode field.
type ControlPlanePostgresSpec struct {
	Mode     string                            `json:"mode"`
	Bundled  *ControlPlanePostgresBundledSpec  `json:"bundled,omitempty"`
	External *ControlPlanePostgresExternalSpec `json:"external,omitempty"`
}

// ControlPlanePostgresBundledSpec deploys a Postgres StatefulSet as
// part of the control-plane.
type ControlPlanePostgresBundledSpec struct {
	Storage     string `json:"storage"`
	Image       string `json:"image,omitempty"`
	PasswordRef string `json:"password_ref,omitempty"`
}

// ControlPlanePostgresExternalSpec points at an already-running managed
// Postgres (RDS, Cloud SQL, Neon, self-managed).
type ControlPlanePostgresExternalSpec struct {
	Host        string `json:"host"`
	Port        int    `json:"port,omitempty"`
	Database    string `json:"database"`
	Username    string `json:"username"`
	PasswordRef string `json:"password_ref"`
	SSLMode     string `json:"ssl_mode,omitempty"`
}

// ControlPlaneIngressSpec optionally exposes the control-plane to the
// outside via a Kubernetes Ingress.
type ControlPlaneIngressSpec struct {
	Enabled       bool   `json:"enabled"`
	Host          string `json:"host,omitempty"`
	ClassName     string `json:"class_name,omitempty"`
	TLSSecretName string `json:"tls_secret_name,omitempty"`
}

// ControlPlaneTransport opts into an rpc.Transport backend beyond the
// always-on HTTP transport. Kind selects the backend (e.g. "amqp",
// "kafka", "nats", "grpc"); Mode picks bundled (deploy alongside the
// control-plane) vs external (reach an existing instance).
type ControlPlaneTransport struct {
	Kind     string                            `json:"kind"`
	Mode     string                            `json:"mode,omitempty"`
	Bundled  *ControlPlaneTransportBundledSpec `json:"bundled,omitempty"`
	External *ControlPlaneTransportConfigSpec  `json:"external,omitempty"`
}

// ControlPlaneTransportBundledSpec deploys the transport backend as
// part of the control-plane release (StatefulSet/Deployment + Service
// + Secret).
type ControlPlaneTransportBundledSpec struct {
	Storage        string            `json:"storage,omitempty"`
	Image          string            `json:"image,omitempty"`
	CredentialsRef string            `json:"credentials_ref,omitempty"`
	Extra          map[string]string `json:"extra,omitempty"`
}

// ControlPlaneTransportConfigSpec points at an externally-managed
// transport instance. Fields are transport-agnostic — the workflow
// passes them straight to the transport plug-in's reconciler.
type ControlPlaneTransportConfigSpec struct {
	URLRef              string            `json:"url_ref,omitempty"`
	BootstrapServersRef string            `json:"bootstrap_servers_ref,omitempty"`
	CredentialsRef      string            `json:"credentials_ref,omitempty"`
	Extra               map[string]string `json:"extra,omitempty"`
}

// ControlPlaneKubernetesSpec pins the control-plane to a specific
// cluster (via an integration_instance reference) and namespace.
type ControlPlaneKubernetesSpec struct {
	Namespace      string           `json:"namespace"`
	ServiceAccount string           `json:"service_account,omitempty"`
	ClusterRef     ManifestSelector `json:"cluster_ref"`
}

// ControlPlaneEnvFrom references an existing Kubernetes Secret or
// ConfigMap whose keys will be projected as environment variables
// on the core container. Exactly one of SecretRef / ConfigMapRef
// must be populated per entry. Mirrors the shape of the upstream
// corev1.EnvFromSource to keep the renderer trivially translatable
// by declarative_apply.
type ControlPlaneEnvFrom struct {
	SecretRef    *ControlPlaneLocalObjectRef `json:"secret_ref,omitempty"`
	ConfigMapRef *ControlPlaneLocalObjectRef `json:"config_map_ref,omitempty"`
}

// ControlPlaneLocalObjectRef names a Kubernetes object in the same
// namespace as the core Deployment. Only the name matters; callers
// must ensure the referenced object exists at apply time.
type ControlPlaneLocalObjectRef struct {
	Name string `json:"name"`
}

// ControlPlaneBootstrapSpec seeds the control-plane's first-boot.
type ControlPlaneBootstrapSpec struct {
	AdminCredentialsRef string   `json:"admin_credentials_ref,omitempty"`
	SeedIntegrations    []string `json:"seed_integrations,omitempty"`
}
