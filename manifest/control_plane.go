package manifest

import (
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

var (
	// supportedControlPlaneTransportKinds mirrors the rpc.Transport
	// backends the core knows how to dispatch through. Extending the
	// list is the signal that a new plug-in has been registered; no
	// other change in this file is needed.
	supportedControlPlaneTransportKinds = []string{"amqp", "kafka", "nats", "grpc"}
	supportedControlPlanePostgresModes  = []string{"bundled", "external", "inherit"}
	supportedControlPlaneTransportModes = []string{"bundled", "external"}
	supportedControlPlanePostgresSSL    = []string{"disable", "require", "verify-ca", "verify-full"}
	controlPlaneStorageSizePattern      = regexp.MustCompile(`^[1-9][0-9]*(Mi|Gi|Ti)$`)
	controlPlaneSecretRefPattern        = regexp.MustCompile(`^secret://[a-z0-9][a-z0-9._:/-]*$`)
	supportedControlPlanePullPolicies   = []string{"Always", "IfNotPresent", "Never"}
	controlPlaneNamePattern             = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)
)

// ParseControlPlaneSpec parses the raw spec payload into the typed
// control_plane manifest.
func ParseControlPlaneSpec(raw json.RawMessage) (model.ControlPlaneManifestSpec, error) {
	var spec model.ControlPlaneManifestSpec
	if err := json.Unmarshal(raw, &spec); err != nil {
		return model.ControlPlaneManifestSpec{}, fmt.Errorf("parse control_plane spec: %w", err)
	}
	return spec, nil
}

// ValidateControlPlaneSpec validates a control_plane manifest describing
// a desired yggdrasil-core deployment.
func ValidateControlPlaneSpec(spec model.ControlPlaneManifestSpec) error {
	if strings.TrimSpace(spec.Image) == "" {
		return fmt.Errorf("control_plane image is required")
	}
	if spec.Replicas <= 0 {
		return fmt.Errorf("control_plane replicas must be greater than zero")
	}
	if name := strings.TrimSpace(spec.Name); name != "" && !controlPlaneNamePattern.MatchString(name) {
		return fmt.Errorf("control_plane name %q must match DNS-1123 label", spec.Name)
	}
	if policy := strings.TrimSpace(spec.PullPolicy); policy != "" && !slices.Contains(supportedControlPlanePullPolicies, policy) {
		return fmt.Errorf("control_plane pull_policy %q is unsupported", spec.PullPolicy)
	}
	if err := validateControlPlaneEnvFrom(spec.ExtraEnvFrom); err != nil {
		return err
	}

	if err := validateControlPlanePostgres(spec.Postgres); err != nil {
		return err
	}
	if err := validateControlPlaneIngress(spec.Ingress); err != nil {
		return err
	}
	if err := validateControlPlaneTransports(spec.Transports); err != nil {
		return err
	}
	if err := validateControlPlaneKubernetes(spec.Kubernetes); err != nil {
		return err
	}
	if err := validateControlPlaneBootstrap(spec.Bootstrap); err != nil {
		return err
	}
	return nil
}

func validateControlPlaneEnvFrom(entries []model.ControlPlaneEnvFrom) error {
	for i, entry := range entries {
		hasSecret := entry.SecretRef != nil && strings.TrimSpace(entry.SecretRef.Name) != ""
		hasCM := entry.ConfigMapRef != nil && strings.TrimSpace(entry.ConfigMapRef.Name) != ""
		switch {
		case !hasSecret && !hasCM:
			return fmt.Errorf("control_plane extra_env_from[%d] must set secret_ref.name or config_map_ref.name", i)
		case hasSecret && hasCM:
			return fmt.Errorf("control_plane extra_env_from[%d] must set exactly one of secret_ref/config_map_ref", i)
		}
	}
	return nil
}

func validateControlPlanePostgres(pg model.ControlPlanePostgresSpec) error {
	mode := strings.ToLower(strings.TrimSpace(pg.Mode))
	if !slices.Contains(supportedControlPlanePostgresModes, mode) {
		return fmt.Errorf("control_plane postgres mode %q is unsupported", pg.Mode)
	}

	switch mode {
	case "bundled":
		if pg.Bundled == nil {
			return fmt.Errorf("control_plane postgres.bundled is required when mode=bundled")
		}
		if pg.External != nil {
			return fmt.Errorf("control_plane postgres.external must be empty when mode=bundled")
		}
		if !controlPlaneStorageSizePattern.MatchString(pg.Bundled.Storage) {
			return fmt.Errorf("control_plane postgres.bundled.storage %q is invalid (expected e.g. 32Gi)", pg.Bundled.Storage)
		}
		if ref := strings.TrimSpace(pg.Bundled.PasswordRef); ref != "" {
			if !controlPlaneSecretRefPattern.MatchString(ref) {
				return fmt.Errorf("control_plane postgres.bundled.password_ref %q is invalid", ref)
			}
		}
	case "external":
		if pg.External == nil {
			return fmt.Errorf("control_plane postgres.external is required when mode=external")
		}
		if pg.Bundled != nil {
			return fmt.Errorf("control_plane postgres.bundled must be empty when mode=external")
		}
		if strings.TrimSpace(pg.External.Host) == "" {
			return fmt.Errorf("control_plane postgres.external.host is required")
		}
		if strings.TrimSpace(pg.External.Database) == "" {
			return fmt.Errorf("control_plane postgres.external.database is required")
		}
		if strings.TrimSpace(pg.External.Username) == "" {
			return fmt.Errorf("control_plane postgres.external.username is required")
		}
		if !controlPlaneSecretRefPattern.MatchString(pg.External.PasswordRef) {
			return fmt.Errorf("control_plane postgres.external.password_ref %q is invalid", pg.External.PasswordRef)
		}
		if pg.External.Port < 0 || pg.External.Port > 65535 {
			return fmt.Errorf("control_plane postgres.external.port %d is out of range", pg.External.Port)
		}
		if ssl := strings.ToLower(strings.TrimSpace(pg.External.SSLMode)); ssl != "" {
			if !slices.Contains(supportedControlPlanePostgresSSL, ssl) {
				return fmt.Errorf("control_plane postgres.external.ssl_mode %q is unsupported", pg.External.SSLMode)
			}
		}
	case "inherit":
		if pg.Bundled != nil {
			return fmt.Errorf("control_plane postgres.bundled must be empty when mode=inherit")
		}
		if pg.External != nil {
			return fmt.Errorf("control_plane postgres.external must be empty when mode=inherit")
		}
	}
	return nil
}

func validateControlPlaneIngress(ingress model.ControlPlaneIngressSpec) error {
	if !ingress.Enabled {
		return nil
	}
	if strings.TrimSpace(ingress.Host) == "" {
		return fmt.Errorf("control_plane ingress.host is required when ingress.enabled=true")
	}
	return nil
}

func validateControlPlaneTransports(transports []model.ControlPlaneTransport) error {
	seen := map[string]struct{}{}
	for _, transport := range transports {
		kind := strings.ToLower(strings.TrimSpace(transport.Kind))
		if kind == "" {
			return fmt.Errorf("control_plane transport kind is required")
		}
		if kind == "http" {
			return fmt.Errorf("control_plane transport %q is always-on and must not be declared", kind)
		}
		if !slices.Contains(supportedControlPlaneTransportKinds, kind) {
			return fmt.Errorf("control_plane transport kind %q is unsupported", transport.Kind)
		}
		if _, exists := seen[kind]; exists {
			return fmt.Errorf("control_plane transport %q is duplicated", kind)
		}
		seen[kind] = struct{}{}

		if err := validateControlPlaneTransportConfig(kind, transport); err != nil {
			return err
		}
	}
	return nil
}

func validateControlPlaneTransportConfig(kind string, transport model.ControlPlaneTransport) error {
	mode := strings.ToLower(strings.TrimSpace(transport.Mode))
	if !slices.Contains(supportedControlPlaneTransportModes, mode) {
		return fmt.Errorf("control_plane transport %q mode %q is unsupported", kind, transport.Mode)
	}

	switch mode {
	case "bundled":
		if transport.Bundled == nil {
			return fmt.Errorf("control_plane transport %q bundled is required when mode=bundled", kind)
		}
		if transport.External != nil {
			return fmt.Errorf("control_plane transport %q external must be empty when mode=bundled", kind)
		}
		if size := strings.TrimSpace(transport.Bundled.Storage); size != "" {
			if !controlPlaneStorageSizePattern.MatchString(size) {
				return fmt.Errorf("control_plane transport %q bundled.storage %q is invalid", kind, size)
			}
		}
		if ref := strings.TrimSpace(transport.Bundled.CredentialsRef); ref != "" {
			if !controlPlaneSecretRefPattern.MatchString(ref) {
				return fmt.Errorf("control_plane transport %q bundled.credentials_ref %q is invalid", kind, ref)
			}
		}
	case "external":
		if transport.External == nil {
			return fmt.Errorf("control_plane transport %q external is required when mode=external", kind)
		}
		if transport.Bundled != nil {
			return fmt.Errorf("control_plane transport %q bundled must be empty when mode=external", kind)
		}
		for label, value := range map[string]string{
			"url_ref":               transport.External.URLRef,
			"bootstrap_servers_ref": transport.External.BootstrapServersRef,
			"credentials_ref":       transport.External.CredentialsRef,
		} {
			value = strings.TrimSpace(value)
			if value == "" {
				continue
			}
			if !controlPlaneSecretRefPattern.MatchString(value) {
				return fmt.Errorf("control_plane transport %q external.%s %q is invalid", kind, label, value)
			}
		}
	}
	return nil
}

func validateControlPlaneKubernetes(kube model.ControlPlaneKubernetesSpec) error {
	if strings.TrimSpace(kube.Namespace) == "" {
		return fmt.Errorf("control_plane kubernetes.namespace is required")
	}
	if err := validateManifestSelector("control_plane kubernetes.cluster_ref", kube.ClusterRef); err != nil {
		return err
	}
	return nil
}

func validateControlPlaneBootstrap(bootstrap model.ControlPlaneBootstrapSpec) error {
	if ref := strings.TrimSpace(bootstrap.AdminCredentialsRef); ref != "" {
		if !controlPlaneSecretRefPattern.MatchString(ref) {
			return fmt.Errorf("control_plane bootstrap.admin_credentials_ref %q is invalid", ref)
		}
	}
	if err := validateNamedStringList("control_plane bootstrap.seed_integrations", bootstrap.SeedIntegrations); err != nil {
		return err
	}
	return nil
}
