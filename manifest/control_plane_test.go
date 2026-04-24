package manifest

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func controlPlaneSpecFixture() model.ControlPlaneManifestSpec {
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

func TestValidateControlPlaneSpec(t *testing.T) {
	if err := ValidateControlPlaneSpec(controlPlaneSpecFixture()); err != nil {
		t.Fatalf("ValidateControlPlaneSpec error: %v", err)
	}
}

func TestValidateControlPlaneSpecRequiresImage(t *testing.T) {
	spec := controlPlaneSpecFixture()
	spec.Image = ""
	if err := ValidateControlPlaneSpec(spec); err == nil {
		t.Fatal("expected missing image to fail validation")
	}
}

func TestValidateControlPlaneSpecRejectsZeroReplicas(t *testing.T) {
	spec := controlPlaneSpecFixture()
	spec.Replicas = 0
	if err := ValidateControlPlaneSpec(spec); err == nil {
		t.Fatal("expected replicas=0 to fail validation")
	}
}

func TestValidateControlPlanePostgresBundledRequiresStorage(t *testing.T) {
	spec := controlPlaneSpecFixture()
	spec.Postgres.Bundled.Storage = "garbage"
	if err := ValidateControlPlaneSpec(spec); err == nil {
		t.Fatal("expected invalid storage size to fail validation")
	}
}

func TestValidateControlPlanePostgresExternal(t *testing.T) {
	spec := controlPlaneSpecFixture()
	spec.Postgres = model.ControlPlanePostgresSpec{
		Mode: "external",
		External: &model.ControlPlanePostgresExternalSpec{
			Host:        "db.example.com",
			Database:    "yggdrasil",
			Username:    "yggdrasil",
			PasswordRef: "secret://yggdrasil/pg-password",
			SSLMode:     "require",
		},
	}
	if err := ValidateControlPlaneSpec(spec); err != nil {
		t.Fatalf("ValidateControlPlaneSpec external postgres error: %v", err)
	}
}

func TestValidateControlPlanePostgresExternalRejectsBadSecretRef(t *testing.T) {
	spec := controlPlaneSpecFixture()
	spec.Postgres = model.ControlPlanePostgresSpec{
		Mode: "external",
		External: &model.ControlPlanePostgresExternalSpec{
			Host:        "db.example.com",
			Database:    "yggdrasil",
			Username:    "yggdrasil",
			PasswordRef: "vault://wrong-scheme",
		},
	}
	if err := ValidateControlPlaneSpec(spec); err == nil {
		t.Fatal("expected bad secret_ref scheme to fail validation")
	}
}

func TestValidateControlPlanePostgresRejectsBothBundledAndExternal(t *testing.T) {
	spec := controlPlaneSpecFixture()
	spec.Postgres.External = &model.ControlPlanePostgresExternalSpec{
		Host: "x", Database: "y", Username: "z", PasswordRef: "secret://a/b",
	}
	if err := ValidateControlPlaneSpec(spec); err == nil {
		t.Fatal("expected both bundled+external to fail validation")
	}
}

func TestValidateControlPlaneTransportsAMQPBundled(t *testing.T) {
	spec := controlPlaneSpecFixture()
	spec.Transports = []model.ControlPlaneTransport{{
		Kind: "amqp",
		Mode: "bundled",
		Bundled: &model.ControlPlaneTransportBundledSpec{
			Storage: "4Gi",
		},
	}}
	if err := ValidateControlPlaneSpec(spec); err != nil {
		t.Fatalf("ValidateControlPlaneSpec amqp bundled error: %v", err)
	}
}

func TestValidateControlPlaneTransportsKafkaExternal(t *testing.T) {
	spec := controlPlaneSpecFixture()
	spec.Transports = []model.ControlPlaneTransport{{
		Kind: "kafka",
		Mode: "external",
		External: &model.ControlPlaneTransportConfigSpec{
			BootstrapServersRef: "secret://kafka/bootstrap",
			CredentialsRef:      "secret://kafka/sasl",
		},
	}}
	if err := ValidateControlPlaneSpec(spec); err != nil {
		t.Fatalf("ValidateControlPlaneSpec kafka external error: %v", err)
	}
}

func TestValidateControlPlaneTransportsRejectsHTTPDeclaration(t *testing.T) {
	spec := controlPlaneSpecFixture()
	spec.Transports = []model.ControlPlaneTransport{{Kind: "http"}}
	err := ValidateControlPlaneSpec(spec)
	if err == nil || !strings.Contains(err.Error(), "always-on") {
		t.Fatalf("expected http transport to be rejected as always-on, got %v", err)
	}
}

func TestValidateControlPlaneTransportsRejectsDuplicates(t *testing.T) {
	spec := controlPlaneSpecFixture()
	spec.Transports = []model.ControlPlaneTransport{
		{Kind: "amqp", Mode: "bundled", Bundled: &model.ControlPlaneTransportBundledSpec{Storage: "4Gi"}},
		{Kind: "amqp", Mode: "external", External: &model.ControlPlaneTransportConfigSpec{URLRef: "secret://x/y"}},
	}
	if err := ValidateControlPlaneSpec(spec); err == nil {
		t.Fatal("expected duplicate transport kind to fail validation")
	}
}

func TestValidateControlPlaneTransportsRejectsUnknownKind(t *testing.T) {
	spec := controlPlaneSpecFixture()
	spec.Transports = []model.ControlPlaneTransport{{Kind: "carrier-pigeon", Mode: "external"}}
	if err := ValidateControlPlaneSpec(spec); err == nil {
		t.Fatal("expected unknown transport kind to fail validation")
	}
}

func TestValidateControlPlaneIngressRequiresHostWhenEnabled(t *testing.T) {
	spec := controlPlaneSpecFixture()
	spec.Ingress = model.ControlPlaneIngressSpec{Enabled: true}
	if err := ValidateControlPlaneSpec(spec); err == nil {
		t.Fatal("expected ingress.enabled without host to fail validation")
	}
}

func TestValidateControlPlaneKubernetesRequiresClusterRef(t *testing.T) {
	spec := controlPlaneSpecFixture()
	spec.Kubernetes.ClusterRef = model.ManifestSelector{}
	if err := ValidateControlPlaneSpec(spec); err == nil {
		t.Fatal("expected missing cluster_ref to fail validation")
	}
}

func TestControlPlaneDocumentValidation(t *testing.T) {
	raw, err := json.Marshal(controlPlaneSpecFixture())
	if err != nil {
		t.Fatalf("json.Marshal error: %v", err)
	}

	doc := model.ManifestDocument{
		APIVersion: "yggdrasil.io/v1alpha1",
		Kind:       "control_plane",
		Metadata: model.ManifestMetadataInput{
			Name:      "primary",
			Namespace: "global",
		},
		Spec: raw,
	}

	if err := ValidateDocument(doc); err != nil {
		t.Fatalf("ValidateDocument(control_plane) error: %v", err)
	}
}

func TestValidateControlPlanePostgresInherit(t *testing.T) {
	spec := controlPlaneSpecFixture()
	spec.Postgres = model.ControlPlanePostgresSpec{Mode: "inherit"}
	if err := ValidateControlPlaneSpec(spec); err != nil {
		t.Fatalf("postgres.mode=inherit should validate, got %v", err)
	}
}

func TestValidateControlPlanePostgresInheritRejectsBundled(t *testing.T) {
	spec := controlPlaneSpecFixture()
	spec.Postgres = model.ControlPlanePostgresSpec{
		Mode:    "inherit",
		Bundled: &model.ControlPlanePostgresBundledSpec{Storage: "10Gi"},
	}
	if err := ValidateControlPlaneSpec(spec); err == nil {
		t.Fatal("expected postgres.mode=inherit with bundled to fail validation")
	}
}

func TestValidateControlPlanePostgresInheritRejectsExternal(t *testing.T) {
	spec := controlPlaneSpecFixture()
	spec.Postgres = model.ControlPlanePostgresSpec{
		Mode: "inherit",
		External: &model.ControlPlanePostgresExternalSpec{
			Host: "example.local", Database: "y", Username: "u",
			PasswordRef: "secret://x",
		},
	}
	if err := ValidateControlPlaneSpec(spec); err == nil {
		t.Fatal("expected postgres.mode=inherit with external to fail validation")
	}
}
