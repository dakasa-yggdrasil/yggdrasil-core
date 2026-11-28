package addons

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"regexp"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

const nativeWorkerRuntimeFileEnv = "YGGDRASIL_NATIVE_WORKER_RUNTIME_FILE"
const nativeWorkerRuntimeSchema = "native_worker_runtime_installation_v1"

var errNativeWorkerInstallation = errors.New("HOLD: protected Native runtime installation unavailable")
var nativeRuntimeSHA = regexp.MustCompile(`^[0-9a-f]{64}$`)
var nativeRuntimeSource = regexp.MustCompile(`^[0-9a-f]{40}$`)
var nativeRuntimeName = regexp.MustCompile(`^[a-z][a-z0-9]*(?:[-_.][a-z0-9]+)*$`)

// This file is private process configuration. It contains references and pins,
// never secret material, workflow inputs or a switch that enables execution.
type nativeWorkerRuntimeConfig struct {
	Schema                string                      `json:"schema"`
	CoreSourceCommit      string                      `json:"core_source_commit"`
	Policy                nativeWorkerPolicyPin       `json:"policy"`
	Profiles              []nativeWorkerProfileFiles  `json:"profiles"`
	PhaseReader           nativeWorkerRPCFiles        `json:"phase_reader"`
	PoolReader            nativeWorkerRPCFiles        `json:"pool_reader"`
	PoolReaderScopeSHA256 string                      `json:"pool_reader_scope_sha256"`
	RegistryWriter        nativeWorkerRPCFiles        `json:"registry_writer"`
	InventoryReader       nativeWorkerRPCFiles        `json:"inventory_reader"`
	FloorReader           nativeWorkerFloorFiles      `json:"floor_reader"`
	FloorWriter           nativeWorkerFloorFiles      `json:"floor_writer"`
	Readiness             *nativeWorkerReadinessFiles `json:"readiness,omitempty"`
	Members               *nativeWorkerMemberFiles    `json:"members,omitempty"`
}

type nativeWorkerPolicyPin struct {
	ID        uuid.UUID `json:"id"`
	Namespace string    `json:"namespace"`
	Name      string    `json:"name"`
	Version   int       `json:"version"`
	Checksum  string    `json:"checksum"`
}

type nativeWorkerTLSFiles struct {
	ServerCAFile            string `json:"server_ca_file"`
	ServerCASHA256          string `json:"server_ca_sha256"`
	ServerCertificateSHA256 string `json:"server_certificate_sha256"`
	ClientCertificateFile   string `json:"client_certificate_file"`
	ClientKeyFile           string `json:"client_key_file"`
}

type nativeWorkerRPCFiles struct {
	nativeWorkerTLSFiles
	BaseURL   string `json:"base_url"`
	HealthURL string `json:"health_url"`
}

type nativeWorkerFloorFiles struct {
	nativeWorkerTLSFiles
	MaxReadAgeSeconds int `json:"max_read_age_seconds"`
}

type nativeWorkerProfileFiles struct {
	Profile             string                     `json:"profile"`
	TemplateFile        string                     `json:"template_file"`
	CLIFile             string                     `json:"cli_file"`
	CLISHA256           string                     `json:"cli_sha256"`
	CLIBytes            int64                      `json:"cli_bytes"`
	AgentTokenFile      string                     `json:"agent_token_file"`
	CAFile              string                     `json:"ca_file"`
	WireGuardMasterFile string                     `json:"wireguard_master_file"`
	ArtifactBucket      string                     `json:"artifact_bucket"`
	ArtifactKey         string                     `json:"artifact_key"`
	ArtifactVersionID   string                     `json:"artifact_version_id"`
	ArtifactCredentials nativeWorkerArtifactSecret `json:"artifact_credentials"`
	GuestRead           *nativeWorkerGuestFiles    `json:"guest_read,omitempty"`
	PhysicalReader      nativeWorkerRPCFiles       `json:"physical_reader"`
	CleanupReader       nativeWorkerRPCFiles       `json:"cleanup_reader"`
	ProviderMutation    nativeWorkerRPCFiles       `json:"provider_mutation"`
}

type nativeWorkerGuestFiles struct {
	Version                        string `json:"version"`
	MasterVersion                  string `json:"master_version"`
	MasterFile                     string `json:"master_file"`
	MasterPublicKey                string `json:"master_public_key"`
	IssuerCAFile                   string `json:"issuer_ca_file"`
	IssuerCASHA256                 string `json:"issuer_ca_sha256"`
	IssuerKeyFile                  string `json:"issuer_key_file"`
	CertificateValiditySeconds     int64  `json:"certificate_validity_seconds"`
	NetworkTemplateFile            string `json:"network_template_file"`
	NetworkTemplateSHA256          string `json:"network_template_sha256"`
	MaxReadAgeSeconds              int    `json:"max_read_age_seconds"`
	PlacementBootstrapPolicySHA256 string `json:"placement_bootstrap_policy_sha256,omitempty"`
}

type nativeWorkerArtifactSecret struct {
	ID          uuid.UUID `json:"id"`
	Namespace   string    `json:"namespace"`
	Name        string    `json:"name"`
	ScopeSHA256 string    `json:"scope_sha256"`
}

func (nativeWorkerRuntimeConfig) String() string {
	return "[private Native installation configuration]"
}
func (c nativeWorkerRuntimeConfig) GoString() string { return c.String() }
func (nativeWorkerRuntimeConfig) MarshalJSON() ([]byte, error) {
	return []byte(`{"private_native_installation":"redacted"}`), nil
}

func nativeWorkerConfigDecode(raw []byte, source string) (nativeWorkerRuntimeConfig, error) {
	var c nativeWorkerRuntimeConfig
	if len(raw) == 0 || len(raw) > 256<<10 || capacity.DecodeNativeCapacity(json.RawMessage(raw), &c) != nil ||
		c.Schema != nativeWorkerRuntimeSchema || !nativeRuntimeSource.MatchString(source) || c.CoreSourceCommit != source ||
		c.Policy.ID == uuid.Nil || !nativeRuntimeName.MatchString(c.Policy.Namespace) || !nativeRuntimeName.MatchString(c.Policy.Name) ||
		c.Policy.Version < 1 || !nativeRuntimeSHA.MatchString(c.Policy.Checksum) || !nativeRuntimeSHA.MatchString(c.PoolReaderScopeSHA256) || len(c.Profiles) < 1 || len(c.Profiles) > 256 {
		return nativeWorkerRuntimeConfig{}, errNativeWorkerInstallation
	}
	seen := map[string]bool{}
	if c.Readiness != nil && (!nativeWorkerPrivatePath(c.Readiness.File) || !nativeRuntimeSHA.MatchString(c.Readiness.SHA256)) {
		return nativeWorkerRuntimeConfig{}, errNativeWorkerInstallation
	}
	if c.Members != nil && (!nativeWorkerPrivatePath(c.Members.File) || !nativeRuntimeSHA.MatchString(c.Members.SHA256)) {
		return nativeWorkerRuntimeConfig{}, errNativeWorkerInstallation
	}
	for _, profile := range c.Profiles {
		if !nativeRuntimeName.MatchString(profile.Profile) || seen[profile.Profile] {
			return nativeWorkerRuntimeConfig{}, errNativeWorkerInstallation
		}
		seen[profile.Profile] = true
	}
	return c, nil
}

func nativeWorkerPolicyMatches(pin nativeWorkerPolicyPin, p model.Manifest) bool {
	return p.ID == pin.ID && p.Kind == "capacity_policy" && p.Metadata.Active && p.Metadata.Namespace == pin.Namespace &&
		p.Metadata.Name == pin.Name && p.Version == pin.Version && p.Checksum == pin.Checksum
}

func nativeWorkerPrivatePath(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && path != "/"
}

func (c nativeWorkerRPCFiles) config(adapter model.CapacityMarketAdapterBinding, profile, binding, source, scope string, capabilities ...string) capacity.NativeWorkerRPCConfig {
	return capacity.NativeWorkerRPCConfig{Adapter: adapter, Profile: profile, BindingName: binding, SDKSourceCommit: source, ScopeSHA256: scope,
		BaseURL: c.BaseURL, HealthURL: c.HealthURL, ServerCAFile: c.ServerCAFile, ServerCASHA256: c.ServerCASHA256,
		ServerCertificateSHA256: c.ServerCertificateSHA256, ClientCertificateFile: c.ClientCertificateFile, ClientKeyFile: c.ClientKeyFile,
		AllowedCapabilities: append([]string(nil), capabilities...)}
}

func (c nativeWorkerFloorFiles) floorConfig(b model.CapacityNativeWorkerNetworkBinding, role string) capacity.NativeWorkerNetworkRPCConfig {
	result := capacity.NativeWorkerNetworkRPCConfig{Role: role, Floor: b.Floor, Template: b.Template, TemplateSHA256: b.TemplateSHA256,
		MaxReadAgeSeconds: c.MaxReadAgeSeconds, ServerCAFile: c.ServerCAFile, ServerCASHA256: c.ServerCASHA256, ServerCertificateSHA256: c.ServerCertificateSHA256,
		ClientCertificateFile: c.ClientCertificateFile, ClientKeyFile: c.ClientKeyFile}
	if role == "reader" {
		result.AdapterID, result.BindingName, result.SystemSourceCommit, result.ScopeSHA256 = b.Reader.AdapterID, b.Reader.BindingName, b.Reader.SystemSourceCommit, b.Reader.ScopeSHA256
	} else {
		result.AdapterID, result.BindingName, result.SystemSourceCommit, result.ScopeSHA256 = b.Writer.AdapterID, b.Writer.BindingName, b.Writer.SystemSourceCommit, b.Writer.ScopeSHA256
	}
	return result
}

func (c nativeWorkerGuestFiles) config() *capacity.NativeWorkerGuestReadConfig {
	return &capacity.NativeWorkerGuestReadConfig{Version: c.Version, MasterVersion: c.MasterVersion, MasterFile: c.MasterFile,
		MasterPublicKey: c.MasterPublicKey, IssuerCAFile: c.IssuerCAFile, IssuerCASHA256: c.IssuerCASHA256, IssuerKeyFile: c.IssuerKeyFile,
		CertificateValiditySeconds: c.CertificateValiditySeconds, NetworkTemplateFile: c.NetworkTemplateFile,
		NetworkTemplateSHA256: c.NetworkTemplateSHA256, MaxReadAgeSeconds: c.MaxReadAgeSeconds, PlacementBootstrapPolicySHA256: c.PlacementBootstrapPolicySHA256}
}
