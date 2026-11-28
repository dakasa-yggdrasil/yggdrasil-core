package repository

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
)

type nativeReadinessImageReceipt struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// This file is reviewed protected process configuration, never a manifest or
// callback input. Its exact whole-file SHA also binds the immutable journal.
type nativeReadinessPrivateConfig struct {
	Schema                string                                     `json:"schema"`
	CoreSourceCommit      string                                     `json:"core_source_commit"`
	PolicyID              string                                     `json:"policy_id"`
	PolicyChecksum        string                                     `json:"policy_checksum"`
	Binding               model.CapacityNativeWorkerReadinessBinding `json:"binding"`
	ProbeContainerName    string                                     `json:"probe_container_name"`
	CoreWorkerTemplate    corev1.Container                           `json:"core_worker_template"`
	CoreWorkerVolumes     []corev1.Volume                            `json:"core_worker_volumes"`
	ImagePullSecrets      []string                                   `json:"image_pull_secrets"`
	ControllerPodSelector metav1.LabelSelector                       `json:"controller_pod_selector"`
	DependencyEgress      []networkingv1.NetworkPolicyEgressRule     `json:"dependency_egress"`
	JournalKeyFile        string                                     `json:"journal_key_file"`
	JournalKeySHA256      string                                     `json:"journal_key_sha256"`
	CoreImageReceipt      nativeReadinessImageReceipt                `json:"core_image_receipt"`
	ProbeImageReceipt     nativeReadinessImageReceipt                `json:"probe_image_receipt"`
	Callback              NativeWorkerReadinessCallbackFiles         `json:"callback"`
	WriterRPC             NativeWorkerReadinessRPCFiles              `json:"writer_rpc"`
	ReaderRPC             NativeWorkerReadinessRPCFiles              `json:"reader_rpc"`
}

// These references are exposed only to the protected addon composition. They
// do not accept endpoint/key overrides from a workflow or HTTP envelope.
type NativeWorkerReadinessCallbackFiles struct {
	ListenAddr            string `json:"listen_addr"`
	ServerName            string `json:"server_name"`
	ServerCertificateFile string `json:"server_certificate_file"`
	ServerKeyFile         string `json:"server_key_file"`
	ServerLeafSHA256      string `json:"server_leaf_sha256"`
	ServerURI             string `json:"server_uri"`
	ClientCAFile          string `json:"client_ca_file"`
	ClientCASHA256        string `json:"client_ca_sha256"`
	ClientLeafSHA256      string `json:"client_leaf_sha256"`
	ClientURI             string `json:"client_uri"`
	BearerTokenSHA256     string `json:"bearer_token_sha256"`
}

type NativeWorkerReadinessRPCFiles struct {
	Profile                 string `json:"profile"`
	BaseURL                 string `json:"base_url"`
	HealthURL               string `json:"health_url"`
	ServerCAFile            string `json:"server_ca_file"`
	ServerCASHA256          string `json:"server_ca_sha256"`
	ServerCertificateSHA256 string `json:"server_certificate_sha256"`
	ClientCertificateFile   string `json:"client_certificate_file"`
	ClientKeyFile           string `json:"client_key_file"`
}

func (nativeReadinessPrivateConfig) String() string {
	return "[private native readiness configuration]"
}
func (c nativeReadinessPrivateConfig) GoString() string { return c.String() }
func (nativeReadinessPrivateConfig) MarshalJSON() ([]byte, error) {
	return []byte(`{"private_native_readiness_configuration":"redacted"}`), nil
}
func (NativeWorkerReadinessCallbackFiles) String() string {
	return "[private native readiness callback references]"
}
func (c NativeWorkerReadinessCallbackFiles) GoString() string { return c.String() }
func (NativeWorkerReadinessCallbackFiles) MarshalJSON() ([]byte, error) {
	return []byte(`{"private_native_readiness_callback_references":"redacted"}`), nil
}
func (NativeWorkerReadinessRPCFiles) String() string {
	return "[private native readiness RPC references]"
}
func (c NativeWorkerReadinessRPCFiles) GoString() string { return c.String() }
func (NativeWorkerReadinessRPCFiles) MarshalJSON() ([]byte, error) {
	return []byte(`{"private_native_readiness_rpc_references":"redacted"}`), nil
}

func (f NativeWorkerReadinessRPCFiles) Config(b model.CapacityNativeWorkerProbeResourceBinding, read bool) capacity.NativeWorkerRPCConfig {
	caps := []string{capacity.EnsureNativeWorkerProbeResource, capacity.DestroyNativeWorkerProbeResource}
	if read {
		caps = []string{capacity.ObserveNativeWorkerProbeResource}
	}
	return capacity.NativeWorkerRPCConfig{Adapter: b.Adapter, Profile: f.Profile, BindingName: b.Name, SDKSourceCommit: b.SourceCommit, ScopeSHA256: b.ScopeSHA256, BaseURL: f.BaseURL, HealthURL: f.HealthURL, ServerCAFile: f.ServerCAFile, ServerCASHA256: f.ServerCASHA256, ServerCertificateSHA256: f.ServerCertificateSHA256, ClientCertificateFile: f.ClientCertificateFile, ClientKeyFile: f.ClientKeyFile, AllowedCapabilities: caps}
}

func nativeReadinessLoadConfig(path, scope string, policy model.Manifest, source string) (nativeReadinessPrivateConfig, []byte, nativeReadinessObservationPins, error) {
	var c nativeReadinessPrivateConfig
	var pins nativeReadinessObservationPins
	if !nativeReadinessSHA(scope) {
		return c, nil, pins, errNativeReadinessRun
	}
	raw, err := nativeReadinessReadFile(path, 2<<20, true)
	defer clear(raw)
	sum := sha256.Sum256(raw)
	if err != nil || hex.EncodeToString(sum[:]) != scope || capacity.DecodeNativeProbeResourceJSON(raw, &c) != nil {
		return c, nil, pins, errNativeReadinessRun
	}
	p, err := parseCapacityPolicy(policy)
	if err != nil || capacity.ValidatePolicy(p) != nil || p.NativeWorkerLifecycleBinding == nil || p.NativeWorkerLifecycleBinding.ReadinessProducer == nil || p.NativeWorkerLifecycleBinding.Network == nil || p.NativeWorkerLifecycleBinding.PhaseObserver == nil || p.NativeWorkerPoolBinding == nil || c.Schema != "native_worker_readiness_producer_bindings_v1" || c.CoreSourceCommit != source || c.CoreSourceCommit != p.NativeWorkerLifecycleBinding.SourceCommit || c.PolicyID != policy.ID.String() || c.PolicyChecksum != policy.Checksum || !reflect.DeepEqual(c.Binding, *p.NativeWorkerLifecycleBinding.ReadinessProducer) || c.Binding.Namespace != policy.Metadata.Namespace || len(validation.IsDNS1123Label(c.ProbeContainerName)) != 0 || c.CoreWorkerTemplate.Name == c.ProbeContainerName || c.WriterRPC.Profile == "" || c.WriterRPC.Profile != c.ReaderRPC.Profile || c.WriterRPC.BaseURL == c.ReaderRPC.BaseURL || c.WriterRPC.ClientCertificateFile == c.ReaderRPC.ClientCertificateFile || c.WriterRPC.ClientKeyFile == c.ReaderRPC.ClientKeyFile || !nativeReadinessSHA(c.JournalKeySHA256) {
		return c, nil, pins, errNativeReadinessRun
	}
	worker, err := json.Marshal(c.CoreWorkerTemplate)
	hash := sha256.Sum256(worker)
	if err != nil || hex.EncodeToString(hash[:]) != c.Binding.StartupTemplateSHA256 || c.CoreWorkerTemplate.Image != c.Binding.CoreWorkerImage || !nativeReadinessCuratedWorker(c.CoreWorkerTemplate, c.CoreWorkerVolumes, c.Binding.CoreWorkerImage) || len(c.ControllerPodSelector.MatchLabels) == 0 || len(c.ControllerPodSelector.MatchExpressions) != 0 || len(c.DependencyEgress) == 0 || !nativeReadinessDependencyEgress(c.DependencyEgress) {
		return c, nil, pins, errNativeReadinessRun
	}
	core, err := nativeReadinessLoadPublishedImage(c.CoreImageReceipt.Path, c.CoreImageReceipt.SHA256, c.Binding.CoreWorkerImage, c.Binding.CoreWorkerSourceCommit, "core")
	if err != nil {
		return c, nil, pins, err
	}
	probe, err := nativeReadinessLoadPublishedImage(c.ProbeImageReceipt.Path, c.ProbeImageReceipt.SHA256, c.Binding.ProbeImage, c.Binding.ProbeSourceCommit, "probe")
	if err != nil {
		return c, nil, pins, err
	}
	key, err := nativeReadinessReadFile(c.JournalKeyFile, 32, true)
	keySHA := sha256.Sum256(key)
	if err != nil || len(key) != 32 || hex.EncodeToString(keySHA[:]) != c.JournalKeySHA256 {
		clear(key)
		return c, nil, pins, errNativeReadinessRun
	}
	network := p.NativeWorkerLifecycleBinding.Network
	pins = nativeReadinessObservationPins{Binding: c.Binding, ProbeContainerName: c.ProbeContainerName, CoreContainerName: c.CoreWorkerTemplate.Name, ProbeRuntimeDigests: probe.RuntimeDigests, CoreRuntimeDigests: core.RuntimeDigests, FloorName: network.Floor.NodeName, FloorUID: network.Floor.NodeUID, FloorProviderID: network.Floor.ProviderID, RegistryUID: p.NativeWorkerPoolBinding.RegistryRef.UID, PodCIDR: network.Template.PodCIDR, ServiceCIDR: network.Template.ServiceCIDR, MaxAge: time.Duration(p.NativeWorkerLifecycleBinding.PhaseObserver.MaxAgeSeconds) * time.Second}
	return c, key, pins, nil
}

func nativeReadinessCuratedWorker(worker corev1.Container, volumes []corev1.Volume, image string) bool {
	if len(worker.Command) != 1 || worker.Command[0] != "/app/yggdrasil-api-worker" || len(worker.Args) != 0 || len(worker.EnvFrom) != 0 {
		return false
	}
	literals := map[string]string{"YGGDRASIL_CORE_PROCESS_ROLE": "api_worker", "HTTP_ADDR": "127.0.0.1:9080", "NATIVE_ADMISSION_ENABLED": "true", "NATIVE_TERMINATION_PROJECTION_DIR": "/run/dakasa-native-admission", "NATIVE_TERMINATION_IMAGE_DIGEST": image[strings.LastIndex(image, "@")+1:], "DB_HOST": "budget-pg-rw.dakasa-persistent.svc.cluster.local", "DB_NAME": "yggdrasil", "DB_PORT": "5432", "DB_SSLMODE": "verify-full", "PGSSLROOTCERT": "/var/run/dakasa/minimum-data-ca/postgres-ca.crt"}
	seen := map[string]bool{}
	for _, e := range worker.Env {
		if seen[e.Name] {
			return false
		}
		seen[e.Name] = true
		if e.Name == "NATIVE_ADMISSION_KEY" {
			if e.Value != "" || e.ValueFrom == nil || e.ValueFrom.SecretKeyRef == nil || e.ValueFrom.SecretKeyRef.Name != "__NATIVE_PROBE_ADMISSION_SECRET__" || e.ValueFrom.SecretKeyRef.Key != "admission.key" {
				return false
			}
			continue
		}
		v, literal := literals[e.Name]
		if e.Name == "NATIVE_TERMINATION_MESSAGE_FILE" {
			v, literal = "/dev/termination-log", true
		}
		if literal {
			if e.ValueFrom != nil || e.Value != v {
				return false
			}
			continue
		}
		if e.ValueFrom != nil {
			if e.Value != "" || e.ValueFrom.SecretKeyRef == nil && e.ValueFrom.ConfigMapKeyRef == nil {
				return false
			}
			continue
		}
		return false
	}
	for name := range literals {
		if !seen[name] {
			return false
		}
	}
	if !seen["NATIVE_ADMISSION_KEY"] {
		return false
	}
	ca := false
	for _, v := range volumes {
		if v.Name == "minimum-data-ca" && v.ConfigMap != nil && v.ConfigMap.Name == "minimum-data-ca" {
			ca = true
		}
	}
	caMount := false
	for _, m := range worker.VolumeMounts {
		if m.Name == "minimum-data-ca" && m.MountPath == "/var/run/dakasa/minimum-data-ca" && m.ReadOnly && m.SubPath == "" && m.SubPathExpr == "" {
			caMount = true
		}
	}
	return ca && caMount
}

func nativeReadinessDependencyEgress(rules []networkingv1.NetworkPolicyEgressRule) bool {
	for _, r := range rules {
		if len(r.To) == 0 || len(r.Ports) == 0 {
			return false
		}
		for _, p := range r.Ports {
			if p.Port == nil || p.Port.Type != 0 || p.Protocol == nil || p.EndPort != nil {
				return false
			}
			n := p.Port.IntVal
			proto := *p.Protocol
			if n != 53 && n != 5432 && n != 5671 && n != 5672 {
				return false
			}
			if proto != corev1.ProtocolTCP && (proto != corev1.ProtocolUDP || n != 53) {
				return false
			}
		}
		for _, p := range r.To {
			if p.IPBlock == nil && p.PodSelector == nil {
				return false
			}
			if p.PodSelector != nil && (len(p.PodSelector.MatchLabels) == 0 || len(p.PodSelector.MatchExpressions) != 0) {
				return false
			}
			if p.NamespaceSelector != nil && (len(p.NamespaceSelector.MatchLabels) != 1 || p.NamespaceSelector.MatchLabels["kubernetes.io/metadata.name"] == "" || len(p.NamespaceSelector.MatchExpressions) != 0) {
				return false
			}
		}
	}
	return true
}
