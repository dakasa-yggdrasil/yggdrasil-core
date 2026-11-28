package repository

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"path/filepath"
	"reflect"
	"slices"
	"strings"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

type nativeMemberPrivateConfig struct {
	Schema           string                                  `json:"schema"`
	CoreSourceCommit string                                  `json:"core_source_commit"`
	PolicyID         string                                  `json:"policy_id"`
	PolicyChecksum   string                                  `json:"policy_checksum"`
	Binding          model.CapacityNativeWorkerMemberBinding `json:"binding"`
	Authority        capacity.NativeWorkerMemberAuthority    `json:"authority"`
	JournalKeyFile   string                                  `json:"journal_key_file"`
	JournalKeySHA256 string                                  `json:"journal_key_sha256"`
	WriterRPC        NativeWorkerReadinessRPCFiles           `json:"writer_rpc"`
	ReaderRPC        NativeWorkerReadinessRPCFiles           `json:"reader_rpc"`
	FenceRPC         NativeWorkerReadinessRPCFiles           `json:"fence_rpc"`
	Callbacks        []NativeWorkerMemberCallbackFiles       `json:"callbacks"`
}

// Protected file references only. Each listener has exactly one role/cert/scope.
// The stock role's profile facts are installer-pinned; no SDK header is alleged.
type NativeWorkerMemberCallbackFiles struct {
	Role                     string                             `json:"role"`
	Files                    NativeWorkerReadinessCallbackFiles `json:"files"`
	StockProfileSourceCommit string                             `json:"stock_profile_source_commit,omitempty"`
	StockProfileSHA256       string                             `json:"stock_profile_sha256,omitempty"`
}

func (nativeMemberPrivateConfig) String() string               { return "[private native member configuration]" }
func (c nativeMemberPrivateConfig) GoString() string           { return c.String() }
func (nativeMemberPrivateConfig) MarshalJSON() ([]byte, error) { return nil, errNativeMember }
func (NativeWorkerMemberCallbackFiles) String() string {
	return "[private native member callback references]"
}
func (c NativeWorkerMemberCallbackFiles) GoString() string           { return c.String() }
func (NativeWorkerMemberCallbackFiles) MarshalJSON() ([]byte, error) { return nil, errNativeMember }

func nativeMemberAuthorityValid(a capacity.NativeWorkerMemberAuthority) bool {
	if !nativeRuntimeCommit(a.SystemSourceCommit) || a.KubeletVersion != "v1.34.6+k3s1" || a.AgentConfigPath != "/etc/rancher/k3s/config.yaml" || len(a.FenceObjects) < 1 || len(a.Enforcement) < 1 || a.LegacyControllers == nil || a.WorkloadContracts == nil || a.WorkloadLineage == nil {
		return false
	}
	for _, required := range []string{"pod-manifest-path=", "manifest-url=", "cloud-provider="} {
		if !slices.Contains(a.ConfiguredKubeletArgs, required) {
			return false
		}
	}
	seen := map[string]bool{}
	priority := false
	for _, o := range a.FenceObjects {
		id, e := uuid.Parse(o.UID)
		key := o.Kind + "/" + o.Namespace + "/" + o.Name
		if e != nil || id == uuid.Nil || id.String() != o.UID || o.ResourceVersion == "" || !nativeReadinessSHA(o.PublicContentSHA256) || seen[key] {
			return false
		}
		seen[key] = true
		switch o.Kind {
		case "ValidatingAdmissionPolicy", "ValidatingAdmissionPolicyBinding", "ConfigMap", "ClusterRole", "Role", "ClusterRoleBinding", "RoleBinding", "Deployment":
		case "PriorityClass":
			want := nativeMemberDigest(map[string]any{"value": 0, "globalDefault": false, "preemptionPolicy": "Never"})
			if o.APIVersion != "scheduling.k8s.io/v1" || o.Name != "dakasa-native-placement-workloads" || o.Namespace != "" || o.PublicContentSHA256 != want {
				return false
			}
			priority = true
		default:
			return false
		}
	}
	if !priority {
		return false
	}
	contracts := map[string]bool{}
	for _, id := range a.WorkloadContracts {
		lineage, ok := a.WorkloadLineage[id]
		if id == "" || contracts[id] || !ok || len(lineage) != 2 || lineage[0].APIVersion != "apps/v1" || lineage[0].Kind != "ReplicaSet" || lineage[1].APIVersion != "apps/v1" || lineage[1].Kind != "Deployment" || !strings.HasPrefix(lineage[1].Name, "nw-") {
			return false
		}
		for _, c := range lineage {
			uid, e := uuid.Parse(c.UID)
			if e != nil || uid == uuid.Nil || uid.String() != c.UID || c.Namespace == "" || c.Name == "" || c.Generation < 1 {
				return false
			}
		}
		contracts[id] = true
	}
	return len(contracts) == len(a.WorkloadLineage)
}
func nativeRuntimeCommit(raw string) bool {
	if len(raw) != 40 {
		return false
	}
	for _, c := range raw {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func nativeMemberLoadConfig(path, scope string, policy model.Manifest, source string) (nativeMemberPrivateConfig, []byte, error) {
	var c nativeMemberPrivateConfig
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || !nativeReadinessSHA(scope) {
		return c, nil, errNativeMember
	}
	raw, e := nativeReadinessReadFile(path, 2<<20, true)
	defer clear(raw)
	if e != nil || nativeMemberRawSHA(raw) != scope || capacity.DecodeNativeProbeResourceJSON(raw, &c) != nil {
		return c, nil, errNativeMember
	}
	p, e := parseCapacityPolicy(policy)
	if e != nil || capacity.ValidatePolicy(p) != nil || p.NativeWorkerLifecycleBinding == nil || p.NativeWorkerLifecycleBinding.Members == nil || p.NativeWorkerPoolBinding == nil || c.Schema != "native_worker_member_bindings_v1" || c.CoreSourceCommit != source || source != p.NativeWorkerLifecycleBinding.SourceCommit || c.PolicyID != policy.ID.String() || c.PolicyChecksum != policy.Checksum || !reflect.DeepEqual(c.Binding, *p.NativeWorkerLifecycleBinding.Members) || !nativeMemberAuthorityValid(c.Authority) || !nativeReadinessSHA(c.JournalKeySHA256) {
		return c, nil, errNativeMember
	}
	seen := map[string]bool{}
	for _, rpc := range []NativeWorkerReadinessRPCFiles{c.WriterRPC, c.ReaderRPC, c.FenceRPC} {
		for _, ref := range []string{rpc.BaseURL, rpc.ClientCertificateFile, rpc.ClientKeyFile} {
			if ref == "" || seen[ref] {
				return c, nil, errNativeMember
			}
			seen[ref] = true
		}
	}
	if c.WriterRPC.Profile != c.Binding.Writer.Name || c.ReaderRPC.Profile != c.Binding.Reader.Name || c.FenceRPC.Profile != c.Binding.AllocatorFenceReader.Name {
		return c, nil, errNativeMember
	}
	if len(c.Callbacks) != 5 {
		return c, nil, errNativeMember
	}
	roles := map[string]bool{}
	listeners := map[string]bool{}
	leaves := map[string]bool{}
	for _, cb := range c.Callbacks {
		if roles[cb.Role] || listeners[cb.Files.ListenAddr] || leaves[cb.Files.ClientLeafSHA256] || cb.Files.ListenAddr == "" || cb.Files.ClientLeafSHA256 == "" {
			return c, nil, errNativeMember
		}
		roles[cb.Role] = true
		listeners[cb.Files.ListenAddr] = true
		leaves[cb.Files.ClientLeafSHA256] = true
		switch cb.Role {
		case NativeMemberWriterRole, NativeMemberReaderRole, NativeAllocatorFenceReaderRole, NativeMemberControllerRole:
			if cb.StockProfileSourceCommit != "" || cb.StockProfileSHA256 != "" {
				return c, nil, errNativeMember
			}
		case NativeMemberSchedulerRole:
			if !nativeRuntimeCommit(cb.StockProfileSourceCommit) || !nativeReadinessSHA(cb.StockProfileSHA256) {
				return c, nil, errNativeMember
			}
		default:
			return c, nil, errNativeMember
		}
	}
	key, e := nativeReadinessReadFile(c.JournalKeyFile, 32, true)
	if e != nil || len(key) != 32 || nativeMemberRawSHA(key) != c.JournalKeySHA256 {
		clear(key)
		return c, nil, errNativeMember
	}
	return c, key, nil
}
func nativeMemberRawSHA(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func memberRPCConfig(f NativeWorkerReadinessRPCFiles, b model.CapacityNativeWorkerProbeResourceBinding, caps ...string) capacity.NativeWorkerRPCConfig {
	return capacity.NativeWorkerRPCConfig{Adapter: b.Adapter, Profile: b.Name, BindingName: b.Name, SDKSourceCommit: b.SourceCommit, ScopeSHA256: b.ScopeSHA256, BaseURL: f.BaseURL, HealthURL: f.HealthURL, ServerCAFile: f.ServerCAFile, ServerCASHA256: f.ServerCASHA256, ServerCertificateSHA256: f.ServerCertificateSHA256, ClientCertificateFile: f.ClientCertificateFile, ClientKeyFile: f.ClientKeyFile, AllowedCapabilities: append([]string(nil), caps...)}
}
func NativeWorkerMemberRPCConfiguration(policy model.Manifest, path, scope string) (capacity.NativeWorkerRPCConfig, capacity.NativeWorkerRPCConfig, capacity.NativeWorkerRPCConfig, error) {
	var z capacity.NativeWorkerRPCConfig
	c, key, e := nativeMemberLoadConfig(path, scope, policy, capacity.CurrentGuestCoreSource())
	clear(key)
	if e != nil {
		return z, z, z, e
	}
	return memberRPCConfig(c.WriterRPC, c.Binding.Writer, "ensure_native_worker_pool_member", "destroy_native_worker_pool_member", "ensure_native_worker_pod_placement", "destroy_native_worker_pod_placement"), memberRPCConfig(c.ReaderRPC, c.Binding.Reader, "observe_native_worker_pool_member", "observe_native_worker_pod_placement"), memberRPCConfig(c.FenceRPC, c.Binding.AllocatorFenceReader, "observe_native_worker_allocator_fence"), nil
}
func NewCapacityNativeWorkerMemberStoreFromProtectedFile(workers CapacityNativeWorkerStore, policy model.Manifest, runtime NativeWorkerMemberRuntime, abort *CapacityNativeWorkerAbortStore, network *NativeWorkerConcreteNetworkRuntime, provider NativeWorkerMemberPrepareProviderFunc, path, scope string) (*CapacityNativeWorkerMemberStore, error) {
	c, key, e := nativeMemberLoadConfig(path, scope, policy, capacity.CurrentGuestCoreSource())
	defer clear(key)
	if e != nil {
		return nil, e
	}
	return NewCapacityNativeWorkerMemberStore(NativeWorkerMemberStoreConfig{Workers: workers, Policy: policy, Runtime: runtime, Abort: abort, Authority: c.Authority, Key: key, Enabled: true, ScopeSHA256: scope, Network: network, PrepareProvider: provider})
}
func NativeWorkerMemberCallbacksConfiguration(policy model.Manifest, path, scope string) ([]NativeWorkerMemberCallbackFiles, error) {
	c, key, e := nativeMemberLoadConfig(path, scope, policy, capacity.CurrentGuestCoreSource())
	clear(key)
	if e != nil {
		return nil, e
	}
	return c.Callbacks, nil
}

// Only protected installation composition receives these transient materials.
// The listener clones them before the caller discards the loader handle.
func NativeWorkerMemberCallbackMaterial(policy model.Manifest, path, scope, role string) (NativeWorkerReadinessCallbackMaterial, error) {
	var empty NativeWorkerReadinessCallbackMaterial
	c, key, e := nativeMemberLoadConfig(path, scope, policy, capacity.CurrentGuestCoreSource())
	clear(key)
	if e != nil {
		return empty, e
	}
	var f *NativeWorkerReadinessCallbackFiles
	for _, candidate := range c.Callbacks {
		if candidate.Role == role {
			copy := candidate.Files
			f = &copy
		}
	}
	if f == nil {
		return empty, errNativeMember
	}
	cert, e := nativeReadinessReadFile(f.ServerCertificateFile, 64<<10, false)
	if e != nil {
		return empty, errNativeMember
	}
	private, e := nativeReadinessReadFile(f.ServerKeyFile, 32<<10, true)
	defer clear(private)
	if e != nil {
		return empty, errNativeMember
	}
	ca, e := nativeReadinessReadFile(f.ClientCAFile, 64<<10, false)
	if e != nil || nativeMemberRawSHA(ca) != f.ClientCASHA256 {
		return empty, errNativeMember
	}
	pair, e := tls.X509KeyPair(cert, private)
	pool := x509.NewCertPool()
	if e != nil || !pool.AppendCertsFromPEM(ca) {
		return empty, errNativeMember
	}
	b := model.CapacityNativeWorkerProbeResourceBinding{Name: c.Binding.Name, SourceCommit: c.CoreSourceCommit, ScopeSHA256: scope}
	switch role {
	case NativeMemberWriterRole:
		b = c.Binding.Writer
	case NativeMemberReaderRole:
		b = c.Binding.Reader
	case NativeAllocatorFenceReaderRole:
		b = c.Binding.AllocatorFenceReader
	case NativeMemberControllerRole, NativeMemberSchedulerRole:
	default:
		return empty, errNativeMember
	}
	return NativeWorkerReadinessCallbackMaterial{Files: *f, CoreSourceCommit: c.CoreSourceCommit, Binding: b, Certificate: pair, ClientCAs: pool}, nil
}
