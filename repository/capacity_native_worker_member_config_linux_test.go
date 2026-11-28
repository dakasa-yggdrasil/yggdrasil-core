//go:build linux

package repository

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

type memberConfigFixture struct {
	base   readinessConfigFixture
	config nativeMemberPrivateConfig
}

// Schema-only protected installation vectors. They exercise the actual closed
// file loader and policy validator; they do not claim an installer, canary,
// configz read or published runtime exists.
func newMemberConfigFixture(t *testing.T) memberConfigFixture {
	t.Helper()
	base := readinessConfigFixtureFor(t)
	binding := func(name, digit string, writer bool) model.CapacityNativeWorkerProbeResourceBinding {
		x := base.c.Binding.ResourceReader
		x.Name = name
		x.Adapter.ManifestID = uuid.NewString()
		x.Adapter.IntegrationTypeID = uuid.NewString()
		x.ScopeSHA256 = strings.Repeat(digit, 64)
		if writer {
			x.PrincipalID = "member-writer"
		}
		return x
	}
	b := model.CapacityNativeWorkerMemberBinding{Mode: capacity.NativeWorkerMemberMode, Name: "members", Writer: binding("member-write", "1", true), Reader: binding("member-read", "2", false), AllocatorFenceReader: binding("allocator-read", "3", false), BootstrapPolicySHA256: strings.Repeat("4", 64), MaxPermitSeconds: 30, MaxReadAgeSeconds: 30}
	base.p.NativeWorkerLifecycleBinding.PreAdmissionAbort = &model.CapacityNativeWorkerAbortBinding{Mode: model.CapacityNativeWorkerAbortSchema, Workflow: model.ManifestSelector{Namespace: "infra", Name: "member-recovery"}, MaxPermitSeconds: 30}
	base.p.NativeWorkerLifecycleBinding.Members = &b
	base.repinPolicy(t)
	a := capacity.NativeWorkerMemberAuthority{SystemSourceCommit: strings.Repeat("c", 40), KubeletVersion: "v1.34.6+k3s1", AgentConfigPath: "/etc/rancher/k3s/config.yaml", ConfiguredKubeletArgs: []string{"pod-manifest-path=", "manifest-url=", "cloud-provider="}, FenceObjects: []model.CapacityNativeWorkerFenceObject{{APIVersion: "scheduling.k8s.io/v1", Kind: "PriorityClass", Name: "dakasa-native-placement-workloads", UID: uuid.NewString(), ResourceVersion: "opaque-priority-rv", PublicContentSHA256: nativeMemberDigest(map[string]any{"value": 0, "globalDefault": false, "preemptionPolicy": "Never"})}}, Enforcement: []model.CapacityNativeWorkerFenceEnforcement{{}}, LegacyControllers: []model.CapacityNativeWorkerLegacyController{}, WorkloadContracts: []string{}, WorkloadLineage: map[string][]model.CapacityNativeWorkerMemberController{}}
	c := nativeMemberPrivateConfig{Schema: "native_worker_member_bindings_v1", CoreSourceCommit: base.source, PolicyID: base.policy.ID.String(), PolicyChecksum: base.policy.Checksum, Binding: b, Authority: a, JournalKeyFile: base.c.JournalKeyFile, JournalKeySHA256: base.c.JournalKeySHA256}
	rpc := func(name string) NativeWorkerReadinessRPCFiles {
		return NativeWorkerReadinessRPCFiles{Profile: name, BaseURL: "https://" + name + ".invalid", ClientCertificateFile: filepath.Join(filepath.Dir(base.path), name+".crt"), ClientKeyFile: filepath.Join(filepath.Dir(base.path), name+".key")}
	}
	c.WriterRPC = rpc(b.Writer.Name)
	c.ReaderRPC = rpc(b.Reader.Name)
	c.FenceRPC = rpc(b.AllocatorFenceReader.Name)
	for i, role := range []string{NativeMemberWriterRole, NativeMemberReaderRole, NativeAllocatorFenceReaderRole, NativeMemberControllerRole, NativeMemberSchedulerRole} {
		cb := NativeWorkerMemberCallbackFiles{Role: role, Files: NativeWorkerReadinessCallbackFiles{ListenAddr: fmt.Sprintf("127.0.0.1:%d", 19450+i), ClientLeafSHA256: nativeMemberDigest(role)}}
		if role == NativeMemberSchedulerRole {
			cb.StockProfileSourceCommit = base.source
			cb.StockProfileSHA256 = strings.Repeat("5", 64)
		}
		c.Callbacks = append(c.Callbacks, cb)
	}
	return memberConfigFixture{base: base, config: c}
}

func (f *memberConfigFixture) write(t *testing.T) string {
	t.Helper()
	// Private fixture marshalling bypasses display redactors only. Production
	// has no public serializer for this protected installation file.
	wire := map[string]any{"schema": f.config.Schema, "core_source_commit": f.config.CoreSourceCommit, "policy_id": f.config.PolicyID, "policy_checksum": f.config.PolicyChecksum, "binding": f.config.Binding, "authority": f.config.Authority, "journal_key_file": f.config.JournalKeyFile, "journal_key_sha256": f.config.JournalKeySHA256}
	type rpcWire NativeWorkerReadinessRPCFiles
	type callbackWire NativeWorkerReadinessCallbackFiles
	wire["writer_rpc"] = rpcWire(f.config.WriterRPC)
	wire["reader_rpc"] = rpcWire(f.config.ReaderRPC)
	wire["fence_rpc"] = rpcWire(f.config.FenceRPC)
	callbacks := []map[string]any{}
	for _, cb := range f.config.Callbacks {
		v := map[string]any{"role": cb.Role, "files": callbackWire(cb.Files)}
		if cb.StockProfileSourceCommit != "" {
			v["stock_profile_source_commit"] = cb.StockProfileSourceCommit
			v["stock_profile_sha256"] = cb.StockProfileSHA256
		}
		callbacks = append(callbacks, v)
	}
	wire["callbacks"] = callbacks
	raw, e := json.Marshal(wire)
	if e != nil || os.WriteFile(f.base.path, raw, 0600) != nil {
		t.Fatal("write private member fixture", e)
	}
	return nativeMemberRawSHA(raw)
}

func TestNativeMemberProtectedLoaderBindsOriginalFilesAndDistinctRoles(t *testing.T) {
	f := newMemberConfigFixture(t)
	if e := capacity.ValidatePolicy(f.base.p); e != nil {
		t.Fatal("synthetic declaration invalid", e)
	}
	scope := f.write(t)
	c, key, e := nativeMemberLoadConfig(f.base.path, scope, f.base.policy, f.base.source)
	defer clear(key)
	if e != nil || !bytes.Equal(key, f.base.key) || len(c.Callbacks) != 5 || c.Binding.Reader.Name != f.config.Binding.Reader.Name {
		t.Fatal("actual protected loader rejected coherent declarations", e)
	}
	if _, e = json.Marshal(c); e == nil {
		t.Fatal("private installation exposed public JSON")
	}
	if strings.Contains(fmt.Sprintf("%+v %#v", c, c), f.config.JournalKeyFile) {
		t.Fatal("private file reference escaped formatting")
	}
	key[0] ^= 1
	_, second, e := nativeMemberLoadConfig(f.base.path, scope, f.base.policy, f.base.source)
	defer clear(second)
	if e != nil || !bytes.Equal(second, f.base.key) {
		t.Fatal("caller mutated original key file", e)
	}
}

func TestNativeMemberProtectedLoaderRejectsCoherentScopeAndAuthoritySubstitution(t *testing.T) {
	for _, fault := range []string{"scope", "source", "policy", "role_alias", "shared_listener", "shared_leaf", "shared_rpc", "reader_principal", "stock_sdk_identity", "priority_name", "priority_hash", "static_arg", "kubelet_version", "agent_path", "lineage_prefix"} {
		t.Run(fault, func(t *testing.T) {
			f := newMemberConfigFixture(t)
			switch fault {
			case "source":
				f.config.CoreSourceCommit = strings.Repeat("b", 40)
			case "policy":
				f.config.PolicyChecksum = strings.Repeat("e", 64)
			case "role_alias":
				f.config.Callbacks[1].Role = f.config.Callbacks[0].Role
			case "shared_listener":
				f.config.Callbacks[1].Files.ListenAddr = f.config.Callbacks[0].Files.ListenAddr
			case "shared_leaf":
				f.config.Callbacks[1].Files.ClientLeafSHA256 = f.config.Callbacks[0].Files.ClientLeafSHA256
			case "shared_rpc":
				f.config.ReaderRPC.ClientKeyFile = f.config.WriterRPC.ClientKeyFile
			case "reader_principal":
				f.config.Binding.Reader.PrincipalID = "writer"
			case "stock_sdk_identity":
				f.config.Callbacks[4].StockProfileSourceCommit = ""
			case "priority_name":
				f.config.Authority.FenceObjects[0].Name = "default"
			case "priority_hash":
				f.config.Authority.FenceObjects[0].PublicContentSHA256 = nativeMemberDigest(map[string]any{"value": 0, "globalDefault": true, "preemptionPolicy": "Never"})
			case "static_arg":
				f.config.Authority.ConfiguredKubeletArgs[0] = "pod-manifest-path=/tmp/manifests"
			case "kubelet_version":
				f.config.Authority.KubeletVersion = "v1.32.0"
			case "agent_path":
				f.config.Authority.AgentConfigPath = "/tmp/config.yaml"
			case "lineage_prefix":
				f.config.Authority.WorkloadContracts = []string{"worker"}
				f.config.Authority.WorkloadLineage["worker"] = []model.CapacityNativeWorkerMemberController{{APIVersion: "apps/v1", Kind: "ReplicaSet", Namespace: "infra", Name: "ordinary-rs", UID: uuid.NewString(), Generation: 1}, {APIVersion: "apps/v1", Kind: "Deployment", Namespace: "infra", Name: "ordinary", UID: uuid.NewString(), Generation: 1}}
			}
			scope := f.write(t)
			if fault == "scope" {
				scope = strings.Repeat("0", 64)
			}
			_, key, e := nativeMemberLoadConfig(f.base.path, scope, f.base.policy, f.base.source)
			clear(key)
			if e == nil {
				t.Fatal("substitution accepted", fault)
			}
		})
	}
}

func TestNativeMemberProtectedLoaderRequiresOriginalKeyAndClosedFileFraming(t *testing.T) {
	for _, fault := range []string{"key_bytes", "key_mode", "config_mode", "alias", "duplicate", "trailing", "null"} {
		t.Run(fault, func(t *testing.T) {
			f := newMemberConfigFixture(t)
			scope := f.write(t)
			raw, e := os.ReadFile(f.base.path)
			if e != nil {
				t.Fatal(e)
			}
			switch fault {
			case "key_bytes":
				if e = os.WriteFile(f.config.JournalKeyFile, bytes.Repeat([]byte{77}, 32), 0600); e != nil {
					t.Fatal(e)
				}
			case "key_mode":
				if e = os.Chmod(f.config.JournalKeyFile, 0644); e != nil {
					t.Fatal(e)
				}
			case "config_mode":
				if e = os.Chmod(f.base.path, 0644); e != nil {
					t.Fatal(e)
				}
			case "alias":
				raw = bytes.Replace(raw, []byte(`"schema":`), []byte(`"Schema":`), 1)
			case "duplicate":
				raw = append([]byte(`{"schema":"duplicate",`), raw[1:]...)
			case "trailing":
				raw = append(raw, []byte(`{}`)...)
			case "null":
				raw = bytes.Replace(raw, []byte(`"journal_key_file":`), []byte(`"journal_key_file":null,"discarded":`), 1)
			}
			if fault == "alias" || fault == "duplicate" || fault == "trailing" || fault == "null" {
				if e = os.WriteFile(f.base.path, raw, 0600); e != nil {
					t.Fatal(e)
				}
				scope = nativeMemberRawSHA(raw)
			}
			_, key, e := nativeMemberLoadConfig(f.base.path, scope, f.base.policy, f.base.source)
			clear(key)
			if e == nil {
				t.Fatal("invalid original file accepted", fault)
			}
		})
	}
}
