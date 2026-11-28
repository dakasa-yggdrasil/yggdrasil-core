//go:build linux

package repository

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

type readinessConfigFixture struct {
	c      nativeReadinessPrivateConfig
	p      model.CapacityPolicySpec
	policy model.Manifest
	path   string
	key    []byte
	source string
}

func readinessConfigSHA(raw []byte) string {
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}

// This fixture contains declarations and schema-only publication vectors. It
// neither creates database records nor claims a real publisher, key or Node.
func readinessConfigFixtureFor(t *testing.T) readinessConfigFixture {
	t.Helper()
	id := func(n int) string { return fmt.Sprintf("%08x-0000-4000-8000-000000000000", n) }
	sha := func(s string) string { return strings.Repeat(s, 64) }
	source := strings.Repeat("a", 40)
	adapter := func(n int) model.CapacityMarketAdapterBinding {
		return model.CapacityMarketAdapterBinding{ManifestID: id(n), Version: 1, Checksum: sha("a"), IntegrationTypeID: id(n + 100), TypeChecksum: sha("b")}
	}
	now := time.Now().UTC()
	p := model.CapacityPolicySpec{Environment: "production", Domain: "workers", Dimension: "native_worker", TargetIdentity: "native/loader-fixture", Owner: "loader-owner", Workflow: model.ManifestSelector{Namespace: "infra", Name: "workers"}, Currency: "USD", Floor: 0, Ceiling: 10, Step: 1, MaxEvidenceAgeSeconds: 60, MaxSampleGapSeconds: 30, MinSamples: 3, DownHoldSeconds: 1, CooldownSeconds: 1, LeaseSeconds: 30, Signals: []model.CapacitySignalRule{{Name: "pending", SourceIdentity: "native/pending", Unit: "units", UpAbove: .8, DownBelow: .3}}, Profiles: []model.CapacityProfile{{Name: "aws", Provider: "aws", Region: "us-east-1", MaxUnits: 10, ReadinessSeconds: 10, ValidationRef: "fixture/workload", ValidationValidUntil: now.Add(time.Hour)}}}
	p.MarketBinding = &model.CapacityMarketBinding{Mode: capacity.CapacityMarketMode, GrowthMode: "policy_bounds", BudgetMode: "bounded_total", BudgetScope: "fixture/budget", BudgetMicros: 1_000_000, WorkloadShapeSHA256: sha("c"), HorizonSeconds: 60, MaxQuoteAgeSeconds: 60, MaxQuotaAgeSeconds: 60, MaxEligibilityAgeSeconds: 60, MinSavingsMicros: 1, MinSavingsBasisPoints: 100, EconomicHoldSeconds: 120, MinResidenceSeconds: 600, Profiles: []model.CapacityMarketProfileBinding{{Profile: "aws", Provider: "aws", Region: "us-east-1", Adapter: adapter(1), PhysicalSpecSHA256: sha("d"), WorkloadShapeSHA256: sha("c"), Architecture: "amd64", BillingStopCondition: "delete", MaxUnreservedAttempts: 10, QuoteSourceIdentity: "fixture/pricing", QuotaSourceIdentity: "fixture/quota", RegistrationBindingSHA: sha("e"), NetworkBindingSHA: sha("f"), QuotaDimensions: []model.CapacityMarketQuotaDimensionBinding{{Scope: "fixture/account", Dimension: "instances", PerUnit: 1}}}}}
	pool := &model.CapacityNativeWorkerPoolBinding{Mode: "native_worker_pool_v1", Name: "workers", SourceCommit: source, Adapter: adapter(2), RealmUID: id(3), PoolUID: id(4), Owner: p.Owner, MaxAgeSeconds: 60, ExpectedPoolEpoch: 1, RegistryRef: model.CapacityNativePoolRegistryRef{Kind: "Lease", Namespace: "infra", Name: "workers", UID: id(5)}, Profiles: []model.CapacityNativeWorkerProfileBinding{{Profile: "aws", Provider: "aws", ProviderIDPrefix: "aws:///", PhysicalSpecSHA256: sha("d"), RegistrationBindingSHA: sha("e"), MinAllocatableMilliCPU: 1000, MinAllocatableMemory: 1 << 30}}, Signals: []model.CapacityMetricSignalBinding{{Name: "pending", BindingName: "pending", BindingSHA256: sha("b"), Adapter: model.CapacityObservationAdapterBinding{IntegrationInstanceID: id(2), InstanceChecksum: sha("a"), IntegrationTypeID: id(102), TypeChecksum: sha("b")}}}, ProtectedNodes: []model.CapacityNativeProtectedNode{{NodeUID: id(6), ProviderID: "hcloud://1"}}}
	p.NativeWorkerPoolBinding = pool
	life := &model.CapacityNativeWorkerLifecycleBinding{Mode: capacity.NativeWorkerLifecycleMode, SourceCommit: source, MaxReadAgeSeconds: 60, Profiles: []model.CapacityNativeWorkerExecutionProfile{{Profile: "aws", Adapter: adapter(10), BindingName: "provider-worker", SDKSourceCommit: strings.Repeat("b", 40), ScopeSHA256: sha("1"), EnsureCapability: "ensure_worker", ObserveCapability: "observe_worker", DestroyCapability: "destroy_worker", LaunchTemplateSHA256: sha("2"), BootstrapSourceCommit: strings.Repeat("c", 40), IPAMScope: "fixture/overlay", OverlayCIDR: "10.90.0.0/16", ExcludedIPv4: []string{"10.90.0.1"}, GuestIdentityPolicySHA256: sha("3")}}, PhaseObserver: &model.CapacityNativeWorkerPhaseReadBinding{Mode: capacity.NativeWorkerPhaseReadMode, Name: "workers-read", SourceCommit: strings.Repeat("d", 40), Adapter: adapter(11), ScopeSHA256: sha("4"), RealmNamespace: "infra", MaxAgeSeconds: 30, QuarantineTaintKey: "dakasa.io/native-worker-unadmitted"}, RegistryWriter: &model.CapacityNativeWorkerRegistryWriterBinding{Adapter: adapter(12), BindingName: "workers-write", PrincipalID: "fixture/registry-writer", SourceCommit: strings.Repeat("e", 40), ScopeSHA256: sha("5"), Capability: "ensure_native_worker_pool", MaxPermitSeconds: 15}}
	p.NativeWorkerLifecycleBinding = life
	network := model.CapacityNativeWorkerNetworkTemplate{Schema: 1, GuestSystemSourceCommit: strings.Repeat("c", 40), Interface: "wg-dakasa", MTU: 1380, TransportCIDR: "10.90.0.0/16", FloorPeerIPv4: "10.90.0.1", FloorPublicKey: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)), ListenPort: 51820, FirewallChain: "DAKASA_NATIVE", PodCIDR: "172.29.0.0/16", ServiceCIDR: "172.30.0.0/16", ClusterDNSIPv4: "172.30.0.10", DNSName: "kubernetes.default.svc.cluster.local"}
	life.Network = &model.CapacityNativeWorkerNetworkBinding{Mode: capacity.NativeWorkerNetworkMode, Writer: model.CapacityNativeWorkerNetworkWriterBinding{AdapterID: id(13), PrincipalID: "fixture/network-writer", BindingName: "network-write", SystemSourceCommit: network.GuestSystemSourceCommit, ScopeSHA256: sha("6")}, Reader: model.CapacityNativeWorkerNetworkReaderBinding{AdapterID: id(14), BindingName: "network-read", SystemSourceCommit: network.GuestSystemSourceCommit, ScopeSHA256: sha("7")}, Floor: model.CapacityNativeWorkerNetworkFloorIdentity{NodeName: "fixture-floor", NodeUID: id(6), ProviderID: "hcloud://1", ClusterUID: pool.RealmUID, CASHA256: sha("8"), NativeIPv4: "10.70.1.2", NativeInterface: "enp7s0"}, Template: network, TemplateSHA256: capacity.NativeWorkerNetworkTemplateSHA256(network), MaxPermitSeconds: 30}
	dir := t.TempDir()
	coreReceipt, coreImage, _ := nativeReadinessPublicationFixture("core")
	probeReceipt, probeImage, _ := nativeReadinessPublicationFixture("probe")
	coreRaw, coreSHA := nativeReadinessImageFixtureBytes(t, coreReceipt)
	probeRaw, probeSHA := nativeReadinessImageFixtureBytes(t, probeReceipt)
	write := func(name string, raw []byte) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	c := nativeReadinessPrivateConfig{Schema: "native_worker_readiness_producer_bindings_v1", CoreSourceCommit: source, ProbeContainerName: "probe", ImagePullSecrets: []string{"fixture-pull"}, ControllerPodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "fixture-authority"}}, CoreImageReceipt: nativeReadinessImageReceipt{Path: write("core-receipt.json", coreRaw), SHA256: coreSHA}, ProbeImageReceipt: nativeReadinessImageReceipt{Path: write("probe-receipt.json", probeRaw), SHA256: probeSHA}}
	c.CoreWorkerTemplate = corev1.Container{Name: "core", Image: coreImage, Command: []string{"/app/yggdrasil-api-worker"}, Env: []corev1.EnvVar{{Name: "YGGDRASIL_CORE_PROCESS_ROLE", Value: "api_worker"}, {Name: "HTTP_ADDR", Value: "127.0.0.1:9080"}, {Name: "NATIVE_ADMISSION_ENABLED", Value: "true"}, {Name: "NATIVE_TERMINATION_PROJECTION_DIR", Value: "/run/dakasa-native-admission"}, {Name: "NATIVE_TERMINATION_IMAGE_DIGEST", Value: coreImage[strings.LastIndex(coreImage, "@")+1:]}, {Name: "DB_HOST", Value: "budget-pg-rw.dakasa-persistent.svc.cluster.local"}, {Name: "DB_NAME", Value: "yggdrasil"}, {Name: "DB_PORT", Value: "5432"}, {Name: "DB_SSLMODE", Value: "verify-full"}, {Name: "PGSSLROOTCERT", Value: "/var/run/dakasa/minimum-data-ca/postgres-ca.crt"}, {Name: "NATIVE_ADMISSION_KEY", ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: "__NATIVE_PROBE_ADMISSION_SECRET__"}, Key: "admission.key"}}}}, VolumeMounts: []corev1.VolumeMount{{Name: "minimum-data-ca", MountPath: "/var/run/dakasa/minimum-data-ca", ReadOnly: true}, {Name: "native-admission", MountPath: "/run/dakasa-native-admission", ReadOnly: true}}}
	c.CoreWorkerVolumes = []corev1.Volume{{Name: "minimum-data-ca", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: "minimum-data-ca"}}}}}
	c.Binding = model.CapacityNativeWorkerReadinessBinding{Mode: capacity.NativeWorkerReadinessMode, Name: "readiness", Namespace: "infra", NamespaceUID: pool.RealmUID, ResourceWriter: model.CapacityNativeWorkerProbeResourceBinding{Adapter: adapter(15), Name: "probe-write", SourceCommit: strings.Repeat("f", 40), ScopeSHA256: sha("9"), PrincipalID: "fixture/probe-writer"}, ResourceReader: model.CapacityNativeWorkerProbeResourceBinding{Adapter: adapter(16), Name: "probe-read", SourceCommit: strings.Repeat("f", 40), ScopeSHA256: sha("a")}, CoreWorkerImage: coreImage, CoreWorkerSourceCommit: source, ProbeImage: probeImage, ProbeSourceCommit: source}
	c.WriterRPC = NativeWorkerReadinessRPCFiles{Profile: "probe", BaseURL: "https://writer.invalid", ClientCertificateFile: filepath.Join(dir, "writer.crt"), ClientKeyFile: filepath.Join(dir, "writer.key")}
	c.ReaderRPC = NativeWorkerReadinessRPCFiles{Profile: "probe", BaseURL: "https://reader.invalid", ClientCertificateFile: filepath.Join(dir, "reader.crt"), ClientKeyFile: filepath.Join(dir, "reader.key")}
	tcp, port := corev1.ProtocolTCP, intstr.FromInt32(5432)
	c.DependencyEgress = []networkingv1.NetworkPolicyEgressRule{{To: []networkingv1.NetworkPolicyPeer{{PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "fixture-db"}}}}, Ports: []networkingv1.NetworkPolicyPort{{Protocol: &tcp, Port: &port}}}}
	key := bytes.Repeat([]byte{19}, 32)
	c.JournalKeyFile, c.JournalKeySHA256 = write("journal.key", key), readinessConfigSHA(key)
	f := readinessConfigFixture{c: c, p: p, policy: model.Manifest{ID: uuid.MustParse(id(30)), Kind: "capacity_policy", APIVersion: "yggdrasil.io/v1alpha1", Metadata: model.ManifestMetadata{Namespace: "infra", Name: "readiness-policy", Active: true}, Version: 1}, path: filepath.Join(dir, "private-config.json"), key: key, source: source}
	f.repinTemplate(t)
	return f
}

func (f *readinessConfigFixture) repinPolicy(t *testing.T) {
	t.Helper()
	f.p.NativeWorkerLifecycleBinding.ReadinessProducer = &f.c.Binding
	raw, err := json.Marshal(f.p)
	if err != nil {
		t.Fatal(err)
	}
	f.policy.Spec, f.policy.Checksum = raw, readinessConfigSHA(raw)
	f.c.PolicyID, f.c.PolicyChecksum = f.policy.ID.String(), f.policy.Checksum
}

func (f *readinessConfigFixture) repinTemplate(t *testing.T) {
	t.Helper()
	raw, err := json.Marshal(f.c.CoreWorkerTemplate)
	if err != nil {
		t.Fatal(err)
	}
	f.c.Binding.StartupTemplateSHA256 = readinessConfigSHA(raw)
	f.repinPolicy(t)
}

func (f *readinessConfigFixture) write(t *testing.T) ([]byte, string) {
	t.Helper()
	// Bypass only display redactors to model the mounted private input. This is
	// not a public serializer or an escape hatch in any production constructor.
	type configWire nativeReadinessPrivateConfig
	type callbackWire NativeWorkerReadinessCallbackFiles
	type rpcWire NativeWorkerReadinessRPCFiles
	raw, err := json.Marshal(configWire(f.c))
	var wire map[string]any
	if err != nil || json.Unmarshal(raw, &wire) != nil {
		t.Fatal("fixture serialization")
	}
	wire["callback"], wire["writer_rpc"], wire["reader_rpc"] = callbackWire(f.c.Callback), rpcWire(f.c.WriterRPC), rpcWire(f.c.ReaderRPC)
	raw, err = json.Marshal(wire)
	if err != nil || os.WriteFile(f.path, raw, 0600) != nil {
		t.Fatal("fixture private file write")
	}
	return raw, readinessConfigSHA(raw)
}

func (f *readinessConfigFixture) load(t *testing.T) (nativeReadinessPrivateConfig, []byte, nativeReadinessObservationPins, error) {
	t.Helper()
	_, scope := f.write(t)
	return nativeReadinessLoadConfig(f.path, scope, f.policy, f.source)
}

func TestNativeReadinessProtectedConfigLoadsExactFilesPolicyAndRuntimePins(t *testing.T) {
	f := readinessConfigFixtureFor(t)
	if err := capacity.ValidatePolicy(f.p); err != nil {
		t.Fatal("synthetic declaration fixture invalid", err)
	}
	c, key, pins, err := f.load(t)
	if err != nil || !bytes.Equal(key, f.key) || !reflect.DeepEqual(c.Binding, f.c.Binding) || pins.Binding != f.c.Binding || pins.FloorUID != f.p.NativeWorkerLifecycleBinding.Network.Floor.NodeUID || pins.RegistryUID != f.p.NativeWorkerPoolBinding.RegistryRef.UID || len(pins.CoreRuntimeDigests) != 3 || len(pins.ProbeRuntimeDigests) != 5 {
		t.Fatal("actual protected loader failed to bind independent files and policy", err)
	}
	clear(key)
	_, again, _, err := f.load(t)
	defer clear(again)
	if err != nil || !bytes.Equal(again, f.key) {
		t.Fatal("caller mutation changed the original key file")
	}
	raw, _ := json.Marshal(c)
	if strings.Contains(fmt.Sprintf("%+v %#v %s", c, c, raw), f.c.JournalKeyFile) {
		t.Fatal("private loader configuration escaped display redaction")
	}
	t.Run("private_references_and_optional_termination_file", func(t *testing.T) {
		f := readinessConfigFixtureFor(t)
		f.c.CoreWorkerTemplate.Env = append(f.c.CoreWorkerTemplate.Env,
			corev1.EnvVar{Name: "DB_USER", ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: "fixture-db"}, Key: "username"}}},
			corev1.EnvVar{Name: "FIXTURE_DEPENDENCY_METADATA", ValueFrom: &corev1.EnvVarSource{ConfigMapKeyRef: &corev1.ConfigMapKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: "fixture-dependency"}, Key: "metadata"}}},
			corev1.EnvVar{Name: "NATIVE_TERMINATION_MESSAGE_FILE", Value: "/dev/termination-log"},
		)
		f.repinTemplate(t)
		_, key, _, err := f.load(t)
		defer clear(key)
		if err != nil || !bytes.Equal(key, f.key) {
			t.Fatal("curated literals blocked normal private references", err)
		}
	})
}

func TestNativeReadinessProtectedConfigRefusesCoherentTemplateAndIdentitySubstitution(t *testing.T) {
	for _, fault := range []string{"policy_id", "policy_checksum", "source", "coherent_source", "namespace_uid", "template_hash", "template_image", "extra_literal", "host_command", "ca_mount", "ca_volume", "same_rpc_principal", "same_rpc_key", "same_reader_writer_adapter", "same_reader_writer_scope", "reader_mutation_principal", "floor_namespace", "unbounded_egress"} {
		t.Run(fault, func(t *testing.T) {
			f := readinessConfigFixtureFor(t)
			switch fault {
			case "policy_id":
				f.c.PolicyID = uuid.NewString()
			case "policy_checksum":
				f.c.PolicyChecksum = strings.Repeat("1", 64)
			case "source":
				f.c.CoreSourceCommit = strings.Repeat("b", 40)
			case "coherent_source":
				f.c.CoreSourceCommit = strings.Repeat("b", 40)
				f.p.NativeWorkerLifecycleBinding.SourceCommit = f.c.CoreSourceCommit
				f.c.Binding.CoreWorkerSourceCommit, f.c.Binding.ProbeSourceCommit = f.c.CoreSourceCommit, f.c.CoreSourceCommit
				f.repinPolicy(t) // the independent expected build Source stays original
			case "namespace_uid":
				f.c.Binding.NamespaceUID = uuid.NewString()
				f.repinPolicy(t)
			case "template_hash":
				f.c.Binding.StartupTemplateSHA256 = strings.Repeat("9", 64)
				f.repinPolicy(t)
			case "template_image":
				f.c.CoreWorkerTemplate.Image = "other.invalid/core@sha256:" + strings.Repeat("a", 64)
				f.repinTemplate(t)
			case "extra_literal":
				f.c.CoreWorkerTemplate.Env = append(f.c.CoreWorkerTemplate.Env, corev1.EnvVar{Name: "UNREVIEWED_INLINE_VALUE", Value: "fixture-only"})
				f.repinTemplate(t)
			case "host_command":
				f.c.CoreWorkerTemplate.Command = []string{"/bin/sh", "-c", "other"}
				f.repinTemplate(t)
			case "ca_mount":
				f.c.CoreWorkerTemplate.VolumeMounts[0].ReadOnly = false
				f.repinTemplate(t)
			case "ca_volume":
				f.c.CoreWorkerVolumes = nil
			case "same_rpc_principal":
				f.c.ReaderRPC.ClientCertificateFile = f.c.WriterRPC.ClientCertificateFile
			case "same_rpc_key":
				f.c.ReaderRPC.ClientKeyFile = f.c.WriterRPC.ClientKeyFile
			case "same_reader_writer_adapter":
				f.c.Binding.ResourceReader.Adapter = f.c.Binding.ResourceWriter.Adapter
				f.repinPolicy(t)
			case "same_reader_writer_scope":
				f.c.Binding.ResourceReader.ScopeSHA256 = f.c.Binding.ResourceWriter.ScopeSHA256
				f.repinPolicy(t)
			case "reader_mutation_principal":
				f.c.Binding.ResourceReader.PrincipalID = "fixture/unauthorized-writer"
				f.repinPolicy(t)
			case "floor_namespace":
				f.c.Binding.Namespace = "foreign"
				f.repinPolicy(t)
			case "unbounded_egress":
				f.c.DependencyEgress[0].To = nil
			}
			if _, key, _, err := f.load(t); err == nil || len(key) != 0 {
				clear(key)
				t.Fatal("coherently repinned but unqualified configuration accepted")
			}
		})
	}
	for _, name := range []string{"YGGDRASIL_CORE_PROCESS_ROLE", "HTTP_ADDR", "NATIVE_ADMISSION_ENABLED", "NATIVE_TERMINATION_PROJECTION_DIR", "NATIVE_TERMINATION_IMAGE_DIGEST", "DB_HOST", "DB_NAME", "DB_PORT", "DB_SSLMODE", "PGSSLROOTCERT", "NATIVE_TERMINATION_MESSAGE_FILE"} {
		for _, reference := range []string{"secret", "configmap"} {
			t.Run("literal_reference_"+name+"_"+reference, func(t *testing.T) {
				f := readinessConfigFixtureFor(t)
				if name == "NATIVE_TERMINATION_MESSAGE_FILE" {
					f.c.CoreWorkerTemplate.Env = append(f.c.CoreWorkerTemplate.Env, corev1.EnvVar{Name: name, Value: "/dev/termination-log"})
				}
				found := false
				for i := range f.c.CoreWorkerTemplate.Env {
					e := &f.c.CoreWorkerTemplate.Env[i]
					if e.Name != name {
						continue
					}
					found = true
					e.Value, e.ValueFrom = "", &corev1.EnvVarSource{}
					if reference == "secret" {
						e.ValueFrom.SecretKeyRef = &corev1.SecretKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: "fixture-runtime"}, Key: "literal"}
					} else {
						e.ValueFrom.ConfigMapKeyRef = &corev1.ConfigMapKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: "fixture-runtime"}, Key: "literal"}
					}
				}
				if !found {
					t.Fatal("literal substitution did not change the fixture")
				}
				f.repinTemplate(t) // Rebind the container hash, policy checksum and private file scope.
				if err := capacity.ValidatePolicy(f.p); err != nil {
					t.Fatal("coherent substitution lost its valid policy declaration", err)
				}
				if _, key, _, err := f.load(t); err == nil || len(key) != 0 {
					clear(key)
					t.Fatal("required literal accepted through a coherently pinned reference")
				}
			})
		}
	}
}

func TestNativeReadinessProtectedConfigRequiresOriginalReceiptAndKeyBytes(t *testing.T) {
	for _, fault := range []string{"receipt_raw", "receipt_kind", "receipt_relabel_source", "key_sha", "short_key", "long_key"} {
		t.Run(fault, func(t *testing.T) {
			f := readinessConfigFixtureFor(t)
			switch fault {
			case "receipt_raw":
				if err := os.WriteFile(f.c.ProbeImageReceipt.Path, []byte(`{}`), 0600); err != nil {
					t.Fatal(err)
				}
			case "receipt_kind":
				f.c.CoreImageReceipt = f.c.ProbeImageReceipt
			case "receipt_relabel_source":
				j, _, _ := nativeReadinessPublicationFixture("probe")
				j["source_commit"] = strings.Repeat("b", 40)
				raw, digest := nativeReadinessImageFixtureBytes(t, j)
				if err := os.WriteFile(f.c.ProbeImageReceipt.Path, raw, 0600); err != nil {
					t.Fatal(err)
				}
				f.c.ProbeImageReceipt.SHA256 = digest
			case "key_sha":
				f.c.JournalKeySHA256 = strings.Repeat("8", 64)
			case "short_key", "long_key":
				n := 31
				if fault == "long_key" {
					n = 33
				}
				raw := bytes.Repeat([]byte{7}, n)
				if err := os.WriteFile(f.c.JournalKeyFile, raw, 0600); err != nil {
					t.Fatal(err)
				}
				f.c.JournalKeySHA256 = readinessConfigSHA(raw)
			}
			if _, key, _, err := f.load(t); err == nil || len(key) != 0 {
				clear(key)
				t.Fatal("incomplete or relabeled private file returned journal key")
			}
		})
	}
}

func TestNativeReadinessProtectedConfigRejectsAliasesAndInsecureFileReferences(t *testing.T) {
	for _, fault := range []string{"scope", "duplicate", "case_alias", "extra", "trailing", "config_mode", "config_symlink", "config_hardlink", "key_mode", "key_symlink", "receipt_mode"} {
		t.Run(fault, func(t *testing.T) {
			f := readinessConfigFixtureFor(t)
			raw, scope := f.write(t)
			path := f.path
			switch fault {
			case "scope":
				scope = strings.Repeat("9", 64)
			case "duplicate":
				raw = append([]byte(`{"schema":"ignored",`), raw[1:]...)
			case "case_alias":
				raw = []byte(strings.Replace(string(raw), `"core_source_commit"`, `"Core_Source_Commit"`, 1))
			case "extra":
				raw = append(raw[:len(raw)-1], []byte(`,"caller_override":true}`)...)
			case "trailing":
				raw = append(raw, []byte(`{}`)...)
			case "config_mode":
				if err := os.Chmod(path, 0644); err != nil {
					t.Fatal(err)
				}
			case "config_symlink":
				path += ".link"
				if err := os.Symlink(f.path, path); err != nil {
					t.Fatal(err)
				}
			case "config_hardlink":
				if err := os.Link(path, path+".hard"); err != nil {
					t.Fatal(err)
				}
			case "key_mode":
				if err := os.Chmod(f.c.JournalKeyFile, 0644); err != nil {
					t.Fatal(err)
				}
			case "key_symlink":
				original := f.c.JournalKeyFile
				f.c.JournalKeyFile += ".link"
				if err := os.Symlink(original, f.c.JournalKeyFile); err != nil {
					t.Fatal(err)
				}
				raw, scope = f.write(t)
			case "receipt_mode":
				if err := os.Chmod(f.c.ProbeImageReceipt.Path, 0666); err != nil {
					t.Fatal(err)
				}
			}
			if fault == "duplicate" || fault == "case_alias" || fault == "extra" || fault == "trailing" {
				if err := os.WriteFile(f.path, raw, 0600); err != nil {
					t.Fatal(err)
				}
				scope = readinessConfigSHA(raw) // isolate semantics, not a stale raw pin
			}
			if _, key, _, err := nativeReadinessLoadConfig(path, scope, f.policy, f.source); err == nil || len(key) != 0 {
				clear(key)
				t.Fatal("unsafe original file or closed configuration alias accepted")
			}
		})
	}
}
