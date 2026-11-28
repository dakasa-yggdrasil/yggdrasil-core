package capacity

import (
	"fmt"
	"regexp"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
	"k8s.io/apimachinery/pkg/util/validation"
)

const NativeWorkerReadinessMode = "native_worker_probe_v1"
const EnsureNativeWorkerProbeResource = "ensure_native_worker_probe_resource"
const DestroyNativeWorkerProbeResource = "destroy_native_worker_probe_resource"
const ObserveNativeWorkerProbeResource = "observe_native_worker_probe_resource"

var nativeProbeImage = regexp.MustCompile(`^[a-z0-9][a-z0-9._:/-]+@sha256:[0-9a-f]{64}$`)

// This validates declarations only. It establishes neither a qualified image
// publisher nor actual Namespace/Node/Pod/Service/packet/startup observations.
func ValidateNativeWorkerReadinessBinding(p model.CapacityPolicySpec) error {
	if p.NativeWorkerLifecycleBinding == nil || p.NativeWorkerLifecycleBinding.ReadinessProducer == nil {
		return nil
	}
	lifecycle := p.NativeWorkerLifecycleBinding
	b := lifecycle.ReadinessProducer
	namespace, err := uuid.Parse(b.NamespaceUID)
	if b.Mode != NativeWorkerReadinessMode || !marketID.MatchString(b.Name) || len(validation.IsDNS1123Label(b.Namespace)) != 0 || err != nil || namespace == uuid.Nil || namespace.String() != b.NamespaceUID ||
		!nativeProbeImage.MatchString(b.ProbeImage) || !nativeProbeImage.MatchString(b.CoreWorkerImage) || !marketCommit.MatchString(b.ProbeSourceCommit) || !marketCommit.MatchString(b.CoreWorkerSourceCommit) || !marketSHA.MatchString(b.StartupTemplateSHA256) ||
		b.ProbeSourceCommit != lifecycle.SourceCommit || b.CoreWorkerSourceCommit != lifecycle.SourceCommit ||
		p.NativeWorkerPoolBinding == nil || lifecycle.Network == nil || lifecycle.PhaseObserver == nil || lifecycle.RegistryWriter == nil || len(lifecycle.Profiles) == 0 || b.Namespace != p.NativeWorkerPoolBinding.RegistryRef.Namespace || b.Namespace != lifecycle.PhaseObserver.RealmNamespace || b.NamespaceUID != p.NativeWorkerPoolBinding.RealmUID {
		return fmt.Errorf("protected Native readiness declarations are incomplete")
	}
	w, r := b.ResourceWriter, b.ResourceReader
	for _, port := range []model.CapacityNativeWorkerProbeResourceBinding{w, r} {
		if !marketAdapterValid(port.Adapter) || !marketID.MatchString(port.Name) || !marketCommit.MatchString(port.SourceCommit) || !marketSHA.MatchString(port.ScopeSHA256) {
			return fmt.Errorf("protected Native probe adapter binding differs")
		}
	}
	if !marketID.MatchString(w.PrincipalID) || r.PrincipalID != "" || w.Adapter.ManifestID == r.Adapter.ManifestID || w.ScopeSHA256 == r.ScopeSHA256 {
		return fmt.Errorf("native probe writer and independent reader must be separate")
	}
	protected := false
	for _, floor := range p.NativeWorkerPoolBinding.ProtectedNodes {
		if floor.NodeUID == lifecycle.Network.Floor.NodeUID && floor.ProviderID == lifecycle.Network.Floor.ProviderID {
			protected = true
		}
	}
	if !protected {
		return fmt.Errorf("native probe floor must be the original protected network floor")
	}
	for _, profile := range lifecycle.Profiles {
		if !marketSHA.MatchString(profile.GuestIdentityPolicySHA256) {
			return fmt.Errorf("native probe requires the sealed per-Attempt guest witness")
		}
	}
	return nil
}
