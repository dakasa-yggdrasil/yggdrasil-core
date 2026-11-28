package repository

import (
	"context"
	"encoding/json"
	"net/netip"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func (s *nativeReadinessProducerState) candidateNode(ctx context.Context, a model.CapacityNativeWorkerAttempt) (model.CapacityNativeWorkerPhaseCandidate, error) {
	var zero model.CapacityNativeWorkerPhaseCandidate
	if a.Physical == nil || a.State != "registered" {
		return zero, errNativeReadinessRun
	}
	o, err := s.ports.Phase(ctx, *s.spec.NativeWorkerLifecycleBinding.PhaseObserver, a.Physical.ProviderID, a.BirthSHA256)
	if err != nil || capacity.NativeWorkerPhaseHeaderValid(s.spec, o, time.Now().UTC()) != nil || !o.CandidateSelected || o.CandidateAbsenceProven || len(o.Candidates) != 1 || o.RequestedProviderID != a.Physical.ProviderID || o.RequestedCreationProofSHA256 != a.BirthSHA256 {
		return zero, errNativeReadinessRun
	}
	n := o.Candidates[0]
	if n.NodeUID != a.NodeUID || n.ProviderID != a.Physical.ProviderID || n.PoolUIDLabel != a.PoolUID || n.NodeName == s.pins.FloorName || n.NodeUID == s.pins.FloorUID || n.Deleting || n.Unschedulable || !n.Ready || !n.Heartbeat.Present || !n.Heartbeat.Fresh || n.Heartbeat.ObservedAt.After(o.ObservedAt) || o.ObservedAt.Sub(n.Heartbeat.ObservedAt) >= s.pins.MaxAge {
		return zero, errNativeReadinessRun
	}
	quarantine := 0
	for _, t := range n.Taints {
		if t.Key == "dakasa.io/native-worker-unadmitted" {
			if t.Value != a.PoolUID || t.Effect != "NoSchedule" {
				return zero, errNativeReadinessRun
			}
			quarantine++
		}
	}
	if quarantine != 1 {
		return zero, errNativeReadinessRun
	}
	owned := 0
	for _, e := range o.Registrations {
		if e.NodeUID == n.NodeUID || e.ProviderID == n.ProviderID {
			if e.NodeUID != a.NodeUID || e.ProviderID != a.Physical.ProviderID || e.Profile != a.Profile || e.PhysicalSpecSHA256 != a.PhysicalSpecSHA256 || e.CapacityPolicyID != a.PolicyID.String() || e.IntentGeneration != a.Generation || e.FencingToken != a.FencingToken || e.CreationProofSHA256 != a.BirthSHA256 || e.Admission.State != "quarantined" {
				return zero, errNativeReadinessRun
			}
			owned++
		}
	}
	if owned != 1 {
		return zero, errNativeReadinessRun
	}
	overlay := 0
	for _, address := range n.Addresses {
		if address.Type != "InternalIP" {
			continue
		}
		ip, err := netip.ParseAddr(address.Address)
		if err != nil || ip.String() != address.Address {
			return zero, errNativeReadinessRun
		}
		if ip.Is4() {
			if address.Address != a.OverlayIPv4 {
				return zero, errNativeReadinessRun
			}
			overlay++
		}
	}
	if overlay != 1 {
		return zero, errNativeReadinessRun
	}
	return n, nil
}

func (s *nativeReadinessProducerState) resourceContext(r nativeReadinessRun, slot string) (model.NativeWorkerProbeResourceContext, error) {
	api, kind, name, ok := capacity.NativeWorkerProbeResourceName(r.ID.String(), slot)
	if !ok {
		return model.NativeWorkerProbeResourceContext{}, errNativeReadinessRun
	}
	b := s.config.Binding.ResourceWriter
	op := "create"
	if slot == "startup_challenge" {
		op = "startup_patch"
	}
	return model.NativeWorkerProbeResourceContext{Schema: model.NativeWorkerProbeResourceContextSchema, BindingName: b.Name, RunID: r.ID.String(), AttemptID: r.Identity.AttemptID.String(), Slot: slot, CoreSourceCommit: s.journal.source, SDKSourceCommit: b.SourceCommit, SDKScopeSHA256: b.ScopeSHA256, Namespace: s.config.Binding.Namespace, NamespaceUID: s.config.Binding.NamespaceUID, APIVersion: api, Kind: kind, Name: name, State: "requested", NotAfter: r.NotAfter, Op: op}, nil
}

func (s *nativeReadinessProducerState) plan(r nativeReadinessRun, slot, node string) (nativeReadinessResourcePlan, error) {
	c, err := s.resourceContext(r, slot)
	if err != nil {
		return nativeReadinessResourcePlan{}, err
	}
	return nativeReadinessResourcePlan{Context: c, ProbeImage: s.config.Binding.ProbeImage, CoreImage: s.config.Binding.CoreWorkerImage, StartupTemplateSHA256: s.config.Binding.StartupTemplateSHA256, NodeName: node, ProbeContainerName: s.config.ProbeContainerName, CoreWorkerTemplate: s.config.CoreWorkerTemplate, CoreWorkerVolumes: s.config.CoreWorkerVolumes, ImagePullSecrets: s.config.ImagePullSecrets, ControllerPodSelector: s.config.ControllerPodSelector, NetworkPolicySpec: s.networkPolicy(r)}, nil
}

func (s *nativeReadinessProducerState) networkPolicy(r nativeReadinessRun) networkingv1.NetworkPolicySpec {
	udp, tcp := corev1.ProtocolUDP, corev1.ProtocolTCP
	port := intstr.FromInt32(9446)
	selector := metav1.LabelSelector{MatchLabels: map[string]string{model.NativeWorkerProbeRunLabel: r.ID.String()}}
	runPeer := networkingv1.NetworkPolicyPeer{PodSelector: &selector}
	return networkingv1.NetworkPolicySpec{PodSelector: selector, PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress}, Ingress: []networkingv1.NetworkPolicyIngressRule{{Ports: []networkingv1.NetworkPolicyPort{{Protocol: &udp, Port: &port}}, From: []networkingv1.NetworkPolicyPeer{runPeer}}, {Ports: []networkingv1.NetworkPolicyPort{{Protocol: &tcp, Port: &port}}, From: []networkingv1.NetworkPolicyPeer{{PodSelector: &s.config.ControllerPodSelector}}}}, Egress: append([]networkingv1.NetworkPolicyEgressRule{{Ports: []networkingv1.NetworkPolicyPort{{Protocol: &udp, Port: &port}}, To: []networkingv1.NetworkPolicyPeer{runPeer}}}, s.config.DependencyEgress...)}
}

func (s *nativeReadinessProducerState) ensure(ctx context.Context, a model.CapacityNativeWorkerAttempt, r nativeReadinessRun, plan nativeReadinessResourcePlan, origin *nativeReadinessOriginalStartupOrigin) (nativeReadinessRun, error) {
	slot := plan.Context.Slot
	if _, exists := nativeReadinessEffectIndex(r, slot); exists {
		// A recorded requested/send_started/received state is not another send
		// right, including a crash before the SDK was invoked. Reobserve only.
		return s.recoverOriginal(ctx, r, slot)
	}
	raw, err := nativeReadinessRenderResource(plan)
	defer clear(raw)
	if err != nil {
		return nativeReadinessRun{}, err
	}
	sha, err := capacity.NativeWorkerProbePublicTemplateSHA(plan.Context, raw)
	if err != nil {
		return nativeReadinessRun{}, err
	}
	plan.Context.PublicTemplateSHA256 = sha
	r, err = s.journal.beginPrivateRequest(ctx, a, r, slot, sha, raw, &plan.Context, origin)
	if err != nil {
		return nativeReadinessRun{}, err
	}
	// Returning an SDK status cannot replace Core custody. Its receiver may
	// have committed even if this original RPC timed out, so read the journal.
	_ = s.ports.Mutate(ctx, s.config.Binding.ResourceWriter, capacity.EnsureNativeWorkerProbeResource, model.NativeWorkerProbeResourceInput{BindingName: s.config.Binding.ResourceWriter.Name, RunID: r.ID.String(), Slot: slot})
	latest, readErr := s.journal.read(ctx, a.ID)
	if readErr != nil {
		return nativeReadinessRun{}, readErr
	}
	return s.recoverOriginal(ctx, latest, slot)
}

func (s *nativeReadinessProducerState) recoverOriginal(ctx context.Context, r nativeReadinessRun, slot string) (nativeReadinessRun, error) {
	i, exists := nativeReadinessEffectIndex(r, slot)
	if !exists {
		return nativeReadinessRun{}, errNativeReadinessRun
	}
	e := r.Effects[i]
	if e.State == "observed" || e.State == "absent" || e.State == "delete_acknowledged" {
		return r, nil
	}
	if e.State == "received" || e.State == "delete_received" {
		wire, err := s.journal.original(r, slot, e.State == "delete_received")
		defer clear(wire)
		var original model.NativeWorkerProbeResourceReceive
		if err != nil || capacity.DecodeNativeCapacity(json.RawMessage(wire), &original) != nil || s.backend.Receive(ctx, original) != nil {
			return r, errNativeReadinessRun
		}
		latest, err := s.journal.read(ctx, r.Identity.AttemptID)
		if err != nil {
			return r, err
		}
		index, exists := nativeReadinessEffectIndex(latest, slot)
		if !exists || (latest.Effects[index].State != "observed" && latest.Effects[index].State != "delete_acknowledged" && latest.Effects[index].State != "absent") {
			return latest, errNativeReadinessRun
		}
		return latest, nil
	}
	return r, errNativeReadinessRun
}

func (s *nativeReadinessProducerState) observe(ctx context.Context, a model.CapacityNativeWorkerAttempt, r nativeReadinessRun, slot string) (model.NativeWorkerProbeResourceObservation, error) {
	var zero model.NativeWorkerProbeResourceObservation
	i, exists := nativeReadinessEffectIndex(r, slot)
	if !exists || r.Effects[i].UID == "" {
		return zero, errNativeReadinessRun
	}
	o, err := s.ports.Read(ctx, s.config.Binding.ResourceReader, model.NativeWorkerProbeResourceInput{BindingName: s.config.Binding.ResourceReader.Name, RunID: r.ID.String(), Slot: slot})
	if err != nil || nativeReadinessObservationHeader(r, s.pins, o, slot, r.Effects[i].UID, time.Now().UTC()) != nil {
		return zero, errNativeReadinessRun
	}
	return o, nil
}
