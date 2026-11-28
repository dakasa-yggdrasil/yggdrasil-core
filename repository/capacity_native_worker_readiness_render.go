package repository

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	lifecycle "github.com/dakasa-yggdrasil/yggdrasil-core/internal/nativelifecycle"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/validation"
)

// A plan is private process configuration plus retained run identity. It is
// never a workflow input or a public digest. Rendering performs no I/O and
// grants no permission to send the resulting private bytes.
type nativeReadinessResourcePlan struct {
	Context                                                model.NativeWorkerProbeResourceContext
	ProbeImage, CoreImage, StartupTemplateSHA256, NodeName string
	ProbeContainerName                                     string
	CoreWorkerTemplate                                     corev1.Container
	CoreWorkerVolumes                                      []corev1.Volume
	ImagePullSecrets                                       []string
	Data                                                   map[string][]byte
	Challenge                                              json.RawMessage
	NetworkPolicySpec                                      networkingv1.NetworkPolicySpec
	ControllerPodSelector                                  metav1.LabelSelector
}

func (nativeReadinessResourcePlan) String() string     { return "[private Native readiness resource plan]" }
func (p nativeReadinessResourcePlan) GoString() string { return p.String() }
func (nativeReadinessResourcePlan) MarshalJSON() ([]byte, error) {
	return []byte(`{"private_native_readiness_resource_plan":"redacted"}`), nil
}

var nativeReadinessMaterialKeys = [...]string{"config.json", "controller-ca.crt", "peer-signing.pub", "server.crt", "server.key", "signing.key"}

func nativeReadinessCanonicalUUID(s string) bool {
	u, e := uuid.Parse(s)
	return e == nil && u != uuid.Nil && u.String() == s
}

func nativeReadinessRenderIdentity(c model.NativeWorkerProbeResourceContext) (metav1.ObjectMeta, error) {
	if c.Schema != model.NativeWorkerProbeResourceContextSchema || !nativeReadinessCanonicalUUID(c.RunID) || !nativeReadinessCanonicalUUID(c.AttemptID) || !nativeReadinessCanonicalUUID(c.NamespaceUID) || len(validation.IsDNS1123Label(c.Namespace)) != 0 || len(validation.IsDNS1123Subdomain(c.BindingName)) != 0 || c.NotAfter.IsZero() {
		return metav1.ObjectMeta{}, errNativeReadinessRun
	}
	for _, s := range []string{c.CoreSourceCommit, c.SDKSourceCommit} {
		raw, e := hex.DecodeString(s)
		if e != nil || len(raw) != 20 || hex.EncodeToString(raw) != s {
			return metav1.ObjectMeta{}, errNativeReadinessRun
		}
	}
	if !nativeReadinessSHA(c.SDKScopeSHA256) {
		return metav1.ObjectMeta{}, errNativeReadinessRun
	}
	r := nativeReadinessRun{ID: uuid.MustParse(c.RunID)}
	name, kind, ok := nativeReadinessSlot(r, c.Slot)
	if !ok || (!nativeReadinessObjectKind(kind) && c.Slot != "startup_challenge") {
		return metav1.ObjectMeta{}, errNativeReadinessRun
	}
	if c.Slot == "startup_challenge" {
		kind = "Pod"
	}
	api := "v1"
	if kind == "NetworkPolicy" {
		api = "networking.k8s.io/v1"
	}
	if c.Name != name || c.Kind != kind || c.APIVersion != api {
		return metav1.ObjectMeta{}, errNativeReadinessRun
	}
	slot := c.Slot
	if slot == "startup_challenge" {
		slot = "candidate_pod"
	}
	return metav1.ObjectMeta{Name: name, Namespace: c.Namespace, Labels: map[string]string{model.NativeWorkerProbeRunLabel: c.RunID, model.NativeWorkerProbeSlotLabel: slot, model.NativeWorkerProbeAttemptLabel: c.AttemptID}}, nil
}

func nativeReadinessRenderResource(p nativeReadinessResourcePlan) ([]byte, error) {
	c := p.Context
	meta, e := nativeReadinessRenderIdentity(c)
	if e != nil {
		return nil, e
	}
	if c.Op == "delete" {
		if c.Slot == "startup_challenge" || !nativeReadinessCanonicalUUID(c.ExpectedUID) || !nativeReadinessResourceVersion(c.ExpectedResourceVersion) {
			return nil, errNativeReadinessRun
		}
		uid, rv := types.UID(c.ExpectedUID), c.ExpectedResourceVersion
		return json.Marshal(metav1.DeleteOptions{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "DeleteOptions"}, Preconditions: &metav1.Preconditions{UID: &uid, ResourceVersion: &rv}})
	}
	if c.Op == "startup_patch" {
		return nativeReadinessRenderStartup(p)
	}
	if c.Op != "create" || c.Slot == "startup_challenge" || c.ExpectedUID != "" || c.ExpectedResourceVersion != "" {
		return nil, errNativeReadinessRun
	}
	var object any
	switch c.Kind {
	case "Pod":
		pod, err := nativeReadinessRenderPod(p, meta)
		if err != nil {
			return nil, err
		}
		object = pod
	case "Service":
		role := "floor_pod"
		if c.Slot == "candidate_service" {
			role = "candidate_pod"
		}
		object = corev1.Service{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Service"}, ObjectMeta: meta, Spec: corev1.ServiceSpec{Type: corev1.ServiceTypeClusterIP, PublishNotReadyAddresses: true, Selector: map[string]string{model.NativeWorkerProbeRunLabel: c.RunID, model.NativeWorkerProbeSlotLabel: role}, Ports: []corev1.ServicePort{{Name: "probe-udp", Protocol: corev1.ProtocolUDP, Port: 9446, TargetPort: intstr.FromInt32(9446)}}}}
	case "Secret":
		keys := nativeReadinessMaterialKeys[:]
		if c.Slot == "admission_secret" {
			keys = []string{"admission.key"}
		}
		if len(p.Data) != len(keys) {
			return nil, errNativeReadinessRun
		}
		for _, key := range keys {
			if len(p.Data[key]) == 0 || len(p.Data[key]) > 128<<10 {
				return nil, errNativeReadinessRun
			}
		}
		if c.Slot == "admission_secret" && (len(p.Data["admission.key"]) < 32 || len(p.Data["admission.key"]) > 512 || strings.ContainsAny(string(p.Data["admission.key"]), "\x00\r\n")) {
			return nil, errNativeReadinessRun
		}
		immutable := true
		object = corev1.Secret{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Secret"}, ObjectMeta: meta, Immutable: &immutable, Type: corev1.SecretTypeOpaque, Data: p.Data}
	case "NetworkPolicy":
		if !nativeReadinessRenderNetwork(p.NetworkPolicySpec, c.RunID, p.ControllerPodSelector) {
			return nil, errNativeReadinessRun
		}
		object = networkingv1.NetworkPolicy{TypeMeta: metav1.TypeMeta{APIVersion: "networking.k8s.io/v1", Kind: "NetworkPolicy"}, ObjectMeta: meta, Spec: p.NetworkPolicySpec}
	default:
		return nil, errNativeReadinessRun
	}
	raw, err := nativeReadinessRenderWire(object)
	if err != nil || len(raw) > 256<<10 {
		return nil, errNativeReadinessRun
	}
	return raw, nil
}

// Kubernetes response structs marshal server-owned zero fields too. They are
// deliberately absent from a create request and its pinned public projection.
func nativeReadinessRenderWire(object any) ([]byte, error) {
	var meta metav1.ObjectMeta
	var api, kind string
	fields := map[string]any{}
	switch v := object.(type) {
	case corev1.Pod:
		meta, api, kind = v.ObjectMeta, "v1", "Pod"
		fields["spec"] = v.Spec
	case corev1.Service:
		meta, api, kind = v.ObjectMeta, "v1", "Service"
		fields["spec"] = v.Spec
	case corev1.Secret:
		meta, api, kind = v.ObjectMeta, "v1", "Secret"
		fields["data"], fields["type"], fields["immutable"] = v.Data, v.Type, v.Immutable
	case networkingv1.NetworkPolicy:
		meta, api, kind = v.ObjectMeta, "networking.k8s.io/v1", "NetworkPolicy"
		fields["spec"] = v.Spec
	default:
		return nil, errNativeReadinessRun
	}
	metadata := map[string]any{"name": meta.Name, "namespace": meta.Namespace, "labels": meta.Labels}
	if len(meta.Annotations) != 0 {
		metadata["annotations"] = meta.Annotations
	}
	fields["apiVersion"], fields["kind"], fields["metadata"] = api, kind, metadata
	return json.Marshal(fields)
}

func nativeReadinessResourceVersion(s string) bool {
	return s != "" && len(s) <= 256 && !strings.ContainsAny(s, "\x00\r\n")
}

func nativeReadinessPinnedImage(s string) bool {
	i := strings.LastIndex(s, "@sha256:")
	return i > 0 && i < 2048 && nativeReadinessSHA(s[i+8:]) && !strings.ContainsAny(s, " \t\r\n")
}

func nativeReadinessRenderPod(p nativeReadinessResourcePlan, meta metav1.ObjectMeta) (corev1.Pod, error) {
	var zero corev1.Pod
	if len(validation.IsDNS1123Subdomain(p.NodeName)) != 0 || len(validation.IsDNS1123Label(p.ProbeContainerName)) != 0 || !nativeReadinessPinnedImage(p.ProbeImage) || len(p.ImagePullSecrets) > 16 {
		return zero, errNativeReadinessRun
	}
	candidate := p.Context.Slot == "candidate_pod"
	no, yes, mode, id := false, true, int32(0440), int64(65532)
	probe := corev1.Container{Name: p.ProbeContainerName, Image: p.ProbeImage, Command: []string{"/app/native-worker-probe"}, Ports: []corev1.ContainerPort{{Name: "control", Protocol: corev1.ProtocolTCP, ContainerPort: 9446}, {Name: "diagnostic", Protocol: corev1.ProtocolUDP, ContainerPort: 9446}}, VolumeMounts: []corev1.VolumeMount{{Name: "probe-material", MountPath: "/run/dakasa-native-worker-probe", ReadOnly: true}}, SecurityContext: &corev1.SecurityContext{RunAsNonRoot: &yes, RunAsUser: &id, RunAsGroup: &id, AllowPrivilegeEscalation: &no, ReadOnlyRootFilesystem: &yes, Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}}}}
	r := nativeReadinessRun{ID: uuid.MustParse(p.Context.RunID)}
	secretSlot := "floor_secret"
	if candidate {
		secretSlot = "candidate_secret"
	}
	config, _, _ := nativeReadinessSlot(r, secretSlot)
	items := make([]corev1.KeyToPath, 0, len(nativeReadinessMaterialKeys))
	for _, key := range nativeReadinessMaterialKeys {
		items = append(items, corev1.KeyToPath{Key: key, Path: key})
	}
	material := corev1.Volume{Name: "probe-material", VolumeSource: corev1.VolumeSource{Projected: &corev1.ProjectedVolumeSource{DefaultMode: &mode, Sources: []corev1.VolumeProjection{{Secret: &corev1.SecretProjection{LocalObjectReference: corev1.LocalObjectReference{Name: config}, Items: items, Optional: &yes}}}}}}
	pod := corev1.Pod{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Pod"}, ObjectMeta: meta, Spec: corev1.PodSpec{NodeName: p.NodeName, RestartPolicy: corev1.RestartPolicyNever, AutomountServiceAccountToken: &no, SecurityContext: &corev1.PodSecurityContext{FSGroup: &id}, Containers: []corev1.Container{probe}}}
	pod.Annotations = map[string]string{"sidecar.istio.io/inject": "false"}
	seen := map[string]bool{}
	for _, name := range p.ImagePullSecrets {
		if len(validation.IsDNS1123Subdomain(name)) != 0 || seen[name] {
			return zero, errNativeReadinessRun
		}
		seen[name] = true
		pod.Spec.ImagePullSecrets = append(pod.Spec.ImagePullSecrets, corev1.LocalObjectReference{Name: name})
	}
	if candidate {
		worker, volumes, err := nativeReadinessRenderWorker(p)
		if err != nil {
			return zero, err
		}
		admission, _, _ := nativeReadinessSlot(r, "admission_secret")
		material.Projected.Sources = append(material.Projected.Sources, corev1.VolumeProjection{Secret: &corev1.SecretProjection{LocalObjectReference: corev1.LocalObjectReference{Name: admission}, Items: []corev1.KeyToPath{{Key: "admission.key", Path: "admission.key"}}, Optional: &no}})
		pod.Annotations[model.NativeWorkerProbeAdmissionAnnotation] = ""
		pod.Spec.Containers = append([]corev1.Container{worker}, probe)
		pod.Spec.Volumes = volumes
		fields := []corev1.DownwardAPIVolumeFile{}
		for _, f := range [][2]string{{"uid", "metadata.uid"}, {"namespace", "metadata.namespace"}, {"name", "metadata.name"}, {"challenge", "metadata.annotations['yggdrasil.io/native-admission-v2']"}} {
			fields = append(fields, corev1.DownwardAPIVolumeFile{Path: f[0], FieldRef: &corev1.ObjectFieldSelector{APIVersion: "v1", FieldPath: f[1]}})
		}
		pod.Spec.Volumes = append(pod.Spec.Volumes, corev1.Volume{Name: "native-admission", VolumeSource: corev1.VolumeSource{DownwardAPI: &corev1.DownwardAPIVolumeSource{DefaultMode: &mode, Items: fields}}})
	}
	pod.Spec.Volumes = append(pod.Spec.Volumes, material)
	return pod, nil
}

// The canonical container is pinned before the sole per-run substitution.
// Deep copies keep retries byte-stable and never mutate private configuration.
func nativeReadinessRenderWorker(p nativeReadinessResourcePlan) (corev1.Container, []corev1.Volume, error) {
	var zero corev1.Container
	raw, err := json.Marshal(p.CoreWorkerTemplate)
	h := sha256.Sum256(raw)
	if err != nil || hex.EncodeToString(h[:]) != p.StartupTemplateSHA256 || !nativeReadinessPinnedImage(p.CoreImage) || p.CoreWorkerTemplate.Image != p.CoreImage || p.CoreWorkerTemplate.Name == p.ProbeContainerName || len(validation.IsDNS1123Label(p.CoreWorkerTemplate.Name)) != 0 || len(p.CoreWorkerTemplate.Command) != 1 || p.CoreWorkerTemplate.Command[0] != "/app/yggdrasil-api-worker" || len(p.CoreWorkerTemplate.Args) != 0 || len(p.CoreWorkerTemplate.EnvFrom) != 0 {
		return zero, nil, errNativeReadinessRun
	}
	worker := *p.CoreWorkerTemplate.DeepCopy()
	r := nativeReadinessRun{ID: uuid.MustParse(p.Context.RunID)}
	admission, _, _ := nativeReadinessSlot(r, "admission_secret")
	found := 0
	for i, env := range worker.Env {
		if env.Name != "NATIVE_ADMISSION_KEY" {
			continue
		}
		found++
		if env.Value != "" || env.ValueFrom == nil || env.ValueFrom.SecretKeyRef == nil || env.ValueFrom.SecretKeyRef.Name != "__NATIVE_PROBE_ADMISSION_SECRET__" || env.ValueFrom.SecretKeyRef.Key != "admission.key" {
			return zero, nil, errNativeReadinessRun
		}
		worker.Env[i].ValueFrom.SecretKeyRef.Name = admission
	}
	if found != 1 {
		return zero, nil, errNativeReadinessRun
	}
	known := map[string]bool{"native-admission": true, "probe-material": true}
	volumes := make([]corev1.Volume, 0, len(p.CoreWorkerVolumes))
	for _, v := range p.CoreWorkerVolumes {
		if len(validation.IsDNS1123Label(v.Name)) != 0 || known[v.Name] {
			return zero, nil, errNativeReadinessRun
		}
		var only corev1.VolumeSource
		if v.Secret != nil {
			if len(validation.IsDNS1123Subdomain(v.Secret.SecretName)) != 0 {
				return zero, nil, errNativeReadinessRun
			}
			only.Secret = v.Secret
		} else if v.ConfigMap != nil {
			if len(validation.IsDNS1123Subdomain(v.ConfigMap.Name)) != 0 {
				return zero, nil, errNativeReadinessRun
			}
			only.ConfigMap = v.ConfigMap
		} else {
			return zero, nil, errNativeReadinessRun
		}
		left, _ := json.Marshal(v.VolumeSource)
		right, _ := json.Marshal(only)
		if string(left) != string(right) {
			return zero, nil, errNativeReadinessRun
		}
		known[v.Name] = true
		volumes = append(volumes, *v.DeepCopy())
	}
	for _, v := range worker.VolumeMounts {
		if !v.ReadOnly || v.SubPath != "" || v.SubPathExpr != "" || !known[v.Name] || v.Name == "probe-material" {
			return zero, nil, errNativeReadinessRun
		}
	}
	return worker, volumes, nil
}

func nativeReadinessRenderStartup(p nativeReadinessResourcePlan) ([]byte, error) {
	c := p.Context
	if c.Slot != "startup_challenge" || !nativeReadinessCanonicalUUID(c.ExpectedUID) || !nativeReadinessResourceVersion(c.ExpectedResourceVersion) || len(p.Challenge) == 0 || len(p.Challenge) > 16384 || !nativeReadinessPinnedImage(p.CoreImage) {
		return nil, errNativeReadinessRun
	}
	var v lifecycle.NativeAdmissionChallenge
	if capacity.DecodeNativeCapacity(p.Challenge, &v) != nil || v.SchemaVersion != 2 || v.Namespace != c.Namespace || v.PodName != c.Name || v.PodUID != c.ExpectedUID || v.WorkloadUID != c.ExpectedUID || v.ContainerName != p.CoreWorkerTemplate.Name || v.ImageDigest != p.CoreImage[strings.LastIndex(p.CoreImage, "@")+1:] || v.IntentGeneration < 1 || !nativeReadinessCanonicalUUID(v.DrainNonce) || !nativeReadinessCanonicalUUID(v.ProcessNonce) || !nativeReadinessSHA(v.LaneRosterSHA256) || v.IssuedAt.IsZero() || !v.IssuedAt.Before(c.NotAfter) {
		return nil, errNativeReadinessRun
	}
	steps := []struct {
		Op    string `json:"op"`
		Path  string `json:"path"`
		Value string `json:"value"`
	}{
		{"test", "/metadata/uid", c.ExpectedUID}, {"test", "/metadata/resourceVersion", c.ExpectedResourceVersion}, {"add", "/metadata/annotations/yggdrasil.io~1native-admission-v2", string(p.Challenge)},
	}
	return json.Marshal(steps)
}

func nativeReadinessRenderNetwork(s networkingv1.NetworkPolicySpec, run string, controller metav1.LabelSelector) bool {
	if _, err := metav1.LabelSelectorAsSelector(&controller); err != nil {
		return false
	}
	if len(s.PodSelector.MatchLabels) != 1 || s.PodSelector.MatchLabels[model.NativeWorkerProbeRunLabel] != run || len(s.PodSelector.MatchExpressions) != 0 || len(s.PolicyTypes) != 2 {
		return false
	}
	seen := map[networkingv1.PolicyType]bool{}
	for _, v := range s.PolicyTypes {
		if v != networkingv1.PolicyTypeIngress && v != networkingv1.PolicyTypeEgress || seen[v] {
			return false
		}
		seen[v] = true
	}
	for _, rule := range s.Ingress {
		if len(rule.Ports) == 0 || len(rule.From) == 0 {
			return false
		}
		for _, port := range rule.Ports {
			if port.Port == nil || port.Port.Type != intstr.Int || port.Port.IntVal != 9446 || port.EndPort != nil || port.Protocol == nil || *port.Protocol != corev1.ProtocolUDP && *port.Protocol != corev1.ProtocolTCP {
				return false
			}
			for _, peer := range rule.From {
				if peer.IPBlock != nil || peer.NamespaceSelector != nil || peer.PodSelector == nil {
					return false
				}
				if *port.Protocol == corev1.ProtocolUDP {
					if len(peer.PodSelector.MatchLabels) != 1 || peer.PodSelector.MatchLabels[model.NativeWorkerProbeRunLabel] != run || len(peer.PodSelector.MatchExpressions) != 0 {
						return false
					}
				} else {
					if len(controller.MatchLabels) == 0 || len(controller.MatchExpressions) != 0 || len(peer.PodSelector.MatchExpressions) != 0 || len(peer.PodSelector.MatchLabels) != len(controller.MatchLabels) {
						return false
					}
					for k, v := range controller.MatchLabels {
						if peer.PodSelector.MatchLabels[k] != v {
							return false
						}
					}
				}
			}
		}
	}
	diagnosticEgress := false
	for _, rule := range s.Egress {
		if len(rule.Ports) == 0 || len(rule.To) == 0 {
			return false
		}
		for _, peer := range rule.To {
			if peer.IPBlock != nil || peer.NamespaceSelector != nil || peer.PodSelector == nil || len(peer.PodSelector.MatchLabels) != 1 || peer.PodSelector.MatchLabels[model.NativeWorkerProbeRunLabel] != run || len(peer.PodSelector.MatchExpressions) != 0 {
				continue
			}
			for _, port := range rule.Ports {
				if port.Protocol != nil && *port.Protocol == corev1.ProtocolUDP && port.Port != nil && port.Port.Type == intstr.Int && port.Port.IntVal == 9446 && port.EndPort == nil {
					diagnosticEgress = true
				}
			}
		}
	}
	return diagnosticEgress
}
