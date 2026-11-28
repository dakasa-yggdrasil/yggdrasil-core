package repository

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	lifecycle "github.com/dakasa-yggdrasil/yggdrasil-core/internal/nativelifecycle"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func nativeReadinessRenderFixture(slot string) nativeReadinessResourcePlan {
	run := nativeReadinessRun{ID: uuid.MustParse("12345678-1234-4234-8234-123456789abc")}
	name, kind, _ := nativeReadinessSlot(run, slot)
	if slot == "startup_challenge" {
		kind = "Pod"
	}
	api := "v1"
	if kind == "NetworkPolicy" {
		api = "networking.k8s.io/v1"
	}
	image := "example.invalid/core@sha256:" + strings.Repeat("a", 64)
	p := nativeReadinessResourcePlan{Context: model.NativeWorkerProbeResourceContext{Schema: model.NativeWorkerProbeResourceContextSchema, BindingName: "closed-probe", RunID: run.ID.String(), AttemptID: "23456789-2345-4345-8345-23456789abcd", CoreSourceCommit: strings.Repeat("b", 40), SDKSourceCommit: strings.Repeat("c", 40), SDKScopeSHA256: strings.Repeat("d", 64), Namespace: "probe-space", NamespaceUID: "34567890-3456-4456-8456-34567890abcd", APIVersion: api, Kind: kind, Name: name, Slot: slot, Op: "create", NotAfter: time.Date(2026, 11, 28, 6, 0, 0, 0, time.UTC)}, NodeName: "candidate-node", ProbeContainerName: "probe", ProbeImage: "example.invalid/probe@sha256:" + strings.Repeat("e", 64), CoreImage: image, ImagePullSecrets: []string{"minimum-ecr-pull"}, ControllerPodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "yggdrasil-authority"}}}
	p.CoreWorkerTemplate = corev1.Container{Name: "core", Image: image, Command: []string{"/app/yggdrasil-api-worker"}, Env: []corev1.EnvVar{{Name: "YGGDRASIL_CORE_PROCESS_ROLE", Value: "api_worker"}, {Name: "NATIVE_ADMISSION_KEY", ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: "__NATIVE_PROBE_ADMISSION_SECRET__"}, Key: "admission.key"}}}, {Name: "HTTP_ADDR", Value: "127.0.0.1:9080"}, {Name: "NATIVE_ADMISSION_ENABLED", Value: "true"}, {Name: "NATIVE_TERMINATION_PROJECTION_DIR", Value: "/run/dakasa-native-admission"}, {Name: "NATIVE_TERMINATION_IMAGE_DIGEST", Value: "sha256:" + strings.Repeat("a", 64)}}, VolumeMounts: []corev1.VolumeMount{{Name: "native-admission", MountPath: "/run/dakasa-native-admission", ReadOnly: true}, {Name: "data-ca", MountPath: "/data-ca", ReadOnly: true}}}
	p.CoreWorkerVolumes = []corev1.Volume{{Name: "data-ca", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: "minimum-data-ca"}}}}}
	raw, _ := json.Marshal(p.CoreWorkerTemplate)
	h := sha256.Sum256(raw)
	p.StartupTemplateSHA256 = hex.EncodeToString(h[:])
	return p
}

func TestNativeReadinessRenderCandidateKeepsOriginalTemplateAndMandatoryAdmission(t *testing.T) {
	p := nativeReadinessRenderFixture("candidate_pod")
	original, _ := json.Marshal(p.CoreWorkerTemplate)
	raw, err := nativeReadinessRenderResource(p)
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]json.RawMessage
	if json.Unmarshal(raw, &wire) != nil || len(wire) != 4 || wire["status"] != nil {
		t.Fatal("server response fields included in create request")
	}
	var metadata map[string]json.RawMessage
	if json.Unmarshal(wire["metadata"], &metadata) != nil || len(metadata) != 4 || metadata["creationTimestamp"] != nil || metadata["uid"] != nil {
		t.Fatal("server metadata included in public template")
	}
	var pod corev1.Pod
	if json.Unmarshal(raw, &pod) != nil {
		t.Fatal("invalid pod")
	}
	if pod.UID != "" || pod.ResourceVersion != "" || len(pod.OwnerReferences) != 0 || !reflect.DeepEqual(pod.Status, corev1.PodStatus{}) || len(pod.Spec.Containers) != 2 || pod.Spec.HostNetwork || pod.Spec.AutomountServiceAccountToken == nil || *pod.Spec.AutomountServiceAccountToken {
		t.Fatal("diagnostic escaped isolated bare Pod")
	}
	if pod.Spec.Containers[0].Name != "core" || pod.Spec.Containers[1].Name != "probe" || pod.Spec.ImagePullSecrets[0].Name != "minimum-ecr-pull" {
		t.Fatal("lost actual two-container/image-pull composition")
	}
	worker := pod.Spec.Containers[0]
	if worker.Env[1].ValueFrom.SecretKeyRef.Name != "nwp-12345678123442348234-as" {
		t.Fatal("per-run admission Secret was not substituted")
	}
	worker.Env[1].ValueFrom.SecretKeyRef.Name = "__NATIVE_PROBE_ADMISSION_SECRET__"
	if !reflect.DeepEqual(worker, p.CoreWorkerTemplate) {
		t.Fatal("more than the one approved template field changed")
	}
	after, _ := json.Marshal(p.CoreWorkerTemplate)
	if !bytes.Equal(original, after) {
		t.Fatal("render mutated original template")
	}
	again, err := nativeReadinessRenderResource(p)
	if err != nil || !bytes.Equal(raw, again) {
		t.Fatal("resume did not render identical bytes")
	}
	material, downward := false, false
	for _, v := range pod.Spec.Volumes {
		if v.Name == "probe-material" {
			material = true
			if v.Projected == nil || *v.Projected.DefaultMode != 0440 || len(v.Projected.Sources) != 2 {
				t.Fatal("missing combined projection")
			}
			a, b := v.Projected.Sources[0].Secret, v.Projected.Sources[1].Secret
			if !*a.Optional || *b.Optional || len(a.Items) != 6 || len(b.Items) != 1 || b.Items[0].Key != "admission.key" {
				t.Fatal("config wait or mandatory admission changed")
			}
		}
		if v.Name == "native-admission" {
			downward = true
			if len(v.DownwardAPI.Items) != 4 || *v.DownwardAPI.DefaultMode != 0440 {
				t.Fatal("native identity projection missing")
			}
		}
	}
	if !material || !downward {
		t.Fatal("diagnostic cannot receive exact run/startup material")
	}
}

func TestNativeReadinessRenderRefusesIdentityAndTemplateSplicing(t *testing.T) {
	cases := map[string]func(*nativeReadinessResourcePlan){
		"foreign_name":        func(p *nativeReadinessResourcePlan) { p.Context.Name = "unrelated" },
		"foreign_kind":        func(p *nativeReadinessResourcePlan) { p.Context.Kind = "Deployment" },
		"noncanonical_source": func(p *nativeReadinessResourcePlan) { p.Context.CoreSourceCommit = strings.Repeat("B", 40) },
		"other_run":           func(p *nativeReadinessResourcePlan) { p.Context.RunID = uuid.NewString() },
		"created_uid":         func(p *nativeReadinessResourcePlan) { p.Context.ExpectedUID = uuid.NewString() },
		"untrusted_template": func(p *nativeReadinessResourcePlan) {
			p.CoreWorkerTemplate.Image = "example.invalid/other@sha256:" + strings.Repeat("a", 64)
		},
		"node_injection": func(p *nativeReadinessResourcePlan) { p.NodeName = "node\nother" },
		"host_volume": func(p *nativeReadinessResourcePlan) {
			p.CoreWorkerVolumes[0].HostPath = &corev1.HostPathVolumeSource{Path: "/"}
		},
		"duplicate_pull_ref": func(p *nativeReadinessResourcePlan) {
			p.ImagePullSecrets = append(p.ImagePullSecrets, p.ImagePullSecrets[0])
		},
		"unpinned_probe": func(p *nativeReadinessResourcePlan) { p.ProbeImage = "example.invalid/probe:latest" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			p := nativeReadinessRenderFixture("candidate_pod")
			mutate(&p)
			if _, err := nativeReadinessRenderResource(p); err == nil {
				t.Fatal("foreign resource/template accepted")
			}
		})
	}
	p := nativeReadinessRenderFixture("floor_initial")
	if _, err := nativeReadinessRenderResource(p); err == nil {
		t.Fatal("logical probe journal step became Kubernetes authority")
	}
}

func TestNativeReadinessRenderFloorAndUDPServiceWithoutAdmissionCycle(t *testing.T) {
	p := nativeReadinessRenderFixture("floor_pod")
	raw, err := nativeReadinessRenderResource(p)
	if err != nil {
		t.Fatal(err)
	}
	var pod corev1.Pod
	if json.Unmarshal(raw, &pod) != nil || len(pod.Spec.Containers) != 1 || len(pod.Spec.Volumes) != 1 || len(pod.Spec.Volumes[0].Projected.Sources) != 1 {
		t.Fatal("floor inherited Core/mandatory candidate admission")
	}
	p = nativeReadinessRenderFixture("candidate_service")
	raw, err = nativeReadinessRenderResource(p)
	if err != nil {
		t.Fatal(err)
	}
	var service corev1.Service
	if json.Unmarshal(raw, &service) != nil || !service.Spec.PublishNotReadyAddresses || service.Spec.Selector[model.NativeWorkerProbeSlotLabel] != "candidate_pod" || len(service.Spec.Selector) != 2 || len(service.Spec.Ports) != 1 || service.Spec.Ports[0].Protocol != corev1.ProtocolUDP || service.Spec.Ports[0].TargetPort.IntVal != 9446 {
		t.Fatal("startup readiness cycle or business Service exposed")
	}
}

func TestNativeReadinessRenderSecretsAreClosedPrivateAndImmutable(t *testing.T) {
	p := nativeReadinessRenderFixture("admission_secret")
	token := strings.Repeat("private-admission-material", 2)
	p.Data = map[string][]byte{"admission.key": []byte(token)}
	raw, err := nativeReadinessRenderResource(p)
	if err != nil {
		t.Fatal(err)
	}
	var secret corev1.Secret
	if json.Unmarshal(raw, &secret) != nil || secret.Immutable == nil || !*secret.Immutable || string(secret.Data["admission.key"]) != token {
		t.Fatal("private material missing or mutable")
	}
	public, _ := json.Marshal(p)
	if bytes.Contains(public, []byte(token)) || strings.Contains(fmt.Sprintf("%+v %#v", p, p), token) {
		t.Fatal("private plan leaked in default formatting")
	}
	p.Data["server.key"] = []byte("other-purpose")
	if _, err := nativeReadinessRenderResource(p); err == nil {
		t.Fatal("extra Secret purpose accepted")
	}
	p = nativeReadinessRenderFixture("candidate_secret")
	p.Data = map[string][]byte{}
	for _, key := range nativeReadinessMaterialKeys {
		p.Data[key] = []byte("retained-" + key)
	}
	if _, err := nativeReadinessRenderResource(p); err != nil {
		t.Fatal(err)
	}
	delete(p.Data, "controller-ca.crt")
	if _, err := nativeReadinessRenderResource(p); err == nil {
		t.Fatal("missing original key accepted")
	}
}

func TestNativeReadinessRenderStartupPatchCannotRetargetOrReplayAnotherOrigin(t *testing.T) {
	p := nativeReadinessRenderFixture("startup_challenge")
	p.Context.Op = "startup_patch"
	p.Context.ExpectedUID = uuid.NewString()
	p.Context.ExpectedResourceVersion = "12345"
	v := lifecycle.NativeAdmissionChallenge{NativeTerminationChallenge: lifecycle.NativeTerminationChallenge{SchemaVersion: 2, Namespace: p.Context.Namespace, PodName: p.Context.Name, PodUID: p.Context.ExpectedUID, WorkloadUID: p.Context.ExpectedUID, ContainerName: "core", ImageDigest: "sha256:" + strings.Repeat("a", 64), IntentGeneration: 1, DrainNonce: uuid.NewString(), IssuedAt: p.Context.NotAfter.Add(-time.Minute), LaneRosterSHA256: strings.Repeat("f", 64)}, ProcessNonce: uuid.NewString()}
	p.Challenge, _ = json.Marshal(v)
	raw, err := nativeReadinessRenderResource(p)
	if err != nil {
		t.Fatal(err)
	}
	var steps []struct{ Op, Path, Value string }
	if json.Unmarshal(raw, &steps) != nil || len(steps) != 3 || steps[0].Op != "test" || steps[0].Value != p.Context.ExpectedUID || steps[1].Op != "test" || steps[1].Value != "12345" || steps[2].Op != "add" || steps[2].Path != "/metadata/annotations/yggdrasil.io~1native-admission-v2" || steps[2].Value != string(p.Challenge) {
		t.Fatal("patch did not preserve exact retained challenge/preconditions")
	}
	v.WorkloadUID = uuid.NewString()
	p.Challenge, _ = json.Marshal(v)
	if _, err := nativeReadinessRenderResource(p); err == nil {
		t.Fatal("another workload origin accepted")
	}
	v.WorkloadUID = p.Context.ExpectedUID
	p.Challenge, _ = json.Marshal(v)
	p.Challenge = append(append(json.RawMessage{}, p.Challenge[:len(p.Challenge)-1]...), []byte(`,"process_nonce":"`+v.ProcessNonce+`"}`)...)
	if _, err := nativeReadinessRenderResource(p); err == nil {
		t.Fatal("duplicate challenge member accepted")
	}
}

func TestNativeReadinessRenderDeletionRequiresRetainedUIDAndResourceVersion(t *testing.T) {
	p := nativeReadinessRenderFixture("candidate_pod")
	p.Context.Op = "delete"
	p.Context.ExpectedUID = uuid.NewString()
	p.Context.ExpectedResourceVersion = "12345"
	raw, err := nativeReadinessRenderResource(p)
	if err != nil {
		t.Fatal(err)
	}
	var options metav1.DeleteOptions
	if json.Unmarshal(raw, &options) != nil || options.Preconditions == nil || string(*options.Preconditions.UID) != p.Context.ExpectedUID || *options.Preconditions.ResourceVersion != "12345" {
		t.Fatal("delete lost exact UID/resourceVersion")
	}
	p.Context.ExpectedResourceVersion = ""
	if _, err := nativeReadinessRenderResource(p); err == nil {
		t.Fatal("unfenced deletion accepted")
	}
	p = nativeReadinessRenderFixture("startup_challenge")
	p.Context.Op = "delete"
	p.Context.ExpectedUID = uuid.NewString()
	p.Context.ExpectedResourceVersion = "12345"
	if _, err := nativeReadinessRenderResource(p); err == nil {
		t.Fatal("startup annotation became Pod deletion authority")
	}
}

func TestNativeReadinessRenderNetworkSeparatesControllerAndDiagnosticTraffic(t *testing.T) {
	p := nativeReadinessRenderFixture("network_policy")
	run := metav1.LabelSelector{MatchLabels: map[string]string{model.NativeWorkerProbeRunLabel: p.Context.RunID}}
	udp, tcp := corev1.ProtocolUDP, corev1.ProtocolTCP
	port := intstr.FromInt32(9446)
	p.NetworkPolicySpec = networkingv1.NetworkPolicySpec{PodSelector: run, PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress}, Ingress: []networkingv1.NetworkPolicyIngressRule{{From: []networkingv1.NetworkPolicyPeer{{PodSelector: &run}}, Ports: []networkingv1.NetworkPolicyPort{{Protocol: &udp, Port: &port}}}, {From: []networkingv1.NetworkPolicyPeer{{PodSelector: p.ControllerPodSelector.DeepCopy()}}, Ports: []networkingv1.NetworkPolicyPort{{Protocol: &tcp, Port: &port}}}}}
	p.NetworkPolicySpec.Egress = []networkingv1.NetworkPolicyEgressRule{{To: []networkingv1.NetworkPolicyPeer{{PodSelector: &run}}, Ports: []networkingv1.NetworkPolicyPort{{Protocol: &udp, Port: &port}}}}
	if _, err := nativeReadinessRenderResource(p); err != nil {
		t.Fatal("fixed controller/diagnostic paths rejected", err)
	}
	originalEgress := p.NetworkPolicySpec.Egress
	p.NetworkPolicySpec.Egress = nil
	if _, err := nativeReadinessRenderResource(p); err == nil {
		t.Fatal("diagnostic accepted with all outgoing probes blocked")
	}
	p.NetworkPolicySpec.Egress = originalEgress
	business := intstr.FromInt32(9080)
	p.NetworkPolicySpec.Ingress[1].Ports[0].Port = &business
	if _, err := nativeReadinessRenderResource(p); err == nil {
		t.Fatal("business HTTP ingress accepted")
	}
	p.NetworkPolicySpec.Ingress[1].Ports[0].Port = &port
	p.NetworkPolicySpec.Ingress[1].From[0].PodSelector = &run
	if _, err := nativeReadinessRenderResource(p); err == nil {
		t.Fatal("diagnostic Pod received controller ingress")
	}
}
