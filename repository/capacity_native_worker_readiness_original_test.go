package repository

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	lifecycle "github.com/dakasa-yggdrasil/yggdrasil-core/internal/nativelifecycle"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func nativeReadinessOriginalFixture(t *testing.T, slot string) (nativeReadinessResourcePlan, []byte, model.NativeWorkerProbeResourceReceive, time.Time, time.Time) {
	t.Helper()
	p := nativeReadinessRenderFixture(slot)
	created := p.Context.NotAfter.Add(-time.Minute).Add(123 * time.Millisecond)
	now := created.Add(5 * time.Second)
	if slot == "admission_secret" {
		p.Data = map[string][]byte{"admission.key": []byte(strings.Repeat("private-run-admission", 2))}
	}
	raw, err := nativeReadinessRenderResource(p)
	if err != nil {
		t.Fatal(err)
	}
	p.Context.PublicTemplateSHA256, err = capacity.NativeWorkerProbePublicTemplateSHA(p.Context, raw)
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]any
	if json.Unmarshal(raw, &wire) != nil {
		t.Fatal("request JSON")
	}
	meta := wire["metadata"].(map[string]any)
	meta["uid"] = uuid.NewString()
	meta["resourceVersion"] = "101"
	meta["creationTimestamp"] = created.Truncate(time.Second).Format(time.RFC3339)
	ack, _ := json.Marshal(wire)
	original := model.NativeWorkerProbeResourceReceive{BindingName: p.Context.BindingName, RunID: p.Context.RunID, Slot: slot, SettlementToken: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32)), HTTPStatus: 201, CompletedAt: now.Add(-time.Second), TransportCompleted: true, OriginalReturn: ack}
	return p, raw, original, created, now
}

func TestNativeReadinessOriginalSecretMatchesPrivateCustodyWithoutPublicSecretHash(t *testing.T) {
	p, request, original, created, now := nativeReadinessOriginalFixture(t, "admission_secret")
	out, err := nativeReadinessQualifyOriginal(p.Context, request, nil, original, created, now, nil)
	if err != nil || out.EventType != "created" || !nativeReadinessCanonicalUUID(out.UID) || out.ResourceVersion != "101" || !nativeReadinessSHA(out.SafeEvidenceSHA256) {
		t.Fatal("original private Secret not qualified", out, err)
	}
	for _, mode := range []string{"private_data_changed", "transport_incomplete", "future_completion", "other_run", "409_adoption"} {
		t.Run(mode, func(t *testing.T) {
			changed := original
			changed.OriginalReturn = append([]byte(nil), original.OriginalReturn...)
			switch mode {
			case "private_data_changed":
				var s corev1.Secret
				_ = json.Unmarshal(changed.OriginalReturn, &s)
				s.Data["admission.key"] = []byte(strings.Repeat("different-secret", 3))
				changed.OriginalReturn, _ = json.Marshal(s)
			case "transport_incomplete":
				changed.TransportCompleted = false
			case "future_completion":
				changed.CompletedAt = now.Add(time.Second)
			case "other_run":
				changed.RunID = uuid.NewString()
			case "409_adoption":
				changed.HTTPStatus = 409
			}
			if _, err := nativeReadinessQualifyOriginal(p.Context, request, nil, changed, created, now, nil); err == nil {
				t.Fatal("unqualified original accepted")
			}
		})
	}
	// Equal private bytes under the same public structure do not create a
	// public brute-force oracle for a run key. The immutable journal, not this
	// pure function's arguments, owns which private request was authorized.
	var expected, actual corev1.Secret
	_ = json.Unmarshal(request, &expected)
	_ = json.Unmarshal(original.OriginalReturn, &actual)
	expected.Data["admission.key"] = []byte(strings.Repeat("other-private-run-key", 2))
	actual.Data = expected.Data
	request2, _ := nativeReadinessRenderWire(expected)
	original.OriginalReturn, _ = json.Marshal(actual)
	other, err := nativeReadinessQualifyOriginal(p.Context, request2, nil, original, created, now, nil)
	if err != nil || out.SafeEvidenceSHA256 != other.SafeEvidenceSHA256 {
		t.Fatal("safe event hashes private material", err)
	}
}

func TestNativeReadinessOriginalPodAcceptsOnlyExactServerDefaults(t *testing.T) {
	p, request, original, created, now := nativeReadinessOriginalFixture(t, "candidate_pod")
	var pod corev1.Pod
	_ = json.Unmarshal(original.OriginalReturn, &pod)
	pod.Spec.DNSPolicy = corev1.DNSClusterFirst
	pod.Spec.SchedulerName = "default-scheduler"
	pod.Spec.ServiceAccountName = "default"
	pod.Spec.DeprecatedServiceAccount = "default"
	grace, preempt, enable, priority, seconds := int64(30), corev1.PreemptLowerPriority, true, int32(0), int64(300)
	pod.Spec.TerminationGracePeriodSeconds = &grace
	pod.Spec.EnableServiceLinks = &enable
	pod.Spec.PreemptionPolicy = &preempt
	pod.Spec.Priority = &priority
	pod.Spec.Tolerations = []corev1.Toleration{{Key: "node.kubernetes.io/not-ready", Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoExecute, TolerationSeconds: &seconds}, {Key: "node.kubernetes.io/unreachable", Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoExecute, TolerationSeconds: &seconds}}
	for i := range pod.Spec.Containers {
		pod.Spec.Containers[i].ImagePullPolicy = corev1.PullIfNotPresent
		pod.Spec.Containers[i].TerminationMessagePath = "/dev/termination-log"
		pod.Spec.Containers[i].TerminationMessagePolicy = corev1.TerminationMessageReadFile
	}
	mode := int32(0644)
	pod.Spec.Volumes[0].ConfigMap.DefaultMode = &mode
	original.OriginalReturn, _ = json.Marshal(pod)
	if _, err := nativeReadinessQualifyOriginal(p.Context, request, nil, original, created, now, nil); err != nil {
		t.Fatal("exact documented API defaults rejected", err)
	}
	for _, mode := range []string{"sidecar", "image", "env", "volume", "sa_token", "toleration", "annotation"} {
		t.Run(mode, func(t *testing.T) {
			changed := *pod.DeepCopy()
			switch mode {
			case "sidecar":
				changed.Spec.Containers = append(changed.Spec.Containers, corev1.Container{Name: "injected"})
			case "image":
				changed.Spec.Containers[0].Image = "unrelated:latest"
			case "env":
				changed.Spec.Containers[0].Env = append(changed.Spec.Containers[0].Env, corev1.EnvVar{Name: "OTHER", Value: "secret"})
			case "volume":
				changed.Spec.Volumes = append(changed.Spec.Volumes, corev1.Volume{Name: "ambient-identity"})
			case "sa_token":
				yes := true
				changed.Spec.AutomountServiceAccountToken = &yes
			case "toleration":
				changed.Spec.Tolerations[0].Key = "unrelated"
			case "annotation":
				changed.Annotations["foreign"] = "value"
			}
			copy := original
			copy.OriginalReturn, _ = json.Marshal(changed)
			if _, err := nativeReadinessQualifyOriginal(p.Context, request, nil, copy, created, now, nil); err == nil {
				t.Fatal("unexpected native mutation normalized away")
			}
		})
	}
}

func TestNativeReadinessOriginalServiceNeedsRealSingleStackIPAndExactTarget(t *testing.T) {
	p, request, original, created, now := nativeReadinessOriginalFixture(t, "candidate_service")
	var service corev1.Service
	_ = json.Unmarshal(original.OriginalReturn, &service)
	service.Spec.ClusterIP = "172.30.1.2"
	service.Spec.ClusterIPs = []string{"172.30.1.2"}
	service.Spec.IPFamilies = []corev1.IPFamily{corev1.IPv4Protocol}
	family, traffic := corev1.IPFamilyPolicySingleStack, corev1.ServiceInternalTrafficPolicyCluster
	service.Spec.IPFamilyPolicy = &family
	service.Spec.InternalTrafficPolicy = &traffic
	service.Spec.SessionAffinity = corev1.ServiceAffinityNone
	original.OriginalReturn, _ = json.Marshal(service)
	if _, err := nativeReadinessQualifyOriginal(p.Context, request, nil, original, created, now, nil); err != nil {
		t.Fatal(err)
	}
	service.Spec.Selector[model.NativeWorkerProbeSlotLabel] = "unrelated_pod"
	original.OriginalReturn, _ = json.Marshal(service)
	if _, err := nativeReadinessQualifyOriginal(p.Context, request, nil, original, created, now, nil); err == nil {
		t.Fatal("Service selector drift accepted")
	}
	service.Spec.Selector[model.NativeWorkerProbeSlotLabel] = "candidate_pod"
	service.Spec.ClusterIPs = append(service.Spec.ClusterIPs, "172.30.1.3")
	original.OriginalReturn, _ = json.Marshal(service)
	if _, err := nativeReadinessQualifyOriginal(p.Context, request, nil, original, created, now, nil); err == nil {
		t.Fatal("second address silently discarded")
	}
}

func TestNativeReadinessOriginalStartupJoinsExactCASAndPreviousRealWorker(t *testing.T) {
	p, _, original, created, now := nativeReadinessOriginalFixture(t, "candidate_pod")
	var prior corev1.Pod
	_ = json.Unmarshal(original.OriginalReturn, &prior)
	c := p.Context
	c.Slot = "startup_challenge"
	c.Op = "startup_patch"
	c.ExpectedUID = string(prior.UID)
	c.ExpectedResourceVersion = prior.ResourceVersion
	challenge := lifecycle.NativeAdmissionChallenge{NativeTerminationChallenge: lifecycle.NativeTerminationChallenge{SchemaVersion: 2, Namespace: c.Namespace, PodName: c.Name, PodUID: c.ExpectedUID, WorkloadUID: c.ExpectedUID, ContainerName: p.CoreWorkerTemplate.Name, ImageDigest: "sha256:" + strings.Repeat("a", 64), IntentGeneration: 1, DrainNonce: uuid.NewString(), IssuedAt: now.Add(-time.Second), LaneRosterSHA256: strings.Repeat("f", 64)}, ProcessNonce: uuid.NewString()}
	p.Context = c
	p.Challenge, _ = json.Marshal(challenge)
	patch, err := nativeReadinessRenderResource(p)
	if err != nil {
		t.Fatal(err)
	}
	c.PublicTemplateSHA256, err = capacity.NativeWorkerProbePublicTemplateSHA(c, patch)
	if err != nil {
		t.Fatal(err)
	}
	priorRaw, _ := json.Marshal(prior)
	next := *prior.DeepCopy()
	next.ResourceVersion = "102"
	next.Annotations[model.NativeWorkerProbeAdmissionAnnotation] = string(p.Challenge)
	original.Slot = c.Slot
	original.HTTPStatus = 200
	original.OriginalReturn, _ = json.Marshal(next)
	out, err := nativeReadinessQualifyOriginal(c, patch, priorRaw, original, created, now, nil)
	if err != nil || out.EventType != "startup_patched" || out.UID != c.ExpectedUID || out.ResourceVersion != "102" {
		t.Fatal("real startup CAS not joined", out, err)
	}
	prior.Spec.Containers = nil
	empty, _ := json.Marshal(prior)
	if _, err := nativeReadinessQualifyOriginal(c, patch, empty, original, created, now, nil); err == nil {
		t.Fatal("missing previous worker accepted")
	}
	next.UID = types.UID(uuid.NewString())
	original.OriginalReturn, _ = json.Marshal(next)
	if _, err := nativeReadinessQualifyOriginal(c, patch, priorRaw, original, created, now, nil); err == nil {
		t.Fatal("CAS result changed actual lifetime")
	}
}

func TestNativeReadinessOriginalStartupUsesRetainedIndependentCurrentVersion(t *testing.T) {
	p, _, original, created, now := nativeReadinessOriginalFixture(t, "candidate_pod")
	var prior corev1.Pod
	_ = json.Unmarshal(original.OriginalReturn, &prior)
	priorRaw, _ := json.Marshal(prior)
	c := p.Context
	c.Slot = "startup_challenge"
	c.Op = "startup_patch"
	c.ExpectedUID = string(prior.UID)
	c.ExpectedResourceVersion = "102"
	p.Context = c
	p.Challenge, _ = json.Marshal(lifecycle.NativeAdmissionChallenge{NativeTerminationChallenge: lifecycle.NativeTerminationChallenge{SchemaVersion: 2, Namespace: c.Namespace, PodName: c.Name, PodUID: c.ExpectedUID, WorkloadUID: c.ExpectedUID, ContainerName: p.CoreWorkerTemplate.Name, ImageDigest: "sha256:" + strings.Repeat("a", 64), IntentGeneration: 1, DrainNonce: uuid.NewString(), IssuedAt: now.Add(-time.Second), LaneRosterSHA256: strings.Repeat("f", 64)}, ProcessNonce: uuid.NewString()})
	patch, err := nativeReadinessRenderResource(p)
	if err != nil {
		t.Fatal(err)
	}
	c.PublicTemplateSHA256, _ = capacity.NativeWorkerProbePublicTemplateSHA(c, patch)
	next := *prior.DeepCopy()
	next.ResourceVersion = "103"
	next.Annotations[model.NativeWorkerProbeAdmissionAnnotation] = string(p.Challenge)
	original.Slot = c.Slot
	original.HTTPStatus = 200
	original.OriginalReturn, _ = json.Marshal(next)
	reader := model.CapacityNativeWorkerProbeResourceBinding{Name: "independent-reader", SourceCommit: c.SDKSourceCommit, ScopeSHA256: strings.Repeat("7", 64), Adapter: model.CapacityMarketAdapterBinding{ManifestID: uuid.NewString(), IntegrationTypeID: uuid.NewString(), Version: 1, Checksum: "sha256:" + strings.Repeat("8", 64), TypeChecksum: "sha256:" + strings.Repeat("9", 64)}}
	o := model.NativeWorkerProbeResourceObservation{Schema: model.NativeWorkerProbeResourceObservationSchema, SourceCommit: reader.SourceCommit, BindingScopeSHA256: reader.ScopeSHA256, Adapter: reader.Adapter, BindingName: reader.Name, RunID: c.RunID, AttemptID: c.AttemptID, Slot: "candidate_pod", ObservedAt: original.CompletedAt.Add(-time.Millisecond), HTTPStatus: 200, ReadComplete: true, Found: true, Namespace: model.NativeWorkerProbeResourceIdentity{APIVersion: "v1", Kind: "Namespace", Name: c.Namespace, UID: c.NamespaceUID, ResourceVersion: "41", CreatedAt: created.Add(-time.Hour)}, Resource: model.NativeWorkerProbeResourceIdentity{APIVersion: "v1", Kind: "Pod", Namespace: c.Namespace, Name: c.Name, UID: c.ExpectedUID, ResourceVersion: c.ExpectedResourceVersion, CreatedAt: prior.CreationTimestamp.Time}, Pod: &model.NativeWorkerProbePodObservation{NodeName: prior.Spec.NodeName}, Node: &model.NativeWorkerProbeNodeObservation{Name: prior.Spec.NodeName, UID: uuid.NewString(), ProviderID: "hcloud://123", RegistrationFound: true}}
	for _, v := range prior.Spec.Containers {
		o.Pod.Containers = append(o.Pod.Containers, model.NativeWorkerProbeContainerObservation{Name: v.Name, Image: v.Image, ImageID: v.Image, ContainerID: "containerd://" + v.Name, StartedAt: created.Add(time.Second), Running: true})
	}
	o.EvidenceSHA256, _ = nativeReadinessDigest(o)
	origin := nativeReadinessOriginalStartupOrigin{Observation: o, Reader: reader}
	if _, err := nativeReadinessQualifyOriginal(c, patch, priorRaw, original, created, now, nil); err == nil {
		t.Fatal("old create version was silently relabeled")
	}
	if _, err := nativeReadinessQualifyOriginal(c, patch, priorRaw, original, created, now, &origin); err != nil {
		t.Fatal("actual independent current version refused", err)
	}
	var after corev1.Pod
	_ = json.Unmarshal(priorRaw, &after)
	if after.ResourceVersion != "101" {
		t.Fatal("original native create mutated")
	}
	for _, mode := range []string{"scope", "version", "source", "body_digest", "late_read", "container_restart", "attempt"} {
		t.Run(mode, func(t *testing.T) {
			raw, _ := json.Marshal(origin)
			var changed nativeReadinessOriginalStartupOrigin
			_ = json.Unmarshal(raw, &changed)
			switch mode {
			case "scope":
				changed.Observation.BindingScopeSHA256 = strings.Repeat("6", 64)
			case "version":
				changed.Observation.Resource.ResourceVersion = "100"
			case "source":
				changed.Observation.SourceCommit = strings.Repeat("a", 40)
			case "body_digest":
				changed.Observation.EvidenceSHA256 = strings.Repeat("b", 64)
			case "late_read":
				changed.Observation.ObservedAt = original.CompletedAt.Add(time.Second)
			case "container_restart":
				changed.Observation.Pod.Containers[0].RestartCount = 1
			case "attempt":
				changed.Observation.AttemptID = uuid.NewString()
			}
			if mode != "body_digest" {
				changed.Observation.EvidenceSHA256 = ""
				changed.Observation.EvidenceSHA256, _ = nativeReadinessDigest(changed.Observation)
			}
			if _, err := nativeReadinessQualifyOriginal(c, patch, priorRaw, original, created, now, &changed); err == nil {
				t.Fatal("foreign current observation accepted")
			}
		})
	}
}

func TestNativeReadinessOriginalDeleteACKNeverSuppliesAbsenceOrFakeResourceVersion(t *testing.T) {
	p, request, original, created, now := nativeReadinessOriginalFixture(t, "admission_secret")
	p.Context.Op = "delete"
	p.Context.ExpectedUID = uuid.NewString()
	p.Context.ExpectedResourceVersion = "101"
	p.Context.PublicTemplateSHA256, _ = capacity.NativeWorkerProbePublicTemplateSHA(p.Context, request)
	status := metav1.Status{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Status"}, Status: metav1.StatusSuccess, Code: 200, Details: &metav1.StatusDetails{Name: p.Context.Name, Kind: "secrets", UID: types.UID(p.Context.ExpectedUID)}}
	original.HTTPStatus = 200
	original.OriginalReturn, _ = json.Marshal(status)
	out, err := nativeReadinessQualifyOriginal(p.Context, request, nil, original, created, now, nil)
	if err != nil || out.EventType != "delete_acknowledged" || out.ResourceVersion != "" || out.UID != p.Context.ExpectedUID {
		t.Fatal("ACK invented absence/new version", out, err)
	}
	status.Code = 0
	original.OriginalReturn, _ = json.Marshal(status)
	if _, err := nativeReadinessQualifyOriginal(p.Context, request, nil, original, created, now, nil); err != nil {
		t.Fatal("native Success Status may omit its redundant code", err)
	}
	original.HTTPStatus = 404
	status.Code = 404
	status.Status = metav1.StatusFailure
	original.OriginalReturn, _ = json.Marshal(status)
	if _, err := nativeReadinessQualifyOriginal(p.Context, request, nil, original, created, now, nil); err == nil {
		t.Fatal("404 became original accepted deletion")
	}
}
