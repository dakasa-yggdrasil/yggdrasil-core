package repository

import (
	"encoding/json"
	"net/netip"
	"reflect"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type nativeReadinessOriginalAcceptance struct {
	UID, ResourceVersion, SafeEvidenceSHA256, EventType string
}

// A retained independent read selects the current CAS version without changing
// the original create response. Reader is protected process configuration.
type nativeReadinessOriginalStartupOrigin struct {
	Observation model.NativeWorkerProbeResourceObservation     `json:"observation"`
	Reader      model.CapacityNativeWorkerProbeResourceBinding `json:"reader"`
}

// The caller must first capture the exact original in encrypted run custody.
// This pure interpretation supplies identity for safe events/cleanup, never a
// fresh grant, readiness, absence or permission to replay. Late originals still
// need custody and may identify a real effect; the live journal independently
// fences every state transition and refuses an expired run as readiness.
func nativeReadinessQualifyOriginal(c model.NativeWorkerProbeResourceContext, expectedPrivateJSON, expectedCandidatePodJSON []byte, original model.NativeWorkerProbeResourceReceive, createdAt, now time.Time, startupOrigin *nativeReadinessOriginalStartupOrigin) (nativeReadinessOriginalAcceptance, error) {
	var zero nativeReadinessOriginalAcceptance
	if _, err := nativeReadinessRenderIdentity(c); err != nil || original.BindingName != c.BindingName || original.RunID != c.RunID || original.Slot != c.Slot || !original.TransportCompleted || len(original.OriginalReturn) == 0 || len(original.OriginalReturn) > 1<<20 || createdAt.IsZero() || now.Before(createdAt) || original.CompletedAt.Before(createdAt) || original.CompletedAt.After(now) {
		return zero, errNativeReadinessRun
	}
	if _, ok := nativeReadinessTokenSHA(original.SettlementToken); !ok {
		return zero, errNativeReadinessRun
	}
	// This is the safe projection of the immutable original create request,
	// including for deletion. DeleteOptions has no resource metadata and is not
	// silently substituted into this protocol's public template digest.
	sha, err := capacity.NativeWorkerProbePublicTemplateSHA(c, expectedPrivateJSON)
	if err != nil || sha != c.PublicTemplateSHA256 {
		return zero, errNativeReadinessRun
	}
	if c.Op == "delete" {
		return nativeReadinessQualifyDelete(c, original, createdAt, now)
	}
	if c.Op == "create" && original.HTTPStatus != 201 || c.Op == "startup_patch" && original.HTTPStatus != 200 || c.Op != "create" && c.Op != "startup_patch" {
		return zero, errNativeReadinessRun
	}
	var head struct {
		APIVersion string            `json:"apiVersion"`
		Kind       string            `json:"kind"`
		Metadata   metav1.ObjectMeta `json:"metadata"`
	}
	// Decode through a raw map first so unknown top-level native fields are
	// subsequently checked by the complete typed object codec, not ignored.
	var fields map[string]json.RawMessage
	if capacity.DecodeNativeProbeResourceJSON(original.OriginalReturn, &fields) != nil || json.Unmarshal(original.OriginalReturn, &head) != nil || head.APIVersion != c.APIVersion || head.Kind != c.Kind {
		return zero, errNativeReadinessRun
	}
	if !nativeReadinessOriginalMetadata(c, head.Metadata, createdAt, now, false) {
		return zero, errNativeReadinessRun
	}
	meta := func(raw []byte) (metav1.ObjectMeta, error) {
		var fields map[string]json.RawMessage
		var m metav1.ObjectMeta
		if capacity.DecodeNativeProbeResourceJSON(raw, &fields) != nil || capacity.DecodeNativeProbeResourceJSON(fields["metadata"], &m) != nil {
			return m, errNativeReadinessRun
		}
		return m, nil
	}
	expectedMeta, err := meta(expectedPrivateJSON)
	startupReadSHA := ""
	if c.Op == "startup_patch" {
		if c.Slot != "startup_challenge" || !nativeReadinessCanonicalUUID(c.ExpectedUID) || !nativeReadinessResourceVersion(c.ExpectedResourceVersion) || head.Metadata.UID == "" || string(head.Metadata.UID) != c.ExpectedUID || head.Metadata.ResourceVersion == c.ExpectedResourceVersion {
			return zero, errNativeReadinessRun
		}
		var prior corev1.Pod
		if capacity.DecodeNativeProbeResourceJSON(expectedCandidatePodJSON, &prior) != nil || string(prior.UID) != c.ExpectedUID || prior.Name != c.Name || prior.Namespace != c.Namespace || prior.DeletionTimestamp != nil || !nativeReadinessResourceVersion(prior.ResourceVersion) {
			return zero, errNativeReadinessRun
		}
		if startupOrigin != nil {
			startupReadSHA, err = nativeReadinessStartupOrigin(c, prior, *startupOrigin, createdAt, original.CompletedAt)
			if err != nil {
				return zero, err
			}
		} else if prior.ResourceVersion != c.ExpectedResourceVersion {
			return zero, errNativeReadinessRun
		}
		value, present := prior.Annotations[model.NativeWorkerProbeAdmissionAnnotation]
		if !present || value != "" {
			return zero, errNativeReadinessRun
		}
		var steps []struct {
			Op    string `json:"op"`
			Path  string `json:"path"`
			Value string `json:"value"`
		}
		if capacity.DecodeNativeProbeResourceJSON(expectedPrivateJSON, &steps) != nil || len(steps) != 3 || steps[0].Op != "test" || steps[0].Path != "/metadata/uid" || steps[0].Value != c.ExpectedUID || steps[1].Op != "test" || steps[1].Path != "/metadata/resourceVersion" || steps[1].Value != c.ExpectedResourceVersion || steps[2].Op != "add" || steps[2].Path != "/metadata/annotations/yggdrasil.io~1native-admission-v2" {
			return zero, errNativeReadinessRun
		}
		var challenge json.RawMessage = json.RawMessage(steps[2].Value)
		plan := nativeReadinessResourcePlan{Context: c, Challenge: challenge}
		// Locate the real API worker, independent of container ordering.
		workers := 0
		for _, container := range prior.Spec.Containers {
			if len(container.Command) == 1 && container.Command[0] == "/app/yggdrasil-api-worker" {
				plan.CoreImage, plan.CoreWorkerTemplate = container.Image, container
				workers++
			}
		}
		if workers != 1 {
			return zero, errNativeReadinessRun
		}
		if _, err := nativeReadinessRenderStartup(plan); err != nil {
			return zero, err
		}
		prior.Annotations = cloneNativeReadinessLabels(prior.Annotations)
		prior.Annotations[model.NativeWorkerProbeAdmissionAnnotation] = steps[2].Value
		expectedMeta = prior.ObjectMeta
		var actual corev1.Pod
		if capacity.DecodeNativeProbeResourceJSON(original.OriginalReturn, &actual) != nil || !nativeReadinessPodSpecMatches(prior.Spec, actual.Spec) {
			return zero, errNativeReadinessRun
		}
	} else {
		if err != nil || expectedMeta.Name != c.Name || expectedMeta.Namespace != c.Namespace || expectedMeta.UID != "" || expectedMeta.ResourceVersion != "" {
			return zero, errNativeReadinessRun
		}
		switch c.Kind {
		case "Pod":
			var expected, actual corev1.Pod
			if capacity.DecodeNativeProbeResourceJSON(expectedPrivateJSON, &expected) != nil || capacity.DecodeNativeProbeResourceJSON(original.OriginalReturn, &actual) != nil || !nativeReadinessPodSpecMatches(expected.Spec, actual.Spec) {
				return zero, errNativeReadinessRun
			}
		case "Secret":
			var expected, actual corev1.Secret
			if capacity.DecodeNativeProbeResourceJSON(expectedPrivateJSON, &expected) != nil || capacity.DecodeNativeProbeResourceJSON(original.OriginalReturn, &actual) != nil {
				return zero, errNativeReadinessRun
			}
			defer func() {
				for _, v := range actual.Data {
					clear(v)
				}
				for _, v := range expected.Data {
					clear(v)
				}
			}()
			if !reflect.DeepEqual(expected.Data, actual.Data) || !reflect.DeepEqual(expected.Immutable, actual.Immutable) || expected.Type != actual.Type || len(actual.StringData) != 0 {
				return zero, errNativeReadinessRun
			}
		case "Service":
			var expected, actual corev1.Service
			if capacity.DecodeNativeProbeResourceJSON(expectedPrivateJSON, &expected) != nil || capacity.DecodeNativeProbeResourceJSON(original.OriginalReturn, &actual) != nil || !nativeReadinessServiceSpecMatches(expected.Spec, actual.Spec) {
				return zero, errNativeReadinessRun
			}
		case "NetworkPolicy":
			var expected, actual networkingv1.NetworkPolicy
			if capacity.DecodeNativeProbeResourceJSON(expectedPrivateJSON, &expected) != nil || capacity.DecodeNativeProbeResourceJSON(original.OriginalReturn, &actual) != nil || !reflect.DeepEqual(expected.Spec, actual.Spec) {
				return zero, errNativeReadinessRun
			}
		default:
			return zero, errNativeReadinessRun
		}
	}
	if !reflect.DeepEqual(expectedMeta.Labels, head.Metadata.Labels) || !reflect.DeepEqual(expectedMeta.Annotations, head.Metadata.Annotations) {
		return zero, errNativeReadinessRun
	}
	out := nativeReadinessOriginalAcceptance{UID: string(head.Metadata.UID), ResourceVersion: head.Metadata.ResourceVersion, EventType: "created"}
	if c.Op == "startup_patch" {
		out.EventType = "startup_patched"
	}
	return nativeReadinessOriginalEvidence(c, original, out, startupReadSHA)
}

func nativeReadinessStartupOrigin(c model.NativeWorkerProbeResourceContext, prior corev1.Pod, origin nativeReadinessOriginalStartupOrigin, createdAt, completedAt time.Time) (string, error) {
	o, b := origin.Observation, origin.Reader
	if o.Schema != model.NativeWorkerProbeResourceObservationSchema || b.SourceCommit != c.SDKSourceCommit || o.SourceCommit != b.SourceCommit || !nativeReadinessSHA(b.ScopeSHA256) || o.BindingScopeSHA256 != b.ScopeSHA256 || b.Name == "" || o.BindingName != b.Name || o.Adapter != b.Adapter || !nativeReadinessCanonicalUUID(b.Adapter.ManifestID) || !nativeReadinessCanonicalUUID(b.Adapter.IntegrationTypeID) || b.Adapter.Version < 1 || b.Adapter.Checksum == "" || b.Adapter.TypeChecksum == "" || b.PrincipalID != "" || o.RunID != c.RunID || o.AttemptID != c.AttemptID || o.Slot != "candidate_pod" && o.Slot != "startup_challenge" || o.HTTPStatus != 200 || !o.ReadComplete || !o.Found || o.MutationAuthorized || o.ReadinessQualified || o.AbsenceProven || o.ObservedAt.Before(createdAt) || o.ObservedAt.After(completedAt) || o.Namespace.Name != c.Namespace || o.Namespace.UID != c.NamespaceUID || o.Namespace.Deleting || o.Resource.APIVersion != "v1" || o.Resource.Kind != "Pod" || o.Resource.Name != c.Name || o.Resource.Namespace != c.Namespace || o.Resource.UID != c.ExpectedUID || o.Resource.ResourceVersion != c.ExpectedResourceVersion || o.Resource.Deleting || !o.Resource.CreatedAt.Equal(prior.CreationTimestamp.Time) || o.Pod == nil || o.Node == nil || o.Pod.NodeName != prior.Spec.NodeName || o.Node.Name != prior.Spec.NodeName || !nativeReadinessCanonicalUUID(o.Node.UID) || o.Node.ProviderID == "" || o.Node.Deleting || !o.Node.RegistrationFound || len(o.Pod.Containers) != len(prior.Spec.Containers) {
		return "", errNativeReadinessRun
	}
	seen := map[string]bool{}
	for _, expected := range prior.Spec.Containers {
		found := false
		for _, actual := range o.Pod.Containers {
			if actual.Name != expected.Name {
				continue
			}
			if found || seen[actual.Name] || actual.Image != expected.Image || actual.ContainerID == "" || actual.ImageID == "" || !actual.Running || actual.StartedAt.IsZero() || actual.StartedAt.Before(prior.CreationTimestamp.Time) || actual.StartedAt.After(o.ObservedAt) || actual.RestartCount != 0 {
				return "", errNativeReadinessRun
			}
			seen[actual.Name], found = true, true
		}
		if !found {
			return "", errNativeReadinessRun
		}
	}
	sha := o.EvidenceSHA256
	o.EvidenceSHA256 = ""
	actual, err := nativeReadinessDigest(o)
	if err != nil || !nativeReadinessSHA(sha) || sha != actual {
		return "", errNativeReadinessRun
	}
	return sha, nil
}

func cloneNativeReadinessLabels(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func nativeReadinessOriginalMetadata(c model.NativeWorkerProbeResourceContext, m metav1.ObjectMeta, createdAt, now time.Time, deleting bool) bool {
	slot := c.Slot
	if slot == "startup_challenge" {
		slot = "candidate_pod"
	}
	// metav1.Time's wire format retains whole seconds. Compare the same
	// precision; it is not independent proof of subsecond clock agreement.
	return m.Name == c.Name && m.Namespace == c.Namespace && nativeReadinessCanonicalUUID(string(m.UID)) && nativeReadinessResourceVersion(m.ResourceVersion) && m.GenerateName == "" && len(m.OwnerReferences) == 0 && len(m.Finalizers) == 0 && (deleting || m.DeletionTimestamp == nil) && !m.CreationTimestamp.Time.Before(createdAt.Truncate(time.Second)) && !m.CreationTimestamp.Time.After(now) && len(m.Labels) == 3 && m.Labels[model.NativeWorkerProbeRunLabel] == c.RunID && m.Labels[model.NativeWorkerProbeSlotLabel] == slot && m.Labels[model.NativeWorkerProbeAttemptLabel] == c.AttemptID
}

func nativeReadinessOriginalEvidence(c model.NativeWorkerProbeResourceContext, original model.NativeWorkerProbeResourceReceive, out nativeReadinessOriginalAcceptance, startupReadSHA string) (nativeReadinessOriginalAcceptance, error) {
	// No private body digest, key, challenge, settlement token or env value.
	v := struct {
		Schema            string                                 `json:"schema"`
		Context           model.NativeWorkerProbeResourceContext `json:"context"`
		UID               string                                 `json:"uid"`
		ResourceVersion   string                                 `json:"resource_version"`
		EventType         string                                 `json:"event_type"`
		HTTPStatus        int                                    `json:"http_status"`
		CompletedAt       time.Time                              `json:"completed_at"`
		StartupReadSHA256 string                                 `json:"startup_read_sha256,omitempty"`
	}{"native_worker_probe_original_public_acceptance_v1", c, out.UID, out.ResourceVersion, out.EventType, original.HTTPStatus, original.CompletedAt, startupReadSHA}
	sha, err := nativeReadinessDigest(v)
	if err != nil {
		return nativeReadinessOriginalAcceptance{}, err
	}
	out.SafeEvidenceSHA256 = sha
	return out, nil
}

func nativeReadinessQualifyDelete(c model.NativeWorkerProbeResourceContext, original model.NativeWorkerProbeResourceReceive, createdAt, now time.Time) (nativeReadinessOriginalAcceptance, error) {
	var zero nativeReadinessOriginalAcceptance
	if c.Slot == "startup_challenge" || !nativeReadinessCanonicalUUID(c.ExpectedUID) || !nativeReadinessResourceVersion(c.ExpectedResourceVersion) || original.HTTPStatus != 200 && original.HTTPStatus != 202 {
		return zero, errNativeReadinessRun
	}
	var fields map[string]json.RawMessage
	if capacity.DecodeNativeProbeResourceJSON(original.OriginalReturn, &fields) != nil {
		return zero, errNativeReadinessRun
	}
	var kind string
	if json.Unmarshal(fields["kind"], &kind) != nil {
		return zero, errNativeReadinessRun
	}
	out := nativeReadinessOriginalAcceptance{UID: c.ExpectedUID, EventType: "delete_acknowledged"}
	if kind == "Status" {
		var status metav1.Status
		if capacity.DecodeNativeProbeResourceJSON(original.OriginalReturn, &status) != nil || status.APIVersion != "v1" || status.Status != metav1.StatusSuccess || status.Details == nil || status.Details.Name != c.Name || string(status.Details.UID) != c.ExpectedUID || status.Code != 0 && status.Code != int32(original.HTTPStatus) {
			return zero, errNativeReadinessRun
		}
		kinds := map[string]string{"Pod": "pods", "Service": "services", "Secret": "secrets", "NetworkPolicy": "networkpolicies"}
		if status.Details.Kind != c.Kind && status.Details.Kind != kinds[c.Kind] {
			return zero, errNativeReadinessRun
		}
		group := ""
		if c.Kind == "NetworkPolicy" {
			group = "networking.k8s.io"
		}
		if status.Details.Group != "" && status.Details.Group != group {
			return zero, errNativeReadinessRun
		}
		out.ResourceVersion = status.ResourceVersion
	} else {
		var m struct {
			APIVersion string            `json:"apiVersion"`
			Kind       string            `json:"kind"`
			Metadata   metav1.ObjectMeta `json:"metadata"`
		}
		if json.Unmarshal(original.OriginalReturn, &m) != nil || m.APIVersion != c.APIVersion || m.Kind != c.Kind || string(m.Metadata.UID) != c.ExpectedUID || !nativeReadinessOriginalMetadata(c, m.Metadata, createdAt, now, true) {
			return zero, errNativeReadinessRun
		}
		out.ResourceVersion = m.Metadata.ResourceVersion
	}
	return nativeReadinessOriginalEvidence(c, original, out, "")
}

// Normalize only exact native defaults. An injected sidecar, credential,
// volume, permission, endpoint, image or changed explicit field remains a
// mismatch. Neither status.readiness nor these defaults qualify admission.
func nativeReadinessPodSpecMatches(expected, actual corev1.PodSpec) bool {
	a := *actual.DeepCopy()
	if expected.DNSPolicy == "" && a.DNSPolicy == corev1.DNSClusterFirst {
		a.DNSPolicy = ""
	}
	if expected.SchedulerName == "" && a.SchedulerName == "default-scheduler" {
		a.SchedulerName = ""
	}
	if expected.ServiceAccountName == "" && a.ServiceAccountName == "default" {
		a.ServiceAccountName = ""
	}
	if expected.DeprecatedServiceAccount == "" && a.DeprecatedServiceAccount == "default" {
		a.DeprecatedServiceAccount = ""
	}
	if expected.TerminationGracePeriodSeconds == nil && a.TerminationGracePeriodSeconds != nil && *a.TerminationGracePeriodSeconds == 30 {
		a.TerminationGracePeriodSeconds = nil
	}
	if expected.EnableServiceLinks == nil && a.EnableServiceLinks != nil && *a.EnableServiceLinks {
		a.EnableServiceLinks = nil
	}
	if expected.PreemptionPolicy == nil && a.PreemptionPolicy != nil && *a.PreemptionPolicy == corev1.PreemptLowerPriority {
		a.PreemptionPolicy = nil
	}
	if expected.Priority == nil && a.Priority != nil && *a.Priority == 0 {
		a.Priority = nil
	}
	if len(expected.Tolerations) == 0 && len(a.Tolerations) == 2 {
		seen := map[string]bool{}
		for _, v := range a.Tolerations {
			if (v.Key != "node.kubernetes.io/not-ready" && v.Key != "node.kubernetes.io/unreachable") || v.Operator != corev1.TolerationOpExists || v.Effect != corev1.TaintEffectNoExecute || v.Value != "" || v.TolerationSeconds == nil || *v.TolerationSeconds != 300 || seen[v.Key] {
				return false
			}
			seen[v.Key] = true
		}
		a.Tolerations = nil
	}
	if len(expected.Containers) != len(a.Containers) || len(expected.InitContainers) != len(a.InitContainers) || len(expected.Volumes) != len(a.Volumes) {
		return false
	}
	for i := range a.Containers {
		nativeReadinessContainerDefaults(expected.Containers[i], &a.Containers[i])
	}
	for i := range a.InitContainers {
		nativeReadinessContainerDefaults(expected.InitContainers[i], &a.InitContainers[i])
	}
	for i := range a.Volumes {
		e, v := expected.Volumes[i], &a.Volumes[i]
		if e.ConfigMap != nil && e.ConfigMap.DefaultMode == nil && v.ConfigMap != nil && v.ConfigMap.DefaultMode != nil && *v.ConfigMap.DefaultMode == 0644 {
			v.ConfigMap.DefaultMode = nil
		}
		if e.Secret != nil && e.Secret.DefaultMode == nil && v.Secret != nil && v.Secret.DefaultMode != nil && *v.Secret.DefaultMode == 0644 {
			v.Secret.DefaultMode = nil
		}
	}
	return reflect.DeepEqual(expected, a)
}

func nativeReadinessContainerDefaults(e corev1.Container, a *corev1.Container) {
	if e.ImagePullPolicy == "" && a.ImagePullPolicy == corev1.PullIfNotPresent {
		a.ImagePullPolicy = ""
	}
	if e.TerminationMessagePath == "" && a.TerminationMessagePath == "/dev/termination-log" {
		a.TerminationMessagePath = ""
	}
	if e.TerminationMessagePolicy == "" && a.TerminationMessagePolicy == corev1.TerminationMessageReadFile {
		a.TerminationMessagePolicy = ""
	}
	for i := range a.Ports {
		if i < len(e.Ports) && e.Ports[i].Protocol == "" && a.Ports[i].Protocol == corev1.ProtocolTCP {
			a.Ports[i].Protocol = ""
		}
	}
	for i := range a.Env {
		if i < len(e.Env) && e.Env[i].ValueFrom != nil && e.Env[i].ValueFrom.FieldRef != nil && e.Env[i].ValueFrom.FieldRef.APIVersion == "" && a.Env[i].ValueFrom != nil && a.Env[i].ValueFrom.FieldRef != nil && a.Env[i].ValueFrom.FieldRef.APIVersion == "v1" {
			a.Env[i].ValueFrom.FieldRef.APIVersion = ""
		}
	}
	for _, pair := range [][2]*corev1.Probe{{e.ReadinessProbe, a.ReadinessProbe}, {e.LivenessProbe, a.LivenessProbe}, {e.StartupProbe, a.StartupProbe}} {
		old, current := pair[0], pair[1]
		if old == nil || current == nil {
			continue
		}
		if old.TimeoutSeconds == 0 && current.TimeoutSeconds == 1 {
			current.TimeoutSeconds = 0
		}
		if old.PeriodSeconds == 0 && current.PeriodSeconds == 10 {
			current.PeriodSeconds = 0
		}
		if old.SuccessThreshold == 0 && current.SuccessThreshold == 1 {
			current.SuccessThreshold = 0
		}
		if old.FailureThreshold == 0 && current.FailureThreshold == 3 {
			current.FailureThreshold = 0
		}
		if old.HTTPGet != nil && current.HTTPGet != nil && old.HTTPGet.Scheme == "" && current.HTTPGet.Scheme == corev1.URISchemeHTTP {
			current.HTTPGet.Scheme = ""
		}
	}
}

func nativeReadinessServiceSpecMatches(expected, actual corev1.ServiceSpec) bool {
	a := *actual.DeepCopy()
	ip, err := netip.ParseAddr(a.ClusterIP)
	if expected.ClusterIP != "" || err != nil || !ip.Is4() || ip.String() != a.ClusterIP || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLoopback() || len(a.ClusterIPs) != 1 || a.ClusterIPs[0] != a.ClusterIP {
		return false
	}
	a.ClusterIP = ""
	a.ClusterIPs = nil
	if expected.SessionAffinity == "" && a.SessionAffinity == corev1.ServiceAffinityNone {
		a.SessionAffinity = ""
	}
	if expected.InternalTrafficPolicy == nil && a.InternalTrafficPolicy != nil && *a.InternalTrafficPolicy == corev1.ServiceInternalTrafficPolicyCluster {
		a.InternalTrafficPolicy = nil
	}
	if expected.IPFamilyPolicy == nil && a.IPFamilyPolicy != nil && *a.IPFamilyPolicy == corev1.IPFamilyPolicySingleStack {
		a.IPFamilyPolicy = nil
	}
	if len(expected.IPFamilies) == 0 && len(a.IPFamilies) == 1 && a.IPFamilies[0] == corev1.IPv4Protocol {
		a.IPFamilies = nil
	}
	return reflect.DeepEqual(expected, a)
}
