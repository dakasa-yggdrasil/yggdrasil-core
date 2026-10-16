package capacity

import (
	"fmt"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// Trust is the internally resolved exact adapter type/instance revision plus
// its fixed operator binding, not a workflow-provided installation boolean.
func CurrentNativeBirthGuard(p model.CapacityPolicySpec, o model.CurrentBirthGuardObservation, now time.Time) error {
	if p.AssessmentBinding == nil || p.HPAExecutionBinding == nil {
		return fmt.Errorf("fixed native birth guard policy required")
	}
	b := p.HPAExecutionBinding
	if o.Operation != ObserveCurrentBirthGuard || o.Status != "observed" || b.BirthGuardBinding == "" || !lowerSHA.MatchString(b.BirthGuardSHA256) || o.BindingName != b.BirthGuardBinding || o.BindingSHA256 != b.BirthGuardSHA256 || o.Namespace != p.AssessmentBinding.Snapshot.Namespace || o.WorkloadUID != p.AssessmentBinding.Snapshot.WorkloadUID || !Fresh(o.ObservedAt, now, p.MaxEvidenceAgeSeconds) || o.AtomicSnapshot || o.BusinessReadinessKnown || o.RuntimeConfigSelfAttested || len(o.Resources) < 12 || len(o.Resources) > 260 || len(o.Processes) < 2 || len(o.Processes) > 64 {
		return fmt.Errorf("current native birth guard observation unavailable")
	}
	counts := map[string]int{}
	seen := map[string]bool{}
	identities := map[string]model.BirthGuardNativeIdentity{}
	uids := map[string]bool{}
	resourceKinds := map[string]string{}
	workloadPresent := false
	for _, r := range o.Resources {
		key := r.Kind + "/" + r.Namespace + "/" + r.Name
		if seen[key] || uids[r.UID] || r.Name == "" || !NativeProcessNonce(r.UID) || r.ResourceVersion == "" || !lowerSHA.MatchString(r.SHA256) {
			return fmt.Errorf("native birth guard resource identity incomplete")
		}
		if r.Kind == "Namespace" || r.Kind == "MutatingWebhookConfiguration" || r.Kind == "ValidatingWebhookConfiguration" {
			if r.Namespace != "" {
				return fmt.Errorf("birth guard cluster scope differs")
			}
		} else if r.Namespace != o.Namespace {
			return fmt.Errorf("birth guard namespace differs")
		}
		seen[key] = true
		identities[key] = r
		uids[r.UID] = true
		resourceKinds[r.UID] = r.Kind
		workloadPresent = workloadPresent || (r.Kind == "Deployment" && r.UID == o.WorkloadUID)
		counts[r.Kind]++
	}
	for _, kind := range []string{"Namespace", "MutatingWebhookConfiguration", "ValidatingWebhookConfiguration", "ConfigMap", "Service", "ServiceAccount", "Endpoints"} {
		if counts[kind] != 1 {
			return fmt.Errorf("native birth guard routing/config coverage incomplete")
		}
	}
	if !workloadPresent || counts["Deployment"] != 2 || counts["Pod"] != len(o.Processes) || counts["ReplicaSet"] < 1 || len(counts) != 10 {
		return fmt.Errorf("native birth guard backend census incomplete")
	}
	seenProcess := map[string]bool{}
	for _, process := range o.Processes {
		if process.PodName == "" || process.NodeName == "" || process.ContainerName == "" || process.ContainerID == "" || process.ResourceVersion == "" || !NativeProcessNonce(process.PodUID) || !NativeProcessNonce(process.ReplicaSetUID) || seenProcess[process.PodUID] || process.RestartCount != 0 || process.StartedAt.IsZero() || process.StartedAt.After(o.ObservedAt) || !capacityNativeImage(process.ImageDigest) || !seen["Pod/"+o.Namespace+"/"+process.PodName] {
			return fmt.Errorf("native birth guard process lifetime incomplete")
		}
		pod := identities["Pod/"+o.Namespace+"/"+process.PodName]
		if pod.UID != process.PodUID || pod.ResourceVersion != process.ResourceVersion || resourceKinds[process.ReplicaSetUID] != "ReplicaSet" {
			return fmt.Errorf("native birth guard process/resource tuple differs")
		}
		seenProcess[process.PodUID] = true
	}
	return nil
}

func capacityNativeImage(value string) bool {
	return len(value) == 71 && value[:7] == "sha256:" && lowerSHA.MatchString(value[7:])
}
