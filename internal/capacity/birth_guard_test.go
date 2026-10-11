package capacity

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

func currentBirthGuardFixture() (model.CapacityPolicySpec, model.CurrentBirthGuardObservation, time.Time) {
	p, _, _, now := boundAssessmentFixture()
	p.ExecutionEnabled = true
	p.AssessmentBinding.Snapshot.WorkloadUID = uuid.NewString()
	p.HPAExecutionBinding = &model.CapacityHPAExecutionBinding{Mode: HPALifetimeExecutionMode, AdapterPrincipalID: "native", PodTerminationBinding: "api", ContainerName: "api", ImageDigest: "sha256:" + strings.Repeat("a", 64), Lanes: []string{"listener"}, ProjectionDirectory: "/native", AdmissionMode: "process_v2", AdmissionPort: 8080, AdmissionWorkflow: model.ManifestSelector{Namespace: "ops", Name: "admit-api"}, BirthGuardBinding: "api-birth", BirthGuardSHA256: strings.Repeat("b", 64)}
	o := model.CurrentBirthGuardObservation{Operation: ObserveCurrentBirthGuard, Status: "observed", BindingName: p.HPAExecutionBinding.BirthGuardBinding, BindingSHA256: p.HPAExecutionBinding.BirthGuardSHA256, Namespace: "platform", WorkloadUID: p.AssessmentBinding.Snapshot.WorkloadUID, ObservedAt: now}
	for _, kind := range []string{"Namespace", "MutatingWebhookConfiguration", "ValidatingWebhookConfiguration", "ConfigMap", "Service", "ServiceAccount", "Endpoints", "Deployment", "Deployment", "ReplicaSet", "Pod", "Pod"} {
		namespace := o.Namespace
		if kind == "Namespace" || kind == "MutatingWebhookConfiguration" || kind == "ValidatingWebhookConfiguration" {
			namespace = ""
		}
		id := uuid.NewString()
		if kind == "Deployment" && len(o.Resources) == 7 {
			id = o.WorkloadUID
		}
		o.Resources = append(o.Resources, model.BirthGuardNativeIdentity{Kind: kind, Namespace: namespace, Name: strings.ToLower(kind) + id, UID: id, ResourceVersion: "1", SHA256: strings.Repeat("c", 64)})
	}
	for _, pod := range o.Resources[10:] {
		o.Processes = append(o.Processes, model.BirthGuardProcess{PodName: pod.Name, PodUID: pod.UID, ResourceVersion: pod.ResourceVersion, ReplicaSetUID: o.Resources[9].UID, NodeName: "worker", ContainerName: "guard", ContainerID: "containerd://" + uuid.NewString(), ImageDigest: "sha256:" + strings.Repeat("d", 64), StartedAt: now.Add(-time.Minute)})
	}
	return p, o, now
}

func TestCurrentNativeBirthGuardRequiresFixedCompleteFreshGraph(t *testing.T) {
	p, o, now := currentBirthGuardFixture()
	if err := ValidateHPAExecutionBinding(p); err != nil {
		t.Fatal(err)
	}
	if err := CurrentNativeBirthGuard(p, o, now); err != nil {
		t.Fatal(err)
	}
	for _, change := range []struct {
		name   string
		mutate func(*model.CurrentBirthGuardObservation)
	}{
		{"missing", func(o *model.CurrentBirthGuardObservation) { *o = model.CurrentBirthGuardObservation{} }},
		{"wrong_binding", func(o *model.CurrentBirthGuardObservation) { o.BindingSHA256 = strings.Repeat("f", 64) }},
		{"stale", func(o *model.CurrentBirthGuardObservation) { o.ObservedAt = now.Add(-time.Hour) }},
		{"atomic_claim", func(o *model.CurrentBirthGuardObservation) { o.AtomicSnapshot = true }},
		{"self_attested", func(o *model.CurrentBirthGuardObservation) { o.RuntimeConfigSelfAttested = true }},
		{"business_ready", func(o *model.CurrentBirthGuardObservation) { o.BusinessReadinessKnown = true }},
		{"incomplete_routing", func(o *model.CurrentBirthGuardObservation) { o.Resources = o.Resources[1:] }},
		{"duplicate_resource", func(o *model.CurrentBirthGuardObservation) { o.Resources[1] = o.Resources[0] }},
		{"foreign_process", func(o *model.CurrentBirthGuardObservation) { o.Processes[0].PodUID = uuid.NewString() }},
		{"not_a_replicaset", func(o *model.CurrentBirthGuardObservation) { o.Processes[0].ReplicaSetUID = o.Resources[0].UID }},
		{"workload_replaced", func(o *model.CurrentBirthGuardObservation) { o.Resources[7].UID = uuid.NewString() }},
		{"backend_restarted", func(o *model.CurrentBirthGuardObservation) { o.Processes[0].RestartCount = 1 }},
	} {
		t.Run(change.name, func(t *testing.T) {
			raw, _ := json.Marshal(o)
			var changed model.CurrentBirthGuardObservation
			if json.Unmarshal(raw, &changed) != nil {
				t.Fatal("fixture")
			}
			change.mutate(&changed)
			if CurrentNativeBirthGuard(p, changed, now) == nil {
				t.Fatal("unknown installation became authority")
			}
		})
	}
	p.HPAExecutionBinding.BirthGuardSHA256 = ""
	if ValidateHPAExecutionBinding(p) == nil {
		t.Fatal("enabled lifetime executor lacks installed guard binding")
	}
	p.ExecutionEnabled = false
	if ValidateHPAExecutionBinding(p) != nil {
		t.Fatal("disabled optional existing policy lost read compatibility")
	}
}
