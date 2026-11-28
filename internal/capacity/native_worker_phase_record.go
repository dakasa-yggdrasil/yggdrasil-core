package capacity

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// NativeWorkerPhaseRecordEvidence is private ledger custody, never an RPC DTO.
// An observed GET alone does not replace the actual original native CAS ACK.
type NativeWorkerPhaseRecordEvidence struct {
	Redeemed bool
	Context  model.CapacityNativeWorkerPhasePermit
	Original model.CapacityNativeWorkerPhaseReceive
}

func (NativeWorkerPhaseRecordEvidence) String() string     { return "[private Native phase record]" }
func (e NativeWorkerPhaseRecordEvidence) GoString() string { return e.String() }

func (NativeWorkerPhaseRecordEvidence) MarshalJSON() ([]byte, error) {
	return []byte(`{"private_native_phase_record":"redacted"}`), nil
}

// ReadLifecyclePhase retains the selected actual Node/registry read. Admission
// additionally obtains the existing independent readiness port after release;
// PreparePhase deliberately requires quarantine and cannot serve this purpose.
func (r *NativeWorkerPhaseReader) ReadLifecyclePhase(ctx context.Context, a model.CapacityNativeWorkerAttempt) (model.CapacityNativeWorkerPhaseReadObservation, *model.CapacityNativeWorkerReadinessProof, error) {
	var zero model.CapacityNativeWorkerPhaseReadObservation
	if r == nil || r.read == nil || a.Physical == nil || ctx == nil || ctx.Err() != nil {
		return zero, nil, fmt.Errorf("Native phase record reader unavailable")
	}
	o, err := r.read(ctx, *r.policy.NativeWorkerLifecycleBinding.PhaseObserver, a.Physical.ProviderID, a.BirthSHA256)
	if err != nil {
		return zero, nil, err
	}
	if _, err = nativePhaseReadCandidate(r.policy, a.Physical.ProviderID, a.BirthSHA256, o, time.Now().UTC()); err != nil {
		return zero, nil, err
	}
	var proof *model.CapacityNativeWorkerReadinessProof
	if a.State == "registered" {
		if r.readiness == nil {
			return zero, nil, fmt.Errorf("independent readiness unavailable")
		}
		proof, err = r.readiness(ctx, a)
		if err != nil {
			return zero, nil, err
		}
	}
	return o, proof, nil
}

type nativePhaseRegistryACK struct {
	Schema         string                                    `json:"schema"`
	RealmUID       string                                    `json:"realm_uid"`
	PoolUID        string                                    `json:"pool_uid"`
	Owner          string                                    `json:"owner"`
	Epoch          int64                                     `json:"epoch"`
	CurrentProfile string                                    `json:"current_profile"`
	Registrations  []model.CapacityNativeWorkerRegistryEntry `json:"registrations"`
}

func nativePhaseObject(raw []byte) (map[string]json.RawMessage, error) {
	var out map[string]json.RawMessage
	if len(raw) == 0 || DecodeNativeCapacity(json.RawMessage(raw), &out) != nil || out == nil {
		return nil, fmt.Errorf("original native object required")
	}
	for k := range out {
		for _, reserved := range []string{"apiVersion", "kind", "metadata", "spec", "uid", "resourceVersion", "deletionTimestamp", "name", "namespace", "annotations", "providerID", "taints", "holderIdentity", "leaseTransitions"} {
			if strings.EqualFold(k, reserved) && k != reserved {
				return nil, fmt.Errorf("noncanonical native field")
			}
		}
	}
	return out, nil
}
func nativePhaseObjectString(o map[string]json.RawMessage, key string) string {
	var s string
	_ = json.Unmarshal(o[key], &s)
	return s
}

// Validate the native response's immutable object and the exact desired entry,
// rather than accepting a 2xx status or current registry contents as an ACK.
func nativePhaseOriginalACK(e NativeWorkerPhaseRecordEvidence) (string, error) {
	c, raw := e.Context, e.Original
	if !e.Redeemed || c.PhaseState != "observed" || raw.PermitID != c.PermitID || raw.BindingName != c.BindingName || !raw.TransportCompleted || raw.HTTPStatus != 200 || raw.CompletedAt.IsZero() {
		return "", fmt.Errorf("complete redeemed original CAS ACK required")
	}
	o, err := nativePhaseObject(raw.OriginalReturn)
	if err != nil {
		return "", err
	}
	m, err := nativePhaseObject(o["metadata"])
	if err != nil {
		return "", err
	}
	rv := nativePhaseObjectString(m, "resourceVersion")
	if rv == "" || nativePhaseObjectString(m, "deletionTimestamp") != "" {
		return "", fmt.Errorf("live original native identity required")
	}
	if c.Action == "release_quarantine" {
		if nativePhaseObjectString(o, "apiVersion") != "v1" || nativePhaseObjectString(o, "kind") != "Node" || nativePhaseObjectString(m, "uid") != c.Node.UID || nativePhaseObjectString(m, "name") != c.Node.Name || rv == c.Node.ResourceVersion {
			return "", fmt.Errorf("exact original Node ACK required")
		}
		spec, err := nativePhaseObject(o["spec"])
		if err != nil || nativePhaseObjectString(spec, "providerID") != c.Node.ProviderID {
			return "", fmt.Errorf("original Node provider differs")
		}
		var taints []struct {
			Key       string `json:"key"`
			Value     string `json:"value,omitempty"`
			Effect    string `json:"effect"`
			TimeAdded string `json:"timeAdded,omitempty"`
		}
		if t, ok := spec["taints"]; ok && DecodeNativeCapacity(t, &taints) != nil {
			return "", fmt.Errorf("original Node taints malformed")
		}
		for _, t := range taints {
			if t.Effect == "NoSchedule" || t.Effect == "NoExecute" {
				return "", fmt.Errorf("original Node still blocks scheduling")
			}
		}
		return rv, nil
	}
	if nativePhaseObjectString(o, "apiVersion") != "coordination.k8s.io/v1" || nativePhaseObjectString(o, "kind") != "Lease" || nativePhaseObjectString(m, "uid") != c.Registry.UID || nativePhaseObjectString(m, "namespace") != c.Registry.Namespace || nativePhaseObjectString(m, "name") != c.Registry.Name || rv == c.ExpectedRegistryResourceVersion {
		return "", fmt.Errorf("exact original registry ACK required")
	}
	var annotations map[string]string
	if DecodeNativeCapacity(m["annotations"], &annotations) != nil {
		return "", fmt.Errorf("original registry annotation required")
	}
	var reg nativePhaseRegistryACK
	if DecodeNativeCapacity(json.RawMessage(annotations["yggdrasil.io/native-worker-pool-v1"]), &reg) != nil || reg.Schema != "native_worker_pool_registry_v1" || reg.RealmUID != c.RealmUID || reg.PoolUID != c.PoolUID || reg.Owner != c.Owner || reg.Epoch != c.Epoch || reg.Registrations == nil || len(reg.Registrations) > 100000 {
		return "", fmt.Errorf("original registry scope differs")
	}
	spec, err := nativePhaseObject(o["spec"])
	if err != nil || nativePhaseObjectString(spec, "holderIdentity") != c.Owner {
		return "", fmt.Errorf("original registry owner differs")
	}
	transitions, present := spec["leaseTransitions"]
	var epoch int64
	if !present || json.Unmarshal(transitions, &epoch) != nil || epoch != c.Epoch {
		return "", fmt.Errorf("complete original registry epoch required")
	}
	count := 0
	for _, entry := range reg.Registrations {
		if entry.NodeUID != c.Node.UID && entry.ProviderID != c.Node.ProviderID {
			continue
		}
		count++
		if !nativePhaseEntryMatches(c.Node, entry) {
			return "", fmt.Errorf("original registry birth differs")
		}
		if c.Action == "register" {
			if entry.Admission != (model.CapacityNativeWorkerRegistryAdmission{State: "quarantined"}) {
				return "", fmt.Errorf("original registration not quarantined")
			}
		} else if entry.Admission.State != "admitted" || nativePhaseAdmission(entry.Admission) != c.Admission {
			return "", fmt.Errorf("original admission evidence differs")
		}
	}
	if count != 1 {
		return "", fmt.Errorf("unique original registration required")
	}
	return rv, nil
}

// ProjectNativeWorkerPhaseRecord is consumed only after protected runtime reads
// and private ledger custody. Existing Record rechecks authority/revision under
// its transaction. It never creates another birth or mutates a permit.
func ProjectNativeWorkerPhaseRecord(p model.CapacityPolicySpec, a model.CapacityNativeWorkerAttempt, physical NativeWorkerLifecycleRead, register NativeWorkerPhaseRecordEvidence, admit, release *NativeWorkerPhaseRecordEvidence, current model.CapacityNativeWorkerPhaseReadObservation, proof *model.CapacityNativeWorkerReadinessProof, now time.Time) (model.CapacityNativeWorkerObservation, error) {
	var zero model.CapacityNativeWorkerObservation
	if a.Physical == nil || !ValidDigest(a.BirthSHA256) || (a.State != "acknowledged" && a.State != "registered") || p.NativeWorkerLifecycleBinding == nil || p.NativeWorkerLifecycleBinding.SourceCommit != a.SourceCommit || p.NativeWorkerLifecycleBinding.RegistryWriter == nil || p.NativeWorkerLifecycleBinding.PhaseObserver == nil || current.ObservedAt.After(now) || !fresh(physical.ObservedAt, now, p.NativeWorkerLifecycleBinding.MaxReadAgeSeconds) || physical.ObservedAt.After(now) || physical.Physical != *a.Physical || !ValidDigest(physical.EvidenceSHA256) {
		return zero, fmt.Errorf("fresh sealed physical read required")
	}
	bound := false
	for _, b := range p.NativeWorkerLifecycleBinding.PhysicalObservers {
		if b.Profile == a.Profile && b.SourceCommit == physical.SourceCommit && b.ScopeSHA256 == physical.ScopeSHA256 && b.Adapter == physical.Adapter {
			bound = true
		}
	}
	if !bound {
		return zero, fmt.Errorf("sealed physical reader binding differs")
	}
	registration := ""
	if p.NativeWorkerPoolBinding != nil {
		for _, profile := range p.NativeWorkerPoolBinding.Profiles {
			if profile.Profile == a.Profile {
				registration = profile.RegistrationBindingSHA
			}
		}
	}
	if !ValidDigest(registration) {
		return zero, fmt.Errorf("qualified Native registration profile required")
	}
	check := func(e NativeWorkerPhaseRecordEvidence, action string) (model.CapacityNativeWorkerPhaseObservation, string, error) {
		c := e.Context
		if e.Original.CompletedAt.After(now) {
			return model.CapacityNativeWorkerPhaseObservation{}, "", fmt.Errorf("future native original refused")
		}
		if c.Action != action || c.AttemptID != a.ID || c.PolicyID != a.PolicyID || c.IntentGeneration != a.Generation || c.FencingToken != a.FencingToken || c.Node.CapacityPolicyID != a.PolicyID.String() || c.Node.IntentGeneration != a.Generation || c.Node.FencingToken != a.FencingToken || c.Operation != p.NativeWorkerLifecycleBinding.RegistryWriter.Capability || c.BindingName != p.NativeWorkerLifecycleBinding.RegistryWriter.BindingName || c.Node.ProviderID != a.Physical.ProviderID || c.Node.CreationProofSHA256 != a.BirthSHA256 || c.Node.Profile != a.Profile || c.Node.PhysicalSpecSHA256 != a.PhysicalSpecSHA256 || c.Node.RegistrationBindingSHA256 != registration || c.WriterScopeSHA256 != p.NativeWorkerLifecycleBinding.RegistryWriter.ScopeSHA256 {
			return model.CapacityNativeWorkerPhaseObservation{}, "", fmt.Errorf("phase is not bound to the sealed birth")
		}
		rv, err := nativePhaseOriginalACK(e)
		if err != nil {
			return model.CapacityNativeWorkerPhaseObservation{}, "", err
		}
		o, err := ObserveNativeWorkerPhaseFromRead(p, c, current, now)
		return o, rv, err
	}
	reg, rv, err := check(register, "register")
	if err != nil {
		return zero, err
	}
	out := model.CapacityNativeWorkerObservation{State: "registered", ExecutionScopeSHA256: a.Execution.ScopeSHA256, ObservedAt: physical.ObservedAt, OriginalReturnSHA256: physical.OriginalReturnSHA256, OriginalAcceptance: physical.Physical, IndependentCurrent: physical.Physical, OriginalRequestID: physical.BirthOriginalRequestID, IndependentRequestID: physical.CurrentRequestID, NodeUID: reg.NodeUID, NodeProviderID: reg.ProviderID, RegistryUID: reg.RegistryUID, RegistryBeforeResourceVersion: register.Context.ExpectedRegistryResourceVersion, RegistryAfterResourceVersion: rv, HCloudWitness: CloneNativeWorkerHCloudWitness(physical.HCloudWitness)}
	if a.Provider == "hetzner" {
		out.IndependentRequestID = physical.BirthIndependentRequestID
	}
	if a.State == "registered" {
		if admit == nil || release == nil || proof == nil {
			return zero, fmt.Errorf("observed admission, release and current readiness required")
		}
		ad, after, err := check(*admit, "admit_registry")
		if err != nil {
			return zero, err
		}
		rel, _, err := check(*release, "release_quarantine")
		if err != nil || !rel.QuarantineAbsent || !rel.Ready || rel.NodeUID != a.NodeUID || ad.NodeUID != a.NodeUID || admit.Context.Admission != release.Context.Admission {
			return zero, fmt.Errorf("same released ready Node required")
		}
		if proof.AttemptID != a.ID || proof.NodeUID != a.NodeUID || proof.ProviderID != a.Physical.ProviderID || proof.WorkerIPv4 != a.OverlayIPv4 || proof.BirthSHA256 != a.BirthSHA256 || proof.Physical != *a.Physical || proof.NetworkBindingSHA256 != a.NetworkBindingSHA256 || proof.PhysicalQualificationSHA256 != a.QualificationEvidenceSHA256 || proof.NetworkBindingSHA256 != admit.Context.Admission.NetworkBindingSHA256 || proof.WarmupEvidenceSHA256 != admit.Context.Admission.WarmupEvidenceSHA256 || !fresh(proof.ObservedAt, now, p.NativeWorkerLifecycleBinding.PhaseObserver.MaxAgeSeconds) || proof.ObservedAt.After(now) || !proof.ValidUntil.After(now) {
			return zero, fmt.Errorf("current independent admission evidence differs")
		}
		out.State = "admitted"
		out.RegistryBeforeResourceVersion, out.RegistryAfterResourceVersion = admit.Context.ExpectedRegistryResourceVersion, after
		out.NetworkBindingSHA256, out.NetworkEvidenceSHA256 = proof.NetworkBindingSHA256, proof.NetworkEvidenceSHA256
		out.WarmupEvidenceSHA256, out.QualificationEvidenceSHA256, out.AdmissionReceiptSHA256 = proof.WarmupEvidenceSHA256, proof.PhysicalQualificationSHA256, ad.AdmissionReceiptSHA256
	}
	if NativeWorkerObservationValid(a, out, now, p.NativeWorkerLifecycleBinding.MaxReadAgeSeconds) != nil {
		return zero, fmt.Errorf("lifecycle record evidence refused")
	}
	return out, nil
}
