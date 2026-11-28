package capacity

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

const NativeWorkerLifecycleMode = "native_worker_lifecycle_v1"

// This authenticates only the registry authority header. It grants no useful
// capacity and neither rewrites nor invents an empty roster during overlap.
func ValidateNativeWorkerPoolAuthority(p model.CapacityPolicySpec, o *model.CapacityNativeWorkerPoolObservation, now time.Time) error {
	b := p.NativeWorkerPoolBinding
	if b == nil || p.NativeWorkerLifecycleBinding == nil || o == nil || !o.Complete || o.Schema != b.Mode || o.SourceCommit != b.SourceCommit ||
		o.Adapter != b.Adapter || o.RealmUID != b.RealmUID || o.PoolUID != b.PoolUID || o.Owner != b.Owner ||
		o.OwnerEpoch != b.ExpectedPoolEpoch || o.RegistryRef != b.RegistryRef || o.OwnerResourceUID != b.RegistryRef.UID ||
		o.OwnerResourceVersion == "" || o.CollectionResourceVersion == "" || !ValidDigest(o.EvidenceSHA256) ||
		!fresh(o.ObservedAt, now, min(b.MaxAgeSeconds, p.NativeWorkerLifecycleBinding.MaxReadAgeSeconds)) {
		return fmt.Errorf("fresh exact Native registry authority required")
	}
	return nil
}

func ValidateNativeWorkerLifecycleBinding(p model.CapacityPolicySpec) error {
	b := p.NativeWorkerLifecycleBinding
	if b == nil {
		return nil
	}
	if b.Mode != NativeWorkerLifecycleMode || !marketCommit.MatchString(b.SourceCommit) ||
		b.MaxReadAgeSeconds < 1 || b.MaxReadAgeSeconds > 300 || p.NativeWorkerPoolBinding == nil ||
		p.MarketBinding == nil || len(p.MutationBindings) != 0 || p.GuestBootstrapBinding != nil ||
		len(b.Profiles) != len(p.MarketBinding.Profiles) {
		return fmt.Errorf("separate closed Native lifecycle binding required")
	}
	seen := map[string]bool{}
	targets := map[string]bool{}
	for _, v := range b.Profiles {
		matched := false
		for _, market := range p.MarketBinding.Profiles {
			if market.Profile == v.Profile {
				matched = true
				if v.Adapter.ManifestID == market.Adapter.ManifestID {
					return fmt.Errorf("read-only pricing instance cannot acquire execution authority")
				}
			}
		}
		cidr, err := netip.ParsePrefix(v.OverlayCIDR)
		target := v.Adapter.ManifestID + "/" + v.BindingName
		if !matched || seen[v.Profile] || targets[target] || !marketAdapterValid(v.Adapter) || !marketID.MatchString(v.BindingName) || !marketCommit.MatchString(v.SDKSourceCommit) || !marketSHA.MatchString(v.ScopeSHA256) ||
			!strings.HasPrefix(v.EnsureCapability, "ensure_") || !strings.HasPrefix(v.ObserveCapability, "observe_") ||
			(!strings.HasPrefix(v.DestroyCapability, "destroy_") && !strings.HasPrefix(v.DestroyCapability, "terminate_")) ||
			!marketID.MatchString(v.EnsureCapability) || !marketID.MatchString(v.ObserveCapability) || !marketID.MatchString(v.DestroyCapability) ||
			!marketSHA.MatchString(v.LaunchTemplateSHA256) || !marketCommit.MatchString(v.BootstrapSourceCommit) || !marketID.MatchString(v.IPAMScope) ||
			err != nil || !cidr.Addr().Is4() || !cidr.Addr().IsPrivate() || cidr != cidr.Masked() || cidr.Bits() < 16 || cidr.Bits() > 30 ||
			len(v.ExcludedIPv4) == 0 || len(v.ExcludedIPv4) > 64 || v.GuestIdentityPolicySHA256 != "" && !marketSHA.MatchString(v.GuestIdentityPolicySHA256) {
			return fmt.Errorf("exact execution source and private server-owned IPAM required")
		}
		excluded := map[string]bool{}
		for _, raw := range v.ExcludedIPv4 {
			ip, err := netip.ParseAddr(raw)
			if err != nil || !ip.Is4() || !cidr.Contains(ip) || ip.String() != raw || excluded[raw] {
				return fmt.Errorf("exact distinct excluded overlay addresses required")
			}
			excluded[raw] = true
		}
		seen[v.Profile] = true
		targets[target] = true
	}
	if err := ValidateNativeWorkerRegistryWriterBinding(p); err != nil {
		return err
	}
	if err := ValidateNativeWorkerAbortBinding(p); err != nil {
		return err
	}
	if err := ValidateNativeWorkerPhysicalObservers(p); err != nil {
		return err
	}
	if err := ValidateNativeWorkerNetworkBinding(p); err != nil {
		return err
	}
	return ValidateNativeWorkerPhaseReadBinding(p)
}

// Safe intent identity deliberately excludes private lease/dispatch credentials.
func NativeWorkerIntentSHA(i model.CapacityIntent, pool string, epoch int64) string {
	raw, _ := json.Marshal(struct {
		Policy            string
		Generation, Fence int64
		Profile           string
		Units             int
		Pool              string
		Epoch             int64
	}{
		i.PolicyID.String(), i.Generation, i.FencingToken, i.Decision.Profile, i.Decision.Units, pool, epoch,
	})
	return fmt.Sprintf("%x", sha256.Sum256(raw))
}

func NativeWorkerUnitReservation(profile MarketProfile, now time.Time) (model.CapacityMarketReservation, int64, error) {
	per, fixed, complete, err := quoteCosts(profile.Quote, profile.HorizonSeconds)
	if err != nil || !complete {
		return model.CapacityMarketReservation{}, 0, fmt.Errorf("complete unit charge required")
	}
	if !profile.Quote.ValidUntil.After(now) {
		return model.CapacityMarketReservation{}, 0, fmt.Errorf("parent quote expired")
	}
	for _, c := range profile.Quote.Costs {
		if c.State == "known" && !c.ValidUntil.After(now) {
			return model.CapacityMarketReservation{}, 0, fmt.Errorf("parent charge evidence expired")
		}
	}
	// Split an ALREADY claimed parent into unit charges. This is not another
	// capacity selection, and static MaxUnits=0 is the observed-constraints
	// sentinel rather than a reason to invent a fixed or unlimited ceiling.
	r := model.CapacityMarketReservation{Schema: CapacityMarketMode, Profile: profile.Profile.Name, Provider: profile.Profile.Provider, Region: profile.Profile.Region, Currency: profile.Currency, BudgetScope: profile.BudgetScope, Units: 1, CostMicros: per, HorizonSeconds: profile.HorizonSeconds, QuoteEvidenceSHA256: profile.Quote.EvidenceSHA256, ObservedAt: now}
	for _, q := range profile.Quote.Quotas {
		if q.State != "known" || q.PerUnit < 1 {
			return r, 0, fmt.Errorf("parent quota unit unknown")
		}
		r.Quotas = append(r.Quotas, model.CapacityMarketQuotaReservation{Provider: r.Provider, Region: r.Region, Scope: q.Scope, Dimension: q.Dimension, Amount: q.PerUnit})
	}
	return r, fixed, nil
}

func ValidateNativeWorkerLaunch(a model.CapacityNativeWorkerAttempt, prepared model.CapacityNativeWorkerLaunch) error {
	if prepared.AttemptID != a.ID || prepared.PoolUID != a.PoolUID || prepared.PoolEpoch != a.PoolEpoch ||
		prepared.Generation != a.Generation || prepared.FencingToken != a.FencingToken ||
		prepared.OverlayIPv4 != a.OverlayIPv4 || prepared.TemplateSHA256 != a.Execution.LaunchTemplateSHA256 ||
		len(prepared.PublicJSON) == 0 || len(prepared.PublicJSON) > 32768 {
		return fmt.Errorf("prepared launch must retain exact attempt authority")
	}
	var raw map[string]json.RawMessage
	if DecodeNativeCapacity(prepared.PublicJSON, &raw) != nil {
		return fmt.Errorf("closed launch JSON required")
	}
	allowed := map[string]bool{}
	for _, k := range []string{"schema", "mode", "source_commit", "pool_id", "pool_uid", "registry", "policy_id", "policy_sha256", "expected_pool_epoch", "intent_generation", "fencing_token", "reservation_id", "intent_sha256", "provider", "floor", "network", "operator", "reserve"} {
		allowed[k] = true
	}
	if len(raw) != len(allowed) {
		return fmt.Errorf("complete public launch context required")
	}
	for k := range raw {
		if !allowed[k] {
			return fmt.Errorf("unknown public launch member")
		}
	}
	equals := func(key string, want any) bool {
		var got any
		v, _ := json.Marshal(want)
		return json.Unmarshal(raw[key], &got) == nil && string(v) == string(raw[key])
	}
	if !equals("schema", 1) || !equals("mode", "native_k3s_worker_v1") || !equals("source_commit", a.Execution.BootstrapSourceCommit) ||
		!equals("pool_uid", a.PoolUID) || !equals("policy_id", a.PolicyID.String()) || !equals("policy_sha256", strings.TrimPrefix(a.PolicyChecksum, "sha256:")) ||
		!equals("expected_pool_epoch", a.PoolEpoch) || !equals("intent_generation", a.Generation) || !equals("fencing_token", a.FencingToken) ||
		!equals("reservation_id", a.ID.String()) || !equals("intent_sha256", a.IntentSHA256) {
		return fmt.Errorf("launch identity differs from server reservation")
	}
	var registry model.CapacityNativePoolRegistryRef
	var network struct {
		WorkerIPv4 string `json:"worker_ipv4"`
	}
	if json.Unmarshal(raw["registry"], &registry) != nil || registry != a.Registry || json.Unmarshal(raw["network"], &network) != nil || network.WorkerIPv4 != a.OverlayIPv4 {
		return fmt.Errorf("launch registry or IPAM differs")
	}
	return nil
}

func NativeWorkerPhysicalValid(a model.CapacityNativeWorkerAttempt, p model.CapacityNativeWorkerPhysical) bool {
	return nativeWorkerPhysicalIdentityValid(a, p) && (a.Provider != "hetzner" || NativeWorkerHCloudWitnessValid(a, p, a.HCloudWitness))
}

func nativeWorkerPhysicalIdentityValid(a model.CapacityNativeWorkerAttempt, p model.CapacityNativeWorkerPhysical) bool {
	ip, e := netip.ParseAddr(p.NativeIPv4)
	return marketID.MatchString(p.ResourceID) && strings.HasPrefix(p.ProviderID, a.ProviderIDPrefix) &&
		p.ProviderID[strings.LastIndex(p.ProviderID, "/")+1:] == p.ResourceID &&
		!p.CreatedAt.IsZero() && !p.CreatedAt.Before(a.CreatedAt.Add(-5*time.Second)) && p.Region == a.Region && marketID.MatchString(p.Zone) &&
		marketID.MatchString(p.ImageID) && marketID.MatchString(p.InstanceType) && marketID.MatchString(p.NetworkID) &&
		p.PhysicalSpecSHA256 == a.PhysicalSpecSHA256 && ValidDigest(p.PhysicalBindingSHA256) && p.LaunchSHA256 == a.LaunchSHA256 &&
		e == nil && ip.Is4() && ip.IsPrivate() && ip.String() == p.NativeIPv4 &&
		func() bool {
			m, e := net.ParseMAC(p.MACAddress)
			return e == nil && len(m) == 6 && m.String() == p.MACAddress && m[0]&1 == 0 && m.String() != "00:00:00:00:00:00"
		}()
}

func NativeWorkerObservationValid(a model.CapacityNativeWorkerAttempt, o model.CapacityNativeWorkerObservation, now time.Time, maxAge int) error {
	if !fresh(o.ObservedAt, now, maxAge) || o.ExecutionScopeSHA256 != a.Execution.ScopeSHA256 {
		return fmt.Errorf("fresh independent observation required")
	}
	if o.State == "unknown" {
		return nil
	}
	if a.Provider == "hetzner" {
		if o.State == "absent" {
			if a.Physical == nil || !NativeWorkerPhysicalValid(a, *a.Physical) {
				return fmt.Errorf("sealed HCloud witness required for absence")
			}
		} else {
			var valid bool
			a, valid = nativeHCloudObservationAttempt(a, o, maxAge)
			if !valid {
				return fmt.Errorf("complete linked HCloud acceptance and independent witness required")
			}
		}
	} else if o.HCloudWitness != nil || o.OriginalRequestID == "" || o.IndependentRequestID == "" {
		// Preserve the existing non-HCloud two-request-ID boundary. HCloud is
		// an explicit typed exception, never an empty-value wildcard.
		if o.State != "absent" {
			return fmt.Errorf("original ACK and independent SDK request IDs required")
		}
	}
	if o.State == "absent" {
		if a.State != "draining" || a.Physical == nil || o.AbsentProviderID != a.Physical.ProviderID ||
			!o.AbsentResourceCreatedAt.Equal(a.Physical.CreatedAt) || o.AbsentOverlayIPv4 != a.OverlayIPv4 ||
			!ValidDigest(o.ProviderAbsenceEvidenceSHA256) || !ValidDigest(o.NetworkAbsenceEvidenceSHA256) {
			return fmt.Errorf("exact prior drain and independent full absence required")
		}
		return nil
	}
	if !NativeWorkerPhysicalValid(a, o.OriginalAcceptance) || o.OriginalAcceptance != o.IndependentCurrent ||
		o.IndependentCurrent.CreatedAt.After(o.ObservedAt) ||
		(a.Physical != nil && *a.Physical != o.IndependentCurrent) {
		return fmt.Errorf("original ACK and independent full SDK identity must join exact launch")
	}
	if o.State == "acknowledged" {
		return nil
	}
	if !marketUUID.MatchString(o.NodeUID) || o.NodeProviderID != o.IndependentCurrent.ProviderID || o.RegistryUID != a.Registry.UID ||
		o.RegistryBeforeResourceVersion == "" || o.RegistryAfterResourceVersion == "" || o.RegistryBeforeResourceVersion == o.RegistryAfterResourceVersion {
		return fmt.Errorf("actual Node and original registry CAS ACK required")
	}
	if o.State == "registered" {
		return nil
	}
	if o.State == "admitted" {
		if o.NetworkBindingSHA256 != a.NetworkBindingSHA256 || o.QualificationEvidenceSHA256 != a.QualificationEvidenceSHA256 || !a.QualificationValidUntil.After(now) {
			return fmt.Errorf("same current bound network and physical qualification required")
		}
		for _, s := range []string{o.NetworkEvidenceSHA256, o.WarmupEvidenceSHA256, o.QualificationEvidenceSHA256, o.AdmissionReceiptSHA256} {
			if !ValidDigest(s) {
				return fmt.Errorf("actual network warmup qualification and admission receipt required")
			}
		}
		return nil
	}
	if o.State == "draining" && a.State == "admitted" && ValidDigest(o.DrainEvidenceSHA256) {
		return nil
	}
	return fmt.Errorf("unsupported lifecycle observation")
}

func NativeWorkerTransitionAllowed(from, to string) bool {
	switch from {
	case "send_started", "unknown":
		return to == "unknown" || to == "acknowledged"
	case "acknowledged":
		return to == "registered"
	case "registered":
		return to == "admitted"
	case "admitted":
		return to == "draining"
	case "draining":
		return to == "absent"
	}
	return false
}

func NativeWorkerSameExecution(a, b model.CapacityNativeWorkerExecutionProfile) bool {
	return reflect.DeepEqual(a, b)
}

// A registry writer is a separate explicit authority. Merely mounting a pool
// or market read binding cannot enable native Kubernetes mutations.
func ValidateNativeWorkerRegistryWriterBinding(p model.CapacityPolicySpec) error {
	if p.NativeWorkerLifecycleBinding == nil || p.NativeWorkerLifecycleBinding.RegistryWriter == nil {
		return nil
	}
	b := p.NativeWorkerLifecycleBinding.RegistryWriter
	if p.NativeWorkerPoolBinding == nil || !marketAdapterValid(b.Adapter) ||
		!marketID.MatchString(b.BindingName) || b.PrincipalID == "" || len(b.PrincipalID) > 256 ||
		strings.ContainsAny(b.PrincipalID, "\x00\r\n") ||
		!marketCommit.MatchString(b.SourceCommit) || !marketSHA.MatchString(b.ScopeSHA256) ||
		b.Capability != "ensure_native_worker_pool" || b.MaxPermitSeconds < 1 || b.MaxPermitSeconds > 30 ||
		b.Adapter.ManifestID == p.NativeWorkerPoolBinding.Adapter.ManifestID {
		return fmt.Errorf("exact separate Native registry writer binding required")
	}
	if p.MarketBinding != nil {
		for _, profile := range p.MarketBinding.Profiles {
			if b.Adapter.ManifestID == profile.Adapter.ManifestID {
				return fmt.Errorf("read-only pricing adapter cannot be the registry writer")
			}
		}
	}
	return nil
}

const ObserveNativeWorkerPhase = "observe_native_worker_phase"
const NativeWorkerPhaseReadMode = "native_worker_phase_observation_v1"

func ValidateNativeWorkerPhaseReadBinding(p model.CapacityPolicySpec) error {
	if p.NativeWorkerLifecycleBinding == nil || p.NativeWorkerLifecycleBinding.PhaseObserver == nil {
		return nil
	}
	b := p.NativeWorkerLifecycleBinding.PhaseObserver
	if p.NativeWorkerPoolBinding == nil || ValidateNativeWorkerPoolBinding(p) != nil || b.Mode != NativeWorkerPhaseReadMode || !marketID.MatchString(b.Name) || !marketCommit.MatchString(b.SourceCommit) || !marketAdapterValid(b.Adapter) || !marketSHA.MatchString(b.ScopeSHA256) || !marketDNSLabel.MatchString(b.RealmNamespace) || b.MaxAgeSeconds < 1 || b.MaxAgeSeconds > p.NativeWorkerLifecycleBinding.MaxReadAgeSeconds || b.QuarantineTaintKey != "dakasa.io/native-worker-unadmitted" {
		return fmt.Errorf("exact protected Native phase observation binding required")
	}
	if w := p.NativeWorkerLifecycleBinding.RegistryWriter; w != nil && w.Adapter.ManifestID == b.Adapter.ManifestID {
		return fmt.Errorf("native phase reads cannot reuse the registry writer instance")
	}
	for _, execution := range p.NativeWorkerLifecycleBinding.Profiles {
		if execution.Adapter.ManifestID == b.Adapter.ManifestID {
			return fmt.Errorf("native phase reads cannot reuse provider execution instances")
		}
	}
	if p.MarketBinding != nil {
		for _, q := range p.MarketBinding.Profiles {
			if q.Adapter.ManifestID == b.Adapter.ManifestID {
				return fmt.Errorf("native phase reads cannot reuse pricing instances")
			}
		}
	}
	return nil
}

// This authenticates a complete read of authority and registry facts. It never
// represents the selected candidates as the complete useful worker pool.
func NativeWorkerPhaseHeaderValid(p model.CapacityPolicySpec, o model.CapacityNativeWorkerPhaseReadObservation, now time.Time) error {
	if ValidateNativeWorkerPhaseReadBinding(p) != nil || p.NativeWorkerLifecycleBinding == nil || p.NativeWorkerLifecycleBinding.PhaseObserver == nil || p.NativeWorkerPoolBinding == nil {
		return fmt.Errorf("native phase observation is disabled")
	}
	b, pool := p.NativeWorkerLifecycleBinding.PhaseObserver, p.NativeWorkerPoolBinding
	r := o.Registry
	if o.Schema != b.Mode || o.SourceCommit != b.SourceCommit || o.Adapter != b.Adapter || o.BindingName != b.Name || o.BindingScopeSHA256 != b.ScopeSHA256 || !o.Complete || !o.FullCollectionComplete || !o.RegistryRegistrationsComplete || o.MutationAuthorized || o.UsefulCapacityQualified || o.CollectionResourceVersion == "" || !ValidDigest(o.EvidenceSHA256) || !fresh(o.ObservedAt, now, b.MaxAgeSeconds) || r.Ref != pool.RegistryRef || r.RealmNamespace != b.RealmNamespace || r.RealmUID != pool.RealmUID || r.PoolUID != pool.PoolUID || r.Owner != p.Owner || r.Owner != pool.Owner || r.Epoch != pool.ExpectedPoolEpoch || r.ResourceVersion == "" || !ValidDigest(r.AnnotationSHA256) || len(o.Registrations) > 100000 {
		return fmt.Errorf("fresh exact Native phase authority facts required")
	}
	profileKnown := false
	for _, profile := range pool.Profiles {
		profileKnown = profileKnown || profile.Profile == r.CurrentProfile
	}
	if !profileKnown {
		return fmt.Errorf("native phase current profile is not source qualified")
	}
	uids, ids := map[string]bool{}, map[string]bool{}
	for _, e := range o.Registrations {
		if !marketUUID.MatchString(e.NodeUID) || !marketUUID.MatchString(e.CapacityPolicyID) || e.IntentGeneration < 1 || e.FencingToken < 1 || !ValidDigest(e.CreationProofSHA256) || e.ProviderID == "" || uids[e.NodeUID] || ids[e.ProviderID] {
			return fmt.Errorf("ambiguous Native phase registry identities")
		}
		qualified := false
		for _, q := range pool.Profiles {
			if e.Profile == q.Profile && strings.HasPrefix(e.ProviderID, q.ProviderIDPrefix) && marketProviderSuffix.MatchString(strings.TrimPrefix(e.ProviderID, q.ProviderIDPrefix)) && e.PhysicalSpecSHA256 == q.PhysicalSpecSHA256 && e.RegistrationBindingSHA256 == q.RegistrationBindingSHA {
				qualified = true
			}
		}
		if !qualified {
			return fmt.Errorf("native phase registry profile is not source qualified")
		}
		admission := e.Admission
		if admission.State == "quarantined" {
			if admission.ReceiptSHA256 != "" || admission.NetworkBindingSHA256 != "" || admission.WarmupEvidenceSHA256 != "" || admission.PhysicalQualificationSHA256 != "" {
				return fmt.Errorf("quarantined native registry contains admission claims")
			}
		} else if admission.State != "admitted" || !ValidDigest(admission.ReceiptSHA256) || !ValidDigest(admission.NetworkBindingSHA256) || !ValidDigest(admission.WarmupEvidenceSHA256) || !ValidDigest(admission.PhysicalQualificationSHA256) {
			return fmt.Errorf("native registry admission facts are incomplete")
		}
		uids[e.NodeUID], ids[e.ProviderID] = true, true
		for _, floor := range pool.ProtectedNodes {
			if e.NodeUID == floor.NodeUID || e.ProviderID == floor.ProviderID {
				return fmt.Errorf("native phase registry contains a protected floor")
			}
		}
	}
	if !o.CandidateSelected && (o.RequestedProviderID != "" || o.RequestedCreationProofSHA256 != "" || o.CandidateAbsenceProven || len(o.Candidates) != 0) {
		return fmt.Errorf("header-only Native read cannot assert worker absence")
	}
	if o.CandidateSelected && (!ValidDigest(o.RequestedCreationProofSHA256) || o.RequestedProviderID == "" || len(o.Candidates) > 1 || o.CandidateAbsenceProven != (len(o.Candidates) == 0)) {
		return fmt.Errorf("native candidate selection and absence facts disagree")
	}
	return nil
}

func nativePhaseReadCandidate(p model.CapacityPolicySpec, provider, birth string, o model.CapacityNativeWorkerPhaseReadObservation, now time.Time) (model.CapacityNativeWorkerPhaseCandidate, error) {
	var empty model.CapacityNativeWorkerPhaseCandidate
	if NativeWorkerPhaseHeaderValid(p, o, now) != nil || !o.CandidateSelected || o.CandidateAbsenceProven || len(o.Candidates) != 1 || o.RequestedProviderID != provider || o.RequestedCreationProofSHA256 != birth || !ValidDigest(birth) {
		return empty, fmt.Errorf("one complete current Native candidate read required")
	}
	n := o.Candidates[0]
	if !marketUUID.MatchString(n.NodeUID) || !marketDNSLabel.MatchString(n.NodeName) || n.NodeResourceVersion == "" || n.ProviderID != provider || n.PoolUIDLabel != p.NativeWorkerPoolBinding.PoolUID || n.Deleting || n.Unschedulable {
		return empty, fmt.Errorf("exact eligible Native Node identity required")
	}
	for _, floor := range p.NativeWorkerPoolBinding.ProtectedNodes {
		if n.NodeUID == floor.NodeUID || n.ProviderID == floor.ProviderID {
			return empty, fmt.Errorf("protected floor is not a Native phase candidate")
		}
	}
	return n, nil
}

func nativePhaseOwnedQuarantine(p model.CapacityPolicySpec, n model.CapacityNativeWorkerPhaseCandidate) (bool, error) {
	found := false
	for _, t := range n.Taints {
		if t.Key != p.NativeWorkerLifecycleBinding.PhaseObserver.QuarantineTaintKey {
			continue
		}
		if found || t.Value != p.NativeWorkerPoolBinding.PoolUID || t.Effect != "NoSchedule" {
			return false, fmt.Errorf("ambiguous Native quarantine ownership")
		}
		found = true
	}
	return found, nil
}

func nativePhaseReady(p model.CapacityPolicySpec, profile string, n model.CapacityNativeWorkerPhaseCandidate, now time.Time) bool {
	if !n.Ready || !n.Heartbeat.Present || !n.Heartbeat.Fresh || !marketUUID.MatchString(n.Heartbeat.UID) || n.Heartbeat.ResourceVersion == "" || !fresh(n.Heartbeat.ObservedAt, now, p.NativeWorkerLifecycleBinding.PhaseObserver.MaxAgeSeconds) || !n.AllocatableKnown {
		return false
	}
	for _, q := range p.NativeWorkerPoolBinding.Profiles {
		if q.Profile == profile {
			return n.AllocatableMilliCPU >= q.MinAllocatableMilliCPU && n.AllocatableMemoryBytes >= q.MinAllocatableMemory
		}
	}
	return false
}

func nativePhaseEntryMatches(n model.CapacityNativeWorkerPhaseNode, e model.CapacityNativeWorkerRegistryEntry) bool {
	return n.UID == e.NodeUID && n.ProviderID == e.ProviderID && n.Profile == e.Profile && n.PhysicalSpecSHA256 == e.PhysicalSpecSHA256 && n.RegistrationBindingSHA256 == e.RegistrationBindingSHA256 && n.CapacityPolicyID == e.CapacityPolicyID && n.IntentGeneration == e.IntentGeneration && n.FencingToken == e.FencingToken && n.CreationProofSHA256 == e.CreationProofSHA256
}

func nativePhaseAdmission(e model.CapacityNativeWorkerRegistryAdmission) model.CapacityNativeWorkerPhaseAdmission {
	return model.CapacityNativeWorkerPhaseAdmission{ReceiptSHA256: e.ReceiptSHA256, NetworkBindingSHA256: e.NetworkBindingSHA256, WarmupEvidenceSHA256: e.WarmupEvidenceSHA256, PhysicalQualificationSHA256: e.PhysicalQualificationSHA256}
}

// The provider/birth selector is only an echo. Current Node, physical lifetime,
// overlay address and independent readiness must join the stored attempt.
func PrepareNativeWorkerPhaseFromRead(p model.CapacityPolicySpec, a model.CapacityNativeWorkerAttempt, action string, o model.CapacityNativeWorkerPhaseReadObservation, proof *model.CapacityNativeWorkerReadinessProof, now time.Time) (model.CapacityNativeWorkerPhasePreparation, error) {
	var out model.CapacityNativeWorkerPhasePreparation
	if a.Physical == nil || !NativeWorkerPhysicalValid(a, *a.Physical) || !ValidDigest(a.BirthSHA256) {
		return out, fmt.Errorf("qualified stored Native birth required")
	}
	n, err := nativePhaseReadCandidate(p, a.Physical.ProviderID, a.BirthSHA256, o, now)
	if err != nil {
		return out, err
	}
	quarantined, err := nativePhaseOwnedQuarantine(p, n)
	if err != nil || !quarantined || a.NodeUID != "" && a.NodeUID != n.NodeUID {
		return out, fmt.Errorf("same quarantined Native Node required")
	}
	addresses := 0
	for _, address := range n.Addresses {
		if address.Type != "InternalIP" {
			continue
		}
		ip, parseErr := netip.ParseAddr(address.Address)
		if parseErr != nil || ip.String() != address.Address {
			return out, fmt.Errorf("native Node InternalIP is not canonical")
		}
		if !ip.Is4() {
			continue
		}
		if address.Address != a.OverlayIPv4 {
			return out, fmt.Errorf("native Node has a conflicting internal IPv4 identity")
		}
		addresses++
	}
	if addresses != 1 {
		return out, fmt.Errorf("native Node must retain its allocated overlay address")
	}
	registration := ""
	for _, profile := range p.NativeWorkerPoolBinding.Profiles {
		if profile.Profile == a.Profile {
			registration = profile.RegistrationBindingSHA
		}
	}
	if !ValidDigest(registration) {
		return out, fmt.Errorf("native registration profile is not qualified")
	}
	for _, claim := range [][2]string{{n.ProfileLabel, a.Profile}, {n.PhysicalSpecSHA256Label, a.PhysicalSpecSHA256}, {n.RegistrationBindingSHA256Label, registration}, {n.PolicyIDLabel, a.PolicyID.String()}, {n.GenerationLabel, strconv.FormatInt(a.Generation, 10)}, {n.FencingTokenLabel, strconv.FormatInt(a.FencingToken, 10)}, {n.CreationProofSHA256Label, a.BirthSHA256}} {
		if claim[0] != "" && claim[0] != claim[1] {
			return out, fmt.Errorf("actual optional Native Node claim differs from its stored birth")
		}
	}
	c := model.CapacityNativeWorkerPhasePermit{Action: action, RealmNamespace: o.Registry.RealmNamespace, RealmUID: o.Registry.RealmUID, Registry: o.Registry.Ref, ExpectedRegistryResourceVersion: o.Registry.ResourceVersion, ExpectedRegistrySHA256: o.Registry.AnnotationSHA256, Node: model.CapacityNativeWorkerPhaseNode{Name: n.NodeName, UID: n.NodeUID, ResourceVersion: n.NodeResourceVersion, ProviderID: n.ProviderID, Profile: a.Profile, PhysicalSpecSHA256: a.PhysicalSpecSHA256, RegistrationBindingSHA256: registration, CapacityPolicyID: a.PolicyID.String(), IntentGeneration: a.Generation, FencingToken: a.FencingToken, CreationProofSHA256: a.BirthSHA256}}
	var existing *model.CapacityNativeWorkerRegistryEntry
	for _, entry := range o.Registrations {
		if entry.NodeUID == n.NodeUID || entry.ProviderID == n.ProviderID {
			if existing != nil || !nativePhaseEntryMatches(c.Node, entry) {
				return out, fmt.Errorf("native candidate registry identity conflicts")
			}
			copied := entry
			existing = &copied
		}
	}
	if action == "register" {
		if a.State != "acknowledged" || existing != nil {
			return out, fmt.Errorf("native registration cannot adopt an existing member")
		}
		return model.CapacityNativeWorkerPhasePreparation{Context: c, ObservedAt: o.ObservedAt}, nil
	}
	if action != "admit_registry" && action != "release_quarantine" || a.State != "registered" || existing == nil || proof == nil || !nativePhaseReady(p, a.Profile, n, now) {
		return out, fmt.Errorf("registered ready Native worker and independent readiness required")
	}
	if proof.AttemptID != a.ID || proof.NodeUID != n.NodeUID || proof.ProviderID != n.ProviderID || proof.WorkerIPv4 != a.OverlayIPv4 || proof.BirthSHA256 != a.BirthSHA256 || proof.Physical != *a.Physical || proof.NetworkBindingSHA256 != a.NetworkBindingSHA256 || proof.PhysicalQualificationSHA256 != a.QualificationEvidenceSHA256 || !ValidDigest(proof.NetworkEvidenceSHA256) || !ValidDigest(proof.WarmupEvidenceSHA256) || !fresh(proof.ObservedAt, now, p.NativeWorkerLifecycleBinding.PhaseObserver.MaxAgeSeconds) || !proof.ValidUntil.After(now) || !a.QualificationValidUntil.After(now) {
		return out, fmt.Errorf("fresh independent Native physical network and warmup evidence required")
	}
	c.Admission = model.CapacityNativeWorkerPhaseAdmission{NetworkBindingSHA256: proof.NetworkBindingSHA256, WarmupEvidenceSHA256: proof.WarmupEvidenceSHA256, PhysicalQualificationSHA256: proof.PhysicalQualificationSHA256}
	if action == "admit_registry" {
		if existing.Admission.State != "quarantined" {
			return out, fmt.Errorf("native registry admission must start quarantined")
		}
	} else {
		if existing.Admission.State != "admitted" || nativePhaseAdmission(existing.Admission).NetworkBindingSHA256 != c.Admission.NetworkBindingSHA256 || existing.Admission.WarmupEvidenceSHA256 != c.Admission.WarmupEvidenceSHA256 || existing.Admission.PhysicalQualificationSHA256 != c.Admission.PhysicalQualificationSHA256 || !ValidDigest(existing.Admission.ReceiptSHA256) {
			return out, fmt.Errorf("native quarantine release requires the same persisted admission")
		}
		c.Admission = nativePhaseAdmission(existing.Admission)
	}
	// Carry the existing evidence-age limits across the later SQL lock, too.
	// Issuing a permit cannot turn a fresh-at-read fact into a longer lease.
	readinessValidUntil := proof.ValidUntil
	maxAge := time.Duration(p.NativeWorkerLifecycleBinding.PhaseObserver.MaxAgeSeconds) * time.Second
	for _, observedAt := range []time.Time{proof.ObservedAt, o.ObservedAt, n.Heartbeat.ObservedAt} {
		if until := observedAt.Add(maxAge); until.Before(readinessValidUntil) {
			readinessValidUntil = until
		}
	}
	return model.CapacityNativeWorkerPhasePreparation{Context: c, ObservedAt: o.ObservedAt, ReadinessValidUntil: readinessValidUntil, NodeReady: true, NetworkVerified: true, WarmupVerified: true, PhysicalQualified: true}, nil
}

func ObserveNativeWorkerPhaseFromRead(p model.CapacityPolicySpec, c model.CapacityNativeWorkerPhasePermit, o model.CapacityNativeWorkerPhaseReadObservation, now time.Time) (model.CapacityNativeWorkerPhaseObservation, error) {
	var out model.CapacityNativeWorkerPhaseObservation
	if c.Action != "register" && c.Action != "admit_registry" && c.Action != "release_quarantine" {
		return out, fmt.Errorf("native phase action is not supported")
	}
	n, err := nativePhaseReadCandidate(p, c.Node.ProviderID, c.Node.CreationProofSHA256, o, now)
	if err != nil {
		return out, err
	}
	if n.NodeUID != c.Node.UID || n.NodeName != c.Node.Name || o.Registry.Ref != c.Registry || o.Registry.RealmUID != c.RealmUID || o.Registry.PoolUID != c.PoolUID || o.Registry.Owner != c.Owner || o.Registry.Epoch != c.Epoch {
		return out, fmt.Errorf("native observed scope differs from the one-CAS permission")
	}
	var entry *model.CapacityNativeWorkerRegistryEntry
	for _, e := range o.Registrations {
		if e.NodeUID == n.NodeUID || e.ProviderID == n.ProviderID {
			if entry != nil || !nativePhaseEntryMatches(c.Node, e) {
				return out, fmt.Errorf("native observed registry conflicts with the permitted birth")
			}
			copy := e
			entry = &copy
		}
	}
	if entry == nil {
		return out, fmt.Errorf("native permitted registration is not independently observed")
	}
	if c.Action != "register" && (entry.Admission.State != "admitted" || nativePhaseAdmission(entry.Admission) != c.Admission) {
		return out, fmt.Errorf("native observed admission differs from the permitted evidence")
	}
	quarantined, err := nativePhaseOwnedQuarantine(p, n)
	if err != nil {
		return out, err
	}
	ready := nativePhaseReady(p, c.Node.Profile, n, now)
	if c.Action == "release_quarantine" && (quarantined || !ready) {
		return out, fmt.Errorf("native quarantine release has not been independently observed")
	}
	return model.CapacityNativeWorkerPhaseObservation{RealmUID: o.Registry.RealmUID, PoolUID: o.Registry.PoolUID, Owner: o.Registry.Owner, Epoch: o.Registry.Epoch, ObservedAt: o.ObservedAt, Applied: true, NodeUID: n.NodeUID, RegistryUID: o.Registry.Ref.UID, RegistryResourceVersion: o.Registry.ResourceVersion, RegistrySHA256: o.Registry.AnnotationSHA256, ProviderID: n.ProviderID, AdmissionReceiptSHA256: entry.Admission.ReceiptSHA256, QuarantineAbsent: !quarantined, Ready: ready}, nil
}

// These callbacks are installed by protected process composition, never decoded
// from workflow input. Readiness resolves its own target from the stored birth,
// rather than receiving a caller-selected host or trusting Node label claims.
type NativeWorkerPhaseReadFunc func(context.Context, model.CapacityNativeWorkerPhaseReadBinding, string, string) (model.CapacityNativeWorkerPhaseReadObservation, error)
type NativeWorkerReadinessFunc func(context.Context, model.CapacityNativeWorkerAttempt) (*model.CapacityNativeWorkerReadinessProof, error)
type NativeWorkerPhaseReader struct {
	policy    model.CapacityPolicySpec
	read      NativeWorkerPhaseReadFunc
	readiness NativeWorkerReadinessFunc
}

func NewNativeWorkerPhaseReader(p model.CapacityPolicySpec, read NativeWorkerPhaseReadFunc, readiness NativeWorkerReadinessFunc) (*NativeWorkerPhaseReader, error) {
	if read == nil || ValidateNativeWorkerPhaseReadBinding(p) != nil || p.NativeWorkerLifecycleBinding == nil || p.NativeWorkerLifecycleBinding.PhaseObserver == nil {
		return nil, fmt.Errorf("protected Native phase reader is not configured")
	}
	// Retain no mutable policy pointers owned by the composition caller.
	raw, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	var own model.CapacityPolicySpec
	if json.Unmarshal(raw, &own) != nil {
		return nil, fmt.Errorf("native phase policy cannot be copied")
	}
	return &NativeWorkerPhaseReader{policy: own, read: read, readiness: readiness}, nil
}

func (r *NativeWorkerPhaseReader) ObservePhaseAuthority(ctx context.Context, _ model.Manifest) (*model.CapacityNativeWorkerPhaseReadObservation, error) {
	if r == nil || r.read == nil {
		return nil, fmt.Errorf("native phase reader is not installed")
	}
	out, err := r.read(ctx, *r.policy.NativeWorkerLifecycleBinding.PhaseObserver, "", "")
	if err != nil {
		return nil, err
	}
	if NativeWorkerPhaseHeaderValid(r.policy, out, time.Now().UTC()) != nil || out.CandidateSelected {
		return nil, fmt.Errorf("native phase authority must be an exact header-only read")
	}
	return &out, nil
}

func (r *NativeWorkerPhaseReader) PreparePhase(ctx context.Context, a model.CapacityNativeWorkerAttempt, action string) (model.CapacityNativeWorkerPhasePreparation, error) {
	var empty model.CapacityNativeWorkerPhasePreparation
	if r == nil || r.read == nil {
		return empty, fmt.Errorf("native phase reader is not installed")
	}
	if a.Physical == nil {
		return empty, fmt.Errorf("native phase preparation requires its stored physical birth")
	}
	out, err := r.read(ctx, *r.policy.NativeWorkerLifecycleBinding.PhaseObserver, a.Physical.ProviderID, a.BirthSHA256)
	if err != nil {
		return empty, err
	}
	if _, err = nativePhaseReadCandidate(r.policy, a.Physical.ProviderID, a.BirthSHA256, out, time.Now().UTC()); err != nil {
		return empty, err
	}
	var proof *model.CapacityNativeWorkerReadinessProof
	if action != "register" {
		if r.readiness == nil {
			return empty, fmt.Errorf("independent Native network and warmup reader is not installed")
		}
		proof, err = r.readiness(ctx, a)
		if err != nil {
			return empty, err
		}
	}
	return PrepareNativeWorkerPhaseFromRead(r.policy, a, action, out, proof, time.Now().UTC())
}

func (r *NativeWorkerPhaseReader) ObservePhase(ctx context.Context, c model.CapacityNativeWorkerPhasePermit) (model.CapacityNativeWorkerPhaseObservation, error) {
	if r == nil || r.read == nil {
		return model.CapacityNativeWorkerPhaseObservation{}, fmt.Errorf("native phase reader is not installed")
	}
	out, err := r.read(ctx, *r.policy.NativeWorkerLifecycleBinding.PhaseObserver, c.Node.ProviderID, c.Node.CreationProofSHA256)
	if err != nil {
		return model.CapacityNativeWorkerPhaseObservation{}, err
	}
	return ObserveNativeWorkerPhaseFromRead(r.policy, c, out, time.Now().UTC())
}
