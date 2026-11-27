package capacity

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"reflect"
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
			len(v.ExcludedIPv4) == 0 || len(v.ExcludedIPv4) > 64 {
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
	return ValidateNativeWorkerRegistryWriterBinding(p)
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
		(a.Physical != nil && *a.Physical != o.IndependentCurrent) || o.OriginalRequestID == "" || o.IndependentRequestID == "" {
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
