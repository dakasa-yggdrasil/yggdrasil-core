package capacity

import (
	"bytes"
	"context"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

func nativeHCloudScopeValid(s *model.CapacityNativeWorkerHCloudProjectScope) bool {
	return s != nil && marketID.MatchString(s.DeclaredProjectID) && s.ProofKind == "reviewed_token_and_network_anchor_v1" &&
		nativeHCloudID(s.AnchorID) && !s.AnchorCreated.IsZero() && s.AnchorOwnerLabelKey != "" && len(s.AnchorOwnerLabelKey) <= 255 &&
		s.AnchorOwnerLabelValue != "" && len(s.AnchorOwnerLabelValue) <= 255 &&
		!strings.ContainsAny(s.AnchorOwnerLabelKey+s.AnchorOwnerLabelValue, "\r\n\t")
}

func nativeHCloudSameScope(a, b model.CapacityNativeWorkerHCloudProjectScope) bool {
	return a.DeclaredProjectID == b.DeclaredProjectID && a.ProofKind == b.ProofKind && a.AnchorID == b.AnchorID &&
		a.AnchorCreated.Equal(b.AnchorCreated) && a.AnchorOwnerLabelKey == b.AnchorOwnerLabelKey && a.AnchorOwnerLabelValue == b.AnchorOwnerLabelValue
}

func nativeHCloudLaunchLabel(digest string) string {
	if !ValidDigest(digest) {
		return ""
	}
	b, err := hex.DecodeString(digest)
	if err != nil {
		return ""
	}
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b))
}

func nativeHCloudReadBindingValid(a model.CapacityNativeWorkerAttempt, b model.CapacityNativeWorkerPhysicalReadBinding) bool {
	return a.Provider == "hetzner" && b.Provider == "hetzner" && b.Profile == a.Profile && b.Region == a.Region &&
		marketAdapterValid(b.Adapter) && b.Adapter.ManifestID != a.Execution.Adapter.ManifestID &&
		marketID.MatchString(b.BindingName) && marketCommit.MatchString(b.SourceCommit) && ValidDigest(b.ScopeSHA256) &&
		b.Capability == ObserveNativeWorkerPhysical && nativeHCloudScopeValid(b.HCloudScope)
}

func cloneHCloudReadBinding(b model.CapacityNativeWorkerPhysicalReadBinding) model.CapacityNativeWorkerPhysicalReadBinding {
	if b.HCloudScope != nil {
		scope := *b.HCloudScope
		b.HCloudScope = &scope
	}
	return b
}

func nativeHCloudFactsValid(a model.CapacityNativeWorkerAttempt, f model.CapacityNativeWorkerHCloudPhysicalFacts) bool {
	prefix, err := netip.ParsePrefix(f.NativeNetworkCIDR)
	ip, ipErr := netip.ParseAddr(f.NativeIPv4)
	return a.Provider == "hetzner" && a.ProviderIDPrefix == "hcloud://" && nativeHCloudSystemID(f.ResourceID) &&
		f.ResourceID != "174243510" && f.ProviderID == "hcloud://"+f.ResourceID && f.AccountID == "" &&
		marketID.MatchString(f.InstanceType) && nativeHCloudID(f.NetworkID) && nativeHCloudSystemID(f.ImageID) &&
		f.Region == a.Region && f.Zone == f.Region && slices.Contains([]string{"hel1", "fsn1", "nbg1"}, f.Zone) && f.NetworkZone == "eu-central" &&
		!a.CreatedAt.IsZero() && !f.CreatedAt.IsZero() && !f.CreatedAt.Before(a.CreatedAt.Add(-5*time.Second)) &&
		f.PhysicalSpecSHA256 == a.PhysicalSpecSHA256 && ValidDigest(f.PhysicalSpecSHA256) && f.LaunchSHA256 == a.LaunchSHA256 &&
		err == nil && prefix == prefix.Masked() && prefix.String() == f.NativeNetworkCIDR && prefix.Addr().Is4() && prefix.Addr().IsPrivate() &&
		prefix.Bits() >= 8 && prefix.Bits() <= 29 && ipErr == nil && ip.Is4() && ip.IsPrivate() && ip.String() == f.NativeIPv4 &&
		prefix.Contains(ip) && ip != prefix.Addr() && nativeHCloudMAC(f.MACAddress)
}

func nativeHCloudAcceptanceJoins(a model.CapacityNativeWorkerAttempt, ack model.CapacityNativeWorkerHCloudAcceptance, o model.CapacityNativeWorkerHCloudPhysicalObservation) bool {
	f := o.Physical
	want := model.CapacityNativeWorkerHCloudObservedLabels{AttemptID: a.ID.String(), PoolUID: a.PoolUID, LaunchSHA256Base32: nativeHCloudLaunchLabel(a.LaunchSHA256)}
	return want.LaunchSHA256Base32 != "" && ack.Labels == want && o.ActualLabels == want && o.ActualLaunchSHA256 == a.LaunchSHA256 &&
		ack.ResourceID == f.ResourceID && ack.ServerName == "nw-"+strings.ReplaceAll(a.ID.String(), "-", "") && o.ServerName == ack.ServerName &&
		ack.CreatedAt.Equal(f.CreatedAt) && nativeHCloudID(ack.ServerTypeID) && ack.InstanceType == f.InstanceType &&
		ack.ImageID == f.ImageID && nativeHCloudID(ack.LocationID) && ack.Location == f.Region && ack.NetworkZone == f.NetworkZone &&
		nativeHCloudID(ack.ActionID) && ack.ActionCommand == "create_server" && (ack.ActionStatus == "running" || ack.ActionStatus == "success") &&
		nativeHCloudRequestID(ack.RequestID, ack.RequestIDObserved) &&
		(ack.NetworkID == "" || ack.NetworkID == f.NetworkID) && (ack.NativeIPv4 == "" || ack.NativeIPv4 == f.NativeIPv4) &&
		(ack.MACAddress == "" || ack.MACAddress == f.MACAddress) &&
		(ack.NetworkID != "" || ack.NativeIPv4 == "" && ack.MACAddress == "")
}

func nativeHCloudReadValid(a model.CapacityNativeWorkerAttempt, ack model.CapacityNativeWorkerHCloudAcceptance, o model.CapacityNativeWorkerHCloudPhysicalObservation, b model.CapacityNativeWorkerPhysicalReadBinding, maxAge int, now time.Time) bool {
	if !nativeHCloudReadBindingValid(a, b) || maxAge < 1 || maxAge > 300 ||
		o.Schema != "hcloud_native_worker_physical_observation_v1" || o.SourceCommit != b.SourceCommit || o.Adapter != b.Adapter ||
		o.BindingName != b.BindingName || o.BindingScopeSHA256 != b.ScopeSHA256 ||
		o.Requested != (model.CapacityNativeWorkerObservationRequest{BindingName: b.BindingName, AttemptID: a.ID.String(), ResourceID: ack.ResourceID, LaunchSHA256: a.LaunchSHA256}) ||
		!o.Complete || o.MutationAuthorized || o.NodeReadyQualified || o.UsefulCapacityQualified || o.AbsenceProven ||
		o.ObservedAt.After(now) || !fresh(o.ObservedAt, now, maxAge) || o.StartedAt.IsZero() || o.StartedAt.After(o.ObservedAt) ||
		o.StartedAt.Before(now.Add(-time.Duration(maxAge)*time.Second)) || o.ProjectScope.AnchorCreated.After(o.StartedAt) ||
		!nativeHCloudSameScope(o.ProjectScope, *b.HCloudScope) || !nativeHCloudFactsValid(a, o.Physical) ||
		o.Physical.CreatedAt.After(o.StartedAt) || !nativeHCloudAcceptanceJoins(a, ack, o) ||
		!slices.Contains([]string{"initializing", "starting", "running", "stopping", "off", "deleting", "rebuilding", "migrating"}, o.InstanceState) ||
		o.RootStorage.Kind != "server_local" || o.RootStorage.SizeGiB < 1 || o.RootStorage.ProviderEncryptionProven ||
		len(o.FirewallIDs) < 1 || len(o.FirewallIDs) > 5 || !slices.IsSorted(o.FirewallIDs) || o.PrimaryIPs == nil || len(o.PrimaryIPs) > 2 {
		return false
	}
	digest := o.EvidenceSHA256
	o.EvidenceSHA256 = ""
	raw, err := json.Marshal(o)
	if err != nil || !ValidDigest(digest) || nativePrivateSHA(raw) != digest {
		return false
	}
	lastFirewall := ""
	for _, id := range o.FirewallIDs {
		if !nativeHCloudID(id) || id == lastFirewall {
			return false
		}
		lastFirewall = id
	}
	kinds, ids := map[string]bool{}, map[string]bool{}
	ipv4 := ""
	for _, ip := range o.PrimaryIPs {
		if !nativeHCloudID(ip.ResourceID) || ids[ip.ResourceID] || kinds[ip.Type] || ip.AssigneeID != o.Physical.ResourceID {
			return false
		}
		ids[ip.ResourceID], kinds[ip.Type] = true, true
		switch ip.Type {
		case "ipv4":
			if ip.IP == "" || !nativePhysicalTransportEndpoint(ip.IP) {
				return false
			}
			ipv4 = ip.IP
		case "ipv6":
			p, err := netip.ParsePrefix(ip.IP)
			if err != nil || !p.Addr().Is6() || !p.Addr().IsGlobalUnicast() || p.Addr().IsPrivate() || p != p.Masked() || p.String() != ip.IP {
				return false
			}
		default:
			return false
		}
	}
	if o.TransportEndpointIPv4 != ipv4 {
		return false // A native/private address cannot replace a missing public fact.
	}
	operations := []string{"GET /networks/{id}", "GET /servers/{id}", "GET /networks/{id}"}
	for range o.FirewallIDs {
		operations = append(operations, "GET /firewalls/{id}")
	}
	for range o.PrimaryIPs {
		operations = append(operations, "GET /primary_ips/{id}")
	}
	operations = append(operations, "GET /servers/{id}", "GET /networks/{id}")
	if len(o.Reads) != len(operations) {
		return false
	}
	previous := o.StartedAt
	for i, read := range o.Reads {
		if read.Operation != operations[i] || read.HTTPStatus != 200 || !nativeHCloudRequestID(read.RequestID, read.RequestIDObserved) ||
			read.ObservedAt.Before(previous) || read.ObservedAt.After(o.ObservedAt) {
			return false
		}
		previous = read.ObservedAt
	}
	return true
}

func materializeNativeHCloudPhysical(a model.CapacityNativeWorkerAttempt, raw []byte, f model.CapacityNativeWorkerHCloudPhysicalFacts) (model.CapacityNativeWorkerPhysical, error) {
	l, err := decodeNativePhysicalLaunch(a, raw)
	if err != nil {
		return model.CapacityNativeWorkerPhysical{}, err
	}
	if !nativeHCloudFactsValid(a, f) || l.Provider.Kind != "hetzner" || l.Provider.AccountID != "" || l.Provider.Region != f.NetworkZone ||
		l.Provider.Zone != f.Zone || l.Provider.ImageID != f.ImageID || l.Provider.NativeNetworkCIDR != f.NativeNetworkCIDR ||
		f.ProviderID == l.Floor.ProviderID {
		return model.CapacityNativeWorkerPhysical{}, errNativePhysical
	}
	provider := nativePhysicalProvider{"hetzner", f.ResourceID, f.ProviderID, "", f.NetworkZone, f.Zone, f.ImageID, f.NativeIPv4, f.NativeNetworkCIDR}
	binding := nativePhysicalBinding{l.Schema, l.Mode, l.SourceCommit, l.PoolID, l.PoolUID, l.Registry, l.PolicyID, l.PolicySHA256, l.ExpectedPoolEpoch, l.IntentGeneration, l.FencingToken, l.ReservationID, l.IntentSHA256, a.LaunchSHA256, provider, l.Floor, l.Network, l.Operator, l.Reserve}
	wire, err := json.Marshal(binding)
	if err != nil {
		return model.CapacityNativeWorkerPhysical{}, errNativePhysical
	}
	out := model.CapacityNativeWorkerPhysical{ResourceID: f.ResourceID, ProviderID: f.ProviderID, AccountID: "", InstanceType: f.InstanceType, NetworkID: f.NetworkID,
		CreatedAt: f.CreatedAt, ImageID: f.ImageID, Region: f.Region, Zone: f.Zone, NativeIPv4: f.NativeIPv4, MACAddress: f.MACAddress,
		PhysicalSpecSHA256: f.PhysicalSpecSHA256, PhysicalBindingSHA256: nativePrivateSHA(wire), LaunchSHA256: f.LaunchSHA256}
	if !nativeWorkerPhysicalIdentityValid(a, out) {
		return model.CapacityNativeWorkerPhysical{}, errNativePhysical
	}
	return out, nil
}

// This validation is historical: a sealed birth does not expire when its
// original read ages. New current decisions still need their own fresh read.
func NativeWorkerHCloudWitnessValid(a model.CapacityNativeWorkerAttempt, p model.CapacityNativeWorkerPhysical, w *model.CapacityNativeWorkerHCloudWitness) bool {
	if w == nil || a.Provider != "hetzner" || a.ID == uuid.Nil || a.PolicyID == uuid.Nil || !marketUUID.MatchString(a.PoolUID) || a.PoolEpoch < 1 || a.Generation < 1 || a.FencingToken < 1 || !marketCommit.MatchString(a.SourceCommit) || w.Schema != nativeHCloudWitnessSchema || w.CoreSourceCommit != a.SourceCommit ||
		w.AttemptID != a.ID.String() || w.PolicyID != a.PolicyID.String() || w.PoolUID != a.PoolUID || w.PoolEpoch != a.PoolEpoch ||
		w.IntentGeneration != a.Generation || w.FencingToken != a.FencingToken || w.LaunchSHA256 != a.LaunchSHA256 ||
		!nativeWorkerPhysicalIdentityValid(a, p) || p.AccountID != "" || !nativeHCloudReadValid(a, w.Acceptance, w.Observation, w.Reader, w.MaxReadAgeSeconds, w.Observation.ObservedAt) {
		return false
	}
	f := w.Observation.Physical
	if p.ResourceID != f.ResourceID || p.ProviderID != f.ProviderID || p.InstanceType != f.InstanceType || p.NetworkID != f.NetworkID ||
		!p.CreatedAt.Equal(f.CreatedAt) || p.ImageID != f.ImageID || p.Region != f.Region || p.Zone != f.Zone || p.NativeIPv4 != f.NativeIPv4 ||
		p.MACAddress != f.MACAddress || p.PhysicalSpecSHA256 != f.PhysicalSpecSHA256 || p.LaunchSHA256 != f.LaunchSHA256 {
		return false
	}
	physical, err := json.Marshal(p)
	if err != nil || w.PhysicalIdentitySHA256 != nativePrivateSHA(physical) {
		return false
	}
	copy := *w
	copy.EvidenceSHA256 = ""
	wire, err := json.Marshal(copy)
	return err == nil && ValidDigest(w.EvidenceSHA256) && nativePrivateSHA(wire) == w.EvidenceSHA256
}

func CloneNativeWorkerHCloudWitness(w *model.CapacityNativeWorkerHCloudWitness) *model.CapacityNativeWorkerHCloudWitness {
	if w == nil {
		return nil
	}
	wire, err := json.Marshal(w)
	var out model.CapacityNativeWorkerHCloudWitness
	if err != nil || len(wire) > 2<<20 || DecodeNativeCapacity(json.RawMessage(wire), &out) != nil {
		return nil
	}
	return &out
}

func nativeHCloudObservationAttempt(a model.CapacityNativeWorkerAttempt, o model.CapacityNativeWorkerObservation, maxAge int) (model.CapacityNativeWorkerAttempt, bool) {
	w := o.HCloudWitness
	if !NativeWorkerHCloudWitnessValid(a, o.IndependentCurrent, w) || o.OriginalRequestID != w.Acceptance.RequestID ||
		o.IndependentRequestID != w.Observation.Reads[len(w.Observation.Reads)-1].RequestID ||
		(a.HCloudWitness == nil && (o.State != "acknowledged" || !o.ObservedAt.Equal(w.Observation.ObservedAt))) ||
		(a.HCloudWitness != nil && (a.Physical == nil || !ValidDigest(a.BirthSHA256))) ||
		(a.HCloudWitness == nil && w.MaxReadAgeSeconds != maxAge) ||
		(a.HCloudWitness != nil && a.HCloudWitness.EvidenceSHA256 != w.EvidenceSHA256) {
		return a, false
	}
	a.HCloudWitness = CloneNativeWorkerHCloudWitness(w)
	return a, a.HCloudWitness != nil
}

// The receiving store checks the immutable policy pin again, independently
// of the protected runtime's qualifier. A witness cannot choose its reader.
func NativeWorkerHCloudWitnessBindingValid(p model.CapacityPolicySpec, a model.CapacityNativeWorkerAttempt, w *model.CapacityNativeWorkerHCloudWitness) bool {
	if a.Provider != "hetzner" {
		return w == nil
	}
	if w == nil || p.NativeWorkerLifecycleBinding == nil || p.NativeWorkerLifecycleBinding.SourceCommit != a.SourceCommit || ValidateNativeWorkerPhysicalObservers(p) != nil {
		return false
	}
	for _, binding := range p.NativeWorkerLifecycleBinding.PhysicalObservers {
		if binding.Profile != a.Profile || !nativeHCloudReadBindingValid(a, binding) || w.Reader.HCloudScope == nil {
			continue
		}
		left, right := binding, w.Reader
		left.HCloudScope, right.HCloudScope = nil, nil
		return left == right && nativeHCloudSameScope(*binding.HCloudScope, *w.Reader.HCloudScope)
	}
	return false
}

func nativeHCloudWitness(a model.CapacityNativeWorkerAttempt, p model.CapacityNativeWorkerPhysical, ack model.CapacityNativeWorkerHCloudAcceptance, o model.CapacityNativeWorkerHCloudPhysicalObservation, b model.CapacityNativeWorkerPhysicalReadBinding, maxAge int) *model.CapacityNativeWorkerHCloudWitness {
	physical, err := json.Marshal(p)
	if err != nil {
		return nil
	}
	out := model.CapacityNativeWorkerHCloudWitness{Schema: nativeHCloudWitnessSchema, CoreSourceCommit: a.SourceCommit,
		AttemptID: a.ID.String(), PolicyID: a.PolicyID.String(), PoolUID: a.PoolUID, PoolEpoch: a.PoolEpoch, IntentGeneration: a.Generation,
		FencingToken: a.FencingToken, LaunchSHA256: a.LaunchSHA256, PhysicalIdentitySHA256: nativePrivateSHA(physical),
		MaxReadAgeSeconds: maxAge, Acceptance: ack, Reader: b, Observation: o}
	wire, err := json.Marshal(out)
	if err != nil {
		return nil
	}
	out.EvidenceSHA256 = nativePrivateSHA(wire)
	return CloneNativeWorkerHCloudWitness(&out)
}

func nativeHCloudStateValid(a model.CapacityNativeWorkerAttempt, sealed bool) bool {
	if !sealed {
		return a.State == "send_started" || a.State == "unknown"
	}
	return a.Physical != nil && ValidDigest(a.BirthSHA256) && NativeWorkerHCloudWitnessValid(a, *a.Physical, a.HCloudWitness) &&
		slices.Contains([]string{"acknowledged", "registered", "admitted", "draining", "aborting"}, a.State)
}

func pureNativeHCloudPhysicalQualify(a model.CapacityNativeWorkerAttempt, launch []byte, original model.CapacityNativeWorkerOriginalReturn, carrier model.CapacityNativeWorkerPhysicalObservation, b model.CapacityNativeWorkerPhysicalReadBinding, maxAge int, now time.Time, sealed bool) (model.CapacityNativeWorkerObservation, error) {
	var out model.CapacityNativeWorkerObservation
	if !nativeHCloudStateValid(a, sealed) || carrier.HCloud == nil || !nativeHCloudReadBindingValid(a, b) {
		return out, errNativePhysical
	}
	aws := carrier
	aws.HCloud = nil
	if !reflect.DeepEqual(aws, model.CapacityNativeWorkerPhysicalObservation{}) {
		return out, errNativePhysical
	}
	ack, err := decodeNativeHCloudAcceptance(a, original)
	if err != nil {
		return out, err
	}
	o := *carrier.HCloud
	if !nativeHCloudReadValid(a, ack, o, b, maxAge, now) {
		return out, errNativePhysical
	}
	p, err := materializeNativeHCloudPhysical(a, launch, o.Physical)
	if err != nil {
		return out, err
	}
	if sealed {
		prior, _ := json.Marshal(a.HCloudWitness.Acceptance)
		current, _ := json.Marshal(ack)
		if p != *a.Physical || !bytes.Equal(prior, current) {
			return out, errNativePhysical
		}
		// A fresh GET is not a second original acceptance or a new birth.
		return model.CapacityNativeWorkerObservation{State: a.State, IndependentCurrent: p, HCloudWitness: CloneNativeWorkerHCloudWitness(a.HCloudWitness)}, nil
	}
	witness := nativeHCloudWitness(a, p, ack, o, b, maxAge)
	last := o.Reads[len(o.Reads)-1]
	out = model.CapacityNativeWorkerObservation{State: "acknowledged", ExecutionScopeSHA256: a.Execution.ScopeSHA256, ObservedAt: o.ObservedAt,
		OriginalReturnSHA256: nativePrivateSHA(original.Wire), OriginalAcceptance: p, IndependentCurrent: p,
		OriginalRequestID: ack.RequestID, IndependentRequestID: last.RequestID, HCloudWitness: witness}
	if NativeWorkerObservationValid(a, out, now, maxAge) != nil {
		return model.CapacityNativeWorkerObservation{}, errNativePhysical
	}
	return out, nil
}

func (q *NativeWorkerACKQualifier) qualifyHCloud(ctx context.Context, a model.CapacityNativeWorkerAttempt, launch []byte, original model.CapacityNativeWorkerOriginalReturn, sealed bool) (model.CapacityNativeWorkerObservation, error) {
	b, ok := q.bindings[a.Profile]
	b = cloneHCloudReadBinding(b)
	if !ok || !nativeHCloudReadBindingValid(a, b) || !nativeHCloudStateValid(a, sealed) {
		return model.CapacityNativeWorkerObservation{}, errNativePhysical
	}
	if _, err := decodeNativePhysicalLaunch(a, launch); err != nil {
		return model.CapacityNativeWorkerObservation{}, errNativePhysical
	}
	ack, err := decodeNativeHCloudAcceptance(a, original)
	if err != nil {
		return model.CapacityNativeWorkerObservation{}, err
	}
	request := model.CapacityNativeWorkerObservationRequest{BindingName: b.BindingName, AttemptID: a.ID.String(), ResourceID: ack.ResourceID, LaunchSHA256: a.LaunchSHA256}
	actual, err := q.read(ctx, cloneHCloudReadBinding(b), request)
	if err != nil || ctx.Err() != nil {
		return model.CapacityNativeWorkerObservation{}, errNativePhysical
	}
	return pureNativeHCloudPhysicalQualify(a, launch, original, actual, b, q.maxAge, time.Now().UTC(), sealed)
}
