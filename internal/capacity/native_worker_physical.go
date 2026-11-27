package capacity

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

const ObserveNativeWorkerPhysical = "observe_native_worker"

var errNativePhysical = errors.New("HOLD: original Native creation and independent physical identity are unqualified")

// Only protected process composition installs this port. The request's four
// selectors are derived from the archived attempt and original provider ACK.
type NativeWorkerPhysicalReadFunc func(context.Context, model.CapacityNativeWorkerPhysicalReadBinding, model.CapacityNativeWorkerObservationRequest) (model.CapacityNativeWorkerPhysicalObservation, error)

// NativeWorkerACKQualifier copies only Source-owned policy bindings. It has no
// workflow input, provider client, creation port, credentials or process gate.
type NativeWorkerACKQualifier struct {
	read     NativeWorkerPhysicalReadFunc
	source   string
	maxAge   int
	bindings map[string]model.CapacityNativeWorkerPhysicalReadBinding
}

func NewNativeWorkerACKQualifier(p model.CapacityPolicySpec, read NativeWorkerPhysicalReadFunc) (*NativeWorkerACKQualifier, error) {
	if read == nil || p.NativeWorkerLifecycleBinding == nil || len(p.NativeWorkerLifecycleBinding.PhysicalObservers) == 0 || ValidateNativeWorkerPhysicalObservers(p) != nil || !marketCommit.MatchString(p.NativeWorkerLifecycleBinding.SourceCommit) || p.NativeWorkerLifecycleBinding.MaxReadAgeSeconds < 1 || p.NativeWorkerLifecycleBinding.MaxReadAgeSeconds > 300 {
		return nil, errNativePhysical
	}
	q := &NativeWorkerACKQualifier{read: read, source: p.NativeWorkerLifecycleBinding.SourceCommit, maxAge: p.NativeWorkerLifecycleBinding.MaxReadAgeSeconds, bindings: map[string]model.CapacityNativeWorkerPhysicalReadBinding{}}
	for _, b := range p.NativeWorkerLifecycleBinding.PhysicalObservers {
		q.bindings[b.Profile] = b
	}
	return q, nil
}

func ValidateNativeWorkerPhysicalObservers(p model.CapacityPolicySpec) error {
	b := p.NativeWorkerLifecycleBinding
	if b == nil || len(b.PhysicalObservers) == 0 {
		return nil // The pre-existing absent wire and policy remain unchanged.
	}
	if len(b.PhysicalObservers) != len(b.Profiles) {
		return errNativePhysical
	}
	seen := map[string]bool{}
	for _, v := range b.PhysicalObservers {
		matched := false
		for _, e := range b.Profiles {
			if v.Adapter.ManifestID == e.Adapter.ManifestID {
				return errNativePhysical
			}
			if e.Profile == v.Profile {
				matched = true
			}
		}
		if b.RegistryWriter != nil && v.Adapter.ManifestID == b.RegistryWriter.Adapter.ManifestID {
			return errNativePhysical
		}
		profile := false
		for _, x := range p.Profiles {
			if x.Name == v.Profile && x.Provider == v.Provider && x.Region == v.Region {
				profile = true
			}
		}
		if p.MarketBinding == nil {
			return errNativePhysical
		}
		for _, m := range p.MarketBinding.Profiles {
			if m.Adapter.ManifestID == v.Adapter.ManifestID {
				return errNativePhysical
			}
		}
		if !matched || !profile || seen[v.Profile] || !marketAdapterValid(v.Adapter) || !marketID.MatchString(v.BindingName) || !marketCommit.MatchString(v.SourceCommit) || !marketSHA.MatchString(v.ScopeSHA256) || v.Capability != ObserveNativeWorkerPhysical {
			return errNativePhysical
		}
		seen[v.Profile] = true
	}
	return nil
}

// QualifyACK never discovers candidates, sends creation, or qualifies a Node.
// A failed/pending original stays unknown/charged through the existing store.
func (q *NativeWorkerACKQualifier) QualifyACK(ctx context.Context, a model.CapacityNativeWorkerAttempt, storedLaunch []byte, original model.CapacityNativeWorkerOriginalReturn) (model.CapacityNativeWorkerObservation, error) {
	return q.qualify(ctx, a, storedLaunch, original, false)
}

// ReobserveACK performs the same independent physical read for an already
// sealed birth. It preserves the actual Attempt state and returns no lifecycle
// transition, permit, Node readiness, admission or useful-capacity assertion.
func (q *NativeWorkerACKQualifier) ReobserveACK(ctx context.Context, a model.CapacityNativeWorkerAttempt, storedLaunch []byte, original model.CapacityNativeWorkerOriginalReturn) (model.CapacityNativeWorkerPhysical, error) {
	out, err := q.qualify(ctx, a, storedLaunch, original, true)
	if err != nil {
		return model.CapacityNativeWorkerPhysical{}, err
	}
	return out.IndependentCurrent, nil
}

func nativePhysicalStateValid(a model.CapacityNativeWorkerAttempt, sealed bool) bool {
	if !sealed {
		return a.State == "send_started" || a.State == "unknown"
	}
	if a.Physical == nil || !ValidDigest(a.BirthSHA256) {
		return false
	}
	switch a.State {
	case "acknowledged", "registered", "admitted", "draining":
		return true
	default:
		return false
	}
}

func (q *NativeWorkerACKQualifier) qualify(ctx context.Context, a model.CapacityNativeWorkerAttempt, storedLaunch []byte, original model.CapacityNativeWorkerOriginalReturn, sealed bool) (model.CapacityNativeWorkerObservation, error) {
	if q == nil || q.read == nil || ctx == nil || ctx.Err() != nil || a.Provider != "aws" || a.SourceCommit != q.source || !nativePhysicalStateValid(a, sealed) {
		return model.CapacityNativeWorkerObservation{}, errNativePhysical
	}
	b, exists := q.bindings[a.Profile]
	if !exists || b.Provider != a.Provider || b.Region != a.Region {
		return model.CapacityNativeWorkerObservation{}, errNativePhysical
	}
	if _, err := decodeNativePhysicalLaunch(a, storedLaunch); err != nil {
		return model.CapacityNativeWorkerObservation{}, err
	}
	ack, err := decodeNativeAWSAcceptance(a, original)
	if err != nil {
		return model.CapacityNativeWorkerObservation{}, err
	}
	request := model.CapacityNativeWorkerObservationRequest{BindingName: b.BindingName, AttemptID: a.ID.String(), ResourceID: ack.resourceID, LaunchSHA256: a.LaunchSHA256}
	actual, err := q.read(ctx, b, request)
	if err != nil || ctx.Err() != nil {
		return model.CapacityNativeWorkerObservation{}, errNativePhysical
	}
	return pureNativePhysicalQualify(a, storedLaunch, original, actual, b, q.maxAge, time.Now().UTC(), sealed)
}

// This mirror retains System nativeworker.Binding's exact field order. The
// complete persisted Launch is copied, and only independently real provider
// identity is materialized. No label, bootstrap receipt or claimed digest is
// accepted as PhysicalBindingSHA256.
type nativePhysicalProvider struct {
	Kind              string `json:"kind"`
	InstanceID        string `json:"instance_id"`
	ProviderID        string `json:"provider_id"`
	AccountID         string `json:"account_id"`
	Region            string `json:"region"`
	Zone              string `json:"zone"`
	ImageID           string `json:"image_id"`
	NativeIPv4        string `json:"native_ipv4"`
	NativeNetworkCIDR string `json:"native_network_cidr"`
}
type nativePhysicalBinding struct {
	Schema            int                    `json:"schema"`
	Mode              string                 `json:"mode"`
	SourceCommit      string                 `json:"source_commit"`
	PoolID            string                 `json:"pool_id"`
	PoolUID           string                 `json:"pool_uid"`
	Registry          nativePrivateRegistry  `json:"registry"`
	PolicyID          string                 `json:"policy_id"`
	PolicySHA256      string                 `json:"policy_sha256"`
	ExpectedPoolEpoch int64                  `json:"expected_pool_epoch"`
	IntentGeneration  int64                  `json:"intent_generation"`
	FencingToken      int64                  `json:"fencing_token"`
	ReservationID     string                 `json:"reservation_id"`
	IntentSHA256      string                 `json:"intent_sha256"`
	LaunchSHA256      string                 `json:"launch_sha256"`
	Provider          nativePhysicalProvider `json:"provider"`
	Floor             nativePrivateFloor     `json:"floor"`
	Network           nativePrivateNetwork   `json:"network"`
	Operator          nativePrivateOperator  `json:"operator"`
	Reserve           nativePrivateReserve   `json:"reserve"`
}

func decodeNativePhysicalLaunch(a model.CapacityNativeWorkerAttempt, raw []byte) (nativePrivateLaunch, error) {
	var l nativePrivateLaunch
	if len(raw) == 0 || len(raw) > 32768 || DecodeNativeCapacity(json.RawMessage(raw), &l) != nil {
		return l, errNativePhysical
	}
	canonical, _ := json.Marshal(l)
	if validateNativePhysicalSystemContext(l) != nil || !bytes.Equal(canonical, raw) || nativePrivateSHA(raw) != a.LaunchSHA256 || ValidateNativeWorkerLaunch(a, model.CapacityNativeWorkerLaunch{AttemptID: a.ID, PoolUID: a.PoolUID, PoolEpoch: a.PoolEpoch, Generation: a.Generation, FencingToken: a.FencingToken, OverlayIPv4: a.OverlayIPv4, TemplateSHA256: a.Execution.LaunchTemplateSHA256, PublicJSON: raw}) != nil {
		return l, errNativePhysical
	}
	return l, nil
}

func materializeNativePhysical(a model.CapacityNativeWorkerAttempt, raw []byte, f model.CapacityNativeWorkerPhysicalFacts) (model.CapacityNativeWorkerPhysical, error) {
	l, err := decodeNativePhysicalLaunch(a, raw)
	if err != nil {
		return model.CapacityNativeWorkerPhysical{}, err
	}

	if nativePhysicalProtectedAWS(f.ResourceID) || a.Provider != "aws" || l.Provider.Kind != "aws" || l.Provider.AccountID != f.AccountID || l.Provider.Region != f.Region || l.Provider.Zone != f.Zone || l.Provider.ImageID != f.ImageID || l.Provider.NativeNetworkCIDR != f.NativeNetworkCIDR || f.ProviderID != "aws:///"+f.Zone+"/"+f.ResourceID || f.AccountID != "153828470928" || !regexp.MustCompile(`^i-[a-f0-9]{17}$`).MatchString(f.ResourceID) || !regexp.MustCompile(`^ami-[a-f0-9]{17}$`).MatchString(f.ImageID) || !regexp.MustCompile(`^[a-z]{2}(?:-gov)?-[a-z]+-[1-9][0-9]*$`).MatchString(f.Region) || !regexp.MustCompile(`^`+regexp.QuoteMeta(f.Region)+`[a-z]$`).MatchString(f.Zone) {
		return model.CapacityNativeWorkerPhysical{}, errNativePhysical
	}
	network, err := netip.ParsePrefix(f.NativeNetworkCIDR)
	ip, ipErr := netip.ParseAddr(f.NativeIPv4)
	if err != nil || ipErr != nil || !network.Addr().Is4() || !network.Addr().IsPrivate() || network != network.Masked() || network.String() != f.NativeNetworkCIDR || !network.Contains(ip) || !ip.IsPrivate() || ip.String() != f.NativeIPv4 || ip == network.Addr() || f.ResourceID == "" || f.ProviderID == l.Floor.ProviderID {
		return model.CapacityNativeWorkerPhysical{}, errNativePhysical
	}
	b := nativePhysicalBinding{l.Schema, l.Mode, l.SourceCommit, l.PoolID, l.PoolUID, l.Registry, l.PolicyID, l.PolicySHA256, l.ExpectedPoolEpoch, l.IntentGeneration, l.FencingToken, l.ReservationID, l.IntentSHA256, a.LaunchSHA256, nativePhysicalProvider{l.Provider.Kind, f.ResourceID, f.ProviderID, f.AccountID, f.Region, f.Zone, f.ImageID, f.NativeIPv4, f.NativeNetworkCIDR}, l.Floor, l.Network, l.Operator, l.Reserve}
	wire, _ := json.Marshal(b)
	p := model.CapacityNativeWorkerPhysical{ResourceID: f.ResourceID, ProviderID: f.ProviderID, AccountID: f.AccountID, InstanceType: f.InstanceType, NetworkID: f.NetworkID, CreatedAt: f.CreatedAt, ImageID: f.ImageID, Region: f.Region, Zone: f.Zone, NativeIPv4: f.NativeIPv4, MACAddress: f.MACAddress, PhysicalSpecSHA256: f.PhysicalSpecSHA256, PhysicalBindingSHA256: nativePrivateSHA(wire), LaunchSHA256: f.LaunchSHA256}
	if !NativeWorkerPhysicalValid(a, p) {
		return model.CapacityNativeWorkerPhysical{}, errNativePhysical
	}
	return p, nil
}

func PureNativePhysicalQualify(a model.CapacityNativeWorkerAttempt, storedLaunch []byte, original model.CapacityNativeWorkerOriginalReturn, o model.CapacityNativeWorkerPhysicalObservation, b model.CapacityNativeWorkerPhysicalReadBinding, maxAge int, now time.Time) (model.CapacityNativeWorkerObservation, error) {
	return pureNativePhysicalQualify(a, storedLaunch, original, o, b, maxAge, now, false)
}

// The sealed mode is private to the two fixed public methods, never wire input.
func pureNativePhysicalQualify(a model.CapacityNativeWorkerAttempt, storedLaunch []byte, original model.CapacityNativeWorkerOriginalReturn, o model.CapacityNativeWorkerPhysicalObservation, b model.CapacityNativeWorkerPhysicalReadBinding, maxAge int, now time.Time, sealed bool) (model.CapacityNativeWorkerObservation, error) {
	var out model.CapacityNativeWorkerObservation
	if a.Provider != "aws" || !nativePhysicalStateValid(a, sealed) || b.Profile != a.Profile || b.Provider != a.Provider || b.Region != a.Region || !marketAdapterValid(b.Adapter) || b.Adapter.ManifestID == a.Execution.Adapter.ManifestID || !marketCommit.MatchString(b.SourceCommit) || !marketSHA.MatchString(b.ScopeSHA256) || b.Capability != ObserveNativeWorkerPhysical || maxAge < 1 || maxAge > 300 {
		return out, errNativePhysical
	}
	ack, err := decodeNativeAWSAcceptance(a, original)
	if err != nil {
		return out, err
	}
	if !nativePhysicalTransportEndpoint(o.TransportEndpointIPv4) || o.Schema != "aws_native_worker_physical_observation_v1" || o.SourceCommit != b.SourceCommit || o.Adapter != b.Adapter || o.BindingName != b.BindingName || o.BindingScopeSHA256 != b.ScopeSHA256 || o.Requested != (model.CapacityNativeWorkerObservationRequest{BindingName: b.BindingName, AttemptID: a.ID.String(), ResourceID: ack.resourceID, LaunchSHA256: a.LaunchSHA256}) || !o.Complete || o.MutationAuthorized || o.NodeReadyQualified || o.UsefulCapacityQualified || o.AbsenceProven || o.ObservedAt.After(now) || !fresh(o.ObservedAt, now, maxAge) || o.StartedAt.IsZero() || o.StartedAt.After(o.ObservedAt) || o.StartedAt.Before(now.Add(-time.Duration(maxAge)*time.Second)) || (o.InstanceState != "pending" && o.InstanceState != "running") {
		return out, errNativePhysical
	}
	digest := o.EvidenceSHA256
	o.EvidenceSHA256 = ""
	evidence, _ := json.Marshal(o)
	if !marketSHA.MatchString(digest) || nativePrivateSHA(evidence) != digest || o.ActualTags != (model.CapacityNativeWorkerObservedTags{AttemptID: a.ID.String(), PoolUID: a.PoolUID, LaunchSHA256: a.LaunchSHA256}) || o.ActualClientToken != a.ID.String() || len(o.Reads) != 7 {
		return out, errNativePhysical
	}
	operations := []string{"GetCallerIdentity", "DescribeInstances", "DescribeSubnets", "DescribeSecurityGroups", "DescribeVolumes", "DescribeNetworkInterfaces", "DescribeInstances"}
	roles := []string{"caller", "before", "network", "security", "root_volume", "primary_interface", "after"}
	seenRequests := map[string]bool{}
	previous := o.StartedAt
	for i, r := range o.Reads {
		if r.Operation != operations[i] || r.Role != roles[i] || !nativePhysicalRequestID(r.RequestID) || r.ObservedAt.Before(previous) || r.ObservedAt.After(o.ObservedAt) || seenRequests[r.RequestID] {
			return out, errNativePhysical
		}
		previous = r.ObservedAt
		seenRequests[r.RequestID] = true
	}
	f := o.Physical
	if f.ResourceID != ack.resourceID || f.AccountID != ack.accountID || f.ImageID != ack.imageID || f.InstanceType != ack.instanceType || f.NetworkID != ack.networkID || f.Zone != ack.zone || f.NativeIPv4 != ack.nativeIPv4 || f.MACAddress != ack.mac || !f.CreatedAt.Equal(ack.createdAt) || f.PhysicalSpecSHA256 != a.PhysicalSpecSHA256 || f.LaunchSHA256 != a.LaunchSHA256 || (ack.rootVolumePresent && o.RootVolume.ResourceID != ack.rootVolumeID) || (ack.rootDevicePresent && o.RootVolume.DeviceName != ack.rootDevice) || (ack.interfaceIDPresent && o.PrimaryInterface.ResourceID != ack.interfaceID) || o.PrimaryInterface.NetworkID != f.NetworkID || o.PrimaryInterface.SubnetID != ack.subnetID || o.PrimaryInterface.NativeIPv4 != f.NativeIPv4 || o.PrimaryInterface.MACAddress != f.MACAddress || o.PrimaryInterface.AttachedInstanceID != f.ResourceID || !o.PrimaryInterface.DeleteOnTermination || o.PrimaryInterface.AttachmentID == "" || o.RootVolume.AttachedInstanceID != f.ResourceID || !o.RootVolume.Encrypted || !o.RootVolume.DeleteOnTermination || o.RootVolume.VolumeType != "gp3" || o.RootVolume.VolumeGiB < 1 || o.RootVolume.IOPS < 1 || o.RootVolume.Throughput < 1 || !regexp.MustCompile(`^arn:aws:kms:`+regexp.QuoteMeta(f.Region)+`:`+regexp.QuoteMeta(f.AccountID)+`:key/[a-f0-9-]{36}$`).MatchString(o.RootVolume.KMSKeyARN) || !regexp.MustCompile(`^vol-[a-f0-9]{17}$`).MatchString(o.RootVolume.ResourceID) || !regexp.MustCompile(`^eni-[a-f0-9]{17}$`).MatchString(o.PrimaryInterface.ResourceID) || !regexp.MustCompile(`^eni-attach-[a-f0-9]{17}$`).MatchString(o.PrimaryInterface.AttachmentID) || !regexp.MustCompile(`^/dev/[a-z0-9]+$`).MatchString(o.RootVolume.DeviceName) {
		return out, errNativePhysical
	}
	p, err := materializeNativePhysical(a, storedLaunch, f)
	if err != nil {
		return out, err
	}
	if p.CreatedAt.After(o.StartedAt) || ack.requestID == o.Reads[6].RequestID || ack.clientToken != a.ID.String() || ack.tags != o.ActualTags {
		return out, errNativePhysical
	}
	out = model.CapacityNativeWorkerObservation{State: "acknowledged", ExecutionScopeSHA256: a.Execution.ScopeSHA256, ObservedAt: o.ObservedAt, OriginalReturnSHA256: fmt.Sprintf("%x", sha256.Sum256(original.Wire)), OriginalAcceptance: p, IndependentCurrent: p, OriginalRequestID: ack.requestID, IndependentRequestID: o.Reads[6].RequestID}
	if NativeWorkerObservationValid(a, out, now, maxAge) != nil {
		return model.CapacityNativeWorkerObservation{}, errNativePhysical
	}
	return out, nil
}

func nativePhysicalRequestID(s string) bool {
	return regexp.MustCompile(`^[A-Za-z0-9-]{1,128}$`).MatchString(s)
}

// Preserve the same explicit retained-host fence as System Provider.Validate,
// even when a forged response tries to make that old ID look newly created.
func nativePhysicalProtectedAWS(id string) bool {
	switch id {
	case "i-0eb40396f80878812", "i-0f051cfd6d8da97e9", "i-070b5767a35c7f0d5":
		return true
	default:
		return false
	}
}

// An optional independently reported Internet endpoint is a fact only, not
// verified reachability, network admission or permission to add a floor peer.
func nativePhysicalTransportEndpoint(raw string) bool {
	if raw == "" {
		return true
	}
	ip, e := netip.ParseAddr(raw)
	return e == nil && ip.Is4() && ip.IsGlobalUnicast() && !ip.IsPrivate() && !ip.IsLoopback() && ip.String() == raw
}
