package capacity

import (
	"encoding/json"
	"errors"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

var errNativeCleanup = errors.New("HOLD: independent Native resource footprint or cleanup is unqualified")
var nativeCleanupVolumeID = regexp.MustCompile(`^vol-[a-f0-9]{17}$`)
var nativeCleanupENIID = regexp.MustCompile(`^eni-[a-f0-9]{17}$`)
var nativeCleanupAttachmentID = regexp.MustCompile(`^eni-attach-[a-f0-9]{8,17}$`)

// Match System Binding.NodeName after actual physical materialization. The
// original pre-create Launch has no InstanceID and cannot supply this alone.
func NativeWorkerBootstrapNodeName(a model.CapacityNativeWorkerAttempt) (string, error) {
	if a.ID == uuid.Nil || a.Physical == nil || !NativeWorkerPhysicalValid(a, *a.Physical) {
		return "", errNativeCleanup
	}
	id := strings.ReplaceAll(a.ID.String(), "-", "")
	name := "nw-" + id[:12] + "-" + a.Physical.ResourceID
	if !marketDNSLabel.MatchString(name) {
		return "", errNativeCleanup
	}
	return name, nil
}

func NativeWorkerResourceFootprintSHA256(f model.CapacityNativeWorkerResourceFootprint) string {
	f.EvidenceSHA256 = ""
	raw, _ := json.Marshal(f)
	return nativePrivateSHA(raw)
}

func nativeCleanupPhysicalSame(p model.CapacityNativeWorkerCleanupPhysical, want model.CapacityNativeWorkerPhysical) bool {
	return p.ResourceID == want.ResourceID && p.ProviderID == want.ProviderID && p.AccountID == want.AccountID && p.InstanceType == want.InstanceType &&
		p.NetworkID == want.NetworkID && p.CreatedAt.Equal(want.CreatedAt) && p.ImageID == want.ImageID && p.Region == want.Region && p.Zone == want.Zone &&
		p.NativeIPv4 == want.NativeIPv4 && p.MACAddress == want.MACAddress && p.PhysicalSpecSHA256 == want.PhysicalSpecSHA256 && p.LaunchSHA256 == want.LaunchSHA256
}

func nativeCleanupPublicIPv4(raw string) bool {
	ip, e := netip.ParseAddr(raw)
	return e == nil && ip.Is4() && ip.String() == raw && ip.IsGlobalUnicast() && !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast()
}

func nativeCleanupHCloudID(raw string) bool {
	id, e := strconv.ParseInt(raw, 10, 64)
	return e == nil && id > 0 && strconv.FormatInt(id, 10) == raw
}

// fresh is required when a newly observed footprint can precede a send.
// Historical immutable custody remains usable for fresh GET-only receiving.
// The actual current provider observation always has its own fresh read window.
func NativeWorkerResourceFootprintValid(p model.CapacityPolicySpec, a model.CapacityNativeWorkerAttempt, launch json.RawMessage, f *model.CapacityNativeWorkerResourceFootprint, now time.Time, fresh bool) bool {
	if p.NativeWorkerLifecycleBinding == nil || p.NativeWorkerPoolBinding == nil || a.Physical == nil || !NativeWorkerPhysicalValid(a, *a.Physical) || !ValidDigest(a.BirthSHA256) ||
		f == nil || f.Schema != "native_worker_resource_footprint_v1" || f.Provider != a.Provider || f.ActualPoolUID != a.PoolUID || f.ActualPoolUID != p.NativeWorkerPoolBinding.PoolUID ||
		f.Requested.AttemptID != a.ID.String() || f.Requested.ResourceID != a.Physical.ResourceID || f.Requested.LaunchSHA256 != a.LaunchSHA256 ||
		f.ObservedAt.IsZero() || f.ObservedAt.Before(f.Physical.CreatedAt) || f.ObservedAt.After(now) || fresh && now.Sub(f.ObservedAt) > time.Duration(p.NativeWorkerLifecycleBinding.MaxReadAgeSeconds)*time.Second ||
		!ValidDigest(f.EvidenceSHA256) || NativeWorkerResourceFootprintSHA256(*f) != f.EvidenceSHA256 || !nativeCleanupPhysicalSame(f.Physical, *a.Physical) ||
		nativePrivateSHA(launch) != a.LaunchSHA256 {
		return false
	}
	var original nativePrivateLaunch
	if DecodeNativeCapacity(launch, &original) != nil || original.ReservationID != a.ID.String() || original.PoolUID != a.PoolUID || original.PolicyID != a.PolicyID.String() ||
		original.PolicySHA256 != strings.TrimPrefix(a.PolicyChecksum, "sha256:") || original.ExpectedPoolEpoch != a.PoolEpoch || original.IntentGeneration != a.Generation || original.FencingToken != a.FencingToken ||
		f.Physical.NativeNetworkCIDR != original.Provider.NativeNetworkCIDR || a.Provider == "aws" && f.Physical.NetworkZone != "" || a.Provider == "hetzner" && f.Physical.NetworkZone != original.Provider.Region {
		return false
	}
	var bound *model.CapacityNativeWorkerPhysicalReadBinding
	for i := range p.NativeWorkerLifecycleBinding.PhysicalObservers {
		b := &p.NativeWorkerLifecycleBinding.PhysicalObservers[i]
		if b.Profile == a.Profile && b.Provider == a.Provider && b.Region == a.Region {
			if bound != nil {
				return false
			}
			bound = b
		}
	}
	if bound == nil || f.Adapter != bound.Adapter || f.SourceCommit != bound.SourceCommit || f.BindingScopeSHA256 != bound.ScopeSHA256 || f.BindingName != bound.BindingName || f.Requested.BindingName != bound.BindingName {
		return false
	}
	if a.Provider == "aws" {
		return nativeCleanupAWSFootprintShape(f)
	}
	if a.Provider != "hetzner" || f.AWS != nil || f.HCloud == nil || bound.HCloudScope == nil || !NativeWorkerHCloudWitnessBindingValid(p, a, a.HCloudWitness) {
		return false
	}
	h, want := f.HCloud, bound.HCloudScope
	s := h.ProjectScope
	if s.DeclaredProjectID != want.DeclaredProjectID || s.ProofKind != want.ProofKind || s.AnchorID != want.AnchorID || !s.AnchorCreated.Equal(want.AnchorCreated) || s.AnchorOwnerLabelKey != want.AnchorOwnerLabelKey || s.AnchorOwnerLabelValue != want.AnchorOwnerLabelValue ||
		h.RootStorage.Kind != "server_local" || h.RootStorage.SizeGiB < 1 || h.RootStorage.ProviderEncryptionProven || h.PrimaryIPs == nil || len(h.PrimaryIPs) > 2 ||
		h.AdditionalVolumeIDs == nil || len(h.AdditionalVolumeIDs) != 0 || h.FloatingIPIDs == nil || len(h.FloatingIPIDs) != 0 {
		return false
	}
	ids, kinds := map[string]bool{}, map[string]bool{}
	for _, ip := range h.PrimaryIPs {
		if !nativeCleanupHCloudID(ip.ResourceID) || ids[ip.ResourceID] || kinds[ip.Type] || ip.AssigneeID != a.Physical.ResourceID {
			return false
		}
		ids[ip.ResourceID], kinds[ip.Type] = true, true
		switch ip.Type {
		case "ipv4":
			if !nativeCleanupPublicIPv4(ip.IP) {
				return false
			}
		case "ipv6":
			v, e := netip.ParsePrefix(ip.IP)
			if e != nil || !v.Addr().Is6() || !v.Addr().IsGlobalUnicast() || v.Addr().IsPrivate() || v != v.Masked() || v.String() != ip.IP {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func nativeCleanupAWSFootprintShape(f *model.CapacityNativeWorkerResourceFootprint) bool {
	if f.AWS == nil || f.HCloud != nil {
		return false
	}
	b, v, n := f.AWS, f.AWS.RootVolume, f.AWS.PrimaryInterface
	if !nativeCleanupVolumeID.MatchString(v.ResourceID) || v.DeviceName == "" || v.AttachedInstanceID != f.Physical.ResourceID || !v.Encrypted ||
		!strings.HasPrefix(v.KMSKeyARN, "arn:aws:kms:"+f.Physical.Region+":"+f.Physical.AccountID+":key/") || v.VolumeType != "gp3" || v.VolumeGiB < 1 || v.IOPS < 1 || v.Throughput < 1 ||
		!v.DeleteOnTermination || !nativeCleanupENIID.MatchString(n.ResourceID) || !nativeCleanupAttachmentID.MatchString(n.AttachmentID) || n.NetworkID != f.Physical.NetworkID ||
		n.SubnetID == "" || n.NativeIPv4 != f.Physical.NativeIPv4 || n.MACAddress != f.Physical.MACAddress || n.AttachedInstanceID != f.Physical.ResourceID || !n.DeleteOnTermination ||
		!slices.Contains([]string{"pending", "running", "stopping", "stopped"}, b.InstanceState) {
		return false
	}
	switch b.PublicIPv4Kind {
	case "none":
		return b.AutomaticPublicIPv4 == ""
	case "automatic":
		return nativeCleanupPublicIPv4(b.AutomaticPublicIPv4)
	case "automatic_released":
		return b.AutomaticPublicIPv4 == "" && (b.InstanceState == "stopped" || b.InstanceState == "stopping")
	}
	return false
}

// Compare an immutable historical resource set across fresh observations. Read
// times/evidence may advance; IDs, lifetimes, ownership, flags and pins may not.
func NativeWorkerResourceFootprintStableEqual(a, b *model.CapacityNativeWorkerResourceFootprint) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	x, y := *a, *b
	// Instance execution state can progress without replacing a resource.
	// Copy the optional arms before normalization so retained custody is intact.
	if x.AWS != nil {
		arm := *x.AWS
		arm.InstanceState = ""
		x.AWS = &arm
	}
	if y.AWS != nil {
		arm := *y.AWS
		arm.InstanceState = ""
		y.AWS = &arm
	}
	x.ObservedAt, y.ObservedAt = time.Time{}, time.Time{}
	x.EvidenceSHA256, y.EvidenceSHA256 = "", ""
	xraw, xe := json.Marshal(x)
	yraw, ye := json.Marshal(y)
	return xe == nil && ye == nil && string(xraw) == string(yraw)
}
