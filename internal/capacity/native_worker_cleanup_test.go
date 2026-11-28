package capacity

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

func nativeCleanupFixture(t *testing.T, provider string) (model.CapacityPolicySpec, model.CapacityNativeWorkerAttempt, []byte, model.CapacityNativeWorkerResourceFootprint, time.Time) {
	t.Helper()
	var p model.CapacityPolicySpec
	var a model.CapacityNativeWorkerAttempt
	var launch []byte
	var read model.CapacityNativeWorkerPhysicalObservation
	var ack model.CapacityNativeWorkerObservation
	var now time.Time
	if provider == "aws" {
		var original model.CapacityNativeWorkerOriginalReturn
		p, a, launch, original, read, now = nativePhysicalFixture(t)
		var err error
		ack, err = PureNativePhysicalQualify(a, launch, original, read, p.NativeWorkerLifecycleBinding.PhysicalObservers[0], 30, now)
		if err != nil {
			t.Fatal(err)
		}
	} else {
		p, a, launch, _, read, ack, now = nativeHCloudFixtureACK(t)
	}
	a.Physical, a.HCloudWitness = &ack.IndependentCurrent, ack.HCloudWitness
	a.State, a.BirthSHA256 = "registered", strings.Repeat("b", 64)
	p.NativeWorkerPoolBinding = &model.CapacityNativeWorkerPoolBinding{PoolUID: a.PoolUID}
	b := p.NativeWorkerLifecycleBinding.PhysicalObservers[0]
	f := model.CapacityNativeWorkerResourceFootprint{Schema: "native_worker_resource_footprint_v1", Provider: provider, SourceCommit: b.SourceCommit, Adapter: b.Adapter, BindingName: b.BindingName, BindingScopeSHA256: b.ScopeSHA256, ActualPoolUID: a.PoolUID}
	if provider == "aws" {
		x := read.Physical
		f.Requested, f.ObservedAt = read.Requested, read.ObservedAt
		f.Physical = model.CapacityNativeWorkerCleanupPhysical{ResourceID: x.ResourceID, ProviderID: x.ProviderID, AccountID: x.AccountID, InstanceType: x.InstanceType, NetworkID: x.NetworkID, NativeNetworkCIDR: x.NativeNetworkCIDR, CreatedAt: x.CreatedAt, ImageID: x.ImageID, Region: x.Region, Zone: x.Zone, NativeIPv4: x.NativeIPv4, MACAddress: x.MACAddress, PhysicalSpecSHA256: x.PhysicalSpecSHA256, LaunchSHA256: x.LaunchSHA256}
		f.AWS = &model.CapacityNativeWorkerAWSResourceFootprint{RootVolume: model.CapacityNativeWorkerCleanupVolume(read.RootVolume), PrimaryInterface: model.CapacityNativeWorkerCleanupInterface(read.PrimaryInterface), InstanceState: read.InstanceState, PublicIPv4Kind: "none"}
	} else {
		h := read.HCloud
		f.Requested, f.ObservedAt = h.Requested, h.ObservedAt
		f.Physical = model.CapacityNativeWorkerCleanupPhysical(h.Physical)
		f.HCloud = &model.CapacityNativeWorkerHCloudResourceFootprint{ProjectScope: model.CapacityNativeWorkerCleanupProjectScope(h.ProjectScope), RootStorage: model.CapacityNativeWorkerCleanupRootStorage(h.RootStorage), PrimaryIPs: []model.CapacityNativeWorkerCleanupPrimaryIP{}, AdditionalVolumeIDs: []string{}, FloatingIPIDs: []string{}}
		for _, ip := range h.PrimaryIPs {
			f.HCloud.PrimaryIPs = append(f.HCloud.PrimaryIPs, model.CapacityNativeWorkerCleanupPrimaryIP(ip))
		}
	}
	f.EvidenceSHA256 = NativeWorkerResourceFootprintSHA256(f)
	return p, a, launch, f, now
}

func TestNativeCleanupFootprintJoinsActualSealedTupleAndHistoricalCustody(t *testing.T) {
	for _, provider := range []string{"aws", "hetzner"} {
		t.Run(provider, func(t *testing.T) {
			p, a, launch, f, now := nativeCleanupFixture(t, provider)
			if !NativeWorkerResourceFootprintValid(p, a, launch, &f, now, true) {
				t.Fatal("valid complete source-bound footprint refused")
			}
			later := now.Add(24 * time.Hour)
			if NativeWorkerResourceFootprintValid(p, a, launch, &f, later, true) || !NativeWorkerResourceFootprintValid(p, a, launch, &f, later, false) {
				t.Fatal("historical custody aged into new authority or became unusable for receiving")
			}
			raw, _ := json.Marshal(f)
			var copy model.CapacityNativeWorkerResourceFootprint
			if json.Unmarshal(raw, &copy) != nil || !NativeWorkerResourceFootprintValid(p, a, launch, &copy, now, true) {
				t.Fatal("committed JSON footprint lost its sealed identity")
			}
			if strings.Contains(string(raw), "physical_binding_sha256") {
				t.Fatal("provider footprint invented Core physical binding hash")
			}
		})
	}
}

func TestNativeCleanupFootprintRefusesRehashedScopeLifetimeAndResourceDrift(t *testing.T) {
	for _, provider := range []string{"aws", "hetzner"} {
		t.Run(provider, func(t *testing.T) {
			p, a, launch, f, now := nativeCleanupFixture(t, provider)
			for _, fault := range []string{"source", "scope", "adapter", "binding", "attempt", "pool", "resource", "lifetime", "network", "private_cidr", "mac", "provider", "other_arm", "missing_arm", "extra_resources", "resource_owner", "before_birth", "future", "launch"} {
				t.Run(fault, func(t *testing.T) {
					raw, _ := json.Marshal(f)
					var bad model.CapacityNativeWorkerResourceFootprint
					_ = json.Unmarshal(raw, &bad)
					wire := append([]byte(nil), launch...)
					switch fault {
					case "source":
						bad.SourceCommit = strings.Repeat("0", 40)
					case "scope":
						bad.BindingScopeSHA256 = strings.Repeat("0", 64)
					case "adapter":
						bad.Adapter.Version++
					case "binding":
						bad.BindingName = "other"
					case "attempt":
						bad.Requested.AttemptID = uuid.NewString()
					case "pool":
						bad.ActualPoolUID = uuid.NewString()
					case "resource":
						bad.Physical.ResourceID = "different"
					case "lifetime":
						bad.Physical.CreatedAt = bad.Physical.CreatedAt.Add(-time.Second)
					case "network":
						bad.Physical.NetworkID = "other"
					case "private_cidr":
						bad.Physical.NativeNetworkCIDR = "10.0.0.0/8" // Still contains the IP; must join original launch.
					case "mac":
						bad.Physical.MACAddress = "02:00:00:00:00:09"
					case "provider":
						bad.Provider = "hcloud"
					case "other_arm":
						if provider == "aws" {
							bad.HCloud = &model.CapacityNativeWorkerHCloudResourceFootprint{}
						} else {
							bad.AWS = &model.CapacityNativeWorkerAWSResourceFootprint{}
						}
					case "missing_arm":
						bad.AWS, bad.HCloud = nil, nil
					case "extra_resources":
						if provider == "aws" {
							bad.AWS.PrimaryInterface.DeleteOnTermination = false
						} else {
							bad.HCloud.AdditionalVolumeIDs = []string{"99"}
						}
					case "resource_owner":
						if provider == "aws" {
							bad.AWS.RootVolume.AttachedInstanceID = "i-11111111111111111"
						} else {
							bad.HCloud.PrimaryIPs[0].AssigneeID = "999"
						}
					case "before_birth":
						bad.ObservedAt = bad.Physical.CreatedAt.Add(-time.Millisecond)
					case "future":
						bad.ObservedAt = now.Add(time.Hour)
					case "launch":
						wire = append(wire, ' ')
					}
					bad.EvidenceSHA256 = NativeWorkerResourceFootprintSHA256(bad)
					if NativeWorkerResourceFootprintValid(p, a, wire, &bad, now, true) {
						t.Fatal("coherent forged footprint matched immutable Source/Attempt")
					}
				})
			}
		})
	}
}

func TestNativeCleanupAWSReleasedAutomaticIPRequiresActualStoppedState(t *testing.T) {
	p, a, launch, f, now := nativeCleanupFixture(t, "aws")
	for _, state := range []string{"stopping", "stopped", "running", "pending"} {
		f.AWS.InstanceState, f.AWS.PublicIPv4Kind, f.AWS.AutomaticPublicIPv4 = state, "automatic_released", ""
		f.EvidenceSHA256 = NativeWorkerResourceFootprintSHA256(f)
		got := NativeWorkerResourceFootprintValid(p, a, launch, &f, now, true)
		if got != (state == "stopped" || state == "stopping") {
			t.Fatal("released automatic address state was invented", state)
		}
	}
	// Snapshot flags cannot become a different historical resource set merely
	// because a new read has a valid hash and a newer timestamp.
	other := f
	other.ObservedAt = now
	other.EvidenceSHA256 = NativeWorkerResourceFootprintSHA256(other)
	if !NativeWorkerResourceFootprintStableEqual(&f, &other) {
		t.Fatal("freshness changed stable resource identity")
	}
	other.AWS = &model.CapacityNativeWorkerAWSResourceFootprint{}
	if NativeWorkerResourceFootprintStableEqual(&f, &other) {
		t.Fatal("different resource set replaced committed historical custody")
	}
}

func TestNativeCleanupStableCustodyAllowsStateProgressButNotResourceReplacement(t *testing.T) {
	_, _, _, f, now := nativeCleanupFixture(t, "aws")
	f.AWS.InstanceState = "pending"
	raw, _ := json.Marshal(f)
	var next model.CapacityNativeWorkerResourceFootprint
	_ = json.Unmarshal(raw, &next)
	next.AWS.InstanceState, next.ObservedAt = "running", now.Add(time.Second)
	next.EvidenceSHA256 = NativeWorkerResourceFootprintSHA256(next)
	if !NativeWorkerResourceFootprintStableEqual(&f, &next) || f.AWS.InstanceState != "pending" || next.AWS.InstanceState != "running" {
		t.Fatal("state progress replaced resource identity or normalization mutated custody")
	}
	for _, fault := range []string{"volume", "interface", "delete_flag", "public_kind", "lifetime"} {
		t.Run(fault, func(t *testing.T) {
			var bad model.CapacityNativeWorkerResourceFootprint
			_ = json.Unmarshal(raw, &bad)
			switch fault {
			case "volume":
				bad.AWS.RootVolume.ResourceID = "vol-11111111111111111"
			case "interface":
				bad.AWS.PrimaryInterface.ResourceID = "eni-11111111111111111"
			case "delete_flag":
				bad.AWS.RootVolume.DeleteOnTermination = false
			case "public_kind":
				bad.AWS.PublicIPv4Kind = "automatic"
			case "lifetime":
				bad.Physical.CreatedAt = bad.Physical.CreatedAt.Add(time.Second)
			}
			bad.EvidenceSHA256 = NativeWorkerResourceFootprintSHA256(bad)
			if NativeWorkerResourceFootprintStableEqual(&f, &bad) {
				t.Fatal("changed resource origin accepted", fault)
			}
		})
	}
}

func TestNativeCleanupBootstrapHostnameRequiresSealedPhysicalResource(t *testing.T) {
	_, a, _, _, _ := nativeCleanupFixture(t, "aws")
	a.ID = uuid.MustParse("11111111-2222-4333-8444-555555555555")
	name, err := NativeWorkerBootstrapNodeName(a)
	if err != nil || name != "nw-111111112222-i-0123456789abcdef0" {
		t.Fatal("System hostname declaration differs", name, err)
	}
	a.Physical = nil
	if _, err = NativeWorkerBootstrapNodeName(a); err == nil {
		t.Fatal("pre-create Launch guessed physical hostname")
	}
}
