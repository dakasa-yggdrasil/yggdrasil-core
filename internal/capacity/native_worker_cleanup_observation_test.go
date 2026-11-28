package capacity

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func nativeCleanupSealTest(o *model.CapacityNativeWorkerCleanupObservation) {
	o.EvidenceSHA256 = ""
	raw, _ := json.Marshal(o)
	o.EvidenceSHA256 = nativePrivateSHA(raw)
}

// Synthetic completed provider DTOs exercise Core's independent receiving
// rules. SDK real-HTTP/TLS qualification belongs to each provider's CI.
func nativeCleanupClosureFixture(t *testing.T, provider string) (model.CapacityPolicySpec, model.CapacityNativeWorkerAttempt, []byte, model.CapacityNativeWorkerResourceFootprint, model.CapacityNativeWorkerCleanupObservation, time.Time) {
	t.Helper()
	p, a, launch, f, now := nativeCleanupFixture(t, provider)
	o := model.CapacityNativeWorkerCleanupObservation{Schema: "native_worker_cleanup_observation_v1", Provider: provider, Mode: "closure", SourceCommit: f.SourceCommit, Adapter: f.Adapter, BindingName: f.BindingName, BindingScopeSHA256: f.BindingScopeSHA256, Requested: f.Requested, StartedAt: now.Add(-time.Millisecond), ObservedAt: now, Complete: true, Footprint: &f}
	if provider == "aws" {
		o.Resources = []model.CapacityNativeWorkerCleanupResource{{Kind: "instance", ResourceID: f.Physical.ResourceID, Outcome: "not_found", NotFoundCode: "InvalidInstanceID.NotFound"}, {Kind: "volume", ResourceID: f.AWS.RootVolume.ResourceID, Outcome: "not_found", NotFoundCode: "InvalidVolume.NotFound"}, {Kind: "network_interface", ResourceID: f.AWS.PrimaryInterface.ResourceID, Outcome: "not_found", NotFoundCode: "InvalidNetworkInterfaceID.NotFound"}}
		for _, pair := range [][2]string{{"GetCallerIdentity", "caller"}, {"DescribeSubnets", "network"}, {"DescribeInstances", "before"}, {"DescribeVolumes", "root_volume"}, {"DescribeNetworkInterfaces", "primary_interface"}, {"DescribeInstances", "after"}} {
			o.AWSReads = append(o.AWSReads, model.CapacityNativeWorkerCleanupAWSRead{Operation: pair[0], Role: pair[1], RequestID: "ci-actual-dto-" + pair[1], ObservedAt: now})
		}
	} else {
		o.Resources = []model.CapacityNativeWorkerCleanupResource{{Kind: "server", ResourceID: f.Physical.ResourceID, Outcome: "not_found", NotFoundCode: "not_found"}, {Kind: "server_local_root", ResourceID: f.Physical.ResourceID, Outcome: "not_found", NotFoundCode: "not_found", NativeState: "coupled_to_server"}}
		for _, ip := range f.HCloud.PrimaryIPs {
			o.Resources = append(o.Resources, model.CapacityNativeWorkerCleanupResource{Kind: "primary_ip", ResourceID: ip.ResourceID, Outcome: "not_found", NotFoundCode: "not_found"})
		}
		for _, role := range []string{"scope_before", "before", "after", "scope_after"} {
			o.HCloudReads = append(o.HCloudReads, model.CapacityNativeWorkerCleanupHCloudRead{Operation: "GET /source-owned/{id}", Role: role, HTTPStatus: 200, ObservedAt: now})
		}
	}
	nativeCleanupSealTest(&o)
	return p, a, launch, f, o, now
}

func TestNativeCleanupClosureRequiresEveryOriginalResourceIndependently(t *testing.T) {
	for _, provider := range []string{"aws", "hetzner"} {
		t.Run(provider, func(t *testing.T) {
			p, a, launch, f, o, now := nativeCleanupClosureFixture(t, provider)
			outcome, closed, err := NativeWorkerCleanupOutcome(p, a, launch, &f, o, now)
			if err != nil || outcome != "not_found" || !closed {
				t.Fatal("complete exact resource closure refused", outcome, closed, err)
			}
			for i := 1; i < len(o.Resources); i++ {
				t.Run(o.Resources[i].Kind, func(t *testing.T) {
					bad := o
					bad.Resources = append([]model.CapacityNativeWorkerCleanupResource(nil), o.Resources...)
					bad.Resources[i].Outcome, bad.Resources[i].NotFoundCode, bad.Resources[i].NativeState = "present", "", "retained"
					nativeCleanupSealTest(&bad)
					outcome, closed, err := NativeWorkerCleanupOutcome(p, a, launch, &f, bad, now)
					if err != nil || outcome != "not_found" || closed {
						t.Fatal("instance absence released retained ancillary charges", outcome, closed, err)
					}
				})
			}
		})
	}
}

func TestNativeCleanupClosureRejectsIncompleteRehashedOrUncommittedOrigin(t *testing.T) {
	for _, provider := range []string{"aws", "hetzner"} {
		t.Run(provider, func(t *testing.T) {
			p, a, launch, f, o, now := nativeCleanupClosureFixture(t, provider)
			for _, fault := range []string{"missing", "duplicate", "extra", "wrong_id", "wrong_code", "attached_absence", "unknown", "invented_terminal", "incomplete", "stale", "future", "mode", "footprint", "read_identity", "digest"} {
				t.Run(fault, func(t *testing.T) {
					raw, _ := json.Marshal(o)
					var bad model.CapacityNativeWorkerCleanupObservation
					_ = json.Unmarshal(raw, &bad)
					switch fault {
					case "missing":
						bad.Resources = bad.Resources[:len(bad.Resources)-1]
					case "duplicate":
						bad.Resources[1] = bad.Resources[0]
					case "extra":
						bad.Resources = append(bad.Resources, bad.Resources[0])
					case "wrong_id":
						bad.Resources[0].ResourceID = "replacement"
					case "wrong_code":
						bad.Resources[0].NotFoundCode = "generic404"
					case "attached_absence":
						bad.Resources[0].AttachedInstanceID = a.Physical.ResourceID
					case "unknown":
						bad.Resources[0].Outcome = "unknown"
					case "invented_terminal":
						bad.Resources[0].Outcome, bad.Resources[0].NativeState, bad.Resources[0].NotFoundCode = "terminal", "stopped", ""
					case "incomplete":
						bad.Complete = false
					case "stale":
						bad.StartedAt = now.Add(-time.Hour)
					case "future":
						bad.ObservedAt = now.Add(time.Second)
					case "mode":
						bad.Mode = "snapshot"
					case "footprint":
						bad.Footprint.ObservedAt = bad.Footprint.ObservedAt.Add(-time.Millisecond)
						bad.Footprint.EvidenceSHA256 = NativeWorkerResourceFootprintSHA256(*bad.Footprint)
					case "read_identity":
						if provider == "aws" {
							bad.AWSReads[0].RequestID = ""
						} else {
							bad.HCloudReads[0].RequestIDObserved = true
						}
					}
					nativeCleanupSealTest(&bad)
					if fault == "digest" {
						bad.EvidenceSHA256 = marketTestSHA("0")
					}
					if _, _, err := NativeWorkerCleanupOutcome(p, a, launch, &f, bad, now); err == nil {
						t.Fatal("incomplete or changed original became closure", fault)
					}
				})
			}
			if _, _, err := NativeWorkerCleanupOutcome(p, a, launch, nil, o, now); err == nil {
				t.Fatal("no committed footprint inferred absence")
			}
		})
	}
}

func TestNativeCleanupTerminatedAWSInstanceDoesNotClosePresentEBSOrENI(t *testing.T) {
	p, a, launch, f, o, now := nativeCleanupClosureFixture(t, "aws")
	o.Resources[0].Outcome, o.Resources[0].NativeState, o.Resources[0].NotFoundCode = "terminal", "terminated", ""
	o.Resources[1].Outcome, o.Resources[1].NativeState, o.Resources[1].NotFoundCode = "present", "available", ""
	nativeCleanupSealTest(&o)
	provider, closed, err := NativeWorkerCleanupOutcome(p, a, launch, &f, o, now)
	if err != nil || provider != "terminal_nonbillable" || closed {
		t.Fatal("terminated instance closed retained volume", provider, closed, err)
	}
	o.Resources[1].Outcome, o.Resources[1].NativeState = "terminal", "deleted"
	nativeCleanupSealTest(&o)
	if _, closed, err = NativeWorkerCleanupOutcome(p, a, launch, &f, o, now); err != nil || !closed {
		t.Fatal("actual deleted EBS plus not-found ENI refused", err)
	}
}
