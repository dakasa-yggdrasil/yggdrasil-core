package capacity

import (
	"encoding/json"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// Provider completion and resource absence are different facts. Core requires
// every exact original ancillary ID before it can release a cost reservation.
func NativeWorkerCleanupOutcome(p model.CapacityPolicySpec, a model.CapacityNativeWorkerAttempt, launch json.RawMessage, historical *model.CapacityNativeWorkerResourceFootprint, o model.CapacityNativeWorkerCleanupObservation, now time.Time) (string, bool, error) {
	if p.NativeWorkerLifecycleBinding == nil || o.Footprint == nil || !NativeWorkerResourceFootprintValid(p, a, launch, o.Footprint, now, historical == nil) ||
		o.Schema != "native_worker_cleanup_observation_v1" || o.Provider != a.Provider || o.SourceCommit != o.Footprint.SourceCommit || o.Adapter != o.Footprint.Adapter ||
		o.BindingName != o.Footprint.BindingName || o.BindingScopeSHA256 != o.Footprint.BindingScopeSHA256 || o.Requested != o.Footprint.Requested || !o.Complete ||
		o.StartedAt.IsZero() || o.StartedAt.After(o.ObservedAt) || o.ObservedAt.After(now) || !fresh(o.StartedAt, now, p.NativeWorkerLifecycleBinding.MaxReadAgeSeconds) || !ValidDigest(o.EvidenceSHA256) {
		return "", false, errNativeCleanup
	}
	unsigned := o
	unsigned.EvidenceSHA256 = ""
	raw, err := json.Marshal(unsigned)
	if err != nil || nativePrivateSHA(raw) != o.EvidenceSHA256 {
		return "", false, errNativeCleanup
	}
	mode := "snapshot"
	if historical != nil {
		mode = "closure"
		want, we := json.Marshal(historical)
		have, he := json.Marshal(o.Footprint)
		if we != nil || he != nil || string(want) != string(have) {
			return "", false, errNativeCleanup
		}
	}
	if o.Mode != mode {
		return "", false, errNativeCleanup
	}
	// These are actual completed Source-bound reads, not synthetic request IDs.
	if a.Provider == "aws" {
		if len(o.HCloudReads) != 0 || len(o.AWSReads) < 6 || len(o.AWSReads) > 16 {
			return "", false, errNativeCleanup
		}
		for _, read := range o.AWSReads {
			if read.Operation == "" || read.Role == "" || read.RequestID == "" || read.ObservedAt.Before(o.StartedAt) || read.ObservedAt.After(o.ObservedAt) {
				return "", false, errNativeCleanup
			}
		}
	} else {
		if len(o.AWSReads) != 0 || len(o.HCloudReads) < 4 || len(o.HCloudReads) > 32 {
			return "", false, errNativeCleanup
		}
		for _, read := range o.HCloudReads {
			if read.Operation == "" || read.Role == "" || read.HTTPStatus != 200 && (mode != "closure" || read.HTTPStatus != 404) || read.RequestIDObserved != (read.RequestID != "") || read.ObservedAt.Before(o.StartedAt) || read.ObservedAt.After(o.ObservedAt) {
				return "", false, errNativeCleanup
			}
		}
	}
	want := map[string]string{}
	providerKind := "instance"
	if a.Provider == "aws" {
		want["volume\x00"+o.Footprint.AWS.RootVolume.ResourceID] = "InvalidVolume.NotFound"
		want["network_interface\x00"+o.Footprint.AWS.PrimaryInterface.ResourceID] = "InvalidNetworkInterfaceID.NotFound"
		want[providerKind+"\x00"+a.Physical.ResourceID] = "InvalidInstanceID.NotFound"
	} else {
		providerKind = "server"
		want[providerKind+"\x00"+a.Physical.ResourceID] = "not_found"
		want["server_local_root\x00"+a.Physical.ResourceID] = "not_found"
		for _, ip := range o.Footprint.HCloud.PrimaryIPs {
			want["primary_ip\x00"+ip.ResourceID] = "not_found"
		}
	}
	if len(o.Resources) != len(want) {
		return "", false, errNativeCleanup
	}
	provider, closed := "unknown", true
	for _, row := range o.Resources {
		key := row.Kind + "\x00" + row.ResourceID
		code, ok := want[key]
		if !ok {
			return "", false, errNativeCleanup
		}
		delete(want, key)
		gone := false
		switch row.Outcome {
		case "not_found":
			if mode != "closure" || row.NotFoundCode != code || row.AttachedInstanceID != "" || row.NativeState != "" && (row.Kind != "server_local_root" || row.NativeState != "coupled_to_server") {
				return "", false, errNativeCleanup
			}
			gone = true
		case "terminal":
			if mode != "closure" || a.Provider != "aws" || row.NotFoundCode != "" || row.AttachedInstanceID != "" ||
				!(row.Kind == "instance" && row.NativeState == "terminated" || row.Kind == "volume" && row.NativeState == "deleted") {
				return "", false, errNativeCleanup
			}
			gone = true
		case "present":
			if row.NotFoundCode != "" || row.AttachedInstanceID != "" && row.AttachedInstanceID != a.Physical.ResourceID {
				return "", false, errNativeCleanup
			}
		default:
			return "", false, errNativeCleanup
		}
		closed = closed && gone
		if row.Kind == providerKind {
			provider = "present"
			if row.Outcome == "not_found" {
				provider = "not_found"
			} else if gone {
				provider = "terminal_nonbillable"
			}
		}
	}
	if len(want) != 0 || mode == "snapshot" && provider != "present" {
		return "", false, errNativeCleanup
	}
	return provider, mode == "closure" && closed, nil
}
