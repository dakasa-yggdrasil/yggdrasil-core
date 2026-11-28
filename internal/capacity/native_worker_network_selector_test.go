package capacity

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

func nativeNetworkSelectorFixture(t *testing.T) (model.CapacityPolicySpec, model.CapacityNativeWorkerAttempt, nativePrivateLaunch) {
	t.Helper()
	p := nativeWorkerNetworkPolicy(t)
	pool, b := p.NativeWorkerPoolBinding, p.NativeWorkerLifecycleBinding.Network
	a := model.CapacityNativeWorkerAttempt{ID: uuid.New(), PolicyID: uuid.New(), PolicyChecksum: "sha256:" + marketTestSHA("a"), PoolUID: pool.PoolUID, PoolEpoch: pool.ExpectedPoolEpoch, Registry: pool.RegistryRef,
		Generation: 7, FencingToken: 11, SourceCommit: p.NativeWorkerLifecycleBinding.SourceCommit, OverlayIPv4: "10.90.0.2", IntentSHA256: marketTestSHA("b")}
	l := nativePrivateLaunch{Schema: 1, Mode: "native_k3s_worker_v1", SourceCommit: b.Template.GuestSystemSourceCommit, PoolID: "ci-workers", PoolUID: a.PoolUID,
		Registry: nativePrivateRegistry{a.Registry.Kind, a.Registry.Namespace, a.Registry.Name, a.Registry.UID}, PolicyID: a.PolicyID.String(), PolicySHA256: strings.TrimPrefix(a.PolicyChecksum, "sha256:"),
		ExpectedPoolEpoch: a.PoolEpoch, IntentGeneration: a.Generation, FencingToken: a.FencingToken, ReservationID: a.ID.String(), IntentSHA256: a.IntentSHA256,
		Floor: nativePrivateFloor{NodeName: b.Floor.NodeName, NodeUID: b.Floor.NodeUID, ProviderID: b.Floor.ProviderID, ClusterUID: b.Floor.ClusterUID, CASHA256: b.Floor.CASHA256},
		Network: nativePrivateNetwork{Mode: "wireguard_routed_v1", TransportCIDR: b.Template.TransportCIDR, WorkerIPv4: a.OverlayIPv4, FloorPeerIPv4: b.Template.FloorPeerIPv4,
			FloorPeerPublicKey: b.Template.FloorPublicKey, WorkerPublicKey: base64.StdEncoding.EncodeToString([]byte(strings.Repeat("w", 32))), PodCIDR: b.Template.PodCIDR, ServiceCIDR: b.Template.ServiceCIDR}}
	return p, a, l
}

func TestNativeNetworkSelectorUsesExactStoredLaunchAndOnlyFiveReadSelectors(t *testing.T) {
	p, a, l := nativeNetworkSelectorFixture(t)
	raw, err := json.Marshal(l)
	if err != nil {
		t.Fatal(err)
	}
	a.LaunchSHA256 = nativePrivateSHA(raw)
	got, err := NativeWorkerNetworkSelector(p, a, json.RawMessage(raw))
	if err != nil || got.BindingName != p.NativeWorkerLifecycleBinding.Network.Reader.BindingName || got.AttemptID != a.ID.String() || got.LaunchSHA256 != a.LaunchSHA256 || got.WorkerPublicKey != l.Network.WorkerPublicKey || got.WorkerIPv4 != a.OverlayIPv4 {
		t.Fatal("immutable launch selectors changed", err)
	}
	encoded, _ := json.Marshal(got)
	var fields map[string]json.RawMessage
	if json.Unmarshal(encoded, &fields) != nil || len(fields) != 5 {
		t.Fatal("read selector invented authority or material fields")
	}
	for _, key := range []string{"binding_name", "attempt_id", "launch_sha256", "worker_public_key", "worker_ipv4"} {
		if len(fields[key]) == 0 {
			t.Fatal("required source-owned selector absent", key)
		}
	}
}

func TestNativeNetworkSelectorRefusesCoherentSubstitutionAndOriginalFraming(t *testing.T) {
	for _, fault := range []string{"zeroAttempt", "zeroPolicy", "hash", "source", "reservation", "policy", "checksum", "pool", "epoch", "generation", "fence", "intent", "registry", "guestSource", "transportCIDR", "podCIDR", "serviceCIDR", "floor", "floorKey", "workerKey", "workerIPv4", "networkAddress", "floorAddress", "schema", "mode", "duplicate", "trailing"} {
		t.Run(fault, func(t *testing.T) {
			p, a, l := nativeNetworkSelectorFixture(t)
			switch fault {
			case "zeroAttempt":
				a.ID = uuid.Nil
			case "zeroPolicy":
				a.PolicyID = uuid.Nil
			case "source":
				a.SourceCommit = strings.Repeat("f", 40)
			case "reservation":
				l.ReservationID = uuid.NewString()
			case "policy":
				l.PolicyID = uuid.NewString()
			case "checksum":
				l.PolicySHA256 = marketTestSHA("f")
			case "pool":
				l.PoolUID = uuid.NewString()
			case "epoch":
				l.ExpectedPoolEpoch++
			case "generation":
				l.IntentGeneration++
			case "fence":
				l.FencingToken++
			case "intent":
				l.IntentSHA256 = marketTestSHA("e")
			case "registry":
				a.Registry.UID, l.Registry.UID = uuid.NewString(), uuid.NewString()
			case "guestSource":
				l.SourceCommit = strings.Repeat("e", 40)
			case "transportCIDR":
				l.Network.TransportCIDR = "10.91.0.0/16"
			case "podCIDR":
				l.Network.PodCIDR = "172.28.0.0/16"
			case "serviceCIDR":
				l.Network.ServiceCIDR = "172.31.0.0/16"
			case "floor":
				l.Floor.NodeUID = uuid.NewString()
			case "floorKey":
				l.Network.FloorPeerPublicKey = l.Network.WorkerPublicKey
			case "workerKey":
				l.Network.WorkerPublicKey = l.Network.FloorPeerPublicKey
			case "workerIPv4":
				l.Network.WorkerIPv4 = "10.90.0.3"
			case "networkAddress":
				a.OverlayIPv4, l.Network.WorkerIPv4 = "10.90.0.0", "10.90.0.0"
			case "floorAddress":
				a.OverlayIPv4, l.Network.WorkerIPv4 = "10.90.0.1", "10.90.0.1"
			case "schema":
				l.Schema++
			case "mode":
				l.Network.Mode = "unbound"
			}
			raw, err := json.Marshal(l)
			if err != nil {
				t.Fatal(err)
			}
			if fault == "duplicate" {
				raw = []byte(strings.Replace(string(raw), `"schema":1`, `"schema":1,"schema":1`, 1))
			}
			if fault == "trailing" {
				raw = append(raw, []byte(` {}`)...)
			}
			a.LaunchSHA256 = nativePrivateSHA(raw) // Coherent raw hash alone never grants scope.
			if fault == "hash" {
				a.LaunchSHA256 = marketTestSHA("0")
			}
			if _, err = NativeWorkerNetworkSelector(p, a, json.RawMessage(raw)); err == nil {
				t.Fatal("coherent substitution or malformed original became a selector")
			}
		})
	}
}
