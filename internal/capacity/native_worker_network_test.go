package capacity

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func nativeWorkerNetworkPolicy(t *testing.T) model.CapacityPolicySpec {
	t.Helper()
	p := newPhaseReaderFixture(t, time.Now().UTC()).p
	pool, life := p.NativeWorkerPoolBinding, p.NativeWorkerLifecycleBinding
	floor := model.CapacityNativeWorkerNetworkFloorIdentity{NodeName: "dakasa-minimum", NodeUID: marketTestUUID(910), ProviderID: "hcloud://177219645", ClusterUID: pool.RealmUID, CASHA256: marketTestSHA("a"), NativeIPv4: "10.70.1.2", NativeInterface: "enp7s0"}
	pool.ProtectedNodes = append(pool.ProtectedNodes, model.CapacityNativeProtectedNode{NodeUID: floor.NodeUID, ProviderID: floor.ProviderID})
	template := model.CapacityNativeWorkerNetworkTemplate{Schema: 1, GuestSystemSourceCommit: strings.Repeat("c", 40), Interface: "wg-dakasa", MTU: 1380, TransportCIDR: "10.90.0.0/16", FloorPeerIPv4: "10.90.0.1", FloorPublicKey: base64.StdEncoding.EncodeToString([]byte(strings.Repeat("f", 32))), ListenPort: 51820, FirewallChain: "DAKASA_NATIVE", PodCIDR: "172.29.0.0/16", ServiceCIDR: "172.30.0.0/16", ClusterDNSIPv4: "172.30.0.10", DNSName: "kubernetes.default.svc.cluster.local"}
	life.Network = &model.CapacityNativeWorkerNetworkBinding{Mode: NativeWorkerNetworkMode, Writer: model.CapacityNativeWorkerNetworkWriterBinding{AdapterID: marketTestUUID(911), PrincipalID: "floor-network/writer", BindingName: "floor-network-write", SystemSourceCommit: template.GuestSystemSourceCommit, ScopeSHA256: marketTestSHA("1")}, Reader: model.CapacityNativeWorkerNetworkReaderBinding{AdapterID: marketTestUUID(912), BindingName: "floor-network-read", SystemSourceCommit: template.GuestSystemSourceCommit, ScopeSHA256: marketTestSHA("2")}, Floor: floor, Template: template, TemplateSHA256: NativeWorkerNetworkTemplateSHA256(template), MaxPermitSeconds: 30}
	for i := range life.Profiles {
		life.Profiles[i].OverlayCIDR = template.TransportCIDR
		life.Profiles[i].BootstrapSourceCommit = template.GuestSystemSourceCommit
		life.Profiles[i].ExcludedIPv4 = []string{template.FloorPeerIPv4}
	}
	return p
}

func TestNativeWorkerNetworkBindingCannotBorrowAuthorityOrInventTemplateGeometry(t *testing.T) {
	p := nativeWorkerNetworkPolicy(t)
	if e := ValidateNativeWorkerLifecycleBinding(p); e != nil {
		t.Fatal("coherent separate network binding refused", e)
	}
	raw, _ := json.Marshal(p)
	for _, fault := range []string{"sameActor", "sameScope", "providerActor", "pricingActor", "registryActor", "phaseActor", "unprotectedFloor", "foreignRealm", "wrongNativeInterface", "privateFloorOverlap", "transportTooWide", "podOverlap", "serviceOverlap", "dnsOutsideService", "guestSource", "writerSource", "unknownFirewall", "unknownDNS", "wrongMTU", "floorAddressAllocatable", "launchGeometry", "duration"} {
		t.Run(fault, func(t *testing.T) {
			var bad model.CapacityPolicySpec
			if e := json.Unmarshal(raw, &bad); e != nil {
				t.Fatal(e)
			}
			life := bad.NativeWorkerLifecycleBinding
			b := life.Network
			switch fault {
			case "sameActor":
				b.Reader.AdapterID = b.Writer.AdapterID
			case "sameScope":
				b.Reader.ScopeSHA256 = b.Writer.ScopeSHA256
			case "providerActor":
				b.Writer.AdapterID = life.Profiles[0].Adapter.ManifestID
			case "pricingActor":
				b.Writer.AdapterID = bad.MarketBinding.Profiles[0].Adapter.ManifestID
			case "registryActor":
				b.Writer.AdapterID = life.RegistryWriter.Adapter.ManifestID
			case "phaseActor":
				b.Reader.AdapterID = life.PhaseObserver.Adapter.ManifestID
			case "unprotectedFloor":
				b.Floor.NodeUID = marketTestUUID(999)
			case "foreignRealm":
				b.Floor.ClusterUID = marketTestUUID(999)
			case "wrongNativeInterface":
				b.Floor.NativeInterface = "enp8s0"
			case "privateFloorOverlap":
				b.Floor.NativeIPv4 = "10.90.0.100"
			case "transportTooWide":
				b.Template.TransportCIDR = "10.0.0.0/8"
			case "podOverlap":
				b.Template.PodCIDR = b.Template.TransportCIDR
			case "serviceOverlap":
				b.Template.ServiceCIDR = b.Template.PodCIDR
			case "dnsOutsideService":
				b.Template.ClusterDNSIPv4 = "10.70.1.2"
			case "guestSource":
				life.Profiles[0].BootstrapSourceCommit = strings.Repeat("d", 40)
			case "writerSource":
				b.Writer.SystemSourceCommit = strings.Repeat("d", 40)
			case "unknownFirewall":
				b.Template.FirewallChain = "caller_chain"
			case "unknownDNS":
				b.Template.DNSName = "unowned.invalid"
			case "wrongMTU":
				b.Template.MTU = 1500
			case "floorAddressAllocatable":
				life.Profiles[0].ExcludedIPv4 = []string{"10.90.0.2"}
			case "launchGeometry":
				life.Profiles[0].OverlayCIDR = "10.91.0.0/16"
			case "duration":
				b.MaxPermitSeconds = 121
			}
			b.TemplateSHA256 = NativeWorkerNetworkTemplateSHA256(b.Template)
			if e := ValidateNativeWorkerLifecycleBinding(bad); e == nil {
				t.Fatal("unqualified network authority or coherent template substitution accepted", fault)
			}
		})
	}
}

func TestNativeWorkerNetworkAbsentBindingPreservesExistingPolicyWire(t *testing.T) {
	p := nativeWorkerNetworkPolicy(t)
	p.NativeWorkerLifecycleBinding.Network = nil
	raw, e := json.Marshal(p.NativeWorkerLifecycleBinding)
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(string(raw), `"network"`) || ValidateNativeWorkerNetworkBinding(p) != nil {
		t.Fatal("absent network invented a wire field or new authority")
	}
	var before map[string]json.RawMessage
	if e = json.Unmarshal(raw, &before); e != nil {
		t.Fatal(e)
	}
	before["network"] = json.RawMessage("null")
	withNull, _ := json.Marshal(before)
	var parsed model.CapacityNativeWorkerLifecycleBinding
	if e = DecodeNativeCapacity(json.RawMessage(withNull), &parsed); e != nil {
		t.Fatal(e)
	}
	if parsed.Network != nil {
		t.Fatal("null network became usable authority")
	}
}
