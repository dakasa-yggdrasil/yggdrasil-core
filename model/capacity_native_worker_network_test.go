package model

import (
	"encoding/json"
	"testing"
)

func TestNativeWorkerNetworkPreimageRetainsConfigurationAndExcludesRoamingFacts(t *testing.T) {
	o := CapacityNativeWorkerNetworkObservation{KernelInventoryComplete: true, Interface: CapacityNativeWorkerNetworkInterfaceFacts{Present: true, Name: "wg-dakasa", MTU: 1380, Addresses: []string{"10.90.0.1/32"}}, Peers: []CapacityNativeWorkerNetworkPeerFacts{{PublicKey: "peer", AllowedIPs: []string{"10.90.0.2/32"}, Endpoint: "203.0.113.1:50000", LastHandshakeUnix: 100}}, Routes: []CapacityNativeWorkerNetworkRouteFacts{{Destination: "10.90.0.2/32", Device: "wg-dakasa", PreferredSource: "10.90.0.1"}}, Firewall: CapacityNativeWorkerNetworkFirewallFacts{Complete: true, Chain: "inet/dakasa_native/DAKASA_NATIVE", Rules: []string{"owned-public-allow"}, RulesSHA256: "original"}}
	want, e := o.PreimageSHA256()
	if e != nil {
		t.Fatal(e)
	}
	o.Peers[0].Endpoint = "203.0.113.1:51000"
	o.Peers[0].LastHandshakeUnix = 110
	o.BindingName = "other-read-scope"
	if got, e := o.PreimageSHA256(); e != nil || got != want {
		t.Fatal("legitimate authenticated endpoint roaming changed static configuration CAS")
	}
	raw, _ := json.Marshal(o)
	for _, fault := range []string{"route", "allowedIP", "firewall", "mtu", "incomplete", "nilPeerInventory"} {
		t.Run(fault, func(t *testing.T) {
			var bad CapacityNativeWorkerNetworkObservation
			if e := json.Unmarshal(raw, &bad); e != nil {
				t.Fatal(e)
			}
			switch fault {
			case "route":
				bad.Routes[0].PreferredSource = "10.90.0.3"
			case "allowedIP":
				bad.Peers[0].AllowedIPs = []string{"10.90.0.0/24"}
			case "firewall":
				bad.Firewall.Rules = []string{"unowned-allow"}
			case "mtu":
				bad.Interface.MTU = 1500
			case "incomplete":
				bad.KernelInventoryComplete = false
			case "nilPeerInventory":
				bad.Peers = nil
			}
			if got, e := bad.PreimageSHA256(); e == nil && got == want {
				t.Fatal("changed or missing actual configuration reused prior CAS", fault)
			}
		})
	}
}
