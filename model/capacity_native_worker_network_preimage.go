package model

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"sort"
)

var errNativeWorkerNetworkPreimage = errors.New("complete Native network preimage required")

// PreimageSHA256 joins only the safe typed kernel state. Reader identity,
// observation time and caller selectors are independently validated by Core
// and never make otherwise identical reader/writer kernel state disagree.
// The bytes are not a private command return or joined bootstrap material.
func (o CapacityNativeWorkerNetworkObservation) PreimageSHA256() (string, error) {
	if !o.KernelInventoryComplete || !o.Firewall.Complete || o.Peers == nil || o.Routes == nil || o.Interface.Addresses == nil || o.Firewall.Rules == nil {
		return "", errNativeWorkerNetworkPreimage
	}
	type configuredPeer struct {
		PublicKey  string   `json:"public_key"`
		AllowedIPs []string `json:"allowed_ips"`
	}
	peers := make([]configuredPeer, 0, len(o.Peers))
	for _, p := range o.Peers {
		if p.AllowedIPs == nil {
			return "", errNativeWorkerNetworkPreimage
		}
		ips := slices.Clone(p.AllowedIPs)
		sort.Strings(ips)
		peers = append(peers, configuredPeer{p.PublicKey, ips})
	}
	sort.Slice(peers, func(i, j int) bool { return peers[i].PublicKey < peers[j].PublicKey })
	v := struct {
		Floor                 CapacityNativeWorkerNetworkFloorFacts     `json:"floor"`
		NetworkTemplateSHA256 string                                    `json:"network_template_sha256"`
		MTU                   int                                       `json:"mtu"`
		Interface             CapacityNativeWorkerNetworkInterfaceFacts `json:"interface"`
		Peers                 []configuredPeer                          `json:"peers"`
		Routes                []CapacityNativeWorkerNetworkRouteFacts   `json:"routes"`
		Firewall              CapacityNativeWorkerNetworkFirewallFacts  `json:"firewall"`
		KernelSettings        CapacityNativeWorkerNetworkKernelSettings `json:"kernel_settings"`
	}{o.Floor, o.NetworkTemplateSHA256, o.MTU, o.Interface, peers, o.Routes, o.Firewall, o.KernelSettings}
	raw, e := json.Marshal(v)
	if e != nil {
		return "", errNativeWorkerNetworkPreimage
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}
