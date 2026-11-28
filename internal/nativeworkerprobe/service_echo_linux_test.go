package nativeworkerprobe

import (
	"crypto/ed25519"
	"net/netip"
	"testing"
	"time"
)

// These selection tests use no socket and are not Service/NAT qualification.
// The separate tagged Kind case runs the unchanged normal agent in real Pods.
func serviceEchoFixture(t *testing.T, path string, echo bool) (*engine, []byte) {
	t.Helper()
	c := testConfig("floor")
	public, own := packetKeys(t)
	peerPublic, peer := packetKeys(t)
	t.Cleanup(func() { wipe(own); wipe(peer) })
	m := &material{config: c, signing: own, peer: peerPublic}
	e := &engine{material: m, initial: emptyBatch(), final: emptyBatch(), changed: make(chan struct{}, 1)}
	e.initial.report.State, e.initial.until = "running", time.Now().Add(time.Second)
	config, signer := peerConfig(c), peer
	if echo {
		config, signer = c, own
	}
	raw, err := makePacket(config, signer, "initial", path, 0)
	if err != nil {
		t.Fatal(err)
	}
	if echo {
		raw = echoPacket(raw, peer)
		if !VerifyPacket(raw, c, public, peerPublic, true) {
			t.Fatal("original signed echo fixture invalid")
		}
	}
	return e, raw
}

func TestProbeServiceEchoAcceptsOnlySignedExactServiceOrPodSource(t *testing.T) {
	for _, item := range []struct {
		name, path, source     string
		echo, tamper, accepted bool
	}{
		{"service_reverse_snat", "service", "10.90.0.3:9446", true, false, true},
		{"service_direct_return", "service", "10.89.0.3:9446", true, false, true},
		{"pod_original", "pod", "10.89.0.3:9446", true, false, true},
		{"pod_cannot_claim_service", "pod", "10.90.0.3:9446", true, false, false},
		{"foreign_echo", "service", "10.90.0.4:9446", true, false, false},
		{"wrong_port", "service", "10.90.0.3:9447", true, false, false},
		{"forged_service_echo", "service", "10.90.0.3:9446", true, true, false},
		{"service_request_cannot_claim_service", "service", "10.90.0.3:9446", false, false, false},
		{"pod_request_cannot_claim_service", "pod", "10.90.0.3:9446", false, false, false},
	} {
		t.Run(item.name, func(t *testing.T) {
			e, raw := serviceEchoFixture(t, item.path, item.echo)
			if item.tamper {
				raw[len(raw)-1] ^= 1
			}
			e.accept(raw, netip.MustParseAddrPort(item.source))
			if got := len(e.initial.report.Received); (got == 1) != item.accepted || got > 1 || len(e.initial.report.Sent) != 0 || len(e.initial.report.Echoed) != 0 {
				t.Fatal("source/signature selection changed send budget", got)
			}
			if item.accepted {
				r := e.initial.report.Received[0]
				if r.Address != item.source || r.Path != item.path || r.PayloadBytes != PayloadBytes || r.PayloadSHA256 != sha(raw) {
					t.Fatal("actual transport source or signed path was rewritten")
				}
			}
		})
	}
}

func TestProbeServiceEchoPreservesSignedPathAndConsumesReplay(t *testing.T) {
	e, raw := serviceEchoFixture(t, "service", true)
	bad := append([]byte(nil), raw...)
	bad[10] = 0
	e.accept(bad, netip.MustParseAddrPort(e.material.config.Peer.ServiceClusterIPv4+":9446"))
	if len(e.initial.report.Received) != 0 {
		t.Fatal("record path substitution bypassed signature")
	}
	service := netip.MustParseAddrPort(e.material.config.Peer.ServiceClusterIPv4 + ":9446")
	e.accept(raw, service)
	if len(e.initial.report.Received) != 1 || e.initial.report.State != "running" {
		t.Fatal("original service echo refused")
	}
	// A second permitted transport spelling is not another logical echo slot.
	e.accept(raw, netip.MustParseAddrPort(e.material.config.Peer.PodIPv4+":9446"))
	if e.initial.report.State != "failed" || e.initial.report.ErrorClass != "datagram_replay" || len(e.initial.report.Received) != 1 || len(e.initial.report.Sent) != 0 || len(e.initial.report.Echoed) != 0 {
		t.Fatal("source alias replenished one-shot echo slot")
	}
	if !VerifyPacket(e.initial.report.Received[0].Packet, e.material.config, e.material.signing.Public().(ed25519.PublicKey), e.material.peer, true) {
		t.Fatal("original packet bytes changed")
	}
}
