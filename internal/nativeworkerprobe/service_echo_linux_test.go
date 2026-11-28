package nativeworkerprobe

import (
	"crypto/ed25519"
	"net"
	"net/netip"
	"testing"
	"time"
)

// Selection fixtures use no socket. The explicit loopback request case below
// verifies an observed-port reply only; neither substitutes for actual Service
// NAT qualification with the normal agent in the separate tagged Kind case.
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
		{"nat_service_request_wrong_ip", "service", "10.89.0.4:7163", false, false, false},
		{"nat_service_request_wrong_mac", "service", "10.89.0.3:7163", false, true, false},
		{"nat_service_request_port_zero", "service", "10.89.0.3:0", false, false, false},
		{"nat_pod_request_refused", "pod", "10.89.0.3:7163", false, false, false},
		{"nat_service_echo_pod_ip_refused", "service", "10.89.0.3:7163", true, false, false},
		{"nat_service_echo_service_ip_refused", "service", "10.90.0.3:61883", true, false, false},
	} {
		t.Run(item.name, func(t *testing.T) {
			e, raw := serviceEchoFixture(t, item.path, item.echo)
			if item.tamper {
				at := len(raw) - 1
				if !item.echo {
					at = packetBodyEnd
				}
				raw[at] ^= 1
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

func TestProbeSignedServiceRequestEchoesExactObservedNATPortWithoutReplay(t *testing.T) {
	for _, port := range []uint16{7163, 61883} {
		t.Run(netip.AddrPortFrom(netip.MustParseAddr("127.0.0.3"), port).String(), func(t *testing.T) {
			c := testConfig("floor")
			c.Identity.PodIPv4, c.Identity.ServiceClusterIPv4 = "127.0.0.2", "127.0.0.4"
			c.Peer.PodIPv4, c.Peer.ServiceClusterIPv4 = "127.0.0.3", "127.0.0.5"
			_, own := packetKeys(t)
			peerPublic, peer := packetKeys(t)
			t.Cleanup(func() { wipe(own); wipe(peer) })
			socket, err := openUDP(c)
			if err != nil {
				t.Fatal("fixed DF socket unavailable", err)
			}
			t.Cleanup(func() { _ = socket.Close() })
			translated := netip.AddrPortFrom(netip.MustParseAddr(c.Peer.PodIPv4), port)
			requester, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(translated))
			if err != nil {
				t.Fatal("explicit CI translated-port socket unavailable", err)
			}
			t.Cleanup(func() { _ = requester.Close() })
			e := &engine{material: &material{config: c, signing: own, peer: peerPublic}, udp: socket, initial: emptyBatch(), final: emptyBatch(), changed: make(chan struct{}, 1)}
			e.initial.report.State, e.initial.until = "running", time.Now().Add(time.Second)
			raw, err := makePacket(peerConfig(c), peer, "initial", "service", 0)
			if err != nil {
				t.Fatal(err)
			}
			if n, err := requester.WriteToUDPAddrPort(raw, netip.AddrPortFrom(netip.MustParseAddr(c.Identity.PodIPv4), Port)); err != nil || n != PayloadBytes {
				t.Fatal("original loopback request incomplete", err)
			}
			if socket.SetReadDeadline(time.Now().Add(time.Second)) != nil {
				t.Fatal("bounded original request read refused")
			}
			buf := make([]byte, PayloadBytes+1)
			n, actual, err := socket.ReadFromUDPAddrPort(buf)
			if err != nil || n != PayloadBytes || actual != translated {
				t.Fatal("actual received source was not the explicit translated port", err)
			}
			e.accept(buf[:n], actual)
			if requester.SetReadDeadline(time.Now().Add(time.Second)) != nil {
				t.Fatal("bounded original echo read refused")
			}
			n, echoSource, err := requester.ReadFromUDPAddrPort(buf)
			if err != nil || n != PayloadBytes || echoSource != netip.AddrPortFrom(netip.MustParseAddr(c.Identity.PodIPv4), Port) || !VerifyPacket(buf[:n], peerConfig(c), peerPublic, own.Public().(ed25519.PublicKey), true) {
				t.Fatal("signed echo did not return to the exact observed port", err)
			}
			b := e.initial.report
			if len(b.Received) != 1 || len(b.Echoed) != 1 || len(b.Sent) != 0 || b.Received[0].Address != actual.String() || b.Echoed[0].Address != b.Received[0].Address || b.Received[0].Path != "service" || b.Echoed[0].Path != "service" || b.Received[0].Sequence != b.Echoed[0].Sequence || b.Received[0].PayloadSHA256 != sha(raw) {
				t.Fatal("echo normalized the actual address or changed its signed slot")
			}
			// A second transport spelling is still the same logical request.
			e.accept(raw, netip.AddrPortFrom(netip.MustParseAddr(c.Peer.PodIPv4), Port))
			if e.initial.report.State != "failed" || e.initial.report.ErrorClass != "datagram_replay" || len(e.initial.report.Received) != 1 || len(e.initial.report.Echoed) != 1 || len(e.initial.report.Sent) != 0 {
				t.Fatal("translated-port alias replenished a request or echo slot")
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
