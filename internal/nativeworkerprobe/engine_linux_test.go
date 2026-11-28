package nativeworkerprobe

import (
	"context"
	"crypto/ed25519"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Linux loopback aliases exercise the real DF socket and signed protocol, not
// a Kubernetes Service/overlay qualification. Only this unexported fixture maps
// both target paths to the same peer socket; the production loader rejects it.
func enginePair(t *testing.T) (*engine, *engine, context.Context) {
	t.Helper()
	c := testConfig("floor")
	c.Identity.PodIPv4, c.Identity.ServiceClusterIPv4 = "127.0.0.2", "127.0.0.2"
	c.Peer.PodIPv4, c.Peer.ServiceClusterIPv4 = "127.0.0.3", "127.0.0.3"
	c.HardNotAfter = time.Now().Add(4 * time.Second)
	p := peerConfig(c)
	pub, key := packetKeys(t)
	peerPub, peerKey := packetKeys(t)
	ctx, cancel := context.WithCancel(context.Background())
	a, ac, err := newEngine(ctx, &material{config: c, scope: "scope-floor", signing: key, peer: peerPub})
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	b, _, err := newEngine(ctx, &material{config: p, scope: "scope-candidate", signing: peerKey, peer: pub})
	if err != nil {
		_ = a.close()
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		if err := a.close(); err != nil {
			t.Error("floor socket close", err)
		}
		if err := b.close(); err != nil {
			t.Error("candidate socket close", err)
		}
	})
	return a, b, ac
}

func waitProbeBatch(t *testing.T, e *engine, name, want string) BatchReport {
	t.Helper()
	until := time.Now().Add(5 * time.Second)
	for time.Now().Before(until) {
		r := e.report(fixtureSource)
		b := r.Initial
		if name == "final" {
			b = r.Final
		}
		if b.State == want {
			return b
		}
		if b.State == "failed" || b.State == "unknown" {
			t.Fatalf("batch %s became %s (%s), wanted %s", name, b.State, b.ErrorClass, want)
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("batch did not reach", name, want)
	return BatchReport{}
}

func TestProbeActualDFUDPCompletesOnlyTwoFiniteBatchesWithoutReplay(t *testing.T) {
	a, b, ctx := enginePair(t)
	for _, e := range []*engine{a, b} {
		raw, err := e.udp.SyscallConn()
		if err != nil {
			t.Fatal(err)
		}
		value := 0
		var optionErr error
		if err = raw.Control(func(fd uintptr) {
			value, optionErr = unix.GetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_MTU_DISCOVER)
		}); err != nil || optionErr != nil || value != unix.IP_PMTUDISC_DO {
			t.Fatal("actual socket did not enforce IPv4 DF", err, optionErr, value)
		}
		if e.start(ctx, "final") {
			t.Fatal("final started before initial")
		}
	}
	for _, phase := range []struct {
		name string
		want int
	}{{"initial", 4}, {"final", 2}} {
		if !a.start(ctx, phase.name) || !b.start(ctx, phase.name) {
			t.Fatal("fixed batch refused", phase.name)
		}
		for _, e := range []*engine{a, b} {
			r := waitProbeBatch(t, e, phase.name, "complete")
			if len(r.Sent) != phase.want || len(r.Echoed) != phase.want || len(r.Received) != 2*phase.want || r.StartedAt == nil || r.CompletedAt == nil {
				t.Fatal("incomplete original send/echo ledger", phase.name, len(r.Sent), len(r.Echoed), len(r.Received))
			}
			peer := peerConfig(e.material.config)
			for _, row := range r.Received {
				request := row.Packet[packetKindIndex] == 0
				config, sender, echoer := e.material.config, e.material.signing.Public().(ed25519.PublicKey), e.material.peer
				if request {
					config, sender, echoer = peer, e.material.peer, nil
				}
				if row.PayloadBytes != 1302 || row.PayloadSHA256 != sha(row.Packet) || !VerifyPacket(row.Packet, config, sender, echoer, !request) {
					t.Fatal("reported original evidence cannot be verified")
				}
			}
			if e.start(ctx, phase.name) {
				t.Fatal("a second batch was allowed")
			}
			// A returned report is a copy, not a handle on the original ledger.
			r.Sent[0].Packet[0] ^= 1
			fresh := e.report(fixtureSource).Initial
			if phase.name == "final" {
				fresh = e.report(fixtureSource).Final
			}
			if fresh.Sent[0].Packet[0] != packetMagic[0] {
				t.Fatal("caller mutated original evidence")
			}
		}
	}
	for _, e := range []*engine{a, b} {
		r := e.report(fixtureSource)
		if len(r.Initial.Sent)+len(r.Final.Sent) != 6 || len(r.Initial.Echoed)+len(r.Final.Echoed) != 6 {
			t.Fatal("run exceeded six sends and six echoes per Pod")
		}
		before := len(r.Initial.Received)
		e.accept(r.Initial.Received[0].Packet, netip.MustParseAddrPort(e.material.config.Peer.PodIPv4+":9446"))
		if len(e.report(fixtureSource).Initial.Received) != before || e.start(ctx, "initial") || e.start(ctx, "final") {
			t.Fatal("completed run replayed")
		}
	}
}

func TestProbeUnstartedPeerCanQueueButCannotEchoAndReplayConsumesRun(t *testing.T) {
	a, _, ctx := enginePair(t)
	peer := peerConfig(a.material.config)
	_, peerKey := packetKeys(t)
	a.material.peer = peerKey.Public().(ed25519.PublicKey)
	raw, err := makePacket(peer, peerKey, "initial", "pod", 0)
	if err != nil {
		t.Fatal(err)
	}
	address := netip.MustParseAddrPort(peer.Identity.PodIPv4 + ":9446")
	a.accept(raw, netip.MustParseAddrPort("127.0.0.4:9446"))
	if len(a.initial.queued) != 0 {
		t.Fatal("authenticated packet from wrong actual source queued")
	}
	a.accept(raw, address)
	if len(a.initial.queued) != 1 || len(a.report(fixtureSource).Initial.Echoed) != 0 {
		t.Fatal("request before authenticated POST caused an echo")
	}
	a.accept(raw, address)
	if a.report(fixtureSource).Initial.State != "failed" || a.start(ctx, "initial") || a.start(ctx, "final") {
		t.Fatal("duplicate request regained one-shot permission")
	}
}

func TestProbeIncompleteSendCannotRetryOrOpenFinal(t *testing.T) {
	a, _, ctx := enginePair(t)
	// A canceled parent forbids the first emission, without turning cancellation
	// into a new run or moving the configured hardNotAfter.
	closed, cancel := context.WithCancel(ctx)
	cancel()
	if a.start(closed, "initial") || len(a.report(fixtureSource).Initial.Sent) != 0 {
		t.Fatal("canceled invocation emitted")
	}
	a.material.config.HardNotAfter = time.Now().Add(200 * time.Millisecond)
	if !a.start(ctx, "initial") {
		t.Fatal("first finite invocation refused")
	}
	r := waitProbeBatch(t, a, "initial", "failed")
	if r.ErrorClass != "datagram_deadline" || len(r.Sent) != 4 || len(r.Echoed) != 0 || a.start(ctx, "initial") || a.start(ctx, "final") {
		t.Fatal("incomplete original exchange retried or opened final", r.State, r.ErrorClass)
	}
}
