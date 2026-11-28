package nativeworkerprobe

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"net"
	"net/netip"
	"sync"
	"time"

	safego "github.com/dakasa-yggdrasil/yggdrasil-core/internal/goroutine"
	"golang.org/x/sys/unix"
)

type queuedPacket struct {
	raw  []byte
	addr netip.AddrPort
}

type batchState struct {
	report   BatchReport
	until    time.Time
	queued   map[string]queuedPacket
	requests map[string]bool
	echoes   map[string]bool
}

type engine struct {
	mu       sync.Mutex
	material *material
	udp      *net.UDPConn
	initial  batchState
	final    batchState
	changed  chan struct{}
	workers  sync.WaitGroup
	stop     context.CancelFunc
}

func emptyBatch() batchState {
	return batchState{report: BatchReport{State: "idle", Sent: []DatagramRecord{}, Received: []DatagramRecord{}, Echoed: []DatagramRecord{}}, queued: map[string]queuedPacket{}, requests: map[string]bool{}, echoes: map[string]bool{}}
}

func openUDP(c Config) (*net.UDPConn, error) {
	address := netip.AddrPortFrom(netip.MustParseAddr(c.Identity.PodIPv4), Port)
	conn, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(address))
	if err != nil {
		return nil, ErrUnavailable
	}
	raw, err := conn.SyscallConn()
	if err == nil {
		var optionErr error
		err = raw.Control(func(fd uintptr) {
			optionErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_DO)
			if optionErr == nil {
				var value int
				value, optionErr = unix.GetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_MTU_DISCOVER)
				if optionErr == nil && value != unix.IP_PMTUDISC_DO {
					optionErr = ErrUnavailable
				}
			}
		})
		if err == nil {
			err = optionErr
		}
	}
	if err != nil || conn.SetReadDeadline(c.HardNotAfter) != nil {
		_ = conn.Close()
		return nil, ErrUnavailable
	}
	return conn, nil
}

func newEngine(parent context.Context, m *material) (*engine, context.Context, error) {
	if parent == nil || parent.Err() != nil || m == nil || !time.Now().Before(m.config.HardNotAfter) {
		return nil, nil, ErrUnavailable
	}
	conn, err := openUDP(m.config)
	if err != nil {
		return nil, nil, err
	}
	ctx, cancel := context.WithDeadline(parent, m.config.HardNotAfter)
	e := &engine{material: m, udp: conn, initial: emptyBatch(), final: emptyBatch(), changed: make(chan struct{}, 1), stop: cancel}
	e.launch("native_probe_receive", func() { e.receive(ctx) })
	return e, ctx, nil
}

func (e *engine) launch(name string, run func()) {
	e.workers.Add(1)
	safego.SafeGo(name, func() {
		defer e.workers.Done()
		returned := false
		defer func() {
			if !returned {
				// Contain and redact even a panic value that embeds material.
				_ = recover()
				e.mu.Lock()
				e.failLocked(&e.initial, "internal_failure")
				e.failLocked(&e.final, "internal_failure")
				e.mu.Unlock()
				e.stop()
			}
		}()
		run()
		returned = true
	})
}

func (e *engine) batch(name string) *batchState {
	if name == "initial" {
		return &e.initial
	}
	return &e.final
}

func (e *engine) signal() {
	select {
	case e.changed <- struct{}{}:
	default:
	}
}

func (e *engine) failLocked(b *batchState, class string) {
	if b.report.State != "failed" && b.report.State != "unknown" {
		now := time.Now().UTC()
		b.report.State, b.report.ErrorClass, b.report.CompletedAt = "failed", class, &now
	}
	e.signal()
}

// The only send plans are compiled. Distinct sequences are planned probes,
// never transport retries; a failed/unknown write consumes its own slot.
func (e *engine) start(ctx context.Context, name string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	b := e.batch(name)
	if ctx.Err() != nil || !time.Now().Before(e.material.config.HardNotAfter) || b.report.State != "idle" || name == "final" && e.initial.report.State != "complete" {
		return false
	}
	now := time.Now().UTC()
	b.until = now.Add(BatchDeadline)
	if e.material.config.HardNotAfter.Before(b.until) {
		b.until = e.material.config.HardNotAfter
	}
	b.report.State, b.report.StartedAt = "running", &now
	e.launch("native_probe_batch", func() { e.runBatch(ctx, name) })
	return true
}

func record(raw []byte, address netip.AddrPort, now time.Time) DatagramRecord {
	batch, path := "initial", "pod"
	if raw[9] == 1 {
		batch = "final"
	}
	if raw[10] == 1 {
		path = "service"
	}
	return DatagramRecord{Batch: batch, Path: path, Sequence: int(raw[11]), PayloadBytes: len(raw), PayloadSHA256: sha(raw), Packet: append([]byte(nil), raw...), Address: address.String(), ObservedAt: now}
}

func packetKey(raw []byte) string { return string([]byte{raw[10], raw[11]}) }

func (e *engine) write(raw []byte, address netip.AddrPort, until time.Time) error {
	if !time.Now().Before(until) || e.udp.SetWriteDeadline(until) != nil {
		return ErrUnavailable
	}
	n, err := e.udp.WriteToUDPAddrPort(raw, address)
	if err != nil || n != PayloadBytes {
		return ErrUnavailable
	}
	return nil
}

func (e *engine) runBatch(parent context.Context, name string) {
	e.mu.Lock()
	b := e.batch(name)
	until := b.until
	queued := b.queued
	b.queued = map[string]queuedPacket{}
	e.mu.Unlock()
	ctx, cancel := context.WithDeadline(parent, until)
	defer cancel()
	for _, p := range queued {
		e.accept(p.raw, p.addr)
	}
	sequences := []int{0, 1}
	if name == "final" {
		sequences = []int{2}
	}
	for _, path := range []string{"pod", "service"} {
		for _, sequence := range sequences {
			target := e.material.config.Peer.PodIPv4
			if path == "service" {
				target = e.material.config.Peer.ServiceClusterIPv4
			}
			address := netip.AddrPortFrom(netip.MustParseAddr(target), Port)
			raw, err := makePacket(e.material.config, e.material.signing, name, path, sequence)
			if err == nil && ctx.Err() == nil {
				err = e.write(raw, address, until)
			}
			e.mu.Lock()
			if err != nil || ctx.Err() != nil || b.report.State != "running" {
				e.failLocked(b, "datagram_send_incomplete")
				e.mu.Unlock()
				return
			}
			b.report.Sent = append(b.report.Sent, record(raw, address, time.Now().UTC()))
			e.mu.Unlock()
		}
	}
	want := 2 * len(sequences)
	for {
		e.mu.Lock()
		if b.report.State != "running" {
			e.mu.Unlock()
			return
		}
		if len(b.requests) == want && len(b.echoes) == want && len(b.report.Echoed) == want && len(b.report.Sent) == want {
			now := time.Now().UTC()
			b.report.State, b.report.CompletedAt = "complete", &now
			e.mu.Unlock()
			return
		}
		e.mu.Unlock()
		select {
		case <-ctx.Done():
			e.mu.Lock()
			e.failLocked(b, "datagram_deadline")
			e.mu.Unlock()
			return
		case <-e.changed:
		}
	}
}

func (e *engine) accept(raw []byte, address netip.AddrPort) {
	if len(raw) != PayloadBytes || address.Port() != Port {
		return
	}
	echo := raw[packetKindIndex] == 1
	ownPublic := e.material.signing.Public().(ed25519.PublicKey)
	valid := VerifyPacket(raw, peerConfig(e.material.config), e.material.peer, ownPublic, false)
	if echo {
		valid = VerifyPacket(raw, e.material.config, ownPublic, e.material.peer, true)
	}
	if !valid {
		return
	}
	// ClusterIP reverse-SNAT may return a service-path echo from the exact
	// configured Service IP. Only its already verified echo/path may use that
	// address; requests and Pod-path echoes still require the peer Pod IP.
	peer := e.material.config.Peer
	if address.Addr().String() != peer.PodIPv4 && (!echo || raw[10] != 1 || address.Addr().String() != peer.ServiceClusterIPv4) {
		return
	}
	name := "initial"
	if raw[9] == 1 {
		name = "final"
	}
	e.mu.Lock()
	b := e.batch(name)
	key := packetKey(raw)
	if b.report.State == "idle" && !echo && (name == "initial" || e.initial.report.State == "complete") {
		if _, duplicate := b.queued[key]; duplicate {
			e.failLocked(b, "datagram_replay")
		} else {
			b.queued[key] = queuedPacket{append([]byte(nil), raw...), address}
		}
		e.mu.Unlock()
		return
	}
	if b.report.State != "running" || !time.Now().Before(b.until) {
		e.mu.Unlock()
		return
	}
	seen := b.requests
	if echo {
		seen = b.echoes
	}
	if seen[key] {
		e.failLocked(b, "datagram_replay")
		e.mu.Unlock()
		return
	}
	seen[key] = true
	b.report.Received = append(b.report.Received, record(raw, address, time.Now().UTC()))
	until := b.until
	e.mu.Unlock()
	if !echo {
		reply := echoPacket(raw, e.material.signing)
		err := e.write(reply, address, until)
		e.mu.Lock()
		if err != nil {
			e.failLocked(b, "echo_send_incomplete")
		} else {
			b.report.Echoed = append(b.report.Echoed, record(reply, address, time.Now().UTC()))
		}
		e.mu.Unlock()
	}
	e.signal()
}

func (e *engine) receive(ctx context.Context) {
	buf := make([]byte, PayloadBytes+1)
	for received := 0; received < 64 && ctx.Err() == nil; received++ {
		n, _, flags, from, err := e.udp.ReadMsgUDPAddrPort(buf, nil)
		if err != nil {
			return
		}
		if flags&unix.MSG_TRUNC != 0 || n != PayloadBytes {
			continue
		}
		e.accept(append([]byte(nil), buf[:n]...), from)
	}
	e.mu.Lock()
	e.failLocked(&e.initial, "receive_limit")
	e.failLocked(&e.final, "receive_limit")
	e.mu.Unlock()
}

func (e *engine) report(source string) Report {
	e.mu.Lock()
	defer e.mu.Unlock()
	clone := func(b BatchReport) BatchReport {
		copyRows := func(rows []DatagramRecord) []DatagramRecord {
			out := append([]DatagramRecord{}, rows...)
			for i := range out {
				out[i].Packet = append([]byte(nil), out[i].Packet...)
			}
			return out
		}
		b.Sent, b.Received, b.Echoed = copyRows(b.Sent), copyRows(b.Received), copyRows(b.Echoed)
		return b
	}
	return Report{Schema: ReportSchema, SourceCommit: source, ConfigSHA256: e.material.scope, Identity: e.material.config.Identity, ObservedAt: time.Now().UTC(), HardNotAfter: e.material.config.HardNotAfter, SigningPublicKey: base64.StdEncoding.EncodeToString(e.material.signing.Public().(ed25519.PublicKey)), Initial: clone(e.initial.report), Final: clone(e.final.report)}
}

func (e *engine) close() error {
	e.stop()
	err := e.udp.Close()
	e.workers.Wait()
	e.material.close()
	if err != nil {
		return ErrUnavailable
	}
	return nil
}
