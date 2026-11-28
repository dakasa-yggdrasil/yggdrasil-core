package repository

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/nativeworkerprobe"
	"github.com/google/uuid"
)

func nativeReadinessEvidenceFixture(role string) (nativeworkerprobe.Config, nativeReadinessRun, ed25519.PrivateKey, ed25519.PrivateKey, time.Time) {
	created := time.Date(2026, 11, 28, 6, 0, 0, 0, time.UTC)
	run := nativeReadinessRun{ID: uuid.MustParse("12345678-1234-4234-8234-123456789abc"), CreatedAt: created, NotAfter: created.Add(90 * time.Second), Identity: nativeReadinessRunIdentity{AttemptID: uuid.MustParse("23456789-2345-4345-8345-23456789abcd"), BirthSHA256: strings.Repeat("a", 64), SourceCommit: strings.Repeat("b", 40), PoolUID: "34567890-3456-4456-8456-34567890abcd", Namespace: "probe-space", NodeUID: "45678901-4567-4567-8567-45678901abcd"}}
	c := nativeworkerprobe.Config{Schema: nativeworkerprobe.ConfigSchema, SourceCommit: run.Identity.SourceCommit, NotBefore: created, HardNotAfter: run.NotAfter, Nonce: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)), Identity: nativeworkerprobe.Identity{RunID: run.ID.String(), AttemptID: run.Identity.AttemptID.String(), BirthSHA256: run.Identity.BirthSHA256, PoolUID: run.Identity.PoolUID, Role: "candidate", Namespace: run.Identity.Namespace, NamespaceUID: uuid.NewString(), PodName: "candidate", PodUID: uuid.NewString(), PodIPv4: "172.29.1.2", NodeName: "candidate-node", NodeUID: run.Identity.NodeUID, ServiceUID: uuid.NewString(), ServiceClusterIPv4: "172.30.1.2"}, Peer: nativeworkerprobe.Peer{PodUID: uuid.NewString(), NodeUID: uuid.NewString(), PodIPv4: "172.29.2.2", ServiceUID: uuid.NewString(), ServiceClusterIPv4: "172.30.2.2"}, Startup: &nativeworkerprobe.StartupConfig{CoreSourceCommit: run.Identity.SourceCommit, ImageDigest: "sha256:" + strings.Repeat("c", 64), WorkloadUID: "unused-in-packet", ContainerName: "core", LaneRosterSHA256: strings.Repeat("d", 64)}}
	if role == "floor" {
		c = nativeReadinessEvidencePeer(c)
		c.Startup = nil
	}
	return c, run, ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, 32)), ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, 32)), created.Add(6 * time.Second)
}

func nativeReadinessEvidencePeer(c nativeworkerprobe.Config) nativeworkerprobe.Config {
	o := c
	o.Identity.PodUID, o.Identity.NodeUID = c.Peer.PodUID, c.Peer.NodeUID
	o.Identity.PodIPv4 = c.Peer.PodIPv4
	o.Identity.ServiceUID, o.Identity.ServiceClusterIPv4 = c.Peer.ServiceUID, c.Peer.ServiceClusterIPv4
	if c.Identity.Role == "floor" {
		o.Identity.Role = "candidate"
	} else {
		o.Identity.Role = "floor"
	}
	o.Peer = nativeworkerprobe.Peer{PodUID: c.Identity.PodUID, NodeUID: c.Identity.NodeUID, PodIPv4: c.Identity.PodIPv4, ServiceUID: c.Identity.ServiceUID, ServiceClusterIPv4: c.Identity.ServiceClusterIPv4}
	return o
}

// Encode public v1 wire vectors independently of the controller predicates.
// VerifyPacket from the actual agent owns canonical body/signature validation.
// These unit vectors do not qualify a live overlay, Service or DF path.
func nativeReadinessEvidencePacket(t *testing.T, c nativeworkerprobe.Config, key, echoKey ed25519.PrivateKey, batch, path string, sequence int, echo bool) []byte {
	t.Helper()
	raw := make([]byte, nativeworkerprobe.PayloadBytes)
	copy(raw, []byte{'D', 'K', 'N', 'W', 'P', '0', '1', 0})
	if batch == "final" {
		raw[9] = 1
	}
	if path == "service" {
		raw[10] = 1
	}
	raw[11] = byte(sequence)
	if c.Identity.Role == "candidate" {
		raw[12] = 1
	}
	for _, p := range []struct {
		offset int
		id     string
	}{{16, c.Identity.RunID}, {32, c.Identity.AttemptID}, {112, c.Identity.PodUID}, {128, c.Identity.NodeUID}, {144, c.Peer.PodUID}, {160, c.Peer.NodeUID}, {216, c.Identity.PoolUID}, {232, c.Identity.NamespaceUID}} {
		id := uuid.MustParse(p.id)
		copy(raw[p.offset:p.offset+16], id[:])
	}
	birth, _ := hex.DecodeString(c.Identity.BirthSHA256)
	copy(raw[48:80], birth)
	nonce, _ := base64.StdEncoding.DecodeString(c.Nonce)
	copy(raw[80:112], nonce)
	target := c.Peer.PodIPv4
	if path == "service" {
		id := uuid.MustParse(c.Peer.ServiceUID)
		copy(raw[176:192], id[:])
		target = c.Peer.ServiceClusterIPv4
	}
	ip := netip.MustParseAddr(target).As4()
	copy(raw[192:196], ip[:])
	source, _ := hex.DecodeString(c.SourceCommit)
	copy(raw[196:216], source)
	end := len(raw) - 2*ed25519.SignatureSize
	copy(raw[end:end+ed25519.SignatureSize], ed25519.Sign(key, raw[:end]))
	if echo {
		raw[8] = 1
		copy(raw[len(raw)-ed25519.SignatureSize:], ed25519.Sign(echoKey, raw[:len(raw)-ed25519.SignatureSize]))
	}
	if !nativeworkerprobe.VerifyPacket(raw, c, key.Public().(ed25519.PublicKey), echoKey.Public().(ed25519.PublicKey), echo) {
		t.Fatal("public wire vector differs from actual agent ABI")
	}
	return raw
}

func nativeReadinessEvidenceBatch(t *testing.T, c nativeworkerprobe.Config, own, peer ed25519.PrivateKey, batch string, r nativeReadinessRun) nativeworkerprobe.BatchReport {
	t.Helper()
	start, end := r.CreatedAt.Add(time.Second), r.CreatedAt.Add(2*time.Second)
	seq := []int{0, 1}
	if batch == "final" {
		seq = []int{2}
		start, end = r.CreatedAt.Add(3*time.Second), r.CreatedAt.Add(4*time.Second)
	}
	b := nativeworkerprobe.BatchReport{State: "complete", StartedAt: &start, CompletedAt: &end}
	remote := nativeReadinessEvidencePeer(c)
	row := func(raw []byte, path string, n int, address string) nativeworkerprobe.DatagramRecord {
		h := sha256.Sum256(raw)
		return nativeworkerprobe.DatagramRecord{Batch: batch, Path: path, Sequence: n, PayloadBytes: len(raw), PayloadSHA256: hex.EncodeToString(h[:]), Packet: raw, Address: address + ":9446", ObservedAt: start.Add(time.Millisecond)}
	}
	for _, path := range []string{"pod", "service"} {
		for _, n := range seq {
			to := c.Peer.PodIPv4
			if path == "service" {
				to = c.Peer.ServiceClusterIPv4
			}
			b.Sent = append(b.Sent, row(nativeReadinessEvidencePacket(t, c, own, peer, batch, path, n, false), path, n, to))
			b.Received = append(b.Received, row(nativeReadinessEvidencePacket(t, remote, peer, own, batch, path, n, false), path, n, c.Peer.PodIPv4))
			b.Received = append(b.Received, row(nativeReadinessEvidencePacket(t, c, own, peer, batch, path, n, true), path, n, to))
			b.Echoed = append(b.Echoed, row(nativeReadinessEvidencePacket(t, remote, peer, own, batch, path, n, true), path, n, c.Peer.PodIPv4))
		}
	}
	return b
}

func TestNativeReadinessEvidenceChecksActualRequestAndEchoDirections(t *testing.T) {
	sent, echoed, received := 0, 0, 0
	for _, role := range []string{"floor", "candidate"} {
		c, r, own, peer, now := nativeReadinessEvidenceFixture(role)
		for _, batch := range []string{"initial", "final"} {
			b := nativeReadinessEvidenceBatch(t, c, own, peer, batch, r)
			if !nativeReadinessPacketBatch(c, own.Public().(ed25519.PublicKey), peer.Public().(ed25519.PublicKey), b, batch, r, now) {
				t.Fatal("actual8/4received directional semantics rejected", role, batch)
			}
			sent += len(b.Sent)
			echoed += len(b.Echoed)
			received += len(b.Received)
		}
	}
	if sent != 12 || echoed != 12 || received != 24 {
		t.Fatal("finite global protocol envelope changed", sent, echoed, received)
	}
}

func TestNativeReadinessEvidenceServiceNATPairsOnlyOriginalSignedRequestReturn(t *testing.T) {
	for _, role := range []string{"floor", "candidate"} {
		for _, batch := range []string{"initial", "final"} {
			t.Run(role+"/"+batch, func(t *testing.T) {
				c, r, own, peer, now := nativeReadinessEvidenceFixture(role)
				translated := func() nativeworkerprobe.BatchReport {
					b := nativeReadinessEvidenceBatch(t, c, own, peer, batch, r)
					port := func(sequence int) string {
						if sequence%2 == 0 {
							return "7163"
						}
						return "61883"
					}
					for i := range b.Received {
						x := &b.Received[i]
						if x.Path == "service" && x.Packet[8] == 0 {
							x.Address = c.Peer.PodIPv4 + ":" + port(x.Sequence)
						}
					}
					for i := range b.Echoed {
						x := &b.Echoed[i]
						if x.Path == "service" {
							x.Address = c.Peer.PodIPv4 + ":" + port(x.Sequence)
						}
					}
					return b
				}
				valid := func(b nativeworkerprobe.BatchReport) bool {
					return nativeReadinessPacketBatch(c, own.Public().(ed25519.PublicKey), peer.Public().(ed25519.PublicKey), b, batch, r, now)
				}
				if !valid(translated()) {
					t.Fatal("signed Service request and exact observed NAT return address refused")
				}
				for _, fault := range []string{"zero_port", "noncanonical_port", "foreign_ip", "service_ip_request", "pod_request_port", "pod_echo_port", "service_echo_port", "unpaired_return", "swapped_return", "early_echo", "request_signature", "echo_signature"} {
					t.Run(fault, func(t *testing.T) {
						b := translated()
						request, reply := -1, -1
						for i, x := range b.Received {
							if x.Path == "service" && x.Packet[8] == 0 {
								request = i
								break
							}
						}
						if request < 0 {
							t.Fatal("fixture lacks original signed Service request")
						}
						for i, x := range b.Echoed {
							if x.Path == "service" && x.Sequence == b.Received[request].Sequence {
								reply = i
								break
							}
						}
						if reply < 0 {
							t.Fatal("fixture lacks original signed Service request and echo")
						}
						switch fault {
						case "zero_port", "noncanonical_port", "foreign_ip", "service_ip_request":
							address := map[string]string{"zero_port": c.Peer.PodIPv4 + ":0", "noncanonical_port": c.Peer.PodIPv4 + ":07163", "foreign_ip": "192.0.2.9:7163", "service_ip_request": c.Peer.ServiceClusterIPv4 + ":7163"}[fault]
							b.Received[request].Address, b.Echoed[reply].Address = address, address
						case "pod_request_port":
							b.Received[0].Address, b.Echoed[0].Address = c.Peer.PodIPv4+":7163", c.Peer.PodIPv4+":7163"
						case "pod_echo_port":
							b.Received[1].Address = c.Peer.PodIPv4 + ":7163"
						case "service_echo_port":
							b.Received[request+1].Address = c.Peer.ServiceClusterIPv4 + ":7163"
						case "unpaired_return":
							b.Echoed[reply].Address = c.Peer.PodIPv4 + ":9446"
						case "swapped_return":
							b.Echoed[reply].Address = c.Peer.PodIPv4 + ":61883"
						case "early_echo":
							b.Echoed[reply].ObservedAt = b.Received[request].ObservedAt.Add(-time.Nanosecond)
						case "request_signature", "echo_signature":
							x := &b.Received[request]
							offset := len(x.Packet) - 100
							if fault == "echo_signature" {
								x = &b.Echoed[reply]
								offset = len(x.Packet) - 1
							}
							x.Packet[offset] ^= 1
							h := sha256.Sum256(x.Packet)
							x.PayloadSHA256 = hex.EncodeToString(h[:])
						}
						if valid(b) {
							t.Fatal("NAT address claim escaped its signed original request", fault)
						}
					})
				}
			})
		}
	}
}

func TestNativeReadinessEvidenceRefusesCoherentRecordClaimsWithoutMatchingWire(t *testing.T) {
	for _, mode := range []string{"duplicate_sequence", "path_claim", "batch_claim", "hash", "signature", "foreign_address", "service_origin_request", "service_origin_pod_echo", "missing_echo", "extra_request", "foreign_run", "expired"} {
		t.Run(mode, func(t *testing.T) {
			c, r, own, peer, now := nativeReadinessEvidenceFixture("candidate")
			b := nativeReadinessEvidenceBatch(t, c, own, peer, "initial", r)
			switch mode {
			case "duplicate_sequence":
				b.Sent[1] = b.Sent[0]
			case "path_claim":
				b.Sent[0].Path = "service"
			case "batch_claim":
				b.Sent[0].Batch = "final"
			case "hash":
				b.Sent[0].PayloadSHA256 = strings.Repeat("f", 64)
			case "signature":
				b.Sent[0].Packet[len(b.Sent[0].Packet)-100] ^= 1
				h := sha256.Sum256(b.Sent[0].Packet)
				b.Sent[0].PayloadSHA256 = hex.EncodeToString(h[:])
			case "foreign_address":
				b.Received[1].Address = "192.0.2.9:9446"
			case "service_origin_request":
				b.Received[0].Address = c.Peer.ServiceClusterIPv4 + ":9446"
			case "service_origin_pod_echo":
				b.Received[1].Address = c.Peer.ServiceClusterIPv4 + ":9446"
			case "missing_echo":
				b.Received = b.Received[:len(b.Received)-1]
			case "extra_request":
				b.Sent = append(b.Sent, b.Sent[0])
			case "foreign_run":
				r.Identity.BirthSHA256 = strings.Repeat("1", 64)
			case "expired":
				now = r.NotAfter
			}
			if nativeReadinessPacketBatch(c, own.Public().(ed25519.PublicKey), peer.Public().(ed25519.PublicKey), b, "initial", r, now) {
				t.Fatal("record claim acquired network evidence", mode)
			}
		})
	}
}

func TestNativeReadinessEvidenceReportPinsOwnSigningKeyAndFinalOrder(t *testing.T) {
	c, r, own, peer, now := nativeReadinessEvidenceFixture("candidate")
	scope := strings.Repeat("e", 64)
	report := nativeworkerprobe.Report{Schema: nativeworkerprobe.ReportSchema, SourceCommit: c.SourceCommit, ConfigSHA256: scope, Identity: c.Identity, HardNotAfter: r.NotAfter, SigningPublicKey: base64.StdEncoding.EncodeToString(own.Public().(ed25519.PublicKey)), ObservedAt: r.CreatedAt.Add(5 * time.Second), Initial: nativeReadinessEvidenceBatch(t, c, own, peer, "initial", r), Final: nativeReadinessEvidenceBatch(t, c, own, peer, "final", r)}
	if !nativeReadinessReport(c, scope, report, own.Public().(ed25519.PublicKey), peer.Public().(ed25519.PublicKey), r, true, now) {
		t.Fatal("complete two-batch report refused")
	}
	for _, mode := range []string{"key", "scope", "identity", "stale", "final_order", "unexpected_idle"} {
		t.Run(mode, func(t *testing.T) {
			raw, _ := json.Marshal(report)
			var changed nativeworkerprobe.Report
			_ = json.Unmarshal(raw, &changed)
			final := true
			switch mode {
			case "key":
				changed.SigningPublicKey = base64.StdEncoding.EncodeToString(peer.Public().(ed25519.PublicKey))
			case "scope":
				changed.ConfigSHA256 = strings.Repeat("f", 64)
			case "identity":
				changed.Identity.PodUID = uuid.NewString()
			case "stale":
				changed.ObservedAt = now.Add(-5 * time.Second)
			case "final_order":
				tm := r.CreatedAt
				changed.Final.StartedAt = &tm
			case "unexpected_idle":
				final = false
				changed.Final.State = "idle"
			}
			if nativeReadinessReport(c, scope, changed, own.Public().(ed25519.PublicKey), peer.Public().(ed25519.PublicKey), r, final, now) {
				t.Fatal("invalid report accepted", mode)
			}
		})
	}
	report.Final = nativeworkerprobe.BatchReport{State: "idle"}
	if !nativeReadinessReport(c, scope, report, own.Public().(ed25519.PublicKey), peer.Public().(ed25519.PublicKey), r, false, now) {
		t.Fatal("first observation requires fabricated final batch")
	}
}

func TestNativeReadinessEvidenceStartupRetainsProcessOriginAndRealReadiness(t *testing.T) {
	c, r, _, _, now := nativeReadinessEvidenceFixture("candidate")
	scope := strings.Repeat("f", 64)
	s := nativeworkerprobe.StartupInspection{Schema: nativeworkerprobe.StartupSchema, SourceCommit: c.SourceCommit, ConfigSHA256: scope, Identity: c.Identity, ObservedAt: now.Add(-time.Second), AdmissionHTTPStatus: 200, AdmissionState: "waiting_projection", AdmissionObservedAt: now.Add(-2 * time.Second), ImageDigest: c.Startup.ImageDigest, LaneRosterSHA256: c.Startup.LaneRosterSHA256, ProcessNonce: uuid.NewString(), ReadyHTTPStatus: 503, ErrorClass: "startup_pending"}
	if !nativeReadinessStartup(c, scope, s, r, false, now) || nativeReadinessStartup(c, scope, s, r, true, now) {
		t.Fatal("pending process origin confused with readiness")
	}
	ready := s
	ready.AdmissionState = "roots_open"
	ready.ChallengeSHA256 = strings.Repeat("1", 64)
	ready.ReadyHTTPStatus = 200
	ready.ReadyStatus = "ready"
	ready.RabbitMQStatus = "ok"
	ready.ErrorClass = ""
	if !nativeReadinessStartup(c, scope, ready, r, true, now) || !nativeReadinessSameStartup(s, ready) {
		t.Fatal("same observed process cannot progress to readiness")
	}
	for i, mode := range []string{"nonce", "source", "broker", "challenge", "clock", "role"} {
		t.Run(mode, func(t *testing.T) {
			changed := ready
			config := c
			switch mode {
			case "nonce":
				changed.ProcessNonce = "invalid-" + strconv.Itoa(i)
			case "source":
				changed.SourceCommit = strings.Repeat("2", 40)
			case "broker":
				changed.RabbitMQStatus = "degraded"
			case "challenge":
				changed.ChallengeSHA256 = ""
			case "clock":
				changed.AdmissionObservedAt = changed.ObservedAt.Add(time.Second)
			case "role":
				config.Identity.Role = "floor"
			}
			if nativeReadinessStartup(config, scope, changed, r, true, now) {
				t.Fatal("unqualified startup accepted")
			}
		})
	}
	restarted := ready
	restarted.ProcessNonce = uuid.NewString()
	if nativeReadinessSameStartup(s, restarted) {
		t.Fatal("restarted process borrowed predecessor startup")
	}
}
