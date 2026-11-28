package repository

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net"
	"net/netip"
	"strconv"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/nativeworkerprobe"
)

func nativeReadinessProbeContext(c nativeworkerprobe.Config, r nativeReadinessRun, now time.Time) bool {
	if r.ID.String() != c.Identity.RunID || r.Identity.AttemptID.String() != c.Identity.AttemptID || r.Identity.BirthSHA256 != c.Identity.BirthSHA256 || r.Identity.PoolUID != c.Identity.PoolUID || r.Identity.Namespace != c.Identity.Namespace || r.Identity.SourceCommit != c.SourceCommit || !nativeReadinessCanonicalUUID(c.Identity.RunID) || !nativeReadinessCanonicalUUID(c.Identity.AttemptID) || !nativeReadinessSHA(c.Identity.BirthSHA256) || !nativeReadinessCanonicalUUID(c.Identity.PoolUID) || !nativeReadinessCanonicalUUID(c.Identity.NamespaceUID) || c.NotBefore.IsZero() || c.NotBefore.Before(r.CreatedAt.Add(-time.Second)) || c.NotBefore.After(r.CreatedAt) || !c.HardNotAfter.Equal(r.NotAfter) || now.Before(r.CreatedAt) || !now.Before(r.NotAfter) {
		return false
	}
	if c.Identity.Role == "candidate" {
		return c.Identity.NodeUID == r.Identity.NodeUID && c.Peer.NodeUID != r.Identity.NodeUID
	}
	return c.Identity.Role == "floor" && c.Peer.NodeUID == r.Identity.NodeUID && c.Identity.NodeUID != r.Identity.NodeUID
}

// Both directions and both address paths need the exact finite original
// frames. The report's stated counters/hash alone are never network evidence.
func nativeReadinessPacketBatch(config nativeworkerprobe.Config, own, peer ed25519.PublicKey, report nativeworkerprobe.BatchReport, batch string, run nativeReadinessRun, now time.Time) bool {
	count := 4
	seq := []int{0, 1}
	if batch == "final" {
		count = 2
		seq = []int{2}
	} else if batch != "initial" {
		return false
	}
	if !nativeReadinessProbeContext(config, run, now) || len(own) != ed25519.PublicKeySize || len(peer) != ed25519.PublicKeySize || report.State != "complete" || report.ErrorClass != "" || report.StartedAt == nil || report.CompletedAt == nil || report.StartedAt.Before(run.CreatedAt) || report.CompletedAt.Before(*report.StartedAt) || report.CompletedAt.After(now) || report.CompletedAt.After(run.NotAfter) || report.CompletedAt.Sub(*report.StartedAt) > nativeworkerprobe.BatchDeadline || len(report.Sent) != count || len(report.Received) != 2*count || len(report.Echoed) != count {
		return false
	}
	peerConfig := config
	peerConfig.Identity.Role = "floor"
	if config.Identity.Role == "floor" {
		peerConfig.Identity.Role = "candidate"
	}
	peerConfig.Identity.PodUID, peerConfig.Identity.NodeUID = config.Peer.PodUID, config.Peer.NodeUID
	peerConfig.Identity.PodIPv4 = config.Peer.PodIPv4
	peerConfig.Identity.ServiceUID, peerConfig.Identity.ServiceClusterIPv4 = config.Peer.ServiceUID, config.Peer.ServiceClusterIPv4
	peerConfig.Peer = nativeworkerprobe.Peer{PodUID: config.Identity.PodUID, NodeUID: config.Identity.NodeUID, PodIPv4: config.Identity.PodIPv4, ServiceUID: config.Identity.ServiceUID, ServiceClusterIPv4: config.Identity.ServiceClusterIPv4}
	requestsReceived := map[string]nativeworkerprobe.DatagramRecord{}
	// Validate the inbound original before binding an outbound echo to its
	// actual observed return address. Map iteration cannot establish that order.
	for _, group := range []struct {
		kind string
		rows []nativeworkerprobe.DatagramRecord
	}{{"sent", report.Sent}, {"received", report.Received}, {"echoed", report.Echoed}} {
		kind, rows := group.kind, group.rows
		seen := map[string]bool{}
		requests, echoes := 0, 0
		for _, x := range rows {
			validSeq := false
			for _, n := range seq {
				validSeq = validSeq || x.Sequence == n
			}
			if len(x.Packet) != nativeworkerprobe.PayloadBytes {
				return false
			}
			echo := x.Packet[8] == 1
			// These offsets are the v1 signed selection ABI. VerifyPacket binds
			// the complete bytes; also bind every public record's claims to it.
			batchByte, pathByte := byte(0), byte(0)
			if batch == "final" {
				batchByte = 1
			}
			if x.Path == "service" {
				pathByte = 1
			}
			key := strconv.FormatBool(echo) + "/" + x.Path + "/" + strconv.Itoa(x.Sequence)
			if seen[key] || !validSeq || x.Batch != batch || (x.Path != "pod" && x.Path != "service") || x.PayloadBytes != nativeworkerprobe.PayloadBytes || len(x.Packet) != nativeworkerprobe.PayloadBytes || x.ObservedAt.Before(*report.StartedAt) || x.ObservedAt.After(*report.CompletedAt) {
				return false
			}
			if x.Packet[9] != batchByte || x.Packet[10] != pathByte || int(x.Packet[11]) != x.Sequence || x.Packet[8] > 1 || kind == "sent" && echo || kind == "echoed" && !echo {
				return false
			}
			seen[key] = true
			sum := sha256.Sum256(x.Packet)
			if hex.EncodeToString(sum[:]) != x.PayloadSHA256 {
				return false
			}
			sender, signing, echoSigning := config, own, peer
			address := config.Peer.PodIPv4
			if kind == "sent" && x.Path == "service" {
				address = config.Peer.ServiceClusterIPv4
			}
			if kind == "received" {
				if echo {
					echoes++
				} else {
					requests++
					sender, signing, echoSigning = peerConfig, peer, own
				}
			}
			if kind == "echoed" {
				sender, signing, echoSigning = peerConfig, peer, own
			}
			addressOK := x.Address == net.JoinHostPort(address, strconv.Itoa(nativeworkerprobe.Port))
			// Reverse NAT may return a real Service reply from its ClusterIP;
			// only the signed service echo can use this second fixed origin.
			if kind == "received" && echo && x.Path == "service" {
				addressOK = addressOK || x.Address == net.JoinHostPort(config.Peer.ServiceClusterIPv4, strconv.Itoa(nativeworkerprobe.Port))
			}
			// Service DNAT can translate a request's UDP source port. Only the
			// signed Service request from the exact peer Pod can use that port;
			// Pod requests and all returned echoes retain their fixed9446 rule.
			if kind == "received" && !echo && x.Path == "service" {
				origin, err := netip.ParseAddrPort(x.Address)
				addressOK = err == nil && origin.Addr().Is4() && origin.Addr().String() == config.Peer.PodIPv4 && origin.Port() != 0 && origin.String() == x.Address
			}
			selection := x.Path + "/" + strconv.Itoa(x.Sequence)
			if kind == "echoed" {
				original, found := requestsReceived[selection]
				end := nativeworkerprobe.PayloadBytes - ed25519.SignatureSize
				addressOK = found && x.Address == original.Address && !x.ObservedAt.Before(original.ObservedAt) && bytes.Equal(x.Packet[:8], original.Packet[:8]) && bytes.Equal(x.Packet[9:end], original.Packet[9:end])
			}
			if !addressOK || !nativeworkerprobe.VerifyPacket(x.Packet, sender, signing, echoSigning, echo) {
				return false
			}
			if kind == "received" && !echo {
				requestsReceived[selection] = x
			}
		}
		if kind == "received" && (requests != count || echoes != count) {
			return false
		}
	}
	return true
}

func nativeReadinessReport(config nativeworkerprobe.Config, configSHA string, report nativeworkerprobe.Report, own, peer ed25519.PublicKey, run nativeReadinessRun, final bool, now time.Time) bool {
	if !nativeReadinessSHA(configSHA) || len(own) != ed25519.PublicKeySize || report.SigningPublicKey != base64.StdEncoding.EncodeToString(own) || report.Schema != nativeworkerprobe.ReportSchema || report.SourceCommit != config.SourceCommit || report.ConfigSHA256 != configSHA || report.Identity != config.Identity || !report.HardNotAfter.Equal(config.HardNotAfter) || report.ObservedAt.Before(run.CreatedAt) || report.ObservedAt.After(now) || now.Sub(report.ObservedAt) >= 5*time.Second || report.Initial.CompletedAt != nil && report.Initial.CompletedAt.After(report.ObservedAt) || !nativeReadinessPacketBatch(config, own, peer, report.Initial, "initial", run, now) {
		return false
	}
	if final {
		return report.Final.StartedAt != nil && report.Initial.CompletedAt != nil && !report.Final.StartedAt.Before(*report.Initial.CompletedAt) && report.Final.CompletedAt != nil && !report.Final.CompletedAt.After(report.ObservedAt) && nativeReadinessPacketBatch(config, own, peer, report.Final, "final", run, now)
	}
	return report.Final.State == "idle" && report.Final.ErrorClass == "" && report.Final.StartedAt == nil && report.Final.CompletedAt == nil && len(report.Final.Sent) == 0 && len(report.Final.Received) == 0 && len(report.Final.Echoed) == 0
}

func nativeReadinessStartup(config nativeworkerprobe.Config, configSHA string, s nativeworkerprobe.StartupInspection, run nativeReadinessRun, ready bool, now time.Time) bool {
	if !nativeReadinessProbeContext(config, run, now) || config.Identity.Role != "candidate" || config.Startup == nil || !nativeReadinessSHA(configSHA) || s.Schema != nativeworkerprobe.StartupSchema || s.SourceCommit != config.SourceCommit || s.ConfigSHA256 != configSHA || s.Identity != config.Identity || s.AdmissionHTTPStatus != 200 || s.ImageDigest != config.Startup.ImageDigest || s.LaneRosterSHA256 != config.Startup.LaneRosterSHA256 || !nativeReadinessCanonicalUUID(s.ProcessNonce) || s.ObservedAt.Before(run.CreatedAt) || s.ObservedAt.After(now) || now.Sub(s.ObservedAt) >= 5*time.Second || s.AdmissionObservedAt.Before(run.CreatedAt) || s.AdmissionObservedAt.After(s.ObservedAt) || s.ObservedAt.Sub(s.AdmissionObservedAt) >= 5*time.Second {
		return false
	}
	if ready {
		return s.ErrorClass == "" && s.AdmissionState == "roots_open" && s.ReadyHTTPStatus == 200 && s.ReadyStatus == "ready" && s.RabbitMQStatus == "ok" && nativeReadinessSHA(s.ChallengeSHA256)
	}
	return s.AdmissionState == "waiting_projection" && s.ChallengeSHA256 == "" && s.ErrorClass == "startup_pending" && s.ReadyHTTPStatus == 503 && (s.ReadyStatus == "" || s.ReadyStatus == "not_ready") && (s.RabbitMQStatus == "" || s.RabbitMQStatus == "ok" || s.RabbitMQStatus == "degraded")
}

func nativeReadinessSameStartup(a, b nativeworkerprobe.StartupInspection) bool {
	return a.Schema == nativeworkerprobe.StartupSchema && b.Schema == a.Schema && a.Identity == b.Identity && a.SourceCommit == b.SourceCommit && a.ConfigSHA256 == b.ConfigSHA256 && a.ImageDigest == b.ImageDigest && a.LaneRosterSHA256 == b.LaneRosterSHA256 && a.ProcessNonce == b.ProcessNonce
}
