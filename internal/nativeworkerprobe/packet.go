package nativeworkerprobe

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"net/netip"
	"strings"
)

const (
	packetBodyEnd   = PayloadBytes - 2*ed25519.SignatureSize
	packetEchoStart = PayloadBytes - ed25519.SignatureSize
	packetKindIndex = 8
)

var packetMagic = [8]byte{'D', 'K', 'N', 'W', 'P', '0', '1', 0}

func packetSelection(batch, path string, sequence int) (byte, byte, bool) {
	b, p := byte(0), byte(0)
	if batch == "final" {
		b = 1
	} else if batch != "initial" {
		return 0, 0, false
	}
	if path == "service" {
		p = 1
	} else if path != "pod" {
		return 0, 0, false
	}
	return b, p, b == 0 && (sequence == 0 || sequence == 1) || b == 1 && sequence == 2
}

func putUUID(dst []byte, value string) bool {
	if !uuidPattern.MatchString(value) || value == "00000000-0000-0000-0000-000000000000" {
		return false
	}
	b, err := hex.DecodeString(strings.ReplaceAll(value, "-", ""))
	if err != nil || len(dst) != len(b) {
		return false
	}
	copy(dst, b)
	return true
}

// The canonical diagnostic body is fixed-size and entirely public selection.
// Padding is signed too. No private key, bearer or provider material enters it.
func packetBody(c Config, batch, path string, sequence int) ([]byte, error) {
	b, p, valid := packetSelection(batch, path, sequence)
	if !valid || !sourcePattern.MatchString(c.SourceCommit) || !digestPattern.MatchString(c.Identity.BirthSHA256) {
		return nil, ErrUnavailable
	}
	raw := make([]byte, PayloadBytes)
	copy(raw[:8], packetMagic[:])
	raw[9], raw[10], raw[11] = b, p, byte(sequence)
	if c.Identity.Role == "candidate" {
		raw[12] = 1
	} else if c.Identity.Role != "floor" {
		return nil, ErrUnavailable
	}
	for _, row := range []struct {
		start int
		value string
	}{{16, c.Identity.RunID}, {32, c.Identity.AttemptID}, {112, c.Identity.PodUID}, {128, c.Identity.NodeUID}, {144, c.Peer.PodUID}, {160, c.Peer.NodeUID}, {216, c.Identity.PoolUID}, {232, c.Identity.NamespaceUID}} {
		if !putUUID(raw[row.start:row.start+16], row.value) {
			return nil, ErrUnavailable
		}
	}
	birth, _ := hex.DecodeString(c.Identity.BirthSHA256)
	copy(raw[48:80], birth)
	nonce, err := base64.StdEncoding.DecodeString(c.Nonce)
	if err != nil || len(nonce) != 32 || base64.StdEncoding.EncodeToString(nonce) != c.Nonce {
		return nil, ErrUnavailable
	}
	copy(raw[80:112], nonce)
	target := c.Peer.PodIPv4
	if path == "service" {
		if !putUUID(raw[176:192], c.Peer.ServiceUID) {
			return nil, ErrUnavailable
		}
		target = c.Peer.ServiceClusterIPv4
	}
	ip, err := netip.ParseAddr(target)
	if err != nil || !ip.Is4() || ip.String() != target {
		return nil, ErrUnavailable
	}
	value := ip.As4()
	copy(raw[192:196], value[:])
	source, _ := hex.DecodeString(c.SourceCommit)
	copy(raw[196:216], source)
	return raw, nil
}

func makePacket(c Config, key ed25519.PrivateKey, batch, path string, sequence int) ([]byte, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, ErrUnavailable
	}
	raw, err := packetBody(c, batch, path, sequence)
	if err != nil {
		return nil, err
	}
	copy(raw[packetBodyEnd:packetEchoStart], ed25519.Sign(key, raw[:packetBodyEnd]))
	return raw, nil
}

// VerifyPacket also permits the protected controller to independently verify
// the original reported frame using the exact Source-owned sender Config.
func VerifyPacket(raw []byte, sender Config, signing, echoSigning ed25519.PublicKey, echo bool) bool {
	if len(raw) != PayloadBytes || len(signing) != ed25519.PublicKeySize || raw[packetKindIndex] > 1 || (raw[packetKindIndex] == 1) != echo {
		return false
	}
	batch, path := "initial", "pod"
	if raw[9] == 1 {
		batch = "final"
	} else if raw[9] != 0 {
		return false
	}
	if raw[10] == 1 {
		path = "service"
	} else if raw[10] != 0 {
		return false
	}
	expected, err := packetBody(sender, batch, path, int(raw[11]))
	if err != nil {
		return false
	}
	canonical := append([]byte(nil), raw[:packetBodyEnd]...)
	canonical[packetKindIndex] = 0
	if !bytes.Equal(canonical, expected[:packetBodyEnd]) || !ed25519.Verify(signing, canonical, raw[packetBodyEnd:packetEchoStart]) {
		return false
	}
	if echo {
		return len(echoSigning) == ed25519.PublicKeySize && ed25519.Verify(echoSigning, raw[:packetEchoStart], raw[packetEchoStart:])
	}
	return bytes.Equal(raw[packetEchoStart:], make([]byte, ed25519.SignatureSize))
}

func echoPacket(request []byte, key ed25519.PrivateKey) []byte {
	raw := append([]byte(nil), request...)
	raw[packetKindIndex] = 1
	copy(raw[packetEchoStart:], ed25519.Sign(key, raw[:packetEchoStart]))
	return raw
}

func peerConfig(c Config) Config {
	out := c
	out.Identity.PodUID, out.Identity.NodeUID = c.Peer.PodUID, c.Peer.NodeUID
	out.Identity.ServiceUID, out.Identity.ServiceClusterIPv4 = c.Peer.ServiceUID, c.Peer.ServiceClusterIPv4
	out.Identity.PodIPv4 = c.Peer.PodIPv4
	if c.Identity.Role == "floor" {
		out.Identity.Role = "candidate"
	} else {
		out.Identity.Role = "floor"
	}
	out.Peer = Peer{PodUID: c.Identity.PodUID, NodeUID: c.Identity.NodeUID, PodIPv4: c.Identity.PodIPv4, ServiceUID: c.Identity.ServiceUID, ServiceClusterIPv4: c.Identity.ServiceClusterIPv4}
	return out
}
