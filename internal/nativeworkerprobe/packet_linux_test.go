package nativeworkerprobe

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
)

func packetKeys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, key
}

func TestProbeSignedOriginalRequestAndEchoBindEachFixedSelection(t *testing.T) {
	c := testConfig("floor")
	pub, key := packetKeys(t)
	echoPub, echoKey := packetKeys(t)
	for _, selection := range []struct {
		batch string
		seq   int
	}{{"initial", 0}, {"initial", 1}, {"final", 2}} {
		for _, path := range []string{"pod", "service"} {
			raw, err := makePacket(c, key, selection.batch, path, selection.seq)
			if err != nil || len(raw) != 1302 || !VerifyPacket(raw, c, pub, nil, false) {
				t.Fatal("canonical request refused", selection, path, err)
			}
			original := append([]byte(nil), raw...)
			echo := echoPacket(raw, echoKey)
			if !bytes.Equal(raw, original) || !VerifyPacket(echo, c, pub, echoPub, true) || VerifyPacket(echo, c, pub, echoPub, false) || VerifyPacket(raw, c, pub, echoPub, true) {
				t.Fatal("original/echo signatures or kind not independently bound")
			}
			for _, offset := range []int{0, 8, 9, 10, 11, 12, 15, 16, 32, 48, 80, 112, 128, 144, 160, 176, 192, 196, 216, packetBodyEnd - 1, packetBodyEnd, packetEchoStart, PayloadBytes - 1} {
				bad := append([]byte(nil), echo...)
				bad[offset] ^= 1
				if VerifyPacket(bad, c, pub, echoPub, true) {
					t.Fatalf("changed original frame accepted at %d", offset)
				}
			}
			for _, change := range []func(*Config){
				func(v *Config) { v.Identity.RunID = testUUID(11) },
				func(v *Config) { v.Identity.AttemptID = testUUID(11) },
				func(v *Config) { v.Identity.BirthSHA256 = strings.Repeat("c", 64) },
				func(v *Config) { v.Identity.PoolUID = testUUID(11) },
				func(v *Config) { v.Identity.NamespaceUID = testUUID(11) },
				func(v *Config) { v.Nonce = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{8}, 32)) },
				func(v *Config) { v.Identity.PodUID = testUUID(11) },
				func(v *Config) { v.Identity.NodeUID = testUUID(11) },
				func(v *Config) { v.Peer.PodUID = testUUID(11) },
				func(v *Config) { v.Peer.NodeUID = testUUID(11) },
				func(v *Config) { v.SourceCommit = strings.Repeat("f", 40) },
			} {
				changed := c
				change(&changed)
				if VerifyPacket(echo, changed, pub, echoPub, true) {
					t.Fatal("different current run/lifetime/physical selection accepted")
				}
			}
			changed := c
			if path == "service" {
				changed.Peer.ServiceUID = testUUID(11)
			} else {
				changed.Peer.PodIPv4 = "10.89.0.4"
			}
			if VerifyPacket(echo, changed, pub, echoPub, true) {
				t.Fatal("destination UID/address changed")
			}
		}
	}
}

func TestProbePacketRefusesUnplannedBatchSequenceSizeAndWrongKeys(t *testing.T) {
	c := testConfig("candidate")
	pub, key := packetKeys(t)
	other, otherKey := packetKeys(t)
	for _, s := range []struct {
		batch, path string
		seq         int
	}{{"initial", "pod", 2}, {"final", "pod", 0}, {"final", "service", 3}, {"initial", "arbitrary", 0}, {"replay", "pod", 0}, {"initial", "pod", -1}} {
		if _, err := makePacket(c, key, s.batch, s.path, s.seq); err == nil {
			t.Fatal("unplanned send admitted", s)
		}
	}
	raw, err := makePacket(c, key, "initial", "pod", 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{nil, raw[:len(raw)-1], append(append([]byte{}, raw...), 0)} {
		if VerifyPacket(bad, c, pub, nil, false) {
			t.Fatal("noncanonical size accepted")
		}
	}
	if VerifyPacket(raw, c, other, nil, false) || VerifyPacket(echoPacket(raw, otherKey), c, pub, pub, true) {
		t.Fatal("foreign sender/echo identity accepted")
	}
	if _, err := makePacket(c, nil, "initial", "pod", 0); err == nil {
		t.Fatal("missing signing identity accepted")
	}
}
