package mfa

import (
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	wa "github.com/go-webauthn/webauthn/webauthn"
)

func TestNewWebAuthnRequiresConfig(t *testing.T) {
	t.Parallel()
	if _, err := NewWebAuthn(Config{}); err == nil {
		t.Fatal("expected error when RPID is missing")
	}
	if _, err := NewWebAuthn(Config{RPID: "yggdrasil.dakasa.me"}); err == nil {
		t.Fatal("expected error when origins are missing")
	}
	engine, err := NewWebAuthn(Config{
		RPID:    "yggdrasil.dakasa.me",
		Origins: []string{"https://yggdrasil.dakasa.me"},
	})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if engine == nil {
		t.Fatal("expected non-nil engine")
	}
}

func TestSessionStorePutTakeIsOneShot(t *testing.T) {
	t.Parallel()
	store := NewSessionStore(100 * time.Millisecond)
	data := wa.SessionData{Challenge: "abc"}
	store.Put("k", data)

	got, err := store.Take("k")
	if err != nil {
		t.Fatalf("first take err: %v", err)
	}
	if got.Challenge != "abc" {
		t.Fatalf("got challenge %q want %q", got.Challenge, "abc")
	}
	// Second take must fail — one-shot semantics prevent replay.
	if _, err := store.Take("k"); err == nil {
		t.Fatal("expected second take to fail (one-shot)")
	}
}

func TestSessionStoreExpiresEntries(t *testing.T) {
	t.Parallel()
	store := NewSessionStore(10 * time.Millisecond)
	store.Put("k", wa.SessionData{Challenge: "abc"})
	time.Sleep(20 * time.Millisecond)
	if _, err := store.Take("k"); err == nil {
		t.Fatal("expected expired take to fail")
	}
}

func TestRegistrationAndLoginKeysAreDistinct(t *testing.T) {
	t.Parallel()
	if RegistrationKey("u") == LoginKey("u") {
		t.Fatal("registration and login keys must be distinct so a passkey enroll can't be replayed as a login")
	}
}

func TestDeviceKindFromAttachmentNormalizes(t *testing.T) {
	t.Parallel()
	cases := map[protocol.AuthenticatorAttachment]string{
		protocol.Platform:      "platform",
		protocol.CrossPlatform: "cross-platform",
		"":                     "",
		"bogus":                "",
	}
	for in, want := range cases {
		if got := DeviceKindFromAttachment(in); got != want {
			t.Errorf("DeviceKindFromAttachment(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestTransportsToStringsFiltersBlanks(t *testing.T) {
	t.Parallel()
	got := TransportsToStrings([]protocol.AuthenticatorTransport{
		protocol.USB,
		protocol.NFC,
		"",
	})
	want := []string{"usb", "nfc"}
	if len(got) != len(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("got[%d] = %q want %q", i, got[i], want[i])
		}
	}
	if TransportsToStrings(nil) != nil {
		t.Fatal("nil input must return nil to preserve JSON omitempty")
	}
}
