package mfa

import "testing"

func TestContactOTPSecrets(t *testing.T) {
	seen := make(map[string]bool)
	for range 32 {
		token, code, err := GenerateContactOTP()
		if err != nil || !ValidContactOTPToken(token) || !ValidContactOTPCode(code) {
			t.Fatal("generated challenge does not satisfy the token/code contract")
		}
		if seen[token] {
			t.Fatal("challenge entropy repeated")
		}
		seen[token] = true
		digest := HashContactOTPCode(token, code)
		if !VerifyContactOTPCode(token, code, digest) || VerifyContactOTPCode(token+"other", code, digest) {
			t.Fatal("code is not cryptographically bound to its opaque challenge")
		}
		if digest == HashContactOTPToken(code) || digest == HashContactOTPToken(token) {
			t.Fatal("challenge/code vault uses an enumerable unkeyed digest")
		}
	}
}

func TestContactOTPHMACRFC4231(t *testing.T) {
	// RFC 4231 test case 2 independently fixes the HMAC-SHA256 construction.
	want := "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
	if HashContactOTPCode("Jefe", "what do ya want for nothing?") != want {
		t.Fatal("contact code digest does not match HMAC-SHA256")
	}
}

func TestContactOTPStrictCodeShape(t *testing.T) {
	if !ValidContactOTPCode("000001") {
		t.Fatal("leading zero code was rejected")
	}
	for _, code := range []string{"", "12345", "1234567", "123 56", " 123456", "123456 ", "１２３４５６", "12345a"} {
		if ValidContactOTPCode(code) || VerifyContactOTPCode("key", code, HashContactOTPCode("key", code)) {
			t.Fatal("noncanonical code was accepted")
		}
	}
	for _, token := range []string{"", "short", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"} {
		if ValidContactOTPToken(token) {
			t.Fatal("malformed opaque challenge token was accepted")
		}
	}
}

func TestContactDeliverySelector(t *testing.T) {
	t.Setenv("AUTH_EMAIL_INTEGRATION", "namespace/email")
	t.Setenv("AUTH_SMS_INTEGRATION", "namespace/sms")
	for channel, want := range map[string]string{"email": "email", "sms": "sms"} {
		namespace, name, configured := ContactDeliverySelector(channel)
		if !configured || namespace != "namespace" || name != want {
			t.Fatal("configured canonical delivery selector was not resolved")
		}
	}
	if _, _, configured := ContactDeliverySelector("unknown"); configured {
		t.Fatal("unsupported channel received a delivery selector")
	}
	for _, value := range []string{"", "mail", "/mail", "ns/", "ns/mail/extra", "ns /mail", "ns/mail extra"} {
		t.Setenv("AUTH_EMAIL_INTEGRATION", value)
		if _, _, configured := ContactDeliverySelector("email"); configured {
			t.Fatal("malformed delivery selector counted as configured")
		}
	}
}
