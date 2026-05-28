package privacy

import "testing"

func TestMaskEmail(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"standard", "giovanni.martins@dakasa.me", "gi***@dakasa.me"},
		{"short local", "bo@dakasa.me", "bo***@dakasa.me"},
		{"single char local", "x@dakasa.me", "*@dakasa.me"},
		{"empty", "", ""},
		{"trim ws", "  gi@dakasa.me  ", "gi***@dakasa.me"},
		{"no @", "noatsign", "noatsign"},
		{"trailing @", "user@", "user@"},
		{"leading @", "@dakasa.me", "@dakasa.me"},
		{"multi @", "weird@@case@dakasa.me", "we***@@case@dakasa.me"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := MaskEmail(c.in)
			if got != c.want {
				t.Fatalf("MaskEmail(%q) = %q; want %q", c.in, got, c.want)
			}
		})
	}
}

func TestMaskIP(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"ipv4 standard", "192.168.1.42", "192.168.1.***"},
		{"ipv4 public", "8.8.8.8", "8.8.8.***"},
		{"ipv6 standard", "2001:db8::1", "2001:db8::****"},
		{"ipv6 expanded", "2001:0db8:0000:0000:0000:0000:0000:0001", "2001:db8::****"},
		{"empty", "", ""},
		{"unparseable", "not-an-ip", "not-an-ip"},
		{"trim ws", "  10.0.0.1  ", "10.0.0.***"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := MaskIP(c.in)
			if got != c.want {
				t.Fatalf("MaskIP(%q) = %q; want %q", c.in, got, c.want)
			}
		})
	}
}

func TestMaskToken(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"non-empty", "ya29.a0AfH6SMC...", "tok_***"},
		{"short", "abc", "tok_***"},
		{"empty", "", ""},
		{"whitespace only", "   ", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := MaskToken(c.in)
			if got != c.want {
				t.Fatalf("MaskToken(%q) = %q; want %q", c.in, got, c.want)
			}
		})
	}
}

// Canary: MaskToken MUST NEVER leak any prefix of the input. Even one
// char of token leakage breaks the contract.
func TestMaskTokenNeverLeaksPrefix(t *testing.T) {
	tokens := []string{
		"secret",
		"yggdrasil.SECRET_TOKEN_XYZ",
		"abcdefghijklmnop",
		"1234567890",
	}
	for _, tok := range tokens {
		got := MaskToken(tok)
		if got == tok || (len(got) > 0 && len(tok) > 0 && got[0] == tok[0] && got != "tok_***") {
			t.Fatalf("MaskToken(%q) leaked: returned %q", tok, got)
		}
	}
}
