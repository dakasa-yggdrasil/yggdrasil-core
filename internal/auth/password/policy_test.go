package password

import (
	"errors"
	"testing"
)

func TestValidateStrength(t *testing.T) {
	common := map[string]struct{}{
		"password":   {},
		"qwerty":     {},
		"letmein123": {},
		"sunshine":   {},
	}
	tests := []struct {
		name       string
		password   string
		minLen     int
		userTokens []string
		want       error
	}{
		{"valid", "z9-Forest-River-Iceland", 12, []string{"ana@dakasa.co", "ana"}, nil},
		{"too short", "abc123", 12, nil, ErrPasswordTooShort},
		{"contains email local", "ana-needs-coffee-now", 12, []string{"ana@dakasa.co", "ana"}, ErrPasswordContainsIdentity},
		{"contains display name word", "iLoveSilvaMartins!", 12, []string{"Silva Martins", "smartins"}, ErrPasswordContainsIdentity},
		{"too common", "letmein123", 8, nil, ErrPasswordTooCommon},
		{"common case-insensitive", "Password", 8, nil, ErrPasswordTooCommon},
		{"short token ignored", "uuuuuuuuuuuuuu", 12, []string{"u"}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateStrength(tt.password, tt.minLen, common, tt.userTokens)
			if !errors.Is(err, tt.want) {
				t.Fatalf("got %v want %v", err, tt.want)
			}
		})
	}
}
