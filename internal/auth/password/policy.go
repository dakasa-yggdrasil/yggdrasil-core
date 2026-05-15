package password

import (
	"errors"
	"strings"
)

var (
	ErrPasswordTooShort         = errors.New("password too short")
	ErrPasswordContainsIdentity = errors.New("password contains personal identifier")
	ErrPasswordTooCommon        = errors.New("password is too common")
)

// ValidateStrength applies the active NIST 800-63B 2017+ policy:
//  1. min length
//  2. cannot contain any userToken of length >= 4 (case-insensitive substring),
//     or any email local-part of length >= 3 derived from an email token
//  3. lowercased password must not be in commonPasswords
//
// Returns nil when all checks pass.
func ValidateStrength(password string, minLength int, commonPasswords map[string]struct{}, userTokens []string) error {
	if len(password) < minLength {
		return ErrPasswordTooShort
	}
	lowered := strings.ToLower(password)
	for _, token := range userTokens {
		t := strings.ToLower(strings.TrimSpace(token))
		if len(t) < 3 {
			continue
		}
		for _, part := range splitIdentityToken(t) {
			// Email local parts (derived before the first @) use a lower threshold of 3.
			// All other parts use a threshold of 4 to avoid too-short false matches.
			minPartLen := 4
			if strings.Contains(t, "@") && !strings.Contains(part, "@") {
				// part came from splitting an email address — lower threshold
				minPartLen = 3
			}
			if len(part) < minPartLen {
				continue
			}
			if strings.Contains(lowered, part) {
				return ErrPasswordContainsIdentity
			}
		}
	}
	if _, hit := commonPasswords[lowered]; hit {
		return ErrPasswordTooCommon
	}
	return nil
}

func splitIdentityToken(t string) []string {
	t = strings.ToLower(t)
	seps := []string{"@", ".", "-", "_", " "}
	parts := []string{t}
	for _, s := range seps {
		var next []string
		for _, p := range parts {
			next = append(next, strings.Split(p, s)...)
		}
		parts = next
	}
	return parts
}

// LoadCommonPasswords reads a wordlist file at startup (one password per line).
func LoadCommonPasswords(path string) (map[string]struct{}, error) {
	data, err := readFile(path)
	if err != nil {
		return nil, err
	}
	out := make(map[string]struct{}, 1000)
	for _, line := range strings.Split(strings.TrimSpace(data), "\n") {
		l := strings.ToLower(strings.TrimSpace(line))
		if l == "" {
			continue
		}
		out[l] = struct{}{}
	}
	return out, nil
}

func readFile(p string) (string, error) {
	b, err := osReadFile(p)
	return string(b), err
}
