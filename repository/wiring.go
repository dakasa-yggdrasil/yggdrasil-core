package repository

import "github.com/dakasa-yggdrasil/yggdrasil-core/internal/auth/password"

func init() {
	verifyPasswordBridge = func(scheme, encoded, plaintext string) error {
		return password.Verify(password.Scheme(scheme), encoded, plaintext)
	}
}
