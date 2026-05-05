package oidc

import "golang.org/x/crypto/bcrypt"

// bcryptCompare wraps bcrypt.CompareHashAndPassword. Indirection makes it
// trivially mockable in tests without pulling bcrypt into storage.go's
// import set just for one call.
func bcryptCompare(hash, plaintext string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(plaintext))
}
