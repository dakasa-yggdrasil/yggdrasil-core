package saml

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
)

// openPrivateKey decrypts the envelope-protected private key blob. The blob
// shape matches `internal/cryptoenvelope`'s seal output: 12-byte nonce ||
// ciphertext || 16-byte GCM tag.
func openPrivateKey(blob, key []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("DEK must be 32 bytes (AES-256)")
	}
	if len(blob) < 12+16 {
		return nil, errors.New("ciphertext too short")
	}
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes new: %w", err)
	}
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, fmt.Errorf("gcm new: %w", err)
	}
	nonce, body := blob[:gcm.NonceSize()], blob[gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, body, nil)
	if err != nil {
		return nil, fmt.Errorf("gcm open: %w", err)
	}
	return plain, nil
}
