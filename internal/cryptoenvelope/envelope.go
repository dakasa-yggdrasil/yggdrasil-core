// Package cryptoenvelope implements AES-GCM envelope encryption with a
// pluggable Key Encryption Key (KEK) — either a static 32-byte key (dev) or
// AWS KMS (prod). Per-record Data Encryption Keys (DEKs) are wrapped by the
// KEK and stored alongside ciphertext.
package cryptoenvelope

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
)

// Envelope seals/opens secrets using AES-256-GCM. Either kek (static) or kms
// (KMS-backed) is set; never both.
type Envelope struct {
	kek []byte
	kms KMSClient
}

// NewWithStaticKEK builds an Envelope that wraps DEKs with a 32-byte static
// key. Use only for dev/local — production should use NewWithKMSClient.
func NewWithStaticKEK(kek []byte) *Envelope {
	if len(kek) != 32 {
		panic("kek must be exactly 32 bytes")
	}
	return &Envelope{kek: kek}
}

// Seal generates a fresh DEK, encrypts plaintext with AES-GCM(DEK), then wraps
// the DEK with the configured KEK (static or KMS). Returns (ciphertext, wrappedDEK).
func (e *Envelope) Seal(ctx context.Context, plaintext []byte) ([]byte, []byte, error) {
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		return nil, nil, fmt.Errorf("generate dek: %w", err)
	}
	ct, err := aesGCMSeal(dek, plaintext)
	if err != nil {
		return nil, nil, fmt.Errorf("seal data: %w", err)
	}
	wrappedDEK, err := e.wrapDEK(ctx, dek)
	if err != nil {
		return nil, nil, fmt.Errorf("wrap dek: %w", err)
	}
	return ct, wrappedDEK, nil
}

// Open unwraps the DEK and decrypts ciphertext. Returns an error on tamper
// (GCM auth failure) or wrong KEK.
func (e *Envelope) Open(ctx context.Context, ciphertext, wrappedDEK []byte) ([]byte, error) {
	dek, err := e.unwrapDEK(ctx, wrappedDEK)
	if err != nil {
		return nil, errors.New("dek unwrap failed (tamper or wrong kek)")
	}
	pt, err := aesGCMOpen(dek, ciphertext)
	if err != nil {
		return nil, errors.New("data decrypt failed (tamper)")
	}
	return pt, nil
}

func (e *Envelope) wrapDEK(ctx context.Context, dek []byte) ([]byte, error) {
	if e.kms != nil {
		return e.kms.Encrypt(ctx, dek)
	}
	return aesGCMSeal(e.kek, dek)
}

func (e *Envelope) unwrapDEK(ctx context.Context, wrappedDEK []byte) ([]byte, error) {
	if e.kms != nil {
		return e.kms.Decrypt(ctx, wrappedDEK)
	}
	return aesGCMOpen(e.kek, wrappedDEK)
}

func aesGCMSeal(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	out := aead.Seal(nil, nonce, plaintext, nil)
	return append(nonce, out...), nil
}

func aesGCMOpen(key, blob []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(blob) < aead.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}
	nonce := blob[:aead.NonceSize()]
	ct := blob[aead.NonceSize():]
	return aead.Open(nil, nonce, ct, nil)
}
