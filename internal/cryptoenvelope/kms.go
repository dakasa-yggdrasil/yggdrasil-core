package cryptoenvelope

import (
	"context"
	"errors"
)

// ErrKMSDecryptFailed is returned when the KMS client rejects a wrapped DEK.
// Callers should treat this as tamper or KEK rotation gap, not a transient
// network error.
var ErrKMSDecryptFailed = errors.New("kms decrypt failed")

// KMSClient is the minimal contract Envelope needs to wrap/unwrap DEKs through
// AWS KMS (or any KMS-shaped service). Implementations should be safe for
// concurrent use.
type KMSClient interface {
	Encrypt(ctx context.Context, plaintext []byte) ([]byte, error)
	Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error)
}

// NewWithKMSClient builds an Envelope that delegates DEK wrap/unwrap to the
// given KMSClient. Production deployments should use this constructor.
func NewWithKMSClient(c KMSClient) *Envelope {
	return &Envelope{kms: c}
}
