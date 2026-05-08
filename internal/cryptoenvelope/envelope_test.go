package cryptoenvelope

import (
	"context"
	"testing"
)

func make32() []byte {
	return []byte("0123456789ABCDEF0123456789ABCDEF")
}

func TestSealOpenRoundtrip(t *testing.T) {
	env := NewWithStaticKEK(make32())
	ctx := context.Background()
	plaintext := []byte("super-secret-totp-seed")

	ct, dek, err := env.Seal(ctx, plaintext)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if len(ct) == 0 || len(dek) == 0 {
		t.Fatal("expected non-empty ciphertext and dek")
	}

	out, err := env.Open(ctx, ct, dek)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if string(out) != string(plaintext) {
		t.Fatalf("expected %q, got %q", plaintext, out)
	}
}

func TestOpenTamperedCiphertextFails(t *testing.T) {
	env := NewWithStaticKEK(make32())
	ctx := context.Background()

	ct, dek, err := env.Seal(ctx, []byte("data"))
	if err != nil {
		t.Fatal(err)
	}
	ct[len(ct)-1] ^= 0xFF
	if _, err := env.Open(ctx, ct, dek); err == nil {
		t.Fatal("expected tamper detection error")
	}
}

func TestOpenTamperedDEKFails(t *testing.T) {
	env := NewWithStaticKEK(make32())
	ctx := context.Background()

	ct, dek, err := env.Seal(ctx, []byte("data"))
	if err != nil {
		t.Fatal(err)
	}
	dek[len(dek)-1] ^= 0xFF
	if _, err := env.Open(ctx, ct, dek); err == nil {
		t.Fatal("expected dek-tamper detection error")
	}
}

type fakeKMSClient struct {
	encryptCalls int
	decryptCalls int
}

func (f *fakeKMSClient) Encrypt(ctx context.Context, plaintext []byte) ([]byte, error) {
	f.encryptCalls++
	out := make([]byte, len(plaintext)+4)
	copy(out, []byte("KMS:"))
	copy(out[4:], plaintext)
	return out, nil
}

func (f *fakeKMSClient) Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error) {
	f.decryptCalls++
	if len(ciphertext) < 4 || string(ciphertext[:4]) != "KMS:" {
		return nil, ErrKMSDecryptFailed
	}
	return ciphertext[4:], nil
}

func TestKMSEnvelopeRoundtrip(t *testing.T) {
	client := &fakeKMSClient{}
	env := NewWithKMSClient(client)
	ct, dek, err := env.Seal(context.Background(), []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	if client.encryptCalls != 1 {
		t.Fatalf("expected 1 KMS encrypt, got %d", client.encryptCalls)
	}
	pt, err := env.Open(context.Background(), ct, dek)
	if err != nil {
		t.Fatal(err)
	}
	if string(pt) != "payload" {
		t.Fatalf("got %q", pt)
	}
}
