package repository

import (
	"bytes"
	"context"
	"crypto/rand"
	"testing"
	"time"

	"github.com/google/uuid"
)

// The original low-level journal fixture exercises late custody/cleanup only;
// it does not pretend a synthetic native body is a qualified Kubernetes ACK.
// Production uses the independent bound observation and atomic event path.
func (s *nativeReadinessRunJournal) receiveAbsent(ctx context.Context, r nativeReadinessRun, slot, uid, evidence string, observed time.Time) (nativeReadinessRun, error) {
	name, kind, ok := nativeReadinessSlot(r, slot)
	if !ok || !nativeReadinessObjectKind(kind) || uid == "" || !nativeReadinessSHA(evidence) || observed.IsZero() {
		return nativeReadinessRun{}, errNativeReadinessRun
	}
	return s.edit(ctx, r, nil, func(current *nativeReadinessRun, now time.Time) error {
		if observed.Before(current.CreatedAt) || observed.After(now) {
			return errNativeReadinessRun
		}
		for i := range current.Effects {
			e := &current.Effects[i]
			if e.Name == name && e.Kind == kind && e.UID == uid && e.State == "delete_received" && e.PrivateDeleteOriginal != nil {
				e.State, e.EvidenceSHA256, e.ObservedAt = "absent", evidence, observed
				return nil
			}
		}
		return errNativeReadinessRun
	})
}

func TestNativeReadinessRunKeysAreBoundToOriginalRunIdentityAndLifetime(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	s := &nativeReadinessRunJournal{key: &nativeReadinessRunKey{key: key}}
	now := time.Date(2026, 11, 28, 0, 0, 0, 0, time.UTC)
	r := nativeReadinessRun{Schema: "native_worker_readiness_run_v1", ID: uuid.New(), Identity: nativeReadinessRunIdentity{AttemptID: uuid.New(), PolicyID: uuid.New(), BirthSHA256: "original-birth", NodeUID: uuid.NewString(), ProducerScope: "original-scope"}, CreatedAt: now, NotAfter: now.Add(time.Minute), Revision: 1}
	plain := bytes.Repeat([]byte("independent-test-run-keys-"), 20)
	nonce, sealed, err := s.crypt(r, nil, plain, true)
	if err != nil || bytes.Contains(sealed, plain) || len(nonce) != 12 {
		t.Fatal("private key encryption failed", err)
	}
	_, got, err := s.crypt(r, nonce, sealed, false)
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatal("original run keys could not be resumed", err)
	}
	clear(got)
	for _, fault := range []string{"run", "attempt", "policy", "birth", "node", "scope", "start", "end", "nonce", "ciphertext", "key"} {
		t.Run(fault, func(t *testing.T) {
			other := r
			n, c := bytes.Clone(nonce), bytes.Clone(sealed)
			otherKey := bytes.Clone(key)
			switch fault {
			case "run":
				other.ID = uuid.New()
			case "attempt":
				other.Identity.AttemptID = uuid.New()
			case "policy":
				other.Identity.PolicyID = uuid.New()
			case "birth":
				other.Identity.BirthSHA256 += "-foreign"
			case "node":
				other.Identity.NodeUID = uuid.NewString()
			case "scope":
				other.Identity.ProducerScope += "-foreign"
			case "start":
				other.CreatedAt = other.CreatedAt.Add(time.Nanosecond)
			case "end":
				other.NotAfter = other.NotAfter.Add(time.Second)
			case "nonce":
				n[0] ^= 1
			case "ciphertext":
				c[0] ^= 1
			case "key":
				otherKey[0] ^= 1
			}
			otherStore := &nativeReadinessRunJournal{key: &nativeReadinessRunKey{key: otherKey}}
			if _, material, err := otherStore.crypt(other, n, c, false); err == nil || material != nil {
				t.Fatal("changed run context or ciphertext disclosed private keys")
			}
		})
	}
	// Mutable receiving history is deliberately outside AEAD identity. It may
	// advance without re-encrypting, renewing, replacing or losing the same keys.
	next := r
	next.Revision++
	next.Effects = []nativeReadinessEffect{{Kind: "Pod", Name: "received", UID: uuid.NewString(), State: "observed"}}
	if _, material, err := s.crypt(next, nonce, sealed, false); err != nil || !bytes.Equal(material, plain) {
		t.Fatal("receiving history replaced original key identity", err)
	}
}
