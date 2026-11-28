package repository

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func nativeReadinessEffectIndex(r nativeReadinessRun, slot string) (int, bool) {
	name, kind, ok := nativeReadinessSlot(r, slot)
	if !ok {
		return 0, false
	}
	for i, e := range r.Effects {
		if e.Name == name && e.Kind == kind {
			return i, true
		}
	}
	return 0, false
}

func nativeReadinessTokenSHA(token string) (string, bool) {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	defer clear(raw)
	if err != nil || len(raw) != 32 || base64.RawURLEncoding.EncodeToString(raw) != token {
		return "", false
	}
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:]), true
}

// Core commits requested before the SDK RPC. Only the authenticated SDK's one
// redemption changes it to send_started immediately before the native effect.
// Delete is owned cleanup, so it uses its own finite deadline after run expiry.
func (s *nativeReadinessRunJournal) redeem(ctx context.Context, a model.CapacityNativeWorkerAttempt, r nativeReadinessRun, slot string) (nativeReadinessRun, string, error) {
	index, exists := nativeReadinessEffectIndex(r, slot)
	if !exists {
		return nativeReadinessRun{}, "", errNativeReadinessRun
	}
	state := r.Effects[index].State
	if state != "requested" && state != "delete_requested" {
		return nativeReadinessRun{}, "", errNativeReadinessRun
	}
	random := make([]byte, 32)
	defer clear(random)
	if _, err := rand.Read(random); err != nil {
		return nativeReadinessRun{}, "", errNativeReadinessRun
	}
	token := base64.RawURLEncoding.EncodeToString(random)
	hash, ok := nativeReadinessTokenSHA(token)
	if !ok {
		return nativeReadinessRun{}, "", errNativeReadinessRun
	}
	var grow *model.CapacityNativeWorkerAttempt
	if state == "requested" {
		grow = &a
	}
	next, err := s.edit(ctx, r, grow, func(current *nativeReadinessRun, now time.Time) error {
		i, ok := nativeReadinessEffectIndex(*current, slot)
		if !ok {
			return errNativeReadinessRun
		}
		e := &current.Effects[i]
		if e.State != state || e.SettlementTokenSHA256 != "" || !e.OperationExpiresAt.After(now) {
			return errNativeReadinessRun
		}
		if state == "delete_requested" {
			if !nativeReadinessObjectKind(e.Kind) || e.UID == "" || e.DeleteTokenSHA256 != "" {
				return errNativeReadinessRun
			}
			e.State = "delete_started"
			e.DeleteTokenSHA256 = hash
		} else {
			if e.CreateTokenSHA256 != "" {
				return errNativeReadinessRun
			}
			e.State = "send_started"
			e.CreateTokenSHA256 = hash
		}
		e.SettlementTokenSHA256, e.ObservedAt = hash, now
		return nil
	})
	if err != nil {
		return nativeReadinessRun{}, "", err
	}
	return next, token, nil
}

// Receive retains the exact original native response bytes before any Secret,
// Pod or Status is interpreted. Both incomplete prefixes and malformed replies
// remain private custody; this method establishes no observed resource/absence.
func (s *nativeReadinessRunJournal) captureOriginal(ctx context.Context, r nativeReadinessRun, received model.NativeWorkerProbeResourceReceive) (nativeReadinessRun, error) {
	if received.RunID != r.ID.String() || len(received.OriginalReturn) > 1<<20 {
		return nativeReadinessRun{}, errNativeReadinessRun
	}
	tokenSHA, valid := nativeReadinessTokenSHA(received.SettlementToken)
	if !valid {
		return nativeReadinessRun{}, errNativeReadinessRun
	}
	raw, err := received.MarshalPrivateJSON()
	defer clear(raw)
	if err != nil || len(raw) > 2<<20 {
		return nativeReadinessRun{}, errNativeReadinessRun
	}
	return s.edit(ctx, r, nil, func(current *nativeReadinessRun, now time.Time) error {
		i, exists := nativeReadinessEffectIndex(*current, received.Slot)
		if !exists {
			return errNativeReadinessRun
		}
		e := &current.Effects[i]
		creation := nativeReadinessSHA(e.CreateTokenSHA256) && subtle.ConstantTimeCompare([]byte(tokenSHA), []byte(e.CreateTokenSHA256)) == 1
		deleted := nativeReadinessSHA(e.DeleteTokenSHA256) && subtle.ConstantTimeCompare([]byte(tokenSHA), []byte(e.DeleteTokenSHA256)) == 1
		if creation == deleted {
			return errNativeReadinessRun
		}
		operation := "create"
		if e.Kind == "StartupChallenge" {
			operation = "startup_patch"
		}
		original := &e.PrivateOriginal
		if deleted {
			operation, original = "delete", &e.PrivateDeleteOriginal
		}
		purpose := "original/" + operation + "/" + received.Slot + "/" + tokenSHA
		if *original != nil {
			_, previous, err := s.cryptPurpose(*current, purpose, (*original).Nonce, (*original).Ciphertext, false)
			defer clear(previous)
			if err != nil || !bytes.Equal(previous, raw) {
				return errNativeReadinessRun
			}
			return nil
		}
		if creation && e.State != "send_started" || deleted && e.State != "delete_started" {
			return errNativeReadinessRun
		}
		nonce, sealed, err := s.cryptPurpose(*current, purpose, nil, raw, true)
		if err != nil {
			return err
		}
		*original = &nativeReadinessCipher{Nonce: nonce, Ciphertext: sealed}
		if deleted {
			e.State = "delete_received"
		} else {
			e.State = "received"
		}
		e.ObservedAt = now
		return nil
	})
}
