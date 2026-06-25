package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/controllers/oidc"
	jose "github.com/go-jose/go-jose/v4"
)

// verifyPublicKey is the minimal view the verifier needs of an OP signing key.
// zitadel's op.Key (returned by oidc.Storage.KeySet) satisfies it.
type verifyPublicKey interface {
	ID() string
	Key() any
}

// keySource returns the OP's active public keys (the published /jwks set).
type keySource func(ctx context.Context) ([]verifyPublicKey, error)

// opJWTVerifier verifies OIDC JWTs that THIS OpenID Provider issued, using the
// in-process signing key set — no external JWKS fetch (yggdrasil-core IS the OP
// and holds the keys). It implements the jwtVerifier interface so it can back
// bearerOrSession / the console auth gate.
//
// All of these checks are REQUIRED for a token to authenticate:
//   - RS256 signature against a current OP public key,
//   - `iss` equals the configured issuer,
//   - `exp` is in the future (with a small leeway),
//   - `aud` intersects the configured audience allowlist.
//
// The audience allowlist is the privilege boundary: it is what prevents a token
// minted for an unrelated OIDC client from authenticating the console APIs. The
// verifier is INERT (always fails) unless issuer + at least one audience are
// configured, so enabling JWT auth is an explicit, per-environment opt-in.
type opJWTVerifier struct {
	keys      keySource
	issuer    string
	audiences map[string]struct{}
	now       func() time.Time
	leeway    time.Duration
}

var errJWTVerify = errors.New("oidc jwt verification failed")

// Verify implements jwtVerifier.
func (v *opJWTVerifier) Verify(ctx context.Context, token string) (map[string]any, error) {
	if v == nil || v.issuer == "" || len(v.audiences) == 0 {
		// Not configured → never authenticates (additive, opt-in by design).
		return nil, errJWTVerify
	}

	jws, err := jose.ParseSigned(token, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil || len(jws.Signatures) == 0 {
		return nil, errJWTVerify
	}
	kid := jws.Signatures[0].Header.KeyID

	keys, err := v.keys(ctx)
	if err != nil {
		return nil, fmt.Errorf("load op signing keys: %w", err)
	}

	var payload []byte
	verified := false
	for _, k := range keys {
		// With a kid present, only the matching key is eligible; without one,
		// try every active key to tolerate rotation overlap.
		if kid != "" && k.ID() != kid {
			continue
		}
		if p, verr := jws.Verify(k.Key()); verr == nil {
			payload = p
			verified = true
			break
		}
	}
	if !verified {
		return nil, errJWTVerify
	}

	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, errJWTVerify
	}

	if iss, _ := claims["iss"].(string); iss != v.issuer {
		return nil, errJWTVerify
	}
	if !expInFuture(claims["exp"], v.now().Add(-v.leeway)) {
		return nil, errJWTVerify
	}
	if !audienceAllowed(claims["aud"], v.audiences) {
		return nil, errJWTVerify
	}
	return claims, nil
}

func expInFuture(raw any, now time.Time) bool {
	switch e := raw.(type) {
	case float64:
		return time.Unix(int64(e), 0).After(now)
	case json.Number:
		n, err := e.Int64()
		return err == nil && time.Unix(n, 0).After(now)
	default:
		return false
	}
}

func audienceAllowed(raw any, allow map[string]struct{}) bool {
	switch a := raw.(type) {
	case string:
		_, ok := allow[a]
		return ok
	case []any:
		for _, x := range a {
			if s, ok := x.(string); ok {
				if _, ok := allow[s]; ok {
					return true
				}
			}
		}
	}
	return false
}

// parseConsoleJWTAudiences splits the comma-separated
// YGGDRASIL_CONSOLE_JWT_AUDIENCES env value into a clean allowlist. Blank
// entries are dropped; an empty/absent value yields an empty slice, which keeps
// the JWT branch disabled (newOPJWTVerifier returns nil).
func parseConsoleJWTAudiences(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// newOPJWTVerifier builds a verifier from the OP storage, issuer, and audience
// allowlist. Returns nil — which DISABLES the JWT branch entirely (behavior
// unchanged) — when storage is nil, the issuer is empty, or no audiences are
// configured.
func newOPJWTVerifier(storage *oidc.Storage, issuer string, audiences []string) *opJWTVerifier {
	auds := map[string]struct{}{}
	for _, a := range audiences {
		if a = strings.TrimSpace(a); a != "" {
			auds[a] = struct{}{}
		}
	}
	if storage == nil || strings.TrimSpace(issuer) == "" || len(auds) == 0 {
		return nil
	}
	return &opJWTVerifier{
		keys: func(ctx context.Context) ([]verifyPublicKey, error) {
			ks, err := storage.KeySet(ctx)
			if err != nil {
				return nil, err
			}
			out := make([]verifyPublicKey, 0, len(ks))
			for _, k := range ks {
				out = append(out, k) // op.Key satisfies verifyPublicKey
			}
			return out, nil
		},
		issuer:    strings.TrimSpace(issuer),
		audiences: auds,
		now:       time.Now,
		leeway:    30 * time.Second,
	}
}
