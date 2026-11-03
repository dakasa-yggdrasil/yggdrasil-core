//go:build linux && nativequalification

package httpapi

import (
	"context"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"net/http"
)

// Existing Guest TLS, bearer, principal/member/slot/profile and nonce guards
// have already run. This read-only qualification route has no capacity effect.
func guestQualificationRegistrationClock(ctx context.Context, store repository.CapacityStore, principal, id, nonce string, r *http.Request) (any, error) {
	if r.Method != http.MethodGet || r.URL.ForceQuery || r.ContentLength != 0 || len(r.TransferEncoding) != 0 || r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
		return nil, repository.ErrCapacityMutationAuthorization
	}
	return store.GuestQualificationRegistrationClock(ctx, principal, id, nonce)
}
