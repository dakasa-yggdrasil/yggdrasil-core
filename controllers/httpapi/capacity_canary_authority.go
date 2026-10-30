package httpapi

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
)

const capacityOriginalCanaryAuthorityPath = "/capacity/native/canary-authority"
const capacityOriginalCanaryAuthorityHeader = "X-Capacity-Core-Authority"
const capacityOriginalCanaryScopeHeader = "X-Capacity-Participant-Window"

// This dedicated credential family is resolved before every other surface.
// A malformed, stale or foreign request cannot become a human or directory
// request. There is no HTTP registration, token minting or renewal operation.
func originalCanaryAuthorityClaim(r *http.Request) bool {
	if strings.HasPrefix(r.URL.Path, capacityOriginalCanaryAuthorityPath) {
		return true
	}
	for name := range r.Header {
		if strings.EqualFold(name, capacityOriginalCanaryAuthorityHeader) || strings.EqualFold(name, capacityOriginalCanaryScopeHeader) {
			return true
		}
	}
	return false
}

func originalCanarySingleSHAHeader(r *http.Request, name string) (string, bool) {
	values := []string{}
	for key, entries := range r.Header {
		if strings.EqualFold(key, name) {
			values = append(values, entries...)
		}
	}
	if len(values) != 1 {
		return "", false
	}
	raw, err := hex.DecodeString(values[0])
	return values[0], err == nil && len(raw) == 32 && hex.EncodeToString(raw) == values[0]
}

func originalCanaryForeignCredential(r *http.Request) bool {
	foreign := []string{"Authorization", "Cookie", directoryMachineTokenHeader, "X-Capacity-Mutation-Settlement", "X-Session-Token", "X-Yggdrasil-Workflow-Token", "X-Yggdrasil-Event-Token", "X-Yggdrasil-Auth-Admin-Token", "X-Deploy-Token"}
	for name := range r.Header {
		for _, credential := range foreign {
			if strings.EqualFold(name, credential) {
				// Even an empty credential header is a foreign attempt. The
				// endpoint accepts only the original invocation's two headers.
				return true
			}
		}
	}
	return false
}

func originalCanaryAccessLog(r *http.Request) (method, route string) {
	if !originalCanaryAuthorityClaim(r) {
		return r.Method, r.URL.Path
	}
	// Rejected path and method bytes may themselves contain a credential.
	// The actual outer access logger must never retain them for this family.
	method = http.MethodGet
	if r.Method != http.MethodGet {
		method = "PRIVATE_REFUSED"
	}
	return method, capacityOriginalCanaryAuthorityPath
}

func (s *Server) serveOriginalCanaryAuthority(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	refuse := func(status int) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte("{\"status\":\"original_canary_authority_unavailable\"}\n"))
	}
	if r.Method != http.MethodGet || r.URL.Path != capacityOriginalCanaryAuthorityPath || r.URL.RawPath != "" || r.URL.RawQuery != "" || r.URL.ForceQuery || r.TLS == nil || r.ContentLength != 0 || len(r.TransferEncoding) != 0 || (r.Body != nil && r.Body != http.NoBody) || originalCanaryForeignCredential(r) {
		refuse(http.StatusForbidden)
		return
	}
	bearer, validBearer := originalCanarySingleSHAHeader(r, capacityOriginalCanaryAuthorityHeader)
	scope, validScope := originalCanarySingleSHAHeader(r, capacityOriginalCanaryScopeHeader)
	if !validBearer || !validScope || s.originalCanaryAuthorities == nil {
		refuse(http.StatusUnauthorized)
		return
	}
	// The request cannot extend the captured invocation's owner. Observe
	// retains that original owner and runs the actual installed SQL/RBAC/
	// catalog/dispatch/intent guard both before and after constructing reply.
	owner, cancel := context.WithTimeoutCause(r.Context(), 5*time.Second, capacity.ErrOriginalCanaryAuthority)
	defer cancel()
	reply, err := s.originalCanaryAuthorities.Observe(owner, bearer, scope)
	if err != nil || dispatchContext(owner) != nil {
		refuse(http.StatusUnauthorized)
		return
	}
	raw, err := json.Marshal(reply)
	if err != nil || len(raw) > 16<<10 || dispatchContext(owner) != nil {
		refuse(http.StatusServiceUnavailable)
		return
	}
	// An emitted permission never certifies this writer's return or a
	// recipient's business operation. The recipient must join its original
	// Do/Read/Close and compare this immutable deadline before acceptance.
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(append(raw, '\n'))
}
