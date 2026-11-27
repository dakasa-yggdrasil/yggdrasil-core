package httpapi

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/coreprocess"
	safego "github.com/dakasa-yggdrasil/yggdrasil-core/internal/goroutine"
)

func (s *Server) workerRouteAllowed(r *http.Request) bool {
	if originalCanaryAuthorityClaim(r) || capacityGuestPath(r.URL.Path) || capacityMutationPath(r.URL.Path) || nativeWorkerPhasePath(r.URL.Path) || hostFactoryPath(r.URL.Path) {
		return false
	}
	p := r.URL.Path
	for _, prefix := range []string{"/capacity/", "/api/v1/capacity", "/api/v1/ops", "/api/v1/secrets", "/api/v1/github", "/api/v1/deploy", "/api/v1/bootstrap", "/api/v1/auth", "/auth", "/oidc", "/.well-known", "/internal-runtime/"} {
		if strings.HasPrefix(p, prefix) {
			return r.Method == http.MethodGet && (p == "/api/v1/auth/session" || p == "/api/v1/auth/verify")
		}
	}
	if issuer, err := url.Parse(s.oidcIssuerURL); err == nil && issuer.Path != "" && issuer.Path != "/" && strings.HasPrefix(p, strings.TrimRight(issuer.Path, "/")) {
		return false
	}
	if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
		return true
	}
	if r.Method != http.MethodPost {
		return false
	}
	if p == "/api/v1/workflow-runs" {
		return true
	}
	parts := strings.Split(p, "/")
	return len(parts) == 6 && parts[1] == "api" && parts[2] == "v1" && parts[3] == "integrations" && parts[4] != "" && parts[5] == "surface-query"
}

func (s *Server) withProcessRole(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.processRole == coreprocess.APIWorker && !s.workerRouteAllowed(r) {
			writeProblemJSON(w, http.StatusServiceUnavailable, "core.authority_required", "request requires the configured control authority origin")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func WithWorkerRequestAuditOwners(owner *OriginalWorkflowOwners, failed func()) ServerOption {
	return func(s *Server) { s.requestAuditOwner, s.backgroundFailure = owner, failed }
}

// Keep the existing best-effort asynchronous contract. Workers join these
// actual returns only after every request and workflow producer has stopped.
func (s *Server) launchRequestAudit(name string, work func()) {
	if s.processRole != coreprocess.APIWorker {
		safego.SafeGo(name, work)
		return
	}
	_, finish, err := s.requestAuditOwner.Begin()
	if err != nil {
		if s.backgroundFailure != nil {
			s.backgroundFailure()
		}
		return
	}
	safego.SafeGo(name, func() {
		returned := false
		defer func() {
			if !returned && s.backgroundFailure != nil {
				s.backgroundFailure()
			}
			finish()
		}()
		work()
		returned = true
	})
}
