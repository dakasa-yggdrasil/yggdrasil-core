package httpapi

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

// The callback here is a protocol test fixture. It does not establish actual
// dispatch/RBAC/SQL/lease authority; those remain separate native owning gates.
func originalCanaryHTTPFixture(t *testing.T, guard func(context.Context) error) (*Server, capacity.OriginalCanaryAuthorityScope, capacity.OriginalCanaryAuthorityToken, context.CancelCauseFunc, func()) {
	t.Helper()
	parent, cancel := context.WithCancelCause(t.Context())
	owner, deadlineCancel := context.WithTimeout(parent, 30*time.Second)
	t.Cleanup(deadlineCancel)
	t.Cleanup(func() { cancel(context.Canceled) })
	scope := capacity.OriginalCanaryAuthorityScope{WindowID: uuid.NewString(), ScopeSHA256: strings.Repeat("a", 64), PolicyID: uuid.NewString(), PolicyChecksum: strings.Repeat("b", 64), WorkflowID: uuid.NewString(), WorkflowChecksum: strings.Repeat("c", 64), DispatchJobID: uuid.NewString(), DispatchFence: 1, IntentGeneration: 1, IntentFence: 1, LeaseOwner: uuid.NewString(), ExecutorID: uuid.NewString(), MachinePrincipalID: "protocol-fixture", Deadline: time.Now().UTC().Add(20 * time.Second)}
	server := &Server{originalCanaryAuthorities: capacity.NewOriginalCanaryAuthorityRegistry()}
	token, revoke, err := server.originalCanaryAuthorities.Register(owner, scope, guard)
	if err != nil {
		t.Fatal("original private test registration refused")
	}
	t.Cleanup(revoke)
	return server, scope, token, cancel, revoke
}

func originalCanaryHTTPRequest(t *testing.T, token capacity.OriginalCanaryAuthorityToken, scope capacity.OriginalCanaryAuthorityScope) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "https://core.example"+capacityOriginalCanaryAuthorityPath, nil).WithContext(t.Context())
	r.Header.Set(capacityOriginalCanaryAuthorityHeader, token.HeaderValue())
	r.Header.Set(capacityOriginalCanaryScopeHeader, scope.ScopeSHA256)
	return r
}

func TestOriginalCanaryAuthorityHTTPClosedFamily(t *testing.T) {
	for _, mode := range []string{"default_off", "method", "other_route", "suffix", "query", "raw_path", "force_query", "plaintext", "body", "transfer_encoding", "missing_token", "missing_scope", "duplicate_header", "case_alias_duplicate", "foreign_scope", "foreign_bearer", "cookie", "directory", "mutation_settlement", "unknown_token", "revoked", "original_owner_cancelled"} {
		t.Run(mode, func(t *testing.T) {
			var guards atomic.Int64
			server, scope, token, cancel, revoke := originalCanaryHTTPFixture(t, func(context.Context) error { guards.Add(1); return nil })
			r := originalCanaryHTTPRequest(t, token, scope)
			switch mode {
			case "default_off":
				server.originalCanaryAuthorities = nil
			case "method":
				r.Method = http.MethodPost
			case "other_route":
				r.URL.Path = "/healthz"
			case "suffix":
				r.URL.Path += "/renew"
			case "query":
				r.URL.RawQuery = "scope=caller"
			case "raw_path":
				r.URL.RawPath = "/capacity/native/%63anary-authority"
			case "force_query":
				r.URL.ForceQuery = true
			case "plaintext":
				r.TLS = nil
			case "body":
				r.Body = io.NopCloser(strings.NewReader("caller"))
				r.ContentLength = 6
				t.Cleanup(func() { _ = r.Body.Close() })
			case "transfer_encoding":
				r.TransferEncoding = []string{"chunked"}
			case "missing_token":
				r.Header.Del(capacityOriginalCanaryAuthorityHeader)
			case "missing_scope":
				r.Header.Del(capacityOriginalCanaryScopeHeader)
			case "duplicate_header":
				r.Header.Add(capacityOriginalCanaryAuthorityHeader, token.HeaderValue())
			case "case_alias_duplicate":
				r.Header[strings.ToLower(capacityOriginalCanaryAuthorityHeader)] = []string{token.HeaderValue()}
			case "foreign_scope":
				r.Header.Set(capacityOriginalCanaryScopeHeader, strings.Repeat("d", 64))
			case "foreign_bearer":
				r.Header.Set("Authorization", "Bearer caller")
			case "cookie":
				r.Header.Set("Cookie", "session=caller")
			case "directory":
				r.Header.Set(directoryMachineTokenHeader, "caller")
			case "mutation_settlement":
				r.Header.Set("X-Capacity-Mutation-Settlement", "caller")
			case "unknown_token":
				r.Header.Set(capacityOriginalCanaryAuthorityHeader, strings.Repeat("e", 64))
			case "revoked":
				revoke()
			case "original_owner_cancelled":
				cancel(errors.New("private original cancellation"))
			}
			before := guards.Load()
			fallthroughCalls := 0
			gate := server.requireAuthenticatedConsoleAPIs(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { fallthroughCalls++ }))
			w := httptest.NewRecorder()
			gate.ServeHTTP(w, r)
			if w.Code == http.StatusOK || fallthroughCalls != 0 || guards.Load() != before || w.Header().Get("Cache-Control") != "no-store" || strings.Contains(w.Body.String(), token.HeaderValue()) || strings.Contains(w.Body.String(), "private original cancellation") {
				t.Fatal("private canary family fell through, leaked a cause or admitted a foreign call")
			}
		})
	}
}

func TestOriginalCanaryAuthorityHTTPActualTLSReadClose(t *testing.T) {
	var guards atomic.Int64
	server, scope, token, _, _ := originalCanaryHTTPFixture(t, func(context.Context) error { guards.Add(1); return nil })
	endpoint := httptest.NewTLSServer(server.requireAuthenticatedConsoleAPIs(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("private request escaped") })))
	defer endpoint.Close()
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, endpoint.URL+capacityOriginalCanaryAuthorityPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set(capacityOriginalCanaryAuthorityHeader, token.HeaderValue())
	request.Header.Set(capacityOriginalCanaryScopeHeader, scope.ScopeSHA256)
	response, err := endpoint.Client().Do(request)
	if err != nil {
		t.Fatal("original fixture TLS call did not return")
	}
	raw, readErr := io.ReadAll(io.LimitReader(response.Body, (16<<10)+1))
	closeErr := response.Body.Close()
	var reply capacity.OriginalCanaryAuthorityReply
	if readErr != nil || closeErr != nil || len(raw) > 16<<10 || response.StatusCode != http.StatusOK || json.Unmarshal(raw, &reply) != nil || reply.Schema != capacity.OriginalCanaryAuthoritySchema || reply.Scope != scope || !reply.OriginalLiveLeaseVerified || !reply.CurrentMachineRBACVerified || reply.HumanSessionVerified || reply.UsefulCapacityKnown || reply.FullTransitionQualified || guards.Load() != 3 || strings.Contains(string(raw), token.HeaderValue()) {
		t.Fatal("original bounded protocol Do/Read/Close or closed permission differed")
	}
}

func TestOriginalCanaryAuthorityHTTPForeignCredentialPresence(t *testing.T) {
	for _, header := range []string{"X-Session-Token", "X-Yggdrasil-Workflow-Token", "X-Yggdrasil-Event-Token", "X-Yggdrasil-Auth-Admin-Token", "X-Deploy-Token"} {
		t.Run(header, func(t *testing.T) {
			for _, value := range []string{"caller", ""} {
				var guards atomic.Int64
				server, scope, token, _, _ := originalCanaryHTTPFixture(t, func(context.Context) error { guards.Add(1); return nil })
				r := originalCanaryHTTPRequest(t, token, scope)
				r.Header[strings.ToLower(header)] = []string{value}
				before := guards.Load()
				w := httptest.NewRecorder()
				server.requireAuthenticatedConsoleAPIs(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("mixed private credential escaped") })).ServeHTTP(w, r)
				if w.Code != http.StatusForbidden || guards.Load() != before {
					t.Fatal("existing foreign credential presence supplied private permission")
				}
			}
		})
	}
}

func TestOriginalCanaryAuthorityHTTPActualAccessLogPrivacy(t *testing.T) {
	for _, mode := range []string{"private_suffix", "private_header_foreign_path", "private_method", "ordinary_logging_preserved"} {
		t.Run(mode, func(t *testing.T) {
			server, scope, token, _, _ := originalCanaryHTTPFixture(t, func(context.Context) error { return nil })
			core, logs := observer.New(zap.InfoLevel)
			server.logger = zap.New(core)
			r := originalCanaryHTTPRequest(t, token, scope)
			privatePath := "private_caller_path_" + token.HeaderValue()
			switch mode {
			case "private_suffix":
				r.URL.Path += "/" + privatePath
			case "private_header_foreign_path":
				r.URL.Path = "/healthz/" + privatePath
			case "private_method":
				r.Method = token.HeaderValue()
			case "ordinary_logging_preserved":
				r.Header = make(http.Header)
				r.URL.Path = "/healthz"
			}
			w := httptest.NewRecorder()
			server.withLogging(server.requireAuthenticatedConsoleAPIs(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))).ServeHTTP(w, r)
			entries := logs.FilterMessage("http request served").All()
			if len(entries) != 1 {
				t.Fatal("actual access logger did not return")
			}
			fields := entries[0].ContextMap()
			if mode == "ordinary_logging_preserved" {
				if w.Code != http.StatusNoContent || fields["path"] != "/healthz" || fields["method"] != http.MethodGet {
					t.Fatal("ordinary logging changed")
				}
				return
			}
			if w.Code != http.StatusForbidden || fields["path"] != capacityOriginalCanaryAuthorityPath {
				t.Fatal("private access log retained caller path or private request escaped")
			}
			encoded, err := json.Marshal(fields)
			if err != nil || strings.Contains(string(encoded), token.HeaderValue()) || strings.Contains(string(encoded), privatePath) {
				t.Fatal("original outer access log leaked private caller bytes")
			}
		})
	}
}

func TestOriginalCanaryAuthorityHTTPHeldOriginalGuard(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var guards atomic.Int64
	server, scope, token, cancel, _ := originalCanaryHTTPFixture(t, func(ctx context.Context) error {
		if guards.Add(1) == 3 {
			close(entered)
			<-release
			return errors.Join(ctx.Err(), context.Cause(ctx))
		}
		return nil
	})
	r := originalCanaryHTTPRequest(t, token, scope)
	r.TLS = &tls.ConnectionState{}
	w := httptest.NewRecorder()
	returned := make(chan struct{})
	go func() {
		server.requireAuthenticatedConsoleAPIs(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("private guard escaped") })).ServeHTTP(w, r)
		close(returned)
	}()
	select {
	case <-entered:
	case <-t.Context().Done():
		close(release)
		<-returned
		t.Fatal("original guard did not reach its final call")
	}
	cancel(errors.New("private held original cancellation"))
	select {
	case <-returned:
		close(release)
		t.Fatal("cancel substituted for an original guard return")
	default:
	}
	close(release)
	<-returned
	if w.Code == http.StatusOK || strings.Contains(w.Body.String(), "private held original cancellation") {
		t.Fatal("cancelled original guard supplied permission or leaked its cause")
	}
}
