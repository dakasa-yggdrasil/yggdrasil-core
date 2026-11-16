package httpapi

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/coreprocess"
)

// Invoked by the existing async owning root; no additional test root/census.
func productionWorkerRoleRefusals(t *testing.T) {
	t.Helper()
	workerSharedConfigurationRefusals(t)
	workerRequestAuditJoin(t)
	for _, value := range []string{"api", "API_WORKER", " api_worker", "authority ", "worker", "false"} {
		if _, err := coreprocess.ParseRole(value); err == nil {
			t.Fatal("unknown process role gained authority", value)
		}
	}
	for _, value := range []string{"", string(coreprocess.Authority)} {
		if role, err := coreprocess.ParseRole(value); err != nil || role != coreprocess.Authority {
			t.Fatal("default authority behavior changed")
		}
	}
	for _, check := range []struct {
		role    coreprocess.Role
		path    string
		allowed bool
	}{{coreprocess.Authority, "/app/yggdrasil-core", true}, {coreprocess.APIWorker, coreprocess.APIWorkerExecutable, true}, {coreprocess.Authority, coreprocess.APIWorkerExecutable, false}, {coreprocess.APIWorker, "/app/yggdrasil-core", false}, {coreprocess.APIWorker, "/app/entrypoint.sh", false}} {
		if err := coreprocess.ValidateExecutable(check.role, check.path); (err == nil) != check.allowed {
			t.Fatal("version-skew worker executable guard changed", check.role, check.path)
		}
	}
	if coreprocess.ShutdownBudget(coreprocess.APIWorker) != 30*time.Minute+10*time.Second || coreprocess.ShutdownBudget(coreprocess.Authority) != 10*time.Second {
		t.Fatal("original operation or dependency deadline changed")
	}
	limiter := newLoginRateLimiter(2, time.Hour, time.Hour)
	s := &Server{processRole: coreprocess.APIWorker, loginLimiter: limiter}
	var calls int
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path == "/api/v1/auth/login" {
			_, _ = s.loginLimiter.checkOrConsume("same-source")
		}
		w.WriteHeader(http.StatusNoContent)
	})
	worker := s.withProcessRole(next)
	for _, path := range []string{"/api/v1/auth/login", "/api/v1/auth/mfa/factors/webauthn/begin", "/api/v1/secrets", "/api/v1/github/webhook", "/api/v1/capacity/mutations/native/redeem", "/api/v1/ops/workflows", "/capacity/native/canary-authority", "/api/v1/manifests?kind=control_plane", "/api/v1/events", "/api/v1/integration-types/x/sync"} {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"process_role":"authority"}`))
		request.Header.Set("Authorization", "Bearer caller-cannot-change-role")
		worker.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusServiceUnavailable || calls != 0 {
			t.Fatal("API worker delegated an authority operation", path, recorder.Code)
		}
	}
	request := httptest.NewRequest(http.MethodGet, "/api/v1/auth/session", nil)
	request.Header.Set(capacityOriginalCanaryAuthorityHeader, strings.Repeat("a", 64))
	recorder := httptest.NewRecorder()
	worker.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusServiceUnavailable || calls != 0 {
		t.Fatal("private authority credential escaped through shared-session route")
	}
	for i := 0; i < 2; i++ {
		allowed, _ := limiter.checkOrConsume("same-source")
		if !allowed {
			t.Fatal("misrouted worker requests consumed the authority login budget")
		}
	}
	allowed, _ := limiter.checkOrConsume("same-source")
	if allowed {
		t.Fatal("test login budget not exhausted")
	}
	for _, route := range []struct{ method, path string }{{http.MethodGet, "/api/v1/auth/session"}, {http.MethodGet, "/api/v1/manifests"}, {http.MethodPost, "/api/v1/workflow-runs?process_role=authority"}, {http.MethodPost, "/api/v1/integrations/declared/surface-query"}} {
		r := httptest.NewRecorder()
		worker.ServeHTTP(r, httptest.NewRequest(route.method, route.path, nil))
		if r.Code != http.StatusNoContent {
			t.Fatal("ordinary API route refused", route)
		}
	}
	before := calls
	authority := (&Server{processRole: coreprocess.Authority}).withProcessRole(next)
	r := httptest.NewRecorder()
	authority.ServeHTTP(r, httptest.NewRequest(http.MethodPost, "/api/v1/manifests", nil))
	if r.Code != http.StatusNoContent || calls != before+1 {
		t.Fatal("authority route behavior changed")
	}
}

func workerRequestAuditJoin(t *testing.T) {
	t.Helper()
	owner, err := NewOriginalWorkflowOwners(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	var failed atomic.Int32
	s := &Server{processRole: coreprocess.APIWorker, requestAuditOwner: owner, backgroundFailure: func() { failed.Add(1) }}
	s.launchRequestAudit("core_worker_owned_audit_source", func() { close(entered); <-release })
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("original best-effort audit did not start")
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if err := owner.Join(canceled); !errors.Is(err, context.Canceled) {
		t.Fatal("pending audit became a returned request lane", err)
	}
	close(release)
	if err := owner.Join(t.Context()); err != nil || failed.Load() != 0 {
		t.Fatal("real audit return did not join", err)
	}
	s.launchRequestAudit("core_worker_refused_post_shutdown_audit", func() { t.Error("sealed audit owner launched new work") })
	if failed.Load() != 1 {
		t.Fatal("late audit admission did not fence native completion")
	}
}

func workerSharedConfigurationRefusals(t *testing.T) {
	t.Helper()
	valid := map[string]string{"AUTH_THIRD_PARTY_STATE_SECRET": strings.Repeat("s", 32), "YGGDRASIL_CSRF_HMAC_SECRET": strings.Repeat("c", 32), "YGGDRASIL_AUTH_KEK_BASE64": base64.StdEncoding.EncodeToString([]byte(strings.Repeat("k", 32))), "BROKER_URL": "amqp://ci:only@127.0.0.1:5672/", "NATIVE_ADMISSION_ENABLED": "true", "NATIVE_ADMISSION_KEY": strings.Repeat("n", 32), "NATIVE_TERMINATION_PROJECTION_DIR": t.TempDir(), "NATIVE_TERMINATION_IMAGE_DIGEST": "sha256:" + strings.Repeat("a", 64)}
	old := map[string]string{}
	present := map[string]bool{}
	for name, value := range valid {
		old[name], present[name] = os.LookupEnv(name)
		t.Setenv(name, value)
	}
	defer func() {
		for name := range valid {
			if present[name] {
				_ = os.Setenv(name, old[name])
			} else {
				_ = os.Unsetenv(name)
			}
		}
	}()
	if err := coreprocess.ValidateWorkerEnvironment(); err != nil {
		t.Fatal("declared shared worker configuration refused", err)
	}
	for _, change := range []struct{ name, value string }{{"AUTH_THIRD_PARTY_STATE_SECRET", ""}, {"AUTH_THIRD_PARTY_STATE_SECRET", strings.Repeat("s", 31)}, {"YGGDRASIL_CSRF_HMAC_SECRET", ""}, {"YGGDRASIL_AUTH_KEK_BASE64", "bad-raw-private-value"}, {"YGGDRASIL_AUTH_KEK_BASE64", base64.StdEncoding.EncodeToString([]byte(strings.Repeat("k", 31)))}, {"BROKER_URL", ""}, {"BROKER_URL", "not-a-broker"}, {"NATIVE_ADMISSION_ENABLED", "false"}, {"NATIVE_ADMISSION_ENABLED", " true"}} {
		t.Setenv(change.name, change.value)
		if err := coreprocess.ValidateWorkerEnvironment(); err == nil || strings.Contains(err.Error(), "bad-raw-private-value") {
			t.Fatal("worker generated/fell back or leaked missing shared material", change.name)
		}
		t.Setenv(change.name, valid[change.name])
	}
	for _, change := range []struct{ name, value string }{{"NATIVE_ADMISSION_KEY", ""}, {"NATIVE_TERMINATION_PROJECTION_DIR", "relative"}, {"NATIVE_TERMINATION_IMAGE_DIGEST", "mutable:latest"}} {
		t.Setenv(change.name, change.value)
		if _, err := coreprocess.NewLifetime(); err == nil {
			t.Fatal("unbound native worker configuration started", change.name)
		}
		t.Setenv(change.name, valid[change.name])
	}
}
