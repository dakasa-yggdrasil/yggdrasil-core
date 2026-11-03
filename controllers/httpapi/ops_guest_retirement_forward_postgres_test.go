//go:build recoveryfixture && !nativequalification

package httpapi

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/manifest"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// A real child starts after the original context/lease naturally expire. This
// tests the handler's actual process barrier without backdating any original or
// exporting a production barrier override. All databases are disposable local
// PG16/17 created by the tagged shared builder; no native Guest/cloud is used.
func TestGuestRetirementForwardHistoricalHTTPPostgres(t *testing.T) {
	if os.Getenv("GUEST_FORWARD_HTTP_CHILD") == "true" {
		guestRetirementForwardHTTPChild(t)
		return
	}
	for _, provider := range []string{"aws", "hetzner"} {
		t.Run(provider, func(t *testing.T) {
			f := repository.NewGuestRetirementForwardRecoveryFixture(t, provider, 3, 3)
			before := f.PreservedOriginals()
			f.FinishFailedRun("retire-original-guest")
			_ = f.WaitHistoricalBarrier()
			actor := uuid.New()
			if _, err := f.DB.Exec(`INSERT INTO public.collaborators(id,slug,status,display_name,traits) VALUES($1,$2,'active','Declared recovery test human','{"yggdrasil_admin":true}'::jsonb)`, actor, "forward-human-"+actor.String()); err != nil {
				t.Fatal(err)
			}
			var identity guestRetirementForwardHTTPDBIdentity
			if err := f.DB.QueryRow(`SELECT current_database(),COALESCE(host(inet_server_addr()),'unix'),COALESCE(inet_server_port(),0),current_setting('server_version_num')::int/10000`).Scan(&identity.Database, &identity.Address, &identity.Port, &identity.Major); err != nil {
				t.Fatal(err)
			}
			u, err := url.Parse(os.Getenv("FAILED_SERVING_FIXTURE_ADMIN_URL"))
			if err != nil {
				t.Fatal(err)
			}
			u.Path = "/" + identity.Database
			identityBody, err := json.Marshal(identity)
			if err != nil {
				t.Fatal(err)
			}
			want, err := strconv.Atoi(os.Getenv("FAILED_SERVING_TEST_PG_MAJOR"))
			if err != nil {
				t.Fatal(err)
			}
			if _, err = decodeGuestRetirementForwardHTTPDBIdentity(identityBody, u.Path, want); err != nil {
				t.Fatal("parent-owned disposable DB identity invalid", err)
			}
			body, err := json.Marshal(f.HistoricalRequest())
			if err != nil {
				t.Fatal(err)
			}
			binary, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			ctx, stop := context.WithTimeout(context.Background(), 45*time.Second)
			defer stop()
			child := exec.CommandContext(ctx, binary, "-test.run=^TestGuestRetirementForwardHistoricalHTTPPostgres$", "-test.count=1")
			child.Env = append(os.Environ(), "GUEST_FORWARD_HTTP_CHILD=true", "GUEST_FORWARD_HTTP_DB="+u.String(), "GUEST_FORWARD_HTTP_DB_IDENTITY="+base64.StdEncoding.EncodeToString(identityBody), "GUEST_FORWARD_HTTP_BODY="+base64.StdEncoding.EncodeToString(body), "GUEST_FORWARD_HTTP_ACTOR="+actor.String())
			if output, err := child.CombinedOutput(); err != nil {
				t.Fatalf("actual child HTTP boundary failed: %v\n%s", err, output)
			}
			if !reflect.DeepEqual(before, f.PreservedOriginals()) {
				t.Fatal("HTTP admission rewrote original Guest/run evidence")
			}
			var ledger, reads, deletes int
			if err := f.DB.QueryRow(`SELECT (SELECT count(*) FROM public.capacity_guest_retirement_forwards),(SELECT count(*) FROM public.capacity_guest_retirement_forward_reads),(SELECT count(*) FROM public.capacity_vm_retirement_delete_bindings)`).Scan(&ledger, &reads, &deletes); err != nil || ledger != 1 || reads != 0 || deletes != 0 {
				t.Fatal("HTTP admission gained native authority or duplicate rows", ledger, reads, deletes, err)
			}
		})
	}
}

// The already admitted parent captures this exact local disposable endpoint.
// Container server addresses are compared to it, never to a private CIDR list.
type guestRetirementForwardHTTPDBIdentity struct {
	Database string `json:"database"`
	Address  string `json:"address"`
	Port     int    `json:"port"`
	Major    int    `json:"major"`
}

func decodeGuestRetirementForwardHTTPDBIdentity(raw []byte, path string, want int) (guestRetirementForwardHTTPDBIdentity, error) {
	var identity guestRetirementForwardHTTPDBIdentity
	if len(raw) > 1024 || capacity.DecodeGuestLifecycle(raw, &identity) != nil || "/"+identity.Database != path || !strings.HasPrefix(identity.Database, "failed_serving_fixture_") || (want != 16 && want != 17) || identity.Major != want || (identity.Address == "unix" && identity.Port != 0) || (identity.Address != "unix" && (net.ParseIP(identity.Address) == nil || identity.Port < 1 || identity.Port > 65535)) {
		return identity, errors.New("closed parent-owned disposable database identity required")
	}
	return identity, nil
}

func guestRetirementForwardHTTPChild(t *testing.T) {
	t.Helper()
	if os.Getenv("CAPACITY_RECOVERY_FIXTURE_ONLY") != "true" {
		t.Fatal("explicit fixture gate required")
	}
	u, err := url.Parse(os.Getenv("GUEST_FORWARD_HTTP_DB"))
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") || (u.Hostname() != "127.0.0.1" && u.Hostname() != "localhost" && u.Hostname() != "::1" && !(u.Hostname() == "" && strings.HasPrefix(u.Query().Get("host"), "/"))) || !strings.HasPrefix(u.Path, "/failed_serving_fixture_") {
		t.Fatal("only parent-owned disposable local DB permitted")
	}
	db, err := sql.Open("postgres", u.String())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	want, err := strconv.Atoi(os.Getenv("FAILED_SERVING_TEST_PG_MAJOR"))
	if err != nil || want != 16 && want != 17 {
		t.Fatal("explicit major16/17 required")
	}
	identityBody, err := base64.StdEncoding.DecodeString(os.Getenv("GUEST_FORWARD_HTTP_DB_IDENTITY"))
	if err != nil {
		t.Fatal("parent-owned disposable DB identity missing or malformed")
	}
	expected, err := decodeGuestRetirementForwardHTTPDBIdentity(identityBody, u.Path, want)
	if err != nil {
		t.Fatal(err)
	}
	var actual guestRetirementForwardHTTPDBIdentity
	if err = db.QueryRow(`SELECT current_database(),COALESCE(host(inet_server_addr()),'unix'),COALESCE(inet_server_port(),0),current_setting('server_version_num')::int/10000`).Scan(&actual.Database, &actual.Address, &actual.Port, &actual.Major); err != nil || actual != expected {
		t.Fatalf("actual disposable DB identity differs: actual=%+v expected=%+v err=%v", actual, expected, err)
	}
	body, err := base64.StdEncoding.DecodeString(os.Getenv("GUEST_FORWARD_HTTP_BODY"))
	if err != nil || len(body) > 4096 {
		t.Fatal("closed parent request required")
	}
	req, err := decodeGuestRetirementForwardRequest(bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	policy, err := repository.GetManifestByID(context.Background(), db, uuid.MustParse(req.PolicyID))
	if err != nil {
		t.Fatal(err)
	}
	p, err := manifest.ParseCapacityPolicySpec(policy.Spec)
	if err != nil || p.GuestRetirementBinding == nil || len(p.Profiles) != 1 {
		t.Fatal("exact declared policy", err)
	}
	capacity.RecoveryFixtureApprovalScope(t)
	if err = capacity.RegisterRecoveryFixtureApproval(p, *p.GuestRetirementBinding, p.Profiles[0].Provider); err != nil {
		t.Fatal(err)
	}
	actor, err := uuid.Parse(os.Getenv("GUEST_FORWARD_HTTP_ACTOR"))
	if err != nil || actor == uuid.Nil {
		t.Fatal("actual fixture human required")
	}
	s := &Server{db: db, logger: zap.NewNop()}
	mux := http.NewServeMux()
	base := "/api/v1/ops/capacity/guest-retirement-poweroff-forwards"
	mux.HandleFunc("POST "+base, s.requireOpsPermissionFunc(permManageWorkflows, s.handleOpsGuestRetirementForward))
	mux.HandleFunc("GET "+base+"/{preregistrationId}", s.requireOpsPermissionFunc(permManageWorkflows, s.handleOpsGuestRetirementForwardRead))
	h := s.csrfMiddleware(mux)
	makeRequest := func(method, path string, csrf bool) *http.Request {
		r := rbacTestRequestWithClaims(method, path, actor)
		r.Body = io.NopCloser(bytes.NewReader(body))
		claims, _ := claimsFromContext(r.Context())
		if csrf {
			session, err := uuid.Parse(claims["session_id"].(string))
			if err != nil {
				t.Fatal(err)
			}
			r.Header.Set(csrfHeaderName, computeCSRFToken(session))
		}
		return r
	}
	t.Setenv("YGGDRASIL_CSRF_ENFORCE", "enforce")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, makeRequest(http.MethodPost, base, false))
	if w.Code != http.StatusForbidden {
		t.Fatal("session POST bypassed CSRF", w.Code)
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, makeRequest(http.MethodPost, base, true))
	if w.Code != http.StatusCreated {
		t.Fatalf("historical original HTTP failed: %d %s", w.Code, w.Body.String())
	}
	// Discard the successful POST body. Stored GET must recover the immutable
	// request without replaying admission, Guest work or provider operations.
	w = httptest.NewRecorder()
	h.ServeHTTP(w, makeRequest(http.MethodGet, base+"/"+req.PreregistrationID, false))
	var rows []map[string]any
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &rows) != nil || len(rows) != 1 || rows[0]["stage"] != "requested" || rows[0]["retirement_request_id"] != req.RetirementRequestID || rows[0]["normal_guest_success_claimed"] != false || rows[0]["guest_command_replayed"] != false || rows[0]["native_off_observed"] != false {
		t.Fatal("lost-response stored read did not preserve original failure", w.Code)
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, makeRequest(http.MethodPost, base, true))
	if w.Code != http.StatusConflict {
		t.Fatal("duplicate historical POST was replayed", w.Code)
	}
}
