//go:build recoveryfixture && !nativequalification

package httpapi

// This test process is launched only by the signed repository fixture. The
// real handler and DB are used; tokens, signatures and all history are test
// data, and no Guest or provider transport is contacted.
import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/contactphone"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	amqp "github.com/rabbitmq/amqp091-go"
	"go.uber.org/zap"
)

func TestLABHetznerSignedDisposalHTTP(t *testing.T) {
	fixtureDir := os.Getenv("LAB_HETZNER_HTTP_FIXTURE_DIR")
	if fixtureDir == "" {
		t.Skip("explicit LAB fixture only")
	}
	dsn, err := url.Parse(os.Getenv("LAB_HETZNER_DB_URL"))
	if err != nil || dsn.Hostname() != "127.0.0.1" || !strings.HasPrefix(strings.TrimPrefix(dsn.Path, "/"), "recovery_fixture_") {
		t.Fatal("disposable local DB required")
	}
	db, err := sql.Open("postgres", dsn.String())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	originalTransport := http.DefaultTransport
	loopbackTransport := originalTransport.(*http.Transport).Clone()
	loopbackTransport.Proxy = nil
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	loopbackTransport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, _, e := net.SplitHostPort(address)
		if e != nil || host != "127.0.0.1" {
			return nil, io.ErrUnexpectedEOF
		}
		return dialer.DialContext(ctx, network, address)
	}
	http.DefaultTransport = loopbackTransport
	defer func() { http.DefaultTransport = originalTransport; loopbackTransport.CloseIdleConnections() }()
	var name string
	var major int
	if err = db.QueryRow(`SELECT current_database(),current_setting('server_version_num')::int/10000`).Scan(&name, &major); err != nil || name != strings.TrimPrefix(dsn.Path, "/") || major != 16 {
		t.Fatal("fixture DB identity", err)
	}
	var policy model.CapacityPolicySpec
	raw, err := os.ReadFile(filepath.Join(fixtureDir, "policy.json"))
	if err != nil || json.Unmarshal(raw, &policy) != nil || policy.GuestRetirementBinding == nil {
		t.Fatal("synthetic policy required")
	}
	capacity.RecoveryFixtureApprovalScope(t)
	if err = capacity.RegisterRecoveryFixtureApproval(policy, *policy.GuestRetirementBinding, "hetzner"); err != nil {
		t.Fatal(err)
	}
	brokerURL, err := url.Parse(os.Getenv("LAB_HETZNER_BROKER_URL"))
	if err != nil || brokerURL.Scheme != "amqp" || brokerURL.Hostname() != "127.0.0.1" || brokerURL.Port() == "" {
		t.Fatal("isolated broker required")
	}
	broker, err := amqp.Dial(brokerURL.String())
	if err != nil {
		t.Fatal(err)
	}
	defer broker.Close()
	preID, lastRun := os.Getenv("LAB_HETZNER_PRE"), os.Getenv("LAB_HETZNER_FAILED_RUN")
	if !dispositionGrantID(preID) || !dispositionGrantID(lastRun) {
		t.Fatal("synthetic original IDs required")
	}
	t.Setenv(contactphone.EnrollmentPolicyEnv, "false")
	t.Setenv("YGGDRASIL_CONSOLE_RBAC_ENFORCE", "enforce")
	actor := directoryHTTPPerson(t, db, false)
	traits := map[string]any{"yggdrasil_admin": true}
	if _, err = repository.UpdateCollaborator(t.Context(), db, model.UpdateCollaboratorRequest{ID: actor.ID.String(), Traits: &traits}); err != nil {
		t.Fatal(err)
	}
	s := &Server{db: db, rabbitmq: broker, logger: zap.NewNop()}
	mux := http.NewServeMux()
	route := "/api/v1/ops/capacity/failed-installed-guest-disposals"
	mux.HandleFunc("POST "+route, s.requireOpsPermissionFunc(permManageWorkflows, s.handleOpsFailedInstalledGuestDisposal))
	mux.HandleFunc("GET "+route+"/{preregistrationId}", s.requireOpsPermissionFunc(permManageWorkflows, s.handleOpsFailedInstalledGuestDisposalRead))
	mux.HandleFunc("POST "+route+"/advance", s.requireOpsPermissionFunc(permManageWorkflows, s.handleOpsFailedInstalledGuestDisposalAdvance))
	authed := bearerOrSession(fakeJWTVerifier{validForToken: "lab-hetzner-only", claims: map[string]any{"collaborator_id": actor.ID.String()}})(mux)
	var requests atomic.Int32
	var admitted atomic.Int32
	outer := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" && r.URL.Path == route {
			requests.Add(1)
			rec := httptest.NewRecorder()
			authed.ServeHTTP(rec, r)
			admitted.Store(int32(rec.Code))
			if rec.Code != 201 {
				http.Error(w, "LAB admission held", rec.Code)
				return
			}
			hj, ok := w.(http.Hijacker)
			if !ok {
				t.Error("hijack unavailable")
				return
			}
			conn, _, e := hj.Hijack()
			if e != nil {
				t.Error(e)
				return
			}
			_ = conn.Close()
			return
		}
		authed.ServeHTTP(w, r)
	})
	server := httptest.NewTLSServer(outer)
	defer server.Close()
	client := server.Client()
	client.Timeout = 15 * time.Second
	call := func(method, path, token string, body []byte) (*http.Response, error) {
		req, e := http.NewRequest(method, server.URL+path, bytes.NewReader(body))
		if e != nil {
			return nil, e
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		return client.Do(req)
	}
	negative, e := call("GET", route+"/"+preID, "invalid", nil)
	if e != nil {
		t.Fatal(e)
	}
	_ = negative.Body.Close()
	if negative.StatusCode != 401 {
		t.Fatal("invalid bearer accepted")
	}
	marker := filepath.Join(fixtureDir, "request-possible-send")
	f, e := os.OpenFile(marker, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.WriteString("one original POST; GET only after unknown\n"); e != nil {
		t.Fatal(e)
	}
	if e = f.Sync(); e != nil {
		t.Fatal(e)
	}
	_ = f.Close()
	parent, e := os.Open(fixtureDir)
	if e != nil {
		t.Fatal(e)
	}
	e = parent.Sync()
	_ = parent.Close()
	if e != nil {
		t.Fatal(e)
	}
	payload, _ := json.Marshal(map[string]string{"preregistration_id": preID, "expected_failed_run_id": lastRun, "replacement_mode": repository.FailedInstalledCoreReplacementMode})
	response, e := call("POST", route, "lab-hetzner-only", payload)
	if response != nil {
		_ = response.Body.Close()
	}
	if e == nil || admitted.Load() != 201 {
		t.Fatalf("expected original committed/lost response status=%d error=%v", admitted.Load(), e)
	}
	if _, e = os.Stat(marker); e != nil {
		t.Fatal("durable no-replay marker lost")
	}
	// An existing possible-send marker prohibits a second POST; reconciliation is GET only.
	if f, e = os.OpenFile(marker, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600); e == nil {
		_ = f.Close()
		t.Fatal("duplicate marker accepted")
	}
	got, e := call("GET", route+"/"+preID, "lab-hetzner-only", nil)
	if e != nil {
		t.Fatal(e)
	}
	defer got.Body.Close()
	if got.StatusCode != 200 {
		t.Fatal("readback", got.StatusCode)
	}
	var rows []map[string]any
	if json.NewDecoder(got.Body).Decode(&rows) != nil || len(rows) != 1 || rows[0]["stage"] != "requested" || rows[0]["retirement_mode"] != "original_production_v2" || rows[0]["business_effects_preserved"] != true || rows[0]["replacement_mode"] != repository.FailedInstalledCoreReplacementMode {
		t.Fatal("disposition readback")
	}
	admission, ok := rows[0]["id"].(string)
	if !ok || !dispositionGrantID(admission) {
		t.Fatal("admission identity")
	}
	payload, _ = json.Marshal(map[string]string{"preregistration_id": preID, "admission_id": admission})
	denied, e := call("POST", route+"/advance", "lab-hetzner-only", payload)
	if e != nil {
		t.Fatal(e)
	}
	_, _ = io.Copy(io.Discard, denied.Body)
	_ = denied.Body.Close()
	if denied.StatusCode != 409 {
		t.Fatal("advance without V2 quiescence admitted", denied.StatusCode)
	}
	var count int
	if err = db.QueryRow(`SELECT count(*) FROM public.capacity_guest_failed_installed_disposals WHERE preregistration_id=$1`, preID).Scan(&count); err != nil || count != 1 || requests.Load() != 1 {
		t.Fatal("duplicate or unproved transition", count, requests.Load(), err)
	}
	// Ensure this process has not resolved a non-loopback provider by accident.
	if host, _, e := net.SplitHostPort(server.Listener.Addr().String()); e != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		t.Fatal("fixture server not loopback")
	}
	t.Log("LAB_HETZNER_CORE_BOUND_HTTPS_LOST_RESPONSE_GET_ONLY_ADVANCE_HELD production_authority=false")
}
