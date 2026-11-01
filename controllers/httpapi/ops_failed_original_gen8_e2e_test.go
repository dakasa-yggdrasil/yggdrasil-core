package httpapi

// Isolated end-to-end qualification fixture. All identities, observations,
// JWT verification and provider responses are synthetic; there is no provider
// contact or production authority. Core handlers and PostgreSQL are real.
import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/contactphone"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	amqp "github.com/rabbitmq/amqp091-go"
	"go.uber.org/zap"
)

func TestLABGen8AuthenticatedHTTPPostgresLostResponse(t *testing.T) {
	seedBin := os.Getenv("LAB_GEN8_REPOSITORY_TEST_BIN")
	if seedBin == "" {
		t.Skip("explicit LAB integration only")
	}
	dsn := os.Getenv("ORIGINAL_CREATE_DISPOSITION_PG_DSN")
	if !strings.Contains(dsn, "host=/") || !strings.Contains(dsn, "dbname=original_disposition_test_") {
		t.Fatal("isolated Unix PostgreSQL required")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var dbName string
	var local bool
	var schema int
	if err = db.QueryRow(`SELECT current_database(),inet_server_addr() IS NULL,(SELECT max(version_id) FROM public.goose_db_version WHERE is_applied)`).Scan(&dbName, &local, &schema); err != nil || !local || !strings.HasPrefix(dbName, "original_disposition_test_") || schema != 82 {
		t.Fatal("isolated schema82 required", err)
	}
	brokerURL := os.Getenv("LAB_GEN8_BROKER_URL")
	brokerAddress, parseErr := url.Parse(brokerURL)
	if parseErr != nil || brokerAddress.Scheme != "amqp" || brokerAddress.Hostname() != "127.0.0.1" || brokerAddress.Port() == "" || brokerAddress.User == nil {
		t.Fatal("explicit loopback broker required")
	}
	broker, err := amqp.Dial(brokerURL)
	if err != nil {
		t.Fatal(err)
	}
	defer broker.Close()
	if broker.IsClosed() {
		t.Fatal("broker closed")
	}
	dir := t.TempDir()
	if err = os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	rawType, err := os.ReadFile("../../repository/testdata/capacity_aws_denied_source_expected_1655_type_spec.json")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	counts := map[string]int{}
	var seedURL, seedToken string
	adapter := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		observer := strings.HasPrefix(r.Host, "integration-aws-accepted-failed-readonly.")
		k := r.Method + " " + r.URL.Path
		if observer {
			k = "observer " + k
		} else {
			k = "creator " + k
		}
		mu.Lock()
		counts[k]++
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if !observer && r.Method == "GET" && r.URL.Path == "/" {
			w.WriteHeader(200)
			return
		}
		if !observer && r.Method == "POST" && r.URL.Path == "/rpc/describe" {
			_, _ = w.Write(rawType)
			return
		}
		if observer && r.Method == "POST" && r.URL.Path == "/rpc/describe" {
			_ = json.NewEncoder(w).Encode(map[string]any{"schema": "aws_original_enrolled_failed_create_readonly_describe_v1", "provider": "aws-accepted-failed-readonly", "version": "1.65.7", "source_commit": "2f2273391775ff0c8c1c65db6708a59bcc747018", "transport": "http_json", "describe_endpoint": "/rpc/describe", "execute_endpoint": "/rpc/execute", "operation": "observe_original_enrolled_failed_create_absence", "request_schema": "aws_original_enrolled_failed_create_absence_read_request_v1", "original_adapter_version": "1.65.5", "original_adapter_source_commit": "c34e330d8b266bb88e29ae7cf7b01df6f9fd96ce", "native_mutations": 0, "normal_adapter_operations": false, "AMQP_registered": false})
			return
		}
		if observer && r.Method == "POST" && r.URL.Path == "/rpc/execute" {
			var envelope map[string]any
			if json.NewDecoder(io.LimitReader(r.Body, 2<<20)).Decode(&envelope) != nil || envelope["operation"] != "observe_original_enrolled_failed_create_absence" || envelope["capability"] != "observe_original_enrolled_failed_create_absence" {
				http.Error(w, "closed fixture operation required", 400)
				return
			}
			mu.Lock()
			observationURL := seedURL + "/observation/" + seedToken
			mu.Unlock()
			resp, e := http.Get(observationURL)
			if e != nil {
				http.Error(w, "fixture unavailable", 500)
				return
			}
			defer resp.Body.Close()
			if resp.StatusCode != 200 {
				http.Error(w, "fixture held", 500)
				return
			}
			var observation any
			if json.NewDecoder(resp.Body).Decode(&observation) != nil {
				http.Error(w, "fixture invalid", 500)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"operation": envelope["operation"], "capability": envelope["capability"], "status": "observed", "output": observation})
			return
		}
		http.Error(w, "fixture route refused", 404)
	}))
	defer adapter.Close()
	oldTransport := http.DefaultTransport
	tr := oldTransport.(*http.Transport).Clone()
	tr.Proxy = nil
	d := &net.Dialer{Timeout: 2 * time.Second}
	tr.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, _, e := net.SplitHostPort(address)
		if e != nil {
			return nil, e
		}
		if host == "integration-aws-accepted-failed-readonly.dakasa.svc.cluster.local" {
			address = strings.TrimPrefix(adapter.URL, "http://")
		} else if host != "127.0.0.1" {
			return nil, fmt.Errorf("LAB non-loopback refused")
		}
		return d.DialContext(ctx, network, address)
	}
	http.DefaultTransport = tr
	defer func() { http.DefaultTransport = oldTransport; tr.CloseIdleConnections() }()
	seed := exec.Command(seedBin, "-test.run=^TestLABGen8SeedAndReadonlyObserver$", "-test.v")
	seed.Dir = "../../repository"
	seed.Env = append(os.Environ(), "LAB_GEN8_FIXTURE_DIR="+dir, "LAB_GEN8_CREATOR_URL="+adapter.URL)
	var seedLog bytes.Buffer
	seed.Stdout = &seedLog
	seed.Stderr = &seedLog
	if err = seed.Start(); err != nil {
		t.Fatal(err)
	}
	seedFinished := false
	defer func() {
		if !seedFinished && seed.Process != nil {
			_ = seed.Process.Kill()
			_ = seed.Wait()
		}
	}()
	var meta map[string]string
	for until := time.Now().Add(20 * time.Second); time.Now().Before(until); time.Sleep(20 * time.Millisecond) {
		raw, e := os.ReadFile(filepath.Join(dir, "seed.json"))
		if e == nil && json.Unmarshal(raw, &meta) == nil {
			break
		}
	}
	if meta["grant"] == "" {
		_ = seed.Process.Kill()
		_ = seed.Wait()
		seedFinished = true
		t.Fatalf("seed failed to report: %s", seedLog.String())
	}
	mu.Lock()
	seedURL, seedToken = meta["seed_url"], meta["seed_token"]
	mu.Unlock()
	var grantBefore, runBefore, witnessBefore string
	if err = db.QueryRow(`SELECT grant_record::text FROM public.capacity_mutation_grants WHERE id=$1`, meta["grant"]).Scan(&grantBefore); err != nil {
		t.Fatal(err)
	}
	if err = db.QueryRow(`SELECT to_jsonb(w)::text FROM public.workflow_runs w WHERE id=$1`, meta["run"]).Scan(&runBefore); err != nil {
		t.Fatal(err)
	}
	if err = db.QueryRow(`SELECT witness_sha256 FROM public.capacity_guest_original_create_witnesses WHERE preregistration_id=$1`, meta["pre"]).Scan(&witnessBefore); err != nil {
		t.Fatal(err)
	}
	defer func() {
		resp, e := http.Post(seedURL+"/shutdown/"+seedToken, "application/json", nil)
		if e == nil {
			_ = resp.Body.Close()
		} else {
			_ = seed.Process.Kill()
		}
		if e = seed.Wait(); e != nil {
			t.Errorf("seed exit: %v %s", e, seedLog.String())
		}
		seedFinished = true
	}()
	t.Setenv(contactphone.EnrollmentPolicyEnv, "false")
	t.Setenv("YGGDRASIL_CONSOLE_RBAC_ENFORCE", "enforce")
	actor := directoryHTTPPerson(t, db, false)
	traits := map[string]any{"yggdrasil_admin": true}
	if _, err = repository.UpdateCollaborator(t.Context(), db, model.UpdateCollaboratorRequest{ID: actor.ID.String(), Traits: &traits}); err != nil {
		t.Fatal(err)
	}
	s := &Server{db: db, rabbitmq: broker, logger: zap.NewNop()}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/ops/capacity/failed-original-dispositions", s.requireOpsPermissionFunc(permManageWorkflows, s.handleOpsFailedOriginalDisposition))
	mux.HandleFunc("GET /api/v1/ops/capacity/failed-original-dispositions/{grantId}", s.requireOpsPermissionFunc(permManageWorkflows, s.handleOpsFailedOriginalDispositionRead))
	authed := bearerOrSession(fakeJWTVerifier{validForToken: "lab-synthetic-token", claims: map[string]any{"collaborator_id": actor.ID.String()}})(mux)
	posts := 0
	status := 0
	wrapped := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			mu.Lock()
			posts++
			mu.Unlock()
			rec := httptest.NewRecorder()
			authed.ServeHTTP(rec, r)
			mu.Lock()
			status = rec.Code
			code := status
			mu.Unlock()
			if code != http.StatusCreated {
				http.Error(w, fmt.Sprintf("LAB handler failed %d: %s", code, rec.Body.String()), code)
				return
			}
			h, ok := w.(http.Hijacker)
			if !ok {
				t.Error("hijack unavailable")
				return
			}
			conn, _, e := h.Hijack()
			if e != nil {
				t.Error(e)
				return
			}
			_ = conn.Close()
			return
		}
		authed.ServeHTTP(w, r)
	})
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "yggdrasil.dakasa.me"}, DNSNames: []string{"yggdrasil.dakasa.me"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	coreServer := httptest.NewUnstartedServer(wrapped)
	coreServer.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	coreServer.StartTLS()
	defer coreServer.Close()
	pool := x509.NewCertPool()
	parsedCert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool.AddCert(parsedCert)
	negativeTransport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "yggdrasil.dakasa.me", MinVersion: tls.VersionTLS12}}
	defer negativeTransport.CloseIdleConnections()
	negativeClient := &http.Client{Transport: negativeTransport, Timeout: 5 * time.Second}
	negativeReq, err := http.NewRequest(http.MethodGet, coreServer.URL+"/api/v1/ops/capacity/failed-original-dispositions/"+meta["grant"], nil)
	if err != nil {
		t.Fatal(err)
	}
	negativeReq.Header.Set("Authorization", "Bearer incorrect-lab-token")
	negativeResp, err := negativeClient.Do(negativeReq)
	if err != nil {
		t.Fatal("negative authenticated TLS request", err)
	}
	_ = negativeResp.Body.Close()
	if negativeResp.StatusCode != http.StatusUnauthorized {
		t.Fatal("invalid bearer admitted", negativeResp.StatusCode)
	}
	certPath := filepath.Join(dir, "core-ca.pem")
	if err = os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	_, port, err := net.SplitHostPort(coreServer.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"uncertain", "replay", "get"} {
		cmd := exec.Command("python3", "-I", "-B", "testdata/lab_gen8_courier/run_fixture.py", action, dir, port, certPath, meta["grant"], meta["job"])
		out, e := cmd.CombinedOutput()
		if e != nil {
			mu.Lock()
			code := status
			observed := make(map[string]int, len(counts))
			for k, v := range counts {
				observed[k] = v
			}
			mu.Unlock()
			t.Fatalf("courier %s: %v %s; handler=%d fixture_routes=%v", action, e, out, code, observed)
		}
		t.Logf("courier %s: %s", action, strings.TrimSpace(string(out)))
	}
	mu.Lock()
	postCount, finalStatus := posts, status
	mu.Unlock()
	if postCount != 1 || finalStatus != 201 {
		t.Fatalf("one original POST required: posts=%d status=%d", postCount, finalStatus)
	}
	var count int
	var state string
	var ack sql.NullTime
	if err = db.QueryRow(`SELECT count(*) FROM public.capacity_failed_original_dispositions WHERE grant_id=$1`, meta["grant"]).Scan(&count); err != nil || count != 1 {
		t.Fatal("exactly one ledger", count, err)
	}
	if err = db.QueryRow(`SELECT state,finalization_ack_at FROM public.capacity_dispatch_jobs WHERE id=$1`, meta["job"]).Scan(&state, &ack); err != nil || state != "failed_disposed" || ack.Valid {
		t.Fatal("original unknown ACK changed", state, ack, err)
	}
	var grantAfter, runAfter, witnessAfter string
	if err = db.QueryRow(`SELECT grant_record::text FROM public.capacity_mutation_grants WHERE id=$1`, meta["grant"]).Scan(&grantAfter); err != nil || grantAfter != grantBefore {
		t.Fatal("original grant changed", err)
	}
	if err = db.QueryRow(`SELECT to_jsonb(w)::text FROM public.workflow_runs w WHERE id=$1`, meta["run"]).Scan(&runAfter); err != nil || runAfter != runBefore {
		t.Fatal("original run changed", err)
	}
	if err = db.QueryRow(`SELECT witness_sha256 FROM public.capacity_guest_original_create_witnesses WHERE preregistration_id=$1`, meta["pre"]).Scan(&witnessAfter); err != nil || witnessAfter != witnessBefore {
		t.Fatal("original witness changed", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if counts["observer POST /rpc/execute"] != 1 || counts["observer POST /rpc/describe"] < 2 || counts["creator POST /rpc/describe"] < 1 {
		t.Fatal("expected read-only observer lifecycle", counts)
	}
	for route, count := range counts {
		if count > 0 && route != "observer POST /rpc/execute" && route != "observer POST /rpc/describe" && route != "creator POST /rpc/describe" && route != "creator GET /" {
			t.Fatal("unexpected adapter route", route, counts)
		}
	}
	t.Logf("LAB_AUTHENTICATED_CORE_SCHEMA82_GET_RECONCILED post=%d observer_execute=%d production_authority=false", posts, counts["observer POST /rpc/execute"])
}
