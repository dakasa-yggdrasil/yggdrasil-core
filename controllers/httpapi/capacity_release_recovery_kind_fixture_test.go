package httpapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// These negative requests use the actual default-deny middleware and verified
// TLS route. Their protocol-shaped body is not a native return certificate.
func TestCapacityMutationNativeResultAuthorizationPostgres(t *testing.T) {
	dsn := os.Getenv("DB_URL")
	if dsn == "" {
		if os.Getenv("REQUIRE_CAPACITY_POSTGRES") == "true" {
			t.Fatal("native result authorization requires actual PostgreSQL")
		}
		t.Skip("remote PostgreSQL native result authorization")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal("original PostgreSQL unavailable", err)
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	instanceID := uuid.NewString()
	credential := uuid.NewString()
	principal, err := json.Marshal([]capacityMutationPrincipalConfig{{PrincipalID: "native-result-wrong-capability", Status: "active", ExpiresAt: time.Now().Add(time.Hour), RotationID: "ci-only", TokenSHA256: fmt.Sprintf("%x", sha256.Sum256([]byte(credential))), IntegrationInstanceID: instanceID, Capabilities: []string{capacity.EnsureNativePodDrain}}})
	if err != nil {
		t.Fatal("original principal source unavailable", err)
	}
	t.Setenv(capacityMutationPrincipalsEnv, string(principal))
	t.Setenv("YGGDRASIL_CAPACITY_EXECUTION_ENABLED", "true")
	principals, err := loadCapacityMutationPrincipals(nil, nil, nil)
	if err != nil {
		t.Fatal("original mutation principal rejected", err)
	}
	server := &Server{db: db, capacityMutationPrincipals: principals}
	var escaped atomic.Bool
	handler := server.requireAuthenticatedConsoleAPIs(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		escaped.Store(true)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	original := httptest.NewTLSServer(handler)
	defer original.Close()
	for _, scenario := range []struct {
		name, token string
		status      int
	}{
		{"anonymous_result_default_deny", "", http.StatusUnauthorized},
		{"authenticated_result_wrong_capability", credential, http.StatusForbidden},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			commandID := uuid.New()
			result := model.CapacityNativeReleaseResult{Protocol: capacity.NativeReleaseResultProtocol, CommandID: commandID, AttemptID: uuid.New(), IntegrationInstanceID: instanceID, IntegrationTypeID: uuid.NewString(), Capability: capacity.DestroyNativePodProtection, RequestSHA256: strings.Repeat("a", 64), AdapterSourceCommit: strings.Repeat("b", 40), ReturnNonce: strings.Repeat("c", 64), OriginalStatus: 409, OriginalResponseSHA256: strings.Repeat("d", 64), Outcome: "rejected_no_effect", OneSend: true, DoReturned: true, ReadReturned: true, CloseReturned: true}
			raw, err := json.Marshal(result)
			if err != nil {
				t.Fatal("closed negative protocol body unavailable", err)
			}
			noAcknowledgement := func() {
				t.Helper()
				var results, adapterACKs, callerACKs, decisions int
				if err := db.QueryRowContext(ctx, `SELECT count(*),count(*) FILTER(WHERE adapter_ack_at IS NOT NULL),count(*) FILTER(WHERE caller_ack_at IS NOT NULL) FROM public.capacity_native_release_results WHERE command_id=$1`, commandID).Scan(&results, &adapterACKs, &callerACKs); err != nil {
					t.Fatal("original result census unavailable", err)
				}
				if err := db.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_native_release_recovery_decisions WHERE parent_command_id=$1 OR command_id=$1`, commandID).Scan(&decisions); err != nil {
					t.Fatal("original decision census unavailable", err)
				}
				if results != 0 || adapterACKs != 0 || callerACKs != 0 || decisions != 0 {
					t.Fatal("refused result request retained an ACK or recovery authority")
				}
			}
			noAcknowledgement()
			request, err := http.NewRequestWithContext(ctx, http.MethodPost, original.URL+capacityMutationBasePath+"/native/result", bytes.NewReader(raw))
			if err != nil {
				t.Fatal("original TLS result request unavailable", err)
			}
			request.Header.Set("Content-Type", "application/json")
			if scenario.token != "" {
				request.Header.Set("Authorization", "Bearer "+scenario.token)
			}
			reply, err := original.Client().Do(request)
			var body []byte
			var readErr, closeErr error
			if reply != nil && reply.Body != nil {
				body, readErr = io.ReadAll(io.LimitReader(reply.Body, 32769))
				closeErr = reply.Body.Close()
			}
			if err != nil || readErr != nil || closeErr != nil || reply == nil || reply.TLS == nil || len(reply.TLS.VerifiedChains) == 0 || len(body) > 32768 || reply.StatusCode != scenario.status || escaped.Load() {
				t.Fatal("original authenticated result route did not refuse the expected actor")
			}
			if bytes.Contains(body, []byte(credential)) || bytes.Contains(body, []byte(result.ReturnNonce)) {
				t.Fatal("result refusal disclosed a private credential")
			}
			noAcknowledgement()
		})
	}
}

// This proxy never manufactures an API status. Its one fixture-owned
// annotation mutation advances the REAL Pod RV before forwarding the original
// finalizer PUT unchanged, forcing the native API to return its genuine409.
func nativeReleaseConflictProxy(t *testing.T, ctx context.Context, path, realm string, enabled bool) (string, *atomic.Int32) {
	count := new(atomic.Int32)
	if !enabled {
		return path, count
	}
	rc, err := clientcmd.BuildConfigFromFlags("", path)
	if err != nil {
		t.Fatal("original operator transport unavailable")
	}
	rc = rest.CopyConfig(rc)
	rc.TLSClientConfig.NextProtos = []string{"http/1.1"}
	transport, err := rest.TransportFor(rc)
	if err != nil {
		t.Fatal("original operator auth unavailable")
	}
	origin, err := url.Parse(rc.Host)
	if err != nil {
		t.Fatal("original native API origin unavailable")
	}
	proxy := httputil.NewSingleHostReverseProxy(origin)
	proxy.Transport = transport
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/api/v1/namespaces/"+realm+"/pods/") {
			raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20+1))
			closeErr := r.Body.Close()
			if err != nil || closeErr != nil || len(raw) > 1<<20 {
				w.WriteHeader(503)
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(raw))
			var pod struct {
				Metadata struct {
					Name       string   `json:"name"`
					Finalizers []string `json:"finalizers"`
				} `json:"metadata"`
			}
			if json.Unmarshal(raw, &pod) != nil {
				w.WriteHeader(503)
				return
			}
			retained := false
			for _, f := range pod.Metadata.Finalizers {
				retained = retained || f == "yggdrasil.io/capacity-native-termination"
			}
			if !retained && count.CompareAndSwap(0, 1) {
				if err := exec.CommandContext(ctx, "kubectl", "-n", realm, "annotate", "pod", pod.Metadata.Name, "fixture.yggdrasil.io/native-conflict=original", "--overwrite").Run(); err != nil {
					w.WriteHeader(503)
					return
				}
			}
		}
		proxy.ServeHTTP(w, r)
	}))
	t.Cleanup(server.Close)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("original private kubeconfig unavailable")
	}
	config, err := clientcmd.Load(raw)
	if err != nil {
		t.Fatal("original private kubeconfig invalid")
	}
	cluster := config.Clusters[config.Contexts[config.CurrentContext].Cluster]
	cluster.Server = server.URL
	cluster.CertificateAuthority = ""
	cluster.CertificateAuthorityData = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	cluster.InsecureSkipTLSVerify = false
	out, err := clientcmd.Write(*config)
	if err != nil {
		t.Fatal("fixed native proxy transport unavailable")
	}
	bound := filepath.Join(t.TempDir(), "original-one-send.kubeconfig")
	if os.WriteFile(bound, out, 0600) != nil {
		t.Fatal("fixed native private transport write failed")
	}
	return bound, count
}

func TestCapacityNativeReleaseRecoveryKinDHTTP(t *testing.T) {
	if os.Getenv("REQUIRE_CAPACITY_NATIVE_KIND") != "true" {
		t.Skip("remote original native release recovery")
	}
	for _, name := range []string{"forced_conflict_new_authority_confirmed", "forced_conflict_adapter_ack_held", "forced_conflict_caller_ack_held", "forced_conflict_source_changed_hold", "forced_conflict_rbac_revoked_hold", "forced_conflict_late_owner_hold", "stale_witness_unredeemed_original_retry"} {
		t.Run(name, func(t *testing.T) { qualifyCapacityNativeKinDHTTP(t, false, "", false, name) })
	}
}

func assertNativeReleaseNoRecoveryBeforeCaller(t *testing.T, parent context.Context, db *sql.DB, realm string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	var pending, decisions int
	err := db.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_native_release_results r JOIN public.capacity_native_command_identities i ON i.id=r.command_id WHERE i.namespace=$1 AND r.adapter_ack_at IS NOT NULL AND r.caller_ack_at IS NULL`, realm).Scan(&pending)
	if err != nil || db.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_native_release_recovery_decisions d JOIN public.capacity_native_command_identities i ON i.id=d.command_id WHERE i.namespace=$1`, realm).Scan(&decisions) != nil || pending != 1 || decisions != 0 {
		t.Error("held ORIGINAL callback/caller return admitted recovery")
	}
}

func assertNativeReleaseRecoveryIdentities(t *testing.T, ctx context.Context, db *sql.DB, realm, source string, conflicts int32) {
	t.Helper()
	var count int
	err := db.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_native_release_recovery_decisions d JOIN public.capacity_native_commands child ON child.id=d.command_id JOIN public.capacity_native_commands parent ON parent.id=d.parent_command_id JOIN public.capacity_native_release_results r ON r.command_id=parent.id WHERE child.namespace=$1 AND parent.state='rejected_no_effect' AND child.state='confirmed' AND parent.command_record->>'adapter_source_commit'=$2 AND child.id<>parent.id AND child.authority_token_sha256<>parent.authority_token_sha256 AND child.command_record->>'attempt_id'<>parent.command_record->>'attempt_id' AND child.command_record->>'parent_attempt_id'=parent.command_record->>'attempt_id' AND d.fence::text=child.command_record->>'recovery_fence' AND child.command_record->>'expires_at'=parent.command_record->>'expires_at' AND r.adapter_ack_at IS NOT NULL AND r.caller_ack_at IS NOT NULL`, realm, source).Scan(&count)
	if err != nil || conflicts != 1 || count != 1 {
		t.Fatal("genuine native409 did not reach new durable fenced release", err)
	}
	var rejected int
	if db.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_native_commands WHERE namespace=$1 AND state='rejected_no_effect' AND operation=$2`, realm, capacity.DestroyNativePodProtection).Scan(&rejected) != nil || rejected != 1 {
		t.Fatal("original native409 was relabelled or replayed")
	}
}

func nativeCoreResultTrust(t *testing.T, server *httptest.Server) string {
	t.Helper()
	if server.Certificate() == nil {
		t.Fatal("native callback TLS source absent")
	}
	if _, err := x509.ParseCertificate(server.Certificate().Raw); err != nil {
		t.Fatal("native callback certificate invalid")
	}
	path := filepath.Join(t.TempDir(), "native-core-tls.pem")
	if os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600) != nil {
		t.Fatal("native callback trust source write failed")
	}
	return path
}

type nativeReleaseIdentityRow struct {
	sequence   int
	state      string
	redeemedBy string
	attempt    string
	parent     string
	results    int
	decisions  int
}

// A release identity that was never redeemed carries no attempt, no original
// result and no recovery decision. Its state alone is not that proof.
func (r nativeReleaseIdentityRow) unredeemedRefusal() bool {
	return r.state == "refused_no_redemption" && r.redeemedBy == "" && r.attempt == uuid.Nil.String() && r.results == 0 && r.decisions == 0
}

// Every permanent release identity of one Pod, hot or archived, in sequence.
func nativeReleaseIdentities(t *testing.T, ctx context.Context, db *sql.DB, realm, subject string) []nativeReleaseIdentityRow {
	t.Helper()
	rows, err := db.QueryContext(ctx, `SELECT i.sequence,COALESCE(c.state,a.command_record->>'state',''),COALESCE(c.command_record->>'redeemed_by',a.command_record->>'redeemed_by',''),COALESCE(c.command_record->>'attempt_id',a.command_record->>'attempt_id',''),COALESCE(c.command_record->>'parent_command_id',a.command_record->>'parent_command_id',''),(SELECT count(*) FROM public.capacity_native_release_results r WHERE r.command_id=i.id),(SELECT count(*) FROM public.capacity_native_release_recovery_decisions d WHERE d.parent_command_id=i.id OR d.command_id=i.id) FROM public.capacity_native_command_identities i LEFT JOIN public.capacity_native_commands c ON c.id=i.id LEFT JOIN public.capacity_native_command_archive a ON a.id=i.id WHERE i.namespace=$1 AND i.subject_uid=$2 AND i.operation=$3 AND i.phase='release' ORDER BY i.sequence`, realm, subject, capacity.DestroyNativePodProtection)
	if err != nil {
		t.Fatal("original release identity census unavailable", err)
	}
	defer rows.Close()
	out := []nativeReleaseIdentityRow{}
	for rows.Next() {
		var row nativeReleaseIdentityRow
		if err := rows.Scan(&row.sequence, &row.state, &row.redeemedBy, &row.attempt, &row.parent, &row.results, &row.decisions); err != nil {
			t.Fatal("original release identity row unavailable", err)
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		t.Fatal("original release identity census incomplete", err)
	}
	return out
}

// Leading original refusals proven unredeemed before the single redeemed
// parent are not replacement authority; any identity after it would be.
func nativeReleaseUnredeemedPredecessors(t *testing.T, ctx context.Context, db *sql.DB, realm, subject string) int {
	t.Helper()
	leading := 0
	for _, row := range nativeReleaseIdentities(t, ctx, db, realm, subject) {
		if !row.unredeemedRefusal() {
			break
		}
		leading++
	}
	return leading
}

// The fixture advanced the REAL Pod RV between Core's current witness and the
// original adapter read. The installed adapter must itself refuse before any
// redemption; Core revokes that token and only a fresh witness mints the next
// ORIGINAL permission. A refusal never hides a redemption or a recovery.
func assertNativeReleaseStaleWitnessRetry(t *testing.T, ctx context.Context, db *sql.DB, realm, subject string, injected int32, adapterLog string) {
	t.Helper()
	raw, err := os.ReadFile(adapterLog)
	if err != nil {
		t.Fatal("actual native adapter diagnostics unavailable", err)
	}
	refusedBeforeRedemption := false
	for _, line := range strings.Split(string(raw), "\n") {
		_, payload, found := strings.Cut(line, "NATIVE_POD_ORIGINAL_REFUSAL_V1:")
		if !found {
			continue
		}
		var facts struct {
			Phase          string `json:"phase"`
			Terminated     bool   `json:"terminated_state"`
			ReceiptPresent bool   `json:"receipt_present"`
			VersionMatched bool   `json:"resource_version_matched"`
			Authority      bool   `json:"authority"`
		}
		if json.Unmarshal([]byte(strings.TrimSpace(payload)), &facts) == nil && facts.Phase == "release-observe" && facts.Terminated && facts.ReceiptPresent && !facts.VersionMatched && !facts.Authority {
			refusedBeforeRedemption = true
		}
	}
	identities := nativeReleaseIdentities(t, ctx, db, realm, subject)
	if injected != 1 || !refusedBeforeRedemption || len(identities) < 2 || identities[0].sequence != 1 || !identities[0].unredeemedRefusal() {
		t.Fatal("stale original witness was not refused by the adapter and revoked unredeemed", injected, refusedBeforeRedemption, len(identities))
	}
	fresh := false
	for _, row := range identities[1:] {
		if row.state == "refused_no_redemption" && !row.unredeemedRefusal() {
			t.Fatal("a refused original release hides a redemption or recovery")
		}
		fresh = fresh || (row.parent == "" && row.results == 1 && row.state != "refused_no_redemption" && row.attempt != uuid.Nil.String())
	}
	if !fresh {
		t.Fatal("no fresh original permission followed the revoked stale witness")
	}
}

func nativeReleaseIdentityCount(t *testing.T, ctx context.Context, db *sql.DB, realm string) int {
	t.Helper()
	var n int
	if db.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_native_command_identities WHERE namespace=$1`, realm).Scan(&n) != nil {
		t.Fatal("complete original native identity census unavailable")
	}
	return n
}
