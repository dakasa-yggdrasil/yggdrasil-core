package httpapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"errors"
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
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

type nativeRecoveryFrameRequest struct {
	Operation string `json:"operation"`
	Input     struct {
		PodName string `json:"pod_name"`
	} `json:"input"`
}

// The one real RV-race injection belongs only to an original execute request.
// Core also performs empty-body connectivity GETs through this same proxy;
// describe and connectivity requests must reach the original adapter unchanged.
func nativeRecoveryFrameExecuteRequest(r *http.Request, raw []byte) (nativeRecoveryFrameRequest, error) {
	var out nativeRecoveryFrameRequest
	if r.Method != http.MethodPost || r.URL.Path != "/rpc/execute" {
		return out, nil
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return out, errors.New("original recovery execute request unavailable")
	}
	return out, nil
}

func TestCapacityNativeRecoveryFrameProxyRoutes(t *testing.T) {
	for _, scenario := range []struct {
		name, method, path, body, operation, pod string
		refused                                  bool
	}{
		{"original_empty_connectivity_get", http.MethodGet, "/", "", "", "", false},
		{"original_empty_health_get", http.MethodGet, "/healthz", "", "", "", false},
		{"original_describe_post", http.MethodPost, "/rpc/describe", "{}", "", "", false},
		{"other_route_is_not_execute", http.MethodPost, "/other", "", "", "", false},
		{"get_execute_cannot_inject", http.MethodGet, "/rpc/execute", `{"operation":"observe_capacity_pod_inventory","input":{"pod_name":"original"}}`, "", "", false},
		{"original_inventory_execute", http.MethodPost, "/rpc/execute", `{"operation":"observe_capacity_pod_inventory","input":{"pod_name":"original"}}`, capacity.ObserveNativePodInventory, "original", false},
		{"original_release_execute", http.MethodPost, "/rpc/execute", `{"operation":"destroy_capacity_pod_drain_protection","input":{"pod_name":"original"}}`, capacity.DestroyNativePodProtection, "original", false},
		{"malformed_execute_refused", http.MethodPost, "/rpc/execute", "{", "", "", true},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			r := httptest.NewRequest(scenario.method, "http://original"+scenario.path, strings.NewReader(scenario.body))
			raw, readErr := io.ReadAll(r.Body)
			closeErr := r.Body.Close()
			if readErr != nil || closeErr != nil {
				t.Fatal("original proxy request read/close unavailable")
			}
			operation, err := nativeRecoveryFrameExecuteRequest(r, raw)
			if (err != nil) != scenario.refused || operation.Operation != scenario.operation || operation.Input.PodName != scenario.pod || string(raw) != scenario.body {
				t.Fatal("non-execute request gained an injection or original execute request was changed")
			}
		})
	}
}

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
	rc.NextProtos = []string{"http/1.1"}
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
	for _, name := range []string{"forced_conflict_new_authority_confirmed", "forced_conflict_adapter_ack_held", "forced_conflict_caller_ack_held", "forced_conflict_source_changed_hold", "forced_conflict_rbac_revoked_hold", "forced_conflict_late_owner_hold", "stale_witness_unredeemed_original_retry", "forced_conflict_recovery_inventory_race"} {
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

func assertNativeReleaseRecoveryIdentities(t *testing.T, ctx context.Context, db *sql.DB, realm, subject, source string, conflicts int32, policy model.Manifest, p model.CapacityPolicySpec, snapshot []byte, census nativeReleaseChainCensus) {
	t.Helper()
	var count int
	err := db.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_native_release_recovery_decisions d JOIN public.capacity_native_commands child ON child.id=d.command_id JOIN public.capacity_native_commands parent ON parent.id=d.parent_command_id JOIN public.capacity_native_release_results r ON r.command_id=parent.id WHERE child.namespace=$1 AND parent.state='rejected_no_effect' AND child.state='confirmed' AND parent.command_record->>'adapter_source_commit'=$2 AND child.id<>parent.id AND child.authority_token_sha256<>parent.authority_token_sha256 AND child.command_record->>'attempt_id'<>parent.command_record->>'attempt_id' AND child.command_record->>'parent_attempt_id'=parent.command_record->>'attempt_id' AND d.fence::text=child.command_record->>'recovery_fence' AND child.command_record->>'expires_at'=parent.command_record->>'expires_at' AND r.adapter_ack_at IS NOT NULL AND r.caller_ack_at IS NOT NULL`, realm, source).Scan(&count)
	if err != nil || conflicts != 1 || count != 1 {
		t.Fatal("genuine native409 did not reach new durable fenced release", err)
	}
	var original struct {
		Bundle struct {
			Checkpoint model.CapacityNativePodCheckpoint `json:"checkpoint"`
		} `json:"bundle"`
	}
	if json.Unmarshal(snapshot, &original) != nil {
		t.Fatal("original released checkpoint census unavailable")
	}
	if err := validateNativeReleaseChain(census, realm, subject, source, policy, p, original.Bundle.Checkpoint); err != nil {
		t.Fatal("original native409 chain was relabelled, replayed or admitted without exact authority", err)
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

// One event of `kubectl get pod --watch --output-watch-events
// --show-managed-fields -o json` for the victim Pod.
type nativeKindPodWatchEvent struct {
	Type   string `json:"type"`
	Object struct {
		Metadata struct {
			ResourceVersion            string            `json:"resourceVersion"`
			DeletionGracePeriodSeconds *int64            `json:"deletionGracePeriodSeconds"`
			Finalizers                 []string          `json:"finalizers"`
			Annotations                map[string]string `json:"annotations"`
			ManagedFields              []struct {
				Manager     string `json:"manager"`
				Operation   string `json:"operation"`
				Subresource string `json:"subresource"`
				Time        string `json:"time"`
			} `json:"managedFields"`
		} `json:"metadata"`
		Status json.RawMessage `json:"status"`
	} `json:"object"`
}

type nativeKindPodWatchStatus struct {
	Phase      string `json:"phase"`
	Conditions []struct {
		Type   string `json:"type"`
		Status string `json:"status"`
	} `json:"conditions"`
	ContainerStatuses []struct {
		Ready bool                       `json:"ready"`
		State map[string]json.RawMessage `json:"state"`
	} `json:"containerStatuses"`
}

// One version of the victim Pod, as diagnostics only and never an oracle.
// Annotation values (the drain challenge among them) and the complete status
// appear only as a short digest, so a rewrite under an unchanged key or field
// list is still visible without printing the value.
type nativeKindPodVersion struct {
	at      time.Time
	event   string
	facts   map[string]string
	writers []string
}

var nativeKindPodFactKeys = []string{"grace", "phase", "containers", "conditions", "status", "finalizers", "annotations"}

func nativeKindPodVersionOf(at time.Time, e nativeKindPodWatchEvent) nativeKindPodVersion {
	m := e.Object.Metadata
	grace := "unset"
	if m.DeletionGracePeriodSeconds != nil {
		grace = strconv.FormatInt(*m.DeletionGracePeriodSeconds, 10)
	}
	annotations := []string{}
	for key, value := range m.Annotations {
		digest := sha256.Sum256([]byte(value))
		annotations = append(annotations, fmt.Sprintf("%s#%.4x", key, digest[:]))
	}
	sort.Strings(annotations)
	var status nativeKindPodWatchStatus
	var compact bytes.Buffer
	statusDigest := "undecoded"
	if json.Compact(&compact, e.Object.Status) == nil && json.Unmarshal(e.Object.Status, &status) == nil {
		digest := sha256.Sum256(compact.Bytes())
		statusDigest = fmt.Sprintf("%.4x", digest[:])
	}
	conditions := []string{}
	for _, c := range status.Conditions {
		conditions = append(conditions, c.Type+"="+c.Status)
	}
	sort.Strings(conditions)
	containers := []string{}
	for _, c := range status.ContainerStatuses {
		states := []string{}
		for state := range c.State {
			states = append(states, state)
		}
		sort.Strings(states)
		containers = append(containers, strings.Join(states, "+")+"/ready="+strconv.FormatBool(c.Ready))
	}
	writers := []string{}
	for _, f := range m.ManagedFields {
		writers = append(writers, f.Manager+"/"+f.Operation+"/"+f.Subresource+"@"+f.Time)
	}
	sort.Strings(writers)
	return nativeKindPodVersion{at: at, event: e.Type, writers: writers, facts: map[string]string{"rv": m.ResourceVersion, "grace": grace, "phase": status.Phase, "containers": strings.Join(containers, ","), "conditions": strings.Join(conditions, ","), "status": statusDigest, "finalizers": strings.Join(m.Finalizers, ","), "annotations": strings.Join(annotations, ",")}}
}

// The facts that differ between two versions and every managedFields entry
// (manager/operation/subresource@time) the later version adds. A version that
// changes grace and adds no entry is only reported, not attributed here.
func nativeKindPodVersionChanges(previous, current nativeKindPodVersion) []string {
	changed := []string{}
	for _, key := range nativeKindPodFactKeys {
		if previous.facts[key] != current.facts[key] {
			changed = append(changed, key)
		}
	}
	seen := map[string]bool{}
	for _, writer := range previous.writers {
		seen[writer] = true
	}
	for _, writer := range current.writers {
		if !seen[writer] {
			changed = append(changed, "writer="+writer)
		}
	}
	return changed
}

// Successive watch events in arrival order. A stream cut by the watch stop
// keeps every complete event before the cut and returns its decode error.
func nativeKindDecodePodWatch(r io.Reader, now func() time.Time, record func(nativeKindPodVersion)) error {
	decoder := json.NewDecoder(r)
	for {
		var event nativeKindPodWatchEvent
		if err := decoder.Decode(&event); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		record(nativeKindPodVersionOf(now(), event))
	}
}

func nativeKindPodTimelineLines(versions []nativeKindPodVersion) []string {
	lines := make([]string, 0, len(versions))
	for i, v := range versions {
		changed := "first"
		if i > 0 {
			changed = strings.Join(nativeKindPodVersionChanges(versions[i-1], v), ";")
		}
		lines = append(lines, fmt.Sprintf("#%d at=%s event=%s rv=%s grace=%s phase=%s containers=%s conditions=%s status=%s finalizers=%s annotations=%s changed=%s writers=%s", i, v.at.Format(time.RFC3339Nano), v.event, v.facts["rv"], v.facts["grace"], v.facts["phase"], v.facts["containers"], v.facts["conditions"], v.facts["status"], v.facts["finalizers"], v.facts["annotations"], changed, strings.Join(v.writers, ",")))
	}
	return lines
}

// Read-only watch of one Pod from now on, with the local arrival time of each
// version. It never writes. A watch that cannot start is logged, never failed:
// it is diagnostics for the unknown resourceVersion writer, not an oracle. The
// stop line carries the last 2 KiB of kubectl stderr, so a watch that exits
// after Start still names its reason; WaitDelay bounds Wait on that copy.
func nativeKindWatchPod(t *testing.T, parent context.Context, realm, name string) func() []nativeKindPodVersion {
	t.Helper()
	ctx, cancel := context.WithCancel(parent)
	cmd := exec.CommandContext(ctx, "kubectl", "-n", realm, "get", "pod", name, "--watch", "--output-watch-events", "--show-managed-fields", "-o", "json")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	cmd.WaitDelay = 5 * time.Second
	stdout, err := cmd.StdoutPipe()
	if err == nil {
		err = cmd.Start()
	}
	if err != nil {
		cancel()
		t.Logf("native victim pod watch unavailable: %v", err)
		return func() []nativeKindPodVersion { return nil }
	}
	var mu sync.Mutex
	versions := []nativeKindPodVersion{}
	var decodeErr error
	done := make(chan struct{})
	go func() {
		defer close(done)
		err := nativeKindDecodePodWatch(stdout, func() time.Time { return time.Now().UTC() }, func(v nativeKindPodVersion) {
			mu.Lock()
			versions = append(versions, v)
			mu.Unlock()
		})
		mu.Lock()
		decodeErr = err
		mu.Unlock()
	}()
	var once sync.Once
	var out []nativeKindPodVersion
	return func() []nativeKindPodVersion {
		once.Do(func() {
			cancel()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
			}
			waitErr := cmd.Wait()
			<-done
			reason := stderr.Bytes()
			if len(reason) > 2048 {
				reason = reason[len(reason)-2048:]
			}
			mu.Lock()
			out = append([]nativeKindPodVersion(nil), versions...)
			stopErr := decodeErr
			mu.Unlock()
			t.Logf("native victim pod watch stopped versions=%d decode=%v wait=%v stderr=%q", len(out), stopErr, waitErr, reason)
		})
		return out
	}
}

// Durable facts of every release identity of one Pod (hot or archived), its
// original result and decisions, the durable inputs of the recovery admission
// predicate (parent state, protocol, caller return, expiry, result digest and
// deadline equality, intent generation, fence and lease), the intent and its
// recent phase events, and the latest durable witness. States, resource
// versions, times and equality booleans only: no token, nonce, digest value,
// request or result body.
func nativeKindLogReleaseLedger(t *testing.T, db *sql.DB, realm, subject string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	rows, err := db.QueryContext(ctx, `SELECT i.sequence,COALESCE(c.command_record,a.command_record),c.id IS NOT NULL,r.command_id IS NOT NULL,COALESCE(r.adapter_result->>'outcome',''),COALESCE(r.adapter_result->>'original_status',''),r.adapter_ack_at IS NOT NULL,r.caller_ack_at IS NOT NULL,(SELECT count(*) FROM public.capacity_native_release_recovery_decisions d WHERE d.parent_command_id=i.id),(SELECT count(*) FROM public.capacity_native_release_recovery_decisions d WHERE d.command_id=i.id),i.generation,COALESCE(c.state,''),c.updated_at,COALESCE(r.adapter_result_sha256=(COALESCE(c.command_record,a.command_record)->>'original_result_sha256'),false),COALESCE(r.original_deadline=(COALESCE(c.command_record,a.command_record)->>'expires_at')::timestamptz,false) FROM public.capacity_native_command_identities i LEFT JOIN public.capacity_native_commands c ON c.id=i.id LEFT JOIN public.capacity_native_command_archive a ON a.id=i.id LEFT JOIN public.capacity_native_release_results r ON r.command_id=i.id WHERE i.namespace=$1 AND i.subject_uid=$2 AND i.operation=$3 AND i.phase='release' ORDER BY i.sequence`, realm, subject, capacity.DestroyNativePodProtection)
	if err != nil {
		t.Logf("native release ledger unavailable: %v", err)
		return
	}
	identities := 0
	for rows.Next() {
		var sequence, parentOf, childOf int
		var generation int64
		var record []byte
		var hot, result, adapterACK, callerACK, resultDigestMatches, deadlineMatches bool
		var outcome, status, hotState string
		var hotUpdatedAt sql.NullTime
		if err := rows.Scan(&sequence, &record, &hot, &result, &outcome, &status, &adapterACK, &callerACK, &parentOf, &childOf, &generation, &hotState, &hotUpdatedAt, &resultDigestMatches, &deadlineMatches); err != nil {
			rows.Close()
			t.Logf("native release ledger row unavailable: %v", err)
			return
		}
		identities++
		var command model.CapacityNativeCommand
		var request model.AdapterDestroyCapacityPodDrainProtectionRequest
		decodeErr := json.Unmarshal(record, &command)
		if decodeErr == nil {
			decodeErr = json.Unmarshal(command.Request, &request)
		}
		hotUpdated, callerReturn := "archived", "unset"
		if hotUpdatedAt.Valid {
			hotUpdated = hotUpdatedAt.Time.UTC().Format(time.RFC3339Nano)
		}
		if command.CallerReturnObservedAt != nil {
			callerReturn = command.CallerReturnObservedAt.UTC().Format(time.RFC3339Nano)
		}
		t.Logf("native release ledger seq=%d hot=%t decode=%v state=%s redeemed=%t attempt=%t parent=%t created=%s updated=%s expected_rv=%s result=%t outcome=%s original_status=%s adapter_ack=%t caller_ack=%t decisions_as_parent=%d decisions_as_child=%d", sequence, hot, decodeErr, command.State, command.RedeemedBy != "", command.AttemptID != uuid.Nil, command.ParentCommandID != "", command.CreatedAt.Format(time.RFC3339Nano), command.UpdatedAt.Format(time.RFC3339Nano), request.ExpectedPodResourceVersion, result, outcome, status, adapterACK, callerACK, parentOf, childOf)
		t.Logf("native release ledger admission seq=%d generation=%d hot_state=%s hot_updated_at=%s intent_generation=%d fencing=%d protocol=%t caller_return_observed_at=%s expires_at=%s result_digest_matches=%t deadline_matches=%t", sequence, generation, hotState, hotUpdated, command.IntentGeneration, command.FencingToken, command.ReleaseProtocol == capacity.NativeReleaseResultProtocol, callerReturn, command.ExpiresAt.UTC().Format(time.RFC3339Nano), resultDigestMatches, deadlineMatches)
	}
	err = rows.Err()
	rows.Close()
	t.Logf("native release ledger identities=%d rows=%v", identities, err)
	var intentPhase, intentGeneration, intentFencing, leaseExpiresAt, recoveryOnly string
	var intentUpdatedAt time.Time
	if err := db.QueryRowContext(ctx, `SELECT COALESCE(intent->>'phase',''),COALESCE(intent->>'generation',''),COALESCE(intent->>'fencing_token',''),COALESCE(intent->>'lease_expires_at',''),COALESCE(intent->>'recovery_only',''),updated_at FROM public.capacity_intents WHERE namespace=$1 ORDER BY updated_at DESC LIMIT 1`, realm).Scan(&intentPhase, &intentGeneration, &intentFencing, &leaseExpiresAt, &recoveryOnly, &intentUpdatedAt); err != nil {
		t.Logf("native release ledger intent unavailable: %v", err)
	} else {
		t.Logf("native release ledger intent phase=%s generation=%s fencing=%s lease_expires_at=%s recovery_only=%s updated_at=%s", intentPhase, intentGeneration, intentFencing, leaseExpiresAt, recoveryOnly, intentUpdatedAt.UTC().Format(time.RFC3339Nano))
	}
	events, err := db.QueryContext(ctx, `SELECT e.generation,e.fencing_token,e.phase,e.recorded_at FROM (SELECT id,generation,fencing_token,phase,recorded_at FROM public.capacity_intent_events WHERE namespace=$1 ORDER BY id DESC LIMIT 16) e ORDER BY e.id`, realm)
	if err != nil {
		t.Logf("native release ledger intent events unavailable: %v", err)
	} else {
		for events.Next() {
			var eventGeneration, eventFencing int64
			var eventPhase string
			var recordedAt time.Time
			if err := events.Scan(&eventGeneration, &eventFencing, &eventPhase, &recordedAt); err != nil {
				t.Logf("native release ledger intent event unavailable: %v", err)
				break
			}
			t.Logf("native release ledger intent event generation=%d fencing=%d phase=%s recorded_at=%s", eventGeneration, eventFencing, eventPhase, recordedAt.UTC().Format(time.RFC3339Nano))
		}
		t.Logf("native release ledger intent events rows=%v", events.Err())
		events.Close()
	}
	checkpoints, err := db.QueryContext(ctx, `SELECT checkpoint_record FROM public.capacity_native_lifetimes WHERE namespace=$1 AND pod_uid=$2 UNION ALL SELECT bundle_record->'checkpoint' FROM public.capacity_native_lifetime_archive WHERE namespace=$1 AND pod_uid=$2`, realm, subject)
	if err != nil {
		t.Logf("native release ledger checkpoint unavailable: %v", err)
		return
	}
	defer checkpoints.Close()
	for checkpoints.Next() {
		var raw []byte
		if err := checkpoints.Scan(&raw); err != nil {
			t.Logf("native release ledger checkpoint row unavailable: %v", err)
			return
		}
		var cp model.CapacityNativePodCheckpoint
		var witness model.AdapterCapacityPodTerminationResponse
		decodeErr := json.Unmarshal(raw, &cp)
		if decodeErr == nil {
			decodeErr = json.Unmarshal(cp.NativeTerminationReceipt, &witness)
		}
		confirmed := "unset"
		if cp.ConfirmedAt != nil {
			confirmed = cp.ConfirmedAt.Format(time.RFC3339Nano)
		}
		t.Logf("native release ledger checkpoint decode=%v state=%s rv=%s confirmed_at=%s witness_rv=%s witness_observed_at=%s", decodeErr, cp.State, cp.PodResourceVersion, confirmed, witness.Observation.PodResourceVersion, witness.Observation.ObservedAt.Format(time.RFC3339Nano))
	}
	if err := checkpoints.Err(); err != nil {
		t.Logf("native release ledger checkpoint rows: %v", err)
	}
}

// The victim Pod timeline is diagnostics only. It must keep arrival order,
// name the managedFields entry each Update adds, show a grace-only version
// that adds no entry, reduce annotation values to a digest, and keep every
// complete version before a cut stream while returning the cut.
func TestNativeKindPodTimelineNamesEachWriter(t *testing.T) {
	const base = `"finalizers":["yggdrasil.io/capacity-native-termination","qualification.dakasa.io/held-native-deletion"],"annotations":{"fixture.yggdrasil.io/challenge":"private-challenge-value"}`
	const controller = `{"manager":"kube-controller-manager","operation":"Update","time":"2026-10-12T02:12:30Z"}`
	const kubelet = `{"manager":"kubelet","operation":"Update","subresource":"status","time":"2026-10-12T02:12:38Z"}`
	const running = `"status":{"phase":"Running","conditions":[{"type":"Ready","status":"False"}],"containerStatuses":[{"ready":false,"state":{"terminated":{"exitCode":0}}}]}`
	const succeeded = `"status":{"phase":"Succeeded","conditions":[{"type":"Ready","status":"False"}],"containerStatuses":[{"ready":false,"state":{"terminated":{"exitCode":0}}}]}`
	stream := `{"type":"ADDED","object":{"metadata":{"resourceVersion":"10","deletionGracePeriodSeconds":30,` + base + `,"managedFields":[` + controller + `]},` + running + `}}
{"type":"MODIFIED","object":{"metadata":{"resourceVersion":"11","deletionGracePeriodSeconds":30,` + base + `,"managedFields":[` + controller + `,` + kubelet + `]},` + succeeded + `}}
{"type":"MODIFIED","object":{"metadata":{"resourceVersion":"12","deletionGracePeriodSeconds":0,` + base + `,"managedFields":[` + controller + `,` + kubelet + `]},` + succeeded + `}}
{"type":"MODIFIED","object":{"metadata":{"resourceVersion":"13"`
	tick := time.Date(2026, 10, 12, 2, 12, 39, 0, time.UTC)
	versions := []nativeKindPodVersion{}
	err := nativeKindDecodePodWatch(strings.NewReader(stream), func() time.Time { tick = tick.Add(time.Millisecond); return tick }, func(v nativeKindPodVersion) { versions = append(versions, v) })
	if err == nil || len(versions) != 3 {
		t.Fatal("cut watch stream lost a complete version or hid the cut", err, len(versions))
	}
	for i, rv := range []string{"10", "11", "12"} {
		if versions[i].facts["rv"] != rv || (i > 0 && !versions[i].at.After(versions[i-1].at)) {
			t.Fatal("victim versions lost their resourceVersion or arrival order", i)
		}
	}
	if got := strings.Join(nativeKindPodVersionChanges(versions[0], versions[1]), ";"); got != "phase;status;writer=kubelet/Update/status@2026-10-12T02:12:38Z" {
		t.Fatal("status version did not name its writer", got)
	}
	if got := strings.Join(nativeKindPodVersionChanges(versions[1], versions[2]), ";"); got != "grace" {
		t.Fatal("grace-only version was attributed or widened", got)
	}
	digest := sha256.Sum256([]byte("private-challenge-value"))
	lines := nativeKindPodTimelineLines(versions)
	if len(lines) != 3 || !strings.Contains(lines[0], "changed=first") || !strings.Contains(lines[0], "containers=terminated/ready=false") || !strings.Contains(lines[0], "conditions=Ready=False") || !strings.Contains(lines[0], fmt.Sprintf("annotations=fixture.yggdrasil.io/challenge#%.4x", digest[:])) || !strings.Contains(lines[2], "rv=12 grace=0 phase=Succeeded") || !strings.Contains(lines[2], "changed=grace writers=") {
		t.Fatal("victim timeline lines lost a fact", lines)
	}
	for _, line := range lines {
		if strings.Contains(line, "private-challenge-value") {
			t.Fatal("victim timeline printed an annotation value")
		}
	}
	empty := []nativeKindPodVersion{}
	if err := nativeKindDecodePodWatch(strings.NewReader(""), time.Now, func(v nativeKindPodVersion) { empty = append(empty, v) }); err != nil || len(empty) != 0 {
		t.Fatal("empty watch stream invented a version", err, len(empty))
	}
	if err := nativeKindDecodePodWatch(strings.NewReader("not-json"), time.Now, func(v nativeKindPodVersion) { empty = append(empty, v) }); err == nil || len(empty) != 0 {
		t.Fatal("malformed watch stream was accepted", len(empty))
	}
}
