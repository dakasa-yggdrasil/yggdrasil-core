package repository

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity/executorpower"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
)

// Executed only from a disposable Core 32fe fixture. The raw wire is copied
// from its committed handler return, not from a live or provider resource.
func TestLABCoreBoundLegacyDecode(t *testing.T) {
	path, dsn := os.Getenv("LAB_DISPOSAL_WIRE"), os.Getenv("LAB_FALLBACK_DB")
	if path == "" || dsn == "" {
		t.Skip("isolated cross-source fixture absent")
	}
	labFallbackFixtureURL(t, dsn)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	view, err := decodeFailedInstalledDisposalRead(raw)
	if err != nil {
		t.Fatal("fallback read", err)
	}
	var legacy FailedInstalledGuestDisposal
	if decodeFailedInstalledDisposal(raw, &legacy) == nil {
		t.Fatal("mutating decoder accepted new wire")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var version int
	if err = db.QueryRow(`SELECT max(version_id) FROM goose_db_version WHERE is_applied`).Scan(&version); err != nil || version != 82 {
		t.Fatal("schema82 fixture required", version, err)
	}
	rows, err := (CapacityStore{DB: db}).ReadFailedInstalledGuestDisposal(context.Background(), view.PreregistrationID)
	if err != nil {
		t.Fatal("PG read", err)
	}
	matched := false
	for _, row := range rows {
		if row.ID == view.ID && row.Stage == view.Stage && row.ReplacementMode == view.ReplacementMode {
			matched = true
		}
	}
	if !matched {
		t.Fatal("requested stage absent from PG read")
	}
	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, _, err = loadFailedInstalledDisposalTx(context.Background(), tx, view.ID, view.Stage); err == nil {
		t.Fatal("mutating ledger load allowed")
	}
	policy := model.Manifest{}
	policy.Metadata.Namespace = view.Namespace
	p := model.CapacityPolicySpec{Environment: view.Environment, Domain: view.Domain, Dimension: view.Dimension}
	if err = guardFallbackNewerDisposalTx(context.Background(), tx); err == nil {
		t.Fatal("unsupported mutation issuance or redemption gate allowed")
	}
	if err = requireFailedInstalledReplacementTx(context.Background(), tx, policy, p); err == nil {
		t.Fatal("nil-binding replacement allowed")
	}
	p.GuestNotifyReconcileBinding = &model.CapacityGuestNotifyReconcileBinding{}
	if err = requireFailedInstalledReplacementTx(context.Background(), tx, policy, p); err == nil {
		t.Fatal("Guest replacement allowed")
	}
	var after []byte
	if err = tx.QueryRow(`SELECT original_wire FROM public.capacity_guest_failed_installed_disposals WHERE id=$1 AND stage=$2`, view.ID, view.Stage).Scan(&after); err != nil || !bytes.Equal(raw, after) {
		t.Fatal("wire changed", err)
	}
	t.Log("LAB_FALLBACK_PG82_COMPAT_READ_MUTATION_REPLACEMENT_HELD_ORIGINAL_UNCHANGED")
	if err = tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if view.Stage == "terminal" {
		labFallbackAuthorityPG(t, dsn)
		labFallbackStartup(t, dsn)
	}
	if err = db.QueryRow(`SELECT original_wire FROM public.capacity_guest_failed_installed_disposals WHERE id=$1 AND stage=$2`, view.ID, view.Stage).Scan(&after); err != nil || !bytes.Equal(raw, after) {
		t.Fatal("wire changed across startup", err)
	}
	if err = db.QueryRow(`SELECT max(version_id) FROM goose_db_version WHERE is_applied`).Scan(&version); err != nil || version != 82 {
		t.Fatal("migration version changed across startup", version, err)
	}
}

// These are disposable unrelated scopes in the same PG82 fixture. No adapter,
// broker, Guest or provider is called and no permission may be produced.
func labFallbackAuthorityPG(t *testing.T, dsn string) {
	t.Helper()
	labFallbackFixtureURL(t, dsn)
	t.Setenv("DB_URL", dsn)
	f := mutationPostgresFixture(t, false)
	ctx := context.Background()
	if _, err := f.store.IssueMutation(ctx, f.policy, f.intent.Generation, f.intent.FencingToken, f.intent.LeaseOwner, f.plans[5]); !errors.Is(err, errFallbackNewerDisposition) {
		t.Fatal("cross-dimension IssueMutation did not reach HOLD", err)
	}
	if _, err := f.store.IssueCompensation(ctx, f.policy, model.CapacityCompensationIssue{}); !errors.Is(err, errFallbackNewerDisposition) {
		t.Fatal("cross-dimension IssueCompensation did not reach HOLD", err)
	}
	var grants int
	if err := f.db.QueryRow(`SELECT count(*) FROM public.capacity_mutation_grants WHERE namespace=$1`, f.policy.Metadata.Namespace).Scan(&grants); err != nil || grants != 0 {
		t.Fatal("HOLD created a mutation grant", grants, err)
	}
	db, envelope := capacityDispatchPostgresFixture(t)
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = EnqueueCapacityDispatch(ctx, tx, envelope); !errors.Is(err, ErrCapacityDispatchEnvelope) {
		_ = tx.Rollback()
		t.Fatal("cross-dimension dispatch admitted", err)
	}
	if err = tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	var jobs int
	if err = db.QueryRow(`SELECT count(*) FROM public.capacity_dispatch_jobs WHERE realm=$1`, envelope.Realm).Scan(&jobs); err != nil || jobs != 0 {
		t.Fatal("dispatch HOLD created a job", jobs, err)
	}
	_, g, _ := powerCallbackFixture(t)
	wire, err := json.Marshal(g)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`INSERT INTO public.capacity_mutation_grants(id,namespace,environment,domain,dimension,generation,integration_instance_id,scope_checksum,profile_name,slot,state,grant_record,expires_at) VALUES($1,$2,$3,$4,$5,1,$6,$7,$8,1,'issued',$9::jsonb,$10)`, g.ID, g.Scope.Namespace, g.Scope.Environment, g.Scope.Domain, g.Scope.Dimension, g.Binding.IntegrationID, executorpower.Digest(g.Binding.Resource), executorPowerProfile, string(wire), g.ExpiresAt)
	if err != nil {
		t.Fatal("synthetic issued power fixture", err)
	}
	c := executorpower.Claim{GrantID: g.ID, Action: g.Action, CommandID: g.CommandID, RequestSHA: g.RequestSHA, AttemptID: uuid.NewString(), SettlementSHA: executorpower.Digest(strings.Repeat("t", 32))}
	reply, err := (CapacityStore{DB: db, ExecutionEnabled: true, ExecutorPowerEnabled: true}).RedeemExecutorPower(ctx, g.Binding.AdapterPrincipal, g.Binding.IntegrationID, c)
	if !errors.Is(err, errFallbackNewerDisposition) || reply.Mode != "" {
		t.Fatal("cross-dimension power redeem escaped HOLD", reply, err)
	}
	var state string
	if err = db.QueryRow(`SELECT state FROM public.capacity_mutation_grants WHERE id=$1`, g.ID).Scan(&state); err != nil || state != "issued" {
		t.Fatal("held power grant changed", state, err)
	}
	t.Log("LAB_FALLBACK_PG82_CROSS_SCOPE_ISSUE_COMPENSATION_DISPATCH_POWER_REDEEM_HELD")
}

func labFallbackFixtureURL(t *testing.T, dsn string) *url.URL {
	t.Helper()
	u, err := url.Parse(dsn)
	if os.Getenv("GITHUB_ACTIONS") != "true" || err != nil || u.Scheme != "postgres" || u.Hostname() != "127.0.0.1" || u.User == nil {
		t.Fatal("fixture URL required", err)
	}
	password, ok := u.User.Password()
	if !ok || u.User.Username() != "postgres" || password != "fixture-only" {
		t.Fatal("fixture identity required")
	}
	port := u.Port()
	if port == "" {
		t.Fatal("fixture port required")
	}
	name := strings.TrimPrefix(u.Path, "/")
	if !regexp.MustCompile(`^recovery_fixture_[0-9a-f]{32}$`).MatchString(name) {
		t.Fatal("fixture database required")
	}
	return u
}

// The actual fallback goose and Core binaries run against the already-migrated
// disposable database. Broker and bootstrap are deliberately absent.
func labFallbackStartup(t *testing.T, dsn string) {
	t.Helper()
	u := labFallbackFixtureURL(t, dsn)
	password, _ := u.User.Password()
	port := u.Port()
	name := strings.TrimPrefix(u.Path, "/")
	root, goose, core := os.Getenv("LAB_FALLBACK_ROOT"), os.Getenv("LAB_FALLBACK_GOOSE"), os.Getenv("LAB_FALLBACK_CORE")
	if root == "" || goose == "" || core == "" {
		t.Fatal("fallback binaries required")
	}
	env := []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"), "DB_HOST=127.0.0.1", "DB_PORT=" + port, "DB_NAME=" + name, "DB_USER=postgres", "DB_PASSWORD=" + password, "DB_SSLMODE=disable"}
	migration := exec.Command(goose, "up")
	migration.Dir = root
	migration.Env = env
	output, err := migration.CombinedOutput()
	if err != nil {
		t.Fatalf("fallback entrypoint migration step failed: %v: %s", err, output)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	cmd := exec.Command(core)
	cmd.Dir = root
	cmd.Env = append(env, "HTTP_ADDR="+addr)
	var logs bytes.Buffer
	cmd.Stdout = &logs
	cmd.Stderr = &logs
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	stopped := false
	defer func() {
		if !stopped {
			_ = cmd.Process.Kill()
			<-done
		}
	}()
	client := &http.Client{Timeout: time.Second}
	deadline := time.Now().Add(20 * time.Second)
	ready := false
	for time.Now().Before(deadline) {
		select {
		case e := <-done:
			stopped = true
			t.Fatalf("fallback exited before health: %v: %s", e, logs.String())
		default:
		}
		resp, e := client.Get("http://" + addr + "/healthz")
		if e == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == 200 {
				ready = true
				break
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !ready {
		_ = cmd.Process.Kill()
		<-done
		stopped = true
		t.Fatalf("fallback health timeout: %s", logs.String())
	}
	if err = cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case e := <-done:
		stopped = true
		if e != nil {
			t.Fatalf("fallback shutdown: %v: %s", e, logs.String())
		}
	case <-time.After(15 * time.Second):
		t.Fatal("fallback shutdown timed out")
	}
	t.Log("LAB_FALLBACK_ACTUAL_GOOSE_AND_CORE_SCHEMA82_HEALTH_SHUTDOWN_PASS")
}
