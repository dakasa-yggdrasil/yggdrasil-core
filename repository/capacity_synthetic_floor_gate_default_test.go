//go:build !recoveryfixture || nativequalification

package repository

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

const floorFixtureOutputLimit = 128 << 10
const floorFixtureMinimumRemaining = 165 * time.Second

func floorFixtureEnoughTime(remaining time.Duration) bool {
	return remaining >= floorFixtureMinimumRemaining
}

type floorFixtureCapture struct {
	buf   []byte
	total int64
}

func (w *floorFixtureCapture) Write(p []byte) (int, error) {
	w.total += int64(len(p))
	remaining := floorFixtureOutputLimit - len(w.buf)
	if remaining > 0 {
		w.buf = append(w.buf, p[:min(remaining, len(p))]...)
	}
	return len(p), nil
}

// The bounded child output can include arbitrary test inputs and connection
// errors. Retain its byte count, prefix digest and fixed source locations only.
func floorFixtureSummary(out, stderr *floorFixtureCapture, exitCode int) string {
	locations := regexp.MustCompile(`capacity_synthetic_floor_gate_postgres_test\.go:[0-9]{1,6}`)
	combined := append(append([]byte(nil), out.buf...), stderr.buf...)
	matches := locations.FindAll(combined, 8)
	seen := make(map[string]bool)
	var safe []string
	for _, m := range matches {
		if !seen[string(m)] {
			seen[string(m)] = true
			safe = append(safe, string(m))
		}
	}
	return fmt.Sprintf("exit=%d stdout_bytes=%d stdout_prefix_sha256=%x stdout_truncated=%t stderr_bytes=%d stderr_prefix_sha256=%x stderr_truncated=%t locations=%v", exitCode, out.total, sha256.Sum256(out.buf), out.total > int64(len(out.buf)), stderr.total, sha256.Sum256(stderr.buf), stderr.total > int64(len(stderr.buf)), safe)
}

func floorFixtureCensus(out *floorFixtureCapture) bool {
	return syntheticRepositoryCensus(out, "TestSyntheticFloorDrainBudgetPostgres", "")
}

// Require the parent and selected child separately; a duplicate or skip is not evidence.
func syntheticRepositoryCensus(out *floorFixtureCapture, root, child string) bool {
	if out.total != int64(len(out.buf)) {
		return false
	}
	scanner := bufio.NewScanner(bytes.NewReader(out.buf))
	scanner.Buffer(make([]byte, 1024), floorFixtureOutputLimit)
	counts := map[string]int{}
	for scanner.Scan() {
		var event struct {
			Action string `json:"Action"`
			Test   string `json:"Test"`
		}
		if json.Unmarshal(scanner.Bytes(), &event) != nil {
			return false
		}
		if event.Action == "fail" || event.Action == "skip" {
			return false
		}
		if event.Action == "run" || event.Action == "pass" {
			counts[event.Test+":"+event.Action]++
		}
	}
	if scanner.Err() != nil || counts[root+":run"] != 1 || counts[root+":pass"] != 1 || counts[":pass"] != 1 {
		return false
	}
	if child != "" && (counts[child+":run"] != 1 || counts[child+":pass"] != 1) {
		return false
	}
	if child == "TestCapacityMutationCompensationPostgres/unprotected_failed_create" {
		nested := child + "/global_slot_precedes_child_row_during_foreign_issue"
		return counts[nested+":run"] == 1 && counts[nested+":pass"] == 1
	}
	return true
}

func floorFixtureReapDatabase(ctx context.Context, admin *sql.DB, name string) error {
	if len(name) != len("recovery_fixture_")+32 || !strings.HasPrefix(name, "recovery_fixture_") || strings.Trim(name[len("recovery_fixture_"):], "0123456789abcdef") != "" {
		return errors.New("invalid synthetic database identity")
	}
	if _, err := admin.ExecContext(ctx, "DROP DATABASE IF EXISTS "+pq.QuoteIdentifier(name)+" WITH (FORCE)"); err != nil {
		return err
	}
	var remains bool
	if err := admin.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname=$1)`, name).Scan(&remains); err != nil {
		return err
	}
	if remains {
		return errors.New("synthetic database still exists")
	}
	return nil
}

func floorFixtureCleanupAfterJoin(ctx context.Context, admin *sql.DB, name string, groupErr error) error {
	if groupErr != nil {
		return groupErr
	}
	return floorFixtureReapDatabase(ctx, admin, name)
}

// Invoke only the explicitly synthetic test build. The child creates and
// drops its own PG16 database; it cannot qualify native or production facts.
func runSyntheticFloorGate(t *testing.T) {
	runSyntheticRepositoryGate(t, "TestSyntheticFloorDrainBudgetPostgres", "")
}

func runSyntheticRepositoryGate(t *testing.T, rootTest, childTest string) bool {
	t.Helper()
	// Only these reviewed fixture cases may be selected by the original tests.
	allowed := (rootTest == "TestSyntheticFloorDrainBudgetPostgres" || rootTest == "TestSyntheticFailedFloorRecoveryPostgres") && childTest == "" ||
		rootTest == "TestCapacityMutationCompensationPostgres" && (childTest == "unprotected_failed_create" || childTest == "protected_failed_create_without_serving_membership" || childTest == "lost_create_reply_uses_separate_native_readback" || childTest == "protected_lost_create_reply")
	if !allowed {
		t.Fatal("unsupported synthetic fixture case")
	}
	fullChild, pattern := "", "^"+rootTest+"$"
	if childTest != "" {
		fullChild = rootTest + "/" + childTest
		pattern += "/^" + childTest + "$"
	}
	dsn := os.Getenv("DB_URL")
	if dsn == "" {
		if os.Getenv("REQUIRE_CAPACITY_POSTGRES") == "true" {
			t.Fatal("DB_URL required by capacity gate")
		}
		t.Skip("PostgreSQL integration runs in CI")
	}
	goBinary := os.Getenv("CAPACITY_TEST_GO")
	if goBinary == "" {
		var err error
		goBinary, err = exec.LookPath("go")
		if err != nil {
			t.Fatal("Go executable unavailable")
		}
	}
	if !filepath.IsAbs(goBinary) {
		t.Fatal("absolute Go executable required")
	}
	rootRaw, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		t.Fatal("fixture source root unavailable")
	}
	root := strings.TrimSpace(string(rootRaw))
	if !filepath.IsAbs(root) || exec.Command("git", "-C", root, "diff", "--quiet", "HEAD", "--").Run() != nil {
		t.Fatal("fixture source must be clean")
	}
	parsed, parseErr := url.Parse(dsn)
	if parseErr != nil || (parsed.Scheme != "postgres" && parsed.Scheme != "postgresql") {
		t.Fatal("local synthetic database required")
	}
	host, socket := parsed.Hostname(), parsed.Query().Get("host")
	if !pg16LocalDSN(host, socket) {
		t.Fatal("remote synthetic database refused")
	}
	admin, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal("synthetic database owner unavailable")
	}
	defer admin.Close()
	var addr string
	var major int
	if err = admin.QueryRow(`SELECT COALESCE(inet_server_addr()::text,'unix'), current_setting('server_version_num')::int / 10000`).Scan(&addr, &major); err != nil || major != 16 || !pg16LocalServer(host, addr) {
		t.Fatal("actual local PG16 owner required")
	}
	name := "recovery_fixture_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	var existing bool
	if err = admin.QueryRow(`SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname=$1)`, name).Scan(&existing); err != nil || existing {
		t.Fatal("unique synthetic database owner required")
	}
	// Do not start if the enclosing Go test timeout could kill this owner
	// before its child timeout and independent database cleanup can finish.
	if deadline, ok := t.Deadline(); ok && !floorFixtureEnoughTime(time.Until(deadline)) {
		t.Fatal("insufficient time to own and clean synthetic fixture")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, goBinary, "test", "-race", "-json", "-timeout=120s", "-buildvcs=true", "-tags", "recoveryfixture", "./repository", "-run", pattern, "-count=1")
	floorFixtureConfigureProcess(cmd)
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "CAPACITY_RECOVERY_FIXTURE_ONLY=true", "CAPACITY_RECOVERY_FIXTURE_DATABASE="+name, "RECOVERY_FIXTURE_ADMIN_URL="+dsn, "GOWORK=off")
	var out, stderr floorFixtureCapture
	cmd.Stdout, cmd.Stderr = &out, &stderr
	err = cmd.Run()
	exitCode := 0
	if err != nil {
		exitCode = -1
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			exitCode = exit.ExitCode()
		}
	}
	groupErr := floorFixtureJoinProcessGroup(cmd)
	cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cleanupCancel()
	cleanupErr := floorFixtureCleanupAfterJoin(cleanupCtx, admin, name, groupErr)
	if groupErr != nil {
		t.Log("synthetic floor child:", floorFixtureSummary(&out, &stderr, exitCode), "process_group_joined=false", "database_cleanup_pending=", name)
		t.Fatal("synthetic child process group did not join; database cleanup pending")
	}
	t.Log("synthetic floor child:", floorFixtureSummary(&out, &stderr, exitCode), "process_group_joined=true", "database_cleanup_confirmed=", cleanupErr == nil)
	if cleanupErr != nil {
		t.Fatal("synthetic database cleanup unconfirmed")
	}
	if err != nil || !syntheticRepositoryCensus(&out, rootTest, fullChild) {
		t.Fatal("isolated synthetic repository fixture failed or incomplete; no physical qualification was granted")
	}
	return true
}
