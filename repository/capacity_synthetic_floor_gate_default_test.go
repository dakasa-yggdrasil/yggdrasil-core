//go:build !recoveryfixture || nativequalification

package repository

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

const floorFixtureOutputLimit = 128 << 10

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
	if out.total != int64(len(out.buf)) {
		return false
	}
	scanner := bufio.NewScanner(bytes.NewReader(out.buf))
	scanner.Buffer(make([]byte, 1024), floorFixtureOutputLimit)
	var run, pass, packagePass bool
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
		if event.Test == "TestSyntheticFloorDrainBudgetPostgres" {
			if event.Action == "run" {
				run = true
			}
			if event.Action == "pass" {
				pass = true
			}
		}
		if event.Test == "" && event.Action == "pass" {
			packagePass = true
		}
	}
	return scanner.Err() == nil && run && pass && packagePass
}

// Invoke only the explicitly synthetic test build. The child creates and
// drops its own PG16 database; it cannot qualify native or production facts.
func runSyntheticFloorGate(t *testing.T) {
	t.Helper()
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
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, goBinary, "test", "-race", "-json", "-buildvcs=true", "-tags", "recoveryfixture", "./repository", "-run", "^TestSyntheticFloorDrainBudgetPostgres$", "-count=1")
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "CAPACITY_RECOVERY_FIXTURE_ONLY=true", "RECOVERY_FIXTURE_ADMIN_URL="+dsn, "GOWORK=off")
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
	t.Log("synthetic floor child:", floorFixtureSummary(&out, &stderr, exitCode))
	if err != nil || !floorFixtureCensus(&out) {
		t.Fatal("isolated synthetic floor fixture failed or incomplete; no physical qualification was granted")
	}
}
