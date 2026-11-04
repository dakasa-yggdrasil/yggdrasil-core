package executoractivity

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	_ "github.com/lib/pq"
)

// No migration, container or database is created here. Linux operators must
// explicitly name a dedicated loopback test database and apply the approved
// migration separately. This fixture never falls back to DB_URL or production.
func TestExecutorRealPostgresConcurrentIngressAndRestart(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getenv("EXECUTOR_ACTIVITY_LINUX_PG_TEST") != "isolated" {
		t.Skip("requires explicitly approved isolated Linux PostgreSQL")
	}
	dsn := os.Getenv("EXECUTOR_ACTIVITY_TEST_DB_URL")
	u, err := url.Parse(dsn)
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") || (u.Hostname() != "127.0.0.1" && u.Hostname() != "::1") || !regexp.MustCompile(`^/executor_lab_[a-z0-9_]{1,40}$`).MatchString(u.Path) || u.Fragment != "" {
		t.Fatal("dedicated loopback executor_lab_* database required")
	}
	for k := range u.Query() {
		if k != "sslmode" {
			t.Fatal("database URI overrides refused")
		}
	}
	if u.Query().Get("sslmode") != "disable" {
		t.Fatal("explicit loopback test TLS posture required")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal("cannot open isolated test database")
	}
	db.SetMaxOpenConns(4)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var database string
	if err = db.QueryRowContext(ctx, `SELECT current_database()`).Scan(&database); err != nil || database != strings.TrimPrefix(u.Path, "/") {
		db.Close()
		t.Fatal("isolated database identity unavailable")
	}
	id, err := powerID()
	if err != nil {
		db.Close()
		t.Fatal(err)
	}
	scope := "postgres-integration/" + id
	binding := fmt.Sprintf("%x", sha256.Sum256([]byte(scope)))
	t.Cleanup(func() {
		cleanup, done := context.WithTimeout(context.Background(), 3*time.Second)
		defer done()
		_, err := db.ExecContext(cleanup, `DELETE FROM public.capacity_executor_activity WHERE scope_key=$1 AND binding_sha256=$2`, scope, binding)
		if err != nil {
			t.Error("isolated test row cleanup failed")
		}
		db.Close()
	})
	authorize := func(context.Context, *sql.Tx) error { return nil } // authentication covered separately; this fixture owns only SQL behavior.
	if _, err = RunPostgres(ctx, db, scope, binding, activityTestPolicy, true, authorize, func(*ExecutorActivityState, time.Time) error { return nil }); err != nil {
		t.Fatal("approved migration/table unavailable or initialization failed", err)
	}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for _, task := range []string{"run-a", "run-b"} {
		wg.Add(1)
		go func(task string) {
			defer wg.Done()
			_, err := RunPostgres(ctx, db, scope, binding, activityTestPolicy, false, authorize, func(s *ExecutorActivityState, now time.Time) error {
				return ApplyWorkflowOperation(s, activityTestPolicy, "capacity.record_executor_activity", "machine:test", WorkflowRequest{JobID: "job-" + task, Event: ExecutorActivityEvent{TaskID: task, Sequence: 1}}, now)
			})
			results <- err
		}(task)
	}
	wg.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatal(err)
		}
	}
	// New connection pool models controller reconstruction; PostgreSQL owns state.
	restarted, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal("restart connection failed")
	}
	defer restarted.Close()
	state, err := RunPostgres(ctx, restarted, scope, binding, activityTestPolicy, false, authorize, func(*ExecutorActivityState, time.Time) error { return nil })
	if err != nil || state.Revision != 4 || len(state.Tasks) != 2 || activeJobs(state) != 2 {
		t.Fatal("SQL serialization/restart lost task or job", err, state.Revision)
	}
}
