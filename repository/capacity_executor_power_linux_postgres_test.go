package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/url"
	"os"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

// This test owns SQL custody/index behavior only. It confers no provider,
// workflow, Guest provisioning, or live resource authority.
func TestExecutorPowerRealPostgresLedger(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getenv("EXECUTOR_POWER_LINUX_PG_TEST") != "isolated" {
		t.Skip("requires approved isolated Linux PostgreSQL")
	}
	dsn := os.Getenv("EXECUTOR_POWER_TEST_DB_URL")
	u, err := url.Parse(dsn)
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") || (u.Hostname() != "127.0.0.1" && u.Hostname() != "::1") || !regexp.MustCompile(`^/executor_lab_[a-z0-9_]{1,40}$`).MatchString(u.Path) || u.Fragment != "" || u.Query().Get("sslmode") != "disable" {
		t.Fatal("dedicated loopback executor_lab_* database required")
	}
	for k := range u.Query() {
		if k != "sslmode" {
			t.Fatal("database URI override refused")
		}
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	db.SetMaxOpenConns(4)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ns := "power-sql-" + uuid.NewString()
	t.Cleanup(func() {
		_, e := db.Exec(`DELETE FROM public.capacity_mutation_grants WHERE namespace=$1`, ns)
		if e != nil {
			t.Error(e)
		}
		_, e = db.Exec(`DELETE FROM public.capacity_resource_slots WHERE namespace=$1`, ns)
		if e != nil {
			t.Error(e)
		}
	})
	var database string
	if err = db.QueryRowContext(ctx, `SELECT current_database()`).Scan(&database); err != nil || database != strings.TrimPrefix(u.Path, "/") {
		t.Fatal("isolated database identity unavailable", err)
	}
	// Migrations must be applied independently by the approved lab runner.
	for _, index := range []string{"capacity_executor_power_resource_idx", "capacity_executor_power_command_idx", "capacity_executor_power_open_adoption_idx", "capacity_executor_power_vm_overlap_idx"} {
		var found bool
		if err = db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM pg_indexes WHERE schemaname='public' AND indexname=$1)`, index).Scan(&found); err != nil || !found {
			t.Fatal("migration67 missing", index, err)
		}
	}
	resource := func(instance, kind string) string {
		raw, _ := json.Marshal(map[string]any{"authority_kind": kind, "resource": map[string]string{"instance_id": instance}})
		return string(raw)
	}
	insertSlot := func(conn *sql.DB, instance, kind string) error {
		_, e := conn.ExecContext(ctx, `INSERT INTO public.capacity_resource_slots(integration_instance_id,scope_checksum,profile_name,slot,namespace,environment,domain,dimension,resource_id,slot_record) VALUES($1,'sql-test','executor_power_v1',1,$2,'lab','executor','power',$3,$4::jsonb)`, uuid.NewString(), ns, instance, resource(instance, kind))
		return e
	}
	uniqueError := func(e error) bool {
		type sqlStater interface{ SQLState() string }
		s, ok := e.(sqlStater)
		return ok && s.SQLState() == "23505"
	}
	t.Run("concurrent_global_adoption_unique", func(t *testing.T) {
		start := make(chan struct{})
		out := make(chan error, 2)
		var wg sync.WaitGroup
		for i := 0; i < 2; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				out <- insertSlot(db, "i-00000000000000001", "ec2_operator_adoption_v1")
			}()
		}
		close(start)
		wg.Wait()
		close(out)
		success, conflict := 0, 0
		for e := range out {
			if e == nil {
				success++
			} else if uniqueError(e) {
				conflict++
			} else {
				t.Fatal(e)
			}
		}
		if success != 1 || conflict != 1 {
			t.Fatalf("success=%d conflict=%d", success, conflict)
		}
	})
	t.Run("legacy_then_adoption_collision", func(t *testing.T) {
		if e := insertSlot(db, "i-00000000000000002", ""); e != nil {
			t.Fatal(e)
		}
		if e := insertSlot(db, "i-00000000000000002", "ec2_operator_adoption_v1"); !uniqueError(e) {
			t.Fatal("legacy overlap admitted", e)
		}
	})
	t.Run("adoption_then_legacy_collision", func(t *testing.T) {
		if e := insertSlot(db, "i-00000000000000003", "ec2_operator_adoption_v1"); e != nil {
			t.Fatal(e)
		}
		if e := insertSlot(db, "i-00000000000000003", ""); !uniqueError(e) {
			t.Fatal("reverse legacy overlap admitted", e)
		}
		tx, e := db.BeginTx(ctx, nil)
		if e != nil {
			t.Fatal(e)
		}
		defer tx.Rollback()
		if e = guardExecutorPowerAdoption(ctx, tx, "i-00000000000000003"); e != ErrCapacityConflict {
			t.Fatal("legacy destroy guard failed", e)
		}
	})
	insertGrant := func(command, adoption, state string) error {
		raw, _ := json.Marshal(map[string]string{"authority_kind": "ec2_power_v1", "command_id": command, "adoption_id": adoption})
		_, e := db.ExecContext(ctx, `INSERT INTO public.capacity_mutation_grants(id,namespace,environment,domain,dimension,generation,integration_instance_id,scope_checksum,profile_name,slot,state,grant_record,expires_at) VALUES($1,$2,'lab','executor','power',1,$3,'sql-test','executor_power_v1',1,$4,$5::jsonb,clock_timestamp()+interval '30 seconds')`, uuid.NewString(), ns, uuid.NewString(), state, string(raw))
		return e
	}
	t.Run("concurrent_command_unique", func(t *testing.T) {
		command := uuid.NewString()
		start, out := make(chan struct{}), make(chan error, 2)
		var wg sync.WaitGroup
		for i := 0; i < 2; i++ {
			wg.Add(1)
			go func() { defer wg.Done(); <-start; out <- insertGrant(command, uuid.NewString(), "issued") }()
		}
		close(start)
		wg.Wait()
		close(out)
		success, conflict := 0, 0
		for e := range out {
			if e == nil {
				success++
			} else if uniqueError(e) {
				conflict++
			} else {
				t.Fatal(e)
			}
		}
		if success != 1 || conflict != 1 {
			t.Fatalf("success=%d conflict=%d", success, conflict)
		}
	})
	t.Run("command_tombstone_and_open_adoption", func(t *testing.T) {
		command, adoption := uuid.NewString(), uuid.NewString()
		if e := insertGrant(command, adoption, "settled"); e != nil {
			t.Fatal(e)
		}
		if e := insertGrant(uuid.NewString(), adoption, "issued"); !uniqueError(e) {
			t.Fatal("unresolved adoption obtained second grant", e)
		}
		if _, e := db.ExecContext(ctx, `UPDATE public.capacity_mutation_grants SET state='confirmed' WHERE namespace=$1 AND grant_record->>'command_id'=$2`, ns, command); e != nil {
			t.Fatal(e)
		}
		if e := insertGrant(command, uuid.NewString(), "issued"); !uniqueError(e) {
			t.Fatal("confirmed command replay admitted", e)
		}
		if e := insertGrant(uuid.NewString(), adoption, "issued"); e != nil {
			t.Fatal("resolved adoption cannot receive new command", e)
		}
	})
	t.Run("new_connection_retains_custody", func(t *testing.T) {
		restarted, e := sql.Open("postgres", dsn)
		if e != nil {
			t.Fatal(e)
		}
		defer restarted.Close()
		if e = insertSlot(restarted, "i-00000000000000001", "ec2_operator_adoption_v1"); !uniqueError(e) {
			t.Fatal("restart lost global adoption custody", e)
		}
	})
}
