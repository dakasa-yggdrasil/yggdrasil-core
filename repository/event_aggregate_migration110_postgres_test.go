package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/lib/pq"
	"github.com/pressly/goose/v3"
)

// The owning PostgreSQL16/17 CI step selects this root explicitly. No native
// provider is contacted: the exact public identity is only an isolated DB input.
func TestEventAggregateIDTextMigration110Postgres(t *testing.T) {
	dsn := os.Getenv("DB_URL")
	if dsn == "" {
		if os.Getenv("REQUIRE_EVENT_AGGREGATE110_POSTGRES") == "true" {
			t.Fatal("required schema110 PostgreSQL owner has no DB_URL")
		}
		t.Skip("DB_URL not set; PostgreSQL qualification runs in its owning CI step")
	}
	u, err := url.Parse(dsn)
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") || (u.Hostname() != "127.0.0.1" && u.Hostname() != "localhost") {
		t.Fatal("schema110 CI requires its loopback PostgreSQL owner")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	admin, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal("open CI PostgreSQL owner", err)
	}
	t.Cleanup(func() { _ = admin.Close() })
	name := fmt.Sprintf("schema110_%d", time.Now().UnixNano())
	if _, err = admin.ExecContext(ctx, "CREATE DATABASE "+pq.QuoteIdentifier(name)); err != nil {
		t.Fatal("create isolated schema110 database", err)
	}
	u.Path = "/" + name
	db, err := sql.Open("postgres", u.String())
	if err != nil {
		t.Fatal("open isolated schema110 database", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		cleanup, done := context.WithTimeout(context.Background(), 10*time.Second)
		defer done()
		if _, e := admin.ExecContext(cleanup, "DROP DATABASE "+pq.QuoteIdentifier(name)+" WITH (FORCE)"); e != nil {
			t.Error("drop isolated schema110 database", e)
		}
	})
	var major int
	if err = db.QueryRowContext(ctx, "SELECT current_setting('server_version_num')::integer/10000").Scan(&major); err != nil || (major != 16 && major != 17) {
		t.Fatal("actual PostgreSQL16/17 required", major, err)
	}
	if expected := os.Getenv("EXPECTED_POSTGRES_MAJOR"); expected != "" && expected != strconv.Itoa(major) {
		t.Fatal("actual PostgreSQL owner differs from CI matrix")
	}
	_, file, _, _ := runtime.Caller(0)
	migrations := filepath.Join(filepath.Dir(file), "..", "db", "migrations")
	if err = goose.SetDialect("postgres"); err != nil {
		t.Fatal(err)
	}
	if err = goose.UpToContext(ctx, db, migrations, 109); err != nil {
		t.Fatal("real production migrations through109", err)
	}
	query := func(statement string) string {
		t.Helper()
		var value string
		if e := db.QueryRowContext(ctx, statement).Scan(&value); e != nil {
			t.Fatal("schema110 public catalog query", e)
		}
		return value
	}
	typeOf := func() string {
		return query("SELECT format_type(atttypid,atttypmod) FROM pg_attribute WHERE attrelid='public.event_log'::regclass AND attname='aggregate_id' AND NOT attisdropped")
	}
	history := func() string {
		return query("SELECT coalesce(jsonb_agg(to_jsonb(v) ORDER BY id),'[]'::jsonb)::text FROM public.goose_db_version v")
	}
	rows := func() string {
		return query("SELECT coalesce(jsonb_agg(to_jsonb(e) ORDER BY event_id),'[]'::jsonb)::text FROM public.event_log e")
	}
	request := func(id, key string) model.EmitEventRequest {
		return model.EmitEventRequest{Type: "kubernetes.object.ensured", SchemaVersion: "v1", AggregateType: "kubernetes_object", AggregateID: id,
			Payload: mutationPayloadForTest("kubernetes", "object", "ensured", id, "6827a9a6-c7af-4d3d-a9fc-4fafe59e2a64"), IdempotencyKey: key}
	}
	emit := func(req model.EmitEventRequest) (model.EmitEventOutcome, error) {
		t.Helper()
		tx, e := db.BeginTx(ctx, nil)
		if e != nil {
			return model.EmitEventOutcome{}, e
		}
		defer tx.Rollback()
		out, e := EmitEventWithOutcome(ctx, tx, req)
		if e == nil {
			e = tx.Commit()
		}
		return out, e
	}
	short := "admissionregistration.k8s.io/v1/MutatingWebhookConfiguration//core-api-native-guard-mutate@f07fda11-c6da-40a8-919a-5a476b9b115e"
	long := "admissionregistration.k8s.io/v1/ValidatingWebhookConfiguration//core-api-native-guard-validate@e6891fb9-cc82-4ce0-b0ba-53704e1dbc12"
	if len(short) != 127 || len(long) != 131 || typeOf() != "character varying(128)" {
		t.Fatal("real109 boundary or original public identity changed")
	}
	for i, id := range []string{short, strings.Repeat("x", 128)} {
		if _, err = emit(request(id, fmt.Sprintf("schema110-old-%d", i))); err != nil {
			t.Fatal("127/128 identities must fit109", err)
		}
	}
	oldRows, oldHistory := rows(), history()
	for _, id := range []string{strings.Repeat("x", 129), long} {
		_, e := emit(request(id, "schema110-old-refusal"))
		var pg *pq.Error
		if !errors.As(e, &pg) || pg.Code != "22001" || rows() != oldRows || history() != oldHistory {
			t.Fatal("109 must refuse129/131 atomically as string_data_right_truncation", e)
		}
	}
	before := eventAggregate110Catalog(t, ctx, db)
	eventAggregate110Evidence(t, "BEFORE109-PRESERVATION-VIEW.json", before, typeOf(), oldRows, oldHistory)
	if err = goose.UpToContext(ctx, db, migrations, 110); err != nil || typeOf() != "text" {
		t.Fatal("real109 to110 widening", err)
	}
	after := eventAggregate110Catalog(t, ctx, db)
	eventAggregate110Evidence(t, "AFTER110-PRESERVATION-VIEW.json", after, typeOf(), rows(), history())
	if before != after || rows() != oldRows {
		t.Fatal("widening changed old rows, other columns, indexes, constraints, triggers or functions")
	}
	var old, added []map[string]any
	if json.Unmarshal([]byte(oldHistory), &old) != nil || json.Unmarshal([]byte(history()), &added) != nil || len(added) != len(old)+1 || !reflect.DeepEqual(old, added[:len(old)]) || added[len(old)]["version_id"] != float64(110) || added[len(old)]["is_applied"] != true {
		t.Fatal("sole genuine110 history append must preserve whole109 prefix")
	}
	// Unused rollback is safe; used rollback must never truncate audit identity.
	if err = goose.DownContext(ctx, db, migrations); err != nil || typeOf() != "character varying(128)" || history() != oldHistory || rows() != oldRows {
		t.Fatal("unused110 Down must restore109 exactly", err)
	}
	if err = goose.UpToContext(ctx, db, migrations, 110); err != nil {
		t.Fatal("reapply110", err)
	}
	stableHistory := history()
	content, err := os.ReadFile(filepath.Join(migrations, "00110_event_log_aggregate_id_text.sql"))
	if err != nil {
		t.Fatal(err)
	}
	up := strings.SplitN(string(content), "-- +goose Down", 2)[0]
	if _, err = db.ExecContext(ctx, up); err != nil || history() != stableHistory || rows() != oldRows || after != eventAggregate110Catalog(t, ctx, db) {
		t.Fatal("Up SQL must be independently idempotent without another history row", err)
	}
	first, err := emit(request(long, "schema110-original-vwc-shape"))
	if err != nil || first.Deduped {
		t.Fatal("131-character original envelope shape must persist unmodified", err)
	}
	second, err := emit(request(long, "schema110-original-vwc-shape"))
	if err != nil || !second.Deduped || second.EventID != first.EventID {
		t.Fatal("existing same-type/idempotency uniqueness must remain effective", err)
	}
	var got string
	var count int
	if err = db.QueryRowContext(ctx, "SELECT count(*),min(aggregate_id) FROM public.event_log WHERE idempotency_key=$1", "schema110-original-vwc-shape").Scan(&count, &got); err != nil || count != 1 || got != long {
		t.Fatal("complete131 identity must remain exact in one row", err)
	}
	usedRows, usedHistory := rows(), history()
	if err = goose.DownContext(ctx, db, migrations); err == nil || !strings.Contains(err.Error(), "widening is in use") || typeOf() != "text" || rows() != usedRows || history() != usedHistory || after != eventAggregate110Catalog(t, ctx, db) {
		t.Fatal("used110 Down must refuse atomically without truncation", err)
	}
	// Match the old C7 runner filesystem: all original SQL, no110 source file.
	oldDir := t.TempDir()
	files, err := filepath.Glob(filepath.Join(migrations, "*.sql"))
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range files {
		base := filepath.Base(path)
		v, e := strconv.Atoi(strings.SplitN(base, "_", 2)[0])
		if e != nil {
			t.Fatal(e)
		}
		if v > 109 {
			continue
		}
		b, e := os.ReadFile(path)
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join(oldDir, base), b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	if err = goose.UpContext(ctx, db, oldDir); err != nil || rows() != usedRows || history() != usedHistory {
		t.Fatal("unchanged pinned C7 Goose with only old109 files must no-op on110", err)
	}
	if query("SELECT coalesce(jsonb_agg(to_jsonb(e) ORDER BY event_id),'[]'::jsonb)::text FROM public.event_log e WHERE idempotency_key LIKE 'schema110-old-%'") != oldRows {
		t.Fatal("all original109 rows must remain byte/semantic exact after long emit, dedup and refused Down")
	}
	t.Logf("schema110 PostgreSQL%d: real109 boundary127/128 and refused129/131; old rows/catalog preserved; one110 append; idempotence; unused/used Down; complete131 emit+dedup; oldC7 runner compatibility", major)
}

func eventAggregate110Evidence(t *testing.T, name, catalog, columnType, rows, history string) {
	t.Helper()
	dir := os.Getenv("EVENT_SCHEMA110_EVIDENCE_DIR")
	if dir == "" {
		return
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal("schema110 evidence directory", err)
	}
	data, err := json.Marshal(map[string]any{"actual_aggregate_id_type": columnType, "preservation_view_target_type_normalized_only": json.RawMessage(catalog), "original_event_rows": json.RawMessage(rows), "actual_goose_history": json.RawMessage(history)})
	if err != nil {
		t.Fatal("schema110 evidence encoding", err)
	}
	if err = os.WriteFile(filepath.Join(dir, name), append(data, '\n'), 0600); err != nil {
		t.Fatal("schema110 evidence retention", err)
	}
}

func eventAggregate110Catalog(t *testing.T, ctx context.Context, db *sql.DB) string {
	t.Helper()
	// Only the target's type is normalized. All other column attributes and
	// complete public catalog definitions must remain exact across the widening.
	const query = `SELECT jsonb_build_object(
 'columns',(SELECT coalesce(jsonb_agg(x ORDER BY x->>'table',x->>'number'),'[]') FROM (SELECT jsonb_build_object('table',c.relname,'number',a.attnum,'name',a.attname,'type',CASE WHEN c.relname='event_log' AND a.attname='aggregate_id' THEN '<only-widened-type>' ELSE format_type(a.atttypid,a.atttypmod) END,'not_null',a.attnotnull,'default',pg_get_expr(d.adbin,d.adrelid),'identity',a.attidentity,'generated',a.attgenerated,'collation',a.attcollation::regcollation::text) x FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace LEFT JOIN pg_attrdef d ON d.adrelid=c.oid AND d.adnum=a.attnum WHERE n.nspname='public' AND c.relkind IN('r','p') AND a.attnum>0 AND NOT a.attisdropped) q),
 'indexes',(SELECT coalesce(jsonb_agg(jsonb_build_object('name',ci.relname,'table',c.relname,'definition',pg_get_indexdef(i.indexrelid),'unique',i.indisunique,'primary',i.indisprimary,'ready',i.indisready,'valid',i.indisvalid) ORDER BY c.relname,ci.relname),'[]') FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid JOIN pg_class ci ON ci.oid=i.indexrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public'),
 'constraints',(SELECT coalesce(jsonb_agg(jsonb_build_object('name',k.conname,'table',c.relname,'definition',pg_get_constraintdef(k.oid),'kind',k.contype,'validated',k.convalidated,'deferrable',k.condeferrable,'deferred',k.condeferred) ORDER BY c.relname,k.conname),'[]') FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public'),
 'triggers',(SELECT coalesce(jsonb_agg(jsonb_build_object('table',c.relname,'name',t.tgname,'enabled',t.tgenabled,'definition',pg_get_triggerdef(t.oid)) ORDER BY c.relname,t.tgname),'[]') FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND NOT t.tgisinternal),
 'functions',(SELECT coalesce(jsonb_agg(jsonb_build_object('name',p.proname,'arguments',pg_get_function_identity_arguments(p.oid),'definition',pg_get_functiondef(p.oid)) ORDER BY p.proname,pg_get_function_identity_arguments(p.oid)),'[]') FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public' AND p.prokind IN('f','p'))
)::text`
	var value string
	if err := db.QueryRowContext(ctx, query).Scan(&value); err != nil {
		t.Fatal("complete schema110 catalog preservation", err)
	}
	return value
}
