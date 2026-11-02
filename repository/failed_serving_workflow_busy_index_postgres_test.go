//go:build recoveryfixture && !nativequalification

package repository

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
	"github.com/pressly/goose/v3"
)

const failedServingBusyIndex89Name = "workflow_runs_workflow_id_idx"

// This is a disposable PostgreSQL index/query qualification, not a provider or
// Guest fixture. It calls the unchanged production predicate with legal rows,
// including inconsistent UUID/catalog identities and unfinished terminal rows.
// No production constraint is removed and no planner option is overridden.
func failedServingWorkflowBusyIndex89(t *testing.T) {
	t.Helper()
	db := failedServingDB(t)
	ctx := failedServingContext(t)
	migrations := filepath.Join(failedServingRepositoryRoot(t), "db", "migrations")
	failedServingIndex89Catalog(t, ctx, db)

	// Only the new additive index is reversed in this new disposable database.
	// Reapplying through real Goose on a populated table proves NO TRANSACTION
	// rather than testing a separately copied CREATE INDEX implementation.
	if err := goose.DownContext(ctx, db, migrations); err != nil {
		t.Fatal("disposable index89 baseline", err)
	}
	if version, err := goose.GetDBVersionContext(ctx, db); err != nil || version != 88 {
		t.Fatal("only index89 may be reversed for the isolated baseline", version, err)
	}
	const fillerRows = 100000
	if _, err := db.ExecContext(ctx, `INSERT INTO public.workflow_runs
 (workflow_namespace,workflow_name,workflow_id,status,finished_at,metadata)
 SELECT 'unrelated-index89','completed-other-workflow',gen_random_uuid(),'succeeded',clock_timestamp(),
 jsonb_build_object('declared_fixture_padding',repeat(md5(n::text),24))
 FROM generate_series(1,$1) n`, fillerRows); err != nil {
		t.Fatal("bounded production-shaped completed-history fixture", err)
	}
	if _, err := db.ExecContext(ctx, `ANALYZE public.workflow_runs`); err != nil {
		t.Fatal(err)
	}
	policy := model.Manifest{Metadata: model.ManifestMetadata{Namespace: "index89-target"}}
	p := model.CapacityPolicySpec{Environment: "production", Domain: "notify", Dimension: "index89-readonly-fixture"}
	p.Workflow.Name = "target-workflow"
	p.MutationBindings = []model.CapacityMutationBinding{{IntegrationInstanceID: uuid.NewString(), ScopeChecksum: strings.Repeat("a", 64), ProfileName: "index89-profile"}}
	workflow := model.Manifest{ID: uuid.New()}
	preID, now := uuid.NewString(), time.Now().UTC()
	b := p.MutationBindings[0]
	args := []any{workflow.ID, policy.Metadata.Namespace, p.Workflow.Name, p.Environment, p.Domain, p.Dimension, preID, now, b.IntegrationInstanceID, b.ScopeChecksum, b.ProfileName}
	query := failedServingIndex89ProductionQuery(t)
	before := failedServingIndex89Explain(t, ctx, db, query, args)
	if !before.workflowSequential || before.newIndex {
		t.Fatal("missing-index baseline did not reproduce the complete UUID-arm scan", before)
	}
	if err := goose.UpContext(ctx, db, migrations); err != nil {
		t.Fatal("real concurrent index89 migration on populated history", err)
	}
	failedServingIndex89Catalog(t, ctx, db)
	if _, err := db.ExecContext(ctx, `ANALYZE public.workflow_runs`); err != nil {
		t.Fatal(err)
	}
	after := failedServingIndex89Explain(t, ctx, db, query, args)
	if after.workflowSequential || !after.newIndex || !after.nameIndex || !after.bitmapOr {
		t.Fatal("unforced complete predicate did not use both identity indexes", after)
	}
	var rows, bytes int64
	if err := db.QueryRowContext(ctx, `SELECT count(*),pg_table_size('public.workflow_runs') FROM public.workflow_runs`).Scan(&rows, &bytes); err != nil || rows != fillerRows {
		t.Fatal("fixture shape differs", rows, bytes, err)
	}
	t.Logf("WORKFLOW_BUSY_INDEX89_PLAN rows=%d table_bytes=%d before_ms=%.3f after_ms=%.3f both_identity_indexes=true planner_overrides=false production_benchmark=false", rows, bytes, before.executionMS, after.executionMS)

	cases := []struct {
		name, namespace, nameValue, status string
		id                                 any
		finished                           any
		busy                               bool
	}{
		{"uuid_only_foreign_catalog_running_with_finish", "foreign", "foreign", "running", workflow.ID, now, true},
		{"names_only_foreign_uuid_terminal_unfinished", policy.Metadata.Namespace, p.Workflow.Name, "failed", uuid.New(), nil, true},
		{"names_only_legacy_null_uuid", policy.Metadata.Namespace, p.Workflow.Name, "pending", nil, nil, true},
		{"both_identities_cancelled_unfinished", policy.Metadata.Namespace, p.Workflow.Name, "cancelled", workflow.ID, nil, true},
		{"uuid_only_succeeded_unfinished", "foreign", "foreign", "succeeded", workflow.ID, nil, true},
		{"both_identities_succeeded_finished", policy.Metadata.Namespace, p.Workflow.Name, "succeeded", workflow.ID, now, false},
		{"names_only_failed_finished", policy.Metadata.Namespace, p.Workflow.Name, "failed", uuid.New(), now, false},
		{"uuid_only_cancelled_finished", "foreign", "foreign", "cancelled", workflow.ID, now, false},
		{"unrelated_pending_is_outside_both_arms", "foreign", "foreign", "pending", uuid.New(), nil, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tx, err := db.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			if _, err = tx.ExecContext(ctx, `INSERT INTO public.workflow_runs(workflow_namespace,workflow_name,workflow_id,status,finished_at) VALUES($1,$2,$3,$4,$5)`, c.namespace, c.nameValue, c.id, c.status, c.finished); err != nil {
				t.Fatal("all adversarial workflow rows must satisfy the production schema", err)
			}
			// The actual predicate reads its own legal transaction row; this is
			// query semantics, not a claim about a second public API transaction.
			err = failedServingBusyTx(ctx, tx, policy, p, workflow, preID, now)
			if c.busy && !errors.Is(err, ErrCapacityConflict) || !c.busy && err != nil {
				t.Fatal("complete production busy predicate changed", c.name, err)
			}
		})
	}
	if err := goose.UpContext(ctx, db, migrations); err != nil {
		t.Fatal("all-applied latest migration replay", err)
	}
	// This is the exact v3.27 Up entry point shipped by the unchanged old
	// scripts/goose, presented with its old <=88 files and the newer database.
	// It is not execution of an old container or a claim of native rollout.
	oldFiles := t.TempDir()
	entries, err := os.ReadDir(migrations)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		version, err := strconv.ParseInt(strings.SplitN(entry.Name(), "_", 2)[0], 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		if version > 88 {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(migrations, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(oldFiles, entry.Name()), raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := goose.UpContext(ctx, db, oldFiles); err != nil {
		t.Fatal("old88 migration file view rejects compatible additive schema89", err)
	}
	if version, err := goose.GetDBVersionContext(ctx, db); err != nil || version != 89 {
		t.Fatal("old88 file view changed the latest applied schema", version, err)
	}
	failedServingIndex89Catalog(t, ctx, db)
	t.Log("WORKFLOW_BUSY_INDEX89_SCHEMA89_VALID_READY_NONUNIQUE_OLD88_UP_COMPATIBLE_RUNTIME_GO_UNCHANGED")
}

func failedServingIndex89Catalog(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()
	var valid, ready, live, unique, primary, exclusion, noExpression, noPredicate bool
	var keys, attributes int
	var method, definition string
	err := db.QueryRowContext(ctx, `SELECT i.indisvalid,i.indisready,i.indislive,i.indisunique,i.indisprimary,i.indisexclusion,
 i.indnkeyatts,i.indnatts,am.amname,pg_get_indexdef(i.indexrelid),i.indexprs IS NULL,i.indpred IS NULL
 FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid JOIN pg_namespace n ON n.oid=c.relnamespace
 JOIN pg_am am ON am.oid=c.relam WHERE n.nspname='public' AND c.relname=$1 AND i.indrelid='public.workflow_runs'::regclass`, failedServingBusyIndex89Name).Scan(&valid, &ready, &live, &unique, &primary, &exclusion, &keys, &attributes, &method, &definition, &noExpression, &noPredicate)
	want := "CREATE INDEX workflow_runs_workflow_id_idx ON public.workflow_runs USING btree (workflow_id)"
	if err != nil || !valid || !ready || !live || unique || primary || exclusion || keys != 1 || attributes != 1 || method != "btree" || definition != want || !noExpression || !noPredicate {
		t.Fatal("index name alone is not a valid/ready exact nonunique workflow UUID index", definition, err)
	}
}

// Resolve the real source statement, including its unchanged grant constant.
// A full production-file SHA pin also preserves unknown-status and NULL guards
// without removing constraints to manufacture otherwise impossible table rows.
func failedServingIndex89ProductionQuery(t *testing.T) string {
	t.Helper()
	path := filepath.Join(failedServingRepositoryRoot(t), "repository", "capacity_guest_failed_serving_disposal.go")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	if hex.EncodeToString(digest[:]) != "244904c4d6880db4f687ab8771e154397bc76f2c5933a0a88f81ce52860fe6a2" {
		t.Fatal("index-only migration must preserve the full reviewed production guard bytes")
	}
	file, err := parser.ParseFile(token.NewFileSet(), path, raw, 0)
	if err != nil {
		t.Fatal(err)
	}
	var decode func(ast.Expr) string
	decode = func(expr ast.Expr) string {
		switch node := expr.(type) {
		case *ast.BasicLit:
			if node.Kind == token.STRING {
				value, err := strconv.Unquote(node.Value)
				if err != nil {
					t.Fatal(err)
				}
				return value
			}
		case *ast.BinaryExpr:
			if node.Op == token.ADD {
				return decode(node.X) + decode(node.Y)
			}
		case *ast.Ident:
			if node.Name == "capacityGrantUndisposedSQL" {
				return capacityGrantUndisposedSQL
			}
		}
		t.Fatal("unexpected production busy statement expression")
		return ""
	}
	var query string
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "failedServingBusyTx" {
			continue
		}
		ast.Inspect(fn.Body, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			if ok && selector.Sel.Name == "QueryRowContext" {
				if query != "" || len(call.Args) != 13 {
					t.Fatal("unexpected production busy call census")
				}
				query = decode(call.Args[1])
			}
			return true
		})
	}
	if query == "" {
		t.Fatal("missing production busy statement")
	}
	return query
}

type failedServingIndex89Plan struct {
	workflowSequential, newIndex, nameIndex, bitmapOr bool
	executionMS                                       float64
}

func failedServingIndex89Explain(t *testing.T, ctx context.Context, db *sql.DB, query string, args []any) failedServingIndex89Plan {
	t.Helper()
	var raw []byte
	if err := db.QueryRowContext(ctx, "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) "+query, args...).Scan(&raw); err != nil {
		t.Fatal("bounded native plan of the exact production statement", err)
	}
	var rows []map[string]any
	if json.Unmarshal(raw, &rows) != nil || len(rows) != 1 {
		t.Fatal("one native EXPLAIN JSON result required")
	}
	var out failedServingIndex89Plan
	out.executionMS, _ = rows[0]["Execution Time"].(float64)
	var visit func(any)
	visit = func(value any) {
		switch node := value.(type) {
		case map[string]any:
			if node["Relation Name"] == "workflow_runs" && (node["Node Type"] == "Seq Scan" || node["Node Type"] == "Parallel Seq Scan") {
				out.workflowSequential = true
			}
			out.newIndex = out.newIndex || node["Index Name"] == failedServingBusyIndex89Name
			out.nameIndex = out.nameIndex || node["Index Name"] == "workflow_runs_workflow_idx"
			out.bitmapOr = out.bitmapOr || node["Node Type"] == "BitmapOr"
			for _, child := range node {
				visit(child)
			}
		case []any:
			for _, child := range node {
				visit(child)
			}
		}
	}
	visit(rows[0]["Plan"])
	return out
}
