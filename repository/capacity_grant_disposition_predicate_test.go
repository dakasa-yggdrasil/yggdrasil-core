package repository

import (
	"bufio"
	"context"
	"go/build/constraint"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// Every grant pointer column a migration adds must be named by the shared
// predicate; a new disposition protocol cannot silently stay "pending".
func TestCapacityGrantUndisposedPredicateNamesEveryDispositionPointer(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("..", "db", "migrations", "*.sql"))
	if err != nil || len(files) == 0 {
		t.Fatal("migrations unavailable", err)
	}
	column := regexp.MustCompile(`(?i)ALTER TABLE public\.capacity_mutation_grants\s+ADD COLUMN\s+(?:IF NOT EXISTS\s+)?([a-z_]+_disposition_id)\b`)
	seen := map[string]bool{}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range column.FindAllStringSubmatch(string(raw), -1) {
			seen[strings.ToLower(m[1])] = true
		}
	}
	if len(seen) != 4 {
		t.Fatalf("unexpected grant disposition pointers %v", seen)
	}
	for c := range seen {
		if !strings.Contains(capacityGrantUndisposedSQL, c+" IS NULL") {
			t.Fatalf("predicate omits %s", c)
		}
	}
	if strings.Contains(capacityGrantUndisposedSQL, " OR ") || strings.Count(capacityGrantUndisposedSQL, " IS NULL") != len(seen) {
		t.Fatal("predicate is not the exact conjunction of pointer absence")
	}
}

// Pins only the SQL shape every dimension-wide unresolved check shares (the
// production gen10 Guest refresh regression: AWS originals disposed in earlier
// generations stay 'settled'). The exclusion itself is proven against Postgres
// in TestCountUnresolvedCapacityGrantsPostgresExcludesDisposedOriginal.
func TestCountUnresolvedCapacityGrantsQueryShape(t *testing.T) {
	db, m, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	p := model.CapacityPolicySpec{Environment: "production", Domain: "guest", Dimension: "aws"}
	m.ExpectBegin()
	m.ExpectQuery(`SELECT count\(\*\) FROM public\.capacity_mutation_grants WHERE `+regexp.QuoteMeta(capacityGrantUndisposedSQL)+` AND NOT\(grant_record \? 'authority_kind'\) AND namespace=\$1 AND environment=\$2 AND domain=\$3 AND dimension=\$4 AND state IN \('issued','redeemed','settled','compensating'\)$`).WithArgs("ops", p.Environment, p.Domain, p.Dimension).WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	m.ExpectRollback()
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	n, err := countUnresolvedCapacityGrantsTx(context.Background(), tx, "ops", p)
	if err != nil || n != 0 {
		t.Fatal(n, err)
	}
	_ = tx.Rollback()
	if err = m.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

// Source contract over every repository and message-controller query that
// default builds compile: a grant projection that counts 'settled' as live
// authority must carry the full undisposed predicate, unless it is
// structurally unable to select a disposed original.
func TestCapacityPendingGrantQueriesExcludeDisposedOriginals(t *testing.T) {
	allowed := map[string][]string{
		// Compensation children; a disposition requires no compensation child.
		"capacity_compensation.go": {`grant_record->'grant'->>'compensation_of'=$1`},
		"capacity_executor_power.go": {
			// Executor power authority grants only (authority_kind set).
			`grant_record->>'authority_kind'=$1`,
			// Deliberately conservative global hold: an unknown-identity legacy
			// original blocks every adoption, disposed or not. Out of scope here.
			`grant_record->'grant'->>'capability' ~ '^ensure_' AND state IN ('redeemed','settled','compensating') AND COALESCE(grant_record->'settlement'->>'resource_id','')=''`,
		},
		// Destroy grants; dispositions attach only to the preregistered create grant.
		"capacity_guest_notify_floor_members.go": {`grant_record->'grant'->>'capability'=$6`},
		"capacity_guest_notify_useful.go":        {`grant_record->'grant'->>'capability'=$6`},
		"capacity_guest_retirement.go":           {`grant_record->'grant'->>'capability'=$5`},
		// Open original deadline; a disposition requires the deadline closed.
		"capacity_guest_provisioning.go": {`p.original_deadline>clock_timestamp()`},
	}
	// Disposition protocols that predate the shared constant and spell the full
	// conjunction in a different clause order.
	reordered := map[string]bool{"capacity_enrolled_failed_original_disposition.go": true}
	pointers := []string{"original_disposition_id", "failed_original_disposition_id", "native_denied_disposition_id", "enrolled_failed_disposition_id"}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	controllers, err := filepath.Glob(filepath.Join("..", "controllers", "message", "*.go"))
	if err != nil || len(controllers) == 0 {
		t.Fatal("message controllers unavailable", err)
	}
	files = append(files, controllers...)
	literal := regexp.MustCompile("`[^`]*`")
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		src := string(raw)
		if capacityGrantPredicateQualificationOnly(t, f, src) {
			continue
		}
		name := filepath.Base(f)
		src = strings.NewReplacer("`+capacityGrantUndisposedSQL+`", capacityGrantUndisposedSQL, "` + capacityGrantUndisposedSQL + `", capacityGrantUndisposedSQL).Replace(src)
		for _, q := range literal.FindAllString(src, -1) {
			if !strings.Contains(q, "capacity_mutation_grants") || !strings.Contains(q, "'settled'") || strings.Contains(q, capacityGrantUndisposedSQL) {
				continue
			}
			if reordered[name] && capacityGrantNamesEveryPointer(q, pointers) {
				continue
			}
			exempt := false
			for _, marker := range allowed[name] {
				exempt = exempt || strings.Contains(q, marker)
			}
			if !exempt {
				t.Errorf("%s: pending grant query keeps disposed originals: %.160s", f, q)
			}
		}
	}
}

func capacityGrantNamesEveryPointer(q string, pointers []string) bool {
	for _, c := range pointers {
		if !regexp.MustCompile(`(^|[^a-z_])` + c + ` IS NULL`).MatchString(q) {
			return false
		}
	}
	return true
}

// Reports whether the file's build constraint cannot be satisfied without a
// qualification/fixture tag; such files never ship in the default binary.
func capacityGrantPredicateQualificationOnly(t *testing.T, f, src string) bool {
	t.Helper()
	lines := bufio.NewScanner(strings.NewReader(src))
	for lines.Scan() {
		line := strings.TrimSpace(lines.Text())
		if strings.HasPrefix(line, "package ") {
			return false
		}
		if !constraint.IsGoBuild(line) {
			continue
		}
		expr, err := constraint.Parse(line)
		if err != nil {
			t.Fatal(f, err)
		}
		for _, tag := range []string{"nativequalification", "capacitytest", "recoveryfixture"} {
			if capacityGrantConstraintRequires(expr, tag) {
				return true
			}
		}
		return false
	}
	return false
}

// True when no assignment of the expression's other tags satisfies it with tag off.
func capacityGrantConstraintRequires(expr constraint.Expr, tag string) bool {
	seen := map[string]bool{}
	var others []string
	var walk func(constraint.Expr)
	walk = func(e constraint.Expr) {
		switch x := e.(type) {
		case *constraint.AndExpr:
			walk(x.X)
			walk(x.Y)
		case *constraint.OrExpr:
			walk(x.X)
			walk(x.Y)
		case *constraint.NotExpr:
			walk(x.X)
		case *constraint.TagExpr:
			if x.Tag != tag && !seen[x.Tag] {
				seen[x.Tag] = true
				others = append(others, x.Tag)
			}
		}
	}
	walk(expr)
	for mask := 0; mask < 1<<len(others); mask++ {
		on := map[string]bool{}
		for i, name := range others {
			on[name] = mask&(1<<i) != 0
		}
		if expr.Eval(func(name string) bool { return name != tag && on[name] }) {
			return false
		}
	}
	return true
}
