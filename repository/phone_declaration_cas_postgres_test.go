package repository

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/contactphone"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/cryptoenvelope"
)

func TestPhoneDeclarationCASPostgres(t *testing.T) {
	db := phoneDirectoryPostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	t.Setenv(contactphone.EnrollmentPolicyEnv, "false")
	person := phoneFixture(t, db, false)
	envelope := cryptoenvelope.NewWithStaticKEK([]byte(strings.Repeat("k", 32)))
	self, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = self.Rollback() }()
	var selfPID int
	if self.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&selfPID) != nil {
		t.Fatal("self transaction unavailable")
	}
	declared, err := SetPhoneContactTx(ctx, self, envelope, person.ID, "+12025550121", "ci-self", "self_profile")
	if err != nil {
		t.Fatal("self declaration failed")
	}
	backfill, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = backfill.Rollback() }()
	var backfillPID int
	if backfill.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&backfillPID) != nil {
		t.Fatal("backfill transaction unavailable")
	}
	done := make(chan error, 1)
	go func() {
		_, e := SetPhoneContactIfVersionTx(ctx, backfill, envelope, person.ID, "+12025550122", "ci-operator", 0)
		done <- e
	}()
	// Prove the conditional writer waits behind the exact self writer before
	// it can compare absence, instead of using a prior unlocked lookup.
	for {
		var blocked bool
		if db.QueryRowContext(ctx, `SELECT $1=ANY(pg_blocking_pids($2))`, selfPID, backfillPID).Scan(&blocked) != nil {
			t.Fatal("lock observation failed")
		}
		if blocked {
			break
		}
		select {
		case e := <-done:
			t.Fatalf("backfill did not wait behind self: %v", e)
		case <-ctx.Done():
			t.Fatal("writer did not wait on collaborator authority")
		case <-time.After(10 * time.Millisecond):
		}
	}
	if self.Commit() != nil {
		t.Fatal("self declaration did not commit")
	}
	select {
	case e := <-done:
		if !errors.Is(e, ErrPhoneVersionConflict) {
			t.Fatal("backfill overwrote a racing self declaration")
		}
	case <-ctx.Done():
		t.Fatal("conditional writer did not finish")
	}
	_ = backfill.Rollback()
	current, err := GetPhoneContact(ctx, db, envelope, person.ID)
	if err != nil || current == nil || current.Version != declared.Version || current.DeclarationSource != "self_profile" || current.PhoneE164 != "+12025550121" {
		t.Fatal("conflict changed version/provenance/value")
	}
	var count int
	if db.QueryRowContext(ctx, `SELECT count(*) FROM audit_events WHERE action='collaborator.phone_declared' AND resource_id=$1`, person.ID.String()).Scan(&count) != nil || count != 1 {
		t.Fatal("refused declaration added a successful audit")
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	updated, err := SetPhoneContactIfVersionTx(ctx, tx, envelope, person.ID, "+12025550123", "ci-operator", declared.Version)
	if err != nil || tx.Commit() != nil || updated.Version != declared.Version+1 || updated.DeclarationSource != "operator_assertion" {
		t.Fatal("matched conditional declaration failed")
	}
}
