package repository

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// Real PostgreSQL delay and semantic signed operands only. No production
// enrollment, accepted ledger row or native business authority is invented.
func TestGuestNotifyClosedOriginalClockAfterPostgresRetentionDelay(t *testing.T) {
	dsn := os.Getenv("DB_URL")
	if dsn == "" {
		if os.Getenv("REQUIRE_GUEST_NOTIFY_CANARY_DB_TEST") == "true" {
			t.Fatal("required native DB_URL absent")
		}
		t.Skip("DB_URL absent; no PostgreSQL coverage claimed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SET LOCAL statement_timeout='2s'`); err != nil {
		t.Fatal(err)
	}
	if err = tx.QueryRowContext(ctx, `SELECT current_setting('transaction_read_only')`).Scan(new(string)); err != nil {
		t.Fatal(err)
	}
	c, e, returned := closedCanaryReturnUnit(t, time.Now().UTC())
	var delay any
	if err = tx.QueryRowContext(ctx, `SELECT pg_sleep(0.2)`).Scan(&delay); err != nil {
		t.Fatal(err)
	}
	if !time.Now().After(c.OriginalDeadline) {
		t.Fatal("native delay did not cross immutable original deadline")
	}
	var body model.CapacityGuestNotifyCanaryRead
	if guestNotifyClosedOriginalEnvelope(c, e, returned, &body) != "" {
		t.Fatal("retention delay invalidated original complete response")
	}
	if capacity.ValidateGuestNotifyCanaryEnvelope(c, e, body, time.Now().UTC()) == nil {
		t.Fatal("old wall-clock bug not reproduced")
	}
	late := returned
	late.DriverReturnedAt = c.OriginalDeadline
	if guestNotifyClosedOriginalEnvelope(c, e, late, &body) == "" {
		t.Fatal("native delay admitted late original")
	}
	if err = tx.Rollback(); err != nil {
		t.Fatal(err)
	}
}
