package repository

import (
	"context"
	"database/sql"
	"errors"
	"github.com/google/uuid"
	"github.com/lib/pq"
	"os"
	"strings"
	"testing"
	"time"
)

// Native FK negatives only. No grant, enrollment, accepted nonce, canary or
// signed Guest chain is inserted. Positive original runtime coverage is owned
// by the native workflow fixture, not a fabricated SQL parent.
func TestGuestRetirementV2PostgresAbsentOriginalAuthority(t *testing.T) {
	dsn := os.Getenv("DB_URL")
	if dsn == "" {
		if os.Getenv("REQUIRE_GUEST_RETIREMENT_V2_DB_TEST") == "true" {
			t.Fatal("required native retirement DB_URL absent")
		}
		t.Skip("DB_URL absent; no native PG claim")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	id, missing := uuid.NewString(), uuid.NewString()
	digest := strings.Repeat("a", 64)
	for _, test := range []struct {
		name, statement string
		args            []any
	}{
		{"nonce_without_original", `INSERT INTO public.capacity_vm_retirement_original_returns(intent_id,sequence,kind,previous_sha256,return_sha256,original_return_record,recorded_at,original_wire) VALUES($1,1,'production_clock_nonce_v2','',$2,'{}'::jsonb,clock_timestamp(),'{}'::bytea)`, []any{missing, digest}},
		{"guest_record_without_original", `INSERT INTO public.capacity_vm_retirement_original_returns(intent_id,sequence,kind,previous_sha256,return_sha256,original_return_record,recorded_at,original_wire) VALUES($1,2,'production_retirement_v2:possible_start','',$2,'{}'::jsonb,clock_timestamp(),'{}'::bytea)`, []any{missing, digest}},
		{"native_read_without_original", `INSERT INTO public.capacity_guest_original_native_poweroff_reads(id,intent_id,observation_sha256,original_wire,original_record,recorded_at) VALUES($1,$2,$3,'{}'::bytea,'{}'::jsonb,clock_timestamp())`, []any{id, missing, digest}},
		{"native_absence_without_destroy", `INSERT INTO public.capacity_vm_retirement_native_readbacks(id,destroy_grant_id,observation_sha256,original_observation_record,recorded_at,original_wire) VALUES($1,$2,$3,'{}'::jsonb,clock_timestamp(),'{}'::bytea)`, []any{id, missing, digest}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := tx.ExecContext(ctx, `SAVEPOINT missing_original`); err != nil {
				t.Fatal(err)
			}
			_, err := tx.ExecContext(ctx, test.statement, test.args...)
			var native *pq.Error
			if !errors.As(err, &native) || native.Code != "23503" {
				t.Error("missing original must fail native FK", err)
			}
			if _, err = tx.ExecContext(ctx, `ROLLBACK TO SAVEPOINT missing_original`); err != nil {
				t.Fatal(err)
			}
		})
	}
}
