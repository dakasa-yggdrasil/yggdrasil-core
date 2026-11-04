package repository

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

// Real PostgreSQL negative controls: migration 70 must retain native PK/unique,
// FK and immutable trigger definitions, and refuse writes without an original
// enrolled parent. This deliberately creates NO enrollment, receipt, business
// effect or accepted authority. Positive native producer coverage is separate.
func TestGuestNotifyCanaryPostgresSchemaAndAbsentAuthority(t *testing.T) {
	required := os.Getenv("REQUIRE_GUEST_NOTIFY_CANARY_DB_TEST") == "true"
	dsn := os.Getenv("DB_URL")
	if dsn == "" {
		if required {
			t.Fatal("required native Guest canary DB_URL absent")
		}
		t.Skip("DB_URL absent; no PostgreSQL coverage claimed")
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
	tables := []struct {
		name         string
		uniques, fks int
	}{
		{"capacity_guest_notify_canary_challenges", 2, 4},
		{"capacity_guest_notify_canary_nonces", 2, 1},
		{"capacity_guest_notify_canary_sends", 0, 1},
		{"capacity_guest_notify_canary_returns", 0, 1},
	}
	for _, table := range tables {
		t.Run(table.name, func(t *testing.T) {
			var pks, uniques, fks, triggers int
			err := tx.QueryRowContext(ctx, `SELECT count(*) FILTER(WHERE contype='p'),count(*) FILTER(WHERE contype='u'),count(*) FILTER(WHERE contype='f') FROM pg_constraint WHERE conrelid=to_regclass('public.'||$1)`, table.name).Scan(&pks, &uniques, &fks)
			if err != nil || pks != 1 || uniques != table.uniques || fks != table.fks {
				t.Fatal("native one-use/FK constraints absent", err, pks, uniques, fks)
			}
			err = tx.QueryRowContext(ctx, `SELECT count(*) FROM pg_trigger WHERE tgrelid=to_regclass('public.'||$1) AND NOT tgisinternal AND tgenabled='O' AND tgtype=27 AND tgfoid='public.capacity_guest_notify_canary_immutable()'::regprocedure`, table.name).Scan(&triggers)
			if err != nil || triggers != 1 {
				t.Fatal("native BEFORE UPDATE OR DELETE immutable trigger absent", err, triggers)
			}
		})
	}
	id, missing, policy, workflow := uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()
	digest := strings.Repeat("a", 64)
	for _, test := range []struct {
		name, sql string
		args      []any
	}{
		{"no_original_enrollment", `WITH observed AS MATERIALIZED(SELECT clock_timestamp() AS now) INSERT INTO public.capacity_guest_notify_canary_challenges(id,preregistration_id,record_challenge_id,phase,policy_id,workflow_id,generation,fence,executor_id,lease_owner,challenge_sha256,nonce_sha256,original_wire,original_record,original_deadline,recorded_at) SELECT $1,$2,$1,'publish',$3,$4,1,1,'invalid-parent-negative','invalid-parent-negative',$5,$5,'{}'::bytea,jsonb_build_object('schema','guest_notify_business_canary_publish_challenge_v1','issued_at',observed.now,'original_deadline',observed.now+interval '1 second'),observed.now+interval '1 second',observed.now FROM observed`, []any{id, missing, policy, workflow, digest}},
		{"no_challenge_nonce", `INSERT INTO public.capacity_guest_notify_canary_nonces VALUES($1,$2,'{}'::bytea,'{}'::bytea,$2,'{}'::jsonb,clock_timestamp())`, []any{id, digest}},
		{"no_challenge_possible_send", `INSERT INTO public.capacity_guest_notify_canary_sends VALUES($1,$2,clock_timestamp(),clock_timestamp()+interval '1 second',clock_timestamp())`, []any{id, digest}},
		{"no_challenge_return", `INSERT INTO public.capacity_guest_notify_canary_returns VALUES($1,'accepted',$2,'{}'::bytea,'{}'::jsonb,'{}'::jsonb,clock_timestamp())`, []any{id, digest}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := tx.ExecContext(ctx, `SAVEPOINT absent_authority`); err != nil {
				t.Fatal(err)
			}
			_, err := tx.ExecContext(ctx, test.sql, test.args...)
			var native *pq.Error
			if !errors.As(err, &native) || native.Code != "23503" {
				t.Error("native FK must refuse absent original authority", err)
			}
			if _, err = tx.ExecContext(ctx, `ROLLBACK TO SAVEPOINT absent_authority`); err != nil {
				t.Fatal(err)
			}
		})
	}
}
