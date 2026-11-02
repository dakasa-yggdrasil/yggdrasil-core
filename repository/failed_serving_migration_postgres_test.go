//go:build recoveryfixture && !nativequalification

package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/google/uuid"
)

func TestFailedServingMigration88RejectsForgedLineageAndReplayPostgres(t *testing.T) {
	for _, provider := range []string{"aws", "hetzner"} {
		t.Run(provider, func(t *testing.T) {
			f := newFailedServingFixture(t, provider)
			ctx := failedServingContext(t)
			q := failedServingQuarantine(t, f)
			off := failedServingClone(t, q)
			off.Stage = "quiescent"
			off.RecordID = uuid.NewString()
			off.Inventory = nil
			plan := f.offPlan(t)
			off.NativeOff = &plan
			before, originals := f.rawIntent(t), f.preserved(t)
			var replication string
			if err := f.db.QueryRow(`SHOW session_replication_role`).Scan(&replication); err != nil || replication != "origin" {
				t.Fatal("migration gate must use native triggers", err)
			}
			for _, name := range []string{"foreign_scope", "foreign_admission", "foreign_preregistration", "forged_stage", "claimed_mutation", "claimed_drain", "lost_preservation", "wrong_wire_sha", "detached_terminal"} {
				t.Run(name, func(t *testing.T) {
					r := failedServingClone(t, off)
					r.RecordID = uuid.NewString()
					switch name {
					case "foreign_scope":
						r.Namespace = "foreign-realm"
					case "foreign_admission":
						r.ID = uuid.NewString()
					case "foreign_preregistration":
						r.PreregistrationID = uuid.NewString()
					case "forged_stage":
						r.Stage = "promoted"
					case "claimed_mutation":
						r.CoreOrGuestNativeWriteSent = true
					case "claimed_drain":
						r.GuestWriterDrainClaimed = true
					case "lost_preservation":
						r.BusinessEffectsPreserved = false
					case "detached_terminal":
						r.Stage = "terminal"
						r.NativeOff = nil
						r.Inventory = nil
						r.Absence = nil
					}
					raw := failedServingWire(t, r)
					sha := capacity.BusinessCreationSHA256(raw)
					if name == "wrong_wire_sha" {
						sha = strings.Repeat("f", 64)
					}
					tx, err := f.db.BeginTx(ctx, nil)
					if err != nil {
						t.Fatal(err)
					}
					defer tx.Rollback()
					if err = lockMutationScope(ctx, tx, f.policy.Metadata.Namespace, f.p); err != nil {
						t.Fatal(err)
					}
					_, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_guest_failed_serving_disposals(row_id,admission_id,stage,namespace,environment,domain,dimension,preregistration_id,original_wire,original_record,record_sha256,recorded_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11,$12)`, r.RecordID, r.ID, r.Stage, r.Namespace, r.Environment, r.Domain, r.Dimension, r.PreregistrationID, raw, string(raw), sha, r.RecordedAt)
					if err == nil {
						err = tx.Commit()
					} else {
						_ = tx.Rollback()
					}
					if err == nil {
						t.Fatal("forged/unowned/replayed immutable stage committed")
					}
					if failedServingCount(t, f) != 1 || !reflect.DeepEqual(f.rawIntent(t), before) || !reflect.DeepEqual(f.preserved(t), originals) {
						t.Fatal("SQL refusal changed original lineage")
					}
				})
			}
			failedServingNullableIdentityChecks(t, f, off)
			// The trigger acquires its own advisory locks; the refusal cases
			// above concern lineage/content, never a claimed caller-lock seam.
			realOff := failedServingOff(t, f, q.ID)
			replay := failedServingClone(t, realOff)
			replay.RecordID = uuid.NewString()
			replayTx, e := f.db.BeginTx(ctx, nil)
			if e != nil {
				t.Fatal(e)
			}
			if e = insertFailedServingTx(ctx, replayTx, replay); e == nil {
				e = replayTx.Commit()
			} else {
				_ = replayTx.Rollback()
			}
			if e == nil {
				t.Fatal("successful immutable OFF stage replayed")
			}
			for _, statement := range []string{`UPDATE public.capacity_guest_failed_serving_disposals SET record_sha256=record_sha256 WHERE admission_id=$1`, `DELETE FROM public.capacity_guest_failed_serving_disposals WHERE admission_id=$1`} {
				if _, err := f.db.ExecContext(ctx, statement, q.ID); err == nil {
					t.Fatal("original immutable ledger changed")
				}
			}
			// A foreign policy realm may not create another active quarantine over
			// the same native identity by bypassing the ordinary scope selector.
			r := failedServingClone(t, q)
			r.ID = uuid.NewString()
			r.RecordID = r.ID
			r.Namespace = "another-realm"
			tx, err := f.db.BeginTx(context.Background(), nil)
			if err != nil {
				t.Fatal(err)
			}
			if err = insertFailedServingTx(ctx, tx, r); err == nil {
				err = tx.Commit()
			} else {
				_ = tx.Rollback()
			}
			if err == nil {
				t.Fatal("second active identity admitted in another realm")
			}
		})
	}
}

// Full INSERT refusals keep every production trigger and FK enabled. A forged
// read may be refused by the lineage trigger before CHECK evaluation, so also
// evaluate each ACTUAL catalog CHECK on a baseline-valid row and its missing/
// null variant. SQL FALSE is required: SQL NULL would silently pass a CHECK.
func failedServingNullableIdentityChecks(t *testing.T, f *failedServingFixture, r FailedServingGuestDisposal) {
	t.Helper()
	ctx := failedServingContext(t)
	rows, err := f.db.QueryContext(ctx, `SELECT pg_get_expr(conbin,conrelid) FROM pg_constraint WHERE conrelid='public.capacity_guest_failed_serving_disposals'::regclass AND contype='c'`)
	if err != nil {
		t.Fatal(err)
	}
	expressions := []string{}
	for rows.Next() {
		var expr string
		if err = rows.Scan(&expr); err != nil {
			t.Fatal(err)
		}
		expressions = append(expressions, expr)
	}
	if err = rows.Err(); err != nil {
		t.Fatal(err)
	}
	if err = rows.Close(); err != nil {
		t.Fatal(err)
	}
	baseline := failedServingWire(t, r)
	before, originals := f.rawIntent(t), f.preserved(t)
	for _, key := range []string{"id", "record_id", "stage", "preregistration_id", "namespace", "environment", "domain", "dimension"} {
		expr := ""
		for _, candidate := range expressions {
			if strings.Contains(candidate, "original_record") && strings.Contains(candidate, "'"+key+"'") {
				if expr != "" {
					t.Fatal("ambiguous identity/scope CHECK", key)
				}
				expr = candidate
			}
		}
		if expr == "" {
			t.Fatal("missing native ledger identity/scope CHECK", key)
		}
		// The only interpolated SQL is pg_get_expr output from this newly
		// migrated local database catalog. All fixture values remain parameters.
		checkQuery := `SELECT (` + expr + `) FROM (SELECT $1::jsonb original_record,$2::uuid admission_id,$3::uuid row_id,$4::text stage,$5::uuid preregistration_id,$6::text namespace,$7::text environment,$8::text domain,$9::text dimension) AS candidate`
		evaluate := func(raw []byte) sql.NullBool {
			t.Helper()
			var value sql.NullBool
			if e := f.db.QueryRowContext(ctx, checkQuery, string(raw), r.ID, r.RecordID, r.Stage, r.PreregistrationID, r.Namespace, r.Environment, r.Domain, r.Dimension).Scan(&value); e != nil {
				t.Fatal("native CHECK expression", key, e)
			}
			return value
		}
		if value := evaluate(baseline); !value.Valid || !value.Bool {
			t.Fatal("identity CHECK baseline is not valid", key)
		}
		for _, kind := range []string{"absent", "null"} {
			t.Run(key+"_"+kind, func(t *testing.T) {
				var changed map[string]json.RawMessage
				if json.Unmarshal(baseline, &changed) != nil {
					t.Fatal("baseline raw ledger")
				}
				if kind == "absent" {
					delete(changed, key)
				} else {
					changed[key] = json.RawMessage(`null`)
				}
				raw := failedServingWire(t, changed)
				if value := evaluate(raw); !value.Valid || value.Bool {
					t.Fatal("missing/null JSON identity yields CHECK acceptance or SQL NULL", key, kind)
				}
				tx, e := f.db.BeginTx(ctx, nil)
				if e != nil {
					t.Fatal(e)
				}
				_, e = tx.ExecContext(ctx, `INSERT INTO public.capacity_guest_failed_serving_disposals(row_id,admission_id,stage,namespace,environment,domain,dimension,preregistration_id,original_wire,original_record,record_sha256,recorded_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11,$12)`, r.RecordID, r.ID, r.Stage, r.Namespace, r.Environment, r.Domain, r.Dimension, r.PreregistrationID, raw, string(raw), capacity.BusinessCreationSHA256(raw), r.RecordedAt)
				if e == nil {
					e = tx.Commit()
				} else {
					_ = tx.Rollback()
				}
				if e == nil {
					t.Fatal("missing/null identity or scope committed", key, kind)
				}
				if failedServingCount(t, f) != 1 || !reflect.DeepEqual(f.rawIntent(t), before) || !reflect.DeepEqual(f.preserved(t), originals) {
					t.Fatal("missing/null refusal changed original lineage")
				}
			})
		}
	}
}
