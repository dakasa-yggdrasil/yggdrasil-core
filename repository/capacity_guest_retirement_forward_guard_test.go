package repository

import (
	"context"
	"errors"
	"regexp"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// This unit boundary proves which real guard query must run. The separate
// owned HTTP fixture executes the no-marker path against its actual schema86.
// Mock rows do not qualify a native profile, ledger or mutation permission.
func TestRetirementForwardSlotGuardRequiresLedgerForMarkers(t *testing.T) {
	for _, name := range []string{"no_marker", "missing_ledger", "malformed_unlinked", "malformed_terminal", "exact_terminal", "active_without_private_scope", "exact_private_scope", "foreign_slot"} {
		t.Run(name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			mock.ExpectBegin()
			tx, err := db.Begin()
			if err != nil {
				t.Fatal(err)
			}
			present := name != "no_marker"
			mock.ExpectQuery(regexp.QuoteMeta("SELECT EXISTS(SELECT 1 FROM public.capacity_intents")).WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(present))
			b := model.CapacityMutationBinding{IntegrationInstanceID: "22222222-2222-4222-8222-222222222222", ScopeChecksum: "scope", ProfileName: "profile"}
			id := "11111111-1111-4111-8111-111111111111"
			ctx := context.Background()
			wantError := present && name != "exact_terminal" && name != "exact_private_scope"
			if present {
				q := mock.ExpectQuery(regexp.QuoteMeta("SELECT f.id::text,f.slot,f.stage,COALESCE")).WithArgs(b.IntegrationInstanceID, b.ScopeChecksum, b.ProfileName)
				if name == "missing_ledger" {
					q.WillReturnError(errors.New("required retirement ledger is missing"))
				} else {
					rows := sqlmock.NewRows([]string{"id", "slot", "stage", "marker_matches"})
					switch name {
					case "malformed_unlinked":
						rows.AddRow(nil, nil, nil, false)
					case "malformed_terminal":
						rows.AddRow(id, 3, "terminal", false)
					case "exact_terminal":
						rows.AddRow(id, 3, "terminal", true)
					default:
						rows.AddRow(id, 3, "admitted", true)
					}
					q.WillReturnRows(rows)
				}
			}
			if name == "exact_private_scope" || name == "foreign_slot" {
				slot := 3
				if name == "foreign_slot" {
					slot = 2
				}
				ctx = context.WithValue(ctx, retirementForwardScopeKey{}, retirementForwardScope{id: id, slot: slot})
			}
			err = guardRetirementForwardSlotTx(ctx, tx, b, 3)
			if (err != nil) != wantError {
				t.Fatal("absent/active/malformed ledger boundary changed", name, err)
			}
			mock.ExpectRollback()
			if err = tx.Rollback(); err != nil {
				t.Fatal(err)
			}
			if err = mock.ExpectationsWereMet(); err != nil {
				t.Fatal("unexpected ledger I/O or ignored required query", err)
			}
		})
	}
}
