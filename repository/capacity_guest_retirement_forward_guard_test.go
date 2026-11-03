package repository

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
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

// Callback scope is reconstructed from retained server-owned rows, never a
// caller flag. Actual positive and foreign-grant cases run in the PG corpus.
func TestRetirementForwardCallbackRequiresExactMarkerLedger(t *testing.T) {
	for _, name := range []string{"no_marker", "intent_read_failed", "malformed_intent", "null_marker", "malformed_marker", "requested_marker", "foreign_namespace", "foreign_epoch", "wrong_capability", "compensation", "missing_ledger", "caller_scope_without_ledger", "terminal_history"} {
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
			p := model.CapacityPolicySpec{Environment: "production", Domain: "notify", Dimension: "tail"}
			policy := uuid.MustParse("11111111-1111-4111-8111-111111111111")
			record := capacityMutationRecord{PolicyID: policy, PolicyChecksum: "checksum", Generation: 14, FencingToken: 28, LeaseOwner: "owner", ExecutorID: "executor", Binding: model.CapacityMutationBinding{DestroyCapability: "destroy_vm"}, Grant: model.CapacityMutationGrant{Capability: "destroy_vm", Slot: 3}}
			current := model.CapacityIntent{Namespace: "namespace", Environment: p.Environment, Domain: p.Domain, Dimension: p.Dimension, PolicyID: policy, PolicyChecksum: record.PolicyChecksum, Generation: record.Generation, FencingToken: record.FencingToken, LeaseOwner: record.LeaseOwner, LeaseExecutorID: record.ExecutorID, Phase: "drained", RetirementForward: &model.CapacityGuestRetirementForwardMarker{ID: policy.String(), Stage: "off_qualified"}}
			switch name {
			case "null_marker":
				current.RetirementForward = nil
			case "malformed_marker":
				current.RetirementForward = &model.CapacityGuestRetirementForwardMarker{}
			case "requested_marker":
				current.RetirementForward.Stage = "requested"
			case "foreign_namespace":
				current.Namespace = "foreign"
			case "foreign_epoch":
				current.FencingToken++
			case "wrong_capability":
				record.Grant.Capability = "ensure_vm"
			case "compensation":
				record.Grant.CompensationOf = policy.String()
			case "terminal_history":
				current.RetirementForward.Stage = "terminal"
			}
			raw, err := json.Marshal(current)
			if err != nil {
				t.Fatal(err)
			}
			if name == "malformed_intent" {
				raw = []byte(`{"retirement_forward":`)
			}
			q := mock.ExpectQuery(regexp.QuoteMeta("SELECT intent FROM public.capacity_intents WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4 AND intent ? 'retirement_forward'")).WithArgs("namespace", p.Environment, p.Domain, p.Dimension)
			switch name {
			case "no_marker":
				q.WillReturnRows(sqlmock.NewRows([]string{"intent"}))
			case "intent_read_failed":
				q.WillReturnError(errors.New("required intent table is unavailable"))
			default:
				q.WillReturnRows(sqlmock.NewRows([]string{"intent"}).AddRow(raw))
			}
			if name == "missing_ledger" || name == "caller_scope_without_ledger" {
				mock.ExpectQuery(regexp.QuoteMeta("SELECT original_wire,record_sha256,original_record=convert_from(original_wire,'UTF8')::jsonb FROM public.capacity_guest_retirement_forwards")).WithArgs(policy.String(), "off_qualified").WillReturnError(errors.New("required forward ledger is unavailable"))
			}
			ctx := context.Background()
			if name == "caller_scope_without_ledger" {
				ctx = context.WithValue(ctx, retirementForwardScopeKey{}, retirementForwardScope{id: policy.String(), slot: 3})
			}
			actual, err := retirementForwardCallbackContextTx(ctx, tx, record, "namespace", p)
			wantError := name != "no_marker" && name != "terminal_history"
			if (err != nil) != wantError || !wantError && actual != ctx {
				t.Fatal("callback cannot invent marker/ledger custody", name, err)
			}
			mock.ExpectRollback()
			if err = tx.Rollback(); err != nil {
				t.Fatal(err)
			}
			if err = mock.ExpectationsWereMet(); err != nil {
				t.Fatal("unexpected ledger/write I/O or ignored required read", err)
			}
		})
	}
}
