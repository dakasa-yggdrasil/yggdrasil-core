//go:build linux && nativequalification

package repository

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

func TestSourceRecoveryCleanupChallengeBindsStepEpoch(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	expiry := now.Add(time.Minute)
	executor := uuid.NewString()
	owner := uuid.NewString()
	policy := model.Manifest{ID: uuid.New(), Checksum: strings.Repeat("a", 64)}
	parent := capacityMutationRecord{Generation: 2, FencingToken: 3, LeaseOwner: uuid.NewString(), ExecutorID: uuid.NewString()}
	current := model.CapacityIntent{PolicyID: policy.ID, PolicyChecksum: policy.Checksum, Phase: "preparing", Generation: 2, FencingToken: 4, LeaseOwner: owner, LeaseExecutorID: executor, LeaseExpiresAt: &expiry, RecoveryOnly: true}
	s := CapacityStore{ExecutorID: executor}
	if err := s.recoveryCleanupChallengeLease(policy, &current, parent, 2, 4, owner, now); err != nil {
		t.Fatal("current recovered step epoch refused")
	}
	for _, tc := range []struct {
		name, predicate string
		target          error
		mutate          func(*CapacityStore, *model.CapacityIntent, *int64, *int64, *string, *time.Time)
	}{
		{"stale_generation", "intent-epoch", ErrCapacityConflict, func(_ *CapacityStore, _ *model.CapacityIntent, g, _ *int64, _ *string, _ *time.Time) { *g = 1 }},
		{"stale_fence", "intent-epoch", ErrCapacityConflict, func(_ *CapacityStore, _ *model.CapacityIntent, _, f *int64, _ *string, _ *time.Time) { *f = 3 }},
		{"foreign_owner", "lease", ErrCapacityLease, func(_ *CapacityStore, _ *model.CapacityIntent, _, _ *int64, o *string, _ *time.Time) {
			*o = uuid.NewString()
		}},
		{"empty_owner", "lease", ErrCapacityLease, func(_ *CapacityStore, _ *model.CapacityIntent, _, _ *int64, o *string, _ *time.Time) { *o = "" }},
		{"foreign_executor", "lease", ErrCapacityLease, func(x *CapacityStore, _ *model.CapacityIntent, _, _ *int64, _ *string, _ *time.Time) {
			x.ExecutorID = uuid.NewString()
		}},
		{"expired_lease", "lease", ErrCapacityLease, func(_ *CapacityStore, _ *model.CapacityIntent, _, _ *int64, _ *string, at *time.Time) { *at = expiry }},
		{"not_recovery", "lease-state", ErrCapacityConflict, func(_ *CapacityStore, c *model.CapacityIntent, _, _ *int64, _ *string, _ *time.Time) {
			c.RecoveryOnly = false
		}},
		{"terminal_phase", "lease-state", ErrCapacityConflict, func(_ *CapacityStore, c *model.CapacityIntent, _, _ *int64, _ *string, _ *time.Time) {
			c.Phase = "aborted"
		}},
		{"original_owner", "intent-parent", ErrCapacityConflict, func(_ *CapacityStore, c *model.CapacityIntent, _, _ *int64, o *string, _ *time.Time) {
			c.LeaseOwner, *o = parent.LeaseOwner, parent.LeaseOwner
		}},
		{"original_fence", "intent-parent", ErrCapacityConflict, func(_ *CapacityStore, c *model.CapacityIntent, _, f *int64, _ *string, _ *time.Time) {
			c.FencingToken, *f = parent.FencingToken, parent.FencingToken
		}},
		{"missing_lease", "intent-parent", ErrCapacityConflict, func(_ *CapacityStore, c *model.CapacityIntent, _, _ *int64, _ *string, _ *time.Time) {
			c.LeaseExpiresAt = nil
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, row, generation, fence, claim, at := s, current, int64(2), int64(4), owner, now
			tc.mutate(&store, &row, &generation, &fence, &claim, &at)
			err := store.recoveryCleanupChallengeLease(policy, &row, parent, generation, fence, claim, at)
			if !errors.Is(err, tc.target) || capacity.GuestQualificationPredicate(err) != "original-recovery-cleanup-"+tc.predicate || strings.Contains(err.Error(), owner) || strings.Contains(err.Error(), executor) {
				t.Fatal("step epoch not bound to the locked recovery lease")
			}
		})
	}
}

func TestSourceRecoveryCleanupChallengeTypesEarlyRefusals(t *testing.T) {
	nonce := strings.Repeat("b", 64)
	refused := func(err error, stage string, target error) bool {
		return errors.Is(err, target) && capacity.GuestQualificationPredicate(err) == "original-recovery-cleanup-"+stage && !strings.Contains(err.Error(), "SECRET")
	}
	if _, err := (CapacityStore{}).PrepareSourceRecoveryCleanupChallenge(context.Background(), model.Manifest{}, uuid.NewString(), "SECRET", 2, 4, uuid.NewString()); !refused(err, "nonce", ErrCapacityDisabled) {
		t.Fatal("invalid nonce not typed")
	}
	if _, err := (CapacityStore{ExecutorID: uuid.NewString()}).PrepareSourceRecoveryCleanupChallenge(context.Background(), model.Manifest{}, uuid.NewString(), nonce, 2, 4, uuid.NewString()); !refused(err, "store", ErrCapacityDisabled) {
		t.Fatal("absent store not typed")
	}
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	begin := errors.New("SECRET begin")
	mock.ExpectBegin().WillReturnError(begin)
	s := CapacityStore{DB: db, ExecutorID: uuid.NewString(), WorkflowID: uuid.New()}
	if _, err = s.PrepareSourceRecoveryCleanupChallenge(context.Background(), model.Manifest{}, uuid.NewString(), nonce, 2, 4, uuid.NewString()); !refused(err, "challenge-tx", begin) {
		t.Fatal("transaction refusal not typed")
	}
	mock.ExpectBegin()
	mock.ExpectRollback()
	if _, err = s.PrepareSourceRecoveryCleanupChallenge(context.Background(), model.Manifest{}, uuid.NewString(), nonce, 2, 4, uuid.NewString()); err == nil || capacity.GuestQualificationPredicate(err) != "original-recovery-cleanup-policy" {
		t.Fatal("policy refusal not typed")
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

// The helper is only meaningful if the store passes the caller's step epoch;
// the locked row's own tuple would make the binding tautological.
func TestSourceRecoveryCleanupChallengePassesStepEpoch(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "source_recovery_cleanup_qualification.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if sel, ok := call.Fun.(*ast.SelectorExpr); !ok || sel.Sel.Name != "recoveryCleanupChallengeLease" {
				return true
			}
			calls++
			if fn.Name.Name != "PrepareSourceRecoveryCleanupChallenge" || len(call.Args) != 7 {
				t.Fatal("recovery cleanup lease bound outside the challenge")
			}
			for i, want := range []string{"generation", "fence", "owner"} {
				if id, ok := call.Args[3+i].(*ast.Ident); !ok || id.Name != want {
					t.Fatalf("challenge lease argument %d is not the caller's step epoch", 3+i)
				}
			}
			return true
		})
	}
	if calls != 1 {
		t.Fatal("challenge lease binding call not unique")
	}
}
