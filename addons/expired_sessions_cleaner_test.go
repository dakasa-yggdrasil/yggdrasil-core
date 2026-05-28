package addons

import (
	"context"
	"regexp"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
)

// TestCleanupExpiredSessions_TransitionsRowsToExpired verifies the
// cleanup query flips active-but-expired rows to status=expired.
//
// Audit ref: C5 (no expired-sessions cleanup addon in registry).
func TestCleanupExpiredSessions_TransitionsRowsToExpired(t *testing.T) {
	t.Parallel()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	mock.ExpectExec(regexp.QuoteMeta(`
		UPDATE public.auth_sessions
		SET status = 'expired', updated_at = NOW()
		WHERE status = 'active'
		  AND expires_at < NOW()
	`)).WillReturnResult(sqlmock.NewResult(0, 7))

	n, err := cleanupExpiredSessions(context.Background(), db)
	if err != nil {
		t.Fatalf("cleanupExpiredSessions: %v", err)
	}
	if n != 7 {
		t.Fatalf("expected 7 rows expired, got %d", n)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

// TestExpiredSessionsCleanerInterval_DefaultsTo30Min verifies the
// default cadence when the env knob is unset.
func TestExpiredSessionsCleanerInterval_DefaultsTo30Min(t *testing.T) {
	t.Setenv("EXPIRED_SESSIONS_CLEANER_INTERVAL_SECONDS", "")
	if got := expiredSessionsCleanerInterval(); got != 30*time.Minute {
		t.Fatalf("expected 30m default, got %v", got)
	}
}

// TestExpiredSessionsCleanerInterval_HonorsEnv verifies a custom
// interval is parsed and applied.
func TestExpiredSessionsCleanerInterval_HonorsEnv(t *testing.T) {
	t.Setenv("EXPIRED_SESSIONS_CLEANER_INTERVAL_SECONDS", "600")
	if got := expiredSessionsCleanerInterval(); got != 10*time.Minute {
		t.Fatalf("expected 10m, got %v", got)
	}
}
