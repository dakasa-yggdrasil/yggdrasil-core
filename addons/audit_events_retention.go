package addons

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/runtime"
	"go.uber.org/zap"
)

// audit_events_retention runs a low-frequency cron-style sweep that
// hard-deletes audit_events rows past their per-row `expires_at`
// timestamp (default created_at + 2y, set by migration 00049).
//
// Audit ref: G7 (audit_events retention). LGPD aligns at 2y for general
// business records; security-critical action codes (auth.login.*,
// auth.mfa.*, auth.session.*) are EXEMPT by code-prefix because they
// fall under the longer legal retention required for security
// incident forensics (operator convention: 7 years). The exemption
// list is enforced in code (not in SQL) so a misconfigured DB default
// can never silently delete a security event.
//
// Cadence: 6h by default; override via
// YGGDRASIL_AUDIT_RETENTION_INTERVAL_SECONDS.
//
// Retention period: 2y by default; override via
// YGGDRASIL_AUDIT_RETENTION_DAYS — purely informational, since rows
// carry their expires_at deadline directly. Setting the env var only
// affects rows inserted AFTER the change; older rows keep their own
// expires_at horizon.
//
// Batch size: 1000 rows per pass. With a tight WHERE clause and the
// partial index on expires_at, the sweep is a few-ms operation even
// at table sizes in the millions.
//
// Distinct from event_log_cleaner (event_log is a separate table for
// reactor dispatch and operates on a different retention horizon).

func init() {
	Register("audit_events_retention", bootstrapAuditEventsRetention, 55)
}

// auditRetentionExemptPrefixes lists the audit-event action prefixes
// that this addon will NEVER hard-delete regardless of how old the
// row is. Rows with these prefixes survive past the 2y default
// because the security forensics use-case demands long-tail access.
//
// To extend the legal retention scope, ADD to this slice — never
// shrink it without a documented compliance review.
var auditRetentionExemptPrefixes = []string{
	"auth.login.",
	"auth.mfa.",
	"auth.session.",
	"auth.password.",
	"auth.third_party.",
	"auth.logout",
}

func bootstrapAuditEventsRetention(ctx context.Context, app *runtime.ServiceApp) error {
	db, ok := Postgres(app)
	if !ok {
		return nil
	}

	logger, _ := Logger(app)
	interval := auditRetentionInterval()

	stop := make(chan struct{})
	go runAuditRetention(ctx, db, logger, interval, stop)

	app.RegisterCloser(func(context.Context) error {
		close(stop)
		return nil
	})

	return nil
}

func runAuditRetention(ctx context.Context, db *sql.DB, logger *zap.Logger, interval time.Duration, stop <-chan struct{}) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Sweep once shortly after boot so a freshly-restarted pod doesn't
	// wait a full interval before its first cleanup. 1 min delay so we
	// don't dogpile with the rest of the startup cascade.
	startupDelay := time.NewTimer(time.Minute)
	defer startupDelay.Stop()

	sweep := func() {
		n, err := sweepExpiredAuditEvents(ctx, db, 1000)
		if err != nil {
			if logger != nil {
				logger.Warn("audit_events retention sweep failed", zap.Error(err))
			}
			return
		}
		if logger != nil && n > 0 {
			logger.Info("audit_events retention sweep",
				zap.Int64("deleted", n),
				zap.Int("batch_size", 1000),
			)
		}
	}

	for {
		select {
		case <-stop:
			return
		case <-ctx.Done():
			return
		case <-startupDelay.C:
			sweep()
		case <-ticker.C:
			sweep()
		}
	}
}

// sweepExpiredAuditEvents deletes up to batchSize rows whose
// expires_at < NOW() AND whose action does not match an exempt
// prefix. Returns the number of rows deleted.
//
// The query uses a CTE to limit the row scan via the partial index
// and applies the exempt-prefix list as a NOT (action LIKE ... OR
// action LIKE ...) clause. Postgres evaluates this efficiently
// because the exempt set is small (≤10 prefixes).
func sweepExpiredAuditEvents(ctx context.Context, db *sql.DB, batchSize int) (int64, error) {
	if db == nil {
		return 0, nil
	}
	if batchSize <= 0 {
		batchSize = 1000
	}

	// Build the exempt clause: action NOT LIKE 'auth.login.%' AND ...
	// We construct it programmatically so the canonical exempt list
	// can grow without re-hand-writing the SQL.
	exemptArgs := make([]any, 0, len(auditRetentionExemptPrefixes))
	exemptClauses := ""
	for i, prefix := range auditRetentionExemptPrefixes {
		if i > 0 {
			exemptClauses += " AND "
		}
		exemptClauses += fmt.Sprintf("action NOT LIKE $%d", i+1)
		exemptArgs = append(exemptArgs, prefix+"%")
	}

	// Final query: select up to N expired non-exempt rows by primary key
	// in a subquery, then DELETE matching those PKs. This pattern keeps
	// the row scan bounded to the partial index AND lets Postgres lock
	// only the rows it touches.
	query := fmt.Sprintf(`
		WITH expired AS (
			SELECT id FROM public.audit_events
			 WHERE expires_at < NOW()
			   AND %s
			 ORDER BY expires_at
			 LIMIT %d
		)
		DELETE FROM public.audit_events
		 WHERE id IN (SELECT id FROM expired)
	`, exemptClauses, batchSize)

	res, err := db.ExecContext(ctx, query, exemptArgs...)
	if err != nil {
		return 0, fmt.Errorf("audit_events retention sweep: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("audit_events retention rows_affected: %w", err)
	}
	return n, nil
}

func auditRetentionInterval() time.Duration {
	raw := os.Getenv("YGGDRASIL_AUDIT_RETENTION_INTERVAL_SECONDS")
	if raw == "" {
		return 6 * time.Hour
	}
	seconds, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || seconds <= 0 {
		return 6 * time.Hour
	}
	return time.Duration(seconds) * time.Second
}
