package addons

import (
	"context"
	"database/sql"
	"os"
	"strconv"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/runtime"
	"go.uber.org/zap"
)

// heimdall_inbox_writer is the addon that copies infra.alert.firing rows
// from event_log into heimdall_inbox under a dedicated cursor. The point
// is to give Heimdall its own queue surface, decoupled from the global
// workflow_event_triggers cursor that other consumers share. Heimdall can
// then take its time to react (retry on failure, throttle, group, etc.)
// without other event consumers either blocking it or skipping past
// alerts on its behalf.
//
// One row per source event_id (UNIQUE constraint at table level), so a
// crash mid-batch followed by a re-run from the same cursor is idempotent.

func init() {
	Register("heimdall_inbox_writer", bootstrapHeimdallInboxWriter, 75)
}

func bootstrapHeimdallInboxWriter(ctx context.Context, app *runtime.ServiceApp) error {
	db, ok := Postgres(app)
	if !ok {
		return nil
	}

	logger, _ := Logger(app)
	interval := heimdallInboxWriterInterval()

	stop := make(chan struct{})
	go runHeimdallInboxWriterLoop(ctx, db, logger, interval, stop)

	app.RegisterCloser(func(context.Context) error {
		close(stop)
		return nil
	})

	return nil
}

func runHeimdallInboxWriterLoop(
	ctx context.Context,
	db *sql.DB,
	logger *zap.Logger,
	interval time.Duration,
	stop <-chan struct{},
) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ctx.Done():
			return
		case <-ticker.C:
			runHeimdallInboxWriterPass(ctx, db, logger)
		}
	}
}

// runHeimdallInboxWriterPass tails event_log for new infra.alert.firing
// rows past the writer's last cursor and inserts them into the inbox.
// Cursor is the event_log sequence column (monotonic bigint) so the
// query is efficient and the cursor advances strictly forward.
func runHeimdallInboxWriterPass(ctx context.Context, db *sql.DB, logger *zap.Logger) {
	var cursor string
	if err := db.QueryRowContext(ctx, `
		SELECT last_cursor FROM public.heimdall_inbox_writer_state
		WHERE id = 'heimdall_inbox_writer_loop'
	`).Scan(&cursor); err != nil && err != sql.ErrNoRows {
		if logger != nil {
			logger.Warn("heimdall_inbox_writer: load cursor failed", zap.Error(err))
		}
		return
	}

	cursorSeq := int64(0)
	if cursor != "" {
		if n, err := strconv.ParseInt(cursor, 10, 64); err == nil {
			cursorSeq = n
		}
	}

	rows, err := db.QueryContext(ctx, `
		SELECT event_id, sequence, aggregate_id, payload
		FROM public.event_log
		WHERE type = 'infra.alert.firing'
		  AND sequence > $1
		ORDER BY sequence ASC
		LIMIT 100
	`, cursorSeq)
	if err != nil {
		if logger != nil {
			logger.Warn("heimdall_inbox_writer: query event_log failed", zap.Error(err))
		}
		return
	}
	defer rows.Close()

	type pendingRow struct {
		eventID, aggID string
		seq            int64
		payload        []byte
	}
	pending := make([]pendingRow, 0, 100)
	for rows.Next() {
		var p pendingRow
		if err := rows.Scan(&p.eventID, &p.seq, &p.aggID, &p.payload); err != nil {
			if logger != nil {
				logger.Warn("heimdall_inbox_writer: scan event_log row failed", zap.Error(err))
			}
			continue
		}
		pending = append(pending, p)
	}
	if err := rows.Err(); err != nil {
		if logger != nil {
			logger.Warn("heimdall_inbox_writer: iterate event_log failed", zap.Error(err))
		}
		return
	}

	if len(pending) == 0 {
		return
	}

	maxSeq := cursorSeq
	for _, p := range pending {
		// ON CONFLICT keeps the table idempotent — re-running this pass
		// from the same cursor (e.g. after a process restart that crashed
		// before commit) does not duplicate rows.
		if _, err := db.ExecContext(ctx, `
			INSERT INTO public.heimdall_inbox (source_event_id, aggregate_id, payload)
			VALUES ($1::uuid, $2, $3::jsonb)
			ON CONFLICT (source_event_id) DO NOTHING
		`, p.eventID, p.aggID, string(p.payload)); err != nil {
			if logger != nil {
				logger.Warn("heimdall_inbox_writer: insert inbox failed",
					zap.String("event_id", p.eventID), zap.Error(err))
			}
			// Don't advance cursor past a failed insert — next pass retries.
			break
		}
		if p.seq > maxSeq {
			maxSeq = p.seq
		}
	}

	if maxSeq > cursorSeq {
		if _, err := db.ExecContext(ctx, `
			UPDATE public.heimdall_inbox_writer_state
			SET last_cursor = $1, updated_at = NOW()
			WHERE id = 'heimdall_inbox_writer_loop'
		`, strconv.FormatInt(maxSeq, 10)); err != nil {
			if logger != nil {
				logger.Warn("heimdall_inbox_writer: advance cursor failed", zap.Error(err))
			}
			return
		}
		if logger != nil {
			logger.Info("heimdall_inbox_writer: advanced",
				zap.Int64("from_seq", cursorSeq),
				zap.Int64("to_seq", maxSeq),
				zap.Int("rows", len(pending)))
		}
	}
}

func heimdallInboxWriterInterval() time.Duration {
	raw := os.Getenv("HEIMDALL_INBOX_WRITER_INTERVAL_SECONDS")
	if raw == "" {
		return 10 * time.Second
	}
	seconds, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || seconds <= 0 {
		return 10 * time.Second
	}
	return time.Duration(seconds) * time.Second
}
