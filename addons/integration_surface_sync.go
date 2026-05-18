package addons

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	messagecontroller "github.com/dakasa-yggdrasil/yggdrasil-core/controllers/message"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/integrationsurfaces"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/runtime"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	amqp "github.com/rabbitmq/amqp091-go"
)

func init() {
	// Priority 25 — runs after postgres (20) and rabbitmq (20) but BEFORE
	// http (30) so the HTTP server can read the repo + dispatcher out of
	// app resources at construction time.
	Register("integration_surface_sync", bootstrapIntegrationSurfaceSync, 25)
}

// emitterFromDB wraps repository.EmitEvent in a transaction for use by the
// integrationsurfaces syncer. It validates against the JSON Schema (via
// repository.EmitEvent's contract check) and commits on success.
type emitterFromDB struct {
	db *sql.DB
}

func (e *emitterFromDB) Emit(ctx context.Context, eventType, aggregateID string, payload map[string]any) error {
	tx, err := e.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Aggregate type is the prefix before the first dot ("integration_surface").
	aggType := eventType
	if idx := strings.IndexByte(eventType, '.'); idx >= 0 {
		aggType = eventType[:idx]
	}

	if _, err := repository.EmitEvent(ctx, tx, model.EmitEventRequest{
		Type:          eventType,
		AggregateType: aggType,
		AggregateID:   aggregateID,
		Payload:       payload,
	}); err != nil {
		return fmt.Errorf("emit %q: %w", eventType, err)
	}
	return tx.Commit()
}

// surfaceQueryDispatcher is the production implementation of
// httpapi.SurfaceQueryDispatcher. It forwards the request to
// messagecontroller.ExecuteIntegration (the synchronous adapter-execute
// path) and returns the Output verbatim.
type surfaceQueryDispatcher struct {
	conn *amqp.Connection
	db   *sql.DB
}

func newSurfaceQueryDispatcher(conn *amqp.Connection, db *sql.DB) *surfaceQueryDispatcher {
	return &surfaceQueryDispatcher{conn: conn, db: db}
}

func (d *surfaceQueryDispatcher) Execute(ctx context.Context, req model.ExecuteIntegrationRequest) (any, error) {
	if d.conn == nil {
		return nil, fmt.Errorf("rabbitmq connection unavailable")
	}
	resp, err := messagecontroller.ExecuteIntegration(ctx, d.conn, d.db, req)
	if err != nil {
		return nil, err
	}
	return resp.Output, nil
}

func bootstrapIntegrationSurfaceSync(_ context.Context, app *runtime.ServiceApp) error {
	db, ok := Postgres(app)
	if !ok {
		// Postgres not installed — skip silently (consistent with manifest-sync addon).
		return nil
	}

	repo := integrationsurfaces.NewRepository(db)
	emitter := &emitterFromDB{db: db}
	syncer := integrationsurfaces.NewSyncer(repo, emitter)

	// Stash for the HTTP addon (priority 30) to pick up.
	app.SetResource("integration_surfaces_repo", repo)
	app.SetResource("integration_surfaces_syncer", syncer)
	app.SetResource("integration_surfaces_emitter", emitter)

	// Dispatcher is only useful when rabbitmq is up; surface-query handler
	// returns 503 if the resource isn't there.
	if conn, ok := RabbitMQ(app); ok {
		app.SetResource("integration_surface_query_dispatcher", newSurfaceQueryDispatcher(conn, db))
	}
	return nil
}
