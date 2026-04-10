package addons

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/runtime"
	"github.com/dakasa-yggdrasil/yggdrasil-core/psql"
)

func init() {
	Register("postgres", bootstrapPostgres, 20)
}

func bootstrapPostgres(ctx context.Context, app *runtime.ServiceApp) error {
	db, err := psql.Open()
	if err != nil {
		return fmt.Errorf("open postgres: %w", err)
	}

	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	if err := db.PingContext(pingCtx); err != nil {
		_ = db.Close()
		return fmt.Errorf("ping postgres: %w", err)
	}

	app.SetResource("postgres", db)
	app.RegisterCloser(func(context.Context) error { return db.Close() })
	return nil
}

// Postgres returns the shared SQL handle when the addon is installed.
func Postgres(app *runtime.ServiceApp) (*sql.DB, bool) {
	resource, ok := app.Resource("postgres")
	if !ok {
		return nil, false
	}

	db, ok := resource.(*sql.DB)
	return db, ok
}
