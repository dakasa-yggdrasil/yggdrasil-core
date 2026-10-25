package addons

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/controllers/httpapi"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/goroutine"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/runtime"
	manifestengine "github.com/dakasa-yggdrasil/yggdrasil-core/manifest"
)

const capacityDispatchServiceResource = "capacity_dispatch_private_service"

type capacitySchedulerServiceKey struct{}

func withCapacitySchedulerService(ctx context.Context, service *httpapi.CapacityDispatchService) context.Context {
	return context.WithValue(ctx, capacitySchedulerServiceKey{}, service)
}

func capacitySchedulerService(ctx context.Context) *httpapi.CapacityDispatchService {
	service, _ := ctx.Value(capacitySchedulerServiceKey{}).(*httpapi.CapacityDispatchService)
	return service
}

func init() { Register("capacity_dispatch", bootstrapCapacityDispatch, 65) }

func bootstrapCapacityDispatch(parent context.Context, app *runtime.ServiceApp) error {
	enabled, err := httpapi.CapacityDispatchProcessEnabled()
	if err != nil || !enabled {
		return err
	}
	resource, ok := app.Resource(capacityDispatchServiceResource)
	service, valid := resource.(*httpapi.CapacityDispatchService)
	if !ok || !valid || service == nil {
		return fmt.Errorf("capacity dispatch owning HTTP service unavailable")
	}
	ctx, cancel := context.WithCancel(parent)
	returned := make(chan struct{})
	logger, _ := Logger(app)
	goroutine.SafeGo("capacity_dispatch_worker", func() {
		defer close(returned)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := service.RunPass(ctx); err != nil && logger != nil {
					// Opaque category only; original causes remain private.
					logger.Warn("protected capacity dispatch remains unresolved")
				}
			}
		}
	})
	app.RegisterCloser(func(owner context.Context) error {
		cancel()
		// Stop/cancellation cannot impersonate an original worker return.
		<-returned
		return owner.Err()
	})
	return nil
}

// An absent private owner cannot route a capacity graph or configured policy
// into the legacy dispatcher. This read is a routing refusal, never authorization or a
// capacity observation; the real service remains the sole admission owner.
func capacityScheduleRequiresOwner(ctx context.Context, db *sql.DB, manifestID string) (bool, error) {
	var bound bool
	var raw []byte
	err := db.QueryRowContext(ctx, `SELECT w.spec, EXISTS (
        SELECT 1 FROM
        (SELECT DISTINCT ON(namespace,name) spec FROM public.manifests WHERE kind='capacity_policy' ORDER BY namespace,name,version DESC,id) p
        WHERE p.spec->'workflow'->>'namespace'=w.namespace AND p.spec->'workflow'->>'name'=w.name
        AND p.spec->'controller_binding' IS NOT NULL AND p.spec->'controller_binding' <> 'null'::jsonb
    ) FROM public.manifests w WHERE w.id=$1 AND w.kind='workflow'`, manifestID).Scan(&raw, &bound)
	if err != nil {
		return false, fmt.Errorf("capacity dispatch owner lookup unresolved")
	}
	spec, err := manifestengine.ParseWorkflowSpec(raw)
	if err != nil {
		return false, fmt.Errorf("capacity dispatch owner lookup unresolved")
	}
	return bound || httpapi.CapacityScheduleGraphRequiresOwner(spec), nil
}
