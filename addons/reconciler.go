package addons

import (
	"context"
	"os"
	"strings"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/runtime"
	"github.com/dakasa-yggdrasil/yggdrasil-core/reconciler"
	"go.uber.org/zap"
)

func init() {
	Register("reconciler", bootstrapReconciler, 25)
}

func bootstrapReconciler(ctx context.Context, app *runtime.ServiceApp) error {
	db, ok := Postgres(app)
	if !ok {
		return nil // reconciler is optional if postgres is not available
	}

	logger, _ := Logger(app)
	if logger == nil {
		logger = zap.NewNop()
	}

	enabled := strings.ToLower(os.Getenv("RECONCILE_ENABLED"))
	if enabled == "false" || enabled == "0" {
		logger.Info("reconciler disabled via RECONCILE_ENABLED")
		return nil
	}

	inCluster := strings.ToLower(os.Getenv("KUBE_IN_CLUSTER")) != "false"

	pool, err := reconciler.NewKubeClientPool(db, logger, inCluster)
	if err != nil {
		logger.Warn("reconciler: kube client pool failed, running without reconciler", zap.Error(err))
		return nil // non-fatal — yggdrasil still works, just no materialization
	}

	engine := reconciler.NewEngine(pool, db, logger,
		&reconciler.SecretMaterializer{},
		&reconciler.ManifestMaterializer{},
		&reconciler.ProductMaterializer{},
	)

	loopCtx, cancelLoop := context.WithCancel(context.Background())
	go engine.Run(loopCtx)

	app.SetResource("reconciler", engine)
	app.RegisterCloser(func(context.Context) error {
		cancelLoop()
		return nil
	})

	logger.Info("reconciler addon started")
	return nil
}

// Reconciler returns the shared engine when the addon is installed.
func Reconciler(app *runtime.ServiceApp) (*reconciler.Engine, bool) {
	resource, ok := app.Resource("reconciler")
	if !ok {
		return nil, false
	}
	engine, ok := resource.(*reconciler.Engine)
	return engine, ok
}
