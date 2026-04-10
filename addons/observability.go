package addons

import (
	"context"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/runtime"
	"github.com/dakasa-yggdrasil/yggdrasil-core/monitoring"

	"go.uber.org/zap"
)

func init() {
	Register("observability", bootstrapObservability, 10)
}

func bootstrapObservability(_ context.Context, app *runtime.ServiceApp) error {
	logger := monitoring.NewZapLoggerWithRotation(app.ServiceName)
	monitoring.Logger = logger
	monitoring.SetLogger(logger)

	app.SetResource("logger", logger)
	app.RegisterCloser(func(context.Context) error {
		return logger.Sync()
	})

	return nil
}

// Logger returns the structured logger when the observability addon is installed.
func Logger(app *runtime.ServiceApp) (*zap.Logger, bool) {
	resource, ok := app.Resource("logger")
	if !ok {
		return nil, false
	}

	logger, ok := resource.(*zap.Logger)
	return logger, ok
}
