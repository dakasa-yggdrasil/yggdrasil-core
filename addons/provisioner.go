package addons

import (
	"context"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/runtime"
	"github.com/dakasa-yggdrasil/yggdrasil-core/provisioner"
	"go.uber.org/zap"
)

func init() {
	Register("provisioner", bootstrapProvisioner, 26)
}

func bootstrapProvisioner(ctx context.Context, app *runtime.ServiceApp) error {
	db, ok := Postgres(app)
	if !ok {
		return nil // provisioner is optional if postgres is not available
	}

	logger, _ := Logger(app)
	if logger == nil {
		logger = zap.NewNop()
	}

	p, err := provisioner.NewAWSProvisioner(ctx, db, logger)
	if err != nil {
		// Non-fatal: yggdrasil still works, just no AWS provisioning.
		logger.Warn("aws provisioner not available (non-fatal)", zap.Error(err))
		return nil
	}

	app.SetResource("provisioner", p)
	logger.Info("aws provisioner addon started")
	return nil
}

// Provisioner returns the shared AWSProvisioner when the addon is installed.
func Provisioner(app *runtime.ServiceApp) (*provisioner.AWSProvisioner, bool) {
	resource, ok := app.Resource("provisioner")
	if !ok {
		return nil, false
	}
	p, ok := resource.(*provisioner.AWSProvisioner)
	return p, ok
}
