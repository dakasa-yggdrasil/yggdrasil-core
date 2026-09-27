package addons

import (
	"context"

	"github.com/dakasa-yggdrasil/yggdrasil-core/controllers/httpapi"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/runtime"
)

func init() {
	// Run before Postgres, RabbitMQ consumer registration, first-run seeding,
	// and HTTP construction.
	Register("boot-validation", bootstrapBootValidation, 15)
}

func bootstrapBootValidation(context.Context, *runtime.ServiceApp) error {
	return httpapi.ValidateBootConfiguration()
}
