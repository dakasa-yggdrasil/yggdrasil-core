package addons

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/bootstrap"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/runtime"
	"go.uber.org/zap"
)

// First-run bootstrap env vars. When YGGDRASIL_BOOTSTRAP_ADMIN_USERNAME
// is set on a fresh database, the server provisions the first admin and
// optionally seeds the baseline catalog — enabling `yggdrasil init`
// style one-command onboarding. All variables are opt-in; a production
// deployment that already has an admin simply leaves them unset.
const (
	envBootstrapAdminUsername    = "YGGDRASIL_BOOTSTRAP_ADMIN_USERNAME"
	envBootstrapAdminPassword    = "YGGDRASIL_BOOTSTRAP_ADMIN_PASSWORD"
	envBootstrapAdminEmail       = "YGGDRASIL_BOOTSTRAP_ADMIN_EMAIL"
	envBootstrapAdminDisplayName = "YGGDRASIL_BOOTSTRAP_ADMIN_DISPLAY_NAME"
	envBootstrapManifestsPath    = "YGGDRASIL_BOOTSTRAP_MANIFESTS_PATH"
)

func init() {
	// Priority 30: after postgres (20) — we need the DB handle — but
	// before HTTP (higher priority) so the API starts already seeded.
	// A boot that fails here is intentional: we refuse to serve in a
	// half-configured state.
	Register("first_run_bootstrap", bootstrapFirstRun, 30)
}

// bootstrapFirstRun inspects env vars and the DB state and, when both
// say "fresh install", provisions the admin + seeds. It is a no-op on
// existing deployments (no envvars set, OR envvars set but DB has
// collaborators already). The combined gate (envvar AND empty DB) is
// what makes leaving the env vars permanently set safe — restarting a
// running service does not accidentally re-create anything.
func bootstrapFirstRun(ctx context.Context, app *runtime.ServiceApp) error {
	adminUsername := strings.TrimSpace(os.Getenv(envBootstrapAdminUsername))
	manifestsPath := strings.TrimSpace(os.Getenv(envBootstrapManifestsPath))

	if adminUsername == "" && manifestsPath == "" {
		// Nothing requested; early-exit so the addon costs zero on
		// production startups that do not rely on first-run bootstrap.
		return nil
	}

	db, ok := Postgres(app)
	if !ok {
		return fmt.Errorf("first_run_bootstrap requires postgres addon (priority 20 must run first)")
	}

	cfg := bootstrap.Config{
		AdminUsername:    adminUsername,
		AdminDisplayName: strings.TrimSpace(os.Getenv(envBootstrapAdminDisplayName)),
		AdminEmail:       strings.TrimSpace(os.Getenv(envBootstrapAdminEmail)),
		AdminPassword:    os.Getenv(envBootstrapAdminPassword),
		ManifestsPath:    manifestsPath,
	}

	result, err := bootstrap.Run(ctx, db, cfg)
	if err != nil {
		return fmt.Errorf("first-run bootstrap: %w", err)
	}

	logger, hasLogger := Logger(app)
	if !hasLogger {
		return nil
	}

	if result.AdminCreated && result.AdminCollaborator != nil {
		// Print the admin slug at INFO so operators running `yggdrasil
		// init` can see it in logs. The password is deliberately NOT
		// logged — it was provided via env var and the operator already
		// has it.
		logger.Info("bootstrap: first admin created",
			zap.String("slug", result.AdminCollaborator.Slug),
			zap.String("collaborator_id", result.AdminCollaborator.ID.String()),
		)
	}
	if result.ManifestsValidated > 0 {
		logger.Info("bootstrap: manifests seeded",
			zap.Int("validated", result.ManifestsValidated),
			zap.Int("created", result.ManifestsCreated),
			zap.Int("skipped", result.ManifestsSkipped),
			zap.String("path", cfg.ManifestsPath),
		)
	}

	return nil
}
