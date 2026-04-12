package addons

import (
	"context"
	"os"
	"strings"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/runtime"
	"github.com/dakasa-yggdrasil/yggdrasil-core/provisioner"
	"go.uber.org/zap"
)

func init() {
	Register("deployer", bootstrapDeployer, 27)
}

func bootstrapDeployer(_ context.Context, app *runtime.ServiceApp) error {
	logger, _ := Logger(app)
	if logger == nil {
		logger = zap.NewNop()
	}

	repoBasePath := strings.TrimSpace(os.Getenv("REPO_BASE_PATH"))
	if repoBasePath == "" {
		repoBasePath = "/repos"
	}

	info, err := os.Stat(repoBasePath)
	if err != nil || !info.IsDir() {
		logger.Info("kustomize deployer not available (repo path not found)",
			zap.String("repo_base_path", repoBasePath),
		)
		return nil
	}

	d := provisioner.NewKustomizeDeployer(repoBasePath, logger)
	app.SetResource("deployer", d)
	logger.Info("kustomize deployer addon started",
		zap.String("repo_base_path", repoBasePath),
	)
	return nil
}

// Deployer returns the shared KustomizeDeployer when the addon is installed.
func Deployer(app *runtime.ServiceApp) (*provisioner.KustomizeDeployer, bool) {
	resource, ok := app.Resource("deployer")
	if !ok {
		return nil, false
	}
	d, ok := resource.(*provisioner.KustomizeDeployer)
	return d, ok
}
