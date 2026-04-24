// Command yggdrasil-operator continuously reconciles control_plane
// manifests against the yggdrasil-deploy-control-plane workflow.
//
// It is the event-driven counterpart to `yggdrasil deploy
// control-plane` — one-shot reconcile at user request vs a
// background loop that picks up every new manifest version and
// dispatches the same workflow. Adopters interact with the catalog
// the same way (yggdrasil apply -f control-plane.yaml); the
// operator closes the loop without requiring them to manually
// invoke the CLI.
//
// Deployment: a single pod (usually inside the same cluster as the
// target control plane, so in-cluster networking reaches both the
// core HTTP API and whatever the deploy workflow targets).
//
// Config (env):
//
//	YGGDRASIL_CORE_URL                  — e.g. http://yggdrasil-core:9080 (required)
//	YGGDRASIL_OPERATOR_TOKEN            — bearer token the operator uses (required if core has auth)
//	YGGDRASIL_OPERATOR_POLL_SECONDS     — poll interval; default 30
//	YGGDRASIL_OPERATOR_KUBERNETES_INSTANCE       — default "yggdrasil-core-kubernetes"
//	YGGDRASIL_OPERATOR_SCHEMA_MIGRATIONS_INSTANCE — default "yggdrasil-core-schema-migrations"
//	YGGDRASIL_OPERATOR_INSTANCE_NAMESPACE        — default "global"
//	OPERATOR_HTTP_PORT                  — health server port; default 8090
package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"go.uber.org/zap"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/operator"
)

func main() {
	logger, err := zap.NewProduction()
	if err != nil {
		fmt.Fprintf(os.Stderr, "logger: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = logger.Sync() }()

	cfg, err := loadConfig()
	if err != nil {
		logger.Fatal("config error", zap.Error(err))
	}

	client := operator.NewClient(cfg.CoreURL, cfg.Token)
	reconciler := operator.New(client, logger, cfg.PollInterval, operator.DispatchOptions{
		KubernetesInstance:       cfg.KubernetesInstance,
		SchemaMigrationsInstance: cfg.SchemaMigrationsInstance,
		InstanceNamespace:        cfg.InstanceNamespace,
	})

	healthSrv := newHealthServer(cfg, client, logger)
	go func() {
		if err := healthSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Fatal("health server", zap.Error(err))
		}
	}()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := reconciler.Run(ctx); err != nil {
		logger.Error("reconciler exited with error", zap.Error(err))
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = healthSrv.Shutdown(shutdownCtx)
}

type config struct {
	CoreURL                  string
	Token                    string
	PollInterval             time.Duration
	KubernetesInstance       string
	SchemaMigrationsInstance string
	InstanceNamespace        string
	HTTPPort                 string
}

func loadConfig() (config, error) {
	cfg := config{
		CoreURL:                  strings.TrimSpace(os.Getenv("YGGDRASIL_CORE_URL")),
		Token:                    strings.TrimSpace(os.Getenv("YGGDRASIL_OPERATOR_TOKEN")),
		KubernetesInstance:       strings.TrimSpace(os.Getenv("YGGDRASIL_OPERATOR_KUBERNETES_INSTANCE")),
		SchemaMigrationsInstance: strings.TrimSpace(os.Getenv("YGGDRASIL_OPERATOR_SCHEMA_MIGRATIONS_INSTANCE")),
		InstanceNamespace:        strings.TrimSpace(os.Getenv("YGGDRASIL_OPERATOR_INSTANCE_NAMESPACE")),
		HTTPPort:                 strings.TrimSpace(os.Getenv("OPERATOR_HTTP_PORT")),
	}
	if cfg.CoreURL == "" {
		return cfg, errors.New("YGGDRASIL_CORE_URL is required")
	}
	if raw := strings.TrimSpace(os.Getenv("YGGDRASIL_OPERATOR_POLL_SECONDS")); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n <= 0 {
			return cfg, fmt.Errorf("YGGDRASIL_OPERATOR_POLL_SECONDS must be a positive integer, got %q", raw)
		}
		cfg.PollInterval = time.Duration(n) * time.Second
	}
	if cfg.HTTPPort == "" {
		cfg.HTTPPort = "8090"
	}
	return cfg, nil
}

// newHealthServer exposes /healthz (process liveness) and /readyz
// (core reachable). /readyz is intentionally strict — if the core
// is down, the operator is of no use, so the pod should drain out
// of any load balancer.
func newHealthServer(cfg config, client *operator.Client, logger *zap.Logger) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		if err := client.Readyz(ctx); err != nil {
			logger.Debug("readyz probe failed", zap.Error(err))
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("core_unavailable"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready"))
	})
	return &http.Server{
		Addr:              ":" + cfg.HTTPPort,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
}
