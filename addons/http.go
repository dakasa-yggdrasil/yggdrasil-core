package addons

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/controllers/httpapi"
	"github.com/dakasa-yggdrasil/yggdrasil-core/controllers/oidc"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/runtime"
	"go.uber.org/zap"
)

func init() {
	Register("http", bootstrapHTTP, 30)
}

func bootstrapHTTP(_ context.Context, app *runtime.ServiceApp) error {
	db, ok := Postgres(app)
	if !ok {
		return fmt.Errorf("postgres addon is not available")
	}

	conn, _ := RabbitMQ(app)
	logger, _ := Logger(app)
	if logger == nil {
		logger = zap.NewNop()
	}

	var opts []httpapi.ServerOption
	if engine, ok := Reconciler(app); ok {
		opts = append(opts, httpapi.WithReconciler(engine))
	}
	if p, ok := Provisioner(app); ok {
		opts = append(opts, httpapi.WithProvisioner(p))
	}
	// OIDC provider mount is opt-in via YGGDRASIL_OIDC_ISSUER. When set,
	// httpapi.New invokes oidc.MountOIDC which registers /.well-known/
	// openid-configuration plus /oidc/* (authorize, token, keys, userinfo,
	// end_session). The issuer URL must match exactly what tokens claim
	// in the `iss` field — terminating in /oidc preserves StripPrefix
	// isolation (Task 7 follow-up commit ba95e2d). Empty/unset keeps
	// the routes dormant for clusters that haven't onboarded OIDC yet.
	//
	// Before mounting, we run oidc.EnsureSigningKey to load-or-create the
	// active RS256 keypair (Task 5 bootstrap). Without an active key,
	// MountOIDC's deriveCryptoKey would fail with "fetch active signing
	// key: oidc signing key not found". The Ensure* call is idempotent
	// across multi-pod startup races via FOR UPDATE on the singleton
	// oidc_provider_settings row.
	if issuer := strings.TrimSpace(os.Getenv("YGGDRASIL_OIDC_ISSUER")); issuer != "" {
		if _, ensureErr := oidc.EnsureSigningKey(context.Background(), db); ensureErr != nil {
			return fmt.Errorf("oidc signing key bootstrap: %w", ensureErr)
		}
		opts = append(opts, httpapi.WithOIDCIssuer(issuer))
		logger.Info("yggdrasil OIDC provider enabled", zap.String("issuer", issuer))
	}
	handler, err := httpapi.New(app.ServiceName, db, conn, logger, opts...)
	if err != nil {
		return fmt.Errorf("build http api: %w", err)
	}

	addr := httpListenAddr()
	server := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: httpDurationFromEnv("HTTP_READ_HEADER_TIMEOUT_SECONDS", 10*time.Second),
		ReadTimeout:       httpDurationFromEnv("HTTP_READ_TIMEOUT_SECONDS", 30*time.Second),
		WriteTimeout:      httpDurationFromEnv("HTTP_WRITE_TIMEOUT_SECONDS", 30*time.Second),
		IdleTimeout:       httpDurationFromEnv("HTTP_IDLE_TIMEOUT_SECONDS", 120*time.Second),
	}

	go func() {
		if serveErr := server.ListenAndServe(); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			logger.Fatal("http server stopped unexpectedly", zap.String("addr", addr), zap.Error(serveErr))
		}
	}()

	logger.Info("http api started", zap.String("addr", addr))

	app.SetResource("http_server", server)
	app.SetResource("http_addr", addr)
	app.RegisterCloser(func(ctx context.Context) error {
		return server.Shutdown(ctx)
	})
	return nil
}

func httpListenAddr() string {
	if raw := strings.TrimSpace(os.Getenv("HTTP_ADDR")); raw != "" {
		return raw
	}

	port := strings.TrimSpace(os.Getenv("PORT"))
	if port == "" {
		port = "9080"
	}
	if strings.HasPrefix(port, ":") {
		return port
	}
	return ":" + port
}

func httpDurationFromEnv(name string, fallback time.Duration) time.Duration {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback
	}
	seconds, err := strconv.Atoi(raw)
	if err != nil || seconds <= 0 {
		return fallback
	}
	return time.Duration(seconds) * time.Second
}
