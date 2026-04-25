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
