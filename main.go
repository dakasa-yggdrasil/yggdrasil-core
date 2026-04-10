package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/addons"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/runtime"
	"go.uber.org/zap"
)

func main() {
	serviceName := "yggdrasil-core"
	app := runtime.New(serviceName)

	if err := addons.Apply(context.Background(), app); err != nil {
		panic(err)
	}

	if logger, ok := addons.Logger(app); ok {
		httpAddr, _ := app.Resource("http_addr")
		httpAddrValue, _ := httpAddr.(string)
		logger.Info("yggdrasil-core worker started",
			zap.String("service", serviceName),
			zap.String("http_addr", httpAddrValue),
			zap.String("broker_url", os.Getenv("BROKER_URL")),
			zap.String("db_host", os.Getenv("DB_HOST")),
		)
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_ = app.Shutdown(ctx)
}
