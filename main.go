package main

import (
	"context"
	"errors"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/addons"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/coreprocess"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/runtime"
	"go.uber.org/zap"
)

func main() {
	serviceName := "yggdrasil-core"
	app := runtime.New(serviceName)
	role, err := coreprocess.FromEnvironment()
	if err != nil {
		panic(err)
	}
	if err := coreprocess.ValidateExecutable(role, os.Args[0]); err != nil {
		panic(err)
	}
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(stop)
	startup, cancelStartup := context.WithCancel(context.Background())
	defer cancelStartup()
	var lifetime *coreprocess.Lifetime
	if role == coreprocess.APIWorker {
		lifetime, err = coreprocess.NewLifetime()
		if err != nil {
			panic(err)
		}
		app.SetResource(coreprocess.LifetimeResource, lifetime)
		if err := lifetime.Start("signal", func() error {
			select {
			case <-stop:
				lifetime.BeginDrain()
				cancelStartup()
				return nil
			case <-lifetime.Failed():
				cancelStartup()
				return errors.New("API worker failed before original signal return")
			}
		}); err != nil {
			panic(err)
		}
	}

	if err := addons.Apply(context.Background(), app); err != nil {
		panic(err)
	}
	if lifetime != nil {
		if err := openWorkerAdmission(startup, app, lifetime); err != nil && startup.Err() == nil {
			lifetime.Fail()
		}
	}

	if logger, ok := addons.Logger(app); ok {
		httpAddr, _ := app.Resource("http_addr")
		httpAddrValue, _ := httpAddr.(string)
		logStartup(logger, serviceName, httpAddrValue)
	}

	if lifetime == nil {
		<-stop
	} else {
		<-startup.Done()
	}

	ctx, cancel := context.WithTimeout(context.Background(), coreprocess.ShutdownBudget(role))
	defer cancel()

	shutdownErr := app.Shutdown(ctx)
	if shutdownErr == nil && lifetime != nil {
		lifetime.DependenciesShutdownReturned()
		shutdownErr = lifetime.WriteJoinedReceipt(ctx)
	}
	if shutdownErr != nil {
		if logger, ok := addons.Logger(app); ok {
			logger.Error("core shutdown did not complete")
		}
		os.Exit(1)
	}
}

func openWorkerAdmission(ctx context.Context, app *runtime.ServiceApp, lifetime *coreprocess.Lifetime) error {
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		if conn, ok := addons.RabbitMQ(app); ok && conn != nil && !conn.IsClosed() {
			return lifetime.Open(ctx)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-lifetime.Failed():
			return errors.New("API worker startup failed")
		case <-tick.C:
		}
	}
}

func logStartup(logger *zap.Logger, service, httpAddr string) {
	logger.Info("yggdrasil-core worker started",
		zap.String("service", service),
		zap.String("http_addr", httpAddr),
		zap.Bool("broker_configured", os.Getenv("BROKER_URL") != ""),
		zap.String("db_host", os.Getenv("DB_HOST")),
	)
}
