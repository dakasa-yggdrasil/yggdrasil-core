//go:build linux

package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacityhostfactory"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	err := capacityhostfactory.RunOriginalWorker(ctx, os.Args[1:])
	cancel()
	if err != nil {
		// Never format a private underlying error, payload, key or bearer.
		_, _ = fmt.Fprintln(os.Stderr, "host original factory source refused:", capacityhostfactory.RefusalCode(err))
		os.Exit(78)
	}
}
