package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/nativeworkerprobe"
)

func main() {
	if len(os.Args) != 1 {
		fmt.Fprintln(os.Stderr, "native worker diagnostic unavailable")
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if nativeworkerprobe.Run(ctx) != nil {
		fmt.Fprintln(os.Stderr, "native worker diagnostic unavailable")
		os.Exit(1)
	}
}
