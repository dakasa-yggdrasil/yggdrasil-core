// Package capacityfixturetest supervises the isolated PostgreSQL test owner.
// It is used only by source-qualification tests, not by production runtime.
package capacityfixturetest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

const CleanupReceipt = "owner-cleaned-v1"

// Run sends TERM before escalation and only reports cleanup after both process
// join and the owner's private cleanup receipt. When termination is uncertain,
// callers must preserve the owner directory and report its path.
func Run(ctx context.Context, command *exec.Cmd, ownerDir string, grace time.Duration) (stdout string, cleanupConfirmed bool, err error) {
	var out, diagnostics bytes.Buffer
	command.Stdout, command.Stderr = &out, &diagnostics
	command.WaitDelay = 2 * time.Second
	configureParentDeath(command)
	if err = command.Start(); err != nil {
		return "", false, err
	}
	wait := make(chan error, 1)
	go func() { wait <- command.Wait() }()
	var processErr error
	timedOut := false
	select {
	case processErr = <-wait:
	case <-ctx.Done():
		timedOut = true
		if signalErr := command.Process.Signal(syscall.SIGTERM); signalErr != nil && !errors.Is(signalErr, os.ErrProcessDone) {
			return "", false, fmt.Errorf("owner termination signal failed: %w", signalErr)
		}
		timer := time.NewTimer(grace)
		defer timer.Stop()
		select {
		case processErr = <-wait:
		case <-timer.C:
			_ = command.Process.Kill()
			select {
			case <-wait:
			case <-time.After(3 * time.Second):
			}
			return "", false, errors.New("owner did not join after interruption; cleanup uncertain")
		}
	}
	if errors.Is(processErr, exec.ErrWaitDelay) {
		return "", false, errors.New("owner descendants did not close; cleanup uncertain")
	}
	receipt, readErr := os.ReadFile(filepath.Join(ownerDir, "cleanup-receipt"))
	if readErr != nil || string(receipt) != CleanupReceipt+"\n" {
		return "", false, errors.New("owner cleanup receipt unavailable; cleanup uncertain")
	}
	if timedOut {
		return out.String(), true, fmt.Errorf("owner timed out after confirmed cleanup: %w", ctx.Err())
	}
	if processErr != nil {
		return out.String(), true, fmt.Errorf("owner failed after confirmed cleanup: %w; diagnostic=%q", processErr, diagnostics.String())
	}
	return out.String(), true, nil
}
