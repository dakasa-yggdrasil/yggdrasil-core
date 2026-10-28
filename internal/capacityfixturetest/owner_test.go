package capacityfixturetest

import (
	"context"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestOwnerChild(t *testing.T) {
	mode := os.Getenv("CAPACITY_FIXTURE_TEST_CHILD")
	if mode == "" {
		return
	}
	dir := os.Getenv("CAPACITY_FIXTURE_TEST_DIR")
	ch := make(chan os.Signal, 1)
	if mode == "stuck" {
		signal.Ignore(syscall.SIGTERM)
	} else {
		signal.Notify(ch, syscall.SIGTERM)
	}
	if err := os.WriteFile(filepath.Join(dir, "ready"), []byte("ready"), 0o600); err != nil {
		os.Exit(2)
	}
	if mode == "no-receipt" {
		os.Exit(0)
	}
	if mode == "stuck" {
		for {
			time.Sleep(time.Second)
		}
	}
	<-ch
	if err := os.WriteFile(filepath.Join(dir, "cleanup-receipt"), []byte(CleanupReceipt+"\n"), 0o600); err != nil {
		os.Exit(2)
	}
	os.Exit(0)
}

func TestTimeoutTerminatesAndJoinsOwner(t *testing.T) {
	dir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	command := exec.Command(os.Args[0], "-test.run=^TestOwnerChild$")
	command.Env = append(os.Environ(), "CAPACITY_FIXTURE_TEST_CHILD=clean", "CAPACITY_FIXTURE_TEST_DIR="+dir)
	type result struct {
		confirmed bool
		err       error
	}
	done := make(chan result, 1)
	go func() { _, confirmed, err := Run(ctx, command, dir, 3*time.Second); done <- result{confirmed, err} }()
	waitReady(t, dir)
	cancel()
	r := <-done
	if !r.confirmed || r.err == nil || ctx.Err() == nil {
		t.Fatalf("owner was not joined after cleanup: %+v", r)
	}
}

func TestTimeoutPreservesUncertainOwner(t *testing.T) {
	dir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	command := exec.Command(os.Args[0], "-test.run=^TestOwnerChild$")
	command.Env = append(os.Environ(), "CAPACITY_FIXTURE_TEST_CHILD=stuck", "CAPACITY_FIXTURE_TEST_DIR="+dir)
	type result struct {
		confirmed bool
		err       error
	}
	done := make(chan result, 1)
	go func() {
		_, confirmed, err := Run(ctx, command, dir, 200*time.Millisecond)
		done <- result{confirmed, err}
	}()
	waitReady(t, dir)
	cancel()
	r := <-done
	if r.confirmed || r.err == nil {
		t.Fatalf("uncertain cleanup was accepted: %+v", r)
	}
	if _, err := os.Stat(filepath.Join(dir, "ready")); err != nil {
		t.Fatal("uncertain owner directory not preserved", err)
	}
}

func TestExitWithoutCleanupReceiptIsUncertain(t *testing.T) {
	dir := t.TempDir()
	command := exec.Command(os.Args[0], "-test.run=^TestOwnerChild$")
	command.Env = append(os.Environ(), "CAPACITY_FIXTURE_TEST_CHILD=no-receipt", "CAPACITY_FIXTURE_TEST_DIR="+dir)
	_, confirmed, err := Run(context.Background(), command, dir, time.Second)
	if confirmed || err == nil {
		t.Fatal("exit without cleanup receipt was accepted")
	}
}

func waitReady(t *testing.T, dir string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(filepath.Join(dir, "ready")); err == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("child did not become ready")
}
