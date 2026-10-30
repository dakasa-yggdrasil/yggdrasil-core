//go:build linux

package capacityfixturetest

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// This helper is a separate parent process, allowing the outer test to kill
// the parent itself rather than merely cancelling Run's context.
func TestParentDeathHelper(t *testing.T) {
	if os.Getenv("CAPACITY_FIXTURE_PARENT_DEATH_HELPER") != "1" {
		return
	}
	dir := os.Getenv("CAPACITY_FIXTURE_TEST_DIR")
	child := exec.Command(os.Args[0], "-test.run=^TestOwnerChild$")
	child.Env = append(os.Environ(), "CAPACITY_FIXTURE_TEST_CHILD=clean")
	_, _, err := Run(context.Background(), child, dir, 3*time.Second)
	if err != nil {
		os.Exit(2)
	}
}

func TestOwnerReceivesSignalOnParentDeath(t *testing.T) {
	dir := t.TempDir()
	parent := exec.Command(os.Args[0], "-test.run=^TestParentDeathHelper$")
	parent.Env = append(os.Environ(), "CAPACITY_FIXTURE_PARENT_DEATH_HELPER=1", "CAPACITY_FIXTURE_TEST_DIR="+dir)
	if err := parent.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = parent.Process.Kill(); _ = parent.Wait() }()
	waitReady(t, dir) // Owner installed its signal handler before writing ready.
	if _, err := os.Stat(filepath.Join(dir, "cleanup-receipt")); err == nil {
		t.Fatal("owner terminated before the parent was killed")
	} else if !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if err := parent.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = parent.Wait()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(filepath.Join(dir, "cleanup-receipt"))
		if err == nil && string(data) == CleanupReceipt+"\n" {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("owner did not report cleanup after its parent was killed")
}
