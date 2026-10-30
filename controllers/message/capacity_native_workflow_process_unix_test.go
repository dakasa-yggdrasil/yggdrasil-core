//go:build (linux || darwin) && (!recoveryfixture || nativequalification)

package message

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"
)

// The Go launcher and its test binary stay in a private process group. A
// timeout kills that whole group before the database owner reaps its database.
func nativeFixtureConfigureProcess(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.WaitDelay = 3 * time.Second
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return os.ErrProcessDone
		}
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
}

func nativeFixtureJoinProcessGroup(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return nil
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		err := syscall.Kill(-cmd.Process.Pid, 0)
		if errors.Is(err, syscall.ESRCH) {
			return nil
		}
		if (err != nil && !errors.Is(err, syscall.EPERM)) || time.Now().After(deadline) {
			return errors.New("synthetic child group did not join")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestNativeFixtureProcessTimeoutKillsGroup(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", "sleep 60 & wait")
	nativeFixtureConfigureProcess(cmd)
	if err := cmd.Run(); err == nil || ctx.Err() == nil {
		t.Fatal("expired child did not fail")
	}
	if err := nativeFixtureJoinProcessGroup(cmd); err != nil {
		t.Fatal(err)
	}
}
