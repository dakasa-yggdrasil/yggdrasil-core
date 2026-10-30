//go:build linux && nativequalification

package capacitynativeqemu

import (
	"context"
	"os/exec"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"golang.org/x/sys/unix"
)

// This records actual kernel process/pidfd behavior, not a Guest VM or a
// retirement result. The original child is waited on once by its owner.
func TestOriginalPIDFDExitedAfterOriginalWait(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, "sh", "-c", "read ignored")
	in, err := child.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = child.Start(); err != nil {
		t.Fatal(err)
	}
	joined := false
	defer func() {
		if !joined {
			_ = child.Process.Kill()
			_ = child.Wait()
		}
	}()
	fd, err := unix.PidfdOpen(child.Process.Pid, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	if n, e := unix.Poll(poll, 0); e != nil || n != 0 || poll[0].Revents != 0 {
		t.Fatal("live original pidfd unexpectedly ready", n, e, poll[0].Revents)
	}
	if _, err = in.Write([]byte("x\n")); err != nil {
		t.Fatal(err)
	}
	if err = in.Close(); err != nil {
		t.Fatal(err)
	}
	err = child.Wait()
	joined = true
	if err != nil {
		t.Fatal("original Wait did not succeed", err)
	}

	n, err := unix.Poll(poll, 1000)
	if err != nil || n != 1 || !repository.GuestNativeQEMUPIDFDExited(poll[0].Revents) {
		t.Fatal("reaped original pidfd event not accepted", n, err, poll[0].Revents)
	}
	t.Logf("original reaped pidfd revents=%d", poll[0].Revents)
}
