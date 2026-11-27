//go:build linux

package capacity

import (
	"bytes"
	"context"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func nativePrivateOpenFile(path string, private bool) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errNativePrivateFactory
	}
	fd, e := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, errNativePrivateFactory
	}
	f := os.NewFile(uintptr(fd), "private-native-source")
	st, e := f.Stat()
	if e != nil {
		f.Close()
		return nil, errNativePrivateFactory
	}
	s, ok := st.Sys().(*syscall.Stat_t)
	if !ok || !st.Mode().IsRegular() || st.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || s.Nlink != 1 || s.Uid != 0 && s.Uid != uint32(os.Geteuid()) || st.Mode().Perm()&0022 != 0 || private && st.Mode().Perm()&0077 != 0 {
		f.Close()
		return nil, errNativePrivateFactory
	}
	return f, nil
}

func nativePrivateStable(a, b os.FileInfo) bool {
	return os.SameFile(a, b) && a.Size() == b.Size() && a.ModTime() == b.ModTime() && a.Mode() == b.Mode()
}

func nativePrivateReadFile(path string, limit int64, private bool) ([]byte, error) {
	f, e := nativePrivateOpenFile(path, private)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	a, e := f.Stat()
	if e != nil || a.Size() < 1 || a.Size() > limit {
		return nil, errNativePrivateFactory
	}
	raw, e := io.ReadAll(io.LimitReader(f, limit+1))
	b, se := f.Stat()
	if e != nil || se != nil || int64(len(raw)) != a.Size() || int64(len(raw)) > limit || !nativePrivateStable(a, b) {
		nativePrivateWipe(raw)
		return nil, errNativePrivateFactory
	}
	return raw, nil
}

func nativePrivateOpenExecutable(c NativeWorkerPrivateFactoryConfig) (*os.File, error) {
	f, e := nativePrivateOpenFile(c.CLIFile, false)
	if e != nil {
		return nil, e
	}
	ok := false
	defer func() {
		if !ok {
			f.Close()
		}
	}()
	if nativePrivateVerifyExecutable(f, c) != nil {
		return nil, errNativePrivateFactory
	}
	ok = true
	return f, nil
}

func nativePrivateVerifyExecutable(f *os.File, c NativeWorkerPrivateFactoryConfig) error {
	if f == nil {
		return errNativePrivateFactory
	}
	before, e := f.Stat()
	if e != nil || before.Size() != c.CLIBytes || before.Mode().Perm()&0111 == 0 {
		return errNativePrivateFactory
	}
	h := sha256.New()
	n, e := io.Copy(h, io.NewSectionReader(f, 0, c.CLIBytes+1))
	if e != nil || n != c.CLIBytes || hex.EncodeToString(h.Sum(nil)) != c.CLISHA256 {
		return errNativePrivateFactory
	}
	info, e := buildinfo.Read(f)
	if e != nil {
		return errNativePrivateFactory
	}
	settings := map[string]string{}
	for _, s := range info.Settings {
		settings[s.Key] = s.Value
	}
	after, e := f.Stat()
	if e != nil || !nativePrivateStable(before, after) || settings["vcs.revision"] != c.SystemBuildSource || settings["vcs.modified"] != "false" || settings["GOOS"] != "linux" || settings["GOARCH"] != "amd64" {
		return errNativePrivateFactory
	}
	return nil
}

// Discard both diagnostics rather than retaining data that could contain secrets.
type nativePrivateDiagnosticCount struct{ n atomic.Int64 }

func (w *nativePrivateDiagnosticCount) Write(b []byte) (int, error) {
	w.n.Add(int64(len(b)))
	return len(b), nil
}

func nativePrivateExecute(ctx context.Context, binary *os.File, c NativeWorkerPrivateFactoryConfig, input []byte, expires time.Time) ([]byte, error) {
	if nativePrivateVerifyExecutable(binary, c) != nil {
		return nil, errNativePrivateFactory
	}
	return nativePrivateRunPinned(ctx, binary, input, expires)
}

// Only nativePrivateExecute enters this host runner after validating the exact
// pinned FD. It is not a configurable command or production callback port.
func nativePrivateRunPinned(ctx context.Context, binary *os.File, input []byte, expires time.Time) ([]byte, error) {
	deadline := nativePrivateEarlier(expires, time.Now().Add(15*time.Second))
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	r, w, e := os.Pipe()
	if e != nil {
		return nil, errNativePrivateFactory
	}
	defer r.Close()
	if e = r.SetReadDeadline(deadline.Add(2 * time.Second)); e != nil {
		w.Close()
		return nil, errNativePrivateFactory
	}
	cmd := exec.CommandContext(ctx, "/proc/self/fd/4", "ops", "native-worker", "render-private")
	cmd.ExtraFiles = []*os.File{w, binary}
	cmd.Stdin = bytes.NewReader(input)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/nonexistent", "LANG=C", "LC_ALL=C"}
	var diagnostics nativePrivateDiagnosticCount
	cmd.Stdout = &diagnostics
	cmd.Stderr = &diagnostics
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.WaitDelay = 2 * time.Second
	cmd.Cancel = func() error {
		e := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if e == syscall.ESRCH {
			return os.ErrProcessDone
		}
		return e
	}
	if e = cmd.Start(); e != nil {
		w.Close()
		return nil, errNativePrivateFactory
	}
	w.Close()
	output, readErr := io.ReadAll(io.LimitReader(r, 16385))
	if readErr != nil || len(output) > 16384 {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	r.Close()
	// Observe exit WITHOUT reaping: the original PID still owns this process
	// group, so it cannot be recycled before the one group cleanup signal.
	var info unix.Siginfo
	var originalExitErr error
	for {
		originalExitErr = unix.Waitid(unix.P_PID, cmd.Process.Pid, &info, unix.WEXITED|unix.WNOWAIT, nil)
		if originalExitErr != unix.EINTR {
			break
		}
	}
	cleanupErr := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	waitErr := cmd.Wait()
	absent := nativePrivateGroupAbsent(cmd.Process.Pid)
	if readErr != nil || originalExitErr != nil || cleanupErr != nil && cleanupErr != syscall.ESRCH || waitErr != nil || ctx.Err() != nil || diagnostics.n.Load() != 0 || len(output) == 0 || len(output) > 16384 || !bytes.HasPrefix(output, []byte("#cloud-config\n")) || !absent {
		nativePrivateWipe(output)
		return nil, errNativePrivateFactory
	}
	return output, nil
}

// After reaping, only observe: never signal a potentially recycled group ID.
func nativePrivateGroupAbsent(pid int) bool {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	for {
		if syscall.Kill(-pid, 0) == syscall.ESRCH {
			return true
		}
		select {
		case <-ticker.C:
		case <-deadline.C:
			return false
		}
	}
}

// The child payload is intentionally not exposed through formatting helpers.
var _ json.Marshaler = (*NativeWorkerPrivateFactory)(nil)
