//go:build linux

package addons

import (
	"io"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// The bootstrap produces a regular private file. Symlink mounts, shared
// permissions and in-place changes are refused rather than normalized.
func nativeWorkerReadRuntimeFile(path string) ([]byte, error) {
	if !nativeWorkerPrivatePath(path) {
		return nil, errNativeWorkerInstallation
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, errNativeWorkerInstallation
	}
	f := os.NewFile(uintptr(fd), "private-native-installation")
	before, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, errNativeWorkerInstallation
	}
	a, ok := before.Sys().(*syscall.Stat_t)
	if !ok || !before.Mode().IsRegular() || before.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || before.Mode().Perm() != 0600 ||
		a.Nlink != 1 || a.Uid != 0 && a.Uid != uint32(os.Geteuid()) || before.Size() < 1 || before.Size() > 256<<10 {
		_ = f.Close()
		return nil, errNativeWorkerInstallation
	}
	raw, readErr := io.ReadAll(io.LimitReader(f, (256<<10)+1))
	after, statErr := f.Stat()
	closeErr := f.Close()
	if readErr != nil || statErr != nil || closeErr != nil || int64(len(raw)) != before.Size() {
		return nil, errNativeWorkerInstallation
	}
	b, ok := after.Sys().(*syscall.Stat_t)
	if !ok || a.Dev != b.Dev || a.Ino != b.Ino || a.Mode != b.Mode || a.Uid != b.Uid || a.Gid != b.Gid || a.Nlink != b.Nlink ||
		a.Size != b.Size || a.Mtim != b.Mtim || a.Ctim != b.Ctim {
		return nil, errNativeWorkerInstallation
	}
	return raw, nil
}
