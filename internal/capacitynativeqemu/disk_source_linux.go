//go:build linux && nativequalification

package capacitynativeqemu

import (
	"context"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

// Follow only intentional kernel-native /proc/PID/fd magic links. Observe
// independently checks the same PID/ticks before and after these reads.
func originalQEMUOpenedDisk(ctx context.Context, pid int, slotDir string) (OriginalDisk, int, time.Time, time.Time, error) {
	var zero time.Time
	identity, err := originalDiskAt(ctx, filepath.Join(slotDir, "original.qcow2"))
	if err != nil {
		return identity, 0, zero, zero, err
	}
	directory := filepath.Join("/proc", strconv.Itoa(pid), "fd")
	fd, err := unix.Open(directory, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return identity, 0, zero, zero, ErrOriginalUnknown
	}
	f := os.NewFile(uintptr(fd), directory)
	var fs unix.Statfs_t
	if unix.Fstatfs(fd, &fs) != nil || fs.Type != unix.PROC_SUPER_MAGIC {
		_ = f.Close()
		return identity, 0, zero, zero, ErrOriginalUnknown
	}
	entries, re := f.Readdirnames(1025)
	readAt := time.Now().UTC()
	matched := 0
	if (re != nil && re != io.EOF) || len(entries) >= 1025 {
		_ = f.Close()
		return identity, 0, readAt, zero, ErrOriginalUnknown
	}
	for _, name := range entries {
		descriptor, parseErr := strconv.Atoi(name)
		if parseErr != nil || descriptor < 0 {
			_ = f.Close()
			return identity, 0, readAt, zero, ErrOriginalUnknown
		}
		var stat unix.Stat_t
		if unix.Fstatat(fd, name, &stat, 0) == nil && stat.Mode&unix.S_IFMT == unix.S_IFREG && uint64(stat.Dev) == identity.Device && stat.Ino == identity.Inode {
			if matched == 0 || descriptor+1 < matched {
				matched = descriptor + 1
			}
		}
	}
	ce := f.Close()
	closeAt := time.Now().UTC()
	if ce != nil || ctx.Err() != nil || matched == 0 {
		return identity, 0, readAt, closeAt, ErrOriginalUnknown
	}
	return identity, matched - 1, readAt, closeAt, nil
}
