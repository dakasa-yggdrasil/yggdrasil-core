//go:build linux

package repository

import (
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// A protected original file read is complete only after the actual descriptor
// Close and stable inode metadata. No returned prefix can become a key/config.
func nativeReadinessReadFile(path string, limit int64, private bool) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || limit < 1 || limit > 4<<20 {
		return nil, errNativeReadinessRun
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, errNativeReadinessRun
	}
	before, statErr := f.Stat()
	valid := func(s os.FileInfo) bool {
		if s == nil {
			return false
		}
		x, ok := s.Sys().(*syscall.Stat_t)
		return ok && s.Mode().IsRegular() && s.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) == 0 && s.Mode().Perm()&0022 == 0 && (!private || s.Mode().Perm()&0077 == 0) && x.Nlink == 1 && (x.Uid == 0 || x.Uid == uint32(os.Geteuid())) && s.Size() > 0 && s.Size() <= limit
	}
	if statErr != nil || !valid(before) {
		_ = f.Close()
		return nil, errNativeReadinessRun
	}
	raw, readErr := io.ReadAll(io.LimitReader(f, limit+1))
	after, afterErr := f.Stat()
	closeErr := f.Close()
	last, pathErr := os.Lstat(path)
	if readErr != nil || afterErr != nil || closeErr != nil || pathErr != nil || !valid(after) || !valid(last) || int64(len(raw)) != before.Size() || !os.SameFile(before, after) || !os.SameFile(before, last) || !nativeReadinessSameStat(before.Sys().(*syscall.Stat_t), after.Sys().(*syscall.Stat_t)) || !nativeReadinessSameStat(before.Sys().(*syscall.Stat_t), last.Sys().(*syscall.Stat_t)) {
		clear(raw)
		return nil, errNativeReadinessRun
	}
	return raw, nil
}

func nativeReadinessSameStat(a, b *syscall.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Mode == b.Mode && a.Uid == b.Uid && a.Gid == b.Gid && a.Nlink == b.Nlink && a.Size == b.Size && a.Mtim == b.Mtim && a.Ctim == b.Ctim
}
