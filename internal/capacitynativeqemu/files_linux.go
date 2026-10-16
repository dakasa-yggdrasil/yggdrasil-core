//go:build linux && nativequalification

package capacitynativeqemu

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

// Publish exposes final bytes only after the ORIGINAL Write/fsync/Close. The
// final basename never exists with a partial body and can never be replaced.
func Publish(ctx context.Context, path string, value any) ([]byte, error) {
	if ctx.Err() != nil {
		return nil, ErrOriginalUnknown
	}
	raw, err := json.Marshal(value)
	if err != nil || len(raw) > 2<<20 {
		return nil, ErrOriginalUnknown
	}
	return PublishBytes(ctx, path, raw)
}
func PublishBytes(ctx context.Context, path string, raw []byte) ([]byte, error) {
	if ctx.Err() != nil || len(raw) < 1 || len(raw) > 2<<20 {
		return nil, ErrOriginalUnknown
	}
	directory := filepath.Dir(path)
	f, err := os.CreateTemp(directory, ".original-stage-")
	if err != nil {
		return nil, err
	}
	temporary := f.Name()
	defer os.Remove(temporary)
	err = f.Chmod(0600)
	n, we := f.Write(raw)
	se := f.Sync()
	ce := f.Close()
	if err != nil || we != nil || se != nil || ce != nil || n != len(raw) || ctx.Err() != nil {
		return nil, ErrOriginalUnknown
	}
	if unix.Renameat2(unix.AT_FDCWD, temporary, unix.AT_FDCWD, path, unix.RENAME_NOREPLACE) != nil {
		return nil, ErrOriginalUnknown
	}
	d, err := os.Open(directory)
	if err != nil {
		return nil, ErrOriginalUnknown
	}
	se = d.Sync()
	ce = d.Close()
	if se != nil || ce != nil || ctx.Err() != nil {
		return nil, ErrOriginalUnknown
	}
	return raw, nil
}

func Await(ctx context.Context, path string, out any) ([]byte, error) {
	timer := time.NewTicker(20 * time.Millisecond)
	defer timer.Stop()
	for {
		_, err := os.Lstat(path)
		if err == nil {
			return ReadPrivate(ctx, path, out)
		}
		if !errors.Is(err, os.ErrNotExist) {
			return nil, ErrOriginalUnknown
		}
		select {
		case <-ctx.Done():
			return nil, ErrOriginalUnknown
		case <-timer.C:
		}
	}
}
