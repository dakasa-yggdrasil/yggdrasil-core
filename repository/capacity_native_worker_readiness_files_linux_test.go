//go:build linux

package repository

import (
	"bytes"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestNativeReadinessProtectedFilesRejectAliasesPermissionsAndMultipleLinks(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "private.json")
	body := []byte(`{"private_fixture":"owned exact original bytes"}`)
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	got, err := nativeReadinessReadFile(path, 64<<10, true)
	if err != nil || !bytes.Equal(got, body) {
		t.Fatal("owned original file unavailable", err)
	}
	clear(got)
	symlink := filepath.Join(dir, "alias")
	if err := os.Symlink(path, symlink); err != nil {
		t.Fatal(err)
	}
	if raw, err := nativeReadinessReadFile(symlink, 64<<10, true); err == nil || raw != nil {
		t.Fatal("private path followed a symlink")
	}
	link := filepath.Join(dir, "hardlink")
	if err := os.Link(path, link); err != nil {
		t.Fatal(err)
	}
	if raw, err := nativeReadinessReadFile(path, 64<<10, true); err == nil || raw != nil {
		t.Fatal("private file with another lifetime/link was accepted")
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []os.FileMode{0644, 0620, 0660, 0677} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		if raw, err := nativeReadinessReadFile(path, 64<<10, true); err == nil || raw != nil {
			t.Fatal("unprotected private mode accepted", mode)
		}
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if raw, err := nativeReadinessReadFile(path, 2, true); err == nil || raw != nil {
		t.Fatal("original oversized file returned a usable prefix")
	}
	if raw, err := nativeReadinessReadFile(dir, 64<<10, true); err == nil || raw != nil {
		t.Fatal("directory became a private file")
	}
}

func TestNativeReadinessProtectedFIFORefusesBeforeBlockingStartup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "not-a-regular-key")
	if err := syscall.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	returned := make(chan error, 1)
	go func() {
		raw, err := nativeReadinessReadFile(path, 64<<10, true)
		if raw != nil {
			clear(raw)
			err = nil
		}
		returned <- err
	}()
	// On the old blocking open, release its waiter during cleanup after the
	// real refusal assertion has failed; this is no retry or success fallback.
	t.Cleanup(func() {
		fd, err := syscall.Open(path, syscall.O_WRONLY|syscall.O_NONBLOCK, 0)
		if err == nil {
			_ = syscall.Close(fd)
		}
	})
	select {
	case err := <-returned:
		if err == nil {
			t.Fatal("FIFO became a usable private key/config")
		}
	case <-time.After(time.Second):
		t.Fatal("non-regular protected path blocked startup")
	}
}
