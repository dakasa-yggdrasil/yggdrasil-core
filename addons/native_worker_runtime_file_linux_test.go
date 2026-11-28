//go:build linux

package addons

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/coreprocess"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/runtime"
)

func TestNativeRuntimePrivateConfigurationFileBoundary(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "private.json")
	original := []byte(`{"schema":"synthetic-file-boundary-only"}`)
	if err := os.WriteFile(file, original, 0600); err != nil {
		t.Fatal(err)
	}
	got, err := nativeWorkerReadRuntimeFile(file)
	if err != nil || !bytes.Equal(got, original) {
		t.Fatal("regular private file failed")
	}
	for _, mode := range []os.FileMode{0644, 0640, 0660, 0700} {
		if err := os.Chmod(file, mode); err != nil {
			t.Fatal(err)
		}
		if _, err := nativeWorkerReadRuntimeFile(file); err == nil {
			t.Fatalf("mode %o accepted", mode)
		}
	}
	if err := os.Chmod(file, 0600); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(dir, "symlink.json")
	if err := os.Symlink(file, symlink); err != nil {
		t.Fatal(err)
	}
	if _, err := nativeWorkerReadRuntimeFile(symlink); err == nil {
		t.Fatal("symlink accepted")
	}
	link := filepath.Join(dir, "hardlink.json")
	if err := os.Link(file, link); err != nil {
		t.Fatal(err)
	}
	if _, err := nativeWorkerReadRuntimeFile(file); err == nil {
		t.Fatal("multiply linked file accepted")
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"relative.json", dir, filepath.Join(dir, "missing"), dir + "/./private.json"} {
		if _, err := nativeWorkerReadRuntimeFile(path); err == nil {
			t.Fatalf("unsafe path accepted: %s", path)
		}
	}
	for _, raw := range [][]byte{nil, bytes.Repeat([]byte("x"), (256<<10)+1)} {
		if err := os.WriteFile(file, raw, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := nativeWorkerReadRuntimeFile(file); err == nil {
			t.Fatal("empty or oversized file accepted")
		}
	}
}

func TestNativeRuntimeInvalidConfiguredFilePublishesNothingAndBorrowsDatabase(t *testing.T) {
	unsetHTTPIdentity(t)
	t.Setenv(coreprocess.RoleEnv, string(coreprocess.Authority))
	t.Setenv("YGGDRASIL_OIDC_ISSUER", "")
	t.Setenv("YGGDRASIL_OIDC_CLIENTS_FILE", "")
	file := filepath.Join(t.TempDir(), "invalid.json")
	if err := os.WriteFile(file, []byte(`{"schema":"wrong"}`), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(nativeWorkerRuntimeFileEnv, file)
	db, mock, err := sqlmock.New(sqlmock.MonitorPingsOption(true))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	app := runtime.New("ci")
	app.SetResource("postgres", db)
	if err := bootstrapHTTP(context.Background(), app); err == nil {
		t.Fatal("invalid configured installation fell back to normal HTTP")
	}
	for _, key := range []string{nativeWorkerRuntimeResource, "http_server", "http_tls_server", "http_addr", capacityDispatchServiceResource} {
		if value, exists := app.Resource(key); exists && value != nil {
			t.Fatalf("partial startup published %s", key)
		}
	}
	mock.ExpectPing()
	if err := db.Ping(); err != nil {
		t.Fatal("failed installation closed borrowed database")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
