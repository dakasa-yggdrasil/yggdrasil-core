//go:build linux && nativequalification

package capacitynativeqemu

import (
	"context"
	"errors"
	"reflect"
	"time"

	"encoding/json"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"os"
	"path/filepath"
	"testing"
)

func TestPG17ReadDiagnosticRetainsOnlyClosedStage(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(SlotDirectory(dir, 2), 0700); err != nil {
		t.Fatal(err)
	}
	r := &Realm{PrivateDirectory: dir}
	r.Request.NativeCase = "positive_original_lifecycle"
	if err := r.RecordPG17ReadDiagnostic(context.Background(), "callee", "scope"); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(SlotDirectory(dir, 2), "pg17-read-diagnostic-callee.json")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var d map[string]any
	if err = json.Unmarshal(b, &d); err != nil || len(d) != 3 || d["schema"] != "pg17_native_read_failure_v1" || d["origin"] != "callee" || d["stage"] != "scope" {
		t.Fatalf("unexpected diagnostic %v %v", d, err)
	}
	if err = r.RecordPG17ReadDiagnostic(context.Background(), "callee", "native_read"); err == nil {
		t.Fatal("original diagnostic replaced")
	}
	if err = r.RecordPG17ReadDiagnostic(context.Background(), "client", "private-secret"); err == nil {
		t.Fatal("unapproved diagnostic accepted")
	}
}

func TestPG17NativeReadDiagnosticDoesNotChangeRefusal(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(SlotDirectory(dir, 2), 0700); err != nil {
		t.Fatal(err)
	}
	r := &Realm{PrivateDirectory: dir}
	r.Request.NativeCase = "positive_original_lifecycle"
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	got, err := r.PG17NativeRead(ctx, repository.CapacityStore{}, model.Manifest{}, model.AdapterExecuteIntegrationRequest{})
	if !errors.Is(err, ErrOriginalUnknown) || !reflect.DeepEqual(got, model.AdapterExecuteIntegrationResponse{}) {
		t.Fatalf("scope refusal changed: %#v %v", got, err)
	}
	path := filepath.Join(SlotDirectory(dir, 2), "pg17-read-diagnostic-callee.json")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var d map[string]any
	if json.Unmarshal(b, &d) != nil || d["origin"] != "callee" || d["stage"] != "scope" || len(d) != 3 {
		t.Fatalf("unexpected scope diagnostic %v", d)
	}
}
