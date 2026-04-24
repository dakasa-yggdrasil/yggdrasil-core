package manifest

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// TestBootstrapSeedsValidate walks docs/bootstrap/seeds/**/*.json and
// asserts every shipped seed is (a) decodable into a ManifestDocument
// and (b) passes the kind-specific ValidateDocument path. This runs the
// validator against every seed the self-hosted baseline relies on, so a
// breaking change to any validator is caught at unit-test time instead
// of at first boot of an adopter's deployment.
//
// The walker scans the whole docs/bootstrap/seeds tree rather than a
// hard-coded allowlist — adding a new seed is enough; no need to
// update this test.
func TestBootstrapSeedsValidate(t *testing.T) {
	root, err := repoRelative("docs/bootstrap/seeds")
	if err != nil {
		t.Fatalf("resolve seeds path: %v", err)
	}

	var files []string
	if err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || filepath.Ext(path) != ".json" {
			return nil
		}
		files = append(files, path)
		return nil
	}); err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	if len(files) == 0 {
		t.Fatalf("no seed JSONs discovered under %s", root)
	}

	for _, file := range files {
		file := file
		name, _ := filepath.Rel(root, file)
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile(file)
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			var doc model.ManifestDocument
			if err := json.Unmarshal(data, &doc); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if err := ValidateDocument(doc); err != nil {
				t.Fatalf("ValidateDocument: %v", err)
			}
		})
	}
}

// repoRelative resolves a path relative to the repo root from a test
// running inside a package subdirectory. We walk up until we find
// go.mod rather than hard-coding "../" which would break if the package
// were moved.
func repoRelative(target string) (string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	dir := cwd
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return filepath.Join(dir, target), nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", &os.PathError{Op: "find go.mod", Path: cwd, Err: os.ErrNotExist}
		}
		dir = parent
	}
}
