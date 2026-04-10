package manifest

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func TestBootstrapProductManifestsValidate(t *testing.T) {
	root := filepath.Join("..", "docs", "bootstrap", "manifests", "products")
	files, err := filepath.Glob(filepath.Join(root, "*.json"))
	if err != nil {
		t.Fatalf("Glob error: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("expected bootstrap product manifests to exist")
	}

	for _, file := range files {
		payload, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("ReadFile(%s) error: %v", file, err)
		}

		var document model.ManifestDocument
		if err := json.Unmarshal(payload, &document); err != nil {
			t.Fatalf("json.Unmarshal(%s) error: %v", file, err)
		}

		if err := ValidateDocument(document); err != nil {
			t.Fatalf("ValidateDocument(%s) error: %v", file, err)
		}
	}
}
