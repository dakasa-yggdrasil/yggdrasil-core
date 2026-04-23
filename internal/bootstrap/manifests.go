package bootstrap

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	manifestengine "github.com/dakasa-yggdrasil/yggdrasil-core/manifest"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

// manifestsSummary accumulates counters while importManifestsFromDir
// walks a directory. Used internally to populate Result counters.
type manifestsSummary struct {
	Validated int
	Created   int
	Skipped   int
}

// importManifestsFromDir walks root for *.json files, validates each one
// as a ManifestDocument, and creates a new version through the repository
// — unless an existing manifest with the same (kind, namespace, name)
// already has a matching checksum, in which case the file is skipped.
//
// The dedup rule is what makes rerunning on a live database safe. A
// rebuild of yggdrasil-core ships the same seeds; the server boots and
// runs this, and existing deployments end up as no-ops.
//
// Validation failures fail fast — a bad seed is a packaging bug and
// silently continuing would leave an inconsistent catalog.
func importManifestsFromDir(ctx context.Context, db *sql.DB, root string) (manifestsSummary, error) {
	var summary manifestsSummary

	files, err := discoverManifestFiles(root)
	if err != nil {
		return summary, fmt.Errorf("discover manifests: %w", err)
	}
	if len(files) == 0 {
		// Empty directory is not an error — some self-hosted deployments
		// may intentionally run without the default seeds.
		return summary, nil
	}

	for _, file := range files {
		doc, err := loadManifestDocument(file)
		if err != nil {
			return summary, fmt.Errorf("load %s: %w", file, err)
		}

		doc = manifestengine.NormalizeDocument(doc)
		if err := manifestengine.ValidateDocument(doc); err != nil {
			return summary, fmt.Errorf("validate %s: %w", file, err)
		}

		summary.Validated++

		status, err := upsertManifestVersion(ctx, db, doc)
		if err != nil {
			return summary, fmt.Errorf("import %s: %w", file, err)
		}
		switch status {
		case "created":
			summary.Created++
		case "skipped":
			summary.Skipped++
		}
	}

	return summary, nil
}

func discoverManifestFiles(root string) ([]string, error) {
	if strings.TrimSpace(root) == "" {
		return nil, fmt.Errorf("path is empty")
	}

	info, err := os.Stat(root)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%s is not a directory", root)
	}

	var files []string
	err = filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		if filepath.Ext(path) != ".json" {
			return nil
		}
		files = append(files, path)
		return nil
	})
	if err != nil {
		return nil, err
	}

	sort.Strings(files)
	return files, nil
}

func loadManifestDocument(path string) (model.ManifestDocument, error) {
	payload, err := os.ReadFile(path)
	if err != nil {
		return model.ManifestDocument{}, err
	}

	var doc model.ManifestDocument
	if err := json.Unmarshal(payload, &doc); err != nil {
		return model.ManifestDocument{}, fmt.Errorf("parse JSON: %w", err)
	}
	return doc, nil
}

// upsertManifestVersion persists the document as a new manifest version
// unless an existing active manifest with the same (kind, namespace,
// name) already has the same checksum. The checksum-match short circuit
// is what guarantees idempotency across reboots.
func upsertManifestVersion(ctx context.Context, db *sql.DB, doc model.ManifestDocument) (string, error) {
	checksum, err := manifestengine.Checksum(doc)
	if err != nil {
		return "", err
	}

	existing, err := repository.ResolveManifest(ctx, db, doc.Kind, doc.Metadata.Namespace, doc.Metadata.Name, nil, true)
	switch {
	case err == nil:
		if strings.TrimSpace(existing.Checksum) == checksum {
			return "skipped", nil
		}
	case errors.Is(err, repository.ErrManifestNotFound):
		// Create path below.
	default:
		return "", err
	}

	if _, err := repository.CreateManifestVersion(ctx, db, doc, checksum); err != nil {
		return "", err
	}
	return "created", nil
}
