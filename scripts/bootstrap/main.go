package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	manifestpkg "github.com/dakasa-yggdrasil/yggdrasil-core/manifest"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/psql"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

type importSummary struct {
	Validated int
	Created   int
	Skipped   int
}

func main() {
	root := flag.String("path", "./docs/bootstrap/manifests", "Path to the bootstrap manifest root")
	dryRun := flag.Bool("dry-run", false, "Validate manifests without persisting them")
	timeout := flag.Duration("timeout", 30*time.Second, "Timeout for each database operation")
	flag.Parse()

	files, err := discoverManifestFiles(*root)
	if err != nil {
		exitf("discover manifest files: %v", err)
	}
	if len(files) == 0 {
		exitf("no bootstrap manifests found under %s", *root)
	}

	documents := make([]namedDocument, 0, len(files))
	for _, file := range files {
		document, err := loadManifestDocument(file)
		if err != nil {
			exitf("load %s: %v", file, err)
		}

		document = manifestpkg.NormalizeDocument(document)
		if err := manifestpkg.ValidateDocument(document); err != nil {
			exitf("validate %s: %v", file, err)
		}

		documents = append(documents, namedDocument{
			Path:     file,
			Document: document,
		})
	}

	summary := importSummary{Validated: len(documents)}
	if *dryRun {
		for _, document := range documents {
			fmt.Printf("validated %s (%s/%s/%s)\n", document.Path, document.Document.Kind, document.Document.Metadata.Namespace, document.Document.Metadata.Name)
		}
		printSummary(summary, true)
		return
	}

	db, err := psql.Open()
	if err != nil {
		exitf("open postgres: %v", err)
	}
	defer db.Close()

	for _, document := range documents {
		status, err := importManifest(db, document.Document, *timeout)
		if err != nil {
			exitf("import %s: %v", document.Path, err)
		}
		switch status {
		case "created":
			summary.Created++
		case "skipped":
			summary.Skipped++
		}
		fmt.Printf("%s %s (%s/%s/%s)\n", status, document.Path, document.Document.Kind, document.Document.Metadata.Namespace, document.Document.Metadata.Name)
	}

	printSummary(summary, false)
}

type namedDocument struct {
	Path     string
	Document model.ManifestDocument
}

func discoverManifestFiles(root string) ([]string, error) {
	var files []string

	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
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

	var document model.ManifestDocument
	if err := json.Unmarshal(payload, &document); err != nil {
		return model.ManifestDocument{}, err
	}

	return document, nil
}

func importManifest(db *sql.DB, document model.ManifestDocument, timeout time.Duration) (string, error) {
	checksum, err := manifestpkg.Checksum(document)
	if err != nil {
		return "", err
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	existing, err := repository.ResolveManifest(ctx, db, document.Kind, document.Metadata.Namespace, document.Metadata.Name, nil, true)
	switch {
	case err == nil:
		if strings.TrimSpace(existing.Checksum) == checksum {
			return "skipped", nil
		}
	case errors.Is(err, repository.ErrManifestNotFound):
	default:
		return "", err
	}

	if _, err := repository.CreateManifestVersion(ctx, db, document, checksum); err != nil {
		return "", err
	}

	return "created", nil
}

func printSummary(summary importSummary, dryRun bool) {
	if dryRun {
		fmt.Printf("bootstrap dry-run complete: validated=%d\n", summary.Validated)
		return
	}
	fmt.Printf("bootstrap import complete: validated=%d created=%d skipped=%d\n", summary.Validated, summary.Created, summary.Skipped)
}

func exitf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
