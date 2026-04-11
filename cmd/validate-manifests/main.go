// Command validate-manifests reads a directory of *.json files, parses
// each as a model.ManifestDocument, and runs manifestengine.ValidateDocument
// against it. Reports pass/fail per file and exits with:
//
//	0 — all files pass
//	1 — one or more files fail validation
//	2 — usage or I/O error (e.g., missing directory)
//
// Usage:
//
//	validate-manifests <directory>
//
// Intended to be invoked from the dakasa-system repo during CI or
// manual manifest authoring sessions:
//
//	go run ./cmd/validate-manifests \
//	  /Users/someone/dakasa-system/yggdrasil/dakasa/integration-instances
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	manifestengine "github.com/dakasa-yggdrasil/yggdrasil-core/manifest"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: validate-manifests <directory>")
		os.Exit(2)
	}

	failed, err := validateDirectory(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}

	if failed > 0 {
		fmt.Fprintf(os.Stderr, "\n%d manifest(s) failed validation\n", failed)
		os.Exit(1)
	}

	fmt.Println("\nall manifests valid")
}

// validateDirectory walks dir for *.json files and runs ValidateDocument
// on each. Returns the number of files that failed and any error
// encountered while enumerating the directory. Per-file parse/validate
// errors are printed and counted, not returned — callers distinguish
// validation failures (via count) from usage/I-O errors (via error).
func validateDirectory(dir string) (int, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return 0, fmt.Errorf("stat %s: %w", dir, err)
	}
	if !info.IsDir() {
		return 0, fmt.Errorf("%s is not a directory", dir)
	}

	files, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return 0, fmt.Errorf("glob %s: %w", dir, err)
	}
	if len(files) == 0 {
		fmt.Fprintf(os.Stderr, "warning: no *.json files in %s\n", dir)
		return 0, nil
	}

	failed := 0
	for _, file := range files {
		if err := validateFile(file); err != nil {
			fmt.Fprintf(os.Stderr, "FAIL %s: %v\n", filepath.Base(file), err)
			failed++
			continue
		}
		fmt.Printf("PASS %s\n", filepath.Base(file))
	}
	return failed, nil
}

func validateFile(path string) error {
	payload, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read: %w", err)
	}

	var document model.ManifestDocument
	if err := json.Unmarshal(payload, &document); err != nil {
		return fmt.Errorf("parse: %w", err)
	}

	if err := manifestengine.ValidateDocument(document); err != nil {
		return fmt.Errorf("validate: %w", err)
	}

	return nil
}
