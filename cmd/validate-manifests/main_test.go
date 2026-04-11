package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestValidateManifestsPassesForValidFixture writes one valid
// integration_instance JSON to a temp dir and asserts the tool returns
// nil (no error). The fixture intentionally uses the simplest possible
// valid shape — just enough fields to satisfy ValidateIntegrationInstanceSpec.
func TestValidateManifestsPassesForValidFixture(t *testing.T) {
	dir := t.TempDir()
	valid := `{
		"apiVersion": "yggdrasil.io/v1alpha1",
		"kind": "integration_instance",
		"metadata": {
			"name": "sample-instance",
			"namespace": "global"
		},
		"spec": {
			"type_ref": { "name": "github", "namespace": "global" },
			"status": "active",
			"owners": ["team:platform"],
			"credentials_ref": "secret://github/private-key",
			"config": { "organization": "dakasa" },
			"discovery": { "enabled": false, "mode": "manual" },
			"execution": { "max_batch_size": 10 }
		}
	}`
	if err := os.WriteFile(filepath.Join(dir, "sample.json"), []byte(valid), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	failed, err := validateDirectory(dir)
	if err != nil {
		t.Fatalf("validateDirectory returned unexpected error: %v", err)
	}
	if failed != 0 {
		t.Fatalf("validateDirectory reported %d failures, want 0", failed)
	}
}

// TestValidateManifestsReportsFailureForBadFixture writes a JSON with
// an invalid credentials_ref (no secret:// prefix) and asserts the
// tool reports one failure without returning an error from the function
// itself — exit code semantics are the caller's responsibility.
func TestValidateManifestsReportsFailureForBadFixture(t *testing.T) {
	dir := t.TempDir()
	invalid := `{
		"apiVersion": "yggdrasil.io/v1alpha1",
		"kind": "integration_instance",
		"metadata": {
			"name": "bad-instance",
			"namespace": "global"
		},
		"spec": {
			"type_ref": { "name": "github", "namespace": "global" },
			"status": "active",
			"credentials_ref": "vault://nope",
			"discovery": { "enabled": false, "mode": "manual" },
			"execution": {}
		}
	}`
	if err := os.WriteFile(filepath.Join(dir, "bad.json"), []byte(invalid), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	failed, err := validateDirectory(dir)
	if err != nil {
		t.Fatalf("validateDirectory returned unexpected error: %v", err)
	}
	if failed != 1 {
		t.Fatalf("validateDirectory reported %d failures, want 1", failed)
	}
}

// TestValidateManifestsReturnsErrorForMissingDirectory ensures that a
// non-existent path surfaces the error so the CLI can exit 2 (not a
// validation failure, a usage error).
func TestValidateManifestsReturnsErrorForMissingDirectory(t *testing.T) {
	if _, err := validateDirectory("/definitely/does/not/exist/at/all"); err == nil {
		t.Fatal("expected error for missing directory, got nil")
	}
}
