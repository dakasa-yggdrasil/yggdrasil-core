//go:build capacitytest && nativequalification

package main

import (
	"encoding/json"
	"github.com/dakasa-yggdrasil/yggdrasil-core/manifest"
	"testing"
)

func TestSyntheticWorkflow(t *testing.T) {
	spec := syntheticWorkflow("ci-synthetic-test", "original-native-qemu-create")
	if err := manifest.ValidateWorkflowSpec(spec); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := manifest.ParseWorkflowSpec(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := manifest.ValidateWorkflowSpec(parsed); err != nil {
		t.Fatal(err)
	}
}
