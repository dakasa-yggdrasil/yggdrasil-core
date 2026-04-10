package message

import (
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// TestParseTargetOverridesFromStepInput_WithImageOverrides verifies the
// workflow step input parser picks up the new image_overrides field as
// a string->string map under each target override entry.
func TestParseTargetOverridesFromStepInput_WithImageOverrides(t *testing.T) {
	input := map[string]any{
		"target_overrides": map[string]any{
			"kubernetes-sandbox": map[string]any{
				"integration_instance_ref": map[string]any{
					"name":      "kubernetes-dakasa-validation",
					"namespace": "dakasa",
				},
				"namespace": "dakasa-main",
				"image_overrides": map[string]any{
					"ghcr.io/dakasa-co/identities":   "ghcr.io/dakasa-co/identities:sha-abc1234",
					"ghcr.io/dakasa-co/hall":         "ghcr.io/dakasa-co/hall:sha-abc1234",
				},
			},
		},
	}

	overrides, err := parseTargetOverridesFromStepInput(input)
	if err != nil {
		t.Fatalf("parseTargetOverridesFromStepInput error: %v", err)
	}

	override, ok := overrides["kubernetes-sandbox"]
	if !ok {
		t.Fatal("override for kubernetes-sandbox missing")
	}

	if override.IntegrationInstanceRef.Name != "kubernetes-dakasa-validation" {
		t.Errorf("IntegrationInstanceRef.Name = %q", override.IntegrationInstanceRef.Name)
	}
	if override.Namespace != "dakasa-main" {
		t.Errorf("Namespace = %q", override.Namespace)
	}
	if len(override.ImageOverrides) != 2 {
		t.Fatalf("ImageOverrides count = %d, want 2", len(override.ImageOverrides))
	}
	if override.ImageOverrides["ghcr.io/dakasa-co/identities"] != "ghcr.io/dakasa-co/identities:sha-abc1234" {
		t.Errorf("identities override = %q", override.ImageOverrides["ghcr.io/dakasa-co/identities"])
	}
	if override.ImageOverrides["ghcr.io/dakasa-co/hall"] != "ghcr.io/dakasa-co/hall:sha-abc1234" {
		t.Errorf("hall override = %q", override.ImageOverrides["ghcr.io/dakasa-co/hall"])
	}
}

// TestParseTargetOverridesFromStepInput_ImageOverridesWrongType ensures
// the parser rejects a non-object image_overrides field.
func TestParseTargetOverridesFromStepInput_ImageOverridesWrongType(t *testing.T) {
	input := map[string]any{
		"target_overrides": map[string]any{
			"kubernetes-sandbox": map[string]any{
				"integration_instance_ref": map[string]any{
					"name": "kubernetes-other",
				},
				"image_overrides": "not an object",
			},
		},
	}

	if _, err := parseTargetOverridesFromStepInput(input); err == nil {
		t.Fatal("expected error for non-object image_overrides")
	}
}

// TestParseTargetOverridesFromStepInput_ImageOverridesNonStringValue
// ensures entries with non-string values fail.
func TestParseTargetOverridesFromStepInput_ImageOverridesNonStringValue(t *testing.T) {
	input := map[string]any{
		"target_overrides": map[string]any{
			"kubernetes-sandbox": map[string]any{
				"integration_instance_ref": map[string]any{
					"name": "kubernetes-other",
				},
				"image_overrides": map[string]any{
					"ghcr.io/dakasa-co/identities": 1234,
				},
			},
		},
	}

	if _, err := parseTargetOverridesFromStepInput(input); err == nil {
		t.Fatal("expected error for non-string image_overrides value")
	}
}

// TestImageOverridesForOriginalKey_MatchesByOriginalName asserts that
// imageOverridesForOriginalKey finds the override by the original key
// (the name as written in the Product manifest BEFORE the override
// rewrote it).
func TestImageOverridesForOriginalKey_MatchesByOriginalName(t *testing.T) {
	executor := newProductTargetExecutor(nil, nil, nil).withTargetOverrides(map[string]model.TargetOverride{
		"kubernetes-sandbox": {
			IntegrationInstanceRef: model.ManifestSelector{
				Name:      "kubernetes-dakasa-validation",
				Namespace: "dakasa",
			},
			ImageOverrides: map[string]string{
				"ghcr.io/dakasa-co/identities": "ghcr.io/dakasa-co/identities:sha-abc1234",
			},
		},
	})

	result := executor.imageOverridesForOriginalKey("kubernetes-sandbox")
	if result == nil {
		t.Fatal("expected image overrides for kubernetes-sandbox key")
	}
	if result["ghcr.io/dakasa-co/identities"] != "ghcr.io/dakasa-co/identities:sha-abc1234" {
		t.Errorf("identities override = %q", result["ghcr.io/dakasa-co/identities"])
	}
}

// TestImageOverridesForOriginalKey_NilWhenNoMatch verifies the lookup
// returns nil when no override matches the given key.
func TestImageOverridesForOriginalKey_NilWhenNoMatch(t *testing.T) {
	executor := newProductTargetExecutor(nil, nil, nil).withTargetOverrides(map[string]model.TargetOverride{
		"kubernetes-sandbox": {
			IntegrationInstanceRef: model.ManifestSelector{Name: "kubernetes-dakasa-validation"},
			ImageOverrides:         map[string]string{"a": "b"},
		},
	})

	if result := executor.imageOverridesForOriginalKey("kubernetes-production"); result != nil {
		t.Fatalf("expected nil for unmatched key, got %v", result)
	}
}

// TestImageOverridesForOriginalKey_NilWhenNoImageOverrides verifies that
// an override without ImageOverrides returns nil (not an empty map).
func TestImageOverridesForOriginalKey_NilWhenNoImageOverrides(t *testing.T) {
	executor := newProductTargetExecutor(nil, nil, nil).withTargetOverrides(map[string]model.TargetOverride{
		"kubernetes-sandbox": {
			IntegrationInstanceRef: model.ManifestSelector{Name: "kubernetes-dakasa-validation"},
		},
	})

	if result := executor.imageOverridesForOriginalKey("kubernetes-sandbox"); result != nil {
		t.Fatalf("expected nil when ImageOverrides is empty, got %v", result)
	}
}

// TestImageOverridesForOriginalKey_ReturnsShallowCopy ensures mutations
// on the returned map do not leak back into the executor state.
func TestImageOverridesForOriginalKey_ReturnsShallowCopy(t *testing.T) {
	executor := newProductTargetExecutor(nil, nil, nil).withTargetOverrides(map[string]model.TargetOverride{
		"kubernetes-sandbox": {
			IntegrationInstanceRef: model.ManifestSelector{Name: "kubernetes-dakasa-validation"},
			ImageOverrides:         map[string]string{"a": "b"},
		},
	})

	result := executor.imageOverridesForOriginalKey("kubernetes-sandbox")
	result["a"] = "mutated"

	second := executor.imageOverridesForOriginalKey("kubernetes-sandbox")
	if second["a"] != "b" {
		t.Fatalf("executor state leaked mutation: got %q, want b", second["a"])
	}
}
