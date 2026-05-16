package externalidentity

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractFromOutput_MissingBlock(t *testing.T) {
	out := map[string]any{"other": "stuff"}
	_, ok := ExtractFromOutput(out)
	assert.False(t, ok)
}

func TestExtractFromOutput_ValidBlock(t *testing.T) {
	out := map[string]any{
		"other": "stuff",
		"_yggdrasil": map[string]any{
			"external_identity": map[string]any{
				"external_id":       "U_TEST",
				"external_metadata": map[string]any{"display_name": "QA"},
			},
		},
	}
	ext, ok := ExtractFromOutput(out)
	assert.True(t, ok)
	assert.Equal(t, "U_TEST", ext.ExternalID)
	assert.Equal(t, "QA", ext.ExternalMetadata["display_name"])
}

func TestExtractFromOutput_MalformedMissingExternalID(t *testing.T) {
	out := map[string]any{
		"_yggdrasil": map[string]any{
			"external_identity": map[string]any{"external_metadata": map[string]any{}},
		},
	}
	_, ok := ExtractFromOutput(out)
	assert.False(t, ok, "missing external_id is malformed; skip silently")
}

func TestExtractFromOutput_NilInput(t *testing.T) {
	_, ok := ExtractFromOutput(nil)
	assert.False(t, ok)
}

func TestEmbedIntoInput_CreatesContextBlock(t *testing.T) {
	input := map[string]any{"primary_email": "user@dakasa.me"}
	embed := EmbeddedIdentity{
		ExternalID:       "U_EMBED",
		ExternalMetadata: map[string]any{"display_name": "Test"},
		LinkedAt:         "2026-05-16T12:00:00Z",
	}
	EmbedIntoInput(input, embed)
	ctx, ok := input["_context"].(map[string]any)
	assert.True(t, ok)
	ei, _ := ctx["external_identity"].(map[string]any)
	assert.Equal(t, "U_EMBED", ei["external_id"])
	assert.Equal(t, "2026-05-16T12:00:00Z", ei["linked_at"])
}

func TestEmbedIntoInput_PreservesExistingContext(t *testing.T) {
	input := map[string]any{"_context": map[string]any{"attempt": float64(2)}}
	EmbedIntoInput(input, EmbeddedIdentity{ExternalID: "U"})
	ctx := input["_context"].(map[string]any)
	assert.EqualValues(t, 2, ctx["attempt"])
	assert.NotNil(t, ctx["external_identity"])
}
