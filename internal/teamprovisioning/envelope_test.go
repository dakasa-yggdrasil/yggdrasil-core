package teamprovisioning

import "testing"

func TestExtractFromOutput_MissingBlock(t *testing.T) {
	if _, ok := ExtractFromOutput(map[string]any{"foo": "bar"}); ok {
		t.Fatal("expected no extraction when _yggdrasil missing")
	}
}

func TestExtractFromOutput_ValidBlock(t *testing.T) {
	out := map[string]any{
		"_yggdrasil": map[string]any{
			"team_provisioned": map[string]any{
				"external_id":       "C123",
				"external_metadata": map[string]any{"channel_name": "team-eng"},
			},
		},
	}
	ext, ok := ExtractFromOutput(out)
	if !ok {
		t.Fatal("expected extraction to succeed")
	}
	if ext.ExternalID != "C123" {
		t.Fatalf("expected external_id C123, got %s", ext.ExternalID)
	}
	if ext.ExternalMetadata["channel_name"] != "team-eng" {
		t.Fatalf("expected channel_name team-eng, got %v", ext.ExternalMetadata["channel_name"])
	}
}

func TestExtractFromOutput_MalformedMissingExternalID(t *testing.T) {
	out := map[string]any{
		"_yggdrasil": map[string]any{
			"team_provisioned": map[string]any{"external_metadata": map[string]any{}},
		},
	}
	if _, ok := ExtractFromOutput(out); ok {
		t.Fatal("expected extraction to fail without external_id")
	}
}

func TestExtractFromOutput_NilInput(t *testing.T) {
	if _, ok := ExtractFromOutput(nil); ok {
		t.Fatal("expected no extraction for nil input")
	}
}
