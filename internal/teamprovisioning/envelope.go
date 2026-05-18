package teamprovisioning

import "strings"

// Extracted is the result of ExtractFromOutput.
type Extracted struct {
	ExternalID       string
	ExternalMetadata map[string]any
}

// ExtractFromOutput inspects the adapter's response output map for the
// convention block output._yggdrasil.team_provisioned. Returns (extracted,
// true) when the block is present and well-formed; (zero, false) otherwise.
// Malformed blocks (missing external_id) are silently dropped — log writing
// is opt-in metadata, never load-bearing.
//
// Mirror of internal/externalidentity/envelope.go ExtractFromOutput. Kept
// in its own package so the dependency direction stays one-way (adapters
// → core).
func ExtractFromOutput(output map[string]any) (Extracted, bool) {
	if output == nil {
		return Extracted{}, false
	}
	ygg, ok := output["_yggdrasil"].(map[string]any)
	if !ok {
		return Extracted{}, false
	}
	tp, ok := ygg["team_provisioned"].(map[string]any)
	if !ok {
		return Extracted{}, false
	}
	ext, ok := tp["external_id"].(string)
	if !ok || strings.TrimSpace(ext) == "" {
		return Extracted{}, false
	}
	meta, _ := tp["external_metadata"].(map[string]any)
	return Extracted{ExternalID: ext, ExternalMetadata: meta}, true
}
