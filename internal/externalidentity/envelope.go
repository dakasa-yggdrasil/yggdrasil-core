package externalidentity

import "strings"

// Extracted is the result of ExtractFromOutput.
type Extracted struct {
	ExternalID       string
	ExternalMetadata map[string]any
}

// EmbeddedIdentity is what gets embedded under req._context.external_identity.
type EmbeddedIdentity struct {
	ExternalID       string         `json:"external_id"`
	ExternalMetadata map[string]any `json:"external_metadata"`
	LinkedAt         string         `json:"linked_at,omitempty"`
	LastSeenAt       string         `json:"last_seen_at,omitempty"`
}

// ExtractFromOutput inspects the adapter's response output map for the
// convention block output._yggdrasil.external_identity. Returns (extracted,
// true) when the block is present and well-formed; (zero, false) otherwise.
// Malformed blocks (missing external_id) are silently dropped — identity
// writing is opt-in metadata, never load-bearing.
func ExtractFromOutput(output map[string]any) (Extracted, bool) {
	if output == nil {
		return Extracted{}, false
	}
	ygg, ok := output["_yggdrasil"].(map[string]any)
	if !ok {
		return Extracted{}, false
	}
	id, ok := ygg["external_identity"].(map[string]any)
	if !ok {
		return Extracted{}, false
	}
	ext, ok := id["external_id"].(string)
	if !ok || strings.TrimSpace(ext) == "" {
		return Extracted{}, false
	}
	meta, _ := id["external_metadata"].(map[string]any)
	return Extracted{ExternalID: ext, ExternalMetadata: meta}, true
}

// EmbedIntoInput injects the embed under input._context.external_identity.
// Creates _context if absent. Overwrites existing external_identity if any.
func EmbedIntoInput(input map[string]any, embed EmbeddedIdentity) {
	if input == nil {
		return
	}
	ctx, _ := input["_context"].(map[string]any)
	if ctx == nil {
		ctx = map[string]any{}
		input["_context"] = ctx
	}
	embedded := map[string]any{"external_id": embed.ExternalID}
	if embed.ExternalMetadata != nil {
		embedded["external_metadata"] = embed.ExternalMetadata
	}
	if embed.LinkedAt != "" {
		embedded["linked_at"] = embed.LinkedAt
	}
	if embed.LastSeenAt != "" {
		embedded["last_seen_at"] = embed.LastSeenAt
	}
	ctx["external_identity"] = embedded
}
