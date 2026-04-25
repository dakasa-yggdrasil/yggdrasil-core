package model

import "encoding/json"

// WorkflowTemplateManifestSpec declares a parameterised workflow that adopters
// can instantiate with their own parameter values. Templates serve two
// audiences: (1) operators clicking through the surface-console to onboard
// without authoring JSON; (2) the `yggdrasil instantiate-template` CLI for
// automation.
//
// A template's `body` is a workflow-shaped object with `{{ params.* }}`
// placeholders. Instantiation substitutes values from caller-provided
// `params`, validates the result against the workflow validator, and creates
// a workflow manifest in the caller-chosen namespace.
type WorkflowTemplateManifestSpec struct {
	// DisplayName is the human-readable label shown in marketplace listings.
	DisplayName string `json:"display_name"`

	// Description explains what the template does for human reviewers.
	Description string `json:"description,omitempty"`

	// Category groups templates in marketplace listings (e.g. "deploy", "ci",
	// "audit", "operations"). Free-form string; UIs filter on it.
	Category string `json:"category,omitempty"`

	// Tags allow finer-grained discoverability than category alone.
	Tags []string `json:"tags,omitempty"`

	// Authors lists the principals who own / maintain the template.
	Authors []string `json:"authors,omitempty"`

	// Params declares the inputs the template accepts. Each entry mirrors the
	// JSON Schema-ish shape used by workflow input_schema (type, required,
	// default, description) so adopter UIs can render forms.
	Params map[string]WorkflowTemplateParam `json:"params,omitempty"`

	// Body is the workflow shape with `{{ params.<name> }}` placeholders.
	// Yggdrasil substitutes placeholders against caller-supplied params and
	// posts the result as a workflow manifest.
	Body json.RawMessage `json:"body"`

	// Version of the template itself (independent of manifest version). Bump
	// when changing semantics; adopters pin templates by `version` in their
	// instantiation calls when stability matters.
	Version string `json:"version,omitempty"`
}

// WorkflowTemplateParam describes one template parameter for marketplace UIs.
type WorkflowTemplateParam struct {
	Type        string `json:"type"`
	Description string `json:"description,omitempty"`
	Required    bool   `json:"required,omitempty"`
	Default     any    `json:"default,omitempty"`
	Enum        []any  `json:"enum,omitempty"`
}
