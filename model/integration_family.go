package model

// IntegrationFamilyManifestSpec describes a contract that one or more
// integration_type manifests can implement.
//
// A family enumerates the set of operations that "being a {family}" implies —
// e.g. the rabbitmq family declares install/uninstall/declare_queue/publish/
// observe_queue_health. Each integration_type referencing the family via
// FamilyRef commits to implementing a subset of those operations and exposes
// itself as a provider.
//
// Workflows can target a family + operation pair instead of a concrete
// instance_ref; the runtime resolves the active provider that implements the
// requested operation and dispatches through its adapter. Direct instance_ref
// resolution remains supported for explicit pinning.
type IntegrationFamilyManifestSpec struct {
	// DisplayName is a human-friendly label shown in tooling.
	DisplayName string `json:"display_name,omitempty"`

	// Description explains what the family represents.
	Description string `json:"description,omitempty"`

	// Owners are the teams or roles responsible for the contract.
	Owners []string `json:"owners,omitempty"`

	// Operations enumerates every operation a provider of this family may
	// implement. Providers declare which subset they cover via
	// IntegrationTypeManifestSpec.ImplementedOperations (or via the adapter's
	// describe response). The list is the source of truth for what the family
	// supports semantically — providers cannot extend it ad-hoc.
	Operations []IntegrationFamilyOperation `json:"operations"`

	// Schema describes the inputs/credentials expected to be common across
	// every provider of this family. Provider-specific extras live on the
	// IntegrationTypeManifestSpec.InstanceSchema / CredentialSchema.
	Schema IntegrationFamilySchemaSpec `json:"schema,omitempty"`
}

// IntegrationFamilyOperation describes one operation declared by a family.
//
// Providers reference these by Name when claiming implementation. The runtime
// matches workflow step requests against the union of provider implementations.
type IntegrationFamilyOperation struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	// Idempotent indicates the operation is safe to retry; runtime may use this
	// to short-circuit retries on transient failure.
	Idempotent bool `json:"idempotent,omitempty"`
}

// IntegrationFamilySchemaSpec captures inputs that any provider of the family
// must accept on its instance config or credentials. Empty values mean
// providers are free to define their own surface entirely.
type IntegrationFamilySchemaSpec struct {
	Instance    IntegrationSchemaSpec `json:"instance,omitempty"`
	Credentials IntegrationSchemaSpec `json:"credentials,omitempty"`
}
