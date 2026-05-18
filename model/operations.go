package model

// Operation name constants for adapter capabilities. Until this file existed,
// these names were bare strings inlined at call sites — that pattern continues
// for legacy operations (on_collaborator_*, on_list_identities, etc.) but new
// operations should be declared here for discoverability.

// OperationOnSurfaceQuery is the adapter capability invoked by the
// /api/v1/integrations/{instance_id}/surface-query HTTP proxy. The
// adapter receives {query_name, params} as Input and returns provider-
// specific JSON in Output. See spec 2026-05-17-integration-surfaces §5.5.
const OperationOnSurfaceQuery = "on_surface_query"
