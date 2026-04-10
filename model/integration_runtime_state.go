package model

import "time"

const (
	IntegrationRuntimeCheckKindOverall               = "overall"
	IntegrationRuntimeCheckKindDescribeHandshake     = "describe_handshake"
	IntegrationRuntimeCheckKindTransportConnectivity = "transport_connectivity"

	IntegrationRuntimeStatusHealthy          = "healthy"
	IntegrationRuntimeStatusContractMismatch = "contract_mismatch"
	IntegrationRuntimeStatusInvalidResponse  = "invalid_response"
	IntegrationRuntimeStatusUnreachable      = "unreachable"

	IntegrationInstanceHealthStatusUnknown = "unknown"
)

// IntegrationRuntimeState stores one observed operational check for an integration instance.
type IntegrationRuntimeState struct {
	IntegrationInstance ManifestReference `json:"integration_instance"`
	IntegrationType     ManifestReference `json:"integration_type"`
	CheckKind           string            `json:"check_kind"`
	Status              string            `json:"status"`
	Message             string            `json:"message,omitempty"`
	Details             map[string]any    `json:"details,omitempty"`
	LastCheckedAt       time.Time         `json:"last_checked_at"`
	LastSuccessAt       *time.Time        `json:"last_success_at,omitempty"`
	LastFailureAt       *time.Time        `json:"last_failure_at,omitempty"`
	CreatedAt           time.Time         `json:"created_at"`
	UpdatedAt           time.Time         `json:"updated_at"`
}

// GetIntegrationRuntimeStateRequest fetches one observed integration runtime state.
type GetIntegrationRuntimeStateRequest struct {
	IntegrationInstance ManifestSelector `json:"integration_instance"`
	CheckKind           string           `json:"check_kind,omitempty"`
}

// ListIntegrationRuntimeStatesRequest filters observed integration runtime states.
type ListIntegrationRuntimeStatesRequest struct {
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name,omitempty"`
	Status    string `json:"status,omitempty"`
	CheckKind string `json:"check_kind,omitempty"`
}

// IntegrationInstanceHealth summarizes runtime health for one configured integration instance.
type IntegrationInstanceHealth struct {
	IntegrationInstance ManifestReference         `json:"integration_instance"`
	IntegrationType     ManifestReference         `json:"integration_type"`
	DeclaredStatus      string                    `json:"declared_status"`
	CheckKind           string                    `json:"check_kind"`
	Status              string                    `json:"status"`
	RuntimeState        *IntegrationRuntimeState  `json:"runtime_state,omitempty"`
	RuntimeChecks       []IntegrationRuntimeState `json:"runtime_checks,omitempty"`
}

// GetIntegrationInstanceHealthRequest fetches one derived health summary for an integration instance.
type GetIntegrationInstanceHealthRequest struct {
	IntegrationInstance ManifestSelector `json:"integration_instance"`
	CheckKind           string           `json:"check_kind,omitempty"`
}

// ListIntegrationInstanceHealthRequest filters derived integration instance health summaries.
type ListIntegrationInstanceHealthRequest struct {
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name,omitempty"`
	Status    string `json:"status,omitempty"`
	CheckKind string `json:"check_kind,omitempty"`
}
