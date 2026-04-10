package model

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// TopologyNode is the canonical structural unit of the ecosystem tree.
type TopologyNode struct {
	ID          uuid.UUID      `json:"id"`
	Slug        string         `json:"slug"`
	Kind        string         `json:"kind"`
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	Status      string         `json:"status"`
	ParentID    *uuid.UUID     `json:"parent_id,omitempty"`
	Metadata    map[string]any `json:"metadata,omitempty"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
}

// TopologyEdge is an explicit relation between two topology nodes.
type TopologyEdge struct {
	ID        uuid.UUID      `json:"id"`
	SourceID  uuid.UUID      `json:"source_id"`
	Relation  string         `json:"relation"`
	TargetID  uuid.UUID      `json:"target_id"`
	Status    string         `json:"status"`
	Metadata  map[string]any `json:"metadata,omitempty"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
}

// TopologyDocument stores typed JSON attached to one topology node.
type TopologyDocument struct {
	ID          uuid.UUID       `json:"id"`
	NodeID      uuid.UUID       `json:"node_id"`
	Name        string          `json:"name"`
	Kind        string          `json:"kind"`
	Description string          `json:"description,omitempty"`
	Body        json.RawMessage `json:"body"`
	Metadata    map[string]any  `json:"metadata,omitempty"`
	CreatedAt   time.Time       `json:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
}

// BuildProject is the operational build/runtime scope used by edge runtimes.
type BuildProject struct {
	ID                   uuid.UUID `json:"id"`
	InfraMapID           uuid.UUID `json:"infra-map-id"`
	ProjectEnvResourceID uuid.UUID `json:"project-env-resource-id"`
	BuildName            string    `json:"build-name"`
	EnvType              string    `json:"env-type"`
	Cloud                string    `json:"cloud"`
	Ephemeral            bool      `json:"ephemeral,omitempty"`
	ExpiresAt            string    `json:"expires-at,omitempty"`
	ClusterName          string    `json:"cluster-name,omitempty"`
	ClusterZone          string    `json:"cluster-zone,omitempty"`
	Immutable            bool      `json:"immutable,omitempty"`
}

type UpsertTopologyNodeRequest struct {
	ID          string         `json:"id,omitempty"`
	Slug        string         `json:"slug,omitempty"`
	Kind        string         `json:"kind"`
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	Status      string         `json:"status,omitempty"`
	ParentID    string         `json:"parent_id,omitempty"`
	Metadata    map[string]any `json:"metadata,omitempty"`
}

type GetTopologyNodeRequest struct {
	ID string `json:"id"`
}

type ListTopologyNodeChildrenRequest struct {
	ParentID string `json:"parent_id"`
}

type UpsertTopologyEdgeRequest struct {
	ID       string         `json:"id,omitempty"`
	SourceID string         `json:"source_id"`
	Relation string         `json:"relation"`
	TargetID string         `json:"target_id"`
	Status   string         `json:"status,omitempty"`
	Metadata map[string]any `json:"metadata,omitempty"`
}

type ListTopologyEdgesRequest struct {
	SourceID string `json:"source_id,omitempty"`
	Relation string `json:"relation,omitempty"`
	TargetID string `json:"target_id,omitempty"`
}

type UpsertTopologyDocumentRequest struct {
	ID          string          `json:"id,omitempty"`
	NodeID      string          `json:"node_id"`
	Name        string          `json:"name"`
	Kind        string          `json:"kind"`
	Description string          `json:"description,omitempty"`
	Body        json.RawMessage `json:"body"`
	Metadata    map[string]any  `json:"metadata,omitempty"`
}

type GetTopologyDocumentRequest struct {
	ID     string `json:"id,omitempty"`
	NodeID string `json:"node_id,omitempty"`
	Kind   string `json:"kind,omitempty"`
}

type ListTopologyDocumentsRequest struct {
	NodeID string `json:"node_id,omitempty"`
	Kind   string `json:"kind,omitempty"`
}

type GetTopologyDocumentValueRequest struct {
	ID     string   `json:"id,omitempty"`
	NodeID string   `json:"node_id,omitempty"`
	Kind   string   `json:"kind,omitempty"`
	Path   []string `json:"path,omitempty"`
}

type CreateBuildProjectRequest struct {
	ProjectNodeID string       `json:"project_node_id"`
	Build         BuildProject `json:"build"`
}

type GetBuildProjectRequest struct {
	ID string `json:"id"`
}

type ListBuildProjectsRequest struct {
	ProjectNodeID string `json:"project_node_id"`
	MutableOnly   bool   `json:"mutable_only,omitempty"`
}

type DeleteBuildProjectRequest struct {
	ID string `json:"id"`
}

type TopologyAuthorizationScope struct {
	RBAC     ManifestSelector  `json:"rbac"`
	Policy   *ManifestSelector `json:"policy,omitempty"`
	Resource string            `json:"resource,omitempty"`
	Input    map[string]any    `json:"input,omitempty"`
}

type EvaluateTopologyAccessRequest struct {
	NodeID   string `json:"node_id"`
	Provider string `json:"provider,omitempty"`
	Login    string `json:"login"`
}

type EvaluateTopologyAccessResponse struct {
	Allowed             bool       `json:"allowed"`
	Authority           int        `json:"authority"`
	CollaboratorID      *uuid.UUID `json:"collaborator_id,omitempty"`
	AuthorizationNodeID *uuid.UUID `json:"authorization_node_id,omitempty"`
	Resource            string     `json:"resource,omitempty"`
	Reason              string     `json:"reason,omitempty"`
}
