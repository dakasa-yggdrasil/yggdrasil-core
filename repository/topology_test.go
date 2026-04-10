package repository

import (
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

func TestTopologyAuthorizationResourceDefaultsToNodeID(t *testing.T) {
	t.Parallel()

	nodeID := uuid.New()

	resource := topologyAuthorizationResource(model.TopologyAuthorizationScope{}, nodeID)
	if resource != "core.topology.node."+nodeID.String() {
		t.Fatalf("unexpected default resource %q", resource)
	}
}

func TestTopologyAuthorizationInputPreservesProvidedValues(t *testing.T) {
	t.Parallel()

	nodeID := uuid.New()
	collaboratorID := uuid.New()
	authorizationNodeID := uuid.New()

	input := topologyAuthorizationInput(
		map[string]any{
			"authn": map[string]any{"provider": "custom"},
		},
		model.TopologyNode{
			ID:     nodeID,
			Slug:   "payments",
			Kind:   "project",
			Name:   "Payments",
			Status: "active",
		},
		authorizationNodeID,
		"github",
		"octocat",
		model.Collaborator{
			ID:     collaboratorID,
			Slug:   "col:octocat",
			Status: "active",
		},
		nil,
	)

	authn, ok := input["authn"].(map[string]any)
	if !ok {
		t.Fatalf("expected authn map, got %#v", input["authn"])
	}
	if authn["provider"] != "custom" {
		t.Fatalf("expected provided authn provider to be preserved, got %#v", authn)
	}

	topology, ok := input["topology"].(map[string]any)
	if !ok {
		t.Fatalf("expected topology map, got %#v", input["topology"])
	}
	if topology["authorization_node_id"] != authorizationNodeID.String() {
		t.Fatalf("unexpected authorization node id %#v", topology["authorization_node_id"])
	}

	collaborator, ok := input["collaborator"].(map[string]any)
	if !ok {
		t.Fatalf("expected collaborator map, got %#v", input["collaborator"])
	}
	if collaborator["id"] != collaboratorID.String() {
		t.Fatalf("unexpected collaborator payload %#v", collaborator)
	}
}
