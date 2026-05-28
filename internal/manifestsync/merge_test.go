package manifestsync

import (
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMergeSpec_PreservesReactorsWhenLiveHasNone(t *testing.T) {
	current := model.IntegrationTypeManifestSpec{
		ActionCatalog: []model.IntegrationActionDefinition{{Name: "old_op"}},
		Reactors: []model.IntegrationTypeReactor{
			{EventType: "collaborator.created", Capability: "on_collaborator_created"},
		},
	}
	live := model.IntegrationTypeManifestSpec{
		ActionCatalog: []model.IntegrationActionDefinition{{Name: "new_op_a"}, {Name: "new_op_b"}},
	}

	got, diff := MergeSpec(current, live)

	require.Len(t, got.Reactors, 1, "reactors must be preserved from current")
	assert.Equal(t, "on_collaborator_created", got.Reactors[0].Capability)
	assert.Len(t, got.ActionCatalog, 2, "action_catalog must come from live")
	assert.Contains(t, diff.AddedActions, "new_op_a")
	assert.Contains(t, diff.AddedActions, "new_op_b")
	assert.Contains(t, diff.RemovedActions, "old_op")
}

func TestMergeSpec_IdenticalProducesNoDiff(t *testing.T) {
	spec := model.IntegrationTypeManifestSpec{
		ActionCatalog: []model.IntegrationActionDefinition{{Name: "x"}},
		Reactors:      []model.IntegrationTypeReactor{{EventType: "e", Capability: "c"}},
	}
	got, diff := MergeSpec(spec, spec)
	assert.Equal(t, spec, got)
	assert.Empty(t, diff.AddedActions)
	assert.Empty(t, diff.RemovedActions)
	assert.False(t, diff.SchemaChanged)
	assert.False(t, diff.CapabilitiesChanged)
}

func TestMergeSpec_SchemaChangedFlag(t *testing.T) {
	current := model.IntegrationTypeManifestSpec{
		CredentialSchema: model.IntegrationSchemaSpec{Properties: map[string]model.IntegrationSchemaProperty{"v": {Type: "1"}}},
	}
	live := model.IntegrationTypeManifestSpec{
		CredentialSchema: model.IntegrationSchemaSpec{Properties: map[string]model.IntegrationSchemaProperty{"v": {Type: "2"}}},
	}
	_, diff := MergeSpec(current, live)
	assert.True(t, diff.SchemaChanged)
}

func TestMergeSpec_CapabilitiesChangedFlag(t *testing.T) {
	current := model.IntegrationTypeManifestSpec{
		Capabilities: []string{"a"},
	}
	live := model.IntegrationTypeManifestSpec{
		Capabilities: []string{"a", "b"},
	}
	_, diff := MergeSpec(current, live)
	assert.True(t, diff.CapabilitiesChanged)
}

func TestMergeSpec_OperatorReactorsBeatLive(t *testing.T) {
	// When the operator has already configured reactors, those win even if
	// the adapter's describe response also declares some. Operator override
	// always beats adapter-declared defaults.
	current := model.IntegrationTypeManifestSpec{
		Reactors: []model.IntegrationTypeReactor{{EventType: "e1", Capability: "c1"}},
	}
	live := model.IntegrationTypeManifestSpec{
		Reactors: []model.IntegrationTypeReactor{{EventType: "e2", Capability: "c2"}},
	}
	got, _ := MergeSpec(current, live)
	require.Len(t, got.Reactors, 1)
	assert.Equal(t, "e1", got.Reactors[0].EventType, "operator's reactors must win over adapter-declared")
}

func TestMergeSpec_AdopsLiveReactorsWhenCurrentEmpty(t *testing.T) {
	// Initial registration / re-sync: when no operator has set reactors,
	// the manifest_sync runner adopts whatever the adapter declares in
	// its describe response. This is how adapters seed their canonical
	// reactor subscriptions (e.g. collaborator.session.terminated →
	// on_collaborator_session_terminated) without manual catalog patches.
	current := model.IntegrationTypeManifestSpec{
		ActionCatalog: []model.IntegrationActionDefinition{{Name: "x"}},
		// Reactors empty — operator has not configured any.
	}
	live := model.IntegrationTypeManifestSpec{
		ActionCatalog: []model.IntegrationActionDefinition{{Name: "x"}, {Name: "y"}},
		Reactors: []model.IntegrationTypeReactor{
			{EventType: "collaborator.session.terminated", Capability: "on_collaborator_session_terminated"},
		},
	}
	got, _ := MergeSpec(current, live)
	require.Len(t, got.Reactors, 1)
	assert.Equal(t, "collaborator.session.terminated", got.Reactors[0].EventType)
	assert.Equal(t, "on_collaborator_session_terminated", got.Reactors[0].Capability)
}

func TestMergeSpec_NoReactorsAnywhere(t *testing.T) {
	current := model.IntegrationTypeManifestSpec{
		ActionCatalog: []model.IntegrationActionDefinition{{Name: "x"}},
	}
	live := model.IntegrationTypeManifestSpec{
		ActionCatalog: []model.IntegrationActionDefinition{{Name: "x"}, {Name: "y"}},
	}
	got, _ := MergeSpec(current, live)
	assert.Nil(t, got.Reactors, "no reactors anywhere means no reactors in result")
}

// INTEGRATION_CONTRACT §17 — Domain and Dashboard are operator-managed
// fields declared in the registered manifest, not in the adapter's
// runtime Describe() response. manifest_sync must preserve them.

func TestMergeSpec_PreservesDomainWhenLiveBlanksIt(t *testing.T) {
	// Adapter's Describe() does not include Domain (Phase A) — the
	// runtime contract type omits the field entirely. The operator's
	// manifest had it set; sync must not blank it.
	current := model.IntegrationTypeManifestSpec{
		Domain: "payments",
	}
	live := model.IntegrationTypeManifestSpec{
		// Domain absent — runtime Describe never emits it.
	}
	got, _ := MergeSpec(current, live)
	assert.Equal(t, "payments", got.Domain, "operator-declared domain must survive sync")
}

func TestMergeSpec_AdoptsLiveDomainWhenCurrentEmpty(t *testing.T) {
	// If somehow live carries Domain (e.g. an adapter that augments its
	// Describe in a future SDK), accept it when current is empty.
	current := model.IntegrationTypeManifestSpec{}
	live := model.IntegrationTypeManifestSpec{Domain: "platform"}
	got, _ := MergeSpec(current, live)
	assert.Equal(t, "platform", got.Domain, "live domain seeds when current is empty")
}

func TestMergeSpec_PreservesDashboardWhenLiveBlanksIt(t *testing.T) {
	dashboard := &model.IntegrationDashboardSpec{
		URL:   "https://dashboard.stripe.com",
		Label: "Abrir Stripe",
	}
	current := model.IntegrationTypeManifestSpec{Dashboard: dashboard}
	live := model.IntegrationTypeManifestSpec{} // Dashboard nil
	got, _ := MergeSpec(current, live)
	require.NotNil(t, got.Dashboard, "operator-declared dashboard must survive sync")
	assert.Equal(t, "https://dashboard.stripe.com", got.Dashboard.URL)
	assert.Equal(t, "Abrir Stripe", got.Dashboard.Label)
}

func TestMergeSpec_AdoptsLiveDashboardWhenCurrentEmpty(t *testing.T) {
	dashboard := &model.IntegrationDashboardSpec{URL: "https://app.nfe.io"}
	current := model.IntegrationTypeManifestSpec{}
	live := model.IntegrationTypeManifestSpec{Dashboard: dashboard}
	got, _ := MergeSpec(current, live)
	require.NotNil(t, got.Dashboard)
	assert.Equal(t, "https://app.nfe.io", got.Dashboard.URL)
}
