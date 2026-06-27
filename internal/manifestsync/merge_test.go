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

func TestMergeSpec_UnionsOperatorAndLiveReactors(t *testing.T) {
	// UNION semantics (since 2026-06-27): operator-declared reactors no
	// longer REPLACE the adapter's set; they are unioned with it. The
	// adapter's live-declared reactor is always present, and the
	// operator-only reactor (a different (event_type, capability) pair) is
	// appended. This is the regression guard that an incomplete operator
	// override no longer drops the adapter's reactors.
	current := model.IntegrationTypeManifestSpec{
		Reactors: []model.IntegrationTypeReactor{{EventType: "e1", Capability: "c1"}},
	}
	live := model.IntegrationTypeManifestSpec{
		Reactors: []model.IntegrationTypeReactor{{EventType: "e2", Capability: "c2"}},
	}
	got, _ := MergeSpec(current, live)
	require.Len(t, got.Reactors, 2, "union must contain both adapter and operator reactors")
	// Live (adapter) entries come first.
	assert.Equal(t, "e2", got.Reactors[0].EventType, "adapter-declared reactor must be present")
	assert.Equal(t, "e1", got.Reactors[1].EventType, "operator-only reactor must be appended")
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

func TestMergeSpec_UnionsReactorsNotReplace(t *testing.T) {
	// Regression guard for the prod incident: an INCOMPLETE operator
	// override (1 stored reactor) must NOT drop the adapter's other
	// declared reactors. The adapter declares 3 reactors (one of which
	// the operator also stored); the merged result must carry all 3 from
	// the adapter (union, no replacement). A reactor the operator declared
	// that the adapter does NOT declare must also be preserved.
	overlap := model.IntegrationTypeReactor{EventType: "session.terminated", Capability: "on_session_terminated"}
	operatorOnly := model.IntegrationTypeReactor{EventType: "custom.audit", Capability: "on_custom_audit"}

	current := model.IntegrationTypeManifestSpec{
		// Operator stored only the overlap reactor plus a bespoke one the
		// adapter never declares.
		Reactors: []model.IntegrationTypeReactor{overlap, operatorOnly},
	}
	live := model.IntegrationTypeManifestSpec{
		// Adapter declares its full canonical set of 3 (incl. the overlap).
		Reactors: []model.IntegrationTypeReactor{
			overlap,
			{EventType: "team.created", Capability: "on_team_created"},
			{EventType: "team_membership.added", Capability: "on_team_membership_added"},
		},
	}

	got, _ := MergeSpec(current, live)

	// All 3 adapter reactors are present (the incomplete override did not
	// drop the membership/team reactors), plus the 1 operator-only reactor,
	// with the overlap deduped → 4 total.
	require.Len(t, got.Reactors, 4, "union must keep all adapter reactors plus operator-only, deduped")

	have := map[string]bool{}
	for _, r := range got.Reactors {
		have[r.EventType+"|"+r.Capability] = true
	}
	assert.True(t, have["session.terminated|on_session_terminated"], "overlap reactor present once")
	assert.True(t, have["team.created|on_team_created"], "adapter team.created reactor must NOT be dropped")
	assert.True(t, have["team_membership.added|on_team_membership_added"], "adapter membership reactor must NOT be dropped")
	assert.True(t, have["custom.audit|on_custom_audit"], "operator-only reactor must be preserved")
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

// INTEGRATION_CONTRACT §15 amplification — Display and Icon are
// adapter presentation hints declared in the static manifest, not in
// Describe(). manifest_sync must preserve them across cron ticks.

func TestMergeSpec_PreservesDisplayWhenLiveBlanksIt(t *testing.T) {
	display := &model.IntegrationDisplaySpec{
		Subtitle: "Pagamentos, clientes, assinaturas e webhooks via Stripe.",
		SubtitleLocale: map[string]string{
			"pt-BR": "Pagamentos, clientes, assinaturas e webhooks via Stripe.",
			"en-US": "Payments, customers, subscriptions and webhooks via Stripe.",
		},
	}
	current := model.IntegrationTypeManifestSpec{Display: display}
	live := model.IntegrationTypeManifestSpec{} // Display nil
	got, _ := MergeSpec(current, live)
	require.NotNil(t, got.Display, "operator-declared display must survive sync")
	assert.Equal(t, "Pagamentos, clientes, assinaturas e webhooks via Stripe.", got.Display.Subtitle)
	assert.Equal(t, "Payments, customers, subscriptions and webhooks via Stripe.", got.Display.SubtitleLocale["en-US"])
}

func TestMergeSpec_PreservesIconWhenLiveBlanksIt(t *testing.T) {
	icon := &model.IntegrationIconSpec{
		URL:       "data:image/svg+xml;utf8,<svg/>",
		Accent:    "#635bff",
		AriaLabel: "Stripe",
	}
	current := model.IntegrationTypeManifestSpec{Icon: icon}
	live := model.IntegrationTypeManifestSpec{} // Icon nil
	got, _ := MergeSpec(current, live)
	require.NotNil(t, got.Icon, "operator-declared icon must survive sync")
	assert.Equal(t, "#635bff", got.Icon.Accent)
	assert.Equal(t, "Stripe", got.Icon.AriaLabel)
}

func TestMergeSpec_AdoptsLiveDisplayAndIconWhenCurrentEmpty(t *testing.T) {
	// If a future SDK augments Describe() to carry Display/Icon (e.g.
	// as seed-on-first-registration), accept them when current empty.
	display := &model.IntegrationDisplaySpec{Subtitle: "X"}
	icon := &model.IntegrationIconSpec{URL: "https://example/x.svg", Accent: "#123456"}
	current := model.IntegrationTypeManifestSpec{}
	live := model.IntegrationTypeManifestSpec{Display: display, Icon: icon}
	got, _ := MergeSpec(current, live)
	require.NotNil(t, got.Display)
	assert.Equal(t, "X", got.Display.Subtitle)
	require.NotNil(t, got.Icon)
	assert.Equal(t, "#123456", got.Icon.Accent)
}
