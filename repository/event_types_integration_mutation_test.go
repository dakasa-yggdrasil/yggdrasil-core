package repository

import (
	"regexp"
	"testing"
)

// TestIntegrationMutationEventTypeRegex asserts the canonical pattern that
// adapters MUST use when emitting `<provider>.<resource>.<verb_past>` mutation
// events per INTEGRATION_CONTRACT §6.5. The regex is the load-bearing piece
// validators rely on to route open-ended event types to a single shared
// schema and to enable reactor materialisation.
func TestIntegrationMutationEventTypeRegex(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  bool
	}{
		// Canonical examples lifted straight from §6.5 of the contract.
		{"stripe customer ensured", "stripe.customer.ensured", true},
		{"stripe subscription destroyed", "stripe.subscription.destroyed", true},
		{"efi charge ensured", "efi.charge.ensured", true},
		{"efi charge destroyed", "efi.charge.destroyed", true},
		{"nfeio service_invoice ensured", "nfeio.service_invoice.ensured", true},
		{"github repository ensured", "github.repository.ensured", true},
		{"github team_membership destroyed", "github.team_membership.destroyed", true},
		// `created` covers the money-movement allowlist (e.g. payouts, refunds).
		{"stripe refund created", "stripe.refund.created", true},
		{"efi payout created", "efi.payout.created", true},

		// Non-conformant inputs — must NOT match.
		{"empty", "", false},
		{"missing verb", "stripe.customer", false},
		{"unknown verb", "stripe.customer.updated", false},
		{"wildcard verb", "stripe.customer.*", false},
		{"uppercase provider", "Stripe.customer.ensured", false},
		{"leading digit", "1stripe.customer.ensured", false},
		{"leading dot", ".customer.ensured", false},
		{"trailing dot", "stripe.customer.ensured.", false},
		{"hyphen instead of underscore", "stripe.customer-id.ensured", false},
		{"four segments", "stripe.customer.profile.ensured", false},
		{"non-canon lifecycle event", "collaborator.created", false},
		{"manifest event", "manifest.created", false},
	}

	pattern := regexp.MustCompile(IntegrationMutationEventTypeRegex)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := pattern.MatchString(tc.input)
			if got != tc.want {
				t.Fatalf("MatchString(%q) = %v; want %v", tc.input, got, tc.want)
			}
		})
	}
}

// TestParseIntegrationMutationEventType extracts the (provider, resource, verb)
// triple from the event type. Round-tripping the canonical example confirms
// the helper is consistent with the regex.
func TestParseIntegrationMutationEventType(t *testing.T) {
	provider, resource, verb, ok := ParseIntegrationMutationEventType("stripe.customer.ensured")
	if !ok {
		t.Fatalf("Parse: ok=false on canonical input")
	}
	if provider != "stripe" || resource != "customer" || verb != "ensured" {
		t.Fatalf("Parse: got (%q,%q,%q); want (stripe,customer,ensured)", provider, resource, verb)
	}

	if _, _, _, ok := ParseIntegrationMutationEventType("not.a.match.event"); ok {
		t.Fatalf("Parse: ok=true on non-conformant input")
	}
}

// TestIsIntegrationMutationEvent matches the regex contract — the same
// predicate the materialiser uses to decide whether to fan-out reactions
// to integration_instances.
func TestIsIntegrationMutationEvent(t *testing.T) {
	if !IsIntegrationMutationEvent("stripe.customer.ensured") {
		t.Fatalf("expected mutation event for stripe.customer.ensured")
	}
	if IsIntegrationMutationEvent("manifest.created") {
		t.Fatalf("manifest.created is not a mutation event")
	}
}

// TestIntegrationMutationVerbsClosedSet locks the verb set down. Adding a
// new verb here forces a follow-up to the JSON Schema directory and the
// adapter SDK so we don't end up with split-brain definitions.
func TestIntegrationMutationVerbsClosedSet(t *testing.T) {
	want := []string{"ensured", "destroyed", "created"}
	if len(IntegrationMutationVerbs) != len(want) {
		t.Fatalf("IntegrationMutationVerbs len: got %d, want %d", len(IntegrationMutationVerbs), len(want))
	}
	for i, v := range want {
		if IntegrationMutationVerbs[i] != v {
			t.Fatalf("IntegrationMutationVerbs[%d]: got %q, want %q", i, IntegrationMutationVerbs[i], v)
		}
	}
}

// TestIntegrationMutationCanonExampleConstants pins the constants the
// reference adapters declared as their first mutation events. Constants
// avoid typos at adapter-side call sites.
func TestIntegrationMutationCanonExampleConstants(t *testing.T) {
	cases := []struct {
		got  string
		want string
	}{
		{EventTypeStripeCustomerEnsured, "stripe.customer.ensured"},
		{EventTypeStripeCustomerDestroyed, "stripe.customer.destroyed"},
		{EventTypeStripeSubscriptionEnsured, "stripe.subscription.ensured"},
		{EventTypeStripeSubscriptionDestroyed, "stripe.subscription.destroyed"},
		{EventTypeEFIChargeEnsured, "efi.charge.ensured"},
		{EventTypeEFIChargeDestroyed, "efi.charge.destroyed"},
		{EventTypeNFEIOServiceInvoiceEnsured, "nfeio.service_invoice.ensured"},
		{EventTypeGitHubRepositoryEnsured, "github.repository.ensured"},
		{EventTypeGitHubTeamMembershipDestroyed, "github.team_membership.destroyed"},
		{EventTypeStripeRefundCreated, "stripe.refund.created"},
		{EventTypeEFIPayoutCreated, "efi.payout.created"},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Fatalf("constant mismatch: got %q want %q", c.got, c.want)
		}
		if !IsIntegrationMutationEvent(c.got) {
			t.Fatalf("constant %q must satisfy IsIntegrationMutationEvent", c.got)
		}
	}
}

// TestIntegrationMutationEventConstantsUnique ensures we don't introduce
// duplicate canonical constants pointing at the same wire string.
func TestIntegrationMutationEventConstantsUnique(t *testing.T) {
	seen := map[string]string{}
	for _, c := range []struct {
		name  string
		value string
	}{
		{"EventTypeStripeCustomerEnsured", EventTypeStripeCustomerEnsured},
		{"EventTypeStripeCustomerDestroyed", EventTypeStripeCustomerDestroyed},
		{"EventTypeStripeSubscriptionEnsured", EventTypeStripeSubscriptionEnsured},
		{"EventTypeStripeSubscriptionDestroyed", EventTypeStripeSubscriptionDestroyed},
		{"EventTypeEFIChargeEnsured", EventTypeEFIChargeEnsured},
		{"EventTypeEFIChargeDestroyed", EventTypeEFIChargeDestroyed},
		{"EventTypeNFEIOServiceInvoiceEnsured", EventTypeNFEIOServiceInvoiceEnsured},
		{"EventTypeGitHubRepositoryEnsured", EventTypeGitHubRepositoryEnsured},
		{"EventTypeGitHubTeamMembershipDestroyed", EventTypeGitHubTeamMembershipDestroyed},
		{"EventTypeStripeRefundCreated", EventTypeStripeRefundCreated},
		{"EventTypeEFIPayoutCreated", EventTypeEFIPayoutCreated},
	} {
		if prev, ok := seen[c.value]; ok {
			t.Fatalf("duplicate constant: %s and %s both equal %q", prev, c.name, c.value)
		}
		seen[c.value] = c.name
	}
}
