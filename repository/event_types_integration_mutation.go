package repository

import "regexp"

// IntegrationMutationEventTypeRegex is the canonical pattern adapters MUST
// satisfy when emitting mutation events per INTEGRATION_CONTRACT §6.5:
//
//	<provider>.<resource>.<verb_past>
//
// where:
//   - `<provider>` and `<resource>` are snake_case (a-z, 0-9, underscores;
//     leading character is a-z),
//   - `<verb_past>` is one of `ensured`, `destroyed`, `created`.
//
// `ensured` and `destroyed` cover the idempotent declarative resource ops
// (`ensure_*` / `destroy_*`). `created` is reserved for the money-movement
// allowlist (`create_payout`, `create_refund`) where the semantic is "do
// this one-shot side effect" rather than "ensure this resource state".
//
// The regex is intentionally a closed grammar — the verb set is bounded by
// IntegrationMutationVerbs and any new verb requires a contract amendment
// AND a follow-up schema in docs/contracts/events/v1/integration_mutation/.
const IntegrationMutationEventTypeRegex = `^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*\.(ensured|destroyed|created)$`

// IntegrationMutationVerbs is the closed verb set the regex permits. Order
// is significant for the tests that lock the wire vocabulary down.
var IntegrationMutationVerbs = []string{"ensured", "destroyed", "created"}

// integrationMutationEventTypePattern is the compiled regex used by the
// helpers below. Compiled once at package init to avoid hot-path regex
// compilation on every event emission.
var integrationMutationEventTypePattern = regexp.MustCompile(IntegrationMutationEventTypeRegex)

// IsIntegrationMutationEvent reports whether the given event type conforms
// to the §6.5 mutation event grammar. The materialiser uses this to decide
// whether an event should fan out to integration_instances with matching
// reactor declarations, in addition to the closed canon lifecycle set.
func IsIntegrationMutationEvent(eventType string) bool {
	return integrationMutationEventTypePattern.MatchString(eventType)
}

// ParseIntegrationMutationEventType splits the canonical form into
// (provider, resource, verb). Returns ok=false if the input does not match
// the grammar — call sites should treat that as an invalid event type
// before persisting.
func ParseIntegrationMutationEventType(eventType string) (provider, resource, verb string, ok bool) {
	if !integrationMutationEventTypePattern.MatchString(eventType) {
		return "", "", "", false
	}
	// We know there are exactly two dots given the regex; walk explicitly
	// instead of pulling strings.SplitN here so we keep zero allocations
	// in the happy path.
	firstDot := -1
	lastDot := -1
	for i := 0; i < len(eventType); i++ {
		if eventType[i] == '.' {
			if firstDot == -1 {
				firstDot = i
			} else {
				lastDot = i
			}
		}
	}
	if firstDot == -1 || lastDot == -1 || firstDot == lastDot {
		return "", "", "", false
	}
	return eventType[:firstDot], eventType[firstDot+1 : lastDot], eventType[lastDot+1:], true
}

// Canonical integration mutation event type constants. Adapter authors are
// encouraged to import the constant rather than the literal so the compiler
// catches typos. The set covers the first-wave reference adapters; new
// entries land alongside each adapter's first mutation event.
//
// Conformance: each constant satisfies IntegrationMutationEventTypeRegex and
// has a matching JSON Schema at
// docs/contracts/events/v1/integration_mutation/<verb>.json (a single shared
// schema per verb since the payload shape is identical across providers).
const (
	// Stripe — payments & subscriptions.
	EventTypeStripeCustomerEnsured       = "stripe.customer.ensured"
	EventTypeStripeCustomerDestroyed     = "stripe.customer.destroyed"
	EventTypeStripeSubscriptionEnsured   = "stripe.subscription.ensured"
	EventTypeStripeSubscriptionDestroyed = "stripe.subscription.destroyed"
	EventTypeStripeRefundCreated         = "stripe.refund.created"

	// EFI — Brazilian Pix/boleto.
	EventTypeEFIChargeEnsured   = "efi.charge.ensured"
	EventTypeEFIChargeDestroyed = "efi.charge.destroyed"
	EventTypeEFIPayoutCreated   = "efi.payout.created"

	// NFe.io — service invoices.
	EventTypeNFEIOServiceInvoiceEnsured = "nfeio.service_invoice.ensured"

	// GitHub — repositories, teams.
	EventTypeGitHubRepositoryEnsured       = "github.repository.ensured"
	EventTypeGitHubTeamMembershipDestroyed = "github.team_membership.destroyed"
)
