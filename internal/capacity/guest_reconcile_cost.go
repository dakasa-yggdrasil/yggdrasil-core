package capacity

import (
	"fmt"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

const AdministrativeCostAssumptionMode = "reviewed_administrative_cost_assumption"

func administrativeCostAssumption(p model.CapacityPolicySpec) *model.CapacityAdministrativeCostAssumption {
	if p.GuestNotifyReconcileBinding == nil {
		return nil
	}
	return p.GuestNotifyReconcileBinding.AdministrativeCostAssumption
}

func ValidateAdministrativeCostAssumption(p model.CapacityPolicySpec) error {
	c := administrativeCostAssumption(p)
	if c == nil {
		return nil
	}
	refuse := fmt.Errorf("explicit reviewed original Guest administrative cost assumption required")
	if p.GuestNotifyReconcileBinding.Mode != GuestNotifyReconcileMode || len(p.Profiles) != 1 || len(p.MutationBindings) != 1 || p.Currency != "USD" || c.Mode != AdministrativeCostAssumptionMode || c.ExpiresAt.IsZero() || !ValidDigest(c.ReviewSHA256) || c.ReviewReference == "" || len(c.ReviewReference) > 1024 || strings.TrimSpace(c.ReviewReference) != c.ReviewReference || strings.ContainsAny(c.ReviewReference, "\x00\r\n\t") {
		return refuse
	}
	profile := p.Profiles[0]
	nativeCurrency := map[string]string{"aws": "USD", "hetzner": "USD"}[profile.Provider]
	if nativeCurrency == "" || c.NativeBillingCurrency != nativeCurrency || profile.Name != "notify-"+profile.Provider+"-elastic" || profile.Name != p.MutationBindings[0].ProfileName || profile.UnitMonthlyCostMinor <= 0 || profile.UnitMonthlyCostMinor > 1000000000000 || !profile.QuoteValidUntil.IsZero() || !profile.ValidationValidUntil.IsZero() {
		return refuse
	}
	return nil
}

// Legacy policies keep their two dated native declarations. The explicit new
// mode uses only the expiry of an operator's reviewed planning assumption; it
// must not manufacture long-lived native quote/validation timestamps.
func profilePlanningDeclarations(p model.CapacityPolicySpec, profile model.CapacityProfile) bool {
	if administrativeCostAssumption(p) == nil {
		return !profile.QuoteValidUntil.IsZero() && !profile.ValidationValidUntil.IsZero()
	}
	return ValidateAdministrativeCostAssumption(p) == nil && profile.Name == p.Profiles[0].Name
}

func ProfilePlanningCurrent(p model.CapacityPolicySpec, profile model.CapacityProfile, at time.Time) bool {
	if c := administrativeCostAssumption(p); c != nil {
		return profilePlanningDeclarations(p, profile) && c.ExpiresAt.After(at)
	}
	return profile.QuoteValidUntil.After(at) && profile.ValidationValidUntil.After(at)
}

// Native diagnostics/quotes remain in the provider's currency. The policy's
// administrative planning amount never changes or converts native evidence.
func NativeBillingCurrency(p model.CapacityPolicySpec) string {
	if c := administrativeCostAssumption(p); c != nil {
		if ValidateAdministrativeCostAssumption(p) != nil {
			return ""
		}
		return c.NativeBillingCurrency
	}
	return p.Currency
}
