package capacity

import (
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func guestAdministrativeUnit(t *testing.T) (model.CapacityPolicySpec, time.Time) {
	t.Helper()
	_, p, _, now := guestReconcileUnit(t)
	p.Currency, p.MinSamples, p.MaxSampleGapSeconds, p.UpHoldSeconds, p.DownHoldSeconds, p.CooldownSeconds, p.LeaseSeconds = "USD", 5, 10, 60, 300, 300, 300
	p.Profiles[0].ValidationRef = "declared-unit-source-validation-not-market-price"
	p.Profiles[0].UnitMonthlyCostMinor = 10000
	p.MutationBindings[0].OriginalProviderSourceCommit = strings.Repeat("a", 40)
	p.GuestNotifyReconcileBinding.AdministrativeCostAssumption = &model.CapacityAdministrativeCostAssumption{Mode: AdministrativeCostAssumptionMode, ReviewReference: "unit:operator-budget-not-native-quote", ReviewSHA256: strings.Repeat("8", 64), ExpiresAt: now.Add(time.Hour), NativeBillingCurrency: "USD"}
	return p, now
}

func TestOriginalGuestAdministrativeCostAssumptionClosed(t *testing.T) {
	for _, name := range []string{"valid", "wrong_mode", "missing_ref", "missing_digest", "missing_expiry", "mixed_quote", "mixed_validation", "wrong_native_currency", "zero_cost", "no_guest_mode"} {
		t.Run(name, func(t *testing.T) {
			p, now := guestAdministrativeUnit(t)
			c := p.GuestNotifyReconcileBinding.AdministrativeCostAssumption
			switch name {
			case "wrong_mode":
				c.Mode = "native_quote"
			case "missing_ref":
				c.ReviewReference = ""
			case "missing_digest":
				c.ReviewSHA256 = ""
			case "missing_expiry":
				c.ExpiresAt = time.Time{}
			case "mixed_quote":
				p.Profiles[0].QuoteValidUntil = now.Add(time.Hour)
			case "mixed_validation":
				p.Profiles[0].ValidationValidUntil = now.Add(time.Hour)
			case "wrong_native_currency":
				c.NativeBillingCurrency = "EUR"
			case "zero_cost":
				p.Profiles[0].UnitMonthlyCostMinor = 0
			case "no_guest_mode":
				p.GuestNotifyReconcileBinding.Mode = "capacity_dispatch_prestart_v1"
			}
			if (ValidatePolicy(p) == nil) != (name == "valid") {
				t.Fatal("administrative assumption blurred native quote/validation or legacy authority")
			}
		})
	}
}

func TestOriginalGuestAdministrativeExpiryIsNotNativeQuote(t *testing.T) {
	p, now := guestAdministrativeUnit(t)
	if !p.Profiles[0].QuoteValidUntil.IsZero() || !p.Profiles[0].ValidationValidUntil.IsZero() || !ProfilePlanningCurrent(p, p.Profiles[0], now.Add(61*time.Second)) {
		t.Fatal("assumption fabricated/reused a native sixty-second quote")
	}
	if ProfilePlanningCurrent(p, p.Profiles[0], now.Add(time.Hour)) {
		t.Fatal("administrative review extended itself")
	}
	p.GuestNotifyReconcileBinding.AdministrativeCostAssumption = nil
	if ValidatePolicy(p) == nil {
		t.Fatal("legacy accepted absent dated declarations")
	}
	p.Profiles[0].QuoteValidUntil, p.Profiles[0].ValidationValidUntil = now.Add(60*time.Second), now.Add(time.Hour)
	if ProfilePlanningCurrent(p, p.Profiles[0], now.Add(61*time.Second)) {
		t.Fatal("legacy expired quote weakened")
	}
	p, now = guestAdministrativeUnit(t)
	p.Profiles[0].Provider, p.Profiles[0].Name, p.MutationBindings[0].ProfileName = "hetzner", "notify-hetzner-elastic", "notify-hetzner-elastic"
	p.Profiles[0].UnitMonthlyCostMinor = 6000
	p.GuestNotifyReconcileBinding.AdministrativeCostAssumption.NativeBillingCurrency = "USD"
	if ValidateAdministrativeCostAssumption(p) != nil || NativeBillingCurrency(p) != "USD" || p.Currency != "USD" {
		t.Fatal("selected Hetzner USD native profile was relabeled")
	}
	p.GuestNotifyReconcileBinding.AdministrativeCostAssumption.NativeBillingCurrency = "EUR"
	if ValidateAdministrativeCostAssumption(p) == nil || NativeBillingCurrency(p) != "" {
		t.Fatal("foreign currency accepted for the selected Hetzner USD profile")
	}
	// This does not validate/approve the deliberately unchanged AWS native
	// tuple in this shape-only fixture, or convert any native amount to USD.
}

func TestOriginalGuestAdministrativeCostDoesNotChangeApproval(t *testing.T) {
	p, _ := guestAdministrativeUnit(t)
	before := GuestProductionProfileContractSHA256(p, *p.GuestRetirementBinding, "aws")
	profile := GuestRetirementSHA(p.GuestRetirementBinding.ProfileManifest)
	p.GuestNotifyReconcileBinding.AdministrativeCostAssumption = nil
	if !ValidDigest(before) || before != GuestProductionProfileContractSHA256(p, *p.GuestRetirementBinding, "aws") || profile != GuestRetirementSHA(p.GuestRetirementBinding.ProfileManifest) {
		t.Fatal("outer planning assumption changed the protected profile contract")
	}
}

func TestOriginalGuestReconcileStrictThresholdBoundaries(t *testing.T) {
	for _, name := range []string{"guest_up_equal", "guest_up_above", "guest_down_equal", "guest_down_below", "legacy_up_equal", "legacy_down_equal"} {
		t.Run(name, func(t *testing.T) {
			p, now := guestAdministrativeUnit(t)
			p.UpHoldSeconds, p.DownHoldSeconds, p.CooldownSeconds = 0, 1, 0
			p.Signals[0].UpAbove, p.Signals[0].DownBelow = 3, 0.25
			_, a := fixture(now)
			a.Snapshot.TargetIdentity, a.Snapshot.Owner, a.Snapshot.Profile, a.Snapshot.Units = p.TargetIdentity, p.Owner, p.Profiles[0].Name, 4
			e := &a.Evidence[0]
			e.Name, e.SourceIdentity, e.Unit = p.Signals[0].Name, p.Signals[0].SourceIdentity, p.Signals[0].Unit
			e.WindowStart, e.MaxGapSeconds, e.Samples = now.Add(-time.Minute), 5, 13
			value := 3.0
			switch name {
			case "guest_up_above":
				value = 3.01
			case "guest_down_equal":
				value = 0.25
			case "guest_down_below":
				value = 0.24
			case "legacy_up_equal", "legacy_down_equal":
				p, a = fixture(now)
				p.UpHoldSeconds, p.DownHoldSeconds, p.CooldownSeconds = 0, 1, 0
				value = p.Signals[0].UpAbove
				if name == "legacy_down_equal" {
					value = p.Signals[0].DownBelow
				}
			}
			a = refresh(a, now, value)
			d, err := Assess(p, a, model.CapacityClockState{}, now)
			if err != nil {
				t.Fatal(err)
			}
			later := now.Add(2 * time.Second)
			a = refresh(a, later, value)
			d, err = Assess(p, a, d.Clock, later)
			want := "hold"
			if name == "guest_up_above" || name == "legacy_up_equal" {
				want = "expand"
			}
			if name == "guest_down_below" || name == "legacy_down_equal" {
				want = "drain"
			}
			if err != nil || d.Action != want {
				t.Fatal("strict Guest/inclusive legacy boundary changed", name, d.Action, err)
			}
		})
	}
}

// Actual complete metric ranges and controller cadence are independent. These
// declared synthetic observations exercise the planner only, not SQL or a VM.
func TestOriginalGuestReconcileCadenceAndRangeClocksSeparate(t *testing.T) {
	for _, mode := range []string{"up_sixty_cadence", "down_five_minutes", "controller_gap_expired", "range_gap", "sparse_range", "short_range", "range_not_low", "missing_range", "legacy_sixty_gap"} {
		t.Run(mode, func(t *testing.T) {
			p, now := guestAdministrativeUnit(t)
			p.MaxEvidenceAgeSeconds, p.MinSamples = 120, 61
			p.Signals[0].UpAbove, p.Signals[0].DownBelow = 3, 0.25
			_, a := fixture(now)
			a.Snapshot.TargetIdentity, a.Snapshot.Owner, a.Snapshot.Profile, a.Snapshot.Units = p.TargetIdentity, p.Owner, p.Profiles[0].Name, 4
			e := &a.Evidence[0]
			e.Name, e.SourceIdentity, e.Unit = p.Signals[0].Name, p.Signals[0].SourceIdentity, p.Signals[0].Unit
			e.WindowStart, e.MaxGapSeconds, e.Samples = now.Add(-300*time.Second), 5, 61
			value := 3.01
			if mode == "down_five_minutes" || mode == "short_range" || mode == "range_not_low" {
				value = 0.24
			}
			if mode == "legacy_sixty_gap" {
				p, a = fixture(now)
				p.MaxSampleGapSeconds = 10
				value = 0.9
				a.Evidence[0].MaxGapSeconds = 5
				a.Evidence[0].WindowStart = now.Add(-300 * time.Second)
			}
			a = refresh(a, now, value)
			d, err := Assess(p, a, model.CapacityClockState{}, now)
			if err != nil || d.Action != "hold" {
				t.Fatal("initial hysteresis changed", d, err)
			}
			steps := 1
			if mode == "down_five_minutes" || mode == "short_range" || mode == "range_not_low" {
				steps = 5
			}
			for i := 1; i <= steps; i++ {
				at := now.Add(time.Duration(i) * 60 * time.Second)
				if mode == "controller_gap_expired" {
					at = now.Add(121 * time.Second)
				}
				a = refresh(a, at, value)
				a.Evidence[0].WindowStart = at.Add(-300 * time.Second)
				switch mode {
				case "range_gap":
					a.Evidence[0].MaxGapSeconds = 11
				case "sparse_range":
					a.Evidence[0].Samples = 60
				case "short_range":
					a.Evidence[0].WindowStart = at.Add(-30 * time.Second)
				case "range_not_low":
					v := 0.25
					a.Evidence[0].RangeMax = &v
				case "missing_range":
					a.Evidence[0].Value, a.Evidence[0].RangeMin, a.Evidence[0].RangeMax = nil, nil, nil
				}
				d, err = Assess(p, a, d.Clock, at)
				if err != nil {
					t.Fatal(err)
				}
				if i < steps && d.Action != "hold" {
					t.Fatal("hysteresis completed early", d)
				}
			}
			want := "hold"
			if mode == "up_sixty_cadence" {
				want = "expand"
			}
			if mode == "down_five_minutes" {
				want = "drain"
			}
			if d.Action != want {
				t.Fatal("range/cadence clocks confused", mode, d.Action, d.Reason)
			}
		})
	}
}

func TestOriginalGuestReconcileCoverageWindowOwnsSampleMinimum(t *testing.T) {
	for _, mode := range []string{"coverage_seven_demand_sixty_one", "too_few_coverage", "too_short_coverage", "partial_roster", "coverage_gap", "stale_source"} {
		t.Run(mode, func(t *testing.T) {
			_, p, _, now := guestReconcileUnit(t)
			p.MinSamples, p.MaxSampleGapSeconds = 61, 10
			b := p.GuestNotifyReconcileBinding.MemberCoverage
			value := 2.0
			r := model.CapacityMetricRangeObservation{CapacityEvidence: model.CapacityEvidence{Name: OriginalGuestMemberCoverageName, SourceIdentity: "production/notify/aws/reporting-members", Unit: "members", RequireData: true, Matched: true, DataState: "present", Value: &value, RangeMin: &value, RangeMax: &value, SourceSampledAt: now, WindowStart: now.Add(-30 * time.Second), WindowEnd: now, Samples: 7, CoverageComplete: true, MaxGapSeconds: 5}, Operation: ObserveMetricRange, Binding: b.BindingName, BindingSHA256: b.BindingSHA256, EvaluatedAt: now, OK: true, Reason: "complete"}
			switch mode {
			case "too_few_coverage":
				r.Samples = 4
			case "too_short_coverage":
				r.WindowStart = now.Add(-10 * time.Second)
			case "partial_roster":
				value = 1
			case "coverage_gap":
				r.MaxGapSeconds = 11
			case "stale_source":
				r.SourceSampledAt = now.Add(-time.Minute)
			}
			if (GuestReconcileMemberCoverage(p, r, 2, now) == nil) != (mode == "coverage_seven_demand_sixty_one") {
				t.Fatal("coverage borrowed demand samples or dropped quality", mode)
			}
		})
	}
}
