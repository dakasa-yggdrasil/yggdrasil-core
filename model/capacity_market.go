package model

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"time"
)

var capacityMarketJSONKey = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// CapacityMarketBinding is stable operator policy. Refreshing observations must
// never rewrite this binding or the demand policy fingerprint.
type CapacityMarketBinding struct {
	Mode                     string                                 `json:"mode"`
	GrowthMode               string                                 `json:"growth_mode"`
	WorkloadShapeSHA256      string                                 `json:"workload_shape_sha256"`
	HorizonSeconds           int64                                  `json:"horizon_seconds"`
	BudgetMode               string                                 `json:"budget_mode"`
	BudgetScope              string                                 `json:"budget_scope"`
	BudgetMicros             int64                                  `json:"budget_micros"`
	MaxQuoteAgeSeconds       int                                    `json:"max_quote_age_seconds"`
	MaxQuotaAgeSeconds       int                                    `json:"max_quota_age_seconds"`
	MaxEligibilityAgeSeconds int                                    `json:"max_eligibility_age_seconds"`
	MinSavingsMicros         int64                                  `json:"min_savings_micros"`
	MinSavingsBasisPoints    int                                    `json:"min_savings_basis_points"`
	EconomicHoldSeconds      int                                    `json:"economic_hold_seconds"`
	MinResidenceSeconds      int                                    `json:"min_residence_seconds"`
	Profiles                 []CapacityMarketProfileBinding         `json:"profiles"`
	LegacyAllocators         []CapacityMarketLegacyAllocatorBinding `json:"legacy_allocators,omitempty"`
}

type CapacityMarketAdapterBinding struct {
	ManifestID        string `json:"manifest_id"`
	Version           int    `json:"version"`
	Checksum          string `json:"checksum"`
	IntegrationTypeID string `json:"integration_type_id"`
	TypeChecksum      string `json:"type_checksum"`
}

type CapacityMarketProfileBinding struct {
	Profile                      string                                `json:"profile"`
	Provider                     string                                `json:"provider"`
	Region                       string                                `json:"region"`
	Adapter                      CapacityMarketAdapterBinding          `json:"adapter"`
	PhysicalSpecSHA256           string                                `json:"physical_spec_sha256"`
	WorkloadShapeSHA256          string                                `json:"workload_shape_sha256"`
	Architecture                 string                                `json:"architecture"`
	BillingStopCondition         string                                `json:"billing_stop_condition"`
	ReviewedCostSourceIdentities []string                              `json:"reviewed_cost_source_identities,omitempty"`
	MaxUnreservedAttempts        int                                   `json:"max_unreserved_attempts"`
	QuotaDimensions              []CapacityMarketQuotaDimensionBinding `json:"quota_dimensions"`
	QuoteSourceIdentity          string                                `json:"quote_source_identity"`
	QuotaSourceIdentity          string                                `json:"quota_source_identity"`
	RegistrationBindingSHA       string                                `json:"registration_binding_sha256"`
	NetworkBindingSHA            string                                `json:"network_binding_sha256"`
}

type CapacityMarketQuotaDimensionBinding struct {
	Scope     string `json:"scope"`
	Dimension string `json:"dimension"`
	PerUnit   int64  `json:"per_unit"`
}

// Observations are supplied only by the protected collector. Matching these
// public identities is necessary but is not authentication of a caller's JSON.
type CapacityMarketAssessment struct {
	Schema         string                             `json:"schema"`
	Currency       string                             `json:"currency"`
	HorizonSeconds int64                              `json:"horizon_seconds"`
	ObservedAt     time.Time                          `json:"observed_at"`
	ValidUntil     time.Time                          `json:"valid_until"`
	Profiles       []CapacityMarketProfileQuote       `json:"profiles"`
	Unavailable    []CapacityMarketUnavailableProfile `json:"unavailable,omitempty"`
}

// This is a Core collector outcome, not fabricated provider price/stock data.
type CapacityMarketUnavailableProfile struct {
	Profile    string                       `json:"profile"`
	Provider   string                       `json:"provider"`
	Region     string                       `json:"region"`
	Adapter    CapacityMarketAdapterBinding `json:"adapter"`
	Reason     string                       `json:"reason"`
	ObservedAt time.Time                    `json:"observed_at"`
}

type CapacityMarketProfileQuote struct {
	Profile                     string                        `json:"profile"`
	Provider                    string                        `json:"provider"`
	Region                      string                        `json:"region"`
	Adapter                     CapacityMarketAdapterBinding  `json:"adapter"`
	PhysicalSpecSHA256          string                        `json:"physical_spec_sha256"`
	WorkloadShapeSHA256         string                        `json:"workload_shape_sha256"`
	Architecture                string                        `json:"architecture"`
	BillingStopCondition        string                        `json:"billing_stop_condition"`
	WorkloadQualified           bool                          `json:"workload_qualified"`
	ValidationRef               string                        `json:"validation_ref"`
	ValidationValidUntil        time.Time                     `json:"validation_valid_until"`
	QualificationEvidenceSHA256 string                        `json:"qualification_evidence_sha256"`
	SourceIdentity              string                        `json:"source_identity"`
	EvidenceSHA256              string                        `json:"evidence_sha256"`
	ObservedAt                  time.Time                     `json:"observed_at"`
	ValidUntil                  time.Time                     `json:"valid_until"`
	AllInComplete               bool                          `json:"all_in_complete"`
	Costs                       []CapacityMarketCostComponent `json:"costs"`
	Quotas                      []CapacityMarketQuota         `json:"quotas"`
	Stock                       CapacityMarketEligibility     `json:"stock"`
	Registration                CapacityMarketEligibility     `json:"registration"`
	Network                     CapacityMarketEligibility     `json:"network"`
}

// Every cost covers the assessment's exact horizon. Quantity and PriceQuantity
// use the same explicitly documented billing unit. Minimum and quantum apply
// to Quantity before rational conversion to currency micros, rounded upward.
// Scope is per_unit or fixed; fixed overlap/migration costs are charged once
// when units are nonzero. ChargeCapMicros is zero for no cap, or the verified
// remaining applicable billing-cycle cap; it is never an assumed free month.
// State is known, not_applicable (all numeric fields zero), or unknown.
type CapacityMarketCostComponent struct {
	Name             string    `json:"name"`
	State            string    `json:"state"`
	Scope            string    `json:"scope"`
	BillingUnit      string    `json:"billing_unit"`
	Quantity         int64     `json:"quantity"`
	MinimumQuantity  int64     `json:"minimum_quantity"`
	QuantumQuantity  int64     `json:"quantum_quantity"`
	PriceMicros      int64     `json:"price_micros"`
	PriceQuantity    int64     `json:"price_quantity"`
	ChargeCapMicros  int64     `json:"charge_cap_micros"`
	Basis            string    `json:"basis"`
	SourceIdentity   string    `json:"source_identity"`
	EvidenceSHA256   string    `json:"evidence_sha256"`
	ValidUntil       time.Time `json:"valid_until"`
	LowerBoundMicros int64     `json:"lower_bound_micros"`
}

// Usage is current provider consumption, including current registered units.
// Reservations not yet reflected there are independently supplied by Core's
// locked ledger and are never accepted from this wire observation.
type CapacityMarketQuota struct {
	Dimension      string    `json:"dimension"`
	Scope          string    `json:"scope"`
	State          string    `json:"state"`
	SourceIdentity string    `json:"source_identity"`
	EvidenceSHA256 string    `json:"evidence_sha256"`
	Limit          int64     `json:"limit"`
	Used           int64     `json:"used"`
	PerUnit        int64     `json:"per_unit"`
	ObservedAt     time.Time `json:"observed_at"`
	ValidUntil     time.Time `json:"valid_until"`
}

// Stock states are offered_unreserved (bounded launch attempt, no stock
// guarantee), reserved (an independently bound real reservation), unavailable
// or unknown. Registration/network states are eligible/ineligible/unknown.
// Stock MaxUnits limits additional attempts; registration/network are absolute
// eligible pool units. Unknown never means unlimited or zero demand.
type CapacityMarketEligibility struct {
	State          string    `json:"state"`
	MaxUnits       int       `json:"max_units"`
	BindingSHA256  string    `json:"binding_sha256"`
	EvidenceSHA256 string    `json:"evidence_sha256"`
	ReservationRef string    `json:"reservation_ref,omitempty"`
	ObservedAt     time.Time `json:"observed_at"`
	ValidUntil     time.Time `json:"valid_until"`
}

// CapacityMarketReservation is written by Core under its existing global
// capacity transaction lock. Assessment JSON cannot supply a reservation.
type CapacityMarketReservation struct {
	Schema              string                           `json:"schema"`
	Profile             string                           `json:"profile"`
	Provider            string                           `json:"provider"`
	Region              string                           `json:"region"`
	Currency            string                           `json:"currency"`
	BudgetScope         string                           `json:"budget_scope"`
	Units               int                              `json:"units"`
	CostMicros          int64                            `json:"cost_micros"`
	HorizonSeconds      int64                            `json:"horizon_seconds"`
	QuoteEvidenceSHA256 string                           `json:"quote_evidence_sha256"`
	ObservedAt          time.Time                        `json:"observed_at"`
	Quotas              []CapacityMarketQuotaReservation `json:"quotas"`
}

// Old allocators remain separate owners. This immutable mapping describes
// only the shared provider quota they consume, never authority to run them.
type CapacityMarketLegacyAllocatorBinding struct {
	IntegrationInstanceID string                             `json:"integration_instance_id"`
	ScopeChecksum         string                             `json:"scope_checksum"`
	ProfileName           string                             `json:"profile_name"`
	Namespace             string                             `json:"namespace"`
	Environment           string                             `json:"environment"`
	Domain                string                             `json:"domain"`
	Dimension             string                             `json:"dimension"`
	Quotas                []CapacityMarketLegacyQuotaBinding `json:"quotas"`
}

type CapacityMarketLegacyQuotaBinding struct {
	Provider  string `json:"provider"`
	Region    string `json:"region"`
	Scope     string `json:"scope"`
	Dimension string `json:"dimension"`
	PerUnit   int64  `json:"per_unit"`
}

type CapacityMarketQuotaReservation struct {
	Provider  string `json:"provider"`
	Region    string `json:"region"`
	Scope     string `json:"scope"`
	Dimension string `json:"dimension"`
	Amount    int64  `json:"amount"`
}

func (v *CapacityMarketBinding) UnmarshalJSON(raw []byte) error {
	type plain CapacityMarketBinding
	var out plain
	if err := decodeCapacityMarketJSON(raw, &out); err != nil {
		return err
	}
	*v = CapacityMarketBinding(out)
	return nil
}

func (v *CapacityMarketAssessment) UnmarshalJSON(raw []byte) error {
	type plain CapacityMarketAssessment
	var out plain
	if err := decodeCapacityMarketJSON(raw, &out); err != nil {
		return err
	}
	*v = CapacityMarketAssessment(out)
	return nil
}

// Public capacity observations forbid nulls, duplicate keys, unknown fields,
// trailing values and unbounded nesting before semantic validation.
func decodeCapacityMarketJSON(raw []byte, out any) error {
	if len(raw) == 0 || len(raw) > 2<<20 {
		return fmt.Errorf("bounded capacity market JSON required")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 24 {
			return fmt.Errorf("capacity market JSON nesting exceeded")
		}
		t, err := d.Token()
		if err != nil || t == nil {
			return fmt.Errorf("nonnull capacity market JSON required")
		}
		if delim, ok := t.(json.Delim); ok {
			seen := map[string]bool{}
			for d.More() {
				if delim == '{' {
					key, e := d.Token()
					s, ok := key.(string)
					if e != nil || !ok || !capacityMarketJSONKey.MatchString(s) || seen[s] {
						return fmt.Errorf("duplicate capacity market JSON field")
					}
					seen[s] = true
				}
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
			_, err = d.Token()
			return err
		}
		return nil
	}
	if err := walk(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return fmt.Errorf("trailing capacity market JSON")
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	return d.Decode(out)
}
