package model

import "time"

// CapacityPolicySpec is an operator-owned, provider-neutral capacity envelope.
// Price records and validation references are declarations, not live stock receipts.
type CapacityPolicySpec struct {
	Environment           string               `json:"environment"`
	Domain                string               `json:"domain"`
	Dimension             string               `json:"dimension"`
	TargetIdentity        string               `json:"target_identity"`
	Owner                 string               `json:"owner"`
	Workflow              ManifestSelector     `json:"workflow"`
	Currency              string               `json:"currency"`
	Floor                 int                  `json:"floor"`
	Ceiling               int                  `json:"ceiling"`
	Step                  int                  `json:"step"`
	MaxEvidenceAgeSeconds int                  `json:"max_evidence_age_seconds"`
	MinSamples            int                  `json:"min_samples"`
	MaxSampleGapSeconds   int                  `json:"max_sample_gap_seconds"`
	UpHoldSeconds         int                  `json:"up_hold_seconds"`
	DownHoldSeconds       int                  `json:"down_hold_seconds"`
	CooldownSeconds       int                  `json:"cooldown_seconds"`
	LeaseSeconds          int                  `json:"lease_seconds"`
	ExecutionEnabled      bool                 `json:"execution_enabled"`
	Signals               []CapacitySignalRule `json:"signals"`
	Profiles              []CapacityProfile    `json:"profiles"`
}

type CapacitySignalRule struct {
	Name           string  `json:"name"`
	SourceIdentity string  `json:"source_identity"`
	Unit           string  `json:"unit"`
	UpAbove        float64 `json:"up_above"`
	DownBelow      float64 `json:"down_below"`
}

type CapacityProfile struct {
	Name                 string    `json:"name"`
	Provider             string    `json:"provider"`
	Region               string    `json:"region"`
	MinUnits             int       `json:"min_units"`
	MaxUnits             int       `json:"max_units"`
	UnitMonthlyCostMinor int64     `json:"unit_monthly_cost_minor"`
	QuoteValidUntil      time.Time `json:"quote_valid_until"`
	ValidationValidUntil time.Time `json:"validation_valid_until"`
	ValidationRef        string    `json:"validation_ref"`
	ReadinessSeconds     int       `json:"readiness_seconds"`
}

// CapacityEvidence must carry source sample time independently of adapter/query time.
// A PromQL instant-vector value-pair timestamp is not a scrape timestamp.
type CapacityEvidence struct {
	Name             string    `json:"name"`
	SourceIdentity   string    `json:"source_identity"`
	Unit             string    `json:"unit"`
	RequireData      bool      `json:"require_data"`
	Matched          bool      `json:"matched"`
	DataState        string    `json:"data_state"`
	Value            *float64  `json:"value"`
	RangeMin         *float64  `json:"range_min"`
	RangeMax         *float64  `json:"range_max"`
	SourceSampledAt  time.Time `json:"source_sampled_at"`
	WindowStart      time.Time `json:"window_start"`
	WindowEnd        time.Time `json:"window_end"`
	Samples          int       `json:"samples"`
	CoverageComplete bool      `json:"coverage_complete"`
	MaxGapSeconds    int       `json:"max_gap_seconds"`
}

type CapacitySnapshot struct {
	TargetIdentity          string    `json:"target_identity"`
	ResourceUID             string    `json:"resource_uid"`
	WorkloadUID             string    `json:"workload_uid"`
	WorkloadResourceVersion string    `json:"workload_resource_version"`
	ResourceVersion         string    `json:"resource_version"`
	Owner                   string    `json:"owner"`
	Profile                 string    `json:"profile"`
	Units                   int       `json:"units"`
	ObservedAt              time.Time `json:"observed_at"`
}

type CapacityAssessment struct {
	Snapshot CapacitySnapshot   `json:"snapshot"`
	Evidence []CapacityEvidence `json:"evidence"`
}

type CapacityClockState struct {
	PolicyFingerprint       string    `json:"policy_fingerprint"`
	ResourceUID             string    `json:"resource_uid"`
	WorkloadUID             string    `json:"workload_uid"`
	WorkloadResourceVersion string    `json:"workload_resource_version"`
	Profile                 string    `json:"profile"`
	LastObservedAt          time.Time `json:"last_observed_at"`
	LastActionAt            time.Time `json:"last_action_at"`
	UpSince                 time.Time `json:"up_since"`
	DownSince               time.Time `json:"down_since"`
}

type CapacityDecision struct {
	Action             string             `json:"action"`
	Reason             string             `json:"reason"`
	Profile            string             `json:"profile"`
	Units              int                `json:"units"`
	Floor              int                `json:"floor"`
	ExecutionPermitted bool               `json:"execution_permitted"`
	Clock              CapacityClockState `json:"clock"`
}

// CapacityIntent is one durable generation per logical domain/dimension.
type CapacityIntent struct {
	Namespace      string             `json:"namespace"`
	PolicyName     string             `json:"policy_name"`
	PolicyChecksum string             `json:"policy_checksum"`
	Environment    string             `json:"environment"`
	Domain         string             `json:"domain"`
	Dimension      string             `json:"dimension"`
	Generation     int64              `json:"generation"`
	FencingToken   int64              `json:"fencing_token"`
	Phase          string             `json:"phase"`
	LeaseOwner     string             `json:"lease_owner,omitempty"`
	LeaseExpiresAt *time.Time         `json:"lease_expires_at,omitempty"`
	Decision       CapacityDecision   `json:"decision"`
	Assessment     CapacityAssessment `json:"assessment"`
	UpdatedAt      time.Time          `json:"updated_at"`
}

// CapacityTransitionProof is a receipt assembled by the policy's protected
// workflow from provider observations. Core does not generate these receipts
// or infer readiness, canary health, or a completed drain from replica counts.
type CapacityTransitionProof struct {
	Assessment CapacityAssessment `json:"assessment"`
	ObservedAt time.Time          `json:"observed_at"`
	ReceiptRef string             `json:"receipt_ref"`
	Healthy    bool               `json:"healthy"`
	Inflight   int                `json:"inflight"`
}
