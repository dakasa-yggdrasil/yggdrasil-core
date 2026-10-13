package model

// CapacityVMRetirementObservation is the closed GET-only provider readback of
// one original destroy receipt. It is independent of Guest writer quiescence,
// a powered-off machine, invoice reconciliation and new mutation authority.
// The owning protected consumer rechecks every field against the immutable
// original receipt; RetirementComplete alone never frees a reserved slot.
type CapacityVMRetirementObservation struct {
	CapacityVMNativeTuple
	DestroyGrantID             string                           `json:"destroy_grant_id"`
	DestroyGrantState          string                           `json:"destroy_grant_state"`
	CompensationOf             string                           `json:"compensation_of,omitempty"`
	OriginalOutcome            string                           `json:"original_outcome"`
	OriginalTransportCompleted bool                             `json:"original_transport_completed"`
	ServerAbsent               bool                             `json:"server_absent"`
	ServerAbsenceComplete      bool                             `json:"server_absence_complete"`
	ServerStatus               string                           `json:"server_status,omitempty"`
	ServerObservedAt           string                           `json:"server_observed_at"`
	DeleteAction               CapacityVMRetirementAction       `json:"delete_action"`
	NextActions                []CapacityVMActionObservation    `json:"next_actions"`
	AuxiliaryResources         []CapacityVMAuxiliaryObservation `json:"auxiliary_resources"`
	AuxiliaryInventoryComplete bool                             `json:"auxiliary_inventory_complete"`
	BillableResourcesAbsent    bool                             `json:"billable_resources_absent"`
	BillingExposure            *CapacityVMBillingExposure       `json:"billing_exposure,omitempty"`
	RetirementComplete         bool                             `json:"retirement_complete"`
	HoldReasons                []string                         `json:"hold_reasons"`
	InvoiceReconciled          bool                             `json:"invoice_reconciled"`
	WriterQuiescenceEvidence   bool                             `json:"writer_quiescence_evidence"`
	ProviderFencingEvidence    bool                             `json:"provider_fencing_evidence"`
	ObservationStartedAt       string                           `json:"observation_started_at"`
	ObservedAt                 string                           `json:"observed_at"`
}

// Known retains the main delete ID of the owning original settlement. A GET
// cannot discover a lost identity and retroactively authorize that original.
type CapacityVMRetirementAction struct {
	Known      bool   `json:"known"`
	Observed   bool   `json:"observed"`
	ID         string `json:"id,omitempty"`
	Status     string `json:"status,omitempty"`
	Command    string `json:"command,omitempty"`
	StartedAt  string `json:"started_at,omitempty"`
	FinishedAt string `json:"finished_at,omitempty"`
	ErrorCode  string `json:"error_code,omitempty"`
}

// The fixed admission profile models only a bounded exposure ceiling. These
// fields are never an invoice, a billed amount, a DAU or useful-capacity proof.
type CapacityVMBillingExposure struct {
	Basis                        string                             `json:"basis"`
	Currency                     string                             `json:"currency"`
	WindowStart                  string                             `json:"window_start"`
	WindowEndUpperBound          string                             `json:"window_end_upper_bound"`
	WindowEndSource              string                             `json:"window_end_source"`
	Resources                    []CapacityVMBillableResourceWindow `json:"resources"`
	StartedHoursUpperBound       int64                              `json:"started_hours_upper_bound"`
	CalendarMonthsUpperBound     int64                              `json:"calendar_months_upper_bound"`
	GrossHourlyCeilingMicros     int64                              `json:"gross_hourly_ceiling_micros"`
	GrossMonthlyCeilingMicros    int64                              `json:"gross_monthly_ceiling_micros"`
	HourlyCeilingTotalMicros     int64                              `json:"hourly_ceiling_total_micros"`
	MonthlyCapCeilingTotalMicros int64                              `json:"monthly_cap_ceiling_total_micros"`
	GrossCeilingMicrosUpperBound int64                              `json:"gross_ceiling_micros_upper_bound"`
	IncludesPrimaryIPv4          bool                               `json:"includes_primary_ipv4"`
	ExcludedCosts                []string                           `json:"excluded_costs"`
}

type CapacityVMBillableResourceWindow struct {
	Kind                   string `json:"kind"`
	ID                     string `json:"id"`
	WindowStart            string `json:"window_start"`
	WindowStartSource      string `json:"window_start_source"`
	WindowEndUpperBound    string `json:"window_end_upper_bound"`
	WindowEndSource        string `json:"window_end_source"`
	StartedHoursUpperBound int64  `json:"started_hours_upper_bound"`
}
