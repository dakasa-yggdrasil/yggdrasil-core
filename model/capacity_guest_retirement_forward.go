package model

// This request selects retained Core originals; it supplies no native, clock,
// Guest or operator-effect evidence. HTTP accepts exactly these seven fields.
type CapacityGuestRetirementForwardRequest struct {
	PreregistrationID   string `json:"preregistration_id"`
	RetirementRequestID string `json:"retirement_request_id"`
	PolicyID            string `json:"policy_id"`
	PolicyChecksum      string `json:"policy_checksum"`
	Generation          int64  `json:"generation"`
	FencingToken        int64  `json:"fencing_token"`
	IntentSHA256        string `json:"intent_sha256"`
}

// A pointer into an immutable Core ledger, never independent proof of OFF or
// permission to repeat the Guest command. Guest/enrollment DTOs are unchanged.
type CapacityGuestRetirementForwardMarker struct {
	Schema               string `json:"schema"`
	ID                   string `json:"id"`
	RetirementRequestID  string `json:"retirement_request_id"`
	PreregistrationID    string `json:"preregistration_id"`
	Mode                 string `json:"mode"`
	Stage                string `json:"stage"`
	OriginalIntentSHA256 string `json:"original_intent_sha256"`
	OriginalGeneration   int64  `json:"original_generation"`
	OriginalFence        int64  `json:"original_fence"`
}
