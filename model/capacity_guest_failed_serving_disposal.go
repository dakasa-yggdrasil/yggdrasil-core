package model

// A closed operator CAS request. Every native identity and proof is derived
// from the retained original records; this body grants no provider write.
type CapacityFailedServingGuestDisposalRequest struct {
	PreregistrationID string `json:"preregistration_id"`
	PolicyID          string `json:"policy_id"`
	PolicyChecksum    string `json:"policy_checksum"`
	Generation        int64  `json:"generation"`
	FencingToken      int64  `json:"fencing_token"`
	IntentSHA256      string `json:"intent_sha256"`
}

// This reference freezes an original that previously served. It never claims
// zero historical usefulness, application drain or absence of business effects.
type CapacityFailedServingDisposal struct {
	ID                   string `json:"id"`
	PreregistrationID    string `json:"preregistration_id"`
	OriginalIntentSHA256 string `json:"original_intent_sha256"`
	Stage                string `json:"stage"`
}
