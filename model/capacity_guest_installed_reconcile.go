package model

// CapacityInstalledGuestReconcile links a fresh readiness epoch to an unchanged
// installed original. It does not assert that an old held canary had no effect.
type CapacityInstalledGuestReconcile struct {
	Attempt                             int                                    `json:"attempt"`
	PreviousFence                       int64                                  `json:"previous_fence"`
	PreviousResumeRunID                 string                                 `json:"previous_resume_run_id,omitempty"`
	PreviousResumeRunSHA256             string                                 `json:"previous_resume_run_sha256,omitempty"`
	Schema                              string                                 `json:"schema"`
	OriginalJobID                       string                                 `json:"original_job_id"`
	OriginalRunID                       string                                 `json:"original_run_id"`
	OriginalRunSHA256                   string                                 `json:"original_run_sha256"`
	PreregistrationID                   string                                 `json:"preregistration_id"`
	EnrollmentSHA256                    string                                 `json:"enrollment_sha256"`
	InstallationSHA256                  string                                 `json:"installation_sha256"`
	OriginalGeneration                  int64                                  `json:"original_generation"`
	OriginalFence                       int64                                  `json:"original_fence"`
	NewFence                            int64                                  `json:"new_fence"`
	NewRunID                            string                                 `json:"new_run_id"`
	NewExecutorID                       string                                 `json:"new_executor_id"`
	PreviousCanaries                    []CapacityInstalledGuestPreviousCanary `json:"previous_canaries"`
	OriginalFailurePreserved            bool                                   `json:"original_failure_preserved"`
	OriginalQuiescenceOrNoEffectClaimed bool                                   `json:"original_quiescence_or_no_effect_claimed"`
}

type CapacityInstalledGuestPreviousCanary struct {
	ChallengeID      string `json:"challenge_id"`
	Phase            string `json:"phase"`
	PossibleSend     bool   `json:"possible_send"`
	Outcome          string `json:"outcome"`
	ClosedHTTPStatus int    `json:"closed_HTTP_status"`
	// An incomplete historical GET is still unknown, never an accepted
	// return or a claim that the original operation had no effect.
	OriginalTransportState  string `json:"original_transport_state,omitempty"`
	OriginalTransportSHA256 string `json:"original_transport_sha256,omitempty"`
}
