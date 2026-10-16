//go:build linux && nativequalification

package capacitynativeqemu

// Corpus names only ORIGINAL source rows/artifacts. Fields are not permission
// or fabricated completeness. The owning verifier reads their literal bytes.
type Corpus struct {
	Schema                      string                         `json:"schema"`
	ActualCoreSourceCommit      string                         `json:"actual_core_source_commit"`
	GuestSourceCommit           string                         `json:"guest_source_commit"`
	NativeCase                  string                         `json:"native_case"`
	CaseOutcome                 string                         `json:"case_outcome"`
	PolicyID                    string                         `json:"policy_id"`
	PolicyChecksum              string                         `json:"policy_checksum"`
	WorkflowID                  string                         `json:"workflow_id"`
	WorkflowChecksum            string                         `json:"workflow_checksum"`
	Namespace                   string                         `json:"namespace"`
	ProfileManifestSHA256       string                         `json:"profile_manifest_sha256"`
	OriginalRunIDs              []string                       `json:"original_run_ids"`
	OriginalPreregistrationIDs  []string                       `json:"original_preregistration_ids"`
	NativeResources             []CorpusResource               `json:"native_resources"`
	BurstRetirement             *CorpusRetirement              `json:"burst_retirement,omitempty"`
	BaselineServingProbeSHA256  string                         `json:"baseline_serving_probe_sha256"`
	FailedOwnerDiagnosticSHA256 string                         `json:"failed_owner_diagnostic_sha256,omitempty"`
	FailedRetirementAttempt     *CorpusFailedRetirementAttempt `json:"failed_retirement_attempt,omitempty"`
}
type CorpusFailedRetirementAttempt struct {
	RequestID          string `json:"request_id"`
	IntentSHA256       string `json:"intent_sha256"`
	CallerReturnSHA256 string `json:"caller_return_sha256"`
}
type CorpusResource struct {
	Slot                         int    `json:"slot"`
	ResourceID                   string `json:"resource_id"`
	ResourceCreatedAt            string `json:"resource_created_at"`
	CreatorOriginalSHA256        string `json:"creator_original_sha256"`
	CoreNativeOriginalReadSHA256 string `json:"core_native_original_read_sha256"`
	NativeDiagnosticAfterSHA256  string `json:"native_diagnostic_after_sha256,omitempty"`
	RegistrationSHA256           string `json:"registration_sha256"`
	EnrollmentSHA256             string `json:"enrollment_sha256"`
	ServingProbeSHA256           string `json:"serving_probe_sha256"`
}
type CorpusRetirement struct {
	RequestID                     string   `json:"request_id"`
	IntentSHA256                  string   `json:"intent_sha256"`
	OriginalRecordSHA256s         []string `json:"original_record_sha256s"`
	CallerReturnSHA256            string   `json:"caller_return_sha256"`
	SnapshotChallengeSHA256s      []string `json:"snapshot_challenge_sha256s"`
	AuthorityReadIDs              []string `json:"authority_read_ids"`
	AuthorityTransportReturnCount int      `json:"authority_transport_return_count"`
	NativeOffReturnSHA256         string   `json:"native_off_return_sha256"`
	DestroyGrantID                string   `json:"destroy_grant_id"`
	NativeDeleteReadbackSHA256    string   `json:"native_delete_readback_sha256"`
}
type SourceCaseStage struct {
	Schema                    string `json:"schema"`
	Stage                     string `json:"stage"`
	NativeCase                string `json:"native_case"`
	CaseOutcome               string `json:"case_outcome"`
	NativeCorpusReceiptSHA256 string `json:"native_corpus_receipt_sha256"`
}
