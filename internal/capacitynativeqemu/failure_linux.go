//go:build linux && nativequalification

package capacitynativeqemu

import (
	"context"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"time"
)

type QualificationFailedOwnerReturn struct {
	OriginalReturnedAt time.Time `json:"original_returned_at"`
	OriginalBodySHA256 string    `json:"original_body_sha256"`
	OriginalBodyBytes  int       `json:"original_body_bytes"`
	ErrorClass         string    `json:"error_class"`
}
type QualificationProvisioningRecordRead struct {
	Sequence                int       `json:"sequence"`
	OriginalRecordSHA256    string    `json:"original_record_sha256"`
	OriginalReadReturnedAt  time.Time `json:"original_read_returned_at"`
	OriginalCloseReturnedAt time.Time `json:"original_close_returned_at"`
}
type QualificationProvisioningJournalRead struct {
	LastSequence            int                                   `json:"last_sequence"`
	LastState               string                                `json:"last_state"`
	LastRecordSHA256        string                                `json:"last_record_sha256"`
	EnrollmentSHA256        string                                `json:"enrollment_sha256"`
	AdmissionPossible       bool                                  `json:"admission_possible"`
	AdmissionWriteReturned  bool                                  `json:"admission_write_returned"`
	OriginalReadStartedAt   time.Time                             `json:"original_read_started_at"`
	OriginalReadReturnedAt  time.Time                             `json:"original_read_returned_at"`
	OriginalCloseReturnedAt time.Time                             `json:"original_close_returned_at"`
	Records                 []QualificationProvisioningRecordRead `json:"records"`
}
type CanonicalPayloadPreparation struct {
 Schema string `json:"schema"`
 ActionID string `json:"action_id"`
 SessionNonceSHA256 string `json:"session_nonce_sha256"`
 PreregistrationID string `json:"preregistration_id"`
 ParentGrantID string `json:"parent_grant_id"`
 CreateWitnessSHA256 string `json:"create_witness_sha256"`
 GuestSource string `json:"guest_source"`
 PreparedAt time.Time `json:"prepared_at"`
 OriginalWriteReturnedAt time.Time `json:"original_write_returned_at"`
 OriginalReadReturnedAt time.Time `json:"original_read_returned_at"`
 OriginalBodySHA256 string `json:"original_body_sha256"`
}
type QualificationFailureRecord struct {
 OriginalPayloadPreparation *CanonicalPayloadPreparation `json:"original_payload_preparation,omitempty"`
 OriginalPayloadActionID string `json:"original_payload_action_id,omitempty"`
 OriginalPayloadSessionNonceSHA256 string `json:"original_payload_session_nonce_sha256,omitempty"`
	Schema                        string                                        `json:"schema"`
	NativeCase                    string                                        `json:"native_case"`
	SourceCommit                  string                                        `json:"source_commit"`
	Scope                         string                                        `json:"scope"`
	Phase                         string                                        `json:"phase"`
	Tuple                         model.CapacityGuestNativeTuple                `json:"tuple"`
	PreregistrationID             string                                        `json:"preregistration_id"`
	OriginalCreateWitnessSHA256   string                                        `json:"original_create_witness_sha256"`
	OriginalProvisioningDeadline  time.Time                                     `json:"original_provisioning_deadline"`
	OriginalOperationDeadline     time.Time                                     `json:"original_operation_deadline"`
	OriginalProbeChallengeSHA256  string                                        `json:"original_probe_challenge_sha256,omitempty"`
	Runtime                       model.CapacityGuestRetirementLifetime         `json:"runtime"`
	OriginalChild                 model.CapacityGuestRetirementNativeProcess    `json:"original_child"`
	OriginalStartCalledAt         time.Time                                     `json:"original_start_called_at"`
	OriginalStartReturnedAt       time.Time                                     `json:"original_start_returned_at"`
	OriginalWait                  QualificationFailedOwnerReturn                `json:"original_wait"`
	OriginalExitCode              *int                                          `json:"original_exit_code"`
	OriginalOutputEOF *bool `json:"original_output_eof,omitempty"`
	OriginalOutputCloseSucceeded *bool `json:"original_output_close_succeeded,omitempty"`
	OriginalDiagnosticEOF *bool `json:"original_diagnostic_eof,omitempty"`
	OriginalDiagnosticCloseSucceeded *bool `json:"original_diagnostic_close_succeeded,omitempty"`
	OriginalOutputEOFAndClose     QualificationFailedOwnerReturn                `json:"original_output_eof_and_close"`
	OriginalDiagnosticEOFAndClose QualificationFailedOwnerReturn                `json:"original_diagnostic_eof_and_close"`
	OriginalProbeRead             *QualificationFailedOwnerReturn               `json:"original_probe_read,omitempty"`
	ProvisioningJournal           *QualificationProvisioningJournalRead         `json:"provisioning_journal,omitempty"`
	CensusAfter                   *model.CapacityGuestRetirementProtectedCensus `json:"census_after,omitempty"`
	NativeCensusErrorClass        string                                        `json:"native_census_error_class"`
	RecordedAt                    time.Time                                     `json:"recorded_at"`
	ProducerPublicKey             string                                        `json:"producer_public_key"`
	Signature                     string                                        `json:"signature"`
}

// A failed owner diagnostic proves its authentic partial returns only. It
// never supplies enrollment/noStart/quiescence or poweroff/delete authority.
func (r *Realm) ValidateOriginalFailure(record QualificationFailureRecord, pre model.CapacityGuestOriginalProvisioningPreregistration, witness model.CapacityGuestOriginalCreateWitness, producerPublic string, now time.Time) error {
	_, err := r.ValidateOriginalFailureClassified(record, pre, witness, producerPublic, now)
	return err
}

// ValidateOriginalFailureClassified identifies only the failed closed guard group.
// Labels describe the same refusal and never authorize or retain the record.
func (r *Realm) ValidateOriginalFailureClassified(record QualificationFailureRecord, pre model.CapacityGuestOriginalProvisioningPreregistration, witness model.CapacityGuestOriginalCreateWitness, producerPublic string, now time.Time) (string, error) {
	if PositiveCase(r.Request.NativeCase) || record.Schema != "original_qualification_failed_owner_returns_v1" || record.NativeCase != r.Request.NativeCase || record.SourceCommit != r.Request.SourceCommit || record.Scope != "failed_original_owners_diagnostic_not_capacity_admission_or_quiescence" || record.Phase == "" || record.Tuple != witness.Tuple || record.PreregistrationID != pre.PreregistrationID || record.OriginalCreateWitnessSHA256 != capacity.GuestRetirementSHA(witness) || !record.OriginalProvisioningDeadline.Equal(pre.OriginalDeadline) || record.OriginalOperationDeadline.IsZero() || record.OriginalOperationDeadline.After(r.Request.OriginalContextDeadline) || record.Runtime.PID < 2 || record.Runtime.StartTicks < 1 || record.Runtime.SourceCommit != r.Request.SourceCommit || record.Runtime.BinarySHA256 != r.Profile.OwnerBinarySHA256 || record.OriginalChild.PID < 2 || record.OriginalChild.StartTicks < 1 || record.OriginalStartCalledAt.Before(witness.ObservedAt) || record.OriginalStartReturnedAt.Before(record.OriginalStartCalledAt) || record.RecordedAt.After(now) || record.RecordedAt.Before(record.OriginalStartReturnedAt) || record.ProducerPublicKey != producerPublic || record.OriginalExitCode == nil {
		return "source_refusal_identity", ErrOriginalUnknown
	}
	signature := record.Signature
	record.Signature = ""
	if !verifySignature(producerPublic, signature, record) {
		return "source_refusal_signature", ErrOriginalUnknown
	}
	facts := []QualificationFailedOwnerReturn{record.OriginalWait, record.OriginalOutputEOFAndClose, record.OriginalDiagnosticEOFAndClose}
	if record.OriginalProbeRead != nil {
		facts = append(facts, *record.OriginalProbeRead)
	}
	for _, fact := range facts {
		if fact.OriginalReturnedAt.IsZero() || fact.OriginalReturnedAt.Before(record.OriginalStartReturnedAt) || fact.OriginalReturnedAt.After(record.RecordedAt) || !validSHA(fact.OriginalBodySHA256) || fact.OriginalBodyBytes < 0 || fact.OriginalBodyBytes > capacity.GuestBootstrapLimit || (fact.ErrorClass != "none" && fact.ErrorClass != "original_owner_error") {
			return "source_refusal_owners", ErrOriginalUnknown
		}
	}
	if r.Request.NativeCase == "cancelled_probe_original_join" && record.OriginalProbeRead == nil {
		return "source_refusal_probe", ErrOriginalUnknown
	}
	if stage, err := validateOriginalFailureCaseClassified(record); err != nil {
		return stage, err
	}
	if record.CensusAfter == nil && record.NativeCensusErrorClass != "original_census_error" {
		return "source_refusal_census", ErrOriginalUnknown
	}
	if record.CensusAfter != nil && record.NativeCensusErrorClass != "" {
		return "source_refusal_census", ErrOriginalUnknown
	}
	return "", nil
}

func (r *Realm) OriginalPreregistration(slot int) (model.CapacityGuestOriginalProvisioningPreregistration, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	pre, ok := r.preregistrations[slot]
	if !ok {
		return pre, ErrOriginalUnknown
	}
	return pre, nil
}
func (r *Realm) FreshOriginalNative(ctx context.Context, slot int) (IndependentReturn, error) {
	r.mu.Lock()
	native, ok := r.originals[slot]
	r.mu.Unlock()
	if !ok {
		return IndependentReturn{}, ErrOriginalUnknown
	}
	read, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return Observe(read, SlotDirectory(r.PrivateDirectory, slot), native.Original, r.QEMUBinarySHA256)
}
