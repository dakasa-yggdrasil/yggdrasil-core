//go:build linux && nativequalification

package capacitynativeqemu

func validateOriginalFailureCase(record QualificationFailureRecord) error {
	_, err := validateOriginalFailureCaseClassified(record)
	return err
}

func validateOriginalFailureCaseClassified(record QualificationFailureRecord) (string, error) {
	j := record.ProvisioningJournal
	if j == nil || j.LastSequence < 1 || j.LastSequence > 6 || len(j.Records) != j.LastSequence || !validSHA(j.LastRecordSHA256) || j.OriginalReadStartedAt.Before(record.OriginalWait.OriginalReturnedAt) || j.OriginalReadReturnedAt.Before(j.OriginalReadStartedAt) || j.OriginalCloseReturnedAt.Before(j.OriginalReadReturnedAt) || j.OriginalCloseReturnedAt.After(record.RecordedAt) {
		return "source_refusal_journal", ErrOriginalUnknown
	}
	previous := j.OriginalReadStartedAt
	for n, item := range j.Records {
		if item.Sequence != n+1 || !validSHA(item.OriginalRecordSHA256) || item.OriginalReadReturnedAt.Before(previous) || item.OriginalCloseReturnedAt.Before(item.OriginalReadReturnedAt) || item.OriginalCloseReturnedAt.After(j.OriginalReadReturnedAt) {
			return "source_refusal_journal", ErrOriginalUnknown
		}
		previous = item.OriginalCloseReturnedAt
	}
	if j.Records[len(j.Records)-1].OriginalRecordSHA256 != j.LastRecordSHA256 {
		return "source_refusal_journal", ErrOriginalUnknown
	}
	late := !record.OriginalWait.OriginalReturnedAt.Before(record.OriginalOperationDeadline) && !record.OriginalOutputEOFAndClose.OriginalReturnedAt.Before(record.OriginalOperationDeadline) && record.OriginalWait.ErrorClass == "original_owner_error" && record.OriginalOutputEOFAndClose.ErrorClass == "original_owner_error"
	switch record.NativeCase {
	case "held_hello_original_deadline":
		if record.Phase != "original_preownership_failure" || !record.OriginalOperationDeadline.Equal(record.OriginalProvisioningDeadline) || !late || j.LastSequence != 1 || j.LastState != "possible_profile_start" || j.EnrollmentSHA256 != "" || j.AdmissionPossible || j.AdmissionWriteReturned {
			return "source_refusal_case", ErrOriginalUnknown
		}
	case "held_ack_after_owned_original_deadline":
		if record.Phase != "original_withdraw_held" || !late || j.LastSequence != 6 || j.LastState != "admitted" || !validSHA(j.EnrollmentSHA256) || !j.AdmissionPossible || !j.AdmissionWriteReturned {
			return "source_refusal_case", ErrOriginalUnknown
		}
	case "held_probe_body_original_deadline":
		if record.Phase != "original_probe_held" || !validSHA(record.OriginalProbeChallengeSHA256) || !late || j.LastSequence != 6 || j.LastState != "admitted" || !validSHA(j.EnrollmentSHA256) || !j.AdmissionPossible || !j.AdmissionWriteReturned {
			return "source_refusal_case", ErrOriginalUnknown
		}
	case "cancelled_probe_original_join":
		if record.Phase != "original_probe_held" || !validSHA(record.OriginalProbeChallengeSHA256) || record.OriginalProbeRead == nil || record.OriginalProbeRead.ErrorClass != "none" || record.OriginalProbeRead.OriginalBodyBytes == 0 || !record.OriginalProbeRead.OriginalReturnedAt.Before(record.OriginalOperationDeadline) || record.OriginalWait.OriginalReturnedAt.Before(record.OriginalProbeRead.OriginalReturnedAt) || !record.OriginalWait.OriginalReturnedAt.Before(record.OriginalOperationDeadline) || j.LastSequence != 6 || j.LastState != "admitted" || !validSHA(j.EnrollmentSHA256) || !j.AdmissionPossible || !j.AdmissionWriteReturned {
			return "source_refusal_case", ErrOriginalUnknown
		}
	case "canonical_postloss_unprotected_failed_create_reissue", "canonical_postloss_protected_failed_create_reissue", "canonical_compensation_unprotected_failed_create", "canonical_compensation_protected_failed_create", "canonical_failed_floor_recovery", "failed_owner_after_enrollment", "compensation_unprotected_failed_create", "compensation_protected_failed_create", "source_live_failed_floor_recovery":
		// A known source child exit is diagnostic-only. The original positive
		// retirement still requires successful Withdraw/Wait and is unchanged.
		if record.Phase != "original_probe_failed_owner_exit" || record.OriginalExitCode == nil || *record.OriginalExitCode != 1 || record.OriginalWait.ErrorClass != "original_owner_error" || !record.OriginalWait.OriginalReturnedAt.Before(record.OriginalOperationDeadline) || !record.OriginalOutputEOFAndClose.OriginalReturnedAt.Before(record.OriginalOperationDeadline) || !record.OriginalDiagnosticEOFAndClose.OriginalReturnedAt.Before(record.OriginalOperationDeadline) || record.OriginalOutputEOF == nil || !*record.OriginalOutputEOF || record.OriginalOutputCloseSucceeded == nil || !*record.OriginalOutputCloseSucceeded || record.OriginalDiagnosticEOF == nil || !*record.OriginalDiagnosticEOF || record.OriginalDiagnosticCloseSucceeded == nil || !*record.OriginalDiagnosticCloseSucceeded || j.LastSequence != 6 || j.LastState != "admitted" || !validSHA(j.EnrollmentSHA256) || !j.AdmissionPossible || !j.AdmissionWriteReturned || record.CensusAfter == nil || record.CensusAfter.SourceCommit != record.SourceCommit || !validSHA(record.CensusAfter.RawCensusSHA256) || record.CensusAfter.ObservedAt.Before(record.OriginalWait.OriginalReturnedAt) || record.CensusAfter.ObservedAt.Before(record.OriginalOutputEOFAndClose.OriginalReturnedAt) || record.CensusAfter.ObservedAt.Before(record.OriginalDiagnosticEOFAndClose.OriginalReturnedAt) || record.CensusAfter.ObservedAt.After(record.RecordedAt) {
			return "source_refusal_case", ErrOriginalUnknown
		}
		for _, process := range record.CensusAfter.Processes {
			if process.PID == record.OriginalChild.PID && process.StartTicks == record.OriginalChild.StartTicks {
				return "source_refusal_case", ErrOriginalUnknown
			}
		}
	case "admission_bind_cancelled_original":
		if (record.Phase != "original_preownership_failure" && record.Phase != "original_provisioning_held") || !record.OriginalWait.OriginalReturnedAt.Before(record.OriginalProvisioningDeadline) || j.LastSequence != 5 || j.LastState != "admission_possible" || !validSHA(j.EnrollmentSHA256) || !j.AdmissionPossible || j.AdmissionWriteReturned {
			return "source_refusal_case", ErrOriginalUnknown
		}
	default:
		return "source_refusal_case", ErrOriginalUnknown
	}
	return "", nil
}
