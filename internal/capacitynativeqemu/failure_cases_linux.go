//go:build linux && nativequalification

package capacitynativeqemu

func validateOriginalFailureCase(record QualificationFailureRecord) error {
	j := record.ProvisioningJournal
	if j == nil || j.LastSequence < 1 || j.LastSequence > 6 || len(j.Records) != j.LastSequence || !validSHA(j.LastRecordSHA256) || j.OriginalReadStartedAt.Before(record.OriginalWait.OriginalReturnedAt) || j.OriginalReadReturnedAt.Before(j.OriginalReadStartedAt) || j.OriginalCloseReturnedAt.Before(j.OriginalReadReturnedAt) || j.OriginalCloseReturnedAt.After(record.RecordedAt) {
		return ErrOriginalUnknown
	}
	previous := j.OriginalReadStartedAt
	for n, item := range j.Records {
		if item.Sequence != n+1 || !validSHA(item.OriginalRecordSHA256) || item.OriginalReadReturnedAt.Before(previous) || item.OriginalCloseReturnedAt.Before(item.OriginalReadReturnedAt) || item.OriginalCloseReturnedAt.After(j.OriginalReadReturnedAt) {
			return ErrOriginalUnknown
		}
		previous = item.OriginalCloseReturnedAt
	}
	if j.Records[len(j.Records)-1].OriginalRecordSHA256 != j.LastRecordSHA256 {
		return ErrOriginalUnknown
	}
	late := !record.OriginalWait.OriginalReturnedAt.Before(record.OriginalOperationDeadline) && !record.OriginalOutputEOFAndClose.OriginalReturnedAt.Before(record.OriginalOperationDeadline) && record.OriginalWait.ErrorClass == "original_owner_error" && record.OriginalOutputEOFAndClose.ErrorClass == "original_owner_error"
	switch record.NativeCase {
	case "held_hello_original_deadline":
		if record.Phase != "original_preownership_failure" || !record.OriginalOperationDeadline.Equal(record.OriginalProvisioningDeadline) || !late || j.LastSequence != 1 || j.LastState != "possible_profile_start" || j.EnrollmentSHA256 != "" || j.AdmissionPossible || j.AdmissionWriteReturned {
			return ErrOriginalUnknown
		}
	case "held_ack_after_owned_original_deadline":
		if record.Phase != "original_withdraw_held" || !late || j.LastSequence != 6 || j.LastState != "admitted" || !validSHA(j.EnrollmentSHA256) || !j.AdmissionPossible || !j.AdmissionWriteReturned {
			return ErrOriginalUnknown
		}
	case "held_probe_body_original_deadline":
		if record.Phase != "original_probe_held" || !late || j.LastSequence != 6 || j.LastState != "admitted" || !validSHA(j.EnrollmentSHA256) || !j.AdmissionPossible || !j.AdmissionWriteReturned {
			return ErrOriginalUnknown
		}
	case "cancelled_probe_original_join":
		if record.Phase != "original_probe_held" || record.OriginalProbeRead == nil || record.OriginalProbeRead.ErrorClass != "none" || record.OriginalProbeRead.OriginalBodyBytes == 0 || !record.OriginalProbeRead.OriginalReturnedAt.Before(record.OriginalOperationDeadline) || record.OriginalWait.OriginalReturnedAt.Before(record.OriginalProbeRead.OriginalReturnedAt) || !record.OriginalWait.OriginalReturnedAt.Before(record.OriginalOperationDeadline) || j.LastSequence != 6 || j.LastState != "admitted" || !validSHA(j.EnrollmentSHA256) || !j.AdmissionPossible || !j.AdmissionWriteReturned {
			return ErrOriginalUnknown
		}
	case "admission_bind_cancelled_original":
		if (record.Phase != "original_preownership_failure" && record.Phase != "original_provisioning_held") || !record.OriginalWait.OriginalReturnedAt.Before(record.OriginalProvisioningDeadline) || j.LastSequence != 5 || j.LastState != "admission_possible" || !validSHA(j.EnrollmentSHA256) || !j.AdmissionPossible || j.AdmissionWriteReturned {
			return ErrOriginalUnknown
		}
	default:
		return ErrOriginalUnknown
	}
	return nil
}
