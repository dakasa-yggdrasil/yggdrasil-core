package repository

import (
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// An observed dispatch ACK acknowledges the original failed workflow's return.
// It does not change an uncertain provider settlement into an accepted create.
// The unknown/NULL-ACK lane retains its exact V1 representation.
func nativeDeniedDispatchSchema(job CapacityDispatchJob) (string, bool) {
	if job.State == "unknown" && job.FinalizationAckAt == nil {
		return model.NativeDeniedDispositionSchema, true
	}
	if job.State == "returned" && job.FinalizationAckAt != nil && job.ReturnedAt != nil && job.LeaseExpiresAt != nil &&
		!job.FinalizationAckAt.Before(*job.ReturnedAt) && job.FinalizationAckAt.Before(*job.LeaseExpiresAt) {
		return model.NativeDeniedReturnedACKDispositionSchema, true
	}
	return "", false
}

func nativeDeniedDispositionACKMatches(v model.CapacityNativeDeniedDisposition, actual *time.Time) bool {
	switch v.Schema {
	case model.NativeDeniedDispositionSchema:
		return actual == nil && v.OriginalUnknownACKPreserved && v.OriginalDispatchState == "" && v.OriginalFinalizationACKAt == nil && !v.OriginalFailedWorkflowACKPreserved
	case model.NativeDeniedReturnedACKDispositionSchema:
		return actual != nil && !actual.IsZero() && !v.OriginalUnknownACKPreserved && v.OriginalDispatchState == "returned" && v.OriginalFinalizationACKAt != nil &&
			v.OriginalFinalizationACKAt.Equal(*actual) && v.OriginalFailedWorkflowACKPreserved
	default:
		return false
	}
}
