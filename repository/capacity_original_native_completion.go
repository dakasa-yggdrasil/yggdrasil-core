package repository

import (
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func successfulOriginalMutationProof(record capacityMutationRecord, proof model.CapacityMutationProof, now time.Time) bool {
	if record.EventProvider == "aws" && capacity.AWSOriginalMutationPair(record.Binding) && record.Grant.Capability == record.Binding.EnsureCapability && record.Grant.CompensationOf == "" {
		if record.Settlement == nil || !capacity.AWSOriginalCreateLifecycleComplete(record.Binding, record.Grant, record.Settlement, proof, now) {
			return false
		}
		_, err := capacity.ValidateOriginalAWSCreateReturn(record.Binding, record.Grant, record.AttemptID, *record.Settlement, record.CreatedAt, now)
		return err == nil
	}
	return proof.AWSInstanceLifecycle == nil && completeMutationActionProof(record, proof) && proof.ActionsSuccessful && !proof.ActionsFailed
}
