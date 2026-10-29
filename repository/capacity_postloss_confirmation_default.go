//go:build !linux || !nativequalification

package repository

import (
	"context"
	"database/sql"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// No production source can claim the QEMU-only association.
func (s CapacityStore) canonicalPostlossConfirmationTx(context.Context, *sql.Tx, model.Manifest, model.CapacityPolicySpec, capacityMutationRecord, model.CapacityMutationProof, time.Time) bool {
	return false
}
