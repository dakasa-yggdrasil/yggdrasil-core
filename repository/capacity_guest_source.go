package repository

import (
	"context"
	"database/sql"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// The private source executor resolves its own just-issued grant. No external
// callback exposes a grant-to-preregistration selector or supplies its tuple.
func (s CapacityStore) OriginalGuestProvisioning(ctx context.Context, grantID string) (model.CapacityGuestOriginalProvisioningPreregistration, error) {
	var result model.CapacityGuestOriginalProvisioningPreregistration
	var id string
	if err := s.DB.QueryRowContext(ctx, `SELECT id::text FROM public.capacity_vm_provisioning_preregistrations WHERE create_grant_id=$1`, grantID).Scan(&id); err != nil {
		return result, err
	}
	err := s.guestStoredTransaction(ctx, id, func(tx *sql.Tx, stored guestOriginalStored, now time.Time) error {
		if stored.pre.ExecutorID != s.ExecutorID || stored.pre.WorkflowID != s.WorkflowID.String() || stored.pre.OriginalCreateGrantID != grantID {
			return ErrCapacityMutationAuthorization
		}
		if _, _, err := s.guestCurrentTx(ctx, tx, stored, now, true); err != nil {
			return err
		}
		result = stored.pre
		return nil
	})
	return result, err
}
