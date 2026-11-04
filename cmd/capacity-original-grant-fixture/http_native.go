//go:build linux && capacitytest && nativequalification

package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/dakasa-yggdrasil/yggdrasil-core/controllers/httpapi"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

func syntheticHTTPCallbacks(ctx context.Context, db *sql.DB, source string) (bool, error) {
	input, err := prepareSyntheticWithBaseline(ctx, db, source, 2, 2, 3)
	if err != nil {
		return false, err
	}
	policy, err := repository.GetManifestByID(ctx, db, input.PolicyID)
	if err != nil {
		return false, err
	}
	workflow, err := repository.GetManifestByID(ctx, db, input.WorkflowID)
	if err != nil {
		return false, err
	}
	binding, step, _, err := approved(policy, workflow, input, source)
	if err != nil {
		return false, err
	}
	var baseline int
	if input.Slot != 3 || binding.ProtectedSlots != 2 || db.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_resource_slots WHERE namespace=$1 AND resource_id<>''`, policy.Metadata.Namespace).Scan(&baseline) != nil || baseline != 2 {
		return false, errors.New("synthetic HTTP baseline must contain two registered protected slots")
	}
	var selected *model.CapacityMutationSpecV1
	for _, slot := range binding.Slots {
		if slot.Slot == input.Slot {
			selected = slot.DesiredSpec
		}
	}
	if selected == nil {
		return false, errors.New("synthetic HTTP slot missing")
	}
	spec, err := json.Marshal(selected)
	if err != nil {
		return false, err
	}
	store := repository.CapacityStore{DB: db, ExecutionEnabled: true, WorkflowID: input.WorkflowID, ExecutorID: input.ExecutorID}.WithOriginalGuestProvisioning(step, source, input.NonceSHA256)
	grant, err := store.IssueMutation(ctx, policy, input.Generation, input.Fence, input.LeaseOwner, model.CapacityMutationIssue{BindingName: binding.Name, DesiredSpec: spec})
	if err != nil {
		return false, err
	}
	if grant.Slot != 3 {
		return false, errors.New("synthetic HTTP grant must target slot three")
	}
	if err = httpapi.AssertSyntheticCapacityHTTP(db, grant, binding.AdapterPrincipalID, input.LeaseOwner, input.ExecutorID); err != nil {
		return false, err
	}
	return true, nil
}
