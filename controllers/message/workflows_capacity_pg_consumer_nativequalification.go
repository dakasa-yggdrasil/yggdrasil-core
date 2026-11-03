//go:build linux && nativequalification

package message

import (
	"context"
	"path/filepath"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacitynativeqemu"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
)

// Consume the existing twenty real callback returns at the original caller.
// This is a same-DB assertion, not a profile, caller authority or Native claim.
// No callback, effect, timer, producer output or public schema is added.
func guestOriginalConsumeRedemption(ctx context.Context, store repository.CapacityStore, policy model.Manifest, input guestOriginalStepInput, grant model.CapacityMutationGrant) error {
	if originalGuestNativeRealm == nil || store.DB == nil || ctx.Err() != nil || input.Slot < 1 || input.Slot > 2 || grant.Slot != input.Slot {
		return errOriginalGuestStep
	}
	type fact struct {
		AttemptID           string    `json:"attempt_id"`
		Mode                string    `json:"mode"`
		StartedAt           time.Time `json:"started_at"`
		ReturnedAt          time.Time `json:"returned_at"`
		TypedResponseSHA256 string    `json:"typed_response_sha256"`
	}
	var contract struct {
		Schema     string `json:"schema"`
		CoreSource string `json:"core_source"`
		Slot       int    `json:"slot"`
		GrantID    string `json:"grant_id"`
		WriteOnce  int    `json:"write_once"`
		ReadOnly   int    `json:"read_only"`
		Facts      []fact `json:"facts"`
		ReplayMode string `json:"same_attempt_replay_mode"`
		ReplaySHA  string `json:"same_attempt_typed_response_sha256"`
	}
	if _, err := capacitynativeqemu.ReadPrivate(ctx, filepath.Join(capacitynativeqemu.SlotDirectory(originalGuestNativeRealm.PrivateDirectory, input.Slot), "redemption-concurrency-contract.json"), &contract); err != nil {
		return err
	}
	if contract.Schema != "original_guest_redemption_concurrency_v1" || contract.CoreSource != capacity.CurrentGuestCoreSource() || contract.Slot != input.Slot || contract.GrantID != grant.GrantID || contract.WriteOnce != 1 || contract.ReadOnly != 19 || len(contract.Facts) != 20 || contract.ReplayMode != "read_only" {
		return errOriginalGuestStep
	}
	seen := make(map[string]bool, 20)
	winner := ""
	writes, reads := 0, 0
	for _, row := range contract.Facts {
		if _, err := uuid.Parse(row.AttemptID); err != nil || seen[row.AttemptID] || row.StartedAt.IsZero() || row.ReturnedAt.Before(row.StartedAt) {
			return errOriginalGuestStep
		}
		seen[row.AttemptID] = true
		switch row.Mode {
		case "write_once":
			writes++
			winner = row.AttemptID
		case "read_only":
			reads++
		default:
			return errOriginalGuestStep
		}
		response := model.CapacityMutationRedeemResponse{Mode: row.Mode, GrantID: grant.GrantID, AttemptID: row.AttemptID, RequestSHA256: grant.RequestSHA256, ExpiresAt: grant.ExpiresAt.Format(time.RFC3339Nano), CompensationOf: grant.CompensationOf}
		if capacity.GuestRetirementSHA(response) != row.TypedResponseSHA256 {
			return errOriginalGuestStep
		}
	}
	if writes != 1 || reads != 19 {
		return errOriginalGuestStep
	}
	replay := model.CapacityMutationRedeemResponse{Mode: "read_only", GrantID: grant.GrantID, AttemptID: winner, RequestSHA256: grant.RequestSHA256, ExpiresAt: grant.ExpiresAt.Format(time.RFC3339Nano), CompensationOf: grant.CompensationOf}
	if capacity.GuestRetirementSHA(replay) != contract.ReplaySHA {
		return errOriginalGuestStep
	}
	// This is the exact SQL connection already used by the original protected
	// workflow. Do not infer database identity from an environment variable.
	var state, attempt, request, recordPolicy, checksum string
	if err := store.DB.QueryRowContext(ctx, `SELECT state,grant_record->>'attempt_id',grant_record->'grant'->>'request_sha256',grant_record->>'policy_id',grant_record->>'policy_checksum' FROM public.capacity_mutation_grants WHERE id=$1 AND namespace=$2`, grant.GrantID, policy.Metadata.Namespace).Scan(&state, &attempt, &request, &recordPolicy, &checksum); err != nil {
		return err
	}
	if state != "confirmed" || attempt != winner || request != grant.RequestSHA256 || recordPolicy != policy.ID.String() || checksum != policy.Checksum {
		return errOriginalGuestStep
	}
	var preregistrations int
	if err := store.DB.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_vm_provisioning_preregistrations WHERE create_grant_id=$1`, grant.GrantID).Scan(&preregistrations); err != nil {
		return err
	}
	if preregistrations != 1 || ctx.Err() != nil {
		return errOriginalGuestStep
	}
	return nil
}
