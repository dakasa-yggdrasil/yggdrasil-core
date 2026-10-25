package message

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"net/http"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
)

// Only the backend-admitted disposal of an exact old Guest548 installation may
// use its actual V1 protocol. No workflow input selects a protocol or supplies
// quiescence. Normal production retirement retains the separate V2 owner.
func executeFailedInstalledGuestRetirementV1(ctx context.Context, db *sql.DB, store repository.CapacityStore, policy model.Manifest, p model.CapacityPolicySpec, step model.WorkflowStepSpec, input guestOriginalStepInput, member model.CapacityGuestRetirementMemberBinding, key ed25519.PrivateKey) (any, error) {
	if ctx == nil || ctx.Err() != nil || db == nil || store.DB == nil || p.GuestRetirementBinding == nil || p.GuestRetirementBinding.EvidenceClass != "owned_provisioner_original" || p.GuestNotifyCanaryBinding == nil || input.RequestID != "" {
		return nil, errOriginalGuestStep
	}
	pre, err := uuid.Parse(input.PreregistrationID)
	if err != nil || pre == uuid.Nil || pre.String() != input.PreregistrationID {
		return nil, errOriginalGuestStep
	}
	originalParent, stopParent := context.WithTimeout(ctx, 30*time.Second)
	defer stopParent()
	store = store.WithOriginalGuestNotifyCanary(step, capacity.CurrentGuestCoreSource()).WithOriginalGuestRetirement(step, capacity.CurrentGuestCoreSource())
	legacy, err := store.FailedInstalledGuestLegacyV1(originalParent, policy, input.Generation, input.FencingToken, input.LeaseOwner, input.PreregistrationID)
	if err != nil || !legacy {
		return nil, errOriginalGuestStep
	}
	if err = originalGuestNotifyFloor(originalParent, db, store, policy, p, input, key, "before_retirement_floor"); err != nil {
		return nil, err
	}
	nonce, err := sourceGuestNonce()
	if err != nil {
		return nil, err
	}
	request, err := store.IssueGuestRetirement(originalParent, policy, input.Generation, input.FencingToken, input.LeaseOwner, input.PreregistrationID, nonce, key)
	if err != nil {
		return nil, err
	}
	original, stopOriginal := context.WithDeadline(originalParent, request.Intent.OriginalDeadline)
	defer stopOriginal()
	if err = store.ReserveGuestCaller(original, request); err != nil {
		return nil, err
	}
	client, err := sourceGuestClient(original, db, member)
	if err != nil {
		return nil, err
	}
	defer client.Close()
	body, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	returned, callErr := client.Original(original, http.MethodPost, "/v1/retirement", body)
	var observed model.CapacityGuestRetirementObservation
	decoded := capacity.GuestOriginalHTTPDecode(returned, &observed) == nil
	persisted := false
	retention, stopRetention := context.WithTimeout(context.WithoutCancel(original), 5*time.Second)
	stored, loadErr := store.GuestRetirementOriginal(retention, member.ActorClientPrincipal, request.Intent.RequestID, capacity.GuestRetirementSHA(request.Intent))
	if loadErr == nil {
		persisted = decoded && capacity.GuestRetirementObservedReturnAuthentic(observed, stored.Receipt.Enrollment, request.Intent, observed.ObservedAt)
	}
	retained := repository.GuestOriginalCallerReturn{RequestID: request.Intent.RequestID, AttemptID: request.Intent.AttemptID, StartedAt: returned.StartedAt, DoStartedAt: returned.DoStartedAt, DriverReturnedAt: returned.DriverReturnedAt, PreflightFailed: returned.PreflightFailed, DoReturnedAt: returned.DoReturnedAt, ReadReturnedAt: returned.ReadReturnedAt, CloseReturnedAt: returned.CloseReturnedAt, OriginalDeadline: request.Intent.OriginalDeadline, ReceivedBodyBytes: returned.ReceivedBodyBytes, BodyPersisted: persisted, Status: returned.Status, ResponseSHA256: returned.ResponseSHA256, ResponseBodyScope: returned.ResponseBodyScope, RetainedPrefixBytes: returned.RetainedPrefixBytes, RetainedPrefixSHA256: returned.RetainedPrefixSHA256, DoFailed: returned.DoFailed, ReadFailed: returned.ReadFailed, CloseFailed: returned.CloseFailed, OriginalContextFailed: returned.OriginalContextFailed}
	if persisted {
		retained.Body = returned.Body
	}
	recordErr := store.RecordGuestCallerReturn(retention, retained)
	if persisted && recordErr == nil {
		recordErr = store.RecordGuestObservation(retention, request.Intent.RequestID, observed)
	}
	stopRetention()
	if callErr != nil || recordErr != nil || !persisted {
		return nil, errOriginalGuestStep
	}
	return struct {
		Mode                string                                   `json:"mode"`
		RequestID           string                                   `json:"request_id"`
		IntentSHA256        string                                   `json:"intent_sha256"`
		Observation         model.CapacityGuestRetirementObservation `json:"observation"`
		NativePoweroffKnown bool                                     `json:"native_poweroff_known"`
		OriginalV2Claimed   bool                                     `json:"original_V2_claimed"`
	}{"legacy_guest548_original_v1", request.Intent.RequestID, capacity.GuestRetirementSHA(request.Intent), observed, false, false}, nil
}
