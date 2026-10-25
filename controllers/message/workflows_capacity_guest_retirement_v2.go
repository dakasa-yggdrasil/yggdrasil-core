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

func originalGuestNotifyFloor(ctx context.Context, db *sql.DB, store repository.CapacityStore, policy model.Manifest, p model.CapacityPolicySpec, input guestOriginalStepInput, key ed25519.PrivateKey, usage string) error {
	members, err := store.GuestNotifyFloorMembers(ctx, policy, input.Generation, input.FencingToken, input.LeaseOwner, input.Slot)
	if err != nil {
		return err
	}
	for _, member := range members {
		probe := input
		probe.Slot = member.Slot
		probe.PreregistrationID = member.PreregistrationID
		probe.RequestID = ""
		if _, err = executeOriginalGuestNotifyProbeForUsage(ctx, db, store, policy, p, probe, key, usage); err != nil {
			return err
		}
	}
	return nil
}

// Production uses a distinct original clock owner and closed V2 wire. The
// qualification branch continues to use its own V1 source without projection.
func executeProductionGuestRetirementV2(ctx context.Context, db *sql.DB, store repository.CapacityStore, policy model.Manifest, p model.CapacityPolicySpec, step model.WorkflowStepSpec, input guestOriginalStepInput, member model.CapacityGuestRetirementMemberBinding, key ed25519.PrivateKey) (any, error) {
	if capacity.GuestOriginalNativeQEMUProviderEnabled("native-qemu") || p.GuestRetirementBinding == nil || p.GuestRetirementBinding.EvidenceClass != "owned_provisioner_original" || p.GuestNotifyCanaryBinding == nil || input.RequestID != "" {
		return nil, errOriginalGuestStep
	}
	parsed, err := uuid.Parse(input.PreregistrationID)
	if err != nil || parsed.String() != input.PreregistrationID {
		return nil, errOriginalGuestStep
	}
	store = store.WithOriginalGuestNotifyCanary(step, capacity.CurrentGuestCoreSource()).WithOriginalGuestRetirement(step, capacity.CurrentGuestCoreSource())
	if err = originalGuestNotifyFloor(ctx, db, store, policy, p, input, key, "before_retirement_floor"); err != nil {
		return nil, err
	}
	original, err := capacity.NewGuestRetirementV2OriginalOwner(ctx)
	if err != nil {
		return nil, err
	}
	defer original.Close()
	nonce, err := sourceGuestNonce()
	if err != nil {
		return nil, err
	}
	preflight, err := store.IssueGuestRetirementV2(original, policy, input.Generation, input.FencingToken, input.LeaseOwner, input.PreregistrationID, nonce, key)
	if err != nil {
		return nil, err
	}
	enrollment, err := store.GuestNotifyCanaryEnrollment(original.Context(), policy, input.Generation, input.FencingToken, input.LeaseOwner, input.PreregistrationID)
	if err != nil {
		return nil, err
	}
	client, err := sourceGuestClient(original.Context(), db, member)
	if err != nil {
		return nil, err
	}
	defer client.Close()
	if err = original.AcquireNonce(client, key, preflight, enrollment); err != nil {
		return nil, err
	}
	if err = store.FinalizeGuestRetirementV2Nonce(original); err != nil {
		return nil, err
	}
	if err = store.ReserveGuestCallerV2(original); err != nil {
		return nil, err
	}
	request, _, _, err := original.NonceExchange()
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	returned, callErr := client.Original(original.Context(), http.MethodPost, model.GuestRetirementV2WritePath, body)
	var observed model.CapacityGuestRetirementObservationV2
	persisted := capacity.GuestOriginalHTTPDecode(returned, &observed) == nil && capacity.GuestRetirementV2ObservedReturnAuthentic(observed, enrollment, request.Intent)
	retained := repository.GuestOriginalCallerReturn{RequestID: request.Intent.RequestID, AttemptID: request.Intent.AttemptID, StartedAt: returned.StartedAt, DoStartedAt: returned.DoStartedAt, DriverReturnedAt: returned.DriverReturnedAt, PreflightFailed: returned.PreflightFailed, DoReturnedAt: returned.DoReturnedAt, ReadReturnedAt: returned.ReadReturnedAt, CloseReturnedAt: returned.CloseReturnedAt, OriginalDeadline: request.Intent.OriginalDeadline, ReceivedBodyBytes: returned.ReceivedBodyBytes, BodyPersisted: persisted, Status: returned.Status, ResponseSHA256: returned.ResponseSHA256, ResponseBodyScope: returned.ResponseBodyScope, RetainedPrefixBytes: returned.RetainedPrefixBytes, RetainedPrefixSHA256: returned.RetainedPrefixSHA256, DoFailed: returned.DoFailed, ReadFailed: returned.ReadFailed, CloseFailed: returned.CloseFailed, OriginalContextFailed: returned.OriginalContextFailed}
	if persisted {
		retained.Body = returned.Body
	}
	retention, stop := context.WithTimeout(context.WithoutCancel(original.Context()), 5*time.Second)
	recordErr := store.RecordGuestCallerReturnV2(retention, retained)
	if persisted && recordErr == nil {
		recordErr = store.RecordGuestObservationV2(retention, request.Intent.RequestID, observed)
	}
	stop()
	if callErr != nil || recordErr != nil || !persisted || capacity.GuestRetirementV2Observation(observed, enrollment, request.Intent, false) != nil {
		return nil, errOriginalGuestStep
	}
	return struct {
		RequestID           string                                     `json:"request_id"`
		IntentSHA256        string                                     `json:"intent_sha256"`
		Observation         model.CapacityGuestRetirementObservationV2 `json:"observation"`
		NativePoweroffKnown bool                                       `json:"native_poweroff_known"`
	}{request.Intent.RequestID, capacity.GuestRetirementSHA(request.Intent), observed, false}, nil
}
