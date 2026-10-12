package message

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

type capacityReleaseAuthorizationKey struct{}

// In-process server delegation only. This context field is never reconstructed
// from workflow Auth, metadata, alert input or an adapter response.
func WithCapacityReleaseRecoveryAuthorization(ctx context.Context, authorize func(context.Context) error) context.Context {
	return context.WithValue(ctx, capacityReleaseAuthorizationKey{}, authorize)
}

func activateCapacityReleaseRecovery(ctx context.Context) (context.Context, error) {
	if capacityDispatchInvocationFrom(ctx) != nil {
		return ctx, capacityDispatchFence(ctx)
	}
	authorize, ok := ctx.Value(capacityReleaseAuthorizationKey{}).(func(context.Context) error)
	if !ok || authorize == nil {
		return ctx, errCapacityBoundAssessment
	}
	ctx = WithCapacityDispatchFence(ctx, authorize)
	return ctx, capacityDispatchFence(ctx)
}

type capacityReleaseOriginalReply struct {
	Output       map[string]any
	CallerJoined bool
}

// This is an explicit controller branch, not the original unredeemed-token
// retry loop. Every recovery admission has a new durable parent/fence/command.
// Only an original release proven unredeemed may be followed by a new original.
func runCapacityReleaseRecovery(ctx context.Context, store repository.CapacityStore, policy model.Manifest, p model.CapacityPolicySpec, intent model.CapacityIntent, cp model.CapacityNativePodCheckpoint, call capacityBoundPrivateCall, observe func(model.CapacityNativePodCheckpoint) (model.AdapterCapacityPodTerminationResponse, error), hpa func() (model.CapacityHPAEnvelopeResponse, error), inventory func() (model.AdapterCapacityPodInventoryResponse, error)) error {
	deadline, ok := ctx.Deadline()
	if !ok || intent.LeaseExpiresAt == nil || capacityDispatchInvocationFrom(ctx) == nil {
		return errCapacityBoundAssessment
	}
	if intent.LeaseExpiresAt.Before(deadline) {
		deadline = *intent.LeaseExpiresAt
	}
	fence := func() error {
		return errors.Join(capacityDispatchFence(ctx), nativeAdapterContext(ctx), func() error {
			if !time.Now().Before(deadline) {
				return context.DeadlineExceeded
			}
			return nil
		}())
	}
	var parent *model.CapacityNativeCommand
	for remaining := 0; remaining < 4; remaining++ {
		if err := fence(); err != nil {
			return err
		}
		witness, err := observe(cp)
		if err != nil || capacity.NativePodWitness(p, cp, witness.Observation, time.Now().UTC()) != nil {
			return errCapacityBoundAssessment
		}
		if err = store.ConfirmNativePodWitness(ctx, policy, intent, cp.PodUID, witness); err != nil {
			return err
		}
		cp.State, cp.PodResourceVersion = "confirmed", witness.Observation.PodResourceVersion
		base, err := boundPodObservationRequest(p, cp)
		if err != nil {
			return err
		}
		no := false
		req := model.AdapterDestroyCapacityPodDrainProtectionRequest{AdapterObserveCapacityPodTerminationRequest: base, ExpectedPodResourceVersion: cp.PodResourceVersion, DryRun: &no}
		input, err := boundPrivateMap(req)
		if err != nil {
			return err
		}
		raw, err := json.Marshal(input)
		if err != nil {
			return err
		}
		var command model.CapacityNativeCommand
		var token string
		if parent == nil {
			command, token, err = store.IssueNativeCommand(ctx, policy, intent, capacity.DestroyNativePodProtection, cp.PodUID, raw)
		} else {
			// Current full native census and HPA are independent of the failed
			// CAS. No scalar caller proof or old resource version is reused.
			currentHPA, e := hpa()
			if e != nil {
				return e
			}
			currentInventory, e := inventory()
			if e != nil {
				return e
			}
			if err = fence(); err != nil {
				return err
			}
			command, token, err = store.IssueNativeReleaseRecovery(ctx, policy, intent, *parent, raw, currentHPA, currentInventory, witness)
		}
		if err != nil {
			return err
		}
		if err = fence(); err != nil {
			return err
		}
		input["authority_token"] = token
		var original capacityReleaseOriginalReply
		status, callErr := call(p.AssessmentBinding.Snapshot.Adapter, capacity.DestroyNativePodProtection, input, &original)
		if err = fence(); err != nil {
			return err
		}
		if callErr != nil || !original.CallerJoined {
			// An ORIGINAL release refused before redemption (for example a Pod RV
			// that advanced after this witness) is not an uncertain write. The
			// shared redemption lock proves its token unspent and unredeemable,
			// so only a fresh witness may mint the next original permission
			// within the same four permanent identities. A redeemed original
			// and every recovery command keep HOLD.
			// A failed revoke stays in the private cause so it is never mistaken
			// for a proven redemption; both still end in HOLD.
			var revokeErr error
			if parent == nil {
				var refused bool
				refused, revokeErr = store.RevokeUnredeemedNativeCommand(ctx, policy, intent, command.CommandID)
				if revokeErr == nil && refused {
					continue
				}
			}
			_ = store.MarkNativeCommandUncertain(ctx, command.CommandID)
			return capacityDispatchCause(ctx, errors.Join(errCapacityBoundAssessment, callErr, revokeErr))
		}
		if status == "blocked" {
			retained, err := store.AcknowledgeNativeReleaseCaller(ctx, policy, intent, command.CommandID)
			if err != nil {
				return err
			}
			if err = fence(); err != nil {
				return err
			}
			parent = &retained
			continue
		}
		if status != "released" {
			_ = store.MarkNativeCommandUncertain(ctx, command.CommandID)
			return errCapacityBoundAssessment
		}
		// The independent current native readback confirms this NEW command.
		// It cannot confirm or erase its rejected parent.
		after, err := observe(cp)
		if err != nil {
			return err
		}
		if err = fence(); err != nil {
			return err
		}
		return store.ConfirmNativeCommand(ctx, policy, intent, command.CommandID, after)
	}
	return errCapacityBoundAssessment
}
