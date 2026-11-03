//go:build !nativequalification

package message

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	amqp "github.com/rabbitmq/amqp091-go"
)

// This owner exposes only three fixed native GET operations. It never claims
// a VM mutation lease, sends Guest work or calls an ensure/destroy capability.
// Every return must complete in this original bounded context; a failed GET
// can only be observed again by a fresh explicit operator request.
func failedServingNativeRead(ctx context.Context, db *sql.DB, conn *amqp.Connection, c model.CapacityOriginalCreateDispositionCandidate, op string, input map[string]any, out any) error {
	if ctx.Err() != nil || (op != capacity.VMObserveInventory && op != capacity.VMObserveServer && op != "observe_ec2_instance") {
		return errOriginalCreateDisposition
	}
	provider := ""
	var p model.CapacityPolicySpec
	if json.Unmarshal(c.OriginalPolicy.Spec, &p) != nil {
		return errOriginalCreateDisposition
	}
	for _, profile := range p.Profiles {
		if profile.Name == c.Binding.ProfileName {
			provider = profile.Provider
		}
	}
	if provider != "aws" && provider != "hetzner" || op == "observe_ec2_instance" && provider != "aws" || op == capacity.VMObserveServer && provider != "hetzner" {
		return errOriginalCreateDisposition
	}
	b := c.Binding
	scope := model.CapacityObservationAdapterBinding{IntegrationInstanceID: b.IntegrationInstanceID, InstanceChecksum: b.IntegrationChecksum, IntegrationTypeID: b.IntegrationTypeID, TypeChecksum: b.IntegrationTypeChecksum}
	a, err := resolveOriginalGuestSupplier(ctx, conn, repository.CapacityStore{DB: db}, scope, b.OriginalProviderSourceCommit, provider)
	if err != nil || !capacityBoundCatalogOperation(a.typeSpec, op) {
		return errOriginalCreateDisposition
	}
	returned, err := executeIntegrationThroughResolvedWithPolicy(ctx, conn, model.ExecuteIntegrationRequest{Operation: op, Capability: op, Input: input}, a.instance, a.instanceSpec, a.typ, a.typeSpec, 25*time.Second, integrationExecutionPolicy{detailFreeErrors: true, safeError: errOriginalCreateDisposition, requireExplicitResponse: true, nativeHTTP: &nativeAdapterHTTPPolicy{limit: 2 << 20, parent: ctx}})
	if err != nil || ctx.Err() != nil || returned.Status != "observed" || capacity.DecodeVMObservation(returned.Output, out) != nil {
		return errOriginalCreateDisposition
	}
	after, err := resolveOriginalGuestSupplier(ctx, conn, repository.CapacityStore{DB: db}, scope, b.OriginalProviderSourceCommit, provider)
	if err != nil || after.instance.ID != a.instance.ID || after.instance.Checksum != a.instance.Checksum || after.typ.ID != a.typ.ID || after.typ.Checksum != a.typ.Checksum {
		return errOriginalCreateDisposition
	}
	return nil
}

type failedServingReads struct {
	inventory func(context.Context, model.CapacityOriginalCreateDispositionCandidate) (model.CapacityVMFleetInventory, error)
	off       func(context.Context, model.CapacityOriginalCreateDispositionCandidate) (model.CapacityVMFleetPlan, error)
	absence   func(context.Context, model.CapacityOriginalCreateDispositionCandidate) (model.CapacityOriginalCreateDispositionObservation, error)
}

// The dependency bundle is private source context, not an HTTP/config option.
// Tests can exercise the same owner/commit path with an actual bounded server;
// production binds only the authenticated registry transports below.
func productionFailedServingReads(db *sql.DB, conn *amqp.Connection) failedServingReads {
	return failedServingReads{
		inventory: func(ctx context.Context, c model.CapacityOriginalCreateDispositionCandidate) (model.CapacityVMFleetInventory, error) {
			var inv model.CapacityVMFleetInventory
			err := failedServingNativeRead(ctx, db, conn, c, capacity.VMObserveInventory, map[string]any{"profile": c.Binding.ProfileName}, &inv)
			return inv, err
		},
		off: func(ctx context.Context, c model.CapacityOriginalCreateDispositionCandidate) (model.CapacityVMFleetPlan, error) {
			var plan model.CapacityVMFleetPlan
			fixed := map[string]any{"profile": c.Binding.ProfileName, "slot": 1, "grant_id": c.Request.GrantID, "expected_resource_id": c.Request.ExpectedResourceID, "expected_resource_created_at": c.Request.ExpectedResourceCreatedAt}
			if c.Preregistration.BindingName == "" {
				return plan, errOriginalCreateDisposition
			}
			var p model.CapacityPolicySpec
			if json.Unmarshal(c.OriginalPolicy.Spec, &p) != nil || len(p.Profiles) != 1 {
				return plan, errOriginalCreateDisposition
			}
			if p.Profiles[0].Provider == "aws" {
				var returned struct {
					Plan      model.CapacityVMFleetPlan          `json:"plan"`
					Lifecycle model.CapacityAWSInstanceLifecycle `json:"lifecycle"`
				}
				err := failedServingNativeRead(ctx, db, conn, c, "observe_ec2_instance", fixed, &returned)
				if err != nil || !originalAWSNativeOffLifecycleJoin(returned.Plan, returned.Lifecycle, c.Receipt.ActionID) {
					return plan, errOriginalCreateDisposition
				}
				return returned.Plan, nil
			}
			err := failedServingNativeRead(ctx, db, conn, c, capacity.VMObserveServer, fixed, &plan)
			return plan, err
		},
		absence: func(ctx context.Context, c model.CapacityOriginalCreateDispositionCandidate) (model.CapacityOriginalCreateDispositionObservation, error) {
			var observed model.CapacityOriginalCreateDispositionObservation
			a, provider, err := resolveEnrolledFailedObserver(ctx, db, conn, c)
			if err != nil {
				return observed, errOriginalCreateDisposition
			}
			raw, err := json.Marshal(c.Request)
			if err != nil {
				return observed, errOriginalCreateDisposition
			}
			var fixed map[string]any
			if json.Unmarshal(raw, &fixed) != nil {
				return observed, errOriginalCreateDisposition
			}
			var status string
			var output any
			switch provider {
			case "aws":
				fixed["schema"] = "aws_original_enrolled_failed_create_absence_read_request_v1"
				returned, callErr := executeEnrolledFailedReadonly(ctx, a, fixed)
				err = callErr
				status, output = returned.Status, returned.Output
			case "hetzner":
				returned, callErr := executeIntegrationThroughResolvedWithPolicy(ctx, conn, model.ExecuteIntegrationRequest{Operation: originalCreateDispositionOperation, Capability: originalCreateDispositionOperation, Input: fixed}, a.instance, a.instanceSpec, a.typ, a.typeSpec, 25*time.Second, integrationExecutionPolicy{originalCreateDisposition: true, detailFreeErrors: true, safeError: errOriginalCreateDisposition, requireExplicitResponse: true, nativeHTTP: &nativeAdapterHTTPPolicy{limit: 2 << 20, parent: ctx}})
				err = callErr
				status, output = returned.Status, returned.Output
			default:
				return observed, errOriginalCreateDisposition
			}
			if err != nil || ctx.Err() != nil || status != "observed" || capacityDecodeDisposition(output, &observed) != nil || observed.Provider != provider || observed.AdapterSourceCommit != enrolledFailedObserverSource(provider) {
				return observed, errOriginalCreateDisposition
			}
			after, _, err := resolveEnrolledFailedObserver(ctx, db, conn, c)
			if err != nil || after.instance.ID != a.instance.ID || after.instance.Checksum != a.instance.Checksum || after.typ.ID != a.typ.ID || after.typ.Checksum != a.typ.Checksum {
				return observed, errOriginalCreateDisposition
			}
			return observed, nil
		},
	}
}

func RequestFailedServingGuestQuarantine(parent context.Context, db *sql.DB, conn *amqp.Connection, req model.CapacityFailedServingGuestDisposalRequest, issuer string) (repository.FailedServingGuestDisposal, error) {
	if parent == nil || db == nil || conn == nil {
		return repository.FailedServingGuestDisposal{}, errOriginalCreateDisposition
	}
	return requestFailedServingGuestQuarantine(parent, repository.CapacityStore{DB: db}, req, issuer, productionFailedServingReads(db, conn))
}

func requestFailedServingGuestQuarantine(parent context.Context, store repository.CapacityStore, req model.CapacityFailedServingGuestDisposalRequest, issuer string, reads failedServingReads) (repository.FailedServingGuestDisposal, error) {
	var empty repository.FailedServingGuestDisposal
	ctx, stop := context.WithTimeout(parent, 30*time.Second)
	defer stop()
	owner, err := store.BeginFailedServingGuestQuarantine(ctx, req, issuer)
	if err != nil {
		return empty, err
	}
	if reads.inventory == nil {
		return empty, errOriginalCreateDisposition
	}
	inv, err := reads.inventory(ctx, owner.Candidate())
	if err != nil || ctx.Err() != nil {
		return empty, errOriginalCreateDisposition
	}
	return store.CompleteFailedServingGuestQuarantine(ctx, owner, inv)
}

func ObserveFailedServingGuestNativeOff(parent context.Context, db *sql.DB, conn *amqp.Connection, preID, admissionID, issuer string) (repository.FailedServingGuestDisposal, error) {
	if parent == nil || db == nil || conn == nil {
		return repository.FailedServingGuestDisposal{}, errOriginalCreateDisposition
	}
	return observeFailedServingGuest(parent, repository.CapacityStore{DB: db}, preID, admissionID, issuer, "off", productionFailedServingReads(db, conn))
}

func CompleteFailedServingGuestAbsence(parent context.Context, db *sql.DB, conn *amqp.Connection, preID, admissionID, issuer string) (repository.FailedServingGuestDisposal, error) {
	if parent == nil || db == nil || conn == nil {
		return repository.FailedServingGuestDisposal{}, errOriginalCreateDisposition
	}
	return observeFailedServingGuest(parent, repository.CapacityStore{DB: db}, preID, admissionID, issuer, "absence", productionFailedServingReads(db, conn))
}

func observeFailedServingGuest(parent context.Context, store repository.CapacityStore, preID, admissionID, issuer, mode string, reads failedServingReads) (repository.FailedServingGuestDisposal, error) {
	var empty repository.FailedServingGuestDisposal
	ctx, stop := context.WithTimeout(parent, 30*time.Second)
	defer stop()
	owner, err := store.BeginFailedServingGuestObservation(ctx, preID, admissionID, issuer, mode)
	if err != nil {
		return empty, err
	}
	c := owner.Candidate()
	if mode == "off" {
		if reads.off == nil {
			return empty, errOriginalCreateDisposition
		}
		plan, err := reads.off(ctx, c)
		if err != nil || ctx.Err() != nil {
			return empty, errOriginalCreateDisposition
		}
		return store.CompleteFailedServingGuestNativeOff(ctx, owner, plan)
	}
	if reads.absence == nil || reads.inventory == nil {
		return empty, errOriginalCreateDisposition
	}
	observed, err := reads.absence(ctx, c)
	if err != nil || ctx.Err() != nil {
		return empty, errOriginalCreateDisposition
	}
	inv, err := reads.inventory(ctx, c)
	if err != nil || ctx.Err() != nil {
		return empty, errOriginalCreateDisposition
	}
	return store.CompleteFailedServingGuestAbsence(ctx, owner, observed, inv)
}
