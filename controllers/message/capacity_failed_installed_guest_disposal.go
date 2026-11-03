//go:build !nativequalification

package message

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
	amqp "github.com/rabbitmq/amqp091-go"
)

// Distinct installed/quiescent admission; the provider's existing dedicated
// closed GET-only inventory transport is shared without importing the old
// settled/uninstalled eligibility lane. No caller supplies an absence boolean.
func RecordFailedInstalledGuestNativeAbsence(parent context.Context, db *sql.DB, conn *amqp.Connection, preID, admissionID, issuer string) (repository.FailedInstalledGuestDisposal, error) {
	var empty repository.FailedInstalledGuestDisposal
	if parent == nil || db == nil || conn == nil || issuer == "" {
		return empty, errOriginalCreateDisposition
	}
	ctx, stop := context.WithTimeout(parent, 30*time.Second)
	defer stop()
	store := repository.CapacityStore{DB: db}
	owner, err := store.BeginFailedInstalledGuestAbsence(ctx, preID, admissionID, issuer)
	if err != nil {
		return empty, err
	}
	candidate := owner.Candidate()
	observer, provider, err := resolveEnrolledFailedObserver(ctx, db, conn, candidate)
	if err != nil {
		return empty, errOriginalCreateDisposition
	}
	body, err := json.Marshal(candidate.Request)
	if err != nil {
		return empty, errOriginalCreateDisposition
	}
	var fixed map[string]any
	if json.Unmarshal(body, &fixed) != nil {
		return empty, errOriginalCreateDisposition
	}
	var status string
	var output any
	switch provider {
	case "aws":
		fixed["schema"] = "aws_original_enrolled_failed_create_absence_read_request_v1"
		returned, callErr := executeEnrolledFailedReadonly(ctx, observer, fixed)
		err = callErr
		status, output = returned.Status, returned.Output
	case "hetzner":
		returned, callErr := executeIntegrationThroughResolvedWithPolicy(ctx, conn, model.ExecuteIntegrationRequest{Operation: originalCreateDispositionOperation, Capability: originalCreateDispositionOperation, Input: fixed}, observer.instance, observer.instanceSpec, observer.typ, observer.typeSpec, 25*time.Second, integrationExecutionPolicy{originalCreateDisposition: true, detailFreeErrors: true, safeError: errOriginalCreateDisposition, requireExplicitResponse: true, nativeHTTP: &nativeAdapterHTTPPolicy{limit: 2 << 20, parent: ctx}})
		err = callErr
		status, output = returned.Status, returned.Output
	default:
		return empty, errOriginalCreateDisposition
	}
	if err != nil || ctx.Err() != nil || status != "observed" {
		return empty, errOriginalCreateDisposition
	}
	var observed model.CapacityOriginalCreateDispositionObservation
	if capacityDecodeDisposition(output, &observed) != nil || observed.Provider != provider || observed.AdapterSourceCommit != enrolledFailedObserverSource(provider) {
		return empty, errOriginalCreateDisposition
	}
	after, _, err := resolveEnrolledFailedObserver(ctx, db, conn, candidate)
	if err != nil || after.instance.ID != observer.instance.ID || after.instance.Checksum != observer.instance.Checksum || after.typ.ID != observer.typ.ID || after.typ.Checksum != observer.typ.Checksum {
		return empty, errOriginalCreateDisposition
	}
	return store.CompleteFailedInstalledGuestAbsence(ctx, owner, observed)
}

// A failed five-second provider observation may be repeated as a fresh GET.
// The old Guest write, nonce and workflow are never replayed or renewed.
func AdvanceFailedInstalledGuestNativeCleanup(parent context.Context, db *sql.DB, conn *amqp.Connection, preID, admissionID, issuer string) (repository.FailedInstalledGuestDisposal, error) {
	var empty repository.FailedInstalledGuestDisposal
	if parent == nil || db == nil || conn == nil || issuer == "" {
		return empty, errOriginalCreateDisposition
	}
	ctx, stop := context.WithTimeout(parent, 15*time.Second)
	defer stop()
	store := repository.CapacityStore{DB: db, ExecutionEnabled: capacityExecutionEnabled()}
	read, err := store.FailedInstalledGuestRetirementForReadonly(ctx, preID, admissionID)
	if err != nil {
		return empty, err
	}
	if read.LegacyOriginal != nil {
		legacy := read.LegacyOriginal
		store.WorkflowID = uuid.MustParse(legacy.Request.Intent.WorkflowID)
		store.ExecutorID = legacy.ExecutorID
		ctx = context.WithValue(ctx, originalGuestTransportKey{}, originalGuestTransport{conn: conn})
		if err = sourceFailedInstalledGuestLegacyNativeOff(ctx, store, legacy.Request.Intent.RequestID, preID, admissionID); err != nil {
			return empty, err
		}
		return store.AdvanceFailedInstalledGuestCleanup(ctx, preID, admissionID)
	}
	store.WorkflowID = uuid.MustParse(read.Original.Request.Intent.WorkflowID)
	store.ExecutorID = read.Original.ExecutorID
	i := read.Original.Request.Intent
	input := guestOriginalStepInput{BindingName: read.Original.Binding.MutationBindingName, Slot: i.Slot, Generation: int64(i.Generation), FencingToken: int64(i.Fence), LeaseOwner: i.LeaseOwner, PreregistrationID: preID, RequestID: i.RequestID}
	ctx = context.WithValue(ctx, originalGuestTransportKey{}, originalGuestTransport{conn: conn})
	if _, err = sourceProductionGuestNativeOffV2(ctx, store, read.Policy, read.Spec, input, read.Original); err != nil {
		return empty, err
	}
	return store.AdvanceFailedInstalledGuestCleanup(ctx, preID, admissionID)
}
