//go:build !nativequalification

package message

import (
	"context"
	"database/sql"
	"encoding/json"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	amqp "github.com/rabbitmq/amqp091-go"
	"time"
)

// An independently bounded native absence read feeds a new failed terminal
// ledger. It neither deletes a resource nor repairs the old workflow return.
func RecordEnrolledFailedOriginalDisposition(parent context.Context, db *sql.DB, conn *amqp.Connection, grantID, jobID, issuer string) (model.CapacityEnrolledFailedOriginalDisposition, error) {
	var empty model.CapacityEnrolledFailedOriginalDisposition
	if parent == nil || db == nil || conn == nil || issuer == "" {
		return empty, errOriginalCreateDisposition
	}
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	store := repository.CapacityStore{DB: db}
	owner, err := store.BeginEnrolledFailedOriginalDisposition(ctx, grantID, jobID, issuer)
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
	var returnedStatus string
	var returnedOutput any
	switch provider {
	case "aws":
		fixed["schema"] = "aws_original_enrolled_failed_create_absence_read_request_v1"
		returned, callErr := executeEnrolledFailedReadonly(ctx, observer, fixed)
		err = callErr
		returnedStatus, returnedOutput = returned.Status, returned.Output
	case "hetzner":
		returned, callErr := executeIntegrationThroughResolvedWithPolicy(ctx, conn, model.ExecuteIntegrationRequest{Operation: originalCreateDispositionOperation, Capability: originalCreateDispositionOperation, Input: fixed}, observer.instance, observer.instanceSpec, observer.typ, observer.typeSpec, 25*time.Second, integrationExecutionPolicy{originalCreateDisposition: true, detailFreeErrors: true, safeError: errOriginalCreateDisposition, requireExplicitResponse: true, nativeHTTP: &nativeAdapterHTTPPolicy{limit: 2 << 20, parent: ctx}})
		err = callErr
		returnedStatus, returnedOutput = returned.Status, returned.Output
	default:
		return empty, errOriginalCreateDisposition
	}
	if err != nil || ctx.Err() != nil || returnedStatus != "observed" {
		return empty, errOriginalCreateDisposition
	}
	var observation model.CapacityOriginalCreateDispositionObservation
	if capacityDecodeDisposition(returnedOutput, &observation) != nil || observation.Provider != provider || observation.AdapterSourceCommit != enrolledFailedObserverSource(provider) {
		return empty, errOriginalCreateDisposition
	}
	// Re-resolve immutable observer identities after the actual read. No public
	// catalog replacement or secret hydration can stand in for this same source.
	after, _, err := resolveEnrolledFailedObserver(ctx, db, conn, candidate)
	if err != nil || after.instance.ID != observer.instance.ID || after.instance.Checksum != observer.instance.Checksum || after.typ.ID != observer.typ.ID || after.typ.Checksum != observer.typ.Checksum {
		return empty, errOriginalCreateDisposition
	}
	return store.CompleteEnrolledFailedOriginalDisposition(ctx, owner, observation)
}
