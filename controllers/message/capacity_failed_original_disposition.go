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
func RecordFailedOriginalDisposition(parent context.Context, db *sql.DB, conn *amqp.Connection, grantID, jobID, issuer string) (model.CapacityFailedOriginalDisposition, error) {
	var empty model.CapacityFailedOriginalDisposition
	if parent == nil || db == nil || conn == nil || issuer == "" {
		return empty, errOriginalCreateDisposition
	}
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	store := repository.CapacityStore{DB: db}
	owner, err := store.BeginFailedOriginalDisposition(ctx, grantID, jobID, issuer)
	if err != nil {
		return empty, err
	}
	candidate := owner.Candidate()
	observer, provider, err := resolveDispositionObserver(ctx, db, conn, candidate)
	if err != nil || provider != "hetzner" {
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
	returned, err := executeIntegrationThroughResolvedWithPolicy(ctx, conn, model.ExecuteIntegrationRequest{Operation: originalCreateDispositionOperation, Capability: originalCreateDispositionOperation, Input: fixed}, observer.instance, observer.instanceSpec, observer.typ, observer.typeSpec, 25*time.Second, integrationExecutionPolicy{originalCreateDisposition: true, detailFreeErrors: true, safeError: errOriginalCreateDisposition, requireExplicitResponse: true, nativeHTTP: &nativeAdapterHTTPPolicy{limit: 2 << 20, parent: ctx}})
	if err != nil || ctx.Err() != nil || returned.Status != "observed" {
		return empty, errOriginalCreateDisposition
	}
	var observation model.CapacityOriginalCreateDispositionObservation
	if capacityDecodeDisposition(returned.Output, &observation) != nil || observation.Provider != provider || observation.AdapterSourceCommit != dispositionObserverSource(provider) {
		return empty, errOriginalCreateDisposition
	}
	// Re-resolve immutable observer identities after the actual read. No public
	// catalog replacement or secret hydration can stand in for this same source.
	after, _, err := resolveDispositionObserver(ctx, db, conn, candidate)
	if err != nil || after.instance.ID != observer.instance.ID || after.instance.Checksum != observer.instance.Checksum || after.typ.ID != observer.typ.ID || after.typ.Checksum != observer.typ.Checksum {
		return empty, errOriginalCreateDisposition
	}
	return store.CompleteFailedOriginalDisposition(ctx, owner, observation)
}
