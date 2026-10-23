//go:build !nativequalification

package message

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/manifest"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	amqp "github.com/rabbitmq/amqp091-go"
)

// Filled from the independently published observer sources before admission.
// A new observer source never rewrites the historical creator in an old grant.
const originalCreateDispositionAWS1651Source = "5745ceb06e3221c756a3b6a26da1df248b8b4417"
const originalCreateDispositionAWSObserverSource = "56bbed398dfdb4f53a68f8ed8ff6b7fb6ef0f5f9"
const originalCreateDispositionHetznerObserverSource = "6026f78572a0ebfbf1b50984c2d47ff28bdc714d"

var errOriginalCreateDisposition = errors.New("original create disposition unresolved")

func dispositionObserverSource(provider string) string {
	switch provider {
	case "aws":
		return originalCreateDispositionAWSObserverSource
	case "hetzner":
		return originalCreateDispositionHetznerObserverSource
	}
	return ""
}

func dispositionObserverCatalog(provider string, spec model.IntegrationTypeManifestSpec) bool {
	if spec.Provider != provider || manifest.ValidateIntegrationTypeSpec(spec) != nil {
		return false
	}
	if provider == "aws" && (spec.Adapter.Version != "1.65.2" || spec.Adapter.Transport != "http_json" || spec.Adapter.Endpoints.Execute != "/rpc/execute" || spec.Adapter.Endpoints.Describe != "/rpc/describe") {
		return false
	}
	if provider == "hetzner" && (spec.Adapter.Version != "0.3.5" || spec.Adapter.Transport != "rabbitmq") {
		return false
	}
	expectedResource := "server"
	if provider == "aws" {
		expectedResource = "ec2_instance"
	}
	count := 0
	for _, action := range spec.ActionCatalog {
		if action.Name != originalCreateDispositionOperation {
			continue
		}
		if !action.Idempotent || len(action.ResourceTypes) != 1 || action.ResourceTypes[0] != expectedResource || (action.Category != "" && action.Category != "capability") {
			return false
		}
		for _, resource := range spec.ResourceTypes {
			for _, kind := range action.ResourceTypes {
				if kind != resource.Name {
					continue
				}
				for _, allowed := range resource.DefaultActions {
					if allowed == originalCreateDispositionOperation {
						count++
					}
				}
			}
		}
	}
	return count == 1 && len(dispositionObserverSource(provider)) == 40
}

// Resolve the current read observer through the ORIGINAL instance's logical
// identity. Its fresh revision is pinned independently; an inactive original
// creator remains historical, never silently relabelled as the observer.
func resolveDispositionObserver(ctx context.Context, db *sql.DB, conn *amqp.Connection, candidate model.CapacityOriginalCreateDispositionCandidate) (capacityResolvedObservationAdapter, string, error) {
	var empty capacityResolvedObservationAdapter
	original, err := resolveManifestForKind(ctx, db, "integration_instance", candidate.Binding.IntegrationInstanceID, "", "", nil)
	if err != nil || original.ID.String() != candidate.Binding.IntegrationInstanceID || original.Checksum != candidate.Binding.IntegrationChecksum {
		return empty, "", errOriginalCreateDisposition
	}
	current, err := repository.ResolveManifest(ctx, db, "integration_instance", original.Metadata.Namespace, original.Metadata.Name, nil, true)
	if err != nil || !current.Metadata.Active {
		return empty, "", errOriginalCreateDisposition
	}
	instance, err := manifest.ParseIntegrationInstanceSpec(current.Spec)
	if err != nil {
		return empty, "", errOriginalCreateDisposition
	}
	typ, err := resolveManifestForKind(ctx, db, "integration_type", instance.TypeRef.ManifestID, instance.TypeRef.Namespace, instance.TypeRef.Name, instance.TypeRef.Version)
	if err != nil || !typ.Metadata.Active {
		return empty, "", errOriginalCreateDisposition
	}
	spec, err := manifest.ParseIntegrationTypeSpec(typ.Spec)
	if err != nil || !dispositionObserverCatalog(spec.Provider, spec) || !originalGuestSupplierSourceConfigFor(spec.Provider, instance, dispositionObserverSource(spec.Provider)) {
		return empty, "", errOriginalCreateDisposition
	}
	im, is, tm, ts, err := resolveIntegrationInstance(ctx, conn, db, model.ManifestSelector{ManifestID: current.ID.String()})
	if err != nil || !im.Metadata.Active || im.ID != current.ID || im.Checksum != current.Checksum || !tm.Metadata.Active || tm.ID != typ.ID || tm.Checksum != typ.Checksum || !dispositionObserverCatalog(spec.Provider, ts) || !originalGuestSupplierSourceConfigFor(spec.Provider, is, dispositionObserverSource(spec.Provider)) {
		return empty, "", errOriginalCreateDisposition
	}
	return capacityResolvedObservationAdapter{im, is, tm, ts}, spec.Provider, nil
}

// RecordOriginalCreateDisposition is an administrative accounting boundary.
// The HTTP caller supplies only a grant UUID; this function obtains the native
// output itself. It has no ensure, destroy, grant, workflow or Guest operation.
func RecordOriginalCreateDisposition(parent context.Context, db *sql.DB, conn *amqp.Connection, grantID, issuer string) (model.CapacityOriginalCreateDisposition, error) {
	var empty model.CapacityOriginalCreateDisposition
	if parent == nil || db == nil || conn == nil || issuer == "" {
		return empty, errOriginalCreateDisposition
	}
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	store := repository.CapacityStore{DB: db}
	owner, err := store.BeginOriginalCreateDisposition(ctx, grantID, issuer)
	if err != nil {
		return empty, err
	}
	candidate := owner.Candidate()
	observer, provider, err := resolveDispositionObserver(ctx, db, conn, candidate)
	if err != nil {
		return empty, err
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
	return store.CompleteOriginalCreateDisposition(ctx, owner, observation)
}

func capacityDecodeDisposition(value any, out *model.CapacityOriginalCreateDispositionObservation) error {
	// The shared closed decoder rejects unknown and duplicate authority fields.
	return capacity.DecodeVMObservation(value, out)
}
