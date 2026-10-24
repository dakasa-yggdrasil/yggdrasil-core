//go:build !nativequalification

package message

import (
	"context"
	"database/sql"
	"encoding/json"
	"reflect"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/manifest"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	amqp "github.com/rabbitmq/amqp091-go"
)

// Independently published observer compiler source. CI/image/runtime admission
// remains separate, and no historical creator config is relabelled.
const nativeDeniedAWSObserverSource = "c34e330d8b266bb88e29ae7cf7b01df6f9fd96ce"

func nativeDeniedObserverSourceReady(source string) bool {
	if len(source) != 40 || source == originalCreateDispositionAWSObserverSource {
		return false
	}
	for _, c := range source {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// Exact live catalogue changes from reviewed 1.65.4 to 1.65.5 Source. The
// historical envelope is not verified by pretending a 1.65.4 Describe succeeded.
const nativeDeniedAWSObserverVersion = "1.65.5"
const nativeDeniedObserverDescription = "Read-only original create disposition: accepted-tuple resource/auxiliary absence, or the explicit aws_original_authorization_denied_read_request_v1 discriminator proving one original denied RunInstances request and a complete same-client-token instance census. Denied mode does not reconstruct an HTTP response or claim volume/interface absence. No create, terminate, grant, witness, enrollment, business or savings authority."

type nativeDeniedResolvedObserver struct {
	capacityResolvedObservationAdapter
	currentType model.Manifest
}
type nativeDeniedResolverReads struct {
	historical func(context.Context, string, string) (model.Manifest, error)
	current    func(context.Context, string, string) (model.Manifest, error)
	hydrate    func(context.Context, *model.IntegrationInstanceManifestSpec) error
	validate   func(model.IntegrationInstanceManifestSpec, model.IntegrationTypeManifestSpec) error
	handshake  func(context.Context, model.Manifest, model.Manifest, model.IntegrationInstanceManifestSpec, model.IntegrationTypeManifestSpec) error
}

// Compare the ENTIRE public JSON contract. Only these two reviewed values may
// differ. Unknown fields, input examples, routes, schemas or actions cannot be
// silently lost in a permissive typed decoder.
func nativeDeniedCatalogPair(old, current model.Manifest) (model.IntegrationTypeManifestSpec, model.IntegrationTypeManifestSpec, error) {
	var empty model.IntegrationTypeManifestSpec
	oldSpec, e := manifest.ParseIntegrationTypeSpec(old.Spec)
	if e != nil || !dispositionObserverCatalog("aws", oldSpec) {
		return empty, empty, errOriginalCreateDisposition
	}
	currentSpec, e := manifest.ParseIntegrationTypeSpec(current.Spec)
	if e != nil || manifest.ValidateIntegrationTypeSpec(currentSpec) != nil || currentSpec.Adapter.Version != nativeDeniedAWSObserverVersion || !current.Metadata.Active || current.Kind != "integration_type" || old.Kind != "integration_type" || current.ID == old.ID || current.Metadata.Namespace != old.Metadata.Namespace || current.Metadata.Name != old.Metadata.Name {
		return empty, empty, errOriginalCreateDisposition
	}
	var expected, actual map[string]any
	if json.Unmarshal(old.Spec, &expected) != nil || json.Unmarshal(current.Spec, &actual) != nil {
		return empty, empty, errOriginalCreateDisposition
	}
	adapter, ok := expected["adapter"].(map[string]any)
	if !ok {
		return empty, empty, errOriginalCreateDisposition
	}
	adapter["version"] = nativeDeniedAWSObserverVersion
	actions, ok := expected["action_catalog"].([]any)
	if !ok {
		return empty, empty, errOriginalCreateDisposition
	}
	matches := 0
	for _, v := range actions {
		a, ok := v.(map[string]any)
		if !ok {
			return empty, empty, errOriginalCreateDisposition
		}
		if a["name"] == originalCreateDispositionOperation {
			matches++
			a["description"] = nativeDeniedObserverDescription
		}
	}
	if matches != 1 || !reflect.DeepEqual(expected, actual) {
		return empty, empty, errOriginalCreateDisposition
	}
	return oldSpec, currentSpec, nil
}
func resolveNativeDeniedObserverWith(ctx context.Context, c model.CapacityNativeDeniedCandidate, source string, d nativeDeniedResolverReads) (nativeDeniedResolvedObserver, error) {
	var empty nativeDeniedResolvedObserver
	if !nativeDeniedObserverSourceReady(source) || c.Request.OriginalAdapterSourceCommit != originalCreateDispositionAWSObserverSource || d.historical == nil || d.current == nil || d.hydrate == nil || d.validate == nil || d.handshake == nil {
		return empty, errOriginalCreateDisposition
	}
	b := c.Original.Binding
	im, e := d.historical(ctx, "integration_instance", b.IntegrationInstanceID)
	if e != nil || im.Kind != "integration_instance" || !im.Metadata.Active || im.ID.String() != b.IntegrationInstanceID || im.Checksum != b.IntegrationChecksum {
		return empty, errOriginalCreateDisposition
	}
	is, e := manifest.ParseIntegrationInstanceSpec(im.Spec)
	if e != nil || !originalGuestSupplierSourceConfigFor("aws", is, c.Request.OriginalAdapterSourceCommit) {
		return empty, errOriginalCreateDisposition
	}
	tm, e := d.historical(ctx, "integration_type", b.IntegrationTypeID)
	// This exact historical TYPE may be inactive after auto-sync. Its IID remains
	// active, and a separate current type/Describe below is mandatory for reads.
	if e != nil || tm.ID.String() != b.IntegrationTypeID || tm.Checksum != b.IntegrationTypeChecksum || (is.TypeRef.ManifestID != "" && is.TypeRef.ManifestID != tm.ID.String()) || (is.TypeRef.Namespace != "" && is.TypeRef.Namespace != tm.Metadata.Namespace) || (is.TypeRef.Name != "" && is.TypeRef.Name != tm.Metadata.Name) || (is.TypeRef.Version != nil && *is.TypeRef.Version != tm.Version) {
		return empty, errOriginalCreateDisposition
	}
	live, e := d.current(ctx, tm.Metadata.Namespace, tm.Metadata.Name)
	if e != nil {
		return empty, errOriginalCreateDisposition
	}
	oldSpec, liveSpec, e := nativeDeniedCatalogPair(tm, live)
	if e != nil {
		return empty, e
	}
	if e = d.hydrate(ctx, &is); e != nil || !originalGuestSupplierSourceConfigFor("aws", is, c.Request.OriginalAdapterSourceCommit) {
		return empty, errOriginalCreateDisposition
	}
	if e = d.validate(is, oldSpec); e != nil {
		return empty, e
	}
	if e = d.handshake(ctx, im, live, is, liveSpec); e != nil {
		return empty, e
	}
	return nativeDeniedResolvedObserver{capacityResolvedObservationAdapter: capacityResolvedObservationAdapter{im, is, tm, oldSpec}, currentType: live}, nil
}
func resolveNativeDeniedObserver(ctx context.Context, db *sql.DB, conn *amqp.Connection, c model.CapacityNativeDeniedCandidate) (nativeDeniedResolvedObserver, error) {
	return resolveNativeDeniedObserverWith(ctx, c, nativeDeniedAWSObserverSource, nativeDeniedResolverReads{
		historical: func(ctx context.Context, kind, id string) (model.Manifest, error) {
			return resolveManifestForKind(ctx, db, kind, id, "", "", nil)
		},
		current: func(ctx context.Context, namespace, name string) (model.Manifest, error) {
			return repository.ResolveManifest(ctx, db, "integration_type", namespace, name, nil, true)
		},
		hydrate: func(ctx context.Context, is *model.IntegrationInstanceManifestSpec) error {
			return hydrateIntegrationInstanceSecrets(ctx, db, is)
		},
		validate: manifest.ValidateHydratedIntegrationInstanceInputs,
		handshake: func(ctx context.Context, im, tm model.Manifest, is model.IntegrationInstanceManifestSpec, ts model.IntegrationTypeManifestSpec) error {
			return verifyResolvedIntegrationType(ctx, conn, db, im, tm, is, ts)
		},
	})
}
func RecordNativeDeniedDisposition(parent context.Context, db *sql.DB, conn *amqp.Connection, grantID, jobID, issuer string) (model.CapacityNativeDeniedDisposition, error) {
	var empty model.CapacityNativeDeniedDisposition
	if parent == nil || db == nil || conn == nil || !nativeDeniedObserverSourceReady(nativeDeniedAWSObserverSource) || !nativeDeniedReadonlySourceReady(nativeDeniedReadonlySource) {
		return empty, errOriginalCreateDisposition
	}
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	store := repository.CapacityStore{DB: db}
	owner, err := store.BeginNativeDeniedDisposition(ctx, grantID, jobID, issuer)
	if err != nil {
		return empty, err
	}
	candidate := owner.Candidate()
	observer, err := resolveNativeDeniedObserver(ctx, db, conn, candidate)
	if err != nil {
		return empty, err
	}
	if describeNativeDeniedReadonly(ctx, nativeDeniedReadonlySource) != nil {
		return empty, errOriginalCreateDisposition
	}
	raw, err := json.Marshal(candidate.Request)
	if err != nil {
		return empty, errOriginalCreateDisposition
	}
	var fixed map[string]any
	if json.Unmarshal(raw, &fixed) != nil {
		return empty, errOriginalCreateDisposition
	}
	reply, err := executeNativeDeniedReadonly(ctx, observer, fixed)
	if err != nil || ctx.Err() != nil || reply.Status != "observed" {
		return empty, errOriginalCreateDisposition
	}
	body, err := json.Marshal(reply.Output)
	if err != nil {
		return empty, errOriginalCreateDisposition
	}
	var observation model.CapacityNativeDeniedObservation
	if capacity.DecodeGuestLifecycle(body, &observation) != nil || observation.AdapterSourceCommit != nativeDeniedReadonlySource {
		return empty, errOriginalCreateDisposition
	}
	after, err := resolveNativeDeniedObserver(ctx, db, conn, candidate)
	if err != nil || after.instance.ID != observer.instance.ID || after.instance.Checksum != observer.instance.Checksum || after.typ.ID != observer.typ.ID || after.typ.Checksum != observer.typ.Checksum || after.currentType.ID != observer.currentType.ID || after.currentType.Checksum != observer.currentType.Checksum {
		return empty, errOriginalCreateDisposition
	}
	if describeNativeDeniedReadonly(ctx, nativeDeniedReadonlySource) != nil {
		return empty, errOriginalCreateDisposition
	}
	return store.CompleteNativeDeniedDisposition(ctx, owner, observation)
}
