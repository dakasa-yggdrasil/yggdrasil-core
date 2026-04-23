package message

import (
	"context"
	"database/sql"
	"fmt"

	manifestengine "github.com/dakasa-yggdrasil/yggdrasil-core/manifest"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

// manifestPersistError classifies persistence failures so callers can map
// them to transport-specific response codes (AMQP reply code, HTTP status,
// workflow step error) without parsing error strings.
type manifestPersistError struct {
	Code string
	Err  error
}

func (e *manifestPersistError) Error() string { return e.Err.Error() }
func (e *manifestPersistError) Unwrap() error { return e.Err }

const (
	manifestPersistCodeBadRequest       = "bad_request"
	manifestPersistCodeValidationFailed = "validation_failed"
	manifestPersistCodeInternalError    = "internal_error"
)

// persistManifestVersion runs the canonical manifest write pipeline: normalize
// the envelope, validate kind-specific spec, compute a deterministic checksum,
// then within one transaction persist the new version and emit a
// manifest.created event. Callers get back the full repository record
// (ID, version, checksum, metadata) on success, or a *manifestPersistError
// whose Code identifies which stage rejected the document.
//
// This is the single source of truth for "what it means to create a
// manifest" in the engine. The AMQP manifest.create handler and the
// workflow step kind=yggdrasil, operation=apply_manifest both call through
// here so the two code paths cannot diverge in validation rules or event
// emission.
func persistManifestVersion(ctx context.Context, db *sql.DB, doc model.ManifestDocument) (model.Manifest, error) {
	doc = manifestengine.NormalizeDocument(doc)

	if err := manifestengine.ValidateDocument(doc); err != nil {
		return model.Manifest{}, &manifestPersistError{Code: manifestPersistCodeValidationFailed, Err: err}
	}

	checksum, err := manifestengine.Checksum(doc)
	if err != nil {
		return model.Manifest{}, &manifestPersistError{Code: manifestPersistCodeInternalError, Err: fmt.Errorf("checksum manifest: %w", err)}
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return model.Manifest{}, &manifestPersistError{Code: manifestPersistCodeInternalError, Err: fmt.Errorf("begin tx: %w", err)}
	}
	defer func() { _ = tx.Rollback() }()

	manifestRecord, err := repository.CreateManifestVersionTx(ctx, tx, doc, checksum)
	if err != nil {
		return model.Manifest{}, &manifestPersistError{Code: manifestPersistCodeInternalError, Err: err}
	}

	eventPayload := map[string]interface{}{
		"manifest_id": manifestRecord.ID.String(),
		"kind":        manifestRecord.Kind,
		"namespace":   manifestRecord.Metadata.Namespace,
		"name":        manifestRecord.Metadata.Name,
		"version":     manifestRecord.Version,
		"checksum":    manifestRecord.Checksum,
	}
	if len(manifestRecord.Metadata.Labels) > 0 {
		eventPayload["labels"] = manifestRecord.Metadata.Labels
	}

	if _, err := repository.EmitEvent(ctx, tx, model.EmitEventRequest{
		Type:          "manifest.created",
		SchemaVersion: "v1",
		AggregateType: "manifest",
		AggregateID:   manifestRecord.ID.String(),
		Payload:       eventPayload,
	}); err != nil {
		return model.Manifest{}, &manifestPersistError{Code: manifestPersistCodeInternalError, Err: fmt.Errorf("emit manifest.created event: %w", err)}
	}

	if err := tx.Commit(); err != nil {
		return model.Manifest{}, &manifestPersistError{Code: manifestPersistCodeInternalError, Err: fmt.Errorf("commit manifest tx: %w", err)}
	}

	return manifestRecord, nil
}
