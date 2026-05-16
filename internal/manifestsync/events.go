package manifestsync

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
)

// SkipReason is the enum of reasons a sync attempt was skipped or failed.
// Values must match the JSON Schema enum in
// docs/contracts/events/v1/integration_type/sync_skipped.json.
type SkipReason string

const (
	SkipReasonTypeNotFound          SkipReason = "type_not_found"
	SkipReasonNoInstances           SkipReason = "no_instances"
	SkipReasonNoDescribableInstance SkipReason = "no_describable_instance"
	SkipReasonRPCFailed             SkipReason = "rpc_failed"
	SkipReasonInvalidDescribe       SkipReason = "invalid_describe"
	SkipReasonApplyFailed           SkipReason = "apply_failed"
)

// syncedInputs holds the data needed to build an integration_type.synced payload.
type syncedInputs struct {
	TypeID           uuid.UUID
	TypeNamespace    string
	TypeName         string
	FromVersion      int
	ToVersion        int
	Diff             Diff
	SourceInstanceID uuid.UUID
	SyncedAt         time.Time
}

// skippedInputs holds the data needed to build an integration_type.sync_skipped payload.
type skippedInputs struct {
	TypeID              uuid.UUID
	TypeNamespace       string
	TypeName            string
	Reason              SkipReason
	Error               string     // omitted from payload when empty
	AttemptedInstanceID *uuid.UUID // nil → JSON null (required field per schema)
	AttemptedAt         time.Time
}

// noOpInputs holds the data needed to build an integration_type.sync_no_op payload.
type noOpInputs struct {
	TypeID           uuid.UUID
	TypeNamespace    string
	TypeName         string
	SourceInstanceID uuid.UUID
	CheckedAt        time.Time
}

// contractMismatchInputs holds the data for a runtime_state.contract_mismatch_detected payload.
type contractMismatchInputs struct {
	InstanceID        uuid.UUID
	TypeID            uuid.UUID
	InstanceNamespace string
	InstanceName      string
	TypeNamespace     string
	TypeName          string
	DetectedAt        time.Time
}

// buildSyncedPayload constructs the payload map for integration_type.synced.
// JSON keys match docs/contracts/events/v1/integration_type/synced.json.
//
// The added/removed slices are converted to []any rather than left as []string
// because the event validator (contracts.ValidateEventPayload) inspects the
// payload via reflection BEFORE json.Marshal, and its jsonschema library
// rejects typed Go slices in a map[string]any with "invalid jsonType []string".
// Converting to []any matches the type the validator expects after a round-trip.
func buildSyncedPayload(in syncedInputs) map[string]any {
	added := make([]any, len(in.Diff.AddedActions))
	for i, a := range in.Diff.AddedActions {
		added[i] = a
	}
	removed := make([]any, len(in.Diff.RemovedActions))
	for i, a := range in.Diff.RemovedActions {
		removed[i] = a
	}
	return map[string]any{
		"type_id":            in.TypeID.String(),
		"type_namespace":     in.TypeNamespace,
		"type_name":          in.TypeName,
		"from_version":       in.FromVersion,
		"to_version":         in.ToVersion,
		"source_instance_id": in.SourceInstanceID.String(),
		"synced_at":          in.SyncedAt.UTC().Format(time.RFC3339),
		"diff_summary": map[string]any{
			"added_actions":        added,
			"removed_actions":      removed,
			"schema_changed":       in.Diff.SchemaChanged,
			"capabilities_changed": in.Diff.CapabilitiesChanged,
		},
	}
}

// buildSkippedPayload constructs the payload map for integration_type.sync_skipped.
// JSON keys match docs/contracts/events/v1/integration_type/sync_skipped.json.
// The "error" key is omitted when in.Error is empty.
// "attempted_instance_id" is always present (null when in.AttemptedInstanceID == nil).
func buildSkippedPayload(in skippedInputs) map[string]any {
	var attemptedInstanceID any
	if in.AttemptedInstanceID != nil {
		attemptedInstanceID = in.AttemptedInstanceID.String()
	}

	p := map[string]any{
		"type_id":               in.TypeID.String(),
		"type_namespace":        in.TypeNamespace,
		"type_name":             in.TypeName,
		"reason":                string(in.Reason),
		"attempted_instance_id": attemptedInstanceID,
		"attempted_at":          in.AttemptedAt.UTC().Format(time.RFC3339),
	}

	if in.Error != "" {
		p["error"] = in.Error
	}

	return p
}

// buildNoOpPayload constructs the payload map for integration_type.sync_no_op.
// JSON keys match docs/contracts/events/v1/integration_type/sync_no_op.json.
func buildNoOpPayload(in noOpInputs) map[string]any {
	return map[string]any{
		"type_id":            in.TypeID.String(),
		"type_namespace":     in.TypeNamespace,
		"type_name":          in.TypeName,
		"source_instance_id": in.SourceInstanceID.String(),
		"checked_at":         in.CheckedAt.UTC().Format(time.RFC3339),
	}
}

// buildContractMismatchPayload constructs the payload map for
// runtime_state.contract_mismatch_detected.
// JSON keys match docs/contracts/events/v1/runtime_state/contract_mismatch_detected.json.
func buildContractMismatchPayload(in contractMismatchInputs) map[string]any {
	return map[string]any{
		"instance_id":        in.InstanceID.String(),
		"type_id":            in.TypeID.String(),
		"instance_namespace": in.InstanceNamespace,
		"instance_name":      in.InstanceName,
		"type_namespace":     in.TypeNamespace,
		"type_name":          in.TypeName,
		"detected_at":        in.DetectedAt.UTC().Format(time.RFC3339),
	}
}

// emitEvent opens a short transaction, calls repository.EmitEvent, and commits.
// On any error the transaction is rolled back.
// aggregateID is serialized as a string (UUID) for the aggregate_id column.
func emitEvent(ctx context.Context, db *sql.DB, eventType string, aggregateID uuid.UUID, payload map[string]any) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("emitEvent: begin tx: %w", err)
	}

	_, err = repository.EmitEvent(ctx, tx, model.EmitEventRequest{
		Type:          eventType,
		AggregateType: aggregateTypeFor(eventType),
		AggregateID:   aggregateID.String(),
		Payload:       payload,
	})
	if err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("emitEvent %s: %w", eventType, err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("emitEvent %s: commit: %w", eventType, err)
	}

	return nil
}

// aggregateTypeFor derives the aggregate_type from the dot-separated event type string.
// e.g. "integration_type.synced" → "integration_type",
//
//	"runtime_state.contract_mismatch_detected" → "runtime_state".
func aggregateTypeFor(eventType string) string {
	for i := 0; i < len(eventType); i++ {
		if eventType[i] == '.' {
			return eventType[:i]
		}
	}
	return eventType
}
