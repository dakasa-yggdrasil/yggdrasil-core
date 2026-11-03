package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

const CapacityDemandCursorID = "capacity_dispatch_demand_v1"
const CapacityDemandBatchLimit = 100

var ErrCapacityDemand = errors.New("original capacity demand unresolved")

func capacityDemandContext(ctx context.Context) error {
	if ctx == nil {
		return ErrCapacityDemand
	}
	return capacityDispatchContextFailure(ctx)
}

// Column idempotency is private to the scheduled emitter for this event type.
// Generic HTTP publication cannot write it; JSON metadata is not this column.
type CapacityDemandEvent struct {
	EventID        uuid.UUID
	Sequence       int64
	RunID          uuid.UUID
	SourceWorkflow CapacityDispatchManifestPin
	EmittedAt      time.Time
	SHA256         string
}

type CapacityDemandCandidate struct {
	EventID  uuid.UUID
	Sequence int64
}

// Demand is scoped by an operator policy, never by event-provided authority.
// Permanent wake keys are the deduplication boundary. Sequence is allocated
// before COMMIT and therefore cannot exclude a later-visible original event.
type CapacityDemandScope struct {
	Realm, Environment, Domain, Dimension string
	SourceWorkflowID                      uuid.UUID
	MaxAgeSeconds                         int
}

func (s CapacityDemandScope) CursorID() (string, error) {
	if !capacityDispatchText(s.Realm, 64) || !capacityDispatchText(s.Environment, 128) || !capacityDispatchText(s.Domain, 128) || !capacityDispatchText(s.Dimension, 128) || s.SourceWorkflowID == uuid.Nil || s.MaxAgeSeconds < 1 || s.MaxAgeSeconds > 3600 {
		return "", ErrCapacityDemand
	}
	// Keep the complete SHA256 inside the original VARCHAR(64) column. The
	// protocol belongs to the preimage, not an overlength visible prefix.
	raw, err := json.Marshal([]string{CapacityDemandCursorID, s.Realm, s.Environment, s.Domain, s.Dimension})
	if err != nil {
		return "", err
	}
	return capacityDispatchSHA(raw), nil
}

// ReadCapacityDemandBatch selects one latest fresh, not-yet-admitted completion
// for this dimension. At most64 policies are read in one original10s pass,
// below the100-candidate cap. Bad/stale demand cannot consume another policy's
// budget. No cursor/sequence threshold, table lock or emitter serialization.
func ReadCapacityDemandBatch(ctx context.Context, db *sql.DB, scope CapacityDemandScope) (out []CapacityDemandCandidate, err error) {
	if db == nil || capacityDemandContext(ctx) != nil {
		return nil, errors.Join(ErrCapacityDemand, capacityDemandContext(ctx))
	}
	if _, err = scope.CursorID(); err != nil {
		return nil, err
	}
	rows, err := db.QueryContext(ctx, `SELECT e.event_id,e.sequence FROM public.event_log e
        WHERE e.type='workflow.run.completed' AND e.schema_version='v1' AND e.aggregate_type='workflow_run'
        AND e.idempotency_key=e.aggregate_id AND e.actor_type IS NULL AND e.actor_id IS NULL
        AND e.actor_context IS NULL AND e.metadata IS NULL
        AND e.payload->'workflow_ref'->>'id'=$5
        AND e.emitted_at<=clock_timestamp() AND e.emitted_at>=clock_timestamp()-($6 * interval '1 second')
        AND NOT EXISTS (SELECT 1 FROM public.capacity_dispatch_wakes w
            WHERE w.realm=$1 AND w.environment=$2 AND w.domain=$3 AND w.dimension=$4
            AND w.source_tick='event:'||e.event_id::text)
        ORDER BY e.emitted_at DESC,e.sequence DESC,e.event_id LIMIT 1`,
		scope.Realm, scope.Environment, scope.Domain, scope.Dimension, scope.SourceWorkflowID.String(), scope.MaxAgeSeconds)
	if err != nil {
		return nil, errors.Join(ErrCapacityDemand, err, capacityDemandContext(ctx))
	}
	for rows.Next() {
		var item CapacityDemandCandidate
		if err = rows.Scan(&item.EventID, &item.Sequence); err != nil {
			break
		}
		if item.EventID == uuid.Nil || item.Sequence < 1 || len(out) >= CapacityDemandBatchLimit {
			err = ErrCapacityDemand
			break
		}
		out = append(out, item)
	}
	joined := errors.Join(err, rows.Err(), rows.Close(), capacityDemandContext(ctx))
	if joined != nil {
		return nil, errors.Join(ErrCapacityDemand, joined)
	}
	return out, nil
}

// Read-only original identity recovery. Reading never claims or releases work.
func ReadCapacityDispatchJob(ctx context.Context, db *sql.DB, id uuid.UUID) (CapacityDispatchJob, error) {
	if db == nil || id == uuid.Nil || capacityDemandContext(ctx) != nil {
		return CapacityDispatchJob{}, errors.Join(ErrCapacityDispatchClaim, capacityDemandContext(ctx))
	}
	job, err := readCapacityDispatchJob(ctx, db, id, false)
	return job, errors.Join(err, capacityDemandContext(ctx))
}

func canonicalDemandUUID(s string) bool {
	id, err := uuid.Parse(s)
	return err == nil && id != uuid.Nil && id.String() == s
}

type scheduledCompletionPayload struct {
	Workflow struct {
		ID        string `json:"id"`
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
		Version   int    `json:"version"`
	} `json:"workflow_ref"`
	RunID       string `json:"run_id"`
	Status      string `json:"status"`
	StartedAt   string `json:"started_at"`
	FinishedAt  string `json:"finished_at"`
	StepCount   int    `json:"step_count"`
	TriggeredBy string `json:"triggered_by"`
}

// ReadCapacityDemandEvent reads the original immutable event AND its original
// terminal scheduled run. ActorNULL or a similar payload alone never qualifies.
// This establishes application-source lineage under trusted Core DB ownership,
// not a cryptographic claim against a database administrator.
func ReadCapacityDemandEvent(ctx context.Context, db *sql.DB, id uuid.UUID) (out CapacityDemandEvent, err error) {
	if db == nil || id == uuid.Nil || capacityDemandContext(ctx) != nil {
		return out, errors.Join(ErrCapacityDemand, capacityDemandContext(ctx))
	}
	var kind, schema, aggregate, aggregateID string
	var key, actorType, actorID, actorContext, metadata sql.NullString
	var payload, runMetadata, result []byte
	var sourceNamespace, sourceName, status string
	var version sql.NullInt64
	var started, finished sql.NullTime
	err = db.QueryRowContext(ctx, `SELECT e.event_id,e.sequence,e.type,e.schema_version,e.aggregate_type,e.aggregate_id,
        e.idempotency_key,e.actor_type,e.actor_id,e.actor_context::text,e.metadata::text,e.emitted_at,
        substring(convert_to(e.payload::text,'UTF8') FROM 1 FOR 16385),
        r.workflow_namespace,r.workflow_name,r.workflow_version,r.status,
        substring(convert_to(r.metadata::text,'UTF8') FROM 1 FOR 16385),
        substring(convert_to(r.result::text,'UTF8') FROM 1 FOR 16385),r.started_at,r.finished_at
        FROM public.event_log e JOIN public.workflow_runs r ON r.id::text=e.aggregate_id
        WHERE e.event_id=$1`, id).Scan(&out.EventID, &out.Sequence, &kind, &schema, &aggregate, &aggregateID,
		&key, &actorType, &actorID, &actorContext, &metadata, &out.EmittedAt, &payload,
		&sourceNamespace, &sourceName, &version, &status, &runMetadata, &result, &started, &finished)
	if joined := errors.Join(err, capacityDemandContext(ctx)); joined != nil {
		return out, errors.Join(ErrCapacityDemand, joined)
	}
	if out.EventID != id || out.Sequence < 1 || kind != "workflow.run.completed" || schema != "v1" || aggregate != "workflow_run" || !canonicalDemandUUID(aggregateID) || !key.Valid || key.String != aggregateID || actorType.Valid || actorID.Valid || actorContext.Valid || metadata.Valid || out.EmittedAt.IsZero() || (status != "succeeded" && status != "failed") || !started.Valid || !finished.Valid || finished.Time.Before(started.Time) || len(payload) == 0 || len(payload) > 16384 || len(runMetadata) == 0 || len(runMetadata) > 16384 || len(result) == 0 || len(result) > 16384 {
		return out, ErrCapacityDemand
	}
	var p scheduledCompletionPayload
	var m map[string]json.RawMessage
	var response model.RunWorkflowResponse
	if capacity.DecodeBusinessJSON(payload, &p) != nil || capacity.DecodeBusinessJSON(runMetadata, &m) != nil || capacity.DecodeBusinessJSON(result, &response) != nil {
		return out, ErrCapacityDemand
	}
	var triggered, manifestID, scheduledFor string
	if json.Unmarshal(m["triggered_by"], &triggered) != nil || json.Unmarshal(m["manifest_id"], &manifestID) != nil || json.Unmarshal(m["scheduled_for"], &scheduledFor) != nil || triggered != "workflow_scheduler" || !canonicalDemandUUID(manifestID) {
		return out, ErrCapacityDemand
	}
	if _, e := time.Parse(time.RFC3339, scheduledFor); e != nil {
		return out, ErrCapacityDemand
	}
	// The original scheduler persists a logical namespace/name selector with
	// NULL workflow_version. Its actual stored response and manifest_id bind
	// the executed version; an explicitly persisted version must still match.
	if response.Workflow.Version < 1 || (version.Valid && version.Int64 != int64(response.Workflow.Version)) || p.RunID != aggregateID || p.TriggeredBy != "schedule" || p.Workflow.ID != manifestID || p.Workflow.Namespace != sourceNamespace || p.Workflow.Name != sourceName || p.Workflow.ID != response.Workflow.ID.String() || p.Workflow.Namespace != response.Workflow.Namespace || p.Workflow.Name != response.Workflow.Name || p.Workflow.Version != response.Workflow.Version || p.Status != status || response.Status != status || p.StartedAt != response.StartedAt.Format(time.RFC3339) || p.FinishedAt != response.FinishedAt.Format(time.RFC3339) || p.StepCount != len(response.Steps) || p.StepCount < 1 || response.StartedAt.IsZero() || response.FinishedAt.Before(response.StartedAt) {
		return out, ErrCapacityDemand
	}
	wf, e := GetManifestByID(ctx, db, response.Workflow.ID)
	if e != nil || wf.Kind != "workflow" || wf.Metadata.Namespace != sourceNamespace || wf.Metadata.Name != sourceName || wf.Version != response.Workflow.Version {
		return out, errors.Join(ErrCapacityDemand, e)
	}
	out.RunID, _ = uuid.Parse(aggregateID)
	out.SourceWorkflow = CapacityDispatchManifestPin{ID: wf.ID, Namespace: wf.Metadata.Namespace, Name: wf.Metadata.Name, Version: wf.Version, Checksum: wf.Checksum}
	// Include original column identity and raw payload/result hashes. No private
	// result or event body becomes dispatch metadata, an output or a log.
	raw, _ := json.Marshal([]any{out.EventID.String(), out.Sequence, key.String, aggregate, aggregateID, out.EmittedAt.UTC().Format(time.RFC3339Nano), capacityDispatchSHA(payload), capacityDispatchSHA(runMetadata), capacityDispatchSHA(result), out.SourceWorkflow})
	out.SHA256 = capacityDispatchSHA(raw)
	return out, errors.Join(capacityDemandContext(ctx))
}

// The existing cursor table retains an informational row per fixed dimension.
// Read-only absence is empty; this value is never a candidate high-water mark.
func ReadCapacityDemandCursor(ctx context.Context, db *sql.DB, scope CapacityDemandScope) (string, error) {
	if db == nil || capacityDemandContext(ctx) != nil {
		return "", errors.Join(ErrCapacityDemand, capacityDemandContext(ctx))
	}
	id, err := scope.CursorID()
	if err != nil {
		return "", err
	}
	var cursor string
	err = db.QueryRowContext(ctx, `SELECT last_cursor FROM public.workflow_event_trigger_state WHERE id=$1`, id).Scan(&cursor)
	if errors.Is(err, sql.ErrNoRows) {
		return "", capacityDemandContext(ctx)
	}
	if err != nil {
		return "", errors.Join(ErrCapacityDemand, err, capacityDemandContext(ctx))
	}
	if cursor != "" {
		n, e := strconv.ParseInt(cursor, 10, 64)
		if e != nil || n < 0 || strconv.FormatInt(n, 10) != cursor {
			return "", ErrCapacityDemand
		}
	}
	return cursor, capacityDemandContext(ctx)
}

// The per-dimension cursor is diagnostic only. It records the last actual
// admission, even a lower sequence committed late. It never filters candidates.
// Its CAS shares the original wake TX; uncertain commits are recovered by wakes.
func AdvanceCapacityDemandCursor(ctx context.Context, tx *sql.Tx, scope CapacityDemandScope, old, next string) error {
	if tx == nil || capacityDemandContext(ctx) != nil {
		return errors.Join(ErrCapacityDemand, capacityDemandContext(ctx))
	}
	parse := func(s string) (int64, error) {
		if s == "" {
			return 0, nil
		}
		n, e := strconv.ParseInt(s, 10, 64)
		if e != nil || n < 0 || strconv.FormatInt(n, 10) != s {
			return 0, ErrCapacityDemand
		}
		return n, nil
	}
	id, err := scope.CursorID()
	_, e := parse(old)
	b, f := parse(next)
	if err != nil || e != nil || f != nil || b < 1 {
		return ErrCapacityDemand
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO public.workflow_event_trigger_state(id,last_cursor) VALUES($1,'') ON CONFLICT(id) DO NOTHING`, id); err != nil {
		return errors.Join(ErrCapacityDemand, err)
	}
	result, err := tx.ExecContext(ctx, `UPDATE public.workflow_event_trigger_state SET last_cursor=$3,updated_at=clock_timestamp() WHERE id=$1 AND last_cursor=$2`, id, old, next)
	if err != nil {
		return errors.Join(ErrCapacityDemand, err)
	}
	n, err := result.RowsAffected()
	if err != nil || n != 1 {
		return errors.Join(ErrCapacityDemand, err)
	}
	return capacityDemandContext(ctx)
}
