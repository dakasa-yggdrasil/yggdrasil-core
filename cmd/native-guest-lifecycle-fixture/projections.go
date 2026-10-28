//go:build linux && nativequalification

package main

import (
	"context"
	"encoding/json"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	q "github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacitynativeqemu"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"path/filepath"
	"strconv"
)

const snapshotReturnProjectionSQL = `SELECT c.ordinal,r.return_sha256,r.original_wire FROM public.capacity_guest_runtime_snapshot_challenges c JOIN public.capacity_guest_runtime_snapshot_returns r ON r.challenge_id=c.id WHERE c.intent_id=$1 ORDER BY c.ordinal`

// Facts are a fixed typed allowlist projection. OriginalRawSHA256 always
// hashes the untouched private SQL bytea, never this projection/remarshal.
type nonsecretReturnProjection struct {
	Schema               string                     `json:"schema"`
	ProjectionClass      string                     `json:"projection_class"`
	Kind                 string                     `json:"kind"`
	OriginalIdentity     string                     `json:"original_identity"`
	OriginalRecordSHA256 string                     `json:"original_record_sha256"`
	OriginalRawSHA256    string                     `json:"original_raw_sha256"`
	OriginalRawBytes     int                        `json:"original_raw_bytes"`
	Facts                map[string]json.RawMessage `json:"facts"`
}

func (f *fixture) projectOriginal(ctx context.Context, name, kind, identity, digest string, wire []byte, typed any, keys []string) error {
	if !capacity.ValidDigest(digest) || len(wire) < 1 {
		return q.ErrOriginalUnknown
	}
	canonical, err := json.Marshal(typed)
	if err != nil {
		return err
	}
	var object map[string]json.RawMessage
	if json.Unmarshal(canonical, &object) != nil {
		return q.ErrOriginalUnknown
	}
	facts := map[string]json.RawMessage{}
	for _, key := range keys {
		if value, present := object[key]; present {
			facts[key] = value
		}
	}
	projection := nonsecretReturnProjection{"core_original_guest_nonsecret_return_projection_v1", "typed_allowlisted_facts_not_original_raw_bytes", kind, identity, digest, capacity.BusinessCreationSHA256(wire), len(wire), facts}
	_, err = q.Publish(ctx, filepath.Join(f.private, name), projection)
	return err
}

// No raw request, privateNonce, bearer, certificate/key, config, body/error or
// source ISO enters these files. Shared16 Record contains only native facts,
// opaque digests and source IDs; the signed Observation is never exported raw.
func (f *fixture) exportOriginalRetirementProjections(ctx context.Context, requestID string) error {
	var callerWire []byte
	var callerSHA string
	if err := f.db.QueryRowContext(ctx, `SELECT original_wire,return_sha256 FROM public.capacity_guest_original_caller_returns WHERE intent_id=$1`, requestID).Scan(&callerWire, &callerSHA); err != nil {
		return err
	}
	var caller repository.GuestOriginalCallerReturn
	if capacity.DecodeGuestLifecycle(callerWire, &caller) != nil {
		return q.ErrOriginalUnknown
	}
	callerKeys := []string{"request_id", "attempt_id", "started_at", "do_started_at", "driver_returned_at", "preflight_failed", "do_returned_at", "read_returned_at", "close_returned_at", "original_deadline", "status", "received_body_bytes", "body_persisted", "response_sha256", "response_body_scope", "retained_prefix_bytes", "retained_prefix_sha256", "do_failed", "read_failed", "close_failed", "original_context_failed"}
	if err := f.projectOriginal(ctx, "core-original-retirement-caller-projection.json", "retirement_caller_return", requestID, callerSHA, callerWire, caller, callerKeys); err != nil {
		return err
	}
	rows, err := f.db.QueryContext(ctx, `SELECT sequence,return_sha256,original_wire FROM public.capacity_vm_retirement_original_returns WHERE intent_id=$1 ORDER BY sequence`, requestID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var ordinal int
		var digest string
		var wire []byte
		if err = rows.Scan(&ordinal, &digest, &wire); err != nil {
			rows.Close()
			return err
		}
		var observation model.CapacityGuestRetirementObservation
		if capacity.DecodeGuestLifecycle(wire, &observation) != nil {
			rows.Close()
			return q.ErrOriginalUnknown
		}
		if err = f.projectOriginal(ctx, "core-original-retirement-journal-"+strconv.Itoa(ordinal)+"-projection.json", "retirement_journal", requestID, digest, wire, observation, []string{"schema", "record", "record_sha256", "journal_complete", "hold_reasons", "active_attempt_id", "active_intent_sha256", "reader", "observed_at"}); err != nil {
			rows.Close()
			return err
		}
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return err
	}
	if err = rows.Close(); err != nil {
		return err
	}
	rows, err = f.db.QueryContext(ctx, `SELECT ordinal,challenge_sha256,original_wire FROM public.capacity_guest_runtime_snapshot_challenges WHERE intent_id=$1 ORDER BY ordinal`, requestID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var ordinal int
		var digest string
		var wire []byte
		if err = rows.Scan(&ordinal, &digest, &wire); err != nil {
			rows.Close()
			return err
		}
		var challenge model.CapacityGuestRuntimeSnapshotChallenge
		if capacity.DecodeGuestLifecycle(wire, &challenge) != nil {
			rows.Close()
			return q.ErrOriginalUnknown
		}
		// Explicit field tags, rather than deleting a secret-looking substring.
		keys := []string{"schema", "purpose", "challenge_id", "binding_name", "slot", "preregistration_id", "preregistration_nonce_sha256", "original_registration_sha256", "original_create_witness_sha256", "enrollment_sha256", "profile_manifest_sha256", "tuple", "request_id", "attempt_id", "intent_sha256", "phase", "policy_id", "policy_checksum", "workflow_id", "workflow_checksum", "generation", "fence", "lease_owner", "core_source_commit", "issued_at", "original_deadline"}
		if err = f.projectOriginal(ctx, "core-original-runtime-snapshot-challenge-"+strconv.Itoa(ordinal)+"-projection.json", "runtime_snapshot_challenge", challenge.ChallengeID, digest, wire, challenge, keys); err != nil {
			rows.Close()
			return err
		}
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return err
	}
	if err = rows.Close(); err != nil {
		return err
	}
	rows, err = f.db.QueryContext(ctx, snapshotReturnProjectionSQL, requestID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var ordinal int
		var digest string
		var wire []byte
		if err = rows.Scan(&ordinal, &digest, &wire); err != nil {
			rows.Close()
			return err
		}
		var snapshot model.CapacityGuestRuntimeSnapshot
		if capacity.DecodeGuestLifecycle(wire, &snapshot) != nil {
			rows.Close()
			return q.ErrOriginalUnknown
		}
		keys := []string{"schema", "purpose", "challenge_id", "challenge_sha256", "preregistration_id", "original_registration_sha256", "original_create_witness_sha256", "profile_manifest_sha256", "enrollment_sha256", "tuple", "actor", "runtime", "writers", "writer_roster_sha256", "protected_census", "original_read_started_at", "original_read_returned_at", "original_reads_returned", "original_closes_returned", "original_context_failed", "hold_reasons", "reader", "observed_at"}
		if err = f.projectOriginal(ctx, "core-original-runtime-snapshot-"+strconv.Itoa(ordinal)+"-projection.json", "runtime_snapshot_return", snapshot.ChallengeID, digest, wire, snapshot, keys); err != nil {
			rows.Close()
			return err
		}
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return err
	}
	if err = rows.Close(); err != nil {
		return err
	}
	rows, err = f.db.QueryContext(ctx, `SELECT r.id::text,r.phase,r.ordinal,a.authority_sha256,a.original_wire FROM public.capacity_guest_original_authority_reads r JOIN public.capacity_guest_original_authority_returns a ON a.read_id=r.id WHERE r.intent_id=$1 ORDER BY CASE r.phase WHEN 'before_start' THEN 0 ELSE 1 END,r.ordinal`, requestID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var id, phase, digest string
		var ordinal int
		var wire []byte
		if err = rows.Scan(&id, &phase, &ordinal, &digest, &wire); err != nil {
			rows.Close()
			return err
		}
		var authority model.CapacityGuestRetirementAuthority
		if capacity.DecodeGuestLifecycle(wire, &authority) != nil {
			rows.Close()
			return q.ErrOriginalUnknown
		}
		if err = f.projectOriginal(ctx, "core-original-authority-"+phase+"-"+strconv.Itoa(ordinal)+"-projection.json", "retirement_authority", id, digest, wire, authority, []string{"schema", "purpose", "phase", "intent_sha256", "attempt_id", "nonce_sha256", "enrollment_sha256", "state", "source_commit", "original_deadline", "observed_at"}); err != nil {
			rows.Close()
			return err
		}
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return err
	}
	if err = rows.Close(); err != nil {
		return err
	}
	rows, err = f.db.QueryContext(ctx, `SELECT r.id::text,r.phase,r.ordinal,t.native_stage,t.return_sha256,t.original_wire FROM public.capacity_guest_original_authority_reads r JOIN public.capacity_guest_original_authority_transport_returns t ON t.read_id=r.id WHERE r.intent_id=$1 ORDER BY CASE r.phase WHEN 'before_start' THEN 0 ELSE 1 END,r.ordinal,t.native_stage`, requestID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var id, phase, stage, digest string
		var ordinal int
		var wire []byte
		if err = rows.Scan(&id, &phase, &ordinal, &stage, &digest, &wire); err != nil {
			rows.Close()
			return err
		}
		var transport map[string]json.RawMessage
		if json.Unmarshal(wire, &transport) != nil {
			rows.Close()
			return q.ErrOriginalUnknown
		}
		keys := []string{"read_id", "native_stage", "original_deadline", "started_at", "do_started_at", "do_returned_at", "read_returned_at", "close_returned_at", "driver_returned_at", "status", "response_sha256", "received_body_bytes", "response_body_scope", "retained_prefix_bytes", "retained_prefix_sha256", "preflight_failed", "do_failed", "read_failed", "close_failed", "original_context_failed"}
		if err = f.projectOriginal(ctx, "core-original-authority-transport-"+phase+"-"+strconv.Itoa(ordinal)+"-"+stage+"-projection.json", "authority_transport_return", id, digest, wire, transport, keys); err != nil {
			rows.Close()
			return err
		}
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return err
	}
	return rows.Close()
}
