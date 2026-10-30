//go:build linux && nativequalification

package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	q "github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacitynativeqemu"
)

type startupTransportFact struct {
	State                 string `json:"state"`
	OriginalReturnSHA256  string `json:"original_return_sha256,omitempty"`
	Status                *int   `json:"status,omitempty"`
	BodyScope             string `json:"body_scope,omitempty"`
	PreflightFailed       *bool  `json:"preflight_failed,omitempty"`
	DoFailed              *bool  `json:"do_failed,omitempty"`
	ReadFailed            *bool  `json:"read_failed,omitempty"`
	CloseFailed           *bool  `json:"close_failed,omitempty"`
	OriginalContextFailed *bool  `json:"original_context_failed,omitempty"`
}

// Decode only fixed facts from one hash-bound return. Never emit raw bytes,
// bodies, endpoints, identities or errors. Invalid/missing fields remain unknown.
func startupOriginalTransport(raw []byte, digest, readID, stage string) (startupTransportFact, bool) {
	unknown := startupTransportFact{State: "UNKNOWN"}
	if len(raw) == 0 || len(raw) > 8192 || capacity.BusinessCreationSHA256(raw) != digest {
		return unknown, false
	}
	var v struct {
		ReadID                string `json:"read_id"`
		Stage                 string `json:"native_stage"`
		Status                *int   `json:"status"`
		BodyScope             string `json:"response_body_scope"`
		PreflightFailed       *bool  `json:"preflight_failed"`
		DoFailed              *bool  `json:"do_failed"`
		ReadFailed            *bool  `json:"read_failed"`
		CloseFailed           *bool  `json:"close_failed"`
		OriginalContextFailed *bool  `json:"original_context_failed"`
	}
	if json.Unmarshal(raw, &v) != nil || v.ReadID != readID || v.Stage != stage || v.Status == nil || *v.Status < 0 || *v.Status > 599 || v.PreflightFailed == nil || v.DoFailed == nil || v.ReadFailed == nil || v.CloseFailed == nil || v.OriginalContextFailed == nil {
		return unknown, false
	}
	if v.BodyScope != capacity.GuestOriginalBodyNoRead && v.BodyScope != capacity.GuestOriginalBodyCompleteRead && v.BodyScope != capacity.GuestOriginalBodyIncompleteRead {
		return unknown, false
	}
	return startupTransportFact{State: "RECORDED_ORIGINAL_RETURN", OriginalReturnSHA256: digest, Status: v.Status, BodyScope: v.BodyScope, PreflightFailed: v.PreflightFailed, DoFailed: v.DoFailed, ReadFailed: v.ReadFailed, CloseFailed: v.CloseFailed, OriginalContextFailed: v.OriginalContextFailed}, true
}

// A bounded diagnostic read after a failed workflow; it never grants authority
// and absence means only that a row was not visible in this observation.
func (f *fixture) retainStartupAuthorityDiagnostic(ctx context.Context, preregistrationID, retirementStatus string) {
	if (f.request.NativeCase != "actor_startup_delay_positive" && f.request.NativeCase != "positive_original_lifecycle") || retirementStatus != "failed" || f.db == nil || preregistrationID == "" {
		return
	}
	diagnostic, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	rows, err := f.db.QueryContext(diagnostic, `SELECT r.id::text,
EXISTS(SELECT 1 FROM public.capacity_guest_runtime_snapshot_challenges c WHERE c.intent_id=r.intent_id AND c.phase=r.phase AND c.ordinal=r.ordinal),
EXISTS(SELECT 1 FROM public.capacity_guest_runtime_snapshot_returns s JOIN public.capacity_guest_runtime_snapshot_challenges c ON c.id=s.challenge_id WHERE c.intent_id=r.intent_id AND c.phase=r.phase AND c.ordinal=r.ordinal),
EXISTS(SELECT 1 FROM public.capacity_guest_original_authority_returns a WHERE a.read_id=r.id)
FROM public.capacity_guest_original_authority_reads r JOIN public.capacity_vm_retirement_intents i ON i.id=r.intent_id
WHERE i.preregistration_id=$1 AND r.phase='before_start' AND r.ordinal=2 LIMIT 2`, preregistrationID)
	if err != nil {
		return
	}
	defer rows.Close()
	fact := struct {
		Schema                  string               `json:"schema"`
		Scope                   string               `json:"scope"`
		ReadState               string               `json:"read_state"`
		ChallengeObserved       *bool                `json:"challenge_observed,omitempty"`
		SnapshotReturnObserved  *bool                `json:"snapshot_return_observed,omitempty"`
		AuthorityReturnObserved *bool                `json:"authority_return_observed,omitempty"`
		Snapshot                startupTransportFact `json:"snapshot"`
		Journal                 startupTransportFact `json:"journal"`
	}{Schema: "qualification_startup_authority_ordinal2_v1", Scope: "historical_nonatomic_source_observation_only_not_authority", ReadState: "NOT_OBSERVED_UNKNOWN", Snapshot: startupTransportFact{State: "UNKNOWN"}, Journal: startupTransportFact{State: "UNKNOWN"}}
	if rows.Next() {
		var id string
		var challenge, snapshot, authority bool
		if rows.Scan(&id, &challenge, &snapshot, &authority) != nil || rows.Next() || rows.Err() != nil || rows.Close() != nil || id == "" {
			return
		}
		fact.ReadState = "OBSERVED"
		fact.ChallengeObserved = &challenge
		fact.SnapshotReturnObserved = &snapshot
		fact.AuthorityReturnObserved = &authority
		for _, target := range []struct {
			stage string
			dst   *startupTransportFact
		}{{"snapshot", &fact.Snapshot}, {"journal", &fact.Journal}} {
			var raw []byte
			var digest string
			err := f.db.QueryRowContext(diagnostic, `SELECT original_wire,return_sha256 FROM public.capacity_guest_original_authority_transport_returns WHERE read_id=$1 AND native_stage=$2 AND octet_length(original_wire)<=8192`, id, target.stage).Scan(&raw, &digest)
			if err == sql.ErrNoRows {
				target.dst.State = "NOT_OBSERVED_UNKNOWN"
				continue
			}
			if err != nil {
				return
			}
			if v, ok := startupOriginalTransport(raw, digest, id, target.stage); ok {
				*target.dst = v
			}
		}
	} else if rows.Err() != nil || rows.Close() != nil {
		return
	}
	_, _ = q.Publish(diagnostic, filepath.Join(f.private, "core-startup-authority-diagnostic.json"), fact)
}
