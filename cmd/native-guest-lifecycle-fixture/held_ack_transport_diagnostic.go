//go:build linux && nativequalification

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	q "github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacitynativeqemu"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

// This is a historical projection of one existing caller return, never a
// replacement for the original signed failure or an authority for progress.
type heldAckTransportDiagnostic struct {
	Schema                string `json:"schema"`
	Scope                 string `json:"scope"`
	OriginalReturnSHA256  string `json:"original_return_sha256"`
	Status                int    `json:"status"`
	BodyScope             string `json:"body_scope"`
	PreflightFailed       bool   `json:"preflight_failed"`
	DoFailed              bool   `json:"do_failed"`
	ReadFailed            bool   `json:"read_failed"`
	CloseFailed           bool   `json:"close_failed"`
	OriginalContextFailed bool   `json:"original_context_failed"`
}

func (f *fixture) retainHeldAckTransportDiagnostic(ctx context.Context, preregistrationID, retirementStatus string) {
	if f.request.NativeCase != "held_ack_after_owned_original_deadline" || retirementStatus != "failed" || f.db == nil || preregistrationID == "" {
		return
	}
	diagnostic, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	rows, err := f.db.QueryContext(diagnostic, `SELECT c.original_wire,c.return_sha256 FROM public.capacity_vm_retirement_intents i JOIN public.capacity_guest_original_caller_returns c ON c.intent_id=i.id WHERE i.preregistration_id=$1 AND octet_length(c.original_wire)<=1048576 LIMIT 2`, preregistrationID)
	if err != nil {
		return
	}
	defer rows.Close()
	if !rows.Next() {
		return
	}
	var raw []byte
	var digest string
	if rows.Scan(&raw, &digest) != nil || rows.Next() || rows.Err() != nil || rows.Close() != nil || len(raw) > 1<<20 || capacity.BusinessCreationSHA256(raw) != digest {
		return
	}
	var original repository.GuestOriginalCallerReturn
	if json.Unmarshal(raw, &original) != nil {
		return
	}
	canonical, err := json.Marshal(original)
	if err != nil || !bytes.Equal(canonical, raw) || original.Status < 0 || original.Status > 599 {
		return
	}
	switch original.ResponseBodyScope {
	case capacity.GuestOriginalBodyNoRead, capacity.GuestOriginalBodyCompleteRead, capacity.GuestOriginalBodyIncompleteRead:
	default:
		return
	}
	fact := heldAckTransportDiagnostic{
		Schema: "qualification_held_ack_original_transport_v1", Scope: "historical_original_caller_return_only_not_authority",
		OriginalReturnSHA256: digest, Status: original.Status, BodyScope: original.ResponseBodyScope,
		PreflightFailed: original.PreflightFailed, DoFailed: original.DoFailed, ReadFailed: original.ReadFailed,
		CloseFailed: original.CloseFailed, OriginalContextFailed: original.OriginalContextFailed,
	}
	_, _ = q.Publish(diagnostic, filepath.Join(f.private, "core-held-ack-transport-diagnostic.json"), fact)
}
