package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"reflect"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

type guestRetirementForwardEvidence struct {
	NonceSHA256     string   `json:"nonce_sha256"`
	JournalSHA256   []string `json:"journal_sha256"`
	CallerSHA256    string   `json:"caller_sha256"`
	AuthoritySHA256 []string `json:"authority_sha256"`
	TransportSHA256 []string `json:"transport_sha256"`
	FrameSHA256     string   `json:"frame_sha256"`
}

// Validate the WHOLE retained original, including an optional genuine fourth
// Guest record. Authentication of a prefix never fabricates the missing ACK.
func guestRetirementForwardEvidenceTx(ctx context.Context, tx *sql.Tx, s GuestRetirementOriginalV2) (guestRetirementForwardEvidence, error) {
	e := guestRetirementForwardEvidence{JournalSHA256: []string{}, AuthoritySHA256: []string{}, TransportSHA256: []string{}}
	i := s.Request.Intent
	rows, err := tx.QueryContext(ctx, `SELECT sequence,kind,original_wire,return_sha256,previous_sha256,original_return_record=convert_from(original_wire,'UTF8')::jsonb FROM public.capacity_vm_retirement_original_returns WHERE intent_id=$1 ORDER BY sequence`, i.RequestID)
	if err != nil {
		return e, err
	}
	observations := []model.CapacityGuestRetirementObservationV2{}
	count := 0
	for rows.Next() {
		var sequence int
		var kind, digest, previous string
		var raw []byte
		var same bool
		if err = rows.Scan(&sequence, &kind, &raw, &digest, &previous, &same); err != nil {
			rows.Close()
			return e, err
		}
		if !same || sequence != count+1 || count > 4 {
			rows.Close()
			return e, ErrCapacityConflict
		}
		if count == 0 {
			var n guestRetirementV2NonceReturn
			if kind != guestRetirementV2NonceKind || previous != "" || capacity.DecodeGuestLifecycle(raw, &n) != nil || capacity.GuestRetirementSHA(n) != digest || !guestRetirementV2NonceJoin(n, s) {
				rows.Close()
				return e, ErrCapacityConflict
			}
			e.NonceSHA256 = digest
		} else {
			var o model.CapacityGuestRetirementObservationV2
			if capacity.DecodeGuestLifecycle(raw, &o) != nil || o.Record.Sequence != count || kind != "production_retirement_v2:"+o.Record.State || digest != o.RecordSHA256 || previous != o.Record.PreviousSHA256 {
				rows.Close()
				return e, ErrCapacityConflict
			}
			observations = append(observations, o)
			e.JournalSHA256 = append(e.JournalSHA256, digest)
		}
		count++
	}
	er, cl := rows.Err(), rows.Close()
	if er != nil {
		return e, er
	}
	if cl != nil {
		return e, cl
	}
	if !capacity.GuestRetirementForwardPrefix(observations, s.Receipt.Enrollment, i) {
		return e, ErrCapacityConflict
	}
	var callerWire []byte
	var same bool
	if err = tx.QueryRowContext(ctx, `SELECT original_wire,return_sha256,original_record=convert_from(original_wire,'UTF8')::jsonb FROM public.capacity_guest_original_caller_returns WHERE intent_id=$1`, i.RequestID).Scan(&callerWire, &e.CallerSHA256, &same); err != nil {
		return e, ErrCapacityConflict
	}
	var c GuestOriginalCallerReturn
	if !same || capacity.BusinessCreationSHA256(callerWire) != e.CallerSHA256 || capacity.DecodeGuestLifecycle(callerWire, &c) != nil || !guestForwardCallerTimelineValid(c, i) {
		return e, ErrCapacityConflict
	}
	// Complete normal success must use the unchanged normal lane instead.
	if c.Status == 200 && c.BodyPersisted && !c.DoFailed && !c.ReadFailed && !c.CloseFailed && !c.OriginalContextFailed && c.DriverReturnedAt.Before(i.OriginalDeadline) {
		return e, ErrCapacityConflict
	}
	if c.BodyPersisted {
		var o model.CapacityGuestRetirementObservationV2
		if capacity.DecodeGuestLifecycle(c.Body, &o) != nil || !capacity.GuestRetirementV2ObservedReturnAuthentic(o, s.Receipt.Enrollment, i) || !reflect.DeepEqual(o, observations[len(observations)-1]) {
			return e, ErrCapacityConflict
		}
	} else if len(c.Body) != 0 {
		return e, ErrCapacityConflict
	}
	var attempt, requestSHA string
	var possible time.Time
	if err = tx.QueryRowContext(ctx, `SELECT attempt_id::text,request_sha256,possible_send_at FROM public.capacity_guest_original_caller_attempts WHERE intent_id=$1`, i.RequestID).Scan(&attempt, &requestSHA, &possible); err != nil || attempt != i.AttemptID || requestSHA != s.RequestSHA256 || c.StartedAt.Before(possible) {
		return e, ErrCapacityConflict
	}
	// Read/authority rows are complete closed sets, never a filtered favorable set.
	// The read deadline is stored at PostgreSQL timestamp precision; compare its
	// upper bound in that same representation. The raw authority still has to
	// precede the exact native signed deadline below, without a time tolerance.
	ar, err := tx.QueryContext(ctx, `SELECT r.id::text,r.phase,r.ordinal,r.possible_read_at,r.original_deadline,v.original_wire,v.authority_sha256,v.original_record=convert_from(v.original_wire,'UTF8')::jsonb,r.original_deadline<=$2::timestamptz FROM public.capacity_guest_original_authority_reads r LEFT JOIN public.capacity_guest_original_authority_returns v ON v.read_id=r.id WHERE r.intent_id=$1 ORDER BY CASE r.phase WHEN 'before_start' THEN 0 ELSE 1 END,r.ordinal`, i.RequestID, i.OriginalDeadline.Format(time.RFC3339Nano))
	if err != nil {
		return e, err
	}
	type transportRef struct {
		id                string
		started, deadline time.Time
		expected          model.CapacityGuestRetirementObservationV2
	}
	refs := []transportRef{}
	n := 0
	for ar.Next() {
		var id, phase, digest string
		var ordinal int
		var started, deadline time.Time
		var raw []byte
		var consistent, deadlineWithinOriginalPG bool
		if err = ar.Scan(&id, &phase, &ordinal, &started, &deadline, &raw, &digest, &consistent, &deadlineWithinOriginalPG); err != nil {
			ar.Close()
			return e, err
		}
		wantPhase := "before_start"
		if n >= 2 {
			wantPhase = "before_poweroff"
		}
		var authority model.CapacityGuestRetirementAuthorityV2
		if n >= 4 || phase != wantPhase || ordinal != n%2+1 || !consistent || capacity.DecodeGuestLifecycle(raw, &authority) != nil || capacity.GuestRetirementSHA(authority) != digest || authority.Schema != capacity.GuestRetirementV2AuthoritySchema || authority.Purpose != capacity.GuestRetirementV2Purpose || authority.Phase != phase || authority.IntentSHA256 != capacity.GuestRetirementSHA(i) || authority.AttemptID != i.AttemptID || authority.NonceSHA256 != i.NonceSHA256 || authority.EnrollmentSHA256 != i.EnrollmentSHA256 || authority.State != "authorized" || authority.SourceCommit != s.Binding.CoreAuthoritySourceCommit || !authority.OriginalDeadline.Equal(i.OriginalDeadline) || authority.GuestNonceSHA256 != capacity.GuestRetirementSHA(i.GuestNonce) || authority.GuestExpiresMonotonicNS != i.GuestExpiresMonotonicNS || !guestForwardAuthorityReadClockValid(started, deadline, deadlineWithinOriginalPG, authority.ObservedAt, i.IssuedAt, i.OriginalDeadline) {
			ar.Close()
			return e, ErrCapacityConflict
		}
		e.AuthoritySHA256 = append(e.AuthoritySHA256, digest)
		if n > 0 {
			expected := n
			if phase == "before_start" {
				expected = 1
			}
			refs = append(refs, transportRef{id, started, deadline, observations[expected-1]})
		}
		n++
	}
	er, cl = ar.Err(), ar.Close()
	if er != nil {
		return e, er
	}
	if cl != nil {
		return e, cl
	}
	if n != 4 {
		return e, ErrCapacityConflict
	}
	// lib/pq has one result stream per transaction. Close the complete authority
	// row set before reading its retained transport joins.
	for _, ref := range refs {
		if err = guestRetirementForwardAuthorityTransportTx(ctx, tx, ref.id, ref.started, ref.deadline, ref.expected, &e); err != nil {
			return e, err
		}
	}
	var transports int
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_guest_original_authority_transport_returns t JOIN public.capacity_guest_original_authority_reads r ON r.id=t.read_id WHERE r.intent_id=$1`, i.RequestID).Scan(&transports); err != nil || transports != 3 {
		return e, ErrCapacityConflict
	}
	// UTC and deterministic ordering make this a complete frame hash, not a
	// latest-row authority. Immutable individual joins above remain mandatory.
	var frame []byte
	err = tx.QueryRowContext(ctx, `SELECT jsonb_build_object('returns',(SELECT jsonb_agg(to_jsonb(r) ORDER BY sequence) FROM public.capacity_vm_retirement_original_returns r WHERE intent_id=$1),'caller',(SELECT to_jsonb(c) FROM public.capacity_guest_original_caller_returns c WHERE intent_id=$1),'attempt',(SELECT to_jsonb(a) FROM public.capacity_guest_original_caller_attempts a WHERE intent_id=$1),'authority',(SELECT jsonb_agg(jsonb_build_object('read',to_jsonb(r),'return',to_jsonb(v)) ORDER BY CASE r.phase WHEN 'before_start' THEN 0 ELSE 1 END,r.ordinal) FROM public.capacity_guest_original_authority_reads r LEFT JOIN public.capacity_guest_original_authority_returns v ON v.read_id=r.id WHERE r.intent_id=$1),'transport',(SELECT jsonb_agg(to_jsonb(t) ORDER BY t.read_id,t.native_stage) FROM public.capacity_guest_original_authority_transport_returns t JOIN public.capacity_guest_original_authority_reads r ON r.id=t.read_id WHERE r.intent_id=$1))::text`, i.RequestID).Scan(&frame)
	if err != nil {
		return e, err
	}
	e.FrameSHA256 = capacity.BusinessCreationSHA256(frame)
	return e, nil
}
func guestRetirementForwardAuthorityTransportTx(ctx context.Context, tx *sql.Tx, id string, started, deadline time.Time, expected model.CapacityGuestRetirementObservationV2, e *guestRetirementForwardEvidence) error {
	var raw, body []byte
	var digest string
	var consistent bool
	err := tx.QueryRowContext(ctx, `SELECT original_wire,original_reply_wire,return_sha256,original_record=convert_from(original_wire,'UTF8')::jsonb FROM public.capacity_guest_original_authority_transport_returns WHERE read_id=$1 AND native_stage='journal'`, id).Scan(&raw, &body, &digest, &consistent)
	if err != nil || !consistent || capacity.BusinessCreationSHA256(raw) != digest {
		return ErrCapacityConflict
	}
	var diagnostic capacity.GuestOriginalHTTPReturn
	if capacity.DecodeGuestLifecycle(raw, &diagnostic) != nil || len(diagnostic.Body) != 0 || diagnostic.StartedAt.Before(started) || !diagnostic.DriverReturnedAt.Before(deadline) {
		return ErrCapacityConflict
	}
	diagnostic.Body = body
	var actual model.CapacityGuestRetirementObservationV2
	if capacity.GuestOriginalHTTPDecode(diagnostic, &actual) != nil || !reflect.DeepEqual(actual, expected) {
		return ErrCapacityConflict
	}
	e.TransportSHA256 = append(e.TransportSHA256, digest)
	return nil
}

// Changes outside the named exact disposal remain outstanding, including
// malformed/unreturned workflow states and cross-realm native authority.
func retirementForwardQuietTx(ctx context.Context, tx *sql.Tx, x retirementForwardSnapshot, ownRun, ownDestroy string) error {
	i := x.original.Request.Intent
	var busy int
	err := tx.QueryRowContext(ctx, `WITH matching AS (SELECT w.id FROM public.workflow_runs w JOIN public.manifests m ON m.id=w.workflow_id AND m.kind='workflow' AND m.namespace=$1 AND m.name=$2 WHERE w.id::text<>$3 AND (w.status NOT IN('succeeded','failed','cancelled') OR w.finished_at IS NULL) UNION SELECT w.id FROM public.workflow_runs w WHERE w.workflow_namespace=$1 AND w.workflow_name=$2 AND w.id::text<>$3 AND (w.status NOT IN('succeeded','failed','cancelled') OR w.finished_at IS NULL)) SELECT count(*) FROM matching`, x.spec.Workflow.Namespace, x.spec.Workflow.Name, ownRun).Scan(&busy)
	if err != nil || busy != 0 {
		return ErrCapacityConflict
	}
	err = tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_mutation_grants WHERE `+capacityGrantUndisposedSQL+` AND integration_instance_id=$1 AND scope_checksum=$2 AND profile_name=$3 AND state IN('issued','redeemed','settled','compensating') AND id::text<>$4`, x.binding.IntegrationInstanceID, x.binding.ScopeChecksum, x.binding.ProfileName, ownDestroy).Scan(&busy)
	if err != nil || busy != 0 {
		return ErrCapacityConflict
	}
	err = tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_guest_notify_canary_challenges WHERE policy_id=$1 AND original_deadline>clock_timestamp()`, i.PolicyID).Scan(&busy)
	if err != nil || busy != 0 {
		return ErrCapacityConflict
	}
	return nil
}

func retirementForwardEvidenceSHA(e guestRetirementForwardEvidence) string {
	raw, _ := json.Marshal(e)
	return capacity.BusinessCreationSHA256(raw)
}

// The bool is a source-owned PostgreSQL comparison, never a caller assertion.
// Keep original native timestamps exact for the actual authority observation.
func guestForwardAuthorityReadClockValid(started, deadline time.Time, deadlineWithinOriginalPG bool, observed, issued, originalDeadline time.Time) bool {
	return deadlineWithinOriginalPG && !started.Before(issued) && deadline.Sub(started) <= 5*time.Second && !observed.Before(started) && observed.Before(deadline) && observed.Before(originalDeadline)
}

// Reapply the original caller ingress timeline invariants without requiring its
// success ACK. A late/context-failed original remains a truthful failed fact.
func guestForwardCallerTimelineValid(c GuestOriginalCallerReturn, i model.CapacityGuestRetirementIntentV2) bool {
	return GuestOriginalCallerBodyFactsValid(c) && c.RequestID == i.RequestID && c.AttemptID == i.AttemptID && c.OriginalDeadline.Equal(i.OriginalDeadline) && !c.PreflightFailed && !c.StartedAt.Before(i.IssuedAt) && !c.DriverReturnedAt.Before(c.StartedAt) && !c.DoStartedAt.Before(c.StartedAt) && !c.DoReturnedAt.Before(c.DoStartedAt) && !c.DoReturnedAt.After(c.DriverReturnedAt) && (c.CloseReturnedAt.IsZero() || !c.CloseReturnedAt.Before(c.DoReturnedAt) && !c.CloseReturnedAt.After(c.DriverReturnedAt)) && (c.ReadReturnedAt.IsZero() || !c.ReadReturnedAt.Before(c.DoReturnedAt) && !c.CloseReturnedAt.Before(c.ReadReturnedAt) && !c.CloseReturnedAt.After(c.DriverReturnedAt)) && (c.DoFailed || !c.ReadReturnedAt.IsZero() && !c.CloseReturnedAt.IsZero())
}
