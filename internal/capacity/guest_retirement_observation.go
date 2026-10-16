package capacity

import (
	"fmt"
	"reflect"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// Authentication for append-only retention is deliberately separate from
// quiescence/admission. An original uncertain/late/partial return remains a
// durable fact but cannot satisfy GuestRetirementObservation's complete joins.
func GuestRetirementObservedReturnAuthentic(o model.CapacityGuestRetirementObservation, e model.CapacityGuestRetirementEnrollment, i model.CapacityGuestRetirementIntent, now time.Time) bool {
	r := o.Record
	if o.Schema != GuestRetirementSchema || r.Schema != GuestRetirementSchema || r.Sequence < 1 || r.Sequence > 4 || r.Intent != i || r.IntentSHA256 != GuestRetirementSHA(i) || r.EnrollmentSHA256 != GuestRetirementSHA(e) || o.RecordSHA256 != GuestRetirementSHA(r) || o.Reader != e.Statement.Actor || !GuestRetirementLifetime(o.Reader) || o.ObservedAt.IsZero() || o.ObservedAt.After(now) || r.RecordedAt.IsZero() || r.RecordedAt.After(o.ObservedAt) || r.PossibleStartAt.Before(i.IssuedAt) || r.RecordedAt.Before(r.PossibleStartAt) || r.PoweredOffObserved || (r.Sequence == 1 && r.PreviousSHA256 != "") || (r.Sequence > 1 && !ValidDigest(r.PreviousSHA256)) {
		return false
	}
	states := []string{"possible_start", "quiescent", "poweroff_possible_start", "poweroff_command_returned"}
	if r.State != states[r.Sequence-1] && (r.State != "uncertain" || (r.Sequence != 2 && r.Sequence != 4)) {
		return false
	}
	if (o.ActiveAttemptID != "" || o.ActiveIntentSHA256 != "") && (o.ActiveAttemptID != i.AttemptID || o.ActiveIntentSHA256 != GuestRetirementSHA(i)) {
		return false
	}
	signature := o.Signature
	o.Signature = ""
	return guestRetirementVerify(e.Statement.ObservationPublicKey, signature, o)
}

// A signature authenticates a source return; it does not supply its missing
// operation, original caller return, cgroup history or native machine-off.
func GuestRetirementObservation(o model.CapacityGuestRetirementObservation, e model.CapacityGuestRetirementEnrollment, i model.CapacityGuestRetirementIntent, now time.Time, active bool) error {
	r := o.Record
	states := []string{"possible_start", "quiescent", "poweroff_possible_start", "poweroff_command_returned"}
	if o.Schema != GuestRetirementSchema || r.Schema != GuestRetirementSchema || r.Sequence < 1 || r.Sequence > len(states) || (r.State != states[r.Sequence-1] && (r.State != "uncertain" || (r.Sequence != 2 && r.Sequence != 4))) || r.Intent != i || r.IntentSHA256 != GuestRetirementSHA(i) || r.EnrollmentSHA256 != GuestRetirementSHA(e) || o.RecordSHA256 != GuestRetirementSHA(r) || !o.JournalComplete || o.HoldReasons == nil || len(o.HoldReasons) != 0 || o.Reader != e.Statement.Actor || !GuestRetirementLifetime(o.Reader) || o.ObservedAt.IsZero() || o.ObservedAt.After(now) || now.Sub(o.ObservedAt) > 30*time.Second || r.RecordedAt.IsZero() || r.RecordedAt.After(o.ObservedAt) || r.PossibleStartAt.Before(i.IssuedAt) || r.RecordedAt.Before(r.PossibleStartAt) || !r.RecordedAt.Before(i.OriginalDeadline) || r.WriterQuiescenceScope != "enrolled_roster_only" || r.PoweredOffObserved || (r.Sequence == 1 && r.PreviousSHA256 != "") || (r.Sequence > 1 && !ValidDigest(r.PreviousSHA256)) {
		return fmt.Errorf("complete original Guest journal return required")
	}
	if active && (o.ActiveAttemptID != i.AttemptID || o.ActiveIntentSHA256 != GuestRetirementSHA(i) || !now.Before(i.OriginalDeadline)) {
		return fmt.Errorf("actual original Guest attempt is not currently active")
	}
	if !active && ((o.ActiveAttemptID != "" || o.ActiveIntentSHA256 != "") && (o.ActiveAttemptID != i.AttemptID || o.ActiveIntentSHA256 != GuestRetirementSHA(i))) {
		return fmt.Errorf("foreign original Guest attempt")
	}
	if r.Sequence == 1 {
		if r.RuntimeOperation != nil || r.RuntimeReturn != nil || r.WriterQuiescenceEvidence || r.PoweroffPossibleStartAt != nil || r.PoweroffOperation != nil || r.PoweroffCommandReturned {
			return fmt.Errorf("possible-start record fabricated a return")
		}
	} else {
		if r.RuntimeOperation == nil || r.RuntimeReturn == nil || !r.WriterQuiescenceEvidence || !guestPlacementReturned(*r.RuntimeOperation, r.PossibleStartAt, r.RecordedAt) || r.RuntimeReturn.Withdraw.StartedAt.Before(r.RuntimeOperation.StartedAt) || r.RuntimeReturn.ReturnedAt.After(r.RuntimeOperation.WaitReturnedAt) || GuestRetirementRuntimeReturn(*r.RuntimeReturn, e, i, r.RecordedAt) != nil {
			return fmt.Errorf("original withdrawal, drain and worker/connection joins required")
		}
		for _, w := range r.RuntimeReturn.Writers {
			if w.AdmissionClosedAt.Before(r.RuntimeOperation.StartedAt) {
				return fmt.Errorf("writer admission closure preceded its original operation")
			}
		}
	}
	if r.Sequence < 3 {
		if r.PoweroffPossibleStartAt != nil || r.PoweroffOperation != nil || r.PoweroffCommandReturned {
			return fmt.Errorf("poweroff lacks original durable admission")
		}
	} else if r.PoweroffPossibleStartAt == nil || r.PoweroffPossibleStartAt.Before(r.RuntimeOperation.WaitReturnedAt) || r.PoweroffPossibleStartAt.After(r.RecordedAt) {
		return fmt.Errorf("original poweroff possible-start required")
	}
	if r.Sequence == 3 && (r.PoweroffOperation != nil || r.PoweroffCommandReturned) {
		return fmt.Errorf("possible-poweroff record fabricated a command return")
	}
	if r.Sequence == 4 && (r.PoweroffOperation == nil || !r.PoweroffCommandReturned || !guestPlacementReturned(*r.PoweroffOperation, *r.PoweroffPossibleStartAt, r.RecordedAt)) {
		return fmt.Errorf("actual original poweroff command return required")
	}
	signature := o.Signature
	o.Signature = ""
	if !guestRetirementVerify(e.Statement.ObservationPublicKey, signature, o) {
		return fmt.Errorf("original Guest journal signature refused")
	}
	return nil
}

func GuestRetirementRecordSuccessor(previous, next model.CapacityGuestRetirementRecord) bool {
	return next.Sequence == previous.Sequence+1 && next.PreviousSHA256 == GuestRetirementSHA(previous) && next.Intent == previous.Intent && next.IntentSHA256 == previous.IntentSHA256 && next.EnrollmentSHA256 == previous.EnrollmentSHA256 && next.PossibleStartAt.Equal(previous.PossibleStartAt) && !next.RecordedAt.Before(previous.RecordedAt) && (previous.Sequence == 1 || (reflect.DeepEqual(previous.RuntimeOperation, next.RuntimeOperation) && reflect.DeepEqual(previous.RuntimeReturn, next.RuntimeReturn) && previous.WriterQuiescenceEvidence == next.WriterQuiescenceEvidence)) && (previous.Sequence < 3 || reflect.DeepEqual(previous.PoweroffPossibleStartAt, next.PoweroffPossibleStartAt))
}
