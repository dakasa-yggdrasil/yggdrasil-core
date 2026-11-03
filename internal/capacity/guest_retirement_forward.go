package capacity

import "github.com/dakasa-yggdrasil/yggdrasil-core/model"

// GuestRetirementForwardPrefix validates the original signed *prefix*, not a
// command completion or a caller ACK. It never changes the normal V2 proof.
// Clock validation stays at the authenticated original Guest operation times.
func GuestRetirementForwardPrefix(observed []model.CapacityGuestRetirementObservationV2, enrollment model.CapacityGuestRetirementEnrollment, intent model.CapacityGuestRetirementIntentV2) bool {
	if (len(observed) != 3 && len(observed) != 4) || ValidateGuestRetirementV2Nonce(intent, enrollment) != nil {
		return false
	}
	states := []string{"possible_start", "quiescent", "poweroff_possible_start", "poweroff_command_returned"}
	for n, row := range observed {
		if row.Record.Sequence != n+1 || row.Record.State != states[n] || GuestRetirementV2Observation(row, enrollment, intent, false) != nil || row.Record.PoweredOffObserved || n < 3 && (row.Record.PoweroffCommandReturned || row.Record.PoweroffOperation != nil) {
			return false
		}
		if n > 0 && !GuestRetirementV2RecordSuccessor(observed[n-1].Record, row.Record) {
			return false
		}
	}
	return observed[2].Record.WriterQuiescenceEvidence && observed[2].Record.PoweroffPossibleStartAt != nil
}
