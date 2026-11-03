//go:build recoveryfixture && !nativequalification

package capacity

import (
	"encoding/json"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// These are signed cryptographic operands, not native Guest/provider authority.
// The repository independently authenticates enrollment/nonce/caller/context.
func TestGuestRetirementForwardAuthenticatedWholePrefix(t *testing.T) {
	t.Run("enrolled_empty_roster", func(t *testing.T) {
		r, e, _, observer := retirementV2Unit(t)
		r.Intent.GuestNonce = retirementV2UnitNonce(r, e, observer)
		r.Intent.GuestExpiresMonotonicNS = r.Intent.GuestNonce.ExpiresMonotonicNS - 1000000
		rows := RecoveryFixtureRetirementJournal(t, r.Intent, e)
		// Construct a distinct signed empty-roster operand before admission.
		// The repository still authenticates the original enrollment separately.
		e.Statement.Writers = []model.CapacityGuestRetirementWriter{}
		e.Statement.WriterRosterSHA256 = GuestRetirementSHA(e.Statement.Writers)
		r.Intent.Writers = []model.CapacityGuestRetirementWriter{}
		r.Intent.WriterRosterSHA256 = e.Statement.WriterRosterSHA256
		r.Intent.EnrollmentSHA256 = GuestRetirementSHA(e)
		r.Intent.GuestNonce = retirementV2UnitNonce(r, e, observer)
		for n := range rows {
			row := &rows[n]
			row.Record.Intent = r.Intent
			row.Record.IntentSHA256 = GuestRetirementSHA(r.Intent)
			row.Record.EnrollmentSHA256 = GuestRetirementSHA(e)
			row.Record.Clock.GuestNonceSHA256 = GuestRetirementSHA(r.Intent.GuestNonce)
			if row.Record.RuntimeReturn != nil {
				runtime := *row.Record.RuntimeReturn
				runtime.IntentSHA256 = GuestRetirementSHA(r.Intent)
				runtime.WriterRosterSHA256 = e.Statement.WriterRosterSHA256
				runtime.Writers = []model.CapacityGuestRetirementWriterReturn{}
				runtime.CensusBefore.Processes = []model.CapacityGuestRetirementNativeProcess{}
				runtime.Clock.GuestNonceSHA256 = GuestRetirementSHA(r.Intent.GuestNonce)
				row.Record.RuntimeReturn = &runtime
			}
			if n > 0 {
				row.Record.PreviousSHA256 = rows[n-1].RecordSHA256
			}
			row.RecordSHA256 = GuestRetirementSHA(row.Record)
			row.Clock = row.Record.Clock
			row.ActiveIntentSHA256 = GuestRetirementSHA(r.Intent)
			row.Signature = ""
			row.Signature, _ = GuestLifecycleSignature(observer, *row)
		}
		if !GuestRetirementForwardPrefix(rows[:3], e, r.Intent) || !GuestRetirementForwardPrefix(rows, e, r.Intent) {
			t.Fatal("a genuinely enrolled empty roster was relabeled as missing evidence")
		}
	})
	for _, length := range []int{3, 4} {
		r, e, key, observer := retirementV2Unit(t)
		r.Intent.GuestNonce = retirementV2UnitNonce(r, e, observer)
		r.Intent.GuestExpiresMonotonicNS = r.Intent.GuestNonce.ExpiresMonotonicNS - 1000000
		r.Signature, _ = GuestLifecycleSignature(key, r.Intent)
		original := RecoveryFixtureRetirementJournal(t, r.Intent, e)
		if !GuestRetirementForwardPrefix(original[:length], e, r.Intent) {
			t.Fatal("genuine complete authenticated prefix refused", length)
		}
		for _, name := range []string{"missing", "extra", "uncertain", "foreign_enrollment", "bad_link", "missing_runtime", "false_quiescence", "fabricated_poweroff", "late_kernel", "invalid_signature"} {
			t.Run(name+string(rune('0'+length)), func(t *testing.T) {
				raw, _ := json.Marshal(original[:length])
				var rows []model.CapacityGuestRetirementObservationV2
				if err := json.Unmarshal(raw, &rows); err != nil {
					t.Fatal(err)
				}
				switch name {
				case "missing":
					rows = rows[:2]
				case "extra":
					rows = append(rows, rows[len(rows)-1])
					rows = append(rows, rows[len(rows)-1])
				case "uncertain":
					rows[1].Record.State = "uncertain"
				case "foreign_enrollment":
					rows[1].Record.EnrollmentSHA256 = rows[1].Record.IntentSHA256
				case "bad_link":
					rows[2].Record.PreviousSHA256 = rows[0].RecordSHA256
				case "missing_runtime":
					rows[1].Record.RuntimeReturn = nil
				case "false_quiescence":
					rows[2].Record.WriterQuiescenceEvidence = false
				case "fabricated_poweroff":
					rows[2].Record.PoweroffCommandReturned = true
					rows[2].Record.PoweroffOperation = original[3].Record.PoweroffOperation
				case "late_kernel":
					rows[len(rows)-1].Record.Clock.ReturnedMonotonicNS = rows[len(rows)-1].Record.Clock.ExpiresMonotonicNS
					rows[len(rows)-1].Clock = rows[len(rows)-1].Record.Clock
				case "invalid_signature":
					rows[len(rows)-1].Signature = "invalid"
				}
				if name != "invalid_signature" {
					for n := range rows {
						rows[n].RecordSHA256 = GuestRetirementSHA(rows[n].Record)
						rows[n].Signature = ""
						rows[n].Signature, _ = GuestLifecycleSignature(observer, rows[n])
					}
				}
				if GuestRetirementForwardPrefix(rows, e, r.Intent) {
					t.Fatal("malformed/uncertain/late whole frame accepted", name, length)
				}
			})
		}
	}
}
