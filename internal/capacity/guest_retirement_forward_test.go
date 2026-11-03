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
		r, e, key, observer := retirementV2Unit(t)
		// Declare the distinct empty enrollment and intent BEFORE nonce/journal
		// construction, so every original hash, clock and signature binds it.
		e.Statement.Writers = []model.CapacityGuestRetirementWriter{}
		e.Statement.WriterRosterSHA256 = GuestRetirementSHA(e.Statement.Writers)
		r.Intent.Writers = []model.CapacityGuestRetirementWriter{}
		r.Intent.WriterRosterSHA256 = e.Statement.WriterRosterSHA256
		r.Intent.EnrollmentSHA256 = GuestRetirementSHA(e)
		r.Intent.GuestNonce = retirementV2UnitNonce(r, e, observer)
		r.Intent.GuestExpiresMonotonicNS = r.Intent.GuestNonce.ExpiresMonotonicNS - 1000000
		r.Signature, _ = GuestLifecycleSignature(key, r.Intent)
		rows := RecoveryFixtureRetirementJournal(t, r.Intent, e)
		if !GuestRetirementForwardPrefix(rows[:3], e, r.Intent) || !GuestRetirementForwardPrefix(rows, e, r.Intent) {
			t.Fatal("a genuinely enrolled empty roster was relabeled as missing evidence")
		}
		for _, row := range rows[1:] {
			if GuestRetirementV2Observation(row, e, r.Intent, true) == nil || GuestRetirementV2RuntimeReturn(*row.Record.RuntimeReturn, e, r.Intent, row.Record.RecordedAt) == nil {
				t.Fatal("forward-only empty roster changed normal V2 validation")
			}
		}
		nilEnrollment, nilIntent := e, r.Intent
		nilEnrollment.Statement.Writers, nilIntent.Writers = nil, nil
		if guestRetirementForwardEnrolledEmptyRoster(nilEnrollment, r.Intent) || guestRetirementForwardEnrolledEmptyRoster(e, nilIntent) {
			t.Fatal("missing roster was relabeled as an explicitly enrolled empty roster")
		}
		wrongRoster := r.Intent
		wrongRoster.WriterRosterSHA256 = r.Intent.NonceSHA256
		if guestRetirementForwardEnrolledEmptyRoster(e, wrongRoster) {
			t.Fatal("foreign roster hash enabled the empty-roster allowance")
		}
		for _, invalid := range []string{"missing_writer_return", "missing_before_census", "missing_after_census", "unknown_process"} {
			wire, err := json.Marshal(rows)
			if err != nil {
				t.Fatal(err)
			}
			var changed []model.CapacityGuestRetirementObservationV2
			if err = json.Unmarshal(wire, &changed); err != nil {
				t.Fatal(err)
			}
			for n := range changed {
				row := &changed[n]
				if row.Record.RuntimeReturn != nil {
					switch invalid {
					case "missing_writer_return":
						row.Record.RuntimeReturn.Writers = nil
					case "missing_before_census":
						row.Record.RuntimeReturn.CensusBefore.Processes = nil
					case "missing_after_census":
						row.Record.RuntimeReturn.CensusAfter.Processes = nil
					case "unknown_process":
						row.Record.RuntimeReturn.CensusBefore.Processes = []model.CapacityGuestRetirementNativeProcess{{PID: 999, StartTicks: 999}}
					}
				}
				if n > 0 {
					row.Record.PreviousSHA256 = changed[n-1].RecordSHA256
				}
				row.RecordSHA256 = GuestRetirementSHA(row.Record)
				row.Signature = ""
				row.Signature, _ = GuestLifecycleSignature(observer, *row)
			}
			if GuestRetirementForwardPrefix(changed[:3], e, r.Intent) || GuestRetirementForwardPrefix(changed, e, r.Intent) {
				t.Fatal("signed empty-roster frame concealed missing/foreign native census", invalid)
			}
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
