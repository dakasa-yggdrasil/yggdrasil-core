//go:build linux && nativequalification

package capacitynativeqemu

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func TestHeldHelloFailureValidationGroups(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicText := base64.StdEncoding.EncodeToString(public)
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	deadline := t0.Add(10 * time.Second)
	witness := model.CapacityGuestOriginalCreateWitness{PreregistrationID: "original", ObservedAt: t0}
	pre := model.CapacityGuestOriginalProvisioningPreregistration{PreregistrationID: "original", OriginalDeadline: deadline}
	realm := Realm{Request: SourceRequest{NativeCase: "held_hello_original_deadline", SourceCommit: "source", OriginalContextDeadline: t0.Add(time.Minute)}, Profile: model.CapacityGuestProtectedProfileManifest{OwnerBinarySHA256: "binary"}}
	exit := 1
	digest := capacity.BusinessCreationSHA256([]byte("actual"))
	fact := QualificationFailedOwnerReturn{OriginalReturnedAt: t0.Add(11 * time.Second), OriginalBodySHA256: digest, ErrorClass: "original_owner_error"}
	original := QualificationFailureRecord{
		Schema: "original_qualification_failed_owner_returns_v1", NativeCase: realm.Request.NativeCase, SourceCommit: realm.Request.SourceCommit,
		Scope: "failed_original_owners_diagnostic_not_capacity_admission_or_quiescence", Phase: "original_preownership_failure",
		Tuple: witness.Tuple, PreregistrationID: pre.PreregistrationID, OriginalCreateWitnessSHA256: capacity.GuestRetirementSHA(witness),
		OriginalProvisioningDeadline: deadline, OriginalOperationDeadline: deadline,
		Runtime:               model.CapacityGuestRetirementLifetime{PID: 2, StartTicks: 1, SourceCommit: "source", BinarySHA256: "binary"},
		OriginalChild:         model.CapacityGuestRetirementNativeProcess{PID: 3, StartTicks: 1},
		OriginalStartCalledAt: t0.Add(time.Second), OriginalStartReturnedAt: t0.Add(2 * time.Second),
		OriginalWait: fact, OriginalOutputEOFAndClose: fact, OriginalDiagnosticEOFAndClose: fact, OriginalExitCode: &exit,
		ProvisioningJournal: &QualificationProvisioningJournalRead{LastSequence: 1, LastState: "possible_profile_start", LastRecordSHA256: digest,
			OriginalReadStartedAt: t0.Add(12 * time.Second), OriginalReadReturnedAt: t0.Add(13 * time.Second), OriginalCloseReturnedAt: t0.Add(13 * time.Second),
			Records: []QualificationProvisioningRecordRead{{Sequence: 1, OriginalRecordSHA256: digest, OriginalReadReturnedAt: t0.Add(12 * time.Second), OriginalCloseReturnedAt: t0.Add(12 * time.Second)}}},
		NativeCensusErrorClass: "original_census_error", RecordedAt: t0.Add(14 * time.Second), ProducerPublicKey: publicText,
	}
	for _, tc := range []struct{ name, want string }{
		{"valid", ""}, {"identity", "source_refusal_identity"}, {"signature", "source_refusal_signature"},
		{"owners", "source_refusal_owners"}, {"journal", "source_refusal_journal"}, {"case", "source_refusal_case"}, {"census", "source_refusal_census"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			record := original
			journal := *original.ProvisioningJournal
			journal.Records = append([]QualificationProvisioningRecordRead(nil), journal.Records...)
			record.ProvisioningJournal = &journal
			switch tc.name {
			case "identity":
				record.PreregistrationID = "foreign"
			case "owners":
				record.OriginalWait.OriginalBodySHA256 = "invalid"
			case "journal":
				record.ProvisioningJournal.Records[0].Sequence = 2
			case "case":
				record.ProvisioningJournal.AdmissionPossible = true
			case "census":
				record.NativeCensusErrorClass = ""
			}
			wire, err := json.Marshal(record)
			if err != nil {
				t.Fatal(err)
			}
			record.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(private, wire))
			if tc.name == "signature" {
				record.Signature = base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
			}
			label, err := realm.ValidateOriginalFailureClassified(record, pre, witness, publicText, t0.Add(15*time.Second))
			originalErr := realm.ValidateOriginalFailure(record, pre, witness, publicText, t0.Add(15*time.Second))
			if label != tc.want || (tc.want == "" && (err != nil || originalErr != nil)) || (tc.want != "" && (!errors.Is(err, ErrOriginalUnknown) || !errors.Is(originalErr, ErrOriginalUnknown))) {
				t.Fatalf("closed validation classification differs: %q", label)
			}
		})
	}
}
