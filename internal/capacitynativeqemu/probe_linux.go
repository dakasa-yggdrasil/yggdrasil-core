//go:build linux && nativequalification

package capacitynativeqemu

import (
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"time"
)

const qualificationProbeSchema = "original_qualification_serving_probe_v1"
const qualificationProbePurpose = "same_original_admitted_writer_useful_echo"

type QualificationProbeChallenge = capacity.QualificationProbeChallenge
type QualificationProbeRequest = capacity.QualificationProbeRequest
type QualificationPipeIdentity = capacity.QualificationPipeIdentity
type QualificationWriterProbeReturn = capacity.QualificationWriterProbeReturn
type QualificationProbeReceipt = capacity.QualificationProbeReceipt

func ValidateProbeReturn(request QualificationProbeRequest, receipt QualificationProbeReceipt, enrollment model.CapacityGuestRetirementEnrollment, registrationSHA string, now time.Time) error {
	return capacity.ValidateProbeReturn(request, receipt, enrollment, registrationSHA, now)
}
func verifySignature(public, signature string, value any) bool {
	return capacity.GuestQualificationSignature(public, signature, value)
}
