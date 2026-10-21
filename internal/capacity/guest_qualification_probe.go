package capacity

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"golang.org/x/sys/unix"
	"reflect"
	"time"
)

const qualificationProbeSchema = "original_qualification_serving_probe_v2"
const qualificationProbePurpose = "same_original_admitted_writer_useful_echo"
const qualificationEchoSchema = "original_qualification_writer_echo_v1"
const qualificationEchoPrefix = "original-admitted-useful-echo:"

type QualificationProbeNonce struct {
	Schema             string                                `json:"schema"`
	ChallengeID        string                                `json:"challenge_id"`
	EnrollmentSHA256   string                                `json:"enrollment_sha256"`
	Actor              model.CapacityGuestRetirementLifetime `json:"actor"`
	Runtime            model.CapacityGuestRetirementLifetime `json:"runtime"`
	Writer             model.CapacityGuestRetirementWriter   `json:"writer"`
	NonceSHA256        string                                `json:"nonce_sha256"`
	PreflightSHA256    string                                `json:"preflight_sha256"`
	IssuedMonotonicNS  int64                                 `json:"issued_monotonic_ns"`
	ExpiresMonotonicNS int64                                 `json:"expires_monotonic_ns"`
	Signature          string                                `json:"signature"`
}

type QualificationProbeChallenge struct {
	Schema           string                                `json:"schema"`
	Purpose          string                                `json:"purpose"`
	ChallengeID      string                                `json:"challenge_id"`
	EnrollmentSHA256 string                                `json:"enrollment_sha256"`
	Tuple            model.CapacityGuestNativeTuple        `json:"tuple"`
	Actor            model.CapacityGuestRetirementLifetime `json:"actor"`
	Runtime          model.CapacityGuestRetirementLifetime `json:"runtime"`
	Writer           model.CapacityGuestRetirementWriter   `json:"writer"`
	NonceSHA256      string                                `json:"nonce_sha256"`
	GuestNonce       QualificationProbeNonce               `json:"guest_nonce"`
	IssuedAt         time.Time                             `json:"issued_at"`
	OriginalDeadline time.Time                             `json:"original_deadline"`
}
type QualificationProbeRequest struct {
	Challenge QualificationProbeChallenge `json:"challenge"`
	Signature string                      `json:"signature"`
}
type QualificationWriterEcho struct {
	Schema                 string                                `json:"schema"`
	ChallengeSHA256        string                                `json:"challenge_sha256"`
	Writer                 model.CapacityGuestRetirementLifetime `json:"writer"`
	Echo                   string                                `json:"echo"`
	OriginalReadReturnedAt time.Time                             `json:"original_read_returned_at"`
}
type QualificationPipeIdentity struct {
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
	Mode   uint32 `json:"mode"`
}
type QualificationWriterProbeReturn struct {
	Schema                                string                              `json:"schema"`
	ChallengeSHA256                       string                              `json:"challenge_sha256"`
	Writer                                model.CapacityGuestRetirementWriter `json:"writer"`
	InputPipe                             QualificationPipeIdentity           `json:"input_pipe"`
	OutputPipe                            QualificationPipeIdentity           `json:"output_pipe"`
	OriginalProbeStartedAt                time.Time                           `json:"original_probe_started_at"`
	OriginalWriteSHA256                   string                              `json:"original_write_sha256"`
	OriginalWriteBytes                    int                                 `json:"original_write_bytes"`
	OriginalWriteReturnedAt               time.Time                           `json:"original_write_returned_at"`
	OriginalReadSHA256                    string                              `json:"original_read_sha256"`
	OriginalReadReturnedAt                time.Time                           `json:"original_read_returned_at"`
	OriginalDuplicateInputCloseReturnedAt time.Time                           `json:"original_duplicate_input_close_returned_at"`
	OriginalEcho                          QualificationWriterEcho             `json:"original_echo"`
	OriginalNativeAfterReturnedAt         time.Time                           `json:"original_native_after_returned_at"`
}
type QualificationProbeReceipt struct {
	Schema                               string                                       `json:"schema"`
	ChallengeSHA256                      string                                       `json:"challenge_sha256"`
	EnrollmentSHA256                     string                                       `json:"enrollment_sha256"`
	OriginalRegistrationSHA256           string                                       `json:"original_registration_sha256"`
	Actor                                model.CapacityGuestRetirementLifetime        `json:"actor"`
	Runtime                              model.CapacityGuestRetirementLifetime        `json:"runtime"`
	WriterProbe                          QualificationWriterProbeReturn               `json:"writer_probe"`
	CensusBefore                         model.CapacityGuestRetirementProtectedCensus `json:"census_before"`
	CensusAfter                          model.CapacityGuestRetirementProtectedCensus `json:"census_after"`
	OriginalReadStartedAt                time.Time                                    `json:"original_read_started_at"`
	OriginalRuntimeSocketCloseReturnedAt time.Time                                    `json:"original_runtime_socket_close_returned_at"`
	OriginalNativeAfterReturnedAt        time.Time                                    `json:"original_native_after_returned_at"`
	Signature                            string                                       `json:"signature"`
}

// Source qualification only: success proves the SAME admitted echo writer,
// never a complete production catalog, business readiness or provider fencing.
func ValidateProbeReturn(request QualificationProbeRequest, receipt QualificationProbeReceipt, enrollment model.CapacityGuestRetirementEnrollment, registrationSHA string, now time.Time) error {
	c := request.Challenge
	s := enrollment.Statement
	p := receipt.WriterProbe
	e := p.OriginalEcho
	if c.Schema != qualificationProbeSchema || c.Purpose != qualificationProbePurpose || !guestUUID(c.ChallengeID) || c.EnrollmentSHA256 != GuestRetirementSHA(enrollment) || c.Tuple != s.Tuple || c.Actor != s.Actor || c.Runtime != s.Runtime || len(s.Writers) != 1 || c.Writer != s.Writers[0] || c.Writer.ID != GuestQualificationWriter || !ValidDigest(c.NonceSHA256) || c.IssuedAt.IsZero() || c.IssuedAt.After(now) || c.OriginalDeadline.Sub(c.IssuedAt) > 5*time.Second || !c.OriginalDeadline.After(c.IssuedAt) || !now.Before(c.OriginalDeadline) || !guestQualificationSignature(s.CoreIntentPublicKey, request.Signature, c) {
		return fmt.Errorf("authentic original qualification probe required")
	}
	if ValidateQualificationProbeNonce(c, enrollment) != nil {
		return fmt.Errorf("authentic guest nonce required")
	}
	if receipt.Schema != qualificationProbeSchema || receipt.ChallengeSHA256 != GuestRetirementSHA(c) || receipt.EnrollmentSHA256 != c.EnrollmentSHA256 || receipt.OriginalRegistrationSHA256 != registrationSHA || receipt.Actor != c.Actor || receipt.Runtime != c.Runtime || receipt.OriginalReadStartedAt.IsZero() || receipt.OriginalRuntimeSocketCloseReturnedAt.Before(p.OriginalNativeAfterReturnedAt) || receipt.OriginalNativeAfterReturnedAt.Before(receipt.OriginalRuntimeSocketCloseReturnedAt) || !GuestRetirementProtectedCensus(receipt.CensusBefore, enrollment, p.OriginalProbeStartedAt, true) || !GuestRetirementProtectedCensus(receipt.CensusAfter, enrollment, receipt.OriginalNativeAfterReturnedAt, true) || !reflect.DeepEqual(receipt.CensusBefore.Processes, receipt.CensusAfter.Processes) || receipt.CensusBefore.RawCensusSHA256 != receipt.CensusAfter.RawCensusSHA256 {
		return fmt.Errorf("authentic original qualification probe required")
	}
	if p.Schema != qualificationProbeSchema || p.ChallengeSHA256 != GuestRetirementSHA(c) || p.Writer != c.Writer || p.InputPipe.Device == 0 || p.InputPipe.Inode == 0 || p.InputPipe.Mode&unix.S_IFMT != unix.S_IFIFO || p.OutputPipe.Device == 0 || p.OutputPipe.Inode == 0 || p.OutputPipe.Mode&unix.S_IFMT != unix.S_IFIFO || p.InputPipe == p.OutputPipe || !ValidDigest(p.OriginalWriteSHA256) || p.OriginalWriteBytes < 1 || p.OriginalWriteBytes > 65536 || p.OriginalProbeStartedAt.Before(receipt.CensusBefore.ObservedAt) || p.OriginalWriteReturnedAt.Before(p.OriginalProbeStartedAt) || p.OriginalDuplicateInputCloseReturnedAt.Before(p.OriginalWriteReturnedAt) || p.OriginalReadReturnedAt.Before(p.OriginalDuplicateInputCloseReturnedAt) || p.OriginalNativeAfterReturnedAt.Before(p.OriginalReadReturnedAt) || e.Schema != qualificationEchoSchema || e.ChallengeSHA256 != GuestRetirementSHA(c) || e.Writer != c.Writer.Lifetime || e.Echo != qualificationEchoPrefix+c.NonceSHA256 || e.OriginalReadReturnedAt.Before(p.OriginalProbeStartedAt) || e.OriginalReadReturnedAt.After(p.OriginalReadReturnedAt) || p.OriginalReadSHA256 != GuestRetirementSHA(e) {
		return fmt.Errorf("authentic original qualification probe required")
	}
	signature := receipt.Signature
	receipt.Signature = ""
	if !guestQualificationSignature(s.ObservationPublicKey, signature, receipt) {
		return fmt.Errorf("authentic original qualification probe required")
	}
	return nil
}
func guestQualificationSignature(public, signature string, value any) bool {
	key, e1 := base64.StdEncoding.DecodeString(public)
	sig, e2 := base64.StdEncoding.DecodeString(signature)
	raw, e3 := json.Marshal(value)
	return e1 == nil && e2 == nil && e3 == nil && len(key) == ed25519.PublicKeySize && len(sig) == ed25519.SignatureSize && base64.StdEncoding.EncodeToString(key) == public && base64.StdEncoding.EncodeToString(sig) == signature && ed25519.Verify(ed25519.PublicKey(key), raw, sig)
}

// Verify a separate producer signature without granting phase authority.
func GuestQualificationSignature(public, signature string, value any) bool {
	return guestQualificationSignature(public, signature, value)
}
