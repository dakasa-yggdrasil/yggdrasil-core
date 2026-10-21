package capacity

import (
	"bytes"
	"fmt"
	"reflect"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

const GuestNotifyBusinessQuerySHA256 = "9a4b0834f5a89e01adf0a6784570373bf28fcb8ff0a87d76179ca97b2656ae4e"

const GuestNotifyCanaryChallengeSchema = "guest_notify_business_canary_challenge_v1"
const GuestNotifyCanaryReadSchema = "guest_notify_business_canary_read_v1"
const GuestNotifyCanaryReadPurpose = "original_notify_creation_read_only"
const GuestNotifyCanaryPublicationChallengeSchema = "guest_notify_business_canary_publish_challenge_v1"
const GuestNotifyCanaryPublicationSchema = "guest_notify_business_canary_publication_v1"
const GuestNotifyCanaryPublicationPurpose = "create_notify_original_canary_once"
const GuestNotifyCanaryPath = "/v1/guest/provisioning/notify-creation-canary"
const GuestNotifyCanaryPublicationPath = "/v1/guest/provisioning/notify-creation-canary-publication"

func GuestNotifyCanaryUsage(s string) bool {
	return s == "initial_useful_membership" || s == "before_retirement_floor" || s == "after_retirement_floor"
}
func ValidateGuestNotifyCanaryBinding(p model.CapacityPolicySpec) error {
	b := p.GuestNotifyCanaryBinding
	if b == nil {
		return nil
	}
	r := p.GuestRetirementBinding
	if b.Mode != "original_guest_notify_canary_v1" || b.Name == "" || len(b.Name) > 64 || r == nil || r.EvidenceClass != "owned_provisioner_original" || r.ProfileManifest.CoverageClass != "complete_production_roster" || len(r.ProfileManifest.Writers) != 1 || b.WriterID != r.ProfileManifest.Writers[0].ID || b.NotifySourceCommit != r.ProfileManifest.Writers[0].SourceCommit || !businessSource.MatchString(b.NotifySourceCommit) || b.QuerySHA256 != GuestNotifyBusinessQuerySHA256 || !ValidDigest(b.RecipientSHA256) || b.RecipientCount != 2 || b.Database == "" || !businessDecimal(b.DatabaseOID, 32) || !businessDecimal(b.SystemID, 64) || len(b.TableOIDs) != 4 || b.MinimumPublicationIntervalSeconds < 5 || b.MinimumPublicationIntervalSeconds > 3600 || b.MinimumPublicationIntervalSeconds > p.MaxEvidenceAgeSeconds || b.MaximumPublicationsPerHour < 1 || b.MaximumPublicationsPerHour > 120 {
		return fmt.Errorf("fixed original Guest Notify canary binding required")
	}
	if ValidateGuestNotifyCanaryTopology(r.ProfileManifest.NotifyCanaryTopology) != nil || b.TopologySHA256 != GuestRetirementSHA(r.ProfileManifest.NotifyCanaryTopology) || r.ProfileManifest.NotifyCanaryTopology.Binding != r.MutationBindingName {
		return fmt.Errorf("source-pinned declarative Notify canary topology required")
	}
	provider := ""
	for _, profile := range p.Profiles {
		if profile.Name == r.ProfileManifest.Profile {
			if provider != "" {
				return fmt.Errorf("one Notify canary provider required")
			}
			provider = profile.Provider
		}
	}
	if provider != "aws" && provider != "hetzner" || len(r.Members) == 0 {
		return fmt.Errorf("original Notify member provider required")
	}
	for _, member := range r.Members {
		if GuestNotifyQueue(r.ProfileManifest.NotifyCanaryTopology, provider, member.Slot) == "" {
			return fmt.Errorf("declarative Notify queue missing for original member slot")
		}
	}
	seen := map[string]bool{}
	for _, id := range b.TableOIDs {
		if !businessDecimal(id, 32) || seen[id] {
			return fmt.Errorf("exact Guest Notify table identities required")
		}
		seen[id] = true
	}
	return nil
}
func GuestNotifyCanaryPublication(c model.CapacityGuestNotifyCanaryChallenge) bool {
	return c.Schema == GuestNotifyCanaryPublicationChallengeSchema && c.Purpose == GuestNotifyCanaryPublicationPurpose && c.RecordChallengeID == c.ChallengeID
}
func validateGuestNotifyCanaryChallengeBase(c model.CapacityGuestNotifyCanaryChallenge, e model.CapacityGuestRetirementEnrollment, now time.Time) error {
	publish := GuestNotifyCanaryPublication(c)
	if (!publish && (c.Schema != GuestNotifyCanaryChallengeSchema || c.Purpose != GuestNotifyCanaryReadPurpose)) || !guestUUID(c.ChallengeID) || !guestUUID(c.RecordChallengeID) || !ValidDigest(c.NonceSHA256) || !GuestNotifyCanaryUsage(c.UsageClass) || c.BindingName != e.Statement.BindingName || c.Slot != e.Statement.Tuple.Slot || !guestUUID(c.PreregistrationID) || !ValidDigest(c.PreregistrationNonceSHA256) || !ValidDigest(c.OriginalRegistrationSHA256) || !ValidDigest(c.OriginalCreateWitnessSHA256) || c.EnrollmentSHA256 != GuestRetirementSHA(e) || !ValidDigest(c.ProfileManifestSHA256) || c.Tuple != e.Statement.Tuple || (c.Tuple.Provider != "aws" && c.Tuple.Provider != "hetzner") || !guestUUID(c.PolicyID) || !ValidDigest(c.PolicyChecksum) || !guestUUID(c.WorkflowID) || !ValidDigest(c.WorkflowChecksum) || c.Generation == 0 || c.Fence == 0 || c.LeaseOwner == "" || c.CoreSourceCommit != e.Statement.CoreAuthoritySourceCommit || !businessSource.MatchString(c.CoreSourceCommit) || c.IssuedAt.IsZero() || c.IssuedAt.After(now) || !now.Before(c.OriginalDeadline) || !c.OriginalDeadline.After(c.IssuedAt) || c.OriginalDeadline.Sub(c.IssuedAt) > 5*time.Second {
		return fmt.Errorf("scoped one-use original Guest Notify challenge required")
	}
	sig := c.Signature
	c.Signature = ""
	if !guestRetirementVerify(e.Statement.CoreIntentPublicKey, sig, c) {
		return fmt.Errorf("original Guest Notify Core challenge signature refused")
	}
	return nil
}

// This validates the signed original process/pipe envelope only. The separately
// joined native publisher and consumer SQL snapshots must prove fresh useful
// creation before any member or protected-floor authority can be recorded.
func ValidateGuestNotifyCanaryEnvelope(c model.CapacityGuestNotifyCanaryChallenge, e model.CapacityGuestRetirementEnrollment, r model.CapacityGuestNotifyCanaryRead, now time.Time) error {
	fail := fmt.Errorf("complete original Guest Notify process and pipe return required")
	if ValidateGuestNotifyCanaryChallenge(c, e, now) != nil {
		return fail
	}
	schema, purpose := GuestNotifyCanaryReadSchema, GuestNotifyCanaryReadPurpose
	if GuestNotifyCanaryPublication(c) {
		schema, purpose = GuestNotifyCanaryPublicationSchema, GuestNotifyCanaryPublicationPurpose
	}
	if r.Schema != schema || r.Purpose != purpose || r.ChallengeID != c.ChallengeID || r.ChallengeSHA256 != GuestRetirementSHA(c) || r.PreregistrationID != c.PreregistrationID || r.EnrollmentSHA256 != c.EnrollmentSHA256 || r.Tuple != c.Tuple || r.Actor != e.Statement.Actor || r.Runtime != e.Statement.Runtime || r.Reader != e.Statement.Actor || !reflect.DeepEqual(r.Writers, e.Statement.Writers) || len(r.Writers) != 1 || r.WriterRosterSHA256 != e.Statement.WriterRosterSHA256 || r.WriterRosterSHA256 != GuestRetirementSHA(r.Writers) || !GuestRetirementProtectedCensus(r.CensusBefore, e, r.OriginalRequestWriteReturnedAt, true) || !GuestRetirementProtectedCensus(r.CensusAfter, e, r.ObservedAt, true) || r.CensusBefore.RawCensusSHA256 != r.CensusAfter.RawCensusSHA256 || !reflect.DeepEqual(r.CensusBefore.Processes, r.CensusAfter.Processes) || r.CensusBefore.ObservedAt.Before(r.OriginalReadStartedAt) || r.CensusAfter.ObservedAt.Before(r.OriginalFrameReadReturnedAt) || r.OriginalReadStartedAt.IsZero() || r.OriginalRequestWriteReturnedAt.Before(r.OriginalReadStartedAt) || r.OriginalFrameReadReturnedAt.Before(r.OriginalRequestWriteReturnedAt) || r.ObservedAt.Before(r.OriginalFrameReadReturnedAt) || r.ObservedAt.IsZero() || r.OriginalContextFailed || r.HoldReasons == nil || len(r.HoldReasons) != 0 || len(r.NotifyOriginalReturn) < 2 || len(r.NotifyOriginalReturn) > 16<<10 || r.NotifyOriginalReturn[len(r.NotifyOriginalReturn)-1] != '\n' || bytes.Contains(r.NotifyOriginalReturn[:len(r.NotifyOriginalReturn)-1], []byte("\n")) || r.NotifyOriginalReturnSHA256 != BusinessCreationSHA256(r.NotifyOriginalReturn) {
		return fail
	}
	sig := r.Signature
	r.Signature = ""
	if !guestRetirementVerify(e.Statement.ObservationPublicKey, sig, r) {
		return fail
	}
	return nil
}
