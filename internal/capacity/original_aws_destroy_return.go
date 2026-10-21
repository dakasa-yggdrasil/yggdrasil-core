package capacity

import (
	"fmt"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"regexp"
	"time"
)

// ValidateOriginalAWSDestroyReturn is disjoint from original creation. The
// existing authenticated nonce/principal transaction must own this settlement;
// this validator alone creates no authority or absence/quiescence claim.
func ValidateOriginalAWSDestroyReturn(b model.CapacityMutationBinding, g model.CapacityMutationGrant, attempt string, s model.CapacityMutationSettleRequest, issuedAt, now time.Time) (time.Time, error) {
	fail := func() (time.Time, error) {
		return time.Time{}, fmt.Errorf("authentic original AWS TerminateInstances return required")
	}
	r := s.OriginalProviderDestroyReturn
	if r == nil || s.OriginalProviderCreateReturn != nil || !AWSOriginalMutationPair(b) || r.Schema != "aws_original_terminate_instances_return_v1" || r.Provider != "aws" || r.AdapterSourceCommit != b.OriginalProviderSourceCommit || !guestUUID(g.GrantID) || !guestUUID(attempt) || g.Capability != b.DestroyCapability || g.CompensationOf != "" || g.BindingName != b.Name || g.IntegrationInstanceID != b.IntegrationInstanceID || g.ScopeChecksum != b.ScopeChecksum || g.ProfileName != b.ProfileName || g.Slot <= b.ProtectedSlots || g.Slot > b.MaxSlots || (g.State != "redeemed" && g.State != "settled" && g.State != "confirmed") || s.Outcome != "accepted" || !s.TransportCompleted || s.GrantID != g.GrantID || s.AttemptID != attempt || s.RequestSHA256 != g.RequestSHA256 || r.GrantID != g.GrantID || r.AttemptID != attempt || r.RequestSHA256 != g.RequestSHA256 || !ValidDigest(r.RequestSHA256) || !regexp.MustCompile(`^i-(?:[0-9a-f]{8}|[0-9a-f]{17})$`).MatchString(g.ExpectedResourceID) || r.ResourceID != g.ExpectedResourceID || s.ResourceID != g.ExpectedResourceID || r.ResourceCreatedAt != g.ExpectedResourceCreatedAt || s.ResourceCreatedAt != g.ExpectedResourceCreatedAt || r.ActionID == "" || len(r.ActionID) > 128 || s.ActionID != r.ActionID || r.NextActionIDs == nil || len(r.NextActionIDs) != 0 || len(s.NextActionIDs) != 0 || r.ResponseStatus != 200 || !ValidDigest(r.ResponseBodySHA256) || r.ResponseBytes < 2 || r.ResponseBytes > 2<<20 || !s.AuxiliaryInventoryComplete || len(s.AuxiliaryResources) != 2 || issuedAt.IsZero() {
		return fail()
	}
	parse := func(raw string) (time.Time, bool) {
		v, err := time.Parse(time.RFC3339Nano, raw)
		return v, err == nil && !v.IsZero() && v.UTC().Format(time.RFC3339Nano) == raw
	}
	called, a := parse(r.CalledAt)
	returned, z := parse(r.ReturnedAt)
	deadline, c := parse(r.ContextDeadline)
	observed, d := parse(s.ObservedAt)
	created, e := parse(r.ResourceCreatedAt)
	if !a || !z || !c || !d || !e || called.Before(issuedAt) || returned.Before(called) || !returned.Before(deadline) || deadline.After(g.ExpiresAt) || returned.After(observed) || observed.After(now.Add(5*time.Second)) || returned.After(now) || created.After(called.Add(5*time.Second)) {
		return fail()
	}
	// The exact pre-write owned root/primary-interface inventory is retained in
	// this separate immutable receipt; later absence must cover both native IDs.
	for n, aux := range s.AuxiliaryResources {
		prefix, kind := "vol-", "aws_ebs_volume"
		if n == 1 {
			prefix, kind = "eni-", "aws_network_interface"
		}
		if aux.Kind != kind || !aux.RequiresAbsence || !regexp.MustCompile(`^`+prefix+`(?:[0-9a-f]{8}|[0-9a-f]{17})$`).MatchString(aux.ID) {
			return fail()
		}
	}
	return returned, nil
}
