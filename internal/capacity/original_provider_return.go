package capacity

import (
	"fmt"
	"slices"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// ValidateOriginalHetznerCreateReturn validates only a return already received
// through the authenticated owning settlement. Calling it creates no authority.
func ValidateOriginalHetznerCreateReturn(b model.CapacityMutationBinding, g model.CapacityMutationGrant, attempt string, settle model.CapacityMutationSettleRequest, reservedAt, now time.Time) (time.Time, error) {
	fail := func() (time.Time, error) {
		return time.Time{}, fmt.Errorf("authentic original Hetzner create return required")
	}
	r := settle.OriginalProviderCreateReturn
	if r == nil || !businessSource.MatchString(b.OriginalProviderSourceCommit) || r.Schema != "hetzner_original_create_return_v1" || r.Provider != "hetzner" || r.AdapterSourceCommit != b.OriginalProviderSourceCommit || !guestUUID(g.GrantID) || !guestUUID(attempt) || g.CompensationOf != "" || b.EnsureCapability != "ensure_server" || g.Capability != b.EnsureCapability || g.Slot < 1 || g.Slot > 64 || g.BindingName != b.Name || g.IntegrationInstanceID != b.IntegrationInstanceID || g.ScopeChecksum != b.ScopeChecksum || g.ProfileName != b.ProfileName || (g.State != "redeemed" && g.State != "settled" && g.State != "confirmed") || settle.Outcome != "accepted" || !settle.TransportCompleted || settle.GrantID != g.GrantID || settle.AttemptID != attempt || settle.RequestSHA256 != g.RequestSHA256 || r.GrantID != g.GrantID || r.AttemptID != attempt || r.RequestSHA256 != g.RequestSHA256 || !ValidDigest(r.RequestSHA256) || r.ResourceID == "" || r.ResourceID != settle.ResourceID || r.ResourceCreatedAt != settle.ResourceCreatedAt || r.ActionID == "" || r.ActionID != settle.ActionID || r.NextActionIDs == nil || !slices.Equal(r.NextActionIDs, settle.NextActionIDs) || len(r.NextActionIDs) > 32 || r.ResponseStatus != 201 || !ValidDigest(r.ResponseBodySHA256) || r.ResponseBytes < 2 || r.ResponseBytes > 2<<20 || reservedAt.IsZero() {
		return fail()
	}
	parse := func(raw string) (time.Time, bool) {
		v, e := time.Parse(time.RFC3339Nano, raw)
		return v, e == nil && !v.IsZero() && v.UTC().Format(time.RFC3339Nano) == raw
	}
	called, a := parse(r.CalledAt)
	returned, z := parse(r.ReturnedAt)
	deadline, c := parse(r.ContextDeadline)
	observed, d := parse(settle.ObservedAt)
	created, e := parse(r.ResourceCreatedAt)
	if !a || !z || !c || !d || !e || called.Before(reservedAt) || returned.Before(called) || !returned.Before(deadline) || deadline.After(g.ExpiresAt) || returned.After(observed) || observed.After(now.Add(5*time.Second)) || returned.After(now) || created.Before(reservedAt.Add(-5*time.Second)) || created.After(returned.Add(5*time.Second)) {
		return fail()
	}
	seen := map[string]bool{r.ActionID: true}
	for _, id := range r.NextActionIDs {
		if id == "" || seen[id] {
			return fail()
		}
		seen[id] = true
	}
	return returned, nil
}
