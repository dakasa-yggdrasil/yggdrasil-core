package capacity

import (
	"strings"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// ADR-0093: Core refuses, at issue time, every challenge lease_owner the Guest
// refuses with bootstrap.BootIdentity, so a mismatch can no longer commit a
// publish row and then fail at the Guest nonce GET. Every other identifier the
// Guest checks with BootIdentity was already a canonical UUID here.
func TestGuestNotifyCanaryChallengeRequiresGuestUUIDOwner(t *testing.T) {
	for _, test := range []struct {
		name, owner string
		admitted    bool
	}{
		{"vm_lease_uuid_v4", "77777777-7777-4777-8777-777777777777", true},
		{"maintenance_uuid_v5", "b70152ca-6493-5b62-b930-6245b7caeb93", true},
		{"legacy_maintenance", "notify-maintenance:" + strings.Repeat("a", 64), false},
		{"empty", "", false},
		{"free_text", "unit-lease-owner", false},
		{"nil_uuid", "00000000-0000-0000-0000-000000000000", false},
		{"uppercase", "B70152CA-6493-5B62-B930-6245B7CAEB93", false},
		{"braced", "{b70152ca-6493-5b62-b930-6245b7caeb93}", false},
		{"urn", "urn:uuid:b70152ca-6493-5b62-b930-6245b7caeb93", false},
		{"undashed", "b70152ca64935b62b9306245b7caeb93", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			c, e, _, core, _, now := guestNotifyUnit(t)
			c.LeaseOwner = test.owner
			c.GuestNonce = model.CapacityGuestNotifyCanaryNonce{}
			c.Signature = ""
			c.Signature, _ = GuestLifecycleSignature(core, c)
			if (ValidateGuestNotifyCanaryPreflight(c, e, now) == nil) != test.admitted {
				t.Fatalf("preflight admission for lease_owner %q is not %v", test.owner, test.admitted)
			}
			for _, id := range []*string{&c.ChallengeID, &c.RecordChallengeID, &c.PreregistrationID, &c.PolicyID, &c.WorkflowID} {
				if !guestUUID(*id) {
					t.Fatal("a Guest BootIdentity field is not a canonical UUID in the unit challenge")
				}
			}
		})
	}
	// The other BootIdentity fields keep refusing a non-UUID independently.
	for _, field := range []string{"challenge", "record", "preregistration", "policy", "workflow"} {
		t.Run("non_uuid_"+field, func(t *testing.T) {
			c, e, _, core, _, now := guestNotifyUnit(t)
			c.GuestNonce = model.CapacityGuestNotifyCanaryNonce{}
			bad := "notify-maintenance:" + strings.Repeat("b", 64)
			switch field {
			case "challenge":
				c.ChallengeID = bad
			case "record":
				c.RecordChallengeID = bad
			case "preregistration":
				c.PreregistrationID = bad
			case "policy":
				c.PolicyID = bad
			case "workflow":
				c.WorkflowID = bad
			}
			c.Signature = ""
			c.Signature, _ = GuestLifecycleSignature(core, c)
			if ValidateGuestNotifyCanaryPreflight(c, e, now) == nil {
				t.Fatal("non-UUID Guest BootIdentity field admitted")
			}
		})
	}
}
