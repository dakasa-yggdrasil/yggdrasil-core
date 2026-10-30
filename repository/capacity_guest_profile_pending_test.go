package repository

import (
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
	"strings"
	"testing"
	"time"
)

// These are content-only values, not SQL rows, lease/registry authority or a
// positive witness fixture. The real locked pending path must also complete
// guestCurrentTx and its original durable preregistration joins.
func TestGuestOriginalProfilePendingContentRequiresOriginalCreate(t *testing.T) {
	now := time.Now().UTC()
	pid, wid := uuid.New(), uuid.New()
	for _, provider := range []string{"aws", "hetzner"} {
		for _, state := range []string{"issued", "redeemed", "settled"} {
			for _, fault := range []string{"", "grant", "binding", "slot", "capability", "digest", "compensation", "policy", "workflow", "generation", "fence", "executor", "lease", "source", "provider", "state", "expired_issued", "settlement", "attempt", "outcome", "transport", "receipt_digest", "receipt_attempt"} {
				t.Run(provider+"/"+state+"/"+fault, func(t *testing.T) {
					b := model.CapacityMutationBinding{Name: "native", IntegrationInstanceID: "instance", ScopeChecksum: strings.Repeat("a", 64), ProfileName: "profile", EnsureCapability: "ensure_ec2_instance"}
					p := model.CapacityPolicySpec{MutationBindings: []model.CapacityMutationBinding{b}, Profiles: []model.CapacityProfile{{Name: b.ProfileName, Provider: provider}}}
					pre := model.CapacityGuestOriginalProvisioningPreregistration{OriginalCreateGrantID: uuid.NewString(), OriginalCreateRequestSHA256: strings.Repeat("b", 64), PolicyID: pid.String(), WorkflowID: wid.String(), PolicyChecksum: strings.Repeat("c", 64), Generation: 2, Fence: 3, LeaseOwner: "owner", ExecutorID: "executor", Slot: 1, CoreSourceCommit: strings.Repeat("d", 40)}
					stored := guestOriginalStored{pre: pre, binding: model.CapacityGuestRetirementBinding{MutationBindingName: b.Name, CoreAuthoritySourceCommit: pre.CoreSourceCommit}}
					r := capacityMutationRecord{Grant: model.CapacityMutationGrant{GrantID: pre.OriginalCreateGrantID, BindingName: b.Name, IntegrationInstanceID: b.IntegrationInstanceID, ScopeChecksum: b.ScopeChecksum, ProfileName: b.ProfileName, Slot: 1, Capability: b.EnsureCapability, RequestSHA256: pre.OriginalCreateRequestSHA256, State: state, ExpiresAt: now.Add(time.Minute)}, Binding: b, PolicyID: pid, WorkflowID: wid, PolicyChecksum: pre.PolicyChecksum, Generation: 2, FencingToken: 3, LeaseOwner: pre.LeaseOwner, ExecutorID: pre.ExecutorID, EventProvider: provider}
					if state != "issued" {
						r.AttemptID = uuid.NewString()
					}
					if state == "settled" {
						r.Settlement = &model.CapacityMutationSettleRequest{GrantID: r.Grant.GrantID, AttemptID: r.AttemptID, RequestSHA256: r.Grant.RequestSHA256, Outcome: "accepted", TransportCompleted: true}
					}
					applies := true
					switch fault {
					case "grant":
						r.Grant.GrantID = uuid.NewString()
					case "binding":
						r.Binding.Name = "foreign"
					case "slot":
						r.Grant.Slot++
					case "capability":
						r.Grant.Capability = "terminate_ec2_instance"
					case "digest":
						r.Grant.RequestSHA256 = strings.Repeat("f", 64)
					case "compensation":
						r.Grant.CompensationOf = "other"
					case "policy":
						r.PolicyID = uuid.New()
					case "workflow":
						r.WorkflowID = uuid.New()
					case "generation":
						r.Generation++
					case "fence":
						r.FencingToken++
					case "executor":
						r.ExecutorID = "other"
					case "lease":
						r.LeaseOwner = "other"
					case "source":
						stored.pre.CoreSourceCommit = strings.Repeat("e", 40)
					case "provider":
						r.EventProvider = "native-qemu"
					case "state":
						r.Grant.State = "confirmed"
					case "expired_issued":
						r.Grant.ExpiresAt = now
						applies = state == "issued"
					case "settlement":
						if state == "settled" {
							r.Settlement = nil
						} else {
							r.Settlement = &model.CapacityMutationSettleRequest{}
						}
					case "attempt":
						r.AttemptID = ""
						applies = state != "issued"
					case "outcome", "transport", "receipt_digest", "receipt_attempt":
						applies = state == "settled"
						if applies {
							switch fault {
							case "outcome":
								r.Settlement.Outcome = "unknown"
							case "transport":
								r.Settlement.TransportCompleted = false
							case "receipt_digest":
								r.Settlement.RequestSHA256 = "other"
							case "receipt_attempt":
								r.Settlement.AttemptID = "other"
							}
						}
					}
					want := fault == "" || !applies
					if guestOriginalCreateStillPending(p, stored, r, state, now) != want {
						t.Fatal("pending content admitted foreign/terminal original", state, fault)
					}
				})
			}
		}
	}
}
