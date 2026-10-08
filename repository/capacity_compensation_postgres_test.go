package repository

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

func TestCapacityMutationCompensationPostgres(t *testing.T) {
	ctx := context.Background()
	for _, scenario := range []struct {
		name                 string
		protected, lostReply bool
	}{
		{"unprotected_failed_create", false, false},
		{"protected_failed_create_without_serving_membership", true, false},
		{"lost_create_reply_uses_separate_native_readback", false, true},
		{"protected_lost_create_reply", true, true},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			protected, lostReply := scenario.protected, scenario.lostReply
			f := mutationPostgresFixture(t, !protected)
			failedSlot := 5
			if protected {
				failedSlot = 1
				for slot := 2; slot <= 5; slot++ {
					f.record(t, slot)
				}
			}
			parent := f.issue(t, failedSlot)
			nonce := uuid.NewString()
			r := mutationRedeem(parent, nonce)
			if _, err := f.store.RedeemMutation(ctx, f.binding.AdapterPrincipalID, r); err != nil {
				t.Fatal(err)
			}
			settlement := mutationSettlement(r, f.created)
			nativeResourceID, nativeCreatedAt := settlement.ResourceID, settlement.ResourceCreatedAt
			if lostReply {
				settlement.Outcome, settlement.ResourceID, settlement.ResourceCreatedAt, settlement.ActionID = "uncertain", "", "", ""
				settlement.NextActionIDs, settlement.AuxiliaryResources, settlement.AuxiliaryInventoryComplete = nil, nil, false
			}
			if _, err := f.store.SettleMutation(ctx, f.binding.AdapterPrincipalID, nonce, settlement); err != nil {
				t.Fatal(err)
			}
			failed := f.proof(t, failedSlot)
			failed.GrantID, failed.ResourceID, failed.ResourceCreatedAt, failed.ObservedCreationGrantID = parent.GrantID, nativeResourceID, nativeCreatedAt, parent.GrantID
			failed.ActionHistoryComplete = lostReply
			failed.ActionsTerminal, failed.ActionsFailed, failed.SpecVerified, failed.CompensationIdentityVerified = true, true, false, true
			failed.ActionIDs = []string{"native-action", "bootstrap-action"}
			var desired model.CapacityMutationSpecV1
			if err := json.Unmarshal(f.plans[failedSlot].DesiredSpec, &desired); err != nil {
				t.Fatal(err)
			}
			desired.Capability = f.binding.DestroyCapability
			desired.ExpectedResourceID, desired.ExpectedResourceCreatedAt = nativeResourceID, nativeCreatedAt
			// The canonical projection is sorted explicitly by the production planner.
			desiredRaw, _ := json.Marshal(desired)
			zero := 0
			drain := model.CapacityTransitionProof{Assessment: freshCapacityTestAssessment(f.a, 4), ObservedAt: time.Now().UTC(), ReceiptRef: "fixture:never-routed-and-complete-floor", Healthy: true, MembershipComplete: true, AdmissionClosed: true, RoutingWithdrawn: true, Inflight: &zero, NativeActionsInflight: &zero}
			issue := model.CapacityCompensationIssue{ParentGrantID: parent.GrantID, Mutation: model.CapacityMutationIssue{BindingName: f.binding.Name, DesiredSpec: desiredRaw}, FailedProof: failed, DrainProof: drain}
			if _, err := f.store.IssueCompensation(ctx, f.policy, issue); err == nil {
				t.Fatal("default-disabled binding authorized compensation")
			}
			if _, err := f.db.ExecContext(ctx, `UPDATE public.capacity_intents SET intent=jsonb_set(intent,'{lease_expires_at}',to_jsonb($2::text)) WHERE namespace=$1`, f.policy.Metadata.Namespace, time.Now().Add(-time.Second).UTC().Format(time.RFC3339Nano)); err != nil {
				t.Fatal(err)
			}
			recovery := f.store
			recovery.ExecutionEnabled, recovery.ExecutorID = false, uuid.NewString()
			lease, err := recovery.Recover(ctx, f.policy, 1, freshCapacityTestAssessment(f.a, 4))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := recovery.IssueMutation(ctx, f.policy, 1, lease.FencingToken, lease.LeaseOwner, f.plans[6]); err == nil {
				t.Fatal("historical recovery authorized another provider write")
			}
			var p model.CapacityPolicySpec
			_ = json.Unmarshal(f.policy.Spec, &p)
			p.MutationBindings[0].CompensationEnabled = true
			raw, _ := json.Marshal(p)
			current, err := CreateManifestVersion(ctx, f.db, model.ManifestDocument{APIVersion: f.policy.APIVersion, Kind: f.policy.Kind, Metadata: model.ManifestMetadataInput{Namespace: f.policy.Metadata.Namespace, Name: f.policy.Metadata.Name}, Spec: raw}, fmt.Sprintf("%x", sha256.Sum256(raw)))
			if err != nil {
				t.Fatal(err)
			}
			issuer := f.store
			issuer.ExecutorID = uuid.NewString()
			paused := issuer
			paused.ExecutionEnabled = false
			if _, err := paused.IssueCompensation(ctx, current, issue); !errors.Is(err, ErrCapacityDisabled) {
				t.Fatal("paused process admitted cleanup", err)
			}
			for _, scenario := range []string{"unknown_action", "successful_action", "wrong_parent", "wrong_creation_label", "missing_identity", "running_business", "running_native", "open_admission", "routed", "incomplete_inventory", "below_floor", "wrong_tuple", "incomplete_action_history"} {
				bad := issue
				switch scenario {
				case "unknown_action":
					bad.FailedProof.ActionsTerminal = false
				case "successful_action":
					bad.FailedProof.ActionsSuccessful = true
				case "wrong_parent":
					bad.ParentGrantID = uuid.NewString()
				case "wrong_creation_label":
					bad.FailedProof.ObservedCreationGrantID = uuid.NewString()
				case "missing_identity":
					bad.FailedProof.CompensationIdentityVerified = false
				case "running_business":
					one := 1
					bad.DrainProof.Inflight = &one
				case "running_native":
					one := 1
					bad.DrainProof.NativeActionsInflight = &one
				case "open_admission":
					bad.DrainProof.AdmissionClosed = false
				case "routed":
					bad.DrainProof.RoutingWithdrawn = false
				case "incomplete_inventory":
					bad.DrainProof.MembershipComplete = false
				case "below_floor":
					bad.DrainProof.Assessment.Snapshot.Units = 1
				case "wrong_tuple":
					bad.Mutation.DesiredSpec = json.RawMessage(string(desiredRaw))
					bad.FailedProof.ResourceID = "replacement"
				case "incomplete_action_history":
					if !lostReply {
						continue
					}
					bad.FailedProof.ActionHistoryComplete = false
				}
				if _, err := issuer.IssueCompensation(ctx, current, bad); err == nil {
					t.Fatal("unsafe compensation admitted", scenario)
				}
			}
			// Two concurrent invocations within the same protected run get one
			// durable child; a different run cannot adopt the private authority.
			var wg sync.WaitGroup
			grants := make(chan model.CapacityMutationGrant, 2)
			failures := make(chan error, 2)
			for i := 0; i < 2; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					g, err := issuer.IssueCompensation(ctx, current, issue)
					grants <- g
					failures <- err
				}()
			}
			wg.Wait()
			child, repeated := <-grants, <-grants
			if first, second := <-failures, <-failures; first != nil || second != nil || child.GrantID != repeated.GrantID || child.CompensationOf != parent.GrantID {
				t.Fatal("compensation issuance was not singular", child, repeated, first, second)
			}
			if lostReply {
				// An expired, never-redeemed child may be replaced, but the parent
				// native lifetime cannot be changed even with its original label.
				if _, err := f.db.ExecContext(ctx, `UPDATE public.capacity_mutation_grants SET expires_at=$2::text::timestamptz,grant_record=jsonb_set(grant_record,'{grant,expires_at}',to_jsonb($2::text)) WHERE id=$1`, child.GrantID, time.Now().Add(-time.Second).UTC().Format(time.RFC3339Nano)); err != nil {
					t.Fatal(err)
				}
				replacement := issue
				replacement.FailedProof.ResourceID = "replacement-lifetime"
				changed := desired
				changed.ExpectedResourceID = replacement.FailedProof.ResourceID
				replacement.Mutation.DesiredSpec, _ = json.Marshal(changed)
				if _, err := issuer.IssueCompensation(ctx, current, replacement); !errors.Is(err, ErrCapacityConflict) {
					t.Fatal("expired child replaced pinned parent lifetime", err)
				}
				replacement = issue
				created, _ := time.Parse(time.RFC3339Nano, nativeCreatedAt)
				replacement.FailedProof.ResourceCreatedAt = created.Add(time.Second).Format(time.RFC3339Nano)
				changed = desired
				changed.ExpectedResourceCreatedAt = replacement.FailedProof.ResourceCreatedAt
				replacement.Mutation.DesiredSpec, _ = json.Marshal(changed)
				if _, err := issuer.IssueCompensation(ctx, current, replacement); !errors.Is(err, ErrCapacityConflict) {
					t.Fatal("expired child changed pinned creation time", err)
				}
				reissued, err := issuer.IssueCompensation(ctx, current, issue)
				if err != nil || reissued.GrantID == child.GrantID || reissued.ExpectedResourceID != nativeResourceID || reissued.ExpectedResourceCreatedAt != nativeCreatedAt {
					t.Fatal("same immutable lifetime could not reissue unused child", reissued, err)
				}
				child = reissued
			}
			stranger := issuer
			stranger.ExecutorID = uuid.NewString()
			if _, err := stranger.IssueCompensation(ctx, current, issue); !errors.Is(err, ErrCapacityConflict) {
				t.Fatal("another run adopted cleanup authority", err)
			}
			childNonce := uuid.NewString()
			redemption := mutationRedeem(child, childNonce)
			badRedemption := redemption
			badRedemption.CompensationOf = ""
			if _, err := issuer.RedeemMutation(ctx, f.binding.AdapterPrincipalID, badRedemption); !errors.Is(err, ErrCapacityMutationAuthorization) {
				t.Fatal("child redemption omitted parent identity", err)
			}
			permission, err := issuer.RedeemMutation(ctx, f.binding.AdapterPrincipalID, redemption)
			if err != nil || permission.Mode != "write_once" || permission.CompensationOf != parent.GrantID {
				t.Fatal("separate cleanup authority did not redeem", permission, err)
			}
			if again, err := issuer.RedeemMutation(ctx, f.binding.AdapterPrincipalID, redemption); err != nil || again.Mode != "read_only" {
				t.Fatal("cleanup redemption replayed a native send", again, err)
			}
			deleted := failed
			deleted.GrantID, deleted.RequestSHA256 = child.GrantID, child.RequestSHA256
			deleted.ActionsSuccessful, deleted.ActionsFailed, deleted.ResourceAbsent = true, false, true
			deleted.AuxiliaryAbsent = []model.CapacityMutationAuxiliaryResource{{Kind: "primary_ip", ID: "ip-fixture"}}
			if _, err := issuer.ConfirmCompensation(ctx, current, deleted); err == nil {
				t.Fatal("native absence replaced owning transport settlement")
			}
			deleteSettlement := mutationSettlement(redemption, nativeCreatedAt)
			if _, err := issuer.SettleMutation(ctx, f.binding.AdapterPrincipalID, childNonce, deleteSettlement); err != nil {
				t.Fatal(err)
			}
			missingIP := deleted
			missingIP.AuxiliaryAbsent = nil
			if _, err := issuer.ConfirmCompensation(ctx, current, missingIP); err == nil {
				t.Fatal("paid IP absence was not required")
			}
			paused = issuer
			paused.ExecutionEnabled = false
			if _, err := f.db.ExecContext(ctx, `UPDATE public.manifests SET active=false WHERE id=$1`, current.ID); err != nil {
				t.Fatal(err)
			}
			confirmed, err := paused.ConfirmCompensation(ctx, current, deleted)
			if err != nil || confirmed.State != "confirmed" {
				t.Fatal("paused cleanup readback did not close exact authority", confirmed, err)
			}
			if _, err := paused.ConfirmCompensation(ctx, current, deleted); err != nil {
				t.Fatal("exact confirmation replay failed", err)
			}
			parentReceipt, err := issuer.MutationReceipt(ctx, f.binding.AdapterPrincipalID, parent.GrantID)
			if err != nil || parentReceipt.Grant.State != "compensated" {
				t.Fatal("parent reservation remained unresolved", parentReceipt, err)
			}
			if parentReceipt.NativeReadback == nil || parentReceipt.NativeReadback.ResourceID != nativeResourceID || parentReceipt.NativeReadback.ResourceCreatedAt != nativeCreatedAt || parentReceipt.ResourceID != settlement.ResourceID || parentReceipt.ResourceCreatedAt != settlement.ResourceCreatedAt || parentReceipt.ActionID != settlement.ActionID || parentReceipt.Outcome != settlement.Outcome {
				t.Fatal("native readback overwrote or escaped owning transport evidence", parentReceipt)
			}
			var eventParent string
			if err := f.db.QueryRowContext(ctx, `SELECT payload->'observed'->>'compensation_of' FROM public.event_log WHERE metadata->>'namespace'=$1 AND type='fixture.server.destroyed'`, f.policy.Metadata.Namespace).Scan(&eventParent); err != nil || eventParent != parent.GrantID {
				t.Fatal("destroyed event lost compensation lineage", eventParent, err)
			}
			var serving, ensured, destroyed int
			if err := f.db.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_resource_slots WHERE namespace=$1 AND resource_id<>''`, f.policy.Metadata.Namespace).Scan(&serving); err != nil {
				t.Fatal(err)
			}
			if err := f.db.QueryRowContext(ctx, `SELECT count(*) FILTER(WHERE type='fixture.server.ensured'),count(*) FILTER(WHERE type='fixture.server.destroyed') FROM public.event_log WHERE metadata->>'namespace'=$1`, f.policy.Metadata.Namespace).Scan(&ensured, &destroyed); err != nil {
				t.Fatal(err)
			}
			if serving != 4 || ensured != 0 || destroyed != 1 {
				t.Fatal("failed creation became serving capacity or duplicate applied event", serving, ensured, destroyed)
			}
			terminal := model.CapacityTransitionProof{Assessment: freshCapacityTestAssessment(f.a, 4), ObservedAt: time.Now().UTC(), ReceiptRef: "fixture:closed-failed-create", Healthy: true, Inflight: &zero, MutationInflight: &zero, MutationAuthorityKind: "core_mutation_grants", MembershipComplete: true, NoMutationVerified: true}
			if _, err := recovery.Reconcile(ctx, f.policy, 1, lease.FencingToken, lease.LeaseOwner, "aborted", terminal); err == nil {
				t.Fatal("compensated write became a no-mutation abort")
			}
			terminal.NoMutationVerified = false
			if _, err := recovery.Reconcile(ctx, f.policy, 1, lease.FencingToken, lease.LeaseOwner, "reconciled_partial", terminal); err != nil {
				t.Fatal("completed compensation left original recovery stuck", err)
			}
		})
	}
}
