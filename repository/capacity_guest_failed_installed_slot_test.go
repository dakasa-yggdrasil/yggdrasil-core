package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

func testFailedInstalledLaterSlotBoundaries(t *testing.T) {
	now := time.Now().UTC()
	expired := now.Add(-time.Second)
	policy := model.Manifest{ID: uuid.New(), Checksum: "original"}
	p := model.CapacityPolicySpec{Floor: 1, Ceiling: 8, GuestNotifyReconcileBinding: &model.CapacityGuestNotifyReconcileBinding{}, GuestRetirementBinding: &model.CapacityGuestRetirementBinding{EvidenceClass: "owned_provisioner_original", GuestSourceCommit: "current-v2"}}
	for _, n := range []int{2, 3, 8} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			base := model.CapacityIntent{PolicyID: policy.ID, PolicyChecksum: policy.Checksum, Phase: "preparing", Generation: 6, FencingToken: 13, LeaseExpiresAt: &expired, Decision: model.CapacityDecision{Action: "expand", Units: n}, BaselineSnapshot: model.CapacitySnapshot{Units: n - 1}, Assessment: model.CapacityAssessment{Snapshot: model.CapacitySnapshot{Units: n - 1}}}
			for _, name := range []string{"failed_tail", "already_observed_tail", "not_expansion", "multiple_new_members", "above_ceiling", "lost_survivor", "extra_member", "legacy548", "useful_generation"} {
				t.Run(name, func(t *testing.T) {
					old, spec := base, p
					binding := *p.GuestRetirementBinding
					spec.GuestRetirementBinding = &binding
					switch name {
					case "already_observed_tail":
						old.Assessment.Snapshot.Units = n
					case "not_expansion":
						old.Decision.Action = "drain"
					case "multiple_new_members":
						old.BaselineSnapshot.Units = n - 2
					case "above_ceiling":
						spec.Ceiling = n - 1
					case "lost_survivor":
						old.Assessment.Snapshot.Units = n - 2
					case "extra_member":
						old.Assessment.Snapshot.Units = n + 1
					case "legacy548":
						binding.GuestSourceCommit = "548734eef627404f10b5117e0ec7f27582ae9048"
					case "useful_generation":
						old.Phase = "promoted"
					}
					want := name == "failed_tail" || name == "already_observed_tail"
					if failedInstalledDisposalCandidate(old, spec, policy, now) != want {
						t.Fatal("only one unpromoted newly installed tail member may be disposed")
					}
				})
			}
			r := FailedInstalledGuestDisposal{PreregistrationID: uuid.NewString(), OriginalIntent: base}
			members := make([]GuestNotifyFloorMember, n)
			for i := range members {
				members[i] = GuestNotifyFloorMember{Slot: i + 1, PreregistrationID: uuid.NewString()}
			}
			members[n-1].PreregistrationID = r.PreregistrationID
			if !failedInstalledDisposalMembersMatch(r, members) {
				t.Fatal("exact enrolled prefix refused")
			}
			for _, mutate := range []func([]GuestNotifyFloorMember){
				func(m []GuestNotifyFloorMember) { m[0].Slot = n + 1 },
				func(m []GuestNotifyFloorMember) { m[0].Slot = n },
				func(m []GuestNotifyFloorMember) { m[0].PreregistrationID = r.PreregistrationID },
				func(m []GuestNotifyFloorMember) { m[n-1].PreregistrationID = uuid.NewString() },
			} {
				changed := append([]GuestNotifyFloorMember(nil), members...)
				mutate(changed)
				if failedInstalledDisposalMembersMatch(r, changed) {
					t.Fatal("a sparse, duplicate or swapped failed member was admitted")
				}
			}
		})
	}
}

// This tests only the real SQL accounting query. Synthetic challenge rows are
// written with FKs disabled in a rolled-back CI transaction and cannot satisfy
// the production receipt, signature, original-run or Guest retirement gates.
func testFailedInstalledLaterSlotAccountingPostgres(t *testing.T, db *sql.DB, namespace string) {
	for _, name := range []string{"exact_surviving_prefix", "missing_survivor", "missing_read", "foreign_lifetime", "foreign_instance", "foreign_scope", "foreign_profile", "non_prefix", "extra_member", "useful_failed_member", "promoted_failed_generation"} {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			tx, err := db.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			if _, err = tx.ExecContext(ctx, `SET LOCAL session_replication_role=replica`); err != nil {
				t.Fatal(err)
			}
			r := FailedInstalledGuestDisposal{Namespace: namespace, Environment: "production", Domain: "notify", Dimension: "slot-n-accounting-" + uuid.NewString(), PreregistrationID: uuid.NewString(), OriginalIntent: model.CapacityIntent{Generation: 6, Decision: model.CapacityDecision{Units: 2}}}
			now := time.Now().UTC().Truncate(time.Microsecond)
			instance, scope, profile, resource, created := uuid.NewString(), "slot-n-scope", "original", "surviving-native", now.Add(-time.Hour).Format(time.RFC3339Nano)
			peer := model.CapacityGuestNativeTuple{InstanceID: instance, ScopeChecksum: scope, Profile: profile, Slot: 1, ResourceID: resource, CreatedAt: created}
			rowSlot := 1
			if name == "non_prefix" {
				rowSlot, peer.Slot = 3, 3
			}
			insertSlot := func(slot int, id string) {
				t.Helper()
				if _, err := tx.ExecContext(ctx, `INSERT INTO public.capacity_resource_slots(integration_instance_id,scope_checksum,profile_name,slot,namespace,environment,domain,dimension,resource_id,slot_record) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,jsonb_build_object('resource_created_at',$10::text))`, instance, scope, profile, slot, r.Namespace, r.Environment, r.Domain, r.Dimension, id, created); err != nil {
					t.Fatal(err)
				}
			}
			if name != "missing_survivor" {
				insertSlot(rowSlot, resource)
			}
			if name == "extra_member" {
				insertSlot(3, "extra-native")
			}
			switch name {
			case "foreign_lifetime":
				peer.CreatedAt = now.Add(-2 * time.Hour).Format(time.RFC3339Nano)
			case "foreign_instance":
				peer.InstanceID = uuid.NewString()
			case "foreign_scope":
				peer.ScopeChecksum = "other-scope"
			case "foreign_profile":
				peer.Profile = "other-profile"
			}
			insertRead := func(pre string, tuple model.CapacityGuestNativeTuple) {
				t.Helper()
				id := uuid.NewString()
				deadline := now.Add(-time.Minute)
				wire, e := json.Marshal(map[string]any{"schema": capacity.GuestNotifyCanaryChallengeSchema, "issued_at": deadline.Add(-time.Second), "original_deadline": deadline, "tuple": tuple})
				if e != nil {
					t.Fatal(e)
				}
				digest := capacity.BusinessCreationSHA256([]byte(id))
				if _, e = tx.ExecContext(ctx, `INSERT INTO public.capacity_guest_notify_canary_challenges(id,preregistration_id,record_challenge_id,phase,policy_id,workflow_id,generation,fence,executor_id,lease_owner,challenge_sha256,nonce_sha256,original_wire,original_record,original_deadline,recorded_at) VALUES($1,$2,$1,'read',$3,$4,5,12,$5,$6,$7,$7,$8,$9::jsonb,$10,$10)`, id, pre, uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString(), digest, wire, string(wire), deadline); e != nil {
					t.Fatal(e)
				}
				if _, e = tx.ExecContext(ctx, `INSERT INTO public.capacity_guest_notify_canary_returns(challenge_id,outcome,return_sha256,original_wire,original_transport,recorded_at) VALUES($1,'accepted',$2,'{}'::bytea,'{}'::jsonb,$3)`, id, digest, deadline); e != nil {
					t.Fatal(e)
				}
			}
			if name != "missing_read" {
				insertRead(uuid.NewString(), peer)
			}
			if name == "useful_failed_member" {
				insertRead(r.PreregistrationID, model.CapacityGuestNativeTuple{Slot: 2})
			}
			if name == "promoted_failed_generation" {
				if _, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_intent_events(namespace,environment,domain,dimension,generation,fencing_token,phase,receipt_ref) VALUES($1,$2,$3,$4,6,13,'promoted','unqualified-storage-only')`, r.Namespace, r.Environment, r.Domain, r.Dimension); err != nil {
					t.Fatal(err)
				}
			}
			if got := failedInstalledZeroUsefulTx(ctx, tx, r, now, ""); (got == nil) != (name == "exact_surviving_prefix") {
				t.Fatal("failed member or exact surviving prefix misclassified", got)
			}
		})
	}
}
