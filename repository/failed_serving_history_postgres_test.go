//go:build recoveryfixture && !nativequalification

package repository

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

func (f *failedServingFixture) historicalUnknown(t *testing.T, index int) (uuid.UUID, uuid.UUID) {
	t.Helper()
	start := f.pre.ReservedAt.Add(time.Hour + time.Duration(index)*6*time.Minute)
	lease, returned := start.Add(5*time.Minute), start.Add(11*time.Second)
	e := abandonedDispatchEnvelope(t, f.policy.Metadata.Namespace, start.Format(time.RFC3339Nano))
	e.Environment, e.Domain, e.Dimension = f.p.Environment, f.p.Domain, f.p.Dimension
	e.Policy = CapacityDispatchManifestPin{ID: f.policy.ID, Namespace: f.policy.Metadata.Namespace, Name: f.policy.Metadata.Name, Version: f.policy.Version, Checksum: f.policy.Checksum}
	e.Workflow = CapacityDispatchManifestPin{ID: f.workflow.ID, Namespace: f.workflow.Metadata.Namespace, Name: f.workflow.Metadata.Name, Version: f.workflow.Version, Checksum: f.workflow.Checksum}
	e.RBAC.Namespace = f.policy.Metadata.Namespace
	f.exec(t, `INSERT INTO public.manifests(id,api_version,kind,namespace,name,version,checksum,spec,active) VALUES($1,'v1','rbac',$2,$3,$4,$5,'{}'::jsonb,true)`, e.RBAC.ID, e.RBAC.Namespace, e.RBAC.Name+"-"+e.RBAC.ID.String(), e.RBAC.Version, e.RBAC.Checksum)
	// Manifest name is part of the immutable envelope pin.
	e.RBAC.Name += "-" + e.RBAC.ID.String()
	e.Inputs = map[string]any{"policy": map[string]any{"namespace": e.Policy.Namespace, "name": e.Policy.Name}}
	e.Metadata = map[string]any{WorkflowRunCreatorMachinePrincipalMetadataKey: e.MachinePrincipalID, "triggered_by": "workflow_scheduler", "manifest_id": e.Workflow.ID.String(), "scheduled_for": e.SourceTick}
	e.InputsSHA256, e.MetadataSHA256, _ = CapacityDispatchEnvelopeHashes(e)
	wire, err := encodeCapacityDispatchEnvelope(e)
	if err != nil {
		t.Fatal(err)
	}
	ids := []string{"plan-original-guest", "provision-original-notify", "retire-original-guest", "refresh-original-membership", "complete-original-provision", "finish-original-retirement", "complete-original-retirement"}
	ops := []string{"capacity.plan_original_guest", "capacity.provision_original_guest", "capacity.retire_original_guest", "capacity.complete_original_guest", "capacity.complete_original_guest", "capacity.finish_original_guest_retirement", "capacity.complete_original_guest"}
	steps := []map[string]any{}
	for i, id := range ids {
		s := map[string]any{"id": id, "kind": "yggdrasil", "operation": ops[i], "capability": ops[i], "status": "skipped"}
		if i == 0 {
			s["status"], s["attempts"], s["metadata"] = "succeeded", 1, map[string]any{"mode": "refresh", "slot": 0, "reason": "signal_evidence_unavailable", "generation": f.intent.Generation, "fencing_token": f.intent.FencingToken, "lease_owner": "", "preregistration_id": ""}
		}
		if i == 3 {
			stage := "nonce_finalize"
			if index%2 == 1 {
				stage = "reserve_send"
			}
			s["status"], s["attempts"], s["error"], s["metadata"] = "failed", 1, "original Guest reconciliation held", map[string]any{"original_guest_reconcile_refusal_stage": "fresh_original_canary", "original_guest_notify_refusal_stage": stage}
		}
		steps = append(steps, s)
	}
	result := failedServingWire(t, map[string]any{"status": "failed", "workflow": map[string]any{"id": e.Workflow.ID, "kind": "workflow", "namespace": e.Workflow.Namespace, "name": e.Workflow.Name, "version": e.Workflow.Version}, "steps": steps})
	const reason = "capacity dispatch original deadline exceeded"
	f.exec(t, `INSERT INTO public.workflow_runs(id,workflow_id,status,workflow_namespace,workflow_name,workflow_version,started_at,finished_at,error,result,inputs,metadata,updated_at) VALUES($1,$2,'failed',$3,$4,$5,$6,$7,$8,$9::jsonb,$10::jsonb,$11::jsonb,$7)`, e.RunID, e.Workflow.ID, e.Workflow.Namespace, e.Workflow.Name, e.Workflow.Version, start, returned, reason, string(result), string(failedServingWire(t, e.Inputs)), string(failedServingWire(t, e.Metadata)))
	leaseOwner := uuid.New()
	f.exec(t, `INSERT INTO public.capacity_dispatch_jobs(id,run_id,protocol,realm,environment,domain,dimension,source_tick,envelope,envelope_sha256,state,lease_owner,fencing_token,lease_expires_at,started_at,returned_at,return_status,return_error,pending_wake_count) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'unknown',$11,1,$12,$13,$14,'failed',$15,$16)`, e.JobID, e.RunID, e.Protocol, e.Realm, e.Environment, e.Domain, e.Dimension, e.SourceTick, string(wire), capacityDispatchSHA(wire), leaseOwner, lease, start, returned, reason, MaxCapacityDispatchPendingWakes)
	c := f.historicalChallenge(t, start.Add(2*time.Second))
	f.insertHistoricalChallenge(t, c, "publish")
	f.exec(t, `INSERT INTO public.capacity_guest_notify_canary_sends(challenge_id,request_sha256,possible_send_at,original_deadline,recorded_at) VALUES($1,$2,$3,$4,$3)`, c.ChallengeID, capacity.GuestRetirementSHA(model.CapacityGuestNotifyCanaryRequest{Challenge: c}), c.IssuedAt.Add(time.Millisecond), c.OriginalDeadline)
	if index%2 == 0 {
		f.exec(t, `INSERT INTO public.capacity_guest_notify_canary_returns(challenge_id,outcome,return_sha256,original_wire,original_transport,recorded_at) VALUES($1,'held',$2,NULL,'{"declared_storage_only":true,"CanaryReturnValidationStage":"original_transport"}'::jsonb,$3)`, c.ChallengeID, strings.Repeat("f", 64), c.IssuedAt.Add(time.Second))
	}
	var runSHA, membersSHA string
	if err = f.db.QueryRow(`SELECT encode(sha256(convert_to(to_jsonb(w)::text,'UTF8')),'hex'),public.unknown_maintenance_dispatch_effect_scan(j.id)->>'current_members_sha256' FROM public.capacity_dispatch_jobs j JOIN public.workflow_runs w ON w.id=j.run_id WHERE j.id=$1`, e.JobID).Scan(&runSHA, &membersSHA); err != nil {
		t.Fatal(err)
	}
	r := CapacityDispatchUnknownMaintenanceDispositionRequest{CapacityDispatchAbandonedDispositionRequest: CapacityDispatchAbandonedDispositionRequest{JobID: e.JobID, ExpectedRunID: e.RunID, ExpectedEnvelopeSHA256: capacityDispatchSHA(wire), ExpectedFencingToken: 1, ExpectedLeaseOwner: leaseOwner, ExpectedPendingWakeCount: MaxCapacityDispatchPendingWakes, Issuer: failedServingIssuerForTest()}, ExpectedReturnedAt: returned, ExpectedRunSHA256: runSHA, ExpectedMembersSHA256: membersSHA}
	barrier := CapacityDispatchExecutorBarrier{ProcessStartedAt: lease.Add(time.Minute), Hostname: "declared-failed-serving-history-fixture", PID: 4242, SourceCommit: strings.Repeat("a", 40)}
	if _, err = DisposeUnknownMaintenanceDispatch(context.Background(), f.db, r, barrier, abandonedAllow); err != nil {
		t.Fatal("legitimate schema87 unknown disposition", index, err)
	}
	return e.JobID, e.RunID
}

func TestFailedServingPreservesDisposedUnknownACKNullAndHeldSendsPostgres(t *testing.T) {
	for _, provider := range []string{"aws", "hetzner"} {
		t.Run(provider, func(t *testing.T) {
			f := newFailedServingFixtureHistory(t, provider, true)
			ctx := failedServingContext(t)
			for i := 0; i < 4; i++ {
				f.historicalUnknown(t, i)
			}
			capture := func() string {
				var raw string
				if err := f.db.QueryRow(`SELECT jsonb_agg(jsonb_build_object('job',to_jsonb(j),'workflow',to_jsonb(w),'receipt',to_jsonb(d)) ORDER BY j.id)::text FROM public.capacity_dispatch_jobs j JOIN public.workflow_runs w ON w.id=j.run_id JOIN public.capacity_dispatch_unknown_maintenance_dispositions d ON d.job_id=j.id WHERE j.realm=$1`, f.policy.Metadata.Namespace).Scan(&raw); err != nil {
					t.Fatal(err)
				}
				return raw
			}
			before, originals := capture(), f.preserved(t)
			q := failedServingQuarantine(t, f)
			failedServingOff(t, f, q.ID)
			o, err := f.store.BeginFailedServingGuestObservation(ctx, f.pre.PreregistrationID, q.ID, failedServingIssuerForTest(), "absence")
			if err != nil {
				t.Fatal(err)
			}
			if _, err = f.store.CompleteFailedServingGuestAbsence(ctx, o, failedServingAbsence(t, o), f.inventory(t, true)); err != nil {
				t.Fatal("historical uncertain remote effects incorrectly require success", err)
			}
			if capture() != before || !reflect.DeepEqual(f.preserved(t), originals) {
				t.Fatal("closed dispatch/canary history was rewritten")
			}
			var jobs, acks, held, missing int
			if err = f.db.QueryRow(`SELECT count(*),count(finalization_ack_at) FROM public.capacity_dispatch_jobs WHERE realm=$1 AND state='unknown_maintenance_disposed'`, f.policy.Metadata.Namespace).Scan(&jobs, &acks); err != nil || jobs != 4 || acks != 0 {
				t.Fatal("historical unknown/ACK NULL lost", err)
			}
			if err = f.db.QueryRow(`SELECT count(*) FILTER(WHERE r.outcome='held'),count(*) FILTER(WHERE r.challenge_id IS NULL) FROM public.capacity_guest_notify_canary_sends s JOIN public.capacity_guest_notify_canary_challenges c ON c.id=s.challenge_id LEFT JOIN public.capacity_guest_notify_canary_returns r ON r.challenge_id=s.challenge_id WHERE c.preregistration_id=$1`, f.pre.PreregistrationID).Scan(&held, &missing); err != nil || held != 2 || missing != 2 {
				t.Fatal("held/unreturned possible sends lost", held, missing, err)
			}
			var history []map[string]json.RawMessage
			if json.Unmarshal(q.HistoricalUnknowns, &history) != nil || len(history) != 4 {
				t.Fatal("immutable admission omitted legitimate closed unknowns")
			}
		})
	}
}
