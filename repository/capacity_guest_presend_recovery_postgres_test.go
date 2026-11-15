package repository

import (
	"context"
	"database/sql"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// Declared pre-send history and read observations, not a live provider or
// signed Guest fixture. Every tested recovery transaction uses normal guards.
// This stays inside the existing owning PG root and preserves its node census.
func testOriginalGuestPresendRecoveryPostgres(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()
	wire := func(v any) []byte {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	read := func(name string) model.CapacityPolicySpec {
		raw, err := os.ReadFile("../internal/capacity/testdata/" + name + "-notify-hetzner-production-contract.json")
		if err != nil {
			t.Fatal(err)
		}
		var p model.CapacityPolicySpec
		if json.Unmarshal(raw, &p) != nil {
			t.Fatal("existing public contract")
		}
		return p
	}
	// The public binding stores hexadecimal digests; native labels use the
	// canonical lowercase unpadded base32 encoding in vmLabelDigest. Keep this
	// fixture data encoding available in the default repository test build.
	labelDigest := func(digest string) string {
		raw, err := hex.DecodeString(digest)
		if err != nil {
			t.Fatal("declared binding digest", err)
		}
		return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw))
	}
	for _, fault := range []string{"complete", "interrupted_expired", "interrupted_live", "wrong_original_owner", "wrong_executor", "nonfailed_run", "missing_ack", "live_original_lease", "unexpired_grant", "attempt", "settlement", "changed_baseline", "incomplete_inventory", "missing_coverage", "other_authority", "wrong_plan_owner", "wrong_run_selector", "duplicate_failed_run", "cleanup_lane", "installed_lane", "undisposed_history", "foreign_source", "current_dispatch_expired", "stopped_member", "locked_member", "confirmed_epoch"} {
		func() {
			ns := "presend-" + uuid.NewString()
			var wfID uuid.UUID
			var runIDs []uuid.UUID
			defer func() {
				tx, err := db.BeginTx(ctx, nil)
				if err != nil {
					t.Fatal(err)
				}
				defer tx.Rollback()
				if _, err = tx.ExecContext(ctx, `SET LOCAL session_replication_role=replica`); err != nil {
					t.Fatal(err)
				}
				for _, q := range []string{
					`DELETE FROM public.capacity_dispatch_wakes WHERE realm=$1`,
					`DELETE FROM public.capacity_dispatch_jobs WHERE realm=$1`,
					`DELETE FROM public.capacity_vm_provisioning_preregistrations WHERE preregistration_record->>'policy_id' IN(SELECT id::text FROM public.manifests WHERE namespace=$1)`,
					`DELETE FROM public.capacity_intent_events WHERE namespace=$1`,
					`DELETE FROM public.capacity_mutation_grants WHERE namespace=$1`,
					`DELETE FROM public.capacity_intents WHERE namespace=$1`,
					`DELETE FROM public.manifests WHERE namespace=$1`,
				} {
					if _, err = tx.ExecContext(ctx, q, ns); err != nil {
						t.Fatal(err)
					}
				}
				for _, runID := range runIDs {
					if _, err = tx.ExecContext(ctx, `DELETE FROM public.workflow_runs WHERE id=$1`, runID); err != nil {
						t.Fatal(err)
					}
				}
				if _, err = tx.ExecContext(ctx, `DELETE FROM public.manifests WHERE id=$1`, wfID); err != nil {
					t.Fatal(err)
				}
				if err = tx.Commit(); err != nil {
					t.Fatal(err)
				}
			}()
			prior, p := read("original"), read("b509")
			prior.GuestRetirementBinding.CoreAuthoritySourceCommit = capacity.GuestD11ProtocolAuthority
			prior.Workflow.Name, p.Workflow.Name = ns, ns
			p.ExecutionEnabled = true
			if !capacity.GuestBindingAuthorityCurrent(prior, *prior.GuestRetirementBinding) || !capacity.GuestBindingAuthorityCurrent(p, *p.GuestRetirementBinding) {
				t.Fatal("existing approvals")
			}
			// Replica is used solely to DECLARE immutable expired history and
			// individual adversarial fixtures; never for the operation under test.
			tx, err := db.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			must := func(q string, args ...any) {
				if _, e := tx.ExecContext(ctx, q, args...); e != nil {
					t.Fatal(fault, e)
				}
			}
			must(`SET LOCAL session_replication_role=replica`)
			insert := func(kind, namespace, name string, version int, spec any, active bool) model.Manifest {
				m := model.Manifest{ID: uuid.New(), Kind: kind, Metadata: model.ManifestMetadata{Namespace: namespace, Name: name, Active: active}, Version: version, Checksum: capacity.BusinessCreationSHA256([]byte(uuid.NewString())), Spec: wire(spec)}
				must(`INSERT INTO public.manifests(id,api_version,kind,namespace,name,version,checksum,spec,active) VALUES($1,'v1',$2,$3,$4,$5,$6,$7::jsonb,$8)`, m.ID, kind, namespace, name, version, m.Checksum, string(m.Spec), active)
				return m
			}
			birth := insert("capacity_policy", ns, "notify-hetzner-elastic-capacity", 12, prior, false)
			p.GuestContractSuccessor = &model.CapacityGuestContractSuccessor{Schema: capacity.GuestContractSuccessorSchema, RetainedPolicyContracts: []model.CapacityGuestRetainedPolicyContract{{PolicyID: birth.ID.String(), PolicyChecksum: birth.Checksum, ContractSHA256: guestContractDigest(prior)}}}
			original := insert("capacity_policy", ns, birth.Metadata.Name, 13, p, false)
			current := insert("capacity_policy", ns, birth.Metadata.Name, 14, p, true)
			rbac := insert("rbac", ns, "private-dispatch", 1, map[string]any{}, true)
			graph, err := capacity.OriginalGuestReconcileGraph(current, p)
			if err != nil {
				t.Fatal(err)
			}
			on, off := true, false
			spec := model.WorkflowManifestSpec{Authorization: &model.WorkflowAuthorizationSpec{RBAC: model.ManifestSelector{ManifestID: rbac.ID.String()}}, DispatchMode: "async", Trigger: model.WorkflowTriggerSpec{Mode: "schedule", Enabled: &on, Schedule: &model.WorkflowScheduleTriggerSpec{CronExpression: "* * * * *"}}, InputSchema: model.WorkflowInputSchemaSpec{Required: []string{"policy"}, AdditionalProperties: &off, Properties: map[string]model.IntegrationSchemaProperty{"policy": {Type: "object"}}}, Steps: graph}
			if capacity.ValidateOriginalGuestReconcileGraph(spec, current, p) != nil {
				t.Fatal("canonical seven-step fixture")
			}
			wf := insert("workflow", p.Workflow.Namespace, ns, 1, spec, true)
			wfID = wf.ID
			now := time.Now().UTC().Truncate(time.Microsecond)
			start := now.Add(-20 * time.Minute)
			reserved, returned, expired := start.Add(2*time.Second), start.Add(3*time.Second), start.Add(300*time.Second)
			owner, executor := uuid.NewString(), uuid.NewString()
			b := p.MutationBindings[0]
			grant := model.CapacityMutationGrant{GrantID: uuid.NewString(), BindingName: b.Name, Capability: b.EnsureCapability, IntegrationInstanceID: b.IntegrationInstanceID, ScopeChecksum: b.ScopeChecksum, ProfileName: b.ProfileName, Slot: 2, RequestSHA256: b.Slots[1].DesiredSpecSHA256, ExpiresAt: expired, State: "issued"}
			record := capacityMutationRecord{Grant: grant, Binding: b, PolicyID: original.ID, PolicyChecksum: original.Checksum, WorkflowID: wf.ID, Generation: 13, FencingToken: 29, LeaseOwner: owner, ExecutorID: executor, CreatedAt: reserved, EventProvider: "hetzner", EventResource: "server"}
			pre := model.CapacityGuestOriginalProvisioningPreregistration{Schema: capacity.GuestPreregistrationSchema, PreregistrationID: uuid.NewString(), BindingName: p.GuestRetirementBinding.Members[1].Name, OriginalCreateGrantID: grant.GrantID, OriginalCreateRequestSHA256: grant.RequestSHA256, NonceSHA256: capacity.BusinessCreationSHA256([]byte(uuid.NewString())), ProfileManifestSHA256: p.GuestRetirementBinding.ProfileManifestSHA256, PolicyID: original.ID.String(), PolicyChecksum: original.Checksum, WorkflowID: wf.ID.String(), WorkflowChecksum: wf.Checksum, OriginalWorkflowStepID: p.GuestRetirementBinding.ProfileManifest.OriginalProvisioningStepID, OriginalWorkflowStepTimeoutSeconds: 600, OriginalWorkflowContextDeadline: expired, CoreSourceCommit: p.GuestRetirementBinding.CoreAuthoritySourceCommit, Generation: 13, Fence: 29, LeaseOwner: owner, ExecutorID: executor, Slot: 2, OriginalDeadline: expired, ReservedAt: reserved}
			if !capacity.GuestOriginalProvisioningDeadlineMatches(pre, p.GuestRetirementBinding.ProfileManifest) {
				t.Fatal("original captured deadline")
			}
			inventory := func(view model.CapacityPolicySpec, populated bool) model.CapacityVMFleetInventory {
				binding := view.MutationBindings[0]
				d := binding.Slots[0]
				inv := model.CapacityVMFleetInventory{IntegrationInstanceID: binding.IntegrationInstanceID, ScopeChecksum: binding.ScopeChecksum, ProfileChecksum: d.DesiredSpec.ProfileChecksum, AdmissionChecksum: d.DesiredSpec.AdmissionChecksum, ProfileName: binding.ProfileName, ProtectedSlots: binding.ProtectedSlots, MaxSlots: 8, Complete: true, ObservationStartedAt: now.Add(-time.Second).Format(time.RFC3339Nano), ObservedAt: now.Format(time.RFC3339Nano)}
				for slot := 1; slot <= 8; slot++ {
					if !populated || slot != 1 {
						inv.MissingSlots = append(inv.MissingSlots, slot)
					}
				}
				if populated {
					inv.Members = []model.CapacityVMFleetInventoryMember{{Slot: 1, Protected: binding.ProtectedSlots >= 1, DesiredSpec: *d.DesiredSpec, RequestSHA256: d.DesiredSpecSHA256, Server: model.CapacityVMServerObservation{CapacityVMNativeTuple: model.CapacityVMNativeTuple{ID: "700001", CreatedAt: now.Add(-time.Hour).Format(time.RFC3339Nano)}, Name: d.DesiredSpec.NativeName, Status: "running", PhysicalSpecVerified: true, ObservedAt: inv.ObservedAt, Labels: map[string]string{"yggdrasil.io/owner": view.Owner, "yggdrasil.io/scope": labelDigest(binding.ScopeChecksum), "yggdrasil.io/spec": labelDigest(d.DesiredSpec.ProfileChecksum), "yggdrasil.io/profile": binding.ProfileName, "yggdrasil.io/slot": "1"}}}}
				}
				return inv
			}
			views := []model.CapacityPolicySpec{p, prior}
			inventories := []capacity.GuestContractInventory{{ContractSHA256: guestContractDigest(p), Inventory: inventory(p, false)}, {ContractSHA256: guestContractDigest(prior), Inventory: inventory(prior, true)}}
			snapshot, _, err := capacity.GuestContractReconcileSnapshot(current, p, views, inventories, now)
			if err != nil {
				t.Fatal(err)
			}
			assessment := model.CapacityAssessment{Snapshot: snapshot}
			for _, signal := range p.Signals {
				value := 4.25
				assessment.Evidence = append(assessment.Evidence, model.CapacityEvidence{Name: signal.Name, SourceIdentity: signal.SourceIdentity, Unit: signal.Unit, RequireData: true, Matched: true, DataState: "present", Value: &value, RangeMin: &value, RangeMax: &value, SourceSampledAt: now, WindowStart: now.Add(-time.Minute), WindowEnd: now, Samples: max(10, p.MinSamples), CoverageComplete: true, MaxGapSeconds: 1})
			}
			coverage := *p.GuestNotifyReconcileBinding.MemberCoverage
			count := 1.0
			reporting := model.CapacityMetricRangeObservation{CapacityEvidence: model.CapacityEvidence{Name: capacity.OriginalGuestMemberCoverageName, SourceIdentity: "production/notify/hetzner/reporting-members", Unit: "members", RequireData: true, Matched: true, DataState: "present", Value: &count, RangeMin: &count, RangeMax: &count, SourceSampledAt: now, WindowStart: now.Add(-time.Minute), WindowEnd: now, Samples: 10, CoverageComplete: true, MaxGapSeconds: 1}, Operation: capacity.ObserveMetricRange, Binding: coverage.BindingName, BindingSHA256: coverage.BindingSHA256, EvaluatedAt: now, OK: true, Reason: "complete"}
			intent := model.CapacityIntent{Namespace: ns, PolicyName: current.Metadata.Name, PolicyID: original.ID, PolicyChecksum: original.Checksum, Environment: p.Environment, Domain: p.Domain, Dimension: p.Dimension, Generation: 13, FencingToken: 29, Phase: "preparing", LeaseOwner: owner, LeaseExecutorID: executor, LeaseExpiresAt: &expired, BaselineSnapshot: snapshot, Assessment: assessment, Decision: model.CapacityDecision{Action: "expand", Reason: "sustained_pressure", Profile: b.ProfileName, Units: 2, Floor: 1, ExecutionPermitted: true}, UpdatedAt: start}
			if fault == "interrupted_expired" || fault == "interrupted_live" {
				intent.RecoveryOnly, intent.Decision.ExecutionPermitted, intent.FencingToken, intent.LeaseOwner, intent.LeaseExecutorID = true, false, 30, uuid.NewString(), uuid.NewString()
			}
			if fault == "interrupted_live" || fault == "live_original_lease" {
				live := now.Add(time.Minute)
				intent.LeaseExpiresAt = &live
			}
			if fault == "wrong_original_owner" {
				intent.LeaseOwner = uuid.NewString()
			}
			if fault == "wrong_executor" {
				record.ExecutorID = uuid.NewString()
			}
			if fault == "unexpired_grant" {
				record.Grant.ExpiresAt = now.Add(time.Minute)
			}
			if fault == "attempt" {
				record.AttemptID = uuid.NewString()
			}
			if fault == "settlement" {
				record.Settlement = &model.CapacityMutationSettleRequest{Outcome: "uncertain"}
			}
			if fault == "changed_baseline" {
				intent.BaselineSnapshot.ResourceVersion = "replacement"
			}
			if fault == "stopped_member" {
				inventories[1].Inventory.Members[0].Server.Status = "off"
			}
			if fault == "locked_member" {
				inventories[1].Inventory.Members[0].Server.Locked = true
			}
			if fault == "incomplete_inventory" {
				inventories[1].Inventory.Complete = false
			}
			if fault == "missing_coverage" {
				reporting.OK = false
			}
			if fault == "cleanup_lane" {
				intent.WitnessedUnenrolledExpansionCleanupID = uuid.NewString()
			}
			must(`INSERT INTO public.capacity_intents(namespace,environment,domain,dimension,intent,updated_at) VALUES($1,$2,$3,$4,$5::jsonb,$6)`, ns, p.Environment, p.Domain, p.Dimension, string(wire(intent)), intent.UpdatedAt)
			seedGrant := func(r capacityMutationRecord) {
				must(`INSERT INTO public.capacity_mutation_grants(id,namespace,environment,domain,dimension,generation,integration_instance_id,scope_checksum,profile_name,slot,state,grant_record,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::jsonb,$13)`, r.Grant.GrantID, ns, p.Environment, p.Domain, p.Dimension, r.Generation, r.Binding.IntegrationInstanceID, r.Binding.ScopeChecksum, r.Binding.ProfileName, r.Grant.Slot, r.Grant.State, string(wire(r)), r.Grant.ExpiresAt)
			}
			if fault == "installed_lane" {
				record.Grant.State = "confirmed"
				assessment.Snapshot.Units = 2
			}
			seedGrant(record)
			// A disposed old accepted CREATE deliberately remains SETTLED. The
			// shared predicate owns that historical closure; an undisposed one
			// must still block, regardless of its earlier generation.
			history := record
			history.Grant = model.CapacityMutationGrant{GrantID: uuid.NewString(), BindingName: prior.MutationBindings[0].Name, Capability: prior.MutationBindings[0].EnsureCapability, IntegrationInstanceID: prior.MutationBindings[0].IntegrationInstanceID, ScopeChecksum: prior.MutationBindings[0].ScopeChecksum, ProfileName: prior.MutationBindings[0].ProfileName, Slot: 1, RequestSHA256: prior.MutationBindings[0].Slots[0].DesiredSpecSHA256, ExpiresAt: expired, State: "settled"}
			history.Binding, history.Generation = prior.MutationBindings[0], 7
			history.AttemptID = uuid.NewString()
			history.Settlement = &model.CapacityMutationSettleRequest{Outcome: "accepted", ResourceID: "600001", TransportCompleted: true}
			seedGrant(history)
			if fault != "undisposed_history" {
				must(`UPDATE public.capacity_mutation_grants SET enrolled_failed_disposition_id=$2 WHERE id=$1`, history.Grant.GrantID, uuid.New())
			}
			if fault == "other_authority" || fault == "confirmed_epoch" {
				other := record
				other.Grant.GrantID, other.Grant.Slot = uuid.NewString(), 3
				if fault == "confirmed_epoch" {
					other.Grant.State = "confirmed"
				}
				seedGrant(other)
			}
			must(`INSERT INTO public.capacity_vm_provisioning_preregistrations(id,create_grant_id,nonce_sha256,profile_manifest_sha256,preregistration_record,original_deadline,created_at,original_wire,binding_wire) VALUES($1,$2,$3,$4,$5::jsonb,$6,$7,$8,$9)`, pre.PreregistrationID, pre.OriginalCreateGrantID, pre.NonceSHA256, pre.ProfileManifestSHA256, string(wire(pre)), pre.OriginalDeadline, pre.ReservedAt, wire(pre), wire(p.GuestRetirementBinding))
			var oldJobID string
			seedRun := func(policy model.Manifest, failed bool) CapacityDispatchEnvelope {
				e := CapacityDispatchEnvelope{Protocol: CapacityDispatchProtocol, JobID: uuid.New(), RunID: uuid.New(), Realm: ns, Environment: p.Environment, Domain: p.Domain, Dimension: p.Dimension, SourceTick: uuid.NewString(), Policy: guestPresendManifestPin(policy), Workflow: guestPresendManifestPin(wf), RBAC: guestPresendManifestPin(rbac), MachinePrincipalID: "capacity-controller", PrincipalSHA256: strings.Repeat("1", 64), BindingSHA256: strings.Repeat("2", 64), Inputs: map[string]any{"policy": map[string]any{"namespace": ns, "name": policy.Metadata.Name}}}
				e.Metadata = map[string]any{WorkflowRunCreatorMachinePrincipalMetadataKey: e.MachinePrincipalID, "triggered_by": "workflow_scheduler", "manifest_id": wf.ID.String(), "scheduled_for": e.SourceTick, "capacity_dispatch_job_id": e.JobID.String(), "capacity_dispatch_protocol": e.Protocol}
				e.InputsSHA256, e.MetadataSHA256, err = CapacityDispatchEnvelopeHashes(e)
				if err != nil {
					t.Fatal(err)
				}
				envelope, err := encodeCapacityDispatchEnvelope(e)
				if err != nil {
					t.Fatal(err)
				}
				status, state, started, deadline := "running", "started", now.Add(-time.Second), now.Add(5*time.Minute)
				var finish, ack any
				var result any
				workflowName := ns
				if failed {
					status, state, started, deadline, finish, ack = "failed", "returned", start, expired, returned, returned.Add(time.Second)
					out := model.RunWorkflowResponse{Workflow: model.ManifestReference{ID: wf.ID, Kind: "workflow", Namespace: wf.Metadata.Namespace, Name: wf.Metadata.Name, Version: wf.Version}, Status: "failed", StartedAt: start, FinishedAt: returned}
					for _, step := range graph {
						r := model.WorkflowRunStepResult{ID: step.ID, Kind: "yggdrasil", Operation: step.Use.Operation, Status: "skipped"}
						if step.ID == "plan-original-guest" {
							r.Status, r.StartedAt, r.FinishedAt = "succeeded", start, start.Add(time.Second)
							r.Metadata = map[string]any{"mode": "provision", "generation": int64(13), "fencing_token": int64(29), "lease_owner": owner, "slot": 2, "preregistration_id": "", "reason": "sustained_pressure"}
							if fault == "wrong_plan_owner" {
								r.Metadata["lease_owner"] = uuid.NewString()
							}
						}
						if step.ID == pre.OriginalWorkflowStepID {
							r.Status, r.StartedAt, r.FinishedAt = "failed", start.Add(time.Second), returned
							r.Metadata = map[string]any{"original_guest_refusal_predicate": "original-guest-step-25"}
						}
						out.Steps = append(out.Steps, r)
					}
					result = string(wire(out))
					if fault == "nonfailed_run" {
						status = "succeeded"
					}
					if fault == "missing_ack" {
						ack = nil
					}
					if fault == "wrong_run_selector" {
						workflowName = "foreign"
					}
					oldJobID = e.JobID.String()
				}
				runIDs = append(runIDs, e.RunID)
				must(`INSERT INTO public.workflow_runs(id,workflow_namespace,workflow_name,workflow_version,status,inputs,metadata,result,started_at,finished_at) VALUES($1,$2,$3,$4,$5,$6::jsonb,$7::jsonb,$8::jsonb,$9,$10)`, e.RunID, wf.Metadata.Namespace, workflowName, wf.Version, status, string(wire(e.Inputs)), string(wire(e.Metadata)), result, started, finish)
				if fault == "missing_ack" && !failed {
					return e
				}
				if fault == "current_dispatch_expired" && !failed {
					started, deadline = now.Add(-2*time.Second), now.Add(-time.Second)
					must(`UPDATE public.workflow_runs SET started_at=$2 WHERE id=$1`, e.RunID, started)
				}
				must(`INSERT INTO public.capacity_dispatch_jobs(id,run_id,protocol,realm,environment,domain,dimension,source_tick,envelope,envelope_sha256,state,lease_owner,fencing_token,lease_expires_at,started_at,returned_at,return_status,finalization_ack_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,1,$13,$14,$15,$16,$17)`, e.JobID, e.RunID, e.Protocol, ns, p.Environment, p.Domain, p.Dimension, e.SourceTick, string(envelope), capacityDispatchSHA(envelope), state, uuid.New(), deadline, started, finish, map[bool]any{true: "failed", false: nil}[failed], ack)
				return e
			}
			seedRun(original, true)
			if fault == "duplicate_failed_run" {
				seedRun(original, true)
			}
			currentRun := seedRun(current, false)
			if err = tx.Commit(); err != nil {
				t.Fatal(err)
			}
			store := CapacityStore{DB: db, ExecutionEnabled: true, WorkflowID: wf.ID, ExecutorID: uuid.NewString(), OriginalRunID: currentRun.RunID}.WithOriginalGuestContractReconcile(wf, graph[0], capacity.CurrentGuestCoreSource(), "", "", inventories, reporting)
			if fault == "foreign_source" {
				store.guestReconcile.source = strings.Repeat("f", 40)
			}
			// Whole rows prove the hook cannot rewrite original failure/ACK,
			// preregistration, workflow identity, catalog or grant content.
			originals := func() string {
				var raw string
				e := db.QueryRowContext(ctx, `SELECT jsonb_build_object('pre',(SELECT to_jsonb(x) FROM public.capacity_vm_provisioning_preregistrations x WHERE id=$1),'job',(SELECT to_jsonb(x) FROM public.capacity_dispatch_jobs x WHERE id=$2),'run',(SELECT to_jsonb(w) FROM public.workflow_runs w JOIN public.capacity_dispatch_jobs j ON j.run_id=w.id WHERE j.id=$2),'historical_grants',(SELECT jsonb_agg(to_jsonb(g) ORDER BY id) FROM public.capacity_mutation_grants g WHERE namespace=$3 AND generation<>13),'catalog',(SELECT jsonb_agg(to_jsonb(m) ORDER BY id) FROM public.manifests m WHERE namespace=$3 OR id=$4))::text`, pre.PreregistrationID, oldJobID, ns, wf.ID).Scan(&raw)
				if e != nil {
					t.Fatal(e)
				}
				return raw
			}
			state := func() string {
				var raw string
				if e := db.QueryRowContext(ctx, `SELECT jsonb_build_object('intent',(SELECT intent FROM public.capacity_intents WHERE namespace=$1),'grants',(SELECT jsonb_agg(grant_record ORDER BY id) FROM public.capacity_mutation_grants WHERE namespace=$1),'events',(SELECT count(*) FROM public.capacity_intent_events WHERE namespace=$1))::text`, ns).Scan(&raw); e != nil {
					t.Fatal(e)
				}
				return raw
			}
			before, immutable := state(), originals()
			if fault == "missing_ack" {
				check, e := db.BeginTx(ctx, nil)
				if e != nil {
					t.Fatal(e)
				}
				_, e = store.guestPresendFailedRunTx(ctx, check, original, p, pre, now)
				check.Rollback()
				if e == nil {
					t.Fatal("unacknowledged original run admitted")
				}
			}
			done, err := store.TryRecoverOriginalGuestPresend(ctx, current, assessment)
			if fault != "complete" && fault != "interrupted_expired" {
				if (fault == "installed_lane" || fault == "cleanup_lane" || fault == "live_original_lease" || fault == "interrupted_live") && err != nil {
					t.Fatal(fault, "unrelated/live lane must retain its ordinary HOLD or resume", err)
				}
				if done || state() != before || originals() != immutable {
					t.Fatal(fault, "refused recovery changed authority/history", err)
				}
				return
			}
			if err != nil || !done {
				t.Fatal(fault, "real canonical source recovery refused", err)
			}
			var after model.CapacityIntent
			var grantRaw []byte
			if e := db.QueryRowContext(ctx, `SELECT intent FROM public.capacity_intents WHERE namespace=$1`, ns).Scan(&grantRaw); e != nil || json.Unmarshal(grantRaw, &after) != nil {
				t.Fatal(e)
			}
			if after.Phase != "aborted" || !after.RecoveryOnly || after.Generation != 13 || after.FencingToken != intent.FencingToken+1 || after.Decision.ExecutionPermitted || after.LeaseOwner != "" || after.LeaseExecutorID != "" || after.LeaseExpiresAt != nil || !reflect.DeepEqual(after.BaselineSnapshot, intent.BaselineSnapshot) {
				t.Fatal(fault, "unexpected recovery transition", after)
			}
			if e := db.QueryRowContext(ctx, `SELECT grant_record FROM public.capacity_mutation_grants WHERE id=$1`, grant.GrantID).Scan(&grantRaw); e != nil {
				t.Fatal(e)
			}
			var afterGrant capacityMutationRecord
			if json.Unmarshal(grantRaw, &afterGrant) != nil {
				t.Fatal("grant record")
			}
			record.Grant.State = "expired"
			if !reflect.DeepEqual(afterGrant, record) || originals() != immutable || store.WorkflowID != wf.ID || store.OriginalRunID != currentRun.RunID || store.guestReconcile == nil {
				t.Fatal("closure changed immutable original or workflow identity")
			}
			closed := state()
			if again, e := store.TryRecoverOriginalGuestPresend(ctx, current, assessment); again || e != nil || state() != closed {
				t.Fatal("closed original was recovered again", e)
			}
		}()
	}
}
