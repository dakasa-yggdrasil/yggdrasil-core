package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// Declared catalog/ledger rows reproduce the failed pre-send CREATE shape.
// No signed Guest, provider return or approval is fabricated. Recover and
// Reconcile run their complete real transactions with ordinary trigger roles.
func testGuestContractHistoricalRecoveryPostgres(t *testing.T, ctx context.Context, db *sql.DB, catalogNamespace string) {
	t.Helper()
	readContract := func(name string) model.CapacityPolicySpec {
		raw, err := os.ReadFile("../internal/capacity/testdata/" + name + "-notify-hetzner-production-contract.json")
		if err != nil {
			t.Fatal(err)
		}
		var p model.CapacityPolicySpec
		if err = json.Unmarshal(raw, &p); err != nil {
			t.Fatal(err)
		}
		return p
	}
	priorBase, headBase := readContract("original"), readContract("b509")
	priorBase.GuestRetirementBinding.CoreAuthoritySourceCommit = capacity.GuestD11ProtocolAuthority
	for _, p := range []model.CapacityPolicySpec{priorBase, headBase} {
		if !capacity.GuestBindingAuthorityCurrent(p, *p.GuestRetirementBinding) {
			t.Fatal("existing complete public contract approval required")
		}
	}
	marshal := func(value any) []byte {
		b, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	clone := func(p model.CapacityPolicySpec) model.CapacityPolicySpec {
		var out model.CapacityPolicySpec
		if err := json.Unmarshal(marshal(p), &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	must := func(query string, args ...any) {
		if _, err := db.ExecContext(ctx, query, args...); err != nil {
			t.Fatal(err)
		}
	}
	// The existing PG fixture owns this namespace and removes these catalog
	// rows. Their immutable public IDs/checksums stay the approved operands.
	binding := headBase.MutationBindings[0]
	must(`INSERT INTO public.manifests(id,api_version,kind,namespace,name,version,checksum,spec,active) VALUES($1,'v1','integration_type',$2,'historical-recovery-type',1,$3,'{}'::jsonb,true)`, binding.IntegrationTypeID, catalogNamespace, binding.IntegrationTypeChecksum)
	for n, p := range []model.CapacityPolicySpec{priorBase, headBase} {
		b := p.MutationBindings[0]
		must(`INSERT INTO public.manifests(id,api_version,kind,namespace,name,version,checksum,spec,active) VALUES($1,'v1','integration_instance',$2,$3,1,$4,$5::jsonb,true)`, b.IntegrationInstanceID, catalogNamespace, "historical-recovery-instance-"+string(rune('a'+n)), b.IntegrationChecksum, string(marshal(map[string]any{"type_ref": model.ManifestSelector{ManifestID: b.IntegrationTypeID}})))
	}
	for _, fault := range []string{"complete", "current_policy", "wrong_checksum", "wrong_generation", "retained_checksum", "retained_contract", "binding_checksum", "inactive_workflow", "live_original_lease", "mutation_inflight", "no_mutation_proof", "replacement_baseline", "redeemed_authority", "confirmed_mutation"} {
		func() {
			ns, name := "historical-recovery-"+uuid.NewString(), "notify-hetzner-elastic-capacity"
			defer func() {
				// Only fixture teardown bypasses immutable-history delete guards.
				// Every tested transaction above runs with the ordinary role.
				tx, err := db.BeginTx(ctx, nil)
				if err != nil {
					t.Fatal(err)
				}
				defer tx.Rollback()
				if _, err = tx.ExecContext(ctx, `SET LOCAL session_replication_role=replica`); err != nil {
					t.Fatal(err)
				}
				for _, table := range []string{"capacity_intent_events", "capacity_mutation_grants", "capacity_intents", "manifests"} {
					if _, err = tx.ExecContext(ctx, "DELETE FROM public."+table+" WHERE namespace=$1", ns); err != nil {
						t.Fatal(err)
					}
				}
				if err = tx.Commit(); err != nil {
					t.Fatal(err)
				}
			}()
			prior, head := clone(priorBase), clone(headBase)
			priorDigest, headDigest := guestContractDigest(prior), guestContractDigest(head)
			prior.Workflow.Name, head.Workflow.Name = ns, ns
			if guestContractDigest(prior) != priorDigest || guestContractDigest(head) != headDigest {
				t.Fatal("declared workflow name changed approved physical contracts")
			}
			insert := func(kind, logical string, version int, checksum string, spec any, active bool) model.Manifest {
				raw := marshal(spec)
				namespace := ns
				if kind == "workflow" {
					namespace = head.Workflow.Namespace
				}
				m := model.Manifest{ID: uuid.New(), Kind: kind, Metadata: model.ManifestMetadata{Namespace: namespace, Name: logical}, Version: version, Checksum: checksum, Spec: raw}
				must(`INSERT INTO public.manifests(id,api_version,kind,namespace,name,version,checksum,spec,active) VALUES($1,'v1',$2,$3,$4,$5,$6,$7::jsonb,$8)`, m.ID, kind, namespace, logical, version, checksum, string(raw), active)
				return m
			}
			sha := func() string { return capacity.BusinessCreationSHA256([]byte(uuid.NewString())) }
			birth := insert("capacity_policy", name, 1, sha(), prior, false)
			head.GuestContractSuccessor = &model.CapacityGuestContractSuccessor{Schema: capacity.GuestContractSuccessorSchema, RetainedPolicyContracts: []model.CapacityGuestRetainedPolicyContract{{PolicyID: birth.ID.String(), PolicyChecksum: birth.Checksum, ContractSHA256: priorDigest}}}
			if fault == "retained_checksum" {
				head.GuestContractSuccessor.RetainedPolicyContracts[0].PolicyChecksum = strings.Repeat("f", 64)
			}
			if fault == "retained_contract" {
				head.GuestContractSuccessor.RetainedPolicyContracts[0].ContractSHA256 = strings.Repeat("e", 64)
			}
			original := insert("capacity_policy", name, 13, sha(), head, false)
			current := insert("capacity_policy", name, 14, sha(), head, true)
			wf := insert("workflow", head.Workflow.Name, 1, sha(), map[string]any{"authorization": map[string]any{}}, fault != "inactive_workflow")
			defer must(`DELETE FROM public.manifests WHERE id=$1`, wf.ID)
			now := time.Now().UTC()
			expired := now.Add(-time.Second)
			assessment := model.CapacityAssessment{Snapshot: model.CapacitySnapshot{TargetIdentity: head.TargetIdentity, ResourceUID: "declared-floor-resource", WorkloadUID: "declared-floor-workload", WorkloadResourceVersion: "10", ResourceVersion: "1", Owner: head.Owner, Profile: head.Profiles[0].Name, Units: 1, ObservedAt: now}}
			for _, signal := range head.Signals {
				v := signal.UpAbove + 1
				assessment.Evidence = append(assessment.Evidence, model.CapacityEvidence{Name: signal.Name, SourceIdentity: signal.SourceIdentity, Unit: signal.Unit, RequireData: true, Matched: true, DataState: "present", Value: &v, RangeMin: &v, RangeMax: &v, SourceSampledAt: now, WindowStart: now.Add(-time.Minute), WindowEnd: now, Samples: max(head.MinSamples, 10), CoverageComplete: true, MaxGapSeconds: 1})
			}
			owner, executor := uuid.NewString(), uuid.NewString()
			intent := model.CapacityIntent{Namespace: ns, PolicyName: name, PolicyID: original.ID, PolicyChecksum: original.Checksum, Environment: head.Environment, Domain: head.Domain, Dimension: head.Dimension, Generation: 13, FencingToken: 29, Phase: "preparing", LeaseOwner: owner, LeaseExecutorID: executor, LeaseExpiresAt: &expired, BaselineSnapshot: assessment.Snapshot, Assessment: assessment, Decision: model.CapacityDecision{Action: "prepare", Reason: "sustained_pressure", Profile: head.Profiles[0].Name, Units: 2, Floor: head.Floor, ExecutionPermitted: true}, UpdatedAt: now.Add(-time.Minute)}
			if fault == "live_original_lease" {
				live := now.Add(time.Minute)
				intent.LeaseExpiresAt = &live
			}
			b := head.MutationBindings[0]
			grant := model.CapacityMutationGrant{GrantID: uuid.NewString(), BindingName: b.Name, Capability: b.EnsureCapability, IntegrationInstanceID: b.IntegrationInstanceID, ScopeChecksum: b.ScopeChecksum, ProfileName: b.ProfileName, Slot: 2, RequestSHA256: b.Slots[1].DesiredSpecSHA256, ExpiresAt: expired, State: "issued"}
			record := capacityMutationRecord{Grant: grant, Binding: b, PolicyID: original.ID, PolicyChecksum: original.Checksum, WorkflowID: wf.ID, Generation: intent.Generation, FencingToken: intent.FencingToken, LeaseOwner: owner, ExecutorID: executor, CreatedAt: now.Add(-time.Minute), EventProvider: "hetzner", EventResource: "server"}
			if fault == "redeemed_authority" || fault == "confirmed_mutation" {
				record.Grant.State = "redeemed"
				record.AttemptID, record.SettlementTokenSHA256 = uuid.NewString(), strings.Repeat("a", 64)
				if fault == "confirmed_mutation" {
					record.Grant.State = "confirmed"
				}
			}
			must(`INSERT INTO public.capacity_intents(namespace,environment,domain,dimension,intent,updated_at) VALUES($1,$2,$3,$4,$5::jsonb,$6)`, ns, head.Environment, head.Domain, head.Dimension, string(marshal(intent)), intent.UpdatedAt)
			must(`INSERT INTO public.capacity_mutation_grants(id,namespace,environment,domain,dimension,generation,integration_instance_id,scope_checksum,profile_name,slot,state,grant_record,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::jsonb,$13)`, grant.GrantID, ns, head.Environment, head.Domain, head.Dimension, intent.Generation, b.IntegrationInstanceID, b.ScopeChecksum, b.ProfileName, grant.Slot, record.Grant.State, string(marshal(record)), expired)
			if fault == "binding_checksum" {
				must(`UPDATE public.manifests SET checksum=$2 WHERE id=$1`, b.IntegrationInstanceID, strings.Repeat("d", 64))
				defer must(`UPDATE public.manifests SET checksum=$2 WHERE id=$1`, b.IntegrationInstanceID, b.IntegrationChecksum)
			}
			read := func() string {
				var original string
				if err := db.QueryRowContext(ctx, `SELECT jsonb_build_object('intent',i.intent,'grant',g.grant_record,'events',(SELECT count(*) FROM public.capacity_intent_events e WHERE e.namespace=i.namespace),'catalog',(SELECT jsonb_agg(to_jsonb(m) ORDER BY m.kind,m.version,m.id) FROM public.manifests m WHERE m.namespace=i.namespace))::text FROM public.capacity_intents i JOIN public.capacity_mutation_grants g ON g.namespace=i.namespace WHERE i.namespace=$1`, ns).Scan(&original); err != nil {
					t.Fatal(err)
				}
				return original
			}
			before := read()
			store := CapacityStore{DB: db, ExecutionEnabled: true, WorkflowID: wf.ID, ExecutorID: uuid.NewString()}
			// Historical recovery must not relax normal acquisition or mutation.
			if _, err := store.Assess(ctx, original, assessment); err == nil {
				t.Fatal(fault, "inactive successor admitted ordinary assessment")
			}
			if _, err := store.IssueMutation(ctx, original, intent.Generation, intent.FencingToken, owner, model.CapacityMutationIssue{BindingName: b.Name, DesiredSpec: marshal(b.Slots[1].DesiredSpec)}); err == nil {
				t.Fatal(fault, "inactive successor admitted ordinary provider permission")
			}
			if read() != before {
				t.Fatal(fault, "ordinary refused writes changed originals")
			}
			selected, generation := original, intent.Generation
			switch fault {
			case "current_policy":
				selected = current
			case "wrong_checksum":
				selected.Checksum = strings.Repeat("c", 64)
			case "wrong_generation":
				generation++
			}
			recovered, err := store.Recover(ctx, selected, generation, assessment)
			recoverRefused := fault == "current_policy" || fault == "wrong_checksum" || fault == "wrong_generation" || fault == "retained_checksum" || fault == "retained_contract" || fault == "binding_checksum" || fault == "inactive_workflow" || fault == "live_original_lease"
			if recoverRefused {
				if err == nil || read() != before {
					t.Fatal(fault, "invalid historical recovery changed originals", err)
				}
				return
			}
			if err != nil || !recovered.RecoveryOnly || recovered.Decision.ExecutionPermitted || recovered.PolicyID != original.ID || recovered.Generation != 13 || recovered.FencingToken != 30 || recovered.LeaseExecutorID != store.ExecutorID || recovered.LeaseOwner == owner {
				t.Fatal(fault, "exact inactive successor could not acquire recovery-only fence", err, recovered)
			}
			if _, err = store.RenewRecovery(ctx, original, recovered.Generation, recovered.FencingToken, recovered.LeaseOwner); err != nil {
				t.Fatal(fault, "historical recovery lease renewal refused", err)
			}
			zero, one := 0, 1
			proof := model.CapacityTransitionProof{Assessment: assessment, ObservedAt: time.Now().UTC(), ReceiptRef: "declared-provider-observation:no-send", Healthy: true, Inflight: &zero, MutationInflight: &zero, NoMutationVerified: true, MutationAuthorityKind: "core_mutation_grants"}
			if _, err = store.Advance(ctx, original, recovered.Generation, recovered.FencingToken, recovered.LeaseOwner, "prepared", proof); err == nil {
				t.Fatal(fault, "recovery-only fence admitted ordinary acquisition phase")
			}
			switch fault {
			case "mutation_inflight":
				proof.MutationInflight = &one
			case "no_mutation_proof":
				proof.NoMutationVerified = false
			case "replacement_baseline":
				proof.Assessment.Snapshot.WorkloadUID = "different-floor-workload"
			}
			preReconcile := read()
			finished, err := store.Reconcile(ctx, original, recovered.Generation, recovered.FencingToken, recovered.LeaseOwner, "aborted", proof)
			if fault != "complete" {
				if err == nil || read() != preReconcile {
					t.Fatal(fault, "unsafe abort accepted or mutated ledger", err)
				}
				return
			}
			if err != nil || finished.Phase != "aborted" || finished.Decision.ExecutionPermitted || finished.LeaseOwner != "" || finished.LeaseExpiresAt != nil || finished.Assessment.Snapshot.Units != 1 {
				t.Fatal("verified original no-send baseline could not close as aborted", err, finished)
			}
			var raw []byte
			var state string
			if err = db.QueryRowContext(ctx, `SELECT state,grant_record FROM public.capacity_mutation_grants WHERE id=$1`, grant.GrantID).Scan(&state, &raw); err != nil {
				t.Fatal(err)
			}
			var after capacityMutationRecord
			if err = json.Unmarshal(raw, &after); err != nil {
				t.Fatal(err)
			}
			expected := record
			expected.Grant.State = "expired"
			if state != "expired" || !reflect.DeepEqual(after, expected) || after.AttemptID != "" || after.Settlement != nil || after.Proof != nil {
				t.Fatal("abort changed more than never-redeemed permission expiry")
			}
			var active bool
			var checksum string
			if err = db.QueryRowContext(ctx, `SELECT active,checksum FROM public.manifests WHERE id=$1`, current.ID).Scan(&active, &checksum); err != nil || !active || checksum != current.Checksum {
				t.Fatal("historical recovery changed current successor", err)
			}
			if _, err = store.Recover(ctx, original, intent.Generation, assessment); !errors.Is(err, ErrCapacityConflict) {
				t.Fatal("terminal abort reopened original recovery", err)
			}
		}()
	}
}
