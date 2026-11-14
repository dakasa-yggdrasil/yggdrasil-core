//go:build recoveryfixture && !nativequalification

package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/pressly/goose/v3"
)

// Two explicitly separate witnesses in the existing M99 owning child. Current
// Source produces real PUB/READ originals and a real UNKNOWN finish. The other
// database contains DECLARED historical operands constructed before sealing;
// it proves the full 900-second admission/guards, not a live 900-second journey.
// No production/cloud service is contacted and no original is aged or ACKed.
func supersededHTTPMaintenancePostgresRegression(t *testing.T) {
	t.Helper()
	dir := os.Getenv("PREACTION_PLAN_LOGS")
	if !filepath.IsAbs(dir) {
		t.Fatal("owned M104 evidence directory required")
	}
	putRaw := func(name string, raw []byte) {
		t.Helper()
		if len(raw) == 0 || len(raw) > 16<<20 {
			t.Fatal("bounded complete M104 evidence required", name, len(raw))
		}
		file, e := os.OpenFile(filepath.Join(dir, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			t.Fatal(e)
		}
		_, e = file.Write(append(raw, '\n'))
		closeErr := file.Close()
		if e != nil || closeErr != nil {
			t.Fatal("whole M104 evidence", e, closeErr)
		}
	}
	put := func(name string, v any) { t.Helper(); putRaw(name, installedTimeoutWire(t, v)) }
	f := newFailedServingFixtureHistory(t, "aws", true)
	if err := goose.UpToContext(context.Background(), f.db, filepath.Join(failedServingRepositoryRoot(t), "db/migrations"), 103); err != nil {
		t.Fatal("M104 actual before103", err)
	}
	before := installedReadinessCatalog(t, f.db)
	if err := goose.UpToContext(context.Background(), f.db, filepath.Join(failedServingRepositoryRoot(t), "db/migrations"), 104); err != nil {
		t.Fatal("M104 actual Up104", err)
	}
	after := installedReadinessCatalog(t, f.db)
	putRaw("M104-WHOLE-CATALOG-BEFORE103.PUBLIC.json", before)
	putRaw("M104-WHOLE-CATALOG-AFTER104.PUBLIC.json", after)
	base := supersededHTTPBaseRows(t, f.db)
	job := supersededHTTPStart(t, f)
	step := f.step(t, "refresh-original-membership")
	store := f.store.WithOriginalGuestReconcile(f.workflow, step, capacity.CurrentGuestCoreSource(), "refresh", "", f.inventory(t, false), model.CapacityMetricRangeObservation{}).WithOriginalGuestNotifyCanary(step, capacity.CurrentGuestCoreSource())
	store.OriginalRunID = job.RunID
	ctx, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	generation, fence, owner, err := store.GuestNotifyMaintenanceEpoch(ctx, f.policy, f.pre.PreregistrationID)
	if err != nil {
		t.Fatal("M104 genuine maintenance epoch", err)
	}
	publication, err := store.IssueGuestNotifyCanaryPublication(ctx, f.policy, generation, fence, owner, f.pre.PreregistrationID, "steady_useful_membership", failedServingKey('c'))
	if err != nil {
		t.Fatal("M104 genuine PUB issue", err)
	}
	pub := supersededHTTPFinalize(t, ctx, store, f, publication, generation, fence, owner)
	response, _ := capacity.RecoveryFixtureCanaryResponse(t, f.p, pub, f.receipt.Enrollment, nil)
	returned := failedServingHTTP(t, response, response.OriginalReadStartedAt.Add(-time.Millisecond))
	if delay := time.Until(returned.DriverReturnedAt) + time.Millisecond; delay > 0 {
		time.Sleep(delay)
	}
	if _, err = store.RecordGuestNotifyCanaryReturn(ctx, f.policy, generation, fence, owner, pub, returned); err != nil {
		t.Fatal("M104 genuine accepted PUB", err)
	}
	read, err := store.IssueGuestNotifyCanaryRead(ctx, f.policy, generation, fence, owner, f.pre.PreregistrationID, "steady_useful_membership", pub.ChallengeID, failedServingKey('c'))
	if err != nil {
		t.Fatal("M104 genuine READ issue", err)
	}
	read = supersededHTTPFinalize(t, ctx, store, f, read, generation, fence, owner)
	// No READ-return API is called: preserve the authentic missing return.
	stop()
	originals := f.preserved(t)
	replacement := supersededHTTPHistoricalPublication(t, f.db, f.policy, f.p)
	r := supersededHTTPResult(t, job, generation, fence, *job.StartedAt, time.Now().UTC())
	err = FinishCapacityDispatch(context.Background(), f.db, job, r, time.Now().UTC(), errors.New("declared original refresh refused"))
	if !errors.Is(err, ErrCapacityDispatchUnknown) {
		t.Fatal("M104 real Source finish must retain UNKNOWN", err)
	}
	var unknown, failed, missingACK, pair bool
	if err = f.db.QueryRow(`SELECT j.state='unknown',w.status='failed' AND w.error='capacity dispatch original workflow returned error' AND j.return_error=w.error AND j.finalization_error IS NULL,j.finalization_ack_at IS NULL,
 (SELECT count(*)=2 FROM public.capacity_guest_notify_canary_challenges WHERE id IN($2,$3)) AND (SELECT count(*)=2 FROM public.capacity_guest_notify_canary_nonces WHERE challenge_id IN($2,$3)) AND (SELECT count(*)=2 FROM public.capacity_guest_notify_canary_sends WHERE challenge_id IN($2,$3)) AND (SELECT count(*)=1 AND bool_and(outcome='accepted' AND original_wire IS NOT NULL AND business_observation IS NOT NULL) FROM public.capacity_guest_notify_canary_returns WHERE challenge_id IN($2,$3)) AND NOT EXISTS(SELECT 1 FROM public.capacity_guest_notify_canary_returns WHERE challenge_id=$3)
	 FROM public.capacity_dispatch_jobs j JOIN public.workflow_runs w ON w.id=j.run_id WHERE j.id=$1`, job.JobID, pub.ChallengeID, read.ChallengeID).Scan(&unknown, &failed, &missingACK, &pair); err != nil || !unknown || !failed || !missingACK || !pair || !reflect.DeepEqual(originals, f.preserved(t)) {
		t.Fatal("M104 genuine originals retained", err, unknown, failed, missingACK, pair)
	}
	var liveRaw string
	if err = f.db.QueryRow(`SELECT jsonb_build_object('job',to_jsonb(j),'run',to_jsonb(w),'pair',(SELECT jsonb_agg(jsonb_build_object('challenge',to_jsonb(c),'nonce',to_jsonb(n),'send',to_jsonb(s),'return',to_jsonb(r)) ORDER BY c.phase DESC) FROM public.capacity_guest_notify_canary_challenges c JOIN public.capacity_guest_notify_canary_nonces n ON n.challenge_id=c.id JOIN public.capacity_guest_notify_canary_sends s ON s.challenge_id=c.id LEFT JOIN public.capacity_guest_notify_canary_returns r ON r.challenge_id=c.id WHERE c.id IN($2,$3)))::text FROM public.capacity_dispatch_jobs j JOIN public.workflow_runs w ON w.id=j.run_id WHERE j.id=$1`, job.JobID, pub.ChallengeID, read.ChallengeID).Scan(&liveRaw); err != nil {
		t.Fatal(err)
	}
	if remaining := time.Until(read.OriginalDeadline); remaining > 0 {
		if remaining > 5*time.Second {
			t.Fatal("original READ closure bound")
		}
		time.Sleep(remaining + time.Millisecond)
	}
	put("M104-CURRENT-SOURCE-PRODUCER-WITNESS.PUBLIC.json", map[string]any{"schema": "m104_current_source_producer_fixture_v1", "fixture_only": true, "workflow_result_fixture_declared": true, "full_workflow_execution_claimed": false, "whole_originals": json.RawMessage(liveRaw), "replacement_policy_id": replacement, "real_finish_unknown": true, "original_ACK_absent": true, "live_900_second_admission_claimed": false})
	// A different owned database receives its initial historical operands once.
	// The current witness above remains completely unchanged and unresolved.
	h := supersededHTTPHistoricalFixture(t, f, base)
	supersededHTTPHistoricalChecks(t, h, put)
}

func supersededHTTPFinalize(t *testing.T, ctx context.Context, store CapacityStore, f *failedServingFixture, c model.CapacityGuestNotifyCanaryChallenge, generation, fence int64, owner string) model.CapacityGuestNotifyCanaryChallenge {
	t.Helper()
	c = capacity.RecoveryFixtureCanaryNonce(t, c, f.receipt.Enrollment)
	if err := store.FinalizeGuestNotifyCanaryNonce(ctx, f.policy, generation, fence, owner, c, failedServingHTTP(t, c.GuestNonce, time.Now().UTC())); err != nil {
		t.Fatal("M104 real nonce", err)
	}
	if err := store.ReserveGuestNotifyCanarySend(ctx, f.policy, generation, fence, owner, c); err != nil {
		t.Fatal("M104 real possible send", err)
	}
	return c
}

func supersededHTTPStart(t *testing.T, f *failedServingFixture) CapacityDispatchJob {
	t.Helper()
	pin := func(m model.Manifest) CapacityDispatchManifestPin {
		return CapacityDispatchManifestPin{ID: m.ID, Namespace: m.Metadata.Namespace, Name: m.Metadata.Name, Version: m.Version, Checksum: m.Checksum}
	}
	rbac := CapacityDispatchManifestPin{ID: uuid.New(), Namespace: f.policy.Metadata.Namespace, Name: "failed-serving-unit-rbac", Version: 1, Checksum: capacityDispatchSHA([]byte("declared-M104-rbac"))}
	f.exec(t, `INSERT INTO public.manifests(id,api_version,kind,namespace,name,version,checksum,spec,active) VALUES($1,'v1','rbac',$2,$3,1,$4,'{}'::jsonb,true)`, rbac.ID, rbac.Namespace, rbac.Name, rbac.Checksum)
	e := CapacityDispatchEnvelope{Protocol: CapacityDispatchProtocol, JobID: uuid.New(), RunID: uuid.New(), Realm: f.policy.Metadata.Namespace, Environment: f.p.Environment, Domain: f.p.Domain, Dimension: f.p.Dimension, SourceTick: time.Now().UTC().Format(time.RFC3339Nano), Policy: pin(f.policy), Workflow: pin(f.workflow), RBAC: rbac, MachinePrincipalID: "capacity-controller", PrincipalSHA256: capacityDispatchSHA([]byte("declared-M104-principal")), BindingSHA256: capacityDispatchSHA([]byte("declared-M104-binding"))}
	e.Inputs = map[string]any{"policy": map[string]any{"namespace": f.policy.Metadata.Namespace, "name": f.policy.Metadata.Name}}
	e.Metadata = map[string]any{WorkflowRunCreatorMachinePrincipalMetadataKey: e.MachinePrincipalID, "triggered_by": "workflow_scheduler", "manifest_id": e.Workflow.ID.String(), "scheduled_for": e.SourceTick}
	e.InputsSHA256, e.MetadataSHA256, _ = CapacityDispatchEnvelopeHashes(e)
	tx, err := f.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	j, merged, err := EnqueueCapacityDispatch(context.Background(), tx, e)
	if err != nil || merged {
		t.Fatal("M104 new Source dispatch", err, merged)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	j, err = ClaimCapacityDispatch(context.Background(), f.db, e.Realm, e.Environment, uuid.New(), 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	j, err = StartCapacityDispatch(context.Background(), f.db, j)
	if err != nil {
		t.Fatal(err)
	}
	return j
}

// This is an explicit CI-only seed of the historical pre-publication-guard race.
// Never call this through a production route or claim current publication
// admission allowed it. Both versions are new; old policy is not reactivated.
func supersededHTTPHistoricalPublication(t *testing.T, db *sql.DB, old model.Manifest, p model.CapacityPolicySpec) uuid.UUID {
	t.Helper()
	if len(p.Signals) == 0 {
		t.Fatal("declared signals required")
	}
	p.Signals = append([]model.CapacitySignalRule(nil), p.Signals...)
	p.Signals[0].UpAbove = -1
	p.Signals[0].DownBelow = -2
	aSpec := failedServingWire(t, p)
	a, b := uuid.New(), uuid.New()
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err = tx.Exec(`UPDATE public.manifests SET active=false WHERE id=$1`, old.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(`INSERT INTO public.manifests(id,api_version,kind,namespace,name,version,checksum,spec,active) VALUES($1,'v1','capacity_policy',$2,$3,$4,$5,$6::jsonb,false),($7,'v1','capacity_policy',$2,$3,$8,$9,$10::jsonb,true)`, a, old.Metadata.Namespace, old.Metadata.Name, old.Version+1, capacity.BusinessCreationSHA256(aSpec), string(aSpec), b, old.Version+2, old.Checksum, string(old.Spec)); err != nil {
		t.Fatal("declared historical policy publication", err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	return b
}

func supersededHTTPResult(t *testing.T, job CapacityDispatchJob, generation, fence int64, started, finished time.Time) model.RunWorkflowResponse {
	t.Helper()
	ids := []string{"plan-original-guest", "provision-original-notify", "retire-original-guest", "refresh-original-membership", "complete-original-provision", "finish-original-retirement", "complete-original-retirement"}
	ops := []string{capacity.PlanOriginalGuestOperation, capacity.ProvisionOriginalGuestOperation, capacity.RetireOriginalGuestOperation, capacity.CompleteOriginalGuestOperation, capacity.CompleteOriginalGuestOperation, "capacity.finish_original_guest_retirement", capacity.CompleteOriginalGuestOperation}
	r := model.RunWorkflowResponse{Workflow: model.ManifestReference{ID: job.Workflow.ID, Kind: "workflow", Namespace: job.Workflow.Namespace, Name: job.Workflow.Name, Version: job.Workflow.Version}, Status: "failed", StartedAt: started, FinishedAt: finished}
	for i, id := range ids {
		s := model.WorkflowRunStepResult{ID: id, Kind: "yggdrasil", Operation: ops[i], Capability: ops[i], Status: "skipped", StartedAt: started, FinishedAt: finished}
		if i == 0 {
			s.Status = "succeeded"
			s.Attempts = 1
			s.Metadata = map[string]any{"mode": "refresh", "slot": 0, "reason": "down_window_pending", "generation": generation, "fencing_token": fence, "lease_owner": "", "preregistration_id": ""}
		}
		if i == 3 {
			s.Status = "failed"
			s.Attempts = 1
			s.Error = "original Guest reconciliation held"
			s.Metadata = map[string]any{"original_guest_reconcile_refusal_stage": "fresh_original_canary", "original_guest_notify_refusal_stage": "original_HTTP_or_return"}
		}
		r.Steps = append(r.Steps, s)
	}
	return r
}

var supersededHTTPBaseTables = []string{"manifests", "capacity_mutation_grants", "capacity_vm_provisioning_preregistrations", "capacity_guest_original_create_witnesses", "capacity_vm_original_enrollments", "capacity_guest_original_installations", "capacity_resource_slots", "capacity_intents", "capacity_intent_events"}

func supersededHTTPBaseRows(t *testing.T, db *sql.DB) map[string][]json.RawMessage {
	t.Helper()
	out := map[string][]json.RawMessage{}
	for _, table := range supersededHTTPBaseTables {
		var raw []byte
		if err := db.QueryRow(`SELECT COALESCE(jsonb_agg(to_jsonb(t)),'[]'::jsonb)::text FROM public.` + pq.QuoteIdentifier(table) + ` t`).Scan(&raw); err != nil {
			t.Fatal("declared base snapshot", table, err)
		}
		var rows []json.RawMessage
		if json.Unmarshal(raw, &rows) != nil {
			t.Fatal("base rows")
		}
		out[table] = rows
	}
	return out
}

type supersededHTTPHistorical struct {
	db        *sql.DB
	request   CapacityDispatchSupersededHTTPMaintenanceDispositionRequest
	barrier   CapacityDispatchExecutorBarrier
	canaryIDs []string
}

func supersededHTTPHistoricalFixture(t *testing.T, f *failedServingFixture, base map[string][]json.RawMessage) supersededHTTPHistorical {
	t.Helper()
	// Implementation below builds each historical row BEFORE its first INSERT;
	// neither current witness originals nor target sealed rows are rewritten.
	db := failedServingDB(t)
	if err := goose.UpToContext(context.Background(), db, filepath.Join(failedServingRepositoryRoot(t), "db/migrations"), 104); err != nil {
		t.Fatal(err)
	}
	return supersededHTTPSeedHistorical(t, db, f, base)
}

func supersededHTTPSeedHistorical(t *testing.T, db *sql.DB, f *failedServingFixture, base map[string][]json.RawMessage) supersededHTTPHistorical {
	t.Helper()
	ctx := context.Background()
	start := f.pre.ReservedAt.Add(45 * time.Minute).UTC().Truncate(time.Millisecond)
	lease := start.Add(5 * time.Minute)
	returned := start.Add(10 * time.Second)
	generation, fence := f.intent.Generation+1, f.intent.FencingToken+1
	old := f.policy
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	// Every following row is its FIRST target-database insertion. Existing
	// signed birth/enrollment/install bytes are copied exactly; only declared
	// initial observation bookkeeping is chosen for this historical fixture.
	if _, err = tx.Exec(`SET LOCAL session_replication_role=replica`); err != nil {
		t.Fatal(err)
	}
	for _, table := range supersededHTTPBaseTables {
		for _, raw := range base[table] {
			var row map[string]json.RawMessage
			if json.Unmarshal(raw, &row) != nil {
				t.Fatal("initial row")
			}
			if table == "capacity_intents" {
				i := f.intent
				i.Generation = generation
				i.FencingToken = fence
				i.Decision.Reason = "down_window_pending"
				i.Decision.ExecutionPermitted = false
				i.UpdatedAt = start.Add(time.Second)
				row["intent"] = failedServingWire(t, i)
				row["updated_at"] = failedServingWire(t, start.Add(time.Second))
			}
			if table == "capacity_intent_events" {
				row["generation"] = failedServingWire(t, generation)
				row["fencing_token"] = failedServingWire(t, fence)
			}
			if table == "capacity_resource_slots" {
				var slot map[string]any
				if json.Unmarshal(row["slot_record"], &slot) != nil {
					t.Fatal("initial slot")
				}
				slot["observed_at"] = start.Add(2 * time.Second)
				slot["receipt_ref"] = "original-guest-reconcile:declared-M104-historical"
				row["slot_record"] = failedServingWire(t, slot)
				row["updated_at"] = failedServingWire(t, start.Add(2*time.Second))
				row["revision"] = failedServingWire(t, int64(2))
			}
			wire := failedServingWire(t, row)
			if _, err = tx.Exec(`INSERT INTO public.`+pq.QuoteIdentifier(table)+` SELECT (jsonb_populate_record(NULL::public.`+pq.QuoteIdentifier(table)+`,$1::jsonb)).*`, string(wire)); err != nil {
				t.Fatal("initial historical base", table, err)
			}
		}
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	// Original job/run and result are declared historical storage operands,
	// never a backdated Source execution. The separate live witness above owns
	// the real FinishCapacityDispatch and PUB/READ producer assertions.
	e := abandonedDispatchEnvelope(t, old.Metadata.Namespace, start.Format(time.RFC3339Nano))
	e.Environment = f.p.Environment
	e.Domain = f.p.Domain
	e.Dimension = f.p.Dimension
	e.Policy = installedTimeoutPin(old)
	e.Workflow = installedTimeoutPin(f.workflow)
	e.RBAC.Namespace = old.Metadata.Namespace
	e.RBAC.Name = "failed-serving-unit-rbac"
	e.Inputs = map[string]any{"policy": map[string]any{"namespace": old.Metadata.Namespace, "name": old.Metadata.Name}}
	e.Metadata["manifest_id"] = e.Workflow.ID.String()
	e.InputsSHA256, e.MetadataSHA256, err = CapacityDispatchEnvelopeHashes(e)
	if err != nil {
		t.Fatal(err)
	}
	owner := uuid.New()
	wire, err := encodeCapacityDispatchEnvelope(e)
	if err != nil {
		t.Fatal(err)
	}
	job := CapacityDispatchJob{CapacityDispatchEnvelope: e, State: "unknown", LeaseOwner: owner, FencingToken: 1, StartedAt: &start, LeaseExpiresAt: &lease, ReturnedAt: &returned, PendingWakeCount: 1}
	result := supersededHTTPResult(t, job, generation, fence, start, returned)
	tx, err = db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err = tx.Exec(`SET LOCAL session_replication_role=replica`); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(`INSERT INTO public.manifests(id,api_version,kind,namespace,name,version,checksum,spec,active) VALUES($1,'v1','rbac',$2,$3,$4,$5,'{}'::jsonb,true)`, e.RBAC.ID, e.RBAC.Namespace, e.RBAC.Name, e.RBAC.Version, e.RBAC.Checksum); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(`INSERT INTO public.workflow_runs(id,workflow_namespace,workflow_name,workflow_version,status,inputs,metadata,result,error,started_at,finished_at,created_at,updated_at) VALUES($1,$2,$3,$4,'failed',$5::jsonb,$6::jsonb,$7::jsonb,$8,$9,$10,$9,$10)`, e.RunID, e.Workflow.Namespace, e.Workflow.Name, e.Workflow.Version, mustEncodeJSON(e.Inputs, "{}"), mustEncodeJSON(e.Metadata, "{}"), string(failedServingWire(t, result)), capacityDispatchSupersededHTTPMaintenanceError, start, returned); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(`INSERT INTO public.capacity_dispatch_jobs(id,run_id,protocol,realm,environment,domain,dimension,source_tick,envelope,envelope_sha256,state,lease_owner,fencing_token,lease_expires_at,started_at,returned_at,return_status,return_error,pending_wake_count,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'unknown',$11,1,$12,$13,$14,'failed',$15,1,$13,$14)`, e.JobID, e.RunID, e.Protocol, e.Realm, e.Environment, e.Domain, e.Dimension, e.SourceTick, string(wire), capacityDispatchSHA(wire), owner, lease, start, returned, capacityDispatchSupersededHTTPMaintenanceError); err != nil {
		t.Fatal(err)
	}
	read, publication, pubBody, pubTransport := capacity.RecoveryFixtureCausal(t, f.p, f.reg, f.receipt, uint64(fence), GuestNotifyMaintenanceOwner(f.store.ExecutorID), start.Add(3*time.Second))
	// Existing pure Source operands use fixed private-fixture IDs. They have
	// no Native authority and are unique within this newly owned database.
	// Retarget only the declared later maintenance epoch/usage BEFORE signing
	// or inserting; original signed birth/registration remains byte exact.
	for _, c := range []*model.CapacityGuestNotifyCanaryChallenge{&publication, &read} {
		c.Generation = uint64(generation)
		c.UsageClass = "steady_useful_membership"
		c.GuestNonce.PreflightSHA256 = capacity.GuestNotifyPreflightSHA(*c)
		c.GuestNonce.Signature = ""
		c.GuestNonce.Signature, _ = capacity.GuestLifecycleSignature(failedServingKey('o'), c.GuestNonce)
		c.Signature = ""
		c.Signature, _ = capacity.GuestLifecycleSignature(failedServingKey('c'), *c)
		if err = capacity.ValidateGuestNotifyCanaryChallenge(*c, f.receipt.Enrollment, c.IssuedAt.Add(time.Millisecond)); err != nil {
			t.Fatal("declared historical Source challenge coherence", err)
		}
	}
	if !capacity.GuestNotifyCausalPair(publication, read) {
		t.Fatal("declared historical Source pair coherence")
	}
	var frame capacity.GuestNotifyOriginalFrame
	if json.Unmarshal(pubBody.NotifyOriginalReturn, &frame) != nil {
		t.Fatal("actual pure Source frame")
	}
	frame.RequestSHA256 = capacity.GuestRetirementSHA(publication)
	pubBody.ChallengeSHA256 = frame.RequestSHA256
	pubBody.NotifyOriginalReturn = append(failedServingWire(t, frame), '\n')
	pubBody.NotifyOriginalReturnSHA256 = capacity.BusinessCreationSHA256(pubBody.NotifyOriginalReturn)
	pubBody.Signature = ""
	pubBody.Signature, _ = capacity.GuestLifecycleSignature(failedServingKey('o'), pubBody)
	pubTransport.Body = failedServingWire(t, pubBody)
	pubTransport.ResponseSHA256 = capacity.BusinessCreationSHA256(pubTransport.Body)
	pubTransport.ReceivedBodyBytes = len(pubTransport.Body)
	pubTransport.RetainedPrefixBytes = len(pubTransport.Body)
	pubTransport.RetainedPrefixSHA256 = pubTransport.ResponseSHA256
	if err = capacity.ValidateGuestNotifyCanaryEnvelope(publication, f.receipt.Enrollment, pubBody, pubTransport.DriverReturnedAt); err != nil {
		t.Fatal("declared historical full Source PUB envelope", err)
	}
	pubFact, factErr := capacity.GuestNotifyPublicationFacts(f.p, publication, f.receipt.Enrollment, pubBody)
	if factErr != nil {
		t.Fatal("declared historical full Source PUB facts", factErr)
	}
	for _, final := range []model.CapacityGuestNotifyCanaryChallenge{publication, read} {
		preflight := final
		preflight.GuestNonce = model.CapacityGuestNotifyCanaryNonce{}
		preflight.Signature = ""
		preflight.Signature, _ = capacity.GuestLifecycleSignature(failedServingKey('c'), preflight)
		phase := "publish"
		if preflight.ChallengeID == read.ChallengeID {
			phase = "read"
		}
		// Construct the original and finalized nonce independently before either
		// first INSERT; no sealed challenge is altered to obtain admission.
		nonce := final.GuestNonce
		original := failedServingWire(t, preflight)
		finalWire := failedServingWire(t, final)
		nonceWire := failedServingWire(t, nonce)
		if _, err = tx.Exec(`INSERT INTO public.capacity_guest_notify_canary_challenges(id,preregistration_id,record_challenge_id,phase,policy_id,workflow_id,generation,fence,executor_id,lease_owner,challenge_sha256,nonce_sha256,original_wire,original_record,original_deadline,recorded_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14::jsonb,$15,$16)`, preflight.ChallengeID, f.pre.PreregistrationID, preflight.RecordChallengeID, phase, old.ID, f.workflow.ID, generation, fence, f.store.ExecutorID, preflight.LeaseOwner, capacity.BusinessCreationSHA256(original), preflight.NonceSHA256, original, string(original), preflight.OriginalDeadline, preflight.IssuedAt); err != nil {
			t.Fatal(err)
		}
		nonceReturn := failedServingHTTP(t, nonce, preflight.IssuedAt.Add(time.Millisecond))
		nonceReturn.DoReturnedAt = preflight.IssuedAt.Add(2 * time.Millisecond)
		nonceReturn.ReadReturnedAt = preflight.IssuedAt.Add(3 * time.Millisecond)
		nonceReturn.CloseReturnedAt = preflight.IssuedAt.Add(4 * time.Millisecond)
		nonceReturn.DriverReturnedAt = preflight.IssuedAt.Add(5 * time.Millisecond)
		nonceReturn.Body = nil
		if _, err = tx.Exec(`INSERT INTO public.capacity_guest_notify_canary_nonces VALUES($1,$2,$3,$4,$5,$6::jsonb,$7)`, preflight.ChallengeID, nonce.NonceSHA256, nonceWire, finalWire, capacity.BusinessCreationSHA256(finalWire), string(failedServingWire(t, nonceReturn)), preflight.IssuedAt.Add(6*time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		requestWire := failedServingWire(t, model.CapacityGuestNotifyCanaryRequest{Challenge: final})
		if _, err = tx.Exec(`INSERT INTO public.capacity_guest_notify_canary_sends VALUES($1,$2,$3,$4,$3)`, preflight.ChallengeID, capacity.BusinessCreationSHA256(requestWire), preflight.IssuedAt.Add(10*time.Millisecond), preflight.OriginalDeadline); err != nil {
			t.Fatal(err)
		}
		issue := map[string]any{"schema": "guest_authority_issue_v1", "issue_kind": "canary_challenge", "issue_id": preflight.ChallengeID, "issuer_actual_source_commit": capacity.CurrentGuestCoreSource(), "protocol_authority_source_commit": f.p.GuestRetirementBinding.CoreAuthoritySourceCommit, "compatibility_map_sha256": capacity.GuestProtocolCompatibilityMapSHA256(), "profile": f.p.GuestRetirementBinding.ProfileManifest.Profile, "policy_id": old.ID, "workflow_id": f.workflow.ID, "executor_id": f.store.ExecutorID, "issued_wire_sha256": capacity.BusinessCreationSHA256(original)}
		issueWire := failedServingWire(t, issue)
		if _, err = tx.Exec(`INSERT INTO public.capacity_guest_authority_issues(issue_kind,issue_id,issuer_actual_source_commit,protocol_authority_source_commit,compatibility_map_sha256,profile,policy_id,workflow_id,executor_id,issued_wire_sha256,original_wire,original_record,recorded_at) VALUES('canary_challenge',$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb,$12)`, preflight.ChallengeID, capacity.CurrentGuestCoreSource(), f.p.GuestRetirementBinding.CoreAuthoritySourceCommit, capacity.GuestProtocolCompatibilityMapSHA256(), f.p.GuestRetirementBinding.ProfileManifest.Profile, old.ID, f.workflow.ID, f.store.ExecutorID, capacity.BusinessCreationSHA256(original), issueWire, string(issueWire), preflight.IssuedAt); err != nil {
			t.Fatal(err)
		}
		if phase == "publish" {
			ret := pubTransport
			bodyWire := append([]byte(nil), ret.Body...)
			ret.Body = nil
			diagnostic := struct {
				capacity.GuestOriginalHTTPReturn
				Stage string `json:"CanaryReturnValidationStage"`
			}{ret, "accepted"}
			if _, err = tx.Exec(`INSERT INTO public.capacity_guest_notify_canary_returns(challenge_id,outcome,return_sha256,original_wire,original_transport,business_observation,recorded_at) VALUES($1,'accepted',$2,$3,$4::jsonb,$5::jsonb,$6)`, publication.ChallengeID, capacity.BusinessCreationSHA256(bodyWire), bodyWire, string(failedServingWire(t, diagnostic)), string(failedServingWire(t, pubFact)), publication.IssuedAt.Add(450*time.Millisecond)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	replacement := supersededHTTPHistoricalPublication(t, db, old, f.p)
	h := supersededHTTPHistorical{db: db, request: CapacityDispatchSupersededHTTPMaintenanceDispositionRequest{CapacityDispatchUnknownMaintenanceDispositionRequest: CapacityDispatchUnknownMaintenanceDispositionRequest{CapacityDispatchAbandonedDispositionRequest: CapacityDispatchAbandonedDispositionRequest{JobID: e.JobID, ExpectedRunID: e.RunID, ExpectedEnvelopeSHA256: capacityDispatchSHA(wire), ExpectedFencingToken: 1, ExpectedLeaseOwner: owner, ExpectedPendingWakeCount: 1, Issuer: "collaborator:" + uuid.NewString()}, ExpectedReturnedAt: returned}, ExpectedReplacementPolicyID: replacement, ExpectedReplacementPolicyVersion: old.Version + 2, ExpectedReplacementPolicyChecksum: old.Checksum}, barrier: CapacityDispatchExecutorBarrier{ProcessStartedAt: lease.Add(time.Minute), Hostname: "declared-historical-M104-fixture", PID: 4242, SourceCommit: capacity.CurrentGuestCoreSource()}, canaryIDs: []string{publication.ChallengeID, read.ChallengeID}}
	if err = db.QueryRowContext(ctx, `SELECT encode(sha256(convert_to(to_jsonb(w)::text,'UTF8')),'hex'),public.superseded_http_maintenance_dispatch_effect_scan($1)->>'current_members_sha256' FROM public.workflow_runs w WHERE w.id=$2`, e.JobID, e.RunID).Scan(&h.request.ExpectedRunSHA256, &h.request.ExpectedMembersSHA256); err != nil {
		t.Fatal(err)
	}
	return h
}

func supersededHTTPHistoricalChecks(t *testing.T, h supersededHTTPHistorical, put func(string, any)) {
	t.Helper()
	ctx := context.Background()
	snapshot := func() string {
		t.Helper()
		var raw string
		if err := h.db.QueryRow(`SELECT jsonb_build_object('job',to_jsonb(j),'run',to_jsonb(w),'canaries',(SELECT jsonb_agg(jsonb_build_object('challenge',to_jsonb(c),'nonce',to_jsonb(n),'send',to_jsonb(s),'return',to_jsonb(r)) ORDER BY c.id) FROM public.capacity_guest_notify_canary_challenges c LEFT JOIN public.capacity_guest_notify_canary_nonces n ON n.challenge_id=c.id LEFT JOIN public.capacity_guest_notify_canary_sends s ON s.challenge_id=c.id LEFT JOIN public.capacity_guest_notify_canary_returns r ON r.challenge_id=c.id WHERE c.id IN($2,$3)))::text FROM public.capacity_dispatch_jobs j JOIN public.workflow_runs w ON w.id=j.run_id WHERE j.id=$1`, h.request.JobID, h.canaryIDs[0], h.canaryIDs[1]).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		return raw
	}
	before := snapshot()
	var raw string
	var admissible, old91 bool
	if err := h.db.QueryRow(`SELECT public.superseded_http_maintenance_dispatch_effect_scan($1)::text,public.superseded_http_maintenance_dispatch_admissible($1,$2,clock_timestamp()),public.http_maintenance_dispatch_admission_valid($1)`, h.request.JobID, h.barrier.ProcessStartedAt).Scan(&raw, &admissible, &old91); err != nil || !admissible || old91 {
		t.Fatal("independent historical positive before negatives, old91 must refuse", err, admissible, old91, raw)
	}
	scan, err := decodeSupersededHTTPMaintenanceScan([]byte(raw))
	if err != nil {
		t.Fatal("Go exact historical scan", err, raw)
	}
	put("M104-DECLARED-HISTORICAL-ADMISSION-SCAN.PUBLIC.json", json.RawMessage(raw))
	casCases := []struct {
		name   string
		change func(*CapacityDispatchSupersededHTTPMaintenanceDispositionRequest)
	}{
		{"run", func(r *CapacityDispatchSupersededHTTPMaintenanceDispositionRequest) { r.ExpectedRunID = uuid.New() }},
		{"envelope", func(r *CapacityDispatchSupersededHTTPMaintenanceDispositionRequest) {
			r.ExpectedEnvelopeSHA256 = strings.Repeat("f", 64)
		}},
		{"fence", func(r *CapacityDispatchSupersededHTTPMaintenanceDispositionRequest) { r.ExpectedFencingToken++ }},
		{"owner", func(r *CapacityDispatchSupersededHTTPMaintenanceDispositionRequest) {
			r.ExpectedLeaseOwner = uuid.New()
		}},
		{"wake", func(r *CapacityDispatchSupersededHTTPMaintenanceDispositionRequest) { r.ExpectedPendingWakeCount++ }},
		{"return", func(r *CapacityDispatchSupersededHTTPMaintenanceDispositionRequest) {
			r.ExpectedReturnedAt = r.ExpectedReturnedAt.Add(time.Microsecond)
		}},
		{"run_wire", func(r *CapacityDispatchSupersededHTTPMaintenanceDispositionRequest) {
			r.ExpectedRunSHA256 = strings.Repeat("a", 64)
		}},
		{"members", func(r *CapacityDispatchSupersededHTTPMaintenanceDispositionRequest) {
			r.ExpectedMembersSHA256 = strings.Repeat("b", 64)
		}},
		{"replacement_id", func(r *CapacityDispatchSupersededHTTPMaintenanceDispositionRequest) {
			r.ExpectedReplacementPolicyID = uuid.New()
		}},
		{"replacement_version", func(r *CapacityDispatchSupersededHTTPMaintenanceDispositionRequest) {
			r.ExpectedReplacementPolicyVersion++
		}},
		{"replacement_checksum", func(r *CapacityDispatchSupersededHTTPMaintenanceDispositionRequest) {
			first := byte('0')
			if r.ExpectedReplacementPolicyChecksum[0] == first {
				first = '1'
			}
			r.ExpectedReplacementPolicyChecksum = string(first) + r.ExpectedReplacementPolicyChecksum[1:]
		}},
		{"caller", func(r *CapacityDispatchSupersededHTTPMaintenanceDispositionRequest) { r.Issuer = "machine:fixture" }},
	}
	for _, test := range casCases {
		r := h.request
		test.change(&r)
		if reflect.DeepEqual(r, h.request) {
			t.Fatal("M104 negative CAS operand must differ from actual baseline", test.name)
		}
		if _, e := DisposeSupersededHTTPMaintenanceDispatch(ctx, h.db, r, h.barrier, abandonedAllow); e == nil {
			t.Fatal("M104 stale/caller CAS accepted", test.name)
		}
		if snapshot() != before {
			t.Fatal("M104 CAS refusal changed originals", test.name)
		}
	}
	for _, barrier := range []CapacityDispatchExecutorBarrier{{ProcessStartedAt: time.Time{}, Hostname: "declared", PID: 1, SourceCommit: h.barrier.SourceCommit}, {ProcessStartedAt: h.request.ExpectedReturnedAt, Hostname: "declared", PID: 1, SourceCommit: h.barrier.SourceCommit}, {ProcessStartedAt: time.Now().Add(time.Hour), Hostname: "declared", PID: 1, SourceCommit: h.barrier.SourceCommit}} {
		if _, e := DisposeSupersededHTTPMaintenanceDispatch(ctx, h.db, h.request, barrier, abandonedAllow); e == nil {
			t.Fatal("M104 missing/old/future process barrier accepted")
		}
	}
	var lease time.Time
	if err = h.db.QueryRow(`SELECT lease_expires_at FROM public.capacity_dispatch_jobs WHERE id=$1`, h.request.JobID).Scan(&lease); err != nil {
		t.Fatal(err)
	}
	for _, at := range []time.Time{lease.Add(899 * time.Second), lease.Add(900 * time.Second)} {
		var ok bool
		if err = h.db.QueryRow(`SELECT public.superseded_http_maintenance_dispatch_admissible($1,$2,$3)`, h.request.JobID, h.barrier.ProcessStartedAt, at).Scan(&ok); err != nil || ok != !at.Before(lease.Add(900*time.Second)) {
			t.Fatal("M104 exact unchanged900 boundary", err, ok, at)
		}
	}
	// Append-only storage faults live only inside rolled-back transactions.
	// The actual production decoder and SQL admission see the SAME new rows.
	faults := []struct {
		name, query string
		args        []any
	}{
		{"late_read_return", `INSERT INTO public.capacity_guest_notify_canary_returns(challenge_id,outcome,return_sha256,original_wire,original_transport,recorded_at) VALUES($1,'held',$2,NULL,'{}'::jsonb,clock_timestamp())`, []any{h.canaryIDs[1], strings.Repeat("d", 64)}},
		{"provider_authority", `INSERT INTO public.capacity_mutation_grants(id,namespace,environment,domain,dimension,generation,integration_instance_id,scope_checksum,profile_name,slot,state,grant_record,expires_at,updated_at) SELECT $1,namespace,environment,domain,dimension,generation,integration_instance_id,scope_checksum,profile_name,2,'issued',grant_record,clock_timestamp()+interval '1 minute',clock_timestamp() FROM public.capacity_mutation_grants LIMIT 1`, []any{uuid.New()}},
		{"extra_member", `INSERT INTO public.capacity_resource_slots(integration_instance_id,scope_checksum,profile_name,slot,namespace,environment,domain,dimension,resource_id,slot_record,revision,updated_at) SELECT integration_instance_id,scope_checksum,profile_name,2,namespace,environment,domain,dimension,'declared-other-resource',slot_record,revision,clock_timestamp() FROM public.capacity_resource_slots LIMIT 1`, nil},
		{"latest_paused", `INSERT INTO public.manifests(id,api_version,kind,namespace,name,version,checksum,spec,active) SELECT $1,api_version,kind,namespace,name,version+1,checksum,spec,false FROM public.manifests WHERE id=$2`, []any{uuid.New(), h.request.ExpectedReplacementPolicyID}},
	}
	for _, fault := range faults {
		tx, e := h.db.Begin()
		if e != nil {
			t.Fatal(e)
		}
		_, e = tx.Exec(fault.query, fault.args...)
		if e != nil {
			tx.Rollback()
			t.Fatal("M104 append-only negative must reach scan", fault.name, e)
		}
		var value string
		var sqlOK bool
		e = tx.QueryRow(`SELECT public.superseded_http_maintenance_dispatch_effect_scan($1)::text,public.superseded_http_maintenance_dispatch_admissible($1,$2,clock_timestamp())`, h.request.JobID, h.barrier.ProcessStartedAt).Scan(&value, &sqlOK)
		_, goErr := decodeSupersededHTTPMaintenanceScan([]byte(value))
		tx.Rollback()
		if e != nil || sqlOK || goErr == nil {
			t.Fatal("M104 actual append-only negative parity", fault.name, e, sqlOK, goErr, value)
		}
		if snapshot() != before {
			t.Fatal("M104 rollback changed originals", fault.name)
		}
	}
	// Every new result/equivalence/epoch/pair and inherited counter is checked
	// independently by Go and the pure immutable-scan SQL predicate.
	var tree map[string]json.RawMessage
	if json.Unmarshal([]byte(raw), &tree) != nil {
		t.Fatal("scan proof")
	}
	for _, name := range []string{"equivalent_policy_valid", "other_catalog_pins_valid", "stable_epoch_valid", "readonly_result_valid", "invalid_canary_pair_rows"} {
		var changed map[string]json.RawMessage
		_ = json.Unmarshal([]byte(raw), &changed)
		changed[name] = json.RawMessage("false")
		if name == "invalid_canary_pair_rows" {
			changed[name] = json.RawMessage("1")
		}
		wire := failedServingWire(t, changed)
		var sqlOK bool
		if err = h.db.QueryRow(`SELECT public.superseded_http_maintenance_dispatch_effect_scan_tolerable($1::jsonb)`, string(wire)).Scan(&sqlOK); err != nil {
			t.Fatal(err)
		}
		if _, e := decodeSupersededHTTPMaintenanceScan(wire); e == nil || sqlOK {
			t.Fatal("M104 pure proof negative mismatch", name, e, sqlOK)
		}
	}
	var wg sync.WaitGroup
	out := make(chan error, 2)
	wg.Add(2)
	for i := 0; i < 2; i++ {
		go func() {
			defer wg.Done()
			_, e := DisposeSupersededHTTPMaintenanceDispatch(ctx, h.db, h.request, h.barrier, abandonedAllow)
			out <- e
		}()
	}
	wg.Wait()
	close(out)
	winners := 0
	for e := range out {
		if e == nil {
			winners++
		}
	}
	if winners != 1 {
		t.Fatal("M104 actual scope-lock single winner", winners)
	}
	d, err := GetSupersededHTTPMaintenanceDispatchDisposition(ctx, h.db, h.request.JobID)
	if err != nil || d.State != CapacityDispatchSupersededHTTPMaintenanceState || d.OriginalRunSHA256 != h.request.ExpectedRunSHA256 || d.ReplacementPolicyID != h.request.ExpectedReplacementPolicyID {
		t.Fatal("M104 historical receipt", err, d)
	}
	for _, field := range []string{"original_policy_version", "replacement_policy_checksum", "original_run_sha256", "original_dispatch_updated_at", "canary_evidence_wire"} {
		var ok bool
		query := `SELECT public.superseded_http_maintenance_dispatch_receipt_valid(jsonb_populate_record(NULL::public.capacity_dispatch_superseded_http_maintenance_dispositions,to_jsonb(d)||jsonb_build_object($2::text,CASE $2::text WHEN 'original_policy_version' THEN to_jsonb(d.original_policy_version+1) WHEN 'replacement_policy_checksum' THEN to_jsonb(repeat('a',64)) WHEN 'original_run_sha256' THEN to_jsonb(repeat('b',64)) WHEN 'original_dispatch_updated_at' THEN to_jsonb(d.original_dispatch_updated_at+interval '1 microsecond') ELSE to_jsonb(convert_to('{}','UTF8')) END))) FROM public.capacity_dispatch_superseded_http_maintenance_dispositions d WHERE d.job_id=$1`
		if err = h.db.QueryRow(query, h.request.JobID, field).Scan(&ok); err != nil || ok {
			t.Fatal("M104 pure archived field binding", field, err, ok)
		}
	}
	var after string
	if err = h.db.QueryRow(`SELECT jsonb_build_object('job',to_jsonb(j)||jsonb_build_object('state','unknown','updated_at',d.original_dispatch_updated_at),'run',to_jsonb(w),'canaries',(SELECT jsonb_agg(jsonb_build_object('challenge',to_jsonb(c),'nonce',to_jsonb(n),'send',to_jsonb(s),'return',to_jsonb(r)) ORDER BY c.id) FROM public.capacity_guest_notify_canary_challenges c LEFT JOIN public.capacity_guest_notify_canary_nonces n ON n.challenge_id=c.id LEFT JOIN public.capacity_guest_notify_canary_sends s ON s.challenge_id=c.id LEFT JOIN public.capacity_guest_notify_canary_returns r ON r.challenge_id=c.id WHERE c.id IN($2,$3)))::text FROM public.capacity_dispatch_jobs j JOIN public.workflow_runs w ON w.id=j.run_id JOIN public.capacity_dispatch_superseded_http_maintenance_dispositions d ON d.job_id=j.id WHERE j.id=$1`, h.request.JobID, h.canaryIDs[0], h.canaryIDs[1]).Scan(&after); err != nil || after != before {
		t.Fatal("M104 receipt changed original bodies/ACK", err)
	}
	for _, query := range []string{`UPDATE public.capacity_dispatch_jobs SET state='unknown' WHERE id=$1`, `UPDATE public.capacity_dispatch_jobs SET finalization_ack_at=clock_timestamp() WHERE id=$1`, `UPDATE public.capacity_dispatch_jobs SET updated_at=updated_at+interval '1 microsecond' WHERE id=$1`, `UPDATE public.workflow_runs SET error='changed original' WHERE id=(SELECT run_id FROM public.capacity_dispatch_jobs WHERE id=$1)`, `UPDATE public.capacity_dispatch_superseded_http_maintenance_dispositions SET reason='different' WHERE job_id=$1`, `DELETE FROM public.capacity_dispatch_superseded_http_maintenance_dispositions WHERE job_id=$1`} {
		_, e := h.db.Exec(query, h.request.JobID)
		var pg *pq.Error
		if !errors.As(e, &pg) || pg.Code != "P0001" {
			t.Fatal("M104 immutable archive/original guard", e)
		}
	}
	_, err = h.db.Exec(`INSERT INTO public.capacity_guest_notify_canary_returns(challenge_id,outcome,return_sha256,original_wire,original_transport,recorded_at) VALUES($1,'held',$2,NULL,'{}'::jsonb,clock_timestamp())`, h.canaryIDs[1], strings.Repeat("e", 64))
	var late *pq.Error
	if !errors.As(err, &late) || late.Code != "P0001" {
		t.Fatal("M104 missing READ must stay permanently missing after receipt", err)
	}
	// Execute only the verbatim first Down refusal inside a rolled-back CI
	// transaction. Never apply a downgrade or erase retained provenance.
	migration, readErr := os.ReadFile(filepath.Join(failedServingRepositoryRoot(t), "db/migrations/00104_superseded_http_maintenance_dispatch_dispositions.sql"))
	if readErr != nil {
		t.Fatal(readErr)
	}
	down := strings.SplitN(string(migration), "-- +goose Down", 2)
	if len(down) != 2 {
		t.Fatal("actual Down source")
	}
	block := strings.SplitN(down[1], "-- +goose StatementBegin", 2)
	if len(block) != 2 {
		t.Fatal("actual Down first block")
	}
	exact := strings.SplitN(block[1], "-- +goose StatementEnd", 2)
	if len(exact) != 2 {
		t.Fatal("actual Down block end")
	}
	downTx, err := h.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	_, err = downTx.Exec(exact[0])
	downTx.Rollback()
	var downError *pq.Error
	if !errors.As(err, &downError) || downError.Code != "P0001" {
		t.Fatal("M104 used Down must refuse exact Source", err)
	}
	put("M104-ACTUAL-DOWN-REFUSAL.PUBLIC.json", map[string]any{"sqlstate": string(downError.Code), "message": downError.Message, "verbatim_between_markers_sha256": capacity.BusinessCreationSHA256([]byte(exact[0])), "rollback_only": true})
	// A later normal version deactivates B, but cannot invalidate the retained
	// historical receipt or make it depend on current membership/active state.
	tx, err := h.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	var policy model.Manifest
	var spec []byte
	if err = tx.QueryRow(`SELECT id,namespace,name,version,checksum,spec FROM public.manifests WHERE id=$1`, h.request.ExpectedReplacementPolicyID).Scan(&policy.ID, &policy.Metadata.Namespace, &policy.Metadata.Name, &policy.Version, &policy.Checksum, &spec); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	active := true
	_, err = CreateManifestVersionTx(ctx, tx, model.ManifestDocument{APIVersion: "v1", Kind: "capacity_policy", Metadata: model.ManifestMetadataInput{Namespace: policy.Metadata.Namespace, Name: policy.Metadata.Name, Active: &active}, Spec: spec}, policy.Checksum)
	if err != nil {
		tx.Rollback()
		t.Fatal("M104 later normal publication", err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, err = GetSupersededHTTPMaintenanceDispatchDisposition(ctx, h.db, h.request.JobID); err != nil {
		t.Fatal("M104 historical receipt followed latest policy", err)
	}
	var terminalOK bool
	if err = h.db.QueryRow(`SELECT public.superseded_http_maintenance_dispatch_terminal_valid($1)`, h.request.JobID).Scan(&terminalOK); err != nil || !terminalOK {
		t.Fatal("M104 typed SQL terminal after later policy", err, terminalOK)
	}
	readTx, err := h.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = readTx.Exec(`SET LOCAL TIME ZONE 'America/Sao_Paulo'`); err != nil {
		readTx.Rollback()
		t.Fatal(err)
	}
	err = retirementContinuationTerminalReceiptTx(ctx, readTx, h.request.JobID, CapacityDispatchSupersededHTTPMaintenanceState, d.RecordedAt)
	readTx.Rollback()
	if err != nil {
		t.Fatal("M104 typed Go terminal after later policy", err)
	}
	put("M104-DECLARED-HISTORICAL-OPERATOR-WITNESS.PUBLIC.json", map[string]any{"schema": "m104_declared_historical_operator_fixture_v1", "fixture_only": true, "current_live_900_second_itinerary_claimed": false, "separate_initial_historical_database": true, "closed_cas_refusals": len(casCases), "append_only_rollback_negatives": len(faults), "original_job_run_canaries_preserved": true, "same_request_race_winners": winners, "old91_still_refuses": true, "later_active_policy_changed_historical_read_still_valid": true, "record": d, "admission_scan": scan})
}
