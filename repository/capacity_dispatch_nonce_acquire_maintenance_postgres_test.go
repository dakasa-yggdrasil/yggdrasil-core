//go:build recoveryfixture && !nativequalification

package repository

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
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

// The current producer and the mature historical admission use different owned
// databases. No sealed row is aged, no original ACK is invented, and neither
// witness claims a live 900-second itinerary or a real Guest/provider call.
func nonceAcquireMaintenance105PostgresRegression(t *testing.T) {
	t.Helper()
	f := newFailedServingFixtureHistory(t, "hetzner", true)
	dir := os.Getenv("PREACTION_PLAN_LOGS")
	if !filepath.IsAbs(dir) {
		t.Fatal("owned M105 evidence directory required")
	}
	put := func(name string, raw []byte) {
		t.Helper()
		if len(raw) == 0 || len(raw) > 16<<20 || filepath.Base(name) != name {
			t.Fatal("bounded whole M105 artifact required", name)
		}
		file, err := os.OpenFile(filepath.Join(dir, name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal(err)
		}
		n, writeErr := file.Write(append(raw, '\n'))
		closeErr := file.Close()
		if writeErr != nil || closeErr != nil || n != len(raw)+1 {
			t.Fatal("whole M105 artifact", name, n, writeErr, closeErr)
		}
	}
	migrations := filepath.Join(failedServingRepositoryRoot(t), "db/migrations")
	if err := goose.UpToContext(context.Background(), f.db, migrations, 104); err != nil {
		t.Fatal(err)
	}
	before := installedReadinessCatalog(t, f.db)
	if err := goose.UpToContext(context.Background(), f.db, migrations, 105); err != nil {
		t.Fatal("M105 actual companion Up", err)
	}
	after := installedReadinessCatalog(t, f.db)
	put("M105-WHOLE-CATALOG-BEFORE104.PUBLIC.json", before)
	put("M105-WHOLE-CATALOG-AFTER105.PUBLIC.json", after)
	nonceAcquire105Catalog(t, f.db, migrations, before, after, put)
	base := supersededHTTPBaseRows(t, f.db)
	job := supersededHTTPStart(t, f)
	step := f.step(t, "refresh-original-membership")
	store := f.store.WithOriginalGuestReconcile(f.workflow, step, capacity.CurrentGuestCoreSource(), "refresh", "", f.inventory(t, false), model.CapacityMetricRangeObservation{}).WithOriginalGuestNotifyCanary(step, capacity.CurrentGuestCoreSource())
	store.OriginalRunID = job.RunID
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	generation, fence, owner, err := store.GuestNotifyMaintenanceEpoch(ctx, f.policy, f.pre.PreregistrationID)
	if err != nil {
		t.Fatal("M105 actual maintenance epoch", err)
	}
	publication, err := store.IssueGuestNotifyCanaryPublication(ctx, f.policy, generation, fence, owner, f.pre.PreregistrationID, "steady_useful_membership", failedServingKey('c'))
	if err != nil || publication.GuestNonce != (model.CapacityGuestNotifyCanaryNonce{}) {
		t.Fatal("M105 actual prepared PUB", err)
	}
	// Prepare only a local signed refusal operand while the publication is valid.
	// It is never persisted and is used after the unchanged natural expiry.
	late := capacity.RecoveryFixtureCanaryNonce(t, publication, f.receipt.Enrollment)
	originals := f.preserved(t)
	// Expire this original context naturally. Acquire's real early deadline
	// refusal precedes any transport access; no network client is constructed.
	<-ctx.Done()
	final, returned, acquireErr := capacity.AcquireGuestNotifyCanaryNonce(ctx, nil, failedServingKey('c'), publication, f.receipt.Enrollment)
	if !errors.Is(ctx.Err(), context.DeadlineExceeded) || acquireErr == nil || returned.Status != 0 || !reflect.DeepEqual(final, publication) {
		t.Fatal("M105 real expired nonce acquisition must preserve preflight", acquireErr, returned)
	}
	refusalCtx, refusalCancel := context.WithTimeout(context.Background(), time.Second)
	defer refusalCancel()
	if err = store.FinalizeGuestNotifyCanaryNonce(refusalCtx, f.policy, generation, fence, owner, late, failedServingHTTP(t, late.GuestNonce, time.Now().UTC())); err == nil {
		t.Fatal("expired prepared PUB acquired a persisted nonce")
	}
	if err = store.ReserveGuestNotifyCanarySend(refusalCtx, f.policy, generation, fence, owner, late); err == nil {
		t.Fatal("expired prepared PUB acquired possible-send authority")
	}
	result := nonceAcquire105Result(t, job, generation, fence, *job.StartedAt, time.Now().UTC())
	if err = FinishCapacityDispatch(context.Background(), f.db, job, result, time.Now().UTC(), context.DeadlineExceeded); !errors.Is(err, ErrCapacityDispatchUnknown) {
		t.Fatal("M105 genuine first finish must retain UNKNOWN", err)
	}
	var valid bool
	var current []byte
	if err = f.db.QueryRow(`SELECT j.state='unknown' AND j.finalization_ack_at IS NULL AND j.finalization_error IS NULL AND j.return_error='capacity dispatch original deadline exceeded' AND w.status='failed' AND w.error=j.return_error AND
 (SELECT count(*)=1 FROM capacity_guest_notify_canary_challenges WHERE id=$2) AND
 NOT EXISTS(SELECT 1 FROM capacity_guest_notify_canary_nonces WHERE challenge_id=$2) AND NOT EXISTS(SELECT 1 FROM capacity_guest_notify_canary_sends WHERE challenge_id=$2) AND NOT EXISTS(SELECT 1 FROM capacity_guest_notify_canary_returns WHERE challenge_id=$2),
 jsonb_build_object('job',to_jsonb(j),'run',to_jsonb(w),'challenge',(SELECT to_jsonb(c) FROM capacity_guest_notify_canary_challenges c WHERE id=$2),'authority',(SELECT to_jsonb(a) FROM capacity_guest_authority_issues a WHERE issue_kind='canary_challenge' AND issue_id=$2))::text
 FROM capacity_dispatch_jobs j JOIN workflow_runs w ON w.id=j.run_id WHERE j.id=$1`, job.JobID, publication.ChallengeID).Scan(&valid, &current); err != nil || !valid || !reflect.DeepEqual(originals, f.preserved(t)) {
		t.Fatal("M105 actual current producer originals", err, valid)
	}
	put("M105-CURRENT-SOURCE-PRODUCER-WITNESS.PUBLIC.json", failedServingWire(t, map[string]any{"schema": "nonce_acquire105_current_source_fixture_v1", "fixture_only": true, "workflow_result_fixture_declared": true, "full_workflow_execution_claimed": false, "real_prepared_publication": true, "real_expired_acquire_before_transport": true, "HTTP_execution_claimed": false, "real_finish_unknown": true, "original_ACK_absent": true, "live_900_second_admission_claimed": false, "whole_originals": json.RawMessage(current)}))
	h := nonceAcquire105HistoricalFixture(t, f, base, migrations)
	// The current unresolved witness is finished and retained; close its pool
	// before the finite historical races open their distinct fixture sessions.
	if err = f.db.Close(); err != nil {
		t.Fatal(err)
	}
	nonceAcquire105HistoricalChecks(t, h, f, migrations, put)
	for _, kind := range []string{"nonce", "send", "return"} {
		racing := nonceAcquire105HistoricalFixture(t, f, base, migrations)
		nonceAcquire105LateRace(t, racing, f, kind, kind == "nonce", put)
		if err = racing.db.Close(); err != nil {
			t.Fatal(err)
		}
	}
	nonceAcquire105EmptyDown(t, migrations, put)
}

func nonceAcquire105Result(t *testing.T, job CapacityDispatchJob, generation, fence int64, started, finished time.Time) model.RunWorkflowResponse {
	t.Helper()
	r := supersededHTTPResult(t, job, generation, fence, started, finished)
	r.Steps[0].Metadata["reason"] = "capacity_boundary"
	r.Steps[3].Metadata["original_guest_notify_refusal_stage"] = "nonce_acquire"
	r.Steps[3].Metadata["original_guest_notify_nonce_http_status"] = 0
	return r
}

type nonceAcquire105Historical struct {
	db          *sql.DB
	request     CapacityDispatchUnknownMaintenanceDispositionRequest
	barrier     CapacityDispatchExecutorBarrier
	publication model.CapacityGuestNotifyCanaryChallenge
	lateNonce   model.CapacityGuestNotifyCanaryChallenge
	lease       time.Time
	policy      model.Manifest
}

func nonceAcquire105HistoricalFixture(t *testing.T, f *failedServingFixture, base map[string][]json.RawMessage, migrations string) nonceAcquire105Historical {
	t.Helper()
	// This existing owner closes its admin connection after CREATE, keeping
	// the finite multi-database race witness below the unchanged eight-session
	// lane budget. It still verifies the exact local93 prefix and UUID database.
	db := preActionPlanDB(t, &preActionPlanDBOwner{})
	db.SetMaxOpenConns(3)
	db.SetMaxIdleConns(1)
	if err := goose.UpToContext(context.Background(), db, migrations, 105); err != nil {
		t.Fatal(err)
	}
	start := f.pre.ReservedAt.Add(45 * time.Minute).UTC().Truncate(time.Millisecond)
	lease, returned := start.Add(5*time.Minute), start.Add(10*time.Second)
	generation, fence := f.intent.Generation+1, f.intent.FencingToken+1
	policy := f.policy
	policy.ID, policy.Version = uuid.New(), f.policy.Version+1
	policy.Checksum = capacity.BusinessCreationSHA256(policy.Spec)
	prior := nonceAcquire105DeclaredTwin(t, f, base, false)
	duplicate := nonceAcquire105DeclaredTwin(t, f, base, true)
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err = tx.Exec(`SET LOCAL session_replication_role=replica`); err != nil {
		t.Fatal(err)
	}
	// These are FIRST target-database INSERTs of declared mature history.
	// Signed birth/enrollment/install wires are copied exactly. A distinct
	// compatible current policy and later unleased epoch are chosen up front.
	for _, table := range supersededHTTPBaseTables {
		for _, raw := range base[table] {
			var row map[string]json.RawMessage
			if json.Unmarshal(raw, &row) != nil {
				t.Fatal("M105 initial base row")
			}
			if table == "manifests" {
				row["created_at"], row["updated_at"] = failedServingWire(t, start.Add(-time.Hour)), failedServingWire(t, start.Add(-time.Hour))
				if string(row["id"]) == `"`+f.policy.ID.String()+`"` {
					row["active"] = json.RawMessage("false")
				}
			}
			if table == "capacity_intents" {
				i := f.intent
				i.PolicyID, i.PolicyChecksum = policy.ID, policy.Checksum
				i.Generation, i.FencingToken = generation, fence
				i.Decision.Reason, i.Decision.ExecutionPermitted = "capacity_boundary", false
				i.UpdatedAt = start.Add(time.Second)
				row["intent"], row["updated_at"] = failedServingWire(t, i), failedServingWire(t, i.UpdatedAt)
			}
			if table == "capacity_intent_events" {
				row["generation"], row["fencing_token"] = failedServingWire(t, generation), failedServingWire(t, fence)
			}
			if table == "capacity_resource_slots" {
				var slot map[string]any
				if json.Unmarshal(row["slot_record"], &slot) != nil {
					t.Fatal("M105 initial slot")
				}
				slot["observed_at"], slot["receipt_ref"] = start.Add(2*time.Second), "original-guest-reconcile:declared-M105-historical"
				row["slot_record"], row["updated_at"], row["revision"] = failedServingWire(t, slot), failedServingWire(t, start.Add(2*time.Second)), json.RawMessage("2")
			}
			if _, err = tx.Exec(`INSERT INTO public.`+pq.QuoteIdentifier(table)+` SELECT (jsonb_populate_record(NULL::public.`+pq.QuoteIdentifier(table)+`,$1::jsonb)).*`, string(failedServingWire(t, row))); err != nil {
				t.Fatal("M105 initial historical row", table, err)
			}
		}
	}
	for _, table := range nonceAcquire105TwinTables {
		if _, err = tx.Exec(`INSERT INTO public.`+pq.QuoteIdentifier(table)+` SELECT (jsonb_populate_record(NULL::public.`+pq.QuoteIdentifier(table)+`,$1::jsonb)).*`, string(prior[table])); err != nil {
			t.Fatal("M105 initial declared different-incarnation family", table, err)
		}
	}
	// An exact full-tuple duplicate meets the unchanged real UNIQUE barrier.
	// This is an initial declared-storage attempt before the first commit,
	// not an executed membership scan or a fabricated tuple hash.
	if _, err = tx.Exec(`SAVEPOINT duplicate_full_tuple105`); err != nil {
		t.Fatal(err)
	}
	var duplicateError error
	for _, table := range nonceAcquire105TwinTables {
		_, duplicateError = tx.Exec(`INSERT INTO public.`+pq.QuoteIdentifier(table)+` SELECT (jsonb_populate_record(NULL::public.`+pq.QuoteIdentifier(table)+`,$1::jsonb)).*`, string(duplicate[table]))
		if duplicateError != nil {
			var pg *pq.Error
			if table != "capacity_vm_original_enrollments" || !errors.As(duplicateError, &pg) || pg.Code != "23505" || !strings.Contains(pg.Constraint, "resource_tuple_sha256") {
				t.Fatal("M105 duplicate must hit the actual full-tuple UNIQUE boundary", table, duplicateError)
			}
			break
		}
	}
	if duplicateError == nil {
		t.Fatal("M105 exact full physical incarnation was duplicated")
	}
	if _, err = tx.Exec(`ROLLBACK TO SAVEPOINT duplicate_full_tuple105`); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(`RELEASE SAVEPOINT duplicate_full_tuple105`); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(`INSERT INTO manifests(id,api_version,kind,namespace,name,version,checksum,spec,active,created_at,updated_at) VALUES($1,'v1','capacity_policy',$2,$3,$4,$5,$6::jsonb,true,$7,$7)`, policy.ID, policy.Metadata.Namespace, policy.Metadata.Name, policy.Version, policy.Checksum, string(policy.Spec), start.Add(-time.Minute)); err != nil {
		t.Fatal("M105 initial declared compatible policy version", err)
	}
	e := abandonedDispatchEnvelope(t, policy.Metadata.Namespace, start.Format(time.RFC3339Nano))
	e.Environment, e.Domain, e.Dimension = f.p.Environment, f.p.Domain, f.p.Dimension
	e.Policy, e.Workflow = installedTimeoutPin(policy), installedTimeoutPin(f.workflow)
	e.RBAC.Namespace, e.RBAC.Name = policy.Metadata.Namespace, "failed-serving-unit-rbac"
	e.Inputs = map[string]any{"policy": map[string]any{"namespace": policy.Metadata.Namespace, "name": policy.Metadata.Name}}
	e.Metadata["manifest_id"] = e.Workflow.ID.String()
	e.InputsSHA256, e.MetadataSHA256, err = CapacityDispatchEnvelopeHashes(e)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := encodeCapacityDispatchEnvelope(e)
	if err != nil {
		t.Fatal(err)
	}
	owner := uuid.New()
	job := CapacityDispatchJob{CapacityDispatchEnvelope: e, State: "unknown", LeaseOwner: owner, FencingToken: 1, StartedAt: &start, LeaseExpiresAt: &lease, ReturnedAt: &returned, PendingWakeCount: 1}
	result := nonceAcquire105Result(t, job, generation, fence, start, returned)
	const deadlineError = "capacity dispatch original deadline exceeded"
	if _, err = tx.Exec(`INSERT INTO manifests(id,api_version,kind,namespace,name,version,checksum,spec,active,created_at,updated_at) VALUES($1,'v1','rbac',$2,$3,$4,$5,'{}'::jsonb,true,$6,$6)`, e.RBAC.ID, e.RBAC.Namespace, e.RBAC.Name, e.RBAC.Version, e.RBAC.Checksum, start.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(`INSERT INTO workflow_runs(id,workflow_namespace,workflow_name,workflow_version,status,inputs,metadata,result,error,started_at,finished_at,created_at,updated_at) VALUES($1,$2,$3,$4,'failed',$5::jsonb,$6::jsonb,$7::jsonb,$8,$9,$10,$9,$10)`, e.RunID, e.Workflow.Namespace, e.Workflow.Name, e.Workflow.Version, mustEncodeJSON(e.Inputs, "{}"), mustEncodeJSON(e.Metadata, "{}"), string(failedServingWire(t, result)), deadlineError, start, returned); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(`INSERT INTO capacity_dispatch_jobs(id,run_id,protocol,realm,environment,domain,dimension,source_tick,envelope,envelope_sha256,state,lease_owner,fencing_token,lease_expires_at,started_at,returned_at,return_status,return_error,pending_wake_count,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'unknown',$11,1,$12,$13,$14,'failed',$15,1,$13,$14)`, e.JobID, e.RunID, e.Protocol, e.Realm, e.Environment, e.Domain, e.Dimension, e.SourceTick, string(wire), capacityDispatchSHA(wire), owner, lease, start, returned, deadlineError); err != nil {
		t.Fatal(err)
	}
	_, publication, _, _ := capacity.RecoveryFixtureCausal(t, f.p, f.reg, f.receipt, uint64(fence), GuestNotifyMaintenanceOwner(f.store.ExecutorID), start.Add(3*time.Second))
	publication.PolicyID, publication.PolicyChecksum = policy.ID.String(), policy.Checksum
	publication.Generation, publication.Fence = uint64(generation), uint64(fence)
	publication.UsageClass = "steady_useful_membership"
	declaredNonce := publication.GuestNonce
	publication.GuestNonce, publication.Signature = model.CapacityGuestNotifyCanaryNonce{}, ""
	publication.Signature, err = capacity.GuestLifecycleSignature(failedServingKey('c'), publication)
	if err != nil || capacity.ValidateGuestNotifyCanaryPreflight(publication, f.receipt.Enrollment, publication.IssuedAt.Add(time.Millisecond)) != nil {
		t.Fatal("M105 declared historical prepared Source challenge", err)
	}
	// This held late-write operand belongs only to the initial declared history.
	// Rebind the causal fixture nonce to this exact prepared PUB before sealing;
	// never mint a nonce by passing an expired challenge to a wall-clock factory.
	lateNonce := publication
	lateNonce.GuestNonce = declaredNonce
	lateNonce.GuestNonce.PreflightSHA256 = capacity.GuestNotifyPreflightSHA(publication)
	lateNonce.GuestNonce.Signature = ""
	lateNonce.GuestNonce.Signature, err = capacity.GuestLifecycleSignature(failedServingKey('o'), lateNonce.GuestNonce)
	if err != nil {
		t.Fatal("M105 initial declared historical nonce signature", err)
	}
	lateNonce.Signature = ""
	lateNonce.Signature, err = capacity.GuestLifecycleSignature(failedServingKey('c'), lateNonce)
	declaredCheckAt := publication.IssuedAt.Add(time.Millisecond)
	if err != nil || !declaredCheckAt.After(publication.IssuedAt) || !declaredCheckAt.Before(publication.OriginalDeadline) || capacity.ValidateGuestNotifyCanaryNonce(lateNonce, f.receipt.Enrollment) != nil || capacity.ValidateGuestNotifyCanaryChallenge(lateNonce, f.receipt.Enrollment, declaredCheckAt) != nil {
		t.Fatal("M105 initial declared nonce must match its original challenge time", err)
	}
	pubWire := failedServingWire(t, publication)
	if _, err = tx.Exec(`INSERT INTO capacity_guest_notify_canary_challenges(id,preregistration_id,record_challenge_id,phase,policy_id,workflow_id,generation,fence,executor_id,lease_owner,challenge_sha256,nonce_sha256,original_wire,original_record,original_deadline,recorded_at) VALUES($1,$2,$1,'publish',$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::jsonb,$13,$14)`, publication.ChallengeID, f.pre.PreregistrationID, policy.ID, f.workflow.ID, generation, fence, f.store.ExecutorID, publication.LeaseOwner, capacity.BusinessCreationSHA256(pubWire), publication.NonceSHA256, pubWire, string(pubWire), publication.OriginalDeadline, publication.IssuedAt); err != nil {
		t.Fatal(err)
	}
	issue := map[string]any{"schema": "guest_authority_issue_v1", "issue_kind": "canary_challenge", "issue_id": publication.ChallengeID, "issuer_actual_source_commit": capacity.CurrentGuestCoreSource(), "protocol_authority_source_commit": f.p.GuestRetirementBinding.CoreAuthoritySourceCommit, "compatibility_map_sha256": capacity.GuestProtocolCompatibilityMapSHA256(), "profile": f.p.GuestRetirementBinding.ProfileManifest.Profile, "policy_id": policy.ID, "workflow_id": f.workflow.ID, "executor_id": f.store.ExecutorID, "issued_wire_sha256": capacity.BusinessCreationSHA256(pubWire)}
	issueWire := failedServingWire(t, issue)
	if _, err = tx.Exec(`INSERT INTO capacity_guest_authority_issues(issue_kind,issue_id,issuer_actual_source_commit,protocol_authority_source_commit,compatibility_map_sha256,profile,policy_id,workflow_id,executor_id,issued_wire_sha256,original_wire,original_record,recorded_at) VALUES('canary_challenge',$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb,$12)`, publication.ChallengeID, capacity.CurrentGuestCoreSource(), f.p.GuestRetirementBinding.CoreAuthoritySourceCommit, capacity.GuestProtocolCompatibilityMapSHA256(), f.p.GuestRetirementBinding.ProfileManifest.Profile, policy.ID, f.workflow.ID, f.store.ExecutorID, capacity.BusinessCreationSHA256(pubWire), issueWire, string(issueWire), publication.IssuedAt); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	h := nonceAcquire105Historical{db: db, publication: publication, lateNonce: lateNonce, lease: lease, policy: policy, request: CapacityDispatchUnknownMaintenanceDispositionRequest{CapacityDispatchAbandonedDispositionRequest: CapacityDispatchAbandonedDispositionRequest{JobID: job.JobID, ExpectedRunID: job.RunID, ExpectedEnvelopeSHA256: capacityDispatchSHA(wire), ExpectedFencingToken: 1, ExpectedLeaseOwner: owner, ExpectedPendingWakeCount: 1, Issuer: "collaborator:" + uuid.NewString()}, ExpectedReturnedAt: returned}, barrier: CapacityDispatchExecutorBarrier{ProcessStartedAt: lease.Add(time.Minute), Hostname: "declared-historical-M105-fixture", PID: 4242, SourceCommit: capacity.CurrentGuestCoreSource()}}
	if err = db.QueryRow(`SELECT encode(sha256(convert_to(to_jsonb(w)::text,'UTF8')),'hex'),public.unknown_maintenance_dispatch_effect_scan($1)->>'current_members_sha256' FROM workflow_runs w WHERE id=$2`, job.JobID, job.RunID).Scan(&h.request.ExpectedRunSHA256, &h.request.ExpectedMembersSHA256); err != nil {
		t.Fatal(err)
	}
	return h
}

var nonceAcquire105TwinTables = []string{"capacity_mutation_grants", "capacity_vm_provisioning_preregistrations", "capacity_vm_original_enrollments", "capacity_guest_original_installations"}

// Only the unselected prior family is declared storage. No signature/native
// truth is claimed for it. The selected current signed birth wires are never
// rewritten. Whole fields and self-hashes stay consistent for the real joins.
func nonceAcquire105DeclaredTwin(t *testing.T, f *failedServingFixture, base map[string][]json.RawMessage, samePhysical bool) map[string][]byte {
	t.Helper()
	ids := map[string]string{f.pre.PreregistrationID: uuid.NewString(), f.pre.OriginalCreateGrantID: uuid.NewString(), f.pre.NonceSHA256: capacityDispatchSHA([]byte(uuid.NewString())), f.reg.Result.ProductionClock.Authority.CreateWitness.OriginalCreateAttemptID: uuid.NewString()}
	resource := f.reg.Result.Tuple.ResourceID
	priorResource := "122"
	if resource == priorResource {
		priorResource = "121"
	}
	created, err := time.Parse(time.RFC3339Nano, f.reg.Result.Tuple.CreatedAt)
	if err != nil {
		t.Fatal(err)
	}
	var remap func(any) any
	remap = func(value any) any {
		switch v := value.(type) {
		case string:
			if n, ok := ids[v]; ok {
				return n
			}
			if !samePhysical && v == resource {
				return priorResource
			}
			if strings.HasPrefix(v, `\x`) {
				b, e := hex.DecodeString(v[2:])
				var nested any
				if e != nil || json.Unmarshal(b, &nested) != nil {
					t.Fatal("declared twin JSON bytea")
				}
				return `\x` + hex.EncodeToString(failedServingWire(t, remap(nested)))
			}
		case map[string]any:
			for k, x := range v {
				if !samePhysical && k == "resource_created_at" && x == f.reg.Result.Tuple.CreatedAt {
					v[k] = created.Add(-time.Minute).Format(time.RFC3339Nano)
				} else {
					v[k] = remap(x)
				}
			}
		case []any:
			for n := range v {
				v[n] = remap(v[n])
			}
		}
		return value
	}
	rows := map[string]map[string]any{}
	for _, table := range nonceAcquire105TwinTables {
		if len(base[table]) != 1 {
			t.Fatal("one complete current birth family to clone", table)
		}
		var value any
		if json.Unmarshal(base[table][0], &value) != nil {
			t.Fatal("whole initial twin row")
		}
		rows[table] = remap(value).(map[string]any)
	}
	decode := func(value any, target any) {
		t.Helper()
		s, ok := value.(string)
		if !ok || !strings.HasPrefix(s, `\x`) {
			t.Fatal("declared twin bytea required")
		}
		b, e := hex.DecodeString(s[2:])
		if e != nil || json.Unmarshal(b, target) != nil {
			t.Fatal("declared twin typed wire", e)
		}
	}
	wire := func(v any) string { return `\x` + hex.EncodeToString(failedServingWire(t, v)) }
	var registration model.CapacityGuestOriginalProvisioningRegistration
	var receipt model.CapacityGuestOriginalProvisioningReceipt
	var installation model.CapacityGuestOriginalInstallationConfirmation
	en := rows["capacity_vm_original_enrollments"]
	decode(en["registration_wire"], &registration)
	decode(en["receipt_wire"], &receipt)
	if json.Unmarshal(failedServingWire(t, en["enrollment_record"]), &receipt.Enrollment) != nil {
		t.Fatal("declared twin enrollment")
	}
	receipt.Enrollment.Statement.OriginalNativeResultSHA256 = capacity.GuestRetirementSHA(registration.Result)
	receipt.Enrollment.Statement.OriginalProvisioningClockSHA256 = capacity.GuestRetirementSHA(*registration.Result.ProductionClock)
	registration.EnrollmentStatement = receipt.Enrollment.Statement
	receipt.Enrollment.Signature, err = capacity.GuestLifecycleSignature(failedServingKey('i'), receipt.Enrollment.Statement)
	if err != nil {
		t.Fatal(err)
	}
	receipt.OriginalProvisioningSHA256 = capacity.GuestRetirementSHA(registration)
	en["registration_wire"], en["receipt_wire"] = wire(registration), wire(receipt)
	en["enrollment_record"] = receipt.Enrollment
	en["original_provisioning_sha256"], en["enrollment_sha256"] = receipt.OriginalProvisioningSHA256, capacity.GuestRetirementSHA(receipt.Enrollment)
	en["resource_tuple_sha256"] = capacity.GuestRetirementSHA(receipt.Enrollment.Statement.Tuple)
	ins := rows["capacity_guest_original_installations"]
	decode(ins["original_wire"], &installation)
	installation.EnrollmentSHA256, installation.OriginalReceiptSHA256 = capacity.GuestRetirementSHA(receipt.Enrollment), capacity.GuestRetirementSHA(receipt)
	ins["original_wire"], ins["confirmation_sha256"] = wire(installation), capacity.GuestRetirementSHA(installation)
	out := map[string][]byte{}
	for table, row := range rows {
		out[table] = failedServingWire(t, row)
	}
	return out
}

func nonceAcquire105Snapshot(t *testing.T, h nonceAcquire105Historical) string {
	t.Helper()
	var raw string
	if err := h.db.QueryRow(`SELECT jsonb_build_object('job',to_jsonb(j)-ARRAY['state','updated_at','unknown_maintenance_disposition_id'],'run',to_jsonb(w),'challenge',to_jsonb(c),'authority',(SELECT to_jsonb(a) FROM capacity_guest_authority_issues a WHERE issue_kind='canary_challenge' AND issue_id=c.id),'nonces',(SELECT coalesce(jsonb_agg(to_jsonb(n)),'[]'::jsonb) FROM capacity_guest_notify_canary_nonces n WHERE challenge_id=c.id),'sends',(SELECT coalesce(jsonb_agg(to_jsonb(s)),'[]'::jsonb) FROM capacity_guest_notify_canary_sends s WHERE challenge_id=c.id),'returns',(SELECT coalesce(jsonb_agg(to_jsonb(r)),'[]'::jsonb) FROM capacity_guest_notify_canary_returns r WHERE challenge_id=c.id))::text FROM capacity_dispatch_jobs j JOIN workflow_runs w ON w.id=j.run_id JOIN capacity_guest_notify_canary_challenges c ON c.id=$2 WHERE j.id=$1`, h.request.JobID, h.publication.ChallengeID).Scan(&raw); err != nil {
		t.Fatal("M105 whole original custody", err)
	}
	return raw
}

func nonceAcquire105HistoricalChecks(t *testing.T, h nonceAcquire105Historical, f *failedServingFixture, migrations string, put func(string, []byte)) {
	t.Helper()
	ctx := context.Background()
	nonceAcquire105OldGoose(t, h.db, migrations, put)
	before := nonceAcquire105Snapshot(t, h)
	var raw []byte
	var admitted, oldResult, old91 bool
	if err := h.db.QueryRow(`SELECT public.unknown_maintenance_dispatch_effect_scan($1)::text,public.unknown_maintenance_dispatch_effect_scan_tolerable(public.unknown_maintenance_dispatch_effect_scan($1)),public.unknown_maintenance_dispatch_result_valid(w.result,i.intent->>'generation',i.intent->>'fencing_token'),public.http_maintenance_dispatch_admission_valid($1) FROM capacity_dispatch_jobs j JOIN workflow_runs w ON w.id=j.run_id JOIN capacity_intents i ON (i.namespace,i.environment,i.domain,i.dimension)=(j.realm,j.environment,j.domain,j.dimension) WHERE j.id=$1`, h.request.JobID).Scan(&raw, &admitted, &oldResult, &old91); err != nil || !admitted || oldResult || old91 {
		t.Fatal("M105 independent prepared-only admission and unchanged old predicates", err, admitted, oldResult, old91, string(raw))
	}
	var scan CapacityDispatchUnknownMaintenanceEffectScan
	if json.Unmarshal(raw, &scan) != nil || !scan.tolerable() || scan.CurrentMemberCount != 1 || scan.CurrentMembersSHA256 != h.request.ExpectedMembersSHA256 {
		t.Fatal("unchanged M87 Go scan ABI refuses legitimate SQL105 subtype")
	}
	var priorFamilies int
	if err := h.db.QueryRow(`SELECT count(*) FROM capacity_dispatch_jobs j JOIN capacity_resource_slots s ON (s.namespace,s.environment,s.domain,s.dimension)=(j.realm,j.environment,j.domain,j.dimension) JOIN capacity_mutation_grants g ON (g.namespace,g.environment,g.domain,g.dimension,g.slot,g.integration_instance_id,g.scope_checksum,g.profile_name)=(s.namespace,s.environment,s.domain,s.dimension,s.slot,s.integration_instance_id,s.scope_checksum,s.profile_name) AND g.state='confirmed' JOIN capacity_vm_provisioning_preregistrations pr ON pr.create_grant_id=g.id JOIN capacity_vm_original_enrollments en ON en.preregistration_id=pr.id JOIN capacity_guest_original_installations ins ON ins.preregistration_id=pr.id WHERE j.id=$1 AND s.slot=1 AND public.http_maintenance_dispatch_policy_continuous((pr.preregistration_record->>'policy_id')::uuid,pr.preregistration_record->>'policy_checksum',$2,$3) AND NOT EXISTS(SELECT 1 FROM capacity_vm_retirement_intents ri WHERE ri.preregistration_id=pr.id)`, h.request.JobID, h.policy.ID, h.policy.Checksum).Scan(&priorFamilies); err != nil || priorFamilies != 2 {
		t.Fatal("M105 prior same-slot confirmed incarnation must remain a real pre-physical candidate", err, priorFamilies)
	}
	var selected bool
	if err := h.db.QueryRow(`SELECT $1::jsonb#>>'{nonce_acquire_prepared_only,membership,preregistration,id}'=$2::text AND $1::jsonb#>>'{nonce_acquire_prepared_only,membership,slot,resource_id}'=$3::text AND $1::jsonb#>>'{nonce_acquire_prepared_only,membership,enrollment,enrollment_record,statement,tuple,resource_created_at}'=$4::text AND $1::jsonb#>>'{nonce_acquire_prepared_only,membership,preregistration,preregistration_record,generation}'<>$1::jsonb#>>'{nonce_acquire_prepared_only,intent,generation}'`, string(raw), h.publication.PreregistrationID, h.publication.Tuple.ResourceID, h.publication.Tuple.CreatedAt).Scan(&selected); err != nil || !selected {
		t.Fatal("M105 exact current physical/birth selection before STRICT", err, selected)
	}
	put("M105-DECLARED-HISTORICAL-ADMISSION-SCAN.PUBLIC.json", raw)
	cas := []struct {
		name   string
		change func(*CapacityDispatchUnknownMaintenanceDispositionRequest)
	}{
		{"job", func(r *CapacityDispatchUnknownMaintenanceDispositionRequest) { r.JobID = uuid.New() }},
		{"run", func(r *CapacityDispatchUnknownMaintenanceDispositionRequest) { r.ExpectedRunID = uuid.New() }},
		{"envelope", func(r *CapacityDispatchUnknownMaintenanceDispositionRequest) {
			r.ExpectedEnvelopeSHA256 = nonceAcquire105DifferentDigest(r.ExpectedEnvelopeSHA256)
		}},
		{"fence", func(r *CapacityDispatchUnknownMaintenanceDispositionRequest) { r.ExpectedFencingToken++ }},
		{"owner", func(r *CapacityDispatchUnknownMaintenanceDispositionRequest) { r.ExpectedLeaseOwner = uuid.New() }},
		{"wake", func(r *CapacityDispatchUnknownMaintenanceDispositionRequest) { r.ExpectedPendingWakeCount++ }},
		{"returned", func(r *CapacityDispatchUnknownMaintenanceDispositionRequest) {
			r.ExpectedReturnedAt = r.ExpectedReturnedAt.Add(time.Microsecond)
		}},
		{"run_sha", func(r *CapacityDispatchUnknownMaintenanceDispositionRequest) {
			r.ExpectedRunSHA256 = nonceAcquire105DifferentDigest(r.ExpectedRunSHA256)
		}},
		{"members_sha", func(r *CapacityDispatchUnknownMaintenanceDispositionRequest) {
			r.ExpectedMembersSHA256 = nonceAcquire105DifferentDigest(r.ExpectedMembersSHA256)
		}},
	}
	for _, v := range cas {
		r := h.request
		v.change(&r)
		if reflect.DeepEqual(r, h.request) {
			t.Fatal("M105 stale CAS operand did not change", v.name)
		}
		if _, err := DisposeUnknownMaintenanceDispatch(ctx, h.db, r, h.barrier, abandonedAllow); err == nil || nonceAcquire105Snapshot(t, h) != before {
			t.Fatal("M105 stale CAS accepted or changed originals", v.name, err)
		}
	}
	for _, barrier := range []CapacityDispatchExecutorBarrier{{}, {ProcessStartedAt: h.lease, Hostname: "old-process", PID: 1, SourceCommit: h.barrier.SourceCommit}, {ProcessStartedAt: time.Now().Add(time.Hour), Hostname: "future-process", PID: 1, SourceCommit: h.barrier.SourceCommit}} {
		if _, err := DisposeUnknownMaintenanceDispatch(ctx, h.db, h.request, barrier, abandonedAllow); err == nil {
			t.Fatal("M105 missing/old/future server process accepted")
		}
	}
	r := h.request
	r.Issuer = "machine:caller"
	if _, err := DisposeUnknownMaintenanceDispatch(ctx, h.db, r, h.barrier, abandonedAllow); err == nil {
		t.Fatal("M105 caller authority accepted")
	}
	if _, err := DisposeUnknownMaintenanceDispatch(ctx, h.db, h.request, h.barrier, func(context.Context) error { return errors.New("declared administrator revoked") }); err == nil {
		t.Fatal("M105 administrative revalidation refusal ignored")
	}
	nonceAcquire105ProofVectors(t, h, raw, put)
	// Current catalog and effect faults are appended only in rolled-back
	// transactions; no sealed original job/run/challenge is edited for a gate.
	faults := []struct{ name, query string }{
		{"later_inactive_policy", `INSERT INTO manifests(id,api_version,kind,namespace,name,version,checksum,spec,active) SELECT $2,api_version,kind,namespace,name,version+1,checksum,spec,false FROM manifests WHERE id=$1`},
		{"other_active_policy", `INSERT INTO manifests(id,api_version,kind,namespace,name,version,checksum,spec,active) SELECT $2,api_version,kind,namespace,name,version+1,checksum,spec,true FROM manifests WHERE id=$1`},
		{"extra_member", `INSERT INTO capacity_resource_slots(integration_instance_id,scope_checksum,profile_name,slot,namespace,environment,domain,dimension,resource_id,slot_record,revision,updated_at) SELECT integration_instance_id,scope_checksum,profile_name,2,namespace,environment,domain,dimension,'declared-other-member',slot_record,revision,clock_timestamp() FROM capacity_resource_slots LIMIT 1`},
		{"provider_authority", `INSERT INTO capacity_mutation_grants(id,namespace,environment,domain,dimension,generation,integration_instance_id,scope_checksum,profile_name,slot,state,grant_record,expires_at,updated_at) SELECT $2,namespace,environment,domain,dimension,generation,integration_instance_id,scope_checksum,profile_name,2,'issued',grant_record,clock_timestamp()+interval '1 minute',clock_timestamp() FROM capacity_mutation_grants LIMIT 1`},
	}
	const logicalCatalogQuery = `SELECT COALESCE(jsonb_agg(to_jsonb(m) ORDER BY m.version,m.id),'[]'::jsonb)::text FROM public.manifests m WHERE m.kind='capacity_policy' AND m.namespace=$1 AND m.name=$2`
	var catalogBefore string
	if err := h.db.QueryRow(logicalCatalogQuery, h.policy.Metadata.Namespace, h.policy.Metadata.Name).Scan(&catalogBefore); err != nil {
		t.Fatal("M105 whole logical policy catalog before faults", err)
	}
	otherActiveStorageRefused := false
	for _, fault := range faults {
		tx, err := h.db.Begin()
		if err != nil {
			t.Fatal(err)
		}
		args := []any{h.policy.ID, uuid.New()}
		if fault.name == "extra_member" {
			args = nil
		}
		if fault.name == "provider_authority" {
			// Use a typed first placeholder as well; lib/pq must never infer an
			// unused untyped parameter in a polymorphic fixture expression.
			fault.query = strings.ReplaceAll(fault.query, "$2", "$1")
			args = []any{uuid.New()}
		}
		if _, err = tx.Exec(fault.query, args...); err != nil {
			rollbackErr := tx.Rollback()
			var pg *pq.Error
			// A second ACTIVE row cannot reach a scan: the original schema's
			// partial UNIQUE index rejects it before any catalog activation.
			if fault.name != "other_active_policy" || rollbackErr != nil || !errors.As(err, &pg) || pg.Code != "23505" || pg.Constraint != "manifests_single_active_uidx" {
				t.Fatal("M105 append-only fault must reach real scan or exact original storage boundary", fault.name, err, rollbackErr)
			}
			var catalogAfter string
			if catalogErr := h.db.QueryRow(logicalCatalogQuery, h.policy.Metadata.Namespace, h.policy.Metadata.Name).Scan(&catalogAfter); catalogErr != nil || catalogAfter != catalogBefore || nonceAcquire105Snapshot(t, h) != before {
				t.Fatal("M105 original ACTIVE uniqueness refusal changed catalog or originals", catalogErr)
			}
			otherActiveStorageRefused = true
			continue
		}
		if fault.name == "other_active_policy" {
			tx.Rollback()
			t.Fatal("M105 original single-ACTIVE storage boundary did not refuse")
		}
		var ok bool
		err = tx.QueryRow(`SELECT public.unknown_maintenance_dispatch_effect_scan_tolerable(public.unknown_maintenance_dispatch_effect_scan($1))`, h.request.JobID).Scan(&ok)
		tx.Rollback()
		if err != nil || ok || nonceAcquire105Snapshot(t, h) != before {
			t.Fatal("M105 live fault admitted or changed originals", fault.name, err, ok)
		}
	}
	if !otherActiveStorageRefused {
		t.Fatal("M105 original single-ACTIVE storage refusal was not exercised")
	}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for n := 0; n < 2; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := DisposeUnknownMaintenanceDispatch(ctx, h.db, h.request, h.barrier, abandonedAllow)
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	winners := 0
	for err := range results {
		if err == nil {
			winners++
		}
	}
	if winners != 1 {
		t.Fatal("M105 two unchanged M87 disposers must have one winner", winners)
	}
	d, err := ReadCapacityDispatchUnknownMaintenanceDisposition(ctx, h.db, h.request.JobID)
	if err != nil || d.State != "unknown_maintenance_disposed" || d.HistoricalReturn != "unknown" || d.OriginalRunSHA256 != h.request.ExpectedRunSHA256 || nonceAcquire105Snapshot(t, h) != before {
		t.Fatal("M105 unchanged M87 retained GET or original custody", err, d)
	}
	var pure bool
	if err = h.db.QueryRow(`SELECT public.unknown_maintenance_nonce_acquire_receipt_valid105(d) FROM capacity_dispatch_unknown_maintenance_dispositions d WHERE job_id=$1`, h.request.JobID).Scan(&pure); err != nil || !pure {
		t.Fatal("M105 retained receipt pure validation", err, pure)
	}
	for _, field := range []string{"original_dispatch_sha256", "original_run_sha256", "current_members_sha256", "original_returned_at", "disposing_core_process_started_at", "provider_mutation_evidence"} {
		var ok bool
		query := `SELECT public.unknown_maintenance_nonce_acquire_receipt_valid105(jsonb_populate_record(NULL::public.capacity_dispatch_unknown_maintenance_dispositions,to_jsonb(d)||jsonb_build_object($2::text,CASE $2::text WHEN 'original_dispatch_sha256' THEN to_jsonb($3::text) WHEN 'original_run_sha256' THEN to_jsonb($4::text) WHEN 'current_members_sha256' THEN to_jsonb($5::text) WHEN 'original_returned_at' THEN to_jsonb(d.original_returned_at+interval '1 microsecond') WHEN 'disposing_core_process_started_at' THEN d.provider_mutation_evidence#>'{nonce_acquire_prepared_only,dispatch,lease_expires_at}' ELSE d.provider_mutation_evidence-'nonce_acquire_prepared_only' END))) FROM capacity_dispatch_unknown_maintenance_dispositions d WHERE d.job_id=$1`
		if err = h.db.QueryRow(query, h.request.JobID, field, nonceAcquire105DifferentDigest(d.OriginalDispatchSHA256), nonceAcquire105DifferentDigest(d.OriginalRunSHA256), nonceAcquire105DifferentDigest(d.CurrentMembersSHA256)).Scan(&ok); err != nil || ok {
			t.Fatal("M105 pure receipt field binding accepted", field, err)
		}
	}
	for _, seconds := range []int{899, 900} {
		var ok bool
		if err = h.db.QueryRow(`SELECT public.unknown_maintenance_nonce_acquire_receipt_valid105(jsonb_populate_record(NULL::public.capacity_dispatch_unknown_maintenance_dispositions,jsonb_set(to_jsonb(d),'{recorded_at}',to_jsonb($2::timestamptz)))) FROM capacity_dispatch_unknown_maintenance_dispositions d WHERE job_id=$1`, h.request.JobID, h.lease.Add(time.Duration(seconds)*time.Second)).Scan(&ok); err != nil || ok != (seconds == 900) {
			t.Fatal("M105 exact original expiry plus900 boundary", seconds, err, ok)
		}
	}
	for _, kind := range []string{"nonce", "send", "return"} {
		query, args := nonceAcquire105LateInsert(t, h, f, kind)
		_, err = h.db.Exec(query, args...)
		var pg *pq.Error
		if !errors.As(err, &pg) || pg.Code != "P0001" || pg.Message != "prepared-only nonce maintenance challenge is permanently closed" {
			t.Fatal("M105 archived challenge gained a late child", kind, err)
		}
		// The new trigger must not replace an existing missing-parent FK with
		// an invented maintenance error on an unrelated nonexistent challenge.
		args[0] = uuid.NewString()
		_, err = h.db.Exec(query, args...)
		if !errors.As(err, &pg) || pg.Code != "23503" {
			t.Fatal("M105 changed old missing-parent FK behavior", kind, err)
		}
	}
	for _, query := range []string{`UPDATE capacity_dispatch_jobs SET state='unknown' WHERE id=$1`, `UPDATE capacity_dispatch_jobs SET finalization_ack_at=clock_timestamp() WHERE id=$1`, `UPDATE workflow_runs SET error='rewritten original' WHERE id=(SELECT run_id FROM capacity_dispatch_jobs WHERE id=$1)`, `UPDATE capacity_dispatch_unknown_maintenance_dispositions SET reason='different' WHERE job_id=$1`, `DELETE FROM capacity_dispatch_unknown_maintenance_dispositions WHERE job_id=$1`} {
		_, err = h.db.Exec(query, h.request.JobID)
		var pg *pq.Error
		if !errors.As(err, &pg) || pg.Code != "P0001" {
			t.Fatal("M105 original/receipt immutability", err)
		}
	}
	block, migration := nonceAcquire105Down(t, migrations)
	tx, err := h.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	_, err = tx.Exec(block)
	tx.Rollback()
	var down *pq.Error
	if !errors.As(err, &down) || down.Code != "P0001" || down.Message != "used prepared-only nonce maintenance proof is permanent provenance" {
		t.Fatal("M105 exact actual Down must retain used proof", err)
	}
	put("M105-ACTUAL-DOWN-REFUSAL.PUBLIC.json", failedServingWire(t, map[string]any{"sqlstate": string(down.Code), "message": down.Message, "actual_source_block_sha256": capacity.BusinessCreationSHA256([]byte(block)), "migration105_sha256": capacity.BusinessCreationSHA256(migration), "rollback_only": true}))
	// New current policy/member state cannot rewrite a stored historical proof.
	tx, err = h.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	active := true
	_, err = CreateManifestVersionTx(ctx, tx, model.ManifestDocument{APIVersion: "v1", Kind: "capacity_policy", Metadata: model.ManifestMetadataInput{Namespace: h.policy.Metadata.Namespace, Name: h.policy.Metadata.Name, Active: &active}, Spec: h.policy.Spec}, h.policy.Checksum)
	if err != nil {
		tx.Rollback()
		t.Fatal("M105 later ordinary compatible publication", err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, err = h.db.Exec(`INSERT INTO capacity_resource_slots(integration_instance_id,scope_checksum,profile_name,slot,namespace,environment,domain,dimension,resource_id,slot_record,revision,updated_at) SELECT integration_instance_id,scope_checksum,profile_name,2,namespace,environment,domain,dimension,'declared-later-current-member',slot_record,revision,clock_timestamp() FROM capacity_resource_slots LIMIT 1`); err != nil {
		t.Fatal("M105 later declared current membership", err)
	}
	retained, err := ReadCapacityDispatchUnknownMaintenanceDisposition(ctx, h.db, h.request.JobID)
	if err != nil || !reflect.DeepEqual(retained, d) || nonceAcquire105Snapshot(t, h) != before {
		t.Fatal("M105 historical GET depends on later current state", err)
	}
	if err = h.db.QueryRow(`SELECT public.unknown_maintenance_nonce_acquire_receipt_valid105(d) FROM capacity_dispatch_unknown_maintenance_dispositions d WHERE job_id=$1`, h.request.JobID).Scan(&pure); err != nil || !pure {
		t.Fatal("M105 pure archived receipt followed later policy/member state", err)
	}
	put("M105-DECLARED-HISTORICAL-OPERATOR-WITNESS.PUBLIC.json", failedServingWire(t, map[string]any{"schema": "nonce_acquire105_declared_historical_operator_fixture_v1", "fixture_only": true, "mature_history_constructed_before_first_insert": true, "unfiltered_same_slot_confirmed_families": priorFamilies, "exact_current_physical_family_selected": selected, "unselected_prior_family_declared_storage_only": true, "duplicate_same_full_tuple_refused_23505_before_seal": true, "live_900_second_itinerary_claimed": false, "unchanged_M87_nine_field_operator_and_GET": true, "CAS_refusals": len(cas), "other_active_policy_refused_by_existing_unique_23505": otherActiveStorageRefused, "same_request_race_winners": winners, "old87_result_and91_admission_still_refuse": true, "original_job_run_challenge_authority_and_ACK_preserved": true, "historical_GET_after_later_policy_and_members": true, "record": d}))
}

func nonceAcquire105DifferentDigest(value string) string {
	first := byte('0')
	if value[0] == first {
		first = '1'
	}
	return string(first) + value[1:]
}

func nonceAcquire105ProofVectors(t *testing.T, h nonceAcquire105Historical, raw []byte, put func(string, []byte)) {
	t.Helper()
	var scan map[string]json.RawMessage
	if json.Unmarshal(raw, &scan) != nil {
		t.Fatal("M105 scan JSON")
	}
	proof := scan["nonce_acquire_prepared_only"]
	var positive bool
	if err := h.db.QueryRow(`SELECT public.unknown_maintenance_nonce_acquire_proof_valid105($1::jsonb)`, string(proof)).Scan(&positive); err != nil || !positive {
		t.Fatal("M105 genuine stored proof positive before negatives", err)
	}
	checked := 0
	for _, key := range []string{"schema", "dispatch", "run", "policy", "intent", "membership", "challenge", "authority_issue", "policy_lineage"} {
		var ok bool
		if err := h.db.QueryRow(`SELECT public.unknown_maintenance_nonce_acquire_proof_valid105($1::jsonb-$2::text)`, string(proof), key).Scan(&ok); err != nil || ok {
			t.Fatal("M105 missing proof field accepted", key, err)
		}
		checked++
	}
	for _, key := range []string{"slot", "grant", "preregistration", "enrollment", "installation"} {
		var ok bool
		if err := h.db.QueryRow(`SELECT public.unknown_maintenance_nonce_acquire_proof_valid105(jsonb_set($1::jsonb,'{membership}',($1::jsonb->'membership')-$2::text))`, string(proof), key).Scan(&ok); err != nil || ok {
			t.Fatal("M105 missing whole birth member row accepted", key, err)
		}
		checked++
	}
	vectors := []struct{ name, path, value string }{
		{"schema", "schema", `"caller-proof"`},
		{"ACK", "dispatch,finalization_ack_at", `"2020-01-01T00:00:00Z"`},
		{"return_error", "dispatch,return_error", `"changed"`},
		{"finalization_error", "dispatch,finalization_error", `"uncertain"`},
		{"envelope_wire", "dispatch,envelope_sha256", `"` + strings.Repeat("0", 64) + `"`},
		{"run_status", "run,status", `"succeeded"`},
		{"run_error", "run,error", `"changed"`},
		{"reason", "run,result,steps,0,metadata,reason", `"down_window_pending"`},
		{"mode", "run,result,steps,0,metadata,mode", `"provision"`},
		{"stage", "run,result,steps,3,metadata,original_guest_notify_refusal_stage", `"nonce_finalize"`},
		{"HTTP_status", "run,result,steps,3,metadata,original_guest_notify_nonce_http_status", `200`},
		{"mutating_step", "run,result,steps,1,status", `"succeeded"`},
		{"policy_active", "policy,active", `false`},
		{"policy_checksum", "policy,checksum", `"` + nonceAcquire105DifferentDigest(h.policy.Checksum) + `"`},
		{"epoch", "intent,generation", `0`},
		{"lease", "intent,lease_owner", `"caller-owner"`},
		{"decision", "intent,decision,action", `"provision"`},
		{"member_id", "membership,slot,resource_id", `"foreign-resource"`},
		{"member_scope", "membership,slot,scope_checksum", `"foreign-scope"`},
		{"birth_generation", "membership,grant,generation", `0`},
		{"birth_state", "membership,grant,state", `"issued"`},
		{"prereg_wire", "membership,preregistration,original_wire", `"\\x7b7d"`},
		{"enrollment_wire", "membership,enrollment,receipt_wire", `"\\x7b7d"`},
		{"installation_wire", "membership,installation,original_wire", `"\\x7b7d"`},
		{"publication_phase", "challenge,phase", `"read"`},
		{"publication_record", "challenge,record_challenge_id", `"` + uuid.NewString() + `"`},
		{"publication_wire", "challenge,original_wire", `"\\x7b7d"`},
		{"publication_nonce", "challenge,nonce_sha256", `""`},
		{"publication_fence", "challenge,fence", `0`},
		{"publication_executor", "challenge,executor_id", `"` + uuid.NewString() + `"`},
		{"publication_time", "challenge,recorded_at", `"2100-01-01T00:00:00Z"`},
		{"authority_wire", "authority_issue,original_wire", `"\\x7b7d"`},
		{"authority_issue", "authority_issue,issue_id", `"` + uuid.NewString() + `"`},
		{"authority_hash", "authority_issue,issued_wire_sha256", `"` + strings.Repeat("0", 64) + `"`},
		{"lineage", "policy_lineage", `[]`},
	}
	for _, v := range vectors {
		var ok bool
		var changed []byte
		if err := h.db.QueryRow(`SELECT jsonb_set($1::jsonb,$2::text[],$3::jsonb,true)::text`, string(proof), pq.Array(strings.Split(v.path, ",")), v.value).Scan(&changed); err != nil || bytes.Equal(changed, proof) {
			t.Fatal("M105 negative proof operand must change", v.name, err)
		}
		if err := h.db.QueryRow(`SELECT public.unknown_maintenance_nonce_acquire_proof_valid105($1::jsonb)`, string(changed)).Scan(&ok); err != nil || ok {
			t.Fatal("M105 pure proof gate accepted", v.name, err)
		}
		checked++
	}
	var base map[string]json.RawMessage
	if json.Unmarshal(scan["base"], &base) != nil || len(base) != 47 {
		t.Fatal("M105 exact inherited base47")
	}
	for key, original := range base {
		var changed map[string]json.RawMessage
		if json.Unmarshal(raw, &changed) != nil {
			t.Fatal("M105 original scan clone")
		}
		var bad map[string]json.RawMessage
		_ = json.Unmarshal(scan["base"], &bad)
		value := json.RawMessage("1")
		if string(original) == "false" {
			value = json.RawMessage("true")
		} else if len(original) > 0 && original[0] == '"' {
			value = json.RawMessage(`"wrong-schema"`)
		} else {
			n, err := strconv.ParseInt(string(original), 10, 64)
			if err != nil {
				t.Fatal("M105 actual base counter must be an integer", key)
			}
			value = json.RawMessage(strconv.FormatInt(n+1, 10))
		}
		bad[key] = value
		changed["base"] = failedServingWire(t, bad)
		var ok bool
		if err := h.db.QueryRow(`SELECT public.unknown_maintenance_dispatch_effect_scan_tolerable($1::jsonb)`, string(failedServingWire(t, changed))).Scan(&ok); err != nil || ok {
			t.Fatal("M105 inherited effect/schema/false-claim gate accepted", key, err)
		}
	}
	put("M105-PROOF-AND-EFFECT-REFUSALS.PUBLIC.json", failedServingWire(t, map[string]any{"schema": "nonce_acquire105_closed_proof_refusals_v1", "nested_proof_fields": 9, "whole_member_rows": 5, "proof_refusals": checked, "inherited_base_fields_checked": len(base), "all_refused": true, "fixture_only": true}))
}

func nonceAcquire105LateInsert(t *testing.T, h nonceAcquire105Historical, f *failedServingFixture, kind string) (string, []any) {
	t.Helper()
	switch kind {
	case "nonce":
		final := h.lateNonce
		transport := failedServingHTTP(t, final.GuestNonce, h.publication.IssuedAt.Add(time.Millisecond))
		transport.Body = nil
		return `INSERT INTO capacity_guest_notify_canary_nonces(challenge_id,guest_nonce_sha256,nonce_wire,final_challenge_wire,final_challenge_sha256,original_transport,recorded_at) VALUES($1,$2,$3,$4,$5,$6::jsonb,$7)`, []any{h.publication.ChallengeID, final.GuestNonce.NonceSHA256, failedServingWire(t, final.GuestNonce), failedServingWire(t, final), capacity.GuestRetirementSHA(final), string(failedServingWire(t, transport)), h.publication.IssuedAt.Add(6 * time.Millisecond)}
	case "send":
		return `INSERT INTO capacity_guest_notify_canary_sends(challenge_id,request_sha256,possible_send_at,original_deadline,recorded_at) VALUES($1,$2,$3,$4,$3)`, []any{h.publication.ChallengeID, strings.Repeat("d", 64), h.publication.IssuedAt.Add(time.Millisecond), h.publication.OriginalDeadline}
	case "return":
		return `INSERT INTO capacity_guest_notify_canary_returns(challenge_id,outcome,return_sha256,original_wire,original_transport,recorded_at) VALUES($1,'held',$2,NULL,'{}'::jsonb,$3)`, []any{h.publication.ChallengeID, strings.Repeat("e", 64), h.publication.IssuedAt.Add(time.Millisecond)}
	default:
		t.Fatal("closed M105 race kind")
		return "", nil
	}
}

func nonceAcquire105LateRace(t *testing.T, h nonceAcquire105Historical, f *failedServingFixture, kind string, writerFirst bool, put func(string, []byte)) {
	t.Helper()
	ctx, stop := context.WithTimeout(context.Background(), 10*time.Second)
	defer stop()
	connection, err := h.db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	var pid int
	if err = connection.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
		t.Fatal(err)
	}
	query, args := nonceAcquire105LateInsert(t, h, f, kind)
	operator := make(chan error, 1)
	writer := make(chan error, 1)
	if writerFirst {
		tx, e := connection.BeginTx(ctx, nil)
		if e != nil {
			t.Fatal(e)
		}
		defer tx.Rollback()
		if _, e = tx.ExecContext(ctx, query, args...); e != nil {
			t.Fatal("M105 declared append must reach its shared scope trigger", kind, e)
		}
		go func() {
			_, e := DisposeUnknownMaintenanceDispatch(ctx, h.db, h.request, h.barrier, abandonedAllow)
			operator <- e
		}()
		nonceAcquire105WaitBlocked(t, ctx, h.db, 0, pid)
		if e = tx.Commit(); e != nil {
			t.Fatal(e)
		}
		if e = <-operator; e == nil {
			t.Fatal("M105 operator ignored a first committed nonce", kind)
		}
		var receipts int
		if e = h.db.QueryRowContext(ctx, `SELECT count(*) FROM capacity_dispatch_unknown_maintenance_dispositions WHERE job_id=$1`, h.request.JobID).Scan(&receipts); e != nil || receipts != 0 {
			t.Fatal("M105 refused race wrote receipt", e, receipts)
		}
	} else {
		entered, proceed := make(chan struct{}), make(chan struct{})
		var once sync.Once
		go func() {
			_, e := DisposeUnknownMaintenanceDispatch(ctx, h.db, h.request, h.barrier, func(ctx context.Context) error {
				var e error
				once.Do(func() {
					close(entered)
					select {
					case <-proceed:
					case <-ctx.Done():
						e = ctx.Err()
					}
				})
				return e
			})
			operator <- e
		}()
		select {
		case <-entered:
		case <-ctx.Done():
			t.Fatal("M105 operator did not reach real revalidation", kind)
		}
		go func() { _, e := connection.ExecContext(ctx, query, args...); writer <- e }()
		nonceAcquire105WaitBlocked(t, ctx, h.db, pid, 0)
		close(proceed)
		if e := <-operator; e != nil {
			t.Fatal("M105 first operator failed real commit", kind, e)
		}
		var pg *pq.Error
		if e := <-writer; !errors.As(e, &pg) || pg.Code != "P0001" || pg.Message != "prepared-only nonce maintenance challenge is permanently closed" {
			t.Fatal("M105 later writer escaped archived challenge freeze", kind, e)
		}
	}
	put("M105-SCOPE-RACE-"+strings.ToUpper(kind)+".PUBLIC.json", failedServingWire(t, map[string]any{"schema": "nonce_acquire105_real_backend_race_v1", "kind": kind, "writer_committed_first": writerFirst, "actual_blocking_observed": true, "original_challenge_not_rewritten": true, "fixture_only": true}))
}

func nonceAcquire105WaitBlocked(t *testing.T, ctx context.Context, db *sql.DB, targetPID, holderPID int) {
	t.Helper()
	for {
		var blocked bool
		if err := db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity a WHERE a.datname=current_database() AND a.pid<>pg_backend_pid() AND (($1::int>0 AND a.pid=$1::int AND cardinality(pg_blocking_pids(a.pid))>0) OR ($1::int=0 AND $2::int=ANY(pg_blocking_pids(a.pid)))))`, targetPID, holderPID).Scan(&blocked); err != nil {
			t.Fatal("M105 actual backend blocking query", err)
		}
		if blocked {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal("M105 expected shared scope serialization was not observed")
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func nonceAcquire105Down(t *testing.T, migrations string) (string, []byte) {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(migrations, "00105_*.sql"))
	if err != nil || len(files) != 1 {
		t.Fatal("one exact Source105 migration required", err, files)
	}
	raw, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	down := strings.SplitN(string(raw), "-- +goose Down", 2)
	if len(down) != 2 {
		t.Fatal("M105 actual Source Down required")
	}
	parts := strings.SplitN(down[1], "-- +goose StatementBegin", 2)
	if len(parts) != 2 {
		t.Fatal("M105 exact first Down block")
	}
	body := strings.SplitN(parts[1], "-- +goose StatementEnd", 2)
	if len(body) != 2 {
		t.Fatal("M105 exact Down block end")
	}
	return body[0], raw
}

func nonceAcquire105OldGoose(t *testing.T, db *sql.DB, migrations string, put func(string, []byte)) {
	t.Helper()
	oldDir := t.TempDir()
	entries, err := os.ReadDir(migrations)
	if err != nil {
		t.Fatal(err)
	}
	versions := map[int]bool{}
	files := []map[string]any{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		if len(e.Name()) < 6 || e.Name()[5] != '_' {
			t.Fatal("canonical migration filename", e.Name())
		}
		n, err := strconv.Atoi(e.Name()[:5])
		if err != nil {
			t.Fatal(err)
		}
		if n > 104 {
			continue
		}
		if versions[n] || n < 1 || n == 40 {
			t.Fatal("exact old migration roster", e.Name())
		}
		versions[n] = true
		raw, err := os.ReadFile(filepath.Join(migrations, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(oldDir, e.Name()), raw, 0600); err != nil {
			t.Fatal(err)
		}
		copied, err := os.ReadFile(filepath.Join(oldDir, e.Name()))
		if err != nil || !bytes.Equal(raw, copied) {
			t.Fatal("exact old Goose Source copy", e.Name(), err)
		}
		files = append(files, map[string]any{"path": e.Name(), "bytes": len(raw), "sha256": capacity.BusinessCreationSHA256(raw)})
	}
	if len(versions) != 103 {
		t.Fatal("103 exact Source migrations through104 required", len(versions))
	}
	for n := 1; n <= 104; n++ {
		if n != 40 && !versions[n] {
			t.Fatal("missing original migration", n)
		}
	}
	before := installedReadinessCatalog(t, db)
	put("M105-OLD-GOOSE105-BEFORE.original.json", before)
	// This is the unchanged production Goose Up library path with the exact
	// old image's migration directory, not a claim to boot the old image here.
	if err = goose.UpContext(context.Background(), db, oldDir); err != nil {
		t.Fatal("old Goose directory must no-op on complete DB105", err)
	}
	after := installedReadinessCatalog(t, db)
	put("M105-OLD-GOOSE105-AFTER.original.json", after)
	if !bytes.Equal(before, after) {
		t.Fatal("old Goose changed whole DB105 history/catalog")
	}
	put("M105-OLD-GOOSE104-DIRECTORY-NOOP.PUBLIC.json", failedServingWire(t, map[string]any{"schema": "nonce_acquire105_old_goose_directory_noop_v1", "local_migration_files": files, "local_max": 104, "database_schema": 105, "whole_catalog_and_history_before_sha256": capacity.BusinessCreationSHA256(before), "whole_catalog_and_history_after_sha256": capacity.BusinessCreationSHA256(after), "whole_equal": true, "old_image_boot_claimed": false, "fixture_only": true}))
}

func nonceAcquire105Catalog(t *testing.T, db *sql.DB, migrations string, before, after []byte, put func(string, []byte)) {
	t.Helper()
	var a, b map[string]json.RawMessage
	if json.Unmarshal(before, &a) != nil || json.Unmarshal(after, &b) != nil || len(a) != len(b) {
		t.Fatal("M105 complete catalogs")
	}
	for _, field := range []string{"server_version_num", "columns", "indexes"} {
		if !bytes.Equal(a[field], b[field]) {
			t.Fatal("M105 changed unrelated public catalog", field)
		}
	}
	var aw, bw string
	var ah, bh []map[string]any
	if json.Unmarshal(a["history_wire"], &aw) != nil || json.Unmarshal(b["history_wire"], &bw) != nil || json.Unmarshal([]byte(aw), &ah) != nil || json.Unmarshal([]byte(bw), &bh) != nil || len(bh) != len(ah)+1 || !reflect.DeepEqual(ah, bh[:len(ah)]) || ah[len(ah)-1]["version_id"] != float64(104) || bh[len(ah)]["version_id"] != float64(105) || bh[len(ah)]["is_applied"] != true {
		t.Fatal("M105 sole full history append")
	}
	var af, bf []map[string]any
	if json.Unmarshal(a["functions"], &af) != nil || json.Unmarshal(b["functions"], &bf) != nil {
		t.Fatal("M105 function catalogs")
	}
	key := func(v map[string]any) string { return v["name"].(string) + "(" + v["arguments"].(string) + ")" }
	by := map[string]map[string]any{}
	for _, v := range bf {
		by[key(v)] = v
	}
	changed := []string{}
	legacyBodies := map[string]string{}
	for _, old := range af {
		v, exists := by[key(old)]
		if !exists {
			t.Fatal("M105 removed prior function", old["name"])
		}
		if !reflect.DeepEqual(old, v) {
			changed = append(changed, old["name"].(string))
			body := strings.SplitN(old["definition"].(string), "AS $function$", 2)
			if len(body) != 2 {
				t.Fatal("exact old pg_get_functiondef body required", old["name"])
			}
			legacyBodies[old["name"].(string)] = strings.SplitN(body[1], "$function$", 2)[0]
		}
		delete(by, key(old))
	}
	added := []string{}
	for _, v := range by {
		added = append(added, v["name"].(string))
	}
	sort.Strings(changed)
	sort.Strings(added)
	wantAdded := []string{"guard_unknown_maintenance_nonce_acquire_canary105", "guard_unknown_maintenance_nonce_acquire_receipt105", "unknown_maintenance_dispatch_effect_scan87_legacy105", "unknown_maintenance_dispatch_scan_tolerable87_legacy105", "unknown_maintenance_nonce_acquire_effect_scan105", "unknown_maintenance_nonce_acquire_proof_valid105", "unknown_maintenance_nonce_acquire_receipt_valid105", "unknown_maintenance_nonce_acquire_result_valid105", "unknown_maintenance_nonce_acquire_scan_tolerable105"}
	if !reflect.DeepEqual(changed, []string{"unknown_maintenance_dispatch_effect_scan", "unknown_maintenance_dispatch_effect_scan_tolerable"}) || !reflect.DeepEqual(added, wantAdded) {
		t.Fatal("M105 exact two dispatch wrappers and nine additive functions", changed, added)
	}
	for oldName, legacyName := range map[string]string{"unknown_maintenance_dispatch_effect_scan": "unknown_maintenance_dispatch_effect_scan87_legacy105", "unknown_maintenance_dispatch_effect_scan_tolerable": "unknown_maintenance_dispatch_scan_tolerable87_legacy105"} {
		var actual string
		if err := db.QueryRow(`SELECT prosrc FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public' AND p.proname=$1`, legacyName).Scan(&actual); err != nil || actual != legacyBodies[oldName] {
			t.Fatal("M105 changed exact legacy87 fallback body", oldName, err)
		}
	}
	for _, field := range []string{"constraints", "triggers"} {
		var old, next []map[string]any
		if json.Unmarshal(a[field], &old) != nil || json.Unmarshal(b[field], &next) != nil {
			t.Fatal("M105 complete object roster", field)
		}
		objects := map[string]map[string]any{}
		for _, v := range next {
			objects[v["table"].(string)+"/"+v["name"].(string)] = v
			if field == "constraints" && v["validated"] != true {
				t.Fatal("M105 unvalidated constraint", v)
			}
		}
		for _, v := range old {
			k := v["table"].(string) + "/" + v["name"].(string)
			if !reflect.DeepEqual(v, objects[k]) {
				t.Fatal("M105 changed old constraint/trigger", k)
			}
			delete(objects, k)
		}
		keys := []string{}
		for k := range objects {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		want := []string{"capacity_dispatch_unknown_maintenance_dispositions/unknown_maintenance_nonce_acquire_proof105"}
		if field == "triggers" {
			want = []string{"capacity_dispatch_unknown_maintenance_dispositions/unknown_maintenance_nonce_acquire_receipt105", "capacity_guest_notify_canary_nonces/unknown_nonce_acquire_nonces105", "capacity_guest_notify_canary_returns/unknown_nonce_acquire_returns105", "capacity_guest_notify_canary_sends/unknown_nonce_acquire_sends105"}
		}
		if !reflect.DeepEqual(keys, want) {
			t.Fatal("M105 exact additive constraint/trigger inventory", field, keys)
		}
	}
	_, migration := nonceAcquire105Down(t, migrations)
	up := strings.SplitN(string(migration), "-- +goose Down", 2)[0]
	for _, name := range append(added, changed...) {
		pos := strings.Index(up, "CREATE OR REPLACE FUNCTION public."+name+"(")
		if pos < 0 {
			t.Fatal("M105 exact Source function", name)
		}
		part := up[pos:]
		body := strings.SplitN(part, "AS $$", 2)
		if len(body) != 2 {
			t.Fatal("M105 exact Source function delimiter", name)
		}
		expected := strings.SplitN(body[1], "$$;", 2)[0]
		var actual string
		if err := db.QueryRow(`SELECT prosrc FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public' AND p.proname=$1`, name).Scan(&actual); err != nil || actual != expected {
			t.Fatal("M105 installed function differs from actual Source", name, err)
		}
	}
	put("M105-PG-CHECK-DEPARSE.RESULT.PUBLIC.json", failedServingWire(t, map[string]any{"schema": "nonce_acquire105_complete_catalog_v1", "source_commit": capacity.CurrentGuestCoreSource(), "migration105_sha256": capacity.BusinessCreationSHA256(migration), "whole_history_sole105_append": true, "changed_functions": changed, "added_functions": added, "legacy87_bodies_exact": true, "prior87_91_104_and_all_other_public_objects_preserved": true, "new_constraints": 1, "new_triggers": 4, "fixture_only": true}))
}

func nonceAcquire105EmptyDown(t *testing.T, migrations string, put func(string, []byte)) {
	t.Helper()
	db := preActionPlanDB(t, &preActionPlanDBOwner{})
	if err := goose.UpToContext(context.Background(), db, migrations, 104); err != nil {
		t.Fatal(err)
	}
	before := installedReadinessCatalog(t, db)
	put("M105-EMPTY-DOWN-BEFORE104.original.json", before)
	if err := goose.UpToContext(context.Background(), db, migrations, 105); err != nil {
		t.Fatal(err)
	}
	if err := goose.DownTo(db, migrations, 104); err != nil {
		t.Fatal("M105 empty actual Down", err)
	}
	after := installedReadinessCatalog(t, db)
	put("M105-EMPTY-DOWN-AFTER104.original.json", after)
	var a, b map[string]json.RawMessage
	if json.Unmarshal(before, &a) != nil || json.Unmarshal(after, &b) != nil {
		t.Fatal("M105 empty Down catalogs")
	}
	// The pinned Goose PostgreSQL dialect deletes this version on Down;
	// it does not append a false history row. Require its actual exact restore.
	if !bytes.Equal(a["history_wire"], b["history_wire"]) {
		t.Fatal("M105 empty Down must restore exact prior104 history")
	}
	delete(a, "history_wire")
	delete(b, "history_wire")
	if !reflect.DeepEqual(a, b) {
		t.Fatal("M105 empty Down did not restore complete104 catalog")
	}
	version, err := goose.GetDBVersion(db)
	if err != nil || version != 104 {
		t.Fatal("M105 empty Down current version", version, err)
	}
	put("M105-EMPTY-DOWN-RESTORED104.PUBLIC.json", failedServingWire(t, map[string]any{"schema": "nonce_acquire105_empty_down_v1", "whole_catalog_objects_restored104": true, "whole_prior104_goose_history_restored": true, "pinned_Goose_PostgreSQL_Down_deletes_version105_row": true, "schema_after": version, "before104_sha256": capacity.BusinessCreationSHA256(before), "after_Down104_sha256": capacity.BusinessCreationSHA256(after), "fixture_only": true}))
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
}
