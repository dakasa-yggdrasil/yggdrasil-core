//go:build recoveryfixture && !nativequalification

package repository

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// Signed synthetic operands in a disposable CI database, with every FK and
// trigger enabled. This is repository integration evidence, never production
// Guest/process custody, provider observation or business-effect evidence.
type failedTailFixture struct {
	db               *sql.DB
	p                model.CapacityPolicySpec
	policy, workflow model.Manifest
	steps            []model.WorkflowStepSpec
	store            CapacityStore
	pre              [2]model.CapacityGuestOriginalProvisioningPreregistration
	reg              [2]model.CapacityGuestOriginalProvisioningRegistration
	receipt          [2]model.CapacityGuestOriginalProvisioningReceipt
	intent           model.CapacityIntent
	requested        FailedInstalledGuestDisposal
	claimJob         CapacityDispatchJob
	claimEnvelope    CapacityDispatchEnvelope
	rbac             CapacityDispatchManifestPin
	tick             int
}

func tailFixtureWire(t *testing.T, v any) []byte {
	t.Helper()
	w, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func (f *failedTailFixture) exec(t *testing.T, query string, args ...any) {
	t.Helper()
	if _, err := f.db.Exec(query, args...); err != nil {
		t.Fatal("signed tail fixture", err)
	}
}

func newFailedTailFixture(t *testing.T) *failedTailFixture {
	t.Helper()
	capacity.RecoveryFixtureApprovalScope(t)
	f := &failedTailFixture{db: recoveryTestIsolatedDB(t)}
	f.db.SetMaxOpenConns(2)
	p, b, reg1, receipt1, installed1 := capacity.RecoveryFixtureInstalledSlot(t, 1)
	_, _, reg2, receipt2, installed2 := capacity.RecoveryFixtureInstalledSlot(t, 2)
	f.reg, f.receipt = [2]model.CapacityGuestOriginalProvisioningRegistration{reg1, reg2}, [2]model.CapacityGuestOriginalProvisioningReceipt{receipt1, receipt2}
	for i := range f.pre {
		f.pre[i] = f.reg[i].Result.ProductionClock.Authority.Preregistration
	}
	p.ExecutionEnabled, p.LeaseSeconds = true, 30
	p.GuestNotifyCanaryBinding.MinimumPublicationIntervalSeconds = 5
	if err := capacity.RegisterRecoveryFixtureApproval(p, b, "hetzner"); err != nil {
		t.Fatal(err)
	}
	f.p = p
	f.policy = model.Manifest{ID: uuid.MustParse(f.pre[1].PolicyID), Kind: "capacity_policy", Checksum: f.pre[1].PolicyChecksum, Version: 1, Metadata: model.ManifestMetadata{Namespace: "dakasa-production", Name: "recovery-tail-unit", Active: true}, Spec: tailFixtureWire(t, p)}
	steps, err := capacity.OriginalGuestReconcileGraph(f.policy, p)
	if err != nil {
		t.Fatal(err)
	}
	f.steps = steps
	enabled, no := true, false
	wfs := model.WorkflowManifestSpec{Trigger: model.WorkflowTriggerSpec{Mode: "schedule", Enabled: &enabled, Schedule: &model.WorkflowScheduleTriggerSpec{CronExpression: "* * * * *", CatchupPolicy: "skip"}}, Authorization: &model.WorkflowAuthorizationSpec{RBAC: model.ManifestSelector{Namespace: "dakasa-production", Name: "unit-rbac"}}, DispatchMode: "async", InputSchema: model.WorkflowInputSchemaSpec{Required: []string{"policy"}, AdditionalProperties: &no, Properties: map[string]model.IntegrationSchemaProperty{"policy": {Type: "object"}}}, Steps: steps}
	f.workflow = model.Manifest{ID: uuid.MustParse(f.pre[1].WorkflowID), Kind: "workflow", Checksum: f.pre[1].WorkflowChecksum, Version: 1, Metadata: model.ManifestMetadata{Namespace: p.Workflow.Namespace, Name: p.Workflow.Name, Active: true}, Spec: tailFixtureWire(t, wfs)}
	for _, m := range []model.Manifest{f.policy, f.workflow} {
		f.exec(t, `INSERT INTO public.manifests(id,api_version,kind,namespace,name,version,checksum,spec,active)VALUES($1,'v1',$2,$3,$4,1,$5,$6::jsonb,true)`, m.ID, m.Kind, m.Metadata.Namespace, m.Metadata.Name, m.Checksum, string(m.Spec))
	}
	mutation := p.MutationBindings[0]
	f.exec(t, `INSERT INTO public.manifests(id,api_version,kind,namespace,name,version,checksum,spec,active)VALUES($1,'v1','integration_type','test-recovery','unit-type',1,$2,'{}'::jsonb,true)`, mutation.IntegrationTypeID, mutation.IntegrationTypeChecksum)
	ref := tailFixtureWire(t, map[string]any{"type_ref": map[string]any{"manifest_id": mutation.IntegrationTypeID}})
	f.exec(t, `INSERT INTO public.manifests(id,api_version,kind,namespace,name,version,checksum,spec,active)VALUES($1,'v1','integration_instance','test-recovery','unit-instance',1,$2,$3::jsonb,true)`, mutation.IntegrationInstanceID, mutation.IntegrationChecksum, string(ref))
	for i := range f.pre {
		pre, reg, receipt := f.pre[i], f.reg[i], f.receipt[i]
		witness := reg.Result.ProductionClock.Authority.CreateWitness
		tx, err := f.db.Begin()
		if err != nil {
			t.Fatal(err)
		}
		g := guestOriginalStorageFixture{pre: pre, binding: b, wire: tailFixtureWire(t, pre), bindingWire: tailFixtureWire(t, b)}
		guestOriginalStoragePre(t, tx, context.Background(), g, g.wire, g.wire, pre.OriginalDeadline)
		if err = tx.Commit(); err != nil {
			t.Fatal(err)
		}
		providerReturn := &model.CapacityOriginalProviderCreateReturn{Schema: "hetzner_original_create_server_return_v1", Provider: "hetzner", AdapterSourceCommit: mutation.OriginalProviderSourceCommit, GrantID: pre.OriginalCreateGrantID, AttemptID: witness.OriginalCreateAttemptID, RequestSHA256: pre.OriginalCreateRequestSHA256, ResourceID: witness.Tuple.ResourceID, ResourceCreatedAt: witness.Tuple.CreatedAt, NextActionIDs: []string{}, CalledAt: pre.ReservedAt.Format(time.RFC3339Nano), ReturnedAt: witness.OriginalCreateReturnedAt.Format(time.RFC3339Nano), ContextDeadline: pre.OriginalDeadline.Format(time.RFC3339Nano), ResponseStatus: 201, ResponseBodySHA256: strings.Repeat("a", 64), ResponseBytes: 2}
		created := capacityMutationRecord{PolicyID: f.policy.ID, PolicyChecksum: f.policy.Checksum, WorkflowID: f.workflow.ID, Binding: mutation, Generation: pre.Generation, FencingToken: pre.Fence, ExecutorID: pre.ExecutorID, LeaseOwner: pre.LeaseOwner, AttemptID: witness.OriginalCreateAttemptID, Grant: model.CapacityMutationGrant{GrantID: pre.OriginalCreateGrantID, BindingName: mutation.Name, IntegrationInstanceID: mutation.IntegrationInstanceID, ScopeChecksum: mutation.ScopeChecksum, ProfileName: mutation.ProfileName, Slot: pre.Slot, Capability: mutation.EnsureCapability, RequestSHA256: pre.OriginalCreateRequestSHA256, State: "confirmed"}, Settlement: &model.CapacityMutationSettleRequest{GrantID: pre.OriginalCreateGrantID, AttemptID: witness.OriginalCreateAttemptID, RequestSHA256: pre.OriginalCreateRequestSHA256, Outcome: "accepted", TransportCompleted: true, ResourceID: witness.Tuple.ResourceID, ResourceCreatedAt: witness.Tuple.CreatedAt, NextActionIDs: []string{}, AuxiliaryResources: []model.CapacityMutationAuxiliaryResource{}, AuxiliaryInventoryComplete: true, OriginalProviderCreateReturn: providerReturn}, Proof: &model.CapacityMutationProof{Slot: pre.Slot, ResourceID: witness.Tuple.ResourceID, ResourceCreatedAt: witness.Tuple.CreatedAt}}
		created.Settlement.AuxiliaryResources = []model.CapacityMutationAuxiliaryResource{{Kind: "ssh_key", ID: "signed-fixture-key-" + pre.PreregistrationID, RequiresAbsence: true}}
		f.exec(t, `UPDATE public.capacity_mutation_grants SET namespace=$2,environment=$3,domain=$4,dimension=$5,generation=$6,integration_instance_id=$7,scope_checksum=$8,profile_name=$9,slot=$10,state='confirmed',grant_record=$11::jsonb WHERE id=$1`, pre.OriginalCreateGrantID, f.policy.Metadata.Namespace, p.Environment, p.Domain, p.Dimension, pre.Generation, mutation.IntegrationInstanceID, mutation.ScopeChecksum, mutation.ProfileName, pre.Slot, string(tailFixtureWire(t, created)))
		f.exec(t, `INSERT INTO public.capacity_guest_original_create_witnesses(preregistration_id,original_create_attempt_id,resource_tuple_sha256,witness_sha256,original_wire,original_record,recorded_at)VALUES($1,$2,$3,$4,$5,$6::jsonb,$7)`, pre.PreregistrationID, witness.OriginalCreateAttemptID, capacity.GuestRetirementSHA(witness.Tuple), capacity.GuestRetirementSHA(witness), tailFixtureWire(t, witness), string(tailFixtureWire(t, witness)), witness.ObservedAt)
		f.exec(t, `INSERT INTO public.capacity_vm_original_enrollments(preregistration_id,resource_tuple_sha256,enrollment_sha256,original_provisioning_sha256,enrollment_record,recorded_at,registration_wire,receipt_wire)VALUES($1,$2,$3,$4,$5::jsonb,$6,$7,$8)`, pre.PreregistrationID, capacity.GuestRetirementSHA(receipt.Enrollment.Statement.Tuple), capacity.GuestRetirementSHA(receipt.Enrollment), receipt.OriginalProvisioningSHA256, string(tailFixtureWire(t, receipt.Enrollment)), receipt.RecordedAt, tailFixtureWire(t, reg), tailFixtureWire(t, receipt))
		installed := []model.CapacityGuestOriginalInstallationConfirmation{installed1, installed2}[i]
		f.exec(t, `INSERT INTO public.capacity_guest_original_installations(preregistration_id,original_wire,confirmation_sha256,recorded_at)VALUES($1,$2,$3,$4)`, pre.PreregistrationID, tailFixtureWire(t, installed), capacity.GuestRetirementSHA(installed), receipt.RecordedAt.Add(time.Second))
		tx, err = f.db.Begin()
		if err != nil {
			t.Fatal(err)
		}
		slot := capacityResourceSlot{BindingName: mutation.Name, ProfileName: mutation.ProfileName, DesiredSpecSHA256: mutation.Slots[i].DesiredSpecSHA256, ResourceID: witness.Tuple.ResourceID, ResourceCreatedAt: witness.Tuple.CreatedAt, ObservedAt: time.Now().UTC(), ReceiptRef: "signed-test-fixture"}
		if err = saveMutationSlot(context.Background(), tx, f.policy.Metadata.Namespace, p, mutation, i+1, slot); err != nil {
			t.Fatal(err)
		}
		if err = tx.Commit(); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().UTC()
	expires := now.Add(2 * time.Second)
	snapshot := model.CapacitySnapshot{TargetIdentity: p.TargetIdentity, Owner: p.Owner, ResourceUID: "fixture-resource", WorkloadUID: "fixture-workload", WorkloadResourceVersion: "1", ResourceVersion: "1", Profile: mutation.ProfileName, Units: 1, ObservedAt: now}
	f.intent = model.CapacityIntent{Namespace: f.policy.Metadata.Namespace, PolicyName: f.policy.Metadata.Name, PolicyID: f.policy.ID, PolicyChecksum: f.policy.Checksum, Environment: p.Environment, Domain: p.Domain, Dimension: p.Dimension, Generation: 2, FencingToken: 2, Phase: "preparing", LeaseOwner: f.pre[1].LeaseOwner, LeaseExecutorID: f.pre[1].ExecutorID, LeaseExpiresAt: &expires, Decision: model.CapacityDecision{Action: "expand", Profile: mutation.ProfileName, Units: 2, Floor: 1}, BaselineSnapshot: snapshot, Assessment: model.CapacityAssessment{Snapshot: snapshot}, UpdatedAt: now}
	f.exec(t, `INSERT INTO public.capacity_intents(namespace,environment,domain,dimension,intent)VALUES($1,$2,$3,$4,$5::jsonb)`, f.policy.Metadata.Namespace, p.Environment, p.Domain, p.Dimension, string(tailFixtureWire(t, f.intent)))
	f.store = CapacityStore{DB: f.db, ExecutionEnabled: true, WorkflowID: f.workflow.ID, ExecutorID: f.pre[1].ExecutorID}
	return f
}

func (f *failedTailFixture) dispatch(t *testing.T) (CapacityDispatchEnvelope, CapacityDispatchJob) {
	t.Helper()
	if f.tick == 0 {
		f.rbac = CapacityDispatchManifestPin{ID: uuid.New(), Namespace: f.policy.Metadata.Namespace, Name: "unit-rbac", Version: 1, Checksum: capacityDispatchSHA([]byte("fixture-rbac"))}
		f.exec(t, `INSERT INTO public.manifests(id,api_version,kind,namespace,name,version,checksum,spec,active)VALUES($1,'v1','rbac',$2,$3,$4,$5,'{}'::jsonb,true)`, f.rbac.ID, f.rbac.Namespace, f.rbac.Name, f.rbac.Version, f.rbac.Checksum)
	}
	pin := func(m model.Manifest) CapacityDispatchManifestPin {
		return CapacityDispatchManifestPin{ID: m.ID, Namespace: m.Metadata.Namespace, Name: m.Metadata.Name, Version: m.Version, Checksum: m.Checksum}
	}
	e := CapacityDispatchEnvelope{Protocol: CapacityDispatchProtocol, JobID: uuid.New(), RunID: uuid.New(), Realm: f.policy.Metadata.Namespace, Environment: f.p.Environment, Domain: f.p.Domain, Dimension: f.p.Dimension, SourceTick: time.Now().UTC().Add(time.Duration(f.tick) * time.Second).Truncate(time.Second).Format(time.RFC3339), Policy: pin(f.policy), Workflow: pin(f.workflow), RBAC: f.rbac, MachinePrincipalID: "capacity-controller", PrincipalSHA256: capacityDispatchSHA([]byte("test-principal")), BindingSHA256: capacityDispatchSHA([]byte("test-binding"))}
	f.tick++
	e.Inputs = map[string]any{"policy": map[string]any{"namespace": f.policy.Metadata.Namespace, "name": f.policy.Metadata.Name}}
	e.Metadata = map[string]any{WorkflowRunCreatorMachinePrincipalMetadataKey: e.MachinePrincipalID, "triggered_by": "workflow_scheduler", "manifest_id": f.workflow.ID.String(), "scheduled_for": e.SourceTick, "capacity_dispatch_job_id": e.JobID.String(), "capacity_dispatch_protocol": e.Protocol}
	var err error
	e.InputsSHA256, e.MetadataSHA256, err = CapacityDispatchEnvelopeHashes(e)
	if err != nil {
		t.Fatal(err)
	}
	capacityDispatchEnqueueFixture(t, f.db, e)
	j := capacityDispatchClaimFixture(t, f.db, e, 30*time.Second)
	j, err = StartCapacityDispatch(context.Background(), f.db, j)
	if err != nil {
		t.Fatal(err)
	}
	return e, j
}

func tailFixtureHTTP(t *testing.T, body any, at time.Time) capacity.GuestOriginalHTTPReturn {
	t.Helper()
	w := tailFixtureWire(t, body)
	sha := capacity.BusinessCreationSHA256(w)
	return capacity.GuestOriginalHTTPReturn{StartedAt: at, DoStartedAt: at.Add(time.Millisecond), DoReturnedAt: at.Add(51 * time.Millisecond), ReadReturnedAt: at.Add(52 * time.Millisecond), CloseReturnedAt: at.Add(53 * time.Millisecond), DriverReturnedAt: at.Add(54 * time.Millisecond), Status: 200, Body: w, ReceivedBodyBytes: len(w), ResponseSHA256: sha, ResponseBodyScope: capacity.GuestOriginalBodyCompleteRead, RetainedPrefixBytes: len(w), RetainedPrefixSHA256: sha}
}

func (f *failedTailFixture) canary(t *testing.T, usage string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	step := f.steps[3]
	if usage == "after_retirement_floor" {
		step = f.steps[4]
	}
	store := f.store.WithOriginalGuestNotifyCanary(step, capacity.CurrentGuestCoreSource())
	core := ed25519.NewKeyFromSeed([]byte(strings.Repeat("c", 32)))
	e := f.receipt[0].Enrollment
	probe := func(c model.CapacityGuestNotifyCanaryChallenge, pub *capacity.GuestNotifyPublicationReply) *capacity.GuestNotifyPublicationReply {
		c = capacity.RecoveryFixtureCanaryNonce(t, c, e)
		nonceAt := time.Now().UTC()
		nonceReturn := tailFixtureHTTP(t, c.GuestNonce, nonceAt)
		if err := store.FinalizeGuestNotifyCanaryNonce(ctx, f.policy, f.intent.Generation, f.intent.FencingToken, f.intent.LeaseOwner, c, nonceReturn); err != nil {
			t.Fatal("survivor finalize nonce", err)
		}
		if err := store.ReserveGuestNotifyCanarySend(ctx, f.policy, f.intent.Generation, f.intent.FencingToken, f.intent.LeaseOwner, c); err != nil {
			t.Fatal("survivor reserve send", err)
		}
		response, pubFacts := capacity.RecoveryFixtureCanaryResponse(t, f.p, c, e, pub)
		returned := tailFixtureHTTP(t, response, response.OriginalReadStartedAt.Add(-time.Millisecond))
		time.Sleep(time.Until(returned.DriverReturnedAt) + time.Millisecond)
		if _, err := store.RecordGuestNotifyCanaryReturn(ctx, f.policy, f.intent.Generation, f.intent.FencingToken, f.intent.LeaseOwner, c, returned); err != nil {
			t.Fatal("survivor useful return", err)
		}
		return pubFacts
	}
	pub, err := store.IssueGuestNotifyCanaryPublication(ctx, f.policy, f.intent.Generation, f.intent.FencingToken, f.intent.LeaseOwner, f.pre[0].PreregistrationID, usage, core)
	if err != nil {
		t.Fatal("survivor issue publication", err)
	}
	facts := probe(pub, nil)
	read, err := store.IssueGuestNotifyCanaryRead(ctx, f.policy, f.intent.Generation, f.intent.FencingToken, f.intent.LeaseOwner, f.pre[0].PreregistrationID, usage, pub.ChallengeID, core)
	if err != nil {
		t.Fatal("survivor issue read", err)
	}
	probe(read, facts)
}

func (f *failedTailFixture) requestAndClaim(t *testing.T) {
	t.Helper()
	e, j := f.dispatch(t)
	r := capacityDispatchResponse(e, "failed")
	for _, step := range f.steps {
		x := model.WorkflowRunStepResult{ID: step.ID, Status: "skipped"}
		if step.ID == "plan-original-guest" || step.ID == "provision-original-notify" {
			x.Status = "succeeded"
		}
		if step.ID == "provision-original-notify" {
			x.Metadata = map[string]any{"preregistration": f.pre[1]}
		}
		if step.ID == "complete-original-provision" {
			x.Status = "failed"
		}
		r.Steps = append(r.Steps, x)
	}
	if err := FinishCapacityDispatch(context.Background(), f.db, j, r, time.Now().UTC(), nil); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Until(*f.intent.LeaseExpiresAt) + time.Millisecond)
	requested, err := f.store.RequestFailedInstalledGuestDisposal(context.Background(), f.pre[1].PreregistrationID, e.RunID.String(), "collaborator:"+uuid.NewString())
	if err != nil {
		t.Fatal("real tail request", err)
	}
	f.requested = requested
	claimEnvelope, claimJob := f.dispatch(t)
	f.claimJob = claimJob
	f.claimEnvelope = claimEnvelope
	f.store.OriginalRunID = claimEnvelope.RunID
	inv := capacity.RecoveryFixtureInventory(t, f.p, f.reg[0], time.Now().UTC())
	member := inv.Members[0]
	member.Slot, member.Protected = 2, false
	member.DesiredSpec = *f.p.MutationBindings[0].Slots[1].DesiredSpec
	member.RequestSHA256 = f.p.MutationBindings[0].Slots[1].DesiredSpecSHA256
	member.Server.ID, member.Server.CreatedAt, member.Server.Name = f.reg[1].Result.Tuple.ResourceID, f.reg[1].Result.Tuple.CreatedAt, member.DesiredSpec.NativeName
	member.Server.Labels = map[string]string{}
	for k, v := range inv.Members[0].Server.Labels {
		member.Server.Labels[k] = v
	}
	member.Server.Labels["yggdrasil.io/slot"] = "2"
	inv.Members = append(inv.Members, member)
	inv.MissingSlots = []int{3, 4, 5, 6, 7, 8}
	f.store = f.store.WithOriginalGuestReconcile(f.workflow, f.steps[0], capacity.CurrentGuestCoreSource(), "", "", inv, model.CapacityMetricRangeObservation{})
	assessment := f.intent.Assessment
	assessment.Snapshot.Units, assessment.Snapshot.ObservedAt = 2, time.Now().UTC()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	next, pre, claimed, err := f.store.TryClaimFailedInstalledGuestDisposal(ctx, f.policy, assessment)
	if err != nil || !claimed || pre != f.pre[1].PreregistrationID || FailedInstalledDisposalClaimSlot(next) != 2 || next.Decision.Units != 1 || next.Generation != 2 || next.FencingToken != 3 {
		t.Fatal("real tail claim must retain survivor", next, pre, claimed, err)
	}
	f.intent = next
}

func (f *failedTailFixture) retire(t *testing.T, refused bool) model.CapacityGuestRetirementRequestV2 {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	owner, err := capacity.NewGuestRetirementV2OriginalOwner(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	store := f.store.WithOriginalGuestNotifyCanary(f.steps[3], capacity.CurrentGuestCoreSource()).WithOriginalGuestRetirement(f.steps[3], capacity.CurrentGuestCoreSource())
	core := ed25519.NewKeyFromSeed([]byte(strings.Repeat("c", 32)))
	preflight, err := store.IssueGuestRetirementV2(owner, f.policy, 2, 3, f.intent.LeaseOwner, f.pre[1].PreregistrationID, capacity.BusinessCreationSHA256([]byte(uuid.NewString())), core)
	if err != nil {
		t.Fatal("real tail V2 issue", err)
	}
	client := capacity.RecoveryFixtureRetirementNonceClient(t, preflight, f.receipt[1].Enrollment)
	if err = owner.AcquireNonce(client, core, preflight, f.receipt[1].Enrollment); err != nil {
		t.Fatal("real original V2 nonce exchange", err)
	}
	if err = store.FinalizeGuestRetirementV2Nonce(owner); err != nil {
		t.Fatal("real V2 nonce ledger", err)
	}
	if err = store.ReserveGuestCallerV2(owner); err != nil {
		t.Fatal("real V2 possible send", err)
	}
	request, _, _, err := owner.NonceExchange()
	if err != nil {
		t.Fatal(err)
	}
	journal := capacity.RecoveryFixtureRetirementJournal(t, request.Intent, f.receipt[1].Enrollment)
	limit := len(journal)
	if refused {
		limit = 1
	}
	for _, observed := range journal[:limit] {
		if err = store.RecordGuestObservationV2(owner.Context(), request.Intent.RequestID, observed); err != nil {
			t.Fatal("real V2 journal custody", err)
		}
	}
	start := time.Now().UTC()
	body := tailFixtureWire(t, journal[3])
	status, persisted := 200, true
	if refused {
		body = []byte(`{"held":true}`)
		status, persisted = 409, false
	}
	sha := capacity.BusinessCreationSHA256(body)
	caller := GuestOriginalCallerReturn{RequestID: request.Intent.RequestID, AttemptID: request.Intent.AttemptID, StartedAt: start, DoStartedAt: start.Add(time.Millisecond), DoReturnedAt: start.Add(80 * time.Millisecond), ReadReturnedAt: start.Add(81 * time.Millisecond), CloseReturnedAt: start.Add(82 * time.Millisecond), DriverReturnedAt: start.Add(83 * time.Millisecond), OriginalDeadline: request.Intent.OriginalDeadline, Status: status, BodyPersisted: persisted, ReceivedBodyBytes: len(body), ResponseBodyScope: capacity.GuestOriginalBodyCompleteRead, ResponseSHA256: sha, RetainedPrefixBytes: len(body), RetainedPrefixSHA256: sha}
	if persisted {
		caller.Body = body
	} else {
		caller.Body = []byte{}
	}
	time.Sleep(time.Until(caller.DriverReturnedAt) + time.Millisecond)
	if err = store.RecordGuestCallerReturnV2(owner.Context(), caller); err != nil {
		t.Fatal("real closed V2 caller", err)
	}
	return request
}

func (f *failedTailFixture) finishDispatch(t *testing.T, request model.CapacityGuestRetirementRequestV2, refused bool) {
	t.Helper()
	status := "succeeded"
	if refused {
		status = "failed"
	}
	r := capacityDispatchResponse(f.claimEnvelope, status)
	for _, step := range f.steps {
		s := model.WorkflowRunStepResult{ID: step.ID, Status: "skipped"}
		if step.ID == "plan-original-guest" {
			s.Status = "succeeded"
			s.Metadata = map[string]any{"mode": "retire", "reason": "failed_installed_disposal", "slot": float64(2), "generation": float64(2), "fencing_token": float64(3), "lease_owner": f.intent.LeaseOwner, "preregistration_id": f.pre[1].PreregistrationID}
		}
		if step.ID == "retire-original-guest" {
			s.Status = "succeeded"
			s.Metadata = map[string]any{"request_id": request.Intent.RequestID}
			if refused {
				s.Status = "failed"
				s.Error = v2RefusedRetireStepError
				s.Metadata = map[string]any{"original_guest_refusal_predicate": v2RefusedRetireStepPredicate}
			}
		}
		if !refused && (step.ID == "finish-original-retirement" || step.ID == "complete-original-retirement") {
			s.Status = "succeeded"
		}
		r.Steps = append(r.Steps, s)
	}
	if err := FinishCapacityDispatch(context.Background(), f.db, f.claimJob, r, time.Now().UTC(), nil); err != nil {
		t.Fatal("real disposal dispatch finalization", err)
	}
}

func (f *failedTailFixture) offReturn(t *testing.T, challenge GuestNativePoweroffReadV2) GuestNativePoweroffReturnV2 {
	t.Helper()
	plan := capacity.RecoveryFixtureNativeOffPlan(t, f.p, f.pre[1], f.receipt[1].Enrollment.Statement.Tuple)
	started := time.Now().UTC()
	return GuestNativePoweroffReturnV2{Schema: v2NativePoweroffReturnSchema, Challenge: challenge, Status: "observed", Plan: &plan, StartedAtCore: started, OriginalReturnedAtCore: started.Add(time.Millisecond)}
}

func (f *failedTailFixture) retirementFloor(usage, ack string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tx, err := f.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	return f.store.guestNotifyRetirementFloorTx(ctx, tx, f.policy, f.p, f.intent, 2, time.Now().UTC(), usage, ack)
}

func (f *failedTailFixture) completeAbsence(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var survivorBefore string
	if err := f.db.QueryRow(`SELECT slot_record::text FROM public.capacity_resource_slots WHERE namespace=$1 AND slot=1`, f.policy.Metadata.Namespace).Scan(&survivorBefore); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"foreign_slot", "foreign_lifetime", "exact"} {
		owner, err := f.store.BeginFailedInstalledGuestAbsence(ctx, f.pre[1].PreregistrationID, f.requested.ID, "collaborator:"+uuid.NewString())
		if err != nil {
			t.Fatal("real tail absence begin", err)
		}
		c := owner.Candidate()
		r := c.Request
		now := time.Now().UTC()
		o := model.CapacityOriginalCreateDispositionObservation{InventoryBasis: "original_accepted_auxiliary_inventory_v1", Schema: model.OriginalCreateDispositionObservationSchema, Provider: "hetzner", Profile: r.Profile, Slot: r.Slot, GrantID: r.GrantID, AttemptID: r.AttemptID, RequestSHA256: r.RequestSHA256, ResourceID: r.ExpectedResourceID, ResourceCreatedAt: r.ExpectedResourceCreatedAt, OriginalAdapterSourceCommit: r.OriginalAdapterSourceCommit, AdapterSourceCommit: enrolledFailedHetznerCreator, ResourceState: "absent", ResourceAbsenceComplete: true, AuxiliaryInventoryComplete: true, SharedResourcesPreserved: true, AuxiliaryResources: []model.CapacityVMAuxiliaryObservation{}, NativeReads: []model.CapacityOriginalCreateDispositionNativeRead{}, ObservationStartedAt: now, ObservedAt: now.Add(5 * time.Millisecond)}
		resources := []model.CapacityMutationAuxiliaryResource{{Kind: "server", ID: r.ExpectedResourceID}}
		resources = append(resources, r.AuxiliaryResources...)
		for i, a := range resources {
			wire := []byte(`{"error":"not_found"}`)
			called := now.Add(time.Duration(i) * time.Millisecond)
			returned := called.Add(time.Microsecond)
			o.NativeReads = append(o.NativeReads, model.CapacityOriginalCreateDispositionNativeRead{Operation: "GetExactOriginal", ResourceKind: a.Kind, ResourceID: a.ID, Status: 404, ResponseSHA256: capacity.BusinessCreationSHA256(wire), ResponseBytes: int64(len(wire)), ResponseBodyBase64: base64.StdEncoding.EncodeToString(wire), ResponseRepresentation: "raw_http_body_v1", CalledAt: called, ReturnedAt: returned})
			if i > 0 {
				o.AuxiliaryResources = append(o.AuxiliaryResources, model.CapacityVMAuxiliaryObservation{Kind: a.Kind, ID: a.ID, Absent: true, ObservedAt: returned.Format(time.RFC3339Nano)})
			}
		}
		if mode == "foreign_slot" {
			o.Slot = 1
		}
		if mode == "foreign_lifetime" {
			o.ResourceCreatedAt = now.Add(-time.Hour).Format(time.RFC3339Nano)
		}
		disposed, err := f.store.CompleteFailedInstalledGuestAbsence(ctx, owner, o)
		if mode != "exact" {
			if err == nil {
				t.Fatal("foreign native absence accepted", mode)
			}
			continue
		}
		if err != nil || disposed.Stage != "terminal" {
			t.Fatal("real tail absence terminal", disposed.Stage, err)
		}
	}
	var survivorAfter string
	var target capacityResourceSlot
	var raw []byte
	if err := f.db.QueryRow(`SELECT slot_record::text FROM public.capacity_resource_slots WHERE namespace=$1 AND slot=1`, f.policy.Metadata.Namespace).Scan(&survivorAfter); err != nil || survivorBefore != survivorAfter {
		t.Fatal("disposal changed surviving slot", err)
	}
	if err := f.db.QueryRow(`SELECT slot_record FROM public.capacity_resource_slots WHERE namespace=$1 AND slot=2`, f.policy.Metadata.Namespace).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if json.Unmarshal(raw, &target) != nil || !target.Tombstone || target.ResourceID != "" {
		t.Fatal("only failed tail must be tombstoned")
	}
	if err := f.db.QueryRow(`SELECT intent FROM public.capacity_intents WHERE namespace=$1 AND dimension=$2`, f.policy.Metadata.Namespace, f.p.Dimension).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var current model.CapacityIntent
	if json.Unmarshal(raw, &current) != nil || current.Phase != "disposed_failed_installed" || current.Decision.Units != 1 || current.Assessment.Snapshot.Units != 1 || current.Generation != 2 || current.FencingToken != 3 || current.LeaseExpiresAt != nil || current.FailedInstalledDisposal == nil || current.FailedInstalledDisposal.Stage != "terminal" {
		t.Fatal("failed expansion reset the surviving fleet or promoted the failed generation", current)
	}
}

func TestRecoveryFixtureFailedExpansionTailV2TerminalPostgres(t *testing.T) {
	for _, mode := range []string{"complete_v2", "refused_v2_native_off"} {
		t.Run(mode, func(t *testing.T) {
			f := newFailedTailFixture(t)
			f.canary(t, "initial_useful_membership")
			f.requestAndClaim(t)
			time.Sleep(5 * time.Second)
			f.canary(t, "before_retirement_floor")
			refused := mode == "refused_v2_native_off"
			request := f.retire(t, refused)
			if refused {
				f.finishDispatch(t, request, true)
				time.Sleep(time.Until(*f.intent.LeaseExpiresAt) + time.Millisecond)
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				owner, err := f.store.PrepareFailedInstalledV2RefusedNativeOffRead(ctx, f.pre[1].PreregistrationID, f.requested.ID, request.Intent.RequestID, "collaborator:"+uuid.NewString())
				if err != nil {
					t.Fatal("real refused tail admission", err)
				}
				_, disposal, err := f.store.RecordFailedInstalledV2RefusedNativeOffRead(ctx, owner, f.offReturn(t, owner.Challenge()))
				if err != nil || disposal.Stage != "quiescent" {
					t.Fatal("real refused tail native OFF qualification", disposal.Stage, err)
				}
			} else {
				if err := f.retirementFloor("after_retirement_floor", request.Intent.RequestID); err == nil {
					t.Fatal("pre-withdrawal useful read replaced the required new post-ACK floor canary")
				}
				time.Sleep(5 * time.Second)
				f.canary(t, "after_retirement_floor")
				if err := f.retirementFloor("after_retirement_floor", request.Intent.RequestID); err != nil {
					t.Fatal("fresh original floor read after the caller ACK was refused", err)
				}
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				challenge, err := f.store.PrepareGuestNativePoweroffReadV2(ctx, request.Intent.RequestID)
				if err != nil {
					t.Fatal("real tail native OFF prepare", err)
				}
				if err = f.store.RecordGuestNativePoweroffV2(ctx, f.offReturn(t, challenge)); err != nil {
					t.Fatal("real tail native OFF return", err)
				}
				store := f.store.WithOriginalGuestNotifyCanary(f.steps[4], capacity.CurrentGuestCoreSource())
				disposal, handled, err := store.PrepareFailedInstalledGuestNativeCleanup(ctx, f.policy, 2, 3, f.intent.LeaseOwner, request.Intent.RequestID)
				if err != nil || !handled || disposal.Stage != "quiescent" {
					t.Fatal("real V2 tail cleanup transition", disposal.Stage, handled, err)
				}
				f.finishDispatch(t, request, false)
			}
			f.completeAbsence(t)
		})
	}
}

func TestRecoveryFixtureFailedExpansionTailRequestClaimAndCanariesPostgres(t *testing.T) {
	f := newFailedTailFixture(t)
	f.canary(t, "initial_useful_membership")
	f.requestAndClaim(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	store := f.store.WithOriginalGuestNotifyCanary(f.steps[4], capacity.CurrentGuestCoreSource())
	members, err := store.GuestNotifyFloorMembers(ctx, f.policy, 2, 3, f.intent.LeaseOwner, 2)
	if err != nil || len(members) != 1 || members[0].Slot != 1 {
		t.Fatal("actual survivor discovery", members, err)
	}
	if _, err := store.GuestNotifyFloorMembers(ctx, f.policy, 2, 3, f.intent.LeaseOwner, 1); err == nil {
		t.Fatal("surviving first member substituted for the failed tail")
	}
	checkFloor := func(usage string) error {
		tx, err := f.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer tx.Rollback()
		return store.guestNotifyRetirementFloorTx(ctx, tx, f.policy, f.p, f.intent, 2, time.Now().UTC(), usage, "")
	}
	if checkFloor("before_retirement_floor") == nil {
		t.Fatal("old useful read substituted for required new floor canary")
	}
	core := ed25519.NewKeyFromSeed([]byte(strings.Repeat("c", 32)))
	for _, usage := range []string{"initial_useful_membership", "steady_useful_membership", "before_retirement_floor", "after_retirement_floor"} {
		if _, err := store.IssueGuestNotifyCanaryPublication(ctx, f.policy, 2, 3, f.intent.LeaseOwner, f.pre[1].PreregistrationID, usage, core); err == nil {
			t.Fatal("failed tail received a new canary", usage)
		}
	}
	if _, err := store.IssueGuestNotifyCanaryPublication(ctx, f.policy, 2, 3, f.intent.LeaseOwner, f.pre[0].PreregistrationID, "initial_useful_membership", core); err == nil {
		t.Fatal("survivor received non-floor canary during disposal")
	}
	time.Sleep(5 * time.Second)
	f.canary(t, "before_retirement_floor")
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := checkFloor("before_retirement_floor"); err != nil {
		t.Fatal("fresh real before-floor read not joined", err)
	}
	for _, changed := range []string{"stale_native", "foreign_native_lifetime"} {
		t.Run(changed, func(t *testing.T) {
			tx, err := f.db.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			field, value := "observed_at", time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano)
			if changed == "foreign_native_lifetime" {
				field, value = "resource_created_at", time.Now().Add(-2*time.Hour).UTC().Format(time.RFC3339Nano)
			}
			if _, err := tx.ExecContext(ctx, `UPDATE public.capacity_resource_slots SET slot_record=jsonb_set(slot_record,ARRAY[$1::text],to_jsonb($2::text)) WHERE namespace=$3 AND slot=1`, field, value, f.policy.Metadata.Namespace); err != nil {
				t.Fatal(err)
			}
			if err := store.guestNotifyRetirementFloorTx(ctx, tx, f.policy, f.p, f.intent, 2, time.Now().UTC(), "before_retirement_floor", ""); err == nil {
				t.Fatal("changed survivor retained floor authority", changed)
			}
		})
	}
}
