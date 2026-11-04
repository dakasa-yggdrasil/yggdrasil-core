//go:build recoveryfixture && !nativequalification

package repository

import (
	"context"
	"database/sql"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/manifest"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
	"github.com/lib/pq"
)

// AdmissionDiagnostics is a bounded, later observation of the disposable test
// database after a failed operation. It never retries that operation, changes
// stored evidence, commits a transaction or attributes the earlier refusal.
func (f *GuestRetirementForwardRecoveryFixture) AdmissionDiagnostics() string {
	report := map[string]any{"later_observation_only": true, "earlier_refusal_branch_measured": false}
	encode := func() string {
		raw, err := json.Marshal(report)
		if err != nil || len(raw) > 16<<10 {
			return `{"later_observation_only":true,"diagnostic_output_unavailable":true}`
		}
		return string(raw)
	}
	if f == nil || f.DB == nil || f.private == nil || !strings.HasSuffix(filepath.Base(os.Args[0]), ".test") || os.Getenv("CAPACITY_RECOVERY_FIXTURE_ONLY") != "true" {
		report["test_fixture_required"] = true
		return encode()
	}
	ctx, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	tx, err := f.DB.BeginTx(ctx, nil)
	if err != nil {
		report["begin_error_type"] = fmt.Sprintf("%T", err)
		return encode()
	}
	defer tx.Rollback()
	stage := func(name string, err error) {
		report[name] = map[string]any{"ok": err == nil, "error_type": fmt.Sprintf("%T", err)}
	}
	_, err = tx.ExecContext(ctx, `SET LOCAL TIME ZONE 'UTC'`)
	stage("utc_session", err)
	original, loadErr := loadGuestRetirementV2Tx(ctx, tx, f.Request.Intent.RequestID, true)
	stage("load_original", loadErr)
	if loadErr == nil {
		i := original.Request.Intent
		report["request_matches_fixture"] = reflect.DeepEqual(original.Request, f.Request)
		rows, rowErr := tx.QueryContext(ctx, `SELECT r.phase,r.ordinal,r.possible_read_at,r.original_deadline,v.original_wire,v.authority_sha256,r.original_deadline<=$2::timestamptz FROM public.capacity_guest_original_authority_reads r LEFT JOIN public.capacity_guest_original_authority_returns v ON v.read_id=r.id WHERE r.intent_id=$1 ORDER BY CASE r.phase WHEN 'before_start' THEN 0 ELSE 1 END,r.ordinal LIMIT 5`, i.RequestID, i.OriginalDeadline.Format(time.RFC3339Nano))
		authorities := []map[string]any{}
		if rowErr == nil {
			for rows.Next() {
				if len(authorities) == 4 {
					report["extra_authority_rows"] = true
					break
				}
				var phase string
				var ordinal int
				var started, deadline time.Time
				var raw []byte
				var digest sql.NullString
				var withinOriginalPG bool
				if rowErr = rows.Scan(&phase, &ordinal, &started, &deadline, &raw, &digest, &withinOriginalPG); rowErr != nil {
					break
				}
				var authority model.CapacityGuestRetirementAuthorityV2
				decoded := capacity.DecodeGuestLifecycle(raw, &authority) == nil
				entry := map[string]any{"phase": phase, "ordinal": ordinal, "decoded": decoded, "deadline_minus_signed_original_ns": deadline.Sub(i.OriginalDeadline).Nanoseconds(), "deadline_after_original": deadline.After(i.OriginalDeadline), "started_before_issued": started.Before(i.IssuedAt), "budget_ns": deadline.Sub(started).Nanoseconds(), "budget_over_five_seconds": deadline.Sub(started) > 5*time.Second}
				entry["deadline_within_original_pg"] = withinOriginalPG
				if decoded {
					entry["schema_matches"] = authority.Schema == capacity.GuestRetirementV2AuthoritySchema
					entry["sha_matches"] = digest.Valid && capacity.GuestRetirementSHA(authority) == digest.String
					entry["observed_minus_started_ns"] = authority.ObservedAt.Sub(started).Nanoseconds()
					entry["observed_before_start"] = authority.ObservedAt.Before(started)
					entry["observed_at_or_after_deadline"] = !authority.ObservedAt.Before(deadline)
					entry["signed_deadline_matches"] = authority.OriginalDeadline.Equal(i.OriginalDeadline)
					entry["observed_at_or_after_signed_native_deadline"] = !authority.ObservedAt.Before(i.OriginalDeadline)
				}
				authorities = append(authorities, entry)
			}
			if rowErr == nil {
				rowErr = rows.Err()
			}
			if closeErr := rows.Close(); rowErr == nil {
				rowErr = closeErr
			}
		}
		stage("authority_rows", rowErr)
		report["authority"] = authorities
		_, err = guestRetirementForwardEvidenceTx(ctx, tx, original)
		stage("evidence", err)
		receipt, receiptErr := guestOriginalCreateReceiptV2Tx(ctx, tx, original)
		stage("create_receipt", receiptErr)
		if receiptErr == nil {
			report["create_receipt_pins"] = map[string]any{"confirmed": receipt.Grant.State == "confirmed", "grant_matches": receipt.Grant.GrantID == original.Preregistration.OriginalCreateGrantID, "resource_matches": receipt.ResourceID == i.Tuple.ResourceID, "created_at_matches": receipt.ResourceCreatedAt == i.Tuple.CreatedAt}
		}
		x, snapshotErr := f.Store.retirementForwardSnapshotTx(ctx, tx, i.RequestID)
		stage("snapshot", snapshotErr)
		if x.current.PolicyID != uuid.Nil {
			report["current_epoch"] = map[string]any{"generation": x.current.Generation, "fence": x.current.FencingToken, "phase": x.current.Phase, "baseline_units": x.current.BaselineSnapshot.Units, "decision_units": x.current.Decision.Units, "target_slot": i.Slot, "generation_matches_original": x.current.Generation == int64(i.Generation), "fence_matches_original": x.current.FencingToken == int64(i.Fence), "owner_matches_original": x.current.LeaseOwner == i.LeaseOwner, "executor_matches_original": x.current.LeaseExecutorID == original.ExecutorID}
		}
		if snapshotErr == nil {
			stage("quiet", retirementForwardQuietTx(ctx, tx, x, f.RunID.String(), ""))
		}
		var pgNow time.Time
		var active int
		var maxDeadline sql.NullTime
		err = tx.QueryRowContext(ctx, `SELECT clock_timestamp(),count(*) FILTER(WHERE original_deadline>clock_timestamp()),max(original_deadline) FROM public.capacity_guest_notify_canary_challenges WHERE policy_id=$1`, i.PolicyID).Scan(&pgNow, &active, &maxDeadline)
		stage("canary_window", err)
		if err == nil {
			report["active_canary_windows"] = active
			if maxDeadline.Valid {
				report["max_canary_deadline_minus_pg_now_ns"] = maxDeadline.Time.Sub(pgNow).Nanoseconds()
			}
		}
	}
	err = tx.Rollback()
	report["rollback_completed"] = err == nil || err == sql.ErrTxDone
	report["rollback_error_type"] = fmt.Sprintf("%T", err)
	return encode()
}

// GuestRetirementForwardRecoveryFixture is declared signed storage and transport
// data in an owned disposable PG16/17 database. No Guest/provider is contacted.
// The starting N-member reduction is an explicit initial storage operand, not
// evidence that an expansion or native business effect occurred. Subsequent
// nonce, canary, authority, journal, caller and recovery operations use the real
// repository APIs with FK/trigger enforcement. No stored original is rewritten.
// This file is absent from default and nativequalification builds.
type GuestRetirementForwardRecoveryFixture struct {
	DB                 *sql.DB
	Store              CapacityStore
	Policy, Workflow   model.Manifest
	Spec               model.CapacityPolicySpec
	Intent             model.CapacityIntent
	Pre                model.CapacityGuestOriginalProvisioningPreregistration
	Registration       model.CapacityGuestOriginalProvisioningRegistration
	Receipt            model.CapacityGuestOriginalProvisioningReceipt
	Request            model.CapacityGuestRetirementRequestV2
	Caller             GuestOriginalCallerReturn
	RunID              uuid.UUID
	Journal            []model.CapacityGuestRetirementObservationV2
	retainedCanaryIDs  []string
	originalRunID      uuid.UUID
	private            *failedServingFixture
	members            []*failedServingFixture
	job                CapacityDispatchJob
	envelope           CapacityDispatchEnvelope
	t                  *testing.T
	fractionalOriginal bool
	ordinarySuccess    bool
}

// NewGuestRetirementForwardRecoveryFixture accepts only the same test-process,
// explicit environment, exact-source, loopback/Unix disposable PG16/17 and
// mutex/cleanup gates enforced by newFailedServingFixtureHistory. It cannot
// accept an existing database, URL, signing key, clock or proof from its caller.
func NewGuestRetirementForwardRecoveryFixture(tb testing.TB, provider string, tail, prefixRecords int) *GuestRetirementForwardRecoveryFixture {
	return newGuestRetirementForwardRecoveryFixture(tb, provider, tail, prefixRecords, 30, false, false)
}

// NewGuestRetirementForwardLiveWorkflowFixture declares a live workflow lease
// of300s BEFORE its first policy/intent insert and retirement frame. It never
// extends an existing original timer. Historical tests use the30s constructor.
func NewGuestRetirementForwardLiveWorkflowFixture(tb testing.TB, provider string, tail, prefixRecords int) *GuestRetirementForwardRecoveryFixture {
	return newGuestRetirementForwardRecoveryFixture(tb, provider, tail, prefixRecords, 300, false, false)
}

// NewGuestRetirementForwardFractionalOriginalFixture declares one short original
// before its first Issue. No caller can supply a clock, deadline or prior frame.
func NewGuestRetirementForwardFractionalOriginalFixture(tb testing.TB, provider string) *GuestRetirementForwardRecoveryFixture {
	return newGuestRetirementForwardRecoveryFixture(tb, provider, 2, 3, 30, true, false)
}

// NewGuestRetirementOrdinaryRecoveryFixture declares a complete original Guest
// success before its first caller insert. It creates no forward admission and
// never rewrites a failed caller, ACK, journal, original clock or lease.
func NewGuestRetirementOrdinaryRecoveryFixture(tb testing.TB, provider string) *GuestRetirementForwardRecoveryFixture {
	return newGuestRetirementForwardRecoveryFixture(tb, provider, 2, 4, 300, false, true)
}

func newGuestRetirementForwardRecoveryFixture(tb testing.TB, provider string, tail, prefixRecords, initialLeaseSeconds int, fractionalOriginal, ordinarySuccess bool) *GuestRetirementForwardRecoveryFixture {
	tb.Helper()
	t, ok := tb.(*testing.T)
	if !ok || !strings.HasSuffix(filepath.Base(os.Args[0]), ".test") || os.Getenv("CAPACITY_RECOVERY_FIXTURE_ONLY") != "true" {
		tb.Fatal("owning test process and explicit recovery fixture gate required")
	}
	if tail < 2 || tail > 8 || (prefixRecords < 1 || prefixRecords > 4) {
		t.Fatal("closed tail2..8/prefix1..4 fixture operands (only3|4 admissible)")
	}
	if fractionalOriginal && (tail != 2 || prefixRecords != 3 || initialLeaseSeconds != 30) {
		t.Fatal("closed initial fractional original fixture")
	}
	base := newFailedServingFixtureLease(t, provider, true, initialLeaseSeconds)
	f := &GuestRetirementForwardRecoveryFixture{DB: base.db, Store: base.store, Policy: base.policy, Workflow: base.workflow, Spec: base.p, private: base, t: t, members: []*failedServingFixture{base}, fractionalOriginal: fractionalOriginal, ordinarySuccess: ordinarySuccess}
	// Complete declared read catalog for actual bounded message supplier calls;
	// version0.1.0 remains explicitly synthetic, never an enrolled adapter claim.
	typeSpec := failedServingTypeSpec(provider, f.Spec.MutationBindings[0])
	readActions := []string{capacity.VMObserveInventory, capacity.VMObserveServer, capacity.VMObserveRetirement}
	if provider == "aws" {
		readActions = []string{capacity.VMObserveInventory, "observe_ec2_instance"}
	}
	for _, action := range readActions {
		typeSpec.ActionCatalog = append(typeSpec.ActionCatalog, model.IntegrationActionDefinition{Name: action, ResourceTypes: []string{typeSpec.ResourceTypes[0].Name}, Idempotent: true})
		typeSpec.ResourceTypes[0].DefaultActions = append(typeSpec.ResourceTypes[0].DefaultActions, action)
		typeSpec.Execution.IdempotentActions = append(typeSpec.Execution.IdempotentActions, action)
	}
	if err := manifest.ValidateIntegrationTypeSpec(typeSpec); err != nil {
		t.Fatal("declared complete read catalog", err)
	}
	base.exec(t, `UPDATE public.manifests SET spec=$2::jsonb WHERE id=$1`, f.Spec.MutationBindings[0].IntegrationTypeID, string(failedServingWire(t, typeSpec)))

	for slot := 2; slot <= tail; slot++ {
		f.members = append(f.members, f.seedMember(slot))
	}
	// This is the initial DECLARED storage context, before any retirement frame
	// exists. No source time, previous retirement, binding or history is edited.
	now := time.Now().UTC()
	expires := now.Add(time.Duration(f.Spec.LeaseSeconds) * time.Second)
	snapshot, err := capacity.GuestReconcileSnapshot(f.Policy, f.Spec, f.Inventory(true), now)
	if err != nil {
		t.Fatal("declared exact member inventory", err)
	}
	i := base.intent
	i.Generation = int64(tail + 2)
	i.FencingToken = int64(tail + 3)
	i.Phase = "draining"
	i.BaselineSnapshot = snapshot
	i.Assessment = model.CapacityAssessment{Snapshot: snapshot}
	i.Decision = model.CapacityDecision{Action: "drain", Reason: "sustained_low_pressure", Profile: snapshot.Profile, Units: tail - 1, Floor: f.Spec.Floor, ExecutionPermitted: true}
	i.LeaseOwner = uuid.NewString()
	i.LeaseExecutorID = f.Store.ExecutorID
	i.LeaseExpiresAt = &expires
	i.UpdatedAt = now
	base.exec(t, `UPDATE public.capacity_intents SET intent=$2::jsonb,updated_at=clock_timestamp() WHERE namespace=$1`, f.Policy.Metadata.Namespace, string(failedServingWire(t, i)))
	base.exec(t, `INSERT INTO public.capacity_intent_events(namespace,environment,domain,dimension,generation,fencing_token,phase,receipt_ref) VALUES($1,$2,$3,$4,$5,$6,'draining','declared-initial-healthy-tail-reduction')`, f.Policy.Metadata.Namespace, f.Spec.Environment, f.Spec.Domain, f.Spec.Dimension, i.Generation, i.FencingToken)
	f.Intent = i
	ctx, stop := context.WithTimeout(context.Background(), 10*time.Second)
	members, pending, err := f.PlanStore().OriginalGuestReconcileMembers(ctx, f.Policy)
	stop()
	if err != nil || pending || len(members) != tail {
		t.Fatal("real owned member read/refresh", len(members), pending, err)
	}
	// All surviving members must independently satisfy the existing native and
	// useful before-floor guard. Publication spacing is observed, never reset.
	f.Canaries("before_retirement_floor")
	f.startDispatch()
	target := f.members[tail-1]
	f.Pre, f.Registration, f.Receipt = target.pre, target.reg, target.receipt
	f.makeOriginal(prefixRecords)
	rows, err := f.DB.Query(`SELECT id::text FROM public.capacity_guest_notify_canary_challenges ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		f.retainedCanaryIDs = append(f.retainedCanaryIDs, id)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		t.Fatal(err)
	}
	if err = rows.Close(); err != nil {
		t.Fatal(err)
	}
	// Observe natural closure of the retained original canary windows before
	// exposing the fixture to admission; no stored deadline or ACK is changed.
	var delay float64
	if err = f.DB.QueryRow(`SELECT COALESCE(GREATEST(0,EXTRACT(EPOCH FROM(max(original_deadline)-clock_timestamp()))),0) FROM public.capacity_guest_notify_canary_challenges`).Scan(&delay); err != nil || delay > 6 {
		t.Fatal("bounded original canary windows", delay, err)
	}
	if delay > 0 {
		time.Sleep(time.Duration(delay*float64(time.Second)) + 5*time.Millisecond)
	}
	f.originalRunID = f.RunID
	return f
}

// seedMember derives a distinct signed declared birth from the existing
// provider-specific shape. Rehashing/re-signing is done before the FIRST insert;
// it never normalizes or changes an already retained retirement frame.
func (f *GuestRetirementForwardRecoveryFixture) seedMember(slot int) *failedServingFixture {
	t := f.t
	base := f.private
	b := *f.Spec.GuestRetirementBinding
	m := f.Spec.MutationBindings[0]
	pre := base.pre
	old := pre
	pre.PreregistrationID, pre.OriginalCreateGrantID = uuid.NewString(), uuid.NewString()
	pre.BindingName = b.Members[slot-1].Name
	pre.Generation, pre.Fence = int64(slot+1), int64(slot+1)
	pre.Slot = slot
	pre.NonceSHA256 = capacity.BusinessCreationSHA256([]byte(pre.PreregistrationID))
	pre.OriginalCreateRequestSHA256 = m.Slots[slot-1].DesiredSpecSHA256
	var original capacityMutationRecord
	var raw []byte
	if err := f.DB.QueryRow(`SELECT grant_record FROM public.capacity_mutation_grants WHERE id=$1`, old.OriginalCreateGrantID).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if json.Unmarshal(raw, &original) != nil || original.Settlement == nil || original.Proof == nil {
		t.Fatal("complete declared create shape required")
	}
	resource := strconv.Itoa(123 + slot)
	if f.Spec.Profiles[0].Provider == "aws" {
		resource = fmt.Sprintf("i-%017x", 123+slot)
	}
	replacements := map[string]string{old.PreregistrationID: pre.PreregistrationID, old.OriginalCreateGrantID: pre.OriginalCreateGrantID, old.BindingName: pre.BindingName, old.NonceSHA256: pre.NonceSHA256, old.OriginalCreateRequestSHA256: pre.OriginalCreateRequestSHA256, base.reg.Result.Tuple.ResourceID: resource, original.AttemptID: uuid.NewString(), capacity.GuestProfileBootstrapSHA(b.ProfileManifest, 1): capacity.GuestProfileBootstrapSHA(b.ProfileManifest, slot)}
	if original.Settlement.ActionID != "" {
		action := strconv.Itoa(77 + slot)
		if f.Spec.Profiles[0].Provider == "aws" {
			action = uuid.NewString()
		}
		replacements[original.Settlement.ActionID] = action
	}
	clone := func(in, out any) {
		var v any
		if json.Unmarshal(failedServingWire(t, in), &v) != nil {
			t.Fatal("declared member shape")
		}
		var walk func(any) any
		walk = func(x any) any {
			switch z := x.(type) {
			case string:
				if n, ok := replacements[z]; ok {
					return n
				}
			case []any:
				for j := range z {
					z[j] = walk(z[j])
				}
			case map[string]any:
				for k, a := range z {
					if k == "slot" {
						z[k] = slot
					} else {
						z[k] = walk(a)
					}
				}
			}
			return x
		}
		if json.Unmarshal(failedServingWire(t, walk(v)), out) != nil {
			t.Fatal("declared member rebind")
		}
	}
	var reg model.CapacityGuestOriginalProvisioningRegistration
	var receipt model.CapacityGuestOriginalProvisioningReceipt
	var installed model.CapacityGuestOriginalInstallationConfirmation
	clone(base.reg, &reg)
	clone(base.receipt, &receipt)
	clone(base.installed, &installed)
	var next capacityMutationRecord
	clone(original, &next)
	next.Generation, next.FencingToken = pre.Generation, pre.Fence
	next.Binding = m
	next.Grant.Slot = slot
	next.Settlement.OriginalProviderCreateReturn.ActionID = next.Settlement.ActionID
	clock := reg.Result.ProductionClock
	clock.Authority.Preregistration = pre
	clock.Authority.Profile = b.ProfileManifest
	w := &clock.Authority.CreateWitness
	w.OriginalCreateSettlementSHA256 = capacity.GuestRetirementSHA(next.Settlement)
	w.Signature = ""
	w.Signature, _ = capacity.GuestLifecycleSignature(failedServingKey('c'), *w)
	clock.Authority.Signature = ""
	clock.Authority.Signature, _ = capacity.GuestLifecycleSignature(failedServingKey('c'), clock.Authority)
	reg.Result.OriginalCreateSettlementSHA256 = w.OriginalCreateSettlementSHA256
	reg.Result.BootstrapOriginalObservation.JournalSHA256 = capacity.GuestRetirementSHA(reg.Result.BootstrapOriginalJournal)
	reg.Result.WriterRosterSHA256 = capacity.GuestRetirementSHA(reg.Result.Writers)
	reg.EnrollmentStatement.WriterRosterSHA256 = reg.Result.WriterRosterSHA256
	reg.EnrollmentStatement.OriginalNativeResultSHA256 = capacity.GuestRetirementSHA(reg.Result)
	reg.EnrollmentStatement.OriginalProvisioningClockSHA256 = capacity.GuestRetirementSHA(*clock)
	reg.Signature = ""
	reg.Signature, _ = capacity.GuestLifecycleSignature(failedServingKey('p'), reg)
	receipt.PreregistrationID = pre.PreregistrationID
	receipt.OriginalProvisioningSHA256 = capacity.GuestRetirementSHA(reg)
	receipt.Enrollment.Statement = reg.EnrollmentStatement
	receipt.Enrollment.Signature, _ = capacity.GuestLifecycleSignature(failedServingKey('i'), receipt.Enrollment.Statement)
	installed.OriginalReceiptSHA256 = capacity.GuestRetirementSHA(receipt)
	installed.EnrollmentSHA256 = capacity.GuestRetirementSHA(receipt.Enrollment)
	installed.ProductionClock.OriginalProvisioningClockSHA256 = capacity.GuestRetirementSHA(*clock)
	installed.Signature = ""
	installed.Signature, _ = capacity.GuestLifecycleSignature(failedServingKey('p'), installed)
	if err := capacity.GuestOriginalRegistration(f.Spec, b, b.Members[slot-1], *w, reg, receipt.RecordedAt); err != nil {
		t.Fatal("new declared member signed registration", err)
	}
	if err := capacity.GuestRetirementEnrollment(f.Spec, b, b.Members[slot-1], receipt.Enrollment, receipt.RecordedAt); err != nil {
		t.Fatal(err)
	}
	if err := capacity.GuestOriginalInstallationV2(pre, receipt, installed, b.ProvisionerPublicKey, *clock, receipt.RecordedAt.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	tx, err := f.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	exec := func(q string, args ...any) {
		if _, err := tx.Exec(q, args...); err != nil {
			t.Fatal("declared initial member", err)
		}
	}
	exec(`INSERT INTO public.capacity_mutation_grants(id,namespace,environment,domain,dimension,generation,integration_instance_id,scope_checksum,profile_name,slot,state,grant_record,expires_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'confirmed',$11::jsonb,$12,$13)`, pre.OriginalCreateGrantID, f.Policy.Metadata.Namespace, f.Spec.Environment, f.Spec.Domain, f.Spec.Dimension, pre.Generation, m.IntegrationInstanceID, m.ScopeChecksum, m.ProfileName, slot, string(failedServingWire(t, next)), pre.OriginalDeadline, pre.ReservedAt)
	exec(`INSERT INTO public.capacity_vm_provisioning_preregistrations(id,create_grant_id,nonce_sha256,profile_manifest_sha256,preregistration_record,original_deadline,created_at,original_wire,binding_wire) VALUES($1,$2,$3,$4,$5::jsonb,$6,$7,$8,$9)`, pre.PreregistrationID, pre.OriginalCreateGrantID, pre.NonceSHA256, pre.ProfileManifestSHA256, string(failedServingWire(t, pre)), pre.OriginalDeadline, pre.ReservedAt, failedServingWire(t, pre), failedServingWire(t, b))
	exec(`INSERT INTO public.capacity_guest_original_create_witnesses(preregistration_id,original_create_attempt_id,resource_tuple_sha256,witness_sha256,original_wire,original_record,recorded_at) VALUES($1,$2,$3,$4,$5,$6::jsonb,$7)`, pre.PreregistrationID, w.OriginalCreateAttemptID, capacity.GuestRetirementSHA(w.Tuple), capacity.GuestRetirementSHA(*w), failedServingWire(t, *w), string(failedServingWire(t, *w)), w.ObservedAt)
	exec(`INSERT INTO public.capacity_vm_original_enrollments(preregistration_id,resource_tuple_sha256,enrollment_sha256,original_provisioning_sha256,enrollment_record,recorded_at,registration_wire,receipt_wire) VALUES($1,$2,$3,$4,$5::jsonb,$6,$7,$8)`, pre.PreregistrationID, capacity.GuestRetirementSHA(receipt.Enrollment.Statement.Tuple), capacity.GuestRetirementSHA(receipt.Enrollment), receipt.OriginalProvisioningSHA256, string(failedServingWire(t, receipt.Enrollment)), receipt.RecordedAt, failedServingWire(t, reg), failedServingWire(t, receipt))
	exec(`INSERT INTO public.capacity_guest_original_installations(preregistration_id,original_wire,confirmation_sha256,recorded_at) VALUES($1,$2,$3,$4)`, pre.PreregistrationID, failedServingWire(t, installed), capacity.GuestRetirementSHA(installed), receipt.RecordedAt.Add(time.Second))
	owned := capacityResourceSlot{BindingName: m.Name, ProfileName: m.ProfileName, DesiredSpecSHA256: m.Slots[slot-1].DesiredSpecSHA256, ResourceID: resource, ResourceCreatedAt: reg.Result.Tuple.CreatedAt, ObservedAt: time.Now().UTC(), ReceiptRef: "declared-initial-forward-member"}
	if err = saveMutationSlot(context.Background(), tx, f.Policy.Metadata.Namespace, f.Spec, m, slot, owned); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	return &failedServingFixture{db: f.DB, p: f.Spec, policy: f.Policy, workflow: f.Workflow, steps: base.steps, store: f.Store, pre: pre, reg: reg, receipt: receipt, installed: installed}
}

func (f *GuestRetirementForwardRecoveryFixture) step(id string) model.WorkflowStepSpec {
	return f.private.step(f.t, id)
}
func (f *GuestRetirementForwardRecoveryFixture) RetirementStore() CapacityStore {
	return f.Store.WithOriginalGuestRetirement(f.step("retire-original-guest"), capacity.CurrentGuestCoreSource()).WithOriginalGuestNotifyCanary(f.step("retire-original-guest"), capacity.CurrentGuestCoreSource())
}
func (f *GuestRetirementForwardRecoveryFixture) FinishStore() CapacityStore {
	return f.Store.WithOriginalGuestNotifyCanary(f.step("finish-original-retirement"), capacity.CurrentGuestCoreSource())
}
func (f *GuestRetirementForwardRecoveryFixture) PlanStore() CapacityStore {
	return f.Store.WithOriginalGuestReconcile(f.Workflow, f.step("plan-original-guest"), capacity.CurrentGuestCoreSource(), "retire", f.Request.Intent.RequestID, f.Inventory(true), model.CapacityMetricRangeObservation{})
}

func forwardFixtureVMLabelDigest(digest string) string {
	raw, err := hex.DecodeString(digest)
	if err != nil {
		return ""
	}
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw))
}

func (f *GuestRetirementForwardRecoveryFixture) Inventory(targetPresent bool) model.CapacityVMFleetInventory {
	t := f.t
	inv := capacity.RecoveryFixtureInventory(t, f.Spec, f.private.reg, time.Now().UTC())
	inv.Members = nil
	inv.MissingSlots = nil
	m := f.Spec.MutationBindings[0]
	for j, x := range f.members {
		slot := j + 1
		if !targetPresent && slot == len(f.members) {
			continue
		}
		d := m.Slots[j]
		labels := map[string]string{"yggdrasil.io/owner": f.Spec.Owner, "yggdrasil.io/scope": forwardFixtureVMLabelDigest(m.ScopeChecksum), "yggdrasil.io/spec": forwardFixtureVMLabelDigest(d.DesiredSpec.ProfileChecksum), "yggdrasil.io/profile": m.ProfileName, "yggdrasil.io/slot": strconv.Itoa(slot), "yggdrasil.io/intent": x.pre.OriginalCreateGrantID}
		server := model.CapacityVMServerObservation{CapacityVMNativeTuple: model.CapacityVMNativeTuple{ID: x.reg.Result.Tuple.ResourceID, CreatedAt: x.reg.Result.Tuple.CreatedAt}, Name: d.DesiredSpec.NativeName, Status: "running", PhysicalSpecVerified: true, ObservedAt: inv.ObservedAt, Labels: labels}
		inv.Members = append(inv.Members, model.CapacityVMFleetInventoryMember{Slot: slot, Protected: slot <= m.ProtectedSlots, DesiredSpec: *d.DesiredSpec, RequestSHA256: d.DesiredSpecSHA256, Server: server})
	}
	for slot := 1; slot <= m.MaxSlots; slot++ {
		if slot > len(f.members) || (!targetPresent && slot == len(f.members)) {
			inv.MissingSlots = append(inv.MissingSlots, slot)
		}
	}
	return inv
}

// Canaries performs each real publication/read once; it waits for the actual
// PG publication interval before creating a fresh five-second context.
func (f *GuestRetirementForwardRecoveryFixture) Canaries(usage string) {
	t := f.t
	store := f.RetirementStore()
	if usage == "after_retirement_floor" {
		store = f.FinishStore()
	}
	for _, member := range f.members[:len(f.members)-1] {
		var delay float64
		if err := f.DB.QueryRow(`SELECT COALESCE(GREATEST(0,EXTRACT(EPOCH FROM(max(recorded_at)+$1*interval '1 second'-clock_timestamp()))),0) FROM public.capacity_guest_notify_canary_challenges WHERE phase='publish' AND preregistration_id=$2`, f.Spec.GuestNotifyCanaryBinding.MinimumPublicationIntervalSeconds, member.pre.PreregistrationID).Scan(&delay); err != nil || delay > 6 {
			t.Fatal("bounded real publication interval", delay, err)
		}
		if delay > 0 {
			time.Sleep(time.Duration(delay*float64(time.Second)) + 5*time.Millisecond)
		}
		ctx, stop := context.WithTimeout(context.Background(), 30*time.Second)
		if usage == "before_retirement_floor" {
			next, err := f.Store.Renew(ctx, f.Policy, f.Intent.Generation, f.Intent.FencingToken, f.Intent.LeaseOwner)
			if err != nil {
				stop()
				t.Fatal(err)
			}
			f.Intent = next
		}
		probe := func(c model.CapacityGuestNotifyCanaryChallenge, pub *capacity.GuestNotifyPublicationReply) *capacity.GuestNotifyPublicationReply {
			c = capacity.RecoveryFixtureCanaryNonce(t, c, member.receipt.Enrollment)
			if err := store.FinalizeGuestNotifyCanaryNonce(ctx, f.Policy, f.Intent.Generation, f.Intent.FencingToken, f.Intent.LeaseOwner, c, failedServingHTTP(t, c.GuestNonce, time.Now().UTC())); err != nil {
				t.Fatal("forward survivor nonce", err)
			}
			if err := store.ReserveGuestNotifyCanarySend(ctx, f.Policy, f.Intent.Generation, f.Intent.FencingToken, f.Intent.LeaseOwner, c); err != nil {
				t.Fatal("forward survivor send", err)
			}
			reply, facts := capacity.RecoveryFixtureCanaryResponse(t, f.Spec, c, member.receipt.Enrollment, pub)
			returned := failedServingHTTP(t, reply, reply.OriginalReadStartedAt.Add(-time.Millisecond))
			if d := time.Until(returned.DriverReturnedAt) + time.Millisecond; d > 0 {
				time.Sleep(d)
			}
			if _, err := store.RecordGuestNotifyCanaryReturn(ctx, f.Policy, f.Intent.Generation, f.Intent.FencingToken, f.Intent.LeaseOwner, c, returned); err != nil {
				t.Fatal("forward survivor useful", err)
			}
			return facts
		}
		pub, err := store.IssueGuestNotifyCanaryPublication(ctx, f.Policy, f.Intent.Generation, f.Intent.FencingToken, f.Intent.LeaseOwner, member.pre.PreregistrationID, usage, failedServingKey('c'))
		if err != nil {
			stop()
			t.Fatal("forward survivor publish", err)
		}
		facts := probe(pub, nil)
		read, err := store.IssueGuestNotifyCanaryRead(ctx, f.Policy, f.Intent.Generation, f.Intent.FencingToken, f.Intent.LeaseOwner, member.pre.PreregistrationID, usage, pub.ChallengeID, failedServingKey('c'))
		if err != nil {
			stop()
			t.Fatal(err)
		}
		probe(read, facts)
		stop()
	}
}

func (f *GuestRetirementForwardRecoveryFixture) startDispatch() {
	t := f.t
	pin := func(m model.Manifest) CapacityDispatchManifestPin {
		return CapacityDispatchManifestPin{ID: m.ID, Namespace: m.Metadata.Namespace, Name: m.Metadata.Name, Version: m.Version, Checksum: m.Checksum}
	}
	rbac := CapacityDispatchManifestPin{ID: uuid.New(), Namespace: f.Policy.Metadata.Namespace, Name: "failed-serving-unit-rbac", Version: 1, Checksum: capacityDispatchSHA([]byte("declared-forward-rbac"))}
	if f.envelope.RBAC.ID != uuid.Nil {
		rbac = f.envelope.RBAC
	} else {
		f.private.exec(t, `INSERT INTO public.manifests(id,api_version,kind,namespace,name,version,checksum,spec,active)VALUES($1,'v1','rbac',$2,$3,1,$4,'{}'::jsonb,true)`, rbac.ID, rbac.Namespace, rbac.Name, rbac.Checksum)
	}
	e := CapacityDispatchEnvelope{Protocol: CapacityDispatchProtocol, JobID: uuid.New(), RunID: uuid.New(), Realm: f.Policy.Metadata.Namespace, Environment: f.Spec.Environment, Domain: f.Spec.Domain, Dimension: f.Spec.Dimension, SourceTick: time.Now().UTC().Truncate(time.Second).Format(time.RFC3339), Policy: pin(f.Policy), Workflow: pin(f.Workflow), RBAC: rbac, MachinePrincipalID: "capacity-controller", PrincipalSHA256: capacityDispatchSHA([]byte("declared-forward-principal")), BindingSHA256: capacityDispatchSHA([]byte("declared-forward-binding"))}
	e.Inputs = map[string]any{"policy": map[string]any{"namespace": f.Policy.Metadata.Namespace, "name": f.Policy.Metadata.Name}}
	e.Metadata = map[string]any{WorkflowRunCreatorMachinePrincipalMetadataKey: e.MachinePrincipalID, "triggered_by": "workflow_scheduler", "manifest_id": f.Workflow.ID.String(), "scheduled_for": e.SourceTick, "capacity_dispatch_job_id": e.JobID.String(), "capacity_dispatch_protocol": e.Protocol}
	var err error
	e.InputsSHA256, e.MetadataSHA256, err = CapacityDispatchEnvelopeHashes(e)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := f.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, _, err = EnqueueCapacityDispatch(context.Background(), tx, e); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	j, err := ClaimCapacityDispatch(context.Background(), f.DB, e.Realm, e.Environment, uuid.New(), time.Duration(f.Spec.LeaseSeconds)*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	j, err = StartCapacityDispatch(context.Background(), f.DB, j)
	if err != nil {
		t.Fatal(err)
	}
	f.job, f.envelope, f.RunID = j, e, e.RunID
	f.Store.OriginalRunID = e.RunID
}

func (f *GuestRetirementForwardRecoveryFixture) makeOriginal(count int) {
	t := f.t
	deadline := time.Now().Add(30 * time.Second)
	if f.fractionalOriginal {
		deadline = time.Now().UTC().Truncate(time.Microsecond).Add(4*time.Second + 789*time.Nanosecond)
	}
	ctx, stop := context.WithDeadline(context.Background(), deadline)
	defer stop()
	owner, err := capacity.NewGuestRetirementV2OriginalOwner(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	store := f.RetirementStore()
	preflight, err := store.IssueGuestRetirementV2(owner, f.Policy, f.Intent.Generation, f.Intent.FencingToken, f.Intent.LeaseOwner, f.Pre.PreregistrationID, capacity.BusinessCreationSHA256([]byte(uuid.NewString())), failedServingKey('c'))
	if err != nil {
		t.Fatal("ordinary tail V2 issue", err)
	}
	if err = owner.AcquireNonce(capacity.RecoveryFixtureRetirementNonceClient(t, preflight, f.Receipt.Enrollment), failedServingKey('c'), preflight, f.Receipt.Enrollment); err != nil {
		t.Fatal(err)
	}
	if err = store.FinalizeGuestRetirementV2Nonce(owner); err != nil {
		t.Fatal(err)
	}
	if err = store.ReserveGuestCallerV2(owner); err != nil {
		t.Fatal(err)
	}
	f.Request, _, _, err = owner.NonceExchange()
	if err != nil {
		t.Fatal(err)
	}
	callerStarted := time.Now().UTC()
	f.Journal = capacity.RecoveryFixtureRetirementJournal(t, f.Request.Intent, f.Receipt.Enrollment)
	authority := func(phase string, observed *model.CapacityGuestRetirementObservationV2) {
		read, e := store.ReserveGuestAuthorityReadV2(ctx, f.Spec.GuestRetirementBinding.Members[f.Pre.Slot-1].ActorClientPrincipal, f.Request.Intent.RequestID, capacity.GuestRetirementSHA(f.Request.Intent), phase)
		if e != nil {
			t.Fatal("real authority reserve", e)
		}
		if observed != nil {
			ret := failedServingHTTP(t, *observed, time.Now().UTC())
			if d := time.Until(ret.DriverReturnedAt) + time.Millisecond; d > 0 {
				time.Sleep(d)
			}
			if e = store.RecordGuestAuthorityTransportV2(ctx, read, ret); e != nil {
				t.Fatal("real authority transport", e)
			}
		}
		if _, e = store.FinishGuestAuthorityReadV2(ctx, read, observed); e != nil {
			parentDeadline, _ := ctx.Deadline()
			t.Fatalf("real authority return phase=%s ordinal=%d ctx_err=%v parent_remaining=%s read_remaining=%s: %v later_diagnostics=%s", phase, read.Ordinal, ctx.Err(), time.Until(parentDeadline), time.Until(read.Deadline), e, f.AdmissionDiagnostics())
		}
	}
	authority("before_start", nil)
	for n := 0; n < count; n++ {
		o := f.Journal[n]
		if d := time.Until(o.ObservedAt) + time.Millisecond; d > 0 {
			time.Sleep(d)
		}
		if err = store.RecordGuestObservationV2(ctx, f.Request.Intent.RequestID, o); err != nil {
			t.Fatal("real retained signed prefix", n, err)
		}
		switch n {
		case 0:
			authority("before_start", &o)
		case 1:
			authority("before_poweroff", &o)
		case 2:
			authority("before_poweroff", &o)
		}
	}
	start := time.Now().UTC()
	f.Caller = GuestOriginalCallerReturn{RequestID: f.Request.Intent.RequestID, AttemptID: f.Request.Intent.AttemptID, StartedAt: callerStarted, DoStartedAt: callerStarted.Add(time.Millisecond), DoReturnedAt: start.Add(2 * time.Millisecond), DriverReturnedAt: start.Add(3 * time.Millisecond), OriginalDeadline: f.Request.Intent.OriginalDeadline, DoFailed: true, Body: []byte{}, ResponseBodyScope: capacity.GuestOriginalBodyNoRead, RetainedPrefixSHA256: capacity.BusinessCreationSHA256(nil)}
	if f.ordinarySuccess {
		if count != 4 {
			t.Fatal("ordinary fixture requires complete original journal before caller success")
		}
		body := failedServingWire(t, f.Journal[3])
		sha := capacity.BusinessCreationSHA256(body)
		f.Caller.DoFailed, f.Caller.Status, f.Caller.BodyPersisted = false, 200, true
		f.Caller.Body = body
		f.Caller.ReadReturnedAt = start.Add(3 * time.Millisecond)
		f.Caller.CloseReturnedAt = start.Add(4 * time.Millisecond)
		f.Caller.DriverReturnedAt = start.Add(5 * time.Millisecond)
		f.Caller.ReceivedBodyBytes, f.Caller.RetainedPrefixBytes = len(body), len(body)
		f.Caller.ResponseSHA256, f.Caller.RetainedPrefixSHA256 = sha, sha
		f.Caller.ResponseBodyScope = capacity.GuestOriginalBodyCompleteRead
	}
	time.Sleep(time.Until(f.Caller.DriverReturnedAt) + time.Millisecond)
	if err = store.RecordGuestCallerReturnV2(ctx, f.Caller); err != nil {
		t.Fatal("real failed caller retained", err)
	}
}

func (f *GuestRetirementForwardRecoveryFixture) HistoricalRequest() model.CapacityGuestRetirementForwardRequest {
	var raw []byte
	if err := f.DB.QueryRow(`SELECT intent::text FROM public.capacity_intents WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4`, f.Policy.Metadata.Namespace, f.Spec.Environment, f.Spec.Domain, f.Spec.Dimension).Scan(&raw); err != nil {
		f.t.Fatal(err)
	}
	var i model.CapacityIntent
	if json.Unmarshal(raw, &i) != nil {
		f.t.Fatal("current intent")
	}
	f.Intent = i
	return model.CapacityGuestRetirementForwardRequest{PreregistrationID: f.Pre.PreregistrationID, RetirementRequestID: f.Request.Intent.RequestID, PolicyID: f.Policy.ID.String(), PolicyChecksum: f.Policy.Checksum, Generation: i.Generation, FencingToken: i.FencingToken, IntentSHA256: capacity.BusinessCreationSHA256(raw)}
}

// FinishFailedRun keeps the original caller failure and exact seven-step plan.
// It can represent a failed retire or failed finish after a live admission.
func (f *GuestRetirementForwardRecoveryFixture) FinishFailedRun(failedStep string) {
	_ = f.HistoricalRequest() // Read the actual current marker/epoch before the immutable run return.
	forwardID := ""
	if f.Intent.RetirementForward != nil {
		forwardID = f.Intent.RetirementForward.ID
	}
	if failedStep != "retire-original-guest" && failedStep != "finish-original-retirement" {
		f.t.Fatal("closed failed step")
	}
	r := model.RunWorkflowResponse{Workflow: model.ManifestReference{ID: f.Workflow.ID, Kind: "workflow", Namespace: f.Workflow.Metadata.Namespace, Name: f.Workflow.Metadata.Name, Version: f.Workflow.Version}, Status: "failed"}
	for _, step := range f.private.steps {
		x := model.WorkflowRunStepResult{ID: step.ID, Status: "skipped"}
		switch step.ID {
		case "plan-original-guest":
			x.Status = "succeeded"
			x.Metadata = map[string]any{"mode": "retire", "generation": f.Intent.Generation, "fencing_token": f.Intent.FencingToken, "lease_owner": f.Intent.LeaseOwner, "preregistration_id": f.Pre.PreregistrationID, "slot": f.Pre.Slot, "request_id": f.Request.Intent.RequestID}
		case "retire-original-guest":
			x.Status = "succeeded"
			x.Metadata = map[string]any{"request_id": f.Request.Intent.RequestID, "retirement_forward_id": forwardID, "normal_guest_success": false}
		}
		if step.ID == failedStep {
			x.Status = "failed"
			x.Error = "original_guest_partial_poweroff_return_unknown"
		}
		r.Steps = append(r.Steps, x)
	}
	if err := FinishCapacityDispatch(context.Background(), f.DB, f.job, r, time.Now().UTC(), nil); err != nil {
		f.t.Fatal("real failed dispatch finalization", err)
	}
}

// WaitHistoricalBarrier observes natural expiry only. It never modifies old
// deadlines, leases, ACKs or process metadata. The returned process operand is
// explicitly DECLARED for DAO tests; HTTP tests must start a real child AFTER
// this wait if they require the handler's actual current-process barrier.
func (f *GuestRetirementForwardRecoveryFixture) WaitHistoricalBarrier() CapacityDispatchExecutorBarrier {
	f.t.Helper()
	var delay float64
	if err := f.DB.QueryRow(`SELECT GREATEST(0,EXTRACT(EPOCH FROM(GREATEST((c.intent->>'lease_expires_at')::timestamptz,r.original_deadline,x.original_context_deadline)-clock_timestamp()))) FROM public.capacity_vm_retirement_intents r JOIN public.capacity_guest_original_retirement_contexts x ON x.intent_id=r.id CROSS JOIN public.capacity_intents c WHERE r.id=$1 AND c.namespace=$2`, f.Request.Intent.RequestID, f.Policy.Metadata.Namespace).Scan(&delay); err != nil || delay > 31 {
		f.t.Fatal("bounded actual original expiry", delay, err)
	}
	if delay > 0 {
		time.Sleep(time.Duration(delay*float64(time.Second)) + 10*time.Millisecond)
	}
	return CapacityDispatchExecutorBarrier{ProcessStartedAt: time.Now().UTC(), Hostname: "declared-forward-dao-test-process", PID: 4242, SourceCommit: capacity.CurrentGuestCoreSource()}
}

func (f *GuestRetirementForwardRecoveryFixture) NativeOffReturn(read GuestRetirementForwardRead, status string) GuestRetirementForwardReadReturn {
	plan := capacity.RecoveryFixtureNativeOffPlan(f.t, f.Spec, f.Pre, f.Receipt.Enrollment.Statement.Tuple)
	if f.Spec.Profiles[0].Provider == "aws" {
		plan.DesiredSpec.Capability = "observe_ec2_instance"
		plan.RequestSHA256 = f.Spec.MutationBindings[0].Slots[f.Pre.Slot-1].DesiredSpecSHA256
		plan.Server.Status = "stopped"
	}
	if status != "" {
		plan.Server.Status = status
	}
	at := time.Now().UTC()
	return GuestRetirementForwardReadReturn{Schema: GuestRetirementForwardReadReturnSchema, Read: read, Status: "observed", Plan: &plan, StartedAtCore: at, OriginalReturnedAtCore: at}
}

func (f *GuestRetirementForwardRecoveryFixture) PreservedOriginals() map[string]string {
	out := map[string]string{}
	for _, m := range f.members {
		for k, v := range m.preserved(f.t) {
			// New useful canaries are expected; original provisioning and the
			// complete retirement frame remain immutable independently.
			if k == "challenges" || k == "nonces" || k == "sends" || k == "returns" {
				continue
			}
			out[m.pre.PreregistrationID+":"+k] = v
		}
	}
	var raw []byte
	if err := f.DB.QueryRow(`SELECT jsonb_build_object('intent',(SELECT encode(original_wire,'hex') FROM public.capacity_vm_retirement_intents WHERE id=$1),'returns',(SELECT jsonb_agg(to_jsonb(r) ORDER BY sequence) FROM public.capacity_vm_retirement_original_returns r WHERE intent_id=$1),'contexts',(SELECT to_jsonb(c) FROM public.capacity_guest_original_retirement_contexts c WHERE intent_id=$1),'caller',(SELECT to_jsonb(c) FROM public.capacity_guest_original_caller_returns c WHERE intent_id=$1),'attempt',(SELECT to_jsonb(a) FROM public.capacity_guest_original_caller_attempts a WHERE intent_id=$1),'reads',(SELECT jsonb_agg(to_jsonb(r) ORDER BY phase,ordinal) FROM public.capacity_guest_original_authority_reads r WHERE intent_id=$1),'authorities',(SELECT jsonb_agg(to_jsonb(v) ORDER BY v.read_id) FROM public.capacity_guest_original_authority_returns v JOIN public.capacity_guest_original_authority_reads r ON r.id=v.read_id WHERE r.intent_id=$1),'transports',(SELECT jsonb_agg(to_jsonb(v) ORDER BY v.read_id) FROM public.capacity_guest_original_authority_transport_returns v JOIN public.capacity_guest_original_authority_reads r ON r.id=v.read_id WHERE r.intent_id=$1))::text`, f.Request.Intent.RequestID).Scan(&raw); err != nil {
		f.t.Fatal(err)
	}
	out["whole-retained-retirement-frame"] = capacity.BusinessCreationSHA256(raw)
	for _, entry := range []struct{ name, query string }{
		{"old_canary_challenges", `SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY id),'[]'::jsonb)::text FROM public.capacity_guest_notify_canary_challenges t WHERE id::text=ANY($1::text[])`},
		{"old_canary_nonces", `SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY challenge_id),'[]'::jsonb)::text FROM public.capacity_guest_notify_canary_nonces t WHERE challenge_id::text=ANY($1::text[])`},
		{"old_canary_sends", `SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY challenge_id),'[]'::jsonb)::text FROM public.capacity_guest_notify_canary_sends t WHERE challenge_id::text=ANY($1::text[])`},
		{"old_canary_returns", `SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY challenge_id),'[]'::jsonb)::text FROM public.capacity_guest_notify_canary_returns t WHERE challenge_id::text=ANY($1::text[])`},
	} {
		if err := f.DB.QueryRow(entry.query, pq.Array(f.retainedCanaryIDs)).Scan(&raw); err != nil {
			f.t.Fatal(err)
		}
		out[entry.name] = capacity.BusinessCreationSHA256(raw)
	}
	if err := f.DB.QueryRow(`SELECT row_to_json(w)::text FROM public.workflow_runs w WHERE id=$1`, f.originalRunID).Scan(&raw); err != nil {
		f.t.Fatal(err)
	}
	out["original_workflow_run"] = capacity.BusinessCreationSHA256(raw)

	return out
}

// DestroySettlement and NativeAbsenceReturn declare provider DTOs only; callers
// still must use the real Issue/Redeem/Settle/read/Confirm APIs. They do not write
// rows, resolve unknown outcomes, issue native DELETE or confer any authority.
func (f *GuestRetirementForwardRecoveryFixture) DestroySettlement(grant model.CapacityMutationGrant, attempt string) model.CapacityMutationSettleRequest {
	at := time.Now().UTC()
	stamp := at.Format(time.RFC3339Nano)
	provider := f.Spec.Profiles[0].Provider
	action, schema, status := "99", "hetzner_original_delete_server_return_v1", 200
	aux := []model.CapacityMutationAuxiliaryResource{{Kind: "ssh_key", ID: "declared-owned-forward-key", RequiresAbsence: true}}
	if provider == "aws" {
		action, schema = uuid.NewString(), "aws_original_terminate_instances_return_v1"
		aux = []model.CapacityMutationAuxiliaryResource{{Kind: "aws_ebs_volume", ID: "vol-00000000000000456", RequiresAbsence: true}, {Kind: "aws_network_interface", ID: "eni-00000000000000456", RequiresAbsence: true}}
	}
	s := model.CapacityMutationSettleRequest{GrantID: grant.GrantID, AttemptID: attempt, RequestSHA256: grant.RequestSHA256, Outcome: "accepted", TransportCompleted: true, ResourceID: grant.ExpectedResourceID, ResourceCreatedAt: grant.ExpectedResourceCreatedAt, ActionID: action, NextActionIDs: []string{}, AuxiliaryResources: aux, AuxiliaryInventoryComplete: true, ObservedAt: stamp}
	if provider == "aws" {
		declaredBody := []byte("declared-original-forward-delete-return")
		s.OriginalProviderDestroyReturn = &model.CapacityOriginalProviderDestroyReturn{Schema: schema, Provider: provider, AdapterSourceCommit: f.Spec.MutationBindings[0].OriginalProviderSourceCommit, GrantID: grant.GrantID, AttemptID: attempt, RequestSHA256: grant.RequestSHA256, ResourceID: grant.ExpectedResourceID, ResourceCreatedAt: grant.ExpectedResourceCreatedAt, ActionID: action, NextActionIDs: []string{}, CalledAt: stamp, ReturnedAt: stamp, ContextDeadline: at.Add(5 * time.Second).Format(time.RFC3339Nano), ResponseStatus: status, ResponseBodySHA256: capacity.BusinessCreationSHA256(declaredBody), ResponseBytes: int64(len(declaredBody))}
	}

	return s
}
func (f *GuestRetirementForwardRecoveryFixture) NativeAbsenceReturn(read GuestRetirementForwardRead, receipt model.CapacityMutationReceipt) GuestRetirementForwardReadReturn {
	o, at := f.nativeAbsenceObservation(receipt)
	returned := GuestRetirementForwardReadReturn{Schema: GuestRetirementForwardReadReturnSchema, Read: read, Status: "observed", Observation: &o, OriginalDestroyReceipt: &receipt, StartedAtCore: at, OriginalReturnedAtCore: at}
	if read.Tuple.Provider == "aws" && read.AdapterSourceCommit == enrolledFailedAWSCreator {
		// Declared fresh response, never a publication claim or fallback fixture
		// pin. CI must run only after Root binds the actual qualified publication.
		source := RetirementReadonlyAWSObserverSource()
		if !originalDispositionHex(source, 40) {
			f.t.Fatal("actual dedicated retirement observer Source must be bound before qualification")
		}
		wire := GuestRetirementReadonlyReturn{Schema: GuestRetirementReadonlyReturnSchema, ObserverSourceCommit: source, OriginalAdapterSourceCommit: read.AdapterSourceCommit, ReadID: read.ReadID, ReadSHA256: capacity.GuestRetirementSHA(read), OriginalReceiptSHA256: capacity.GuestRetirementSHA(receipt), Observation: o}
		returned.ObserverSourceCommit = source
		var err error
		returned.OriginalObserverReturn, err = json.Marshal(wire)
		if err != nil {
			f.t.Fatal(err)
		}
	}
	return returned
}

// A shared declared provider DTO has no read/admission identity of its own.
func (f *GuestRetirementForwardRecoveryFixture) nativeAbsenceObservation(receipt model.CapacityMutationReceipt) (model.CapacityVMRetirementObservation, time.Time) {
	at := time.Now().UTC()
	stamp := at.Format(time.RFC3339Nano)
	g := receipt.Grant
	o := model.CapacityVMRetirementObservation{CapacityVMNativeTuple: model.CapacityVMNativeTuple{ID: g.ExpectedResourceID, CreatedAt: g.ExpectedResourceCreatedAt}, DestroyGrantID: g.GrantID, DestroyGrantState: g.State, CompensationOf: g.CompensationOf, OriginalOutcome: receipt.Outcome, OriginalTransportCompleted: receipt.TransportCompleted, ServerAbsent: true, ServerAbsenceComplete: true, ServerObservedAt: stamp, NextActions: []model.CapacityVMActionObservation{}, AuxiliaryResources: []model.CapacityVMAuxiliaryObservation{}, AuxiliaryInventoryComplete: true, BillableResourcesAbsent: true, RetirementComplete: true, HoldReasons: []string{}, ObservationStartedAt: stamp, ObservedAt: stamp}
	for _, a := range receipt.AuxiliaryResources {
		o.AuxiliaryResources = append(o.AuxiliaryResources, model.CapacityVMAuxiliaryObservation{Kind: a.Kind, ID: a.ID, Absent: true, ObservedAt: stamp})
	}
	if f.Spec.Profiles[0].Provider == "aws" {
		o.AWSRetirementLifecycle = &model.CapacityAWSRetirementLifecycle{Schema: "aws_original_terminate_and_native_absence_v1", RequestID: receipt.ActionID, EC2State: "terminated", ObservedAt: at}
	} else {
		o.DeleteAction = model.CapacityVMRetirementAction{Known: true, Observed: true, ID: receipt.ActionID, Status: "success", Command: "delete_server", StartedAt: stamp, FinishedAt: stamp}
		x := &model.CapacityVMBillingExposure{Basis: "profile_admission_ceiling_not_invoice", Currency: capacity.NativeBillingCurrency(f.Spec), WindowStart: g.ExpectedResourceCreatedAt, WindowEndUpperBound: stamp, WindowEndSource: "native_delete_action_finished", Resources: []model.CapacityVMBillableResourceWindow{{Kind: "server", ID: g.ExpectedResourceID, WindowStart: g.ExpectedResourceCreatedAt, WindowStartSource: "native_server_created_at", WindowEndUpperBound: stamp, WindowEndSource: "native_delete_action_finished", StartedHoursUpperBound: 3}}, StartedHoursUpperBound: 3, CalendarMonthsUpperBound: 1, ExcludedCosts: []string{"declared source fixture; not invoice"}}
		for _, aux := range receipt.AuxiliaryResources {
			x.Resources = append(x.Resources, model.CapacityVMBillableResourceWindow{Kind: aux.Kind, ID: aux.ID, WindowStart: g.ExpectedResourceCreatedAt, WindowStartSource: "server_creation_proxy_not_native_ip_creation", WindowEndUpperBound: stamp, WindowEndSource: "first_complete_absence_observation", StartedHoursUpperBound: 3})
		}
		o.BillingExposure = x
	}
	return o, at
}

func (f *GuestRetirementForwardRecoveryFixture) OrdinaryAbsenceReturn(read GuestNativePoweroffReadV2, receipt model.CapacityMutationReceipt) GuestNativeAbsenceReturnV2 {
	f.t.Helper()
	o, at := f.nativeAbsenceObservation(receipt)
	r := GuestNativeAbsenceReturnV2{Schema: "original_core_guest_native_absence_return_v2", Challenge: read, DestroyGrantID: receipt.Grant.GrantID, OriginalDestroyReceiptSHA256: capacity.GuestRetirementSHA(receipt), OriginalDestroyReceipt: &receipt, Status: "observed", Observation: &o, StartedAtCore: at, OriginalReturnedAtCore: at}
	if read.AdapterSourceCommit == enrolledFailedAWSCreator {
		source := RetirementReadonlyAWSObserverSource()
		if !originalDispositionHex(source, 40) {
			f.t.Fatal("actual dedicated ordinary retirement observer Source must be bound before qualification")
		}
		v := GuestRetirementReadonlyReturn{Schema: GuestRetirementReadonlyReturnSchema, ObserverSourceCommit: source, OriginalAdapterSourceCommit: read.AdapterSourceCommit, ReadID: read.ReadID, ReadSHA256: capacity.GuestRetirementSHA(read), OriginalReceiptSHA256: capacity.GuestRetirementSHA(receipt), Observation: o}
		r.ObserverSourceCommit = source
		r.OriginalObserverReturn = failedServingWire(f.t, v)
	}
	return r
}

// SettledOrdinaryDestroy exercises existing original success, fresh OFF,
// survivor floor, drain, grant, redeem and settlement APIs in CI only. No
// forward admission or provider call is used, and no stored original changes.
func (f *GuestRetirementForwardRecoveryFixture) SettledOrdinaryDestroy() model.CapacityMutationReceipt {
	f.t.Helper()
	if !f.ordinarySuccess {
		f.t.Fatal("ordinary successful caller constructor required")
	}
	ctx, stop := context.WithTimeout(context.Background(), 30*time.Second)
	defer stop()
	finish := f.FinishStore()
	f.Canaries("after_retirement_floor")
	if members, pending, err := f.PlanStore().OriginalGuestReconcileMembers(ctx, f.Policy); err != nil || pending || len(members) != len(f.members) {
		f.t.Fatal("ordinary current native inventory", err)
	}
	read, err := finish.PrepareGuestNativePoweroffReadV2(ctx, f.Request.Intent.RequestID)
	if err != nil {
		f.t.Fatal("ordinary signed success native OFF prepare", err)
	}
	plan := capacity.RecoveryFixtureNativeOffPlan(f.t, f.Spec, f.Pre, f.Receipt.Enrollment.Statement.Tuple)
	if f.Spec.Profiles[0].Provider == "aws" {
		plan.DesiredSpec.Capability, plan.Server.Status = "observe_ec2_instance", "stopped"
		plan.RequestSHA256 = f.Spec.MutationBindings[0].Slots[f.Pre.Slot-1].DesiredSpecSHA256
	}
	at := time.Now().UTC()
	if err = finish.RecordGuestNativePoweroffV2(ctx, GuestNativePoweroffReturnV2{Schema: "original_core_guest_native_poweroff_read_return_v2", Challenge: read, Status: "observed", Plan: &plan, StartedAtCore: at, OriginalReturnedAtCore: at}); err != nil {
		f.t.Fatal("ordinary original OFF join", err)
	}
	f.Intent, err = finish.AdvanceGuestRetirementDrainedV2(ctx, f.Policy, f.Intent.Generation, f.Intent.FencingToken, f.Intent.LeaseOwner, f.Request.Intent.RequestID, f.Pre.PreregistrationID, f.Pre.Slot)
	if err != nil {
		f.t.Fatal("ordinary original drain", err)
	}
	b := f.Spec.MutationBindings[0]
	spec := *b.Slots[f.Pre.Slot-1].DesiredSpec
	spec.Capability, spec.ExpectedResourceID, spec.ExpectedResourceCreatedAt = b.DestroyCapability, f.Request.Intent.Tuple.ResourceID, f.Request.Intent.Tuple.CreatedAt
	grant, err := finish.IssueMutation(ctx, f.Policy, f.Intent.Generation, f.Intent.FencingToken, f.Intent.LeaseOwner, model.CapacityMutationIssue{BindingName: b.Name, DesiredSpec: failedServingWire(f.t, spec)})
	if err != nil {
		f.t.Fatal("ordinary one destroy grant", err)
	}
	callback := CapacityStore{DB: f.DB, ExecutionEnabled: true}
	nonce := uuid.NewString()
	request := model.CapacityMutationRedeemRequest{GrantID: grant.GrantID, Capability: grant.Capability, IntegrationInstanceID: grant.IntegrationInstanceID, ScopeChecksum: grant.ScopeChecksum, ProfileName: grant.ProfileName, Slot: grant.Slot, RequestSHA256: grant.RequestSHA256, AttemptID: uuid.NewString(), SettlementTokenSHA256: capacity.BusinessCreationSHA256([]byte(nonce)), ExpectedResourceID: grant.ExpectedResourceID, ExpectedResourceCreatedAt: grant.ExpectedResourceCreatedAt, CompensationOf: grant.CompensationOf}
	permit, err := callback.RedeemMutation(ctx, b.AdapterPrincipalID, request)
	if err != nil || permit.Mode != "write_once" {
		f.t.Fatal("ordinary single redemption", err)
	}
	if _, err = callback.SettleMutation(ctx, b.AdapterPrincipalID, nonce, f.DestroySettlement(grant, request.AttemptID)); err != nil {
		f.t.Fatal("ordinary settled original destroy", err)
	}
	receipt, err := finish.NativeMutationReceipt(ctx, f.Policy, b, grant.GrantID)
	if err != nil || receipt.Grant.State != "settled" {
		f.t.Fatal("ordinary actual settled receipt", err)
	}
	return receipt
}

// CompletionOperands is explicitly declared memberCoverage30/Demand300 input,
// not an adapter/Prometheus read. No policy/budget/min61 field is changed.
func (f *GuestRetirementForwardRecoveryFixture) CompletionOperands() (CapacityStore, model.CapacityAssessment) {
	inv := f.Inventory(false)
	now := time.Now().UTC()
	snapshot, err := capacity.GuestReconcileSnapshot(f.Policy, f.Spec, inv, now)
	if err != nil {
		f.t.Fatal(err)
	}
	a := model.CapacityAssessment{Snapshot: snapshot}
	for _, signal := range f.Spec.Signals {
		value := 0.1
		a.Evidence = append(a.Evidence, model.CapacityEvidence{Name: signal.Name, SourceIdentity: signal.SourceIdentity, Unit: signal.Unit, RequireData: true, Matched: true, DataState: "present", Value: &value, RangeMin: &value, RangeMax: &value, SourceSampledAt: now, WindowStart: now.Add(-300 * time.Second), WindowEnd: now, Samples: f.Spec.MinSamples, CoverageComplete: true, MaxGapSeconds: 5})
	}
	b := f.Spec.GuestNotifyReconcileBinding.MemberCoverage
	count := float64(len(f.members) - 1)
	coverage := model.CapacityMetricRangeObservation{Operation: capacity.ObserveMetricRange, Binding: b.BindingName, BindingSHA256: b.BindingSHA256, EvaluatedAt: now, OK: true, Reason: "complete", CapacityEvidence: model.CapacityEvidence{Name: capacity.OriginalGuestMemberCoverageName, SourceIdentity: "production/notify/" + f.Spec.Profiles[0].Provider + "/reporting-members", Unit: "members", RequireData: true, Matched: true, DataState: "present", Value: &count, RangeMin: &count, RangeMax: &count, SourceSampledAt: now, WindowStart: now.Add(-30 * time.Second), WindowEnd: now, Samples: 7, CoverageComplete: true, MaxGapSeconds: 5}}
	return f.Store.WithOriginalGuestReconcile(f.Workflow, f.step("complete-original-retirement"), capacity.CurrentGuestCoreSource(), "retire", f.Request.Intent.RequestID, inv, coverage), a
}

// StartSuccessorDispatch enters the same real immutable Enqueue/Claim/Start
// protocol after the prior run returned; it never reuses the failed run ID.
func (f *GuestRetirementForwardRecoveryFixture) StartSuccessorDispatch() { f.startDispatch() }
