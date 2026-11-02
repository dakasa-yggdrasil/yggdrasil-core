package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// DECLARED storage histories shaped like production disposal 8ef5f76c
// (Hetzner gen8, blocked Guest b509.../c9b7...) and its AWS gen10 peer of the
// same Guest build. Explicitly isolated Unix-socket database (schema85). The
// rows are synthetic SQL operands, never a signed enrollment, a real canary,
// provider absence or a compiled production approval; no provider or Guest
// call is exercised. The Go admission path is only exercised up to its
// refusals; the positive acceptance is proven at the migration85 guard and the
// gate is exercised through its authority seam.

const externalCauseEvidence = "2026-11-02 ~07:20Z: RabbitMQ user dakasa-notify lacked read/configure on notify.guest-canary.*; fixed and made durable.\n" +
	"AWS gen10 (same Guest build) reached promoted with an accepted canary read at ~07:34Z."

type externalCauseOptions struct {
	requestedOnly     bool
	coreBoundMarker   bool
	peerSameDimension bool
	peerOtherSource   bool
	readBeforeFailure bool
	readHeld          bool
	peerNotPromoted   bool
	peerTombstone     bool
	peerRetired       bool
	intentOtherID     bool
}

type externalCauseFixture struct {
	db              *sql.DB
	ns              string
	scope           model.CapacityPolicySpec
	peerScope       model.CapacityPolicySpec
	source          string
	disposedBinding model.CapacityGuestRetirementBinding
	disposedPre     string
	disposedWire    []byte
	policyChecksum  string
	peerPre         string
	peerProfile     string
	disposal        FailedInstalledGuestDisposal
	policyID        uuid.UUID
	runID           uuid.UUID
	finishedAt      time.Time
	readID          string
	readAt          time.Time
	returnAt        time.Time
	resource        string
}

func externalCauseHex(n int) string {
	return strings.Repeat(strings.ReplaceAll(uuid.NewString(), "-", ""), 3)[:n]
}

func externalCauseGrant(t *testing.T, tx *sql.Tx, ctx context.Context, id, ns string, scope model.CapacityPolicySpec) {
	t.Helper()
	if _, err := tx.ExecContext(ctx, `INSERT INTO public.capacity_mutation_grants(id,namespace,environment,domain,dimension,generation,integration_instance_id,scope_checksum,profile_name,slot,state,grant_record,expires_at) VALUES($1,$2,$3,$4,$5,1,$6,$7,'external-cause-storage',2,'settled','{}'::jsonb,$8)`, id, ns, scope.Environment, scope.Domain, scope.Dimension, uuid.NewString(), externalCauseHex(64), time.Now().Add(-3*time.Hour)); err != nil {
		t.Fatal(err)
	}
}

func externalCausePre(t *testing.T, tx *sql.Tx, ctx context.Context, ns string, scope model.CapacityPolicySpec, source string) guestOriginalStorageFixture {
	t.Helper()
	f := guestOriginalStorageRecords(t)
	f.binding.GuestSourceCommit = source
	raw, err := json.Marshal(f.binding)
	if err != nil {
		t.Fatal(err)
	}
	f.bindingWire = raw
	externalCauseGrant(t, tx, ctx, f.pre.OriginalCreateGrantID, ns, scope)
	if _, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_vm_provisioning_preregistrations(id,create_grant_id,nonce_sha256,profile_manifest_sha256,preregistration_record,original_deadline,created_at,original_wire,binding_wire) VALUES($1,$2,$3,$4,$5::jsonb,$6,$7,$8,$9)`, f.pre.PreregistrationID, f.pre.OriginalCreateGrantID, f.pre.NonceSHA256, f.pre.ProfileManifestSHA256, string(f.wire), f.pre.OriginalDeadline, f.pre.ReservedAt, f.wire, f.bindingWire); err != nil {
		t.Fatal(err)
	}
	return f
}

// externalCauseDisposalChain writes requested (and, unless requestedOnly, the
// storage-only claimed, quiescent and terminal rows) for one disposed Guest.
func externalCauseDisposalChain(t *testing.T, tx *sql.Tx, ctx context.Context, r FailedInstalledGuestDisposal, requestedOnly bool) (FailedInstalledGuestDisposal, string) {
	t.Helper()
	sha, err := insertFailedInstalledDisposalTx(ctx, tx, r)
	if err != nil {
		t.Fatal("requested", err)
	}
	if requestedOnly {
		return r, sha
	}
	r.Stage = "claimed"
	r.AdmissionSHA256 = sha
	r.ClaimedIntent = &model.CapacityIntent{Generation: 8, FencingToken: 22}
	if _, err = insertFailedInstalledDisposalTx(ctx, tx, r); err != nil {
		t.Fatal("claimed", err)
	}
	r.Stage = "quiescent"
	r.RetirementRequestID = uuid.NewString()
	r.NativePoweroffSHA256 = externalCauseHex(64)
	if _, err = insertFailedInstalledDisposalTx(ctx, tx, r); err != nil {
		t.Fatal("quiescent", err)
	}
	r.Stage = "terminal"
	r.TerminalIssuer = "external-cause-storage-test"
	r.Observation = &model.CapacityOriginalCreateDispositionObservation{}
	r.ObservationSHA256 = externalCauseHex(64)
	if _, err = insertFailedInstalledDisposalTx(ctx, tx, r); err != nil {
		t.Fatal("terminal", err)
	}
	return r, sha
}

func externalCausePGFixture(t *testing.T, db *sql.DB, o externalCauseOptions) externalCauseFixture {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	must := func(q string, a ...any) {
		t.Helper()
		if _, err := tx.ExecContext(ctx, q, a...); err != nil {
			t.Fatal(err)
		}
	}
	short := externalCauseHex(8)
	f := externalCauseFixture{db: db, ns: "external-cause-" + uuid.NewString(), source: externalCauseHex(40), policyID: uuid.New(), runID: uuid.New()}
	f.scope = model.CapacityPolicySpec{Environment: "production", Domain: "notify", Dimension: "hetzner-vm-members-" + short}
	f.peerScope = model.CapacityPolicySpec{Environment: "production", Domain: "notify", Dimension: "aws-vm-members-" + short}
	if o.peerSameDimension {
		f.peerScope = f.scope
	}
	// Storage-only active policy revision of the disposal's scope: migration 85
	// re-derives admitted_policy_id/admitted_policy_checksum from it.
	f.policyChecksum = externalCauseHex(64)
	policyScope, err := json.Marshal(map[string]string{"environment": f.scope.Environment, "domain": f.scope.Domain, "dimension": f.scope.Dimension})
	if err != nil {
		t.Fatal(err)
	}
	must(`INSERT INTO public.manifests(id,api_version,kind,namespace,name,version,checksum,spec,active) VALUES($1,'v1','capacity_policy',$2,'hetzner',1,$3,$4::jsonb,true)`, f.policyID, f.ns, f.policyChecksum, string(policyScope))

	// The disposed Guest's original failed run, two hours ago.
	f.finishedAt = time.Now().UTC().Add(-2 * time.Hour).Truncate(time.Microsecond)
	must(`INSERT INTO public.workflow_runs(id,workflow_namespace,workflow_name,workflow_id,status,created_at,finished_at) VALUES($1,$2,'original-guest-reconcile',$3,'failed',$4,$5)`, f.runID, f.ns, f.policyID, f.finishedAt.Add(-time.Minute), f.finishedAt)
	var runWire string
	if err = tx.QueryRowContext(ctx, `SELECT row_to_json(w)::text FROM public.workflow_runs w WHERE id=$1`, f.runID).Scan(&runWire); err != nil {
		t.Fatal(err)
	}

	disposed := externalCausePre(t, tx, ctx, f.ns, f.scope, f.source)
	f.disposedPre, f.disposedBinding, f.disposedWire = disposed.pre.PreregistrationID, disposed.binding, disposed.bindingWire
	peerSource := f.source
	if o.peerOtherSource {
		peerSource = externalCauseHex(40)
	}
	peer := externalCausePre(t, tx, ctx, f.ns, f.peerScope, peerSource)
	f.peerPre, f.peerProfile = peer.pre.PreregistrationID, peer.binding.ProfileManifestSHA256
	must(`INSERT INTO public.capacity_vm_original_enrollments(preregistration_id,resource_tuple_sha256,enrollment_sha256,original_provisioning_sha256,enrollment_record,recorded_at) VALUES($1,$2,$3,$4,'{}'::jsonb,$5)`, f.peerPre, externalCauseHex(64), externalCauseHex(64), externalCauseHex(64), peer.pre.ReservedAt)

	r := FailedInstalledGuestDisposal{Schema: "failed_installed_guest_disposal_v1", ID: uuid.NewString(), Stage: "requested", Namespace: f.ns, Environment: f.scope.Environment, Domain: f.scope.Domain, Dimension: f.scope.Dimension, PreregistrationID: f.disposedPre, Issuer: "external-cause-storage-test", ActualCoreSource: externalCauseHex(40), OriginalRun: runWire, LastFailedRun: runWire, InstallationSHA256: externalCauseHex(64), EnrollmentSHA256: externalCauseHex(64), BlockedGuestSource: f.source, BlockedProfileSHA256: disposed.binding.ProfileManifestSHA256, BusinessEffectsPreserved: true, RetirementMode: failedInstalledV2Mode}
	if o.coreBoundMarker {
		m := coreReplacementStorageMarker()
		r.ReplacementMode, r.OriginalFailedIssuerCoreSource, r.ReplacementCoreSource, r.ActualCoreSource = m.ReplacementMode, m.OriginalFailedIssuerCoreSource, m.ReplacementCoreSource, m.ActualCoreSource
	}
	var sha string
	f.disposal, sha = externalCauseDisposalChain(t, tx, ctx, r, o.requestedOnly)
	stage := "terminal"
	if o.requestedOnly {
		stage = "requested"
	}
	marker := model.CapacityFailedInstalledDisposal{ID: f.disposal.ID, AdmissionSHA256: sha, PreregistrationID: f.disposedPre, Stage: stage}
	if o.intentOtherID {
		marker.ID = uuid.NewString()
	}
	intent := model.CapacityIntent{Namespace: f.ns, Environment: f.scope.Environment, Domain: f.scope.Domain, Dimension: f.scope.Dimension, PolicyID: f.policyID, Generation: 8, FencingToken: 22, Phase: "disposed_failed_installed", FailedInstalledDisposal: &marker}
	intentRaw, _ := json.Marshal(intent)
	if !o.peerSameDimension {
		must(`INSERT INTO public.capacity_intents(namespace,environment,domain,dimension,intent) VALUES($1,$2,$3,$4,$5::jsonb)`, f.ns, f.scope.Environment, f.scope.Domain, f.scope.Dimension, string(intentRaw))
	}

	// The peer's accepted read one hour ago (or before the failure).
	f.readAt = time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond)
	if o.readBeforeFailure {
		f.readAt = f.finishedAt.Add(-10 * time.Minute)
	}
	f.returnAt = f.readAt.Add(2 * time.Second)
	pub := uuid.NewString()
	f.readID = uuid.NewString()
	for i, id := range []string{pub, f.readID} {
		phase, schema, outcome := "publish", "guest_notify_business_canary_publish_challenge_v1", "accepted"
		if i == 1 {
			phase, schema = "read", "guest_notify_business_canary_challenge_v1"
			if o.readHeld {
				outcome = "held"
			}
		}
		c := map[string]any{"schema": schema, "issued_at": f.readAt, "original_deadline": f.readAt.Add(5 * time.Second), "challenge_id": id}
		wire, _ := json.Marshal(c)
		digest := capacity.BusinessCreationSHA256(wire)
		must(`INSERT INTO public.capacity_guest_notify_canary_challenges(id,preregistration_id,record_challenge_id,phase,policy_id,workflow_id,generation,fence,executor_id,lease_owner,challenge_sha256,nonce_sha256,original_wire,original_record,original_deadline,recorded_at) VALUES($1,$2,$3,$4,$5,$5,10,30,$6,'external-cause-storage',$7,$8,$9,$10::jsonb,$11,$12)`, id, f.peerPre, pub, phase, f.policyID, uuid.NewString(), digest, capacity.BusinessCreationSHA256([]byte(id)), wire, string(wire), f.readAt.Add(5*time.Second), f.readAt)
		must(`INSERT INTO public.capacity_guest_notify_canary_returns(challenge_id,outcome,return_sha256,original_wire,original_transport,recorded_at) VALUES($1,$2,$3,$4,'{}'::jsonb,$5)`, id, outcome, digest, []byte(`{}`), f.returnAt)
	}

	peerPhase := "promoted"
	if o.peerNotPromoted {
		peerPhase = "preparing"
	}
	peerIntent := model.CapacityIntent{Namespace: f.ns, Environment: f.peerScope.Environment, Domain: f.peerScope.Domain, Dimension: f.peerScope.Dimension, PolicyID: f.policyID, Generation: 10, FencingToken: 30, Phase: peerPhase}
	peerRaw, _ := json.Marshal(peerIntent)
	if o.peerSameDimension {
		// One intent row per scope: the disposal's own row stands for both.
		must(`INSERT INTO public.capacity_intents(namespace,environment,domain,dimension,intent) VALUES($1,$2,$3,$4,$5::jsonb)`, f.ns, f.scope.Environment, f.scope.Domain, f.scope.Dimension, string(intentRaw))
	} else {
		must(`INSERT INTO public.capacity_intents(namespace,environment,domain,dimension,intent) VALUES($1,$2,$3,$4,$5::jsonb)`, f.ns, f.peerScope.Environment, f.peerScope.Domain, f.peerScope.Dimension, string(peerRaw))
	}
	f.resource = "i-" + externalCauseHex(17)
	record := `{"binding_name":"notify-aws","profile_name":"notify-aws-elastic","desired_spec_sha256":"` + externalCauseHex(64) + `","resource_id":"` + f.resource + `","resource_created_at":"` + f.finishedAt.Add(-24*time.Hour).Format(time.RFC3339) + `","receipt_ref":"original-guest-reconcile:test","observed_at":"` + f.readAt.Format(time.RFC3339Nano) + `","tombstone":` + map[bool]string{true: "true", false: "false"}[o.peerTombstone] + `}`
	must(`INSERT INTO public.capacity_resource_slots(integration_instance_id,scope_checksum,profile_name,slot,namespace,environment,domain,dimension,resource_id,slot_record,revision,updated_at) VALUES($1,$2,'notify-aws-elastic',1,$3,$4,$5,$6,$7,$8::jsonb,2,$9)`, uuid.New(), externalCauseHex(64), f.ns, f.peerScope.Environment, f.peerScope.Domain, f.peerScope.Dimension, f.resource, record, f.readAt)
	if o.peerRetired {
		must(`INSERT INTO public.capacity_vm_retirement_intents(id,preregistration_id,attempt_id,nonce_sha256,intent_sha256,intent_record,original_deadline,created_at) VALUES($1,$2,$3,$4,$5,'{}'::jsonb,$6,$7)`, uuid.NewString(), f.peerPre, uuid.NewString(), externalCauseHex(64), externalCauseHex(64), peer.pre.OriginalDeadline, peer.pre.ReservedAt)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f externalCauseFixture) admission() FailedInstalledExternalCauseAdmission {
	return FailedInstalledExternalCauseAdmission{
		ID: uuid.NewString(), Schema: FailedInstalledExternalCauseSchema, DisposalID: f.disposal.ID, DisposalStage: "terminal", PreregistrationID: f.disposedPre,
		Namespace: f.ns, Environment: f.scope.Environment, Domain: f.scope.Domain, Dimension: f.scope.Dimension,
		BlockedGuestSource: f.source, BlockedProfileSHA256: f.disposedBinding.ProfileManifestSHA256,
		AdmittedBindingSHA256: originalDispositionDigest(f.disposedWire), AdmittedPolicyID: f.policyID.String(), AdmittedPolicyChecksum: f.policyChecksum,
		OriginalFailedRunID: f.runID.String(), OriginalFailedRunFinishedAt: f.finishedAt,
		PeerPreregistrationID: f.peerPre, PeerNamespace: f.ns, PeerEnvironment: f.peerScope.Environment, PeerDomain: f.peerScope.Domain, PeerDimension: f.peerScope.Dimension,
		PeerGuestSource: f.source, PeerProfileSHA256: f.peerProfile, PeerReadChallengeID: f.readID, PeerReadRecordedAt: f.readAt, PeerReadReturnRecordedAt: f.returnAt,
		PeerIntentGeneration: 10, PeerIntentFencingToken: 30, PeerResourceID: f.resource,
		Issuer: "collaborator:" + uuid.NewString(), Reason: FailedInstalledExternalCauseReason, CauseEvidenceSHA256: failedInstalledExternalCauseEvidenceSHA(externalCauseEvidence),
	}
}

// insertAdmission writes one admission row directly (the migration85 guard is
// the authority here), with recorded_at taken inside the same transaction.
func (f externalCauseFixture) insertAdmission(t *testing.T, mutate func(*FailedInstalledExternalCauseAdmission)) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tx, err := f.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	a := f.admission()
	if mutate != nil {
		mutate(&a)
	}
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&a.RecordedAt); err != nil {
		return err
	}
	if err = insertFailedInstalledExternalCauseAdmissionTx(ctx, tx, a, externalCauseEvidence); err != nil {
		return err
	}
	return tx.Commit()
}

func (f externalCauseFixture) admissions(t *testing.T) int {
	t.Helper()
	var n int
	if err := f.db.QueryRow(`SELECT count(*) FROM public.capacity_guest_failed_installed_external_cause_admissions WHERE preregistration_id=$1 OR disposal_id=$2`, f.disposedPre, f.disposal.ID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func externalCauseSchema85(t *testing.T, db *sql.DB) {
	t.Helper()
	var schema int64
	if err := db.QueryRow(`SELECT max(version_id) FROM public.goose_db_version WHERE is_applied`).Scan(&schema); err != nil || schema != 85 {
		t.Fatal("owning schema85 required", schema, err)
	}
}

func TestFailedInstalledExternalCauseMigration85Guards(t *testing.T) {
	db := originalDispositionPG(t)
	externalCauseSchema85(t, db)
	t.Run("accepts_the_exact_rederived_admission_once", func(t *testing.T) {
		f := externalCausePGFixture(t, db, externalCauseOptions{})
		if err := f.insertAdmission(t, nil); err != nil {
			t.Fatal("exact admission refused", err)
		}
		if err := f.insertAdmission(t, nil); err == nil {
			t.Fatal("second admission for one disposal accepted")
		}
		for _, q := range []string{
			`UPDATE public.capacity_guest_failed_installed_external_cause_admissions SET cause_evidence='rewritten',cause_evidence_sha256=encode(sha256(convert_to('rewritten','UTF8')),'hex') WHERE disposal_id=$1`,
			`UPDATE public.capacity_guest_failed_installed_external_cause_admissions SET admitted_binding_sha256=repeat('a',64) WHERE disposal_id=$1`,
			`DELETE FROM public.capacity_guest_failed_installed_external_cause_admissions WHERE disposal_id=$1`,
		} {
			if _, err := db.Exec(q, f.disposal.ID); err == nil {
				t.Fatal("immutable admission rewritten", q)
			}
		}
		if f.admissions(t) != 1 {
			t.Fatal("admission count changed")
		}
	})
	t.Run("refuses_forged_or_unproven_facts", func(t *testing.T) {
		for name, mutate := range map[string]func(*FailedInstalledExternalCauseAdmission){
			"other_blocked_source": func(a *FailedInstalledExternalCauseAdmission) {
				a.BlockedGuestSource = externalCauseHex(40)
				a.PeerGuestSource = a.BlockedGuestSource
			},
			"other_blocked_profile": func(a *FailedInstalledExternalCauseAdmission) { a.BlockedProfileSHA256 = externalCauseHex(64) },
			"forged_run_finish": func(a *FailedInstalledExternalCauseAdmission) {
				a.OriginalFailedRunFinishedAt = a.OriginalFailedRunFinishedAt.Add(-time.Hour)
			},
			"forged_read_time": func(a *FailedInstalledExternalCauseAdmission) {
				a.PeerReadRecordedAt = a.PeerReadRecordedAt.Add(time.Second)
			},
			"forged_peer_scope":      func(a *FailedInstalledExternalCauseAdmission) { a.PeerDimension = "other-dimension" },
			"forged_peer_generation": func(a *FailedInstalledExternalCauseAdmission) { a.PeerIntentGeneration = 11 },
			"forged_peer_resource":   func(a *FailedInstalledExternalCauseAdmission) { a.PeerResourceID = "i-forged" },
			"forged_peer_profile":    func(a *FailedInstalledExternalCauseAdmission) { a.PeerProfileSHA256 = externalCauseHex(64) },
			"evidence_hash_mismatch": func(a *FailedInstalledExternalCauseAdmission) { a.CauseEvidenceSHA256 = externalCauseHex(64) },
			"forged_issuer":          func(a *FailedInstalledExternalCauseAdmission) { a.Issuer = "operator" },
			// The admitted digest must be the SHA-256 of the disposed Guest's own
			// binding_wire, not any other binding with the same source and profile.
			"forged_binding_digest":   func(a *FailedInstalledExternalCauseAdmission) { a.AdmittedBindingSHA256 = externalCauseHex(64) },
			"forged_policy_checksum":  func(a *FailedInstalledExternalCauseAdmission) { a.AdmittedPolicyChecksum = externalCauseHex(64) },
			"forged_policy_id":        func(a *FailedInstalledExternalCauseAdmission) { a.AdmittedPolicyID = uuid.NewString() },
			"forged_reason":           func(a *FailedInstalledExternalCauseAdmission) { a.Reason = "cause_fixed" },
			"peer_is_disposed_itself": func(a *FailedInstalledExternalCauseAdmission) { a.PeerPreregistrationID = a.PreregistrationID },
		} {
			t.Run(name, func(t *testing.T) {
				f := externalCausePGFixture(t, db, externalCauseOptions{})
				if err := f.insertAdmission(t, mutate); err == nil {
					t.Fatal("forged admission accepted", name)
				}
				if f.admissions(t) != 0 {
					t.Fatal("refused admission wrote a row", name)
				}
			})
		}
	})
	t.Run("refuses_unqualified_histories", func(t *testing.T) {
		for name, o := range map[string]externalCauseOptions{
			"requested_only_disposal": {requestedOnly: true},
			"core_bound_marker":       {coreBoundMarker: true},
			"peer_same_dimension":     {peerSameDimension: true},
			"peer_other_Guest_build":  {peerOtherSource: true},
			"read_before_failure":     {readBeforeFailure: true},
			"read_held":               {readHeld: true},
			"peer_not_promoted":       {peerNotPromoted: true},
			"peer_slot_tombstone":     {peerTombstone: true},
			"peer_retired":            {peerRetired: true},
			"intent_names_other":      {intentOtherID: true},
		} {
			t.Run(name, func(t *testing.T) {
				f := externalCausePGFixture(t, db, o)
				if err := f.insertAdmission(t, func(a *FailedInstalledExternalCauseAdmission) {
					if o.peerOtherSource {
						// Declared as the same build; the guard reads the peer's own binding.
						a.PeerGuestSource = a.BlockedGuestSource
					}
				}); err == nil {
					t.Fatal("unqualified history admitted", name)
				}
				if f.admissions(t) != 0 {
					t.Fatal("refused admission wrote a row", name)
				}
			})
		}
	})
}

// The Go admission refuses before any write when the disposal, its marker,
// the request or the current policy do not qualify. Storage-only fixtures
// cannot reach acceptance: their policy is not a validated Guest policy.
func TestFailedInstalledExternalCauseAdmissionPostgresRefusals(t *testing.T) {
	db := originalDispositionPG(t)
	externalCauseSchema85(t, db)
	stub := func(model.CapacityPolicySpec, model.CapacityGuestRetirementBinding) bool { return true }
	issuer := "collaborator:" + uuid.NewString()
	admit := func(f externalCauseFixture, pre, peer, evidence, who string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, err := (CapacityStore{DB: db}).admitFailedInstalledExternalCauseReplacement(ctx, FailedInstalledExternalCauseReplacementRequest{PreregistrationID: pre, PeerPreregistrationID: peer, CauseEvidence: evidence, Issuer: who}, strings.Repeat("e", 40), stub)
		return err
	}
	base := externalCausePGFixture(t, db, externalCauseOptions{})
	t.Run("closed_request", func(t *testing.T) {
		for name, args := range map[string][4]string{
			"uppercase_pre":   {strings.ToUpper(base.disposedPre), base.peerPre, externalCauseEvidence, issuer},
			"nil_peer":        {base.disposedPre, uuid.Nil.String(), externalCauseEvidence, issuer},
			"same_preregs":    {base.disposedPre, base.disposedPre, externalCauseEvidence, issuer},
			"empty_evidence":  {base.disposedPre, base.peerPre, "", issuer},
			"blank_evidence":  {base.disposedPre, base.peerPre, " \n\t ", issuer},
			"large_evidence":  {base.disposedPre, base.peerPre, strings.Repeat("x", FailedInstalledExternalCauseEvidenceMax+1), issuer},
			"control_char":    {base.disposedPre, base.peerPre, "bell\u0007", issuer},
			"invalid_utf8":    {base.disposedPre, base.peerPre, string([]byte{0xff, 0xfe}), issuer},
			"issuer_not_user": {base.disposedPre, base.peerPre, externalCauseEvidence, "workflow:abc"},
		} {
			if err := admit(base, args[0], args[1], args[2], args[3]); !errors.Is(err, errFailedInstalledExternalCauseRequest) {
				t.Fatal("malformed request reached the database", name, err)
			}
		}
		if base.admissions(t) != 0 {
			t.Fatal("refused request wrote a row")
		}
	})
	t.Run("storage_only_policy_never_admitted", func(t *testing.T) {
		if err := admit(base, base.disposedPre, base.peerPre, externalCauseEvidence, issuer); err == nil {
			t.Fatal("unvalidated storage policy admitted a same-build replacement")
		}
		if base.admissions(t) != 0 {
			t.Fatal("refused admission wrote a row")
		}
	})
	for name, o := range map[string]externalCauseOptions{
		"requested_only_disposal": {requestedOnly: true},
		"core_bound_marker":       {coreBoundMarker: true},
		"intent_names_other":      {intentOtherID: true},
	} {
		t.Run(name, func(t *testing.T) {
			f := externalCausePGFixture(t, db, o)
			if err := admit(f, f.disposedPre, f.peerPre, externalCauseEvidence, issuer); !errors.Is(err, ErrCapacityConflict) {
				t.Fatal("unqualified disposal not refused as a conflict", name, err)
			}
			if f.admissions(t) != 0 {
				t.Fatal("refused admission wrote a row", name)
			}
		})
	}
	t.Run("existing_admission", func(t *testing.T) {
		f := externalCausePGFixture(t, db, externalCauseOptions{})
		if err := f.insertAdmission(t, nil); err != nil {
			t.Fatal(err)
		}
		if err := admit(f, f.disposedPre, f.peerPre, externalCauseEvidence, issuer); !errors.Is(err, ErrCapacityConflict) {
			t.Fatal("second admission not refused", err)
		}
		if f.admissions(t) != 1 {
			t.Fatal("admission count changed")
		}
	})
}

// The gate accepts the unchanged blocked binding of an admitted disposal and
// nothing else; every other disposal of the dimension is still checked, and
// the compiled approval is still required.
func TestFailedInstalledExternalCauseGatePostgres(t *testing.T) {
	db := originalDispositionPG(t)
	externalCauseSchema85(t, db)
	approve := func(model.CapacityPolicySpec, model.CapacityGuestRetirementBinding) bool { return true }
	reject := func(model.CapacityPolicySpec, model.CapacityGuestRetirementBinding) bool { return false }
	gate := func(f externalCauseFixture, b model.CapacityGuestRetirementBinding, authority guestBindingAuthority) error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		p := f.scope
		p.GuestNotifyReconcileBinding = &model.CapacityGuestNotifyReconcileBinding{}
		p.GuestRetirementBinding = &b
		var policy model.Manifest
		policy.Metadata.Namespace = f.ns
		return requireFailedInstalledReplacementWithAuthorityTx(ctx, tx, policy, p, strings.Repeat("e", 40), authority)
	}
	changed := func(f externalCauseFixture) model.CapacityGuestRetirementBinding {
		b := f.disposedBinding
		b.GuestSourceCommit = externalCauseHex(40)
		b.ProfileManifestSHA256 = externalCauseHex(64)
		return b
	}

	f := externalCausePGFixture(t, db, externalCauseOptions{})
	if gate(f, f.disposedBinding, approve) == nil {
		t.Fatal("unchanged blocked binding accepted without an admission")
	}
	if gate(f, changed(f), approve) != nil {
		t.Fatal("both-changed approved binding refused")
	}
	if err := f.insertAdmission(t, nil); err != nil {
		t.Fatal(err)
	}
	if err := gate(f, f.disposedBinding, approve); err != nil {
		t.Fatal("admitted unchanged binding refused", err)
	}
	if gate(f, f.disposedBinding, reject) == nil {
		t.Fatal("admission bypassed the compiled approval")
	}
	if gate(f, changed(f), approve) != nil {
		t.Fatal("admission narrowed the both-changed branch")
	}
	for name, edit := range map[string]func(*model.CapacityGuestRetirementBinding){
		"only_source_changed":  func(b *model.CapacityGuestRetirementBinding) { b.GuestSourceCommit = externalCauseHex(40) },
		"only_profile_changed": func(b *model.CapacityGuestRetirementBinding) { b.ProfileManifestSHA256 = externalCauseHex(64) },
		"same_build_other_binding": func(b *model.CapacityGuestRetirementBinding) {
			b.Members = append([]model.CapacityGuestRetirementMemberBinding(nil), b.Members...)
			b.Members[0].Origin = "https://other.example.invalid"
		},
		"same_build_other_Core_authority": func(b *model.CapacityGuestRetirementBinding) { b.CoreAuthoritySourceCommit = externalCauseHex(40) },
	} {
		b := f.disposedBinding
		edit(&b)
		if gate(f, b, approve) == nil {
			t.Fatal("admission accepted a binding other than the exact admitted one", name)
		}
	}

	t.Run("older_disposal_of_the_dimension_still_checked", func(t *testing.T) {
		// Shaped like ac198bfd (548734/3bc51d81) preceding 8ef5f76c: the older
		// terminal blocks its own build; the admitted unchanged binding differs
		// from it in both Source and profile, so it passes the changed branch.
		g := externalCausePGFixture(t, db, externalCauseOptions{})
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		older := externalCausePre(t, tx, ctx, g.ns, g.scope, externalCauseHex(40))
		r := g.disposal
		r = FailedInstalledGuestDisposal{Schema: r.Schema, ID: uuid.NewString(), Stage: "requested", Namespace: r.Namespace, Environment: r.Environment, Domain: r.Domain, Dimension: r.Dimension, PreregistrationID: older.pre.PreregistrationID, Issuer: r.Issuer, ActualCoreSource: externalCauseHex(40), OriginalRun: r.OriginalRun, LastFailedRun: r.LastFailedRun, InstallationSHA256: externalCauseHex(64), EnrollmentSHA256: externalCauseHex(64), BlockedGuestSource: older.binding.GuestSourceCommit, BlockedProfileSHA256: externalCauseHex(64), BusinessEffectsPreserved: true, RetirementMode: failedInstalledV2Mode}
		externalCauseDisposalChain(t, tx, ctx, r, false)
		if err = tx.Commit(); err != nil {
			t.Fatal(err)
		}
		if err = g.insertAdmission(t, nil); err != nil {
			t.Fatal(err)
		}
		if err = gate(g, g.disposedBinding, approve); err != nil {
			t.Fatal("older disposal with a different build blocked the admitted binding", err)
		}
		olderBuild := g.disposedBinding
		olderBuild.GuestSourceCommit = r.BlockedGuestSource
		olderBuild.ProfileManifestSHA256 = r.BlockedProfileSHA256
		if gate(g, olderBuild, approve) == nil {
			t.Fatal("older disposal's blocked build accepted")
		}
	})
	t.Run("requested_disposal_of_the_dimension_still_blocks", func(t *testing.T) {
		g := externalCausePGFixture(t, db, externalCauseOptions{})
		if err := g.insertAdmission(t, nil); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		other := externalCausePre(t, tx, ctx, g.ns, g.scope, externalCauseHex(40))
		r := g.disposal
		r = FailedInstalledGuestDisposal{Schema: r.Schema, ID: uuid.NewString(), Stage: "requested", Namespace: r.Namespace, Environment: r.Environment, Domain: r.Domain, Dimension: r.Dimension, PreregistrationID: other.pre.PreregistrationID, Issuer: r.Issuer, ActualCoreSource: externalCauseHex(40), OriginalRun: r.OriginalRun, LastFailedRun: r.LastFailedRun, InstallationSHA256: externalCauseHex(64), EnrollmentSHA256: externalCauseHex(64), BlockedGuestSource: other.binding.GuestSourceCommit, BlockedProfileSHA256: externalCauseHex(64), BusinessEffectsPreserved: true, RetirementMode: failedInstalledV2Mode}
		externalCauseDisposalChain(t, tx, ctx, r, true)
		if err = tx.Commit(); err != nil {
			t.Fatal(err)
		}
		if gate(g, g.disposedBinding, approve) == nil {
			t.Fatal("a requested (non-terminal) disposal of the dimension was bypassed")
		}
	})
}
