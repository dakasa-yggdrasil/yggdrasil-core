//go:build linux && nativequalification

package repository_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	q "github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacitynativeqemu"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
)

type guestOriginalNativeCorpus = q.Corpus

func guestOriginalPostgres(t *testing.T) *sql.DB {
	t.Helper()
	if os.Getenv("DB_URL") == "" {
		t.Fatal("same original native caller DB_URL is mandatory")
	}
	db, err := sql.Open("postgres", os.Getenv("DB_URL"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Error(err)
		}
	})
	return db
}

type guestOriginalStored struct {
	pre     model.CapacityGuestOriginalProvisioningPreregistration
	binding model.CapacityGuestRetirementBinding
	member  model.CapacityGuestRetirementMemberBinding
	witness model.CapacityGuestOriginalCreateWitness
}

func loadGuestOriginalTx(ctx context.Context, tx *sql.Tx, id string) (guestOriginalStored, error) {
	var s guestOriginalStored
	var preWire, bindingWire []byte
	var consistent bool
	if err := tx.QueryRowContext(ctx, `SELECT original_wire,binding_wire,preregistration_record=convert_from(original_wire,'UTF8')::jsonb AND original_deadline=(preregistration_record->>'original_deadline')::timestamptz AND created_at=(preregistration_record->>'reserved_at')::timestamptz AND id::text=preregistration_record->>'preregistration_id' AND create_grant_id::text=preregistration_record->>'original_create_grant_id' AND nonce_sha256=preregistration_record->>'nonce_sha256' AND profile_manifest_sha256=preregistration_record->>'profile_manifest_sha256' FROM public.capacity_vm_provisioning_preregistrations WHERE id=$1`, id).Scan(&preWire, &bindingWire, &consistent); err != nil {
		return s, err
	}
	if !consistent || capacity.DecodeGuestLifecycle(preWire, &s.pre) != nil || capacity.DecodeGuestLifecycle(bindingWire, &s.binding) != nil || !capacity.GuestOriginalProvisioningDeadlineMatches(s.pre, s.binding.ProfileManifest) {
		return s, errors.New("original preregistration canonical bytes do not join")
	}
	for _, m := range s.binding.Members {
		if m.Slot == s.pre.Slot && m.Name == s.pre.BindingName {
			s.member = m
		}
	}
	if s.member.Name == "" {
		return s, errors.New("original member absent")
	}
	return s, nil
}

func loadGuestWitnessTx(ctx context.Context, tx *sql.Tx, s *guestOriginalStored) error {
	var raw []byte
	var digest string
	var consistent bool
	if err := tx.QueryRowContext(ctx, `SELECT original_wire,witness_sha256,original_record=convert_from(original_wire,'UTF8')::jsonb FROM public.capacity_guest_original_create_witnesses WHERE preregistration_id=$1`, s.pre.PreregistrationID).Scan(&raw, &digest, &consistent); err != nil {
		return err
	}
	if !consistent || capacity.BusinessCreationSHA256(raw) != digest || capacity.DecodeGuestLifecycle(raw, &s.witness) != nil || s.witness.PreregistrationID != s.pre.PreregistrationID {
		return errors.New("original native create witness bytes diverge")
	}
	return nil
}

func loadGuestReceiptTx(ctx context.Context, tx *sql.Tx, id string) (model.CapacityGuestOriginalProvisioningReceipt, string, error) {
	var receipt model.CapacityGuestOriginalProvisioningReceipt
	var original model.CapacityGuestOriginalProvisioningRegistration
	var raw, registration []byte
	var digest string
	var consistent bool
	if err := tx.QueryRowContext(ctx, `SELECT receipt_wire,registration_wire,enrollment_sha256,enrollment_record=convert_from(receipt_wire,'UTF8')::jsonb->'enrollment' AND recorded_at=(convert_from(receipt_wire,'UTF8')::jsonb->>'recorded_at')::timestamptz FROM public.capacity_vm_original_enrollments WHERE preregistration_id=$1`, id).Scan(&raw, &registration, &digest, &consistent); err != nil {
		return receipt, "", err
	}
	if !consistent || capacity.DecodeGuestLifecycle(raw, &receipt) != nil || capacity.DecodeGuestLifecycle(registration, &original) != nil || receipt.PreregistrationID != id || capacity.GuestRetirementSHA(receipt.Enrollment) != digest || receipt.OriginalProvisioningSHA256 != capacity.GuestRetirementSHA(original) || receipt.Enrollment.Statement.OriginalNativeResultSHA256 != capacity.GuestRetirementSHA(original.Result) {
		return receipt, "", errors.New("original signed callback and enrollment diverge")
	}
	return receipt, capacity.GuestRetirementSHA(original), nil
}

func guestOriginalProbe(t *testing.T, tx *sql.Tx, ctx context.Context, preregistrationID, digest string, enrollment model.CapacityGuestRetirementEnrollment, registrationSHA string) q.QualificationProbeReceipt {
	t.Helper()
	wire := guestOriginalNativeWire(t, tx, ctx, `SELECT original_wire,return_sha256,original_record=convert_from(original_wire,'UTF8')::jsonb FROM public.capacity_guest_qualification_native_source_returns WHERE preregistration_id=$1 AND native_stage='serving_probe' AND return_sha256=$2`, preregistrationID, digest)
	var probe q.QualificationProbeReceipt
	if capacity.DecodeGuestLifecycle(wire, &probe) != nil {
		t.Fatal("closed original useful echo receipt absent")
	}
	var challengeWire []byte
	var consistent bool
	if err := tx.QueryRowContext(ctx, `SELECT original_wire,original_record=convert_from(original_wire,'UTF8')::jsonb AND original_deadline=(original_record->'challenge'->>'original_deadline')::timestamptz AND recorded_at<=(original_record->'challenge'->>'original_deadline')::timestamptz FROM public.capacity_guest_qualification_probe_challenges WHERE preregistration_id=$1 AND challenge_sha256=$2`, preregistrationID, probe.ChallengeSHA256).Scan(&challengeWire, &consistent); err != nil || !consistent {
		t.Fatal("actual signed probe challenge was not reserved before its original deadline", err)
	}
	var request q.QualificationProbeRequest
	if capacity.DecodeGuestLifecycle(challengeWire, &request) != nil || capacity.GuestRetirementSHA(request.Challenge) != probe.ChallengeSHA256 || q.ValidateProbeReturn(request, probe, enrollment, registrationSHA, probe.OriginalNativeAfterReturnedAt) != nil {
		t.Fatal("same original admitted writer did not return its actual useful echo")
	}
	return probe
}

type guestOriginalDestroyRecord struct {
	Grant      model.CapacityMutationGrant          `json:"grant"`
	Binding    model.CapacityMutationBinding        `json:"binding"`
	AttemptID  string                               `json:"attempt_id"`
	Settlement *model.CapacityMutationSettleRequest `json:"settlement"`
	Proof      *model.CapacityMutationProof         `json:"proof"`
}

type guestOriginalAuthorityTransport struct {
	ReadID                string    `json:"read_id"`
	Stage                 string    `json:"native_stage"`
	OriginalDeadline      time.Time `json:"original_deadline"`
	StartedAt             time.Time `json:"started_at"`
	DoStartedAt           time.Time `json:"do_started_at"`
	DoReturnedAt          time.Time `json:"do_returned_at"`
	ReadReturnedAt        time.Time `json:"read_returned_at"`
	CloseReturnedAt       time.Time `json:"close_returned_at"`
	DriverReturnedAt      time.Time `json:"driver_returned_at"`
	Status                int       `json:"status"`
	ResponseSHA256        string    `json:"response_sha256"`
	ReceivedBodyBytes     int       `json:"received_body_bytes"`
	ResponseBodyScope     string    `json:"response_body_scope"`
	RetainedPrefixBytes   int       `json:"retained_prefix_bytes"`
	RetainedPrefixSHA256  string    `json:"retained_prefix_sha256"`
	PreflightFailed       bool      `json:"preflight_failed"`
	DoFailed              bool      `json:"do_failed"`
	ReadFailed            bool      `json:"read_failed"`
	CloseFailed           bool      `json:"close_failed"`
	OriginalContextFailed bool      `json:"original_context_failed"`
}

func guestOriginalNativeSource(value string) bool {
	raw, err := hex.DecodeString(value)
	return err == nil && len(raw) == 20 && value == strings.ToLower(value)
}

func guestOriginalNativeUUID(value string) bool {
	u, err := uuid.Parse(value)
	return err == nil && u != uuid.Nil && u.String() == value
}

func guestOriginalNativeReceipt(t *testing.T) guestOriginalNativeCorpus {
	t.Helper()
	path := os.Getenv("CAPACITY_GUEST_NATIVE_CORPUS_FILE")
	if path == "" {
		if os.Getenv("REQUIRE_CAPACITY_GUEST_NATIVE_CORPUS") == "true" {
			t.Fatal("actual native Core/QEMU corpus receipt is mandatory")
		}
		t.Skip("positive owning lifecycle runs only in the joint original native Core/QEMU job")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > capacity.GuestBootstrapLimit {
		t.Fatal("bounded original native corpus receipt required")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var corpus guestOriginalNativeCorpus
	if capacity.DecodeGuestLifecycle(raw, &corpus) != nil {
		t.Fatal("closed original native corpus receipt required")
	}
	if corpus.Schema != "core_original_guest_native_qemu_corpus_v1" || !guestOriginalNativeSource(corpus.ActualCoreSourceCommit) || !guestOriginalNativeSource(corpus.GuestSourceCommit) || (corpus.NativeCase != "positive_original_lifecycle" && corpus.NativeCase != "actor_startup_delay_positive") || corpus.CaseOutcome != "ORIGINAL_PROTECTED_LIFECYCLE_JOINED" || !guestOriginalNativeUUID(corpus.PolicyID) || !guestOriginalNativeUUID(corpus.WorkflowID) || corpus.Namespace == "" || !capacity.ValidDigest(corpus.PolicyChecksum) || !capacity.ValidDigest(corpus.WorkflowChecksum) || !capacity.ValidDigest(corpus.ProfileManifestSHA256) || len(corpus.OriginalPreregistrationIDs) != 2 || len(corpus.NativeResources) != 2 || len(corpus.OriginalRunIDs) < 2 || len(corpus.OriginalRunIDs) > 8 || corpus.BurstRetirement == nil || !guestOriginalNativeUUID(corpus.BurstRetirement.RequestID) || !guestOriginalNativeUUID(corpus.BurstRetirement.DestroyGrantID) || len(corpus.BurstRetirement.OriginalRecordSHA256s) != 4 || len(corpus.BurstRetirement.SnapshotChallengeSHA256s) != 2 || len(corpus.BurstRetirement.AuthorityReadIDs) != 4 || corpus.BurstRetirement.AuthorityTransportReturnCount != 5 || !capacity.ValidDigest(corpus.BaselineServingProbeSHA256) {
		t.Fatal("receipt is not a complete original positive native lifecycle")
	}
	for _, ids := range [][]string{corpus.OriginalRunIDs, corpus.OriginalPreregistrationIDs, corpus.BurstRetirement.AuthorityReadIDs} {
		seen := map[string]bool{}
		for _, id := range ids {
			if !guestOriginalNativeUUID(id) || seen[id] {
				t.Fatal("original native identities are missing or reused")
			}
			seen[id] = true
		}
	}
	return corpus
}

func guestOriginalNativeWire(t *testing.T, tx *sql.Tx, ctx context.Context, query string, args ...any) []byte {
	t.Helper()
	var raw []byte
	var digest string
	var consistent bool
	if err := tx.QueryRowContext(ctx, query, args...).Scan(&raw, &digest, &consistent); err != nil || !consistent || !capacity.ValidDigest(digest) || capacity.BusinessCreationSHA256(raw) != digest {
		t.Fatalf("missing or divergent actual native original bytes: %v", err)
	}
	return raw
}

// This verifier performs SELECTs over the SAME ephemeral database written by
// the independently compiled clean Core command. It never imports/replays the
// exported receipt, seeds phases, sends requests or grants fresh permission.
// Default go test build metadata is never substituted for the original Core.
func TestCapacityGuestOriginalNativeCorpusPostgres(t *testing.T) {
	c := guestOriginalNativeReceipt(t)
	db := guestOriginalPostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	var policyRaw []byte
	var checksum, namespace string
	if err := tx.QueryRowContext(ctx, `SELECT spec,checksum,namespace FROM public.manifests WHERE id=$1 AND kind='capacity_policy'`, c.PolicyID).Scan(&policyRaw, &checksum, &namespace); err != nil || checksum != c.PolicyChecksum || namespace != c.Namespace {
		t.Fatal("original native policy does not join", err)
	}
	var p model.CapacityPolicySpec
	if err := json.Unmarshal(policyRaw, &p); err != nil || p.GuestRetirementBinding == nil || capacity.ValidateGuestRetirementBinding(p, p.GuestRetirementBinding) != nil {
		t.Fatal("original protected source profile is not registration-valid", err)
	}
	if p.GuestRetirementBinding.CoreAuthoritySourceCommit != c.ActualCoreSourceCommit || p.GuestRetirementBinding.GuestSourceCommit != c.GuestSourceCommit || p.GuestRetirementBinding.ProfileManifestSHA256 != c.ProfileManifestSHA256 || p.GuestRetirementBinding.EvidenceClass != "native_qemu_qualification" || p.GuestRetirementBinding.ProfileManifest.ProductionCatalogSHA256 != "" {
		t.Fatal("original native source was relabeled or expanded into production coverage")
	}
	if err := tx.QueryRowContext(ctx, `SELECT checksum FROM public.manifests WHERE id=$1 AND kind='workflow' AND namespace=$2`, c.WorkflowID, c.Namespace).Scan(&checksum); err != nil || checksum != c.WorkflowChecksum {
		t.Fatal("original native workflow does not join", err)
	}
	for _, run := range c.OriginalRunIDs {
		var count int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM (`+q.OriginalWorkflowIdentitySQL+`) exact_original`, run, c.WorkflowID).Scan(&count); err != nil || count != 1 {
			t.Fatal("original public workflow run absent", err)
		}
	}
	var baseline, burst guestOriginalStored
	var nativeInitial [2]q.IndependentReturn
	for n, resource := range c.NativeResources {
		if resource.Slot != n+1 || !guestOriginalNativeUUID(resource.ResourceID) || !capacity.ValidDigest(resource.CreatorOriginalSHA256) || !capacity.ValidDigest(resource.CoreNativeOriginalReadSHA256) || !capacity.ValidDigest(resource.RegistrationSHA256) || !capacity.ValidDigest(resource.EnrollmentSHA256) || !capacity.ValidDigest(resource.ServingProbeSHA256) {
			t.Fatal("original native resource roster malformed")
		}
		stored, err := loadGuestOriginalTx(ctx, tx, c.OriginalPreregistrationIDs[n])
		if err != nil {
			t.Fatal(err)
		}
		if stored.pre.PolicyID != c.PolicyID || stored.pre.PolicyChecksum != c.PolicyChecksum || stored.pre.WorkflowID != c.WorkflowID || stored.pre.WorkflowChecksum != c.WorkflowChecksum || stored.pre.CoreSourceCommit != c.ActualCoreSourceCommit || stored.pre.Slot != resource.Slot || stored.pre.ProfileManifestSHA256 != c.ProfileManifestSHA256 {
			t.Fatal("original protected reservation/source differs from actual corpus")
		}
		if err := loadGuestWitnessTx(ctx, tx, &stored); err != nil {
			t.Fatal(err)
		}
		receipt, registrationSHA, err := loadGuestReceiptTx(ctx, tx, stored.pre.PreregistrationID)
		if err != nil {
			t.Fatal(err)
		}
		if registrationSHA != resource.RegistrationSHA256 || capacity.GuestRetirementSHA(receipt.Enrollment) != resource.EnrollmentSHA256 || receipt.Enrollment.Statement.Tuple.ResourceID != resource.ResourceID || receipt.Enrollment.Statement.Tuple.CreatedAt != resource.ResourceCreatedAt || stored.witness.Tuple != receipt.Enrollment.Statement.Tuple {
			t.Fatal("actual native tuple/registration/enrollment is not the original")
		}
		if capacity.GuestOriginalCreateWitness(p, stored.binding, stored.member, stored.pre, stored.witness, receipt.Enrollment.Statement.CoreIntentPublicKey, stored.witness.ObservedAt) != nil || capacity.GuestRetirementEnrollment(p, stored.binding, stored.member, receipt.Enrollment, receipt.Enrollment.Statement.IssuedAt) != nil {
			t.Fatal("original signed enrollment/create source does not join")
		}
		var registrationWire []byte
		if err := tx.QueryRowContext(ctx, `SELECT registration_wire FROM public.capacity_vm_original_enrollments WHERE preregistration_id=$1`, stored.pre.PreregistrationID).Scan(&registrationWire); err != nil {
			t.Fatal(err)
		}
		var registration model.CapacityGuestOriginalProvisioningRegistration
		if capacity.DecodeGuestLifecycle(registrationWire, &registration) != nil || capacity.GuestOriginalRegistration(p, stored.binding, stored.member, stored.witness, registration, receipt.RecordedAt) != nil {
			t.Fatal("real bootstrap/source placement cannot be replaced by a completeness claim")
		}
		readWire := guestOriginalNativeWire(t, tx, ctx, `SELECT original_wire,return_sha256,original_record=convert_from(original_wire,'UTF8')::jsonb FROM public.capacity_guest_qualification_native_source_returns WHERE preregistration_id=$1 AND native_stage='native_read' AND return_sha256=$2`, stored.pre.PreregistrationID, resource.CoreNativeOriginalReadSHA256)
		var read q.IndependentReturn
		if capacity.DecodeGuestLifecycle(readWire, &read) != nil || read.Schema != "core_independent_original_qemu_read_v1" || read.OriginalCreatorSHA256 != resource.CreatorOriginalSHA256 || read.Original.OriginalCreateReturnedAt.Before(read.Original.OriginalCreateStartedAt) || read.Original.OriginalReadStartedAt.Before(read.Original.OriginalCreateReturnedAt) || strings.ToLower(read.UUID.UUID) != resource.ResourceID || read.Original.ResourceID != resource.ResourceID || read.Original.Slot != resource.Slot || read.Original.OriginalSourceCommit != c.GuestSourceCommit || read.Before.PID != read.Original.QEMU.PID || read.Before.StartTicks != read.Original.QEMU.StartTicks || read.After.PID != read.Before.PID || read.After.StartTicks != read.Before.StartTicks || read.QMPPeerPID != int32(read.Before.PID) || read.StartedAt.Before(read.Original.OriginalReadReturnedAt) || read.ReadReturnedAt.Before(read.StartedAt) || read.CloseReturnedAt.Before(read.ReadReturnedAt) || len(read.IO) < 7 || !read.Status.Running || read.Status.Status != "running" || read.Status.SingleStep {
			t.Fatal("actual Core native read does not join the original creator")
		}
		if read.Before.PPID != read.Original.QEMU.PPID || read.After.PPID != read.Before.PPID || read.OriginalDisk.Device == 0 || read.OriginalDisk.Inode == 0 || read.OriginalDiskFD < 0 || read.OriginalDiskReadReturnedAt.Before(read.StartedAt) || read.OriginalDiskDirectoryCloseReturnedAt.Before(read.OriginalDiskReadReturnedAt) || read.OriginalDiskDirectoryCloseReturnedAt.After(read.ReadReturnedAt) {
			t.Fatal("original QEMU process did not independently own the precreate disk inode")
		}
		nativeInitial[n] = read
		var nativeCreated string
		if err := tx.QueryRowContext(ctx, `SELECT original_record->'original'->>'original_create_returned_at' FROM public.capacity_guest_qualification_native_source_returns WHERE preregistration_id=$1 AND native_stage='native_read' AND return_sha256=$2`, stored.pre.PreregistrationID, resource.CoreNativeOriginalReadSHA256).Scan(&nativeCreated); err != nil || nativeCreated != resource.ResourceCreatedAt {
			t.Fatal("native created timestamp was supplied by the caller", err)
		}
		if !stored.witness.OriginalCreateReturnedAt.Equal(read.Original.OriginalCreateReturnedAt) || !stored.witness.OriginalCreateReturnedAt.Before(read.CloseReturnedAt) {
			t.Fatal("witness create return was replaced by a later native QMP observation")
		}
		guestOriginalProbe(t, tx, ctx, stored.pre.PreregistrationID, resource.ServingProbeSHA256, receipt.Enrollment, registrationSHA)
		for _, wrong := range []string{resource.ResourceCreatedAt + "0", "2000-01-01T00:00:00Z"} {
			var matches int
			if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_vm_original_enrollments WHERE preregistration_id=$1 AND enrollment_record->'statement'->'tuple'->>'resource_id'=$2 AND enrollment_record->'statement'->'tuple'->>'resource_created_at'=$3`, stored.pre.PreregistrationID, resource.ResourceID, wrong).Scan(&matches); err != nil || matches != 0 {
				t.Fatal("native exact resource_created_at selector adopted a different identity", err)
			}
		}
		if n == 0 {
			baseline = stored
		} else {
			burst = stored
		}
	}
	retired, err := (repository.CapacityStore{DB: db}).GuestRetirementOriginal(ctx, burst.member.ActorClientPrincipal, c.BurstRetirement.RequestID, c.BurstRetirement.IntentSHA256)
	if err != nil {
		t.Fatal(err)
	}
	if retired.Request.Intent.IssuedAt.IsZero() || !retired.Request.Intent.OriginalDeadline.After(retired.Request.Intent.IssuedAt) || retired.Request.Intent.OriginalDeadline.Sub(retired.Request.Intent.IssuedAt) > 30*time.Second || retired.Preregistration.PreregistrationID != burst.pre.PreregistrationID || capacity.GuestRetirementSHA(retired.Request.Intent) != c.BurstRetirement.IntentSHA256 || retired.Request.Intent.Tuple.ResourceID != c.NativeResources[1].ResourceID || retired.Request.Intent.Tuple.CreatedAt != c.NativeResources[1].ResourceCreatedAt {
		t.Fatal("retirement adopted another original VM")
	}
	var quiescent model.CapacityGuestRetirementObservation
	for n, digest := range c.BurstRetirement.OriginalRecordSHA256s {
		var raw []byte
		var actual string
		if err := tx.QueryRowContext(ctx, `SELECT original_wire,return_sha256 FROM public.capacity_vm_retirement_original_returns WHERE intent_id=$1 AND sequence=$2`, c.BurstRetirement.RequestID, n+1).Scan(&raw, &actual); err != nil || actual != digest {
			t.Fatal("original return chain differs from corpus", err)
		}
		var original model.CapacityGuestRetirementObservation
		if capacity.DecodeGuestLifecycle(raw, &original) != nil || original.RecordSHA256 != digest || capacity.GuestRetirementSHA(original.Record) != digest || original.Record.Sequence != n+1 || capacity.GuestRetirementObservation(original, retired.Receipt.Enrollment, retired.Request.Intent, original.ObservedAt, false) != nil || (n > 0 && !capacity.GuestRetirementRecordSuccessor(quiescent.Record, original.Record)) {
			t.Fatal("stored original record hash does not join")
		}
		quiescent = original
	}
	if quiescent.Record.State != "poweroff_command_returned" || !quiescent.Record.WriterQuiescenceEvidence {
		t.Fatal("real original seq1..4 did not return source quiescence")
	}
	callerWire := guestOriginalNativeWire(t, tx, ctx, `SELECT original_wire,return_sha256,original_record=convert_from(original_wire,'UTF8')::jsonb FROM public.capacity_guest_original_caller_returns WHERE intent_id=$1 AND return_sha256=$2`, c.BurstRetirement.RequestID, c.BurstRetirement.CallerReturnSHA256)
	var caller repository.GuestOriginalCallerReturn
	var originalCallerReply model.CapacityGuestRetirementObservation
	if capacity.DecodeGuestLifecycle(callerWire, &caller) != nil || !repository.GuestOriginalCallerBodyFactsValid(caller) || caller.ResponseBodyScope != capacity.GuestOriginalBodyCompleteRead || caller.RequestID != retired.Request.Intent.RequestID || caller.AttemptID != retired.Request.Intent.AttemptID || caller.Status != 200 || caller.PreflightFailed || caller.DoFailed || caller.ReadFailed || caller.CloseFailed || caller.OriginalContextFailed || !caller.BodyPersisted || caller.ReceivedBodyBytes != len(caller.Body) || caller.ResponseSHA256 != capacity.BusinessCreationSHA256(caller.Body) || caller.DoStartedAt.Before(caller.StartedAt) || caller.DoReturnedAt.Before(caller.DoStartedAt) || caller.ReadReturnedAt.Before(caller.DoReturnedAt) || caller.CloseReturnedAt.Before(caller.ReadReturnedAt) || caller.DriverReturnedAt.Before(caller.CloseReturnedAt) || !caller.CloseReturnedAt.After(quiescent.Record.RecordedAt) || !caller.OriginalDeadline.Equal(retired.Request.Intent.OriginalDeadline) || !caller.DriverReturnedAt.Before(caller.OriginalDeadline) || capacity.DecodeGuestLifecycle(caller.Body, &originalCallerReply) != nil || !reflect.DeepEqual(originalCallerReply, quiescent) {
		t.Fatal("native public caller completion differs from original Read/Close")
	}
	for n, digest := range c.BurstRetirement.SnapshotChallengeSHA256s {
		challengeWire := guestOriginalNativeWire(t, tx, ctx, `SELECT original_wire,challenge_sha256,original_record=convert_from(original_wire,'UTF8')::jsonb FROM public.capacity_guest_runtime_snapshot_challenges WHERE intent_id=$1 AND phase='before_start' AND ordinal=$2 AND challenge_sha256=$3`, c.BurstRetirement.RequestID, n+1, digest)
		var challenge model.CapacityGuestRuntimeSnapshotChallenge
		if capacity.DecodeGuestLifecycle(challengeWire, &challenge) != nil || challenge.OriginalRegistrationSHA256 != retired.RegistrationSHA || challenge.OriginalCreateWitnessSHA256 != retired.WitnessSHA {
			t.Fatal("fresh before_start source challenge does not join original enrollment")
		}
		snapshotWire := guestOriginalNativeWire(t, tx, ctx, `SELECT original_wire,return_sha256,original_record=convert_from(original_wire,'UTF8')::jsonb FROM public.capacity_guest_runtime_snapshot_returns WHERE challenge_id=$1`, challenge.ChallengeID)
		var snapshot model.CapacityGuestRuntimeSnapshot
		if capacity.DecodeGuestLifecycle(snapshotWire, &snapshot) != nil || capacity.GuestRuntimeSnapshot(challenge, retired.Receipt.Enrollment, retired.Request.Intent, snapshot, snapshot.ObservedAt) != nil {
			t.Fatal("before_start reused absence/seq0 instead of a fresh real source read")
		}
	}
	for n, id := range c.BurstRetirement.AuthorityReadIDs {
		phase := "before_start"
		ordinal := n + 1
		if n >= 2 {
			phase = "before_poweroff"
			ordinal = n - 1
		}
		var actualPhase string
		var actualOrdinal int
		if err := tx.QueryRowContext(ctx, `SELECT phase,ordinal FROM public.capacity_guest_original_authority_reads WHERE id=$1 AND intent_id=$2`, id, c.BurstRetirement.RequestID).Scan(&actualPhase, &actualOrdinal); err != nil || phase != actualPhase || ordinal != actualOrdinal {
			t.Fatal("scoped original authority read identity differs", err)
		}
		wire := guestOriginalNativeWire(t, tx, ctx, `SELECT original_wire,authority_sha256,original_record=convert_from(original_wire,'UTF8')::jsonb FROM public.capacity_guest_original_authority_returns WHERE read_id=$1`, id)
		var authority model.CapacityGuestRetirementAuthority
		if capacity.DecodeGuestLifecycle(wire, &authority) != nil || authority.State != "authorized" || authority.SourceCommit != c.ActualCoreSourceCommit || authority.IntentSHA256 != c.BurstRetirement.IntentSHA256 || !authority.OriginalDeadline.Equal(retired.Request.Intent.OriginalDeadline) {
			t.Fatal("current authority was replaced by a receipt completion claim")
		}
	}
	rows, err := tx.QueryContext(ctx, `SELECT tr.original_wire,tr.return_sha256,tr.original_reply_wire,tr.original_record=convert_from(tr.original_wire,'UTF8')::jsonb AND r.original_deadline=(tr.original_record->>'original_deadline')::timestamptz,r.id::text,r.phase,r.ordinal,tr.native_stage FROM public.capacity_guest_original_authority_transport_returns tr JOIN public.capacity_guest_original_authority_reads r ON r.id=tr.read_id WHERE r.intent_id=$1 ORDER BY r.phase,r.ordinal,tr.native_stage`, c.BurstRetirement.RequestID)
	if err != nil {
		t.Fatal(err)
	}
	type transportRow struct {
		wire, reply                  []byte
		digest, readID, phase, stage string
		ordinal                      int
		consistent                   bool
	}
	var transports []transportRow
	for rows.Next() {
		var row transportRow
		if err := rows.Scan(&row.wire, &row.digest, &row.reply, &row.consistent, &row.readID, &row.phase, &row.ordinal, &row.stage); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		transports = append(transports, row)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		t.Fatal(err)
	}
	if err := rows.Close(); err != nil || len(transports) != 5 {
		t.Fatal("five actual original authority Read/Close returns missing", err)
	}
	for _, row := range transports {
		wire, reply, digest, readID, phase, stage, ordinal, consistent := row.wire, row.reply, row.digest, row.readID, row.phase, row.stage, row.ordinal, row.consistent
		var returned guestOriginalAuthorityTransport
		if !consistent || capacity.BusinessCreationSHA256(wire) != digest || capacity.DecodeGuestLifecycle(wire, &returned) != nil || !capacity.GuestOriginalHTTPBodyFactsValid(returned.ResponseBodyScope, returned.ReadReturnedAt, returned.ReceivedBodyBytes, returned.ResponseSHA256, returned.RetainedPrefixBytes, returned.RetainedPrefixSHA256, returned.ReadFailed) || returned.ResponseBodyScope != capacity.GuestOriginalBodyCompleteRead || returned.RetainedPrefixBytes != len(reply) || returned.RetainedPrefixSHA256 != capacity.BusinessCreationSHA256(reply) || returned.ReadID != readID || returned.Stage != stage || returned.Status != 200 || returned.PreflightFailed || returned.DoFailed || returned.ReadFailed || returned.CloseFailed || returned.OriginalContextFailed || len(reply) == 0 || returned.ReceivedBodyBytes != len(reply) || returned.ResponseSHA256 != capacity.BusinessCreationSHA256(reply) || returned.StartedAt.IsZero() || returned.DoStartedAt.Before(returned.StartedAt) || returned.DoReturnedAt.Before(returned.DoStartedAt) || returned.ReadReturnedAt.Before(returned.DoReturnedAt) || returned.CloseReturnedAt.Before(returned.ReadReturnedAt) || returned.DriverReturnedAt.Before(returned.CloseReturnedAt) || !returned.DriverReturnedAt.Before(returned.OriginalDeadline) {
			rows.Close()
			t.Fatal("actual original authority transport and exact complete body do not join")
		}
		if phase == "before_start" && stage == "snapshot" && (ordinal == 1 || ordinal == 2) {
			var challengeWire []byte
			if err := tx.QueryRowContext(ctx, `SELECT original_wire FROM public.capacity_guest_runtime_snapshot_challenges WHERE intent_id=$1 AND phase=$2 AND ordinal=$3`, c.BurstRetirement.RequestID, phase, ordinal).Scan(&challengeWire); err != nil {
				rows.Close()
				t.Fatal(err)
			}
			var challenge model.CapacityGuestRuntimeSnapshotChallenge
			var snapshot model.CapacityGuestRuntimeSnapshot
			if capacity.DecodeGuestLifecycle(challengeWire, &challenge) != nil || capacity.DecodeGuestLifecycle(reply, &snapshot) != nil || capacity.GuestRuntimeSnapshot(challenge, retired.Receipt.Enrollment, retired.Request.Intent, snapshot, returned.DriverReturnedAt) != nil {
				rows.Close()
				t.Fatal("actual snapshot transport cannot be replaced by a source count")
			}
			canonical, err := json.Marshal(snapshot)
			if err != nil || !bytes.Equal(canonical, reply) {
				rows.Close()
				t.Fatal("snapshot canonical original HTTP bytes diverge")
			}
		} else if stage == "journal" && ((phase == "before_start" && ordinal == 2) || (phase == "before_poweroff" && (ordinal == 1 || ordinal == 2))) {
			sequence := ordinal + 1
			if phase == "before_start" {
				sequence = 1
			}
			var observation model.CapacityGuestRetirementObservation
			if capacity.DecodeGuestLifecycle(reply, &observation) != nil || observation.Record.Sequence != sequence || observation.RecordSHA256 != c.BurstRetirement.OriginalRecordSHA256s[sequence-1] || capacity.GuestRetirementObservation(observation, retired.Receipt.Enrollment, retired.Request.Intent, returned.DriverReturnedAt, true) != nil {
				rows.Close()
				t.Fatal("actual active original journal transport does not join its source record")
			}
			canonical, err := json.Marshal(observation)
			if err != nil || !bytes.Equal(canonical, reply) {
				rows.Close()
				t.Fatal("journal canonical original HTTP bytes diverge")
			}
		} else {
			rows.Close()
			t.Fatal("unexpected original authority transport phase")
		}
	}
	offWire := guestOriginalNativeWire(t, tx, ctx, `SELECT original_wire,observation_sha256,original_record=convert_from(original_wire,'UTF8')::jsonb FROM public.capacity_guest_original_native_poweroff_reads WHERE intent_id=$1 AND observation_sha256=$2`, c.BurstRetirement.RequestID, c.BurstRetirement.NativeOffReturnSHA256)
	var off repository.GuestNativeQEMUOffReturn
	var join repository.GuestNativeQEMUPIDFDReturn
	var joinWire []byte
	if err := tx.QueryRowContext(ctx, `SELECT original_native_join_wire FROM public.capacity_guest_original_native_poweroff_reads WHERE intent_id=$1 AND observation_sha256=$2`, c.BurstRetirement.RequestID, c.BurstRetirement.NativeOffReturnSHA256).Scan(&joinWire); err != nil {
		t.Fatal(err)
	}
	sameProcess := func(a, b repository.GuestNativeQEMUProcess) bool {
		return a.PID == b.PID && a.PPID == b.PPID && a.StartTicks == b.StartTicks
	}
	creator := nativeInitial[1].Original.QEMU
	if capacity.DecodeGuestLifecycle(offWire, &off) != nil || capacity.DecodeGuestLifecycle(joinWire, &join) != nil || off.Schema != "core_original_guest_native_qemu_fixture_v1" || off.Stage != "native-off-original.json" || off.Scope != "original_burst_native_off" || off.Slot != 2 || off.ResourceID != retired.Request.Intent.Tuple.ResourceID || off.SourceCommit != c.GuestSourceCommit || off.CreatorOriginalSHA256 != c.NativeResources[1].CreatorOriginalSHA256 || off.QEMU.PID != creator.PID || off.QEMU.PPID != creator.PPID || off.QEMU.StartTicks != creator.StartTicks || off.QEMU.StatSHA256 != creator.StatSHA256 || off.OriginalWaitCode != 0 || !off.OriginalStderrEOF || off.OriginalWaitReturnedAt.Before(quiescent.Record.PoweroffOperation.WaitReturnedAt) || off.OriginalStderrCloseReturnedAt.Before(off.OriginalWaitReturnedAt) || join.Schema != "core_original_same_qemu_pidfd_join_v1" || join.ResourceID != off.ResourceID || join.CreatorOriginalSHA256 != off.CreatorOriginalSHA256 || !sameProcess(join.Before, off.QEMU) || !sameProcess(join.Before, join.After) || join.OriginalPinStartedAt.IsZero() || join.OriginalPinReturnedAt.Before(join.OriginalPinStartedAt) || join.OriginalPinReturnedAt.After(retired.Request.Intent.IssuedAt) || !repository.GuestNativeQEMUPIDFDExited(join.OriginalPollRevents) || join.OriginalPollReturnedAt.Before(off.OriginalWaitReturnedAt) || join.OriginalPollReturnedAt.Before(caller.DriverReturnedAt) || join.OriginalCloseReturnedAt.Before(join.OriginalPollReturnedAt) || !join.OriginalCloseReturnedAt.Before(retired.Request.Intent.OriginalDeadline) {
		t.Fatal("actual original QEMU Wait, stderr EOF/Close and the pre-intent PIDFD join do not agree")
	}
	deleteWire := guestOriginalNativeWire(t, tx, ctx, `SELECT original_wire,observation_sha256,original_observation_record=convert_from(original_wire,'UTF8')::jsonb FROM public.capacity_vm_retirement_native_readbacks WHERE destroy_grant_id=$1 AND observation_sha256=$2`, c.BurstRetirement.DestroyGrantID, c.BurstRetirement.NativeDeleteReadbackSHA256)
	var destroyRaw []byte
	if err := tx.QueryRowContext(ctx, `SELECT grant_record FROM public.capacity_mutation_grants WHERE id=$1`, c.BurstRetirement.DestroyGrantID).Scan(&destroyRaw); err != nil {
		t.Fatal(err)
	}
	var destroy guestOriginalDestroyRecord
	var observed repository.GuestNativeQEMUDeleteReadback
	if json.Unmarshal(destroyRaw, &destroy) != nil || destroy.Settlement == nil || destroy.Proof == nil || destroy.Grant.State != "confirmed" || capacity.DecodeGuestLifecycle(deleteWire, &observed) != nil || observed.OriginalDelete.CreatorOriginalSHA256 != off.CreatorOriginalSHA256 || observed.OriginalDelete.OriginalDisk != nativeInitial[1].OriginalDisk || observed.OriginalDelete.OriginalUnlinkCalledAt.Before(join.OriginalCloseReturnedAt) || !observed.OriginalDirectoryCloseReturnedAt.Before(retired.Request.Intent.OriginalDeadline) {
		t.Fatal("owning original DELETE did not complete its closed native readback")
	}
	// Revalidate using the original read's returned-at instant. This issues no
	// write authority and never reinterprets old evidence as currently fresh.
	at := observed.OriginalDirectoryCloseReturnedAt
	observationGrant := destroy.Grant
	observationGrant.State = observed.GrantState
	r := model.CapacityMutationReceipt{Grant: observationGrant, AttemptID: destroy.AttemptID, Outcome: destroy.Settlement.Outcome, TransportCompleted: destroy.Settlement.TransportCompleted, ResourceID: destroy.Settlement.ResourceID, ResourceCreatedAt: destroy.Settlement.ResourceCreatedAt, ActionID: destroy.Settlement.ActionID, NextActionIDs: destroy.Settlement.NextActionIDs, AuxiliaryResources: destroy.Settlement.AuxiliaryResources, AuxiliaryInventoryComplete: destroy.Settlement.AuxiliaryInventoryComplete}
	proof, err := repository.GuestNativeQEMUDeleteProof(p, destroy.Binding, r, observed, at, destroy.Proof.ReceiptRef)
	if err != nil || !reflect.DeepEqual(proof, *destroy.Proof) {
		t.Fatal("native physical deletion proof diverges from actual original provider read", err)
	}
	baselineReceipt, baselineRegistrationSHA, err := loadGuestReceiptTx(ctx, tx, baseline.pre.PreregistrationID)
	if err != nil {
		t.Fatal(err)
	}
	baselineProbe := guestOriginalProbe(t, tx, ctx, baseline.pre.PreregistrationID, c.BaselineServingProbeSHA256, baselineReceipt.Enrollment, baselineRegistrationSHA)
	if !baselineProbe.OriginalReadStartedAt.After(at) {
		t.Fatal("baseline real live writer was not observed after burst deletion")
	}
}
