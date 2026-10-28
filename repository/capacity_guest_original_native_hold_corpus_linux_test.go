//go:build linux && nativequalification

package repository_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	q "github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacitynativeqemu"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

func guestOriginalHoldReceipt(t *testing.T) (q.Corpus, string) {
	t.Helper()
	path := os.Getenv("CAPACITY_GUEST_NATIVE_CORPUS_FILE")
	if os.Getenv("REQUIRE_CAPACITY_GUEST_NATIVE_CORPUS") != "true" || path == "" {
		t.Fatal("actual owning native HOLD corpus is mandatory")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > capacity.GuestBootstrapLimit {
		t.Fatal("bounded original native HOLD receipt required")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var c q.Corpus
	if capacity.DecodeGuestLifecycle(raw, &c) != nil {
		t.Fatal("closed original native HOLD corpus required")
	}
	allowed := map[string]bool{"held_hello_original_deadline": true, "held_ack_after_owned_original_deadline": true, "held_probe_body_original_deadline": true, "cancelled_probe_original_join": true, "admission_bind_cancelled_original": true}
	runs := 2
	if c.NativeCase == "held_ack_after_owned_original_deadline" {
		runs = 4 // Includes the real public low-demand observation before claim.
	}
	if c.Schema != "core_original_guest_native_qemu_corpus_v1" || !allowed[c.NativeCase] || c.NativeCase != os.Getenv("GUEST_ORIGINAL_NATIVE_CASE") || c.CaseOutcome != "ORIGINAL_EXPECTED_HOLD_OWNERS_JOINED" || !guestOriginalNativeSource(c.ActualCoreSourceCommit) || !guestOriginalNativeSource(c.GuestSourceCommit) || !guestOriginalNativeUUID(c.PolicyID) || !guestOriginalNativeUUID(c.WorkflowID) || !capacity.ValidDigest(c.PolicyChecksum) || !capacity.ValidDigest(c.WorkflowChecksum) || !capacity.ValidDigest(c.ProfileManifestSHA256) || !capacity.ValidDigest(c.FailedOwnerDiagnosticSHA256) || !capacity.ValidDigest(c.BaselineServingProbeSHA256) || c.BurstRetirement != nil || len(c.OriginalPreregistrationIDs) != 2 || len(c.NativeResources) != 2 || len(c.OriginalRunIDs) != runs || c.Namespace == "" {
		t.Fatal("HOLD case was missing, relabeled or promoted to positive native lifecycle")
	}
	for _, ids := range [][]string{c.OriginalRunIDs, c.OriginalPreregistrationIDs} {
		seen := map[string]bool{}
		for _, id := range ids {
			if !guestOriginalNativeUUID(id) || seen[id] {
				t.Fatal("original HOLD identities reused or missing")
			}
			seen[id] = true
		}
	}
	return c, filepath.Dir(path)
}

func guestOriginalHoldNative(t *testing.T, tx *sql.Tx, ctx context.Context, preID, stage, digest string) q.IndependentReturn {
	t.Helper()
	wire := guestOriginalNativeWire(t, tx, ctx, `SELECT original_wire,return_sha256,original_record=convert_from(original_wire,'UTF8')::jsonb FROM public.capacity_guest_qualification_native_source_returns WHERE preregistration_id=$1 AND native_stage=$2 AND return_sha256=$3`, preID, stage, digest)
	var native q.IndependentReturn
	if capacity.DecodeGuestLifecycle(wire, &native) != nil || native.Schema != "core_independent_original_qemu_read_v1" || native.Before.PID < 2 || native.Before.PPID < 1 || native.Before.StartTicks < 1 || !capacity.ValidDigest(native.Before.StatSHA256) || !capacity.ValidDigest(native.After.StatSHA256) || native.After.PID != native.Before.PID || native.After.PPID != native.Before.PPID || native.After.StartTicks != native.Before.StartTicks || native.QMPPeerPID != int32(native.Before.PID) || native.Before.PID != native.Original.QEMU.PID || native.Before.PPID != native.Original.QEMU.PPID || native.Before.StartTicks != native.Original.QEMU.StartTicks || !capacity.ValidDigest(native.ExecutableSHA256) || !capacity.ValidDigest(native.CommandLineSHA256) || native.ReadReturnedAt.Before(native.StartedAt) || native.CloseReturnedAt.Before(native.ReadReturnedAt) || !native.Status.Running || native.Status.SingleStep || native.Status.Status != "running" || strings.ToLower(native.UUID.UUID) != native.Original.ResourceID || len(native.IO) < 7 || len(native.IO) > 64 || native.OriginalDisk.Inode == 0 || native.OriginalDiskFD < 0 || native.OriginalDiskReadReturnedAt.Before(native.StartedAt) || native.OriginalDiskDirectoryCloseReturnedAt.Before(native.OriginalDiskReadReturnedAt) || native.OriginalDiskDirectoryCloseReturnedAt.After(native.ReadReturnedAt) {
		t.Fatal("actual diagnostic QMP/kernel read did not close on the same running original")
	}
	previous := native.StartedAt
	reads, writes := 0, 0
	for _, io := range native.IO {
		if (io.Direction != "read" && io.Direction != "write") || !capacity.ValidDigest(io.SHA256) || io.Bytes < 1 || io.Bytes > capacity.GuestBootstrapLimit || io.ReturnedAt.Before(previous) || io.ReturnedAt.After(native.ReadReturnedAt) {
			t.Fatal("diagnostic original native IO prefix replaced full actual returns")
		}
		if io.Direction == "read" {
			reads++
		} else {
			writes++
		}
		previous = io.ReturnedAt
	}
	if reads < 4 || writes != 3 {
		t.Fatal("full original QMP greeting/capabilities/UUID/status returns missing")
	}
	return native
}

// This root runs once for EACH of the five fixed expected-HOLD owning cases.
// It consumes actual command records with readonly SQL and closed original file
// bytes. It never seeds data, sends requests, overrides Go source identity or
// converts a signed diagnostic into admission/noStart/quiescence permission.
func TestCapacityGuestOriginalNativeHoldCorpusPostgres(t *testing.T) {
	c, private := guestOriginalHoldReceipt(t)
	ack := c.NativeCase == "held_ack_after_owned_original_deadline"
	bind := c.NativeCase == "admission_bind_cancelled_original"
	enrolledBurst := c.NativeCase != "held_hello_original_deadline"
	physicalBurst := ack || c.NativeCase == "held_probe_body_original_deadline" || c.NativeCase == "cancelled_probe_original_join"
	db := guestOriginalPostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	var rawPolicy []byte
	var checksum, namespace string
	if err := tx.QueryRowContext(ctx, `SELECT spec,checksum,namespace FROM public.manifests WHERE id=$1 AND kind='capacity_policy'`, c.PolicyID).Scan(&rawPolicy, &checksum, &namespace); err != nil || checksum != c.PolicyChecksum || namespace != c.Namespace {
		t.Fatal("original HOLD policy absent", err)
	}
	var p model.CapacityPolicySpec
	if json.Unmarshal(rawPolicy, &p) != nil || p.GuestRetirementBinding == nil || capacity.ValidateGuestRetirementBinding(p, p.GuestRetirementBinding) != nil || p.GuestRetirementBinding.CoreAuthoritySourceCommit != c.ActualCoreSourceCommit || p.GuestRetirementBinding.GuestSourceCommit != c.GuestSourceCommit || p.GuestRetirementBinding.ProfileManifestSHA256 != c.ProfileManifestSHA256 || p.GuestRetirementBinding.EvidenceClass != "native_qemu_qualification" || p.GuestRetirementBinding.ProfileManifest.ProductionCatalogSHA256 != "" {
		t.Fatal("actual failed original source was expanded or relabeled")
	}
	if err := tx.QueryRowContext(ctx, `SELECT checksum FROM public.manifests WHERE id=$1 AND kind='workflow' AND namespace=$2`, c.WorkflowID, c.Namespace).Scan(&checksum); err != nil || checksum != c.WorkflowChecksum {
		t.Fatal("original HOLD workflow absent", err)
	}
	for n, id := range c.OriginalRunIDs {
		var status string
		expected := "failed"
		if n == 0 || (ack && (n == 1 || n == 2)) {
			expected = "succeeded"
		}
		if err := tx.QueryRowContext(ctx, q.OriginalWorkflowIdentitySQL, id, c.WorkflowID).Scan(&status); err != nil || status != expected {
			t.Fatal("real public caller baseline/failed run missing", err)
		}
	}
	var originals [2]guestOriginalStored
	var initial [2]q.IndependentReturn
	var enrollments [2]model.CapacityGuestOriginalProvisioningReceipt
	var registrationSHAs [2]string
	for n, resource := range c.NativeResources {
		if resource.Slot != n+1 || !guestOriginalNativeUUID(resource.ResourceID) || !capacity.ValidDigest(resource.CreatorOriginalSHA256) || !capacity.ValidDigest(resource.CoreNativeOriginalReadSHA256) || !capacity.ValidDigest(resource.NativeDiagnosticAfterSHA256) {
			t.Fatal("actual HOLD native roster malformed")
		}
		stored, err := loadGuestOriginalTx(ctx, tx, c.OriginalPreregistrationIDs[n])
		if err != nil {
			t.Fatal(err)
		}
		if stored.pre.PolicyID != c.PolicyID || stored.pre.PolicyChecksum != c.PolicyChecksum || stored.pre.WorkflowID != c.WorkflowID || stored.pre.WorkflowChecksum != c.WorkflowChecksum || stored.pre.CoreSourceCommit != c.ActualCoreSourceCommit || stored.pre.Slot != n+1 || stored.pre.ProfileManifestSHA256 != c.ProfileManifestSHA256 || stored.pre.OriginalWorkflowStepTimeoutSeconds != 600 || stored.binding.ProfileManifest.OriginalProvisioningBudgetSeconds != 420 {
			t.Fatal("original HOLD reservation/actual step/budget does not join")
		}
		if err := loadGuestWitnessTx(ctx, tx, &stored); err != nil {
			t.Fatal(err)
		}
		if stored.witness.Tuple.ResourceID != resource.ResourceID || stored.witness.Tuple.CreatedAt != resource.ResourceCreatedAt {
			t.Fatal("HOLD native tuple adopted another original")
		}
		native := guestOriginalHoldNative(t, tx, ctx, stored.pre.PreregistrationID, "native_read", resource.CoreNativeOriginalReadSHA256)
		var creator q.CreatorReturn
		creatorWire, err := q.ReadPrivate(ctx, filepath.Join(q.SlotDirectory(private, resource.Slot), "creator-original.json"), &creator)
		if err != nil || capacity.BusinessCreationSHA256(creatorWire) != resource.CreatorOriginalSHA256 || native.OriginalCreatorSHA256 != resource.CreatorOriginalSHA256 || !reflect.DeepEqual(creator, native.Original) || creator.OriginalSourceCommit != c.GuestSourceCommit || creator.ResourceID != resource.ResourceID || creator.Slot != resource.Slot || creator.OriginalCreateReturnedAt.UTC().Format(time.RFC3339Nano) != resource.ResourceCreatedAt || !stored.witness.OriginalCreateReturnedAt.Equal(creator.OriginalCreateReturnedAt) || !stored.witness.OriginalCreateReturnedAt.Before(native.CloseReturnedAt) || creator.OriginalCreateReturnedAt.Before(creator.OriginalCreateStartedAt) || creator.OriginalReadStartedAt.Before(creator.OriginalCreateReturnedAt) || creator.OriginalReadReturnedAt.Before(creator.OriginalReadStartedAt) || native.StartedAt.Before(creator.OriginalReadReturnedAt) {
			t.Fatal("Popen original RETURN bytes/native joins diverge", err)
		}
		var ready q.Stage
		readyWire, err := q.ReadPrivate(ctx, filepath.Join(q.SlotDirectory(private, resource.Slot), "ready.json"), &ready)
		if err != nil || ready.Schema != q.FixtureSchema || ready.Stage != "ready.json" || ready.Slot != resource.Slot || ready.CoreActualSourceCommit != c.ActualCoreSourceCommit || ready.SourceCommit != c.GuestSourceCommit || !ready.OriginalDeadline.Equal(stored.pre.OriginalDeadline) || !capacity.ValidDigest(ready.OriginalRecordSHA256) {
			t.Fatal("original before-create private stage cannot join", err)
		}
		var grantExpiresText string
		var grantConsistent bool
		if err := tx.QueryRowContext(ctx, `SELECT grant_record->'grant'->>'expires_at',expires_at=(grant_record->'grant'->>'expires_at')::timestamptz FROM public.capacity_mutation_grants WHERE id=$1`, stored.pre.OriginalCreateGrantID).Scan(&grantExpiresText, &grantConsistent); err != nil || !grantConsistent {
			t.Fatal("original create permission expiry bytes diverge", err)
		}
		grantExpires, err := time.Parse(time.RFC3339Nano, grantExpiresText)
		if err != nil || q.CheckCreator(creator, resource.Slot, resource.ResourceID, c.GuestSourceCommit, creator.CreatorSourceSHA256, capacity.BusinessCreationSHA256(readyWire), ready.RecordedAt, grantExpires, stored.pre.OriginalDeadline) != nil {
			t.Fatal("actual original creator Read/Close/IO and Popen bounds incomplete", err)
		}
		var enrollmentCount int
		expectedEnrollment := 1
		if n == 1 && !enrolledBurst {
			expectedEnrollment = 0
		}
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_vm_original_enrollments WHERE preregistration_id=$1`, stored.pre.PreregistrationID).Scan(&enrollmentCount); err != nil || enrollmentCount != expectedEnrollment {
			t.Fatal("baseline original enrollment missing or duplicated", err)
		}
		if enrollmentCount == 0 {
			if resource.RegistrationSHA256 != "" || resource.EnrollmentSHA256 != "" || resource.ServingProbeSHA256 != "" {
				t.Fatal("missing burst enrollment became supplied completeness")
			}
		} else {
			receipt, registrationSHA, err := loadGuestReceiptTx(ctx, tx, stored.pre.PreregistrationID)
			if err != nil {
				t.Fatal(err)
			}
			if receipt.Enrollment.Statement.Tuple != stored.witness.Tuple || resource.RegistrationSHA256 != registrationSHA || resource.EnrollmentSHA256 != capacity.GuestRetirementSHA(receipt.Enrollment) || capacity.GuestOriginalCreateWitness(p, stored.binding, stored.member, stored.pre, stored.witness, receipt.Enrollment.Statement.CoreIntentPublicKey, stored.witness.ObservedAt) != nil || capacity.GuestRetirementEnrollment(p, stored.binding, stored.member, receipt.Enrollment, receipt.Enrollment.Statement.IssuedAt) != nil {
				t.Fatal("optional actual original enrollment was forged or adopted")
			}
			var registrationWire []byte
			var registration model.CapacityGuestOriginalProvisioningRegistration
			if err := tx.QueryRowContext(ctx, `SELECT registration_wire FROM public.capacity_vm_original_enrollments WHERE preregistration_id=$1`, stored.pre.PreregistrationID).Scan(&registrationWire); err != nil || capacity.DecodeGuestLifecycle(registrationWire, &registration) != nil || capacity.GuestOriginalRegistration(p, stored.binding, stored.member, stored.witness, registration, registration.Result.OriginalReturnedAt) != nil {
				t.Fatal("actual optional original placement/bootstrap bytes incomplete", err)
			}
			enrollments[n], registrationSHAs[n] = receipt, registrationSHA
		}
		if n == 0 || ack {
			if !capacity.ValidDigest(resource.ServingProbeSHA256) {
				t.Fatal("baseline initial real useful echo missing")
			}
			guestOriginalProbe(t, tx, ctx, stored.pre.PreregistrationID, resource.ServingProbeSHA256, enrollments[n].Enrollment, registrationSHAs[n])
		} else if resource.ServingProbeSHA256 != "" {
			t.Fatal("failed original burst supplied a capacity-phase useful row")
		}
		originals[n], initial[n] = stored, native
	}
	for _, stored := range originals {
		if capacity.GuestOriginalCreateWitness(p, stored.binding, stored.member, stored.pre, stored.witness, enrollments[0].Enrollment.Statement.CoreIntentPublicKey, stored.witness.ObservedAt) != nil {
			t.Fatal("original failed-create Core witness signature did not join the same original signing authority")
		}
	}
	if bind {
		var state string
		if err := tx.QueryRowContext(ctx, `SELECT state FROM public.capacity_mutation_grants WHERE id=$1`, originals[1].pre.OriginalCreateGrantID).Scan(&state); err != nil || (state != "settled" && state != "confirmed") {
			t.Fatal("bind cancellation lost its actual settled/enrolled original create", err)
		}
		physicalBurst = state == "confirmed"
	}
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_vm_provisioning_preregistrations p JOIN public.capacity_mutation_grants g ON g.id=p.create_grant_id WHERE g.namespace=$1`, c.Namespace).Scan(&count); err != nil || count != 2 {
		t.Fatal("failed original caused an extra provisioning attempt", err)
	}
	for _, census := range []string{
		`SELECT count(*) FROM public.capacity_guest_original_create_witnesses w JOIN public.capacity_vm_provisioning_preregistrations p ON p.id=w.preregistration_id WHERE p.preregistration_record->>'policy_id'=$1`,
		`SELECT count(*) FROM public.capacity_guest_qualification_native_source_returns r JOIN public.capacity_vm_provisioning_preregistrations p ON p.id=r.preregistration_id WHERE p.preregistration_record->>'policy_id'=$1 AND r.native_stage='native_read'`,
		`SELECT count(*) FROM public.capacity_guest_qualification_native_source_returns r JOIN public.capacity_vm_provisioning_preregistrations p ON p.id=r.preregistration_id WHERE p.preregistration_record->>'policy_id'=$1 AND r.native_stage='diagnostic_native_read'`,
	} {
		if err := tx.QueryRowContext(ctx, census, c.PolicyID).Scan(&count); err != nil || count != 2 {
			t.Fatal("original native read/witness identities were missing, duplicated or retried", err)
		}
	}
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_guest_qualification_native_source_returns WHERE preregistration_id=$1 AND native_stage='source_refusal'`, originals[1].pre.PreregistrationID).Scan(&count); err != nil || count != 1 {
		t.Fatal("failed original diagnostic was replaced or duplicated", err)
	}
	failureWire := guestOriginalNativeWire(t, tx, ctx, `SELECT original_wire,return_sha256,original_record=convert_from(original_wire,'UTF8')::jsonb FROM public.capacity_guest_qualification_native_source_returns WHERE preregistration_id=$1 AND native_stage='source_refusal' AND return_sha256=$2`, originals[1].pre.PreregistrationID, c.FailedOwnerDiagnosticSHA256)
	var failure q.QualificationFailureRecord
	if capacity.DecodeGuestLifecycle(failureWire, &failure) != nil {
		t.Fatal("actual source failure diagnostic incomplete")
	}
	// The validation realm is reconstructed solely from immutable original
	// step/profile/source fields; it opens no native realm and grants no write.
	realm := q.Realm{Request: q.SourceRequest{NativeCase: c.NativeCase, SourceCommit: c.GuestSourceCommit, OriginalContextDeadline: originals[1].pre.OriginalWorkflowContextDeadline}, Profile: originals[1].binding.ProfileManifest}
	if realm.ValidateOriginalFailure(failure, originals[1].pre, originals[1].witness, originals[1].binding.ProvisionerPublicKey, failure.RecordedAt) != nil {
		t.Fatal("original Wait/output EOF/diagnostic Close/body hashes did not join authentic producer")
	}
	if enrolledBurst {
		statement := enrollments[1].Enrollment.Statement
		if failure.Runtime != statement.Runtime || len(statement.Writers) != 1 || failure.OriginalChild.PID != statement.Writers[0].Lifetime.PID || failure.OriginalChild.StartTicks != statement.Writers[0].Lifetime.StartTicks {
			t.Fatal("failed owner diagnostic adopted another enrolled runtime/writer lifetime")
		}
	}
	journal := failure.ProvisioningJournal
	expectedSequence, expectedState := 6, "admitted"
	if !enrolledBurst {
		expectedSequence, expectedState = 1, "possible_profile_start"
	}
	if bind {
		expectedSequence, expectedState = 5, "admission_possible"
	}
	if journal == nil || journal.LastSequence != expectedSequence || journal.LastState != expectedState || len(journal.Records) != expectedSequence || !capacity.ValidDigest(journal.LastRecordSHA256) || journal.AdmissionPossible != enrolledBurst || journal.AdmissionWriteReturned != (enrolledBurst && !bind) || journal.OriginalReadStartedAt.Before(failure.OriginalStartReturnedAt) || journal.OriginalReadReturnedAt.Before(journal.OriginalReadStartedAt) || journal.OriginalCloseReturnedAt.Before(journal.OriginalReadReturnedAt) || journal.OriginalCloseReturnedAt.After(failure.RecordedAt) {
		t.Fatal("signed source journal did not retain the actual partial admission boundary")
	}
	if (enrolledBurst && journal.EnrollmentSHA256 != c.NativeResources[1].EnrollmentSHA256) || (!enrolledBurst && journal.EnrollmentSHA256 != "") {
		t.Fatal("source journal adopted another enrollment")
	}
	previousClose := journal.OriginalReadStartedAt
	for n, record := range journal.Records {
		if record.Sequence != n+1 || !capacity.ValidDigest(record.OriginalRecordSHA256) || record.OriginalReadReturnedAt.Before(previousClose) || record.OriginalCloseReturnedAt.Before(record.OriginalReadReturnedAt) || record.OriginalCloseReturnedAt.After(journal.OriginalReadReturnedAt) {
			t.Fatal("source journal replaced actual ordered Read/Close returns")
		}
		previousClose = record.OriginalCloseReturnedAt
	}
	if journal.Records[expectedSequence-1].OriginalRecordSHA256 != journal.LastRecordSHA256 {
		t.Fatal("source journal last original bytes diverge")
	}
	switch c.NativeCase {
	case "held_hello_original_deadline":
		if failure.Phase != "original_preownership_failure" || !failure.OriginalOperationDeadline.Equal(originals[1].pre.OriginalDeadline) || failure.OriginalWait.OriginalReturnedAt.Before(failure.OriginalOperationDeadline) || failure.OriginalOutputEOFAndClose.OriginalReturnedAt.Before(failure.OriginalOperationDeadline) || failure.OriginalWait.ErrorClass != "original_owner_error" || failure.OriginalProbeRead != nil {
			t.Fatal("held HELLO replaced the original provisioning deadline/owner returns")
		}
	case "admission_bind_cancelled_original":
		if failure.Phase != "original_provisioning_held" || !failure.OriginalOperationDeadline.Equal(originals[1].pre.OriginalDeadline) || failure.OriginalProbeRead != nil || !failure.OriginalWait.OriginalReturnedAt.Before(failure.OriginalOperationDeadline) || !failure.OriginalOutputEOFAndClose.OriginalReturnedAt.Before(failure.OriginalOperationDeadline) {
			t.Fatal("bind cancellation supplied a later admission or replacement original deadline")
		}
	case "held_probe_body_original_deadline", "cancelled_probe_original_join":
		var probeWire []byte
		var consistent bool
		if err := tx.QueryRowContext(ctx, `SELECT original_wire,original_record=convert_from(original_wire,'UTF8')::jsonb AND original_deadline=(original_record->'challenge'->>'original_deadline')::timestamptz AND recorded_at<(original_record->'challenge'->>'original_deadline')::timestamptz FROM public.capacity_guest_qualification_probe_challenges WHERE preregistration_id=$1 AND usage_class='capacity_phase' AND original_deadline=$2`, originals[1].pre.PreregistrationID, failure.OriginalOperationDeadline).Scan(&probeWire, &consistent); err != nil || !consistent {
			t.Fatal("failed probe lost its committed original signed challenge", err)
		}
		var probeRequest q.QualificationProbeRequest
		if capacity.DecodeGuestLifecycle(probeWire, &probeRequest) != nil {
			t.Fatal("failed probe challenge bytes were not closed")
		}
		ch := probeRequest.Challenge
		statement := enrollments[1].Enrollment.Statement
		if failure.Phase != "original_probe_held" || ch.Tuple != statement.Tuple || ch.Actor != statement.Actor || ch.Runtime != statement.Runtime || len(statement.Writers) != 1 || ch.Writer != statement.Writers[0] || ch.EnrollmentSHA256 != c.NativeResources[1].EnrollmentSHA256 || !ch.OriginalDeadline.Equal(failure.OriginalOperationDeadline) || ch.OriginalDeadline.Sub(ch.IssuedAt) != 5*time.Second || !capacity.GuestQualificationSignature(statement.CoreIntentPublicKey, probeRequest.Signature, ch) {
			t.Fatal("failed probe renewed or adopted another original challenge")
		}
		if c.NativeCase == "held_probe_body_original_deadline" {
			if failure.OriginalProbeRead != nil || failure.OriginalWait.OriginalReturnedAt.Before(ch.OriginalDeadline) || failure.OriginalOutputEOFAndClose.OriginalReturnedAt.Before(ch.OriginalDeadline) || failure.OriginalWait.ErrorClass != "original_owner_error" {
				t.Fatal("held probe prefix replaced late original owners/terminal EOF")
			}
		} else {
			probe := failure.OriginalProbeRead
			if probe == nil || probe.ErrorClass != "none" || !probe.OriginalReturnedAt.Before(ch.OriginalDeadline) || probe.OriginalReturnedAt.Before(ch.IssuedAt) || failure.OriginalWait.OriginalReturnedAt.Before(probe.OriginalReturnedAt) || failure.OriginalOutputEOFAndClose.OriginalReturnedAt.Before(probe.OriginalReturnedAt) || !failure.OriginalWait.OriginalReturnedAt.Before(ch.OriginalDeadline) || !failure.OriginalOutputEOFAndClose.OriginalReturnedAt.Before(ch.OriginalDeadline) {
				t.Fatal("cancelled probe replaced its original echo/owner joins")
			}
		}
	}
	for n, resource := range c.NativeResources {
		fresh := guestOriginalHoldNative(t, tx, ctx, originals[n].pre.PreregistrationID, "diagnostic_native_read", resource.NativeDiagnosticAfterSHA256)
		if fresh.StartedAt.Before(failure.RecordedAt) || !reflect.DeepEqual(fresh.Original, initial[n].Original) || fresh.OriginalCreatorSHA256 != resource.CreatorOriginalSHA256 || fresh.Before.PID != initial[n].Before.PID || fresh.Before.StartTicks != initial[n].Before.StartTicks || fresh.QMPPeerPID != initial[n].QMPPeerPID || fresh.ExecutableSHA256 != initial[n].ExecutableSHA256 || fresh.CommandLineSHA256 != initial[n].CommandLineSHA256 || fresh.OriginalDisk != initial[n].OriginalDisk {
			t.Fatal("diagnostic read adopted a replacement QEMU or preceded the original owner returns")
		}
	}
	diagnosticWire := guestOriginalNativeWire(t, tx, ctx, `SELECT original_wire,return_sha256,original_record=convert_from(original_wire,'UTF8')::jsonb FROM public.capacity_guest_qualification_native_source_returns WHERE preregistration_id=$1 AND native_stage='diagnostic_serving_probe' AND return_sha256=$2`, originals[0].pre.PreregistrationID, c.BaselineServingProbeSHA256)
	var diagnostic q.QualificationProbeReceipt
	if capacity.DecodeGuestLifecycle(diagnosticWire, &diagnostic) != nil || diagnostic.OriginalReadStartedAt.Before(failure.RecordedAt) {
		t.Fatal("baseline diagnostic actual useful echo did not follow the failed original")
	}
	var challengeWire []byte
	var consistent bool
	if err := tx.QueryRowContext(ctx, `SELECT original_wire,original_record=convert_from(original_wire,'UTF8')::jsonb AND original_deadline=(original_record->'challenge'->>'original_deadline')::timestamptz FROM public.capacity_guest_qualification_probe_challenges WHERE preregistration_id=$1 AND challenge_sha256=$2 AND usage_class='diagnostic_only'`, originals[0].pre.PreregistrationID, diagnostic.ChallengeSHA256).Scan(&challengeWire, &consistent); err != nil || !consistent {
		t.Fatal("diagnostic challenge was missing or upgraded into capacity phase", err)
	}
	var challenge q.QualificationProbeRequest
	if capacity.DecodeGuestLifecycle(challengeWire, &challenge) != nil || capacity.GuestRetirementSHA(challenge.Challenge) != diagnostic.ChallengeSHA256 || q.ValidateProbeReturn(challenge, diagnostic, enrollments[0].Enrollment, registrationSHAs[0], diagnostic.OriginalNativeAfterReturnedAt) != nil {
		t.Fatal("baseline same original useful writer diagnostic cannot join independently")
	}
	var retirementCount int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_vm_retirement_intents WHERE preregistration_id IN (SELECT id FROM public.capacity_vm_provisioning_preregistrations WHERE preregistration_record->>'policy_id'=$1)`, c.PolicyID).Scan(&retirementCount); err != nil {
		t.Fatal(err)
	}
	if ack {
		failed := c.FailedRetirementAttempt
		if failed == nil || retirementCount != 1 || !guestOriginalNativeUUID(failed.RequestID) || !capacity.ValidDigest(failed.IntentSHA256) || !capacity.ValidDigest(failed.CallerReturnSHA256) {
			t.Fatal("ACK deadline lost its actual original retirement identity")
		}
		var intentWire []byte
		var consistent bool
		if err := tx.QueryRowContext(ctx, `SELECT original_wire,intent_record=convert_from(original_wire,'UTF8')::jsonb->'intent' AND original_deadline=(intent_record->>'original_deadline')::timestamptz AND created_at=(intent_record->>'issued_at')::timestamptz AND id::text=intent_record->>'request_id' AND attempt_id::text=intent_record->>'attempt_id' AND nonce_sha256=intent_record->>'nonce_sha256' FROM public.capacity_vm_retirement_intents WHERE id=$1 AND preregistration_id=$2 AND intent_sha256=$3`, failed.RequestID, originals[1].pre.PreregistrationID, failed.IntentSHA256).Scan(&intentWire, &consistent); err != nil || !consistent {
			t.Fatal("ACK HOLD original intent bytes do not join", err)
		}
		var request model.CapacityGuestRetirementRequest
		if capacity.DecodeGuestLifecycle(intentWire, &request) != nil || request.Nonce != "" || capacity.GuestRetirementSHA(request.Intent) != failed.IntentSHA256 || capacity.GuestRetirementRequest(request, enrollments[1].Enrollment, request.Intent.IssuedAt, false) != nil {
			t.Fatal("ACK HOLD actual intent signature/source tuple diverge")
		}
		retired := repository.GuestRetirementOriginal{Request: request, Receipt: enrollments[1]}
		if request.Intent.PolicyID != c.PolicyID || request.Intent.PolicyChecksum != c.PolicyChecksum || request.Intent.WorkflowID != c.WorkflowID || request.Intent.WorkflowChecksum != c.WorkflowChecksum || request.Intent.OriginalDeadline.Sub(request.Intent.IssuedAt) > 30*time.Second {
			t.Fatal("ACK HOLD retirement adopted another source or renewed its deadline")
		}
		var actualSource, executorID string
		if err := tx.QueryRowContext(ctx, `SELECT core_actual_source_commit,executor_id::text FROM public.capacity_guest_original_retirement_contexts WHERE intent_id=$1`, failed.RequestID).Scan(&actualSource, &executorID); err != nil || actualSource != c.ActualCoreSourceCommit || !guestOriginalNativeUUID(executorID) {
			t.Fatal("ACK HOLD original Core context absent", err)
		}
		if failure.Phase != "original_withdraw_held" || !failure.OriginalOperationDeadline.Equal(retired.Request.Intent.OriginalDeadline) || failure.OriginalWait.OriginalReturnedAt.Before(retired.Request.Intent.OriginalDeadline) || failure.OriginalOutputEOFAndClose.OriginalReturnedAt.Before(retired.Request.Intent.OriginalDeadline) || failure.OriginalWait.ErrorClass != "original_owner_error" {
			t.Fatal("held ACK replaced original withdrawal deadline/owner returns")
		}
		priorEcho := failure.OriginalProbeRead
		var priorEchoReceiptSHA string
		if priorEcho == nil || priorEcho.ErrorClass != "none" || !priorEcho.OriginalReturnedAt.Before(retired.Request.Intent.IssuedAt) {
			t.Fatal("ACK HOLD lost the earlier actual useful echo")
		}
		if err := tx.QueryRowContext(ctx, `SELECT return_sha256 FROM public.capacity_guest_qualification_native_source_returns WHERE preregistration_id=$1 AND native_stage='serving_probe' AND original_record->'writer_probe'->>'original_read_sha256'=$2`, originals[1].pre.PreregistrationID, priorEcho.OriginalBodySHA256).Scan(&priorEchoReceiptSHA); err != nil {
			t.Fatal("ACK diagnostic adopted another probe body", err)
		}
		priorProbe := guestOriginalProbe(t, tx, ctx, originals[1].pre.PreregistrationID, priorEchoReceiptSHA, enrollments[1].Enrollment, registrationSHAs[1])
		priorEchoWire, err := json.Marshal(priorProbe.WriterProbe.OriginalEcho)
		if err != nil || priorEcho.OriginalBodyBytes != len(priorEchoWire) || capacity.BusinessCreationSHA256(priorEchoWire) != priorEcho.OriginalBodySHA256 || priorEcho.OriginalReturnedAt.Before(priorProbe.WriterProbe.OriginalEcho.OriginalReadReturnedAt) || priorEcho.OriginalReturnedAt.After(priorProbe.WriterProbe.OriginalReadReturnedAt) {
			t.Fatal("ACK diagnostic replaced original echo Read bytes/times", err)
		}
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_guest_original_caller_attempts WHERE intent_id=$1 AND attempt_id=$2`, failed.RequestID, retired.Request.Intent.AttemptID).Scan(&count); err != nil || count != 1 {
			t.Fatal("ACK HOLD retried its sole original POST", err)
		}
		callerWire := guestOriginalNativeWire(t, tx, ctx, `SELECT original_wire,return_sha256,original_record=convert_from(original_wire,'UTF8')::jsonb FROM public.capacity_guest_original_caller_returns WHERE intent_id=$1 AND return_sha256=$2`, failed.RequestID, failed.CallerReturnSHA256)
		var caller repository.GuestOriginalCallerReturn
		if capacity.DecodeGuestLifecycle(callerWire, &caller) != nil || caller.RequestID != failed.RequestID || caller.AttemptID != retired.Request.Intent.AttemptID || !caller.OriginalDeadline.Equal(retired.Request.Intent.OriginalDeadline) || caller.StartedAt.Before(retired.Request.Intent.IssuedAt) || caller.PreflightFailed || caller.DoStartedAt.Before(caller.StartedAt) || caller.DoReturnedAt.Before(caller.DoStartedAt) || caller.DriverReturnedAt.Before(caller.DoReturnedAt) || !repository.GuestOriginalCallerBodyFactsValid(caller) || (!caller.DoFailed && (caller.ReadReturnedAt.IsZero() || caller.CloseReturnedAt.IsZero())) || (!caller.ReadReturnedAt.IsZero() && (caller.ReadReturnedAt.Before(caller.DoReturnedAt) || caller.CloseReturnedAt.Before(caller.ReadReturnedAt) || caller.DriverReturnedAt.Before(caller.CloseReturnedAt))) || (!caller.DoFailed && !caller.ReadFailed && !caller.CloseFailed && !caller.OriginalContextFailed && caller.Status == 200) {
			t.Fatal("ACK HOLD replaced its real original caller return metadata")
		}
		rows, err := tx.QueryContext(ctx, `SELECT sequence,original_wire FROM public.capacity_vm_retirement_original_returns WHERE intent_id=$1 ORDER BY sequence`, failed.RequestID)
		if err != nil {
			t.Fatal(err)
		}
		sequence := 0
		var previous model.CapacityGuestRetirementRecord
		for rows.Next() {
			var n int
			var wire []byte
			var observed model.CapacityGuestRetirementObservation
			if err := rows.Scan(&n, &wire); err != nil {
				rows.Close()
				t.Fatal(err)
			}
			if capacity.DecodeGuestLifecycle(wire, &observed) != nil || n != sequence+1 || n > 3 || observed.Record.Sequence != n || !capacity.GuestRetirementObservedReturnAuthentic(observed, retired.Receipt.Enrollment, retired.Request.Intent, observed.ObservedAt) || (sequence > 0 && observed.Record.PreviousSHA256 != capacity.GuestRetirementSHA(previous)) {
				rows.Close()
				t.Fatal("ACK HOLD fabricated a complete/fresh retirement chain")
			}
			previous = observed.Record
			sequence = n
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		if err := rows.Close(); err != nil || sequence < 1 {
			t.Fatal("ACK HOLD lost its original possible-start journal", err)
		}
	} else if c.FailedRetirementAttempt != nil || retirementCount != 0 {
		t.Fatal("pre-retirement HOLD supplied a privileged original retirement")
	}
	for _, forbidden := range []string{
		`SELECT count(*) FROM public.capacity_mutation_grants WHERE grant_record->>'policy_id'=$1 AND grant_record->'grant'->>'capability'='destroy_server'`,
		`SELECT count(*) FROM public.capacity_vm_retirement_delete_bindings d JOIN public.capacity_mutation_grants g ON g.id=d.destroy_grant_id WHERE g.grant_record->>'policy_id'=$1`,
		`SELECT count(*) FROM public.capacity_guest_original_native_poweroff_reads n JOIN public.capacity_vm_retirement_intents r ON r.id=n.intent_id WHERE r.intent_record->>'policy_id'=$1`,
	} {
		if err := tx.QueryRowContext(ctx, forbidden, c.PolicyID).Scan(&count); err != nil || count != 0 {
			t.Fatal("diagnostic acquired retirement/off/DELETE authority", err)
		}
	}
	var live, tombstones int
	expectedLive := 1
	if physicalBurst {
		expectedLive = 2
	}
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FILTER(WHERE resource_id<>''),count(*) FILTER(WHERE resource_id='' OR slot_record->>'tombstone'='true') FROM public.capacity_resource_slots WHERE namespace=$1`, c.Namespace).Scan(&live, &tombstones); err != nil || live != expectedLive || tombstones != 0 {
		t.Fatal("expected HOLD became capacity or a tombstone", err)
	}
	var baselineID, baselineCreated, baselineTombstone string
	if err := tx.QueryRowContext(ctx, `SELECT resource_id,slot_record->>'resource_created_at',slot_record->>'tombstone' FROM public.capacity_resource_slots WHERE namespace=$1 AND integration_instance_id=$2 AND scope_checksum=$3 AND profile_name=$4 AND slot=1`, c.Namespace, originals[0].witness.Tuple.InstanceID, originals[0].witness.Tuple.ScopeChecksum, originals[0].witness.Tuple.Profile).Scan(&baselineID, &baselineCreated, &baselineTombstone); err != nil || baselineID != c.NativeResources[0].ResourceID || baselineCreated != c.NativeResources[0].ResourceCreatedAt || baselineTombstone != "false" {
		t.Fatal("diagnostic adopted baseline capacity from another native original", err)
	}
	if physicalBurst {
		var id, created, tombstone string
		if err := tx.QueryRowContext(ctx, `SELECT resource_id,slot_record->>'resource_created_at',slot_record->>'tombstone' FROM public.capacity_resource_slots WHERE namespace=$1 AND integration_instance_id=$2 AND scope_checksum=$3 AND profile_name=$4 AND slot=2`, c.Namespace, originals[1].witness.Tuple.InstanceID, originals[1].witness.Tuple.ScopeChecksum, originals[1].witness.Tuple.Profile).Scan(&id, &created, &tombstone); err != nil || id != c.NativeResources[1].ResourceID || created != c.NativeResources[1].ResourceCreatedAt || tombstone != "false" {
			t.Fatal("HOLD lost the enrolled original burst or granted tombstone", err)
		}
	}
	expectedApplied := 0
	if physicalBurst {
		expectedApplied = 1
	}
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM public.event_log WHERE idempotency_key=$1`, "capacity-mutation/"+originals[1].pre.OriginalCreateGrantID).Scan(&count); err != nil || count != expectedApplied {
		t.Fatal("source diagnostic changed actual original physical confirmation", err)
	}
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_guest_qualification_native_source_returns WHERE preregistration_id=$1 AND native_stage='serving_probe' AND return_sha256=$2`, originals[0].pre.PreregistrationID, c.BaselineServingProbeSHA256).Scan(&count); err != nil || count != 0 {
		t.Fatal("post-failure diagnostic renewed a capacity-phase source row", err)
	}
}
