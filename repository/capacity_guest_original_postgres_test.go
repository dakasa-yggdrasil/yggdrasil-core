package repository

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
)

func guestOriginalPostgres(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("DB_URL")
	if dsn == "" {
		if os.Getenv("REQUIRE_CAPACITY_POSTGRES") == "true" || os.Getenv("REQUIRE_CAPACITY_GUEST_ORIGINAL_POSTGRES") == "true" {
			t.Fatal("DB_URL required by original Guest PostgreSQL gate")
		}
		t.Skip("original Guest PostgreSQL corpus runs in CI")
	}
	db, err := sql.Open("postgres", dsn)
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

type guestOriginalStorageFixture struct {
	pre                      model.CapacityGuestOriginalProvisioningPreregistration
	binding                  model.CapacityGuestRetirementBinding
	wire, bindingWire        []byte
	intentID, destroyGrantID string
}

// These expired records test PostgreSQL representation, foreign keys and
// immutability only. They have no real provider creation, original writer,
// signed enrollment or permission to destroy, and always roll back. The native
// binary/QEMU corpus is the sole positive owning lifecycle supplier.
func guestOriginalStorageRecords(t *testing.T) guestOriginalStorageFixture {
	t.Helper()
	at := time.Now().Add(-2 * time.Hour).UTC().Truncate(time.Second).Add(123456789 * time.Nanosecond)
	profile := model.CapacityGuestProtectedProfileManifest{Schema: "original_guest_protected_profile_v1", Profile: "storage-only-unqualified", MutationBinding: "storage-only", OriginalProvisioningBudgetSeconds: 60, OriginalProvisioningStepID: "original-source-step", Writers: []model.CapacityGuestProtectedWriterDefinition{}}
	binding := model.CapacityGuestRetirementBinding{ProfileManifest: profile, ProfileManifestSHA256: capacity.GuestRetirementSHA(profile), Members: []model.CapacityGuestRetirementMemberBinding{{Name: "storage-only-member", Slot: 2, ActorClientPrincipal: "storage-only-actor", ProvisionerClientPrincipal: "storage-only-provisioner"}}}
	pre := model.CapacityGuestOriginalProvisioningPreregistration{Schema: capacity.GuestPreregistrationSchema, PreregistrationID: uuid.NewString(), BindingName: binding.Members[0].Name, OriginalCreateGrantID: uuid.NewString(), OriginalCreateRequestSHA256: strings.Repeat("a", 64), NonceSHA256: capacity.BusinessCreationSHA256([]byte(uuid.NewString())), ProfileManifestSHA256: binding.ProfileManifestSHA256, PolicyID: uuid.NewString(), PolicyChecksum: strings.Repeat("b", 64), WorkflowID: uuid.NewString(), WorkflowChecksum: strings.Repeat("c", 64), OriginalWorkflowStepID: profile.OriginalProvisioningStepID, OriginalWorkflowStepTimeoutSeconds: 60, OriginalWorkflowContextDeadline: at.Add(50 * time.Second), CoreSourceCommit: strings.Repeat("d", 40), Generation: 1, Fence: 1, LeaseOwner: uuid.NewString(), ExecutorID: uuid.NewString(), Slot: 2, OriginalDeadline: at.Add(50 * time.Second), ReservedAt: at}
	wire, err := json.Marshal(pre)
	if err != nil {
		t.Fatal(err)
	}
	bindingWire, err := json.Marshal(binding)
	if err != nil {
		t.Fatal(err)
	}
	return guestOriginalStorageFixture{pre: pre, binding: binding, wire: wire, bindingWire: bindingWire, intentID: uuid.NewString(), destroyGrantID: uuid.NewString()}
}

func guestOriginalStorageTx(t *testing.T, db *sql.DB) (*sql.Tx, context.Context) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tx.Rollback(); cancel() })
	return tx, ctx
}

func guestOriginalStorageGrant(t *testing.T, tx *sql.Tx, ctx context.Context, id string) {
	t.Helper()
	_, err := tx.ExecContext(ctx, `INSERT INTO public.capacity_mutation_grants(id,namespace,environment,domain,dimension,generation,integration_instance_id,scope_checksum,profile_name,slot,state,grant_record,expires_at) VALUES($1,$2,'ci-storage','vm','physical_membership',1,$3,$4,'unqualified-storage',2,'settled','{}'::jsonb,$5)`, id, "guest-storage-"+uuid.NewString(), uuid.NewString(), strings.Repeat("a", 64), time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
}

func guestOriginalStoragePre(t *testing.T, tx *sql.Tx, ctx context.Context, f guestOriginalStorageFixture, record []byte, wire any, deadline time.Time) {
	t.Helper()
	guestOriginalStorageGrant(t, tx, ctx, f.pre.OriginalCreateGrantID)
	_, err := tx.ExecContext(ctx, `INSERT INTO public.capacity_vm_provisioning_preregistrations(id,create_grant_id,nonce_sha256,profile_manifest_sha256,preregistration_record,original_deadline,created_at,original_wire,binding_wire) VALUES($1,$2,$3,$4,$5::jsonb,$6,$7,$8,$9)`, f.pre.PreregistrationID, f.pre.OriginalCreateGrantID, f.pre.NonceSHA256, f.pre.ProfileManifestSHA256, string(record), deadline, f.pre.ReservedAt, wire, f.bindingWire)
	if err != nil {
		t.Fatal(err)
	}
}

func guestOriginalStorageChain(t *testing.T, tx *sql.Tx, ctx context.Context, f guestOriginalStorageFixture) {
	t.Helper()
	guestOriginalStoragePre(t, tx, ctx, f, f.wire, f.wire, f.pre.OriginalDeadline)
	guestOriginalStorageGrant(t, tx, ctx, f.destroyGrantID)
	for _, insert := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO public.capacity_vm_original_enrollments(preregistration_id,resource_tuple_sha256,enrollment_sha256,original_provisioning_sha256,enrollment_record,recorded_at) VALUES($1,$2,$3,$4,'{}'::jsonb,$5)`, []any{f.pre.PreregistrationID, capacity.BusinessCreationSHA256([]byte(uuid.NewString())), capacity.BusinessCreationSHA256([]byte(uuid.NewString())), strings.Repeat("e", 64), f.pre.ReservedAt}},
		{`INSERT INTO public.capacity_vm_retirement_intents(id,preregistration_id,attempt_id,nonce_sha256,intent_sha256,intent_record,original_deadline,created_at) VALUES($1,$2,$3,$4,$5,'{}'::jsonb,$6,$7)`, []any{f.intentID, f.pre.PreregistrationID, uuid.NewString(), capacity.BusinessCreationSHA256([]byte(uuid.NewString())), capacity.BusinessCreationSHA256([]byte(uuid.NewString())), f.pre.OriginalDeadline, f.pre.ReservedAt}},
	} {
		if _, err := tx.ExecContext(ctx, insert.query, insert.args...); err != nil {
			t.Fatal(err)
		}
	}
}

func guestOriginalExpectedSQLRefusal(t *testing.T, tx *sql.Tx, ctx context.Context, query string, args ...any) {
	t.Helper()
	if _, err := tx.ExecContext(ctx, `SAVEPOINT original_guest_refusal`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, query, args...); err == nil {
		t.Fatal("permanent original record mutation accepted")
	}
	if _, err := tx.ExecContext(ctx, `ROLLBACK TO SAVEPOINT original_guest_refusal`); err != nil {
		t.Fatal(err)
	}
}

func TestCapacityGuestOriginalPostgres(t *testing.T) {
	db := guestOriginalPostgres(t)
	t.Run("public_observe_redacted_private_lease_exact", func(t *testing.T) {
		// Actual PostgreSQL manifest/intent/lease paths, with no native create,
		// original-source override, provider receipt or seeded successful phase.
		f := mutationPostgresFixture(t, false)
		ctx := context.Background()
		public, err := f.store.Observe(ctx, f.policy)
		if err != nil || public.LeaseOwner != "" || public.LeaseExecutorID != "" || public.Generation != f.intent.Generation || public.FencingToken != f.intent.FencingToken || public.LeaseExpiresAt == nil {
			t.Fatal("public Observe exposed or lost original lease state", err)
		}
		if err := f.store.ValidateNativeObservationLease(ctx, f.policy, f.intent.Generation, f.intent.FencingToken, f.intent.LeaseOwner); err != nil {
			t.Fatal("same private current lease refused", err)
		}
		for _, bad := range []struct {
			owner string
			fence int64
			want  error
		}{{uuid.NewString(), f.intent.FencingToken, ErrCapacityLease}, {f.intent.LeaseOwner, f.intent.FencingToken + 1, ErrCapacityConflict}} {
			if err := f.store.ValidateNativeObservationLease(ctx, f.policy, f.intent.Generation, bad.fence, bad.owner); !errors.Is(err, bad.want) {
				t.Fatal("foreign owner/stale fence gained private lease", err)
			}
		}
		if _, err := f.db.ExecContext(ctx, `UPDATE public.capacity_intents SET intent=jsonb_set(intent,'{lease_expires_at}',to_jsonb($2::text)) WHERE namespace=$1`, f.policy.Metadata.Namespace, time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano)); err != nil {
			t.Fatal(err)
		}
		if err := f.store.ValidateNativeObservationLease(ctx, f.policy, f.intent.Generation, f.intent.FencingToken, f.intent.LeaseOwner); !errors.Is(err, ErrCapacityLease) {
			t.Fatal("expired private lease admitted by public redacted observation", err)
		}
		public, err = f.store.Observe(ctx, f.policy)
		if err != nil || public.LeaseOwner != "" || public.LeaseExecutorID != "" {
			t.Fatal("historical public observation disclosed private owner", err)
		}
	})
	t.Run("claimed_complete_production_roster_registry_hold_before_reservation", func(t *testing.T) {
		tx, ctx := guestOriginalStorageTx(t, db)
		// Syntactically complete operator claims are deliberately NOT real
		// catalog/image/handle originals. All shape/profile/binding predicates
		// pass; the compiled EMPTY production registry is the refusing boundary.
		// This is source-structural negative coverage, never a GoTest supplier.
		source, digest := strings.Repeat("a", 40), strings.Repeat("b", 64)
		profile := model.CapacityGuestProtectedProfileManifest{Schema: capacity.GuestProtectedProfileSchema, Profile: "claimed-production-profile", CoverageClass: "complete_production_roster", ProductionCatalogSHA256: digest, MutationBinding: "claimed-production-binding", BootstrapOwnerSourceCommit: source, BootstrapOwnerBinarySHA256: digest, BootstrapReaderBinarySHA256: digest, BootstrapPayloadSHA256: digest, BootstrapSHA256: digest, OriginalProvisioningBudgetSeconds: 420, OriginalProvisioningStepID: "original-production-create", OwnerSourceCommit: source, OwnerBinarySHA256: digest, OwnerImageDigest: "sha256:" + strings.Repeat("c", 64), ProtectedCgroup: capacity.GuestProtectedCgroup, ActorSourceCommit: source, ActorBinarySHA256: digest, RuntimeClientCommandSHA256: digest, PoweroffCommandSHA256: digest, Writers: []model.CapacityGuestProtectedWriterDefinition{{ID: "claimed-production-writer", SourceCommit: source, BinarySHA256: digest, CommandSHA256: strings.Repeat("d", 64), ImageDigest: "sha256:" + strings.Repeat("e", 64), SourceImageReceiptSHA256: strings.Repeat("f", 64), HandleContractSHA256: strings.Repeat("1", 64), CgroupRelativePath: "claimed-production-writer"}}}
		b := model.CapacityMutationBinding{Name: profile.MutationBinding, ProfileName: profile.Profile, MaxSlots: 1, Slots: []model.CapacityMutationSlotBinding{{Slot: 1, DesiredSpec: &model.CapacityMutationSpecV1{BootstrapSHA256: digest}}}}
		binding := model.CapacityGuestRetirementBinding{Mode: capacity.GuestRetirementSchema, MutationBindingName: b.Name, EvidenceClass: "owned_provisioner_original", ProvisionerSourceCommit: source, GuestSourceCommit: source, CoreAuthoritySourceCommit: source, ProvisionerPublicKey: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)), EnrollmentIssuerPublicKey: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32)), EnrollmentSigningKeyRef: "secret://source/claimed-enrollment#value", IntentSigningKeyRef: "secret://source/claimed-intent#value", ProfileManifest: profile, ProfileManifestSHA256: capacity.GuestRetirementSHA(profile), MaxEvidenceAgeSeconds: 30, Members: []model.CapacityGuestRetirementMemberBinding{{Name: "claimed-member", Slot: 1, Origin: "https://guest.invalid", ServerCARef: "secret://source/claimed-ca#value", ClientCertificateRef: "secret://source/claimed-cert#value", ClientKeyRef: "secret://source/claimed-key#value", ActorClientPrincipal: "claimed-actor", ProvisionerClientPrincipal: "claimed-provisioner"}}}
		p := model.CapacityPolicySpec{MaxEvidenceAgeSeconds: 30, Profiles: []model.CapacityProfile{{Name: profile.Profile, Provider: "fixture"}}, MutationBindings: []model.CapacityMutationBinding{b}, GuestRetirementBinding: &binding}
		if err := capacity.ValidateGuestRetirementBinding(p, &binding); err != nil {
			t.Fatal("negative refused on shape rather than registry", err)
		}
		if p.Profiles[0].Name != binding.ProfileManifest.Profile || p.Profiles[0].Provider != "fixture" || binding.ProfileManifestSHA256 != capacity.GuestRetirementSHA(binding.ProfileManifest) {
			t.Fatal("registry test lost the matching approved policy/profile shape")
		}
		if capacity.GuestOriginalProfileEnabled(p, binding, "fixture") {
			t.Fatal("claimed catalog/OCI/source-image/handle hashes approved production")
		}
		grantID, namespace := uuid.NewString(), "guest-registry-hold-"+uuid.NewString()
		policy := model.Manifest{ID: uuid.New(), Metadata: model.ManifestMetadata{Namespace: namespace}}
		record := capacityMutationRecord{Grant: model.CapacityMutationGrant{GrantID: grantID, Slot: 1}, Binding: b, EventProvider: "fixture"}
		// Registry is checked BEFORE the private source-origin/VCS predicate,
		// workflow reads, prereg INSERT and grant COMMIT. No source is spoofed.
		if err := (CapacityStore{DB: db}).reserveGuestOriginalTx(ctx, tx, policy, p, model.CapacityIntent{}, record, time.Now().UTC()); !errors.Is(err, ErrCapacityConflict) {
			t.Fatal("compiled registry did not HOLD before reservation", err)
		}
		var prereg, grants int
		if err := tx.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM public.capacity_vm_provisioning_preregistrations WHERE create_grant_id=$1),(SELECT count(*) FROM public.capacity_mutation_grants WHERE id=$1)`, grantID).Scan(&prereg, &grants); err != nil || prereg != 0 || grants != 0 {
			t.Fatal("registry refusal created original prereg/grant", prereg, grants, err)
		}
		// No provider interface is called by this transaction seam. Its early
		// source refusal is not an observed native send-count or lifecycle pass.
	})
	t.Run("canonical_bytes_survive_native_timestamp_representation", func(t *testing.T) {
		tx, ctx := guestOriginalStorageTx(t, db)
		f := guestOriginalStorageRecords(t)
		guestOriginalStoragePre(t, tx, ctx, f, f.wire, f.wire, f.pre.OriginalDeadline)
		stored, err := loadGuestOriginalTx(ctx, tx, f.pre.PreregistrationID)
		if err != nil || !stored.pre.ReservedAt.Equal(f.pre.ReservedAt) || !stored.pre.OriginalDeadline.Equal(f.pre.OriginalDeadline) {
			t.Fatalf("canonical timestamp bytes lost: %+v %v", stored.pre, err)
		}
		var raw []byte
		var native time.Time
		var castMatches bool
		if err := tx.QueryRowContext(ctx, `SELECT original_wire,original_deadline,original_deadline=(preregistration_record->>'original_deadline')::timestamptz FROM public.capacity_vm_provisioning_preregistrations WHERE id=$1`, f.pre.PreregistrationID).Scan(&raw, &native, &castMatches); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(raw, f.wire) || native.Equal(f.pre.OriginalDeadline) || !castMatches {
			t.Fatal("canonical BYTEA was replaced by native microseconds or PG cast no longer joins")
		}
		if capacity.GuestOriginalProfileEnabled(model.CapacityPolicySpec{}, stored.binding, "native-qemu") {
			t.Fatal("storage representation became execution authority")
		}
	})
	for _, name := range []string{"legacy_missing_bytes", "jsonb_differs_from_original_bytes", "native_deadline_differs_from_original", "profile_hash_not_original", "binding_bytes_missing"} {
		t.Run(name, func(t *testing.T) {
			tx, ctx := guestOriginalStorageTx(t, db)
			f := guestOriginalStorageRecords(t)
			record := append([]byte(nil), f.wire...)
			var wire any = f.wire
			deadline := f.pre.OriginalDeadline
			switch name {
			case "legacy_missing_bytes":
				wire = nil
			case "jsonb_differs_from_original_bytes":
				different := f.pre
				different.ExecutorID = uuid.NewString()
				record, _ = json.Marshal(different)
			case "native_deadline_differs_from_original":
				deadline = deadline.Add(time.Second)
			case "profile_hash_not_original":
				different := f.pre
				different.ProfileManifestSHA256 = strings.Repeat("f", 64)
				record, _ = json.Marshal(different)
				wire = record
			case "binding_bytes_missing":
				f.bindingWire = nil
			}
			guestOriginalStoragePre(t, tx, ctx, f, record, wire, deadline)
			if _, err := loadGuestOriginalTx(ctx, tx, f.pre.PreregistrationID); err == nil {
				t.Fatal("missing or inconsistent original bytes adopted")
			}
			var count int
			if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_vm_provisioning_preregistrations WHERE id=$1`, f.pre.PreregistrationID).Scan(&count); err != nil || count != 1 {
				t.Fatal("HOLD removed original reservation", err)
			}
		})
	}
	for _, name := range []string{"legacy_enrollment_without_receipt", "provider_off_without_original_guest_joins", "failed_create_without_never_started_producer"} {
		t.Run(name, func(t *testing.T) {
			tx, ctx := guestOriginalStorageTx(t, db)
			f := guestOriginalStorageRecords(t)
			guestOriginalStorageChain(t, tx, ctx, f)
			s := CapacityStore{DB: db}
			var err error
			switch name {
			case "legacy_enrollment_without_receipt":
				_, _, err = loadGuestReceiptTx(ctx, tx, f.pre.PreregistrationID)
			case "provider_off_without_original_guest_joins":
				wire := []byte(`{"server":{"status":"off"},"physical_capacity_released":true}`)
				if _, insertErr := tx.ExecContext(ctx, `INSERT INTO public.capacity_vm_retirement_native_readbacks(id,destroy_grant_id,observation_sha256,original_observation_record,original_wire,recorded_at) VALUES($1,$2,$3,$4::jsonb,$5,$6)`, uuid.NewString(), f.destroyGrantID, capacity.BusinessCreationSHA256(wire), string(wire), wire, f.pre.ReservedAt); insertErr != nil {
					t.Fatal(insertErr)
				}
				err = s.guestConfirmedDestroyTx(ctx, tx, model.CapacityPolicySpec{}, capacityMutationRecord{Grant: model.CapacityMutationGrant{GrantID: f.destroyGrantID}}, model.CapacityMutationProof{OwnerVerified: true, SpecVerified: true}, time.Now())
			case "failed_create_without_never_started_producer":
				err = s.guestFailedCreateCleanupTx(ctx, tx, model.CapacityPolicySpec{}, capacityMutationRecord{Grant: model.CapacityMutationGrant{GrantID: f.pre.OriginalCreateGrantID}}, model.CapacityMutationProof{OwnerVerified: true, SpecVerified: true}, time.Now(), "")
			}
			if err == nil {
				t.Fatal("missing original Guest result freed or adopted lifecycle")
			}
			var state string
			if err := tx.QueryRowContext(ctx, `SELECT state FROM public.capacity_mutation_grants WHERE id=$1`, f.destroyGrantID).Scan(&state); err != nil || state != "settled" {
				t.Fatal("negative read changed owning mutation", state, err)
			}
			var count int
			if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_vm_original_enrollments WHERE preregistration_id=$1`, f.pre.PreregistrationID).Scan(&count); err != nil || count != 1 {
				t.Fatal("unknown enrollment was deleted", err)
			}
		})
	}
	t.Run("native_tuple_uses_resource_created_at", func(t *testing.T) {
		tx, ctx := guestOriginalStorageTx(t, db)
		tuple := model.CapacityGuestNativeTuple{ResourceID: "native-storage-identity", CreatedAt: "2026-10-13T01:02:03.123456789Z"}
		wire, err := json.Marshal(tuple)
		if err != nil {
			t.Fatal(err)
		}
		var resource, originalCreated string
		var alias sql.NullString
		if err := tx.QueryRowContext(ctx, `SELECT j->>'resource_id',j->>'resource_created_at',j->>'created_at' FROM (SELECT convert_from($1::bytea,'UTF8')::jsonb AS j) original`, wire).Scan(&resource, &originalCreated, &alias); err != nil {
			t.Fatal(err)
		}
		if resource != tuple.ResourceID || originalCreated != tuple.CreatedAt || alias.Valid {
			t.Fatal("native creation tuple alias lost exact original identity")
		}
		// This is a storage selector check, never a declaration of an original
		// create or proof of quiescence. Wrong created identity cannot match.
		for _, candidate := range []string{tuple.CreatedAt, "2026-10-13T01:02:03.123456Z", "2026-10-13T01:02:04.123456789Z"} {
			var matches bool
			if err := tx.QueryRowContext(ctx, `SELECT convert_from($1::bytea,'UTF8')::jsonb->>'resource_created_at'=$2`, wire, candidate).Scan(&matches); err != nil {
				t.Fatal(err)
			}
			if matches != (candidate == tuple.CreatedAt) {
				t.Fatal("resource tuple was rounded or rewritten")
			}
		}
	})
	t.Run("before_start_challenges_have_independent_original_identity", func(t *testing.T) {
		tx, ctx := guestOriginalStorageTx(t, db)
		f := guestOriginalStorageRecords(t)
		guestOriginalStorageChain(t, tx, ctx, f)
		for ordinal := 1; ordinal <= 2; ordinal++ {
			challenge := model.CapacityGuestRuntimeSnapshotChallenge{ChallengeID: uuid.NewString(), IssuedAt: f.pre.ReservedAt.Add(time.Duration(ordinal) * time.Second), OriginalDeadline: f.pre.ReservedAt.Add(20 * time.Second)}
			wire, err := json.Marshal(challenge)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO public.capacity_guest_runtime_snapshot_challenges(id,intent_id,phase,ordinal,challenge_sha256,original_wire,original_record,original_deadline,recorded_at) VALUES($1,$2,'before_start',$3,$4,$5,$6::jsonb,$7,$8)`, challenge.ChallengeID, f.intentID, ordinal, capacity.GuestRetirementSHA(challenge), wire, string(wire), challenge.OriginalDeadline, challenge.IssuedAt); err != nil {
				t.Fatal(err)
			}
		}
		var identities int
		if err := tx.QueryRowContext(ctx, `SELECT count(DISTINCT id) FROM public.capacity_guest_runtime_snapshot_challenges WHERE intent_id=$1 AND phase='before_start'`, f.intentID).Scan(&identities); err != nil || identities != 2 {
			t.Fatal("before_start read reuses prior original challenge", err)
		}
		guestOriginalExpectedSQLRefusal(t, tx, ctx, `INSERT INTO public.capacity_guest_runtime_snapshot_challenges SELECT $1::uuid,intent_id,phase,ordinal,$2,original_wire,original_record,original_deadline,recorded_at FROM public.capacity_guest_runtime_snapshot_challenges WHERE intent_id=$3 AND ordinal=1`, uuid.NewString(), capacity.BusinessCreationSHA256([]byte(uuid.NewString())), f.intentID)
	})
	t.Run("possible_send_is_permanent_after_deadline", func(t *testing.T) {
		tx, ctx := guestOriginalStorageTx(t, db)
		f := guestOriginalStorageRecords(t)
		guestOriginalStorageChain(t, tx, ctx, f)
		attempt := uuid.NewString()
		digest := capacity.BusinessCreationSHA256([]byte(uuid.NewString()))
		if _, err := tx.ExecContext(ctx, `INSERT INTO public.capacity_guest_original_caller_attempts(intent_id,attempt_id,request_sha256,principal_id,possible_send_at,original_deadline) VALUES($1,$2,$3,'storage-only-actor',$4,$5)`, f.intentID, attempt, digest, f.pre.ReservedAt, f.pre.OriginalDeadline); err != nil {
			t.Fatal(err)
		}
		guestOriginalExpectedSQLRefusal(t, tx, ctx, `UPDATE public.capacity_guest_original_caller_attempts SET original_deadline=clock_timestamp()+interval '1 hour' WHERE intent_id=$1`, f.intentID)
		guestOriginalExpectedSQLRefusal(t, tx, ctx, `DELETE FROM public.capacity_guest_original_caller_attempts WHERE intent_id=$1`, f.intentID)
		guestOriginalExpectedSQLRefusal(t, tx, ctx, `INSERT INTO public.capacity_guest_original_caller_attempts(intent_id,attempt_id,request_sha256,principal_id,possible_send_at,original_deadline) VALUES($1,$2,$3,'replacement-actor',clock_timestamp(),clock_timestamp()+interval '1 hour')`, f.intentID, uuid.NewString(), capacity.BusinessCreationSHA256([]byte(uuid.NewString())))
		var stored string
		if err := tx.QueryRowContext(ctx, `SELECT attempt_id::text FROM public.capacity_guest_original_caller_attempts WHERE intent_id=$1`, f.intentID).Scan(&stored); err != nil || stored != attempt {
			t.Fatal("late recovery adopted original caller", err)
		}
	})
	t.Run("scoped_original_tables_keep_immutable_triggers", func(t *testing.T) {
		tx, ctx := guestOriginalStorageTx(t, db)
		for _, table := range []string{"capacity_vm_provisioning_preregistrations", "capacity_vm_original_enrollments", "capacity_vm_retirement_intents", "capacity_vm_retirement_original_returns", "capacity_vm_retirement_delete_bindings", "capacity_vm_retirement_native_readbacks", "capacity_guest_original_create_witnesses", "capacity_guest_runtime_snapshot_challenges", "capacity_guest_runtime_snapshot_returns", "capacity_guest_original_caller_attempts", "capacity_guest_original_caller_returns", "capacity_guest_original_authority_reads", "capacity_guest_original_authority_returns", "capacity_guest_original_native_poweroff_reads", "capacity_guest_original_retirement_contexts", "capacity_guest_original_authority_transport_returns", "capacity_guest_qualification_probe_challenges", "capacity_guest_qualification_native_source_returns"} {
			var active int
			if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM pg_trigger WHERE tgrelid=('public.'||$1)::regclass AND tgname=$1||'_immutable' AND tgenabled='O' AND NOT tgisinternal AND tgfoid='public.capacity_vm_original_retirement_immutable'::regproc`, table).Scan(&active); err != nil || active != 1 {
				t.Fatalf("immutable trigger missing: %s: %d %v", table, active, err)
			}
		}
		f := guestOriginalStorageRecords(t)
		guestOriginalStorageChain(t, tx, ctx, f)
		for _, item := range []struct{ table, column, key, id string }{{"capacity_vm_provisioning_preregistrations", "original_deadline", "id", f.pre.PreregistrationID}, {"capacity_vm_original_enrollments", "recorded_at", "preregistration_id", f.pre.PreregistrationID}, {"capacity_vm_retirement_intents", "original_deadline", "id", f.intentID}} {
			guestOriginalExpectedSQLRefusal(t, tx, ctx, fmt.Sprintf("UPDATE public.%s SET %s=%s WHERE %s=$1", item.table, item.column, item.column, item.key), item.id)
			guestOriginalExpectedSQLRefusal(t, tx, ctx, fmt.Sprintf("DELETE FROM public.%s WHERE %s=$1", item.table, item.key), item.id)
		}
	})
	t.Run("unknown_original_is_not_a_retry_identity", func(t *testing.T) {
		tx, ctx := guestOriginalStorageTx(t, db)
		f := guestOriginalStorageRecords(t)
		guestOriginalStoragePre(t, tx, ctx, f, f.wire, f.wire, f.pre.OriginalDeadline)
		stored, err := loadGuestOriginalTx(ctx, tx, f.pre.PreregistrationID)
		if err != nil {
			t.Fatal(err)
		}
		if err := loadGuestWitnessTx(ctx, tx, &stored); !errors.Is(err, sql.ErrNoRows) {
			t.Fatalf("absence of native witness did not stay unresolved: %v", err)
		}
		var receipts, witnesses int
		if err := tx.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM public.capacity_vm_original_enrollments WHERE preregistration_id=$1),(SELECT count(*) FROM public.capacity_guest_original_create_witnesses WHERE preregistration_id=$1)`, f.pre.PreregistrationID).Scan(&receipts, &witnesses); err != nil || receipts != 0 || witnesses != 0 {
			t.Fatal("readback minted enrollment or native identity", err)
		}
		guestOriginalExpectedSQLRefusal(t, tx, ctx, `INSERT INTO public.capacity_vm_provisioning_preregistrations(id,create_grant_id,nonce_sha256,profile_manifest_sha256,preregistration_record,original_deadline,created_at) VALUES($1,$2,$3,$4,'{}'::jsonb,clock_timestamp()+interval '1 hour',clock_timestamp())`, uuid.NewString(), f.pre.OriginalCreateGrantID, capacity.BusinessCreationSHA256([]byte(uuid.NewString())), f.pre.ProfileManifestSHA256)
	})
}
