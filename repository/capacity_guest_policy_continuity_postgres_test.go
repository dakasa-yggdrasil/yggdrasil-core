package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// ADR-0094 on real migrated PostgreSQL: an installed Guest member enrolled
// under version N of a capacity_policy is still found under version N+1 when
// the Guest production contract is byte-identical, and refused when the
// contract changed (directly or in an intermediate version), when the
// enrollment belongs to another policy name, a newer version, a checksum that
// is not the stored one, or when the current version is not active. Rows are
// written with session_replication_role=replica inside one rolled-back
// transaction, which skips only FK parents (no grant, signed enrollment,
// witness or installation is fabricated) and the synthetic contract is never
// in the compiled production registry. This exercises the production lookup
// and continuity queries only and grants no Guest or provider authority.
func TestGuestPolicyContinuityPostgres(t *testing.T) {
	required := os.Getenv("REQUIRE_GUEST_NOTIFY_CANARY_DB_TEST") == "true"
	dsn := os.Getenv("DB_URL")
	if dsn == "" {
		if required {
			t.Fatal("required Guest canary DB_URL absent")
		}
		t.Skip("DB_URL absent; no PostgreSQL coverage claimed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SET LOCAL session_replication_role = replica`); err != nil {
		t.Fatal("continuity fixture needs a superuser CI database", err)
	}

	base, _, _ := enrolledRegistryFixture(t)
	base.Environment, base.Domain, base.Dimension = "production", "notify", "aws-vm-members"
	base.Workflow = model.ManifestSelector{Namespace: "dakasa-production", Name: "original-guest-reconcile"}
	base.MinSamples = 61
	base.Signals = []model.CapacitySignalRule{{Name: "handlers", SourceIdentity: "prometheus/notify", Unit: "handlers", UpAbove: 3, DownBelow: 0.25}}
	clone := func(t *testing.T, p model.CapacityPolicySpec) model.CapacityPolicySpec {
		t.Helper()
		raw, e := json.Marshal(p)
		if e != nil {
			t.Fatal(e)
		}
		var out model.CapacityPolicySpec
		if e = json.Unmarshal(raw, &out); e != nil {
			t.Fatal(e)
		}
		return out
	}
	if !capacity.ValidDigest(capacity.GuestPolicyContinuitySHA256(base)) {
		t.Fatal("synthetic contract has no continuity digest")
	}
	// Version N+1 changes only what the production republish changes.
	retuned := func(t *testing.T) model.CapacityPolicySpec {
		p := clone(t, base)
		p.MinSamples = 60
		p.Signals[0].UpAbove, p.Signals[0].DownBelow = -1, -2
		return p
	}
	changed := func(t *testing.T) model.CapacityPolicySpec {
		p := clone(t, base)
		p.GuestRetirementBinding.Members[0].Origin = "https://other.invalid"
		return p
	}
	policy := func(t *testing.T, ns, name string, version int, spec model.CapacityPolicySpec, active bool) model.Manifest {
		t.Helper()
		raw, e := json.Marshal(spec)
		if e != nil {
			t.Fatal(e)
		}
		m := model.Manifest{ID: uuid.New(), Kind: "capacity_policy", Version: version, Checksum: capacity.BusinessCreationSHA256([]byte(uuid.NewString())), Metadata: model.ManifestMetadata{Namespace: ns, Name: name}, Spec: raw}
		if _, e = tx.ExecContext(ctx, `INSERT INTO public.manifests(id,api_version,kind,namespace,name,version,checksum,spec,active) VALUES($1,'v1','capacity_policy',$2,$3,$4,$5,$6::jsonb,$7)`, m.ID, ns, name, version, m.Checksum, string(raw), active); e != nil {
			t.Fatal("policy fixture refused", e)
		}
		return m
	}
	type member struct{ pre, resource, created string }
	enroll := func(t *testing.T, under model.Manifest, checksum string, resource, created string) member {
		t.Helper()
		at := time.Now().Add(-2 * time.Hour).UTC().Truncate(time.Second)
		pre := model.CapacityGuestOriginalProvisioningPreregistration{Schema: capacity.GuestPreregistrationSchema, PreregistrationID: uuid.NewString(), BindingName: "synthetic-member", OriginalCreateGrantID: uuid.NewString(), OriginalCreateRequestSHA256: strings.Repeat("a", 64), NonceSHA256: capacity.BusinessCreationSHA256([]byte(uuid.NewString())), ProfileManifestSHA256: base.GuestRetirementBinding.ProfileManifestSHA256, PolicyID: under.ID.String(), PolicyChecksum: checksum, WorkflowID: uuid.NewString(), WorkflowChecksum: strings.Repeat("c", 64), Slot: 1, Generation: 1, Fence: 1, LeaseOwner: uuid.NewString(), ExecutorID: uuid.NewString(), OriginalDeadline: at.Add(time.Minute), ReservedAt: at}
		wire, e := json.Marshal(pre)
		if e != nil {
			t.Fatal(e)
		}
		bindingWire, e := json.Marshal(base.GuestRetirementBinding)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = tx.ExecContext(ctx, `INSERT INTO public.capacity_vm_provisioning_preregistrations(id,create_grant_id,nonce_sha256,profile_manifest_sha256,preregistration_record,original_deadline,created_at,original_wire,binding_wire) VALUES($1,$2,$3,$4,$5::jsonb,$6,$7,$8,$9)`, pre.PreregistrationID, pre.OriginalCreateGrantID, pre.NonceSHA256, pre.ProfileManifestSHA256, string(wire), pre.OriginalDeadline, pre.ReservedAt, wire, bindingWire); e != nil {
			t.Fatal("preregistration fixture refused", e)
		}
		record, e := json.Marshal(map[string]any{"statement": map[string]any{"tuple": map[string]any{"slot": 1, "resource_id": resource, "resource_created_at": created}}})
		if e != nil {
			t.Fatal(e)
		}
		if _, e = tx.ExecContext(ctx, `INSERT INTO public.capacity_vm_original_enrollments(preregistration_id,resource_tuple_sha256,enrollment_sha256,original_provisioning_sha256,enrollment_record,recorded_at) VALUES($1,$2,$3,$4,$5::jsonb,$6)`, pre.PreregistrationID, capacity.BusinessCreationSHA256([]byte(uuid.NewString())), capacity.BusinessCreationSHA256([]byte(uuid.NewString())), strings.Repeat("e", 64), string(record), at); e != nil {
			t.Fatal("enrollment fixture refused", e)
		}
		return member{pre.PreregistrationID, resource, created}
	}
	lookup := func(t *testing.T, current model.Manifest, m member) (string, error) {
		t.Helper()
		var p model.CapacityPolicySpec
		if e := json.Unmarshal(current.Spec, &p); e != nil {
			t.Fatal(e)
		}
		return guestMemberPreregistrationTx(ctx, tx, current, p, 1, m.resource, m.created)
	}
	continuity := func(t *testing.T, current model.Manifest, prior model.Manifest) error {
		t.Helper()
		var p model.CapacityPolicySpec
		if e := json.Unmarshal(current.Spec, &p); e != nil {
			t.Fatal(e)
		}
		return guestPolicyContinuityTx(ctx, tx, current, p, prior.ID.String(), prior.Checksum)
	}
	resource := func() (string, string) {
		return "i-" + strings.ReplaceAll(uuid.NewString(), "-", "")[:17], time.Now().Add(-24 * time.Hour).UTC().Format(time.RFC3339)
	}
	conflict := func(t *testing.T, err error, what string) {
		t.Helper()
		if !errors.Is(err, ErrCapacityConflict) {
			t.Fatalf("%s: want ErrCapacityConflict, got %v", what, err)
		}
	}
	scope := func() string { return "policy-continuity-" + uuid.NewString() }

	t.Run("same_revision_is_found", func(t *testing.T) {
		ns := scope()
		v1 := policy(t, ns, "notify-aws-elastic-capacity", 1, base, true)
		id, rid := resource()
		m := enroll(t, v1, v1.Checksum, id, rid)
		if got, err := lookup(t, v1, m); err != nil || got != m.pre {
			t.Fatal("same-revision member lost", got, err)
		}
	})
	t.Run("prior_version_with_identical_contract_is_found", func(t *testing.T) {
		ns := scope()
		v1 := policy(t, ns, "notify-aws-elastic-capacity", 1, base, false)
		v2 := policy(t, ns, "notify-aws-elastic-capacity", 2, retuned(t), true)
		id, rid := resource()
		m := enroll(t, v1, v1.Checksum, id, rid)
		if got, err := lookup(t, v2, m); err != nil || got != m.pre {
			t.Fatal("member enrolled under version N stranded under version N+1", got, err)
		}
		if err := continuity(t, v2, v1); err != nil {
			t.Fatal("continuity refused an identical contract", err)
		}
	})
	t.Run("several_identical_versions_keep_the_member", func(t *testing.T) {
		ns := scope()
		v1 := policy(t, ns, "notify-aws-elastic-capacity", 1, base, false)
		policy(t, ns, "notify-aws-elastic-capacity", 2, retuned(t), false)
		v3 := policy(t, ns, "notify-aws-elastic-capacity", 3, base, true)
		id, rid := resource()
		m := enroll(t, v1, v1.Checksum, id, rid)
		if got, err := lookup(t, v3, m); err != nil || got != m.pre {
			t.Fatal("member lost across identical intermediate versions", got, err)
		}
	})
	t.Run("changed_contract_is_refused", func(t *testing.T) {
		ns := scope()
		v1 := policy(t, ns, "notify-aws-elastic-capacity", 1, base, false)
		v2 := policy(t, ns, "notify-aws-elastic-capacity", 2, changed(t), true)
		id, rid := resource()
		m := enroll(t, v1, v1.Checksum, id, rid)
		_, err := lookup(t, v2, m)
		conflict(t, err, "changed Guest contract")
		conflict(t, continuity(t, v2, v1), "changed Guest contract continuity")
	})
	t.Run("changed_intermediate_contract_is_refused", func(t *testing.T) {
		ns := scope()
		v1 := policy(t, ns, "notify-aws-elastic-capacity", 1, base, false)
		policy(t, ns, "notify-aws-elastic-capacity", 2, changed(t), false)
		v3 := policy(t, ns, "notify-aws-elastic-capacity", 3, base, true)
		id, rid := resource()
		m := enroll(t, v1, v1.Checksum, id, rid)
		_, err := lookup(t, v3, m)
		conflict(t, err, "contract changed in an intermediate version")
	})
	t.Run("other_policy_name_is_refused", func(t *testing.T) {
		ns := scope()
		other := policy(t, ns, "notify-hetzner-elastic-capacity", 1, base, true)
		current := policy(t, ns, "notify-aws-elastic-capacity", 2, base, true)
		id, rid := resource()
		m := enroll(t, other, other.Checksum, id, rid)
		if _, err := lookup(t, current, m); !errors.Is(err, sql.ErrNoRows) {
			t.Fatal("another policy's member was adopted", err)
		}
		conflict(t, continuity(t, current, other), "other policy name continuity")
	})
	t.Run("other_namespace_is_refused", func(t *testing.T) {
		other := policy(t, scope(), "notify-aws-elastic-capacity", 1, base, false)
		current := policy(t, scope(), "notify-aws-elastic-capacity", 2, base, true)
		id, rid := resource()
		m := enroll(t, other, other.Checksum, id, rid)
		if _, err := lookup(t, current, m); !errors.Is(err, sql.ErrNoRows) {
			t.Fatal("another namespace's member was adopted", err)
		}
		conflict(t, continuity(t, current, other), "other namespace continuity")
	})
	t.Run("newer_version_is_refused", func(t *testing.T) {
		ns := scope()
		v1 := policy(t, ns, "notify-aws-elastic-capacity", 1, base, true)
		v2 := policy(t, ns, "notify-aws-elastic-capacity", 2, retuned(t), false)
		id, rid := resource()
		m := enroll(t, v2, v2.Checksum, id, rid)
		_, err := lookup(t, v1, m)
		conflict(t, err, "member of a newer version")
	})
	t.Run("inactive_current_is_refused", func(t *testing.T) {
		ns := scope()
		v1 := policy(t, ns, "notify-aws-elastic-capacity", 1, base, false)
		v2 := policy(t, ns, "notify-aws-elastic-capacity", 2, retuned(t), false)
		id, rid := resource()
		m := enroll(t, v1, v1.Checksum, id, rid)
		_, err := lookup(t, v2, m)
		conflict(t, err, "inactive current version")
	})
	t.Run("unstored_prior_checksum_is_refused", func(t *testing.T) {
		ns := scope()
		v1 := policy(t, ns, "notify-aws-elastic-capacity", 1, base, false)
		v2 := policy(t, ns, "notify-aws-elastic-capacity", 2, retuned(t), true)
		id, rid := resource()
		m := enroll(t, v1, strings.Repeat("f", 64), id, rid)
		if _, err := lookup(t, v2, m); !errors.Is(err, sql.ErrNoRows) {
			t.Fatal("an enrollment whose policy checksum is not stored was adopted", err)
		}
		forged := v1
		forged.Checksum = strings.Repeat("f", 64)
		conflict(t, continuity(t, v2, forged), "forged prior checksum")
	})
	t.Run("ambiguous_tuple_is_refused", func(t *testing.T) {
		ns := scope()
		v1 := policy(t, ns, "notify-aws-elastic-capacity", 1, base, false)
		v2 := policy(t, ns, "notify-aws-elastic-capacity", 2, retuned(t), true)
		id, rid := resource()
		enroll(t, v1, v1.Checksum, id, rid)
		m := enroll(t, v2, v2.Checksum, id, rid)
		_, err := lookup(t, v2, m)
		conflict(t, err, "two enrollments of one native tuple")
	})
}

// The stable-epoch carry-over matches only the exact admitted prior revision.
func TestGuestStableEpochPolicyAdmitsOnlyTheAdmittedRevision(t *testing.T) {
	prior := uuid.New()
	admitted := guestStableEpochPolicy{id: prior.String(), checksum: strings.Repeat("a", 64)}
	if !admitted.admits(model.CapacityIntent{PolicyID: prior, PolicyChecksum: strings.Repeat("a", 64)}) {
		t.Fatal("admitted prior revision refused")
	}
	for name, intent := range map[string]model.CapacityIntent{
		"other_id":       {PolicyID: uuid.New(), PolicyChecksum: strings.Repeat("a", 64)},
		"other_checksum": {PolicyID: prior, PolicyChecksum: strings.Repeat("b", 64)},
	} {
		if admitted.admits(intent) {
			t.Fatal(name, "admitted")
		}
	}
	if (guestStableEpochPolicy{}).admits(model.CapacityIntent{}) {
		t.Fatal("empty continuity admitted an intent")
	}
}
