package repository

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/contactphone"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/cryptoenvelope"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
)

func TestDeclaredPhoneLegacyProjectionPostgres(t *testing.T) {
	db := phoneDirectoryPostgres(t)
	t.Setenv(contactphone.EnrollmentPolicyEnv, "false")
	c := phoneFixture(t, db, false)
	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal("legacy projection transaction failed")
	}
	defer func() { _ = tx.Rollback() }()
	// Model metadata admitted before53 without changing any real contact.
	if _, err := tx.Exec(`DROP TRIGGER collaborators_phone_requirement ON public.collaborators`); err != nil {
		t.Fatal("legacy fixture trigger preparation failed")
	}
	if _, err := tx.Exec(`UPDATE collaborators SET metadata='{"_yggdrasil_phone_profile_required":true,"fixture":"retained"}'::jsonb WHERE id=$1`, c.ID); err != nil {
		t.Fatal("legacy metadata fixture failed")
	}
	_, source, _, _ := runtime.Caller(0)
	full, err := os.ReadFile(filepath.Join(filepath.Dir(source), "../db/migrations/00053_declared_phone_contacts.sql"))
	if err != nil {
		t.Fatal("canonical migration source unavailable")
	}
	up := strings.Split(string(full), "-- +goose Down")[0]
	if _, err := tx.Exec(up); err != nil {
		t.Fatal("canonical migration replay failed")
	}
	if tx.Commit() != nil {
		t.Fatal("migration projection did not commit")
	}
	observed, err := GetCollaborator(context.Background(), db, c.ID.String())
	if err != nil || observed.PhoneProfileRequired || observed.Metadata["fixture"] != "retained" {
		t.Fatal("legacy metadata collision created a retrospective requirement or changed unrelated metadata")
	}
	if _, found := observed.Metadata[phoneRequirementProjectionKey]; found {
		t.Fatal("private projection escaped the collaborator response")
	}
	if _, err := db.Exec(`UPDATE collaborators SET phone_profile_required=TRUE,metadata='{"_yggdrasil_phone_profile_required":false}'::jsonb WHERE id=$1`, c.ID); err != nil {
		t.Fatal("pending projection fixture failed")
	}
	observed, err = GetCollaborator(context.Background(), db, c.ID.String())
	if err != nil || !observed.PhoneProfileRequired {
		t.Fatal("generic metadata downgraded authoritative pending state")
	}
}

func phoneDirectoryPostgres(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("DB_URL")
	if dsn == "" {
		if os.Getenv("REQUIRE_DIRECTORY_CONTACT_POSTGRES") == "true" {
			t.Fatal("mandatory directory/contact PostgreSQL gate lacks DB_URL")
		}
		t.Skip("PostgreSQL runs in CI")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal("PostgreSQL connection unavailable")
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.PingContext(context.Background()); err != nil {
		t.Fatal("PostgreSQL connection unavailable")
	}
	return db
}

func phoneFixture(t *testing.T, db *sql.DB, provisional bool) model.Collaborator {
	t.Helper()
	id := uuid.NewString()
	c, err := CreateCollaborator(context.Background(), db, model.CreateCollaboratorRequest{Slug: "phone-ci-" + id, DisplayName: "Contact CI", PrimaryEmail: id + "@example.test", ProvisionalPhone: provisional})
	if err != nil {
		t.Fatal("fixture creation failed")
	}
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM public.collaborators WHERE id=$1`, c.ID) })
	return c
}

func TestDeclaredPhoneAuthorityPostgres(t *testing.T) {
	db := phoneDirectoryPostgres(t)
	ctx := context.Background()
	t.Setenv(contactphone.EnrollmentPolicyEnv, "true")
	t.Setenv("YGGDRASIL_AUTH_KEK_BASE64", base64.StdEncoding.EncodeToString([]byte(strings.Repeat("k", 32))))
	var countBefore, countAfter int
	_ = db.QueryRow(`SELECT count(*) FROM public.collaborators`).Scan(&countBefore)
	if _, err := CreateCollaborator(ctx, db, model.CreateCollaboratorRequest{Slug: "phone-ci-refused", DisplayName: "Refused CI"}); !errors.Is(err, ErrPhoneRequired) {
		t.Fatal("human creation without phone did not fail")
	}
	_ = db.QueryRow(`SELECT count(*) FROM public.collaborators`).Scan(&countAfter)
	if countBefore != countAfter {
		t.Fatal("refused enrollment left a collaborator")
	}
	c := phoneFixture(t, db, true)
	if !c.PhoneProfileRequired || !errors.Is(RequirePhoneProfileComplete(ctx, db, c.ID), ErrPhoneProfileRequired) {
		t.Fatal("provisional identity gained completed access")
	}
	// Existing recovery/account rows stay grandfathered; changing the global
	// rollout policy never clears an already persisted pending requirement.
	t.Setenv(contactphone.EnrollmentPolicyEnv, "false")
	fresh, err := GetCollaborator(ctx, db, c.ID.String())
	if err != nil || !fresh.PhoneProfileRequired {
		t.Fatal("rollback cleared pending enrollment")
	}
	legacy := phoneFixture(t, db, false)
	if RequirePhoneProfileComplete(ctx, db, legacy.ID) != nil {
		t.Fatal("legacy/no-policy account gained a new phone requirement")
	}
	// A generic metadata patch cannot impersonate completion.
	metadata := map[string]any{phoneRequirementProjectionKey: false, "note": "fixture"}
	patched, err := UpdateCollaborator(ctx, db, model.UpdateCollaboratorRequest{ID: c.ID.String(), Metadata: &metadata})
	if err != nil || !patched.PhoneProfileRequired {
		t.Fatal("metadata patch bypassed typed requirement")
	}
	if _, exists := patched.Metadata[phoneRequirementProjectionKey]; exists {
		t.Fatal("private projection key escaped ordinary metadata")
	}
	envelope := cryptoenvelope.NewWithStaticKEK([]byte(strings.Repeat("k", 32)))
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal("transaction unavailable")
	}
	phone, err := SetPhoneContactTx(ctx, tx, envelope, c.ID, "+12025550100", "collaborator:"+c.ID.String(), "self_profile")
	if err != nil {
		_ = tx.Rollback()
		t.Fatal("declaration failed")
	}
	if tx.Commit() != nil {
		t.Fatal("declaration commit failed")
	}
	if phone.Assurance != "declared" || RequirePhoneProfileComplete(ctx, db, c.ID) != nil {
		t.Fatal("successful declaration did not complete the provisional profile")
	}
	var encrypted []byte
	if db.QueryRow(`SELECT phone_ciphertext FROM public.collaborator_phone_contacts WHERE collaborator_id=$1`, c.ID).Scan(&encrypted) != nil || strings.Contains(string(encrypted), phone.PhoneE164) {
		t.Fatal("contact did not remain encrypted at rest")
	}
	var audit string
	if db.QueryRow(`SELECT metadata::text FROM public.audit_events WHERE action='collaborator.phone_declared' AND resource_id=$1 ORDER BY created_at DESC LIMIT 1`, c.ID.String()).Scan(&audit) != nil || strings.Contains(audit, phone.PhoneE164) {
		t.Fatal("declaration/audit conservation or privacy failed")
	}
}

func TestDirectorySnapshotReferencesAndDeclarationStatesPostgres(t *testing.T) {
	db := phoneDirectoryPostgres(t)
	ctx := context.Background()
	t.Setenv(contactphone.EnrollmentPolicyEnv, "false")
	a, b := phoneFixture(t, db, false), phoneFixture(t, db, false)
	team, err := CreateTeam(ctx, db, model.CreateTeamRequest{Slug: "phone-team-" + uuid.NewString(), Name: "Contact CI Team", AssertLeadership: true, Owners: []string{a.Slug}})
	if err != nil {
		t.Fatal("team fixture failed")
	}
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM public.teams WHERE id=$1`, team.ID) })
	manager := a.ID.String()
	if _, err := UpdateCollaborator(ctx, db, model.UpdateCollaboratorRequest{ID: b.ID.String(), ManagerID: &manager}); err != nil {
		t.Fatal("manager fixture failed")
	}
	envelope := cryptoenvelope.NewWithStaticKEK([]byte(strings.Repeat("k", 32)))
	for _, c := range []model.Collaborator{a, b} {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal("transaction unavailable")
		}
		if _, err := SetPhoneContactTx(ctx, tx, envelope, c.ID, "+12025550101", "ci-operator", "operator_assertion"); err != nil {
			_ = tx.Rollback()
			t.Fatal("contact fixture failed")
		}
		if tx.Commit() != nil {
			t.Fatal("contact fixture commit failed")
		}
	}
	basic, err := LoadDirectorySnapshot(ctx, db, nil, false, nil)
	if err != nil {
		t.Fatal("bounded graph export failed")
	}
	raw, _ := json.Marshal(basic)
	if strings.Contains(string(raw), "phone_e164") || strings.Contains(string(raw), "phone_ciphertext") || strings.Contains(string(raw), "primary_email") {
		t.Fatal("basic export disclosed contacts or unrelated PII")
	}
	full, err := LoadDirectorySnapshot(ctx, db, nil, true, envelope)
	if err != nil {
		t.Fatal("contact export failed")
	}
	found := 0
	for _, p := range full.PhoneContacts {
		if p.CollaboratorID == a.ID.String() || p.CollaboratorID == b.ID.String() {
			found++
			if p.State != "ambiguous" || p.PhoneE164 != "" {
				t.Fatal("duplicate declarations became a usable destination")
			}
		}
	}
	if found != 2 {
		t.Fatal("contact states vanished from full export")
	}
	// A two-person cycle is permitted by old one-row writers but must never
	// leave a hierarchy export as valid authority.
	if _, err := db.Exec(`UPDATE public.collaborators SET manager_id=$2 WHERE id=$1`, a.ID, b.ID); err != nil {
		t.Fatal("cycle fixture failed")
	}
	if _, err := LoadDirectorySnapshot(ctx, db, nil, false, nil); !errors.Is(err, ErrDirectorySnapshotInvalid) {
		t.Fatal("cyclic hierarchy exported as complete")
	}
	_, _ = db.Exec(`UPDATE public.collaborators SET manager_id=NULL WHERE id=$1`, a.ID)
}

func TestDeclaredPhoneReadRequiresExactGrantPostgres(t *testing.T) {
	db := phoneDirectoryPostgres(t)
	ctx := context.Background()
	t.Setenv(contactphone.EnrollmentPolicyEnv, "false")
	c := phoneFixture(t, db, false)
	team, err := CreateTeam(ctx, db, model.CreateTeamRequest{Slug: "contact-reader-" + uuid.NewString(), Name: "Contact reader CI"})
	if err != nil {
		t.Fatal("reader fixture failed")
	}
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM public.teams WHERE id=$1`, team.ID) })
	if _, err := UpsertTeamMembership(ctx, db, model.UpsertTeamMembershipRequest{TeamID: team.ID.String(), CollaboratorID: c.ID.String(), Role: "founder"}); err != nil {
		t.Fatal("reader membership failed")
	}
	// Resolve the canonical already-bootstrapped self-management manifest.
	var namespace, name string
	err = db.QueryRow(`SELECT mi.namespace,mi.name FROM public.manifests mi JOIN public.manifests mt ON mt.kind='integration_type' AND mt.active AND mt.name='yggdrasil-self' AND mt.namespace=mi.spec->'type_ref'->>'namespace' AND mt.name=mi.spec->'type_ref'->>'name' WHERE mi.kind='integration_instance' AND mi.active LIMIT 1`).Scan(&namespace, &name)
	if err != nil {
		// This fixture does not run bootstrap workers; create exactly the two
		// minimal manifest rows the production permission join requires.
		namespace = "phone-ci"
		name = "self-" + uuid.NewString()
		for _, item := range []struct{ kind, name, spec string }{{"integration_type", "yggdrasil-self", `{}`}, {"integration_instance", name, `{"type_ref":{"namespace":"phone-ci","name":"yggdrasil-self"}}`}} {
			if _, err := db.Exec(`INSERT INTO public.manifests(api_version,kind,namespace,name,version,spec,checksum,active) VALUES('yggdrasil.io/v1alpha1',$1,$2,$3,1,$4::jsonb,$5,true)`, item.kind, namespace, item.name, item.spec, uuid.NewString()); err != nil {
				t.Fatal("self-management fixture failed")
			}
		}
		t.Cleanup(func() {
			_, _ = db.Exec(`DELETE FROM public.manifests WHERE namespace='phone-ci' AND (name=$1 OR name='yggdrasil-self')`, name)
		})
	}
	for _, action := range []string{"*", "yggdrasil:*"} {
		if _, err := GrantTeamAction(ctx, db, model.GrantTeamActionRequest{TeamID: team.ID.String(), IntegrationInstanceNamespace: namespace, IntegrationInstanceName: name, ActionName: action}); err != nil {
			t.Fatal("wildcard fixture failed")
		}
	}
	traits := map[string]any{"yggdrasil_admin": true}
	if _, err := UpdateCollaborator(ctx, db, model.UpdateCollaboratorRequest{ID: c.ID.String(), Traits: &traits}); err != nil {
		t.Fatal("admin fixture failed")
	}
	if yes, err := HasExactPhoneContactRead(ctx, db, c.ID); err != nil {
		t.Fatal("sensitive grant query unavailable against canonical schema")
	} else if yes {
		t.Fatal("wildcard or admin trait became an implicit contact-read grant")
	}
	if _, err := GrantTeamAction(ctx, db, model.GrantTeamActionRequest{TeamID: team.ID.String(), IntegrationInstanceNamespace: namespace, IntegrationInstanceName: name, ActionName: "yggdrasil:view_contact_phones"}); err != nil {
		t.Fatal("exact grant fixture failed")
	}
	if yes, err := HasExactPhoneContactRead(ctx, db, c.ID); err != nil {
		t.Fatal("sensitive grant query unavailable against canonical schema")
	} else if !yes {
		t.Fatal("explicit contact-read grant not honoured")
	}
	future := time.Now().Add(time.Hour)
	if _, err := db.Exec(`UPDATE public.team_memberships SET starts_at=$2 WHERE collaborator_id=$1`, c.ID, future); err != nil {
		t.Fatal("window fixture failed")
	}
	if yes, err := HasExactPhoneContactRead(ctx, db, c.ID); err != nil || yes {
		t.Fatal("future membership became current contact authority")
	}
}
