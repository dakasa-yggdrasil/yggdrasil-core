package httpapi

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/contactphone"
	"go.uber.org/zap"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
)

// Existing JWT harnesses must model the current collaborator read rather than
// treating a correctly signed old token as proof of completed profile state.
func expectCurrentPhoneProfile(mock sqlmock.Sqlmock, id string, pending bool) {
	metadata, _ := json.Marshal(map[string]bool{"_yggdrasil_phone_profile_required": pending})
	mock.ExpectQuery(`(?i)FROM\s+public\.collaborators`).WithArgs(id).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "slug", "status", "display_name", "primary_email", "manager_id", "primary_team_id",
			"personal_data", "employment_data", "third_party_identities", "traits", "metadata", "version", "created_at", "updated_at",
		}).AddRow(id, "profile-ci", "active", "Profile CI", "person@example.test", nil, nil,
			[]byte("{}"), []byte("{}"), []byte("{}"), []byte("{}"), metadata, 0, time.Now(), time.Now()))
}

func TestPhoneProfileBootRequiresConfiguredEncryption(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	t.Setenv("YGGDRASIL_ENV", "test")
	t.Setenv(contactphone.EnrollmentPolicyEnv, "true")
	t.Setenv("YGGDRASIL_AUTH_KEK_BASE64", "")
	if _, err := New("required-phone-test", db, nil, zap.NewNop()); err == nil || !strings.Contains(err.Error(), "phone contact encryption is not configured") {
		t.Fatal("required phone enrollment booted without encryption readiness")
	}
}

func TestSnapshotInventoryRequiresIntegritySecret(t *testing.T) {
	p := snapshotPrincipalForTest(t, false)
	t.Setenv(snapshotSecretEnv, "")
	if _, err := directorySnapshotSecret([]directoryMachinePrincipal{*p}); err == nil {
		t.Fatal("snapshot inventory used an unsigned cursor fallback")
	}
	t.Setenv(snapshotSecretEnv, strings.Repeat("s", 32))
	if _, err := directorySnapshotSecret([]directoryMachinePrincipal{*p}); err != nil {
		t.Fatal("configured integrity key rejected")
	}
}

func snapshotPrincipalForTest(t *testing.T, phones bool) *directoryMachinePrincipal {
	t.Helper()
	caps := []string{directoryCapabilitySnapshot}
	if phones {
		caps = append(caps, directoryCapabilityPhoneContacts)
	}
	t.Setenv(directoryMachinePrincipalsEnv, testDirectoryMachinePrincipalsJSON(t, testDirectoryPrincipalConfig(testDirectoryToken, "snapshot-reader", caps)))
	principals, err := directoryMachinePrincipalsFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	return &principals[0]
}

func TestSnapshotCursorsBindEffectiveAuthorityAndObservedTime(t *testing.T) {
	p := snapshotPrincipalForTest(t, true)
	key := []byte(strings.Repeat("s", 32))
	at := time.Now().UTC().Add(-time.Minute)
	c := directorySnapshotCursor{Revision: "opaque", Offset: 100, Limit: 100, Phones: true, ObservedAt: at, ExpiresAt: at.Add(snapshotTTL)}
	raw := encodeSnapshotCursor(key, snapshotAuthority(p, true), c)
	got, err := decodeSnapshotCursor(key, snapshotAuthority(p, true), raw, time.Now().UTC())
	if err != nil || !got.ObservedAt.Equal(at) || got.Offset != 100 {
		t.Fatal("cursor lost its snapshot instant")
	}
	delete(p.Capabilities, directoryCapabilityPhoneContacts)
	if _, err := decodeSnapshotCursor(key, snapshotAuthority(p, true), raw, time.Now().UTC()); err == nil {
		t.Fatal("capability change kept an old cursor valid")
	}
	p.Capabilities[directoryCapabilityPhoneContacts] = struct{}{}
	p.AllowedExternalIdentityInstances["00000000-0000-4000-8000-000000000001"] = struct{}{}
	if _, err := decodeSnapshotCursor(key, snapshotAuthority(p, true), raw, time.Now().UTC()); err == nil {
		t.Fatal("instance allowlist change kept an old cursor valid")
	}
	if _, err := decodeSnapshotCursor(key, snapshotAuthority(p, false), raw, time.Now().UTC()); err == nil {
		t.Fatal("contact projection downgraded inside a cursor")
	}
}

func TestSnapshotRevisionIncludesEnrollmentState(t *testing.T) {
	p := snapshotPrincipalForTest(t, false)
	key := []byte(strings.Repeat("s", 32))
	s := repository.DirectorySnapshot{Collaborators: []model.DirectoryCollaborator{{ID: uuid.NewString()}}}
	first := snapshotRevision(key, snapshotAuthority(p, false), s)
	s.Collaborators[0].PhoneProfileRequired = true
	if first == snapshotRevision(key, snapshotAuthority(p, false), s) {
		t.Fatal("pending enrollment did not change the revision")
	}
	first = snapshotRevision(key, snapshotAuthority(p, false), s)
	// Authority changes invalidate a stable dataset too, independently of data.
	p.RotationID = "new-rotation"
	if first == snapshotRevision(key, snapshotAuthority(p, false), s) {
		t.Fatal("rotation did not change the revision")
	}
}

func TestSnapshotCursorAndRevisionBindEffectiveCredentialReplacement(t *testing.T) {
	p := snapshotPrincipalForTest(t, false)
	key := []byte(strings.Repeat("s", 32))
	at := time.Now().UTC()
	s := repository.DirectorySnapshot{}
	firstRevision := snapshotRevision(key, snapshotAuthority(p, false), s)
	cursor := encodeSnapshotCursor(key, snapshotAuthority(p, false), directorySnapshotCursor{
		Revision: firstRevision, Offset: 1, Limit: 100, ObservedAt: at, ExpiresAt: at.Add(snapshotTTL),
	})
	// Accepted configuration replacement with unchanged identity, capabilities,
	// allowlists and rotation metadata still changes the actual credential.
	p.TokenSHA256 = sha256.Sum256([]byte("replacement-test-only-credential"))
	if firstRevision == snapshotRevision(key, snapshotAuthority(p, false), s) {
		t.Fatal("credential replacement preserved the previous revision")
	}
	if _, err := decodeSnapshotCursor(key, snapshotAuthority(p, false), cursor, at); err == nil {
		t.Fatal("replacement credential accepted the previous cursor")
	}
}

func TestSnapshotContactCapabilityFailsBeforeDataRead(t *testing.T) {
	p := snapshotPrincipalForTest(t, false)
	audited := false
	s := &Server{snapshotHMACSecret: []byte(strings.Repeat("s", 32)), directoryAuditSink: func(event model.AuditEvent) error {
		audited = true
		if strings.Contains(string(event.Metadata["path"].(string)), "?") {
			t.Fatal("query leaked into audit")
		}
		return nil
	}}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/directory/snapshot?include_phone=true", nil)
	s.serveDirectorySnapshot(w, r, p)
	if w.Code != http.StatusForbidden || !audited || strings.Contains(w.Body.String(), "phone_contacts") {
		t.Fatal("phone capability refusal must precede any data read")
	}
}

func TestSnapshotQueryRejectsUnknownDuplicateAndOversizedParameters(t *testing.T) {
	for _, q := range []string{"limit=201", "limit=0", "limit=2&limit=2", "include_phone=1", "include_phone=true&extra=1"} {
		if _, _, _, err := parseSnapshotQuery(q); err == nil {
			t.Fatal("invalid query accepted")
		}
	}
}

func TestContactPhoneErrorsNeverEchoBodyMaterial(t *testing.T) {
	var buffer bytes.Buffer
	s := &Server{}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPut, "/api/v1/me/contact/phone", strings.NewReader(`{"phone_e164":"private-value","extra":"cipher-marker"}`))
	s.writePhoneDeclaration(w, r, uuid.Nil, "actor", "self_profile")
	buffer.Write(w.Body.Bytes())
	if w.Code != http.StatusUnprocessableEntity || strings.Contains(buffer.String(), "private-value") || strings.Contains(buffer.String(), "cipher-marker") {
		t.Fatal("contact refusal leaked its body")
	}
	var body map[string]any
	if json.Unmarshal(buffer.Bytes(), &body) != nil {
		t.Fatal("refusal is not JSON")
	}
}
