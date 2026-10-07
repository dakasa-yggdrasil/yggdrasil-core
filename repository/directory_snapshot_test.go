package repository

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/contactphone"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/cryptoenvelope"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

func graphFixture() (DirectorySnapshot, map[string][]string) {
	at := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	a, b, team := uuid.NewString(), uuid.NewString(), uuid.NewString()
	s := DirectorySnapshot{ObservedAt: at, Collaborators: []model.DirectoryCollaborator{
		{ID: a, Slug: "person-a", DisplayName: "Person A", Status: "active", UpdatedAt: at},
		{ID: b, Slug: "person-b", DisplayName: "Person B", Status: "on_leave", ManagerID: &a, UpdatedAt: at},
	}, Teams: []model.DirectoryTeam{{ID: team, Slug: "team", Name: "Team", Type: "team", Status: "active", OwnerIDs: []string{}, UpdatedAt: at}}, Memberships: []model.DirectoryMembership{{ID: uuid.NewString(), TeamID: team, CollaboratorID: b, Active: true, UpdatedAt: at}}, ExternalIdentities: []model.DirectoryExternalIdentity{}}
	return s, map[string][]string{team: {"person-a", a}}
}

func TestDirectoryGraphRejectsCyclesAndResolvesOwners(t *testing.T) {
	s, owners := graphFixture()
	if err := validateDirectoryGraph(&s, owners); err != nil {
		t.Fatal(err)
	}
	if len(s.Teams[0].OwnerIDs) != 1 || s.Teams[0].OwnerIDs[0] != s.Collaborators[0].ID {
		t.Fatal("owner aliases did not collapse to one canonical identity")
	}
	if s.Collaborators[1].Status != "on_leave" {
		t.Fatal("leave status was replaced with absent or active")
	}
	for _, kind := range []string{"manager cycle", "team cycle", "dangling owner", "dangling primary team", "invalid window"} {
		t.Run(kind, func(t *testing.T) {
			s, owners := graphFixture()
			switch kind {
			case "manager cycle":
				s.Collaborators[0].ManagerID = &s.Collaborators[1].ID
			case "team cycle":
				s.Teams[0].ParentTeamID = &s.Teams[0].ID
			case "dangling owner":
				owners[s.Teams[0].ID] = []string{"missing"}
			case "dangling primary team":
				id := uuid.NewString()
				s.Collaborators[0].PrimaryTeamID = &id
			case "invalid window":
				later := s.ObservedAt.Add(time.Hour)
				s.Memberships[0].StartsAt = &later
				s.Memberships[0].EndsAt = &s.ObservedAt
			}
			if !errors.Is(validateDirectoryGraph(&s, owners), ErrDirectorySnapshotInvalid) {
				t.Fatal("invalid graph accepted")
			}
		})
	}
}

func TestDirectoryPaginationCountsAllKindsAndNeverClaimsEarlierPages(t *testing.T) {
	s, owners := graphFixture()
	if validateDirectoryGraph(&s, owners) != nil {
		t.Fatal("fixture invalid")
	}
	offset := 0
	seen := 0
	for {
		p := s.Page(offset, 2, false)
		n := len(p.Collaborators) + len(p.Teams) + len(p.Memberships) + len(p.ExternalIdentities) + len(p.PhoneContacts)
		if n > 2 || p.Offset != offset || p.TotalRecords != s.TotalRecords() {
			t.Fatal("page shape does not conserve records")
		}
		seen += n
		if p.Complete {
			break
		}
		offset += 2
	}
	if seen != s.TotalRecords() {
		t.Fatal("pagination silently lost a kind")
	}
	raw, _ := json.Marshal(s.Page(0, 2, false))
	if strings.Contains(string(raw), "phone_e164") || strings.Contains(string(raw), "personal_data") || strings.Contains(string(raw), "phone_contacts") {
		t.Fatal("basic projection exposed contact data")
	}
}

func TestDeclaredPhonesExposeMissingAndAmbiguousWithoutDestinations(t *testing.T) {
	s, _ := graphFixture()
	contacts := map[string]model.DirectoryPhoneContact{}
	for _, c := range s.Collaborators {
		contacts[c.ID] = model.DirectoryPhoneContact{CollaboratorID: c.ID, PhoneE164: "+12025550100", State: "declared", Assurance: "declared", Version: 1}
	}
	for _, p := range projectDirectoryPhones(s.Collaborators, contacts) {
		if p.State != "ambiguous" || p.PhoneE164 != "" {
			t.Fatal("duplicate declaration selected a destination")
		}
	}
	delete(contacts, s.Collaborators[1].ID)
	p := projectDirectoryPhones(s.Collaborators, contacts)
	if p[0].State != "declared" || p[1].State != "missing" || p[1].Assurance != "" {
		t.Fatal("missing contact became verified or disappeared")
	}
}

func TestPhoneEnvelopeBindsOwnerAndNeverAcceptsCiphertextSwap(t *testing.T) {
	envelope := cryptoenvelope.NewWithStaticKEK([]byte(strings.Repeat("k", 32)))
	id, other := uuid.NewString(), uuid.NewString()
	raw, _ := json.Marshal(sealedPhone{CollaboratorID: id, PhoneE164: "+12025550100"})
	ct, dek, err := envelope.Seal(context.Background(), raw)
	if err != nil {
		t.Fatal("fixture encryption failed")
	}
	if _, err := OpenPhoneContact(context.Background(), envelope, id, ct, dek); err != nil {
		t.Fatal("owner cannot read declaration")
	}
	if _, err := OpenPhoneContact(context.Background(), envelope, other, ct, dek); !errors.Is(err, ErrPhoneUnavailable) {
		t.Fatal("ciphertext swap accepted another owner")
	}
	ct[len(ct)-1] ^= 1
	if _, err := OpenPhoneContact(context.Background(), envelope, id, ct, dek); !errors.Is(err, ErrPhoneUnavailable) {
		t.Fatal("tamper did not fail closed")
	}
}

func TestNewHumanPhonePolicyCannotBeSpoofedThroughJSON(t *testing.T) {
	t.Setenv(contactphone.EnrollmentPolicyEnv, "true")
	var req model.CreateCollaboratorRequest
	if json.Unmarshal([]byte(`{"slug":"new-person","display_name":"New Person","ProvisionalPhone":true}`), &req) != nil {
		t.Fatal("fixture parse failed")
	}
	if !errors.Is(validateNewPhone(req), ErrPhoneRequired) {
		t.Fatal("client spoofed the provisional-only source flag")
	}
	req.ProvisionalPhone = true
	if validateNewPhone(req) != nil {
		t.Fatal("server provisional path cannot finish onboarding")
	}
	req.PhoneE164 = "2025550100"
	if !errors.Is(validateNewPhone(req), contactphone.ErrInvalid) {
		t.Fatal("provisional path accepted noncanonical declaration")
	}
}
