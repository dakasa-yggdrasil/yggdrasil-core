package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"sort"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/collaboratorstate"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/cryptoenvelope"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
	"github.com/lib/pq"
)

var ErrDirectorySnapshotInvalid = errors.New("directory snapshot is invalid or exceeds its resource bounds")

const directoryPeopleBound = 10000
const directoryLinksBound = 100000

// DirectorySnapshot contains only the typed export. It is assembled within a
// single bounded repeatable-read transaction; no personal/employment/identity
// metadata or credential columns are selected. All pages must compare the same
// principal-bound revision before a consumer treats absence as authoritative.
type DirectorySnapshot struct {
	ObservedAt         time.Time                         `json:"-"`
	Collaborators      []model.DirectoryCollaborator     `json:"collaborators"`
	Teams              []model.DirectoryTeam             `json:"teams"`
	Memberships        []model.DirectoryMembership       `json:"memberships"`
	ExternalIdentities []model.DirectoryExternalIdentity `json:"external_identities"`
	PhoneContacts      []model.DirectoryPhoneContact     `json:"phone_contacts,omitempty"`
}

func LoadDirectorySnapshot(ctx context.Context, db *sql.DB, instances []string, phones bool, envelope *cryptoenvelope.Envelope) (DirectorySnapshot, error) {
	s := DirectorySnapshot{Collaborators: []model.DirectoryCollaborator{}, Teams: []model.DirectoryTeam{}, Memberships: []model.DirectoryMembership{}, ExternalIdentities: []model.DirectoryExternalIdentity{}}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return s, ErrDirectorySnapshotInvalid
	}
	defer func() { _ = tx.Rollback() }()
	if tx.QueryRowContext(ctx, `SELECT transaction_timestamp()`).Scan(&s.ObservedAt) != nil {
		return s, ErrDirectorySnapshotInvalid
	}
	rows, err := tx.QueryContext(ctx, `SELECT id::text,slug,display_name,status,manager_id::text,primary_team_id::text,version,updated_at,phone_profile_required FROM public.collaborators ORDER BY id LIMIT 10001`)
	if err != nil {
		return s, ErrDirectorySnapshotInvalid
	}
	for rows.Next() {
		var c model.DirectoryCollaborator
		if rows.Scan(&c.ID, &c.Slug, &c.DisplayName, &c.Status, &c.ManagerID, &c.PrimaryTeamID, &c.Version, &c.UpdatedAt, &c.PhoneProfileRequired) != nil {
			_ = rows.Close()
			return s, ErrDirectorySnapshotInvalid
		}
		s.Collaborators = append(s.Collaborators, c)
	}
	err = rows.Err()
	_ = rows.Close()
	if err != nil || len(s.Collaborators) > directoryPeopleBound {
		return s, ErrDirectorySnapshotInvalid
	}
	s.ObservedAt = s.ObservedAt.UTC()
	owners := map[string][]string{}
	rows, err = tx.QueryContext(ctx, `SELECT id::text,slug,name,type,status,parent_team_id::text,owners,updated_at FROM public.teams ORDER BY id LIMIT 10001`)
	if err != nil {
		return s, ErrDirectorySnapshotInvalid
	}
	for rows.Next() {
		var t model.DirectoryTeam
		var raw []byte
		var refs []string
		if rows.Scan(&t.ID, &t.Slug, &t.Name, &t.Type, &t.Status, &t.ParentTeamID, &raw, &t.UpdatedAt) != nil || json.Unmarshal(raw, &refs) != nil || refs == nil {
			_ = rows.Close()
			return s, ErrDirectorySnapshotInvalid
		}
		owners[t.ID] = refs
		t.OwnerIDs = []string{}
		s.Teams = append(s.Teams, t)
	}
	err = rows.Err()
	_ = rows.Close()
	if err != nil || len(s.Teams) > directoryPeopleBound {
		return s, ErrDirectorySnapshotInvalid
	}
	rows, err = tx.QueryContext(ctx, `SELECT id::text,team_id::text,collaborator_id::text,active,starts_at,ends_at,updated_at FROM public.team_memberships ORDER BY id LIMIT 100001`)
	if err != nil {
		return s, ErrDirectorySnapshotInvalid
	}
	for rows.Next() {
		var m model.DirectoryMembership
		if rows.Scan(&m.ID, &m.TeamID, &m.CollaboratorID, &m.Active, &m.StartsAt, &m.EndsAt, &m.UpdatedAt) != nil {
			_ = rows.Close()
			return s, ErrDirectorySnapshotInvalid
		}
		s.Memberships = append(s.Memberships, m)
	}
	err = rows.Err()
	_ = rows.Close()
	if err != nil || len(s.Memberships) > directoryLinksBound {
		return s, ErrDirectorySnapshotInvalid
	}
	if len(instances) > 0 {
		rows, err = tx.QueryContext(ctx, `SELECT id::text,collaborator_id::text,integration_instance_id::text,external_id,updated_at FROM public.collaborator_external_identities WHERE unlinked_at IS NULL AND integration_instance_id=ANY($1::uuid[]) ORDER BY id LIMIT 100001`, pq.Array(instances))
		if err != nil {
			return s, ErrDirectorySnapshotInvalid
		}
		for rows.Next() {
			var e model.DirectoryExternalIdentity
			if rows.Scan(&e.ID, &e.CollaboratorID, &e.IntegrationInstanceID, &e.ExternalID, &e.UpdatedAt) != nil {
				_ = rows.Close()
				return s, ErrDirectorySnapshotInvalid
			}
			s.ExternalIdentities = append(s.ExternalIdentities, e)
		}
		err = rows.Err()
		_ = rows.Close()
		if err != nil || len(s.ExternalIdentities) > directoryLinksBound {
			return s, ErrDirectorySnapshotInvalid
		}
	}
	if err := validateDirectoryGraph(&s, owners); err != nil {
		return s, err
	}
	if phones {
		if envelope == nil {
			return s, ErrPhoneUnavailable
		}
		rows, err = tx.QueryContext(ctx, `SELECT collaborator_id::text,phone_ciphertext,phone_dek,declaration_source,declared_at,version FROM public.collaborator_phone_contacts ORDER BY collaborator_id LIMIT 10001`)
		if err != nil {
			return s, ErrPhoneUnavailable
		}
		byID := map[string]model.DirectoryPhoneContact{}
		knownPeople := map[string]bool{}
		for _, c := range s.Collaborators {
			knownPeople[c.ID] = true
		}
		for rows.Next() {
			var p model.DirectoryPhoneContact
			var ct, dek []byte
			var declared time.Time
			if rows.Scan(&p.CollaboratorID, &ct, &dek, &p.DeclarationSource, &declared, &p.Version) != nil {
				_ = rows.Close()
				return s, ErrPhoneUnavailable
			}
			p.PhoneE164, err = OpenPhoneContact(ctx, envelope, p.CollaboratorID, ct, dek)
			if err != nil || p.Version <= 0 || p.DeclarationSource != "self_profile" && p.DeclarationSource != "operator_assertion" {
				_ = rows.Close()
				return s, ErrPhoneUnavailable
			}
			p.DeclaredAt = &declared
			p.State = "declared"
			p.Assurance = "declared"
			if !knownPeople[p.CollaboratorID] {
				_ = rows.Close()
				return s, ErrDirectorySnapshotInvalid
			}
			byID[p.CollaboratorID] = p
		}
		err = rows.Err()
		_ = rows.Close()
		if err != nil || len(byID) > directoryPeopleBound {
			return s, ErrPhoneUnavailable
		}
		s.PhoneContacts = projectDirectoryPhones(s.Collaborators, byID)
		if len(byID) > len(s.PhoneContacts) {
			return s, ErrDirectorySnapshotInvalid
		}
	}
	if tx.Commit() != nil {
		return s, ErrDirectorySnapshotInvalid
	}
	return s, nil
}

func directoryCanonicalID(id string) bool {
	u, err := uuid.Parse(id)
	return err == nil && u != uuid.Nil && u.String() == id
}

func validateDirectoryGraph(s *DirectorySnapshot, owners map[string][]string) error {
	people := map[string]model.DirectoryCollaborator{}
	slugs := map[string]string{}
	teams := map[string]model.DirectoryTeam{}
	managers := map[string]*string{}
	parents := map[string]*string{}
	for _, c := range s.Collaborators {
		if !directoryCanonicalID(c.ID) || c.Slug == "" || c.DisplayName == "" || !collaboratorstate.IsKnown(collaboratorstate.Status(c.Status)) || c.Version < 0 || c.UpdatedAt.IsZero() {
			return ErrDirectorySnapshotInvalid
		}
		if _, ok := people[c.ID]; ok {
			return ErrDirectorySnapshotInvalid
		}
		if _, ok := slugs[c.Slug]; ok {
			return ErrDirectorySnapshotInvalid
		}
		people[c.ID] = c
		slugs[c.Slug] = c.ID
		managers[c.ID] = c.ManagerID
	}
	for _, t := range s.Teams {
		if !directoryCanonicalID(t.ID) || t.Slug == "" || t.Name == "" || t.Status == "" || t.Type == "" || t.UpdatedAt.IsZero() {
			return ErrDirectorySnapshotInvalid
		}
		if _, ok := teams[t.ID]; ok {
			return ErrDirectorySnapshotInvalid
		}
		teams[t.ID] = t
		parents[t.ID] = t.ParentTeamID
	}
	if !acyclicDirectory(managers) || !acyclicDirectory(parents) {
		return ErrDirectorySnapshotInvalid
	}
	for _, c := range s.Collaborators {
		if c.PrimaryTeamID != nil {
			if _, ok := teams[*c.PrimaryTeamID]; !ok {
				return ErrDirectorySnapshotInvalid
			}
		}
	}
	for i := range s.Teams {
		ids := map[string]bool{}
		for _, ref := range owners[s.Teams[i].ID] {
			id := slugs[ref]
			if parsed, err := uuid.Parse(ref); err == nil {
				id = parsed.String()
			}
			if _, ok := people[id]; !ok {
				return ErrDirectorySnapshotInvalid
			}
			ids[id] = true
		}
		for id := range ids {
			s.Teams[i].OwnerIDs = append(s.Teams[i].OwnerIDs, id)
		}
		sort.Strings(s.Teams[i].OwnerIDs)
	}
	seen := map[string]bool{}
	for _, m := range s.Memberships {
		if !directoryCanonicalID(m.ID) || seen[m.ID] || m.UpdatedAt.IsZero() {
			return ErrDirectorySnapshotInvalid
		}
		seen[m.ID] = true
		if _, ok := people[m.CollaboratorID]; !ok {
			return ErrDirectorySnapshotInvalid
		}
		if _, ok := teams[m.TeamID]; !ok {
			return ErrDirectorySnapshotInvalid
		}
		if m.StartsAt != nil && m.EndsAt != nil && m.StartsAt.After(*m.EndsAt) {
			return ErrDirectorySnapshotInvalid
		}
	}
	seen = map[string]bool{}
	for _, e := range s.ExternalIdentities {
		if !directoryCanonicalID(e.ID) || !directoryCanonicalID(e.IntegrationInstanceID) || e.ExternalID == "" || seen[e.ID] || e.UpdatedAt.IsZero() {
			return ErrDirectorySnapshotInvalid
		}
		seen[e.ID] = true
		if _, ok := people[e.CollaboratorID]; !ok {
			return ErrDirectorySnapshotInvalid
		}
	}
	return nil
}

func acyclicDirectory(edges map[string]*string) bool {
	state := map[string]int{}
	var visit func(string) bool
	visit = func(id string) bool {
		if state[id] == 1 {
			return false
		}
		if state[id] == 2 {
			return true
		}
		parent, ok := edges[id]
		if !ok {
			return false
		}
		state[id] = 1
		if parent != nil && (!directoryCanonicalID(*parent) || !visit(*parent)) {
			return false
		}
		state[id] = 2
		return true
	}
	for id := range edges {
		if !visit(id) {
			return false
		}
	}
	return true
}

func projectDirectoryPhones(people []model.DirectoryCollaborator, contacts map[string]model.DirectoryPhoneContact) []model.DirectoryPhoneContact {
	counts := map[string]int{}
	for _, p := range contacts {
		counts[p.PhoneE164]++
	}
	out := make([]model.DirectoryPhoneContact, 0, len(people))
	for _, c := range people {
		p, ok := contacts[c.ID]
		if !ok {
			p = model.DirectoryPhoneContact{CollaboratorID: c.ID, State: "missing"}
		}
		if ok && counts[p.PhoneE164] > 1 {
			p.State = "ambiguous"
			p.PhoneE164 = ""
		}
		out = append(out, p)
	}
	return out
}

func (s DirectorySnapshot) TotalRecords() int {
	return len(s.Collaborators) + len(s.Teams) + len(s.Memberships) + len(s.ExternalIdentities) + len(s.PhoneContacts)
}

func (s DirectorySnapshot) Page(offset, limit int, phones bool) model.DirectorySnapshotPage {
	p := model.DirectorySnapshotPage{SchemaVersion: 1, ObservedAt: s.ObservedAt, Offset: offset, Limit: limit, TotalRecords: s.TotalRecords(), ContactsIncluded: phones, Collaborators: []model.DirectoryCollaborator{}, Teams: []model.DirectoryTeam{}, Memberships: []model.DirectoryMembership{}, ExternalIdentities: []model.DirectoryExternalIdentity{}}
	end := offset + limit
	index := 0
	selected := func() bool { i := index; index++; return i >= offset && i < end }
	for _, r := range s.Collaborators {
		if selected() {
			p.Collaborators = append(p.Collaborators, r)
		}
	}
	for _, r := range s.Teams {
		if selected() {
			p.Teams = append(p.Teams, r)
		}
	}
	for _, r := range s.Memberships {
		if selected() {
			p.Memberships = append(p.Memberships, r)
		}
	}
	for _, r := range s.ExternalIdentities {
		if selected() {
			p.ExternalIdentities = append(p.ExternalIdentities, r)
		}
	}
	for _, r := range s.PhoneContacts {
		if selected() {
			p.PhoneContacts = append(p.PhoneContacts, r)
		}
	}
	p.Complete = end >= p.TotalRecords
	return p
}
