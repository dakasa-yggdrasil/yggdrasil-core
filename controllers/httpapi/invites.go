package httpapi

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

// Invite is an in-memory tartaro collaborator invite. The original
// Yggdrasil-core ships without an invites surface, but tartaro-fe expects
// POST /api/v1/invites to issue a code that can then be redeemed via
// /api/v1/invites/validate?code=... during register.
//
// This implementation is intentionally in-memory: it survives until the
// pod restarts. Persistence can be added later by writing through to the
// repository layer. For the bootcamp validation cluster the in-memory
// approach is adequate because tokens are generated on demand and
// consumed within minutes.
type Invite struct {
	Code      string    `json:"code"`
	Roles     []string  `json:"roles"`
	CreatedBy string    `json:"createdBy"`
	CreatedAt time.Time `json:"createdAt"`
	ExpiresAt time.Time `json:"expiresAt"`
	Used      bool      `json:"used"`
	UsedAt    time.Time `json:"usedAt,omitempty"`
}

var inviteStore = struct {
	mu      sync.RWMutex
	invites map[string]*Invite
}{invites: map[string]*Invite{}}

func generateInviteCode() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return "inv_" + hex.EncodeToString(b)
}

// handleInviteCreate — POST /api/v1/invites
//
// Body: { "roles": ["admin", "risk", ...], "ttlMinutes": 1440 (optional) }
// Response: { "invite": { code, roles, createdBy, createdAt, expiresAt } }
//
// Authorization: gated server-side by requireOpsPermissionFunc(permCreateCollaborator)
// at the route registration site in server.go (RBAC sweep #2, 2026-05-28).
// INTEGRATION_CONTRACT §12 — backend is the authorization authority; the SPA
// hiding non-admin affordances is defense-in-depth, not the primary gate.
func (s *Server) handleInviteCreate(w http.ResponseWriter, r *http.Request) {
	token, ok := extractAuthToken(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "not authenticated"})
		return
	}
	_, collaborator, err := repository.ResolveAuthSession(r.Context(), s.db, token)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid session"})
		return
	}

	var body struct {
		Roles      []string `json:"roles"`
		TTLMinutes int      `json:"ttlMinutes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid body"})
		return
	}
	if len(body.Roles) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "roles is required"})
		return
	}
	ttl := body.TTLMinutes
	if ttl <= 0 {
		ttl = 24 * 60 // 24h default
	}

	now := time.Now().UTC()
	invite := &Invite{
		Code:      generateInviteCode(),
		Roles:     body.Roles,
		CreatedBy: collaborator.DisplayName,
		CreatedAt: now,
		ExpiresAt: now.Add(time.Duration(ttl) * time.Minute),
	}

	inviteStore.mu.Lock()
	inviteStore.invites[invite.Code] = invite
	inviteStore.mu.Unlock()

	writeJSON(w, http.StatusCreated, map[string]any{"invite": invite})
}

// handleInviteList — GET /api/v1/invites
// Returns all in-memory invites, newest first.
func (s *Server) handleInviteList(w http.ResponseWriter, r *http.Request) {
	token, ok := extractAuthToken(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "not authenticated"})
		return
	}
	if _, _, err := repository.ResolveAuthSession(r.Context(), s.db, token); err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid session"})
		return
	}

	inviteStore.mu.RLock()
	list := make([]Invite, 0, len(inviteStore.invites))
	for _, inv := range inviteStore.invites {
		list = append(list, *inv)
	}
	inviteStore.mu.RUnlock()

	sort.Slice(list, func(i, j int) bool {
		return list[i].CreatedAt.After(list[j].CreatedAt)
	})

	writeJSON(w, http.StatusOK, map[string]any{
		"invites": list,
		"total":   len(list),
	})
}

// handleInviteValidate — GET /api/v1/invites/validate?code=inv_xxx
// Public endpoint used by the register page to check if a code is
// still claimable. Returns roles so the FE can prefill / preview.
func (s *Server) handleInviteValidate(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "code is required"})
		return
	}

	inviteStore.mu.RLock()
	invite, ok := inviteStore.invites[code]
	valid := false
	var roles []string
	var expiresAt time.Time
	if ok {
		expired := !invite.ExpiresAt.IsZero() && time.Now().UTC().After(invite.ExpiresAt)
		valid = !invite.Used && !expired
		if valid {
			roles = invite.Roles
			expiresAt = invite.ExpiresAt
		}
	}
	inviteStore.mu.RUnlock()

	writeJSON(w, http.StatusOK, map[string]any{
		"valid":     valid,
		"roles":     roles,
		"expiresAt": expiresAt,
	})
}

// MarkInviteUsed flips an invite to used+now and is intended to be
// called from the register handler when a code is redeemed. Exported
// so the auth code path can call it without circular imports.
func MarkInviteUsed(code string) bool {
	inviteStore.mu.Lock()
	defer inviteStore.mu.Unlock()
	inv, ok := inviteStore.invites[code]
	if !ok || inv.Used {
		return false
	}
	inv.Used = true
	inv.UsedAt = time.Now().UTC()
	return true
}
