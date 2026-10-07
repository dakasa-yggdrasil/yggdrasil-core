package httpapi

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/httperr"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

const snapshotSecretEnv = "YGGDRASIL_DIRECTORY_SNAPSHOT_HMAC_SECRET"
const snapshotChangedCode = "directory.snapshot_changed"
const snapshotTTL = 10 * time.Minute

type directorySnapshotCursor struct {
	Revision   string    `json:"revision"`
	Offset     int       `json:"offset"`
	Limit      int       `json:"limit"`
	Phones     bool      `json:"phones"`
	ObservedAt time.Time `json:"observed_at"`
	ExpiresAt  time.Time `json:"expires_at"`
}

func directorySnapshotSecret(principals []directoryMachinePrincipal) ([]byte, error) {
	secret := os.Getenv(snapshotSecretEnv)
	required := false
	for _, p := range principals {
		if directoryMachinePrincipalHasCapability(&p, directoryCapabilitySnapshot) {
			required = true
		}
	}
	if secret == "" && !required {
		return nil, nil
	}
	if len(secret) < 32 {
		return nil, errors.New("YGGDRASIL_DIRECTORY_SNAPSHOT_HMAC_SECRET must contain at least 32 bytes when a snapshot principal is configured")
	}
	return []byte(secret), nil
}

// Bind the effective inventory authority, not just data/identity. Rotation,
// expiry, capability and either instance allowlist changes invalidate cursors.
func snapshotAuthority(p *directoryMachinePrincipal, phones bool) []byte {
	caps := []string{}
	external := []string{}
	tartaro := []string{}
	for c := range p.Capabilities {
		caps = append(caps, c)
	}
	sort.Strings(caps)
	for id := range p.AllowedExternalIdentityInstances {
		external = append(external, id)
	}
	sort.Strings(external)
	for r := range p.AllowedTartaroInstances {
		tartaro = append(tartaro, r.Namespace+"/"+r.Name)
	}
	sort.Strings(tartaro)
	body, _ := json.Marshal(struct {
		ID, Status, Rotation    string
		Expires, Rotated        time.Time
		Caps, External, Tartaro []string
		Phones                  bool
	}{p.PrincipalID, p.Status, p.RotationID, p.ExpiresAt, p.RotatedAt, caps, external, tartaro, phones})
	// Fixed-length internal keying binds the effective credential even when an
	// operator replaces its digest without changing rotation metadata. It never
	// becomes a JSON field, cursor, revision, audit or log value: only the MAC
	// computed with the separate snapshot integrity secret leaves this process.
	authority := append([]byte(nil), p.TokenSHA256[:]...)
	return append(authority, body...)
}

func snapshotMAC(key []byte, domain string, authority, body []byte) []byte {
	m := hmac.New(sha256.New, key)
	_, _ = m.Write([]byte(domain))
	_, _ = m.Write([]byte{0})
	_, _ = m.Write(authority)
	_, _ = m.Write([]byte{0})
	_, _ = m.Write(body)
	return m.Sum(nil)
}

func snapshotRevision(key, authority []byte, s repository.DirectorySnapshot) string {
	body, _ := json.Marshal(s)
	return "r1_" + base64.RawURLEncoding.EncodeToString(snapshotMAC(key, "directory.snapshot.revision.v1", authority, body))
}

func encodeSnapshotCursor(key, authority []byte, c directorySnapshotCursor) string {
	body, _ := json.Marshal(c)
	return base64.RawURLEncoding.EncodeToString(body) + "." + base64.RawURLEncoding.EncodeToString(snapshotMAC(key, "directory.snapshot.cursor.v1", authority, body))
}

func decodeSnapshotCursor(key, authority []byte, raw string, now time.Time) (directorySnapshotCursor, error) {
	var c directorySnapshotCursor
	if len(raw) > 4096 {
		return c, errors.New("invalid snapshot cursor")
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 2 {
		return c, errors.New("invalid snapshot cursor")
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return c, errors.New("invalid snapshot cursor")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || !hmac.Equal(sig, snapshotMAC(key, "directory.snapshot.cursor.v1", authority, body)) {
		return c, errors.New("invalid snapshot cursor")
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if dec.Decode(&c) != nil || !errors.Is(dec.Decode(&struct{}{}), io.EOF) || c.Revision == "" || c.Offset <= 0 || c.Limit < 1 || c.Limit > 200 || c.ObservedAt.IsZero() || !now.Before(c.ExpiresAt) || c.ExpiresAt.After(c.ObservedAt.Add(snapshotTTL)) || c.ObservedAt.After(now) {
		return c, errors.New("invalid snapshot cursor")
	}
	return c, nil
}

func parseSnapshotQuery(raw string) (url.Values, int, bool, error) {
	q, err := url.ParseQuery(raw)
	if err != nil {
		return nil, 0, false, errors.New("invalid snapshot query")
	}
	for k, v := range q {
		if len(v) != 1 || k != "limit" && k != "include_phone" && k != "cursor" {
			return nil, 0, false, errors.New("invalid snapshot query")
		}
	}
	limit := 100
	if v, ok := q["limit"]; ok {
		n, err := strconv.Atoi(v[0])
		if err != nil || n < 1 || n > 200 {
			return nil, 0, false, errors.New("invalid snapshot limit")
		}
		limit = n
	}
	phones := false
	if v, ok := q["include_phone"]; ok {
		if v[0] != "true" && v[0] != "false" {
			return nil, 0, false, errors.New("invalid snapshot contact projection")
		}
		phones = v[0] == "true"
	}
	return q, limit, phones, nil
}

func (s *Server) serveDirectorySnapshot(w http.ResponseWriter, r *http.Request, p *directoryMachinePrincipal) {
	q, limit, phones, err := parseSnapshotQuery(r.URL.RawQuery)
	deny := func(status int, code, reason, detail string) {
		if s.auditDirectoryMachineOutcome(w, r, p, directoryCapabilitySnapshot, "", "denied", reason) {
			writeProblemJSON(w, status, code, detail)
		}
	}
	if err != nil {
		deny(http.StatusBadRequest, httperr.CodeInvalidInput, "invalid_query", "Invalid directory snapshot query.")
		return
	}
	var cursor *directorySnapshotCursor
	if raw, ok := q["cursor"]; ok {
		// include_phone must be explicit on every contact page so its scope is
		// known before authenticating the cursor. No downgrade or inference.
		c, e := decodeSnapshotCursor(s.snapshotHMACSecret, snapshotAuthority(p, phones), raw[0], time.Now().UTC())
		if e != nil {
			deny(http.StatusConflict, snapshotChangedCode, "cursor_invalid", "Restart the directory snapshot from its first page.")
			return
		}
		if (q.Has("limit") && limit != c.Limit) || phones != c.Phones {
			deny(http.StatusConflict, snapshotChangedCode, "projection_changed", "Restart the directory snapshot from its first page.")
			return
		}
		cursor = &c
		limit = c.Limit
	}
	if phones && !directoryMachinePrincipalHasCapability(p, directoryCapabilityPhoneContacts) {
		deny(http.StatusForbidden, httperr.CodePermissionDenied, "phone_capability_missing", "Directory principal lacks the phone contact capability.")
		return
	}
	if len(s.snapshotHMACSecret) < 32 || s.db == nil {
		deny(http.StatusServiceUnavailable, "directory.unavailable", "snapshot_unavailable", "Directory snapshot is unavailable.")
		return
	}
	instances := []string{}
	for id := range p.AllowedExternalIdentityInstances {
		instances = append(instances, id)
	}
	sort.Strings(instances)
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	var observedAt time.Time
	if cursor != nil {
		observedAt = cursor.ObservedAt
	}
	data, err := repository.LoadDirectorySnapshotAt(ctx, s.db, instances, phones, s.envelope, observedAt)
	if err != nil {
		deny(http.StatusServiceUnavailable, "directory.unavailable", "snapshot_invalid", "Directory snapshot is unavailable.")
		return
	}
	authority := snapshotAuthority(p, phones)
	revision := snapshotRevision(s.snapshotHMACSecret, authority, data)
	offset := 0
	expires := data.ObservedAt.Add(snapshotTTL)
	if cursor != nil {
		if cursor.Revision != revision || cursor.Offset >= data.TotalRecords() {
			deny(http.StatusConflict, snapshotChangedCode, "revision_changed", "Restart the directory snapshot from its first page.")
			return
		}
		offset = cursor.Offset
		data.ObservedAt = cursor.ObservedAt
		expires = cursor.ExpiresAt
	}
	page := data.Page(offset, limit, phones)
	page.Revision = revision
	if !page.Complete {
		page.NextCursor = encodeSnapshotCursor(s.snapshotHMACSecret, authority, directorySnapshotCursor{Revision: revision, Offset: offset + limit, Limit: limit, Phones: phones, ObservedAt: data.ObservedAt, ExpiresAt: expires})
	}
	if !s.auditDirectoryMachineOutcome(w, r, p, directoryCapabilitySnapshot, "", "success", "") {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, page)
}
