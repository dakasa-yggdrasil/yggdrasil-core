package httpapi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
)

const capacityGuestPrincipalsEnv = "YGGDRASIL_CAPACITY_GUEST_PRINCIPALS_JSON"
const guestProvisioningBase = "/internal/capacity/guest-provisioning"
const guestRetirementBase = "/internal/capacity/guest-retirement"

type capacityGuestPrincipalConfig struct {
	PrincipalID           string    `json:"principal_id"`
	Status                string    `json:"status"`
	ExpiresAt             time.Time `json:"expires_at"`
	RotationID            string    `json:"rotation_id"`
	RotatedAt             time.Time `json:"rotated_at"`
	TokenSHA256           string    `json:"token_sha256"`
	Role                  string    `json:"role"`
	BindingName           string    `json:"binding_name"`
	Slot                  int       `json:"slot"`
	ProfileManifestSHA256 string    `json:"profile_manifest_sha256"`
}

type capacityGuestPrincipal struct {
	base       validatedMachinePrincipalBase
	role       string
	binding    string
	slot       int
	profileSHA string
}

func loadCapacityGuestPrincipals(workflows []workflowMachinePrincipal, events []eventPublisherPrincipal, directory []directoryMachinePrincipal, mutations []capacityMutationPrincipal) ([]capacityGuestPrincipal, error) {
	if raw, present := os.LookupEnv(capacityGuestPrincipalsEnv); present && strings.TrimSpace(raw) == "" {
		return nil, fmt.Errorf("%s is set but blank", capacityGuestPrincipalsEnv)
	}
	var config []capacityGuestPrincipalConfig
	if err := decodeMachinePrincipalConfig(capacityGuestPrincipalsEnv, &config); err != nil {
		return nil, err
	}
	if config == nil && os.Getenv(capacityGuestPrincipalsEnv) == "" {
		return nil, nil
	}
	if len(config) == 0 || len(config) > 128 {
		return nil, fmt.Errorf("guest inventory requires exact independent scoped principals")
	}
	ids, digests := map[string]bool{}, map[[sha256.Size]byte]bool{}
	var result []capacityGuestPrincipal
	for index, c := range config {
		base, err := validateMachinePrincipalBase(capacityGuestPrincipalsEnv, index, c.PrincipalID, c.Status, c.ExpiresAt, c.RotationID, c.RotatedAt, c.TokenSHA256)
		if err != nil {
			return nil, err
		}
		if ids[base.principalID] || digests[base.tokenSHA256] || (c.Role != "provisioner" && c.Role != "actor") || c.BindingName == "" || len(c.BindingName) > 64 || containsWildcard(c.BindingName) || strings.TrimSpace(c.BindingName) != c.BindingName || strings.ContainsAny(c.BindingName, "/\x00\r\n") || c.Slot < 1 || c.Slot > 64 || !capacity.ValidDigest(c.ProfileManifestSHA256) {
			return nil, fmt.Errorf("guest principal requires exact role/member/slot/profile")
		}
		collision := false
		for _, other := range workflows {
			collision = collision || machineCredentialDigestsCollide(base.tokenSHA256, other.TokenSHA256)
		}
		for _, other := range events {
			collision = collision || machineCredentialDigestsCollide(base.tokenSHA256, other.TokenSHA256)
		}
		for _, other := range directory {
			collision = collision || machineCredentialDigestsCollide(base.tokenSHA256, other.TokenSHA256)
		}
		for _, other := range mutations {
			collision = collision || machineCredentialDigestsCollide(base.tokenSHA256, other.base.tokenSHA256)
		}
		for _, other := range plaintextMachineCredentialScopes() {
			collision = collision || digestMatchesPlaintext(base.tokenSHA256, other.value)
		}
		if collision {
			return nil, fmt.Errorf("guest principal collides with another credential surface")
		}
		ids[base.principalID], digests[base.tokenSHA256] = true, true
		result = append(result, capacityGuestPrincipal{base: base, role: c.Role, binding: c.BindingName, slot: c.Slot, profileSHA: c.ProfileManifestSHA256})
	}
	return result, nil
}

func capacityGuestPath(value string) bool {
	return value == guestProvisioningBase || strings.HasPrefix(value, guestProvisioningBase+"/") || value == guestRetirementBase || strings.HasPrefix(value, guestRetirementBase+"/")
}

func (s *Server) capacityGuestCredential(r *http.Request) *capacityGuestPrincipal {
	for _, value := range r.Header.Values("Authorization") {
		parts := strings.Fields(value)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || len(parts[1]) > 4096 {
			continue
		}
		for i := range s.capacityGuestPrincipals {
			if machineCredentialMatches(parts[1], s.capacityGuestPrincipals[i].base.tokenSHA256) {
				return &s.capacityGuestPrincipals[i]
			}
		}
	}
	return nil
}

func guestScopeMatches(p *capacityGuestPrincipal, binding model.CapacityGuestRetirementBinding, member model.CapacityGuestRetirementMemberBinding) bool {
	return p != nil && p.binding == member.Name && p.slot == member.Slot && p.profileSHA == binding.ProfileManifestSHA256
}

func guestSecret(ctx context.Context, db *sql.DB, ref string) ([]byte, error) {
	value, err := repository.ResolveSecretRef(ctx, db, ref)
	if err != nil {
		return nil, repository.ErrCapacityMutationAuthorization
	}
	text, ok := value.(string)
	if !ok || text == "" || len(text) > 1<<20 {
		return nil, repository.ErrCapacityMutationAuthorization
	}
	return []byte(text), nil
}

func guestSigningKeys(ctx context.Context, db *sql.DB, binding model.CapacityGuestRetirementBinding) (ed25519.PrivateKey, ed25519.PrivateKey, error) {
	a, err := guestSecret(ctx, db, binding.IntentSigningKeyRef)
	if err != nil {
		return nil, nil, err
	}
	b, err := guestSecret(ctx, db, binding.EnrollmentSigningKeyRef)
	if err != nil {
		return nil, nil, err
	}
	intent, e1 := base64.StdEncoding.DecodeString(string(a))
	enrollment, e2 := base64.StdEncoding.DecodeString(string(b))
	if e1 != nil || e2 != nil || len(intent) != ed25519.PrivateKeySize || len(enrollment) != ed25519.PrivateKeySize || base64.StdEncoding.EncodeToString(intent) != string(a) || base64.StdEncoding.EncodeToString(enrollment) != string(b) || !capacity.GuestLifecycleKeyMatches(ed25519.PrivateKey(enrollment), binding.EnrollmentIssuerPublicKey) || binding.IntentSigningKeyRef == binding.EnrollmentSigningKeyRef {
		return nil, nil, repository.ErrCapacityMutationAuthorization
	}
	return ed25519.PrivateKey(intent), ed25519.PrivateKey(enrollment), nil
}

func guestPrivateHTTPClient(ctx context.Context, db *sql.DB, member model.CapacityGuestRetirementMemberBinding) (*capacity.GuestOriginalHTTPClient, error) {
	ca, err := guestSecret(ctx, db, member.ServerCARef)
	if err != nil {
		return nil, err
	}
	cert, err := guestSecret(ctx, db, member.ClientCertificateRef)
	if err != nil {
		return nil, err
	}
	key, err := guestSecret(ctx, db, member.ClientKeyRef)
	if err != nil {
		return nil, err
	}
	return capacity.NewGuestOriginalHTTPClient(member, ca, cert, key)
}

// This branch claims Guest credentials before all console/workflow/directory
// fallbacks, including expired credentials on unrelated and public routes.
func (s *Server) serveCapacityGuestRequest(w http.ResponseWriter, r *http.Request, p *capacityGuestPrincipal) {
	w.Header().Set("Cache-Control", "no-store")
	if p == nil || len(r.Header.Values("Authorization")) != 1 || p.base.status != "active" || !time.Now().Before(p.base.expiresAt) || r.TLS == nil {
		writeProblemJSON(w, 401, "capacity.guest_unauthorized", "an active exact private Guest credential over TLS is required")
		return
	}
	if !capacityGuestPath(r.URL.Path) || path.Clean(r.URL.Path) != r.URL.Path || r.URL.RawPath != "" || (p.role == "provisioner" && !strings.HasPrefix(r.URL.Path, guestProvisioningBase+"/")) || (p.role == "actor" && !strings.HasPrefix(r.URL.Path, guestRetirementBase+"/")) {
		writeProblemJSON(w, 403, "capacity.guest_scope_denied", "credential is restricted to its original Guest scope")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	store := repository.CapacityStore{DB: s.db, ExecutionEnabled: os.Getenv("YGGDRASIL_CAPACITY_EXECUTION_ENABLED") == "true"}
	if s.db == nil {
		guestHTTPError(w, fmt.Errorf("database unavailable"))
		return
	}
	if r.Method == http.MethodGet && p.role == "actor" {
		if r.URL.Path == model.GuestRetirementV2AuthorityPath {
			s.serveGuestOriginalAuthorityV2(w, r.WithContext(ctx), p, store)
		} else {
			s.serveGuestOriginalAuthority(w, r.WithContext(ctx), p, store)
		}
		return
	}
	if r.URL.RawQuery != "" {
		guestHTTPError(w, repository.ErrCapacityMutationAuthorization)
		return
	}
	if r.Method == http.MethodPost && r.URL.Path == guestProvisioningBase+"/registrations" {
		r.Body = http.MaxBytesReader(w, r.Body, capacity.GuestBootstrapLimit)
		raw, err := io.ReadAll(r.Body)
		var registration model.CapacityGuestOriginalProvisioningRegistration
		if err != nil || capacity.DecodeGuestLifecycle(raw, &registration) != nil {
			writeProblemJSON(w, 400, "capacity.guest_invalid", "closed original provisioning registration required")
			return
		}
		binding, member, err := store.GuestProvisioningCallbackScope(ctx, p.base.principalID, registration.Result.PreregistrationID)
		if err != nil || !guestScopeMatches(p, binding, member) {
			guestHTTPError(w, repository.ErrCapacityMutationAuthorization)
			return
		}
		intent, enrollment, err := guestSigningKeys(ctx, s.db, binding)
		if err != nil {
			guestHTTPError(w, err)
			return
		}
		receipt, err := store.RegisterOriginalGuest(ctx, p.base.principalID, registration, intent, enrollment)
		if err != nil {
			guestHTTPError(w, err)
			return
		}
		guestCanonicalReply(w, receipt)
		return
	}
	if r.Method == http.MethodPost && r.URL.Path == guestProvisioningBase+"/installations" {
		r.Body = http.MaxBytesReader(w, r.Body, capacity.GuestBootstrapLimit)
		raw, err := io.ReadAll(r.Body)
		var confirmation model.CapacityGuestOriginalInstallationConfirmation
		if err != nil || capacity.DecodeGuestLifecycle(raw, &confirmation) != nil {
			writeProblemJSON(w, 400, "capacity.guest_invalid", "closed original installation confirmation required")
			return
		}
		canonical, encodeErr := json.Marshal(confirmation)
		if encodeErr != nil || !bytes.Equal(raw, canonical) {
			writeProblemJSON(w, 400, "capacity.guest_invalid", "canonical original installation confirmation required")
			return
		}
		binding, member, err := store.GuestProvisioningCallbackScope(ctx, p.base.principalID, confirmation.PreregistrationID)
		if err != nil || !guestScopeMatches(p, binding, member) {
			guestHTTPError(w, repository.ErrCapacityMutationAuthorization)
			return
		}
		accepted, err := store.RegisterOriginalGuestInstallation(ctx, p.base.principalID, confirmation)
		if err != nil {
			guestHTTPError(w, err)
			return
		}
		guestCanonicalReply(w, accepted)
		return
	}
	if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, guestProvisioningBase+"/bindings/") {
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, guestProvisioningBase+"/bindings/"), "/")
		if len(parts) != 4 || parts[1] != "slots" || (parts[3] != "original" && parts[3] != "original-profile") || parts[0] != p.binding {
			guestHTTPError(w, repository.ErrCapacityMutationAuthorization)
			return
		}
		slot, err := strconv.Atoi(parts[2])
		profile := r.Header.Values("X-Guest-Profile-Manifest-SHA256")
		native := r.Header.Values("X-Guest-Native-Resource-ID")
		profileRead := parts[3] == "original-profile"
		profileHeaderValid := (!profileRead && len(profile) == 1 && profile[0] == p.profileSHA) || (profileRead && len(profile) == 0)
		if err != nil || strconv.Itoa(slot) != parts[2] || slot != p.slot || !profileHeaderValid || len(native) != 1 || native[0] == "" || len(native[0]) > 128 || strings.ContainsAny(native[0], "/ \t\x00\r\n") {
			guestHTTPError(w, repository.ErrCapacityMutationAuthorization)
			return
		}
		if profileRead {
			manifest, err := store.GuestOriginalProfile(ctx, p.base.principalID, p.binding, slot, p.profileSHA, native[0])
			if errors.Is(err, repository.ErrGuestOriginalCreatePending) {
				guestOriginalProfilePendingReply(w)
				return
			}
			if err != nil {
				guestHTTPError(w, err)
				return
			}
			guestCanonicalReply(w, manifest)
			return
		}
		pre, err := store.GuestExactOriginalLookup(ctx, p.base.principalID, p.binding, slot, profile[0], native[0])
		if err != nil {
			guestHTTPError(w, err)
			return
		}
		guestCanonicalReply(w, pre)
		return
	}
	if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, guestProvisioningBase+"/preregistrations/") {
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, guestProvisioningBase+"/preregistrations/"), "/")
		if len(parts) < 1 || len(parts) > 2 {
			guestHTTPError(w, repository.ErrCapacityMutationAuthorization)
			return
		}
		id, err := uuid.Parse(parts[0])
		nonce := r.Header.Values("X-Guest-Preregistration-Nonce-SHA256")
		if err != nil || id == uuid.Nil || id.String() != parts[0] || len(nonce) != 1 || !capacity.ValidDigest(nonce[0]) {
			guestHTTPError(w, repository.ErrCapacityMutationAuthorization)
			return
		}
		binding, member, err := store.GuestProvisioningCallbackScope(ctx, p.base.principalID, id.String())
		if err != nil || !guestScopeMatches(p, binding, member) {
			guestHTTPError(w, repository.ErrCapacityMutationAuthorization)
			return
		}
		var out any
		if len(parts) == 2 && parts[1] == "create-witness" {
			out, err = store.GuestCreateWitness(ctx, p.base.principalID, id.String(), nonce[0])
		} else if len(parts) == 1 {
			out, err = store.GuestProvisioningReceipt(ctx, p.base.principalID, id.String(), nonce[0])
		} else {
			err = repository.ErrCapacityMutationAuthorization
		}
		if err != nil {
			guestHTTPError(w, err)
			return
		}
		guestCanonicalReply(w, out)
		return
	}
	writeProblemJSON(w, 404, "capacity.guest_not_found", "exact original Guest route required")
}

func (s *Server) serveGuestOriginalAuthority(w http.ResponseWriter, r *http.Request, p *capacityGuestPrincipal, store repository.CapacityStore) {
	if !strings.HasPrefix(r.URL.Path, guestRetirementBase+"/intents/") {
		guestHTTPError(w, repository.ErrCapacityMutationAuthorization)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, guestRetirementBase+"/intents/")
	parsed, err := uuid.Parse(id)
	phase := r.URL.Query().Get("phase")
	hash := r.Header.Values("X-Guest-Retirement-Intent-SHA256")
	if err != nil || parsed == uuid.Nil || parsed.String() != id || (phase != "before_start" && phase != "before_poweroff") || r.URL.RawQuery != "phase="+phase || len(hash) != 1 || !capacity.ValidDigest(hash[0]) {
		guestHTTPError(w, repository.ErrCapacityMutationAuthorization)
		return
	}
	original, err := store.GuestRetirementOriginal(r.Context(), p.base.principalID, id, hash[0])
	if err != nil || !guestScopeMatches(p, original.Binding, original.Member) {
		guestHTTPError(w, repository.ErrCapacityMutationAuthorization)
		return
	}
	intent, _, err := guestSigningKeys(r.Context(), s.db, original.Binding)
	if err != nil {
		guestHTTPError(w, err)
		return
	}
	client, err := guestPrivateHTTPClient(r.Context(), s.db, original.Member)
	if err != nil {
		guestHTTPError(w, err)
		return
	}
	defer client.Close()
	read, err := store.ReserveGuestAuthorityRead(r.Context(), p.base.principalID, id, hash[0], phase, intent)
	if err != nil {
		guestHTTPError(w, err)
		return
	}
	ctx, cancel := context.WithDeadline(r.Context(), read.Deadline)
	defer cancel()
	if read.Challenge != nil {
		body, err := json.Marshal(model.CapacityGuestRuntimeSnapshotRequest{Challenge: *read.Challenge})
		if err != nil {
			guestHTTPError(w, err)
			return
		}
		returned, err := client.Original(ctx, http.MethodGet, "/v1/runtime-snapshot", body)
		var snapshot model.CapacityGuestRuntimeSnapshot
		retention, cancelRetention := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		retainedErr := store.RecordGuestAuthorityTransport(retention, read, "snapshot", returned)
		cancelRetention()
		if retainedErr != nil || err != nil || capacity.GuestOriginalHTTPDecode(returned, &snapshot) != nil || store.RecordGuestSnapshot(ctx, read, snapshot) != nil {
			guestHTTPError(w, repository.ErrCapacityConflict)
			return
		}
	}
	var observation *model.CapacityGuestRetirementObservation
	if phase == "before_poweroff" || read.Ordinal > 1 {
		body, err := json.Marshal(original.Request)
		if err != nil {
			guestHTTPError(w, err)
			return
		}
		returned, err := client.Original(ctx, http.MethodGet, "/v1/retirement", body)
		var observed model.CapacityGuestRetirementObservation
		retention, cancelRetention := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		retainedErr := store.RecordGuestAuthorityTransport(retention, read, "journal", returned)
		cancelRetention()
		if retainedErr != nil || err != nil || capacity.GuestOriginalHTTPDecode(returned, &observed) != nil || store.RecordGuestObservation(ctx, id, observed) != nil {
			guestHTTPError(w, repository.ErrCapacityConflict)
			return
		}
		observation = &observed
	}
	authority, err := store.FinishGuestAuthorityRead(ctx, read, observation)
	if err != nil {
		guestHTTPError(w, err)
		return
	}
	guestCanonicalReply(w, authority)
}

func guestCanonicalReply(w http.ResponseWriter, value any) {
	raw, err := json.Marshal(value)
	if err != nil {
		guestHTTPError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	_, _ = w.Write(raw)
}

func guestHTTPError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, repository.ErrCapacityMutationAuthorization), errors.Is(err, sql.ErrNoRows):
		writeProblemJSON(w, 403, "capacity.guest_scope_denied", "exact original Guest scope required")
	case errors.Is(err, repository.ErrCapacityConflict), errors.Is(err, repository.ErrCapacityLease), errors.Is(err, repository.ErrCapacityDisabled):
		writeProblemJSON(w, 409, "capacity.guest_hold", "original Guest authority is expired, reserved or unresolved; recover by exact GET")
	default:
		writeProblemJSON(w, 503, "capacity.guest_unavailable", "original durable Guest state unavailable; recover by exact GET")
	}
}

// A fixed non-authoritative signal; no tuple, profile or native ID is exposed.
func guestOriginalProfilePendingReply(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusTooEarly)
	_, _ = w.Write([]byte(`{"schema":"original_guest_profile_pending_v1","code":"original_create_pending"}`))
}
