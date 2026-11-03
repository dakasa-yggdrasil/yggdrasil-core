package httpapi

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
)

const hostFactoryPrincipalsEnv = "YGGDRASIL_HOST_FACTORY_MACHINE_PRINCIPALS_JSON"
const hostFactoryRouteBase = "/internal/capacity/host-original-factories"
const hostOrdinaryGuardBase = hostFactoryRouteBase + "/ordinary/attempts"

type hostFactoryPrincipalConfig struct {
	PrincipalID   string    `json:"principal_id"`
	Status        string    `json:"status"`
	ExpiresAt     time.Time `json:"expires_at"`
	RotationID    string    `json:"rotation_id"`
	RotatedAt     time.Time `json:"rotated_at"`
	TokenSHA256   string    `json:"token_sha256"`
	Role          string    `json:"role"`
	RootID        string    `json:"root_id"`
	OwnerID       string    `json:"owner_id"`
	BindingSchema string    `json:"binding_schema"`
	BindingSHA256 string    `json:"binding_sha256"`
	ScopeSHA256   string    `json:"scope_sha256"`
}

type hostFactoryPrincipal struct {
	base                                                       validatedMachinePrincipalBase
	role, rootID, ownerID, bindingSchema, bindingSHA, scopeSHA string
}

func hostFactoryUUID(s string) bool {
	x, e := uuid.Parse(s)
	return e == nil && x != uuid.Nil && x.String() == s
}
func hostFactoryBinding(s string) bool {
	return s == "original_host_factory_source_approval_v4" || s == "original_host_factory_root_preparation_v4" || s == "original_host_factory_pre_authority_scope_v4" || s == "factory_ordinary_source_binding_v4"
}

func validateOriginalHostInventory(raw string) error {
	if len(raw) < 2 || len(raw) > 65536 {
		return fmt.Errorf("bounded exact host factory inventory required")
	}
	keys := map[string]bool{"principal_id": true, "status": true, "expires_at": true, "rotation_id": true, "rotated_at": true, "token_sha256": true, "role": true, "root_id": true, "owner_id": true, "binding_schema": true, "binding_sha256": true, "scope_sha256": true}
	d := json.NewDecoder(strings.NewReader(raw))
	first, err := d.Token()
	if err != nil || first != json.Delim('[') {
		return fmt.Errorf("host factory inventory array required")
	}
	count := 0
	for d.More() {
		count++
		if count > 128 {
			return fmt.Errorf("host factory inventory bound exceeded")
		}
		token, err := d.Token()
		if err != nil || token != json.Delim('{') {
			return fmt.Errorf("host factory principal object required")
		}
		seen := map[string]bool{}
		for d.More() {
			token, err = d.Token()
			key, ok := token.(string)
			if err != nil || !ok || !keys[key] || seen[key] {
				return fmt.Errorf("exact unique host factory inventory fields required")
			}
			seen[key] = true
			var value json.RawMessage
			if d.Decode(&value) != nil || string(value) == "null" {
				return fmt.Errorf("null host factory inventory field refused")
			}
		}
		if token, err = d.Token(); err != nil || token != json.Delim('}') || len(seen) != len(keys) {
			return fmt.Errorf("complete host factory principal required")
		}
	}
	if token, err := d.Token(); err != nil || token != json.Delim(']') || count == 0 {
		return fmt.Errorf("nonempty host factory inventory required")
	}
	if _, err = d.Token(); !errors.Is(err, io.EOF) {
		return fmt.Errorf("host factory inventory trailing data refused")
	}
	return nil
}

func originalHostHeader(r *http.Request, name, value string) bool {
	count := 0
	for key, values := range r.Header {
		if strings.EqualFold(key, name) {
			for _, v := range values {
				count++
				if v != value {
					return false
				}
			}
		}
	}
	if value == "" {
		return count == 0
	}
	return count == 1
}

func (s *Server) loadOriginalHostPrincipals(events []eventPublisherPrincipal, directory []directoryMachinePrincipal) error {
	if raw, present := os.LookupEnv(hostFactoryPrincipalsEnv); present && strings.TrimSpace(raw) == "" {
		return fmt.Errorf("host factory inventory set but blank")
	}
	if raw, present := os.LookupEnv(hostFactoryPrincipalsEnv); present {
		if err := validateOriginalHostInventory(raw); err != nil {
			return err
		}
	}
	var config []hostFactoryPrincipalConfig
	if err := decodeMachinePrincipalConfig(hostFactoryPrincipalsEnv, &config); err != nil {
		return err
	}
	if config == nil && os.Getenv(hostFactoryPrincipalsEnv) == "" {
		return nil
	}
	if len(config) < 1 || len(config) > 128 {
		return fmt.Errorf("bounded exact host factory inventory required")
	}
	ids, digests := map[string]bool{}, map[[sha256.Size]byte]bool{}
	for i, c := range config {
		base, err := validateMachinePrincipalBase(hostFactoryPrincipalsEnv, i, c.PrincipalID, c.Status, c.ExpiresAt, c.RotationID, c.RotatedAt, c.TokenSHA256)
		if err != nil {
			return err
		}
		role := c.Role == "host_exterior" || c.Role == "host_registrar" || c.Role == "host_worker" || c.Role == "factory_ordinary_worker" || c.Role == "factory_ordinary_guard_reader"
		if !role || !hostFactoryUUID(c.RootID) || !hostFactoryUUID(c.OwnerID) || !hostFactoryBinding(c.BindingSchema) || !capacity.ValidDigest(c.BindingSHA256) || ids[c.PrincipalID] || digests[base.tokenSHA256] {
			return fmt.Errorf("exact separate host factory role/root/binding required")
		}
		if c.BindingSchema == "original_host_factory_pre_authority_scope_v4" {
			if c.ScopeSHA256 != c.BindingSHA256 || c.Role == "factory_ordinary_worker" || c.Role == "factory_ordinary_guard_reader" {
				return fmt.Errorf("exact Host scope principal required")
			}
		} else if c.ScopeSHA256 != "" || c.Role == "host_worker" || ((c.Role == "factory_ordinary_worker" || c.Role == "factory_ordinary_guard_reader") && c.BindingSchema != "factory_ordinary_source_binding_v4") {
			return fmt.Errorf("root principal cannot use Scope binding")
		}
		collision := false
		for _, other := range s.workflowRunAuth.principals {
			collision = collision || machineCredentialDigestsCollide(base.tokenSHA256, other.TokenSHA256)
		}
		for _, other := range events {
			collision = collision || machineCredentialDigestsCollide(base.tokenSHA256, other.TokenSHA256)
		}
		for _, other := range directory {
			collision = collision || machineCredentialDigestsCollide(base.tokenSHA256, other.TokenSHA256)
		}
		for _, other := range s.capacityMutationPrincipals {
			collision = collision || machineCredentialDigestsCollide(base.tokenSHA256, other.base.tokenSHA256)
		}
		for _, other := range s.capacityGuestPrincipals {
			collision = collision || machineCredentialDigestsCollide(base.tokenSHA256, other.base.tokenSHA256)
		}
		for _, other := range plaintextMachineCredentialScopes() {
			collision = collision || digestMatchesPlaintext(base.tokenSHA256, other.value)
		}
		if collision {
			return fmt.Errorf("host factory credential collides with another surface")
		}
		ids[c.PrincipalID], digests[base.tokenSHA256] = true, true
		s.capacityHostFactoryPrincipals = append(s.capacityHostFactoryPrincipals, hostFactoryPrincipal{base, c.Role, c.RootID, c.OwnerID, c.BindingSchema, c.BindingSHA256, c.ScopeSHA256})
	}
	return nil
}

func hostFactoryPath(value string) bool {
	return value == hostFactoryRouteBase || strings.HasPrefix(value, hostFactoryRouteBase+"/") || value == hostOrdinaryGuardBase || strings.HasPrefix(value, hostOrdinaryGuardBase+"/")
}

func (s *Server) originalHostCredential(r *http.Request) *hostFactoryPrincipal {
	for _, value := range r.Header.Values("Authorization") {
		parts := strings.Fields(value)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || len(parts[1]) > 4096 {
			continue
		}
		for i := range s.capacityHostFactoryPrincipals {
			if machineCredentialMatches(parts[1], s.capacityHostFactoryPrincipals[i].base.tokenSHA256) {
				return &s.capacityHostFactoryPrincipals[i]
			}
		}
	}
	return nil
}

func originalHostHTTPStage(role, stage, family string) bool {
	root := map[string][]string{
		"host_exterior":           {"basal-owner-core", "bootstrap-return-core", "root-preparation", "native-leaf-registrar-by-core", "root-completion", "bootstrap-write-registrar", "ordinary-bootstrap-write"},
		"host_registrar":          {"basal-owner-registrar", "bootstrap-return-registrar", "native-leaf-core-by-registrar", "initial-empty-realm-read", "ordinary-native-leaf-worker"},
		"factory_ordinary_worker": {"ordinary-basal-owner", "ordinary-bootstrap-return", "ordinary-prepared-create-plan"},
	}
	scope := map[string][]string{
		"host_exterior":  {"original-start-return", "exterior-join", "bootstrap-write-worker"},
		"host_worker":    {"basal-owner-worker", "bootstrap-return-worker", "prepared-create-plan", "choice-return"},
		"host_registrar": {"native-leaf-worker", "alive-native-read", "poststart-empty-realm-read", "terminal-read"},
	}
	allowed := root[role]
	if family == "scope" {
		allowed = scope[role]
	}
	for _, v := range allowed {
		if v == stage {
			return true
		}
	}
	return false
}

// Dedicated credentials are claimed before every console/Guest/mutation/
// workflow/public fallback, including expired credentials on foreign paths.
func (s *Server) serveOriginalHostRequest(w http.ResponseWriter, r *http.Request, p *hostFactoryPrincipal) {
	w.Header().Set("Cache-Control", "no-store")
	deny := func(status int) {
		writeProblemJSON(w, status, "capacity.host_factory_unavailable", "exact original source-owned factory request required")
	}
	if p == nil || len(r.Header.Values("Authorization")) != 1 || p.base.status != "active" || !time.Now().Before(p.base.expiresAt) || r.TLS == nil {
		deny(401)
		return
	}
	if r.URL.RawPath != "" || r.URL.Path != path.Clean(r.URL.Path) || r.URL.EscapedPath() != r.URL.Path || !hostFactoryPath(r.URL.Path) {
		deny(403)
		return
	}
	query, queryErr := url.ParseQuery(r.URL.RawQuery)
	if queryErr != nil || !originalHostHeader(r, "X-Factory-Ordinary-Binding-SHA256", map[bool]string{true: p.bindingSHA, false: ""}[p.role == "factory_ordinary_guard_reader"]) {
		deny(403)
		return
	}
	if p.role == "factory_ordinary_guard_reader" {
		guardPath := strings.Split(strings.TrimPrefix(r.URL.Path, hostOrdinaryGuardBase+"/"), "/")
		phase := query.Get("phase")
		if r.Method != "GET" || !strings.HasPrefix(r.URL.Path, hostOrdinaryGuardBase+"/") || len(guardPath) != 2 || !hostFactoryUUID(guardPath[0]) || guardPath[1] != "grant-guard" || len(query) != 3 || len(query["grant_id"]) != 1 || len(query["preregistration_id"]) != 1 || len(query["phase"]) != 1 || !hostFactoryUUID(query.Get("grant_id")) || !hostFactoryUUID(query.Get("preregistration_id")) || (phase != "before_redeem" && phase != "after_redeem" && phase != "before_start") || !originalHostHeader(r, "X-Host-Original-Scope-SHA256", "") || !originalHostHeader(r, "X-Host-Original-Binding-Schema", "") || !originalHostHeader(r, "X-Host-Original-Binding-SHA256", "") {
			deny(403)
			return
		}
		selector := repository.HostFactoryRecordSelector{Family: "root", RootID: p.rootID, OwnerID: p.ownerID, Role: p.role, BindingSchema: p.bindingSchema, BindingSHA256: p.bindingSHA}
		raw, err := (repository.CapacityStore{DB: s.db}).ReadOriginalOrdinaryHostGuard(r.Context(), selector, guardPath[0], query.Get("grant_id"), query.Get("preregistration_id"), phase)
		if err != nil {
			deny(503)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(raw)
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, hostFactoryRouteBase+"/"), "/")
	if len(parts) < 4 || (r.Method != "GET" && r.Method != "POST") {
		deny(403)
		return
	}
	family := "root"
	if parts[0] == "scopes" {
		family = "scope"
	} else if parts[0] != "roots" {
		deny(403)
		return
	}
	selector := repository.HostFactoryRecordSelector{Family: family, RootID: p.rootID, OwnerID: p.ownerID, Role: p.role, BindingSchema: p.bindingSchema, BindingSHA256: p.bindingSHA}
	if family == "root" {
		if parts[1] != p.rootID || !originalHostHeader(r, "X-Host-Original-Scope-SHA256", "") || !originalHostHeader(r, "X-Host-Original-Binding-Schema", p.bindingSchema) || !originalHostHeader(r, "X-Host-Original-Binding-SHA256", p.bindingSHA) || p.scopeSHA != "" {
			deny(403)
			return
		}
	} else {
		if parts[1] != p.scopeSHA || !capacity.ValidDigest(parts[1]) || !originalHostHeader(r, "X-Host-Original-Scope-SHA256", parts[1]) || !originalHostHeader(r, "X-Host-Original-Binding-Schema", "") || !originalHostHeader(r, "X-Host-Original-Binding-SHA256", "") {
			deny(403)
			return
		}
		selector.ScopeSHA256 = parts[1]
	}
	switch parts[2] {
	case "stages":
		if len(parts) != 4 || !originalHostHTTPStage(p.role, parts[3], family) {
			deny(403)
			return
		}
		if r.Method == "GET" {
			if len(query) != 1 || len(query["sha256"]) != 1 || !capacity.ValidDigest(query.Get("sha256")) {
				deny(403)
				return
			}
			selector.RawBodySHA256 = query.Get("sha256")
		} else if len(query) != 0 {
			deny(403)
			return
		}
		selector.Stage = parts[3]
	case "io-calls":
		if len(query) != 0 || len(parts) != 6 || !hostFactoryUUID(parts[3]) || (parts[4] != "chunk" && parts[4] != "manifest" && parts[4] != "inventory") || !capacity.ValidDigest(parts[5]) {
			deny(403)
			return
		}
		selector.RawBodySHA256 = parts[5]
		selector.Kind, selector.HandleID = parts[4], parts[3]
	case "failure-collections":
		if len(query) != 1 || len(query["sha256"]) != 1 || !capacity.ValidDigest(query.Get("sha256")) || len(parts) != 6 || !hostFactoryUUID(parts[3]) || parts[4] != "parts" {
			deny(403)
			return
		}
		selector.RawBodySHA256 = query.Get("sha256")
		ordinal, err := strconv.ParseUint(parts[5], 10, 32)
		if err != nil || ordinal < 1 || ordinal > 2048 || strconv.FormatUint(ordinal, 10) != parts[5] {
			deny(403)
			return
		}
		selector.Kind, selector.CollectionID, selector.PartOrdinal = "failure-part", parts[3], uint32(ordinal)
	default:
		deny(403)
		return
	}
	store := repository.CapacityStore{DB: s.db}
	if r.Method == "GET" {
		raw, err := store.GetOriginalHostRecord(r.Context(), selector)
		if err != nil {
			deny(503)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(raw)
		return
	}
	if r.Body == nil {
		deny(400)
		return
	}
	raw, readErr := io.ReadAll(io.LimitReader(r.Body, 65537))
	closeErr := r.Body.Close()
	if readErr != nil || closeErr != nil || len(raw) < 1 || len(raw) > 65536 || r.Context().Err() != nil {
		deny(400)
		return
	}
	if err := store.AppendOriginalHostRecord(r.Context(), selector, raw); err != nil {
		deny(503)
		return
	}
	w.WriteHeader(http.StatusCreated)
}
