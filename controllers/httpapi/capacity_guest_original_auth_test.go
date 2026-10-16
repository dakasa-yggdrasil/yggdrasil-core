package httpapi

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

func guestOriginalAuthConfig(token, role string) capacityGuestPrincipalConfig {
	digest := sha256.Sum256([]byte(token))
	return capacityGuestPrincipalConfig{PrincipalID: "guest-original-" + role, Status: "active", ExpiresAt: time.Now().Add(time.Hour), RotationID: "original-independent-rotation", TokenSHA256: hex.EncodeToString(digest[:]), Role: role, BindingName: "original-member", Slot: 2, ProfileManifestSHA256: strings.Repeat("a", 64)}
}

func guestOriginalAuthInventory(t *testing.T, config ...capacityGuestPrincipalConfig) []capacityGuestPrincipal {
	t.Helper()
	raw, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(capacityGuestPrincipalsEnv, string(raw))
	principals, err := loadCapacityGuestPrincipals(nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return principals
}

// These tests exercise the public auth middleware, rather than attaching a
// collaborator claim or calling a successful private handler directly. A test
// credential is never an original native provisioning or completion receipt.
func TestCapacityGuestOriginalAuth(t *testing.T) {
	const token = "ci-only-original-guest-actor-bearer"
	for _, test := range []struct {
		name, role, method, target, credential string
		status                                 int
		mutate                                 func(*http.Request, *Server)
	}{
		{name: "unconfigured_private_route", role: "actor", method: "GET", target: "https://core.invalid" + guestRetirementBase + "/intents/original?phase=before_start", status: 401},
		{name: "human_session_cannot_enter_guest", role: "actor", method: "POST", target: "https://core.invalid" + guestProvisioningBase + "/registrations", credential: "human-session", status: 401},
		{name: "actor_cannot_read_public_health", role: "actor", method: "GET", target: "https://core.invalid/healthz", credential: token, status: 403},
		{name: "actor_cannot_dispatch_workflow", role: "actor", method: "POST", target: "https://core.invalid/api/v1/workflow-runs", credential: token, status: 403},
		{name: "actor_cannot_publish_events", role: "actor", method: "POST", target: "https://core.invalid/api/v1/events", credential: token, status: 403},
		{name: "actor_cannot_write_manifest", role: "actor", method: "POST", target: "https://core.invalid/api/v1/manifests", credential: token, status: 403},
		{name: "actor_cannot_use_provisioner_path", role: "actor", method: "POST", target: "https://core.invalid" + guestProvisioningBase + "/registrations", credential: token, status: 403},
		{name: "provisioner_cannot_use_actor_path", role: "provisioner", method: "GET", target: "https://core.invalid" + guestRetirementBase + "/intents/original?phase=before_start", credential: token, status: 403},
		{name: "dot_segment_refused_before_mux_redirect", role: "actor", method: "GET", target: "https://core.invalid" + guestRetirementBase + "/intents/../original", credential: token, status: 403},
		{name: "escaped_path_refused", role: "actor", method: "GET", target: "https://core.invalid" + guestRetirementBase + "/intents/%6Friginal", credential: token, status: 403},
		{name: "expired_credential_still_claims_public_route", role: "actor", method: "GET", target: "https://core.invalid/healthz", credential: token, status: 401, mutate: func(_ *http.Request, s *Server) {
			s.capacityGuestPrincipals[0].base.expiresAt = time.Now().Add(-time.Hour)
		}},
		{name: "revoked_credential_still_claims_public_route", role: "actor", method: "GET", target: "https://core.invalid/healthz", credential: token, status: 401, mutate: func(_ *http.Request, s *Server) { s.capacityGuestPrincipals[0].base.status = "revoked" }},
		{name: "disabled_credential_still_claims_workflow_route", role: "actor", method: "POST", target: "https://core.invalid/api/v1/workflow-runs", credential: token, status: 401, mutate: func(_ *http.Request, s *Server) { s.capacityGuestPrincipals[0].base.status = "disabled" }},
		{name: "plaintext_transport_refused", role: "actor", method: "GET", target: "http://core.invalid" + guestRetirementBase + "/intents/original?phase=before_start", credential: token, status: 401},
		{name: "ambiguous_bearers_do_not_fall_through", role: "actor", method: "GET", target: "https://core.invalid/healthz", credential: token, status: 401, mutate: func(r *http.Request, _ *Server) { r.Header.Add("Authorization", "Bearer human-session") }},
		{name: "guest_cannot_become_original_canary", role: "actor", method: "GET", target: "https://core.invalid" + capacityOriginalCanaryAuthorityPath, credential: token, status: 403, mutate: func(r *http.Request, _ *Server) {
			r.Header.Set(capacityOriginalCanaryAuthorityHeader, strings.Repeat("a", 64))
			r.Header.Set(capacityOriginalCanaryScopeHeader, strings.Repeat("b", 64))
		}},
		{name: "guest_cannot_become_directory_reader", role: "actor", method: "GET", target: "https://core.invalid/api/v1/collaborators/by-email", credential: token, status: 403, mutate: func(r *http.Request, _ *Server) { r.Header.Set(directoryMachineTokenHeader, "directory-bearer") }},
		{name: "database_unavailable_retains_private_claim", role: "actor", method: "GET", target: "https://core.invalid" + guestRetirementBase + "/intents/original?phase=before_start", credential: token, status: 503},
	} {
		t.Run(test.name, func(t *testing.T) {
			s := &Server{capacityGuestPrincipals: guestOriginalAuthInventory(t, guestOriginalAuthConfig(token, test.role))}
			calls := 0
			h := s.requireAuthenticatedConsoleAPIs(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { calls++; w.WriteHeader(http.StatusNoContent) }))
			r := httptest.NewRequest(test.method, test.target, strings.NewReader("{}"))
			if test.credential != "" {
				r.Header.Set("Authorization", "Bearer "+test.credential)
			}
			r.AddCookie(&http.Cookie{Name: authSessionCookieName(), Value: "human-cookie"})
			if test.mutate != nil {
				test.mutate(r, s)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != test.status || calls != 0 || strings.Contains(w.Body.String(), token) || strings.Contains(w.Body.String(), "human-cookie") {
				t.Fatalf("Guest branch: status=%d fallthrough=%d body=%s", w.Code, calls, w.Body.String())
			}
			if w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("private refusal is cacheable")
			}
		})
	}
}

func TestCapacityGuestOriginalInventory(t *testing.T) {
	const token = "ci-only-distinct-original-provisioner-bearer"
	t.Run("unset_is_default_off", func(t *testing.T) {
		old, present := os.LookupEnv(capacityGuestPrincipalsEnv)
		if err := os.Unsetenv(capacityGuestPrincipalsEnv); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if present {
				_ = os.Setenv(capacityGuestPrincipalsEnv, old)
			} else {
				_ = os.Unsetenv(capacityGuestPrincipalsEnv)
			}
		})
		p, err := loadCapacityGuestPrincipals(nil, nil, nil, nil)
		if err != nil || len(p) != 0 {
			t.Fatalf("default-off inventory: %d %v", len(p), err)
		}
	})
	for name, raw := range map[string]string{"blank": "", "whitespace": "  ", "null": "null", "empty": "[]", "object": "{}", "unknown": `[{"principal_id":"guest","authority":true}]`, "trailing": "[] []"} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(capacityGuestPrincipalsEnv, raw)
			if _, err := loadCapacityGuestPrincipals(nil, nil, nil, nil); err == nil {
				t.Fatal("invalid inventory accepted")
			}
		})
	}
	for name, mutate := range map[string]func(*capacityGuestPrincipalConfig){
		"unscoped_role":      func(c *capacityGuestPrincipalConfig) { c.Role = "admin" },
		"wildcard_member":    func(c *capacityGuestPrincipalConfig) { c.BindingName = "guest-*" },
		"member_path":        func(c *capacityGuestPrincipalConfig) { c.BindingName = "guest/member" },
		"member_space":       func(c *capacityGuestPrincipalConfig) { c.BindingName = " guest" },
		"slot_zero":          func(c *capacityGuestPrincipalConfig) { c.Slot = 0 },
		"slot_above_bound":   func(c *capacityGuestPrincipalConfig) { c.Slot = 65 },
		"profile_not_digest": func(c *capacityGuestPrincipalConfig) { c.ProfileManifestSHA256 = "caller-complete" },
		"missing_rotation":   func(c *capacityGuestPrincipalConfig) { c.RotationID = "" },
		"missing_expiry":     func(c *capacityGuestPrincipalConfig) { c.ExpiresAt = time.Time{} },
	} {
		t.Run(name, func(t *testing.T) {
			c := guestOriginalAuthConfig(token, "provisioner")
			mutate(&c)
			raw, _ := json.Marshal([]capacityGuestPrincipalConfig{c})
			t.Setenv(capacityGuestPrincipalsEnv, string(raw))
			if _, err := loadCapacityGuestPrincipals(nil, nil, nil, nil); err == nil {
				t.Fatal("unscoped original credential accepted")
			}
		})
	}
	t.Run("independent_actor_and_provisioner", func(t *testing.T) {
		p := guestOriginalAuthInventory(t, guestOriginalAuthConfig(token, "provisioner"), guestOriginalAuthConfig("ci-only-independent-actor-bearer", "actor"))
		if len(p) != 2 || p[0].base.tokenSHA256 == p[1].base.tokenSHA256 {
			t.Fatal("credential separation lost")
		}
	})
	t.Run("duplicate_identity_or_digest", func(t *testing.T) {
		for _, identity := range []bool{true, false} {
			a, b := guestOriginalAuthConfig(token, "provisioner"), guestOriginalAuthConfig("another-actor", "actor")
			if identity {
				b.PrincipalID = a.PrincipalID
			} else {
				b.TokenSHA256 = a.TokenSHA256
			}
			raw, _ := json.Marshal([]capacityGuestPrincipalConfig{a, b})
			t.Setenv(capacityGuestPrincipalsEnv, string(raw))
			if _, err := loadCapacityGuestPrincipals(nil, nil, nil, nil); err == nil {
				t.Fatal("duplicate original inventory accepted")
			}
		}
	})
	for _, family := range []string{"workflow", "event", "directory", "mutation", "YGGDRASIL_WORKFLOW_RUN_TOKEN", legacyEventPublishTokenEnv, "YGGDRASIL_DEPLOY_TOKEN", "YGGDRASIL_AUTH_ADMIN_TOKEN"} {
		t.Run("collision_"+family, func(t *testing.T) {
			p := guestOriginalAuthInventory(t, guestOriginalAuthConfig(token, "provisioner"))
			var wf []workflowMachinePrincipal
			var ev []eventPublisherPrincipal
			var dir []directoryMachinePrincipal
			var mut []capacityMutationPrincipal
			switch family {
			case "workflow":
				wf = []workflowMachinePrincipal{{TokenSHA256: p[0].base.tokenSHA256}}
			case "event":
				ev = []eventPublisherPrincipal{{TokenSHA256: p[0].base.tokenSHA256}}
			case "directory":
				dir = []directoryMachinePrincipal{{TokenSHA256: p[0].base.tokenSHA256}}
			case "mutation":
				mut = []capacityMutationPrincipal{{base: p[0].base}}
			default:
				t.Setenv(family, token)
			}
			if _, err := loadCapacityGuestPrincipals(wf, ev, dir, mut); err == nil {
				t.Fatal("credential collision accepted")
			}
		})
	}
}

func TestCapacityGuestOriginalClosedRegistration(t *testing.T) {
	const token = "ci-only-closed-original-provisioner"
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s := &Server{db: db, capacityGuestPrincipals: guestOriginalAuthInventory(t, guestOriginalAuthConfig(token, "provisioner"))}
	h := s.requireAuthenticatedConsoleAPIs(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) { t.Fatal("malformed registration fell through") }))
	for name, raw := range map[string]string{"empty": "{}", "null": "null", "trailing": "{} {}", "missing_false": `{"result":{"schema":"original_guest_protected_provisioning_v1"}}`, "caller_authority": `{"result":{},"enrollment_statement":{},"signature":"","complete":true}`, "duplicate": `{"result":{},"result":{}}`} {
		t.Run(name, func(t *testing.T) {
			r := httptest.NewRequest("POST", "https://core.invalid"+guestProvisioningBase+"/registrations", strings.NewReader(raw))
			r.Header.Set("Authorization", "Bearer "+token)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != 400 {
				t.Fatalf("malformed registration reached durable callback: %d %s", w.Code, w.Body.String())
			}
		})
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestCapacityGuestOriginalCanonicalResponse(t *testing.T) {
	receipt := model.CapacityGuestOriginalProvisioningReceipt{PreregistrationID: "same-original", RecordedAt: time.Date(2026, 10, 13, 1, 2, 3, 123456789, time.UTC)}
	w := httptest.NewRecorder()
	guestCanonicalReply(w, receipt)
	want, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	if w.Code != 200 || !bytes.Equal(w.Body.Bytes(), want) || bytes.HasSuffix(w.Body.Bytes(), []byte("\n")) || capacity.BusinessCreationSHA256(w.Body.Bytes()) != capacity.GuestRetirementSHA(receipt) {
		t.Fatal("canonical signed response bytes changed")
	}
	for _, test := range []struct {
		err    error
		status int
	}{{repository.ErrCapacityMutationAuthorization, 403}, {repository.ErrCapacityConflict, 409}, {repository.ErrCapacityLease, 409}, {repository.ErrCapacityDisabled, 409}, {errors.New("private-origin credential or original body must not escape"), 503}} {
		w = httptest.NewRecorder()
		guestHTTPError(w, test.err)
		if w.Code != test.status || strings.Contains(w.Body.String(), test.err.Error()) {
			t.Fatalf("private error disclosure: %d %s", w.Code, w.Body.String())
		}
	}
}
