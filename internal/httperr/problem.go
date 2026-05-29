// Package httperr — RFC 7807 Problem+JSON error response envelope.
//
// §14 INTEGRATION_CONTRACT: every HTTP error response (4xx/5xx) from
// yggdrasil-core MUST conform to RFC 7807 with a stable machine-readable
// `code` field. Surfaces map `code` → localized message via a single
// per-locale table instead of regex-matching English `err.Error()`
// strings (the bug fixed here — 50 humanizer rules across 3 surfaces
// each trying to parse unstructured backend prose).
//
// Wire shape:
//
//   HTTP/1.1 401 Unauthorized
//   Content-Type: application/problem+json
//
//   {
//     "type":     "https://yggdrasil.dakasa.me/errors/auth/invalid-credentials",
//     "title":    "Invalid credentials",
//     "status":   401,
//     "detail":   "The provided email or password is incorrect.",
//     "code":     "auth.invalid_credentials",
//     "instance": "/api/v1/auth/login"
//   }
//
// Additional context fields (validation errors with `errors`, rate-limit
// with `locked_until`, correlation IDs, etc.) flatten into the same JSON
// object — RFC 7807 allows arbitrary problem-specific extensions.
package httperr

import (
	"encoding/json"
	"net/http"
)

// ContentType is the IANA media type for RFC 7807 Problem+JSON responses.
const ContentType = "application/problem+json"

// TypePrefix is the canonical prefix for problem `type` URIs hosted on
// yggdrasil-core. Surface i18n consumers SHOULD treat `code` (not `type`)
// as the stable key; `type` is the human-facing doc URL.
const TypePrefix = "https://yggdrasil.dakasa.me/errors/"

// Problem is the RFC 7807 §3.1 base envelope. Additional context fields
// (e.g. `errors`, `locked_until`, `correlation_id`) are stored in Extra
// and flattened by the MarshalJSON implementation so the wire shape is
// flat per the spec.
type Problem struct {
	Type     string                 `json:"type"`
	Title    string                 `json:"title"`
	Status   int                    `json:"status"`
	Detail   string                 `json:"detail,omitempty"`
	Code     string                 `json:"code"`
	Instance string                 `json:"instance,omitempty"`
	Errors   []FieldError           `json:"errors,omitempty"`
	Extra    map[string]interface{} `json:"-"`
}

// FieldError describes one input-validation issue. The `field` references
// the JSON pointer or path that failed (e.g. "/spec/replicas"). Surfaces
// use this to highlight the offending input.
type FieldError struct {
	Field   string `json:"field"`
	Code    string `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
}

// MarshalJSON flattens Extra into the same JSON object as the base
// fields, producing the wire shape RFC 7807 prescribes. Conflicts
// between Extra keys and reserved fields are resolved in favor of the
// reserved field (Extra cannot shadow Code/Status/Title/Type/Instance/
// Detail/Errors).
func (p *Problem) MarshalJSON() ([]byte, error) {
	out := map[string]interface{}{}
	for k, v := range p.Extra {
		out[k] = v
	}
	// Reserved fields ALWAYS win over Extra, in case a careless caller
	// stuffs a "code" or "status" into Extra.
	out["type"] = p.typeOrDefault()
	out["title"] = p.Title
	out["status"] = p.Status
	out["code"] = p.Code
	if p.Detail != "" {
		out["detail"] = p.Detail
	}
	if p.Instance != "" {
		out["instance"] = p.Instance
	}
	if len(p.Errors) > 0 {
		out["errors"] = p.Errors
	}
	return json.Marshal(out)
}

// typeOrDefault returns Type if set, otherwise synthesizes a default URI
// from the Code namespace. This guarantees the field is never empty on
// the wire — RFC 7807 requires it.
func (p *Problem) typeOrDefault() string {
	if p.Type != "" {
		return p.Type
	}
	if p.Code == "" {
		return TypePrefix + "unknown"
	}
	return TypePrefix + p.Code
}

// Stable code constants. Surfaces key off these — NEVER rename a code
// once it ships. Add new ones; deprecate old ones with a code overlap
// for at least one minor version.
//
// Namespacing: <category>.<specific> with dots. Categories so far:
// auth, permission, manifest, integration, workflow, rate_limit, input,
// internal. Add new categories at the end of the const block.
const (
	// auth.*
	CodeAuthInvalidCredentials      = "auth.invalid_credentials"
	CodeAuthAccountLocked           = "auth.account_locked"
	CodeAuthMFARequired             = "auth.mfa_required"
	CodeAuthMFANotEnrolled          = "auth.mfa_not_enrolled"
	CodeAuthMFAInvalid              = "auth.mfa_invalid"
	CodeAuthMFAFactorUnavailable    = "auth.mfa_factor_unavailable"
	CodeAuthSessionExpired          = "auth.session_expired"
	CodeAuthSessionNotFound         = "auth.session_not_found"
	CodeAuthUnauthenticated         = "auth.unauthenticated"
	CodeAuthWebAuthnNotImplemented  = "auth.webauthn_not_implemented"
	CodeAuthWebAuthnCeremonyExpired = "auth.webauthn_ceremony_expired"
	CodeAuthWebAuthnInvalid         = "auth.webauthn_invalid"
	CodeAuthWebAuthnReplay          = "auth.webauthn_replay"
	CodeAuthWebAuthnNotFound        = "auth.webauthn_credential_not_found"
	CodeAuthWebAuthnLastFactor      = "auth.webauthn_last_factor"
	CodeAuthPasswordTooWeak         = "auth.password_too_weak"
	CodeAuthPasswordUnchanged       = "auth.password_unchanged"
	CodeAuthPasswordChangeRequired  = "auth.password_change_required"
	CodeAuthInvalidCurrentPassword  = "auth.invalid_current_password"
	CodeAuthSetupTokenInvalid       = "auth.setup_token_invalid"
	CodeAuthResetTokenInvalid       = "auth.reset_token_invalid"
	CodeAuthKEKNotConfigured        = "auth.kek_not_configured"

	// permission.*
	CodePermissionDenied = "permission.denied"

	// manifest.*
	CodeManifestValidationFailed = "manifest.validation_failed"
	CodeManifestNotFound         = "manifest.not_found"
	CodeManifestConflict         = "manifest.conflict"

	// integration.*
	CodeIntegrationNotFound   = "integration.not_found"
	CodeIntegrationUnavailable = "integration.unavailable"

	// workflow.*
	CodeWorkflowNotFound   = "workflow.not_found"
	CodeWorkflowInvalid    = "workflow.invalid"

	// rate_limit.*
	CodeRateLimitExceeded = "rate_limit.exceeded"

	// input.*
	CodeInvalidInput   = "input.invalid"
	CodeMissingField   = "input.missing_field"
	CodeMalformedBody  = "input.malformed_body"
	CodeUnknownFields  = "input.unknown_fields"

	// internal.*
	CodeInternal = "internal.error"
)

// Write serializes the problem onto the response writer with the
// application/problem+json media type per RFC 7807 §3.
func Write(w http.ResponseWriter, p *Problem) {
	w.Header().Set("Content-Type", ContentType)
	w.WriteHeader(p.Status)
	_ = json.NewEncoder(w).Encode(p)
}

// WriteProblem is the most common entry point — synthesizes a Problem
// from the typed parameters and writes it. Pass opts for extras.
func WriteProblem(w http.ResponseWriter, status int, code, title, detail string, opts ...Option) {
	p := &Problem{
		Status: status,
		Code:   code,
		Title:  title,
		Detail: detail,
	}
	for _, opt := range opts {
		opt(p)
	}
	Write(w, p)
}

// Option mutates a Problem before serialization. Chain via WithInstance,
// WithExtra, WithField, etc.
type Option func(*Problem)

// WithInstance sets the instance URI (typically the request path).
func WithInstance(uri string) Option {
	return func(p *Problem) { p.Instance = uri }
}

// WithType overrides the auto-derived type URI.
func WithType(uri string) Option {
	return func(p *Problem) { p.Type = uri }
}

// WithFieldError appends one FieldError. Use repeatedly for multi-error
// validation responses.
func WithFieldError(field, code, message string) Option {
	return func(p *Problem) {
		p.Errors = append(p.Errors, FieldError{Field: field, Code: code, Message: message})
	}
}

// WithExtra sets one extension field. Reserved keys (code/title/status/
// type/detail/instance/errors) are silently overridden by the reserved
// values during marshalling.
func WithExtra(key string, value interface{}) Option {
	return func(p *Problem) {
		if p.Extra == nil {
			p.Extra = map[string]interface{}{}
		}
		p.Extra[key] = value
	}
}
