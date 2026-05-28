// Package privacy centralizes PII redaction helpers used across log
// emissions and any non-audit diagnostic context.
//
// Audit ref: G5 (PII log redaction). The Phase 3 close (2026-05-27)
// established the `gi***@dakasa.me` mask for email identifiers in
// audit_events metadata (see controllers/httpapi/auth.go:redactIdentifier).
// This package generalizes that convention so every code path that
// emits a log line can call a single helper and get a consistent
// representation.
//
// Rules:
//   - Emails are always masked at the local-part (first 2 chars + ***)
//     and the @domain segment is preserved (operators need to know if
//     a phishing wave is targeting a single tenant).
//   - IPv4 last octet masked to ***; IPv6 truncated to /64 with ::****.
//   - Tokens / refresh tokens / MFA codes are reduced to tok_*** — we
//     NEVER log even a partial value (logs are a search corpus, partial
//     tokens enable correlation attacks).
package privacy

import (
	"net"
	"strings"
)

// MaskEmail returns the email with its local-part redacted, keeping
// the first two characters and the @domain suffix. Example:
//
//	giovanni.martins@dakasa.me  -> gi***@dakasa.me
//	bo@dakasa.me                -> bo***@dakasa.me
//	x@dakasa.me                 -> *@dakasa.me  (single char local-part)
//	noatsign                    -> noatsign     (returned as-is — not an
//	                                            email; caller should
//	                                            decide whether to log it)
//
// An empty string yields an empty string. Leading/trailing whitespace
// is trimmed before processing.
func MaskEmail(e string) string {
	e = strings.TrimSpace(e)
	if e == "" {
		return ""
	}
	at := strings.IndexByte(e, '@')
	if at <= 0 || at == len(e)-1 {
		// Not a valid-looking email — return unchanged so the caller
		// can decide whether emitting it at all is appropriate. We do
		// not invent an @domain.
		return e
	}
	local := e[:at]
	domain := e[at:]
	if len(local) < 2 {
		return "*" + domain
	}
	return local[:2] + "***" + domain
}

// MaskIP returns the IP with the last octet (IPv4) or final 64 bits
// (IPv6) zeroed out. Operators retain enough info to identify a /24 or
// /64 (useful for rate-limit triage) but cannot pin to a single device.
//
// Examples:
//
//	192.168.1.42          -> 192.168.1.***
//	2001:db8::1           -> 2001:db8::****
//	invalid               -> invalid    (returned as-is when unparseable)
//
// X-Forwarded-For chain values containing commas are not split here —
// the caller should pass the single IP segment it wants to log.
func MaskIP(ip string) string {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return ""
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ip
	}
	if v4 := parsed.To4(); v4 != nil {
		// Mask the last octet.
		idx := strings.LastIndexByte(ip, '.')
		if idx < 0 {
			return ip
		}
		return ip[:idx+1] + "***"
	}
	// IPv6: keep the network prefix (first /64) and replace the
	// interface ID with ****. net.IP isn't textual so we render via
	// String() and chop.
	full := parsed.String()
	// If the IP is in compressed form we need to be defensive. The
	// safest invariant: split on `::` if present, else split into 8
	// hextets and zero the last 4.
	if strings.Contains(full, "::") {
		// Already compressed: append :****
		// e.g. "2001:db8::1" -> "2001:db8::****"
		if i := strings.Index(full, "::"); i >= 0 {
			return full[:i] + "::****"
		}
	}
	parts := strings.Split(full, ":")
	if len(parts) == 8 {
		return strings.Join(parts[:4], ":") + "::****"
	}
	return full
}

// MaskToken returns the universal opaque-token placeholder. We do NOT
// keep a prefix (even a 4-char prefix lets an attacker brute-force the
// remaining entropy from a leaked-log corpus). For human-readable hints
// in audit metadata, callers should use a hash-prefix derived elsewhere
// (e.g. SHA-256 first 8 hex chars) rather than the token bytes.
//
// Empty inputs yield an empty string — caller may want to skip the
// field entirely in that case.
func MaskToken(t string) string {
	if strings.TrimSpace(t) == "" {
		return ""
	}
	return "tok_***"
}
