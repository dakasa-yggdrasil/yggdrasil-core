package manifest

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// capabilityNamePattern is the canonical convention regex from
// spec §5.1: four prefixes plus the reactor convenience on_*.
var capabilityNamePattern = regexp.MustCompile(`^(ensure|observe|destroy|discover|on)_[a-z][a-z0-9_]*$`)

// Warning is one non-conformance entry emitted by the validator
// during integration_type registration. The handler surfaces these
// in the HTTP response and persists them to the manifest's
// metadata JSONB column for the console to read.
type Warning struct {
	Code    string `json:"code"`
	Field   string `json:"field,omitempty"`
	Value   string `json:"value,omitempty"`
	Message string `json:"message"`
}

// CapabilityNamingAllowlist is the loaded form of
// config/capability_naming_allowlist.yaml. It answers
// "is this non-conformant name intentionally exempt?".
type CapabilityNamingAllowlist struct {
	exact  map[string]struct{}
	prefix []string
}

type capabilityNamingAllowlistFile struct {
	Exact  []string `yaml:"exact"`
	Prefix []string `yaml:"prefix"`
}

// LoadCapabilityNamingAllowlist parses the YAML file at path. The
// path is resolved by the caller — typically a config dir baked
// into the image at /app/config/.
func LoadCapabilityNamingAllowlist(path string) (*CapabilityNamingAllowlist, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("capability_naming: read %q: %w", path, err)
	}
	var f capabilityNamingAllowlistFile
	if err := yaml.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("capability_naming: parse %q: %w", path, err)
	}
	al := &CapabilityNamingAllowlist{
		exact:  make(map[string]struct{}, len(f.Exact)),
		prefix: make([]string, 0, len(f.Prefix)),
	}
	for _, e := range f.Exact {
		al.exact[strings.ToLower(strings.TrimSpace(e))] = struct{}{}
	}
	for _, p := range f.Prefix {
		al.prefix = append(al.prefix, strings.ToLower(strings.TrimSpace(p)))
	}
	return al, nil
}

// Allowed reports whether name is exempt from the convention regex.
// Reactor-category entries are unconditionally allowed regardless
// of name (per spec §2.5 — on_* lifecycle hooks are exempt by
// construction and entries like efi_webhook_received are
// reactor-category historical exceptions).
func (al *CapabilityNamingAllowlist) Allowed(name, category string) bool {
	if strings.EqualFold(strings.TrimSpace(category), "reactor") {
		return true
	}
	name = strings.ToLower(strings.TrimSpace(name))
	if _, ok := al.exact[name]; ok {
		return true
	}
	for _, p := range al.prefix {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// ValidateCapabilityName runs name through the convention regex and
// the allowlist. Conformant names emit no warnings. Non-conformant
// names that are not on the allowlist emit one
// CAPABILITY_NAME_NONCONFORMANT warning. The function is
// side-effect-free and Phase 1 callers append the returned slice
// to the registration response without blocking the write.
//
// category is the action_catalog entry's Category field —
// "reactor" is unconditionally allowed (spec §2.5).
func ValidateCapabilityName(name, category string, allowlist *CapabilityNamingAllowlist) []Warning {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		return nil
	}
	if capabilityNamePattern.MatchString(name) {
		return nil
	}
	if allowlist != nil && allowlist.Allowed(name, category) {
		return nil
	}
	return []Warning{{
		Code:    "CAPABILITY_NAME_NONCONFORMANT",
		Value:   name,
		Message: nonconformantMessage(name),
	}}
}

func nonconformantMessage(name string) string {
	suggested := suggestCanonicalName(name)
	if suggested == "" {
		return fmt.Sprintf("Capability name %q does not match convention ^(ensure|observe|destroy|discover|on)_* and is not in the exempt allowlist.", name)
	}
	return fmt.Sprintf("Capability name %q does not match convention ^(ensure|observe|destroy|discover|on)_* and is not in the exempt allowlist. Consider renaming to %q.", name, suggested)
}

// suggestCanonicalName maps common legacy verb prefixes to their
// convention-aligned suggestion. Returns "" when no rule applies
// so the warning message gracefully omits the suggestion.
func suggestCanonicalName(name string) string {
	switch {
	case strings.HasPrefix(name, "create_"):
		return "ensure_" + strings.TrimPrefix(name, "create_")
	case strings.HasPrefix(name, "update_"):
		return "ensure_" + strings.TrimPrefix(name, "update_")
	case strings.HasPrefix(name, "upsert_"):
		return "ensure_" + strings.TrimPrefix(name, "upsert_")
	case strings.HasPrefix(name, "register_"):
		return "ensure_" + strings.TrimPrefix(name, "register_")
	case strings.HasPrefix(name, "set_"):
		return "ensure_" + strings.TrimPrefix(name, "set_")
	case strings.HasPrefix(name, "issue_"):
		return "ensure_" + strings.TrimPrefix(name, "issue_")
	case strings.HasPrefix(name, "list_"):
		return "observe_" + strings.TrimPrefix(name, "list_")
	case strings.HasPrefix(name, "get_"):
		return "observe_" + strings.TrimPrefix(name, "get_")
	case strings.HasPrefix(name, "describe_"):
		return "observe_" + strings.TrimPrefix(name, "describe_")
	case strings.HasPrefix(name, "lookup_"):
		return "observe_" + strings.TrimPrefix(name, "lookup_")
	case strings.HasPrefix(name, "retrieve_"):
		return "observe_" + strings.TrimPrefix(name, "retrieve_")
	case strings.HasPrefix(name, "delete_"):
		return "destroy_" + strings.TrimPrefix(name, "delete_")
	case strings.HasPrefix(name, "unregister_"):
		return "destroy_" + strings.TrimPrefix(name, "unregister_")
	case strings.HasPrefix(name, "remove_"):
		return "destroy_" + strings.TrimPrefix(name, "remove_")
	case strings.HasPrefix(name, "archive_"):
		return "destroy_" + strings.TrimPrefix(name, "archive_")
	case strings.HasPrefix(name, "cancel_"):
		return "destroy_" + strings.TrimPrefix(name, "cancel_")
	}
	return ""
}
