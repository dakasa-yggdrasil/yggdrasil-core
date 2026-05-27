package manifest

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

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
