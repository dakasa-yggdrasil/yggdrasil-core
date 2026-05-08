package scim

import (
	"fmt"
	"strings"
)

// Filter is a parsed RFC 7644 §3.4.2.2 filter expression. The parser only
// covers what External SCIM Service Providers ask for in practice:
//   - eq, ne, co, sw, ew, pr (primary attribute presence)
//   - logical AND between two simple comparisons (rare, but used by AWS IdC)
//
// Anything more complex (parens, OR, nested attribute paths) is rejected with
// ErrUnsupportedFilter — the response should be SCIM 400 invalidFilter.
type Filter struct {
	Attribute string
	Operator  string
	Value     string
	And       *Filter
}

// ErrUnsupportedFilter is returned when the parser encounters syntax beyond
// the simple subset listed above.
var ErrUnsupportedFilter = fmt.Errorf("unsupported scim filter")

// ParseFilter parses a SCIM filter expression. Empty input returns nil, nil
// (no filter == match all).
func ParseFilter(raw string) (*Filter, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}

	// Reject anything we don't intend to support (parens, OR, sub-attribute paths).
	if strings.ContainsAny(raw, "()[]") {
		return nil, ErrUnsupportedFilter
	}
	if containsLowercaseToken(raw, "or") {
		return nil, ErrUnsupportedFilter
	}

	parts := splitOnceCaseInsensitive(raw, " and ")
	left, err := parseSimple(parts[0])
	if err != nil {
		return nil, err
	}
	if len(parts) == 1 {
		return left, nil
	}
	right, err := parseSimple(parts[1])
	if err != nil {
		return nil, err
	}
	left.And = right
	return left, nil
}

func parseSimple(raw string) (*Filter, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, ErrUnsupportedFilter
	}
	// `pr` (presence) is the only operator without a value: `attr pr`.
	if strings.HasSuffix(strings.ToLower(raw), " pr") {
		attr := strings.TrimSpace(raw[:len(raw)-3])
		if attr == "" {
			return nil, ErrUnsupportedFilter
		}
		return &Filter{Attribute: normalizeAttr(attr), Operator: "pr"}, nil
	}

	// Locate the operator (eq/ne/co/sw/ew). Operators are space-delimited.
	tokens := strings.SplitN(raw, " ", 3)
	if len(tokens) != 3 {
		return nil, ErrUnsupportedFilter
	}
	op := strings.ToLower(tokens[1])
	switch op {
	case "eq", "ne", "co", "sw", "ew":
	default:
		return nil, ErrUnsupportedFilter
	}
	val := strings.TrimSpace(tokens[2])
	val = strings.TrimPrefix(val, `"`)
	val = strings.TrimSuffix(val, `"`)
	return &Filter{
		Attribute: normalizeAttr(tokens[0]),
		Operator:  op,
		Value:     val,
	}, nil
}

func normalizeAttr(raw string) string {
	// SCIM attribute names are case-insensitive. Standard fields we care about:
	// userName, externalId, emails, active, displayName.
	return strings.ToLower(strings.TrimSpace(raw))
}

func containsLowercaseToken(s, token string) bool {
	lower := " " + strings.ToLower(s) + " "
	return strings.Contains(lower, " "+token+" ")
}

func splitOnceCaseInsensitive(s, sep string) []string {
	lower := strings.ToLower(s)
	idx := strings.Index(lower, strings.ToLower(sep))
	if idx < 0 {
		return []string{s}
	}
	return []string{s[:idx], s[idx+len(sep):]}
}
