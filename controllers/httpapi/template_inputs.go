package httpapi

import (
	"fmt"
	"regexp"
	"strings"
)

// pushPlaceholderRE matches {{ push.<dotted.path> }} with optional whitespace.
var pushPlaceholderRE = regexp.MustCompile(`\{\{\s*push\.([a-zA-Z0-9_.]+)\s*\}\}`)

// buildInputsFromPush returns a copy of `defaults` where every string value
// has its {{ push.<field> }} placeholders substituted with values from the
// push event. Non-string values are passed through unchanged. Placeholders
// from non-`push.` namespaces are preserved verbatim. Returns an error if a
// `push.*` placeholder references an unknown field.
func buildInputsFromPush(defaults map[string]any, push githubPushEvent) (map[string]any, error) {
	out := make(map[string]any, len(defaults))
	for k, v := range defaults {
		if s, ok := v.(string); ok {
			replaced, err := substitutePushPlaceholders(s, push)
			if err != nil {
				return nil, err
			}
			out[k] = replaced
			continue
		}
		out[k] = v
	}
	return out, nil
}

func substitutePushPlaceholders(s string, push githubPushEvent) (string, error) {
	var firstErr error
	result := pushPlaceholderRE.ReplaceAllStringFunc(s, func(match string) string {
		sub := pushPlaceholderRE.FindStringSubmatch(match)
		if len(sub) != 2 {
			return match
		}
		path := sub[1]
		v, ok := lookupPushField(push, path)
		if !ok {
			if firstErr == nil {
				firstErr = fmt.Errorf("unknown placeholder {{ push.%s }}", path)
			}
			return match
		}
		return v
	})
	if firstErr != nil {
		return "", firstErr
	}
	return result, nil
}

func lookupPushField(p githubPushEvent, path string) (string, bool) {
	switch strings.ToLower(path) {
	case "repository.full_name":
		return p.Repository.FullName, true
	case "repository.clone_url":
		return p.Repository.CloneURL, true
	case "ref":
		return p.Ref, true
	case "head_commit.id":
		return p.HeadCommit.ID, true
	case "head_commit.message":
		return p.HeadCommit.Message, true
	case "pusher.name":
		return p.Pusher.Name, true
	default:
		return "", false
	}
}
