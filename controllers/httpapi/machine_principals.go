package httpapi

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
	"unicode"

	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

const (
	workflowMachinePrincipalsEnv  = "YGGDRASIL_WORKFLOW_MACHINE_PRINCIPALS_JSON"
	eventPublisherPrincipalsEnv   = "YGGDRASIL_EVENT_PUBLISHER_PRINCIPALS_JSON"
	legacyScopedWorkflowTokensEnv = "YGGDRASIL_WORKFLOW_RUN_SCOPED_TOKENS_JSON"
	legacyEventPublishTokenEnv    = "YGGDRASIL_EVENT_PUBLISH_TOKEN"
	legacyEventPublishEnabledEnv  = "YGGDRASIL_EVENT_PUBLISH_LEGACY_ENABLED"
	legacyEventPublishExpiryEnv   = "YGGDRASIL_EVENT_PUBLISH_LEGACY_EXPIRES_AT"
)

type machineWorkflowRef struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
}

type workflowMachinePrincipalConfig struct {
	PrincipalID      string               `json:"principal_id"`
	Status           string               `json:"status"`
	ExpiresAt        time.Time            `json:"expires_at"`
	RotationID       string               `json:"rotation_id"`
	RotatedAt        time.Time            `json:"rotated_at"`
	TokenSHA256      string               `json:"token_sha256"`
	AllowedWorkflows []machineWorkflowRef `json:"allowed_workflows"`
}

type eventPublisherPrincipalConfig struct {
	PrincipalID   string                   `json:"principal_id"`
	Status        string                   `json:"status"`
	ExpiresAt     time.Time                `json:"expires_at"`
	RotationID    string                   `json:"rotation_id"`
	RotatedAt     time.Time                `json:"rotated_at"`
	TokenSHA256   string                   `json:"token_sha256"`
	AllowedEvents []eventPublisherEventRef `json:"allowed_events"`
}

type eventPublisherEventRef struct {
	Provider   string `json:"provider"`
	InstanceID string `json:"instance_id"`
	EventType  string `json:"event_type"`
}

type workflowMachinePrincipal struct {
	PrincipalID      string
	Status           string
	ExpiresAt        time.Time
	RotationID       string
	RotatedAt        time.Time
	TokenSHA256      [sha256.Size]byte
	AllowedWorkflows map[machineWorkflowRef]struct{}
}

// eventPublisherLogicalRef is a grant whose instance_id names the logical
// integration instance as "<namespace>/<name>" (ADR-0021). It only ever
// matches after Core resolved the event's instance_id against the manifests
// table, never by string comparison with the wire value.
type eventPublisherLogicalRef struct {
	Provider  string
	Namespace string
	Name      string
	EventType string
}

type eventPublisherProviderEvent struct {
	Provider  string
	EventType string
}

type eventPublisherPrincipal struct {
	PrincipalID string
	Status      string
	ExpiresAt   time.Time
	RotationID  string
	RotatedAt   time.Time
	TokenSHA256 [sha256.Size]byte
	// AllowedEvents holds exact grants only: an instance_id without "/"
	// (a per-version manifest UUID or a bare instance name), compared as an
	// opaque string with no database access.
	AllowedEvents map[eventPublisherEventRef]struct{}
	// LogicalEvents holds the "<namespace>/<name>" grants.
	LogicalEvents map[eventPublisherLogicalRef]struct{}
	// logicalProviderEvents indexes LogicalEvents by (provider, event_type)
	// so the handler can decide, in memory, whether a database lookup may
	// happen at all.
	logicalProviderEvents map[eventPublisherProviderEvent]struct{}
}

type legacyWorkflowCredential struct {
	Token      string
	Configured bool
	Active     bool
	ExpiresAt  time.Time
}

type legacyEventPublishCredential struct {
	Token      string
	Configured bool
	Active     bool
	ExpiresAt  time.Time
}

// workflowMachinePrincipalsFromEnv loads only credential digests and
// authorization metadata. The previous scoped-token JSON carried raw bearer
// values; accepting it alongside this configuration would preserve the very
// shared-secret exposure this boundary removes, so any presence fails closed.
func workflowMachinePrincipalsFromEnv() ([]workflowMachinePrincipal, error) {
	if strings.TrimSpace(os.Getenv(legacyScopedWorkflowTokensEnv)) != "" {
		return nil, fmt.Errorf("%s is no longer accepted because it contains raw credentials; configure %s with token_sha256 digests", legacyScopedWorkflowTokensEnv, workflowMachinePrincipalsEnv)
	}
	// A variable that is present but blank is a refused inventory, never "no
	// principals" (ADR-0022), exactly as for the event inventory: an
	// ExternalSecret key that resolved to an empty string, or a mask meant
	// for another variable, must not read as "unconfigured" and reopen the
	// anonymous posture. Only a variable that is truly unset means the
	// workflow surface has no principals.
	if raw, present := os.LookupEnv(workflowMachinePrincipalsEnv); present && strings.TrimSpace(raw) == "" {
		return nil, fmt.Errorf("%s is set but blank; unset it or configure at least one principal", workflowMachinePrincipalsEnv)
	}

	rawConfigured := strings.TrimSpace(os.Getenv(workflowMachinePrincipalsEnv)) != ""
	var configs []workflowMachinePrincipalConfig
	if err := decodeMachinePrincipalConfig(workflowMachinePrincipalsEnv, &configs); err != nil {
		return nil, err
	}
	if configs == nil {
		if rawConfigured {
			return nil, fmt.Errorf("%s must be a non-empty JSON array", workflowMachinePrincipalsEnv)
		}
		return nil, nil
	}
	if len(configs) == 0 {
		return nil, fmt.Errorf("%s must contain at least one principal when configured", workflowMachinePrincipalsEnv)
	}

	principals := make([]workflowMachinePrincipal, 0, len(configs))
	seenIDs := make(map[string]struct{}, len(configs))
	seenHashes := make(map[[sha256.Size]byte]struct{}, len(configs))
	for index, config := range configs {
		base, err := validateMachinePrincipalBase(
			workflowMachinePrincipalsEnv,
			index,
			config.PrincipalID,
			config.Status,
			config.ExpiresAt,
			config.RotationID,
			config.RotatedAt,
			config.TokenSHA256,
		)
		if err != nil {
			return nil, err
		}
		if _, duplicate := seenIDs[base.principalID]; duplicate {
			return nil, fmt.Errorf("%s entry %d duplicates principal_id", workflowMachinePrincipalsEnv, index)
		}
		if _, duplicate := seenHashes[base.tokenSHA256]; duplicate {
			return nil, fmt.Errorf("%s entry %d duplicates a credential digest", workflowMachinePrincipalsEnv, index)
		}
		if len(config.AllowedWorkflows) == 0 {
			return nil, fmt.Errorf("%s entry %d requires at least one exact allowed_workflows item", workflowMachinePrincipalsEnv, index)
		}

		allowlist := make(map[machineWorkflowRef]struct{}, len(config.AllowedWorkflows))
		for workflowIndex, workflow := range config.AllowedWorkflows {
			workflow.Namespace = strings.TrimSpace(workflow.Namespace)
			workflow.Name = strings.TrimSpace(workflow.Name)
			if workflow.Namespace == "" || workflow.Name == "" {
				return nil, fmt.Errorf("%s entry %d allowed_workflows item %d requires namespace and name", workflowMachinePrincipalsEnv, index, workflowIndex)
			}
			if containsWildcard(workflow.Namespace) || containsWildcard(workflow.Name) {
				return nil, fmt.Errorf("%s entry %d allowed_workflows item %d must be exact and cannot contain wildcards", workflowMachinePrincipalsEnv, index, workflowIndex)
			}
			if _, duplicate := allowlist[workflow]; duplicate {
				return nil, fmt.Errorf("%s entry %d duplicates an allowed_workflows item", workflowMachinePrincipalsEnv, index)
			}
			allowlist[workflow] = struct{}{}
		}

		principals = append(principals, workflowMachinePrincipal{
			PrincipalID:      base.principalID,
			Status:           base.status,
			ExpiresAt:        base.expiresAt,
			RotationID:       base.rotationID,
			RotatedAt:        base.rotatedAt,
			TokenSHA256:      base.tokenSHA256,
			AllowedWorkflows: allowlist,
		})
		seenIDs[base.principalID] = struct{}{}
		seenHashes[base.tokenSHA256] = struct{}{}
	}
	return principals, nil
}

func eventPublisherPrincipalsFromEnv() ([]eventPublisherPrincipal, error) {
	// A variable that is present but blank is a refused inventory, never "no
	// principals": with no legacy bridge that would open the anonymous
	// development posture wherever YGGDRASIL_ENV is unset. Only a variable
	// that is truly unset means the event surface is unconfigured.
	if raw, present := os.LookupEnv(eventPublisherPrincipalsEnv); present && strings.TrimSpace(raw) == "" {
		return nil, fmt.Errorf("%s is set but blank; unset it or configure at least one principal", eventPublisherPrincipalsEnv)
	}
	rawConfigured := strings.TrimSpace(os.Getenv(eventPublisherPrincipalsEnv)) != ""
	var configs []eventPublisherPrincipalConfig
	if err := decodeMachinePrincipalConfig(eventPublisherPrincipalsEnv, &configs); err != nil {
		return nil, err
	}
	if configs == nil {
		if rawConfigured {
			return nil, fmt.Errorf("%s must be a non-empty JSON array", eventPublisherPrincipalsEnv)
		}
		return nil, nil
	}
	if len(configs) == 0 {
		return nil, fmt.Errorf("%s must contain at least one principal when configured", eventPublisherPrincipalsEnv)
	}

	principals := make([]eventPublisherPrincipal, 0, len(configs))
	seenIDs := make(map[string]struct{}, len(configs))
	seenHashes := make(map[[sha256.Size]byte]struct{}, len(configs))
	for index, config := range configs {
		base, err := validateMachinePrincipalBase(
			eventPublisherPrincipalsEnv,
			index,
			config.PrincipalID,
			config.Status,
			config.ExpiresAt,
			config.RotationID,
			config.RotatedAt,
			config.TokenSHA256,
		)
		if err != nil {
			return nil, err
		}
		if _, duplicate := seenIDs[base.principalID]; duplicate {
			return nil, fmt.Errorf("%s entry %d duplicates principal_id", eventPublisherPrincipalsEnv, index)
		}
		if _, duplicate := seenHashes[base.tokenSHA256]; duplicate {
			return nil, fmt.Errorf("%s entry %d duplicates a credential digest", eventPublisherPrincipalsEnv, index)
		}
		if len(config.AllowedEvents) == 0 {
			return nil, fmt.Errorf("%s entry %d requires at least one allowed_events item", eventPublisherPrincipalsEnv, index)
		}
		allowedEvents := make(map[eventPublisherEventRef]struct{}, len(config.AllowedEvents))
		logicalEvents := make(map[eventPublisherLogicalRef]struct{})
		logicalProviderEvents := make(map[eventPublisherProviderEvent]struct{})
		for eventIndex, event := range config.AllowedEvents {
			event.Provider = strings.TrimSpace(event.Provider)
			event.InstanceID = strings.TrimSpace(event.InstanceID)
			event.EventType = strings.TrimSpace(event.EventType)
			if event.Provider == "" || event.InstanceID == "" || event.EventType == "" {
				return nil, fmt.Errorf("%s entry %d allowed_events item %d requires provider, instance_id, and event_type", eventPublisherPrincipalsEnv, index, eventIndex)
			}
			if containsWildcard(event.Provider) || containsWildcard(event.InstanceID) || containsWildcard(event.EventType) {
				return nil, fmt.Errorf("%s entry %d allowed_events item %d must be exact and cannot contain wildcards", eventPublisherPrincipalsEnv, index, eventIndex)
			}
			if !repository.IsIntegrationMutationEvent(event.EventType) {
				return nil, fmt.Errorf("%s entry %d allowed_events item %d event_type must be an integration mutation event", eventPublisherPrincipalsEnv, index, eventIndex)
			}
			parsedProvider, _, _, _ := repository.ParseIntegrationMutationEventType(event.EventType)
			if parsedProvider != event.Provider {
				return nil, fmt.Errorf("%s entry %d allowed_events item %d provider must match event_type", eventPublisherPrincipalsEnv, index, eventIndex)
			}
			if strings.Contains(event.InstanceID, "/") {
				namespace, name, err := parseLogicalInstanceRef(event.InstanceID)
				if err != nil {
					return nil, fmt.Errorf("%s entry %d allowed_events item %d instance_id %v", eventPublisherPrincipalsEnv, index, eventIndex, err)
				}
				logical := eventPublisherLogicalRef{Provider: event.Provider, Namespace: namespace, Name: name, EventType: event.EventType}
				if _, duplicate := logicalEvents[logical]; duplicate {
					return nil, fmt.Errorf("%s entry %d duplicates an allowed_events item", eventPublisherPrincipalsEnv, index)
				}
				logicalEvents[logical] = struct{}{}
				logicalProviderEvents[eventPublisherProviderEvent{Provider: event.Provider, EventType: event.EventType}] = struct{}{}
				continue
			}
			if _, duplicate := allowedEvents[event]; duplicate {
				return nil, fmt.Errorf("%s entry %d duplicates an allowed_events item", eventPublisherPrincipalsEnv, index)
			}
			allowedEvents[event] = struct{}{}
		}
		principals = append(principals, eventPublisherPrincipal{
			PrincipalID:           base.principalID,
			Status:                base.status,
			ExpiresAt:             base.expiresAt,
			RotationID:            base.rotationID,
			RotatedAt:             base.rotatedAt,
			TokenSHA256:           base.tokenSHA256,
			AllowedEvents:         allowedEvents,
			LogicalEvents:         logicalEvents,
			logicalProviderEvents: logicalProviderEvents,
		})
		seenIDs[base.principalID] = struct{}{}
		seenHashes[base.tokenSHA256] = struct{}{}
	}
	return principals, nil
}

func decodeMachinePrincipalConfig(envName string, target any) error {
	raw := strings.TrimSpace(os.Getenv(envName))
	if raw == "" {
		return nil
	}
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("parse %s: %w", envName, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return fmt.Errorf("%s contains trailing JSON", envName)
	}
	return nil
}

type validatedMachinePrincipalBase struct {
	principalID string
	status      string
	expiresAt   time.Time
	rotationID  string
	rotatedAt   time.Time
	tokenSHA256 [sha256.Size]byte
}

func validateMachinePrincipalBase(
	envName string,
	index int,
	principalID string,
	status string,
	expiresAt time.Time,
	rotationID string,
	rotatedAt time.Time,
	tokenSHA256 string,
) (validatedMachinePrincipalBase, error) {
	principalID = strings.TrimSpace(principalID)
	status = strings.ToLower(strings.TrimSpace(status))
	rotationID = strings.TrimSpace(rotationID)
	tokenSHA256 = strings.TrimSpace(tokenSHA256)
	if principalID == "" || len(principalID) > 256 {
		return validatedMachinePrincipalBase{}, fmt.Errorf("%s entry %d requires principal_id of at most 256 characters", envName, index)
	}
	if containsWildcard(principalID) {
		return validatedMachinePrincipalBase{}, fmt.Errorf("%s entry %d principal_id cannot contain wildcards", envName, index)
	}
	switch status {
	case "active", "disabled", "revoked":
	default:
		return validatedMachinePrincipalBase{}, fmt.Errorf("%s entry %d status must be active, disabled, or revoked", envName, index)
	}
	if expiresAt.IsZero() {
		return validatedMachinePrincipalBase{}, fmt.Errorf("%s entry %d requires expires_at", envName, index)
	}
	if rotationID == "" {
		return validatedMachinePrincipalBase{}, fmt.Errorf("%s entry %d requires rotation_id", envName, index)
	}
	// rotation_id is the required rotation metadata. rotated_at is accepted as
	// an optional audit timestamp; when present it must precede expiry. Keeping
	// it optional lets operators migrate inventories that already have a stable
	// rotation identifier without inventing historical timestamps.
	if !rotatedAt.IsZero() && !expiresAt.After(rotatedAt) {
		return validatedMachinePrincipalBase{}, fmt.Errorf("%s entry %d expires_at must be after rotated_at", envName, index)
	}
	if len(tokenSHA256) != sha256.Size*2 || tokenSHA256 != strings.ToLower(tokenSHA256) {
		return validatedMachinePrincipalBase{}, fmt.Errorf("%s entry %d token_sha256 must be exactly 64 lowercase hexadecimal characters", envName, index)
	}
	decoded, err := hex.DecodeString(tokenSHA256)
	if err != nil || len(decoded) != sha256.Size {
		return validatedMachinePrincipalBase{}, fmt.Errorf("%s entry %d token_sha256 must be exactly 64 lowercase hexadecimal characters", envName, index)
	}
	var digest [sha256.Size]byte
	copy(digest[:], decoded)
	var zero [sha256.Size]byte
	if subtle.ConstantTimeCompare(digest[:], zero[:]) == 1 {
		return validatedMachinePrincipalBase{}, fmt.Errorf("%s entry %d token_sha256 cannot be the all-zero digest", envName, index)
	}
	return validatedMachinePrincipalBase{
		principalID: principalID,
		status:      status,
		expiresAt:   expiresAt.UTC(),
		rotationID:  rotationID,
		rotatedAt:   rotatedAt.UTC(),
		tokenSHA256: digest,
	}, nil
}

func containsWildcard(value string) bool {
	return strings.ContainsAny(value, "*?[]{}")
}

func machineCredentialMatches(candidate string, expected [sha256.Size]byte) bool {
	if candidate == "" {
		return false
	}
	digest := sha256.Sum256([]byte(candidate))
	return subtle.ConstantTimeCompare(digest[:], expected[:]) == 1
}

func activeWorkflowMachinePrincipal(candidate string, principals []workflowMachinePrincipal, now time.Time) *workflowMachinePrincipal {
	var matched *workflowMachinePrincipal
	for index := range principals {
		principal := &principals[index]
		credentialMatches := machineCredentialMatches(candidate, principal.TokenSHA256)
		if credentialMatches && principal.Status == "active" && now.Before(principal.ExpiresAt) {
			matched = principal
		}
	}
	return matched
}

func activeEventPublisherPrincipal(candidate string, principals []eventPublisherPrincipal, now time.Time) *eventPublisherPrincipal {
	var matched *eventPublisherPrincipal
	for index := range principals {
		principal := &principals[index]
		credentialMatches := machineCredentialMatches(candidate, principal.TokenSHA256)
		if credentialMatches && principal.Status == "active" && now.Before(principal.ExpiresAt) {
			matched = principal
		}
	}
	return matched
}

// eventPublisherPrincipalAllows is the exact, database-free check. A wire
// instance_id that contains "/" never matches here: slash-form grants live in
// LogicalEvents and only match through resolution.
func eventPublisherPrincipalAllows(principal *eventPublisherPrincipal, provider, instanceID, eventType string) bool {
	if principal == nil {
		return false
	}
	_, allowed := principal.AllowedEvents[eventPublisherEventRef{
		Provider:   strings.TrimSpace(provider),
		InstanceID: strings.TrimSpace(instanceID),
		EventType:  strings.TrimSpace(eventType),
	}]
	return allowed
}

// eventPublisherPrincipalHasLogicalGrant reports whether the principal holds
// any "<namespace>/<name>" grant for this provider and event type. It gates
// the database lookup.
func eventPublisherPrincipalHasLogicalGrant(principal *eventPublisherPrincipal, provider, eventType string) bool {
	if principal == nil {
		return false
	}
	_, ok := principal.logicalProviderEvents[eventPublisherProviderEvent{
		Provider:  strings.TrimSpace(provider),
		EventType: strings.TrimSpace(eventType),
	}]
	return ok
}

// eventPublisherPrincipalAllowsLogical checks a resolved logical instance.
func eventPublisherPrincipalAllowsLogical(principal *eventPublisherPrincipal, provider, namespace, name, eventType string) bool {
	if principal == nil {
		return false
	}
	_, allowed := principal.LogicalEvents[eventPublisherLogicalRef{
		Provider:  strings.TrimSpace(provider),
		Namespace: namespace,
		Name:      name,
		EventType: strings.TrimSpace(eventType),
	}]
	return allowed
}

// eventPublisherPrincipalDeclares reports whether the inventory declares the
// grant in either form, exact or logical, without resolving anything. It
// exists for inventory checks (an operator's CI can run Core's parser over a
// rendered inventory and ask whether every declared grant survived); request
// authorization must use eventPublisherPrincipalAllows and the resolved
// logical path, never this.
func eventPublisherPrincipalDeclares(principal *eventPublisherPrincipal, provider, instanceID, eventType string) bool {
	instanceID = strings.TrimSpace(instanceID)
	if !strings.Contains(instanceID, "/") {
		return eventPublisherPrincipalAllows(principal, provider, instanceID, eventType)
	}
	namespace, name, err := parseLogicalInstanceRef(instanceID)
	if err != nil {
		return false
	}
	return eventPublisherPrincipalAllowsLogical(principal, provider, namespace, name, eventType)
}

// maxLogicalInstanceRefLength bounds a "<namespace>/<name>" value; it is far
// above any real manifest identity and keeps hostile wire values cheap.
const maxLogicalInstanceRefLength = 512

// parseLogicalInstanceRef accepts exactly "<namespace>/<name>": one "/", both
// parts non-empty, already lowercase, no whitespace, no control characters,
// no wildcard syntax. It is
// strict rather than normalizing so the spelling in a grant is exactly the
// identity it matches. The same parser validates grants at load and literal
// wire values at request time.
func parseLogicalInstanceRef(value string) (string, string, error) {
	if value == "" || len(value) > maxLogicalInstanceRefLength {
		return "", "", errors.New("must be <namespace>/<name> of bounded length")
	}
	if strings.Count(value, "/") != 1 {
		return "", "", errors.New("must contain exactly one \"/\"")
	}
	if value != strings.ToLower(value) {
		return "", "", errors.New("must be lowercase")
	}
	if strings.IndexFunc(value, unicode.IsSpace) >= 0 {
		return "", "", errors.New("must not contain whitespace")
	}
	// Control characters (NUL included) never reach PostgreSQL: the wire
	// value is refused here as not resolvable, which answers 403.
	if strings.IndexFunc(value, unicode.IsControl) >= 0 {
		return "", "", errors.New("must not contain control characters")
	}
	if containsWildcard(value) {
		return "", "", errors.New("must be exact and cannot contain wildcards")
	}
	namespace, name, _ := strings.Cut(value, "/")
	if namespace == "" || name == "" {
		return "", "", errors.New("requires a non-empty namespace and name")
	}
	return namespace, name, nil
}

func workflowMachinePrincipalAllows(principal *workflowMachinePrincipal, namespace, name string) bool {
	if principal == nil {
		return false
	}
	_, allowed := principal.AllowedWorkflows[machineWorkflowRef{
		Namespace: strings.TrimSpace(namespace),
		Name:      strings.TrimSpace(name),
	}]
	return allowed
}

func usableWorkflowMachinePrincipalCount(principals []workflowMachinePrincipal, now time.Time) int {
	count := 0
	for _, principal := range principals {
		if principal.Status == "active" && now.Before(principal.ExpiresAt) {
			count++
		}
	}
	return count
}

func usableEventPublisherPrincipalCount(principals []eventPublisherPrincipal, now time.Time) int {
	count := 0
	for _, principal := range principals {
		if principal.Status == "active" && now.Before(principal.ExpiresAt) {
			count++
		}
	}
	return count
}

func digestForConfiguredToken(token string) ([sha256.Size]byte, bool) {
	token = strings.TrimSpace(token)
	if token == "" {
		return [sha256.Size]byte{}, false
	}
	return sha256.Sum256([]byte(token)), true
}

func machineCredentialDigestsCollide(left, right [sha256.Size]byte) bool {
	return subtle.ConstantTimeCompare(left[:], right[:]) == 1
}

func legacyWorkflowCredentialFromEnv(now time.Time) (legacyWorkflowCredential, error) {
	token := strings.TrimSpace(os.Getenv("YGGDRASIL_WORKFLOW_RUN_TOKEN"))
	enabled := strings.ToLower(strings.TrimSpace(os.Getenv("YGGDRASIL_WORKFLOW_RUN_LEGACY_ENABLED")))
	expiresRaw := strings.TrimSpace(os.Getenv("YGGDRASIL_WORKFLOW_RUN_LEGACY_EXPIRES_AT"))
	if token == "" {
		if enabled != "" || expiresRaw != "" {
			return legacyWorkflowCredential{}, errors.New("legacy workflow migration settings require YGGDRASIL_WORKFLOW_RUN_TOKEN")
		}
		return legacyWorkflowCredential{}, nil
	}
	if enabled != "true" {
		return legacyWorkflowCredential{}, errors.New("YGGDRASIL_WORKFLOW_RUN_TOKEN requires YGGDRASIL_WORKFLOW_RUN_LEGACY_ENABLED=true during migration")
	}
	if expiresRaw == "" {
		return legacyWorkflowCredential{}, errors.New("YGGDRASIL_WORKFLOW_RUN_TOKEN requires YGGDRASIL_WORKFLOW_RUN_LEGACY_EXPIRES_AT during migration")
	}
	expiresAt, err := time.Parse(time.RFC3339, expiresRaw)
	if err != nil {
		return legacyWorkflowCredential{}, errors.New("YGGDRASIL_WORKFLOW_RUN_LEGACY_EXPIRES_AT must be RFC3339")
	}
	return legacyWorkflowCredential{
		Token:      token,
		Configured: true,
		Active:     now.Before(expiresAt),
		ExpiresAt:  expiresAt.UTC(),
	}, nil
}

func legacyEventPublishCredentialFromEnv(now time.Time) (legacyEventPublishCredential, error) {
	token := strings.TrimSpace(os.Getenv(legacyEventPublishTokenEnv))
	enabled := strings.ToLower(strings.TrimSpace(os.Getenv(legacyEventPublishEnabledEnv)))
	expiresRaw := strings.TrimSpace(os.Getenv(legacyEventPublishExpiryEnv))
	if token == "" {
		if enabled != "" || expiresRaw != "" {
			return legacyEventPublishCredential{}, fmt.Errorf("legacy event migration settings require %s", legacyEventPublishTokenEnv)
		}
		return legacyEventPublishCredential{}, nil
	}
	if enabled != "true" {
		return legacyEventPublishCredential{}, fmt.Errorf("%s requires %s=true during migration", legacyEventPublishTokenEnv, legacyEventPublishEnabledEnv)
	}
	if expiresRaw == "" {
		return legacyEventPublishCredential{}, fmt.Errorf("%s requires %s during migration", legacyEventPublishTokenEnv, legacyEventPublishExpiryEnv)
	}
	expiresAt, err := time.Parse(time.RFC3339, expiresRaw)
	if err != nil {
		return legacyEventPublishCredential{}, fmt.Errorf("%s must be RFC3339", legacyEventPublishExpiryEnv)
	}
	return legacyEventPublishCredential{
		Token:      token,
		Configured: true,
		Active:     now.Before(expiresAt),
		ExpiresAt:  expiresAt.UTC(),
	}, nil
}

func constantTimeTokenEqual(candidate, expected string) bool {
	if candidate == "" || expected == "" {
		return false
	}
	candidateDigest := sha256.Sum256([]byte(candidate))
	expectedDigest := sha256.Sum256([]byte(expected))
	return subtle.ConstantTimeCompare(candidateDigest[:], expectedDigest[:]) == 1
}

func scopedMachineWorkflowIdempotencyKey(principalID, clientKey string) string {
	principalID = strings.TrimSpace(principalID)
	clientKey = strings.TrimSpace(clientKey)
	material := fmt.Sprintf("%d:%s%s", len(principalID), principalID, clientKey)
	digest := sha256.Sum256([]byte(material))
	return "machine-sha256:" + hex.EncodeToString(digest[:])
}
