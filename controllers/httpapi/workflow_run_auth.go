package httpapi

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"go.uber.org/zap"
)

// workflowRunAuthConfig is the workflow-run machine credential surface
// (ADR-0017, ADR-0022): the hashed workflow principals and the plaintext
// legacy bridge settings, parsed once. New fills it eagerly at start; a
// Server built as a literal (tests only) fills it once, on first use, from the
// environment of that moment. The outer gate, the dispatch and poll handlers
// and the manifest-write check all read this one copy and never read those
// variables again, so the surface a request sees is exactly the one this
// process loaded. Only the bridge expiry is still evaluated per request.
//
// err is a refused workflow surface: a malformed or set-but-blank inventory,
// the raw scoped-token format, or a workflow digest that another credential
// scope also holds. With err set every machine request to the workflow-run
// routes answers 401 and the anonymous development posture is off; the
// parsed principals are kept only so the boot summary can name them.
//
// legacyErr is refused bridge settings. It switches off the bridge and the
// anonymous posture, while the hashed principals keep authenticating, so a
// half-retired bridge never locks every machine caller out.
type workflowRunAuthConfig struct {
	principals []workflowMachinePrincipal
	err        error
	legacy     legacyWorkflowCredential
	legacyErr  error
}

// loadWorkflowRunAuthConfig parses the workflow inventory and the legacy
// bridge settings from the environment and refuses the workflow surface when
// a workflow digest collides with a directory digest, an event digest, or
// the SHA-256 of a plaintext credential Core reads. event and directory are
// the inventories this process loaded; the collision check runs in every
// environment, not only when validateBootSecrets does.
func loadWorkflowRunAuthConfig(event []eventPublisherPrincipal, directory []directoryMachinePrincipal) *workflowRunAuthConfig {
	config := &workflowRunAuthConfig{}
	config.legacy, config.legacyErr = legacyWorkflowCredentialFromEnv(time.Now().UTC())
	if config.legacyErr != nil {
		config.legacy = legacyWorkflowCredential{}
	}
	config.principals, config.err = workflowMachinePrincipalsFromEnv()
	if config.err != nil {
		config.principals = nil
		return config
	}
	config.err = workflowMachinePrincipalCollisions(config.principals, event, directory)
	return config
}

// legacyActive reports whether the bridge may authenticate at now. The
// settings are parsed once; the expiry is evaluated on every request.
func (c *workflowRunAuthConfig) legacyActive(now time.Time) bool {
	return c.legacyErr == nil && c.legacy.Configured && now.Before(c.legacy.ExpiresAt)
}

// anonymousAllowed reports whether a request that presents no credential may
// use the credential-free development posture: nothing configured on the
// workflow surface, nothing refused, and an explicit development environment.
func (c *workflowRunAuthConfig) anonymousAllowed() bool {
	return c.err == nil && c.legacyErr == nil && !c.legacy.Configured && len(c.principals) == 0 && machineAnonymousAllowed()
}

// machineAnonymousAllowed reports whether YGGDRASIL_ENV explicitly names a
// development environment (ADR-0022). Anonymous workflow dispatch, anonymous
// manifest writes and anonymous event publishing need it on top of an
// unconfigured credential surface, so a production Core whose inventory went
// missing or blank fails closed even though YGGDRASIL_ENV is unset there.
// devEnvAllowsFallback, which keeps the CSRF and OAuth-state development
// fallbacks for anything but "production" and "prod", is deliberately not
// used here.
func machineAnonymousAllowed() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("YGGDRASIL_ENV"))) {
	case "dev", "development", "local", "test":
		return true
	default:
		return false
	}
}

// workflowRunAuthConfig returns the loaded workflow-run surface. New has
// already filled it; for a Server built as a literal the first call loads it
// from the environment, and a literal that already carries a config keeps it.
func (s *Server) workflowRunAuthConfig() *workflowRunAuthConfig {
	s.workflowRunAuthOnce.Do(func() {
		if s.workflowRunAuth == nil {
			s.workflowRunAuth = loadWorkflowRunAuthConfig(s.loadedEventPublisherPrincipals(), s.directoryMachinePrincipals)
		}
	})
	return s.workflowRunAuth
}

// loadedEventPublisherPrincipals returns the event principals this process
// loaded, or nil when the event surface is absent or refused.
func (s *Server) loadedEventPublisherPrincipals() []eventPublisherPrincipal {
	if s.eventPublishAuth == nil || s.eventPublishAuth.err != nil {
		return nil
	}
	return s.eventPublishAuth.principals
}

// workflowMachinePrincipalCollisions lists every workflow principal whose
// digest another credential scope also holds. A shared digest would let one
// bearer act in two scopes: the directory gate runs first and would claim it,
// and a plaintext bridge or static token would give it wider authority once
// the principal expires. Diagnostics name variables and entry indexes, never
// credentials or digests.
func workflowMachinePrincipalCollisions(principals []workflowMachinePrincipal, event []eventPublisherPrincipal, directory []directoryMachinePrincipal) error {
	plaintexts := plaintextMachineCredentialScopes()
	var issues []string
	for index, principal := range principals {
		for directoryIndex, other := range directory {
			if machineCredentialDigestsCollide(principal.TokenSHA256, other.TokenSHA256) {
				issues = append(issues, fmt.Sprintf("%s entry %d credential must differ from %s entry %d", workflowMachinePrincipalsEnv, index, directoryMachinePrincipalsEnv, directoryIndex))
			}
		}
		for eventIndex, other := range event {
			if machineCredentialDigestsCollide(principal.TokenSHA256, other.TokenSHA256) {
				issues = append(issues, fmt.Sprintf("%s entry %d credential must differ from %s entry %d", workflowMachinePrincipalsEnv, index, eventPublisherPrincipalsEnv, eventIndex))
			}
		}
		for _, other := range plaintexts {
			if digestMatchesPlaintext(principal.TokenSHA256, other.value) {
				issues = append(issues, fmt.Sprintf("%s entry %d credential must differ from %s", workflowMachinePrincipalsEnv, index, other.name))
			}
		}
	}
	if len(issues) == 0 {
		return nil
	}
	return errors.New(strings.Join(issues, "; "))
}

// directoryMachinePrincipalCollisions lists every directory principal whose
// digest an event principal or a plaintext credential also holds. New then
// serves an empty directory inventory instead of refusing to boot: the
// directory gate runs before every other credential family and would answer
// 403 to an event adapter whose bearer it claimed, while an empty directory
// set lets that bearer fall through to its own scope and leaves the directory
// reads answering 401 until the inventory is fixed. A collision with a
// workflow digest refuses the workflow surface instead (see
// workflowMachinePrincipalCollisions).
func directoryMachinePrincipalCollisions(directory []directoryMachinePrincipal, event []eventPublisherPrincipal) error {
	plaintexts := plaintextMachineCredentialScopes()
	var issues []string
	for index, principal := range directory {
		for eventIndex, other := range event {
			if machineCredentialDigestsCollide(principal.TokenSHA256, other.TokenSHA256) {
				issues = append(issues, fmt.Sprintf("%s entry %d credential must differ from %s entry %d", directoryMachinePrincipalsEnv, index, eventPublisherPrincipalsEnv, eventIndex))
			}
		}
		for _, other := range plaintexts {
			if digestMatchesPlaintext(principal.TokenSHA256, other.value) {
				issues = append(issues, fmt.Sprintf("%s entry %d credential must differ from %s", directoryMachinePrincipalsEnv, index, other.name))
			}
		}
	}
	if len(issues) == 0 {
		return nil
	}
	return errors.New(strings.Join(issues, "; "))
}

// logWorkflowRunCredentialSurface writes the boot lines of ADR-0022: one
// error line per refused surface and, always, one info summary an operator
// can read after every restart. The summary carries counts, principal ids,
// dates and booleans only, never a credential or a digest.
func logWorkflowRunCredentialSurface(logger *zap.Logger, config *workflowRunAuthConfig, directoryErr error, now time.Time) {
	if logger == nil || config == nil {
		return
	}
	if config.err != nil {
		logger.Error("workflow machine principal inventory refused; every machine request to /api/v1/workflow-runs answers 401 until Core restarts with a valid inventory",
			zap.Error(config.err))
	}
	if config.legacyErr != nil {
		logger.Error("legacy workflow-run bridge settings refused; the bridge and anonymous dispatch are off, workflow principals keep working",
			zap.Error(config.legacyErr))
	}
	if directoryErr != nil {
		logger.Error("directory machine principal digest collides with another credential scope; directory machine reads answer 401",
			zap.Error(directoryErr))
	}

	ids := make([]string, 0, len(config.principals))
	var earliest time.Time
	for _, principal := range config.principals {
		ids = append(ids, principal.PrincipalID)
		if principal.Status == "active" && now.Before(principal.ExpiresAt) && (earliest.IsZero() || principal.ExpiresAt.Before(earliest)) {
			earliest = principal.ExpiresAt
		}
	}
	usable := 0
	if config.err == nil {
		usable = usableWorkflowMachinePrincipalCount(config.principals, now)
	}
	legacyExpiresAt := ""
	if config.legacy.Configured {
		legacyExpiresAt = config.legacy.ExpiresAt.UTC().Format(time.RFC3339)
	}
	earliestExpiry := ""
	if !earliest.IsZero() {
		earliestExpiry = earliest.UTC().Format(time.RFC3339)
	}
	logger.Info("workflow run credential surface loaded",
		zap.Int("principals", len(config.principals)),
		zap.Int("usable", usable),
		zap.Strings("principal_ids", ids),
		zap.String("earliest_expiry", earliestExpiry),
		zap.Bool("workflow_refused", config.err != nil),
		zap.Bool("legacy_configured", config.legacy.Configured),
		zap.Bool("legacy_active", config.err == nil && config.legacyActive(now)),
		zap.String("legacy_expires_at", legacyExpiresAt),
		zap.Bool("legacy_refused", config.legacyErr != nil),
		zap.Bool("anonymous_allowed", config.anonymousAllowed()),
		zap.Bool("directory_refused", directoryErr != nil),
	)
}
