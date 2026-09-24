package httpapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// eventPublishAuthConfig is the event publisher credential surface (ADR-0017,
// ADR-0021), parsed once by New from YGGDRASIL_EVENT_PUBLISHER_PRINCIPALS_JSON
// and the legacy bridge variables. The outer console gate and the handler read
// this same copy and never read those variables again, so the inventory a
// request sees is exactly the one this process loaded.
//
// A refused inventory (malformed, or set but blank) does not stop boot when
// YGGDRASIL_ENV is unset (then validateBootSecrets does not run): err is kept,
// New logs it at error level, and every event request fails closed with 401.
// With YGGDRASIL_ENV=production validateBootSecrets refuses the same
// inventory before New gets here.
//
// Refused legacy bridge settings are kept apart in legacyErr: they switch off
// only the plaintext bridge and the anonymous development posture, while the
// hashed principals keep authenticating, as they did before the load-once
// change.
type eventPublishAuthConfig struct {
	principals []eventPublisherPrincipal
	err        error
	legacy     legacyEventPublishCredential
	legacyErr  error
}

func loadEventPublishAuthConfig() *eventPublishAuthConfig {
	principals, err := eventPublisherPrincipalsFromEnv()
	if err != nil {
		return &eventPublishAuthConfig{err: err}
	}
	config := &eventPublishAuthConfig{principals: principals}
	config.legacy, config.legacyErr = legacyEventPublishCredentialFromEnv(time.Now().UTC())
	if config.legacyErr != nil {
		config.legacy = legacyEventPublishCredential{}
	}
	return config
}

// legacyActive re-evaluates the bridge expiry on every request; only the parse
// is cached.
func (c *eventPublishAuthConfig) legacyActive(now time.Time) bool {
	return c.legacy.Configured && now.Before(c.legacy.ExpiresAt)
}

const (
	eventGrantFormExact   = "exact"
	eventGrantFormLogical = "logical"

	// Every metadata key under this prefix is server-authored. Client values
	// are dropped before the server stamps its own.
	eventPublisherReservedMetadataPrefix        = "yggdrasil.io/publisher_"
	eventPublisherGrantFormMetadataKey          = "yggdrasil.io/publisher_grant_form"
	eventPublisherInstanceNamespaceMetadataKey  = "yggdrasil.io/publisher_instance_namespace"
	eventPublisherInstanceNameMetadataKey       = "yggdrasil.io/publisher_instance_name"
	eventPublisherInstanceManifestIDMetadataKey = "yggdrasil.io/publisher_instance_manifest_id"
	eventPublisherInstanceVersionMetadataKey    = "yggdrasil.io/publisher_instance_version"

	// eventPublishDeniedDetail is the one 403 detail for a mutation event the
	// principal may not publish. Not found, not granted and wrong provider
	// all answer with it, so a caller cannot probe the catalog.
	eventPublishDeniedDetail = "machine event principal is not allowed for this provider, instance, and event type"
	// eventPublishUnavailableDetail is the fixed 503 detail. The database
	// error is logged, never echoed.
	eventPublishUnavailableDetail = "event publisher authorization is temporarily unavailable"

	eventInstanceResolutionTimeout = 3 * time.Second
)

var errEventPublishAuthorizationUnavailable = errors.New("event publish authorization unavailable")

func (s *Server) authorizeEventPublishRequest(r *http.Request) error {
	_, err := s.authenticateEventPublishRequest(r)
	return err
}

func (s *Server) authenticateEventPublishRequest(r *http.Request) (eventPublishActor, error) {
	if r.Method != http.MethodPost || r.URL.Path != "/api/v1/events" {
		return eventPublishActor{}, errWorkflowRunUnauthorized
	}
	// This machine-only route is not wrapped in an event-publish RBAC
	// permission. A verified console session must therefore not become an
	// implicit generic event publisher merely because bearerOrSession attached
	// claims to the request context.
	if _, ok := claimsFromContext(r.Context()); ok {
		return eventPublishActor{}, errWorkflowRunUnauthorized
	}
	config := s.eventPublishAuth
	if config == nil || config.err != nil {
		// Only New builds a production Server, and New keeps a refused
		// inventory as config.err after logging it once. Neither case may
		// fall into the anonymous development posture, and the parser
		// diagnostics stay in the boot log instead of reaching a caller.
		return eventPublishActor{}, errWorkflowRunUnauthorized
	}

	now := time.Now().UTC()
	candidates := []string{
		strings.TrimSpace(r.Header.Get("X-Yggdrasil-Event-Token")),
		bearerToken(r.Header.Get("Authorization")),
	}
	for _, candidate := range candidates {
		if principal := activeEventPublisherPrincipal(candidate, config.principals, now); principal != nil {
			return eventPublishActor{MachinePrincipal: principal}, nil
		}
	}

	// Refused bridge settings switch off the bridge and the anonymous
	// posture below, never the principals matched above.
	if config.legacyErr != nil {
		return eventPublishActor{}, errWorkflowRunUnauthorized
	}

	// Plaintext compatibility bridge. It is accepted only when operators opt in
	// explicitly with a future expiry, remains route-limited here, and is not
	// consulted by workflow, manifest, auth-admin, deploy, or generic ops gates.
	if config.legacyActive(now) {
		for _, candidate := range candidates {
			if constantTimeTokenEqual(candidate, config.legacy.Token) {
				return eventPublishActor{LegacyMigration: true}, nil
			}
		}
	}

	// Preserve anonymous local development only when the event auth surface is
	// entirely unconfigured and the caller did not present a credential that
	// belongs to some other scope.
	if !config.legacy.Configured && len(config.principals) == 0 && !requestPresentsStaticCredential(r) && devEnvAllowsFallback() {
		return eventPublishActor{}, nil
	}
	return eventPublishActor{}, errWorkflowRunUnauthorized
}

// authorizeEventPublishPayload decides the payload against the authenticated
// actor and returns the actor carrying the verified grant (ADR-0021). Order:
//  1. exact triple: in memory, never touches the database;
//  2. only if the principal holds a logical grant for this provider and
//     event_type: resolve instance_id to the logical instance and require an
//     active integration_instance whose active integration_type provider is
//     the event provider, then look the resolved namespace/name up in the
//     principal's logical grants.
//
// Not resolvable, not granted and wrong provider return the same error. A
// database failure returns errEventPublishAuthorizationUnavailable.
func (s *Server) authorizeEventPublishPayload(ctx context.Context, req eventPublishRequest, actor eventPublishActor) (eventPublishActor, error) {
	actor.GrantForm, actor.Instance = "", nil
	if actor.LegacyMigration && strings.TrimSpace(req.EventType) == "" {
		return actor, fmt.Errorf("%w: legacy event bridge cannot publish generic events", errEventPublishAuthorizationDenied)
	}
	principal := actor.MachinePrincipal
	if principal == nil {
		return actor, nil
	}
	if strings.TrimSpace(req.EventType) == "" {
		return actor, fmt.Errorf("%w: machine event principals cannot publish generic events", errEventPublishAuthorizationDenied)
	}
	denied := fmt.Errorf("%w: %s", errEventPublishAuthorizationDenied, eventPublishDeniedDetail)

	if eventPublisherPrincipalAllows(principal, req.Provider, req.InstanceID, req.EventType) {
		actor.GrantForm = eventGrantFormExact
		return actor, nil
	}
	if !eventPublisherPrincipalHasLogicalGrant(principal, req.Provider, req.EventType) {
		return actor, denied
	}

	identity, err := s.resolveEventInstance(ctx, req.InstanceID)
	if errors.Is(err, repository.ErrIntegrationInstanceNotResolvable) {
		return actor, denied
	}
	if err != nil {
		if s.logger != nil {
			if errors.Is(ctx.Err(), context.Canceled) {
				// The caller went away during the lookup. That is not a
				// database outage, so it is not reported as one.
				s.logger.Debug("event publisher instance resolution abandoned: request cancelled",
					zap.String("principal_id", principal.PrincipalID))
			} else {
				s.logger.Error("event publisher instance resolution failed; answering 503",
					zap.String("principal_id", principal.PrincipalID),
					zap.Error(err))
			}
		}
		return actor, errEventPublishAuthorizationUnavailable
	}
	provider := strings.TrimSpace(req.Provider)
	if identity.TypeProvider != provider ||
		!eventPublisherPrincipalAllowsLogical(principal, provider, identity.Namespace, identity.Name, req.EventType) {
		return actor, denied
	}
	actor.GrantForm = eventGrantFormLogical
	actor.Instance = &identity
	return actor, nil
}

// eventInstanceRef is a wire instance_id the logical path may resolve. Exactly
// one form is set: the per-version manifest UUID, or a literal namespace/name.
type eventInstanceRef struct {
	ManifestID uuid.UUID
	Namespace  string
	Name       string
}

// parseEventInstanceRef accepts only the canonical lowercase hyphenated UUID
// (the form Core hands adapters) or a strict "<namespace>/<name>". Anything
// else, a bare instance name included, is not resolvable: a bare name can only
// ever match an exact grant.
func parseEventInstanceRef(wire string) (eventInstanceRef, bool) {
	wire = strings.TrimSpace(wire)
	if strings.Contains(wire, "/") {
		namespace, name, err := parseLogicalInstanceRef(wire)
		if err != nil {
			return eventInstanceRef{}, false
		}
		return eventInstanceRef{Namespace: namespace, Name: name}, true
	}
	id, err := uuid.Parse(wire)
	if err != nil || id.String() != wire {
		return eventInstanceRef{}, false
	}
	return eventInstanceRef{ManifestID: id}, true
}

// resolveEventInstance resolves a wire instance_id to the logical instance
// and its active type provider in one statement, so "not found" and "found"
// both cost one round trip. An unparseable value never reaches the database.
// The lookup is bounded by eventInstanceResolutionTimeout.
func (s *Server) resolveEventInstance(ctx context.Context, wire string) (repository.IntegrationInstanceIdentity, error) {
	ref, ok := parseEventInstanceRef(wire)
	if !ok {
		return repository.IntegrationInstanceIdentity{}, repository.ErrIntegrationInstanceNotResolvable
	}
	ctx, cancel := context.WithTimeout(ctx, eventInstanceResolutionTimeout)
	defer cancel()
	if s.eventInstanceResolver != nil {
		return s.eventInstanceResolver(ctx, ref)
	}
	if s.db == nil {
		return repository.IntegrationInstanceIdentity{}, errEventPublishAuthorizationUnavailable
	}
	if ref.Name != "" {
		return repository.ResolveIntegrationInstanceByName(ctx, s.db, ref.Namespace, ref.Name)
	}
	return repository.ResolveIntegrationInstanceByManifestID(ctx, s.db, ref.ManifestID)
}
