package httpapi

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"

	sdksurface "github.com/dakasa-yggdrasil/yggdrasil-sdk-go/surface"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/integrationsurfaces"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

type surfaceQueryReqBody struct {
	QueryName string         `json:"query_name"`
	Params    map[string]any `json:"params,omitempty"`
}

// surfaceQueryRequirement is the view-access requirement a surface declares for
// one query. The zero value (empty Permission) means "no permission declared"
// — the query is UNGATED. Namespace, when set, lets the gate honour the same
// "any perm in the integration's namespace" rule the SPA's canViewSurface uses
// (surface-toolkit/SurfaceViewGate.tsx); it defaults to the leading segment of
// Permission when the source leaves it blank.
type surfaceQueryRequirement struct {
	// Permission is the canonical permission id the caller must hold (e.g.
	// "clt:contract:view-all"). Empty ⇒ the query is ungated.
	Permission string
	// Namespace is the integration's permission namespace (e.g. "clt"). A caller
	// holding ANY perm under "<namespace>." is allowed, mirroring canViewSurface.
	Namespace string
}

// SurfaceQueryPermSource resolves the permission (if any) a surface declares for
// a given (instanceID, queryName). It is the opt-in seam for the view-access
// gate: a nil source, an absent declaration, or an empty Permission all mean
// "ungated" (zero-lockout). The production implementation reads the surface
// manifest's spec.queries[].requires_permission; tests inject a fake.
type SurfaceQueryPermSource interface {
	RequiredPermission(ctx context.Context, instanceID, queryName string) (surfaceQueryRequirement, error)
}

// surfaceViewAdminPerms are the permissions that bypass the per-query gate — an
// integration/org admin may read any surface query, mirroring the SPA's
// SURFACE_VIEW_ADMIN_PERMS (surface-toolkit/SurfaceViewGate.tsx) and the console
// RBAC catalog (ops_rbac_catalog.go). God-mode ("yggdrasil:*") is handled
// separately by prefix in callerSatisfiesSurfacePerm.
var surfaceViewAdminPerms = []string{
	permManageIntegrations, // yggdrasil:manage_integrations
	permManageOrganization, // yggdrasil:manage_organization
}

func (s *Server) handleIntegrationSurfaceQuery() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.surfaceQueryDispatcher == nil {
			writeJSONError(w, http.StatusServiceUnavailable, "surface query dispatcher not configured")
			return
		}
		instanceID := strings.TrimSpace(r.PathValue("instance_id"))
		if instanceID == "" {
			writeJSONError(w, http.StatusBadRequest, "missing instance_id")
			return
		}
		var body surfaceQueryReqBody
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		if err := dec.Decode(&body); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid body: "+err.Error())
			return
		}
		queryName := strings.TrimSpace(body.QueryName)
		if queryName == "" {
			writeJSONError(w, http.StatusBadRequest, "query_name required")
			return
		}

		// SECURITY: opt-in, zero-lockout view-access gate. A surface MAY declare a
		// required permission for a query (manifest spec.queries[].requires_permission).
		// Enforcement order, matching the design and the SPA's canViewSurface:
		//   (a) query declares NO permission        ⇒ ALLOW (backward-compat; this
		//       is what keeps every current surface and the CLT my-* self-service
		//       reads working).
		//   (b) caller holds an admin bypass perm    ⇒ ALLOW.
		//   (c) caller holds the declared perm, OR any perm in its namespace ⇒ ALLOW.
		//   (d) otherwise                            ⇒ DENY (403 permission_denied),
		//       logged so would-be-denials are observable.
		// A nil perm-source disables the gate entirely (same as case (a) for every
		// query) so deploys/tests that have not wired it are unaffected.
		if !s.authorizeSurfaceQuery(w, r, instanceID, queryName) {
			return
		}

		input := map[string]any{
			"query_name": queryName,
			"params":     body.Params,
		}
		// SECURITY: stamp the SERVER-VERIFIED caller onto the outbound envelope so
		// caller-scoped adapter reads (e.g. CLT "Meu RH") can scope by it instead
		// of a spoofable client-supplied id. The collaborator id is taken from the
		// session claims attached by requireAuthenticatedConsoleAPIs — NEVER from
		// the request body/params. Token/automation callers have no collaborator
		// claim: omit the field rather than stamping an empty string (the adapter
		// treats absence as "no verified caller"). See
		// surface.InputVerifiedCallerID for the contract.
		if claims, ok := claimsFromContext(r.Context()); ok {
			if collabID, _ := claims["collaborator_id"].(string); strings.TrimSpace(collabID) != "" {
				input[sdksurface.InputVerifiedCallerID] = collabID
			}
		}
		req := model.ExecuteIntegrationRequest{
			Integration: model.ManifestSelector{ManifestID: instanceID},
			Operation:   model.OperationOnSurfaceQuery,
			Capability:  model.OperationOnSurfaceQuery,
			Input:       input,
		}
		resp, err := s.surfaceQueryDispatcher.Execute(r.Context(), req)
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]any{
				"error":   "adapter_dispatch_failed",
				"message": err.Error(),
			})
			return
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

// authorizeSurfaceQuery enforces the opt-in view-access gate. It returns true
// when the request may proceed and false when it has already written a deny/error
// response. It is fail-OPEN on "no declaration" (zero-lockout) but fail-CLOSED on
// an infrastructure error while resolving a DECLARED requirement (a surface that
// opted into gating must not silently degrade to open on a DB blip).
func (s *Server) authorizeSurfaceQuery(w http.ResponseWriter, r *http.Request, instanceID, queryName string) bool {
	// Gate disabled (no source wired) ⇒ every query is ungated. This is the
	// default and what keeps current deploys/tests unaffected.
	if s.surfaceQueryPermSource == nil {
		return true
	}

	requirement, err := s.surfaceQueryPermSource.RequiredPermission(r.Context(), instanceID, queryName)
	if err != nil {
		// We could not determine whether this query is gated. Fail closed: a
		// resolution error must not become an accidental allow for a surface that
		// may well be gated. Operators see the 500 regardless of rollout phase.
		if s.logger != nil {
			s.logger.Error("surface-query: permission requirement lookup failed",
				zap.String("instance_id", instanceID),
				zap.String("query_name", queryName),
				zap.Error(err),
			)
		}
		writeJSONError(w, http.StatusInternalServerError, "surface_query_authorization_failed")
		return false
	}

	// (a) No permission declared ⇒ ALLOW (the no-lockout / self-service case).
	required := strings.TrimSpace(requirement.Permission)
	if required == "" {
		return true
	}

	// The query is gated. Resolve the verified caller. An unauthenticated /
	// no-collaborator caller cannot satisfy a declared permission ⇒ deny.
	claims, ok := claimsFromContext(r.Context())
	collabID := ""
	if ok {
		collabID, _ = claims["collaborator_id"].(string)
		collabID = strings.TrimSpace(collabID)
	}
	if collabID == "" {
		s.denySurfaceQuery(w, r, instanceID, queryName, required, "")
		return false
	}

	perms, err := s.resolveCallerPermsForGate(r.Context(), collabID)
	if err != nil {
		// Fail closed on resolver error: a viewer's perms could not be established
		// for a GATED query. Same posture as the ops RBAC middleware.
		if s.logger != nil {
			s.logger.Error("surface-query: caller permission resolution failed",
				zap.String("instance_id", instanceID),
				zap.String("query_name", queryName),
				zap.String("permission", required),
				zap.String("collaborator_id", collabID),
				zap.Error(err),
			)
		}
		writeJSONError(w, http.StatusInternalServerError, "surface_query_authorization_failed")
		return false
	}

	namespace := strings.TrimSpace(requirement.Namespace)
	if namespace == "" {
		namespace = permissionNamespace(required)
	}
	if callerSatisfiesSurfacePerm(perms, required, namespace) {
		return true
	}

	s.denySurfaceQuery(w, r, instanceID, queryName, required, collabID)
	return false
}

// resolveCallerPermsForGate yields the caller's effective permissions, using the
// injected resolver when set (tests) and otherwise the production resolver —
// repository.ResolveYggdrasilPermissions over s.db, honouring traits god-mode —
// the SAME list /me and the ops RBAC gate use.
func (s *Server) resolveCallerPermsForGate(ctx context.Context, collaboratorID string) ([]string, error) {
	if s.callerPermResolver != nil {
		return s.callerPermResolver(ctx, collaboratorID)
	}
	collabUUID, err := uuid.Parse(collaboratorID)
	if err != nil {
		return nil, err
	}
	var traits map[string]any
	if c, cErr := getCollaboratorCached(ctx, s.db, collaboratorID); cErr == nil {
		traits = c.Traits
	}
	return repository.ResolveYggdrasilPermissions(ctx, s.db, collabUUID, traits)
}

// callerSatisfiesSurfacePerm mirrors the SPA's canViewSurface
// (surface-toolkit/SurfaceViewGate.tsx): a caller may read a gated query when
// they hold an admin bypass perm, god-mode, the exact declared permission, or
// ANY permission in the declared namespace.
//
// Namespace matching honours BOTH permission-id conventions in the fleet: the
// dot style ("slack.users.read", which canViewSurface keys on as "${provider}.")
// AND the colon style ("clt:contract:view-all"). A "clt"-namespace requirement
// is therefore satisfied by any "clt:" perm — the same "holds a perm in the
// integration's namespace" intent, applied to colon-separated families. The
// prefix carries the separator so "clt" never matches "cltish.x" / "clta:y".
func callerSatisfiesSurfacePerm(perms []string, required, namespace string) bool {
	nsPrefixes := make([]string, 0, 2)
	if namespace != "" {
		nsPrefixes = append(nsPrefixes, namespace+".", namespace+":")
	}
	for _, p := range perms {
		// God-mode wildcard grant satisfies anything (same as collaboratorHasOpsPermission).
		if p == repository.YggdrasilGodModeAction {
			return true
		}
		// Exact declared permission.
		if p == required {
			return true
		}
		// Admin bypass perms (integration/org admin sees all surfaces).
		for _, admin := range surfaceViewAdminPerms {
			if p == admin {
				return true
			}
		}
		// Namespace match: any perm under "<namespace>." or "<namespace>:".
		for _, nsPrefix := range nsPrefixes {
			if strings.HasPrefix(p, nsPrefix) {
				return true
			}
		}
	}
	return false
}

// permissionNamespace returns the leading namespace segment of a permission id,
// used when the surface declares a perm but no explicit namespace. Splits on the
// first '.' or ':' (perms are either "<ns>.<...>" like "slack.users.read" or
// "<ns>:<...>" like "clt:contract:view-all").
func permissionNamespace(perm string) string {
	if i := strings.IndexAny(perm, ".:"); i > 0 {
		return perm[:i]
	}
	return ""
}

// dbSurfaceQueryPermSource is the production SurfaceQueryPermSource. It resolves
// the surface manifest registered for an integration instance and returns the
// view-access requirement the manifest declares for the query (if any).
//
// Resolution chain (single query): the instance manifest (kind
// integration_instance, by manifest id) → its spec.type_ref → the
// integration_surfaces row whose integration_type matches that type name → the
// surface spec's queries[]. A query that is not listed, or has an empty
// requires_permission, resolves to the zero requirement ⇒ ungated. A missing
// instance or missing surface also resolves to ungated (fail-OPEN on "no
// declaration to enforce" — the gate only ever tightens a surface that has
// explicitly opted in; it must never lock out an instance that has no surface
// manifest or whose surface declares nothing).
type dbSurfaceQueryPermSource struct {
	db *sql.DB
}

// NewDBSurfaceQueryPermSource builds the production permission source over the
// given database handle. Returns nil when db is nil so callers can wire it
// unconditionally and still get the "gate disabled" default.
func NewDBSurfaceQueryPermSource(db *sql.DB) SurfaceQueryPermSource {
	if db == nil {
		return nil
	}
	return &dbSurfaceQueryPermSource{db: db}
}

func (s *dbSurfaceQueryPermSource) RequiredPermission(ctx context.Context, instanceID, queryName string) (surfaceQueryRequirement, error) {
	// Resolve the surface spec for the instance's integration_type. We match the
	// surface registry's integration_type (the type NAME, e.g. "employment-clt")
	// against the instance manifest's spec.type_ref name. The instance id can be
	// either the manifests.id (uuid) or the metadata.name; match both so the
	// handler's instance_id path value resolves regardless of which form callers
	// use. A NULL/absent surface yields sql.ErrNoRows ⇒ ungated.
	const q = `
SELECT isf.spec
FROM public.manifests ii
JOIN public.manifests it
  ON it.kind = 'integration_type'
 AND it.metadata->>'namespace' = (ii.spec->'type_ref'->>'namespace')
 AND it.metadata->>'name'      = (ii.spec->'type_ref'->>'name')
JOIN public.integration_surfaces isf
  ON isf.integration_type = it.metadata->>'name'
 AND isf.active = true
WHERE ii.kind = 'integration_instance'
  AND (ii.id::text = $1 OR ii.metadata->>'name' = $1)
LIMIT 1`

	var specRaw []byte
	err := s.db.QueryRowContext(ctx, q, instanceID).Scan(&specRaw)
	if err == sql.ErrNoRows {
		// No surface manifest for this instance ⇒ nothing declared ⇒ ungated.
		return surfaceQueryRequirement{}, nil
	}
	if err != nil {
		return surfaceQueryRequirement{}, err
	}

	var spec integrationsurfaces.ManifestSpec
	if err := json.Unmarshal(specRaw, &spec); err != nil {
		return surfaceQueryRequirement{}, err
	}
	for _, qd := range spec.Queries {
		if qd.Name != queryName {
			continue
		}
		perm := strings.TrimSpace(qd.RequiresPermission)
		if perm == "" {
			return surfaceQueryRequirement{}, nil // declared but ungated
		}
		return surfaceQueryRequirement{Permission: perm, Namespace: permissionNamespace(perm)}, nil
	}
	// Query not listed in the surface manifest ⇒ ungated.
	return surfaceQueryRequirement{}, nil
}

// denySurfaceQuery writes the 403 permission_denied response and logs the
// would-be-denial so partial-rollout drift between the SPA's gate and this
// backend gate is observable.
func (s *Server) denySurfaceQuery(w http.ResponseWriter, r *http.Request, instanceID, queryName, required, collabID string) {
	if s.logger != nil {
		s.logger.Warn("surface-query: permission denied",
			zap.String("instance_id", instanceID),
			zap.String("query_name", queryName),
			zap.String("permission", required),
			zap.String("collaborator_id", collabID),
			zap.String("path", r.URL.Path),
		)
	}
	writeJSON(w, http.StatusForbidden, map[string]any{
		"error":      "permission_denied",
		"message":    "You do not have the required permission " + required + " to read this surface query.",
		"permission": required,
	})
}
