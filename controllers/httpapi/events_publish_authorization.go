package httpapi

import (
	"errors"
	"net/http"
	"strings"
)

const eventPublisherAuthorizationPath = "/api/v1/events/authorization"

type eventPublisherAuthorizationRequest struct {
	Provider   string `json:"provider"`
	InstanceID string `json:"instance_id"`
	EventType  string `json:"event_type"`
}

type eventPublisherAuthorizationResponse struct {
	Allowed            bool   `json:"allowed"`
	PrincipalID        string `json:"principal_id"`
	Provider           string `json:"provider"`
	InstanceID         string `json:"instance_id"`
	EventType          string `json:"event_type"`
	GrantForm          string `json:"grant_form"`
	GrantCount         int    `json:"grant_count"`
	GrantSetSHA256     string `json:"grant_set_sha256"`
	PrincipalExpiresAt string `json:"principal_expires_at"`
}

// handleEventPublisherAuthorization proves how the bearer on this request is
// authorized without publishing an event. It returns only the authenticated
// principal identity, the matched exact/logical grant and a canonical digest
// of the complete grant set. The bearer and its configured SHA-256 digest are
// never returned.
func (s *Server) handleEventPublisherAuthorization(w http.ResponseWriter, r *http.Request) {
	actor, err := s.authenticateEventPublishRequest(r)
	if err != nil {
		writeMappedError(w, err)
		return
	}
	if actor.MachinePrincipal == nil {
		writeProblemJSON(w, http.StatusForbidden, "event.authorization_denied", "hashed event publisher principal required")
		return
	}

	var request eventPublisherAuthorizationRequest
	if err := decodeJSON(r, &request); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid event authorization request")
		return
	}
	request.Provider = strings.TrimSpace(request.Provider)
	request.InstanceID = strings.TrimSpace(request.InstanceID)
	request.EventType = strings.TrimSpace(request.EventType)
	if request.Provider == "" || request.InstanceID == "" || request.EventType == "" {
		writeJSONError(w, http.StatusBadRequest, "provider, instance_id, and event_type are required")
		return
	}

	actor, err = s.authorizeEventPublishPayload(r.Context(), eventPublishRequest{
		Provider:   request.Provider,
		InstanceID: request.InstanceID,
		EventType:  request.EventType,
	}, actor)
	if errors.Is(err, errEventPublishAuthorizationUnavailable) {
		writeProblemJSON(w, http.StatusServiceUnavailable, "event.authorization_unavailable", eventPublishUnavailableDetail)
		return
	}
	if err != nil {
		writeProblemJSON(w, http.StatusForbidden, "event.authorization_denied", eventPublishDeniedDetail)
		return
	}

	count, fingerprint := eventPublisherGrantSetFingerprint(actor.MachinePrincipal)
	writeJSON(w, http.StatusOK, eventPublisherAuthorizationResponse{
		Allowed:            true,
		PrincipalID:        actor.MachinePrincipal.PrincipalID,
		Provider:           request.Provider,
		InstanceID:         request.InstanceID,
		EventType:          request.EventType,
		GrantForm:          actor.GrantForm,
		GrantCount:         count,
		GrantSetSHA256:     fingerprint,
		PrincipalExpiresAt: actor.MachinePrincipal.ExpiresAt.UTC().Format("2006-01-02T15:04:05Z"),
	})
}
