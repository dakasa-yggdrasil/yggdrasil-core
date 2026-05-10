package httpapi

import (
	"database/sql"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

const maxAvatarImageBytes = 1024 * 1024

func (s *Server) handleUserPreferencesGet(w http.ResponseWriter, r *http.Request) {
	_, collaborator, ok := s.resolveCurrentCollaborator(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"preferences": userPreferencesFromCollaborator(collaborator)})
}

func (s *Server) handleUserPreferencesPatch(w http.ResponseWriter, r *http.Request) {
	_, collaborator, ok := s.resolveCurrentCollaborator(w, r)
	if !ok {
		return
	}

	var req model.UpdateUserPreferencesRequest
	if err := decodeJSON(r, &req); err != nil {
		writeMappedError(w, err)
		return
	}

	personalData, err := patchUserPreferences(collaborator, req)
	if err != nil {
		writeMappedError(w, err)
		return
	}

	updated, err := repository.UpdateCollaborator(r.Context(), s.db, model.UpdateCollaboratorRequest{
		ID:           collaborator.ID.String(),
		PersonalData: &personalData,
	})
	if err != nil {
		writeMappedError(w, err)
		return
	}

	if touchesYggdrasilIdentity(req) {
		if err := markProviderIdentityUpdatesPending(r, s.db, updated); err != nil {
			writeMappedError(w, err)
			return
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{"preferences": userPreferencesFromCollaborator(updated)})
}

func (s *Server) resolveCurrentCollaborator(w http.ResponseWriter, r *http.Request) (model.AuthSession, model.Collaborator, bool) {
	token, ok := extractAuthToken(r)
	if !ok {
		writeJSONError(w, http.StatusUnauthorized, "unauthenticated")
		return model.AuthSession{}, model.Collaborator{}, false
	}

	session, collaborator, err := repository.ResolveAuthSession(r.Context(), s.db, token)
	if err != nil {
		if isAuthUnauthorizedError(err) {
			clearAuthCookie(w)
			writeJSONError(w, http.StatusUnauthorized, "unauthenticated")
			return model.AuthSession{}, model.Collaborator{}, false
		}
		writeMappedError(w, err)
		return model.AuthSession{}, model.Collaborator{}, false
	}
	return session, collaborator, true
}

func userPreferencesFromCollaborator(collaborator model.Collaborator) model.UserPreferences {
	personalData := collaborator.PersonalData
	profile := mapValue(personalData["profile"])
	preferences := mapValue(personalData["preferences"])
	yggdrasil := mapValue(personalData["yggdrasil"])

	preferredName := stringValue(personalData["preferred_name"])
	if preferredName == "" {
		preferredName = stringValue(collaborator.Traits["preferred_name"])
	}

	avatarDataURL := stringValue(profile["avatar_data_url"])

	accentColor := stringValue(preferences["accent_color"])
	if accentColor == "" {
		accentColor = stringValue(yggdrasil["accent_color"])
	}

	return model.UserPreferences{
		PreferredName: preferredName,
		AvatarDataURL: avatarDataURL,
		AccentColor:   accentColor,
	}
}

func patchUserPreferences(collaborator model.Collaborator, req model.UpdateUserPreferencesRequest) (map[string]any, error) {
	personalData := cloneAnyMap(collaborator.PersonalData)
	if personalData == nil {
		personalData = map[string]any{}
	}

	if req.PreferredName != nil {
		value := strings.TrimSpace(*req.PreferredName)
		if len(value) > 80 {
			return nil, fmt.Errorf("preferred_name must be at most 80 characters")
		}
		setOrDelete(personalData, "preferred_name", value)
	}

	if req.AvatarDataURL != nil {
		value := strings.TrimSpace(*req.AvatarDataURL)
		if err := validateOptionalAvatarDataURL(value); err != nil {
			return nil, err
		}
		profile := cloneAnyMap(mapValue(personalData["profile"]))
		if profile == nil {
			profile = map[string]any{}
		}
		delete(profile, "avatar_url")
		delete(personalData, "avatar_url")
		setOrDelete(profile, "avatar_data_url", value)
		setOrDelete(personalData, "profile", profile)
	}

	if req.AccentColor != nil {
		value := strings.TrimSpace(*req.AccentColor)
		if value != "" && !isHexColor(value) {
			return nil, fmt.Errorf("accent_color must be a hex color like #4fd1c5")
		}
		preferences := cloneAnyMap(mapValue(personalData["preferences"]))
		if preferences == nil {
			preferences = map[string]any{}
		}
		setOrDelete(preferences, "accent_color", strings.ToLower(value))
		setOrDelete(personalData, "preferences", preferences)
	}

	return personalData, nil
}

func touchesYggdrasilIdentity(req model.UpdateUserPreferencesRequest) bool {
	return req.PreferredName != nil || req.AvatarDataURL != nil
}

func markProviderIdentityUpdatesPending(r *http.Request, db *sql.DB, collaborator model.Collaborator) error {
	states, err := repository.ListProviderStateByCollaborator(r.Context(), db, collaborator.ID)
	if err != nil {
		return err
	}
	if len(states) == 0 {
		return nil
	}
	for _, state := range states {
		desired := cloneAnyMap(state.DesiredState)
		if desired == nil {
			desired = map[string]any{}
		}
		applyYggdrasilIdentityDesiredState(desired, collaborator)
		_, err := repository.UpsertCollaboratorProviderState(r.Context(), db, model.UpsertProviderStateRequest{
			CollaboratorID: collaborator.ID,
			Provider:       state.Provider,
			ExternalID:     state.ExternalID,
			DesiredState:   desired,
			PendingAction:  model.PendingActionUpdate,
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func applyYggdrasilIdentityDesiredState(desired map[string]any, collaborator model.Collaborator) {
	preferences := userPreferencesFromCollaborator(collaborator)
	displayName := strings.TrimSpace(collaborator.DisplayName)
	fullName := strings.TrimSpace(preferences.PreferredName)
	if fullName == "" {
		fullName = displayName
	}

	setOrDelete(desired, "primary_email", collaborator.PrimaryEmail)
	setOrDelete(desired, "display_name", displayName)
	setOrDelete(desired, "full_name", fullName)
	setOrDelete(desired, "preferred_name", preferences.PreferredName)
	setOrDelete(desired, "avatar_data_url", preferences.AvatarDataURL)
	desired["identity_source"] = "yggdrasil"

	profile := cloneAnyMap(mapValue(desired["profile"]))
	if profile == nil {
		profile = map[string]any{}
	}
	setOrDelete(profile, "display_name", displayName)
	setOrDelete(profile, "full_name", fullName)
	setOrDelete(profile, "preferred_name", preferences.PreferredName)
	setOrDelete(profile, "avatar_data_url", preferences.AvatarDataURL)
	profile["source"] = "yggdrasil"
	setOrDelete(desired, "profile", profile)
}

func validateOptionalAvatarDataURL(value string) error {
	if value == "" {
		return nil
	}

	comma := strings.IndexByte(value, ',')
	if comma < 0 {
		return fmt.Errorf("avatar_data_url must be an imported image")
	}

	metadata := strings.ToLower(value[:comma+1])
	switch metadata {
	case "data:image/png;base64,", "data:image/jpeg;base64,", "data:image/webp;base64,", "data:image/gif;base64,":
	default:
		return fmt.Errorf("avatar_data_url must be a PNG, JPG, WebP, or GIF image")
	}

	encoded := value[comma+1:]
	if encoded == "" {
		return fmt.Errorf("avatar_data_url must contain image data")
	}
	if len(encoded) > ((maxAvatarImageBytes+2)/3)*4+4 {
		return fmt.Errorf("avatar_data_url must be at most 1 MiB")
	}

	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return fmt.Errorf("avatar_data_url must be a valid base64 image")
	}
	if len(decoded) == 0 {
		return fmt.Errorf("avatar_data_url must contain image data")
	}
	if len(decoded) > maxAvatarImageBytes {
		return fmt.Errorf("avatar_data_url must be at most 1 MiB")
	}

	return nil
}

func setOrDelete(target map[string]any, key string, value any) {
	switch typed := value.(type) {
	case string:
		if strings.TrimSpace(typed) == "" {
			delete(target, key)
			return
		}
	case map[string]any:
		if len(typed) == 0 {
			delete(target, key)
			return
		}
	}
	target[key] = value
}

func mapValue(value any) map[string]any {
	if typed, ok := value.(map[string]any); ok {
		return typed
	}
	return nil
}

func stringValue(value any) string {
	if typed, ok := value.(string); ok {
		return strings.TrimSpace(typed)
	}
	return ""
}

func isHexColor(value string) bool {
	return strings.HasPrefix(value, "#") && len(value) == 7 && allHex(value[1:])
}

func allHex(value string) bool {
	for _, r := range value {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') && (r < 'A' || r > 'F') {
			return false
		}
	}
	return true
}
