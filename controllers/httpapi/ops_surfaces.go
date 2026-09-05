package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
	"unicode"

	surfaceclient "github.com/dakasa-yggdrasil/yggdrasil-core/internal/surface"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

type opsSurfaceTargetsResponse struct {
	Targets []model.SurfaceRuntimeTarget `json:"targets"`
}

type opsSurfaceTargetUpsertRequest struct {
	BaseURL     string `json:"base_url"`
	Enabled     *bool  `json:"enabled,omitempty"`
	Description string `json:"description,omitempty"`
}

type opsSurfaceTargetRefreshResponse struct {
	Target    model.SurfaceRuntimeTarget `json:"target"`
	Refreshed bool                       `json:"refreshed"`
	Surface   *model.SurfaceListEntry    `json:"surface,omitempty"`
}

func (s *Server) handleOpsSurfacesList(w http.ResponseWriter, r *http.Request) {
	if s.db == nil {
		writeJSON(w, http.StatusOK, model.SurfaceListResponse{
			Surfaces: []model.SurfaceListEntry{},
		})
		return
	}

	rows, err := repository.ListSurfaceManifests(r.Context(), s.db)
	if err != nil {
		writeMappedError(w, err)
		return
	}
	surfaces := make([]model.SurfaceListEntry, 0, len(rows))
	for _, row := range rows {
		surfaces = append(surfaces, model.SurfaceListEntry{
			Surface:        row.SurfaceID,
			SurfaceVersion: row.SurfaceVersion,
			DisplayName:    row.DisplayName,
			Icon:           row.Icon,
			Health:         surfaceHealthForConsole(row.Health),
		})
	}
	writeJSON(w, http.StatusOK, model.SurfaceListResponse{
		Surfaces: surfaces,
	})
}

func (s *Server) handleOpsSurfaceTargetsList(w http.ResponseWriter, r *http.Request) {
	if s.db == nil {
		writeJSON(w, http.StatusOK, opsSurfaceTargetsResponse{Targets: []model.SurfaceRuntimeTarget{}})
		return
	}
	targets, err := repository.ListSurfaceRuntimeTargets(r.Context(), s.db, true)
	if err != nil {
		writeMappedError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, opsSurfaceTargetsResponse{Targets: targets})
}

func (s *Server) handleOpsSurfaceTargetUpsert(w http.ResponseWriter, r *http.Request) {
	id := normalizeSurfaceID(r.PathValue("id"))
	if id == "" {
		writeJSONError(w, http.StatusBadRequest, "missing surface id")
		return
	}
	var input opsSurfaceTargetUpsertRequest
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	baseURL, ok := normalizedSurfaceBaseURL(input.BaseURL)
	if !ok {
		writeJSONError(w, http.StatusBadRequest, "surface base URL must use http or https")
		return
	}
	enabled := true
	if input.Enabled != nil {
		enabled = *input.Enabled
	}
	target, err := repository.UpsertSurfaceRuntimeTarget(r.Context(), s.db, model.UpsertSurfaceRuntimeTargetRequest{
		SurfaceID:   id,
		BaseURL:     baseURL,
		Enabled:     enabled,
		Description: strings.TrimSpace(input.Description),
	})
	if err != nil {
		writeMappedError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, target)
}

func (s *Server) handleOpsSurfaceTargetDelete(w http.ResponseWriter, r *http.Request) {
	id := normalizeSurfaceID(r.PathValue("id"))
	if id == "" {
		writeJSONError(w, http.StatusBadRequest, "missing surface id")
		return
	}
	if err := repository.DeleteSurfaceRuntimeTarget(r.Context(), s.db, id); err != nil {
		if errors.Is(err, repository.ErrSurfaceRuntimeTargetNotFound) {
			writeJSONError(w, http.StatusNotFound, "surface target not found")
			return
		}
		writeMappedError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleOpsSurfaceTargetRefresh(w http.ResponseWriter, r *http.Request) {
	id := normalizeSurfaceID(r.PathValue("id"))
	if id == "" {
		writeJSONError(w, http.StatusBadRequest, "missing surface id")
		return
	}
	target, err := repository.GetSurfaceRuntimeTarget(r.Context(), s.db, id)
	if errors.Is(err, repository.ErrSurfaceRuntimeTargetNotFound) {
		writeJSONError(w, http.StatusNotFound, "surface target not found")
		return
	}
	if err != nil {
		writeMappedError(w, err)
		return
	}
	if !target.Enabled {
		writeJSONError(w, http.StatusConflict, "surface target is disabled")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	discovery := surfaceclient.NewDiscovery(s.db, surfaceclient.NewClient(nil), s.logger).
		WithReconciler(surfaceclient.NewPermissionsReconciler(s.db, s.logger))
	if err := discovery.RefreshOne(ctx, surfaceclient.AdapterTarget{ID: target.SurfaceID, BaseURL: target.BaseURL}); err != nil {
		writeMappedError(w, err)
		return
	}

	response := opsSurfaceTargetRefreshResponse{Target: target, Refreshed: true}
	if row, err := repository.GetSurfaceManifest(r.Context(), s.db, target.SurfaceID); err == nil {
		surface := surfaceListEntryFromCached(row)
		response.Surface = &surface
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) handleOpsSurfaceManifest(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeJSONError(w, http.StatusBadRequest, "missing surface id")
		return
	}
	if s.db == nil {
		writeJSONError(w, http.StatusNotFound, "surface not found")
		return
	}
	row, err := repository.GetSurfaceManifest(r.Context(), s.db, id)
	if errors.Is(err, repository.ErrSurfaceManifestNotFound) {
		writeJSONError(w, http.StatusNotFound, "surface not found")
		return
	}
	if err != nil {
		writeMappedError(w, err)
		return
	}
	if len(bytes.TrimSpace(row.Raw)) == 0 {
		writeJSONError(w, http.StatusNotFound, "surface not found")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(row.Raw)
}

func (s *Server) handleOpsSurfaceData(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	viewID := r.PathValue("viewId")
	if strings.TrimSpace(id) == "" || strings.TrimSpace(viewID) == "" {
		writeJSONError(w, http.StatusBadRequest, "missing surface id or view id")
		return
	}
	baseURL, ok := s.resolveSurfaceBaseURL(r.Context(), id)
	if !ok {
		writeJSONError(w, http.StatusServiceUnavailable, "surface runtime endpoint not configured")
		return
	}
	body, err := surfaceclient.NewClient(nil).FetchData(r.Context(), baseURL, viewID, r.URL.RawQuery)
	if err != nil {
		writeJSONError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSONBytes(w, http.StatusOK, body)
}

func (s *Server) handleOpsSurfaceAction(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	actionID := r.PathValue("actionId")
	if strings.TrimSpace(id) == "" || strings.TrimSpace(actionID) == "" {
		writeJSONError(w, http.StatusBadRequest, "missing surface id or action id")
		return
	}
	requestBody, err := io.ReadAll(r.Body)
	if err != nil {
		writeMappedError(w, fmt.Errorf("read surface action body: %w", err))
		return
	}
	configResult, err := s.persistOpsSurfaceConfiguration(r.Context(), id, actionID, requestBody)
	if err != nil {
		writeMappedError(w, err)
		return
	}
	baseURL, ok := s.resolveSurfaceBaseURL(r.Context(), id)
	if !ok {
		if configResult != nil {
			writeJSON(w, http.StatusOK, configResult)
			return
		}
		writeJSONError(w, http.StatusServiceUnavailable, "surface runtime endpoint not configured")
		return
	}
	body, err := surfaceclient.NewClient(nil).ExecuteAction(r.Context(), baseURL, actionID, bytes.NewReader(requestBody))
	if err != nil {
		writeJSONError(w, http.StatusBadGateway, err.Error())
		return
	}
	if configResult != nil {
		var adapterResponse any
		if err := json.Unmarshal(body, &adapterResponse); err != nil {
			writeJSONError(w, http.StatusBadGateway, "surface returned invalid JSON")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"configuration": configResult,
			"adapter":       adapterResponse,
		})
		return
	}
	writeJSONBytes(w, http.StatusOK, body)
}

func (s *Server) persistOpsSurfaceConfiguration(ctx context.Context, surfaceID, actionID string, raw []byte) (map[string]any, error) {
	if s.db == nil || strings.TrimSpace(actionID) != "configure" {
		return nil, nil
	}
	secretFields, err := s.opsSurfaceSecretFields(ctx, surfaceID)
	if err != nil {
		return nil, err
	}
	if len(secretFields) == 0 {
		return nil, nil
	}

	payload := map[string]any{}
	if len(bytes.TrimSpace(raw)) > 0 {
		if err := json.Unmarshal(raw, &payload); err != nil {
			return nil, fmt.Errorf("decode surface configuration: %w", err)
		}
	}

	secretData := make(map[string]string, len(secretFields))
	for key := range secretFields {
		value, exists := payload[key]
		if !exists || value == nil || strings.TrimSpace(anyString(value)) == "" {
			continue
		}
		secretValue, err := stringifySecretScalar(value)
		if err != nil {
			return nil, fmt.Errorf("surface configuration field %q: %w", key, err)
		}
		secretData[key] = secretValue
	}
	if len(secretData) == 0 {
		return nil, nil
	}

	namespace := firstNonEmpty(anyString(payload["namespace"]), "global")
	instanceName := firstNonEmpty(anyString(payload["instance_name"]), surfaceID)
	secretName := normalizeSecretNameToken(fmt.Sprintf("%s-%s-surface-config", surfaceID, instanceName))
	secret, err := repository.UpsertManagedSecret(ctx, s.db, model.UpsertManagedSecretRequest{
		Namespace: namespace,
		Name:      secretName,
		Status:    "active",
		Data:      secretData,
		Metadata: map[string]any{
			"source_kind": "ops_surface_config",
			"surface":     surfaceID,
			"instance": map[string]any{
				"namespace": namespace,
				"name":      instanceName,
			},
		},
		Rotation: model.ManagedSecretRotationPolicy{Mode: "manual"},
	})
	if err != nil {
		return nil, err
	}

	return map[string]any{
		"accepted": true,
		"status":   "stored",
		"message":  "Configuração salva. Os segredos foram guardados como managed_secret do Yggdrasil.",
		"secret":   model.BuildManagedSecretView(secret),
		"received": redactOpsSurfacePayload(payload, secretFields),
	}, nil
}

func (s *Server) opsSurfaceSecretFields(ctx context.Context, surfaceID string) (map[string]struct{}, error) {
	row, err := repository.GetSurfaceManifest(ctx, s.db, surfaceID)
	if errors.Is(err, repository.ErrSurfaceManifestNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var manifest model.SurfaceManifest
	if err := json.Unmarshal(row.Raw, &manifest); err != nil {
		return nil, fmt.Errorf("decode cached surface manifest: %w", err)
	}
	for _, page := range manifest.Pages {
		if page.ID != "configure" {
			continue
		}
		fields, _ := page.View["fields"].([]any)
		out := map[string]struct{}{}
		for _, rawField := range fields {
			field, _ := rawField.(map[string]any)
			if strings.TrimSpace(anyString(field["kind"])) != "secret" {
				continue
			}
			name := strings.TrimSpace(anyString(field["field"]))
			if name != "" {
				out[name] = struct{}{}
			}
		}
		return out, nil
	}
	return nil, nil
}

func redactOpsSurfacePayload(input map[string]any, secretFields map[string]struct{}) map[string]any {
	output := make(map[string]any, len(input))
	for key, value := range input {
		if _, ok := secretFields[key]; ok {
			if strings.TrimSpace(fmt.Sprint(value)) == "" {
				output[key] = ""
			} else {
				output[key] = "********"
			}
			continue
		}
		output[key] = value
	}
	return output
}

func (s *Server) resolveSurfaceBaseURL(ctx context.Context, surfaceID string) (string, bool) {
	key := normalizeSurfaceID(surfaceID)
	if s.db != nil {
		target, err := repository.GetSurfaceRuntimeTarget(ctx, s.db, key)
		if err == nil {
			if !target.Enabled {
				return "", false
			}
			return normalizedSurfaceBaseURL(target.BaseURL)
		}
		if !errors.Is(err, repository.ErrSurfaceRuntimeTargetNotFound) {
			return "", false
		}
	}
	if s.surfaceBaseURLs != nil {
		if baseURL := strings.TrimSpace(s.surfaceBaseURLs[key]); baseURL != "" {
			return normalizedSurfaceBaseURL(baseURL)
		}
	}
	if baseURL := strings.TrimSpace(os.Getenv(surfaceBaseURLEnvName(surfaceID))); baseURL != "" {
		return normalizedSurfaceBaseURL(baseURL)
	}
	return "", false
}

func surfaceListEntryFromCached(row model.SurfaceManifestRow) model.SurfaceListEntry {
	return model.SurfaceListEntry{
		Surface:        row.SurfaceID,
		SurfaceVersion: row.SurfaceVersion,
		DisplayName:    row.DisplayName,
		Icon:           row.Icon,
		Health:         surfaceHealthForConsole(row.Health),
	}
}

func normalizedSurfaceBaseURL(value string) (string, bool) {
	if err := validateSurfaceBaseURL(value); err != nil {
		return "", false
	}
	return strings.TrimRight(strings.TrimSpace(value), "/"), true
}

func surfaceHealthForConsole(health string) string {
	switch strings.ToLower(strings.TrimSpace(health)) {
	case "ok", "warn", "error":
		return strings.ToLower(strings.TrimSpace(health))
	case "healthy":
		return "ok"
	case "down", "unhealthy", "unreachable":
		return "error"
	default:
		return "unknown"
	}
}

func writeJSONBytes(w http.ResponseWriter, status int, body []byte) {
	if !json.Valid(body) {
		writeJSONError(w, http.StatusBadGateway, "surface returned invalid JSON")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func normalizeSurfaceID(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func surfaceBaseURLEnvName(surfaceID string) string {
	var b strings.Builder
	b.WriteString("YGGDRASIL_SURFACE_")
	for _, r := range strings.TrimSpace(surfaceID) {
		switch {
		case unicode.IsLetter(r) || unicode.IsDigit(r):
			b.WriteRune(unicode.ToUpper(r))
		default:
			b.WriteByte('_')
		}
	}
	b.WriteString("_BASE_URL")
	return b.String()
}

func validateSurfaceBaseURL(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return fmt.Errorf("surface base URL is required")
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return fmt.Errorf("parse surface base URL: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("surface base URL must use http or https")
	}
	if parsed.Host == "" {
		return fmt.Errorf("surface base URL host is required")
	}
	return nil
}
