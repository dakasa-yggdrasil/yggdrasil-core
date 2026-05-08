package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/stretchr/testify/require"
)

func TestHandleOpsSurfacesList_EmptyByDefault(t *testing.T) {
	s := &Server{}
	req := httptest.NewRequest("GET", "/api/v1/ops/surfaces", nil)
	rec := httptest.NewRecorder()

	s.handleOpsSurfacesList(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var got model.SurfaceListResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&got))
	require.Empty(t, got.Surfaces)
}

func TestHandleOpsSurfaceManifest_NotFound(t *testing.T) {
	s := &Server{}
	req := httptest.NewRequest("GET", "/api/v1/ops/surfaces/heimdall/manifest", nil)
	req.SetPathValue("id", "heimdall")
	rec := httptest.NewRecorder()

	s.handleOpsSurfaceManifest(rec, req)
	require.Equal(t, http.StatusNotFound, rec.Code)
}
