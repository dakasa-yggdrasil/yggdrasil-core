// Package surface implements the yggdrasil-core side of the
// console-ops surface contract: discovery (polling adapters that
// expose GET /surface/manifest), caching, permission reconciliation,
// and proxying GET /surface/data and POST /surface/action through
// to the adapter while enforcing auth + RBAC + audit.
package surface

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	sdksurface "github.com/dakasa-yggdrasil/yggdrasil-sdk-go/surface"
)

// ErrNoSurface is returned when an adapter responds 404 to
// /surface/manifest. Callers MUST treat this as "this adapter does
// not contribute a surface" — NOT as a hard error.
var ErrNoSurface = errors.New("adapter has no surface")

// Client is a thin HTTP client for talking to adapter surface
// endpoints. The base URL is the adapter's health-server URL
// (e.g. "http://heimdall.dakasa.svc.cluster.local:8080").
type Client struct {
	http *http.Client
}

func NewClient(h *http.Client) *Client {
	if h == nil {
		h = &http.Client{Timeout: 10 * time.Second}
	}
	return &Client{http: h}
}

// FetchManifest GETs /surface/manifest from the adapter, validates
// it against the SDK validator, and returns the parsed manifest.
func (c *Client) FetchManifest(ctx context.Context, baseURL string) (sdksurface.Manifest, error) {
	url := strings.TrimRight(baseURL, "/") + "/surface/manifest"
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	resp, err := c.http.Do(req)
	if err != nil {
		return sdksurface.Manifest{}, fmt.Errorf("get manifest %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return sdksurface.Manifest{}, ErrNoSurface
	}
	if resp.StatusCode != http.StatusOK {
		return sdksurface.Manifest{}, fmt.Errorf("get manifest %s: status %d", url, resp.StatusCode)
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return sdksurface.Manifest{}, fmt.Errorf("read manifest body: %w", err)
	}
	var m sdksurface.Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return sdksurface.Manifest{}, fmt.Errorf("decode manifest: %w", err)
	}
	if err := m.Validate(); err != nil {
		return sdksurface.Manifest{}, fmt.Errorf("validate manifest from %s: %w", baseURL, err)
	}
	return m, nil
}

// FetchData proxies GET /surface/data/{viewId}?{rawQuery}.
func (c *Client) FetchData(ctx context.Context, baseURL, viewID, rawQuery string) ([]byte, error) {
	url := strings.TrimRight(baseURL, "/") + "/surface/data/" + viewID
	if rawQuery != "" {
		url += "?" + rawQuery
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch data %s: %w", url, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read data body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return body, fmt.Errorf("fetch data %s: status %d", url, resp.StatusCode)
	}
	return body, nil
}

// ExecuteAction proxies POST /surface/action/{actionId}.
func (c *Client) ExecuteAction(ctx context.Context, baseURL, actionID string, body io.Reader) ([]byte, error) {
	url := strings.TrimRight(baseURL, "/") + "/surface/action/" + actionID
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, url, body)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("execute action %s: %w", url, err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return respBody, fmt.Errorf("execute action %s: status %d", url, resp.StatusCode)
	}
	return respBody, nil
}
