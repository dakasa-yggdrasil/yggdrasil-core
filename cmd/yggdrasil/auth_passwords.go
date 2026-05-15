package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

// newAuthPasswordsCmd returns the "auth passwords" subcommand group.
func newAuthPasswordsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "passwords",
		Short: "Password credential management",
	}
	cmd.AddCommand(newAuthPasswordsSetupTokenCmd())
	return cmd
}

// newAuthPasswordsSetupTokenCmd implements:
//
//	yggdrasil auth passwords setup-token --collaborator <slug>
//	yggdrasil auth passwords setup-token --id <uuid>
//
// It issues a single-use password-setup URL for a collaborator who has not
// yet configured a password. The caller must supply the static admin token via
// YGGDRASIL_AUTH_ADMIN_TOKEN on an instance reachable at YGGDRASIL_URL.
func newAuthPasswordsSetupTokenCmd() *cobra.Command {
	var (
		collaboratorSlug string
		collaboratorID   string
		expiresSeconds   int
	)

	cmd := &cobra.Command{
		Use:   "setup-token",
		Short: "Issue a password setup link for a collaborator",
		Long: `Issue a single-use password-setup URL for a collaborator who has not yet
configured a password.

Requires the static admin token in YGGDRASIL_AUTH_ADMIN_TOKEN and the API
base URL in YGGDRASIL_URL.

When --collaborator (slug) is provided, the collaborator's UUID is resolved via
GET /api/v1/collaborators/{slug} before calling the setup-tokens endpoint.
When --id (UUID) is provided, resolution is skipped.`,
		Example: `  yggdrasil auth passwords setup-token --collaborator alice
  yggdrasil auth passwords setup-token --id 3f1e4b7a-8c2d-4a5f-9e0b-1d2e3f4a5b6c`,
		RunE: func(cmd *cobra.Command, args []string) error {
			id := strings.TrimSpace(collaboratorID)
			slug := strings.TrimSpace(collaboratorSlug)

			if id == "" && slug == "" {
				return fmt.Errorf("one of --collaborator (slug) or --id (UUID) is required")
			}

			// Resolve slug → UUID if needed.
			if id == "" {
				resolved, err := resolveCollaboratorID(slug)
				if err != nil {
					return fmt.Errorf("resolve collaborator %q: %w", slug, err)
				}
				id = resolved
			}

			// POST /api/v1/auth/passwords/setup-tokens
			reqBody := map[string]any{
				"collaborator_id": id,
			}
			if expiresSeconds > 0 {
				reqBody["expires_in_seconds"] = expiresSeconds
			}

			payload, err := json.Marshal(reqBody)
			if err != nil {
				return fmt.Errorf("marshal request: %w", err)
			}

			req, err := http.NewRequest(
				http.MethodPost,
				yggdrasilURL("/api/v1/auth/passwords/setup-tokens"),
				bytes.NewReader(payload),
			)
			if err != nil {
				return fmt.Errorf("build request: %w", err)
			}
			req.Header.Set("Content-Type", "application/json")
			authenticateAdminRequest(req)

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				return fmt.Errorf("API request: %w", err)
			}
			defer resp.Body.Close()

			body, _ := io.ReadAll(resp.Body)
			if resp.StatusCode != http.StatusCreated {
				return fmt.Errorf("API returned %s: %s", resp.Status, strings.TrimSpace(string(body)))
			}

			var out any
			if err := json.Unmarshal(body, &out); err != nil {
				// Fall back to raw output when the body is not JSON.
				fmt.Println(string(body))
				return nil
			}

			pretty, _ := json.MarshalIndent(out, "", "  ")
			fmt.Println(string(pretty))
			return nil
		},
	}

	cmd.Flags().StringVar(&collaboratorSlug, "collaborator", "", "collaborator slug (will be resolved to UUID)")
	cmd.Flags().StringVar(&collaboratorID, "id", "", "collaborator UUID (skips slug resolution)")
	cmd.Flags().IntVar(&expiresSeconds, "expires-in-seconds", 0, "token TTL in seconds (0 = server default, 48 h)")
	return cmd
}

// resolveCollaboratorID calls GET /api/v1/collaborators/{slug} and returns the
// collaborator's UUID. The endpoint accepts both slugs and UUIDs, so callers
// may pass either; a UUID is returned in both cases.
func resolveCollaboratorID(slugOrID string) (string, error) {
	req, err := http.NewRequest(
		http.MethodGet,
		yggdrasilURL("/api/v1/collaborators/"+slugOrID),
		nil,
	)
	if err != nil {
		return "", fmt.Errorf("build request: %w", err)
	}
	authenticateRequest(req)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("API request: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("API returned %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}

	var result struct {
		Collaborator struct {
			ID string `json:"id"`
		} `json:"collaborator"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("decode response: %w", err)
	}
	if result.Collaborator.ID == "" {
		return "", fmt.Errorf("collaborator not found or response missing 'id' field")
	}
	return result.Collaborator.ID, nil
}

// yggdrasilURL builds an absolute URL by appending path to the base URL read
// from YGGDRASIL_URL. Exits with a usage error when the env var is unset.
func yggdrasilURL(path string) string {
	base := strings.TrimRight(strings.TrimSpace(os.Getenv("YGGDRASIL_URL")), "/")
	if base == "" {
		fmt.Fprintln(os.Stderr, "error: YGGDRASIL_URL is required (e.g. http://yggdrasil-core:9080)")
		os.Exit(2)
	}
	return base + path
}

// authenticateRequest injects the session JWT from YGGDRASIL_TOKEN into
// the Authorization header. It mirrors the operator client pattern:
//
//	req.Header.Set("Authorization", "Bearer "+token)
//
// If YGGDRASIL_TOKEN is unset, the header is omitted and the server will
// return 401.
func authenticateRequest(req *http.Request) {
	if token := strings.TrimSpace(os.Getenv("YGGDRASIL_TOKEN")); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
}

// authenticateAdminRequest injects the static admin token from
// YGGDRASIL_AUTH_ADMIN_TOKEN into the X-Yggdrasil-Auth-Admin-Token header,
// which is the header checked by authorizeAuthAdminRequest on the server.
// If YGGDRASIL_AUTH_ADMIN_TOKEN is unset, the header is omitted and the
// server will return 401.
func authenticateAdminRequest(req *http.Request) {
	if token := strings.TrimSpace(os.Getenv("YGGDRASIL_AUTH_ADMIN_TOKEN")); token != "" {
		req.Header.Set("X-Yggdrasil-Auth-Admin-Token", token)
	}
}
