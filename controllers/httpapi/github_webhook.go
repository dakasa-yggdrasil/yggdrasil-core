package httpapi

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"go.uber.org/zap"
)

// githubPushEvent is the subset of the GitHub push webhook payload we need.
type githubPushEvent struct {
	Ref        string `json:"ref"`
	Repository struct {
		FullName string `json:"full_name"`
		CloneURL string `json:"clone_url"`
	} `json:"repository"`
	Pusher struct {
		Name string `json:"name"`
	} `json:"pusher"`
	HeadCommit struct {
		ID       string   `json:"id"`
		Message  string   `json:"message"`
		Modified []string `json:"modified"`
	} `json:"head_commit"`
}

// handleGitHubWebhook receives GitHub webhook events and triggers deploys.
//
//	POST /api/v1/github/webhook
func (s *Server) handleGitHubWebhook(w http.ResponseWriter, r *http.Request) {
	// Read body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "failed to read body"})
		return
	}

	// Validate signature
	secret := os.Getenv("GITHUB_WEBHOOK_SECRET")
	if secret != "" {
		sig := r.Header.Get("X-Hub-Signature-256")
		if !validateWebhookSignature(body, sig, secret) {
			writeJSON(w, http.StatusUnauthorized, errorResponse{Error: "invalid webhook signature"})
			return
		}
	}

	// Route by event type
	event := r.Header.Get("X-GitHub-Event")

	switch event {
	case "push":
		s.handlePushEvent(w, body)
	case "ping":
		writeJSON(w, http.StatusOK, map[string]string{"status": "pong"})
	default:
		writeJSON(w, http.StatusOK, map[string]string{"status": "ignored", "event": event})
	}
}

// handlePushEvent processes a push event and triggers a deploy if the push
// is to the main branch of a known repository.
func (s *Server) handlePushEvent(w http.ResponseWriter, body []byte) {
	var push githubPushEvent
	if err := json.Unmarshal(body, &push); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid push payload"})
		return
	}

	// Only deploy on pushes to main
	if push.Ref != "refs/heads/main" {
		writeJSON(w, http.StatusOK, map[string]string{
			"status": "skipped",
			"reason": fmt.Sprintf("ref %s is not main", push.Ref),
		})
		return
	}

	s.logger.Info("github push received",
		zap.String("repo", push.Repository.FullName),
		zap.String("pusher", push.Pusher.Name),
		zap.String("commit", truncate(push.HeadCommit.Message, 80)),
	)

	// Map repository to product for deployment
	product := repoToProduct(push.Repository.FullName)
	if product == "" {
		writeJSON(w, http.StatusOK, map[string]string{
			"status": "skipped",
			"reason": fmt.Sprintf("repo %s not mapped to a product", push.Repository.FullName),
		})
		return
	}

	// Trigger deploy asynchronously
	if s.deployer != nil {
		go func() {
			s.logger.Info("auto-deploy triggered by push",
				zap.String("repo", push.Repository.FullName),
				zap.String("product", product),
			)

			port := os.Getenv("PORT")
			if port == "" {
				port = "9080"
			}
			url := fmt.Sprintf("http://localhost:%s/api/v1/products/dakasa/%s/deploy", port, product)

			req, err := http.NewRequest("POST", url, nil)
			if err != nil {
				s.logger.Error("auto-deploy: build request failed", zap.Error(err))
				return
			}
			req.Header.Set("Authorization", "Bearer "+os.Getenv("YGGDRASIL_DEPLOY_TOKEN"))

			client := &http.Client{Timeout: 5 * time.Minute}
			resp, err := client.Do(req)
			if err != nil {
				s.logger.Error("auto-deploy failed", zap.String("product", product), zap.Error(err))
				return
			}
			defer func() { _ = resp.Body.Close() }()
			s.logger.Info("auto-deploy completed",
				zap.String("product", product),
				zap.Int("status", resp.StatusCode),
			)
		}()
	}

	writeJSON(w, http.StatusAccepted, map[string]string{
		"status":  "deploying",
		"product": product,
		"repo":    push.Repository.FullName,
	})
}

// repoToProduct maps a GitHub repository full name to a DaKasa product name.
var repoProductMap = map[string]string{
	// dakasa-app services
	"dakasa-co/dakasa-app-identities-api":      "dakasa-app",
	"dakasa-co/dakasa-app-hall-api":             "dakasa-app",
	"dakasa-co/dakasa-app-room-api":             "dakasa-app",
	"dakasa-co/dakasa-app-notify-api":           "dakasa-app",
	"dakasa-co/dakasa-app-media-compressor-api": "dakasa-app",
	"dakasa-co/dakasa-app-rta-api":              "dakasa-app",
	"dakasa-co/dakasa-app-fe":                   "dakasa-app",

	// dakasa-enterprise services
	"dakasa-co/dakasa-enterprise-identities-api":      "dakasa-enterprise",
	"dakasa-co/dakasa-enterprise-ads-api":              "dakasa-enterprise",
	"dakasa-co/dakasa-enterprise-payments-api":         "dakasa-enterprise",
	"dakasa-co/dakasa-enterprise-notify-api":           "dakasa-enterprise",
	"dakasa-co/dakasa-enterprise-media-compressor-api": "dakasa-enterprise",
	"dakasa-co/dakasa-enterprise-rta-api":              "dakasa-enterprise",
	"dakasa-co/dakasa-enterprise-fe":                   "dakasa-enterprise",

	// dakasa-tartaro services
	"dakasa-co/dakasa-tartaro-api": "dakasa-tartaro",
	"dakasa-co/dakasa-tartaro-fe":  "dakasa-tartaro",

	// shared
	"dakasa-co/dakasa-orchestrator": "dakasa-shared",
	"dakasa-co/dakasa-commons":      "", // library, no deploy
	"dakasa-co/dakasa-system":       "", // infra monorepo, no auto-deploy (hostPath, requires manual git pull)

	// yggdrasil
	"dakasa-yggdrasil/yggdrasil-core": "", // self, no auto-deploy
}

func repoToProduct(fullName string) string {
	if product, ok := repoProductMap[fullName]; ok {
		return product
	}
	return ""
}

// validateWebhookSignature checks the X-Hub-Signature-256 header.
func validateWebhookSignature(body []byte, signature, secret string) bool {
	if !strings.HasPrefix(signature, "sha256=") {
		return false
	}
	sig, err := hex.DecodeString(signature[7:])
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return hmac.Equal(sig, mac.Sum(nil))
}

func truncate(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
