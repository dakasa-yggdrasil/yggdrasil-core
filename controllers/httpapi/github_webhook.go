package httpapi

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
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
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "failed to read body"})
		return
	}

	secret := os.Getenv("GITHUB_WEBHOOK_SECRET")
	if secret != "" {
		sig := r.Header.Get("X-Hub-Signature-256")
		if !validateWebhookSignature(body, sig, secret) {
			writeJSON(w, http.StatusUnauthorized, errorResponse{Error: "invalid webhook signature"})
			return
		}
	}

	switch r.Header.Get("X-GitHub-Event") {
	case "push":
		s.handlePushEvent(w, r, body)
	case "ping":
		writeJSON(w, http.StatusOK, map[string]string{"status": "pong"})
	default:
		writeJSON(w, http.StatusOK, map[string]string{
			"status": "ignored",
			"event":  r.Header.Get("X-GitHub-Event"),
		})
	}
}

// handlePushEvent routes a GitHub push event by looking up the matching
// repository_binding manifest and dispatching the workflow it declares.
//
// As of v2.0.0, push routing is fully declarative — there is no hardcoded
// repo→product map. Pushes to repositories with no binding return
// 200 with status "skipped" (so a webhook installation on an unmapped repo
// is harmless rather than an error).
func (s *Server) handlePushEvent(w http.ResponseWriter, r *http.Request, body []byte) {
	var push githubPushEvent
	if err := json.Unmarshal(body, &push); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid push payload"})
		return
	}

	binding, err := repository.FindBindingByRepository(r.Context(), s.db, push.Repository.FullName)
	if errors.Is(err, repository.ErrBindingNotFound) {
		IncWebhookEvent("skipped")
		writeJSON(w, http.StatusOK, map[string]string{
			"status": "skipped",
			"reason": fmt.Sprintf("no repository_binding for %s", push.Repository.FullName),
		})
		return
	}
	if err != nil {
		IncWebhookEvent("failed")
		s.logger.Error("repository_binding lookup failed",
			zap.String("repo", push.Repository.FullName),
			zap.Error(err),
		)
		writeJSON(w, http.StatusInternalServerError, errorResponse{
			Error: "binding lookup failed: " + err.Error(),
		})
		return
	}

	if binding.Spec.Deploy == nil {
		IncWebhookEvent("skipped")
		writeJSON(w, http.StatusOK, map[string]string{
			"status": "skipped",
			"reason": "binding has no deploy spec",
		})
		return
	}

	deploy := binding.Spec.Deploy
	if !matchesBranchFilter(push.Ref, deploy.BranchFilter) {
		IncWebhookEvent("skipped")
		writeJSON(w, http.StatusOK, map[string]string{
			"status": "skipped",
			"reason": fmt.Sprintf("ref %s outside branch_filter", push.Ref),
		})
		return
	}
	if len(deploy.PathFilter) > 0 && !matchesPathFilter(push.HeadCommit.Modified, deploy.PathFilter) {
		IncWebhookEvent("skipped")
		writeJSON(w, http.StatusOK, map[string]string{
			"status": "skipped",
			"reason": "no files matched path_filter",
		})
		return
	}

	inputs, err := buildInputsFromPush(deploy.DefaultInputs, push)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{
			Error: "input templating failed: " + err.Error(),
		})
		return
	}

	switch deploy.WorkflowKind {
	case "yggdrasil":
		if deploy.WorkflowRef == nil {
			writeJSON(w, http.StatusInternalServerError, errorResponse{
				Error: "binding deploy.workflow_ref is missing for yggdrasil dispatch",
			})
			return
		}
		ref := model.ManifestSelector{
			Namespace: deploy.WorkflowRef.Namespace,
			Name:      deploy.WorkflowRef.Name,
		}

		s.logger.Info("github push dispatching workflow",
			zap.String("repo", push.Repository.FullName),
			zap.String("ref", push.Ref),
			zap.String("commit", push.HeadCommit.ID),
			zap.String("binding", binding.Metadata.Namespace+"/"+binding.Metadata.Name),
			zap.String("workflow", ref.Namespace+"/"+ref.Name),
		)

		// Fire-and-forget dispatch in a goroutine so the webhook can ack
		// the push promptly. Errors are logged for operator inspection.
		go func() {
			if err := s.dispatchWorkflow(context.Background(), ref, inputs); err != nil {
				s.logger.Error("webhook dispatch failed",
					zap.String("workflow", ref.Namespace+"/"+ref.Name),
					zap.String("repo", push.Repository.FullName),
					zap.Error(err),
				)
			}
		}()

		IncWebhookEvent("accepted")
		writeJSON(w, http.StatusAccepted, map[string]any{
			"status":   "deploying",
			"workflow": ref.Namespace + "/" + ref.Name,
			"binding":  binding.Metadata.Namespace + "/" + binding.Metadata.Name,
			"repo":     push.Repository.FullName,
		})
	case "github_actions":
		IncWebhookEvent("failed")
		writeJSON(w, http.StatusNotImplemented, errorResponse{
			Error: "github_actions dispatch not implemented in v2.0.0",
		})
	default:
		IncWebhookEvent("failed")
		writeJSON(w, http.StatusInternalServerError, errorResponse{
			Error: "unsupported workflow_kind: " + deploy.WorkflowKind,
		})
	}
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
