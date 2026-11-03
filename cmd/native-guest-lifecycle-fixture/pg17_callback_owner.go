//go:build linux && nativequalification

package main

import (
	"bytes"
	"encoding/json"
	"github.com/dakasa-yggdrasil/yggdrasil-core/controllers/httpapi"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	q "github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacitynativeqemu"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
	"io"
	"net/http"
	"strings"
)

// The trace label is deny-only ownership routing, never authentication or
// permission. Existing bearer/mTLS/RBAC remain inside the original handler.
// Late labelled callbacks enter the SAME sealed original owner and receive
// 503 before handler/DB even after the process execution flag is restored.
func pg17PausedCallbackHTTPHandler(next http.Handler, owners *httpapi.NativeOriginalWorkflowOwners, realm *q.Realm, policy model.Manifest) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		labels := r.Header.Values("X-Original-PG17-Callback")
		if len(labels) == 0 {
			next.ServeHTTP(w, r)
			return
		}
		deny := func() { http.Error(w, "original callback owner unavailable", http.StatusServiceUnavailable) }
		if len(labels) != 1 || labels[0] != "1" || realm == nil || realm.Request.NativeCase != "positive_original_lifecycle" || !strings.HasPrefix(policy.Metadata.Namespace, "original-qemu-") || r.URL.RawQuery != "" {
			deny()
			return
		}
		_, finish, ownerErr := owners.Begin()
		if ownerErr != nil {
			deny()
			return
		}
		defer finish()
		pre, err := realm.OriginalPreregistration(2)
		if err != nil || pre.PolicyID != policy.ID.String() || pre.PolicyChecksum != policy.Checksum || pre.CoreSourceCommit != capacity.CurrentGuestCoreSource() {
			deny()
			return
		}
		callback := false
		if r.Method == http.MethodPost && r.URL.Path == "/api/v1/capacity/mutations/settle" {
			if r.Body == nil {
				deny()
				return
			}
			raw, readErr := io.ReadAll(io.LimitReader(r.Body, 2<<20))
			closeErr := r.Body.Close()
			if readErr != nil || closeErr != nil || len(raw) == 0 || len(raw) >= 2<<20 {
				deny()
				return
			}
			var target struct {
				GrantID string `json:"grant_id"`
			}
			if json.Unmarshal(raw, &target) != nil || target.GrantID != pre.OriginalCreateGrantID {
				deny()
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(raw))
			callback = true
		} else if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/v1/capacity/mutations/") {
			id := strings.TrimPrefix(r.URL.Path, "/api/v1/capacity/mutations/")
			parsed, parseErr := uuid.Parse(id)
			callback = parseErr == nil && parsed.String() == id && id == pre.OriginalCreateGrantID
		}
		if !callback {
			deny()
			return
		}
		next.ServeHTTP(w, r)
	})
}
