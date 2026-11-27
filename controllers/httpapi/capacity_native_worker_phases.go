package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
)

const nativeWorkerPhaseBasePath = "/internal/capacity/native-workers/phase-permits/"

func nativeWorkerPhasePath(p string) bool {
	return p == strings.TrimSuffix(nativeWorkerPhaseBasePath, "/") || strings.HasPrefix(p, nativeWorkerPhaseBasePath)
}

// Only protected process composition installs these independent read/custody
// ports. Neither an HTTP payload nor a workflow can install a runtime callback.
func WithNativeWorkerPhaseRuntime(workers repository.NativeWorkerRuntime, phases repository.NativeWorkerPhaseRuntime) ServerOption {
	return func(s *Server) { s.nativeWorkerRuntime, s.nativeWorkerPhaseRuntime = workers, phases }
}

type nativeWorkerPhaseRequest struct {
	BindingName string    `json:"binding_name"`
	PermitID    uuid.UUID `json:"permit_id"`
}

func decodeNativeWorkerPhaseReceive(raw []byte) (model.CapacityNativeWorkerPhaseReceive, error) {
	var out model.CapacityNativeWorkerPhaseReceive
	fields, err := capacity.NativeCanonicalObject(raw, map[string]bool{"permit_id": true, "binding_name": true, "settlement_token": true, "http_status": true, "transport_completed": true, "original_return": true, "completed_at": true})
	if err != nil || len(fields) != 7 {
		return out, repository.ErrCapacityConflict
	}
	for _, value := range fields {
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return out, repository.ErrCapacityConflict
		}
	}
	if json.Unmarshal(raw, &out) != nil || out.PermitID == uuid.Nil || out.BindingName == "" || out.CompletedAt.IsZero() || len(out.OriginalReturn) > 2<<20 {
		return out, repository.ErrCapacityConflict
	}
	canonicalID, _ := json.Marshal(out.PermitID.String())
	canonicalWire, _ := json.Marshal(out.OriginalReturn)
	if !bytes.Equal(bytes.TrimSpace(fields["permit_id"]), canonicalID) || !bytes.Equal(bytes.TrimSpace(fields["original_return"]), canonicalWire) {
		return out, repository.ErrCapacityConflict
	}
	return out, nil
}

func (s *Server) serveNativeWorkerPhaseRequest(w http.ResponseWriter, r *http.Request, principal *capacityMutationPrincipal) {
	w.Header().Set("Cache-Control", "no-store")
	source := capacity.CurrentGuestCoreSource()
	w.Header().Set("X-Yggdrasil-Source-Commit", source)
	// Authenticate before reading a potentially large original provider return.
	if principal == nil || len(r.Header.Values("Authorization")) != 1 || principal.base.status != "active" || !time.Now().Before(principal.base.expiresAt) || !principal.capabilities["ensure_native_worker_pool"] {
		writeProblemJSON(w, http.StatusUnauthorized, "capacity.native_worker_unauthorized", "an active exact Native registry writer credential is required")
		return
	}
	if r.TLS == nil || path.Clean(r.URL.Path) != r.URL.Path || r.URL.RawPath != "" || !nativeWorkerPhasePath(r.URL.Path) {
		mutationHTTPError(w, repository.ErrCapacityMutationAuthorization)
		return
	}
	if !regexp.MustCompile(`^[a-f0-9]{40}$`).MatchString(source) {
		mutationHTTPError(w, repository.ErrCapacityDisabled)
		return
	}
	action := strings.TrimPrefix(r.URL.Path, nativeWorkerPhaseBasePath)
	var request nativeWorkerPhaseRequest
	var received model.CapacityNativeWorkerPhaseReceive
	if action == "read" && r.Method == http.MethodGet {
		query, err := url.ParseQuery(r.URL.RawQuery)
		if err != nil || len(query) != 2 || len(query["binding_name"]) != 1 || len(query["permit_id"]) != 1 {
			mutationHTTPError(w, repository.ErrCapacityConflict)
			return
		}
		request.BindingName = query.Get("binding_name")
		id := query.Get("permit_id")
		request.PermitID, err = uuid.Parse(id)
		if err != nil || request.PermitID.String() != id {
			mutationHTTPError(w, repository.ErrCapacityConflict)
			return
		}
	} else if (action == "redeem" || action == "receive") && r.Method == http.MethodPost && r.URL.RawQuery == "" {
		limit := int64(4096)
		if action == "receive" {
			limit = 4 << 20
		}
		r.Body = http.MaxBytesReader(w, r.Body, limit)
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			mutationHTTPError(w, repository.ErrCapacityConflict)
			return
		}
		if action == "receive" {
			received, err = decodeNativeWorkerPhaseReceive(raw)
			request = nativeWorkerPhaseRequest{BindingName: received.BindingName, PermitID: received.PermitID}
		} else {
			err = capacity.DecodeNativeCapacity(json.RawMessage(raw), &request)
		}
		if err != nil {
			mutationHTTPError(w, repository.ErrCapacityConflict)
			return
		}
	} else {
		mutationHTTPError(w, repository.ErrCapacityMutationAuthorization)
		return
	}
	if request.PermitID == uuid.Nil || request.BindingName == "" || len(request.BindingName) > 128 {
		mutationHTTPError(w, repository.ErrCapacityConflict)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	enabled := os.Getenv("YGGDRASIL_NATIVE_WORKER_LIFECYCLE_ENABLED") == "true"
	store := repository.CapacityNativeWorkerPhaseStore{Workers: repository.CapacityNativeWorkerStore{Capacity: repository.CapacityStore{DB: s.db, ExecutionEnabled: os.Getenv("YGGDRASIL_CAPACITY_EXECUTION_ENABLED") == "true"}, Runtime: s.nativeWorkerRuntime, Enabled: enabled}, Runtime: s.nativeWorkerPhaseRuntime, Enabled: enabled}
	policy, caller, err := store.ResolvePhaseCaller(ctx, request.PermitID, request.BindingName, principal.base.principalID, principal.instanceID)
	if err != nil {
		mutationHTTPError(w, err)
		return
	}
	var out model.CapacityNativeWorkerPhasePermit
	switch action {
	case "read":
		out, err = store.Read(ctx, policy, request.PermitID, caller)
	case "redeem":
		out, err = store.Redeem(ctx, policy, request.PermitID, caller)
	case "receive":
		_, err = store.Receive(ctx, policy, caller, received)
	}
	if err != nil {
		mutationHTTPError(w, err)
		return
	}
	if action == "receive" {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	writeJSON(w, http.StatusOK, out)
}
