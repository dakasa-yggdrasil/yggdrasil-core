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

const nativeWorkerAttemptBasePath = "/internal/capacity/native-workers/attempts/"
const nativeWorkerAdapterSourceHeader = "X-Yggdrasil-Adapter-Source-Commit"

var nativeWorkerAttemptSource = regexp.MustCompile(`^[a-f0-9]{40}$`)

func nativeWorkerAttemptPath(p string) bool {
	return p == strings.TrimSuffix(nativeWorkerAttemptBasePath, "/") || strings.HasPrefix(p, nativeWorkerAttemptBasePath)
}

// Only protected process composition can install these GET/custody callbacks.
// No payload, environment selector or workflow can create a runtime callback.
func WithNativeWorkerAttemptRuntime(runtime repository.NativeWorkerRuntime) ServerOption {
	return func(s *Server) { s.nativeWorkerRuntime = runtime }
}

type nativeWorkerAttemptRequest struct {
	BindingName string    `json:"binding_name"`
	AttemptID   uuid.UUID `json:"attempt_id"`
}

func decodeNativeWorkerAttemptRequest(raw []byte) (nativeWorkerAttemptRequest, error) {
	var out nativeWorkerAttemptRequest
	fields, err := capacity.NativeCanonicalObject(raw, map[string]bool{"binding_name": true, "attempt_id": true})
	if err != nil || len(fields) != 2 || json.Unmarshal(raw, &out) != nil || out.AttemptID == uuid.Nil || out.BindingName == "" || len(out.BindingName) > 256 {
		return out, repository.ErrCapacityConflict
	}
	id, _ := json.Marshal(out.AttemptID.String())
	if !bytes.Equal(bytes.TrimSpace(fields["attempt_id"]), id) {
		return out, repository.ErrCapacityConflict
	}
	return out, nil
}

func decodeNativeWorkerAttemptReceive(raw []byte) (model.CapacityNativeWorkerCommandReceive, error) {
	var out model.CapacityNativeWorkerCommandReceive
	fields, err := capacity.NativeCanonicalObject(raw, map[string]bool{"binding_name": true, "attempt_id": true, "original_return": true, "capture_complete": true, "error_class": true})
	if err != nil || len(fields) != 5 {
		return out, repository.ErrCapacityConflict
	}
	for _, v := range fields {
		if bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
			return out, repository.ErrCapacityConflict
		}
	}
	if json.Unmarshal(raw, &out) != nil || out.AttemptID == uuid.Nil || out.BindingName == "" || len(out.BindingName) > 256 || len(out.OriginalReturn) > 1<<20 {
		return out, repository.ErrCapacityConflict
	}
	id, _ := json.Marshal(out.AttemptID.String())
	wire, _ := json.Marshal(out.OriginalReturn)
	if !bytes.Equal(bytes.TrimSpace(fields["attempt_id"]), id) || !bytes.Equal(bytes.TrimSpace(fields["original_return"]), wire) {
		return out, repository.ErrCapacityConflict
	}
	return out, nil
}

func (s *Server) serveNativeWorkerAttemptRequest(w http.ResponseWriter, r *http.Request, principal *capacityMutationPrincipal) {
	w.Header().Set("Cache-Control", "no-store")
	source := capacity.CurrentGuestCoreSource()
	w.Header().Set("X-Yggdrasil-Source-Commit", source)
	// A machine credential is checked before any original bytes or command body.
	if principal == nil || len(r.Header.Values("Authorization")) != 1 || principal.base.status != "active" || !time.Now().Before(principal.base.expiresAt) {
		writeProblemJSON(w, http.StatusUnauthorized, "capacity.native_attempt_unauthorized", "an active exact Native execution credential is required")
		return
	}
	sdkValues := r.Header.Values(nativeWorkerAdapterSourceHeader)
	if len(sdkValues) != 1 || !nativeWorkerAttemptSource.MatchString(sdkValues[0]) || r.TLS == nil || path.Clean(r.URL.Path) != r.URL.Path || r.URL.RawPath != "" || !nativeWorkerAttemptPath(r.URL.Path) {
		mutationHTTPError(w, repository.ErrCapacityMutationAuthorization)
		return
	}
	if !nativeWorkerAttemptSource.MatchString(source) {
		mutationHTTPError(w, repository.ErrCapacityDisabled)
		return
	}
	enabled := os.Getenv("YGGDRASIL_NATIVE_WORKER_LIFECYCLE_ENABLED") == "true"
	store := repository.CapacityNativeWorkerCommandStore{Workers: repository.CapacityNativeWorkerStore{Capacity: repository.CapacityStore{DB: s.db, ExecutionEnabled: os.Getenv("YGGDRASIL_CAPACITY_EXECUTION_ENABLED") == "true"}, Runtime: s.nativeWorkerRuntime, Enabled: enabled}}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	// Contexts are Source-written, immutable and private. This indexed check does
	// not select an attempt or grant mutation; exact ID/binding is rejoined below.
	if !store.MachineAuthorized(ctx, principal.instanceID, sdkValues[0], principal.capabilities) {
		mutationHTTPError(w, repository.ErrCapacityMutationAuthorization)
		return
	}
	action := strings.TrimPrefix(r.URL.Path, nativeWorkerAttemptBasePath)
	var request nativeWorkerAttemptRequest
	var received model.CapacityNativeWorkerCommandReceive
	var err error
	if action == "read" && r.Method == http.MethodGet {
		var q url.Values
		q, err = url.ParseQuery(r.URL.RawQuery)
		if err != nil || len(q) != 2 || len(q["binding_name"]) != 1 || len(q["attempt_id"]) != 1 {
			mutationHTTPError(w, repository.ErrCapacityConflict)
			return
		}
		request.BindingName = q.Get("binding_name")
		id := q.Get("attempt_id")
		request.AttemptID, err = uuid.Parse(id)
		if err != nil || request.AttemptID.String() != id {
			mutationHTTPError(w, repository.ErrCapacityConflict)
			return
		}
	} else if (action == "redeem" || action == "receive") && r.Method == http.MethodPost && r.URL.RawQuery == "" {
		limit := int64(4096)
		if action == "receive" {
			limit = 2 << 20
		}
		r.Body = http.MaxBytesReader(w, r.Body, limit)
		raw, e := io.ReadAll(r.Body)
		if e != nil {
			mutationHTTPError(w, repository.ErrCapacityConflict)
			return
		}
		if action == "receive" {
			received, err = decodeNativeWorkerAttemptReceive(raw)
			request = nativeWorkerAttemptRequest{BindingName: received.BindingName, AttemptID: received.AttemptID}
		} else {
			request, err = decodeNativeWorkerAttemptRequest(raw)
		}
		if err != nil {
			mutationHTTPError(w, repository.ErrCapacityConflict)
			return
		}
	} else {
		mutationHTTPError(w, repository.ErrCapacityMutationAuthorization)
		return
	}
	if request.AttemptID == uuid.Nil || request.BindingName == "" || len(request.BindingName) > 256 {
		mutationHTTPError(w, repository.ErrCapacityConflict)
		return
	}
	policy, caller, err := store.Resolve(ctx, request.AttemptID, request.BindingName, principal.instanceID, sdkValues[0], principal.capabilities)
	if err != nil {
		mutationHTTPError(w, err)
		return
	}
	var out model.CapacityNativeWorkerCommand
	switch action {
	case "read":
		out, err = store.Read(ctx, policy, request.AttemptID, caller)
	case "redeem":
		out, err = store.Redeem(ctx, policy, request.AttemptID, caller)
	case "receive":
		err = store.Receive(ctx, policy, caller, received)
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
