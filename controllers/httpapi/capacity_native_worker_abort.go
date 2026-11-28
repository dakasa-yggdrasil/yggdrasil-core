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
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
)

const nativeWorkerAbortBasePath = "/internal/capacity/native-workers/abort-permits/"

func nativeWorkerAbortPath(p string) bool {
	return p == strings.TrimSuffix(nativeWorkerAbortBasePath, "/") || strings.HasPrefix(p, nativeWorkerAbortBasePath)
}

// Only protected process composition installs this independent read-only
// recovery runtime. A machine bearer or process flag cannot construct it.
func WithNativeWorkerAbortRuntime(runtime repository.NativeWorkerAbortRuntime) ServerOption {
	return func(s *Server) { s.nativeWorkerAbortRuntime = runtime }
}

type nativeWorkerAbortRequest struct {
	BindingName string    `json:"binding_name"`
	PermitID    uuid.UUID `json:"permit_id"`
}

func decodeNativeWorkerAbortRequest(raw []byte) (nativeWorkerAbortRequest, error) {
	var out nativeWorkerAbortRequest
	fields, err := capacity.NativeCanonicalObject(raw, map[string]bool{"binding_name": true, "permit_id": true})
	if err != nil || len(fields) != 2 || json.Unmarshal(raw, &out) != nil || out.PermitID == uuid.Nil || out.BindingName == "" || len(out.BindingName) > 256 {
		return out, repository.ErrCapacityConflict
	}
	id, _ := json.Marshal(out.PermitID.String())
	if !bytes.Equal(bytes.TrimSpace(fields["permit_id"]), id) {
		return out, repository.ErrCapacityConflict
	}
	return out, nil
}

func decodeNativeWorkerAbortReceive(raw []byte) (model.CapacityNativeWorkerAbortReceive, error) {
	var out model.CapacityNativeWorkerAbortReceive
	fields, err := capacity.NativeCanonicalObject(raw, map[string]bool{"permit_id": true, "binding_name": true, "settlement_token": true, "original_return": true, "capture_complete": true, "error_class": true})
	if err != nil || len(fields) != 6 {
		return out, repository.ErrCapacityConflict
	}
	for _, value := range fields {
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return out, repository.ErrCapacityConflict
		}
	}
	if json.Unmarshal(raw, &out) != nil || out.PermitID == uuid.Nil || out.BindingName == "" || len(out.BindingName) > 256 || len(out.OriginalReturn) > 1<<20 || out.SettlementToken == "" || len(out.SettlementToken) > 512 {
		return out, repository.ErrCapacityConflict
	}
	id, _ := json.Marshal(out.PermitID.String())
	wire, _ := json.Marshal(out.OriginalReturn)
	if !bytes.Equal(bytes.TrimSpace(fields["permit_id"]), id) || !bytes.Equal(bytes.TrimSpace(fields["original_return"]), wire) || out.ErrorClass != "" && out.CaptureComplete {
		return out, repository.ErrCapacityConflict
	}
	switch out.ErrorClass {
	case "", "ORIGINAL_TRANSPORT_UNCERTAIN", "ORIGINAL_CAPTURE_BOUND_EXCEEDED":
	default:
		return out, repository.ErrCapacityConflict
	}
	return out, nil
}

func (s *Server) serveNativeWorkerAbortRequest(w http.ResponseWriter, r *http.Request, principal *capacityMutationPrincipal) {
	w.Header().Set("Cache-Control", "no-store")
	source := capacity.CurrentGuestCoreSource()
	w.Header().Set("X-Yggdrasil-Source-Commit", source)
	if principal == nil || len(r.Header.Values("Authorization")) != 1 || principal.base.status != "active" || !time.Now().Before(principal.base.expiresAt) {
		writeProblemJSON(w, http.StatusUnauthorized, "capacity.native_abort_unauthorized", "an active exact Native recovery credential is required")
		return
	}
	sdk := r.Header.Values(nativeWorkerAdapterSourceHeader)
	if len(sdk) != 1 || !nativeWorkerAttemptSource.MatchString(sdk[0]) || r.TLS == nil || path.Clean(r.URL.Path) != r.URL.Path || r.URL.RawPath != "" || !nativeWorkerAbortPath(r.URL.Path) {
		mutationHTTPError(w, repository.ErrCapacityMutationAuthorization)
		return
	}
	if !nativeWorkerAttemptSource.MatchString(source) {
		mutationHTTPError(w, repository.ErrCapacityDisabled)
		return
	}
	enabled := os.Getenv("YGGDRASIL_NATIVE_WORKER_LIFECYCLE_ENABLED") == "true"
	store := repository.CapacityNativeWorkerAbortStore{Workers: repository.CapacityNativeWorkerStore{Capacity: repository.CapacityStore{DB: s.db, ExecutionEnabled: os.Getenv("YGGDRASIL_CAPACITY_EXECUTION_ENABLED") == "true"}, Runtime: s.nativeWorkerRuntime, Enabled: enabled, Members: s.nativeWorkerMembers}, Runtime: s.nativeWorkerAbortRuntime, Members: s.nativeWorkerMembers, Enabled: enabled && os.Getenv("YGGDRASIL_NATIVE_WORKER_ABORT_ENABLED") == "true"}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	if !store.MachineAuthorized(ctx, principal.instanceID, sdk[0], principal.capabilities) {
		mutationHTTPError(w, repository.ErrCapacityMutationAuthorization)
		return
	}
	action := strings.TrimPrefix(r.URL.Path, nativeWorkerAbortBasePath)
	var request nativeWorkerAbortRequest
	var received model.CapacityNativeWorkerAbortReceive
	var err error
	if action == "read" && r.Method == http.MethodGet {
		var query url.Values
		query, err = url.ParseQuery(r.URL.RawQuery)
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
	} else if (action == "redeem" || action == "receive" || action == "reconcile") && r.Method == http.MethodPost && r.URL.RawQuery == "" {
		limit := int64(4096)
		if action == "receive" {
			limit = 2 << 20
		}
		r.Body = http.MaxBytesReader(w, r.Body, limit)
		raw, bodyErr := io.ReadAll(r.Body)
		if bodyErr != nil {
			mutationHTTPError(w, repository.ErrCapacityConflict)
			return
		}
		if action == "receive" {
			received, err = decodeNativeWorkerAbortReceive(raw)
			request = nativeWorkerAbortRequest{BindingName: received.BindingName, PermitID: received.PermitID}
		} else {
			request, err = decodeNativeWorkerAbortRequest(raw)
		}
		if err != nil {
			mutationHTTPError(w, repository.ErrCapacityConflict)
			return
		}
	} else {
		mutationHTTPError(w, repository.ErrCapacityMutationAuthorization)
		return
	}
	if request.PermitID == uuid.Nil || request.BindingName == "" || len(request.BindingName) > 256 {
		mutationHTTPError(w, repository.ErrCapacityConflict)
		return
	}
	store, policy, caller, err := store.ResolveAbortCaller(ctx, request.PermitID, request.BindingName, principal.instanceID, sdk[0], principal.capabilities)
	if err != nil {
		mutationHTTPError(w, err)
		return
	}
	var out model.CapacityNativeWorkerAbortPermit
	switch action {
	case "read":
		out, err = store.Read(ctx, policy, request.PermitID, caller)
	case "redeem":
		out, err = store.Redeem(ctx, policy, request.PermitID, caller)
	case "receive":
		err = store.Receive(ctx, policy, caller, received)
	case "reconcile":
		out, err = store.Reconcile(ctx, policy, request.PermitID, caller)
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
