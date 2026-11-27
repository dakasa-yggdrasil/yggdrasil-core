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

const nativeWorkerNetworkBasePath = "/internal/capacity/native-workers/network-permits/"

func nativeWorkerNetworkPath(p string) bool {
	return p == strings.TrimSuffix(nativeWorkerNetworkBasePath, "/") || strings.HasPrefix(p, nativeWorkerNetworkBasePath)
}

func WithNativeWorkerNetworkRuntime(runtime repository.NativeWorkerNetworkRuntime) ServerOption {
	return func(s *Server) { s.nativeWorkerNetworkRuntime = runtime }
}

type nativeWorkerNetworkRequest struct {
	BindingName string    `json:"binding_name"`
	PermitID    uuid.UUID `json:"permit_id"`
}

func decodeNativeWorkerNetworkRequest(raw []byte) (nativeWorkerNetworkRequest, error) {
	var out nativeWorkerNetworkRequest
	fields, e := capacity.NativeCanonicalObject(raw, map[string]bool{"binding_name": true, "permit_id": true})
	if e != nil || len(fields) != 2 || json.Unmarshal(raw, &out) != nil || out.PermitID == uuid.Nil || out.BindingName == "" || len(out.BindingName) > 63 {
		return out, repository.ErrCapacityConflict
	}
	id, _ := json.Marshal(out.PermitID.String())
	if !bytes.Equal(bytes.TrimSpace(fields["permit_id"]), id) {
		return out, repository.ErrCapacityConflict
	}
	return out, nil
}

func decodeNativeWorkerNetworkReceive(raw []byte) (model.CapacityNativeWorkerNetworkOriginalReturn, error) {
	var out model.CapacityNativeWorkerNetworkOriginalReturn
	fields, e := capacity.NativeCanonicalObject(raw, map[string]bool{"schema": true, "permit_id": true, "binding_name": true, "original_return": true, "capture_complete": true, "error_class": true})
	if e != nil || len(fields) < 5 || len(fields) > 6 {
		return out, repository.ErrCapacityConflict
	}
	for _, name := range []string{"schema", "permit_id", "binding_name", "original_return", "capture_complete"} {
		if len(fields[name]) == 0 || bytes.Equal(bytes.TrimSpace(fields[name]), []byte("null")) {
			return out, repository.ErrCapacityConflict
		}
	}
	if json.Unmarshal(raw, &out) != nil || out.Schema != "native_worker_network_receive_v1" || out.BindingName == "" || len(out.BindingName) > 63 || len(out.OriginalReturn) > 1<<20 || len(out.ErrorClass) > 128 || strings.ContainsAny(out.ErrorClass, "\x00\r\n") {
		return out, repository.ErrCapacityConflict
	}
	id, e := uuid.Parse(out.PermitID)
	if e != nil || id == uuid.Nil || id.String() != out.PermitID {
		return out, repository.ErrCapacityConflict
	}
	canonicalID, _ := json.Marshal(out.PermitID)
	wire, _ := json.Marshal(out.OriginalReturn)
	if !bytes.Equal(bytes.TrimSpace(fields["permit_id"]), canonicalID) || !bytes.Equal(bytes.TrimSpace(fields["original_return"]), wire) {
		return out, repository.ErrCapacityConflict
	}
	if errorRaw, ok := fields["error_class"]; ok && bytes.Equal(bytes.TrimSpace(errorRaw), []byte("null")) {
		return out, repository.ErrCapacityConflict
	}
	return out, nil
}

// The exact original incoming body must be fully read and closed before a
// one-use redeem or private custody write can be acknowledged.
func readNativeWorkerNetworkBody(ctx context.Context, body io.ReadCloser) ([]byte, error) {
	if body == nil {
		return nil, repository.ErrCapacityConflict
	}
	raw, readErr := io.ReadAll(body)
	closeErr := body.Close()
	if readErr != nil || closeErr != nil || ctx.Err() != nil {
		return nil, repository.ErrCapacityConflict
	}
	return raw, nil
}

func (s *Server) serveNativeWorkerNetworkRequest(w http.ResponseWriter, r *http.Request, principal *capacityMutationPrincipal) {
	w.Header().Set("Cache-Control", "no-store")
	source := capacity.CurrentGuestCoreSource()
	w.Header().Set("X-Yggdrasil-Source-Commit", source)
	if principal == nil || len(r.Header.Values("Authorization")) != 1 || principal.base.status != "active" || !time.Now().Before(principal.base.expiresAt) {
		writeProblemJSON(w, http.StatusUnauthorized, "capacity.native_network_unauthorized", "an active exact Native network credential is required")
		return
	}
	sdk := r.Header.Values(nativeWorkerAdapterSourceHeader)
	if len(sdk) != 1 || !nativeWorkerAttemptSource.MatchString(sdk[0]) || r.TLS == nil || path.Clean(r.URL.Path) != r.URL.Path || r.URL.RawPath != "" || !nativeWorkerNetworkPath(r.URL.Path) {
		mutationHTTPError(w, repository.ErrCapacityMutationAuthorization)
		return
	}
	if !nativeWorkerAttemptSource.MatchString(source) {
		mutationHTTPError(w, repository.ErrCapacityDisabled)
		return
	}
	enabled := os.Getenv("YGGDRASIL_NATIVE_WORKER_LIFECYCLE_ENABLED") == "true"
	store := repository.CapacityNativeWorkerNetworkStore{Workers: repository.CapacityNativeWorkerStore{Capacity: repository.CapacityStore{DB: s.db, ExecutionEnabled: os.Getenv("YGGDRASIL_CAPACITY_EXECUTION_ENABLED") == "true"}, Runtime: s.nativeWorkerRuntime, Enabled: enabled}, Runtime: s.nativeWorkerNetworkRuntime, AbortRuntime: s.nativeWorkerAbortRuntime, Enabled: enabled && os.Getenv("YGGDRASIL_NATIVE_WORKER_NETWORK_ENABLED") == "true"}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	if !store.MachineAuthorized(ctx, principal.base.principalID, principal.instanceID, sdk[0], principal.capabilities) {
		mutationHTTPError(w, repository.ErrCapacityMutationAuthorization)
		return
	}
	action := strings.TrimPrefix(r.URL.Path, nativeWorkerNetworkBasePath)
	var request nativeWorkerNetworkRequest
	var received model.CapacityNativeWorkerNetworkOriginalReturn
	var e error
	if (action == "read" || action == "reconcile") && r.Method == http.MethodGet {
		var q url.Values
		q, e = url.ParseQuery(r.URL.RawQuery)
		if e != nil || len(q) != 2 || len(q["binding_name"]) != 1 || len(q["permit_id"]) != 1 {
			mutationHTTPError(w, repository.ErrCapacityConflict)
			return
		}
		request.BindingName = q.Get("binding_name")
		request.PermitID, e = uuid.Parse(q.Get("permit_id"))
		if e != nil || request.PermitID.String() != q.Get("permit_id") {
			mutationHTTPError(w, repository.ErrCapacityConflict)
			return
		}
	} else if (action == "redeem" || action == "receive") && r.Method == http.MethodPost && r.URL.RawQuery == "" {
		limit := int64(4096)
		if action == "receive" {
			limit = 2 << 20
		}
		r.Body = http.MaxBytesReader(w, r.Body, limit)
		raw, readErr := readNativeWorkerNetworkBody(ctx, r.Body)
		if readErr != nil {
			mutationHTTPError(w, repository.ErrCapacityConflict)
			return
		}
		if action == "receive" {
			received, e = decodeNativeWorkerNetworkReceive(raw)
			request.BindingName = received.BindingName
			request.PermitID, _ = uuid.Parse(received.PermitID)
		} else {
			request, e = decodeNativeWorkerNetworkRequest(raw)
		}
		if e != nil {
			mutationHTTPError(w, e)
			return
		}
	} else {
		mutationHTTPError(w, repository.ErrCapacityMutationAuthorization)
		return
	}
	if request.PermitID == uuid.Nil || request.BindingName == "" || len(request.BindingName) > 63 {
		mutationHTTPError(w, repository.ErrCapacityConflict)
		return
	}
	store, policy, caller, e := store.ResolveCaller(ctx, request.PermitID, request.BindingName, principal.base.principalID, principal.instanceID, sdk[0], principal.capabilities)
	if e != nil {
		mutationHTTPError(w, e)
		return
	}
	var out model.CapacityNativeWorkerNetworkGrant
	switch action {
	case "read":
		out, e = store.Read(ctx, policy, request.PermitID, caller)
	case "redeem":
		out, e = store.Redeem(ctx, policy, request.PermitID, caller)
	case "receive":
		e = store.Receive(ctx, policy, caller, received)
	case "reconcile":
		out, e = store.Reconcile(ctx, policy, request.PermitID, caller)
	}
	if e != nil {
		mutationHTTPError(w, e)
		return
	}
	if action == "receive" {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	writeJSON(w, http.StatusOK, out)
}
