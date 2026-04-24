package operator

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap/zaptest"
)

// fakeCore is the minimal core HTTP surface the reconciler uses.
// Tests swap manifests and workflow responses to exercise the diff /
// dispatch / retry behavior without a real server.
type fakeCore struct {
	mu           sync.Mutex
	manifests    []ManifestRecord
	workflowResp WorkflowRunResult
	workflowErr  bool
	dispatched   []map[string]any // full payloads posted to /api/v1/workflow-runs
}

func (f *fakeCore) setManifests(list []ManifestRecord) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.manifests = append([]ManifestRecord(nil), list...)
}

func (f *fakeCore) dispatchedCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.dispatched)
}

func (f *fakeCore) server(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/v1/manifests" && r.Method == http.MethodGet:
			f.mu.Lock()
			body := struct {
				Manifests []ManifestRecord `json:"manifests"`
			}{Manifests: f.manifests}
			f.mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(body)
		case r.URL.Path == "/api/v1/workflow-runs" && r.Method == http.MethodPost:
			var payload map[string]any
			raw, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(raw, &payload)
			f.mu.Lock()
			f.dispatched = append(f.dispatched, payload)
			failing := f.workflowErr
			resp := f.workflowResp
			f.mu.Unlock()
			if failing {
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte(`{"error":"synthetic"}`))
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
		case r.URL.Path == "/readyz":
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
}

// TestReconciler_DispatchesOnFirstSight asserts that the operator
// dispatches every control_plane it sees on first reconcile, even if
// the version is unchanged from its perspective (in-memory tracker
// starts empty).
func TestReconciler_DispatchesOnFirstSight(t *testing.T) {
	core := &fakeCore{
		manifests: []ManifestRecord{
			{Kind: "control_plane", Metadata: RecordMetadata{Namespace: "global", Name: "primary"}, Version: 1, Active: true},
			{Kind: "control_plane", Metadata: RecordMetadata{Namespace: "global", Name: "staging"}, Version: 1, Active: true},
		},
		workflowResp: WorkflowRunResult{Status: "succeeded"},
	}
	srv := core.server(t)
	defer srv.Close()

	reconciler := New(NewClient(srv.URL, ""), zaptest.NewLogger(t), 0, DispatchOptions{})
	reconciler.reconcileOnce(context.Background())

	if got, want := core.dispatchedCount(), 2; got != want {
		t.Fatalf("dispatched = %d, want %d", got, want)
	}
}

// TestReconciler_SkipsUnchangedVersion is the central diff test: a
// second pass with the same manifest version must not dispatch again.
func TestReconciler_SkipsUnchangedVersion(t *testing.T) {
	core := &fakeCore{
		manifests: []ManifestRecord{
			{Kind: "control_plane", Metadata: RecordMetadata{Namespace: "global", Name: "primary"}, Version: 3, Active: true},
		},
		workflowResp: WorkflowRunResult{Status: "succeeded"},
	}
	srv := core.server(t)
	defer srv.Close()

	reconciler := New(NewClient(srv.URL, ""), zaptest.NewLogger(t), 0, DispatchOptions{})
	reconciler.reconcileOnce(context.Background())
	reconciler.reconcileOnce(context.Background())

	if got, want := core.dispatchedCount(), 1; got != want {
		t.Fatalf("dispatched = %d after two passes, want %d", got, want)
	}
}

// TestReconciler_DispatchesOnVersionBump is the other half of the
// diff: once a control_plane's version increments, the reconciler
// must pick it up next pass.
func TestReconciler_DispatchesOnVersionBump(t *testing.T) {
	core := &fakeCore{
		manifests: []ManifestRecord{
			{Kind: "control_plane", Metadata: RecordMetadata{Namespace: "global", Name: "primary"}, Version: 1, Active: true},
		},
		workflowResp: WorkflowRunResult{Status: "succeeded"},
	}
	srv := core.server(t)
	defer srv.Close()

	reconciler := New(NewClient(srv.URL, ""), zaptest.NewLogger(t), 0, DispatchOptions{})
	reconciler.reconcileOnce(context.Background())

	core.setManifests([]ManifestRecord{
		{Kind: "control_plane", Metadata: RecordMetadata{Namespace: "global", Name: "primary"}, Version: 2, Active: true},
	})
	reconciler.reconcileOnce(context.Background())

	if got, want := core.dispatchedCount(), 2; got != want {
		t.Fatalf("dispatched = %d, want %d (1 per version)", got, want)
	}
}

// TestReconciler_RetriesAfterWorkflowFailure asserts the tracker is
// NOT updated on a failed run — the next pass retries the same
// version, so a transient failure doesn't lose a reconcile.
func TestReconciler_RetriesAfterWorkflowFailure(t *testing.T) {
	core := &fakeCore{
		manifests: []ManifestRecord{
			{Kind: "control_plane", Metadata: RecordMetadata{Namespace: "global", Name: "primary"}, Version: 1, Active: true},
		},
		workflowResp: WorkflowRunResult{Status: "failed", Steps: []WorkflowRunStep{{ID: "apply-infra", Status: "failed", Error: "boom"}}},
	}
	srv := core.server(t)
	defer srv.Close()

	reconciler := New(NewClient(srv.URL, ""), zaptest.NewLogger(t), 0, DispatchOptions{})
	reconciler.reconcileOnce(context.Background())
	reconciler.reconcileOnce(context.Background())

	if got, want := core.dispatchedCount(), 2; got != want {
		t.Fatalf("dispatched = %d, want %d (failed run must retry)", got, want)
	}
}

// TestReconciler_DispatchPayloadShape verifies the workflow-run
// body the operator sends matches what the deploy workflow expects.
// This is the contract between the operator and the seed workflow;
// drift here would silently break reconciles.
func TestReconciler_DispatchPayloadShape(t *testing.T) {
	core := &fakeCore{
		manifests: []ManifestRecord{
			{Kind: "control_plane", Metadata: RecordMetadata{Namespace: "global", Name: "primary"}, Version: 7, Active: true},
		},
		workflowResp: WorkflowRunResult{Status: "succeeded"},
	}
	srv := core.server(t)
	defer srv.Close()

	reconciler := New(NewClient(srv.URL, ""), zaptest.NewLogger(t), 0, DispatchOptions{
		KubernetesInstance:       "custom-k8s",
		SchemaMigrationsInstance: "custom-sm",
		InstanceNamespace:        "platform",
	})
	reconciler.reconcileOnce(context.Background())

	core.mu.Lock()
	defer core.mu.Unlock()
	if len(core.dispatched) != 1 {
		t.Fatalf("expected exactly one dispatch, got %d", len(core.dispatched))
	}
	payload := core.dispatched[0]
	workflow := payload["workflow"].(map[string]any)
	if name, _ := workflow["name"].(string); name != "yggdrasil-deploy-control-plane" {
		t.Errorf("workflow name = %q, want yggdrasil-deploy-control-plane", name)
	}
	inputs := payload["inputs"].(map[string]any)
	cp := inputs["control_plane"].(map[string]any)
	if cp["name"] != "primary" || cp["namespace"] != "global" {
		t.Errorf("control_plane input = %+v", cp)
	}
	// version is decoded as float64 from JSON — that's fine.
	if v, _ := cp["version"].(float64); v != 7 {
		t.Errorf("control_plane.version = %v, want 7", v)
	}
	k := inputs["kubernetes_instance"].(map[string]any)
	if k["name"] != "custom-k8s" || k["namespace"] != "platform" {
		t.Errorf("kubernetes_instance = %+v", k)
	}
}

// TestReconciler_RunStopsOnContextCancel guards the lifecycle: a
// cancelled context should shut the loop down within one tick-period.
func TestReconciler_RunStopsOnContextCancel(t *testing.T) {
	core := &fakeCore{workflowResp: WorkflowRunResult{Status: "succeeded"}}
	srv := core.server(t)
	defer srv.Close()

	reconciler := New(NewClient(srv.URL, ""), zaptest.NewLogger(t), 100*time.Millisecond, DispatchOptions{})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- reconciler.Run(ctx) }()

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run returned %v on cancel, want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("reconciler did not exit within 2s of cancel")
	}
}
