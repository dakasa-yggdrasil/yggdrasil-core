//go:build recoveryfixture && !nativequalification

package message

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
	amqp "github.com/rabbitmq/amqp091-go"
)

// This uses the real private owner/commit APIs and the production bounded HTTP
// reader, against a verified TLS server with declared provider DTO operands.
// It is Source transport/repository coverage, not an AWS/Hetzner SDK execution,
// authenticated production registry or native Guest/cloud qualification.
type failedServingHTTPFixture struct {
	f             *repository.FailedServingRecoveryFixture
	server        *httptest.Server
	client        *adapterTransportClient
	calls         atomic.Int64
	empty         atomic.Bool
	fault         atomic.Value
	foreignAction atomic.Bool
	candidate     model.CapacityOriginalCreateDispositionCandidate
	mu            sync.RWMutex
}

func newFailedServingHTTPFixture(t *testing.T, provider string) *failedServingHTTPFixture {
	t.Helper()
	x := &failedServingHTTPFixture{f: repository.NewFailedServingRecoveryFixture(t, provider)}
	x.fault.Store("")
	x.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		x.calls.Add(1)
		if r.Method != http.MethodGet || r.Header.Get("X-Capacity-Canary-Read-Key") != strings.Repeat("f", 32) {
			t.Error("fixed private read binding changed")
			http.Error(w, "refused", 403)
			return
		}
		switch x.fault.Load().(string) {
		case "refusal":
			http.Error(w, "DECLARED_PRIVATE_ERROR", 503)
			return
		case "duplicate":
			io.WriteString(w, `{"complete":true,"complete":false}`)
			return
		case "truncated":
			io.WriteString(w, `{"complete":`)
			return
		case "oversized":
			io.WriteString(w, `{"padding":"`+strings.Repeat("x", (2<<20)+1)+`"}`)
			return
		case "timeout":
			<-r.Context().Done()
			return
		case "catalog_changed":
			if _, err := x.f.DB.Exec(`UPDATE public.manifests SET active=false WHERE id=$1`, x.f.Policy.ID); err != nil {
				t.Error(err)
			}
		}
		x.mu.RLock()
		candidate := x.candidate
		x.mu.RUnlock()
		var out any
		switch r.URL.Path {
		case "/inventory":
			out = x.f.Inventory(x.empty.Load())
		case "/off":
			plan := x.f.NativeOffPlan()
			// Provider clocks have no comparison to Core PG time. Actual local
			// HTTP completion owns this fresh read; content retains native time.
			plan.ObservedAt = "2000-01-01T00:00:00Z"
			plan.Server.ObservedAt = plan.ObservedAt
			if provider == "aws" {
				action := candidate.Receipt.ActionID
				if x.foreignAction.Load() {
					action = uuid.NewString()
				}
				at, _ := time.Parse(time.RFC3339Nano, plan.ObservedAt)
				out = struct {
					Plan      model.CapacityVMFleetPlan          `json:"plan"`
					Lifecycle model.CapacityAWSInstanceLifecycle `json:"lifecycle"`
				}{plan, model.CapacityAWSInstanceLifecycle{Schema: "aws_original_request_and_instance_status_v1", RequestID: action, EC2State: "stopped", ObservedAt: at}}
			} else {
				out = plan
			}
		case "/absence":
			out = x.f.Absence(candidate)
		default:
			http.Error(w, "foreign operation", 404)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(out); err != nil {
			t.Error(err)
		}
	}))
	t.Cleanup(x.server.Close)
	x.client = &adapterTransportClient{httpClient: x.server.Client()}
	return x
}

func (x *failedServingHTTPFixture) read(ctx context.Context, path string, c model.CapacityOriginalCreateDispositionCandidate, out any) error {
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) > 30*time.Second || c.Request.ExpectedResourceID != x.f.Registration.Result.Tuple.ResourceID {
		return errors.New("original bounded owner missing")
	}
	x.mu.Lock()
	x.candidate = c
	x.mu.Unlock()
	target := x.server.URL + path
	return x.client.callNativeHTTPJSON(ctx, target, nil, out, adapterCallPolicy{detailFreeErrors: true, native: &nativeAdapterHTTPPolicy{limit: 2 << 20, get: true, requireTLS: true, exactURL: target, readToken: strings.Repeat("f", 32), parent: ctx}})
}

func (x *failedServingHTTPFixture) reads(provider string) failedServingReads {
	return failedServingReads{
		inventory: func(ctx context.Context, c model.CapacityOriginalCreateDispositionCandidate) (model.CapacityVMFleetInventory, error) {
			var out model.CapacityVMFleetInventory
			err := x.read(ctx, "/inventory", c, &out)
			return out, err
		},
		off: func(ctx context.Context, c model.CapacityOriginalCreateDispositionCandidate) (model.CapacityVMFleetPlan, error) {
			if provider == "aws" {
				var out struct {
					Plan      model.CapacityVMFleetPlan          `json:"plan"`
					Lifecycle model.CapacityAWSInstanceLifecycle `json:"lifecycle"`
				}
				err := x.read(ctx, "/off", c, &out)
				if err != nil || !originalAWSNativeOffLifecycleJoin(out.Plan, out.Lifecycle, c.Receipt.ActionID) {
					return model.CapacityVMFleetPlan{}, errOriginalCreateDisposition
				}
				return out.Plan, nil
			}
			var out model.CapacityVMFleetPlan
			err := x.read(ctx, "/off", c, &out)
			return out, err
		},
		absence: func(ctx context.Context, c model.CapacityOriginalCreateDispositionCandidate) (model.CapacityOriginalCreateDispositionObservation, error) {
			var out model.CapacityOriginalCreateDispositionObservation
			err := x.read(ctx, "/absence", c, &out)
			return out, err
		},
	}
}

func TestFailedServingSourceOwnerBoundedHTTPLifecyclePostgres(t *testing.T) {
	t.Setenv("YGGDRASIL_CAPACITY_EXECUTION_ENABLED", "true")
	for _, provider := range []string{"aws", "hetzner"} {
		t.Run(provider, func(t *testing.T) {
			x := newFailedServingHTTPFixture(t, provider)
			reads := x.reads(provider)
			before := x.f.OriginalIntentWire()
			q, err := requestFailedServingGuestQuarantine(context.Background(), x.f.Store, x.f.Request(), "collaborator:"+uuid.NewString(), reads)
			if err != nil || q.Stage != "quarantined" || !reflect.DeepEqual(q.OriginalIntentWire, before) || x.calls.Load() != 1 {
				t.Fatal("actual bounded inventory and atomic owner admission", err)
			}
			var graph model.WorkflowManifestSpec
			if json.Unmarshal(x.f.Workflow.Spec, &graph) != nil {
				t.Fatal("actual stored original graph")
			}
			ctx, stop := context.WithTimeout(context.Background(), 3*time.Second)
			defer stop()
			ctx = context.WithValue(ctx, capacityInvocationKey{}, x.f.Store.ExecutorID)
			ref := model.ManifestReference{ID: x.f.Workflow.ID, Kind: "workflow", Namespace: x.f.Workflow.Metadata.Namespace, Name: x.f.Workflow.Metadata.Name, Version: x.f.Workflow.Version}
			// Unconnected broker sentinel: the exact production scheduler step
			// must HOLD before any collector/hydration/RPC can use this object.
			tick := executeOriginalGuestReconcileStep(ctx, &amqp.Connection{}, x.f.DB, ref, graph.Steps[0], model.WorkflowRunStepResult{Operation: capacity.PlanOriginalGuestOperation}, map[string]any{"policy": map[string]any{"namespace": x.f.Policy.Metadata.Namespace, "name": x.f.Policy.Metadata.Name}})
			if tick.Status != "succeeded" || tick.Metadata["mode"] != "hold" || tick.Metadata["reason"] != "serving_guest_quarantined" || tick.Metadata["admission_id"] != q.ID || tick.Metadata["native_write_sent"] != false || x.calls.Load() != 1 {
				t.Fatal("ordinary missing-coverage tick passed quarantine to a collector", tick.Status, tick.Error)
			}
			off, err := observeFailedServingGuest(context.Background(), x.f.Store, x.f.Pre.PreregistrationID, q.ID, "collaborator:"+uuid.NewString(), "off", reads)
			if err != nil || off.Stage != "quiescent" || x.calls.Load() != 2 || off.NativeOff == nil || off.NativeOff.ObservedAt != "2000-01-01T00:00:00Z" {
				t.Fatal("fresh original GET cannot substitute provider wallclock", err)
			}
			x.empty.Store(true)
			terminal, err := observeFailedServingGuest(context.Background(), x.f.Store, x.f.Pre.PreregistrationID, q.ID, "collaborator:"+uuid.NewString(), "absence", reads)
			if err != nil || terminal.Stage != "terminal" || x.calls.Load() != 4 || terminal.NativeOffRecordID != off.RecordID || terminal.CoreOrGuestNativeWriteSent || terminal.GuestWriterDrainClaimed || !terminal.BusinessEffectsPreserved {
				t.Fatal("separate absence plus whole-profile zero read lost custody", err)
			}
		})
	}
}

func TestFailedServingSourceReadFailureNeverCommitsOrRetriesPostgres(t *testing.T) {
	for _, provider := range []string{"aws", "hetzner"} {
		t.Run(provider, func(t *testing.T) {
			x := newFailedServingHTTPFixture(t, provider)
			reads := x.reads(provider)
			before := x.f.OriginalIntentWire()
			for _, fault := range []string{"refusal", "duplicate", "truncated", "oversized", "timeout", "close_failure", "catalog_changed"} {
				t.Run(fault, func(t *testing.T) {
					x.fault.Store(fault)
					calls := x.calls.Load()
					parent := context.Background()
					stop := func() {}
					if fault == "timeout" {
						parent, stop = context.WithTimeout(parent, 500*time.Millisecond)
					}
					defer stop()
					originalClient := x.client.httpClient
					if fault == "close_failure" {
						copied := *originalClient
						copied.Transport = failedServingCloseFailureTransport{originalClient.Transport}
						x.client.httpClient = &copied
					}
					defer func() { x.client.httpClient = originalClient }()
					if _, err := requestFailedServingGuestQuarantine(parent, x.f.Store, x.f.Request(), "collaborator:"+uuid.NewString(), reads); err == nil || strings.Contains(err.Error(), "DECLARED_PRIVATE_ERROR") {
						t.Fatal("failed/truncated/stale original read admitted or leaked", err)
					}
					if x.calls.Load() != calls+1 || !reflect.DeepEqual(x.f.OriginalIntentWire(), before) {
						t.Fatal("retry or mutation after original failed read")
					}
					var n int
					if err := x.f.DB.QueryRow(`SELECT count(*) FROM public.capacity_guest_failed_serving_disposals`).Scan(&n); err != nil || n != 0 {
						t.Fatal("failed original read appended stage", err)
					}
					if fault == "catalog_changed" {
						if _, err := x.f.DB.Exec(`UPDATE public.manifests SET active=true WHERE id=$1`, x.f.Policy.ID); err != nil {
							t.Fatal(err)
						}
					}
				})
			}
			x.fault.Store("")
			q, err := requestFailedServingGuestQuarantine(context.Background(), x.f.Store, x.f.Request(), "collaborator:"+uuid.NewString(), reads)
			if err != nil {
				t.Fatal("new explicit current GET after read failure", err)
			}
			if provider == "aws" {
				x.foreignAction.Store(true)
				if _, err = observeFailedServingGuest(context.Background(), x.f.Store, x.f.Pre.PreregistrationID, q.ID, "collaborator:"+uuid.NewString(), "off", reads); err == nil {
					t.Fatal("foreign AWS lifecycle action admitted")
				}
				x.foreignAction.Store(false)
			}
		})
	}
}

type failedServingCloseFailureTransport struct{ base http.RoundTripper }

func (x failedServingCloseFailureTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	response, err := x.base.RoundTrip(r)
	if response != nil && response.Body != nil {
		response.Body = failedServingCloseFailureBody{response.Body}
	}
	return response, err
}

type failedServingCloseFailureBody struct{ io.ReadCloser }

func (b failedServingCloseFailureBody) Close() error {
	return errors.Join(b.ReadCloser.Close(), errors.New("declared original Close failure"))
}
