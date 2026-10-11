package message

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/manifest"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
)

type originalNotifyFixtureBody struct {
	io.ReadCloser
	read  func([]byte) (int, error)
	close func() error
}

func (b *originalNotifyFixtureBody) Read(p []byte) (int, error) { return b.read(p) }
func (b *originalNotifyFixtureBody) Close() error               { return b.close() }

// These cases exercise actual TLS/HTTP original returns. Their reply is a
// declared protocol fixture and NEVER native business/lease capacity proof.
func TestCapacityOriginalNotifyWindowSource(t *testing.T) {
	t.Run("private_false_readiness_keeps_whole_ready_roster_guard", func(t *testing.T) {
		// DECLARED protocol fixture: no Pod, SDK or native capacity is created.
		now := time.Now().UTC()
		start := now.Add(-time.Minute)
		podUID, workload, process := uuid.NewString(), uuid.NewString(), uuid.NewString()
		image := "sha256:" + strings.Repeat("a", 64)
		p := model.CapacityPolicySpec{MaxEvidenceAgeSeconds: 60, AssessmentBinding: &model.CapacityBoundAssessmentBinding{Snapshot: model.CapacityHPAMinimumBinding{Namespace: "native", WorkloadUID: workload}}, HPAExecutionBinding: &model.CapacityHPAExecutionBinding{Mode: capacity.HPALifetimeExecutionMode, AdmissionMode: "process_v2", ContainerName: "api", ImageDigest: image, Lanes: []string{"listener"}}}
		pod := model.NativeTerminationObservation{BindingName: "native", Namespace: "native", PodName: "notify-b", PodUID: podUID, PodResourceVersion: "1", PodGeneration: 0, WorkloadUID: workload, WorkloadResourceVersion: "1", ContainerName: "api", ContainerID: "containerd://original", ImageID: "fixture@" + image, ImageDigest: image, StartedAt: &start, Protected: true, ContainerState: "running", State: "running", ObservedAt: now}
		challenge := model.NativePodTerminationChallenge{SchemaVersion: 2, Namespace: "native", PodName: pod.PodName, PodUID: podUID, WorkloadUID: workload, ContainerName: "api", ImageDigest: image, IntentGeneration: 1, DrainNonce: uuid.NewString(), IssuedAt: now.Add(-time.Second), LaneRosterSHA256: capacity.NativeRosterDigest(p.HPAExecutionBinding.Lanes), ProcessNonce: process}
		frame := model.NativeProcessAdmissionObservation{SchemaVersion: 2, Namespace: "native", PodName: pod.PodName, PodUID: podUID, ImageDigest: image, LaneRosterSHA256: challenge.LaneRosterSHA256, ProcessNonce: process, ObservedAt: now, State: "roots_open", Challenge: &challenge, ChallengeSHA256: strings.Repeat("b", 64)}
		identity := OriginalNotifyNativeIdentity{PodName: pod.PodName, PodUID: podUID, PodGeneration: 0, ContainerID: pod.ContainerID, ContainerStart: start, ProcessNonce: process, OriginGeneration: 1, ChallengeSHA256: frame.ChallengeSHA256, ImageDigest: image, LaneRosterSHA256: frame.LaneRosterSHA256}
		falseValue, trueValue := false, true
		private := originalNotifyPrivatePod{NativeTerminationObservation: pod, AdmissionReady: &falseValue}
		if !originalNotifyPrivateFrame(p, identity, private, frame) || !originalNotifyPrivatePodSame(private, private) {
			t.Fatal("original private concrete FALSE mistaken for admission failure")
		}
		if originalNotifyFrame(p, identity, pod, frame) {
			t.Fatal("whole roster no longer requires independent ready admission")
		}
		ready := pod
		ready.AdmissionReady = true
		if !originalNotifyFrame(p, identity, ready, frame) {
			t.Fatal("ordinary actual ready admission contract changed")
		}
		private.AdmissionReady = &trueValue
		if originalNotifyPrivateFrame(p, identity, private, frame) {
			t.Fatal("private source silently promoted readiness")
		}
		for _, raw := range []string{`{"admission_ready":null}`, `{}`} {
			var unknown originalNotifyPrivatePod
			if capacity.DecodeNativeCapacity(json.RawMessage(raw), &unknown) != nil {
				t.Fatal("fixture unknown shape decode unavailable")
			}
			if unknown.AdmissionReady != nil || originalNotifyFalse(unknown.AdmissionReady) {
				t.Fatal("unknown private default became known FALSE")
			}
		}
	})
	t.Run("marker5_without_original_owner_return_stays_pending", func(t *testing.T) {
		known, pending := true, false
		call := originalNotifyParticipantCall{BusinessReturnReceived: &known, BusinessReturnNil: &known, ReceiptStoreReturnReceived: &known, ReceiptStoreReturnNil: &known, FinalMarkerReturnReceived: &known, FinalMarkerReturnNil: &known, OriginalOwnerReturnReceived: &pending, OriginalOwnerReturnNil: &pending, OriginalCauseFree: &known}
		if originalNotifyTrue(call.BusinessReturnReceived, call.BusinessReturnNil, call.ReceiptStoreReturnReceived, call.ReceiptStoreReturnNil, call.FinalMarkerReturnReceived, call.FinalMarkerReturnNil, call.OriginalOwnerReturnReceived, call.OriginalOwnerReturnNil, call.OriginalCauseFree) {
			t.Fatal("visible final marker replaced original owner return")
		}
		call.OriginalOwnerReturnReceived, call.OriginalOwnerReturnNil = nil, nil
		if originalNotifyTrue(call.OriginalOwnerReturnReceived, call.OriginalOwnerReturnNil) {
			t.Fatal("unknown return became known zero")
		}
	})
	t.Run("exact_scope_permission_is_not_business_authority", func(t *testing.T) {
		started := time.Now().UTC()
		scope := OriginalNotifyWindowScope{WindowID: "window", PolicyID: "policy", PolicyChecksum: strings.Repeat("a", 64), WorkflowID: "workflow", Generation: 1, FencingToken: 2, LeaseOwner: "owner", LeaseExecutorID: "executor", Deadline: started.Add(time.Minute), CoreAuthority: &OriginalNotifyCoreBinding{WorkflowChecksum: strings.Repeat("b", 64), DispatchJobID: "job", DispatchFence: 3, MachinePrincipalID: "principal"}}
		sha := strings.Repeat("c", 64)
		reply := capacity.OriginalCanaryAuthorityReply{Schema: capacity.OriginalCanaryAuthoritySchema, Scope: capacity.OriginalCanaryAuthorityScope{WindowID: scope.WindowID, ScopeSHA256: sha, PolicyID: scope.PolicyID, PolicyChecksum: scope.PolicyChecksum, WorkflowID: scope.WorkflowID, WorkflowChecksum: scope.CoreAuthority.WorkflowChecksum, DispatchJobID: scope.CoreAuthority.DispatchJobID, DispatchFence: 3, IntentGeneration: 1, IntentFence: 2, LeaseOwner: scope.LeaseOwner, ExecutorID: scope.LeaseExecutorID, MachinePrincipalID: "principal", Deadline: scope.Deadline}, ObservedAt: started, OriginalLiveLeaseVerified: true, CurrentMachineRBACVerified: true}
		raw, err := json.Marshal(reply)
		if err != nil || originalNotifyAuthorityAccepted(raw, scope, sha, started) != nil {
			t.Fatal("declared permission shape refused")
		}
		for _, mode := range []string{"scope", "useful", "human", "missing", "null"} {
			invalid := bytes.Clone(raw)
			switch mode {
			case "scope":
				invalid = bytes.Replace(invalid, []byte(`"dispatch_fence":3`), []byte(`"dispatch_fence":4`), 1)
			case "useful":
				invalid = bytes.Replace(invalid, []byte(`"useful_capacity_known":false`), []byte(`"useful_capacity_known":true`), 1)
			case "human":
				invalid = bytes.Replace(invalid, []byte(`"human_session_verified":false`), []byte(`"human_session_verified":true`), 1)
			case "missing":
				invalid = bytes.Replace(invalid, []byte(`"current_machine_rbac_verified":true,`), nil, 1)
			case "null":
				invalid = bytes.Replace(invalid, []byte(`"current_machine_rbac_verified":true`), []byte(`"current_machine_rbac_verified":null`), 1)
			}
			if originalNotifyAuthorityAccepted(invalid, scope, sha, started) == nil {
				t.Fatal("scope drift/absent permission/capacity borrow accepted")
			}
		}
	})
	t.Run("legacy_default_off_and_unknown_sticky", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		if runOriginalNotifyWindow(ctx, repository.CapacityStore{}, model.Manifest{}, model.CapacityPolicySpec{}, model.CapacityIntent{}, nil) != nil {
			t.Fatal("absent optional binding changed legacy")
		}
		intent := model.CapacityIntent{OriginalNotifyWindow: &model.CapacityOriginalNotifyWindowMarker{State: "possible_start"}}
		if runOriginalNotifyWindow(ctx, repository.CapacityStore{}, model.Manifest{}, model.CapacityPolicySpec{}, intent, nil) == nil {
			t.Fatal("removing binding erased original uncertainty")
		}
		if runOriginalNotifyWindow(ctx, repository.CapacityStore{}, model.Manifest{}, model.CapacityPolicySpec{NativeNotifyWindowBinding: &model.CapacityNativeNotifyWindowBinding{Mode: originalNotifyWindowMode, ProbeCount: 1}}, model.CapacityIntent{}, nil) == nil {
			t.Fatal("wire config minted private factory")
		}
	})
	t.Run("concrete_false_control_members", func(t *testing.T) {
		raw := []byte(`{"state":"accepted","core_lease_verified":false,"broker_ack_known":false,"RTA_delivery_known":false,"useful_all22_known":false}`)
		if originalNotifyControlAccepted(raw) != nil {
			t.Fatal("closed original accepted shape refused")
		}
		for _, invalid := range []string{strings.Replace(string(raw), `"broker_ack_known":false,`, "", 1), strings.Replace(string(raw), `"broker_ack_known":false`, `"broker_ack_known":null`, 1), strings.Replace(string(raw), `"broker_ack_known":false`, `"broker_ack_known":true`, 1), strings.Replace(string(raw), `"state":"accepted"`, `"STATE":"accepted"`, 1), strings.Replace(string(raw), `"state":"accepted"`, `"state":"accepted","state":"accepted"`, 1), strings.Replace(string(raw), `"state":"accepted"`, `"state":"armed"`, 1)} {
			if originalNotifyControlAccepted([]byte(invalid)) == nil {
				t.Fatal("absent/alias/null/claimed authority accepted")
			}
		}
	})
	t.Run("raw_json_encoding_and_alias_refusal", func(t *testing.T) {
		raw := []byte(`{"window_id":"original","probe_count":1}`)
		var scope OriginalNotifyWindowScope
		if capacity.DecodeNativeCapacity(json.RawMessage(raw), &scope) != nil || scope.WindowID != "original" {
			t.Fatal("literal raw wire contract changed")
		}
		if capacity.DecodeNativeCapacity(raw, &scope) == nil {
			t.Fatal("base64 byte encoding treated as raw object")
		}
		for _, invalid := range []string{`{"WINDOW_ID":"original"}`, `{"window_id":"a","window_id":"b"}`, `{"window_id":"a","proof":true}`} {
			if capacity.DecodeNativeCapacity(json.RawMessage(invalid), &scope) == nil {
				t.Fatal("raw alias/duplicate/caller proof accepted")
			}
		}
	})
	t.Run("literal_typed_scope_order_no_map_hash", func(t *testing.T) {
		deadline := time.Date(2026, 1, 2, 3, 4, 5, 123456000, time.UTC)
		scope := OriginalNotifyWindowScope{CoreAuthority: &OriginalNotifyCoreBinding{WorkflowChecksum: "workflow", DispatchJobID: "job", DispatchFence: 7, MachinePrincipalID: "principal"}, TargetDeployment: "dakasa-notify", WindowID: "window", Namespace: "policy", Environment: "fixture", Domain: "app-notify", Dimension: "reserved_pod_envelope", PolicyID: "policy", PolicyChecksum: "checksum", WorkflowID: "workflow", WorkflowVersion: 3, Generation: 4, FencingToken: 5, LeaseOwner: "owner", LeaseExecutorID: "executor", LeaseExpiresAt: deadline, Deadline: deadline, ProbeCount: 1}
		raw, err := json.Marshal(scope)
		expected := `{"core_authority":{"workflow_checksum":"workflow","dispatch_job_id":"job","dispatch_fence":7,"machine_principal_id":"principal"},"target_deployment":"dakasa-notify","window_id":"window","namespace":"policy","environment":"fixture","domain":"app-notify","dimension":"reserved_pod_envelope","policy_id":"policy","policy_checksum":"checksum","workflow_id":"workflow","workflow_version":3,"generation":4,"fencing_token":5,"lease_owner":"owner","lease_executor_id":"executor","lease_expires_at":"2026-01-02T03:04:05.123456Z","deadline":"2026-01-02T03:04:05.123456Z","probe_count":1}`
		if err != nil || string(raw) != expected {
			t.Fatal("source typed canonical preimage changed")
		}
		var fields map[string]any
		if json.Unmarshal(raw, &fields) != nil {
			t.Fatal("fixture canonical decode")
		}
		sorted, _ := json.Marshal(fields)
		a, _ := originalNotifyDigest(scope)
		if capacity.BusinessCreationSHA256(sorted) == a {
			t.Fatal("map normalization became original scope encoder")
		}
	})
	t.Run("optional_binding_null_alias_duplicate_refused", func(t *testing.T) {
		for _, raw := range []string{`{"native_notify_window_binding":null}`, `{"Native_Notify_Window_Binding":{}}`, `{"native_notify_window_binding":{},"native_notify_window_binding":{}}`, `{"native_notify_window_binding":{"mode":"core_original_bound_machine","proof":true}}`} {
			if _, err := manifest.ParseCapacityPolicySpec(json.RawMessage(raw)); err == nil {
				t.Fatal("present malformed optional config admitted")
			}
		}
		if _, err := manifest.ParseCapacityPolicySpec(json.RawMessage(`{}`)); err != nil {
			t.Fatal("legacy absent optional field refused")
		}
	})
	t.Run("fixed_tls_control_original_return", func(t *testing.T) {
		var requests atomic.Int64
		token, selector, key := strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 40)
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requests.Add(1)
			if r.Method != http.MethodPost || r.URL.Path != originalNotifyWindowControlPath || len(r.Header.Values("X-Capacity-Core-Authority")) != 1 || r.Header.Get("X-Capacity-Core-Authority") != token || r.Header.Get("X-Capacity-Participant-Window") != selector || r.Header.Get("X-Capacity-Window-Control-Key") != key || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
				t.Error("fixed original private headers/route drift")
			}
			raw, err := io.ReadAll(r.Body)
			err = errors.Join(err, r.Body.Close())
			if err != nil || strings.Contains(string(raw), token) || strings.Contains(string(raw), key) {
				t.Error("private header leaked into body")
			}
			w.WriteHeader(http.StatusAccepted)
			_, _ = io.WriteString(w, `{"state":"accepted","core_lease_verified":false,"broker_ack_known":false,"RTA_delivery_known":false,"useful_all22_known":false}`)
		}))
		defer server.Close()
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		raw, err := originalNotifyHTTPRequest(ctx, server.Client(), server.URL+originalNotifyWindowControlPath, http.MethodPost, []byte(`{"operation":"seal"}`), originalNotifyHTTPHeaders{coreBearer: token, scopeSHA: selector, controlKey: key}, http.StatusAccepted, 16<<10)
		if err != nil || originalNotifyControlAccepted(raw) != nil || requests.Load() != 1 {
			t.Fatal("original TLS control unavailable", err)
		}
	})
	t.Run("read_a_has_no_participant_or_authority_header", func(t *testing.T) {
		key := strings.Repeat("r", 40)
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet || r.URL.Path != originalNotifyWindowPath || r.Header.Get("X-Capacity-Canary-Read-Key") != key || len(r.Header.Values("X-Capacity-Participant-Window")) != 0 || len(r.Header.Values("X-Capacity-Core-Authority")) != 0 {
				t.Error("A GET selected B status or borrowed authority")
			}
			_, _ = io.WriteString(w, "original")
		}))
		defer server.Close()
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		raw, err := originalNotifyHTTPRequest(ctx, server.Client(), server.URL+originalNotifyWindowPath, http.MethodGet, nil, originalNotifyHTTPHeaders{readKey: key}, http.StatusOK, 64)
		if err != nil || string(raw) != "original" {
			t.Fatal("original read A unavailable", err)
		}
	})
	t.Run("non_ok_never_reads_but_actual_close_returns", func(t *testing.T) {
		var reads, closes atomic.Int64
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusConflict)
			_, _ = io.WriteString(w, "private response")
		}))
		defer server.Close()
		client := *server.Client()
		native := client.Transport
		client.Transport = nativeCanaryRoundTrip(func(r *http.Request) (*http.Response, error) {
			response, err := native.RoundTrip(r)
			if response != nil && response.Body != nil {
				body := response.Body
				response.Body = &originalNotifyFixtureBody{ReadCloser: body, read: func(p []byte) (int, error) { reads.Add(1); return body.Read(p) }, close: func() error { closes.Add(1); return body.Close() }}
			}
			return response, err
		})
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		if raw, err := originalNotifyHTTPRequest(ctx, &client, server.URL+originalNotifyWindowPath, http.MethodGet, nil, originalNotifyHTTPHeaders{readKey: strings.Repeat("r", 40)}, http.StatusOK, 64); err == nil || len(raw) != 0 || reads.Load() != 0 || closes.Load() != 1 {
			t.Fatal("nonOK body read/Close policy changed")
		}
	})
	t.Run("original_read_and_close_causes_are_opaque", func(t *testing.T) {
		readCause, closeCause := errors.New("private-read-cause"), errors.New("private-close-cause")
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "original") }))
		defer server.Close()
		client := *server.Client()
		native := client.Transport
		client.Transport = nativeCanaryRoundTrip(func(r *http.Request) (*http.Response, error) {
			response, err := native.RoundTrip(r)
			if response != nil && response.Body != nil {
				body := response.Body
				response.Body = &originalNotifyFixtureBody{ReadCloser: body, read: func(p []byte) (int, error) { n, e := body.Read(p); return n, errors.Join(e, readCause) }, close: func() error { return errors.Join(body.Close(), closeCause) }}
			}
			return response, err
		})
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		raw, err := originalNotifyHTTPRequest(ctx, &client, server.URL+originalNotifyWindowPath, http.MethodGet, nil, originalNotifyHTTPHeaders{readKey: strings.Repeat("r", 40)}, http.StatusOK, 64)
		if len(raw) != 0 || !errors.Is(err, readCause) || !errors.Is(err, closeCause) {
			t.Fatal("original causal join dropped")
		}
		for _, format := range []string{"%v", "%+v", "%#v", "%s"} {
			if strings.Contains(fmt.Sprintf(format, err), "private-") {
				t.Fatal("private cause formatted")
			}
		}
		encoded, _ := json.Marshal(err)
		if strings.Contains(string(encoded), "private-") {
			t.Fatal("private cause marshaled")
		}
	})
	for _, phase := range []string{"cancel", "deadline"} {
		t.Run("held_actual_close_"+phase, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "original") }))
			t.Cleanup(server.Close)
			entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
			var once sync.Once
			client := *server.Client()
			native := client.Transport
			client.Transport = nativeCanaryRoundTrip(func(r *http.Request) (*http.Response, error) {
				response, err := native.RoundTrip(r)
				if response != nil && response.Body != nil {
					body := response.Body
					response.Body = &originalNotifyFixtureBody{ReadCloser: body, read: body.Read, close: func() error { close(entered); <-release; return body.Close() }}
				}
				return response, err
			})
			parent, cancel := context.WithCancelCause(t.Context())
			defer cancel(nil)
			owner := parent
			var timerCancel context.CancelFunc = func() {}
			if phase == "deadline" {
				owner, timerCancel = context.WithTimeout(parent, 2*time.Second)
			}
			defer timerCancel()
			var raw []byte
			var returned error
			go func() {
				defer close(done)
				raw, returned = originalNotifyHTTPRequest(owner, &client, server.URL+originalNotifyWindowPath, http.MethodGet, nil, originalNotifyHTTPHeaders{readKey: strings.Repeat("r", 40)}, http.StatusOK, 64)
			}()
			t.Cleanup(func() { once.Do(func() { close(release) }); <-done })
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				t.Fatal("original Close never entered")
			}
			privateCause := errors.New("private-owner-cancel")
			if phase == "cancel" {
				cancel(privateCause)
			} else {
				<-owner.Done()
			}
			select {
			case <-done:
				t.Fatal("owner timeout replaced original Close return")
			default:
			}
			once.Do(func() { close(release) })
			<-done
			if len(raw) != 0 || returned == nil || (phase == "cancel" && !errors.Is(returned, privateCause)) || (phase == "deadline" && !errors.Is(returned, context.DeadlineExceeded)) {
				t.Fatal("late original result accepted or cause lost")
			}
		})
	}
	t.Run("redirect_overflow_and_expired_entry_refused", func(t *testing.T) {
		var foreign, requests atomic.Int64
		var mode atomic.Value
		mode.Store("redirect")
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requests.Add(1)
			if r.URL.Path == "/foreign" {
				foreign.Add(1)
			}
			if mode.Load().(string) == "redirect" {
				w.Header().Set("Location", "/foreign")
				w.WriteHeader(http.StatusFound)
			} else {
				_, _ = io.WriteString(w, strings.Repeat("x", 65))
			}
		}))
		defer server.Close()
		for _, value := range []string{"redirect", "overflow"} {
			mode.Store(value)
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			raw, err := originalNotifyHTTPRequest(ctx, server.Client(), server.URL+originalNotifyWindowPath, http.MethodGet, nil, originalNotifyHTTPHeaders{readKey: strings.Repeat("r", 40)}, http.StatusOK, 64)
			cancel()
			if err == nil || len(raw) != 0 {
				t.Fatal("redirect/partial overflow admitted")
			}
		}
		if foreign.Load() != 0 {
			t.Fatal("redirect replay occurred")
		}
		before := requests.Load()
		ctx, cancel := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
		defer cancel()
		_, err := originalNotifyHTTPRequest(ctx, server.Client(), server.URL+originalNotifyWindowPath, http.MethodGet, nil, originalNotifyHTTPHeaders{readKey: strings.Repeat("r", 40)}, http.StatusOK, 64)
		if !errors.Is(err, context.DeadlineExceeded) || requests.Load() != before {
			t.Fatal("expired owner reached actual native Do")
		}
	})
	t.Run("selector_secret_and_nil_owner_refuse_before_do", func(t *testing.T) {
		var calls atomic.Int64
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
		defer server.Close()
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		headers := originalNotifyHTTPHeaders{coreBearer: strings.Repeat("A", 64), scopeSHA: strings.Repeat("b", 64), controlKey: strings.Repeat("c", 40)}
		if _, err := originalNotifyHTTPRequest(ctx, server.Client(), server.URL+originalNotifyWindowControlPath, http.MethodPost, []byte(`{"operation":"seal"}`), headers, http.StatusAccepted, 64); err == nil {
			t.Fatal("noncanonical bearer admitted")
		}
		headers.coreBearer = strings.Repeat("a", 64)
		headers.controlKey += "\r\nprivate"
		if _, err := originalNotifyHTTPRequest(ctx, server.Client(), server.URL+originalNotifyWindowControlPath, http.MethodPost, []byte(`{"operation":"seal"}`), headers, http.StatusAccepted, 64); err == nil {
			t.Fatal("private header injection reached Do")
		}
		//nolint:staticcheck // SA1012: deliberately require missing-owner refusal before any original request.
		if _, err := originalNotifyHTTPRequest(nil, server.Client(), server.URL+originalNotifyWindowPath, http.MethodGet, nil, originalNotifyHTTPHeaders{readKey: strings.Repeat("r", 40)}, http.StatusOK, 64); err == nil || calls.Load() != 0 {
			t.Fatal("missing owner reached original Do")
		}
		encoded, _ := json.Marshal(headers)
		if string(encoded) != "null" || strings.Contains(fmt.Sprintf("%#v", headers), "private\r") {
			t.Fatal("private headers leaked")
		}
	})
}
