package nativeworkerprobe

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	lifecycle "github.com/dakasa-yggdrasil/yggdrasil-core/internal/nativelifecycle"
)

type originalProbeBody struct {
	reader   io.Reader
	readErr  error
	closeErr error
	closed   int
	onClose  func()
}

func (b *originalProbeBody) Read(p []byte) (int, error) {
	if b.readErr != nil {
		return 0, b.readErr
	}
	return b.reader.Read(p)
}
func (b *originalProbeBody) Close() error {
	b.closed++
	if b.onClose != nil {
		b.onClose()
	}
	return b.closeErr
}

func TestProbeLoopbackOriginalReadCloseContextAndFixedDestinationPrecedeProjection(t *testing.T) {
	for _, fault := range []string{"none", "read", "close", "call", "cancel", "overflow", "destination", "method"} {
		t.Run(fault, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			body := &originalProbeBody{reader: strings.NewReader(`{"state":"waiting_projection"}`)}
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, admissionURL, nil)
			if err != nil {
				t.Fatal(err)
			}
			var callErr error
			switch fault {
			case "read":
				body.readErr = errors.New("private-read-error")
			case "close":
				body.closeErr = errors.New("private-close-error")
			case "call":
				callErr = errors.New("private-call-error")
			case "cancel":
				body.onClose = cancel
			case "overflow":
				body.reader = strings.NewReader(strings.Repeat("x", 65537))
			case "destination":
				req.URL.Path = "/different"
			case "method":
				req.Method = http.MethodPost
			}
			status, raw, err := originalLoopbackResponse(ctx, admissionURL, &http.Response{StatusCode: 200, Body: body, Request: req}, callErr)
			if body.closed != 1 || status != 200 || (err == nil) != (fault == "none") {
				t.Fatal("original completion contract", fault, status, body.closed, err)
			}
			if fault == "none" {
				if string(raw) != `{"state":"waiting_projection"}` {
					t.Fatal("actual body changed")
				}
			} else if raw != nil {
				t.Fatal("incomplete original exposed a body")
			}
		})
	}
	var calls atomic.Int32
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { calls.Add(1); w.WriteHeader(200) }))
	defer s.Close()
	if _, _, err := loopbackRead(context.Background(), s.URL, []byte("never-forward")); err == nil || calls.Load() != 0 {
		t.Fatal("unconfigured destination received a request or key")
	}
}

func fixedStartupServer(t *testing.T, h http.Handler) *httptest.Server {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:9080")
	if err != nil {
		t.Fatal("fixed Source loopback listener unavailable", err)
	}
	s := httptest.NewUnstartedServer(h)
	if err := s.Listener.Close(); err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	s.Listener = listener
	s.Start()
	t.Cleanup(s.Close)
	return s
}

func TestProbeActualLoopbackStartupKeepsProcessNonceAndReadinessDistinctFromAdmission(t *testing.T) {
	for _, item := range []struct {
		name, want string
		roots      bool
	}{{"waiting", "startup_pending", false}, {"roots_open", "", true}, {"restart_between_reads", "startup_origin_changed", true}, {"private_database_error", "startup_pending", true}, {"wrong_actual_pod", "startup_identity_refused", true}, {"stale_process_observation", "startup_identity_refused", true}, {"non_json_ready", "startup_pending", true}} {
		t.Run(item.name, func(t *testing.T) {
			c := testConfig("candidate")
			key := bytes.Repeat([]byte{'k'}, 32)
			e := &engine{material: &material{config: c, scope: strings.Repeat("f", 64), startup: key}}
			nonce := testUUID(11)
			challenge := &lifecycle.NativeAdmissionChallenge{NativeTerminationChallenge: lifecycle.NativeTerminationChallenge{SchemaVersion: 2, Namespace: c.Identity.Namespace, PodName: c.Identity.PodName, PodUID: c.Identity.PodUID, WorkloadUID: c.Startup.WorkloadUID, ContainerName: c.Startup.ContainerName, ImageDigest: c.Startup.ImageDigest, IntentGeneration: 1, DrainNonce: testUUID(12), IssuedAt: time.Now().Add(-time.Second), LaneRosterSHA256: c.Startup.LaneRosterSHA256}, ProcessNonce: nonce}
			var nativeCalls, readyCalls, wrongKey atomic.Int32
			fixedStartupServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/internal-runtime/native-admission":
					count := nativeCalls.Add(1)
					if r.Method != http.MethodGet || r.Header.Get("X-Native-Admission-Key") != string(key) {
						wrongKey.Add(1)
						w.WriteHeader(403)
						return
					}
					a := lifecycle.NativeAdmissionObservation{SchemaVersion: 2, Namespace: c.Identity.Namespace, PodName: c.Identity.PodName, PodUID: c.Identity.PodUID, ImageDigest: c.Startup.ImageDigest, LaneRosterSHA256: c.Startup.LaneRosterSHA256, ProcessNonce: nonce, ObservedAt: time.Now().UTC(), State: "waiting_projection"}
					if item.roots {
						a.State, a.Challenge = "roots_open", challenge
						b, _ := json.Marshal(challenge)
						a.ChallengeSHA256 = sha(b)
					}
					if item.name == "restart_between_reads" && count == 2 {
						a.ProcessNonce = testUUID(13)
						changed := *challenge
						changed.ProcessNonce = a.ProcessNonce
						a.Challenge = &changed
						b, _ := json.Marshal(changed)
						a.ChallengeSHA256 = sha(b)
					}
					if item.name == "wrong_actual_pod" {
						a.PodUID = testUUID(14)
					}
					if item.name == "stale_process_observation" {
						a.ObservedAt = time.Now().Add(-time.Minute)
					}
					if err := json.NewEncoder(w).Encode(a); err != nil {
						t.Error(err)
					}
				case "/readyz":
					readyCalls.Add(1)
					if r.Method != http.MethodGet || r.Header.Get("X-Native-Admission-Key") != "" {
						wrongKey.Add(1)
					}
					if item.name == "non_json_ready" {
						_, _ = io.WriteString(w, "ready")
					} else if item.name == "private_database_error" {
						w.WriteHeader(503)
						_, _ = io.WriteString(w, `{"status":"not_ready","rabbitmq_status":"degraded","error":"private-db-marker"}`)
					} else if !item.roots {
						w.WriteHeader(503)
						_, _ = io.WriteString(w, "process still waiting")
					} else {
						_, _ = io.WriteString(w, `{"status":"ready","rabbitmq_status":"ok"}`)
					}
				default:
					t.Error("unconfigured startup route", r.URL.Path)
					w.WriteHeader(404)
				}
			}))
			out := e.inspectStartup(context.Background(), fixtureSource)
			if out.ErrorClass != item.want || wrongKey.Load() != 0 || out.SourceCommit != fixtureSource || out.ConfigSHA256 != e.material.scope {
				t.Fatal("actual startup projection", out.ErrorClass, item.want, wrongKey.Load())
			}
			if item.want == "" && (out.ProcessNonce != nonce || out.AdmissionState != "roots_open" || out.ReadyHTTPStatus != 200 || out.ReadyStatus != "ready" || out.RabbitMQStatus != "ok" || out.ChallengeSHA256 == "" || nativeCalls.Load() != 2 || readyCalls.Load() != 1) {
				t.Fatal("real process handshake/readiness evidence incomplete")
			}
			if item.name == "waiting" && (out.ProcessNonce != nonce || out.AdmissionState != "waiting_projection" || out.ChallengeSHA256 != "") {
				t.Fatal("waiting process nonce was lost or useful admission invented")
			}
			if strings.Contains(item.name, "wrong_actual") || strings.Contains(item.name, "stale_process") {
				if readyCalls.Load() != 0 {
					t.Fatal("foreign/stale process reached readiness read")
				}
			}
			public, err := json.Marshal(out)
			if err != nil || bytes.Contains(public, key) || bytes.Contains(public, []byte("private-db-marker")) {
				t.Fatal("private response/key escaped startup projection", err)
			}
		})
	}
}
