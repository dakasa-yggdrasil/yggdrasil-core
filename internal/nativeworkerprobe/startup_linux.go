package nativeworkerprobe

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"time"
)

const admissionURL = "http://127.0.0.1:9080/internal-runtime/native-admission"
const readyURL = "http://127.0.0.1:9080/readyz"

type admissionReply struct {
	SchemaVersion    int             `json:"schema_version"`
	Namespace        string          `json:"namespace"`
	PodName          string          `json:"pod_name"`
	PodUID           string          `json:"pod_uid"`
	ImageDigest      string          `json:"image_digest"`
	LaneRosterSHA256 string          `json:"lane_roster_sha256"`
	ProcessNonce     string          `json:"process_nonce"`
	ObservedAt       time.Time       `json:"observed_at"`
	State            string          `json:"state"`
	Challenge        json.RawMessage `json:"challenge,omitempty"`
	ChallengeSHA256  string          `json:"challenge_sha256,omitempty"`
}

type startupChallenge struct {
	SchemaVersion    int       `json:"schema_version"`
	Namespace        string    `json:"namespace"`
	PodName          string    `json:"pod_name"`
	PodUID           string    `json:"pod_uid"`
	WorkloadUID      string    `json:"workload_uid"`
	ContainerName    string    `json:"container_name"`
	ImageDigest      string    `json:"image_digest"`
	IntentGeneration int64     `json:"intent_generation"`
	DrainNonce       string    `json:"drain_nonce"`
	IssuedAt         time.Time `json:"issued_at"`
	LaneRosterSHA256 string    `json:"lane_roster_sha256"`
	ProcessNonce     string    `json:"process_nonce"`
}

// Original completion is required before this safe projection is inspected.
// The two destinations are compiled; redirects/proxy/replay are unavailable.
func loopbackRead(ctx context.Context, url string, key []byte) (int, []byte, error) {
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, MaxConnsPerHost: 1, ResponseHeaderTimeout: 2 * time.Second, DialContext: (&net.Dialer{Timeout: 2 * time.Second}).DialContext}
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return ErrUnavailable }}
	defer client.CloseIdleConnections()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil || (url != admissionURL && url != readyURL) {
		return 0, nil, ErrUnavailable
	}
	request.GetBody = nil
	if url == admissionURL {
		request.Header.Set("X-Native-Admission-Key", string(key))
	}
	response, callErr := client.Do(request)
	return originalLoopbackResponse(ctx, url, response, callErr)
}

func originalLoopbackResponse(ctx context.Context, url string, response *http.Response, callErr error) (int, []byte, error) {
	if response == nil || response.Body == nil {
		return 0, nil, ErrUnavailable
	}
	raw, readErr := io.ReadAll(io.LimitReader(response.Body, 65537))
	closeErr := response.Body.Close()
	status := response.StatusCode
	if callErr != nil || readErr != nil || closeErr != nil || ctx.Err() != nil || len(raw) > 65536 || (url != admissionURL && url != readyURL) || response.Request == nil || response.Request.URL == nil || response.Request.URL.String() != url || response.Request.Method != http.MethodGet {
		wipe(raw)
		return status, nil, ErrUnavailable
	}
	return status, raw, nil
}

func (e *engine) inspectStartup(parent context.Context, source string) StartupInspection {
	c := e.material.config
	out := StartupInspection{Schema: StartupSchema, SourceCommit: source, ConfigSHA256: e.material.scope, Identity: c.Identity, ObservedAt: time.Now().UTC()}
	if c.Identity.Role != "candidate" || c.Startup == nil || len(e.material.startup) < 32 {
		out.ErrorClass = "startup_role_refused"
		return out
	}
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	status, raw, err := loopbackRead(ctx, admissionURL, e.material.startup)
	out.AdmissionHTTPStatus = status
	defer wipe(raw)
	var a admissionReply
	if err != nil || status != http.StatusOK || decodeClosed(raw, &a) != nil {
		out.ErrorClass = "startup_admission_read_incomplete"
		return out
	}
	if a.SchemaVersion != 2 || a.Namespace != c.Identity.Namespace || a.PodName != c.Identity.PodName || a.PodUID != c.Identity.PodUID || a.ImageDigest != c.Startup.ImageDigest || a.LaneRosterSHA256 != c.Startup.LaneRosterSHA256 || !validUUID(a.ProcessNonce) || a.ObservedAt.IsZero() || a.ObservedAt.After(time.Now()) || time.Since(a.ObservedAt) > 5*time.Second {
		out.ErrorClass = "startup_identity_refused"
		return out
	}
	switch a.State {
	case "waiting_projection", "projection_observed", "roots_open", "draining", "invalid_projection", "foreign_process_projection", "origin_changed":
	default:
		out.ErrorClass = "startup_state_refused"
		return out
	}
	if len(a.Challenge) > 0 {
		var challenge startupChallenge
		if decodeClosed(a.Challenge, &challenge) != nil || challenge.SchemaVersion != 2 || challenge.Namespace != a.Namespace || challenge.PodName != a.PodName || challenge.PodUID != a.PodUID || challenge.WorkloadUID != c.Startup.WorkloadUID || challenge.ContainerName != c.Startup.ContainerName || challenge.ImageDigest != a.ImageDigest || challenge.LaneRosterSHA256 != a.LaneRosterSHA256 || challenge.ProcessNonce != a.ProcessNonce || !validUUID(challenge.DrainNonce) || challenge.IntentGeneration < 1 || challenge.IssuedAt.IsZero() || challenge.IssuedAt.After(a.ObservedAt) || !digestPattern.MatchString(a.ChallengeSHA256) {
			out.ErrorClass = "startup_challenge_refused"
			return out
		}
	}
	out.AdmissionState, out.AdmissionObservedAt = a.State, a.ObservedAt
	out.ImageDigest, out.LaneRosterSHA256, out.ProcessNonce, out.ChallengeSHA256 = a.ImageDigest, a.LaneRosterSHA256, a.ProcessNonce, a.ChallengeSHA256
	status, readyRaw, err := loopbackRead(ctx, readyURL, nil)
	out.ReadyHTTPStatus = status
	defer wipe(readyRaw)
	if err != nil {
		out.ErrorClass = "startup_ready_read_incomplete"
		return out
	}
	// /readyz is a distinct original request. Re-read process admission so a
	// restart or a changed projection between the two cannot borrow its result.
	afterStatus, afterRaw, afterErr := loopbackRead(ctx, admissionURL, e.material.startup)
	defer wipe(afterRaw)
	var after admissionReply
	if afterErr != nil || afterStatus != http.StatusOK || decodeClosed(afterRaw, &after) != nil || after.SchemaVersion != a.SchemaVersion || after.Namespace != a.Namespace || after.PodName != a.PodName || after.PodUID != a.PodUID || after.ImageDigest != a.ImageDigest || after.LaneRosterSHA256 != a.LaneRosterSHA256 || after.ProcessNonce != a.ProcessNonce || after.State != a.State || after.ChallengeSHA256 != a.ChallengeSHA256 || !bytes.Equal(after.Challenge, a.Challenge) || after.ObservedAt.Before(a.ObservedAt) || after.ObservedAt.After(time.Now()) || time.Since(after.ObservedAt) > 5*time.Second {
		out.ErrorClass = "startup_origin_changed"
		return out
	}
	out.AdmissionObservedAt = after.ObservedAt
	var ready struct {
		Status         string          `json:"status"`
		Reason         string          `json:"reason,omitempty"`
		RabbitMQStatus string          `json:"rabbitmq_status,omitempty"`
		Error          json.RawMessage `json:"error,omitempty"`
	}
	if decodeClosed(readyRaw, &ready) == nil {
		wipe(ready.Error)
		if (ready.Status != "ready" && ready.Status != "not_ready") || (ready.RabbitMQStatus != "" && ready.RabbitMQStatus != "ok" && ready.RabbitMQStatus != "degraded") {
			out.ErrorClass = "startup_ready_contract_refused"
			return out
		}
		out.ReadyStatus, out.RabbitMQStatus = ready.Status, ready.RabbitMQStatus
	}
	if a.State != "roots_open" || len(a.Challenge) == 0 || status != http.StatusOK || out.ReadyStatus != "ready" || out.RabbitMQStatus != "ok" {
		out.ErrorClass = "startup_pending"
	}
	out.ObservedAt = time.Now().UTC()
	return out
}
