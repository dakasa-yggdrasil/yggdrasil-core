package repository

import (
	"context"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/nativeworkerprobe"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// Fixed PodIP/9446 only. The private run key builds the exact per-run mutual TLS
// transport; no caller URL, proxy, redirect, retry or second POST is available.
func nativeReadinessControl(ctx context.Context, keys *nativeReadinessKeys, r nativeReadinessRun, config nativeworkerprobe.Config, method, path string) (int, []byte, bool) {
	if ctx == nil || ctx.Err() != nil || !time.Now().Before(r.NotAfter) || method != http.MethodGet && method != http.MethodPost || method == http.MethodPost && path != nativeworkerprobe.InitialPath && path != nativeworkerprobe.FinalPath || method == http.MethodGet && path != nativeworkerprobe.ReportPath && path != nativeworkerprobe.StartupPath {
		return 0, nil, false
	}
	call, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	client, closeClient, err := keys.client(call, r, config.Identity.Role, config.Identity.PodIPv4)
	if err != nil {
		return 0, nil, false
	}
	defer closeClient()
	target := "https://" + net.JoinHostPort(config.Identity.PodIPv4, strconv.Itoa(nativeworkerprobe.Port)) + path
	request, err := http.NewRequestWithContext(call, method, target, nil)
	if err != nil {
		return 0, nil, false
	}
	request.GetBody = nil
	response, callErr := client.Do(request)
	return nativeReadinessOriginalControl(call, response, callErr, method, target, config.SourceCommit)
}

func nativeReadinessOriginalControl(ctx context.Context, response *http.Response, callErr error, method, target, source string) (int, []byte, bool) {
	var raw []byte
	status := 0
	valid := response != nil && response.Body != nil && response.Request != nil && response.Request.URL != nil && response.Request.Method == method && response.Request.URL.String() == target && response.TLS != nil && len(response.TLS.VerifiedChains) > 0
	var readErr, closeErr error
	if response != nil {
		status = response.StatusCode
		if response.Body != nil {
			raw, readErr = io.ReadAll(io.LimitReader(response.Body, (256<<10)+1))
			closeErr = response.Body.Close()
		}
		headers := response.Header.Values("X-Yggdrasil-Source-Commit")
		valid = valid && len(headers) == 1 && headers[0] == source && response.Header.Get("Content-Type") == "application/json"
	}
	complete := valid && callErr == nil && readErr == nil && closeErr == nil && ctx != nil && ctx.Err() == nil && len(raw) <= 256<<10
	if len(raw) > 256<<10 {
		raw = raw[:256<<10]
	}
	return status, raw, complete
}

// Only the already captured fixed-route result enters local private custody.
// This finite receiving grace never executes a network/probe/provider effect.
func nativeReadinessCustodyContext(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(parent), 5*time.Second)
}

func nativeReadinessReceiveControl(binding string, r nativeReadinessRun, slot, token string, status int, raw []byte, complete bool) model.NativeWorkerProbeResourceReceive {
	return model.NativeWorkerProbeResourceReceive{BindingName: binding, RunID: r.ID.String(), Slot: slot, SettlementToken: token, HTTPStatus: status, CompletedAt: time.Now().UTC(), TransportCompleted: complete, OriginalReturn: raw}
}
