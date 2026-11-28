package repository

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/nativeworkerprobe"
)

const nativeReadinessControlPollWindow = 10 * time.Second
const nativeReadinessControlReturnReserve = 10 * time.Second

var errNativeReadinessPending = errors.New("native readiness control pending")

// An authenticated idle report proves only that the exact configured control
// process is reachable. It grants no packet, network, warmup or Node proof.
func nativeReadinessIdleReport(c nativeworkerprobe.Config, configSHA string, report nativeworkerprobe.Report, own ed25519.PublicKey, r nativeReadinessRun, now time.Time) bool {
	if !nativeReadinessProbeContext(c, r, now) || !nativeReadinessSHA(configSHA) || len(own) != ed25519.PublicKeySize || report.Schema != nativeworkerprobe.ReportSchema || report.SourceCommit != c.SourceCommit || report.ConfigSHA256 != configSHA || report.Identity != c.Identity || !report.HardNotAfter.Equal(c.HardNotAfter) || report.SigningPublicKey != base64.StdEncoding.EncodeToString(own) || report.ObservedAt.Before(r.CreatedAt) || report.ObservedAt.After(now) || now.Sub(report.ObservedAt) >= 5*time.Second {
		return false
	}
	for _, b := range []nativeworkerprobe.BatchReport{report.Initial, report.Final} {
		if b.State != "idle" || b.ErrorClass != "" || b.StartedAt != nil || b.CompletedAt != nil || len(b.Sent) != 0 || len(b.Received) != 0 || len(b.Echoed) != 0 {
			return false
		}
	}
	return true
}

// Optional Secret projection precedes the actual control listener. GET-only
// waiting captures every original before parsing and does not consume either
// one-shot POST. A later proof invocation resumes the same run and keys.
func (s *nativeReadinessProducerState) awaitInitialControl(ctx context.Context, r nativeReadinessRun, keys *nativeReadinessKeys, f, c nativeworkerprobe.Config, fs, cs string) (nativeReadinessRun, error) {
	if ctx == nil || ctx.Err() != nil || !time.Now().Before(r.NotAfter) {
		return r, errNativeReadinessRun
	}
	_, floorStarted := nativeReadinessEffectIndex(r, "floor_initial")
	_, candidateStarted := nativeReadinessEffectIndex(r, "candidate_initial")
	if floorStarted || candidateStarted {
		// An existing dispatch barrier is not an idle/retry right. The caller
		// resumes the original report/custody path and holds unknown outcomes.
		return r, nil
	}
	window := nativeReadinessControlPollWindow
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline) - nativeReadinessControlReturnReserve
		if remaining <= 0 {
			return r, errNativeReadinessPending
		}
		if remaining < window {
			window = remaining
		}
	}
	if remaining := time.Until(r.NotAfter); remaining < window {
		window = remaining
	}
	poll, cancel := context.WithTimeout(ctx, window)
	defer cancel()
	floorKey, err := keys.key(4)
	if err != nil {
		return r, err
	}
	defer clear(floorKey)
	candidateKey, err := keys.key(5)
	if err != nil {
		return r, err
	}
	defer clear(candidateKey)
	tick := time.NewTicker(200 * time.Millisecond)
	defer tick.Stop()
	for {
		if ctx.Err() != nil || !time.Now().Before(r.NotAfter) {
			return r, errNativeReadinessRun
		}
		if poll.Err() != nil {
			return r, errNativeReadinessPending
		}
		var floor, candidate nativeworkerprobe.Report
		var floorErr, candidateErr error
		r, floorErr = s.readControl(poll, r, keys, f, nativeworkerprobe.ReportPath, "floor_report_initial", &floor)
		if ctx.Err() != nil {
			return r, errNativeReadinessRun
		}
		if poll.Err() != nil {
			return r, errNativeReadinessPending
		}
		r, candidateErr = s.readControl(poll, r, keys, c, nativeworkerprobe.ReportPath, "candidate_report_initial", &candidate)
		now := time.Now().UTC()
		if floorErr == nil && candidateErr == nil && nativeReadinessIdleReport(f, fs, floor, floorKey.Public().(ed25519.PublicKey), r, now) && nativeReadinessIdleReport(c, cs, candidate, candidateKey.Public().(ed25519.PublicKey), r, now) {
			return r, nil
		}
		select {
		case <-ctx.Done():
			return r, errNativeReadinessRun
		case <-poll.Done():
			if ctx.Err() != nil {
				return r, errNativeReadinessRun
			}
			return r, errNativeReadinessPending
		case <-tick.C:
		}
	}
}
