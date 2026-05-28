// Package goroutine ships SafeGo: a fire-and-forget wrapper that
// recovers from panics and bumps a Prometheus counter so a panicking
// background path becomes visible instead of killing the process.
//
// Why this exists:
//   - Go's default behaviour on `go func() { panic(...) }()` is to crash
//     the entire process. Audit goroutines, backchannel logout dispatch,
//     webhook reactor calls — none of these should ever take down core.
//   - Without a metric, ops scrapes a CrashLoopBackOff and the only
//     signal is the container log tail (lost on restart unless a sidecar
//     captures it). With `yggdrasil_goroutine_panics_total{name}`,
//     operators alert on `rate(... > 0)` per call-site.
//
// Usage:
//
//	import "github.com/dakasa-yggdrasil/yggdrasil-core/internal/goroutine"
//
//	goroutine.SafeGo("audit_emit", func() {
//	    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
//	    defer cancel()
//	    _ = repository.RecordAuditEvent(ctx, db, ev)
//	})
//
// The name MUST be a stable, low-cardinality identifier (e.g.,
// "audit_emit", "backchannel_logout_session", "webhook_dispatch"). It
// becomes a Prometheus label value, so don't pass user input.
//
// Audit ref: 2026-05-28 F7.
package goroutine

import (
	"fmt"
	"os"
	"runtime/debug"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/metrics"
)

// SafeGo launches fn in a new goroutine with panic recovery. If fn
// panics, the panic is recovered, the panic value + stack are written
// to stderr (structured key=value format, matches the repository-layer
// log style — zero zap dependency here), and the
// yggdrasil_goroutine_panics_total{name} counter is bumped.
//
// SafeGo NEVER blocks the caller. It returns as soon as the goroutine
// is scheduled.
func SafeGo(name string, fn func()) {
	go runSafe(name, fn)
}

// runSafe is the goroutine body — separated so it can be unit-tested
// synchronously without scheduler noise.
func runSafe(name string, fn func()) {
	defer func() {
		if rec := recover(); rec != nil {
			metrics.IncGoroutinePanic(name)
			// Stderr structured log — keep flat key=value so log
			// scrapers (Loki, CloudWatch) can pivot on `goroutine_name`
			// without a JSON parse step. Stack is multi-line; emit as a
			// final field after %v of the panic.
			fmt.Fprintf(
				os.Stderr,
				"goroutine_panic name=%s panic=%v\nstack=\n%s\n",
				name, rec, debug.Stack(),
			)
		}
	}()
	fn()
}
