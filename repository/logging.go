package repository

import (
	"fmt"
	"os"
	"strings"
	"time"
)

// structuredLog emits a single line to stderr with key=value pairs, in
// a format that Loki / fluent-bit / vector can parse without regex.
//
// We deliberately don't depend on zap here — repository is the data
// access layer and adding a logger dependency would force every test
// helper to wire one. Stderr key=value is structured enough for ops
// aggregators while staying dependency-free.
//
// Audit ref: B4/B8/G2 — replace fmt.Printf (unstructured, no fields)
// with this helper at every repository-level diagnostic site.
//
// Format: `repo ts=<RFC3339Nano> event=<event> k1=v1 k2=v2 ...`
//
// Values containing spaces are JSON-escaped via fmt.Sprintf("%q"). All
// other values are emitted with %v.
func structuredLog(event string, kv ...any) {
	var b strings.Builder
	b.WriteString("repo ts=")
	b.WriteString(time.Now().UTC().Format(time.RFC3339Nano))
	b.WriteString(" event=")
	b.WriteString(event)
	for i := 0; i+1 < len(kv); i += 2 {
		key, ok := kv[i].(string)
		if !ok {
			continue
		}
		b.WriteByte(' ')
		b.WriteString(key)
		b.WriteByte('=')
		val := fmt.Sprintf("%v", kv[i+1])
		if strings.ContainsAny(val, " \t\"") {
			b.WriteString(fmt.Sprintf("%q", val))
		} else {
			b.WriteString(val)
		}
	}
	b.WriteByte('\n')
	_, _ = os.Stderr.WriteString(b.String())
}
