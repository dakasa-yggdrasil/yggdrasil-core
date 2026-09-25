package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/metrics"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"go.uber.org/zap"
)

// Legacy workflow-run bridge observability (ADR-0022). Retiring the plaintext
// YGGDRASIL_WORKFLOW_RUN_TOKEN bridge needs proof that nothing still uses it,
// and that proof must survive a Core restart. Every request the bridge
// authenticates therefore leaves:
//   - a warning log line naming the route, the workflow or run, the caller's
//     user agent and address;
//   - one bump of yggdrasil_workflow_run_legacy_bridge_requests_total{route};
//   - a durable workflow_run.legacy_bridge row in audit_events (a dispatch
//     always, a poll once per run id per process);
//   - on an asynchronous dispatch, the reserved run metadata
//     yggdrasil.io/creator_legacy_workflow_bridge=true.
//
// Recording happens in the dispatch and poll handlers only, never in the
// outer gate, so one request is counted once. The audit write is best effort:
// a failure is counted in yggdrasil_workflow_run_legacy_bridge_audit_failures_total
// and logged, and the request is still served, because the bridge exists to
// keep callers working until they migrate.
const (
	legacyWorkflowBridgeAuditAction  = "workflow_run.legacy_bridge"
	legacyWorkflowBridgeAuditOutcome = "accepted"
	legacyWorkflowBridgeAuditTimeout = 2 * time.Second

	// legacyWorkflowBridgeUserAgentMax bounds the recorded user agent.
	legacyWorkflowBridgeUserAgentMax = 128
	// legacyWorkflowBridgeRemoteIPMax bounds the recorded address, which
	// may come from a client-supplied forwarding header.
	legacyWorkflowBridgeRemoteIPMax = 128
	// legacyWorkflowBridgeAuditColumnMax is the width of audit_events.actor
	// and audit_events.resource_id (VARCHAR(255)).
	legacyWorkflowBridgeAuditColumnMax = 255
	// legacyWorkflowBridgePollDedupeLimit bounds the per-process set of run
	// ids whose poll was already audited; the set is cleared when full.
	legacyWorkflowBridgePollDedupeLimit = 4096
)

var errLegacyWorkflowBridgeAuditStoreUnconfigured = errors.New("legacy workflow bridge audit store is not configured")

// legacyWorkflowBridgePollSet remembers which run ids already produced a
// poll audit row in this process, so a caller polling one run every few
// seconds leaves one row per run instead of one per poll. The counter still
// counts every poll.
type legacyWorkflowBridgePollSet struct {
	mu   sync.Mutex
	seen map[string]struct{}
}

// firstSighting reports whether runID has not produced a poll audit row yet
// and records it. The set is bounded: once it holds
// legacyWorkflowBridgePollDedupeLimit ids it is cleared, so a long-running
// process may audit a run a second time, never unboundedly grow.
func (p *legacyWorkflowBridgePollSet) firstSighting(runID string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, seen := p.seen[runID]; seen {
		return false
	}
	if p.seen == nil || len(p.seen) >= legacyWorkflowBridgePollDedupeLimit {
		p.seen = make(map[string]struct{})
	}
	p.seen[runID] = struct{}{}
	return true
}

// recordLegacyWorkflowBridgeDispatch records one dispatch the legacy bridge
// authenticated. selector is the requested workflow; it is empty when the
// request was refused before its body was read.
func (s *Server) recordLegacyWorkflowBridgeDispatch(r *http.Request, actor workflowRunActor, selector model.ManifestSelector) {
	if !actor.LegacyMigration {
		return
	}
	metrics.IncWorkflowRunLegacyBridgeRequest(metrics.WorkflowRunLegacyBridgeRouteDispatch)
	workflow := legacyWorkflowBridgeWorkflowRef(selector)
	userAgent, remoteIP := legacyWorkflowBridgeCaller(r)
	if s.logger != nil {
		s.logger.Warn("legacy workflow-run bridge accepted",
			zap.String("route", metrics.WorkflowRunLegacyBridgeRouteDispatch),
			zap.String("workflow", workflow),
			zap.String("subject", legacyWorkflowBridgeActor(actor)),
			zap.String("user_agent", userAgent),
			zap.String("remote_ip", remoteIP))
	}
	s.auditLegacyWorkflowBridge(r, actor, metrics.WorkflowRunLegacyBridgeRouteDispatch, "workflow", workflow, userAgent, remoteIP)
}

// recordLegacyWorkflowBridgePoll records one poll the legacy bridge
// authenticated. runID is the canonical run id, or empty when the path did
// not carry a valid one. Every poll is counted; the log line and the audit
// row are written once per run id per process.
func (s *Server) recordLegacyWorkflowBridgePoll(r *http.Request, actor workflowRunActor, runID string) {
	if !actor.LegacyMigration {
		return
	}
	metrics.IncWorkflowRunLegacyBridgeRequest(metrics.WorkflowRunLegacyBridgeRoutePoll)
	if !s.legacyWorkflowBridgePolls.firstSighting(runID) {
		return
	}
	userAgent, remoteIP := legacyWorkflowBridgeCaller(r)
	if s.logger != nil {
		s.logger.Warn("legacy workflow-run bridge accepted",
			zap.String("route", metrics.WorkflowRunLegacyBridgeRoutePoll),
			zap.String("run_id", runID),
			zap.String("subject", legacyWorkflowBridgeActor(actor)),
			zap.String("user_agent", userAgent),
			zap.String("remote_ip", remoteIP))
	}
	s.auditLegacyWorkflowBridge(r, actor, metrics.WorkflowRunLegacyBridgeRoutePoll, "workflow_run", runID, userAgent, remoteIP)
}

// auditLegacyWorkflowBridge stores the workflow_run.legacy_bridge row. It is
// synchronous with a short bound so a stored row means the use was recorded
// before the caller saw its answer, and best effort so a slow or broken
// store never refuses the request.
func (s *Server) auditLegacyWorkflowBridge(r *http.Request, actor workflowRunActor, route, resourceKind, resourceID, userAgent, remoteIP string) {
	traceID, spanID := requestTraceIDs(r)
	event := model.AuditEvent{
		Actor:        legacyWorkflowBridgeActor(actor),
		Action:       legacyWorkflowBridgeAuditAction,
		ResourceKind: resourceKind,
		ResourceID:   boundedAuditText(resourceID, legacyWorkflowBridgeAuditColumnMax),
		Outcome:      legacyWorkflowBridgeAuditOutcome,
		TraceID:      traceID,
		SpanID:       spanID,
		Metadata: map[string]any{
			"route":      route,
			"user_agent": userAgent,
			"remote_ip":  remoteIP,
		},
	}
	var err error
	switch {
	case s.legacyBridgeAuditSink != nil:
		err = s.legacyBridgeAuditSink(event)
	case s.db == nil:
		err = errLegacyWorkflowBridgeAuditStoreUnconfigured
	default:
		ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), legacyWorkflowBridgeAuditTimeout)
		defer cancel()
		err = repository.RecordAuditEvent(ctx, s.db, event)
	}
	if err == nil {
		return
	}
	metrics.IncWorkflowRunLegacyBridgeAuditFailure()
	if s.logger != nil {
		s.logger.Error("legacy workflow-run bridge audit insert failed; the request is still served",
			zap.String("route", route),
			zap.String("resource_id", event.ResourceID),
			zap.Error(err))
	}
}

// legacyWorkflowBridgeActor is the audit actor of the bridge subject,
// "service:legacy-workflow-run-token" unless the operator renamed it, bounded
// to the audit_events.actor column.
func legacyWorkflowBridgeActor(actor workflowRunActor) string {
	subject := actor.Subject
	if subject.Type == "" || subject.ID == "" {
		subject = legacyWorkflowRunSubject()
	}
	return boundedAuditText(subject.Type+":"+subject.ID, legacyWorkflowBridgeAuditColumnMax)
}

// legacyWorkflowBridgeWorkflowRef names the requested workflow the way the
// resolver will select it: the manifest id when one is given, otherwise
// namespace/name with the default namespace.
func legacyWorkflowBridgeWorkflowRef(selector model.ManifestSelector) string {
	if id := strings.TrimSpace(selector.ManifestID); id != "" {
		return boundedAuditText(id, legacyWorkflowBridgeAuditColumnMax)
	}
	name := strings.TrimSpace(selector.Name)
	if name == "" {
		return ""
	}
	namespace := strings.TrimSpace(selector.Namespace)
	if namespace == "" {
		namespace = "global"
	}
	return boundedAuditText(namespace+"/"+name, legacyWorkflowBridgeAuditColumnMax)
}

// legacyWorkflowBridgeCaller returns the bounded user agent and address that
// identify who still uses the bridge.
func legacyWorkflowBridgeCaller(r *http.Request) (userAgent, remoteIP string) {
	return boundedAuditText(r.UserAgent(), legacyWorkflowBridgeUserAgentMax),
		boundedAuditText(clientIP(r), legacyWorkflowBridgeRemoteIPMax)
}

// boundedAuditText trims value, drops control characters and cuts it to at
// most limit bytes on a rune boundary, so a client-supplied header can
// neither break a log line nor exceed a column.
func boundedAuditText(value string, limit int) string {
	value = strings.TrimSpace(value)
	value = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == utf8.RuneError {
			return -1
		}
		return r
	}, value)
	if len(value) <= limit {
		return value
	}
	cut := 0
	for index, r := range value {
		next := index + utf8.RuneLen(r)
		if next > limit {
			break
		}
		cut = next
	}
	return value[:cut]
}
