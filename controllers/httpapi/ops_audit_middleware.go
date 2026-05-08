package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
)

const opsAuditTimeout = 5 * time.Second

// opsAuditEntry is a denormalised payload for the audit middleware.
// CollaboratorID is required, the rest is best-effort metadata.
type opsAuditEntry struct {
	CollaboratorID string
	SessionID      string
	Action         string
	TargetKind     string
	TargetID       string
	ResultStatus   string
	CorrelationID  string
	RequestBody    map[string]any
	Result         map[string]any
}

// withOpsAudit wraps a handler so each call records an audit row in
// audit_events. The action label is fixed; targetKind labels the
// resource; targetIDPath supports `{run_id}`-style placeholders that get
// resolved against r.PathValue.
//
// The wrapper buffers the response so it can detect 4xx/5xx and tag the
// audit row's result_status appropriately. Body capture is bounded to
// 64KB; bigger payloads are truncated and tagged.
func (s *Server) withOpsAudit(action, targetKind, targetIDPattern string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			collabID := opsCollaboratorID(r)
			corrID := r.Header.Get("X-Correlation-ID")
			if corrID == "" {
				corrID = uuid.NewString()
			}

			reqBody := captureRequestBody(r, 64*1024)
			rec := &auditResponseRecorder{
				ResponseWriter: w,
				status:         http.StatusOK,
				body:           &bytes.Buffer{},
				maxBody:        64 * 1024,
			}
			next.ServeHTTP(rec, r)

			status := "success"
			switch {
			case rec.status >= 500:
				status = "error"
			case rec.status >= 400 && rec.status != http.StatusForbidden:
				// 403 is recorded by requireOpsPermission as denied; here we
				// treat any other 4xx as caller error.
				status = "error"
			case rec.status == http.StatusForbidden:
				status = "denied"
			}

			targetID := resolvePathPattern(r, targetIDPattern)

			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), opsAuditTimeout)
				defer cancel()
				_ = s.recordOpsAuditEntry(ctx, opsAuditEntry{
					CollaboratorID: collabID,
					Action:         action,
					TargetKind:     targetKind,
					TargetID:       targetID,
					ResultStatus:   status,
					CorrelationID:  corrID,
					RequestBody:    reqBody,
					Result:         parseJSONOrEmpty(rec.body.Bytes()),
				})
			}()
		})
	}
}

func resolvePathPattern(r *http.Request, pattern string) string {
	// Substitute {key} with r.PathValue("key"). Simple linear scan.
	out := pattern
	for {
		i := indexOf(out, '{')
		if i < 0 {
			break
		}
		j := indexOf(out[i:], '}')
		if j < 0 {
			break
		}
		key := out[i+1 : i+j]
		val := r.PathValue(key)
		out = out[:i] + val + out[i+j+1:]
	}
	return out
}

func indexOf(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}

// recordOpsAuditEntry resolves a collaborator UUID and inserts.
func (s *Server) recordOpsAuditEntry(ctx context.Context, e opsAuditEntry) error {
	var collabPtr *uuid.UUID
	if e.CollaboratorID != "" {
		if id, err := uuid.Parse(e.CollaboratorID); err == nil {
			collabPtr = &id
		}
	}
	actor := e.CollaboratorID
	if actor == "" {
		actor = "anonymous"
	} else {
		actor = "user:" + actor
	}
	return repository.RecordOpsAuditEvent(ctx, s.db, model.OpsAuditEvent{
		Actor:               actor,
		ActorCollaboratorID: collabPtr,
		ActorSessionID:      e.SessionID,
		Action:              e.Action,
		TargetKind:          e.TargetKind,
		TargetID:            e.TargetID,
		ResultStatus:        e.ResultStatus,
		CorrelationID:       e.CorrelationID,
		RequestBody:         e.RequestBody,
		Result:              e.Result,
	})
}

// captureRequestBody reads up to maxBytes from r.Body, restores the
// reader for downstream handlers, and returns the parsed JSON map.
func captureRequestBody(r *http.Request, maxBytes int) map[string]any {
	if r.Body == nil {
		return nil
	}
	buf, err := io.ReadAll(io.LimitReader(r.Body, int64(maxBytes)))
	if err != nil {
		return nil
	}
	r.Body = io.NopCloser(bytes.NewReader(buf))
	return parseJSONOrEmpty(buf)
}

func parseJSONOrEmpty(b []byte) map[string]any {
	if len(b) == 0 {
		return nil
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		return nil
	}
	return out
}

// auditResponseRecorder buffers the status and body for the audit row
// while still streaming to the real ResponseWriter.
type auditResponseRecorder struct {
	http.ResponseWriter
	status  int
	body    *bytes.Buffer
	maxBody int
	wrote   bool
}

func (a *auditResponseRecorder) WriteHeader(code int) {
	a.status = code
	a.wrote = true
	a.ResponseWriter.WriteHeader(code)
}

func (a *auditResponseRecorder) Write(p []byte) (int, error) {
	if !a.wrote {
		a.wrote = true
	}
	if a.body.Len() < a.maxBody {
		room := a.maxBody - a.body.Len()
		if room > len(p) {
			room = len(p)
		}
		a.body.Write(p[:room])
	}
	return a.ResponseWriter.Write(p)
}
