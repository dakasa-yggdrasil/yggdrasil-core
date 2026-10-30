//go:build !nativequalification

package repository

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/uuid"
)

func TestNativeQualificationMutationDefaultRejected(t *testing.T) {
	for _, verb := range []string{"ensured", "destroyed"} {
		t.Run(verb, func(t *testing.T) {
			eventType := "native-qemu.server." + verb
			if IsIntegrationMutationEvent(eventType) {
				t.Fatalf("default build admitted %q", eventType)
			}
			provider, resource, parsedVerb, ok := ParseIntegrationMutationEventType(eventType)
			if ok || provider != "" || resource != "" || parsedVerb != "" {
				t.Fatalf("Parse(%q) = (%q, %q, %q, %v), want empty rejection", eventType, provider, resource, parsedVerb, ok)
			}
		})
	}
}

func TestEmitEventWithOutcomeNativeQualificationDefaultBeforeSQL(t *testing.T) {
	for _, verb := range []string{"ensured", "destroyed"} {
		t.Run(verb, func(t *testing.T) {
			tx, _ := nativeQualificationMockTransaction(t)
			req := nativeQualificationEventRequest(verb)
			// No statement is expected: a SQL attempt would return a different
			// error from sqlmock, rather than this schema rejection.
			outcome, err := EmitEventWithOutcome(context.Background(), tx, req)
			want := fmt.Sprintf("no schema registered for event type %q version %q", req.Type, req.SchemaVersion)
			if err == nil || err.Error() != want {
				t.Fatalf("EmitEventWithOutcome error = %v, want %q before SQL", err, want)
			}
			if outcome.EventID != uuid.Nil || outcome.MaterializedReactions != 0 || outcome.Deduped {
				t.Fatalf("rejected event returned nonzero outcome: %#v", outcome)
			}
		})
	}
}
