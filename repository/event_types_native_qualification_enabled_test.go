//go:build nativequalification

package repository

import (
	"context"
	"encoding/json"
	"regexp"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
)

func TestNativeQualificationMutationEnabledAccepted(t *testing.T) {
	pattern := regexp.MustCompile(IntegrationMutationEventTypeRegex)
	for _, verb := range []string{"ensured", "destroyed"} {
		t.Run(verb, func(t *testing.T) {
			eventType := "native-qemu.server." + verb
			if pattern.MatchString(eventType) {
				t.Fatalf("fixed qualification event %q broadened the generic grammar", eventType)
			}
			if !IsIntegrationMutationEvent(eventType) {
				t.Fatalf("qualification build rejected %q", eventType)
			}
			provider, resource, parsedVerb, ok := ParseIntegrationMutationEventType(eventType)
			if !ok || provider != "native-qemu" || resource != "server" || parsedVerb != verb {
				t.Fatalf("Parse(%q) = (%q, %q, %q, %v), want (native-qemu, server, %s, true)", eventType, provider, resource, parsedVerb, ok, verb)
			}
		})
	}
}

func TestEmitEventWithOutcomeNativeQualificationEnabledDispatch(t *testing.T) {
	for _, verb := range []string{"ensured", "destroyed"} {
		t.Run(verb, func(t *testing.T) {
			tx, mock := nativeQualificationMockTransaction(t)
			req := nativeQualificationEventRequest(verb)
			payload, err := json.Marshal(req.Payload)
			if err != nil {
				t.Fatalf("marshal contract payload: %v", err)
			}
			eventID := uuid.MustParse("018f2b4a-1234-7abc-8ef0-123456789020")
			mock.ExpectQuery(regexp.QuoteMeta("INSERT INTO public.event_log")).
				WithArgs(sqlmock.AnyArg(), req.Type, req.SchemaVersion, req.AggregateType, req.AggregateID, nil, nil, nil, payload, nil, req.IdempotencyKey).
				WillReturnRows(sqlmock.NewRows([]string{"event_id"}).AddRow(eventID.String()))
			mock.ExpectExec(regexp.QuoteMeta("INSERT INTO integration_event_reactions")).
				WithArgs(eventID, req.Type).
				WillReturnResult(sqlmock.NewResult(0, 2))
			outcome, err := EmitEventWithOutcome(context.Background(), tx, req)
			if err != nil {
				t.Fatalf("EmitEventWithOutcome: %v", err)
			}
			if outcome.EventID != eventID || outcome.MaterializedReactions != 2 || outcome.Deduped {
				t.Fatalf("SQL dispatch outcome = %#v, want event %s, two mocked reactions, no dedup", outcome, eventID)
			}
		})
	}
}
