package repository

import (
	"context"
	"database/sql"
	"regexp"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func TestNativeQualificationMutationNearVariants(t *testing.T) {
	cases := []struct {
		name      string
		eventType string
	}{
		{"created", "native-qemu.server.created"},
		{"other_resource", "native-qemu.volume.ensured"},
		{"other_hyphenated_provider", "other-qemu.server.ensured"},
		{"provider_suffix", "native-qemu-extra.server.ensured"},
		{"provider_case", "Native-qemu.server.ensured"},
		{"resource_case", "native-qemu.Server.ensured"},
		{"verb_case", "native-qemu.server.Ensured"},
		{"extra_segment", "native-qemu.server.ensured.extra"},
		{"trailing_dot", "native-qemu.server.destroyed."},
		{"leading_space", " native-qemu.server.ensured"},
		{"trailing_space", "native-qemu.server.destroyed "},
		{"missing_verb", "native-qemu.server"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if IsIntegrationMutationEvent(tc.eventType) {
				t.Fatalf("classification admitted near variant %q", tc.eventType)
			}
			provider, resource, verb, ok := ParseIntegrationMutationEventType(tc.eventType)
			if ok || provider != "" || resource != "" || verb != "" {
				t.Fatalf("Parse(%q) = (%q, %q, %q, %v), want empty rejection", tc.eventType, provider, resource, verb, ok)
			}
		})
	}
}

func TestNativeQualificationMutationGenericGrammar(t *testing.T) {
	cases := []struct {
		name      string
		eventType string
		provider  string
		resource  string
		verb      string
		want      bool
	}{
		{"stripe_ensured", "stripe.customer.ensured", "stripe", "customer", "ensured", true},
		{"stripe_destroyed", "stripe.subscription.destroyed", "stripe", "subscription", "destroyed", true},
		{"stripe_created", "stripe.refund.created", "stripe", "refund", "created", true},
		{"underscore_provider", "native_qemu.server.ensured", "native_qemu", "server", "ensured", true},
		{"digits_and_underscores", "provider1.server_type2.ensured", "provider1", "server_type2", "ensured", true},
		{"generic_created", "nativeqemu.server.created", "nativeqemu", "server", "created", true},
		{"hyphenated_provider", "other-provider.server.ensured", "", "", "", false},
		{"hyphenated_resource", "stripe.service-account.ensured", "", "", "", false},
		{"uppercase_provider", "Stripe.server.ensured", "", "", "", false},
		{"unknown_verb", "stripe.server.updated", "", "", "", false},
	}
	pattern := regexp.MustCompile(IntegrationMutationEventTypeRegex)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := pattern.MatchString(tc.eventType); got != tc.want {
				t.Fatalf("generic grammar for %q = %v, want %v", tc.eventType, got, tc.want)
			}
			if got := IsIntegrationMutationEvent(tc.eventType); got != tc.want {
				t.Fatalf("classification for %q = %v, want %v", tc.eventType, got, tc.want)
			}
			provider, resource, verb, ok := ParseIntegrationMutationEventType(tc.eventType)
			if ok != tc.want || provider != tc.provider || resource != tc.resource || verb != tc.verb {
				t.Fatalf("Parse(%q) = (%q, %q, %q, %v), want (%q, %q, %q, %v)", tc.eventType, provider, resource, verb, ok, tc.provider, tc.resource, tc.verb, tc.want)
			}
		})
	}
}

// These fixtures exercise event contracts and SQL dispatch only. They contain
// no native provisioning evidence and establish no native or production authority.
func nativeQualificationEventRequest(verb string) model.EmitEventRequest {
	return model.EmitEventRequest{
		Type:           "native-qemu.server." + verb,
		SchemaVersion:  "v1",
		AggregateType:  "native-qemu_server",
		AggregateID:    "contract-test-resource",
		IdempotencyKey: "contract-test/" + verb,
		Payload: map[string]any{
			"provider":    "native-qemu",
			"resource":    "server",
			"verb":        verb,
			"resource_id": "contract-test-resource",
			"instance_id": "contract-test-instance",
			"emitted_at":  "2026-10-20T00:00:00Z",
		},
	}
}

func nativeQualificationMockTransaction(t *testing.T) (*sql.Tx, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	mock.ExpectBegin()
	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatalf("begin mock transaction: %v", err)
	}
	t.Cleanup(func() {
		mock.ExpectRollback()
		if err := tx.Rollback(); err != nil {
			t.Errorf("rollback mock transaction: %v", err)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("SQL dispatch expectations: %v", err)
		}
	})
	return tx, mock
}
