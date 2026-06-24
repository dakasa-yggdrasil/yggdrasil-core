package httpapi

import "testing"

func TestIsBrokerAvailable(t *testing.T) {
	t.Run("broker_url_unset_is_not_available", func(t *testing.T) {
		t.Setenv("BROKER_URL", "")
		s := &Server{rabbitmq: nil}
		if s.isBrokerAvailable() {
			t.Fatal("expected unavailable when BROKER_URL unset")
		}
	})
	t.Run("broker_url_set_but_conn_nil_is_not_available", func(t *testing.T) {
		t.Setenv("BROKER_URL", "amqp://unreachable:5672")
		s := &Server{rabbitmq: nil}
		if s.isBrokerAvailable() {
			t.Fatal("expected unavailable when conn is nil")
		}
	})
}
