package message

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-sdk-go/rpc"
	rpcamqp "github.com/dakasa-yggdrasil/yggdrasil-sdk-go/rpc/amqp"
	amqp "github.com/rabbitmq/amqp091-go"
)

type closedSessionTestWire struct{}

func (closedSessionTestWire) Read([]byte) (int, error)    { return 0, io.EOF }
func (closedSessionTestWire) Write(p []byte) (int, error) { return len(p), nil }
func (closedSessionTestWire) Close() error                { return nil }

func TestSessionAMQPTransportUnavailableReturnsClosedWithoutSDKPanic(t *testing.T) {
	// EOF closes the real SDK connection in memory, without a network/broker.
	closed, openErr := amqp.Open(closedSessionTestWire{}, amqp.Config{})
	if openErr == nil || closed == nil || !closed.IsClosed() {
		t.Fatal("fixture did not produce an actually closed SDK connection")
	}
	for _, test := range []struct {
		name string
		conn *amqp.Connection
	}{{"nil", nil}, {"closed", closed}} {
		t.Run(test.name, func(t *testing.T) {
			transport := sessionAMQPTransport(test.conn)
			if sub, err := transport.Consume(rpc.ConsumerConfig{Endpoint: "unavailable"}); sub != nil || !errors.Is(err, rpc.ErrClosed) {
				t.Fatalf("Consume = %v, %v", sub, err)
			}
			if _, err := transport.Request(t.Context(), rpc.Request{Endpoint: "unavailable"}); !errors.Is(err, rpc.ErrClosed) {
				t.Fatalf("Request = %v", err)
			}
			if err := transport.Publish(t.Context(), rpc.Request{Endpoint: "unavailable"}); !errors.Is(err, rpc.ErrClosed) {
				t.Fatalf("Publish = %v", err)
			}
			if err := transport.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
	// The nonnil open snapshot is passed unchanged to the ordinary SDK path.
	if _, ok := sessionAMQPTransport(&amqp.Connection{}).(*rpcamqp.Transport); !ok {
		t.Fatal("a live snapshot did not retain the existing SDK transport")
	}
}

func TestSessionAMQPTransportNilPreservesHTTPAdapterSelection(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != http.MethodPost || r.URL.Path != "/rpc/describe" {
			t.Errorf("HTTP adapter route changed: %s %s", r.Method, r.URL.Path)
		}
		_, _ = io.WriteString(w, sessionTransportDescribeJSON)
	}))
	defer server.Close()
	client := newAdapterTransportClient(sessionAMQPTransport(nil))
	var reply model.AdapterDescribeResponse
	err := client.Call(context.Background(), integrationDescribeContract,
		model.IntegrationTypeManifestSpec{Adapter: model.IntegrationAdapterSpec{Transport: "http_json", Endpoints: model.IntegrationAdapterRoute{Describe: "/rpc/describe"}}},
		model.IntegrationInstanceManifestSpec{Config: map[string]any{"base_url": server.URL}},
		"describe", model.AdapterDescribeRequest{Provider: "guest-bootstrap"}, &reply)
	if err != nil || calls.Load() != 1 || reply.Provider != "guest-bootstrap" {
		t.Fatalf("HTTP adapter with nil AMQP = %v, calls=%d, provider=%q", err, calls.Load(), reply.Provider)
	}
}

// Reused verbatim from the existing canonical Describe fixture. Keeping a
// standalone copy avoids its unrelated Linux-only PG test helper dependency.
const sessionTransportDescribeJSON = `{
  "provider":"guest-bootstrap","domain":"infrastructure",
  "dashboard":{"url":"https://example.invalid/operator","label":"Provider"},
  "display":{"subtitle":"Original native catalog","subtitle_locale":{"en-US":"Original native catalog"}},
  "icon":{"url":"/native-protocol.svg","accent":"#0F766E","aria_label":"Native protocol"},
  "adapter":{"transport":"http_json","version":"1.0.0","endpoints":{"describe":"/rpc/describe","execute":"/rpc/execute"},"queues":{"describe":"protocol.describe","execute":"protocol.execute"},"timeout_seconds":65},
  "capabilities":["describe","execute"],
  "credential_policy":{"source":"secret_ref","materialize_inline":false},
  "guardian_support":{"mode":"light","signals":{}},
  "credential_schema":{"mode":"inline","required":["ssh_private_key"],"properties":{"ssh_private_key":{"type":"string","secret":true,"sensitive":true,"label":"Read-only SSH credential"}}},
  "instance_schema":{"mode":"inline","properties":{"base_url":{"type":"string","label":"Adapter endpoint"}}},
  "resource_types":[{"name":"guest_bootstrap","canonical_prefix":"thirdparty.guest-bootstrap.original","identity_template":"original.{id}","discoverable":false,"default_actions":["observe_guest_bootstrap"]}],
  "action_catalog":[{"name":"observe_guest_bootstrap","resource_types":["guest_bootstrap"],"idempotent":true,"input_schema":{"type":"object","additionalProperties":false,"required":["binding_name"],"properties":{"binding_name":{"type":"string","maxLength":64}}}}],
  "discovery":{"mode":"push","cursor":"none","supports_webhooks":false},
  "normalization":{"external_id_path":"id","fallback_resource_prefix":"thirdparty.guest-bootstrap.original"},
  "execution":{"supports_dry_run":false,"idempotent_actions":["observe_guest_bootstrap"]},
  "extensions":{"allow_custom_resource_types":false,"allow_custom_actions":false,"preserve_raw_payload":false}
}`
