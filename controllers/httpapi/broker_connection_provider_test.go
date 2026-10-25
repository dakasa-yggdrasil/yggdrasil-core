package httpapi

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	amqp "github.com/rabbitmq/amqp091-go"
)

func TestRabbitMQConnectionProviderSelectsCurrentGeneration(t *testing.T) {
	legacy := &amqp.Connection{}
	first := &amqp.Connection{}
	second := &amqp.Connection{}
	current := first
	s := &Server{rabbitmq: legacy}
	WithRabbitMQConnectionProvider(func() *amqp.Connection { return current })(s)
	// The router builds these deps only once, before subsequent HTTP requests.
	deps := s.buildManifestSyncDeps().(*httpManifestSyncDeps)

	for _, conn := range []*amqp.Connection{first, second, nil} {
		current = conn
		if got := s.brokerConnection(); got != conn {
			t.Fatalf("current generation = %p; want %p", got, conn)
		}
		if got := deps.brokerConnection(); got != conn {
			t.Fatalf("reused manifest-sync dependency captured %p; want %p", got, conn)
		}
	}
	if s.rabbitmq != legacy {
		t.Fatal("provider changed the legacy constructor connection")
	}
	WithRabbitMQConnectionProvider(nil)(s)
	if got := s.brokerConnection(); got != legacy {
		t.Fatalf("without a provider the constructor connection = %p; want %p", got, legacy)
	}
}

func TestRabbitMQConnectionProviderReadinessAndDispatchRecoverWithoutNewServer(t *testing.T) {
	t.Setenv("BROKER_URL", "amqp://source-only.invalid")
	db, mock, err := sqlmock.New(sqlmock.MonitorPingsOption(true))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	first, firstWire := openProviderTestConnection(t)
	second, _ := openProviderTestConnection(t)
	current := first
	s := &Server{db: db, rabbitmq: &amqp.Connection{}}
	WithRabbitMQConnectionProvider(func() *amqp.Connection { return current })(s)

	checkReady := func(want string) {
		t.Helper()
		mock.ExpectPing()
		rec := httptest.NewRecorder()
		s.handleReadyz(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
		var body map[string]string
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if rec.Code != http.StatusOK || body["status"] != "ready" || body["rabbitmq_status"] != want {
			t.Fatalf("readiness = %d %v; want ready/%s", rec.Code, body, want)
		}
	}
	checkReady("ok")
	closed := first.NotifyClose(make(chan *amqp.Error, 1))
	_ = firstWire.Close()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("in-memory connection did not close")
	}
	if !first.IsClosed() {
		t.Fatal("test requires an actually closed AMQP connection")
	}
	checkReady("degraded")
	for _, unavailable := range []*amqp.Connection{first, nil} {
		current = unavailable
		rec := httptest.NewRecorder()
		s.handleWorkflowRun(rec, httptest.NewRequest(http.MethodPost, "/api/v1/workflow-runs", strings.NewReader(`{}`)))
		if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "workflow_dispatch_unavailable") {
			t.Fatalf("unavailable generation must refuse dispatch: %d %s", rec.Code, rec.Body.String())
		}
	}
	current = second
	checkReady("ok")
	if !s.isBrokerAvailable() {
		t.Fatal("the same HTTP server did not observe the replacement connection")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestRabbitMQConnectionProviderLivenessUsesOneSnapshot(t *testing.T) {
	t.Setenv("BROKER_URL", "amqp://source-only.invalid")
	calls := 0
	s := &Server{}
	WithRabbitMQConnectionProvider(func() *amqp.Connection {
		calls++
		if calls == 1 {
			return &amqp.Connection{}
		}
		return nil
	})(s)
	if !s.isBrokerAvailable() || calls != 1 {
		t.Fatalf("liveness must use one generation snapshot, calls=%d", calls)
	}
	if s.isBrokerAvailable() || calls != 2 {
		t.Fatalf("the next check must observe unavailable, calls=%d", calls)
	}
}

// The SDK completes a real AMQP handshake over memory only. Ending this stream
// exercises its normal connection-shutdown state without a network or a broker.
type providerTestWire struct {
	reader *bytes.Reader
	done   chan struct{}
	once   sync.Once
}

func (w *providerTestWire) Read(p []byte) (int, error) {
	if w.reader.Len() > 0 {
		return w.reader.Read(p)
	}
	<-w.done
	return 0, io.EOF
}

func (w *providerTestWire) Write(p []byte) (int, error) {
	select {
	case <-w.done:
		return 0, io.ErrClosedPipe
	default:
		return len(p), nil
	}
}

func (w *providerTestWire) Close() error {
	w.once.Do(func() { close(w.done) })
	return nil
}

func openProviderTestConnection(t *testing.T) (*amqp.Connection, *providerTestWire) {
	t.Helper()
	var frames []byte
	method := func(id uint16, body []byte) {
		payload := make([]byte, 4+len(body))
		binary.BigEndian.PutUint16(payload[:2], 10) // connection class
		binary.BigEndian.PutUint16(payload[2:4], id)
		copy(payload[4:], body)
		header := make([]byte, 7)
		header[0] = 1 // method frame, channel 0
		binary.BigEndian.PutUint32(header[3:], uint32(len(payload)))
		frames = append(frames, header...)
		frames = append(frames, payload...)
		frames = append(frames, 0xce)
	}
	method(10, []byte{0, 9, 0, 0, 0, 0, 0, 0, 0, 5, 'P', 'L', 'A', 'I', 'N', 0, 0, 0, 5, 'e', 'n', '_', 'U', 'S'})
	method(30, []byte{0, 0, 0, 2, 0, 0, 0, 0})
	method(41, []byte{0})
	wire := &providerTestWire{reader: bytes.NewReader(frames), done: make(chan struct{})}
	conn, err := amqp.Open(wire, amqp.Config{
		SASL:   []amqp.Authentication{&amqp.PlainAuth{Username: "test", Password: "test"}},
		Locale: "en_US",
	})
	if err != nil {
		_ = wire.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = wire.Close() })
	return conn, wire
}
