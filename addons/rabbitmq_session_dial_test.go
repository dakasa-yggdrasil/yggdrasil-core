package addons

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	amqp "github.com/rabbitmq/amqp091-go"
)

func TestBrokerSessionDialCancellationClosesAnUnresponsiveHandshake(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started, done := make(chan struct{}), make(chan error, 1)
	go func() {
		conn, err := dialBrokerSessionUsing(ctx, "amqp://guest:guest@127.0.0.1:1/", func(context.Context, string, string) (net.Conn, error) {
			close(started)
			return client, nil
		})
		if conn != nil {
			t.Error("cancelled handshake returned a usable session")
		}
		done <- err
	}()
	<-started
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("handshake cancellation=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled handshake retained its socket")
	}
	_ = server.SetWriteDeadline(time.Now().Add(time.Second))
	if _, err := server.Write([]byte("late handshake")); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal("cancelled handshake socket remained open")
	}
}

func TestBrokerSessionDialUsesEarlierContextDeadline(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	started := time.Now()
	conn, err := dialBrokerSessionUsing(ctx, "amqp://guest:guest@127.0.0.1:1/", func(context.Context, string, string) (net.Conn, error) { return client, nil })
	if conn != nil || err == nil {
		t.Fatal("unresponsive handshake succeeded")
	}
	if time.Since(started) > time.Second {
		t.Fatal("handshake ignored caller's shorter deadline")
	}
	// The socket deadline and context deadline can race; both must close the
	// incomplete connection rather than publish it as ready.
	_ = server.SetWriteDeadline(time.Now().Add(time.Second))
	if _, err := server.Write([]byte("late handshake")); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal("expired handshake socket remained open")
	}
}

type countedBrokerSocket struct {
	net.Conn
	closes atomic.Int32
}

func (c *countedBrokerSocket) Close() error { c.closes.Add(1); return c.Conn.Close() }

func TestBrokerSessionDialClosesRejectedSASLConnectionBeforeReturning(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	socket := &countedBrokerSocket{Conn: client}
	serverDone := make(chan error, 1)
	go func() {
		var protocol [8]byte
		if _, err := io.ReadFull(server, protocol[:]); err != nil {
			serverDone <- err
			return
		}
		// connection.start offers only EXTERNAL; the client's default PLAIN
		// authentication cannot negotiate. This is the library's conn+error path.
		payload := []byte{0, 10, 0, 10, 0, 9, 0, 0, 0, 0}
		for _, value := range []string{"EXTERNAL", "en_US"} {
			payload = binary.BigEndian.AppendUint32(payload, uint32(len(value)))
			payload = append(payload, value...)
		}
		frame := []byte{1, 0, 0}
		frame = binary.BigEndian.AppendUint32(frame, uint32(len(payload)))
		frame = append(frame, payload...)
		frame = append(frame, 0xce)
		_, err := server.Write(frame)
		serverDone <- err
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := dialBrokerSessionUsing(ctx, "amqp://guest:guest@127.0.0.1:1/", func(context.Context, string, string) (net.Conn, error) { return socket, nil })
	if conn != nil || !errors.Is(err, amqp.ErrSASL) {
		t.Fatalf("rejected handshake returned conn=%p err=%v", conn, err)
	}
	if socket.closes.Load() == 0 {
		t.Fatal("rejected handshake retained its socket before returning")
	}
	select {
	case err := <-serverDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("handshake server did not finish")
	}
}
