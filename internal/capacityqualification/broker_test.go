//go:build nativequalification

package capacityqualification

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-sdk-go/rpc"
	rpcamqp "github.com/dakasa-yggdrasil/yggdrasil-sdk-go/rpc/amqp"
	amqp "github.com/rabbitmq/amqp091-go"
)

func checkDescribeReply(t *testing.T, reply rpc.Reply) {
	t.Helper()
	var envelope struct {
		OK   bool                          `json:"ok"`
		Data model.AdapterDescribeResponse `json:"data"`
	}
	if err := json.Unmarshal(reply.Body, &envelope); err != nil {
		t.Fatal(err)
	}
	expected, err := NativeDescribe()
	if err != nil {
		t.Fatal(err)
	}
	if !envelope.OK || !reflect.DeepEqual(envelope.Data, expected) {
		t.Fatal("correlated Describe contract mismatch")
	}
}

func TestDedicatedBrokerGracefulClose(t *testing.T) {
	address := os.Getenv("CAPACITY_QUALIFICATION_AMQP_URL")
	if address == "" {
		t.Skip("isolated qualification broker not configured")
	}
	if address != "amqp://guest:guest@127.0.0.1:25680/" && address != "amqp://native:native-ci-only@127.0.0.1:5672/" {
		t.Fatal("only the isolated qualification broker may be used")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	broker, err := dialDedicated(ctx, address, nil)
	if err != nil {
		t.Fatal(err)
	}
	closeDescribe, err := StartDescribe(ctx, broker.Connection)
	if err != nil {
		t.Fatal(err)
	}
	if err := broker.CloseWith(ctx, 2*time.Second, closeDescribe); err != nil {
		t.Fatal(err)
	}
}

func TestDedicatedBrokerBlackholeDuringPartialStartup(t *testing.T) {
	address := os.Getenv("CAPACITY_QUALIFICATION_AMQP_URL")
	if address == "" {
		t.Skip("isolated qualification broker not configured")
	}
	var target string
	switch address {
	case "amqp://guest:guest@127.0.0.1:25680/":
		target = "127.0.0.1:25680"
	case "amqp://native:native-ci-only@127.0.0.1:5672/":
		target = "127.0.0.1:5672"
	default:
		t.Fatal("only the isolated qualification broker may be used")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	var armed atomic.Bool
	release, proxyDone := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(proxyDone)
		client, err := listener.Accept()
		if err != nil {
			return
		}
		defer client.Close()
		server, err := net.Dial("tcp", target)
		if err != nil {
			return
		}
		defer server.Close()
		upstreamDone := make(chan struct{})
		go func() { defer close(upstreamDone); _, _ = io.Copy(server, client); _ = server.Close() }()
		buf := make([]byte, 4096)
		for {
			n, e := server.Read(buf)
			if n > 0 {
				if armed.Load() {
					<-release
				}
				if _, err := client.Write(buf[:n]); err != nil {
					break
				}
			}
			if e != nil {
				break
			}
		}
		_ = client.Close()
		_ = server.Close()
		<-upstreamDone
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	broker, err := dialDedicated(ctx, address, func(ctx context.Context, network, ignored string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, listener.Addr().String())
	})
	if err != nil {
		t.Fatal(err)
	}
	finished := make(chan error, 1)
	go func() {
		_, startErr := broker.StartWith(ctx, 250*time.Millisecond, func() (func() error, error) {
			closeDescribe, err := StartDescribe(ctx, broker.Connection)
			if err != nil {
				return nil, err
			}
			armed.Store(true)
			_, err = ConsumePredeclared(ctx, broker.Connection, rpc.ConsumerConfig{Endpoint: "qualification.original.execute", Concurrency: 1, Timeout: time.Second, Handler: func(context.Context, rpc.Delivery) error { return nil }})
			if err != nil {
				return nil, errors.Join(err, closeDescribe())
			}
			return nil, errors.New("blackholed startup unexpectedly succeeded")
		})
		finished <- errors.Join(startErr, broker.CloseWith(ctx, time.Second, nil))
	}()
	select {
	case err := <-finished:
		if !errors.Is(err, errQualificationBrokerDeadline) {
			t.Fatalf("blackholed partial startup must report guard deadline: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("partial startup did not return")
	}
	close(release)
	select {
	case <-proxyDone:
	case <-time.After(3 * time.Second):
		t.Fatal("startup proxy did not join")
	}
}

func TestDedicatedBrokerWaitsForLocalHandler(t *testing.T) {
	address := os.Getenv("CAPACITY_QUALIFICATION_AMQP_URL")
	if address == "" {
		t.Skip("isolated qualification broker not configured")
	}
	if address != "amqp://guest:guest@127.0.0.1:25680/" && address != "amqp://native:native-ci-only@127.0.0.1:5672/" {
		t.Fatal("only the isolated qualification broker may be used")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	main, err := amqp.Dial(address)
	if err != nil {
		t.Fatal(err)
	}
	defer main.Close()
	broker, err := dialDedicated(ctx, address, nil)
	if err != nil {
		t.Fatal(err)
	}
	started, release := make(chan struct{}), make(chan struct{})
	sub, err := ConsumePredeclared(ctx, broker.Connection, rpc.ConsumerConfig{Endpoint: "qualification.original.execute", Concurrency: 1, Timeout: time.Second, Handler: func(_ context.Context, d rpc.Delivery) error {
		if err := d.Ack(); err != nil {
			return err
		}
		close(started)
		<-release
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := rpcamqp.New(main).Publish(ctx, rpc.Request{Endpoint: "qualification.original.execute", Body: []byte(`{}`)}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal("local handler did not start")
	}
	result := make(chan error, 1)
	go func() { result <- broker.CloseWith(ctx, 150*time.Millisecond, sub.Close) }()
	select {
	case err := <-result:
		t.Fatalf("returned before handler joined: %v", err)
	case <-time.After(400 * time.Millisecond):
	}
	close(release)
	select {
	case err := <-result:
		if !errors.Is(err, errQualificationBrokerDeadline) {
			t.Fatalf("guard deadline not retained: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("handler join did not return")
	}
}

func TestDedicatedBrokerBlackholeJoinsWithoutClosingMain(t *testing.T) {
	address := os.Getenv("CAPACITY_QUALIFICATION_AMQP_URL")
	if address == "" {
		t.Skip("isolated qualification broker not configured")
	}
	var target string
	switch address {
	case "amqp://guest:guest@127.0.0.1:25680/":
		target = "127.0.0.1:25680"
	case "amqp://native:native-ci-only@127.0.0.1:5672/":
		target = "127.0.0.1:5672"
	default:
		t.Fatal("only the isolated qualification broker may be used")
	}
	main, err := amqp.Dial(address)
	if err != nil {
		t.Fatal(err)
	}
	defer main.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	var armed atomic.Bool
	release, proxyDone := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(proxyDone)
		client, err := listener.Accept()
		if err != nil {
			return
		}
		defer client.Close()
		server, err := net.Dial("tcp", target)
		if err != nil {
			return
		}
		defer server.Close()
		upstreamDone := make(chan struct{})
		go func() { defer close(upstreamDone); _, _ = io.Copy(server, client); _ = server.Close() }()
		buf := make([]byte, 4096)
		for {
			n, readErr := server.Read(buf)
			if n > 0 {
				if armed.Load() {
					<-release
				}
				if _, err := client.Write(buf[:n]); err != nil {
					break
				}
			}
			if readErr != nil {
				break
			}
		}
		_ = client.Close()
		_ = server.Close()
		<-upstreamDone
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	broker, err := dialDedicated(ctx, address, func(ctx context.Context, network, ignored string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, listener.Addr().String())
	})
	if err != nil {
		t.Fatal(err)
	}
	closeDescribe, err := StartDescribe(ctx, broker.Connection)
	if err != nil {
		t.Fatal(err)
	}
	replyBefore, err := rpcamqp.New(main).Request(ctx, rpc.Request{Endpoint: DescribeQueue, Body: []byte(`{"provider":"native-qemu","expected_version":"1.0.0"}`), Timeout: time.Second})
	if err != nil {
		t.Fatalf("main-to-dedicated RPC failed: %v", err)
	}
	checkDescribeReply(t, replyBefore)
	armed.Store(true)
	result := make(chan error, 1)
	go func() {
		result <- broker.CloseWith(ctx, 250*time.Millisecond, func() error {
			// Reproduce the driver's heartbeat attempting to extend read time.
			if err := broker.socket.SetReadDeadline(time.Now().Add(time.Hour)); err != nil {
				return err
			}
			return closeDescribe()
		})
	}()
	select {
	case err := <-result:
		if !errors.Is(err, errQualificationBrokerDeadline) {
			t.Fatalf("blackholed cancel must report guard deadline: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("blackholed close did not return")
	}
	close(release)
	select {
	case <-proxyDone:
	case <-time.After(3 * time.Second):
		t.Fatal("proxy did not join")
	}
	closeMainDescribe, err := StartDescribe(ctx, main)
	if err != nil {
		t.Fatal(err)
	}
	reply, err := rpcamqp.New(main).Request(ctx, rpc.Request{Endpoint: DescribeQueue, Body: []byte(`{"provider":"native-qemu","expected_version":"1.0.0"}`), Timeout: time.Second})
	if err != nil {
		t.Fatalf("main connection RPC failed: %v", err)
	}
	checkDescribeReply(t, reply)
	if err := closeMainDescribe(); err != nil {
		t.Fatal(err)
	}
}
