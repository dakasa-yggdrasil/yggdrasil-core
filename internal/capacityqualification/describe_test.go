//go:build nativequalification

package capacityqualification

import (
	"context"
	"encoding/json"
	"os"
	"reflect"
	"testing"
	"time"

	manifestengine "github.com/dakasa-yggdrasil/yggdrasil-core/manifest"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-sdk-go/rpc"
	rpcamqp "github.com/dakasa-yggdrasil/yggdrasil-sdk-go/rpc/amqp"
	amqp "github.com/rabbitmq/amqp091-go"
)

func TestStringHeadersMatchSDK(t *testing.T) {
	got := stringHeaders(amqp.Table{"text": "value", "bytes": []byte("binary"), "number": int32(17), "bool": true, "invalid": make(chan int)})
	want := map[string]string{"text": "value", "bytes": "binary", "number": "17", "bool": "true"}
	if !reflect.DeepEqual(got, want) || stringHeaders(nil) != nil {
		t.Fatalf("unexpected headers: %#v", got)
	}
}

func TestDescribeIsAValidIntegrationType(t *testing.T) {
	response, err := NativeDescribe()
	if err != nil {
		t.Fatal(err)
	}
	wire, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	var spec model.IntegrationTypeManifestSpec
	if err := json.Unmarshal(wire, &spec); err != nil {
		t.Fatal(err)
	}
	if err := manifestengine.ValidateIntegrationTypeSpec(spec); err != nil {
		t.Fatal(err)
	}
}

func TestDescribeOverPredeclaredBroker(t *testing.T) {
	address := os.Getenv("CAPACITY_QUALIFICATION_AMQP_URL")
	if address == "" {
		t.Skip("isolated qualification broker not configured")
	}
	if address != "amqp://guest:guest@127.0.0.1:25680/" && address != "amqp://native:native-ci-only@127.0.0.1:5672/" {
		t.Fatal("only the isolated qualification broker may be used")
	}
	broker, err := amqp.Dial(address)
	if err != nil {
		t.Fatal(err)
	}
	defer broker.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	closeDescribe, err := StartDescribe(ctx, broker)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := closeDescribe(); err != nil {
			t.Error(err)
		}
	}()
	client := rpcamqp.New(broker)
	for _, tc := range []struct {
		body string
		ok   bool
	}{
		{`{"provider":"native-qemu","expected_version":"1.0.0"}`, true},
		{`{"provider":"native-qemu"}`, true},
		{`{"provider":"other","expected_version":"1.0.0"}`, false},
		{`{"provider":"native-qemu","expected_version":"2.0.0"}`, false},
		{`{"provider":"native-qemu","provider":"other"}`, false},
	} {
		reply, err := client.Request(ctx, rpc.Request{Endpoint: DescribeQueue, Body: []byte(tc.body), Timeout: 2 * time.Second})
		if err != nil {
			t.Fatal(err)
		}
		var result struct {
			OK   bool                          `json:"ok"`
			Data model.AdapterDescribeResponse `json:"data"`
		}
		if err := json.Unmarshal(reply.Body, &result); err != nil {
			t.Fatal(err)
		}
		if result.OK != tc.ok {
			t.Fatalf("request %s returned %s", tc.body, reply.Body)
		}
		if tc.ok {
			expected, err := NativeDescribe()
			if err != nil {
				t.Fatal(err)
			}
			got, _ := json.Marshal(result.Data)
			want, _ := json.Marshal(expected)
			if string(got) != string(want) {
				t.Fatalf("describe mismatch: %s", got)
			}
		}
	}
	// Verify Execute consumes the same predeclared quorum queue without an SDK redeclaration.
	sub, err := ConsumePredeclared(ctx, broker, rpc.ConsumerConfig{Endpoint: "qualification.original.execute", Concurrency: 1, Timeout: time.Second, Handler: func(ctx context.Context, d rpc.Delivery) error {
		if d.Headers["qualification"] != "present" {
			t.Error("request headers were not propagated")
		}
		if err := d.Reply(ctx, d.Body, "application/json"); err != nil {
			return err
		}
		return d.Ack()
	}})
	if err != nil {
		t.Fatal(err)
	}
	reply, err := client.Request(ctx, rpc.Request{Endpoint: "qualification.original.execute", Body: []byte(`{"probe":true}`), Headers: map[string]string{"qualification": "present"}, Timeout: 2 * time.Second})
	if err != nil || string(reply.Body) != `{"probe":true}` {
		t.Fatalf("execute reply %s: %v", reply.Body, err)
	}
	if err := sub.Close(); err != nil {
		t.Fatal(err)
	}
}
