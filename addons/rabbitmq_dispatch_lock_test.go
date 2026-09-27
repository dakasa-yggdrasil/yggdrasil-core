package addons

import (
	"errors"
	"testing"

	amqp "github.com/rabbitmq/amqp091-go"
)

type recordingPassiveQueueDeclarer struct {
	names []string
	errAt string
}

func (d *recordingPassiveQueueDeclarer) QueueDeclarePassive(
	name string,
	durable bool,
	autoDelete bool,
	exclusive bool,
	noWait bool,
	args amqp.Table,
) (amqp.Queue, error) {
	if !durable || autoDelete || exclusive || noWait || args != nil {
		return amqp.Queue{}, errors.New("unexpected passive queue contract")
	}
	d.names = append(d.names, name)
	if name == d.errAt {
		return amqp.Queue{}, errors.New("missing queue")
	}
	return amqp.Queue{Name: name}, nil
}

func TestRequireDispatchLockQueuesUsesPassiveDurableDeclarations(t *testing.T) {
	declarer := &recordingPassiveQueueDeclarer{}
	want := []string{"workflow.run", "manifest.create"}
	if err := requireDispatchLockQueuesOnChannel(declarer, want); err != nil {
		t.Fatal(err)
	}
	if len(declarer.names) != len(want) {
		t.Fatalf("checked queues = %v, want %v", declarer.names, want)
	}
	for index := range want {
		if declarer.names[index] != want[index] {
			t.Fatalf("checked queues = %v, want %v", declarer.names, want)
		}
	}
}

func TestRequireDispatchLockQueuesFailsWhenAQueueIsMissing(t *testing.T) {
	declarer := &recordingPassiveQueueDeclarer{errAt: "manifest.create"}
	if err := requireDispatchLockQueuesOnChannel(declarer, []string{"workflow.run", "manifest.create"}); err == nil {
		t.Fatal("missing paused queue did not fail verification")
	}
}
