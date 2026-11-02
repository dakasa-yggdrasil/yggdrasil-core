package capacity

import (
	"strings"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func TestGuestNotifyDeclarativeQueueIdentity(t *testing.T) {
	for _, kind := range []string{"original", "dynamic_enrollment_queue", "foreign_namespace", "foreign_binding", "duplicate_slot", "unsorted", "unknown_provider", "zero_slot", "out_of_profile", "missing_definition_sha"} {
		t.Run(kind, func(t *testing.T) {
			topology := &model.CapacityGuestNotifyCanaryTopology{Schema: "notify_guest_canary_topology_v1", Namespace: "dakasa-production", Binding: "notify-aws-elastic", DefinitionsSHA256: strings.Repeat("a", 64), Queues: []model.CapacityGuestNotifyCanaryQueue{{Provider: "aws", Slot: 1, Name: "notify.guest-canary.dakasa-production.notify-aws-elastic.aws.s1.q"}, {Provider: "aws", Slot: 2, Name: "notify.guest-canary.dakasa-production.notify-aws-elastic.aws.s2.q"}}}
			switch kind {
			case "dynamic_enrollment_queue":
				topology.Queues[0].Name = "notify.guest-canary." + strings.Repeat("a", 64) + ".q"
			case "foreign_namespace":
				topology.Namespace = "other"
			case "foreign_binding":
				topology.Binding = "other"
			case "duplicate_slot":
				topology.Queues[1] = topology.Queues[0]
			case "unsorted":
				topology.Queues[0], topology.Queues[1] = topology.Queues[1], topology.Queues[0]
			case "unknown_provider":
				topology.Queues[0].Provider = "native-qemu"
			case "zero_slot":
				topology.Queues[0].Slot = 0
			case "out_of_profile":
				topology.Queues[1].Slot = 65
			case "missing_definition_sha":
				topology.DefinitionsSHA256 = ""
			}
			queue := GuestNotifyQueue(topology, "aws", 1)
			if (queue != "") != (kind == "original") {
				t.Fatalf("source queue identity %s: %q", kind, queue)
			}
			if kind == "original" && (GuestNotifyQueue(topology, "hetzner", 1) != "" || GuestNotifyQueue(topology, "aws", 3) != "") {
				t.Fatal("undeclared queue adopted")
			}
		})
	}
}
