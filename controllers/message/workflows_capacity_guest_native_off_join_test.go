package message

import (
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"testing"
	"time"
)

func testOriginalAWSNativeOffProducerTimestampJoin(t *testing.T) {
	first := time.Date(2026, 10, 25, 12, 0, 0, 1, time.UTC)
	second := first.Add(20 * time.Millisecond)
	for _, name := range []string{"actual_distinct_GET_timestamps", "foreign_request", "wrong_schema", "running_lifecycle", "running_server", "missing_server", "server_timestamp_alias", "missing_lifecycle_time"} {
		t.Run(name, func(t *testing.T) {
			plan := model.CapacityVMFleetPlan{ObservedAt: second.Format(time.RFC3339Nano), Server: &model.CapacityVMServerObservation{Status: "stopped", ObservedAt: first.Format(time.RFC3339Nano)}}
			lifecycle := model.CapacityAWSInstanceLifecycle{Schema: "aws_original_request_and_instance_status_v1", RequestID: "actual-create-action", EC2State: "stopped", ObservedAt: second}
			switch name {
			case "foreign_request":
				lifecycle.RequestID = "other"
			case "wrong_schema":
				lifecycle.Schema = "other"
			case "running_lifecycle":
				lifecycle.EC2State = "running"
			case "running_server":
				plan.Server.Status = "running"
			case "missing_server":
				plan.Server = nil
			case "server_timestamp_alias":
				plan.ObservedAt = first.Format(time.RFC3339Nano)
			case "missing_lifecycle_time":
				lifecycle.ObservedAt = time.Time{}
			}
			if originalAWSNativeOffLifecycleJoin(plan, lifecycle, "actual-create-action") != (name == "actual_distinct_GET_timestamps") {
				t.Fatal("producer timestamps projected into false equality")
			}
		})
	}
}
