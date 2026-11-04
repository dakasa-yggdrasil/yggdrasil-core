package message

import (
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func originalAWSNativeOffLifecycleJoin(plan model.CapacityVMFleetPlan, lifecycle model.CapacityAWSInstanceLifecycle, actionID string) bool {
	return actionID != "" && lifecycle.RequestID == actionID && lifecycle.Schema == "aws_original_request_and_instance_status_v1" && lifecycle.EC2State == "stopped" && plan.Server != nil && plan.Server.Status == "stopped" && !lifecycle.ObservedAt.IsZero() && lifecycle.ObservedAt.UTC().Format(time.RFC3339Nano) == plan.ObservedAt
}
