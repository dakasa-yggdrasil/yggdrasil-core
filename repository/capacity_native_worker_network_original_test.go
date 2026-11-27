package repository

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

func TestNativeNetworkOriginalCallerClosureIsSeparateFromCaptureAndSuccess(t *testing.T) {
	now := time.Now().UTC()
	start := now.Add(-time.Second)
	returned := now.Add(-time.Millisecond)
	g := model.CapacityNativeWorkerNetworkGrant{PermitID: uuid.NewString(), AttemptID: uuid.NewString(), Action: "install"}
	body := map[string]any{"schema": "native_worker_network_original_batch_v1", "permit_id": g.PermitID, "attempt_id": g.AttemptID, "action": g.Action, "started_at": start, "returned_at": returned, "execution_complete": false, "steps": []any{map[string]any{"step": "source-owned-failed-step", "started_at": start, "returned_at": returned, "process_started": true, "wait_returned": true, "exit_code": 1, "capture_complete": false, "stdout": []byte("bounded private prefix"), "stderr": []byte("private close failure")}}}
	raw, _ := json.Marshal(body)
	v := model.CapacityNativeWorkerNetworkOriginalReturn{OriginalReturn: raw, CaptureComplete: false, ErrorClass: "HOST_BATCH_UNCERTAIN"}
	if !nativeNetworkOriginalCallerClosed(g, v, now) {
		t.Fatal("a real failed but returned process was confused with an active writer")
	}
	for _, fault := range []string{"stillRunning", "missingStartFact", "missingWaitFact", "nullStartFact", "duplicateStep", "impossibleWait", "zeroStart", "foreignPermit", "foreignAttempt", "otherAction", "futureReturn", "backwardReturn", "missingSteps", "oversizeSteps", "unknownTopLevel", "duplicate", "alias", "truncated"} {
		t.Run(fault, func(t *testing.T) {
			var bad map[string]any
			if e := json.Unmarshal(raw, &bad); e != nil {
				t.Fatal(e)
			}
			switch fault {
			case "stillRunning":
				bad["steps"].([]any)[0].(map[string]any)["wait_returned"] = false
			case "missingStartFact":
				delete(bad["steps"].([]any)[0].(map[string]any), "process_started")
			case "missingWaitFact":
				delete(bad["steps"].([]any)[0].(map[string]any), "wait_returned")
			case "nullStartFact":
				bad["steps"].([]any)[0].(map[string]any)["process_started"] = nil
			case "duplicateStep":
				bad["steps"] = append(bad["steps"].([]any), bad["steps"].([]any)[0])
			case "impossibleWait":
				bad["steps"].([]any)[0].(map[string]any)["process_started"] = false
			case "zeroStart":
				bad["steps"].([]any)[0].(map[string]any)["started_at"] = time.Time{}
			case "foreignPermit":
				bad["permit_id"] = uuid.NewString()
			case "foreignAttempt":
				bad["attempt_id"] = uuid.NewString()
			case "otherAction":
				bad["action"] = "remove"
			case "futureReturn":
				bad["returned_at"] = now.Add(time.Second)
			case "backwardReturn":
				bad["returned_at"] = start.Add(-time.Second)
			case "missingSteps":
				delete(bad, "steps")
			case "oversizeSteps":
				bad["steps"] = make([]any, 17)
			case "unknownTopLevel":
				bad["original_caller_closed"] = true
			}
			wire, _ := json.Marshal(bad)
			switch fault {
			case "duplicate":
				wire = []byte(strings.Replace(string(wire), `"action":`, `"action":"remove","action":`, 1))
			case "alias":
				wire = []byte(strings.Replace(string(wire), `"wait_returned":`, `"Wait_Returned":`, 1))
			case "truncated":
				wire = wire[:len(wire)/2]
			}
			v.OriginalReturn = wire
			if nativeNetworkOriginalCallerClosed(g, v, now) {
				t.Fatal("unproved or substituted writer closure accepted", fault)
			}
		})
	}
}
