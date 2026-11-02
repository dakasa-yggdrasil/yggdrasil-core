//go:build !nativequalification

package message

import (
	"encoding/json"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestEnrolledFailedReadonlyDescribeClosedIndependentIdentity(t *testing.T) {
	source := strings.Repeat("d", 40)
	for _, alias := range []string{"", "not-a-source", enrolledFailedAWSCreator, nativeDeniedReadonlySource, originalCreateDispositionAWSObserverSource} {
		raw, _ := json.Marshal(expectedEnrolledFailedDescription(alias))
		if enrolledFailedReadonlySourceReady(alias) || validateEnrolledFailedDescription(raw, alias) == nil {
			t.Fatal("normal/denied/unpublished Source alias admitted")
		}
	}

	for _, name := range []string{"valid", "missing_false", "normal_provider", "wrong_creator", "wrong_operation", "extra", "source_mismatch"} {
		t.Run(name, func(t *testing.T) {
			raw, _ := json.Marshal(expectedEnrolledFailedDescription(source))
			var v map[string]any
			_ = json.Unmarshal(raw, &v)
			switch name {
			case "missing_false":
				delete(v, "AMQP_registered")
			case "normal_provider":
				v["provider"] = "aws"
			case "wrong_creator":
				v["original_adapter_source_commit"] = originalCreateDispositionAWSObserverSource
			case "wrong_operation":
				v["operation"] = originalCreateDispositionOperation
			case "extra":
				v["permission_override"] = false
			case "source_mismatch":
				v["source_commit"] = strings.Repeat("e", 40)
			}
			raw, _ = json.Marshal(v)
			if (validateEnrolledFailedDescription(raw, source) == nil) != (name == "valid") {
				t.Fatal("dedicated Describe seam", name)
			}
		})
	}
}
func TestEnrolledFailedReadonlyExact1655ProtocolProjection(t *testing.T) {
	raw, e := os.ReadFile("../../repository/testdata/capacity_aws_denied_historical_1654_type_spec.json")
	if e != nil {
		t.Fatal(e)
	}
	var full map[string]any
	if json.Unmarshal(raw, &full) != nil {
		t.Fatal("historical full public fixture")
	}
	full["adapter"].(map[string]any)["version"] = "1.65.5"
	for _, item := range full["action_catalog"].([]any) {
		a := item.(map[string]any)
		if a["name"] == originalCreateDispositionOperation {
			a["description"] = nativeDeniedObserverDescription
		}
	}
	raw, _ = json.Marshal(full)
	var spec model.IntegrationTypeManifestSpec
	if json.Unmarshal(raw, &spec) != nil {
		t.Fatal("source-derived1655 fixture")
	}
	o := capacityResolvedObservationAdapter{typeSpec: spec, instanceSpec: model.IntegrationInstanceManifestSpec{Config: map[string]any{"original_capacity": map[string]any{"adapter_source_commit": enrolledFailedAWSCreator}}, Credentials: map[string]any{"DECLARED": "not-a-credential"}}}
	input := map[string]any{"schema": "aws_original_enrolled_failed_create_absence_read_request_v1", "original_adapter_source_commit": enrolledFailedAWSCreator, "original_auxiliary_inventory_complete": false}
	wire, e := enrolledFailedReadonlyEnvelope(o, input)
	if e != nil {
		t.Fatal(e)
	}
	if wire["operation"] != enrolledFailedReadonlyOperation || wire["capability"] != enrolledFailedReadonlyOperation || !reflect.DeepEqual(wire["input"], input) {
		t.Fatal("typed operation/input changed")
	}
	projected := wire["integration"].(map[string]any)["type_spec"].(map[string]any)
	if projected["adapter"].(map[string]any)["version"] != "1.65.5" {
		t.Fatal("historical creator relabelled")
	}
	if _, ok := projected["credential_policy"]; ok {
		t.Fatal("Core-only field passed strict AWS DTO")
	}
	if _, ok := projected["guardian_support"]; ok {
		t.Fatal("Core-only field passed strict AWS DTO")
	}
	input["schema"] = "changed"
	if wire["input"].(map[string]any)["schema"] == input["schema"] {
		t.Fatal("request aliases mutable input")
	}
}
