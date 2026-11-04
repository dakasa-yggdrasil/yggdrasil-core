//go:build !nativequalification

package message

import (
	"bytes"
	"encoding/json"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
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

	// Exercise the actually compiled current publication, not only the legacy
	// synthetic fourteen-field shape above. No fixture pin can enable this path.
	t.Run("compiled_current_publication", func(t *testing.T) {
		current := repository.EnrolledFailedAWSObserverSource()
		if !retirementReadonlySourceReady() {
			t.Fatal("genuine current retirement observer must be bound before CI qualification")
		}
		for _, fault := range []string{"valid", "missing_version", "wrong_version", "missing_retirement_operation", "wrong_retirement_operation", "missing_retirement_request_schema", "wrong_retirement_request_schema"} {
			t.Run(fault, func(t *testing.T) {
				raw, _ := json.Marshal(expectedEnrolledFailedDescription(current))
				var fields map[string]any
				if json.Unmarshal(raw, &fields) != nil || len(fields) != 16 || fields["version"] != repository.RetirementReadonlyAWSObserverVersion() || fields["retirement_operation"] != retirementReadonlyOperation || fields["retirement_request_schema"] != repository.GuestRetirementReadonlyRequestSchema {
					t.Fatal("compiled current Describe is not the closed extended publication")
				}
				if strings.HasPrefix(fault, "missing_") {
					delete(fields, strings.TrimPrefix(fault, "missing_"))
				}
				if strings.HasPrefix(fault, "wrong_") {
					fields[strings.TrimPrefix(fault, "wrong_")] = "foreign"
				}
				raw, _ = json.Marshal(fields)
				if (validateEnrolledFailedDescription(raw, current) == nil) != (fault == "valid") {
					t.Fatal("current Describe version/extension drift admitted", fault)
				}
			})
		}
	})
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

func TestGuestRetirementForwardReadonlyEnvelopeHasNoCallbackAuthority(t *testing.T) {
	raw, err := os.ReadFile("../../repository/testdata/capacity_aws_denied_historical_1654_type_spec.json")
	if err != nil {
		t.Fatal(err)
	}
	var spec model.IntegrationTypeManifestSpec
	if json.Unmarshal(raw, &spec) != nil {
		t.Fatal("historical fixture")
	}
	spec.Adapter.Version = "1.65.5"
	credentials := map[string]any{"grant_bearer": "CALLBACK_MUST_NOT_ESCAPE", "access_key_id": "declared-source-only", "secret_access_key": "declared-source-only"}
	o := capacityResolvedObservationAdapter{typeSpec: spec, instanceSpec: model.IntegrationInstanceManifestSpec{Credentials: credentials, Config: map[string]any{"original_capacity": map[string]any{"adapter_source_commit": enrolledFailedAWSCreator}}}}
	configBefore, _ := json.Marshal(o.instanceSpec.Config)
	receipt := json.RawMessage(`{"grant":{"request_sha256":"original-immutable","generation":9007199254740993},"transport_completed":true}`)
	fixed := map[string]any{"schema": repository.GuestRetirementReadonlyRequestSchema, "profile": "declared", "slot": 3, "read_id": "declared-read", "read_sha256": strings.Repeat("a", 64), "original_adapter_source_commit": enrolledFailedAWSCreator, "original_receipt": receipt, "original_receipt_sha256": capacity.BusinessCreationSHA256(receipt)}
	envelope, err := retirementReadonlyEnvelope(o, fixed)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := json.Marshal(envelope)
	if err != nil || bytes.Contains(wire, []byte("grant_bearer")) || bytes.Contains(wire, []byte("CALLBACK_MUST_NOT_ESCAPE")) || envelope["operation"] != retirementReadonlyOperation || envelope["capability"] != retirementReadonlyOperation {
		t.Fatal("callback authority or wrong operation escaped")
	}
	var returned struct {
		Input struct {
			Receipt json.RawMessage `json:"original_receipt"`
			SHA     string          `json:"original_receipt_sha256"`
		} `json:"input"`
	}
	if json.Unmarshal(wire, &returned) != nil || !bytes.Equal(receipt, returned.Input.Receipt) || returned.Input.SHA != capacity.BusinessCreationSHA256(returned.Input.Receipt) {
		t.Fatal("protected receipt bytes/large integer changed")
	}
	configAfter, _ := json.Marshal(o.instanceSpec.Config)
	if !bytes.Equal(configBefore, configAfter) || o.instanceSpec.Credentials["grant_bearer"] != "CALLBACK_MUST_NOT_ESCAPE" {
		t.Fatal("historical supplier/config mutated")
	}
	if len(envelope["input"].(map[string]any)) != 8 || envelope["auth"] != nil || envelope["metadata"] != nil {
		t.Fatal("extra authority/input")
	}
}
