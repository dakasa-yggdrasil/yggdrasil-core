package model

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"
)

type legacyNativePhysicalReadBinding struct {
	Profile      string                       `json:"profile"`
	Provider     string                       `json:"provider"`
	Region       string                       `json:"region"`
	Adapter      CapacityMarketAdapterBinding `json:"adapter"`
	BindingName  string                       `json:"binding_name"`
	SourceCommit string                       `json:"source_commit"`
	ScopeSHA256  string                       `json:"scope_sha256"`
	Capability   string                       `json:"capability"`
}

type legacyNativeBirth struct {
	Schema                   string                       `json:"schema"`
	AttemptID                uuid.UUID                    `json:"attempt_id"`
	PolicyID                 uuid.UUID                    `json:"policy_id"`
	Generation               int64                        `json:"generation"`
	FencingToken             int64                        `json:"fencing_token"`
	PoolUID                  string                       `json:"pool_uid"`
	PoolEpoch                int64                        `json:"pool_epoch"`
	ExecutionAdapter         CapacityMarketAdapterBinding `json:"execution_adapter"`
	ExecutionScopeSHA256     string                       `json:"execution_scope_sha256"`
	LaunchSHA256             string                       `json:"launch_sha256"`
	OriginalAcceptanceSHA256 string                       `json:"original_acceptance_sha256"`
	IndependentReadSHA256    string                       `json:"independent_read_sha256"`
	OriginalRequestID        string                       `json:"original_request_id"`
	IndependentRequestID     string                       `json:"independent_request_id"`
	Physical                 CapacityNativeWorkerPhysical `json:"physical"`
}

func TestNativeHCloudOptionalWitnessPreservesAWSWireAndEvidence(t *testing.T) {
	oldReader := legacyNativePhysicalReadBinding{Profile: "aws-ci", Provider: "aws", Region: "us-east-1", BindingName: "reader", SourceCommit: strings.Repeat("a", 40), ScopeSHA256: strings.Repeat("b", 64), Capability: "observe_native_worker"}
	before, _ := json.Marshal(oldReader)
	var reader CapacityNativeWorkerPhysicalReadBinding
	if json.Unmarshal(before, &reader) != nil {
		t.Fatal("legacy fixture")
	}
	after, _ := json.Marshal(reader)
	if !bytes.Equal(before, after) || bytes.Contains(after, []byte("hcloud_scope")) {
		t.Fatal("AWS read-binding byte ABI changed")
	}
	oldBirth := legacyNativeBirth{Schema: "native_worker_lifecycle_v1", AttemptID: uuid.New(), PolicyID: uuid.New(), Generation: 1, FencingToken: 2,
		PoolUID: uuid.NewString(), PoolEpoch: 1, OriginalRequestID: "actual-original", IndependentRequestID: "actual-read", Physical: CapacityNativeWorkerPhysical{AccountID: "153828470928"}}
	before, _ = json.Marshal(oldBirth)
	var birth CapacityNativeWorkerBirth
	if json.Unmarshal(before, &birth) != nil {
		t.Fatal("legacy birth fixture")
	}
	after, _ = json.Marshal(birth)
	if !bytes.Equal(before, after) || bytes.Contains(after, []byte("hcloud_witness")) {
		t.Fatal("AWS canonical birth/evidence bytes changed")
	}
	aws := CapacityNativeWorkerPhysicalObservation{Schema: "aws_native_worker_physical_observation_v1", Complete: true}
	before, _ = json.Marshal(aws)
	aws.HCloud = &CapacityNativeWorkerHCloudPhysicalObservation{Schema: "internal-only"}
	after, _ = json.Marshal(aws)
	if !bytes.Equal(before, after) || bytes.Contains(after, []byte("internal-only")) {
		t.Fatal("internal carrier altered public AWS evidence")
	}
}

func TestNativeHCloudObservationWireRetainsActualEmptyAccountAndOptionalHeaders(t *testing.T) {
	o := CapacityNativeWorkerHCloudPhysicalObservation{Schema: "hcloud_native_worker_physical_observation_v1", Physical: CapacityNativeWorkerHCloudPhysicalFacts{
		AccountID: "", Region: "hel1", Zone: "hel1", NetworkZone: "eu-central"}, ProjectScope: CapacityNativeWorkerHCloudProjectScope{
		DeclaredProjectID: "reviewed-logical-project", ProofKind: "reviewed_token_and_network_anchor_v1"},
		Reads: []CapacityNativeWorkerHCloudObservedRPC{{Operation: "GET /servers/{id}", HTTPStatus: 200, RequestID: "", RequestIDObserved: false}}}
	wire, err := json.Marshal(o)
	if err != nil {
		t.Fatal(err)
	}
	for _, literal := range []string{`"account_id":""`, `"region":"hel1"`, `"network_zone":"eu-central"`, `"request_id":""`, `"request_id_observed":false`} {
		if !bytes.Contains(wire, []byte(literal)) {
			t.Fatal("truthful HCloud SDK wire fact lost", literal)
		}
	}
	var restored CapacityNativeWorkerHCloudPhysicalObservation
	if json.Unmarshal(wire, &restored) != nil {
		t.Fatal("typed read decoder")
	}
	again, _ := json.Marshal(restored)
	if !bytes.Equal(wire, again) {
		t.Fatal("typed Core mirror changes the SDK safe-evidence field order")
	}
}
