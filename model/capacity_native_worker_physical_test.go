package model

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// Immutable external AWS58 public DTO declaration, before AWS60's optional
// Internet transport field. This test protects byte and safe-evidence ABI.
type legacyAWS58PhysicalObservation struct {
	Schema                  string                                 `json:"schema"`
	SourceCommit            string                                 `json:"source_commit"`
	Adapter                 CapacityMarketAdapterBinding           `json:"adapter"`
	BindingName             string                                 `json:"binding_name"`
	BindingScopeSHA256      string                                 `json:"binding_scope_sha256"`
	Requested               CapacityNativeWorkerObservationRequest `json:"requested"`
	StartedAt               time.Time                              `json:"started_at"`
	ObservedAt              time.Time                              `json:"observed_at"`
	Complete                bool                                   `json:"complete"`
	ActualTags              CapacityNativeWorkerObservedTags       `json:"actual_tags"`
	ActualClientToken       string                                 `json:"actual_client_token"`
	InstanceState           string                                 `json:"instance_state"`
	Physical                CapacityNativeWorkerPhysicalFacts      `json:"physical"`
	RootVolume              CapacityNativeWorkerObservedVolume     `json:"root_volume"`
	PrimaryInterface        CapacityNativeWorkerObservedInterface  `json:"primary_interface"`
	Reads                   []CapacityNativeWorkerObservedRPC      `json:"reads"`
	EvidenceSHA256          string                                 `json:"evidence_sha256"`
	MutationAuthorized      bool                                   `json:"mutation_authorized"`
	NodeReadyQualified      bool                                   `json:"node_ready_qualified"`
	UsefulCapacityQualified bool                                   `json:"useful_capacity_qualified"`
	AbsenceProven           bool                                   `json:"absence_proven"`
}

func TestNativePhysicalAWS58WireAndEvidenceStayByteExactWithAbsentEndpoint(t *testing.T) {
	old := legacyAWS58PhysicalObservation{Schema: "aws_native_worker_physical_observation_v1", SourceCommit: strings.Repeat("a", 40), BindingName: "reader", BindingScopeSHA256: strings.Repeat("b", 64), Complete: true, Physical: CapacityNativeWorkerPhysicalFacts{ResourceID: "i-0123456789abcdef0", AccountID: "153828470928"}, Reads: []CapacityNativeWorkerObservedRPC{}}
	before, e := json.Marshal(old)
	if e != nil {
		t.Fatal(e)
	}
	var current CapacityNativeWorkerPhysicalObservation
	if e = json.Unmarshal(before, &current); e != nil {
		t.Fatal(e)
	}
	after, e := json.Marshal(current)
	if e != nil || !bytes.Equal(before, after) || sha256.Sum256(before) != sha256.Sum256(after) || bytes.Contains(after, []byte("transport_endpoint_ipv4")) {
		t.Fatal("optional empty endpoint changed the exact AWS58 wire or safe evidence")
	}
	current.TransportEndpointIPv4 = "203.0.113.9"
	paired, e := json.Marshal(current)
	if e != nil {
		t.Fatal(e)
	}
	physical, endpoint, root := bytes.Index(paired, []byte(`"physical":`)), bytes.Index(paired, []byte(`"transport_endpoint_ipv4":`)), bytes.Index(paired, []byte(`"root_volume":`))
	if physical < 0 || endpoint <= physical || root <= endpoint || sha256.Sum256(paired) == sha256.Sum256(before) {
		t.Fatal("AWS60 paired field lost its exact declared position or evidence coverage")
	}
}
