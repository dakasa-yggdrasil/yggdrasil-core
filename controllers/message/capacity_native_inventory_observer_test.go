//go:build !nativequalification

package message

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/dakasa-yggdrasil/yggdrasil-sdk-go/rpc"
	"github.com/google/uuid"
)

func inventoryReadonlyDeclaredSupplier(t *testing.T) capacityResolvedObservationAdapter {
	t.Helper()
	raw, err := os.ReadFile("../../repository/testdata/capacity_aws_denied_historical_1654_type_spec.json")
	if err != nil {
		t.Fatal(err)
	}
	var spec model.IntegrationTypeManifestSpec
	if json.Unmarshal(raw, &spec) != nil {
		t.Fatal("declared historical catalog")
	}
	spec.Adapter.Version = "1.65.5"
	o := capacityResolvedObservationAdapter{typeSpec: spec, instanceSpec: model.IntegrationInstanceManifestSpec{
		Credentials: map[string]any{"access_key_id": "DECLARED_PRIVATE_AWS", "secret_access_key": "DECLARED_PRIVATE_SECRET", "grant_bearer": "CALLBACK_MUST_NOT_ESCAPE"},
		Config:      map[string]any{"original_capacity": map[string]any{"mode": "original_aws_ec2_capacity_v1", "adapter_source_commit": enrolledFailedAWSCreator}},
	}}
	o.instance.ID, o.typ.ID = uuid.New(), uuid.New()
	o.instance.Checksum, o.typ.Checksum = strings.Repeat("a", 64), strings.Repeat("b", 64)
	return o
}

// Only the network destination is substituted in a declared HTTP test. The
// production fixed URL, complete SDK framing and closed decoder still execute.
func installInventoryReadonlyHTTP(t *testing.T, respond func(string, []byte) any) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Host != "integration-aws-inventory-readonly.dakasa.svc.cluster.local:8081" || r.Header.Get("Authorization") != "" {
			t.Error("fixed inventory-only request changed")
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		value := respond(r.URL.Path, raw)
		inner, err := json.Marshal(struct {
			OK   bool `json:"ok"`
			Data any  `json:"data"`
		}{true, value})
		if err != nil {
			t.Error(err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err = json.NewEncoder(w).Encode(rpc.Envelope{ContentType: "application/json", Body: inner}); err != nil {
			t.Error(err)
		}
	}))
	transport := &http.Transport{DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}}
	previous := http.DefaultTransport
	http.DefaultTransport = transport
	t.Cleanup(func() { http.DefaultTransport = previous; transport.CloseIdleConnections(); server.Close() })
}

func inventoryReadonlyDeclaredReturn(in inventoryReadonlyRequest, source string, inventory model.CapacityVMFleetInventory) inventoryReadonlyReturn {
	return inventoryReadonlyReturn{Schema: inventoryReadonlyReturnSchema, ObserverSourceCommit: source, ProfileProducerSourceCommit: enrolledFailedAWSCreator, ReadID: in.ReadID, ReadSHA256: in.ReadSHA256, OriginalDeadlineCore: in.OriginalDeadlineCore, Inventory: inventory}
}

func inventoryReadonlyDecodeTestRequest(t *testing.T, raw []byte) inventoryReadonlyRequest {
	t.Helper()
	var envelope struct {
		Operation  string                   `json:"operation"`
		Capability string                   `json:"capability"`
		Input      inventoryReadonlyRequest `json:"input"`
	}
	if json.Unmarshal(raw, &envelope) != nil || envelope.Operation != inventoryReadonlyOperation || envelope.Capability != inventoryReadonlyOperation || envelope.Input.Schema != inventoryReadonlyRequestSchema {
		t.Error("closed inventory operation changed")
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || len(fields) != 4 || fields["auth"] != nil || fields["metadata"] != nil || bytes.Contains(raw, []byte("CALLBACK_MUST_NOT_ESCAPE")) {
		t.Error("callback/top-level authority escaped")
	}
	var inputFields map[string]any
	if json.Unmarshal(fields["input"], &inputFields) != nil || len(inputFields) != 5 {
		t.Error("inventory selector has extra authority")
	}
	deadline, err := time.Parse(time.RFC3339Nano, envelope.Input.OriginalDeadlineCore)
	id, idErr := uuid.Parse(envelope.Input.ReadID)
	if err != nil || deadline.UTC().Format(time.RFC3339Nano) != envelope.Input.OriginalDeadlineCore || !deadline.After(time.Now()) || time.Until(deadline) > 5*time.Second || idErr != nil || id == uuid.Nil || id.String() != envelope.Input.ReadID || !capacity.ValidDigest(envelope.Input.ReadSHA256) {
		t.Error("original deadline or unique request join missing")
	}
	return envelope.Input
}

func TestInventoryReadonlyDescribeRequiresIndependentPublishedSource(t *testing.T) {
	for _, source := range []string{"", "unpublished", enrolledFailedAWSCreator, nativeDeniedReadonlySource, repository.RetirementReadonlyAWSObserverSource(), repository.EnrolledFailedAWSObserverSource()} {
		raw, _ := json.Marshal(expectedInventoryReadonlyDescription(source))
		if inventoryReadonlySourceReady(source) || validateInventoryReadonlyDescription(raw, source) == nil {
			t.Fatal("unbound or another role's source became inventory authority")
		}
	}
	// CI requires the actual committed compiler pin. Immutable publication and
	// deployment acceptance remain independent release requirements.
	source := inventoryReadonlyAWSObserverSource
	if !inventoryReadonlySourceReady(source) {
		t.Fatal("independently published inventory source must be bound before CI qualification")
	}
	for _, fault := range []string{"exact", "missing_false", "missing_zero", "extra", "normal_provider", "normal_operations", "foreign_source", "foreign_producer", "foreign_version", "foreign_route", "foreign_schema", "duplicate_field", "trailing"} {
		t.Run(fault, func(t *testing.T) {
			raw, _ := json.Marshal(expectedInventoryReadonlyDescription(source))
			var fields map[string]any
			_ = json.Unmarshal(raw, &fields)
			if len(fields) != 15 {
				t.Fatal("exact fifteen-field inventory Describe required")
			}
			switch fault {
			case "missing_false":
				delete(fields, "normal_adapter_operations")
			case "missing_zero":
				delete(fields, "native_mutations")
			case "extra":
				fields["mutations_enabled"] = false
			case "normal_provider":
				fields["provider"] = "aws"
			case "normal_operations":
				fields["normal_adapter_operations"] = true
			case "foreign_source":
				fields["source_commit"] = enrolledFailedAWSCreator
			case "foreign_producer":
				fields["profile_producer_source_commit"] = source
			case "foreign_version":
				fields["profile_producer_version"] = "1.65.8"
			case "foreign_route":
				fields["execute_endpoint"] = "/rpc/mutate"
			case "foreign_schema":
				fields["return_schema"] = inventoryReadonlyRequestSchema
			}
			raw, _ = json.Marshal(fields)
			if fault == "duplicate_field" {
				raw = append([]byte(`{"native_mutations":0,`), raw[1:]...)
			}
			if fault == "trailing" {
				raw = append(raw, []byte(`{}`)...)
			}
			if (validateInventoryReadonlyDescription(raw, source) == nil) != (fault == "exact") {
				t.Fatal("foreign/omitted Describe fact admitted", fault)
			}
		})
	}
}

func TestInventoryReadonlyEnvelopePreservesProducerAndRemovesCallback(t *testing.T) {
	o := inventoryReadonlyDeclaredSupplier(t)
	before, _ := json.Marshal(o.instanceSpec)
	in := inventoryReadonlyRequest{Schema: inventoryReadonlyRequestSchema, Profile: "declared", ReadID: uuid.NewString(), ReadSHA256: strings.Repeat("a", 64), OriginalDeadlineCore: time.Now().UTC().Add(time.Second).Format(time.RFC3339Nano)}
	envelope, err := inventoryReadonlyEnvelope(o, in)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if got := inventoryReadonlyDecodeTestRequest(t, raw); got != in {
		t.Fatal("typed selector changed")
	}
	after, _ := json.Marshal(o.instanceSpec)
	if !bytes.Equal(before, after) || o.instanceSpec.Credentials["grant_bearer"] != "CALLBACK_MUST_NOT_ESCAPE" {
		t.Fatal("historical credential map/config mutated")
	}
	projected := envelope["integration"].(map[string]any)
	instance := projected["instance_spec"].(map[string]any)
	credentials := instance["credentials"].(map[string]any)
	if len(credentials) != 2 || credentials["grant_bearer"] != nil || credentials["access_key_id"] != "DECLARED_PRIVATE_AWS" {
		t.Fatal("callback authority remained or AWS credentials were changed")
	}
	config := instance["config"].(map[string]any)["original_capacity"].(map[string]any)
	typeSpec := projected["type_spec"].(map[string]any)
	if config["adapter_source_commit"] != enrolledFailedAWSCreator || typeSpec["adapter"].(map[string]any)["version"] != "1.65.5" || typeSpec["credential_policy"] != nil || typeSpec["guardian_support"] != nil {
		t.Fatal("immutable producer profile/type relabelled or Core-only fields escaped")
	}
	for _, supplier := range []*originalProductionGuestSupplier{nil, {provider: "hetzner"}, {provider: "aws", binding: model.CapacityMutationBinding{OriginalProviderSourceCommit: strings.Repeat("d", 40)}}} {
		if _, err := callForwardInventoryReadonly(context.Background(), supplier); err == nil {
			t.Fatal("non-c34 producer routed to sibling")
		}
	}
}

func TestInventoryReadonlyHTTPSourceDeadlineAndClosedReturn(t *testing.T) {
	source := strings.Repeat("d", 40) // DECLARED transport operand, not a publication.
	for _, fault := range []string{"exact", "diagnostic_metadata", "foreign_observer", "foreign_producer", "foreign_read", "foreign_hash", "renewed_deadline", "unknown_output", "missing_inventory", "missing_false", "unknown_reply", "post_guard", "post_describe", "cancelled", "no_deadline", "renewed_budget"} {
		t.Run(fault, func(t *testing.T) {
			o := inventoryReadonlyDeclaredSupplier(t)
			inventory := model.CapacityVMFleetInventory{ProfileName: "declared", Members: []model.CapacityVMFleetInventoryMember{}, MissingSlots: []int{}, Complete: true, ObservationStartedAt: time.Now().UTC().Format(time.RFC3339Nano), ObservedAt: time.Now().UTC().Format(time.RFC3339Nano)}
			var describes, executes atomic.Int32
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if fault == "cancelled" {
				cancel()
			}
			if fault == "no_deadline" {
				ctx = context.Background()
			}
			if fault == "renewed_budget" {
				ctx, cancel = context.WithTimeout(context.Background(), 6*time.Second)
				defer cancel()
			}
			deadline, _ := ctx.Deadline()
			installInventoryReadonlyHTTP(t, func(path string, raw []byte) any {
				if path == "/rpc/describe" {
					n := describes.Add(1)
					description := expectedInventoryReadonlyDescription(source)
					if fault == "post_describe" && n == 2 {
						description.SourceCommit = enrolledFailedAWSCreator
					}
					return description
				}
				if path != "/rpc/execute" {
					t.Error("unexpected inventory endpoint")
					return nil
				}
				executes.Add(1)
				in := inventoryReadonlyDecodeTestRequest(t, raw)
				if in.OriginalDeadlineCore != deadline.UTC().Format(time.RFC3339Nano) {
					t.Error("five-second deadline renewed before dispatch")
				}
				returned := inventoryReadonlyDeclaredReturn(in, source, inventory)
				wire, _ := json.Marshal(returned)
				var output map[string]any
				_ = json.Unmarshal(wire, &output)
				switch fault {
				case "foreign_observer":
					output["observer_source_commit"] = enrolledFailedAWSCreator
				case "foreign_producer":
					output["profile_producer_source_commit"] = source
				case "foreign_read":
					output["read_id"] = uuid.NewString()
				case "foreign_hash":
					output["read_sha256"] = strings.Repeat("e", 64)
				case "renewed_deadline":
					output["original_deadline_core"] = deadline.Add(time.Second).UTC().Format(time.RFC3339Nano)
				case "unknown_output":
					output["allow_mutation"] = false
				case "missing_inventory":
					delete(output, "inventory")
				case "missing_false":
					delete(output["inventory"].(map[string]any), "business_ready_evidence")
				}
				reply := map[string]any{"operation": inventoryReadonlyOperation, "capability": inventoryReadonlyOperation, "status": "observed", "output": output}
				if fault == "diagnostic_metadata" {
					reply["metadata"] = map[string]any{"provider": "aws", "native_mutations": 0}
				}
				if fault == "unknown_reply" {
					reply["allow_mutation"] = false
				}
				return reply
			})
			guards := 0
			got, err := readInventoryReadonly(ctx, o, "declared", source, func(context.Context) error {
				guards++
				if fault == "post_guard" && guards == 2 {
					return errors.New("lease changed")
				}
				return nil
			})
			positive := fault == "exact" || fault == "diagnostic_metadata"
			if (err == nil) != positive || positive && (!reflect.DeepEqual(got, inventory) || guards != 2 || describes.Load() != 2 || executes.Load() != 1) || !positive && !reflect.DeepEqual(got, model.CapacityVMFleetInventory{}) {
				t.Fatal("source/deadline/closed-return/lease join", fault, err)
			}
			if (fault == "cancelled" || fault == "no_deadline" || fault == "renewed_budget") && (describes.Load() != 0 || executes.Load() != 0) {
				t.Fatal("invalid original budget reached reader")
			}
		})
	}
}
