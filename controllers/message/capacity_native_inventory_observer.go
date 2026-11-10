//go:build !nativequalification

package message

import (
	"context"
	"encoding/json"
	"reflect"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
)

// Select the exact inventory-only compiler source. Its CI, immutable image
// publication and deployment acceptance remain separate release requirements.
const inventoryReadonlyAWSObserverSource = "9030dba6b2d8b5e1d92013f247e42bc517013d12"
const inventoryReadonlyVersion = "1.0.0"
const inventoryReadonlyProvider = "aws-original-inventory-readonly"
const inventoryReadonlyOrigin = "http://integration-aws-inventory-readonly.dakasa.svc.cluster.local:8081"
const inventoryReadonlyOperation = "observe_original_profile_inventory"
const inventoryReadonlyDescribeSchema = "aws_original_profile_inventory_readonly_describe_v1"
const inventoryReadonlyRequestSchema = "aws_original_profile_inventory_read_request_v1"
const inventoryReadonlyReturnSchema = "aws_original_profile_inventory_read_return_v1"

type inventoryReadonlyDescription struct {
	Schema                      string `json:"schema"`
	Provider                    string `json:"provider"`
	Version                     string `json:"version"`
	SourceCommit                string `json:"source_commit"`
	Transport                   string `json:"transport"`
	DescribeEndpoint            string `json:"describe_endpoint"`
	ExecuteEndpoint             string `json:"execute_endpoint"`
	Operation                   string `json:"operation"`
	RequestSchema               string `json:"request_schema"`
	ReturnSchema                string `json:"return_schema"`
	ProfileProducerVersion      string `json:"profile_producer_version"`
	ProfileProducerSourceCommit string `json:"profile_producer_source_commit"`
	NativeMutations             int    `json:"native_mutations"`
	NormalAdapterOperations     bool   `json:"normal_adapter_operations"`
	AMQPRegistered              bool   `json:"amqp_registered"`
}

type inventoryReadonlyRequest struct {
	Schema               string `json:"schema"`
	Profile              string `json:"profile"`
	ReadID               string `json:"read_id"`
	ReadSHA256           string `json:"read_sha256"`
	OriginalDeadlineCore string `json:"original_deadline_core"`
}

type inventoryReadonlyReturn struct {
	Schema                      string                         `json:"schema"`
	ObserverSourceCommit        string                         `json:"observer_source_commit"`
	ProfileProducerSourceCommit string                         `json:"profile_producer_source_commit"`
	ReadID                      string                         `json:"read_id"`
	ReadSHA256                  string                         `json:"read_sha256"`
	OriginalDeadlineCore        string                         `json:"original_deadline_core"`
	Inventory                   model.CapacityVMFleetInventory `json:"inventory"`
}

func inventoryReadonlySourceReady(source string) bool {
	return enrolledFailedReadonlySourceReady(source) && source != repository.RetirementReadonlyAWSObserverSource() && source != repository.EnrolledFailedAWSObserverSource()
}

func expectedInventoryReadonlyDescription(source string) inventoryReadonlyDescription {
	return inventoryReadonlyDescription{Schema: inventoryReadonlyDescribeSchema, Provider: inventoryReadonlyProvider, Version: inventoryReadonlyVersion, SourceCommit: source, Transport: "http_json", DescribeEndpoint: "/rpc/describe", ExecuteEndpoint: "/rpc/execute", Operation: inventoryReadonlyOperation, RequestSchema: inventoryReadonlyRequestSchema, ReturnSchema: inventoryReadonlyReturnSchema, ProfileProducerVersion: "1.65.5", ProfileProducerSourceCommit: enrolledFailedAWSCreator, NativeMutations: 0, NormalAdapterOperations: false, AMQPRegistered: false}
}

// Compare both the closed typed representation and every original JSON field;
// omitted false/zero facts must not silently become read-only authority.
func validateInventoryReadonlyDescription(raw []byte, source string) error {
	var typed inventoryReadonlyDescription
	if !inventoryReadonlySourceReady(source) || capacity.DecodeGuestLifecycle(raw, &typed) != nil || typed != expectedInventoryReadonlyDescription(source) {
		return errOriginalGuestStep
	}
	expected, err := json.Marshal(expectedInventoryReadonlyDescription(source))
	var actual, fields map[string]any
	if err != nil || json.Unmarshal(raw, &actual) != nil || json.Unmarshal(expected, &fields) != nil || !reflect.DeepEqual(actual, fields) {
		return errOriginalGuestStep
	}
	return nil
}

func describeInventoryReadonly(ctx context.Context, source string) error {
	if ctx == nil || ctx.Err() != nil || !inventoryReadonlySourceReady(source) {
		return errOriginalGuestStep
	}
	child, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	request := struct {
		Provider string `json:"provider"`
		Version  string `json:"expected_version"`
		Source   string `json:"expected_source_commit"`
	}{inventoryReadonlyProvider, inventoryReadonlyVersion, source}
	var raw json.RawMessage
	if newAdapterTransportClient(nil).callNativeHTTPJSON(child, inventoryReadonlyOrigin+"/rpc/describe", request, &raw, adapterCallPolicy{detailFreeErrors: true, native: &nativeAdapterHTTPPolicy{limit: 8192, parent: ctx}}) != nil {
		return errOriginalGuestStep
	}
	return validateInventoryReadonlyDescription(raw, source)
}

// Copy the hydrated credential map before removing callback authority. The
// immutable producer config and its admission/request checksums stay unchanged.
func inventoryReadonlyEnvelope(o capacityResolvedObservationAdapter, in inventoryReadonlyRequest) (map[string]any, error) {
	credentials := make(map[string]any, len(o.instanceSpec.Credentials))
	for key, value := range o.instanceSpec.Credentials {
		if key != "grant_bearer" {
			credentials[key] = value
		}
	}
	o.instanceSpec.Credentials = credentials
	fixed := map[string]any{"schema": in.Schema, "profile": in.Profile, "read_id": in.ReadID, "read_sha256": in.ReadSHA256, "original_deadline_core": in.OriginalDeadlineCore}
	envelope, err := enrolledFailedReadonlyEnvelope(o, fixed)
	if err != nil {
		return nil, errOriginalGuestStep
	}
	envelope["operation"], envelope["capability"] = inventoryReadonlyOperation, inventoryReadonlyOperation
	return envelope, nil
}

// This dispatch is reachable only after productionRetirementSupplierV2 has
// checked the original c34 supplier. It never changes the mutation destination,
// source pin, policy, profile, grant or receipt, and has no normal fallback.
func callForwardInventoryReadonly(ctx context.Context, supplier *originalProductionGuestSupplier) (model.CapacityVMFleetInventory, error) {
	if supplier == nil || supplier.provider != "aws" || supplier.binding.OriginalProviderSourceCommit != enrolledFailedAWSCreator {
		return model.CapacityVMFleetInventory{}, errOriginalGuestStep
	}
	return readInventoryReadonly(ctx, supplier.resolved, supplier.binding.ProfileName, inventoryReadonlyAWSObserverSource, supplier.guard)
}

// The caller already owns the complete five-second deadline, including supplier
// resolution. Send that exact deadline to the sibling; HTTP cancellation alone
// must not leave an SDK handler running under its longer transport default.
func readInventoryReadonly(ctx context.Context, o capacityResolvedObservationAdapter, profile, source string, guard func(context.Context) error) (model.CapacityVMFleetInventory, error) {
	var empty model.CapacityVMFleetInventory
	if ctx == nil || ctx.Err() != nil || !inventoryReadonlySourceReady(source) || guard == nil || profile == "" || o.typeSpec.Provider != "aws" || o.typeSpec.Adapter.Version != "1.65.5" || !originalGuestSupplierCatalogSourceFor("aws", o.typeSpec, enrolledFailedAWSCreator) || !originalGuestSupplierSourceConfigFor("aws", o.instanceSpec, enrolledFailedAWSCreator) {
		return empty, errOriginalGuestStep
	}
	deadline, ok := ctx.Deadline()
	if !ok || !time.Now().Before(deadline) || time.Until(deadline) > 5*time.Second || guard(ctx) != nil {
		return empty, errOriginalGuestStep
	}
	in := inventoryReadonlyRequest{Schema: inventoryReadonlyRequestSchema, Profile: profile, ReadID: uuid.NewString(), OriginalDeadlineCore: deadline.UTC().Format(time.RFC3339Nano)}
	challenge, err := json.Marshal(struct {
		Request          inventoryReadonlyRequest `json:"request"`
		InstanceID       string                   `json:"instance_id"`
		InstanceChecksum string                   `json:"instance_checksum"`
		TypeID           string                   `json:"type_id"`
		TypeChecksum     string                   `json:"type_checksum"`
	}{in, o.instance.ID.String(), o.instance.Checksum, o.typ.ID.String(), o.typ.Checksum})
	if err != nil {
		return empty, errOriginalGuestStep
	}
	in.ReadSHA256 = capacity.BusinessCreationSHA256(challenge)
	envelope, err := inventoryReadonlyEnvelope(o, in)
	if err != nil || describeInventoryReadonly(ctx, source) != nil {
		return empty, errOriginalGuestStep
	}
	var reply struct {
		Operation  string          `json:"operation"`
		Capability string          `json:"capability"`
		Status     string          `json:"status"`
		Output     json.RawMessage `json:"output"`
		Metadata   map[string]any  `json:"metadata,omitempty"` // SDK diagnostics never confer inventory authority.
	}
	if newAdapterTransportClient(nil).callNativeHTTPJSON(ctx, inventoryReadonlyOrigin+"/rpc/execute", envelope, &reply, adapterCallPolicy{detailFreeErrors: true, native: &nativeAdapterHTTPPolicy{limit: 2 << 20, parent: ctx}}) != nil || reply.Operation != inventoryReadonlyOperation || reply.Capability != inventoryReadonlyOperation || reply.Status != "observed" {
		return empty, errOriginalGuestStep
	}
	var observed inventoryReadonlyReturn
	if capacity.DecodeGuestLifecycle(reply.Output, &observed) != nil || observed.Schema != inventoryReadonlyReturnSchema || observed.ObserverSourceCommit != source || observed.ProfileProducerSourceCommit != enrolledFailedAWSCreator || observed.ReadID != in.ReadID || observed.ReadSHA256 != in.ReadSHA256 || observed.OriginalDeadlineCore != in.OriginalDeadlineCore || observed.Inventory.ProfileName != profile {
		return empty, errOriginalGuestStep
	}
	if describeInventoryReadonly(ctx, source) != nil || guard(ctx) != nil || ctx.Err() != nil || !time.Now().Before(deadline) {
		return empty, errOriginalGuestStep
	}
	return observed.Inventory, nil
}
