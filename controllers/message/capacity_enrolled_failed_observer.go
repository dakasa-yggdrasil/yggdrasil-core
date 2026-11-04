//go:build !nativequalification

package message

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/manifest"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	amqp "github.com/rabbitmq/amqp091-go"
	"reflect"
	"time"
)

const enrolledFailedReadonlyOperation = "observe_original_enrolled_failed_create_absence"
const enrolledFailedReadonlyOrigin = "http://integration-aws-accepted-failed-readonly.dakasa.svc.cluster.local:8081"
const enrolledFailedAWSCreator = "c34e330d8b266bb88e29ae7cf7b01df6f9fd96ce"

func enrolledFailedObserverSource(provider string) string {
	if provider == "aws" {
		return repository.EnrolledFailedAWSObserverSource()
	}
	if provider == "hetzner" {
		return originalCreateDispositionHetznerObserverSource
	}
	return ""
}

// The historical normal1655 Type and IID remain authentic normal supplier
// objects. Their complete raw catalogs are checked before projecting a DTO
// solely for the independently described read-only HTTP destination.
func resolveEnrolledFailedObserver(ctx context.Context, db *sql.DB, conn *amqp.Connection, c model.CapacityOriginalCreateDispositionCandidate) (capacityResolvedObservationAdapter, string, error) {
	var empty capacityResolvedObservationAdapter
	provider := ""
	var policy model.CapacityPolicySpec
	if json.Unmarshal(c.OriginalPolicy.Spec, &policy) != nil {
		return empty, "", errOriginalCreateDisposition
	}
	for _, p := range policy.Profiles {
		if p.Name == c.Binding.ProfileName {
			provider = p.Provider
		}
	}
	if provider == "hetzner" {
		return resolveDispositionObserver(ctx, db, conn, c)
	}
	if provider != "aws" || c.Binding.OriginalProviderSourceCommit != enrolledFailedAWSCreator || !enrolledFailedReadonlySourceReady(enrolledFailedObserverSource(provider)) {
		return empty, "", errOriginalCreateDisposition
	}
	im, e := resolveManifestForKind(ctx, db, "integration_instance", c.Binding.IntegrationInstanceID, "", "", nil)
	if e != nil || !im.Metadata.Active || im.Checksum != c.Binding.IntegrationChecksum {
		return empty, "", errOriginalCreateDisposition
	}
	current, e := repository.ResolveManifest(ctx, db, "integration_instance", im.Metadata.Namespace, im.Metadata.Name, nil, true)
	if e != nil || current.ID != im.ID || current.Checksum != im.Checksum || !bytes.Equal(current.Spec, im.Spec) {
		return empty, "", errOriginalCreateDisposition
	}
	is, e := manifest.ParseIntegrationInstanceSpec(im.Spec)
	if e != nil || !originalGuestSupplierSourceConfigFor(provider, is, enrolledFailedAWSCreator) {
		return empty, "", errOriginalCreateDisposition
	}
	tm, e := resolveManifestForKind(ctx, db, "integration_type", c.Binding.IntegrationTypeID, "", "", nil)
	if e != nil || !tm.Metadata.Active || tm.Checksum != c.Binding.IntegrationTypeChecksum {
		return empty, "", errOriginalCreateDisposition
	}
	ts, e := manifest.ParseIntegrationTypeSpec(tm.Spec)
	if e != nil || ts.Provider != "aws" || ts.Adapter.Version != "1.65.5" || ts.Adapter.Transport != "http_json" || manifest.ValidateIntegrationTypeSpec(ts) != nil {
		return empty, "", errOriginalCreateDisposition
	}
	latest, e := repository.ResolveManifest(ctx, db, "integration_type", tm.Metadata.Namespace, tm.Metadata.Name, nil, true)
	if e != nil || latest.ID != tm.ID || latest.Checksum != tm.Checksum || !bytes.Equal(latest.Spec, tm.Spec) {
		return empty, "", errOriginalCreateDisposition
	}
	ri, rs, rt, rts, e := resolveIntegrationInstance(ctx, conn, db, model.ManifestSelector{ManifestID: im.ID.String()})
	if e != nil || ri.ID != im.ID || ri.Checksum != im.Checksum || rt.ID != tm.ID || rt.Checksum != tm.Checksum || !reflect.DeepEqual(rts, ts) || !originalGuestSupplierSourceConfigFor(provider, rs, enrolledFailedAWSCreator) {
		return empty, "", errOriginalCreateDisposition
	}
	if describeEnrolledFailedReadonly(ctx) != nil {
		return empty, "", errOriginalCreateDisposition
	}
	return capacityResolvedObservationAdapter{ri, rs, rt, rts}, provider, nil
}

type enrolledFailedReadonlyDescription struct {
	nativeDeniedReadonlyDescription
	RetirementOperation     string `json:"retirement_operation,omitempty"`
	RetirementRequestSchema string `json:"retirement_request_schema,omitempty"`
}

func expectedEnrolledFailedDescription(source string) enrolledFailedReadonlyDescription {
	out := enrolledFailedReadonlyDescription{nativeDeniedReadonlyDescription: nativeDeniedReadonlyDescription{Schema: "aws_original_enrolled_failed_create_readonly_describe_v1", Provider: "aws-accepted-failed-readonly", Version: "1.65.7", SourceCommit: source, Transport: "http_json", DescribeEndpoint: "/rpc/describe", ExecuteEndpoint: "/rpc/execute", Operation: enrolledFailedReadonlyOperation, RequestSchema: "aws_original_enrolled_failed_create_absence_read_request_v1", OriginalAdapterVersion: "1.65.5", OriginalAdapterSourceCommit: enrolledFailedAWSCreator, NativeMutations: 0, NormalAdapterOperations: false, AMQPRegistered: false}}
	if source != "" && source == repository.RetirementReadonlyAWSObserverSource() && repository.RetirementReadonlyAWSObserverVersion() != "" {
		out.Version = repository.RetirementReadonlyAWSObserverVersion()
		out.RetirementOperation = retirementReadonlyOperation
		out.RetirementRequestSchema = repository.GuestRetirementReadonlyRequestSchema
	}
	return out
}
func validateEnrolledFailedDescription(raw []byte, source string) error {
	var typed enrolledFailedReadonlyDescription
	if !enrolledFailedReadonlySourceReady(source) || capacity.DecodeGuestLifecycle(raw, &typed) != nil || typed != expectedEnrolledFailedDescription(source) {
		return errOriginalCreateDisposition
	}
	expected, e := json.Marshal(expectedEnrolledFailedDescription(source))
	var a, b map[string]any
	if e != nil || json.Unmarshal(raw, &a) != nil || json.Unmarshal(expected, &b) != nil || !reflect.DeepEqual(a, b) {
		return errOriginalCreateDisposition
	}
	return nil
}
func describeEnrolledFailedReadonly(ctx context.Context) error {
	source := enrolledFailedObserverSource("aws")
	if ctx == nil || !enrolledFailedReadonlySourceReady(source) {
		return errOriginalCreateDisposition
	}
	child, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	request := struct {
		Provider string `json:"provider"`
		Version  string `json:"expected_version"`
		Source   string `json:"expected_source_commit"`
	}{"aws-accepted-failed-readonly", expectedEnrolledFailedDescription(source).Version, source}
	var raw json.RawMessage
	if newAdapterTransportClient(nil).callNativeHTTPJSON(child, enrolledFailedReadonlyOrigin+"/rpc/describe", request, &raw, adapterCallPolicy{detailFreeErrors: true, native: &nativeAdapterHTTPPolicy{limit: 8192, parent: ctx}}) != nil {
		return errOriginalCreateDisposition
	}
	return validateEnrolledFailedDescription(raw, source)
}
func executeEnrolledFailedReadonly(ctx context.Context, o capacityResolvedObservationAdapter, fixed map[string]any) (model.AdapterExecuteIntegrationResponse, error) {
	var reply model.AdapterExecuteIntegrationResponse
	if ctx == nil || !enrolledFailedReadonlySourceReady(enrolledFailedObserverSource("aws")) || fixed["schema"] != "aws_original_enrolled_failed_create_absence_read_request_v1" || (len(fixed) != 11 && len(fixed) != 12) {
		return reply, errOriginalCreateDisposition
	}
	envelope, e := enrolledFailedReadonlyEnvelope(o, fixed)
	if e != nil {
		return reply, e
	}
	child, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	if newAdapterTransportClient(nil).callNativeHTTPJSON(child, enrolledFailedReadonlyOrigin+"/rpc/execute", envelope, &reply, adapterCallPolicy{detailFreeErrors: true, native: &nativeAdapterHTTPPolicy{limit: 2 << 20, parent: ctx}}) != nil || reply.Operation != enrolledFailedReadonlyOperation || reply.Capability != enrolledFailedReadonlyOperation || reply.Status != "observed" {
		return model.AdapterExecuteIntegrationResponse{}, errOriginalCreateDisposition
	}
	return reply, nil
}

func enrolledFailedReadonlyEnvelope(o capacityResolvedObservationAdapter, fixed map[string]any) (map[string]any, error) {
	historical := nativeDeniedResolvedObserver{capacityResolvedObservationAdapter: o, currentType: o.typ}
	request, e := nativeDeniedReadonlyEnvelope(historical, fixed)
	if e != nil {
		return nil, e
	}
	// Marshal the exact protocol projection and replace only the two operation
	// labels; no credentials or input/body are retained in public diagnostics.
	raw, e := json.Marshal(request)
	var envelope map[string]any
	if e != nil || json.Unmarshal(raw, &envelope) != nil {
		return nil, errOriginalCreateDisposition
	}
	envelope["operation"], envelope["capability"] = enrolledFailedReadonlyOperation, enrolledFailedReadonlyOperation
	return envelope, nil
}

// A dedicated accepted-failed observer cannot alias the normal creator or the
// separately published authorization-denied reader, even with a well-shaped SHA.
func enrolledFailedReadonlySourceReady(source string) bool {
	return nativeDeniedObserverSourceReady(source) && source != enrolledFailedAWSCreator && source != nativeDeniedReadonlySource
}

const retirementReadonlyOperation = "observe_original_retirement_absence"

func retirementReadonlySourceReady() bool {
	source := repository.RetirementReadonlyAWSObserverSource()
	return enrolledFailedReadonlySourceReady(source) && source == repository.EnrolledFailedAWSObserverSource() && repository.RetirementReadonlyAWSObserverVersion() != ""
}

// Copy the hydrated credentials; stripping callback authority must not mutate
// the historical supplier, its config or the RequestSHA256 sealed in its grant.
func retirementReadonlyEnvelope(o capacityResolvedObservationAdapter, fixed map[string]any) (map[string]any, error) {
	credentials := make(map[string]any, len(o.instanceSpec.Credentials))
	for key, value := range o.instanceSpec.Credentials {
		if key != "grant_bearer" {
			credentials[key] = value
		}
	}
	o.instanceSpec.Credentials = credentials
	envelope, err := enrolledFailedReadonlyEnvelope(o, fixed)
	if err != nil {
		return nil, err
	}
	envelope["operation"], envelope["capability"] = retirementReadonlyOperation, retirementReadonlyOperation
	// Preserve the canonical protected receipt bytes through the historical
	// envelope projection; decoding it through map[string]any would reorder its
	// fields and can round integers before the adapter hashes the actual bytes.
	original, ok := fixed["original_receipt"].(json.RawMessage)
	if !ok || !json.Valid(original) {
		return nil, errOriginalGuestStep
	}
	envelope["input"].(map[string]any)["original_receipt"] = append(json.RawMessage(nil), original...)
	return envelope, nil
}

// A single original five-second context owns receipt capture, Describe and
// execute. There is no normal-adapter fallback, callback or mutation dispatch.
func callRetirementReadonly(ctx context.Context, supplier *originalProductionGuestSupplier, out *repository.GuestRetirementForwardReadReturn) error {
	if ctx == nil || ctx.Err() != nil || !retirementReadonlySourceReady() || supplier.provider != "aws" || supplier.binding.OriginalProviderSourceCommit != enrolledFailedAWSCreator || supplier.guard(ctx) != nil {
		return errOriginalGuestStep
	}
	receipt, err := supplier.store.NativeMutationReceipt(ctx, supplier.policy, supplier.binding, out.Read.DestroyGrantID)
	if err != nil || receipt.Grant.GrantID != out.Read.DestroyGrantID || (receipt.Grant.State != "settled" && receipt.Grant.State != "confirmed") || receipt.Outcome != "accepted" || !receipt.TransportCompleted {
		return errOriginalGuestStep
	}
	out.OriginalDestroyReceipt = &receipt
	receiptRaw, err := json.Marshal(receipt)
	if err != nil {
		return errOriginalGuestStep
	}
	readRaw, err := json.Marshal(out.Read)
	if err != nil {
		return errOriginalGuestStep
	}
	observed, raw, err := readRetirementReadonly(ctx, supplier, out.Read.ReadID, readRaw, receiptRaw)
	if err != nil {
		return err
	}
	candidate := *out
	candidate.Status, candidate.Observation = "observed", &observed.Observation
	candidate.ObserverSourceCommit = observed.ObserverSourceCommit
	candidate.OriginalObserverReturn = raw
	if repository.ValidateGuestRetirementReadonlyReturn(candidate) != nil {
		return errOriginalGuestStep
	}
	// The existing retained-record cap includes both the exact response bytes
	// (base64) and the decoded observation. Leave room for the real final clock
	// replacing the zero time (at most ten extra RFC3339Nano characters).
	retained, err := json.Marshal(candidate)
	if err != nil || len(retained) > (2<<20)-32 {
		return errOriginalGuestStep
	}

	// Retain only the closed public response. Later guard/context failure still
	// records it truthfully, with CallFailed derived by the owning caller.
	*out = candidate
	if describeEnrolledFailedReadonly(ctx) != nil || supplier.guard(ctx) != nil || ctx.Err() != nil {
		return errOriginalGuestStep
	}
	return nil
}

// Common read-only transport: it echoes the genuine owner's challenge hash,
// with the historical protected receipt and no callback credential or fallback.
func readRetirementReadonly(ctx context.Context, supplier *originalProductionGuestSupplier, readID string, readRaw, receiptRaw []byte) (repository.GuestRetirementReadonlyReturn, []byte, error) {
	var observed repository.GuestRetirementReadonlyReturn
	fixed := map[string]any{"schema": repository.GuestRetirementReadonlyRequestSchema, "profile": supplier.binding.ProfileName, "slot": supplier.input.Slot, "read_id": readID, "read_sha256": capacity.BusinessCreationSHA256(readRaw), "original_adapter_source_commit": enrolledFailedAWSCreator, "original_receipt": json.RawMessage(receiptRaw), "original_receipt_sha256": capacity.BusinessCreationSHA256(receiptRaw)}
	envelope, err := retirementReadonlyEnvelope(supplier.resolved, fixed)
	if err != nil || describeEnrolledFailedReadonly(ctx) != nil {
		return observed, nil, errOriginalGuestStep
	}
	var reply struct {
		Operation  string          `json:"operation"`
		Capability string          `json:"capability"`
		Status     string          `json:"status"`
		Output     json.RawMessage `json:"output"`
	}
	if newAdapterTransportClient(nil).callNativeHTTPJSON(ctx, enrolledFailedReadonlyOrigin+"/rpc/execute", envelope, &reply, adapterCallPolicy{detailFreeErrors: true, native: &nativeAdapterHTTPPolicy{limit: 2 << 20, parent: ctx}}) != nil || reply.Operation != retirementReadonlyOperation || reply.Capability != retirementReadonlyOperation || reply.Status != "observed" {
		return observed, nil, errOriginalGuestStep
	}
	if capacity.DecodeGuestLifecycle(reply.Output, &observed) != nil {
		return observed, nil, errOriginalGuestStep
	}
	return observed, append([]byte(nil), reply.Output...), nil
}

func callOrdinaryRetirementReadonly(ctx context.Context, supplier *originalProductionGuestSupplier, out *repository.GuestNativeAbsenceReturnV2) error {
	if ctx == nil || ctx.Err() != nil || !retirementReadonlySourceReady() || supplier.provider != "aws" || supplier.binding.OriginalProviderSourceCommit != enrolledFailedAWSCreator || supplier.guard(ctx) != nil {
		return errOriginalGuestStep
	}
	receipt, err := supplier.store.NativeMutationReceipt(ctx, supplier.policy, supplier.binding, out.DestroyGrantID)
	if err != nil || receipt.Grant.GrantID != out.DestroyGrantID || receipt.Grant.State != "settled" || receipt.Outcome != "accepted" || !receipt.TransportCompleted || capacity.GuestRetirementSHA(receipt) != out.OriginalDestroyReceiptSHA256 {
		return errOriginalGuestStep
	}
	out.OriginalDestroyReceipt = &receipt
	receiptRaw, err := json.Marshal(receipt)
	if err != nil {
		return errOriginalGuestStep
	}
	readRaw, err := json.Marshal(out.Challenge)
	if err != nil {
		return errOriginalGuestStep
	}
	observed, raw, err := readRetirementReadonly(ctx, supplier, out.Challenge.ReadID, readRaw, receiptRaw)
	if err != nil {
		return err
	}
	candidate := *out
	candidate.Status, candidate.Observation = "observed", &observed.Observation
	candidate.ObserverSourceCommit, candidate.OriginalObserverReturn = observed.ObserverSourceCommit, raw
	if repository.ValidateGuestNativeRetirementReadonlyReturn(candidate) != nil {
		return errOriginalGuestStep
	}
	retained, err := json.Marshal(candidate)
	if err != nil || len(retained) > (1<<20)-32 {
		return errOriginalGuestStep
	}
	*out = candidate
	if describeEnrolledFailedReadonly(ctx) != nil || supplier.guard(ctx) != nil || ctx.Err() != nil {
		return errOriginalGuestStep
	}
	return nil
}
