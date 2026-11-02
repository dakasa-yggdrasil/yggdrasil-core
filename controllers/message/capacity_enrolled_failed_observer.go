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

func expectedEnrolledFailedDescription(source string) nativeDeniedReadonlyDescription {
	return nativeDeniedReadonlyDescription{Schema: "aws_original_enrolled_failed_create_readonly_describe_v1", Provider: "aws-accepted-failed-readonly", Version: "1.65.7", SourceCommit: source, Transport: "http_json", DescribeEndpoint: "/rpc/describe", ExecuteEndpoint: "/rpc/execute", Operation: enrolledFailedReadonlyOperation, RequestSchema: "aws_original_enrolled_failed_create_absence_read_request_v1", OriginalAdapterVersion: "1.65.5", OriginalAdapterSourceCommit: enrolledFailedAWSCreator, NativeMutations: 0, NormalAdapterOperations: false, AMQPRegistered: false}
}
func validateEnrolledFailedDescription(raw []byte, source string) error {
	var typed nativeDeniedReadonlyDescription
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
	}{"aws-accepted-failed-readonly", "1.65.7", source}
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
