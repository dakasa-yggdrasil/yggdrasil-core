package capacity

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const hostFactoryLimit = 65536

var ErrHostFactorySourceRefused = errors.New("host original factory source refused")
var ErrHostFactorySourceUnavailable = errors.New("host original factory source unavailable")

// Literal reviewed body schemas. No caller-defined types or marshalers enter this protocol.
var hostFactorySchemas = map[reflect.Type]string{
	reflect.TypeOf(model.HostFactoryPreAuthorityScope{}):                    "original_host_factory_pre_authority_scope_v4",
	reflect.TypeOf(model.HostFactoryBinaryExecution{}):                      "original_host_factory_binary_execution_v4",
	reflect.TypeOf(model.HostFactoryNativeProcess{}):                        "original_host_factory_native_process_v4",
	reflect.TypeOf(model.HostFactoryDescriptorSource{}):                     "original_host_factory_descriptor_source_v4",
	reflect.TypeOf(model.HostFactoryOriginalStartReturn{}):                  "original_host_factory_original_start_return_v5",
	reflect.TypeOf(model.HostFactoryAliveNativeRead{}):                      "original_host_factory_alive_native_read_v5",
	reflect.TypeOf(model.HostFactoryAliveRegistration{}):                    "original_host_factory_alive_registration_v4",
	reflect.TypeOf(model.HostFactoryIssuedAttachment{}):                     "original_host_factory_issued_attachment_v4",
	reflect.TypeOf(model.HostFactoryUnissuedChoiceReservation{}):            "original_host_factory_unissued_choice_reservation_v4",
	reflect.TypeOf(model.HostFactoryUnissuedChoiceBody{}):                   "original_host_factory_unissued_choice_body_v4",
	reflect.TypeOf(model.HostFactoryChoiceReturn{}):                         "original_host_factory_choice_return_v4",
	reflect.TypeOf(model.HostFactoryExteriorJoin{}):                         "original_host_factory_exterior_join_v5",
	reflect.TypeOf(model.HostFactoryTerminalRead{}):                         "original_host_factory_terminal_read_v5",
	reflect.TypeOf(model.HostFactoryUnissuedDisposition{}):                  "original_host_factory_unissued_disposition_v4",
	reflect.TypeOf(model.HostFactoryIssuedChoiceReservation{}):              "original_host_factory_issued_choice_reservation_v4",
	reflect.TypeOf(model.HostFactoryIssuedChoiceBody{}):                     "original_host_factory_issued_choice_body_v4",
	reflect.TypeOf(model.HostFactoryIssuedDisposition{}):                    "original_host_factory_issued_disposition_v4",
	reflect.TypeOf(model.HostFactorySignedEnvelope{}):                       "original_host_factory_signed_envelope_v4",
	reflect.TypeOf(model.HostFactoryBootstrapReturn{}):                      "original_host_factory_bootstrap_return_v4",
	reflect.TypeOf(model.HostFactoryNativeLeaf{}):                           "original_host_factory_native_leaf_v5",
	reflect.TypeOf(model.HostFactorySourceApproval{}):                       "original_host_factory_source_approval_v4",
	reflect.TypeOf(model.HostFactoryOriginalIOFact{}):                       "original_host_factory_original_io_fact_v4",
	reflect.TypeOf(model.HostFactoryDiagnosticIOFact{}):                     "original_host_factory_diagnostic_io_fact_v4",
	reflect.TypeOf(model.HostFactoryFailureDiagnostic{}):                    "original_host_factory_failure_diagnostic_v4",
	reflect.TypeOf(model.HostFactoryArtifactSource{}):                       "original_host_factory_artifact_source_v4",
	reflect.TypeOf(model.HostFactoryPreparedCreatePlan{}):                   "original_host_factory_prepared_create_plan_v4",
	reflect.TypeOf(model.HostFactoryNativeThreadChildRead{}):                "original_host_factory_native_thread_child_read_v4",
	reflect.TypeOf(model.HostFactoryOriginalEmptyRealmRead{}):               "original_host_factory_original_empty_realm_read_v5",
	reflect.TypeOf(model.HostFactoryBootstrapDescriptorSource{}):            "original_host_factory_bootstrap_descriptor_source_v4",
	reflect.TypeOf(model.HostFactoryBasalCallReturn{}):                      "original_host_factory_basal_call_return_v3",
	reflect.TypeOf(model.HostFactoryBasalOwnerObservation{}):                "original_host_factory_basal_owner_observation_v3",
	reflect.TypeOf(model.HostFactoryBasalDescriptorSource{}):                "original_host_factory_basal_descriptor_source_v3",
	reflect.TypeOf(model.HostFactoryRootPreparation{}):                      "original_host_factory_root_preparation_v4",
	reflect.TypeOf(model.HostFactoryRootSignedEnvelope{}):                   "original_host_factory_root_signed_envelope_v4",
	reflect.TypeOf(model.HostFactoryBootstrapSegmentReturn{}):               "original_host_factory_bootstrap_segment_return_v4",
	reflect.TypeOf(model.HostFactoryBootstrapWriteReturn{}):                 "original_host_factory_bootstrap_write_return_v4",
	reflect.TypeOf(model.HostFactoryInitialEmptyRealmRead{}):                "original_host_factory_initial_empty_realm_read_v5",
	reflect.TypeOf(model.HostFactoryOriginalLeaseProvenance{}):              "original_host_factory_original_lease_provenance_v4",
	reflect.TypeOf(model.FactoryOrdinarySourceBinding{}):                    "factory_ordinary_source_binding_v4",
	reflect.TypeOf(model.FactoryOrdinaryBootstrapFrame{}):                   "factory_ordinary_bootstrap_frame_v4",
	reflect.TypeOf(model.FactoryOrdinaryCredentialFrame{}):                  "factory_ordinary_credential_frame_v4",
	reflect.TypeOf(model.FactoryOrdinaryGrantFrame{}):                       "factory_ordinary_grant_frame_v4",
	reflect.TypeOf(model.FactoryOrdinaryGuardRead{}):                        "factory_ordinary_guard_read_v4",
	reflect.TypeOf(model.FactoryOrdinaryDispatchBody{}):                     "factory_ordinary_dispatch_body_v4",
	reflect.TypeOf(model.HostFactoryRootCompletion{}):                       "original_host_factory_root_completion_v4",
	reflect.TypeOf(model.HostFactoryPrimitiveIOReturn{}):                    "original_host_factory_primitive_io_return_v2",
	reflect.TypeOf(model.HostFactoryCallVectorReference{}):                  "original_host_factory_call_vector_reference_v2",
	reflect.TypeOf(model.HostFactoryCallVectorChunk{}):                      "original_host_factory_call_vector_chunk_v2",
	reflect.TypeOf(model.HostFactoryCallVectorManifest{}):                   "original_host_factory_call_vector_manifest_v2",
	reflect.TypeOf(model.HostFactoryNativeStatReturn{}):                     "original_host_factory_native_stat_return_v1",
	reflect.TypeOf(model.HostFactoryNativeAcquiredDescriptor{}):             "original_host_factory_native_acquired_descriptor_v1",
	reflect.TypeOf(model.HostFactoryNativeCallReturn{}):                     "original_host_factory_native_call_return_v1",
	reflect.TypeOf(model.HostFactoryHandleCallInventory{}):                  "original_host_factory_handle_call_inventory_v1",
	reflect.TypeOf(model.HostFactoryHeldExecutableRead{}):                   "original_host_factory_held_executable_read_v1",
	reflect.TypeOf(model.HostFactoryProcessOwnerRead{}):                     "original_host_factory_process_owner_read_v1",
	reflect.TypeOf(model.HostFactoryTaskDirectoryRead{}):                    "original_host_factory_task_directory_read_v1",
	reflect.TypeOf(model.HostFactorySourceAuditReturn{}):                    "original_host_factory_source_audit_return_v1",
	reflect.TypeOf(model.HostFactoryNativeSubjectPin{}):                     "original_host_factory_native_subject_pin_v1",
	reflect.TypeOf(model.HostFactoryNativeObservationReference{}):           "original_host_factory_native_observation_reference_v1",
	reflect.TypeOf(model.HostFactoryNativeObservationRecord{}):              "original_host_factory_native_observation_record_v1",
	reflect.TypeOf(model.HostFactoryNativeObservationCollectionReference{}): "original_host_factory_native_observation_collection_reference_v1",
	reflect.TypeOf(model.HostFactoryNativeObservationManifestReference{}):   "original_host_factory_native_observation_manifest_reference_v1",
	reflect.TypeOf(model.HostFactoryNativeObservationManifest{}):            "original_host_factory_native_observation_manifest_v1",
}

var hostFactoryUUIDFields = map[string]bool{
	"ObservationID": true, "CollectionID": true, "OriginalCensusCollectionID": true,
	"ActualPolicyID":    true,
	"ActualWorkflowID":  true,
	"AllowedPolicyID":   true,
	"AllowedWorkflowID": true,
	"CreatorOwnerID":    true,
	"ObserverOwnerID":   true, "ParentHandleID": true, "OriginalInheritedFromHandleID": true, "OriginalAuditHandleID": true, "SubjectBootID": true,
	"ExecutorID":                    true,
	"FactoryAttemptID":              true,
	"FactoryRealmID":                true,
	"FactoryRootID":                 true,
	"FailureCollectionID":           true,
	"GrantID":                       true,
	"HostBootID":                    true,
	"KeyID":                         true,
	"OriginalAttemptID":             true,
	"OriginalCallID":                true,
	"OriginalCommandHandleID":       true,
	"OriginalCreateCommandHandleID": true,
	"OriginalCreateGrantID":         true,
	"OriginalHandleID":              true,
	"OriginalOwnerID":               true,
	"OriginalProtectedInvocationID": true,
	"OriginalPublicWorkflowRunID":   true,
	"OriginalSelfPIDFDHandleID":     true,
	"PolicyID":                      true,
	"PreregistrationID":             true,
	"RecipientOwnerID":              true,
	"ReservationID":                 true,
	"ScopeRootID":                   true,
	"SubjectOwnerID":                true,
	"WorkflowID":                    true,
}

var hostFactoryEnums = map[string][]string{
	"ObservationKind":               {"process", "task_directory", "thread_children"},
	"Choice":                        {"sealed_before_possible_create"},
	"Result":                        {"same_original_host_factory_permanently_excluded_before_possible_create"},
	"ExecutionClass":                {"linux_owned_binary_subprocess_v1"},
	"ScriptMode":                    {"none_compiled_binary"},
	"Role":                          {"host_core_issuer", "host_exterior", "host_worker", "host_registrar", "host_source_approver", "factory_ordinary_guard_reader", "factory_ordinary_worker"},
	"descriptorRole":                {"control_reader", "control_writer", "stdout_reader", "stdout_writer", "stderr_reader", "stderr_writer", "exterior_worker_pidfd", "registrar_worker_pidfd", "gate_file", "gate_directory", "executable_reader", "cmdline_reader", "bootstrap_reader", "bootstrap_writer", "basal_self_pidfd", "ordinary_credential_reader", "ordinary_credential_writer", "qemu_start_executable_anchor"},
	"Type":                          {"pipe", "pidfd", "regular", "directory"},
	"OriginalReturnClass":           {"eof", "full_write", "success"},
	"OriginalState":                 {"not_called", "called_pending", "returned"},
	"OriginalCloseState":            {"not_acquired", "acquired_pending", "returned"},
	"diagnosticOriginalReturnClass": {"unavailable", "eof", "full_write", "success", "cancelled", "deadline", "io_refused", "short_write", "oversize", "partial", "source_changed", "identity_changed", "unknown", "native_zero_return"},
	"failureCode":                   {"original_context_refused", "role_or_signature_refused", "source_registry_refused", "original_start_refused", "alive_owner_refused", "owner_registration_refused", "original_issue_refused", "choice_conflict", "choice_partial", "original_write_refused", "original_sync_refused", "original_close_refused", "original_wait_refused", "original_pipe_refused", "original_pin_refused", "terminal_read_refused", "native_join_refused", "storage_unknown", "historical_recovery_only"},
	"OriginalRecordState":           {"not_acquired", "acquired_unreadable", "original_bytes_read"},
	"FactoryEntryClass":             {"sealed_a0", "sealed_a1", "ordinary_original_create"},
	"BindingSchema":                 {"original_host_factory_source_approval_v4", "original_host_factory_root_preparation_v4", "original_host_factory_pre_authority_scope_v4", "factory_ordinary_source_binding_v4", "original_host_factory_basal_owner_observation_v3"},
	"BasalOperation":                {"getpid", "getppid", "getuid", "getgid", "pidfd_open_self", "fstat_self_pidfd", "fcntl_getfl_self_pidfd", "fcntl_getfd_self_pidfd"},
	"OriginalHashState":             {"unknown_original_bytes", "actual_public_bytes", "private_withheld", "not_byte_operation"},
	"OriginalSegmentHashState":      {"actual_public_bytes", "private_withheld"},
	"GrantState":                    {"issued", "redeemed"},
	"CallCollectionState":           {"complete_original_calls", "same_original_call_pending", "incomplete_retention"},
	"NativeCallKind":                {"unix_open", "unix_openat", "unix_mkdirat", "unix_fstat", "fcntl_getfl", "fcntl_getfd", "fcntl_setfl", "fcntl_dupfd_cloexec", "unix_getdents64", "unix_pidfd_open", "unix_poll", "unix_pidfd_send_signal", "unix_close", "original_file_close", "original_file_sync", "original_os_pipe", "original_cmd_start", "original_cmd_wait"},
	"SourceAuditOperation":          {"source_file_open", "source_file_fstat", "source_file_read", "source_file_close", "public_workflow_http_do", "public_workflow_body_read", "public_workflow_body_close", "ordinary_authority_http_do", "ordinary_authority_body_read", "ordinary_authority_body_close", "db_open", "db_ping", "db_original_query", "db_close", "broker_connect", "broker_close", "api_listener_open", "api_listener_close", "api_original_serve", "api_original_shutdown", "api_original_close", "api_handler_owner_join", "workflow_owner_join", "source_directory_open", "source_directory_fstat", "source_directory_close", "source_file_write", "source_file_sync", "source_file_rename_noreplace", "source_directory_sync"},
}

type hostFactoryOperationRule struct {
	kind                                              string
	cap                                               int64
	stages, owners, subjects, returns                 []string
	combinations, hostCombinations, exactCombinations [][6]string
}

var hostFactoryOperations = map[string]hostFactoryOperationRule{
	"boot_id_read":                         {"public_byte_read", 65536, []string{"native_alive", "initial_empty", "poststart_empty", "terminal_read"}, []string{"host_exterior", "host_registrar"}, []string{"host_exterior", "host_registrar", "host_worker", "factory_ordinary_worker"}, []string{"success", "eof", "partial", "io_refused", "cancelled", "deadline", "oversize", "source_changed", "identity_changed"}, [][6]string{{"host_exterior", "factory_ordinary_worker", "native_alive", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "boot_id_read"}, {"host_registrar", "factory_ordinary_worker", "native_alive", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "boot_id_read"}}, [][6]string{}, [][6]string{}},
	"stat_before_read":                     {"public_byte_read", 65536, []string{"native_alive", "initial_empty", "poststart_empty", "terminal_read"}, []string{"host_exterior", "host_registrar"}, []string{"host_exterior", "host_registrar", "host_worker", "factory_ordinary_worker"}, []string{"success", "eof", "partial", "io_refused", "cancelled", "deadline", "oversize", "source_changed", "identity_changed"}, [][6]string{{"host_exterior", "factory_ordinary_worker", "native_alive", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "stat_before_read"}, {"host_registrar", "factory_ordinary_worker", "native_alive", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "stat_before_read"}}, [][6]string{}, [][6]string{}},
	"cmdline_read":                         {"public_byte_read", 65536, []string{"native_alive", "initial_empty", "poststart_empty", "terminal_read"}, []string{"host_exterior", "host_registrar"}, []string{"host_exterior", "host_registrar", "host_worker", "factory_ordinary_worker"}, []string{"success", "eof", "partial", "io_refused", "cancelled", "deadline", "oversize", "source_changed", "identity_changed"}, [][6]string{{"host_exterior", "factory_ordinary_worker", "native_alive", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "cmdline_read"}, {"host_registrar", "factory_ordinary_worker", "native_alive", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "cmdline_read"}}, [][6]string{}, [][6]string{}},
	"stat_after_read":                      {"public_byte_read", 65536, []string{"native_alive", "initial_empty", "poststart_empty", "terminal_read"}, []string{"host_exterior", "host_registrar"}, []string{"host_exterior", "host_registrar", "host_worker", "factory_ordinary_worker"}, []string{"success", "eof", "partial", "io_refused", "cancelled", "deadline", "oversize", "source_changed", "identity_changed"}, [][6]string{{"host_exterior", "factory_ordinary_worker", "native_alive", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "stat_after_read"}, {"host_registrar", "factory_ordinary_worker", "native_alive", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "stat_after_read"}}, [][6]string{}, [][6]string{}},
	"thread_stat_before_read":              {"public_byte_read", 65536, []string{"native_alive", "initial_empty", "poststart_empty", "terminal_read"}, []string{"host_exterior", "host_registrar"}, []string{"host_exterior", "host_registrar", "host_worker", "factory_ordinary_worker"}, []string{"success", "eof", "partial", "io_refused", "cancelled", "deadline", "oversize", "source_changed", "identity_changed"}, [][6]string{{"host_exterior", "factory_ordinary_worker", "native_alive", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "thread_stat_before_read"}, {"host_registrar", "factory_ordinary_worker", "native_alive", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "thread_stat_before_read"}}, [][6]string{}, [][6]string{}},
	"thread_children_read":                 {"public_byte_read", 65536, []string{"native_alive", "initial_empty", "poststart_empty", "terminal_read"}, []string{"host_exterior", "host_registrar"}, []string{"host_exterior", "host_registrar", "host_worker", "factory_ordinary_worker"}, []string{"success", "eof", "partial", "io_refused", "cancelled", "deadline", "oversize", "source_changed", "identity_changed"}, [][6]string{{"host_exterior", "factory_ordinary_worker", "native_alive", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "thread_children_read"}, {"host_registrar", "factory_ordinary_worker", "native_alive", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "thread_children_read"}}, [][6]string{}, [][6]string{}},
	"thread_stat_after_read":               {"public_byte_read", 65536, []string{"native_alive", "initial_empty", "poststart_empty", "terminal_read"}, []string{"host_exterior", "host_registrar"}, []string{"host_exterior", "host_registrar", "host_worker", "factory_ordinary_worker"}, []string{"success", "eof", "partial", "io_refused", "cancelled", "deadline", "oversize", "source_changed", "identity_changed"}, [][6]string{{"host_exterior", "factory_ordinary_worker", "native_alive", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "thread_stat_after_read"}, {"host_registrar", "factory_ordinary_worker", "native_alive", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "thread_stat_after_read"}}, [][6]string{}, [][6]string{}},
	"descriptor_fdinfo_read":               {"public_byte_read", 65536, []string{"native_alive", "initial_empty", "poststart_empty", "terminal_read"}, []string{"host_exterior", "host_registrar"}, []string{"host_exterior", "host_registrar", "host_worker", "factory_ordinary_worker"}, []string{"success", "eof", "partial", "io_refused", "cancelled", "deadline", "oversize", "source_changed", "identity_changed"}, [][6]string{{"host_exterior", "factory_ordinary_worker", "native_alive", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "descriptor_fdinfo_read"}, {"host_registrar", "factory_ordinary_worker", "native_alive", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "descriptor_fdinfo_read"}}, [][6]string{}, [][6]string{}},
	"executable_read":                      {"public_byte_read", 134217728, []string{"native_alive", "initial_empty", "poststart_empty", "terminal_read"}, []string{"host_exterior", "host_registrar"}, []string{"host_exterior", "host_registrar", "host_worker", "factory_ordinary_worker"}, []string{"success", "eof", "partial", "io_refused", "cancelled", "deadline", "oversize", "source_changed", "identity_changed"}, [][6]string{{"host_exterior", "factory_ordinary_worker", "native_alive", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "executable_read"}, {"host_registrar", "factory_ordinary_worker", "native_alive", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "executable_read"}}, [][6]string{}, [][6]string{}},
	"qemu_executable_read":                 {"public_byte_read", 134217728, []string{"prepared_create"}, []string{"host_worker", "factory_ordinary_worker"}, []string{"host_worker", "factory_ordinary_worker"}, []string{"success", "eof", "partial", "io_refused", "cancelled", "deadline", "oversize", "source_changed"}, [][6]string{{"factory_ordinary_worker", "factory_ordinary_worker", "prepared_create", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "qemu_executable_read"}}, [][6]string{}, [][6]string{}},
	"original_disk_read":                   {"public_byte_read", 536870912, []string{"prepared_create"}, []string{"host_worker", "factory_ordinary_worker"}, []string{"host_worker", "factory_ordinary_worker"}, []string{"success", "eof", "partial", "io_refused", "cancelled", "deadline", "oversize", "source_changed"}, [][6]string{{"factory_ordinary_worker", "factory_ordinary_worker", "prepared_create", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "original_disk_read"}}, [][6]string{}, [][6]string{}},
	"seed_image_read":                      {"public_byte_read", 536870912, []string{"prepared_create"}, []string{"host_worker", "factory_ordinary_worker"}, []string{"host_worker", "factory_ordinary_worker"}, []string{"success", "eof", "partial", "io_refused", "cancelled", "deadline", "oversize", "source_changed"}, [][6]string{{"factory_ordinary_worker", "factory_ordinary_worker", "prepared_create", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "seed_image_read"}}, [][6]string{}, [][6]string{}},
	"source_iso_read":                      {"public_byte_read", 536870912, []string{"prepared_create"}, []string{"host_worker", "factory_ordinary_worker"}, []string{"host_worker", "factory_ordinary_worker"}, []string{"success", "eof", "partial", "io_refused", "cancelled", "deadline", "oversize", "source_changed"}, [][6]string{{"factory_ordinary_worker", "factory_ordinary_worker", "prepared_create", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "source_iso_read"}}, [][6]string{}, [][6]string{}},
	"bootstrap_challenge32_read":           {"public_byte_read", 32, []string{"root_bootstrap", "registrar_bootstrap", "worker_bootstrap", "ordinary_early_bootstrap"}, []string{"host_exterior", "host_registrar", "host_worker", "factory_ordinary_worker"}, []string{"host_exterior", "host_registrar", "host_worker", "factory_ordinary_worker"}, []string{"success", "eof", "partial", "short_write", "io_refused", "cancelled", "deadline"}, [][6]string{{"factory_ordinary_worker", "factory_ordinary_worker", "ordinary_early_bootstrap", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "bootstrap_challenge32_read"}}, [][6]string{}, [][6]string{}},
	"bootstrap_key64_read":                 {"private_byte_read", 64, []string{"root_bootstrap", "registrar_bootstrap", "worker_bootstrap", "ordinary_early_bootstrap"}, []string{"host_exterior", "host_registrar", "host_worker", "factory_ordinary_worker"}, []string{"host_exterior", "host_registrar", "host_worker", "factory_ordinary_worker"}, []string{"success", "eof", "partial", "short_write", "io_refused", "cancelled", "deadline"}, [][6]string{{"factory_ordinary_worker", "factory_ordinary_worker", "ordinary_early_bootstrap", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "bootstrap_key64_read"}}, [][6]string{}, [][6]string{}},
	"bootstrap_binding_digest32_read":      {"public_byte_read", 32, []string{"root_bootstrap", "registrar_bootstrap", "worker_bootstrap", "ordinary_early_bootstrap"}, []string{"host_exterior", "host_registrar", "host_worker", "factory_ordinary_worker"}, []string{"host_exterior", "host_registrar", "host_worker", "factory_ordinary_worker"}, []string{"success", "eof", "partial", "short_write", "io_refused", "cancelled", "deadline"}, [][6]string{{"factory_ordinary_worker", "factory_ordinary_worker", "ordinary_early_bootstrap", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "bootstrap_binding_digest32_read"}}, [][6]string{}, [][6]string{}},
	"bootstrap_challenge32_write":          {"public_byte_write", 32, []string{"registrar_bootstrap", "worker_bootstrap", "ordinary_early_bootstrap"}, []string{"host_exterior"}, []string{"host_registrar", "host_worker", "factory_ordinary_worker"}, []string{"full_write", "short_write", "partial", "success", "io_refused", "cancelled", "deadline"}, [][6]string{{"host_exterior", "factory_ordinary_worker", "ordinary_early_bootstrap", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "bootstrap_challenge32_write"}}, [][6]string{}, [][6]string{}},
	"bootstrap_key64_write":                {"private_byte_write", 64, []string{"registrar_bootstrap", "worker_bootstrap", "ordinary_early_bootstrap"}, []string{"host_exterior"}, []string{"host_registrar", "host_worker", "factory_ordinary_worker"}, []string{"full_write", "short_write", "partial", "success", "io_refused", "cancelled", "deadline"}, [][6]string{{"host_exterior", "factory_ordinary_worker", "ordinary_early_bootstrap", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "bootstrap_key64_write"}}, [][6]string{}, [][6]string{}},
	"bootstrap_binding_digest32_write":     {"public_byte_write", 32, []string{"registrar_bootstrap", "worker_bootstrap", "ordinary_early_bootstrap"}, []string{"host_exterior"}, []string{"host_registrar", "host_worker", "factory_ordinary_worker"}, []string{"full_write", "short_write", "partial", "success", "io_refused", "cancelled", "deadline"}, [][6]string{{"host_exterior", "factory_ordinary_worker", "ordinary_early_bootstrap", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "bootstrap_binding_digest32_write"}}, [][6]string{}, [][6]string{}},
	"bootstrap_eof_read":                   {"public_byte_read", 1, []string{"root_bootstrap", "registrar_bootstrap", "worker_bootstrap"}, []string{"host_exterior", "host_registrar", "host_worker"}, []string{"host_exterior", "host_registrar", "host_worker"}, []string{"success", "eof", "partial", "io_refused", "cancelled", "deadline"}, [][6]string{}, [][6]string{}, [][6]string{}},
	"ordinary_bootstrap_read":              {"private_byte_read", 65536, []string{"ordinary_early_bootstrap"}, []string{"factory_ordinary_worker"}, []string{"factory_ordinary_worker"}, []string{"success", "eof", "partial", "oversize", "io_refused", "cancelled", "deadline"}, [][6]string{{"factory_ordinary_worker", "factory_ordinary_worker", "ordinary_early_bootstrap", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "ordinary_bootstrap_read"}}, [][6]string{}, [][6]string{}},
	"ordinary_grant_read":                  {"private_byte_read", 65536, []string{"ordinary_late_grant"}, []string{"factory_ordinary_worker"}, []string{"factory_ordinary_worker"}, []string{"success", "eof", "partial", "oversize", "io_refused", "cancelled", "deadline"}, [][6]string{{"factory_ordinary_worker", "factory_ordinary_worker", "ordinary_late_grant", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "ordinary_grant_read"}}, [][6]string{}, [][6]string{}},
	"ordinary_credential_read":             {"private_byte_read", 65536, []string{"ordinary_early_credential"}, []string{"factory_ordinary_worker"}, []string{"factory_ordinary_worker"}, []string{"success", "eof", "partial", "oversize", "io_refused", "cancelled", "deadline"}, [][6]string{{"factory_ordinary_worker", "factory_ordinary_worker", "ordinary_early_credential", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "ordinary_credential_read"}}, [][6]string{}, [][6]string{}},
	"initial_ledger_write":                 {"public_byte_write", 65536, []string{"root_prepare"}, []string{"host_exterior"}, []string{"host_exterior"}, []string{"full_write", "short_write", "partial", "io_refused", "cancelled", "deadline"}, [][6]string{}, [][6]string{}, [][6]string{}},
	"choice_body_write":                    {"public_byte_write", 65536, []string{"choice_write"}, []string{"host_worker"}, []string{"host_worker"}, []string{"full_write", "short_write", "partial", "io_refused", "cancelled", "deadline"}, [][6]string{}, [][6]string{}, [][6]string{}},
	"ordinary_dispatch_write":              {"public_byte_write", 65536, []string{"ordinary_before_start"}, []string{"factory_ordinary_worker"}, []string{"host_worker", "factory_ordinary_worker"}, []string{"full_write", "short_write", "partial", "io_refused", "cancelled", "deadline"}, [][6]string{{"factory_ordinary_worker", "factory_ordinary_worker", "ordinary_before_start", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "ordinary_dispatch_write"}}, [][6]string{}, [][6]string{}},
	"gate_read":                            {"public_byte_read", 65536, []string{"initial_empty", "poststart_empty", "terminal_read"}, []string{"host_exterior", "host_registrar"}, []string{"host_exterior", "host_registrar", "host_worker"}, []string{"success", "eof", "partial", "oversize", "io_refused", "cancelled", "deadline", "source_changed"}, [][6]string{}, [][6]string{}, [][6]string{}},
	"initial_ledger_read":                  {"public_byte_read", 65536, []string{"initial_empty", "poststart_empty", "terminal_read"}, []string{"host_exterior", "host_registrar"}, []string{"host_exterior", "host_registrar", "host_worker"}, []string{"success", "eof", "partial", "oversize", "io_refused", "cancelled", "deadline", "source_changed"}, [][6]string{}, [][6]string{}, [][6]string{}},
	"stdout_read":                          {"public_byte_read", 65536, []string{"worker_exterior_join", "registrar_exterior_join"}, []string{"host_exterior"}, []string{"host_worker", "host_registrar", "factory_ordinary_worker"}, []string{"success", "eof", "partial", "oversize", "io_refused", "cancelled", "deadline"}, [][6]string{{"host_exterior", "factory_ordinary_worker", "worker_exterior_join", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "stdout_read"}}, [][6]string{}, [][6]string{}},
	"stderr_read":                          {"public_byte_read", 65536, []string{"worker_exterior_join", "registrar_exterior_join"}, []string{"host_exterior"}, []string{"host_worker", "host_registrar", "factory_ordinary_worker"}, []string{"success", "eof", "partial", "oversize", "io_refused", "cancelled", "deadline"}, [][6]string{{"host_exterior", "factory_ordinary_worker", "worker_exterior_join", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "stderr_read"}}, [][6]string{}, [][6]string{}},
	"ordinary_guard_before_read":           {"public_byte_read", 65536, []string{"ordinary_redeem", "ordinary_before_start"}, []string{"factory_ordinary_worker"}, []string{"factory_ordinary_worker"}, []string{"success", "eof", "partial", "oversize", "io_refused", "cancelled", "deadline"}, [][6]string{{"factory_ordinary_worker", "factory_ordinary_worker", "ordinary_redeem", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "ordinary_guard_before_read"}, {"factory_ordinary_worker", "factory_ordinary_worker", "ordinary_before_start", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "ordinary_guard_before_read"}}, [][6]string{}, [][6]string{}},
	"ordinary_redeem_response_read":        {"public_byte_read", 65536, []string{"ordinary_redeem", "ordinary_before_start"}, []string{"factory_ordinary_worker"}, []string{"factory_ordinary_worker"}, []string{"success", "eof", "partial", "oversize", "io_refused", "cancelled", "deadline"}, [][6]string{{"factory_ordinary_worker", "factory_ordinary_worker", "ordinary_redeem", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "ordinary_redeem_response_read"}, {"factory_ordinary_worker", "factory_ordinary_worker", "ordinary_before_start", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "ordinary_redeem_response_read"}}, [][6]string{}, [][6]string{}},
	"ordinary_guard_after_read":            {"public_byte_read", 65536, []string{"ordinary_redeem", "ordinary_before_start"}, []string{"factory_ordinary_worker"}, []string{"factory_ordinary_worker"}, []string{"success", "eof", "partial", "oversize", "io_refused", "cancelled", "deadline"}, [][6]string{{"factory_ordinary_worker", "factory_ordinary_worker", "ordinary_redeem", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "ordinary_guard_after_read"}, {"factory_ordinary_worker", "factory_ordinary_worker", "ordinary_before_start", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "ordinary_guard_after_read"}}, [][6]string{}, [][6]string{}},
	"ordinary_guard_before_start_read":     {"public_byte_read", 65536, []string{"ordinary_redeem", "ordinary_before_start"}, []string{"factory_ordinary_worker"}, []string{"factory_ordinary_worker"}, []string{"success", "eof", "partial", "oversize", "io_refused", "cancelled", "deadline"}, [][6]string{{"factory_ordinary_worker", "factory_ordinary_worker", "ordinary_redeem", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "ordinary_guard_before_start_read"}, {"factory_ordinary_worker", "factory_ordinary_worker", "ordinary_before_start", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "ordinary_guard_before_start_read"}}, [][6]string{}, [][6]string{}},
	"root_directory_open":                  {"nonbyte", 0, []string{"root_prepare"}, []string{"host_exterior"}, []string{"host_exterior"}, []string{"success", "io_refused", "cancelled", "deadline", "unknown"}, [][6]string{}, [][6]string{}, [][6]string{}},
	"root_directory_create":                {"nonbyte", 0, []string{"root_prepare"}, []string{"host_exterior"}, []string{"host_exterior"}, []string{"success", "io_refused", "cancelled", "deadline", "unknown"}, [][6]string{}, [][6]string{}, [][6]string{}},
	"gate_open_exclusive":                  {"nonbyte", 0, []string{"choice_write"}, []string{"host_worker"}, []string{"host_worker"}, []string{"success", "io_refused", "cancelled", "deadline", "unknown"}, [][6]string{}, [][6]string{}, [][6]string{}},
	"ordinary_dispatch_open_exclusive":     {"nonbyte", 0, []string{"ordinary_before_start"}, []string{"factory_ordinary_worker"}, []string{"host_worker", "factory_ordinary_worker"}, []string{"success", "io_refused", "cancelled", "deadline", "unknown"}, [][6]string{{"factory_ordinary_worker", "factory_ordinary_worker", "ordinary_before_start", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "ordinary_dispatch_open_exclusive"}}, [][6]string{}, [][6]string{}},
	"initial_ledger_sync":                  {"nonbyte", 0, []string{"root_prepare"}, []string{"host_exterior"}, []string{"host_exterior"}, []string{"success", "io_refused", "cancelled", "deadline", "unknown"}, [][6]string{}, [][6]string{}, [][6]string{}},
	"initial_ledger_close":                 {"nonbyte", 0, []string{"root_prepare"}, []string{"host_exterior"}, []string{"host_exterior"}, []string{"success", "io_refused", "cancelled", "deadline", "unknown"}, [][6]string{}, [][6]string{}, [][6]string{}},
	"root_directory_sync":                  {"nonbyte", 0, []string{"root_prepare"}, []string{"host_exterior"}, []string{"host_exterior"}, []string{"success", "io_refused", "cancelled", "deadline", "unknown"}, [][6]string{}, [][6]string{}, [][6]string{}},
	"root_directory_close":                 {"nonbyte", 0, []string{"root_prepare"}, []string{"host_exterior"}, []string{"host_exterior"}, []string{"success", "io_refused", "cancelled", "deadline", "unknown"}, [][6]string{}, [][6]string{}, [][6]string{}},
	"gate_file_sync":                       {"nonbyte", 0, []string{"choice_write"}, []string{"host_worker"}, []string{"host_worker"}, []string{"success", "io_refused", "cancelled", "deadline", "unknown"}, [][6]string{}, [][6]string{}, [][6]string{}},
	"gate_file_close":                      {"nonbyte", 0, []string{"choice_write"}, []string{"host_worker"}, []string{"host_worker"}, []string{"success", "io_refused", "cancelled", "deadline", "unknown"}, [][6]string{}, [][6]string{}, [][6]string{}},
	"gate_directory_sync":                  {"nonbyte", 0, []string{"choice_write"}, []string{"host_worker"}, []string{"host_worker"}, []string{"success", "io_refused", "cancelled", "deadline", "unknown"}, [][6]string{}, [][6]string{}, [][6]string{}},
	"gate_directory_close":                 {"nonbyte", 0, []string{"choice_write"}, []string{"host_worker"}, []string{"host_worker"}, []string{"success", "io_refused", "cancelled", "deadline", "unknown"}, [][6]string{}, [][6]string{}, [][6]string{}},
	"terminal_gate_close":                  {"nonbyte", 0, []string{"terminal_read"}, []string{"host_registrar"}, []string{"host_worker"}, []string{"success", "io_refused", "cancelled", "deadline", "unknown"}, [][6]string{}, [][6]string{}, [][6]string{}},
	"terminal_directory_close":             {"nonbyte", 0, []string{"terminal_read"}, []string{"host_registrar"}, []string{"host_worker"}, []string{"success", "io_refused", "cancelled", "deadline", "unknown"}, [][6]string{}, [][6]string{}, [][6]string{}},
	"ordinary_dispatch_sync":               {"nonbyte", 0, []string{"ordinary_before_start"}, []string{"factory_ordinary_worker"}, []string{"host_worker", "factory_ordinary_worker"}, []string{"success", "io_refused", "cancelled", "deadline", "unknown"}, [][6]string{{"factory_ordinary_worker", "factory_ordinary_worker", "ordinary_before_start", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "ordinary_dispatch_sync"}}, [][6]string{}, [][6]string{}},
	"ordinary_dispatch_close":              {"nonbyte", 0, []string{"ordinary_before_start"}, []string{"factory_ordinary_worker"}, []string{"host_worker", "factory_ordinary_worker"}, []string{"success", "io_refused", "cancelled", "deadline", "unknown"}, [][6]string{{"factory_ordinary_worker", "factory_ordinary_worker", "ordinary_before_start", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "ordinary_dispatch_close"}}, [][6]string{}, [][6]string{}},
	"ordinary_directory_sync":              {"nonbyte", 0, []string{"ordinary_before_start"}, []string{"factory_ordinary_worker"}, []string{"host_worker", "factory_ordinary_worker"}, []string{"success", "io_refused", "cancelled", "deadline", "unknown"}, [][6]string{{"factory_ordinary_worker", "factory_ordinary_worker", "ordinary_before_start", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "ordinary_directory_sync"}}, [][6]string{}, [][6]string{}},
	"ordinary_directory_close":             {"nonbyte", 0, []string{"ordinary_before_start"}, []string{"factory_ordinary_worker"}, []string{"host_worker", "factory_ordinary_worker"}, []string{"success", "io_refused", "cancelled", "deadline", "unknown"}, [][6]string{{"factory_ordinary_worker", "factory_ordinary_worker", "ordinary_before_start", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "ordinary_directory_close"}}, [][6]string{}, [][6]string{}},
	"ordinary_http_do":                     {"nonbyte", 0, []string{"ordinary_redeem", "ordinary_before_start"}, []string{"factory_ordinary_worker"}, []string{"factory_ordinary_worker"}, []string{"success", "io_refused", "cancelled", "deadline", "unknown"}, [][6]string{{"factory_ordinary_worker", "factory_ordinary_worker", "ordinary_redeem", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "ordinary_http_do"}, {"factory_ordinary_worker", "factory_ordinary_worker", "ordinary_before_start", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "ordinary_http_do"}}, [][6]string{}, [][6]string{}},
	"ordinary_http_body_close":             {"nonbyte", 0, []string{"ordinary_redeem", "ordinary_before_start"}, []string{"factory_ordinary_worker"}, []string{"factory_ordinary_worker"}, []string{"success", "io_refused", "cancelled", "deadline", "unknown"}, [][6]string{{"factory_ordinary_worker", "factory_ordinary_worker", "ordinary_redeem", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "ordinary_http_body_close"}, {"factory_ordinary_worker", "factory_ordinary_worker", "ordinary_before_start", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "ordinary_http_body_close"}}, [][6]string{}, [][6]string{}},
	"worker_start":                         {"nonbyte", 0, []string{"worker_start"}, []string{"host_exterior"}, []string{"host_worker", "factory_ordinary_worker"}, []string{"success", "io_refused", "cancelled", "deadline", "unknown"}, [][6]string{{"host_exterior", "factory_ordinary_worker", "worker_start", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "worker_start"}}, [][6]string{}, [][6]string{}},
	"registrar_start":                      {"nonbyte", 0, []string{"registrar_start"}, []string{"host_exterior"}, []string{"host_registrar"}, []string{"success", "io_refused", "cancelled", "deadline", "unknown"}, [][6]string{}, [][6]string{}, [][6]string{}},
	"qemu_start":                           {"nonbyte", 0, []string{"ordinary_before_start"}, []string{"factory_ordinary_worker"}, []string{"host_worker", "factory_ordinary_worker"}, []string{"success", "io_refused", "cancelled", "deadline", "unknown"}, [][6]string{{"factory_ordinary_worker", "factory_ordinary_worker", "ordinary_before_start", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "qemu_start"}}, [][6]string{}, [][6]string{}},
	"worker_wait":                          {"nonbyte", 0, []string{"worker_exterior_join"}, []string{"host_exterior"}, []string{"host_worker", "factory_ordinary_worker"}, []string{"success", "io_refused", "cancelled", "deadline", "unknown"}, [][6]string{{"host_exterior", "factory_ordinary_worker", "worker_exterior_join", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "worker_wait"}}, [][6]string{}, [][6]string{}},
	"registrar_wait":                       {"nonbyte", 0, []string{"registrar_exterior_join"}, []string{"host_exterior"}, []string{"host_registrar"}, []string{"success", "io_refused", "cancelled", "deadline", "unknown"}, [][6]string{}, [][6]string{}, [][6]string{}},
	"worker_pidfd_pin":                     {"nonbyte", 0, []string{"worker_start"}, []string{"host_exterior", "host_registrar"}, []string{"host_worker", "factory_ordinary_worker"}, []string{"success", "io_refused", "cancelled", "deadline", "unknown"}, [][6]string{{"host_exterior", "factory_ordinary_worker", "worker_start", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "worker_pidfd_pin"}, {"host_registrar", "factory_ordinary_worker", "worker_start", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "worker_pidfd_pin"}}, [][6]string{}, [][6]string{}},
	"registrar_pidfd_pin":                  {"nonbyte", 0, []string{"registrar_start"}, []string{"host_exterior"}, []string{"host_registrar"}, []string{"success", "io_refused", "cancelled", "deadline", "unknown"}, [][6]string{}, [][6]string{}, [][6]string{}},
	"worker_pidfd_poll":                    {"nonbyte", 0, []string{"worker_exterior_join"}, []string{"host_exterior", "host_registrar"}, []string{"host_worker", "factory_ordinary_worker"}, []string{"success", "io_refused", "cancelled", "deadline", "unknown"}, [][6]string{{"host_exterior", "factory_ordinary_worker", "worker_exterior_join", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "worker_pidfd_poll"}, {"host_registrar", "factory_ordinary_worker", "worker_exterior_join", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "worker_pidfd_poll"}}, [][6]string{}, [][6]string{}},
	"registrar_pidfd_poll":                 {"nonbyte", 0, []string{"registrar_exterior_join"}, []string{"host_exterior"}, []string{"host_registrar"}, []string{"success", "io_refused", "cancelled", "deadline", "unknown"}, [][6]string{}, [][6]string{}, [][6]string{}},
	"worker_pidfd_signal":                  {"nonbyte", 0, []string{"cleanup"}, []string{"host_exterior", "host_registrar"}, []string{"host_worker", "factory_ordinary_worker"}, []string{"success", "io_refused", "cancelled", "deadline", "unknown"}, [][6]string{{"host_exterior", "factory_ordinary_worker", "cleanup", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "worker_pidfd_signal"}, {"host_registrar", "factory_ordinary_worker", "cleanup", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "worker_pidfd_signal"}}, [][6]string{}, [][6]string{}},
	"registrar_pidfd_signal":               {"nonbyte", 0, []string{"cleanup"}, []string{"host_exterior"}, []string{"host_registrar"}, []string{"success", "io_refused", "cancelled", "deadline", "unknown"}, [][6]string{}, [][6]string{}, [][6]string{}},
	"worker_pidfd_close":                   {"nonbyte", 0, []string{"worker_exterior_join", "cleanup"}, []string{"host_exterior", "host_registrar"}, []string{"host_worker", "factory_ordinary_worker"}, []string{"success", "io_refused", "cancelled", "deadline", "unknown"}, [][6]string{{"host_exterior", "factory_ordinary_worker", "worker_exterior_join", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "worker_pidfd_close"}, {"host_registrar", "factory_ordinary_worker", "worker_exterior_join", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "worker_pidfd_close"}, {"host_exterior", "factory_ordinary_worker", "cleanup", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "worker_pidfd_close"}, {"host_registrar", "factory_ordinary_worker", "cleanup", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "worker_pidfd_close"}}, [][6]string{}, [][6]string{}},
	"registrar_pidfd_close":                {"nonbyte", 0, []string{"registrar_exterior_join", "cleanup"}, []string{"host_exterior"}, []string{"host_registrar"}, []string{"success", "io_refused", "cancelled", "deadline", "unknown"}, [][6]string{}, [][6]string{}, [][6]string{}},
	"stdout_close":                         {"nonbyte", 0, []string{"worker_start", "registrar_start", "worker_exterior_join", "registrar_exterior_join", "cleanup"}, []string{"host_exterior"}, []string{"host_worker", "host_registrar", "factory_ordinary_worker"}, []string{"success", "io_refused", "cancelled", "deadline", "unknown"}, [][6]string{{"host_exterior", "factory_ordinary_worker", "worker_exterior_join", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "stdout_close"}, {"host_exterior", "factory_ordinary_worker", "cleanup", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "stdout_close"}}, [][6]string{}, [][6]string{}},
	"stderr_close":                         {"nonbyte", 0, []string{"worker_start", "registrar_start", "worker_exterior_join", "registrar_exterior_join", "cleanup"}, []string{"host_exterior"}, []string{"host_worker", "host_registrar", "factory_ordinary_worker"}, []string{"success", "io_refused", "cancelled", "deadline", "unknown"}, [][6]string{{"host_exterior", "factory_ordinary_worker", "worker_exterior_join", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "stderr_close"}, {"host_exterior", "factory_ordinary_worker", "cleanup", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "stderr_close"}}, [][6]string{}, [][6]string{}},
	"stdout_duplicate_writer_close":        {"nonbyte", 0, []string{"worker_exterior_join"}, []string{"host_exterior"}, []string{"host_worker"}, []string{"success", "io_refused", "cancelled", "deadline", "unknown"}, [][6]string{}, [][6]string{}, [][6]string{}},
	"stderr_duplicate_writer_close":        {"nonbyte", 0, []string{"worker_exterior_join"}, []string{"host_exterior"}, []string{"host_worker"}, []string{"success", "io_refused", "cancelled", "deadline", "unknown"}, [][6]string{}, [][6]string{}, [][6]string{}},
	"redundant_stdout_writer_close":        {"nonbyte", 0, []string{"worker_start", "registrar_start", "worker_exterior_join", "registrar_exterior_join", "cleanup"}, []string{"host_exterior"}, []string{"host_worker", "host_registrar", "factory_ordinary_worker"}, []string{"success", "io_refused", "cancelled", "deadline", "unknown"}, [][6]string{{"host_exterior", "factory_ordinary_worker", "worker_start", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "redundant_stdout_writer_close"}, {"host_exterior", "factory_ordinary_worker", "cleanup", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "redundant_stdout_writer_close"}}, [][6]string{}, [][6]string{}},
	"redundant_stderr_writer_close":        {"nonbyte", 0, []string{"worker_start", "registrar_start", "worker_exterior_join", "registrar_exterior_join", "cleanup"}, []string{"host_exterior"}, []string{"host_worker", "host_registrar", "factory_ordinary_worker"}, []string{"success", "io_refused", "cancelled", "deadline", "unknown"}, [][6]string{{"host_exterior", "factory_ordinary_worker", "worker_start", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "redundant_stderr_writer_close"}, {"host_exterior", "factory_ordinary_worker", "cleanup", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "redundant_stderr_writer_close"}}, [][6]string{}, [][6]string{}},
	"control_reader_close":                 {"nonbyte", 0, []string{"choice_write", "cleanup"}, []string{"host_worker"}, []string{"host_worker"}, []string{"success", "io_refused", "cancelled", "deadline", "unknown"}, [][6]string{}, [][6]string{}, [][6]string{}},
	"control_writer_close":                 {"nonbyte", 0, []string{"choice_write", "cleanup"}, []string{"host_exterior"}, []string{"host_worker"}, []string{"success", "io_refused", "cancelled", "deadline", "unknown"}, [][6]string{}, [][6]string{}, [][6]string{}},
	"bootstrap_reader_close":               {"nonbyte", 0, []string{"root_bootstrap", "registrar_bootstrap", "worker_bootstrap", "cleanup"}, []string{"host_exterior", "host_registrar", "host_worker"}, []string{"host_exterior", "host_registrar", "host_worker"}, []string{"success", "io_refused", "cancelled", "deadline", "unknown"}, [][6]string{}, [][6]string{}, [][6]string{}},
	"bootstrap_writer_close":               {"nonbyte", 0, []string{"root_bootstrap", "registrar_bootstrap", "worker_bootstrap", "cleanup"}, []string{"host_exterior"}, []string{"host_exterior", "host_registrar", "host_worker"}, []string{"success", "io_refused", "cancelled", "deadline", "unknown"}, [][6]string{}, [][6]string{}, [][6]string{}},
	"basal_self_pidfd_close":               {"nonbyte", 0, []string{"root_completion", "cleanup"}, []string{"host_exterior", "host_registrar", "host_worker", "factory_ordinary_worker"}, []string{"host_exterior", "host_registrar", "host_worker", "factory_ordinary_worker"}, []string{"success", "io_refused", "cancelled", "deadline", "unknown"}, [][6]string{{"factory_ordinary_worker", "factory_ordinary_worker", "root_completion", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "basal_self_pidfd_close"}, {"factory_ordinary_worker", "factory_ordinary_worker", "cleanup", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "basal_self_pidfd_close"}}, [][6]string{}, [][6]string{}},
	"native_reader_close":                  {"nonbyte", 0, []string{"native_alive", "initial_empty", "poststart_empty", "terminal_read", "cleanup"}, []string{"host_exterior", "host_registrar"}, []string{"host_exterior", "host_registrar", "host_worker", "factory_ordinary_worker"}, []string{"success", "io_refused", "cancelled", "deadline", "unknown"}, [][6]string{{"host_exterior", "factory_ordinary_worker", "native_alive", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "native_reader_close"}, {"host_registrar", "factory_ordinary_worker", "native_alive", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "native_reader_close"}, {"host_exterior", "factory_ordinary_worker", "cleanup", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "native_reader_close"}, {"host_registrar", "factory_ordinary_worker", "cleanup", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "native_reader_close"}}, [][6]string{}, [][6]string{}},
	"artifact_reader_close":                {"nonbyte", 0, []string{"prepared_create", "cleanup"}, []string{"host_worker", "factory_ordinary_worker"}, []string{"host_worker", "factory_ordinary_worker"}, []string{"success", "io_refused", "cancelled", "deadline", "unknown"}, [][6]string{{"factory_ordinary_worker", "factory_ordinary_worker", "prepared_create", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "artifact_reader_close"}, {"factory_ordinary_worker", "factory_ordinary_worker", "cleanup", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "artifact_reader_close"}}, [][6]string{}, [][6]string{}},
	"native_reader_open":                   {"nonbyte", 0, []string{"native_alive", "initial_empty", "poststart_empty", "terminal_read"}, []string{"host_exterior", "host_registrar"}, []string{"host_exterior", "host_registrar", "host_worker", "factory_ordinary_worker"}, []string{"success", "io_refused", "cancelled", "deadline", "unknown"}, [][6]string{{"host_exterior", "factory_ordinary_worker", "native_alive", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "native_reader_open"}, {"host_registrar", "factory_ordinary_worker", "native_alive", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "native_reader_open"}}, [][6]string{}, [][6]string{}},
	"native_reader_fstat":                  {"nonbyte", 0, []string{"native_alive", "initial_empty", "poststart_empty", "terminal_read"}, []string{"host_exterior", "host_registrar"}, []string{"host_exterior", "host_registrar", "host_worker", "factory_ordinary_worker"}, []string{"success", "io_refused", "cancelled", "deadline", "unknown"}, [][6]string{{"host_exterior", "factory_ordinary_worker", "native_alive", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "native_reader_fstat"}, {"host_registrar", "factory_ordinary_worker", "native_alive", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "native_reader_fstat"}}, [][6]string{}, [][6]string{}},
	"artifact_reader_open":                 {"nonbyte", 0, []string{"prepared_create"}, []string{"host_worker", "factory_ordinary_worker"}, []string{"host_worker", "factory_ordinary_worker"}, []string{"success", "io_refused", "cancelled", "deadline", "unknown"}, [][6]string{{"factory_ordinary_worker", "factory_ordinary_worker", "prepared_create", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "artifact_reader_open"}}, [][6]string{}, [][6]string{}},
	"artifact_reader_fstat":                {"nonbyte", 0, []string{"prepared_create"}, []string{"host_worker", "factory_ordinary_worker"}, []string{"host_worker", "factory_ordinary_worker"}, []string{"success", "io_refused", "cancelled", "deadline", "unknown"}, [][6]string{{"factory_ordinary_worker", "factory_ordinary_worker", "prepared_create", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "artifact_reader_fstat"}}, [][6]string{}, [][6]string{}},
	"gate_fstat":                           {"nonbyte", 0, []string{"choice_write", "terminal_read", "ordinary_before_start"}, []string{"host_worker", "host_registrar", "factory_ordinary_worker"}, []string{"host_worker", "factory_ordinary_worker"}, []string{"success", "io_refused", "cancelled", "deadline", "unknown"}, [][6]string{{"factory_ordinary_worker", "factory_ordinary_worker", "ordinary_before_start", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "gate_fstat"}}, [][6]string{{"host_worker", "host_worker", "choice_write", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "gate_fstat"}, {"host_registrar", "host_worker", "terminal_read", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "gate_fstat"}}, [][6]string{}},
	"bootstrap_pipe_create":                {"nonbyte", 0, []string{"root_bootstrap", "registrar_start", "worker_start"}, []string{"host_exterior"}, []string{"host_exterior", "host_registrar", "host_worker", "factory_ordinary_worker"}, []string{"success", "io_refused", "cancelled", "deadline", "unknown"}, [][6]string{{"host_exterior", "factory_ordinary_worker", "worker_start", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "bootstrap_pipe_create"}}, [][6]string{}, [][6]string{}},
	"control_pipe_create":                  {"nonbyte", 0, []string{"registrar_start", "worker_start"}, []string{"host_exterior"}, []string{"host_registrar", "host_worker", "factory_ordinary_worker"}, []string{"success", "io_refused", "cancelled", "deadline", "unknown"}, [][6]string{{"host_exterior", "factory_ordinary_worker", "worker_start", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "control_pipe_create"}}, [][6]string{}, [][6]string{}},
	"stdout_pipe_create":                   {"nonbyte", 0, []string{"registrar_start", "worker_start"}, []string{"host_exterior"}, []string{"host_registrar", "host_worker", "factory_ordinary_worker"}, []string{"success", "io_refused", "cancelled", "deadline", "unknown"}, [][6]string{{"host_exterior", "factory_ordinary_worker", "worker_start", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "stdout_pipe_create"}}, [][6]string{}, [][6]string{}},
	"stderr_pipe_create":                   {"nonbyte", 0, []string{"registrar_start", "worker_start"}, []string{"host_exterior"}, []string{"host_registrar", "host_worker", "factory_ordinary_worker"}, []string{"success", "io_refused", "cancelled", "deadline", "unknown"}, [][6]string{{"host_exterior", "factory_ordinary_worker", "worker_start", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "stderr_pipe_create"}}, [][6]string{}, [][6]string{}},
	"ordinary_credential_pipe_create":      {"nonbyte", 0, []string{"ordinary_bootstrap", "ordinary_early_credential"}, []string{"host_exterior"}, []string{"host_worker", "factory_ordinary_worker"}, []string{"success", "io_refused", "cancelled", "deadline", "unknown"}, [][6]string{{"host_exterior", "factory_ordinary_worker", "ordinary_bootstrap", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "ordinary_credential_pipe_create"}}, [][6]string{}, [][6]string{}},
	"stdio_duplicate_writer_create":        {"nonbyte", 0, []string{"worker_start"}, []string{"host_exterior"}, []string{"host_worker"}, []string{"success", "io_refused", "cancelled", "deadline", "unknown"}, [][6]string{}, [][6]string{}, [][6]string{}},
	"control_frame_read":                   {"public_byte_read", 65536, []string{"choice_control", "prepared_create", "terminal_read"}, []string{"host_worker", "host_registrar"}, []string{"host_worker", "host_registrar"}, []string{"success", "eof", "partial", "full_write", "short_write", "oversize", "io_refused", "cancelled", "deadline"}, [][6]string{}, [][6]string{}, [][6]string{}},
	"control_frame_write":                  {"public_byte_write", 65536, []string{"choice_control", "prepared_create", "terminal_read"}, []string{"host_exterior"}, []string{"host_worker", "host_registrar"}, []string{"full_write", "short_write", "partial", "oversize", "io_refused", "cancelled", "deadline"}, [][6]string{}, [][6]string{}, [][6]string{}},
	"executable_anchor_duplicate":          {"nonbyte", 0, []string{"prepared_create"}, []string{"host_worker", "factory_ordinary_worker"}, []string{"host_worker", "factory_ordinary_worker"}, []string{"success", "io_refused", "unknown"}, [][6]string{{"factory_ordinary_worker", "factory_ordinary_worker", "prepared_create", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "executable_anchor_duplicate"}}, [][6]string{}, [][6]string{}},
	"executable_anchor_close":              {"nonbyte", 0, []string{"ordinary_before_start", "cleanup"}, []string{"host_worker", "factory_ordinary_worker"}, []string{"host_worker", "factory_ordinary_worker"}, []string{"success", "io_refused", "unknown"}, [][6]string{{"factory_ordinary_worker", "factory_ordinary_worker", "ordinary_before_start", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "executable_anchor_close"}, {"factory_ordinary_worker", "factory_ordinary_worker", "cleanup", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "executable_anchor_close"}}, [][6]string{}, [][6]string{}},
	"ordinary_bootstrap_write":             {"private_byte_write", 65536, []string{"ordinary_early_bootstrap"}, []string{"host_exterior"}, []string{"factory_ordinary_worker"}, []string{"full_write", "short_write", "partial", "io_refused", "cancelled", "deadline", "oversize", "source_changed", "identity_changed"}, [][6]string{{"host_exterior", "factory_ordinary_worker", "ordinary_early_bootstrap", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "ordinary_bootstrap_write"}}, [][6]string{}, [][6]string{}},
	"ordinary_bootstrap_prefix_write":      {"public_byte_write", 4, []string{"ordinary_early_bootstrap"}, []string{"host_exterior"}, []string{"factory_ordinary_worker"}, []string{"full_write", "short_write", "partial", "io_refused", "cancelled", "deadline", "oversize", "source_changed", "identity_changed"}, [][6]string{{"host_exterior", "factory_ordinary_worker", "ordinary_early_bootstrap", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "ordinary_bootstrap_prefix_write"}}, [][6]string{}, [][6]string{}},
	"ordinary_bootstrap_prefix_read":       {"public_byte_read", 4, []string{"ordinary_early_bootstrap"}, []string{"factory_ordinary_worker"}, []string{"factory_ordinary_worker"}, []string{"success", "eof", "partial", "io_refused", "cancelled", "deadline", "oversize", "source_changed", "identity_changed"}, [][6]string{{"factory_ordinary_worker", "factory_ordinary_worker", "ordinary_early_bootstrap", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "ordinary_bootstrap_prefix_read"}}, [][6]string{}, [][6]string{}},
	"ordinary_bootstrap_eof_read":          {"public_byte_read", 1, []string{"ordinary_early_bootstrap"}, []string{"factory_ordinary_worker"}, []string{"factory_ordinary_worker"}, []string{"success", "eof", "partial", "io_refused", "cancelled", "deadline", "oversize", "source_changed", "identity_changed"}, [][6]string{{"factory_ordinary_worker", "factory_ordinary_worker", "ordinary_early_bootstrap", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "ordinary_bootstrap_eof_read"}}, [][6]string{}, [][6]string{}},
	"ordinary_bootstrap_writer_close":      {"nonbyte", 0, []string{"ordinary_early_bootstrap", "cleanup"}, []string{"host_exterior"}, []string{"factory_ordinary_worker"}, []string{"success", "io_refused", "cancelled", "deadline", "oversize", "identity_changed"}, [][6]string{{"host_exterior", "factory_ordinary_worker", "ordinary_early_bootstrap", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "ordinary_bootstrap_writer_close"}, {"host_exterior", "factory_ordinary_worker", "cleanup", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "ordinary_bootstrap_writer_close"}}, [][6]string{}, [][6]string{}},
	"ordinary_bootstrap_reader_close":      {"nonbyte", 0, []string{"ordinary_early_bootstrap", "cleanup"}, []string{"factory_ordinary_worker"}, []string{"factory_ordinary_worker"}, []string{"success", "io_refused", "cancelled", "deadline", "oversize", "identity_changed"}, [][6]string{{"factory_ordinary_worker", "factory_ordinary_worker", "ordinary_early_bootstrap", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "ordinary_bootstrap_reader_close"}, {"factory_ordinary_worker", "factory_ordinary_worker", "cleanup", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "ordinary_bootstrap_reader_close"}}, [][6]string{}, [][6]string{}},
	"ordinary_credential_write":            {"private_byte_write", 65536, []string{"ordinary_early_credential"}, []string{"host_exterior"}, []string{"factory_ordinary_worker"}, []string{"full_write", "short_write", "partial", "io_refused", "cancelled", "deadline", "oversize", "source_changed", "identity_changed"}, [][6]string{{"host_exterior", "factory_ordinary_worker", "ordinary_early_credential", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "ordinary_credential_write"}}, [][6]string{}, [][6]string{}},
	"ordinary_credential_prefix_write":     {"public_byte_write", 4, []string{"ordinary_early_credential"}, []string{"host_exterior"}, []string{"factory_ordinary_worker"}, []string{"full_write", "short_write", "partial", "io_refused", "cancelled", "deadline", "oversize", "source_changed", "identity_changed"}, [][6]string{{"host_exterior", "factory_ordinary_worker", "ordinary_early_credential", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "ordinary_credential_prefix_write"}}, [][6]string{}, [][6]string{}},
	"ordinary_credential_prefix_read":      {"public_byte_read", 4, []string{"ordinary_early_credential"}, []string{"factory_ordinary_worker"}, []string{"factory_ordinary_worker"}, []string{"success", "eof", "partial", "io_refused", "cancelled", "deadline", "oversize", "source_changed", "identity_changed"}, [][6]string{{"factory_ordinary_worker", "factory_ordinary_worker", "ordinary_early_credential", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "ordinary_credential_prefix_read"}}, [][6]string{}, [][6]string{}},
	"ordinary_credential_eof_read":         {"public_byte_read", 1, []string{"ordinary_early_credential"}, []string{"factory_ordinary_worker"}, []string{"factory_ordinary_worker"}, []string{"success", "eof", "partial", "io_refused", "cancelled", "deadline", "oversize", "source_changed", "identity_changed"}, [][6]string{{"factory_ordinary_worker", "factory_ordinary_worker", "ordinary_early_credential", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "ordinary_credential_eof_read"}}, [][6]string{}, [][6]string{}},
	"ordinary_credential_writer_close":     {"nonbyte", 0, []string{"ordinary_early_credential", "cleanup"}, []string{"host_exterior"}, []string{"factory_ordinary_worker"}, []string{"success", "io_refused", "cancelled", "deadline", "oversize", "identity_changed"}, [][6]string{{"host_exterior", "factory_ordinary_worker", "ordinary_early_credential", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "ordinary_credential_writer_close"}, {"host_exterior", "factory_ordinary_worker", "cleanup", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "ordinary_credential_writer_close"}}, [][6]string{}, [][6]string{}},
	"ordinary_credential_reader_close":     {"nonbyte", 0, []string{"ordinary_early_credential", "cleanup"}, []string{"factory_ordinary_worker"}, []string{"factory_ordinary_worker"}, []string{"success", "io_refused", "cancelled", "deadline", "oversize", "identity_changed"}, [][6]string{{"factory_ordinary_worker", "factory_ordinary_worker", "ordinary_early_credential", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "ordinary_credential_reader_close"}, {"factory_ordinary_worker", "factory_ordinary_worker", "cleanup", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "ordinary_credential_reader_close"}}, [][6]string{}, [][6]string{}},
	"ordinary_grant_write":                 {"private_byte_write", 65536, []string{"ordinary_late_grant"}, []string{"host_exterior"}, []string{"factory_ordinary_worker"}, []string{"full_write", "short_write", "partial", "io_refused", "cancelled", "deadline", "oversize", "source_changed", "identity_changed"}, [][6]string{{"host_exterior", "factory_ordinary_worker", "ordinary_late_grant", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "ordinary_grant_write"}}, [][6]string{}, [][6]string{}},
	"ordinary_grant_prefix_write":          {"public_byte_write", 4, []string{"ordinary_late_grant"}, []string{"host_exterior"}, []string{"factory_ordinary_worker"}, []string{"full_write", "short_write", "partial", "io_refused", "cancelled", "deadline", "oversize", "source_changed", "identity_changed"}, [][6]string{{"host_exterior", "factory_ordinary_worker", "ordinary_late_grant", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "ordinary_grant_prefix_write"}}, [][6]string{}, [][6]string{}},
	"ordinary_grant_prefix_read":           {"public_byte_read", 4, []string{"ordinary_late_grant"}, []string{"factory_ordinary_worker"}, []string{"factory_ordinary_worker"}, []string{"success", "eof", "partial", "io_refused", "cancelled", "deadline", "oversize", "source_changed", "identity_changed"}, [][6]string{{"factory_ordinary_worker", "factory_ordinary_worker", "ordinary_late_grant", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "ordinary_grant_prefix_read"}}, [][6]string{}, [][6]string{}},
	"ordinary_grant_eof_read":              {"public_byte_read", 1, []string{"ordinary_late_grant"}, []string{"factory_ordinary_worker"}, []string{"factory_ordinary_worker"}, []string{"success", "eof", "partial", "io_refused", "cancelled", "deadline", "oversize", "source_changed", "identity_changed"}, [][6]string{{"factory_ordinary_worker", "factory_ordinary_worker", "ordinary_late_grant", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "ordinary_grant_eof_read"}}, [][6]string{}, [][6]string{}},
	"ordinary_grant_writer_close":          {"nonbyte", 0, []string{"ordinary_late_grant", "cleanup"}, []string{"host_exterior"}, []string{"factory_ordinary_worker"}, []string{"success", "io_refused", "cancelled", "deadline", "oversize", "identity_changed"}, [][6]string{{"host_exterior", "factory_ordinary_worker", "ordinary_late_grant", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "ordinary_grant_writer_close"}, {"host_exterior", "factory_ordinary_worker", "cleanup", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "ordinary_grant_writer_close"}}, [][6]string{}, [][6]string{}},
	"ordinary_grant_reader_close":          {"nonbyte", 0, []string{"ordinary_late_grant", "cleanup"}, []string{"factory_ordinary_worker"}, []string{"factory_ordinary_worker"}, []string{"success", "io_refused", "cancelled", "deadline", "oversize", "identity_changed"}, [][6]string{{"factory_ordinary_worker", "factory_ordinary_worker", "ordinary_late_grant", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "ordinary_grant_reader_close"}, {"factory_ordinary_worker", "factory_ordinary_worker", "cleanup", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "ordinary_grant_reader_close"}}, [][6]string{}, [][6]string{}},
	"workflow_provisioning_nonce_generate": {"private_byte_read", 32, []string{"before_original_issue"}, []string{"host_exterior"}, []string{"host_exterior"}, []string{"success", "eof", "partial", "io_refused"}, [][6]string{}, [][6]string{}, [][6]string{}},
	"ordinary_settlement_nonce_generate":   {"private_byte_read", 32, []string{"ordinary_redeem"}, []string{"factory_ordinary_worker"}, []string{"factory_ordinary_worker"}, []string{"success", "eof", "partial", "io_refused"}, [][6]string{{"factory_ordinary_worker", "factory_ordinary_worker", "ordinary_redeem", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "ordinary_settlement_nonce_generate"}}, [][6]string{}, [][6]string{}},
	"source_approval_read":                 {"public_byte_read", 65536, []string{"root_bootstrap"}, []string{"host_exterior"}, []string{"host_exterior"}, []string{"success", "eof", "partial", "io_refused", "cancelled", "deadline", "oversize", "source_changed", "identity_changed"}, [][6]string{}, [][6]string{}, [][6]string{}},
	"issuer_signing_key64_read":            {"private_byte_read", 64, []string{"issuer_signer_bootstrap"}, []string{"host_exterior"}, []string{"host_core_issuer"}, []string{"success", "partial", "eof", "io_refused", "cancelled", "deadline", "oversize", "source_changed"}, [][6]string{}, [][6]string{}, [][6]string{}},
	"issuer_signing_key_eof_read":          {"private_byte_read", 1, []string{"issuer_signer_bootstrap"}, []string{"host_exterior"}, []string{"host_core_issuer"}, []string{"eof", "partial", "success", "io_refused", "cancelled", "deadline", "oversize"}, [][6]string{}, [][6]string{}, [][6]string{}},
	"issuer_signing_key_close":             {"nonbyte", 0, []string{"issuer_signer_bootstrap"}, []string{"host_exterior"}, []string{"host_core_issuer"}, []string{"success", "io_refused", "unknown"}, [][6]string{}, [][6]string{}, [][6]string{}},
	"fcntl_getfl":                          {"native_scalar", 0, []string{}, []string{}, []string{}, []string{"success", "io_refused", "cancelled", "deadline", "unknown"}, [][6]string{}, [][6]string{}, [][6]string{{"host_exterior", "host_exterior", "root_bootstrap", "original_host_factory_source_approval_v4", "HostFactoryRootSignedEnvelope", "fcntl_getfl"}, {"host_exterior", "host_core_issuer", "issuer_signer_bootstrap", "original_host_factory_source_approval_v4", "HostFactoryRootSignedEnvelope", "fcntl_getfl"}, {"host_worker", "host_worker", "worker_bootstrap", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "fcntl_getfl"}, {"host_worker", "host_worker", "prepared_create", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "fcntl_getfl"}, {"host_worker", "host_worker", "choice_write", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "fcntl_getfl"}, {"factory_ordinary_worker", "factory_ordinary_worker", "ordinary_early_bootstrap", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "fcntl_getfl"}, {"factory_ordinary_worker", "factory_ordinary_worker", "ordinary_early_credential", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "fcntl_getfl"}, {"factory_ordinary_worker", "factory_ordinary_worker", "ordinary_late_grant", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "fcntl_getfl"}, {"factory_ordinary_worker", "factory_ordinary_worker", "prepared_create", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "fcntl_getfl"}, {"factory_ordinary_worker", "factory_ordinary_worker", "ordinary_before_start", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "fcntl_getfl"}, {"host_registrar", "host_registrar", "registrar_bootstrap", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "fcntl_getfl"}, {"host_exterior", "host_exterior", "root_prepare", "original_host_factory_source_approval_v4", "HostFactoryRootSignedEnvelope", "fcntl_getfl"}, {"host_exterior", "host_worker", "worker_start", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "fcntl_getfl"}, {"host_registrar", "host_worker", "worker_start", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "fcntl_getfl"}, {"host_exterior", "host_registrar", "registrar_start", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "fcntl_getfl"}, {"host_exterior", "factory_ordinary_worker", "worker_start", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "fcntl_getfl"}, {"host_registrar", "factory_ordinary_worker", "worker_start", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "fcntl_getfl"}, {"host_exterior", "factory_ordinary_worker", "ordinary_early_bootstrap", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "fcntl_getfl"}, {"host_exterior", "factory_ordinary_worker", "ordinary_early_credential", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "fcntl_getfl"}, {"host_exterior", "factory_ordinary_worker", "ordinary_late_grant", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "fcntl_getfl"}, {"host_exterior", "host_registrar", "registrar_bootstrap", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "fcntl_getfl"}, {"host_exterior", "host_worker", "worker_bootstrap", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "fcntl_getfl"}}},
	"fcntl_getfd":                          {"native_scalar", 0, []string{}, []string{}, []string{}, []string{"success", "io_refused", "cancelled", "deadline", "unknown"}, [][6]string{}, [][6]string{}, [][6]string{{"host_exterior", "host_exterior", "root_bootstrap", "original_host_factory_source_approval_v4", "HostFactoryRootSignedEnvelope", "fcntl_getfd"}, {"host_exterior", "host_core_issuer", "issuer_signer_bootstrap", "original_host_factory_source_approval_v4", "HostFactoryRootSignedEnvelope", "fcntl_getfd"}, {"host_worker", "host_worker", "worker_bootstrap", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "fcntl_getfd"}, {"host_worker", "host_worker", "prepared_create", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "fcntl_getfd"}, {"host_worker", "host_worker", "choice_write", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "fcntl_getfd"}, {"factory_ordinary_worker", "factory_ordinary_worker", "ordinary_early_bootstrap", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "fcntl_getfd"}, {"factory_ordinary_worker", "factory_ordinary_worker", "ordinary_early_credential", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "fcntl_getfd"}, {"factory_ordinary_worker", "factory_ordinary_worker", "ordinary_late_grant", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "fcntl_getfd"}, {"factory_ordinary_worker", "factory_ordinary_worker", "prepared_create", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "fcntl_getfd"}, {"factory_ordinary_worker", "factory_ordinary_worker", "ordinary_before_start", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "fcntl_getfd"}, {"host_registrar", "host_registrar", "registrar_bootstrap", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "fcntl_getfd"}, {"host_exterior", "host_exterior", "root_prepare", "original_host_factory_source_approval_v4", "HostFactoryRootSignedEnvelope", "fcntl_getfd"}, {"host_exterior", "host_worker", "worker_start", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "fcntl_getfd"}, {"host_registrar", "host_worker", "worker_start", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "fcntl_getfd"}, {"host_exterior", "host_registrar", "registrar_start", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "fcntl_getfd"}, {"host_exterior", "factory_ordinary_worker", "worker_start", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "fcntl_getfd"}, {"host_registrar", "factory_ordinary_worker", "worker_start", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "fcntl_getfd"}, {"host_exterior", "factory_ordinary_worker", "ordinary_early_bootstrap", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "fcntl_getfd"}, {"host_exterior", "factory_ordinary_worker", "ordinary_early_credential", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "fcntl_getfd"}, {"host_exterior", "factory_ordinary_worker", "ordinary_late_grant", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "fcntl_getfd"}, {"host_exterior", "host_registrar", "registrar_bootstrap", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "fcntl_getfd"}, {"host_exterior", "host_worker", "worker_bootstrap", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "fcntl_getfd"}}},
	"fcntl_setfl":                          {"native_scalar", 0, []string{}, []string{}, []string{}, []string{"success", "io_refused", "cancelled", "deadline", "unknown"}, [][6]string{}, [][6]string{}, [][6]string{{"host_worker", "host_worker", "worker_bootstrap", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "fcntl_setfl"}, {"host_worker", "host_worker", "choice_write", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "fcntl_setfl"}, {"host_registrar", "host_registrar", "registrar_bootstrap", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "fcntl_setfl"}, {"factory_ordinary_worker", "factory_ordinary_worker", "ordinary_early_bootstrap", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "fcntl_setfl"}, {"factory_ordinary_worker", "factory_ordinary_worker", "ordinary_early_credential", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "fcntl_setfl"}, {"factory_ordinary_worker", "factory_ordinary_worker", "ordinary_late_grant", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "fcntl_setfl"}}},
	"inherited_descriptor_fstat":           {"native_stat", 0, []string{}, []string{}, []string{}, []string{"success", "io_refused", "cancelled", "deadline", "unknown"}, [][6]string{}, [][6]string{}, [][6]string{{"host_worker", "host_worker", "worker_bootstrap", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "inherited_descriptor_fstat"}, {"host_worker", "host_worker", "choice_write", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "inherited_descriptor_fstat"}, {"host_registrar", "host_registrar", "registrar_bootstrap", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "inherited_descriptor_fstat"}, {"factory_ordinary_worker", "factory_ordinary_worker", "ordinary_early_bootstrap", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "inherited_descriptor_fstat"}, {"factory_ordinary_worker", "factory_ordinary_worker", "ordinary_early_credential", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "inherited_descriptor_fstat"}, {"factory_ordinary_worker", "factory_ordinary_worker", "ordinary_late_grant", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "inherited_descriptor_fstat"}}},
	"source_directory_open":                {"native_descriptor", 0, []string{}, []string{}, []string{}, []string{"success", "io_refused", "cancelled", "deadline", "unknown"}, [][6]string{}, [][6]string{}, [][6]string{{"host_exterior", "host_exterior", "root_prepare", "original_host_factory_source_approval_v4", "HostFactoryRootSignedEnvelope", "source_directory_open"}, {"host_worker", "host_worker", "prepared_create", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "source_directory_open"}, {"factory_ordinary_worker", "factory_ordinary_worker", "prepared_create", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "source_directory_open"}}},
	"source_directory_openat":              {"native_descriptor", 0, []string{}, []string{}, []string{}, []string{"success", "io_refused", "cancelled", "deadline", "unknown"}, [][6]string{}, [][6]string{}, [][6]string{{"host_exterior", "host_exterior", "root_prepare", "original_host_factory_source_approval_v4", "HostFactoryRootSignedEnvelope", "source_directory_openat"}, {"host_worker", "host_worker", "prepared_create", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "source_directory_openat"}, {"factory_ordinary_worker", "factory_ordinary_worker", "prepared_create", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "source_directory_openat"}}},
	"source_directory_fstat":               {"native_stat", 0, []string{}, []string{}, []string{}, []string{"success", "io_refused", "cancelled", "deadline", "unknown"}, [][6]string{}, [][6]string{}, [][6]string{{"host_exterior", "host_exterior", "root_prepare", "original_host_factory_source_approval_v4", "HostFactoryRootSignedEnvelope", "source_directory_fstat"}, {"host_worker", "host_worker", "prepared_create", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "source_directory_fstat"}, {"factory_ordinary_worker", "factory_ordinary_worker", "prepared_create", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "source_directory_fstat"}}},
	"source_directory_close":               {"nonbyte", 0, []string{}, []string{}, []string{}, []string{"success", "io_refused", "cancelled", "deadline", "unknown"}, [][6]string{}, [][6]string{}, [][6]string{{"host_exterior", "host_exterior", "root_prepare", "original_host_factory_source_approval_v4", "HostFactoryRootSignedEnvelope", "source_directory_close"}, {"host_worker", "host_worker", "prepared_create", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "source_directory_close"}, {"factory_ordinary_worker", "factory_ordinary_worker", "prepared_create", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "source_directory_close"}, {"host_exterior", "host_exterior", "root_completion", "original_host_factory_source_approval_v4", "HostFactoryRootSignedEnvelope", "source_directory_close"}, {"host_worker", "host_worker", "cleanup", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "source_directory_close"}, {"factory_ordinary_worker", "factory_ordinary_worker", "cleanup", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "source_directory_close"}}},
	"source_prepared_openat":               {"native_descriptor", 0, []string{}, []string{}, []string{}, []string{"success", "io_refused", "cancelled", "deadline", "unknown"}, [][6]string{}, [][6]string{}, [][6]string{{"host_exterior", "host_exterior", "root_bootstrap", "original_host_factory_source_approval_v4", "HostFactoryRootSignedEnvelope", "source_prepared_openat"}, {"host_exterior", "host_core_issuer", "issuer_signer_bootstrap", "original_host_factory_source_approval_v4", "HostFactoryRootSignedEnvelope", "source_prepared_openat"}}},
	"source_prepared_fstat":                {"native_stat", 0, []string{}, []string{}, []string{}, []string{"success", "io_refused", "cancelled", "deadline", "unknown"}, [][6]string{}, [][6]string{}, [][6]string{{"host_exterior", "host_exterior", "root_bootstrap", "original_host_factory_source_approval_v4", "HostFactoryRootSignedEnvelope", "source_prepared_fstat"}, {"host_exterior", "host_core_issuer", "issuer_signer_bootstrap", "original_host_factory_source_approval_v4", "HostFactoryRootSignedEnvelope", "source_prepared_fstat"}}},
	"source_prepared_close":                {"nonbyte", 0, []string{}, []string{}, []string{}, []string{"success", "io_refused", "cancelled", "deadline", "unknown"}, [][6]string{}, [][6]string{}, [][6]string{{"host_exterior", "host_exterior", "root_bootstrap", "original_host_factory_source_approval_v4", "HostFactoryRootSignedEnvelope", "source_prepared_close"}, {"host_exterior", "host_core_issuer", "issuer_signer_bootstrap", "original_host_factory_source_approval_v4", "HostFactoryRootSignedEnvelope", "source_prepared_close"}}},
	"descriptor_fstat":                     {"native_stat", 0, []string{}, []string{}, []string{}, []string{"success", "io_refused", "cancelled", "deadline", "unknown"}, [][6]string{}, [][6]string{}, [][6]string{{"host_exterior", "host_exterior", "root_bootstrap", "original_host_factory_source_approval_v4", "HostFactoryRootSignedEnvelope", "descriptor_fstat"}, {"host_exterior", "host_core_issuer", "issuer_signer_bootstrap", "original_host_factory_source_approval_v4", "HostFactoryRootSignedEnvelope", "descriptor_fstat"}, {"host_worker", "host_worker", "worker_bootstrap", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "descriptor_fstat"}, {"host_worker", "host_worker", "prepared_create", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "descriptor_fstat"}, {"host_worker", "host_worker", "choice_write", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "descriptor_fstat"}, {"factory_ordinary_worker", "factory_ordinary_worker", "ordinary_early_bootstrap", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "descriptor_fstat"}, {"factory_ordinary_worker", "factory_ordinary_worker", "ordinary_early_credential", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "descriptor_fstat"}, {"factory_ordinary_worker", "factory_ordinary_worker", "ordinary_late_grant", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "descriptor_fstat"}, {"factory_ordinary_worker", "factory_ordinary_worker", "prepared_create", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "descriptor_fstat"}, {"factory_ordinary_worker", "factory_ordinary_worker", "ordinary_before_start", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "descriptor_fstat"}, {"host_registrar", "host_registrar", "registrar_bootstrap", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "descriptor_fstat"}, {"host_exterior", "host_exterior", "root_prepare", "original_host_factory_source_approval_v4", "HostFactoryRootSignedEnvelope", "descriptor_fstat"}, {"host_exterior", "host_worker", "worker_start", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "descriptor_fstat"}, {"host_registrar", "host_worker", "worker_start", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "descriptor_fstat"}, {"host_exterior", "host_registrar", "registrar_start", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "descriptor_fstat"}, {"host_exterior", "factory_ordinary_worker", "worker_start", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "descriptor_fstat"}, {"host_registrar", "factory_ordinary_worker", "worker_start", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "descriptor_fstat"}, {"host_exterior", "factory_ordinary_worker", "ordinary_early_bootstrap", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "descriptor_fstat"}, {"host_exterior", "factory_ordinary_worker", "ordinary_early_credential", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "descriptor_fstat"}, {"host_exterior", "factory_ordinary_worker", "ordinary_late_grant", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "descriptor_fstat"}, {"host_exterior", "host_registrar", "registrar_bootstrap", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "descriptor_fstat"}, {"host_exterior", "host_worker", "worker_bootstrap", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "descriptor_fstat"}}},
	"task_inventory_getdents":              {"native_directory_bytes", 65536, []string{}, []string{}, []string{}, []string{"success", "native_zero_return", "partial", "io_refused", "cancelled", "deadline", "oversize", "source_changed", "identity_changed"}, [][6]string{}, [][6]string{}, [][6]string{{"host_exterior", "host_exterior", "initial_empty", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "task_inventory_getdents"}, {"host_exterior", "host_registrar", "initial_empty", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "task_inventory_getdents"}, {"host_registrar", "host_exterior", "initial_empty", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "task_inventory_getdents"}, {"host_registrar", "host_registrar", "initial_empty", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "task_inventory_getdents"}, {"host_exterior", "host_exterior", "poststart_empty", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "task_inventory_getdents"}, {"host_exterior", "host_registrar", "poststart_empty", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "task_inventory_getdents"}, {"host_exterior", "host_worker", "poststart_empty", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "task_inventory_getdents"}, {"host_registrar", "host_exterior", "poststart_empty", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "task_inventory_getdents"}, {"host_registrar", "host_registrar", "poststart_empty", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "task_inventory_getdents"}, {"host_registrar", "host_worker", "poststart_empty", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "task_inventory_getdents"}, {"host_exterior", "host_registrar", "native_alive", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "task_inventory_getdents"}, {"host_registrar", "host_exterior", "native_alive", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "task_inventory_getdents"}, {"host_exterior", "host_worker", "native_alive", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "task_inventory_getdents"}, {"host_registrar", "host_worker", "native_alive", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "task_inventory_getdents"}, {"host_exterior", "factory_ordinary_worker", "native_alive", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "task_inventory_getdents"}, {"host_registrar", "factory_ordinary_worker", "native_alive", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "task_inventory_getdents"}, {"host_registrar", "host_exterior", "terminal_read", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "task_inventory_getdents"}, {"host_registrar", "host_registrar", "terminal_read", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "task_inventory_getdents"}, {"host_exterior", "host_exterior", "poststart_empty", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "task_inventory_getdents"}, {"host_exterior", "host_registrar", "poststart_empty", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "task_inventory_getdents"}, {"host_registrar", "host_exterior", "poststart_empty", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "task_inventory_getdents"}, {"host_registrar", "host_registrar", "poststart_empty", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "task_inventory_getdents"}, {"host_registrar", "host_exterior", "terminal_read", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "task_inventory_getdents"}, {"host_registrar", "host_registrar", "terminal_read", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "task_inventory_getdents"}}},
	"proc_owner_directory_open":            {"native_descriptor", 0, []string{}, []string{}, []string{}, []string{"success", "io_refused", "cancelled", "deadline", "unknown"}, [][6]string{}, [][6]string{}, [][6]string{{"host_exterior", "host_exterior", "initial_empty", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "proc_owner_directory_open"}, {"host_exterior", "host_registrar", "initial_empty", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "proc_owner_directory_open"}, {"host_registrar", "host_exterior", "initial_empty", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "proc_owner_directory_open"}, {"host_registrar", "host_registrar", "initial_empty", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "proc_owner_directory_open"}, {"host_exterior", "host_exterior", "poststart_empty", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "proc_owner_directory_open"}, {"host_exterior", "host_registrar", "poststart_empty", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "proc_owner_directory_open"}, {"host_exterior", "host_worker", "poststart_empty", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "proc_owner_directory_open"}, {"host_registrar", "host_exterior", "poststart_empty", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "proc_owner_directory_open"}, {"host_registrar", "host_registrar", "poststart_empty", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "proc_owner_directory_open"}, {"host_registrar", "host_worker", "poststart_empty", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "proc_owner_directory_open"}, {"host_exterior", "host_registrar", "native_alive", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "proc_owner_directory_open"}, {"host_registrar", "host_exterior", "native_alive", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "proc_owner_directory_open"}, {"host_exterior", "host_worker", "native_alive", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "proc_owner_directory_open"}, {"host_registrar", "host_worker", "native_alive", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "proc_owner_directory_open"}, {"host_exterior", "factory_ordinary_worker", "native_alive", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "proc_owner_directory_open"}, {"host_registrar", "factory_ordinary_worker", "native_alive", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "proc_owner_directory_open"}, {"host_registrar", "host_exterior", "terminal_read", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "proc_owner_directory_open"}, {"host_registrar", "host_registrar", "terminal_read", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "proc_owner_directory_open"}, {"host_exterior", "host_exterior", "poststart_empty", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "proc_owner_directory_open"}, {"host_exterior", "host_registrar", "poststart_empty", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "proc_owner_directory_open"}, {"host_registrar", "host_exterior", "poststart_empty", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "proc_owner_directory_open"}, {"host_registrar", "host_registrar", "poststart_empty", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "proc_owner_directory_open"}, {"host_registrar", "host_exterior", "terminal_read", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "proc_owner_directory_open"}, {"host_registrar", "host_registrar", "terminal_read", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "proc_owner_directory_open"}}},
	"proc_owner_directory_fstat":           {"native_stat", 0, []string{}, []string{}, []string{}, []string{"success", "io_refused", "cancelled", "deadline", "unknown"}, [][6]string{}, [][6]string{}, [][6]string{{"host_exterior", "host_exterior", "initial_empty", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "proc_owner_directory_fstat"}, {"host_exterior", "host_registrar", "initial_empty", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "proc_owner_directory_fstat"}, {"host_registrar", "host_exterior", "initial_empty", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "proc_owner_directory_fstat"}, {"host_registrar", "host_registrar", "initial_empty", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "proc_owner_directory_fstat"}, {"host_exterior", "host_exterior", "poststart_empty", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "proc_owner_directory_fstat"}, {"host_exterior", "host_registrar", "poststart_empty", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "proc_owner_directory_fstat"}, {"host_exterior", "host_worker", "poststart_empty", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "proc_owner_directory_fstat"}, {"host_registrar", "host_exterior", "poststart_empty", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "proc_owner_directory_fstat"}, {"host_registrar", "host_registrar", "poststart_empty", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "proc_owner_directory_fstat"}, {"host_registrar", "host_worker", "poststart_empty", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "proc_owner_directory_fstat"}, {"host_exterior", "host_registrar", "native_alive", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "proc_owner_directory_fstat"}, {"host_registrar", "host_exterior", "native_alive", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "proc_owner_directory_fstat"}, {"host_exterior", "host_worker", "native_alive", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "proc_owner_directory_fstat"}, {"host_registrar", "host_worker", "native_alive", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "proc_owner_directory_fstat"}, {"host_exterior", "factory_ordinary_worker", "native_alive", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "proc_owner_directory_fstat"}, {"host_registrar", "factory_ordinary_worker", "native_alive", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "proc_owner_directory_fstat"}, {"host_registrar", "host_exterior", "terminal_read", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "proc_owner_directory_fstat"}, {"host_registrar", "host_registrar", "terminal_read", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "proc_owner_directory_fstat"}, {"host_exterior", "host_exterior", "poststart_empty", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "proc_owner_directory_fstat"}, {"host_exterior", "host_registrar", "poststart_empty", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "proc_owner_directory_fstat"}, {"host_registrar", "host_exterior", "poststart_empty", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "proc_owner_directory_fstat"}, {"host_registrar", "host_registrar", "poststart_empty", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "proc_owner_directory_fstat"}, {"host_registrar", "host_exterior", "terminal_read", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "proc_owner_directory_fstat"}, {"host_registrar", "host_registrar", "terminal_read", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "proc_owner_directory_fstat"}}},
	"proc_owner_directory_close":           {"nonbyte", 0, []string{}, []string{}, []string{}, []string{"success", "io_refused", "cancelled", "deadline", "unknown"}, [][6]string{}, [][6]string{}, [][6]string{{"host_exterior", "host_exterior", "initial_empty", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "proc_owner_directory_close"}, {"host_exterior", "host_registrar", "initial_empty", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "proc_owner_directory_close"}, {"host_registrar", "host_exterior", "initial_empty", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "proc_owner_directory_close"}, {"host_registrar", "host_registrar", "initial_empty", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "proc_owner_directory_close"}, {"host_exterior", "host_exterior", "poststart_empty", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "proc_owner_directory_close"}, {"host_exterior", "host_registrar", "poststart_empty", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "proc_owner_directory_close"}, {"host_exterior", "host_worker", "poststart_empty", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "proc_owner_directory_close"}, {"host_registrar", "host_exterior", "poststart_empty", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "proc_owner_directory_close"}, {"host_registrar", "host_registrar", "poststart_empty", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "proc_owner_directory_close"}, {"host_registrar", "host_worker", "poststart_empty", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "proc_owner_directory_close"}, {"host_exterior", "host_registrar", "native_alive", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "proc_owner_directory_close"}, {"host_registrar", "host_exterior", "native_alive", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "proc_owner_directory_close"}, {"host_exterior", "host_worker", "native_alive", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "proc_owner_directory_close"}, {"host_registrar", "host_worker", "native_alive", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "proc_owner_directory_close"}, {"host_exterior", "factory_ordinary_worker", "native_alive", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "proc_owner_directory_close"}, {"host_registrar", "factory_ordinary_worker", "native_alive", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "proc_owner_directory_close"}, {"host_registrar", "host_exterior", "terminal_read", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "proc_owner_directory_close"}, {"host_registrar", "host_registrar", "terminal_read", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "proc_owner_directory_close"}, {"host_exterior", "host_exterior", "poststart_empty", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "proc_owner_directory_close"}, {"host_exterior", "host_registrar", "poststart_empty", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "proc_owner_directory_close"}, {"host_registrar", "host_exterior", "poststart_empty", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "proc_owner_directory_close"}, {"host_registrar", "host_registrar", "poststart_empty", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "proc_owner_directory_close"}, {"host_registrar", "host_exterior", "terminal_read", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "proc_owner_directory_close"}, {"host_registrar", "host_registrar", "terminal_read", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "proc_owner_directory_close"}}},
	"gate_directory_duplicate":             {"native_descriptor", 0, []string{"choice_write", "terminal_read", "ordinary_before_start"}, []string{"host_worker", "host_registrar", "factory_ordinary_worker"}, []string{"host_worker", "factory_ordinary_worker"}, []string{"success", "io_refused", "cancelled", "deadline", "unknown"}, [][6]string{{"factory_ordinary_worker", "factory_ordinary_worker", "ordinary_before_start", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "gate_directory_duplicate"}}, [][6]string{{"host_worker", "host_worker", "choice_write", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "gate_directory_duplicate"}, {"host_registrar", "host_worker", "terminal_read", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "gate_directory_duplicate"}}, [][6]string{}},
	"native_subject_pidfd_open":            {"native_descriptor", 0, []string{}, []string{}, []string{}, []string{"success", "io_refused", "cancelled", "deadline", "unknown"}, [][6]string{}, [][6]string{}, [][6]string{{"host_exterior", "host_exterior", "initial_empty", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "native_subject_pidfd_open"}, {"host_exterior", "host_registrar", "initial_empty", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "native_subject_pidfd_open"}, {"host_registrar", "host_exterior", "initial_empty", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "native_subject_pidfd_open"}, {"host_registrar", "host_registrar", "initial_empty", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "native_subject_pidfd_open"}, {"host_exterior", "host_exterior", "poststart_empty", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "native_subject_pidfd_open"}, {"host_exterior", "host_registrar", "poststart_empty", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "native_subject_pidfd_open"}, {"host_exterior", "host_worker", "poststart_empty", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "native_subject_pidfd_open"}, {"host_registrar", "host_exterior", "poststart_empty", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "native_subject_pidfd_open"}, {"host_registrar", "host_registrar", "poststart_empty", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "native_subject_pidfd_open"}, {"host_registrar", "host_worker", "poststart_empty", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "native_subject_pidfd_open"}, {"host_exterior", "host_registrar", "native_alive", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "native_subject_pidfd_open"}, {"host_registrar", "host_exterior", "native_alive", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "native_subject_pidfd_open"}, {"host_exterior", "host_worker", "native_alive", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "native_subject_pidfd_open"}, {"host_registrar", "host_worker", "native_alive", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "native_subject_pidfd_open"}, {"host_exterior", "factory_ordinary_worker", "native_alive", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "native_subject_pidfd_open"}, {"host_registrar", "factory_ordinary_worker", "native_alive", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "native_subject_pidfd_open"}, {"host_registrar", "host_exterior", "terminal_read", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "native_subject_pidfd_open"}, {"host_registrar", "host_registrar", "terminal_read", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "native_subject_pidfd_open"}, {"host_exterior", "host_exterior", "poststart_empty", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "native_subject_pidfd_open"}, {"host_exterior", "host_registrar", "poststart_empty", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "native_subject_pidfd_open"}, {"host_registrar", "host_exterior", "poststart_empty", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "native_subject_pidfd_open"}, {"host_registrar", "host_registrar", "poststart_empty", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "native_subject_pidfd_open"}, {"host_registrar", "host_exterior", "terminal_read", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "native_subject_pidfd_open"}, {"host_registrar", "host_registrar", "terminal_read", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "native_subject_pidfd_open"}}},
	"native_subject_pidfd_fstat":           {"native_stat", 0, []string{}, []string{}, []string{}, []string{"success", "io_refused", "cancelled", "deadline", "unknown"}, [][6]string{}, [][6]string{}, [][6]string{{"host_exterior", "host_exterior", "initial_empty", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "native_subject_pidfd_fstat"}, {"host_exterior", "host_registrar", "initial_empty", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "native_subject_pidfd_fstat"}, {"host_registrar", "host_exterior", "initial_empty", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "native_subject_pidfd_fstat"}, {"host_registrar", "host_registrar", "initial_empty", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "native_subject_pidfd_fstat"}, {"host_exterior", "host_exterior", "poststart_empty", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "native_subject_pidfd_fstat"}, {"host_exterior", "host_registrar", "poststart_empty", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "native_subject_pidfd_fstat"}, {"host_exterior", "host_worker", "poststart_empty", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "native_subject_pidfd_fstat"}, {"host_registrar", "host_exterior", "poststart_empty", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "native_subject_pidfd_fstat"}, {"host_registrar", "host_registrar", "poststart_empty", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "native_subject_pidfd_fstat"}, {"host_registrar", "host_worker", "poststart_empty", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "native_subject_pidfd_fstat"}, {"host_exterior", "host_registrar", "native_alive", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "native_subject_pidfd_fstat"}, {"host_registrar", "host_exterior", "native_alive", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "native_subject_pidfd_fstat"}, {"host_exterior", "host_worker", "native_alive", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "native_subject_pidfd_fstat"}, {"host_registrar", "host_worker", "native_alive", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "native_subject_pidfd_fstat"}, {"host_exterior", "factory_ordinary_worker", "native_alive", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "native_subject_pidfd_fstat"}, {"host_registrar", "factory_ordinary_worker", "native_alive", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "native_subject_pidfd_fstat"}, {"host_registrar", "host_exterior", "terminal_read", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "native_subject_pidfd_fstat"}, {"host_registrar", "host_registrar", "terminal_read", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "native_subject_pidfd_fstat"}, {"host_exterior", "host_exterior", "poststart_empty", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "native_subject_pidfd_fstat"}, {"host_exterior", "host_registrar", "poststart_empty", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "native_subject_pidfd_fstat"}, {"host_registrar", "host_exterior", "poststart_empty", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "native_subject_pidfd_fstat"}, {"host_registrar", "host_registrar", "poststart_empty", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "native_subject_pidfd_fstat"}, {"host_registrar", "host_exterior", "terminal_read", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "native_subject_pidfd_fstat"}, {"host_registrar", "host_registrar", "terminal_read", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "native_subject_pidfd_fstat"}}},
	"native_subject_alive_poll":            {"native_scalar", 0, []string{}, []string{}, []string{}, []string{"success", "io_refused", "cancelled", "deadline", "unknown"}, [][6]string{}, [][6]string{}, [][6]string{{"host_exterior", "host_exterior", "initial_empty", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "native_subject_alive_poll"}, {"host_exterior", "host_registrar", "initial_empty", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "native_subject_alive_poll"}, {"host_registrar", "host_exterior", "initial_empty", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "native_subject_alive_poll"}, {"host_registrar", "host_registrar", "initial_empty", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "native_subject_alive_poll"}, {"host_exterior", "host_exterior", "poststart_empty", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "native_subject_alive_poll"}, {"host_exterior", "host_registrar", "poststart_empty", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "native_subject_alive_poll"}, {"host_exterior", "host_worker", "poststart_empty", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "native_subject_alive_poll"}, {"host_registrar", "host_exterior", "poststart_empty", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "native_subject_alive_poll"}, {"host_registrar", "host_registrar", "poststart_empty", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "native_subject_alive_poll"}, {"host_registrar", "host_worker", "poststart_empty", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "native_subject_alive_poll"}, {"host_exterior", "host_registrar", "native_alive", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "native_subject_alive_poll"}, {"host_registrar", "host_exterior", "native_alive", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "native_subject_alive_poll"}, {"host_exterior", "host_worker", "native_alive", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "native_subject_alive_poll"}, {"host_registrar", "host_worker", "native_alive", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "native_subject_alive_poll"}, {"host_exterior", "factory_ordinary_worker", "native_alive", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "native_subject_alive_poll"}, {"host_registrar", "factory_ordinary_worker", "native_alive", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "native_subject_alive_poll"}, {"host_registrar", "host_exterior", "terminal_read", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "native_subject_alive_poll"}, {"host_registrar", "host_registrar", "terminal_read", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "native_subject_alive_poll"}, {"host_exterior", "host_exterior", "poststart_empty", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "native_subject_alive_poll"}, {"host_exterior", "host_registrar", "poststart_empty", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "native_subject_alive_poll"}, {"host_registrar", "host_exterior", "poststart_empty", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "native_subject_alive_poll"}, {"host_registrar", "host_registrar", "poststart_empty", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "native_subject_alive_poll"}, {"host_registrar", "host_exterior", "terminal_read", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "native_subject_alive_poll"}, {"host_registrar", "host_registrar", "terminal_read", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "native_subject_alive_poll"}}},
	"native_subject_pidfd_close":           {"nonbyte", 0, []string{}, []string{}, []string{}, []string{"success", "io_refused", "cancelled", "deadline", "unknown"}, [][6]string{}, [][6]string{}, [][6]string{{"host_exterior", "host_exterior", "initial_empty", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "native_subject_pidfd_close"}, {"host_exterior", "host_registrar", "initial_empty", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "native_subject_pidfd_close"}, {"host_registrar", "host_exterior", "initial_empty", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "native_subject_pidfd_close"}, {"host_registrar", "host_registrar", "initial_empty", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "native_subject_pidfd_close"}, {"host_exterior", "host_exterior", "poststart_empty", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "native_subject_pidfd_close"}, {"host_exterior", "host_registrar", "poststart_empty", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "native_subject_pidfd_close"}, {"host_exterior", "host_worker", "poststart_empty", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "native_subject_pidfd_close"}, {"host_registrar", "host_exterior", "poststart_empty", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "native_subject_pidfd_close"}, {"host_registrar", "host_registrar", "poststart_empty", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "native_subject_pidfd_close"}, {"host_registrar", "host_worker", "poststart_empty", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "native_subject_pidfd_close"}, {"host_exterior", "host_registrar", "native_alive", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "native_subject_pidfd_close"}, {"host_registrar", "host_exterior", "native_alive", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "native_subject_pidfd_close"}, {"host_exterior", "host_worker", "native_alive", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "native_subject_pidfd_close"}, {"host_registrar", "host_worker", "native_alive", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "native_subject_pidfd_close"}, {"host_exterior", "factory_ordinary_worker", "native_alive", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "native_subject_pidfd_close"}, {"host_registrar", "factory_ordinary_worker", "native_alive", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "native_subject_pidfd_close"}, {"host_registrar", "host_exterior", "terminal_read", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "native_subject_pidfd_close"}, {"host_registrar", "host_registrar", "terminal_read", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "native_subject_pidfd_close"}, {"host_exterior", "host_exterior", "cleanup", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "native_subject_pidfd_close"}, {"host_exterior", "host_registrar", "cleanup", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "native_subject_pidfd_close"}, {"host_registrar", "host_exterior", "cleanup", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "native_subject_pidfd_close"}, {"host_registrar", "host_registrar", "cleanup", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "native_subject_pidfd_close"}, {"host_exterior", "host_exterior", "cleanup", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "native_subject_pidfd_close"}, {"host_exterior", "host_registrar", "cleanup", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "native_subject_pidfd_close"}, {"host_exterior", "host_worker", "cleanup", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "native_subject_pidfd_close"}, {"host_registrar", "host_exterior", "cleanup", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "native_subject_pidfd_close"}, {"host_registrar", "host_registrar", "cleanup", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "native_subject_pidfd_close"}, {"host_registrar", "host_worker", "cleanup", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", "native_subject_pidfd_close"}, {"host_exterior", "factory_ordinary_worker", "cleanup", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "native_subject_pidfd_close"}, {"host_registrar", "factory_ordinary_worker", "cleanup", "factory_ordinary_source_binding_v4", "HostFactoryRootSignedEnvelope", "native_subject_pidfd_close"}, {"host_exterior", "host_exterior", "poststart_empty", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "native_subject_pidfd_close"}, {"host_exterior", "host_registrar", "poststart_empty", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "native_subject_pidfd_close"}, {"host_registrar", "host_exterior", "poststart_empty", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "native_subject_pidfd_close"}, {"host_registrar", "host_registrar", "poststart_empty", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "native_subject_pidfd_close"}, {"host_registrar", "host_exterior", "terminal_read", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "native_subject_pidfd_close"}, {"host_registrar", "host_registrar", "terminal_read", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", "native_subject_pidfd_close"}}},
	"initial_ledger_open_exclusive":        {"native_descriptor", 0, []string{}, []string{}, []string{}, []string{"success", "io_refused", "cancelled", "deadline", "unknown"}, [][6]string{}, [][6]string{}, [][6]string{{"host_exterior", "host_exterior", "root_prepare", "original_host_factory_source_approval_v4", "HostFactoryRootSignedEnvelope", "initial_ledger_open_exclusive"}}},
}

var hostFactorySignatureStages = [][4]string{
	{"HostFactorySourceApproval", "HostFactoryRootSignedEnvelope", "original_host_factory_source_approval_v4", "host_source_approver"},
	{"HostFactoryBasalOwnerObservation", "HostFactoryRootSignedEnvelope", "original_host_factory_source_approval_v4", "host_exterior"},
	{"HostFactoryBootstrapReturn", "HostFactoryRootSignedEnvelope", "original_host_factory_source_approval_v4", "host_exterior"},
	{"HostFactoryRootPreparation", "HostFactoryRootSignedEnvelope", "original_host_factory_source_approval_v4", "host_exterior"},
	{"HostFactoryBasalOwnerObservation", "HostFactoryRootSignedEnvelope", "original_host_factory_root_preparation_v4", "host_registrar"},
	{"HostFactoryBootstrapReturn", "HostFactoryRootSignedEnvelope", "original_host_factory_root_preparation_v4", "host_registrar"},
	{"HostFactoryNativeLeaf", "HostFactoryRootSignedEnvelope", "original_host_factory_root_preparation_v4", "host_registrar"},
	{"HostFactoryNativeLeaf", "HostFactoryRootSignedEnvelope", "original_host_factory_root_preparation_v4", "host_exterior"},
	{"HostFactoryInitialEmptyRealmRead", "HostFactoryRootSignedEnvelope", "original_host_factory_root_preparation_v4", "host_registrar"},
	{"HostFactoryRootCompletion", "HostFactoryRootSignedEnvelope", "original_host_factory_root_preparation_v4", "host_exterior"},
	{"HostFactoryBasalOwnerObservation", "HostFactoryRootSignedEnvelope", "factory_ordinary_source_binding_v4", "factory_ordinary_worker"},
	{"HostFactoryBootstrapReturn", "HostFactoryRootSignedEnvelope", "factory_ordinary_source_binding_v4", "factory_ordinary_worker"},
	{"HostFactoryPreparedCreatePlan", "HostFactoryRootSignedEnvelope", "factory_ordinary_source_binding_v4", "factory_ordinary_worker"},
	{"HostFactoryNativeLeaf", "HostFactoryRootSignedEnvelope", "factory_ordinary_source_binding_v4", "host_registrar"},
	{"FactoryOrdinaryGuardRead", "HostFactoryRootSignedEnvelope", "factory_ordinary_source_binding_v4", "host_core_issuer"},
	{"HostFactoryBasalOwnerObservation", "HostFactorySignedEnvelope", "original_host_factory_pre_authority_scope_v4", "host_worker"},
	{"HostFactoryBootstrapReturn", "HostFactorySignedEnvelope", "original_host_factory_pre_authority_scope_v4", "host_worker"},
	{"HostFactoryPreparedCreatePlan", "HostFactorySignedEnvelope", "original_host_factory_pre_authority_scope_v4", "host_worker"},
	{"HostFactoryNativeLeaf", "HostFactorySignedEnvelope", "original_host_factory_pre_authority_scope_v4", "host_registrar"},
	{"HostFactoryOriginalStartReturn", "HostFactorySignedEnvelope", "original_host_factory_pre_authority_scope_v4", "host_exterior"},
	{"HostFactoryAliveNativeRead", "HostFactorySignedEnvelope", "original_host_factory_pre_authority_scope_v4", "host_registrar"},
	{"HostFactoryOriginalEmptyRealmRead", "HostFactorySignedEnvelope", "original_host_factory_pre_authority_scope_v4", "host_registrar"},
	{"HostFactoryChoiceReturn", "HostFactorySignedEnvelope", "original_host_factory_pre_authority_scope_v4", "host_worker"},
	{"HostFactoryExteriorJoin", "HostFactorySignedEnvelope", "original_host_factory_pre_authority_scope_v4", "host_exterior"},
	{"HostFactoryTerminalRead", "HostFactorySignedEnvelope", "original_host_factory_pre_authority_scope_v4", "host_registrar"},
	{"HostFactoryBootstrapWriteReturn", "HostFactoryRootSignedEnvelope", "original_host_factory_root_preparation_v4", "host_exterior"},
	{"HostFactoryBootstrapWriteReturn", "HostFactorySignedEnvelope", "original_host_factory_pre_authority_scope_v4", "host_exterior"},
	{"HostFactoryBootstrapWriteReturn", "HostFactoryRootSignedEnvelope", "factory_ordinary_source_binding_v4", "host_exterior"},
	{"HostFactoryOriginalLeaseProvenance", "HostFactoryRootSignedEnvelope", "original_host_factory_root_preparation_v4", "host_core_issuer"},
	{"HostFactoryPreAuthorityScope", "HostFactoryRootSignedEnvelope", "original_host_factory_root_preparation_v4", "host_core_issuer"},
	{"HostFactoryAliveRegistration", "HostFactorySignedEnvelope", "original_host_factory_pre_authority_scope_v4", "host_core_issuer"},
	{"HostFactoryIssuedAttachment", "HostFactorySignedEnvelope", "original_host_factory_pre_authority_scope_v4", "host_core_issuer"},
	{"HostFactoryUnissuedChoiceReservation", "HostFactorySignedEnvelope", "original_host_factory_pre_authority_scope_v4", "host_core_issuer"},
	{"HostFactoryIssuedChoiceReservation", "HostFactorySignedEnvelope", "original_host_factory_pre_authority_scope_v4", "host_core_issuer"},
	{"HostFactoryUnissuedDisposition", "HostFactorySignedEnvelope", "original_host_factory_pre_authority_scope_v4", "host_core_issuer"},
	{"HostFactoryIssuedDisposition", "HostFactorySignedEnvelope", "original_host_factory_pre_authority_scope_v4", "host_core_issuer"},
	{"HostFactoryHandleCallInventory", "HostFactoryRootSignedEnvelope", "original_host_factory_source_approval_v4", "host_exterior"},
	{"HostFactoryHandleCallInventory", "HostFactoryRootSignedEnvelope", "original_host_factory_root_preparation_v4", "host_exterior"},
	{"HostFactoryHandleCallInventory", "HostFactoryRootSignedEnvelope", "original_host_factory_root_preparation_v4", "host_registrar"},
	{"HostFactoryHandleCallInventory", "HostFactorySignedEnvelope", "original_host_factory_pre_authority_scope_v4", "host_exterior"},
	{"HostFactoryHandleCallInventory", "HostFactorySignedEnvelope", "original_host_factory_pre_authority_scope_v4", "host_registrar"},
	{"HostFactoryHandleCallInventory", "HostFactorySignedEnvelope", "original_host_factory_pre_authority_scope_v4", "host_worker"},
	{"HostFactoryHandleCallInventory", "HostFactoryRootSignedEnvelope", "factory_ordinary_source_binding_v4", "host_exterior"},
	{"HostFactoryHandleCallInventory", "HostFactoryRootSignedEnvelope", "factory_ordinary_source_binding_v4", "host_registrar"},
	{"HostFactoryHandleCallInventory", "HostFactoryRootSignedEnvelope", "factory_ordinary_source_binding_v4", "factory_ordinary_worker"},
	{"HostFactoryNativeObservationRecord", "HostFactoryRootSignedEnvelope", "original_host_factory_root_preparation_v4", "host_exterior"},
	{"HostFactoryNativeObservationRecord", "HostFactoryRootSignedEnvelope", "original_host_factory_root_preparation_v4", "host_registrar"},
	{"HostFactoryNativeObservationRecord", "HostFactorySignedEnvelope", "original_host_factory_pre_authority_scope_v4", "host_exterior"},
	{"HostFactoryNativeObservationRecord", "HostFactorySignedEnvelope", "original_host_factory_pre_authority_scope_v4", "host_registrar"},
	{"HostFactoryNativeObservationRecord", "HostFactoryRootSignedEnvelope", "factory_ordinary_source_binding_v4", "host_exterior"},
	{"HostFactoryNativeObservationRecord", "HostFactoryRootSignedEnvelope", "factory_ordinary_source_binding_v4", "host_registrar"},
	{"HostFactoryNativeObservationManifest", "HostFactoryRootSignedEnvelope", "original_host_factory_root_preparation_v4", "host_exterior"},
	{"HostFactoryNativeObservationManifest", "HostFactoryRootSignedEnvelope", "original_host_factory_root_preparation_v4", "host_registrar"},
	{"HostFactoryNativeObservationManifest", "HostFactorySignedEnvelope", "original_host_factory_pre_authority_scope_v4", "host_exterior"},
	{"HostFactoryNativeObservationManifest", "HostFactorySignedEnvelope", "original_host_factory_pre_authority_scope_v4", "host_registrar"},
	{"HostFactoryNativeObservationManifest", "HostFactoryRootSignedEnvelope", "factory_ordinary_source_binding_v4", "host_exterior"},
	{"HostFactoryNativeObservationManifest", "HostFactoryRootSignedEnvelope", "factory_ordinary_source_binding_v4", "host_registrar"},
}

var hostFactoryDiagnosticStages = []string{"native_alive", "initial_empty", "poststart_empty", "terminal_read", "prepared_create", "root_bootstrap", "registrar_bootstrap", "worker_bootstrap", "ordinary_early_bootstrap", "ordinary_late_grant", "ordinary_early_credential", "root_prepare", "choice_write", "ordinary_before_start", "worker_exterior_join", "registrar_exterior_join", "ordinary_redeem", "worker_start", "registrar_start", "cleanup", "root_completion", "ordinary_bootstrap", "choice_control", "before_original_issue", "issuer_signer_bootstrap"}

// DecodeHostFactory admits only exact original canonical bytes. It assigns the
// target only after the complete closed shape and intrinsic guards pass.
func DecodeHostFactory(raw []byte, target any) error {
	v := reflect.ValueOf(target)
	if v.Kind() != reflect.Pointer || v.IsNil() || !hostFactoryKnown(v.Elem().Type()) || len(raw) == 0 || len(raw) > hostFactoryLimit || !utf8.Valid(raw) {
		return ErrHostFactorySourceRefused
	}
	fresh := reflect.New(v.Elem().Type())
	if hostFactoryShape(raw, v.Elem().Type(), 0) != nil || json.Unmarshal(raw, fresh.Interface()) != nil || ValidateHostFactory(fresh.Interface()) != nil {
		return ErrHostFactorySourceRefused
	}
	encoded, err := json.Marshal(fresh.Interface())
	if err != nil || !bytes.Equal(encoded, raw) {
		return ErrHostFactorySourceRefused
	}
	v.Elem().Set(fresh.Elem())
	return nil
}

func CanonicalHostFactory(value any) ([]byte, error) {
	if ValidateHostFactory(value) != nil {
		return nil, ErrHostFactorySourceRefused
	}
	raw, err := json.Marshal(value)
	if err != nil || len(raw) == 0 || len(raw) > hostFactoryLimit {
		return nil, ErrHostFactorySourceRefused
	}
	return raw, nil
}

func HostFactoryRawSHA256(raw []byte) string {
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}

func hostFactoryKnown(t reflect.Type) bool { _, ok := hostFactorySchemas[t]; return ok }
func hostFactoryShape(raw []byte, t reflect.Type, depth int) error {
	if depth > 48 || len(raw) > hostFactoryLimit {
		return ErrHostFactorySourceRefused
	}
	if t == reflect.TypeOf([]model.HostFactoryNativeAcquiredDescriptor{}) && bytes.Equal(raw, []byte("null")) {
		return nil
	}
	if t.Kind() == reflect.Pointer {
		if bytes.Equal(raw, []byte("null")) {
			return nil
		}
		return hostFactoryShape(raw, t.Elem(), depth+1)
	}
	if bytes.Equal(raw, []byte("null")) {
		return ErrHostFactorySourceRefused
	}
	if t == reflect.TypeOf(time.Time{}) {
		return nil
	}
	switch t.Kind() {
	case reflect.Struct:
		allowed := map[string]bool{}
		for i := 0; i < t.NumField(); i++ {
			tag := strings.Split(t.Field(i).Tag.Get("json"), ",")[0]
			if tag != "" && tag != "-" {
				allowed[tag] = true
			}
		}
		fields, err := NativeCanonicalObject(raw, allowed)
		if err != nil {
			return ErrHostFactorySourceRefused
		}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			tag := strings.Split(f.Tag.Get("json"), ",")[0]
			if tag == "" || tag == "-" {
				continue
			}
			r, ok := fields[tag]
			if !ok {
				if !hostFactoryKnown(t) && strings.Contains(f.Tag.Get("json"), ",omitempty") {
					continue
				}
				return ErrHostFactorySourceRefused
			}
			if hostFactoryShape(r, f.Type, depth+1) != nil {
				return ErrHostFactorySourceRefused
			}
		}
	case reflect.Slice, reflect.Array:
		var items []json.RawMessage
		if json.Unmarshal(raw, &items) != nil || items == nil || len(items) > 4096 || (t.Kind() == reflect.Array && len(items) != t.Len()) {
			return ErrHostFactorySourceRefused
		}
		for _, r := range items {
			if hostFactoryShape(r, t.Elem(), depth+1) != nil {
				return ErrHostFactorySourceRefused
			}
		}
	case reflect.Map, reflect.Interface:
		return ErrHostFactorySourceRefused
	}
	return nil
}

// ValidateHostFactory provides structural/byte consistency, never native
// observation, current lease authority, SQL relation existence or approval.
func ValidateHostFactory(value any) error {
	v := reflect.ValueOf(value)
	if !v.IsValid() {
		return ErrHostFactorySourceRefused
	}
	if v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return ErrHostFactorySourceRefused
		}
		v = v.Elem()
	}
	if !hostFactoryKnown(v.Type()) || hostFactoryValue(v, "", 0) != nil {
		return ErrHostFactorySourceRefused
	}
	raw, err := json.Marshal(value)
	if err != nil || len(raw) > hostFactoryLimit {
		return ErrHostFactorySourceRefused
	}
	return nil
}

func hostFactoryValue(v reflect.Value, name string, depth int) error {
	if depth > 48 {
		return ErrHostFactorySourceRefused
	}
	if v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return nil
		}
		return hostFactoryValue(v.Elem(), name, depth+1)
	}
	if v.Type() == reflect.TypeOf(time.Time{}) {
		t := v.Interface().(time.Time)
		_, offset := t.Zone()
		if t.IsZero() || offset != 0 {
			return ErrHostFactorySourceRefused
		}
		return nil
	}
	switch v.Kind() {
	case reflect.Struct:
		if !hostFactoryKnown(v.Type()) {
			return nil
		} // existing grant/prereg shape is checked separately in the private grant frame
		schema := hostFactorySchemas[v.Type()]
		for i := 0; i < v.NumField(); i++ {
			f := v.Type().Field(i)
			if f.Name == "Schema" && v.Field(i).String() != schema {
				return ErrHostFactorySourceRefused
			}
			if f.Name == "Purpose" && v.Type() != reflect.TypeOf(model.HostFactorySourceAuditReturn{}) && v.Type() != reflect.TypeOf(model.HostFactorySignedEnvelope{}) && v.Type() != reflect.TypeOf(model.HostFactoryRootSignedEnvelope{}) && v.Field(i).String() != schema {
				return ErrHostFactorySourceRefused
			}
			if f.Name == "Role" && (v.Type() == reflect.TypeOf(model.HostFactoryDescriptorSource{}) || v.Type() == reflect.TypeOf(model.HostFactoryBootstrapDescriptorSource{}) || v.Type() == reflect.TypeOf(model.HostFactoryBasalDescriptorSource{})) {
				if !hostFactoryHas(hostFactoryEnums["descriptorRole"], v.Field(i).String()) {
					return ErrHostFactorySourceRefused
				}
				continue
			}
			if f.Name == "Role" && v.Type() == reflect.TypeOf(model.HostFactoryArtifactSource{}) {
				if !hostFactoryHas([]string{"qemu_executable", "original_disk", "seed_image", "source_iso"}, v.Field(i).String()) {
					return ErrHostFactorySourceRefused
				}
				continue
			}
			if v.Type() == reflect.TypeOf(model.HostFactorySourceAuditReturn{}) && f.Name == "Operation" {
				if !hostFactoryHas(hostFactoryEnums["SourceAuditOperation"], v.Field(i).String()) {
					return ErrHostFactorySourceRefused
				}
				continue
			}
			// A retained Fstat struct is an original numeric return, including
			// unlinked or unsupported objects. Positive descriptor users apply
			// their own inode/link/type rules; do not erase diagnostic values.
			if v.Type() == reflect.TypeOf(model.HostFactoryNativeStatReturn{}) && (f.Name == "Size" || f.Name == "LinkCount" || f.Name == "Inode") {
				continue
			}
			if hostFactoryValue(v.Field(i), f.Name, depth+1) != nil {
				return ErrHostFactorySourceRefused
			}
		}
		return hostFactoryIntrinsic(v.Interface())
	case reflect.Slice, reflect.Array:
		if name == "ReturnedDescriptors" && v.Kind() == reflect.Slice && v.IsNil() {
			return nil
		}
		lo, hi := 0, 64
		switch name {
		case "OriginalCalls":
			lo, hi = 1, 16
		case "ChildBodySHAs":
			lo, hi = 1, 16
		case "Operations", "OperationVectors":
			hi = 32
		case "ParsedTIDs":
			lo, hi = 0, 4096
		case "ThreadReads":
			lo, hi = 1, 4096
		case "Observations", "Children":
			hi = 16
		case "AllowedFactoryEntryClasses":
			lo, hi = 1, 3
		case "DiagnosticStageRawSHAs":
			hi = 2048
		}
		if v.Kind() == reflect.Slice && (v.IsNil() || v.Len() < lo || v.Len() > hi) {
			return ErrHostFactorySourceRefused
		}
		seen := map[string]bool{}
		for i := 0; i < v.Len(); i++ {
			if hostFactoryValue(v.Index(i), name, depth+1) != nil {
				return ErrHostFactorySourceRefused
			}
			if v.Index(i).Kind() == reflect.String {
				s := v.Index(i).String()
				if seen[s] {
					return ErrHostFactorySourceRefused
				}
				seen[s] = true
			}
		}
	case reflect.String:
		return hostFactoryString(v.String(), name)
	case reflect.Int, reflect.Int64, reflect.Int32:
		n := v.Int()
		lo, hi := int64(0), int64(536870913)
		switch name {
		case "PID", "PPID", "TID", "OriginalWorkerPID", "SubjectPID", "RequestedPID", "ReturnedPID", "ParsedTIDs":
			lo, hi = 1, 2147483647
		case "ChildPIDs":
			lo, hi = 1, 2147483647
		case "OriginalDescriptorNumber", "InputDescriptorNumber":
			hi = 2147483647
		case "Generation", "Fence":
			lo, hi = 1, 9007199254740991
		case "Slot", "AllowedSlot":
			lo, hi = 1, 64
		case "OriginalStepTimeoutSeconds", "ApprovedProvisioningBudgetSeconds":
			lo, hi = 1, 86400
		case "OriginalExecutableReadBytes":
			lo, hi = 1, 134217728
		case "OriginalCmdlineReadBytes":
			lo, hi = 1, 65536
		case "OriginalRawBytes":
			hi = 65537
		case "OriginalWaitCode":
			hi = 255
		case "OriginalExitCode":
			lo, hi = -1, 255
		case "OriginalScalar":
			lo, hi = -1, 4294967295
		case "RequestedArgument":
			lo, hi = 0, 4294967295
		case "OriginalPIDFDPollRevents", "RegistrarOriginalPollRevents":
			if n != 1 && n != 17 {
				return ErrHostFactorySourceRefused
			}
		case "ExpectedBytes", "OriginalTotalBytes":
			hi = 64
		case "InitialControlLedgerBytes", "OriginalReadBytes", "OriginalWrittenBytes", "OriginalStdoutBytes", "OriginalStderrBytes":
			hi = 65536
		}
		if n < lo || n > hi {
			return ErrHostFactorySourceRefused
		}
	case reflect.Uint, reflect.Uint64, reflect.Uint32:
		n := v.Uint()
		switch name {
		case "StartTicks", "SubjectStartTicks", "ThreadStartTicks", "Inode", "ExecutableInode", "SourceInode", "LinkCount", "ExecutableLinkCount", "SourceLinkCount":
			if n == 0 {
				return ErrHostFactorySourceRefused
			}
		case "Mode", "SourceMode", "ExecutableMode":
			if n > 65535 {
				return ErrHostFactorySourceRefused
			}
		case "DescriptorFlags":
			if n > 1 {
				return ErrHostFactorySourceRefused
			}
		case "FirstOrdinal", "LastOrdinal", "OriginalCallOrdinal", "OriginalCallCount":
			if n > 65536 {
				return ErrHostFactorySourceRefused
			}
		case "OriginalObservationCount", "OriginalCensusOrdinal":
			if n < 1 || n > 4096 {
				return ErrHostFactorySourceRefused
			}
		case "PartOrdinal":
			if n < 1 || n > 2048 {
				return ErrHostFactorySourceRefused
			}
		case "Level":
			if n > 3 {
				return ErrHostFactorySourceRefused
			}
		case "OriginalVectorReferenceCount":
			if n > 32 {
				return ErrHostFactorySourceRefused
			}
		case "OriginalRawBytes":
			if n > 65537 {
				return ErrHostFactorySourceRefused
			}
		case "OriginalErrno":
			if n > 4095 {
				return ErrHostFactorySourceRefused
			}
		case "OriginalPollRevents":
			if n > 65535 {
				return ErrHostFactorySourceRefused
			}
		case "OriginalSourceBytes":
			if n < 1 || n > 536870912 {
				return ErrHostFactorySourceRefused
			}
		}
	case reflect.Bool:
	default:
		return ErrHostFactorySourceRefused
	}
	return nil
}

func hostFactoryHas(values []string, value string) bool {
	for _, s := range values {
		if s == value {
			return true
		}
	}
	return false
}
func hostFactoryIdentifier(s string, limit int) bool {
	if len(s) < 1 || len(s) > limit {
		return false
	}
	for i, c := range []byte(s) {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' {
			continue
		}
		if i > 0 && (c == '_' || c == '.' || c == '-') {
			continue
		}
		return false
	}
	return true
}
func hostFactoryHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for _, c := range []byte(s) {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
func hostFactoryString(s, name string) error {
	if name == "OriginalAcquisitionState" {
		if !hostFactoryHas([]string{"not_acquired", "acquired_held", "original_close_pending", "original_close_returned"}, s) {
			return ErrHostFactorySourceRefused
		}
		return nil
	}
	if name == "OriginalStage" {
		if !hostFactoryHas(hostFactoryDiagnosticStages, s) {
			return ErrHostFactorySourceRefused
		}
		return nil
	}
	if name == "OriginalCallID" || strings.HasSuffix(name, "CallID") {
		parts := strings.Split(s, ":")
		if len(parts) != 2 || !guestUUID(parts[0]) {
			return ErrHostFactorySourceRefused
		}
		n, err := strconv.ParseUint(parts[1], 10, 64)
		if err != nil || n < 1 || n > 65536 || strconv.FormatUint(n, 10) != parts[1] {
			return ErrHostFactorySourceRefused
		}
		return nil
	}
	if hostFactoryUUIDFields[name] || name == "HostBootID" {
		if !guestUUID(s) {
			return ErrHostFactorySourceRefused
		}
		return nil
	}
	if strings.HasSuffix(name, "SHA256") || strings.HasSuffix(name, "SHAs") || name == "ApprovedPeerSourceCODE" || strings.HasSuffix(name, "SourceCommit") {
		n := 64
		if name == "ApprovedPeerSourceCODE" || strings.HasSuffix(name, "SourceCommit") {
			n = 40
		}
		if !hostFactoryHex(s, n) {
			return ErrHostFactorySourceRefused
		}
		return nil
	}
	enum := name
	switch name {
	case "OwnerRole", "ObserverRole":
		enum = "Role"
	case "OriginalCloseClass", "OriginalReturnClass":
		enum = "diagnosticOriginalReturnClass"
	case "FailureCode":
		enum = "failureCode"
	case "RetentionState", "CollectionState":
		enum = "CallCollectionState"
	case "AllowedFactoryEntryClasses":
		enum = "FactoryEntryClass"
	}
	if values, ok := hostFactoryEnums[enum]; ok {
		if !hostFactoryHas(values, s) {
			return ErrHostFactorySourceRefused
		}
		return nil
	}
	if name == "Operation" {
		if _, ok := hostFactoryOperations[s]; !ok && !hostFactoryHas(hostFactoryEnums["BasalOperation"], s) {
			return ErrHostFactorySourceRefused
		}
		return nil
	}
	if name == "BodyBase64" || name == "SignatureBase64" || strings.HasSuffix(name, "RawBase64") {
		b, e := base64.StdEncoding.DecodeString(s)
		if e != nil || len(b) == 0 || len(b) > hostFactoryLimit || base64.StdEncoding.EncodeToString(b) != s {
			return ErrHostFactorySourceRefused
		}
		if name == "SignatureBase64" && len(b) != 64 {
			return ErrHostFactorySourceRefused
		}
		return nil
	}
	if name == "OrdinaryGuardBearer" || name == "MutationBearer" {
		if len(s) == 0 || len(s) > 4096 {
			return ErrHostFactorySourceRefused
		}
		for _, c := range []byte(s) {
			if c < 33 || c > 126 {
				return ErrHostFactorySourceRefused
			}
		}
		return nil
	}
	if name == "CoreAuthorityOrigin" {
		if !strings.HasPrefix(s, "https://127.0.0.1:") || len(s) > 64 {
			return ErrHostFactorySourceRefused
		}
		p, e := strconv.ParseUint(strings.TrimPrefix(s, "https://127.0.0.1:"), 10, 16)
		if e != nil || p == 0 || strconv.FormatUint(p, 10) != strings.TrimPrefix(s, "https://127.0.0.1:") {
			return ErrHostFactorySourceRefused
		}
		return nil
	}
	limit := 128
	if strings.Contains(name, "Namespace") {
		limit = 253
	}
	if strings.HasSuffix(name, "StepID") {
		limit = 64
	}
	if !hostFactoryIdentifier(s, limit) {
		return ErrHostFactorySourceRefused
	}
	return nil
}

func HostFactoryOperationCap(operation string) (int64, error) {
	r, ok := hostFactoryOperations[operation]
	if !ok {
		return 0, ErrHostFactorySourceRefused
	}
	return r.cap, nil
}

func ValidateHostFactoryOperation(operation, ownerRole, subjectRole, stage, bindingSchema, envelopeType string) error {
	r, ok := hostFactoryOperations[operation]
	if !ok {
		return ErrHostFactorySourceRefused
	}
	tuple := [6]string{ownerRole, subjectRole, stage, bindingSchema, envelopeType, operation}
	if len(r.exactCombinations) > 0 {
		for _, c := range r.exactCombinations {
			if c == tuple {
				return nil
			}
		}
		return ErrHostFactorySourceRefused
	}
	ordinary := bindingSchema == "factory_ordinary_source_binding_v4" || ownerRole == "factory_ordinary_worker" || subjectRole == "factory_ordinary_worker"
	if ordinary {
		for _, c := range r.combinations {
			if c == tuple {
				return nil
			}
		}
		return ErrHostFactorySourceRefused
	}
	if len(r.hostCombinations) > 0 {
		for _, c := range r.hostCombinations {
			if c == tuple {
				return nil
			}
		}
		return ErrHostFactorySourceRefused
	}
	if !hostFactoryHas(r.stages, stage) || !hostFactoryHas(r.owners, ownerRole) || !hostFactoryHas(r.subjects, subjectRole) {
		return ErrHostFactorySourceRefused
	}
	expected := "HostFactoryRootSignedEnvelope"
	switch bindingSchema {
	case "original_host_factory_pre_authority_scope_v4":
		expected = "HostFactorySignedEnvelope"
	case "original_host_factory_source_approval_v4", "original_host_factory_root_preparation_v4":
	default:
		return ErrHostFactorySourceRefused
	}
	if expected != envelopeType {
		return ErrHostFactorySourceRefused
	}
	if bindingSchema == "original_host_factory_source_approval_v4" && (ownerRole != "host_exterior" || subjectRole != "host_exterior" && subjectRole != "host_core_issuer") {
		return ErrHostFactorySourceRefused
	}
	if bindingSchema == "original_host_factory_root_preparation_v4" && (ownerRole == "host_worker" || subjectRole == "host_worker") {
		return ErrHostFactorySourceRefused
	}
	if stage == "root_bootstrap" && bindingSchema != "original_host_factory_source_approval_v4" || stage == "registrar_bootstrap" && bindingSchema != "original_host_factory_root_preparation_v4" || stage == "worker_bootstrap" && bindingSchema != "original_host_factory_pre_authority_scope_v4" {
		return ErrHostFactorySourceRefused
	}
	return nil
}

func hostFactoryIntrinsic(value any) error {
	if hostFactoryRepresentationIntrinsic(value) != nil {
		return ErrHostFactorySourceRefused
	}
	if hostFactoryNativeIntrinsic(value) != nil {
		return ErrHostFactorySourceRefused
	}
	fail := ErrHostFactorySourceRefused
	switch x := value.(type) {
	case model.HostFactoryPreAuthorityScope:
		if !hostFactoryHas([]string{"sealed_a0", "sealed_a1"}, x.FactoryEntryClass) || x.ApprovedProvisioningBudgetSeconds > x.OriginalStepTimeoutSeconds || x.OriginalContextDeadline.Sub(x.OriginalContextStartedAt) != 600*time.Second || !x.OriginalLeaseExpiresAt.After(x.OriginalContextStartedAt) || x.OriginalLeaseExpiresAt.After(x.OriginalContextDeadline) {
			return fail
		}
	case model.HostFactorySourceApproval:
		if !x.OriginalApprovalDeadline.After(x.ApprovedAt) || x.AllowedAssessStepID == x.AllowedClaimStepID || x.AllowedOriginalStepID == x.AllowedClaimStepID || x.AllowedOriginalStepID == x.AllowedAssessStepID {
			return fail
		}
	case model.HostFactoryBinaryExecution:
		if x.ExecutionClass != "linux_owned_binary_subprocess_v1" || x.ScriptMode != "none_compiled_binary" || x.ExecutableMode&0170000 != 0100000 || x.ExecutableMode&0111 == 0 || !hostFactoryOrdered(x.OriginalExecutableReadStartedAt, x.OriginalExecutableReadReturnedAt, x.OriginalExecutableCloseReturnedAt) || !hostFactoryOrdered(x.OriginalExecutableReadStartedAt, x.OriginalCmdlineReadReturnedAt, x.OriginalCmdlineCloseReturnedAt) {
			return fail
		}
	case model.HostFactoryDescriptorSource:
		return hostFactoryDescriptor(x.Role, x.Type, x.Mode, x.LinkCount, x.Flags, x.DescriptorFlags)
	case model.HostFactoryBootstrapDescriptorSource:
		return hostFactoryDescriptor(x.Role, x.Type, x.Mode, x.LinkCount, x.Flags, x.DescriptorFlags)
	case model.HostFactoryBasalDescriptorSource:
		if x.Role != "basal_self_pidfd" {
			return fail
		}
		return hostFactoryDescriptor(x.Role, x.Type, x.Mode, x.LinkCount, x.Flags, x.DescriptorFlags)
	case model.HostFactoryNativeProcess:
		operations := [5]string{"boot_id_read", "stat_before_read", "executable_read", "cmdline_read", "stat_after_read"}
		owner := ""
		if !hostFactoryOrdered(x.OriginalNativeReadStartedAt, x.OriginalNativeReadReturnedAt, x.OriginalNativeCloseReturnedAt) {
			return fail
		}
		for i, r := range x.NativeReadOperations {
			if r.Operation != operations[i] || !r.OriginalEOF || r.OriginalReturnClass != "eof" || i > 0 && r.OwnerPrimitiveRawSHA256 != owner {
				return fail
			}
			owner = r.OwnerPrimitiveRawSHA256
			if r.OriginalCalledAt.Before(x.OriginalNativeReadStartedAt) || r.OriginalReturnedAt.After(x.OriginalNativeReadReturnedAt) || r.OriginalCloseReturnedAt.After(x.OriginalNativeCloseReturnedAt) || i > 0 && r.OriginalCalledAt.Before(x.NativeReadOperations[i-1].OriginalCloseReturnedAt) {
				return fail
			}
		}
		before, exe, cmdline, after := x.NativeReadOperations[1], x.NativeReadOperations[2], x.NativeReadOperations[3], x.NativeReadOperations[4]
		if x.OriginalStatBeforeSHA256 != before.OriginalSHA256 || x.OriginalStatAfterSHA256 != after.OriginalSHA256 || x.Execution.ExecutableSHA256 != exe.OriginalSHA256 || int64(x.Execution.OriginalExecutableReadBytes) != exe.OriginalCount || x.Execution.OriginalCmdlineReadSHA256 != cmdline.OriginalSHA256 || int64(x.Execution.OriginalCmdlineReadBytes) != cmdline.OriginalCount || !x.Execution.OriginalExecutableReadStartedAt.Equal(exe.OriginalCalledAt) || !x.Execution.OriginalExecutableReadReturnedAt.Equal(exe.OriginalReturnedAt) || !x.Execution.OriginalExecutableCloseReturnedAt.Equal(exe.OriginalCloseReturnedAt) || !x.Execution.OriginalCmdlineReadReturnedAt.Equal(cmdline.OriginalReturnedAt) || !x.Execution.OriginalCmdlineCloseReturnedAt.Equal(cmdline.OriginalCloseReturnedAt) {
			return fail
		}
	case model.HostFactoryOriginalIOFact:
		r, ok := hostFactoryOperations[x.Operation]
		if !ok || r.kind != "public_byte_read" && r.kind != "public_byte_write" || x.OriginalCount > r.cap || !hostFactoryHas(hostFactoryEnums["OriginalReturnClass"], x.OriginalReturnClass) || !hostFactoryOrdered(x.OriginalCalledAt, x.OriginalReturnedAt, x.OriginalCloseReturnedAt) || x.OriginalReturnedAt.After(x.OriginalOperationDeadline) || x.OriginalCloseReturnedAt.After(x.OriginalOperationDeadline) || x.OriginalCallVector.CollectionState != "complete_original_calls" || x.OriginalCallVector.OriginalCallCount == 0 || x.OriginalCallVector.Operation != x.Operation || x.OriginalCallVector.OriginalHandleID != x.OriginalHandleID || x.OriginalCallVector.SubjectOwnerID != x.SubjectOwnerID || x.OriginalCallVector.OwnerPrimitiveRawSHA256 == nil || *x.OriginalCallVector.OwnerPrimitiveRawSHA256 != x.OwnerPrimitiveRawSHA256 {
			return fail
		}
		if r.kind == "public_byte_read" && (!x.OriginalEOF || x.OriginalReturnClass != "eof") || r.kind == "public_byte_write" && (x.OriginalEOF || x.OriginalReturnClass != "full_write") {
			return fail
		}
		if !hostFactoryClosePair(x.Operation, x.OriginalCloseCallVector.Operation) || x.OriginalCloseCallVector.CollectionState != "complete_original_calls" || x.OriginalCloseCallVector.OriginalCallCount != 1 || x.OriginalCloseCallVector.OriginalHandleID != x.OriginalHandleID || x.OriginalCloseCallVector.OriginalOwnerID != x.OriginalCallVector.OriginalOwnerID || x.OriginalCloseCallVector.SubjectOwnerID != x.SubjectOwnerID || x.OriginalCloseCallVector.OwnerPrimitiveRawSHA256 == nil || *x.OriginalCloseCallVector.OwnerPrimitiveRawSHA256 != x.OwnerPrimitiveRawSHA256 || x.OriginalCloseCallVector.FirstOrdinal <= x.OriginalCallVector.LastOrdinal || x.OriginalCount == 0 && x.OriginalSHA256 != HostFactoryRawSHA256(nil) {
			return fail
		}
	case model.HostFactoryPrimitiveIOReturn:
		return hostFactoryPrimitive(x, false)
	case model.HostFactoryDiagnosticIOFact:
		p := model.HostFactoryPrimitiveIOReturn{Operation: x.Operation, OriginalHandleID: x.OriginalHandleID, OwnerPrimitiveRawSHA256: x.OwnerPrimitiveRawSHA256, OriginalState: x.OriginalState, OriginalCalledAt: x.OriginalCalledAt, OriginalReturnedAt: x.OriginalReturnedAt, OriginalCount: x.OriginalCount, OriginalSHA256: x.OriginalSHA256, OriginalReturnClass: x.OriginalReturnClass, SubjectOwnerID: x.SubjectOwnerID, OriginalOperationDeadline: x.OriginalOperationDeadline, OriginalHashState: x.OriginalHashState, OriginalEOF: x.OriginalEOF}
		if hostFactoryPrimitive(p, true) != nil {
			return fail
		}
		if x.OriginalCloseState == "returned" {
			if x.OriginalCloseReturnedAt == nil || !hostFactoryHas([]string{"success", "io_refused", "unknown"}, x.OriginalCloseClass) {
				return fail
			}
		} else if x.OriginalCloseReturnedAt != nil || x.OriginalCloseClass != "unavailable" {
			return fail
		}
		if x.OriginalCallVector.Operation != x.Operation || x.OriginalCallVector.OriginalHandleID != x.OriginalHandleID || x.OriginalCallVector.SubjectOwnerID != x.SubjectOwnerID || x.OriginalCloseCallVector.OriginalHandleID != x.OriginalHandleID {
			return fail
		}
		if x.OriginalState == "not_called" && x.OriginalCallVector.OriginalCallCount != 0 || x.OriginalState != "not_called" && x.OriginalCallVector.OriginalCallCount == 0 || x.OriginalCloseState == "not_acquired" && x.OriginalCloseCallVector.OriginalCallCount != 0 {
			return fail
		}
		if x.OriginalCloseState == "returned" && x.OriginalCloseCallVector.OriginalCallCount != 1 {
			return fail
		}
	case model.HostFactoryCallVectorReference:
		if x.OriginalCallCount == 0 {
			if x.FirstOrdinal != 0 || x.LastOrdinal != 0 || x.ManifestRootSHA256 != nil || x.CollectionState == "same_original_call_pending" {
				return fail
			}
		} else {
			if x.FirstOrdinal == 0 || x.LastOrdinal < x.FirstOrdinal || x.OriginalCallCount > x.LastOrdinal-x.FirstOrdinal+1 || x.OwnerPrimitiveRawSHA256 == nil || x.ManifestRootSHA256 == nil && x.CollectionState != "incomplete_retention" {
				return fail
			}
		}
	case model.HostFactoryCallVectorChunk:
		if len(x.OriginalCalls) < 1 || len(x.OriginalCalls) > 16 || x.FirstOrdinal < 1 || x.LastOrdinal-x.FirstOrdinal+1 != uint64(len(x.OriginalCalls)) {
			return fail
		}
		pending := false
		for i, p := range x.OriginalCalls {
			if p.OriginalState == "not_called" || p.Operation != x.Operation || p.OriginalHandleID != x.OriginalHandleID || p.OwnerPrimitiveRawSHA256 == nil || *p.OwnerPrimitiveRawSHA256 != x.OwnerPrimitiveRawSHA256 || p.OriginalCallOrdinal == nil || *p.OriginalCallOrdinal != x.FirstOrdinal+uint64(i) || p.OriginalCalledAt == nil || p.OriginalCalledAt.After(x.RecordedAt) || p.OriginalReturnedAt != nil && p.OriginalReturnedAt.After(x.RecordedAt) {
				return fail
			}
			pending = pending || p.OriginalState == "called_pending"
			if i > 0 && (p.SubjectOwnerID != x.OriginalCalls[0].SubjectOwnerID || x.OriginalCalls[i-1].OriginalReturnedAt == nil || p.OriginalCalledAt.Before(*x.OriginalCalls[i-1].OriginalReturnedAt)) {
				return fail
			}
		}
		if pending && len(x.OriginalCalls) != 1 {
			return fail
		}
	case model.HostFactoryCallVectorManifest:
		if x.FirstOrdinal == 0 || x.LastOrdinal < x.FirstOrdinal || x.OriginalCallCount < 1 || x.OriginalCallCount > x.LastOrdinal-x.FirstOrdinal+1 {
			return fail
		}
	case model.HostFactoryBasalCallReturn:
		if x.OriginalReturnClass != "success" || !hostFactoryOrdered(x.OriginalCalledAt, x.OriginalReturnedAt) {
			return fail
		}
		switch x.Operation {
		case "getpid", "getppid":
			if x.OriginalScalar < 1 || x.OriginalScalar > 2147483647 {
				return fail
			}
		case "getuid", "getgid":
			if x.OriginalScalar < 0 || x.OriginalScalar > 4294967295 {
				return fail
			}
		case "pidfd_open_self":
			if x.OriginalScalar < 0 || x.OriginalScalar > 2147483647 {
				return fail
			}
		case "fstat_self_pidfd":
			if x.OriginalScalar != 0 {
				return fail
			}
		case "fcntl_getfl_self_pidfd":
			if x.OriginalScalar&3 != 2 || x.OriginalScalar & ^int64(3|0x8000) != 0 {
				return fail
			}
		case "fcntl_getfd_self_pidfd":
			if x.OriginalScalar != 1 {
				return fail
			}
		default:
			return fail
		}
	case model.HostFactoryBasalOwnerObservation:
		if x.OriginalContextDeadline.Sub(x.OriginalContextStartedAt) != 600*time.Second {
			return fail
		}
		for i, c := range x.Calls {
			if c.Operation != hostFactoryEnums["BasalOperation"][i] || c.OriginalCalledAt.Before(x.OriginalContextStartedAt) || c.OriginalReturnedAt.After(x.OriginalContextDeadline) || i > 0 && c.OriginalCalledAt.Before(x.Calls[i-1].OriginalReturnedAt) {
				return fail
			}
		}
		if x.Calls[4].OriginalScalar != int64(x.OriginalSelfPIDFDSource.OriginalDescriptorNumber) || x.Calls[6].OriginalScalar != int64(x.OriginalSelfPIDFDSource.Flags) || x.Calls[7].OriginalScalar != int64(x.OriginalSelfPIDFDSource.DescriptorFlags) {
			return fail
		}
	case model.HostFactoryBootstrapSegmentReturn:
		r, ok := hostFactoryOperations[x.Operation]
		if !ok || r.cap != int64(x.ExpectedBytes) || x.ExpectedBytes != 32 && x.ExpectedBytes != 64 || x.OriginalTotalBytes != x.ExpectedBytes || x.OriginalCallVector.Operation != x.Operation || x.OriginalCallVector.OriginalHandleID != x.OriginalHandleID || x.OriginalCallVector.CollectionState != "complete_original_calls" || x.OriginalCallVector.OriginalCallCount == 0 || x.OriginalCallVector.OwnerPrimitiveRawSHA256 == nil || *x.OriginalCallVector.OwnerPrimitiveRawSHA256 != x.OwnerPrimitiveRawSHA256 {
			return fail
		}
		if strings.HasPrefix(r.kind, "private_") {
			if x.OriginalSegmentHashState != "private_withheld" || x.OriginalSegmentSHA256 != nil {
				return fail
			}
		} else if x.OriginalSegmentHashState != "actual_public_bytes" || x.OriginalSegmentSHA256 == nil {
			return fail
		}
	case model.HostFactoryBootstrapReturn:
		eof, close := "bootstrap_eof_read", "bootstrap_reader_close"
		actor := map[string]string{"original_host_factory_source_approval_v4": "host_exterior", "original_host_factory_root_preparation_v4": "host_registrar", "original_host_factory_pre_authority_scope_v4": "host_worker", "factory_ordinary_source_binding_v4": "factory_ordinary_worker"}[x.BootstrapBindingSchema]
		if actor == "" || x.Role != actor || x.OriginalBootstrapSource.Role != "bootstrap_reader" {
			return fail
		}
		if x.BootstrapBindingSchema == "original_host_factory_source_approval_v4" {
			if x.OriginalBootstrapSource.Type != "regular" {
				return fail
			}
		} else if x.OriginalBootstrapSource.Type != "pipe" {
			return fail
		}
		if x.BootstrapBindingSchema == "factory_ordinary_source_binding_v4" {
			eof, close = "ordinary_bootstrap_eof_read", "ordinary_bootstrap_reader_close"
			if x.Role != "factory_ordinary_worker" {
				return fail
			}
		}
		if !hostFactoryBootstrapSegments(x.SegmentReturns, "read", x.OwnerPrimitiveRawSHA256) || x.OriginalEOFReturn.Operation != eof || x.OriginalEOFReturn.OriginalState != "returned" || x.OriginalEOFReturn.OriginalCount == nil || *x.OriginalEOFReturn.OriginalCount != 0 || x.OriginalEOFReturn.OriginalEOF == nil || !*x.OriginalEOFReturn.OriginalEOF || x.OriginalEOFReturn.OriginalReturnClass != "eof" || x.OriginalBootstrapCloseReturn.Operation != close || x.OriginalBootstrapCloseReturn.OriginalState != "returned" || x.OriginalBootstrapCloseReturn.OriginalReturnClass != "success" {
			return fail
		}
		if x.OriginalEOFReturn.OriginalHandleID != x.SegmentReturns[0].OriginalHandleID || x.OriginalBootstrapCloseReturn.OriginalHandleID != x.SegmentReturns[0].OriginalHandleID || x.OriginalEOFReturn.OwnerPrimitiveRawSHA256 == nil || *x.OriginalEOFReturn.OwnerPrimitiveRawSHA256 != x.OwnerPrimitiveRawSHA256 || x.OriginalBootstrapCloseReturn.OwnerPrimitiveRawSHA256 == nil || *x.OriginalBootstrapCloseReturn.OwnerPrimitiveRawSHA256 != x.OwnerPrimitiveRawSHA256 || x.OriginalEOFReturn.OriginalReturnedAt.After(x.OriginalEOFReturn.OriginalOperationDeadline) || x.OriginalBootstrapCloseReturn.OriginalReturnedAt.After(x.OriginalBootstrapCloseReturn.OriginalOperationDeadline) || !hostFactoryOrdered(x.SegmentReturns[2].OriginalReturnedAt, *x.OriginalEOFReturn.OriginalReturnedAt, *x.OriginalBootstrapCloseReturn.OriginalReturnedAt, x.OriginalPrivateConsumerReturnedAt) {
			return fail
		}
		if x.OriginalBootstrapSource.OwnerPrimitiveRawSHA256 != x.OwnerPrimitiveRawSHA256 || !hostFactoryBootstrapPrimaryVector(x.OriginalEOFReturn, x.SegmentReturns[0].OriginalCallVector, x.OwnerPrimitiveRawSHA256) || !hostFactoryBootstrapPrimaryVector(x.OriginalBootstrapCloseReturn, x.SegmentReturns[0].OriginalCallVector, x.OwnerPrimitiveRawSHA256) || x.OriginalEOFReturn.OriginalCallVector.FirstOrdinal <= x.SegmentReturns[2].OriginalCallVector.LastOrdinal || x.OriginalBootstrapCloseReturn.OriginalCallVector.FirstOrdinal <= x.OriginalEOFReturn.OriginalCallVector.LastOrdinal {
			return fail
		}
	case model.HostFactoryBootstrapWriteReturn:
		for _, segment := range x.SegmentReturns {
			if segment.OriginalCallVector.SubjectOwnerID != x.RecipientOwnerID {
				return fail
			}
		}
		if x.OriginalWriterCloseReturn.SubjectOwnerID != x.RecipientOwnerID || x.OriginalWriterCloseReturn.OriginalCallVector.SubjectOwnerID != x.RecipientOwnerID {
			return fail
		}
		close := "bootstrap_writer_close"
		if x.BindingSchema == "factory_ordinary_source_binding_v4" {
			close = "ordinary_bootstrap_writer_close"
		}
		if !hostFactoryBootstrapSegments(x.SegmentReturns, "write", x.WriterPrimitiveRawSHA256) || x.OriginalWriterCloseReturn.Operation != close || x.OriginalWriterCloseReturn.OriginalState != "returned" || x.OriginalWriterCloseReturn.OriginalReturnClass != "success" {
			return fail
		}
		if x.OriginalWriterSource.Role != "bootstrap_writer" || x.OriginalWriterCloseReturn.OriginalHandleID != x.SegmentReturns[0].OriginalHandleID || x.OriginalWriterCloseReturn.OwnerPrimitiveRawSHA256 == nil || *x.OriginalWriterCloseReturn.OwnerPrimitiveRawSHA256 != x.WriterPrimitiveRawSHA256 || x.OriginalWriterCloseReturn.OriginalReturnedAt.Before(x.SegmentReturns[2].OriginalReturnedAt) || x.OriginalWriterCloseReturn.OriginalReturnedAt.After(x.OriginalWriterCloseReturn.OriginalOperationDeadline) {
			return fail
		}
		if x.OriginalWriterSource.OwnerPrimitiveRawSHA256 != x.WriterPrimitiveRawSHA256 || !hostFactoryBootstrapPrimaryVector(x.OriginalWriterCloseReturn, x.SegmentReturns[0].OriginalCallVector, x.WriterPrimitiveRawSHA256) || x.OriginalWriterCloseReturn.OriginalCallVector.FirstOrdinal <= x.SegmentReturns[2].OriginalCallVector.LastOrdinal {
			return fail
		}
	case model.HostFactoryNativeLeaf:
		if x.ObserverRole == x.Role || !hostFactoryHas([]string{"host_exterior", "host_registrar"}, x.ObserverRole) || x.Process.ObservationKind != "process" || x.OriginalTaskInventoryRead.ObservationKind != "task_directory" || x.Process.SubjectPrimitiveRawSHA256 != x.SubjectPrimitiveRawSHA256 || x.Process.ObserverPrimitiveRawSHA256 != x.ObserverPrimitiveRawSHA256 || x.OriginalTaskInventoryRead.ObserverPrimitiveRawSHA256 != x.ObserverPrimitiveRawSHA256 || x.Process.SubjectOwnerID != x.OriginalTaskInventoryRead.SubjectOwnerID || x.OriginalSubjectPinSource != nil && x.OriginalSubjectPinSource.OwnerPrimitiveRawSHA256 != x.ObserverPrimitiveRawSHA256 {
			return fail
		}
	case model.HostFactoryNativeThreadChildRead:
		seen := map[int]bool{}
		for _, pid := range x.ChildPIDs {
			if seen[pid] {
				return fail
			}
			seen[pid] = true
		}
	case model.HostFactoryPreparedCreatePlan:
		roles := [4]string{"qemu_executable", "original_disk", "seed_image", "source_iso"}
		for i, a := range x.OriginalArtifacts {
			if a.Role != roles[i] || a.OriginalSourceReadReturnedAt.After(x.PreparedAt) || a.OriginalSourceCloseReturnedAt.After(x.PreparedAt) {
				return fail
			}
		}
		if x.OriginalArtifacts[0].OriginalSourceBytes > 134217728 || x.ExecutableStartAnchorSource.Role != "qemu_start_executable_anchor" || x.ExecutableStartAnchorSource.Device != x.OriginalArtifacts[0].SourceDevice || x.ExecutableStartAnchorSource.Inode != x.OriginalArtifacts[0].SourceInode || x.ExecutableStartAnchorSource.OwnerPrimitiveRawSHA256 != x.OwnerPrimitiveRawSHA256 {
			return fail
		}
	case model.HostFactoryArtifactSource:
		if x.SourceMode&0170000 != 0100000 || x.SourceLinkCount != 1 || !hostFactoryOrdered(x.OriginalSourceReadStartedAt, x.OriginalSourceReadReturnedAt, x.OriginalSourceCloseReturnedAt) {
			return fail
		}
	case model.HostFactoryUnissuedChoiceReservation:
		if !x.OriginalChoiceDeadline.After(x.ReservedAt) {
			return fail
		}
	case model.HostFactoryIssuedChoiceReservation:
		if !x.OriginalChoiceDeadline.After(x.ReservedAt) {
			return fail
		}
	case model.HostFactoryChoiceReturn:
		if !hostFactoryHas([]string{"original_host_factory_unissued_choice_body_v4", "original_host_factory_issued_choice_body_v4"}, x.ChoiceBodySchema) || x.OriginalWrittenBytes < 1 || x.ChoiceBodySHA256 != x.OriginalWrittenSHA256 || x.OriginalGateSource.Role != "gate_file" || x.OriginalDirectorySource.Role != "gate_directory" || !hostFactoryOrdered(x.OriginalWriteStartedAt, x.OriginalWriteReturnedAt, x.OriginalFileSyncReturnedAt, x.OriginalFileCloseReturnedAt, x.OriginalDirectorySyncReturnedAt, x.OriginalDirectoryCloseReturnedAt) {
			return fail
		}
	case model.HostFactoryOriginalStartReturn:
		if x.Exterior.ObservationKind != "process" || !hostFactoryOrdered(x.OriginalWorkerStartCalledAt, x.OriginalWorkerStartReturnedAt, x.OriginalPIDFDPinStartedAt, x.OriginalPIDFDPinReturnedAt) {
			return fail
		}
	case model.HostFactoryAliveNativeRead:
		if x.Worker.ObservationKind != "process" || x.Exterior.ObservationKind != "process" || x.Registrar.ObservationKind != "process" || !hostFactoryOrdered(x.RegistrarPinStartedAt, x.RegistrarPinReturnedAt, x.OriginalReadReturnedAt, x.OriginalReadCloseReturnedAt, x.ObservedAt) || !hostFactoryOrdered(x.OriginalReadStartedAt, x.OriginalReadReturnedAt) {
			return fail
		}
	case model.HostFactoryExteriorJoin:
		if x.Exterior.ObservationKind != "process" || x.OriginalWaitCode != 0 || !x.OriginalStdoutEOF || !x.OriginalStderrEOF || !hostFactoryOrdered(x.OriginalStdoutReadStartedAt, x.OriginalStdoutReadReturnedAt, x.OriginalStdoutCloseReturnedAt, x.RecordedAt) || !hostFactoryOrdered(x.OriginalStderrReadStartedAt, x.OriginalStderrReadReturnedAt, x.OriginalStderrCloseReturnedAt, x.RecordedAt) || !hostFactoryOrdered(x.OriginalWaitReturnedAt, x.OriginalPIDFDPollReturnedAt, x.OriginalPIDFDCloseReturnedAt, x.RecordedAt) {
			return fail
		}
	case model.HostFactoryTerminalRead:
		if x.ReaderBefore.ObservationKind != "process" || x.ReaderAfter.ObservationKind != "process" || x.ExteriorBefore.ObservationKind != "process" || x.ExteriorAfter.ObservationKind != "process" || x.ChoiceBodySHA256 != x.OriginalReadSHA256 || x.OriginalReadBytes < 1 || !hostFactoryOrdered(x.RegistrarOriginalPollReturnedAt, x.RegistrarOriginalPinCloseReturnedAt, x.ObservedAt) || !hostFactoryOrdered(x.OriginalReadStartedAt, x.OriginalReadReturnedAt, x.OriginalFileCloseReturnedAt, x.OriginalDirectoryCloseReturnedAt, x.ObservedAt) {
			return fail
		}
	case model.HostFactoryInitialEmptyRealmRead:
		if x.ControlBefore.ObservationKind != "process" || x.ControlAfter.ObservationKind != "process" || x.RegistrarBefore.ObservationKind != "process" || x.RegistrarAfter.ObservationKind != "process" || !hostFactoryOrdered(x.OriginalReadStartedAt, x.OriginalReadReturnedAt, x.OriginalReadCloseReturnedAt, x.ObservedAt) {
			return fail
		}
	case model.HostFactoryOriginalEmptyRealmRead:
		if x.ControlProcessBefore.ObservationKind != "process" || x.ControlProcessAfter.ObservationKind != "process" || x.WorkerBefore.ObservationKind != "process" || x.WorkerAfter.ObservationKind != "process" || !hostFactoryOrdered(x.OriginalReadStartedAt, x.OriginalReadReturnedAt, x.OriginalReadCloseReturnedAt, x.ObservedAt) {
			return fail
		}
	case model.HostFactoryOriginalLeaseProvenance:
		if x.ExecutorID != x.OriginalProtectedInvocationID || !hostFactoryOrdered(x.OriginalClaimReturnedAt, x.CurrentLeaseReadReturnedAt, x.OriginalLeaseExpiresAt) {
			return fail
		}
	case model.HostFactoryIssuedAttachment:
		if !hostFactoryOrdered(x.OriginalReservedAt, x.AttachedAt) || x.OriginalCreateGrantExpiresAt.Sub(x.OriginalReservedAt) > 60*time.Second || !x.OriginalCreateGrantExpiresAt.After(x.OriginalReservedAt) || !x.OriginalProvisioningDeadline.After(x.OriginalReservedAt) {
			return fail
		}
	case model.HostFactoryRootPreparation:
		if x.OriginalContextDeadline.Sub(x.OriginalContextStartedAt) != 600*time.Second || x.RootDirectorySource.Role != "gate_directory" || x.OriginalIssuerSigningKeyReadReturns[0].Operation != "issuer_signing_key64_read" || x.OriginalIssuerSigningKeyReadReturns[1].Operation != "issuer_signing_key_eof_read" || x.OriginalIssuerSigningKeyReadReturns[2].Operation != "issuer_signing_key_close" {
			return fail
		}
		if !hostFactoryIssuerKeyReturns(x) {
			return fail
		}
	case model.HostFactoryFailureDiagnostic:
		if x.OriginalContextDeadline.Sub(x.OriginalContextStartedAt) != 600*time.Second || x.OriginalOperationDeadline.After(x.OriginalContextDeadline) || x.PartOrdinal == 1 && x.PreviousPartRawSHA256 != nil || x.PartOrdinal > 1 && x.PreviousPartRawSHA256 == nil || int(x.OriginalVectorReferenceCount) != len(x.Operations) {
			return fail
		}
		if x.OriginalRecordState == "original_bytes_read" {
			if x.OriginalRecordSHA256 == nil || x.OriginalRawBytes == nil || *x.OriginalRawBytes == 0 && *x.OriginalRecordSHA256 != HostFactoryRawSHA256(nil) {
				return fail
			}
		} else if x.OriginalRecordSHA256 != nil || x.OriginalRawBytes != nil {
			return fail
		}
		if x.RetentionState == "complete_original_calls" && !x.FinalPart {
			return fail
		}
		seen := map[[2]string]bool{}
		for _, r := range x.Operations {
			id := [2]string{r.Operation, r.OriginalHandleID}
			if seen[id] || x.RetentionState == "complete_original_calls" && r.CollectionState != "complete_original_calls" {
				return fail
			}
			seen[id] = true
		}
	case model.FactoryOrdinaryCredentialFrame:
		if x.OrdinaryGuardBearer == x.MutationBearer {
			return fail
		}
	case model.FactoryOrdinaryGrantFrame:
		return hostFactoryGrantFrame(x)
	}
	return nil
}

func hostFactoryOrdered(ts ...time.Time) bool {
	for i, t := range ts {
		if t.IsZero() || i > 0 && t.Before(ts[i-1]) {
			return false
		}
	}
	return true
}

// Each pairing names the actual operation family that can close this handle.
// The enclosing source/binding/stage consumer still verifies the exact122
// operation tuple; a Wait, Poll, signal or arbitrary nonbyte record is no Close.
func hostFactoryClosePair(operation, close string) bool {
	switch operation {
	case "boot_id_read", "stat_before_read", "stat_after_read", "executable_read", "cmdline_read", "task_inventory_read", "thread_stat_before_read", "thread_stat_after_read", "thread_children_read", "descriptor_fdinfo_read", "source_approval_read", "initial_ledger_read":
		return close == "native_reader_close"
	case "qemu_executable_read", "original_disk_read", "seed_image_read", "source_iso_read":
		return close == "artifact_reader_close"
	case "stdout_read":
		return close == "stdout_close"
	case "stderr_read":
		return close == "stderr_close"
	case "gate_read":
		return close == "terminal_gate_close" || close == "native_reader_close"
	case "bootstrap_challenge32_read", "bootstrap_binding_digest32_read", "bootstrap_eof_read":
		return close == "bootstrap_reader_close" || close == "ordinary_bootstrap_reader_close"
	case "ordinary_bootstrap_prefix_read", "ordinary_bootstrap_eof_read":
		return close == "ordinary_bootstrap_reader_close"
	case "ordinary_credential_prefix_read", "ordinary_credential_eof_read":
		return close == "ordinary_credential_reader_close"
	case "ordinary_grant_prefix_read", "ordinary_grant_eof_read":
		return close == "ordinary_grant_reader_close"
	case "ordinary_guard_before_read", "ordinary_guard_after_read", "ordinary_guard_before_start_read", "ordinary_redeem_response_read":
		return close == "ordinary_http_body_close"
	case "control_frame_read":
		return close == "control_reader_close"
	case "initial_ledger_write":
		return close == "initial_ledger_close"
	case "choice_body_write":
		return close == "gate_file_close"
	case "ordinary_dispatch_write":
		return close == "ordinary_dispatch_close"
	case "control_frame_write":
		return close == "control_writer_close"
	case "bootstrap_challenge32_write", "bootstrap_binding_digest32_write":
		return close == "bootstrap_writer_close" || close == "ordinary_bootstrap_writer_close"
	case "ordinary_bootstrap_prefix_write":
		return close == "ordinary_bootstrap_writer_close"
	case "ordinary_credential_prefix_write":
		return close == "ordinary_credential_writer_close"
	case "ordinary_grant_prefix_write":
		return close == "ordinary_grant_writer_close"
	default:
		return false
	}
}

func hostFactoryIssuerKeyReturns(x model.HostFactoryRootPreparation) bool {
	key, eof, close := x.OriginalIssuerSigningKeyReadReturns[0], x.OriginalIssuerSigningKeyReadReturns[1], x.OriginalIssuerSigningKeyReadReturns[2]
	source := x.OriginalIssuerSigningKeySource
	if source.Type != "regular" || source.Mode != 0100600 || source.LinkCount != 1 || source.Flags&3 != 0 || source.Flags&0x20000 == 0 || source.DescriptorFlags != 1 || source.OwnerPrimitiveRawSHA256 != x.CoreBasalOwnerRawSHA256 {
		return false
	}
	for i, r := range x.OriginalIssuerSigningKeyReadReturns {
		ref := r.OriginalCallVector
		if r.OriginalState != "returned" || r.OriginalCalledAt == nil || r.OriginalReturnedAt == nil || r.OriginalCalledAt.Before(x.OriginalContextStartedAt) || r.OriginalReturnedAt.After(x.OriginalContextDeadline) || r.OriginalReturnedAt.After(r.OriginalOperationDeadline) || r.OriginalOperationDeadline.After(x.OriginalContextDeadline) || r.OwnerPrimitiveRawSHA256 == nil || *r.OwnerPrimitiveRawSHA256 != x.CoreBasalOwnerRawSHA256 || ref.OwnerPrimitiveRawSHA256 == nil || *ref.OwnerPrimitiveRawSHA256 != x.CoreBasalOwnerRawSHA256 || ref.CollectionState != "complete_original_calls" || ref.OriginalCallCount == 0 || r.OriginalHandleID != key.OriginalHandleID || r.SubjectOwnerID != key.SubjectOwnerID || ref.OriginalOwnerID != key.OriginalCallVector.OriginalOwnerID || r.OriginalCloseCallVector.OriginalCallCount != 0 || r.OriginalCloseState == "returned" {
			return false
		}
		if i > 0 && (r.OriginalCalledAt.Before(*x.OriginalIssuerSigningKeyReadReturns[i-1].OriginalReturnedAt) || ref.FirstOrdinal <= x.OriginalIssuerSigningKeyReadReturns[i-1].OriginalCallVector.LastOrdinal) {
			return false
		}
	}
	if key.OriginalCalledAt.Before(source.OriginalFstatReturnedAt) || key.OriginalCount == nil || *key.OriginalCount != 64 || key.OriginalSHA256 != nil || key.OriginalHashState != "private_withheld" || key.OriginalReturnClass != "success" || key.OriginalEOF == nil || *key.OriginalEOF {
		return false
	}
	if eof.OriginalCount == nil || *eof.OriginalCount != 0 || eof.OriginalSHA256 != nil || eof.OriginalHashState != "private_withheld" || eof.OriginalReturnClass != "eof" || eof.OriginalEOF == nil || !*eof.OriginalEOF {
		return false
	}
	if close.OriginalCount != nil || close.OriginalSHA256 != nil || close.OriginalHashState != "not_byte_operation" || close.OriginalReturnClass != "success" || close.OriginalEOF != nil || close.OriginalCallVector.OriginalCallCount != 1 {
		return false
	}
	return true
}
func hostFactorySameProcess(a, b model.HostFactoryNativeProcess) bool {
	return a.HostBootID == b.HostBootID && a.PID == b.PID && a.PPID == b.PPID && a.StartTicks == b.StartTicks && a.UID == b.UID && a.GID == b.GID && a.ProcessNonceSHA256 == b.ProcessNonceSHA256 && a.BootstrapReturnSHA256 == b.BootstrapReturnSHA256 && a.Execution.ActualBinarySourceCommit == b.Execution.ActualBinarySourceCommit && a.Execution.ExecutableDevice == b.Execution.ExecutableDevice && a.Execution.ExecutableInode == b.Execution.ExecutableInode && a.Execution.ExecutableSHA256 == b.Execution.ExecutableSHA256 && a.Execution.FixedArgvSHA256 == b.Execution.FixedArgvSHA256
}
func hostFactoryBootstrapSegments(v [3]model.HostFactoryBootstrapSegmentReturn, direction, owner string) bool {
	ops := [3]string{"bootstrap_challenge32_", "bootstrap_key64_", "bootstrap_binding_digest32_"}
	sizes := [3]int{32, 64, 32}
	for i, r := range v {
		if r.Operation != ops[i]+direction || r.ExpectedBytes != sizes[i] || r.OwnerPrimitiveRawSHA256 != owner || i > 0 && r.OriginalHandleID != v[0].OriginalHandleID {
			return false
		}
		if r.OriginalCallVector.OriginalOwnerID != v[0].OriginalCallVector.OriginalOwnerID || r.OriginalCallVector.SubjectOwnerID != v[0].OriginalCallVector.SubjectOwnerID || r.OriginalCallVector.OwnerPrimitiveRawSHA256 == nil || *r.OriginalCallVector.OwnerPrimitiveRawSHA256 != owner || i > 0 && (r.OriginalCallVector.FirstOrdinal <= v[i-1].OriginalCallVector.LastOrdinal || r.OriginalReturnedAt.Before(v[i-1].OriginalReturnedAt)) {
			return false
		}
	}
	return true
}

func hostFactoryBootstrapPrimaryVector(f model.HostFactoryDiagnosticIOFact, segment model.HostFactoryCallVectorReference, basal string) bool {
	r := f.OriginalCallVector
	return r.CollectionState == "complete_original_calls" && r.OriginalCallCount > 0 && r.OriginalHandleID == segment.OriginalHandleID && r.OriginalOwnerID == segment.OriginalOwnerID && r.SubjectOwnerID == segment.SubjectOwnerID && r.OwnerPrimitiveRawSHA256 != nil && *r.OwnerPrimitiveRawSHA256 == basal && f.OriginalCloseCallVector.OriginalCallCount == 0 && f.OriginalCloseState != "returned"
}
func hostFactoryDescriptor(role, kind string, mode uint32, links uint64, flags, descriptorFlags uint32) error {
	if !hostFactoryHas(hostFactoryEnums["descriptorRole"], role) || flags & ^uint32(3|0x800|0x8000|0x10000|0x20000) != 0 {
		return ErrHostFactorySourceRefused
	}
	access := flags & 3
	if strings.Contains(role, "pidfd") {
		if kind != "pidfd" || access != 2 || flags & ^uint32(3|0x8000) != 0 || descriptorFlags != 1 {
			return ErrHostFactorySourceRefused
		}
		return nil
	}
	if flags&0x800 == 0 && role != "stdout_writer" && role != "stderr_writer" {
		return ErrHostFactorySourceRefused
	}
	switch role {
	case "gate_file":
		if kind != "regular" || mode != 0100600 || links != 1 || flags&0x20000 == 0 || access != 0 && access != 1 || descriptorFlags != 1 {
			return ErrHostFactorySourceRefused
		}
	case "gate_directory":
		if kind != "directory" || mode != 0040700 || flags&0x30000 != 0x30000 || access != 0 || descriptorFlags != 1 {
			return ErrHostFactorySourceRefused
		}
	case "qemu_start_executable_anchor", "executable_reader", "cmdline_reader":
		if kind != "regular" || access != 0 || descriptorFlags != 1 {
			return ErrHostFactorySourceRefused
		}
	case "bootstrap_reader":
		if kind == "regular" {
			if mode != 0100600 || links != 1 || flags&0x20000 == 0 || access != 0 || descriptorFlags != 1 {
				return ErrHostFactorySourceRefused
			}
			return nil
		}
		if kind != "pipe" || access != 0 || descriptorFlags != 0 {
			return ErrHostFactorySourceRefused
		}
	default:
		if kind != "pipe" {
			return ErrHostFactorySourceRefused
		}
		writer := strings.HasSuffix(role, "writer")
		if writer && access != 1 || !writer && access != 0 {
			return ErrHostFactorySourceRefused
		}
		if writer && descriptorFlags != 1 && role != "stdout_writer" && role != "stderr_writer" {
			return ErrHostFactorySourceRefused
		}
	}
	return nil
}

func hostFactoryPrimitive(x model.HostFactoryPrimitiveIOReturn, aggregate bool) error {
	r, ok := hostFactoryOperations[x.Operation]
	if !ok {
		return ErrHostFactorySourceRefused
	}
	if x.OriginalState == "not_called" {
		if x.OriginalNativeReturn != nil {
			return ErrHostFactorySourceRefused
		}
		if x.OriginalCalledAt != nil || x.OriginalReturnedAt != nil || x.OriginalCount != nil || x.OriginalSHA256 != nil || x.OriginalEOF != nil || x.OriginalCallOrdinal != nil || x.OriginalCallID != nil || x.OriginalReturnClass != "unavailable" || x.OriginalHashState != "unknown_original_bytes" {
			return ErrHostFactorySourceRefused
		}
		return nil
	}
	if x.OriginalCalledAt == nil {
		return ErrHostFactorySourceRefused
	}
	if !aggregate {
		if x.OriginalCallOrdinal == nil || *x.OriginalCallOrdinal < 1 || x.OriginalCallID == nil || *x.OriginalCallID != x.OriginalHandleID+":"+strconv.FormatUint(*x.OriginalCallOrdinal, 10) {
			return ErrHostFactorySourceRefused
		}
		if !strings.HasSuffix(x.Operation, "_close") && *x.OriginalCallOrdinal >= 65536 {
			return ErrHostFactorySourceRefused
		} // original handle slot65536 is reserved for Close
	}
	if x.OriginalState == "called_pending" {
		if x.OriginalNativeReturn != nil && x.OriginalNativeReturn.OriginalErrorPresent != nil {
			return ErrHostFactorySourceRefused
		}
		if x.OriginalNativeReturn != nil && hostFactoryNativeOperation(x.Operation, *x.OriginalNativeReturn) != nil {
			return ErrHostFactorySourceRefused
		}
		if x.OriginalReturnedAt != nil || x.OriginalCount != nil || x.OriginalSHA256 != nil || x.OriginalEOF != nil || x.OriginalReturnClass != "unavailable" || x.OriginalHashState != "unknown_original_bytes" {
			return ErrHostFactorySourceRefused
		}
		return nil
	}
	if x.OriginalState != "returned" || x.OriginalReturnedAt == nil || x.OriginalReturnedAt.Before(*x.OriginalCalledAt) || !hostFactoryHas(r.returns, x.OriginalReturnClass) {
		return ErrHostFactorySourceRefused
	}
	if r.kind == "nonbyte" || r.kind == "native_scalar" || r.kind == "native_stat" || r.kind == "native_descriptor" {
		if !aggregate {
			if x.OriginalNativeReturn == nil || x.OriginalNativeReturn.OriginalErrorPresent == nil || hostFactoryNativeOperation(x.Operation, *x.OriginalNativeReturn) != nil {
				return ErrHostFactorySourceRefused
			}
			if x.OriginalReturnClass == "success" && *x.OriginalNativeReturn.OriginalErrorPresent {
				return ErrHostFactorySourceRefused
			}
		}
		if x.OriginalCount != nil || x.OriginalSHA256 != nil || x.OriginalEOF != nil || x.OriginalHashState != "not_byte_operation" {
			return ErrHostFactorySourceRefused
		}
		return nil
	}
	if r.kind == "native_directory_bytes" {
		if aggregate || x.OriginalNativeReturn == nil || x.OriginalNativeReturn.Kind != "unix_getdents64" || x.OriginalNativeReturn.OriginalErrorPresent == nil || x.OriginalNativeReturn.OriginalScalar == nil || x.OriginalEOF == nil || *x.OriginalEOF {
			return ErrHostFactorySourceRefused
		}
		n := *x.OriginalNativeReturn.OriginalScalar
		if *x.OriginalNativeReturn.OriginalErrorPresent {
			if x.OriginalCount != nil || x.OriginalSHA256 != nil || x.OriginalHashState != "unknown_original_bytes" || x.OriginalReturnClass == "success" || x.OriginalReturnClass == "native_zero_return" {
				return ErrHostFactorySourceRefused
			}
			return nil
		}
		if n < 0 || n > 65536 || x.OriginalCount == nil || *x.OriginalCount != n || x.OriginalHashState != "actual_public_bytes" || x.OriginalSHA256 == nil || n == 0 && (*x.OriginalSHA256 != HostFactoryRawSHA256(nil) || x.OriginalReturnClass != "native_zero_return") || n > 0 && x.OriginalReturnClass == "native_zero_return" {
			return ErrHostFactorySourceRefused
		}
		return nil
	}
	cap := r.cap + 1
	if !aggregate && cap > 65536 {
		cap = 65536
	}
	if x.OriginalCount == nil || *x.OriginalCount < 0 || *x.OriginalCount > cap {
		return ErrHostFactorySourceRefused
	}
	if x.OriginalNativeReturn != nil {
		return ErrHostFactorySourceRefused
	}
	read := strings.HasSuffix(r.kind, "read")
	if read {
		if x.OriginalEOF == nil || *x.OriginalEOF != (x.OriginalReturnClass == "eof") {
			return ErrHostFactorySourceRefused
		}
	} else if x.OriginalEOF != nil {
		return ErrHostFactorySourceRefused
	}
	if strings.HasPrefix(r.kind, "private_") {
		if x.OriginalHashState != "private_withheld" || x.OriginalSHA256 != nil {
			return ErrHostFactorySourceRefused
		}
	} else {
		if x.OriginalHashState != "actual_public_bytes" || x.OriginalSHA256 == nil || *x.OriginalCount == 0 && *x.OriginalSHA256 != HostFactoryRawSHA256(nil) {
			return ErrHostFactorySourceRefused
		}
	}
	return nil
}

func hostFactoryGrantFrame(x model.FactoryOrdinaryGrantFrame) error {
	grantRaw, e := base64.StdEncoding.DecodeString(x.OriginalGrantRecordRawBase64)
	if e != nil {
		return ErrHostFactorySourceRefused
	}
	preRaw, e := base64.StdEncoding.DecodeString(x.OriginalPreregistrationRawBase64)
	if e != nil {
		return ErrHostFactorySourceRefused
	}
	g, p := model.CapacityMutationGrant{}, model.CapacityGuestOriginalProvisioningPreregistration{}
	if guestClosedJSON(grantRaw, reflect.TypeOf(g), 0) != nil || json.Unmarshal(grantRaw, &g) != nil || guestClosedJSON(preRaw, reflect.TypeOf(p), 0) != nil || json.Unmarshal(preRaw, &p) != nil {
		return ErrHostFactorySourceRefused
	}
	a, e1 := json.Marshal(g)
	b, e2 := json.Marshal(p)
	c, e3 := json.Marshal(x.OriginalGrant)
	d, e4 := json.Marshal(x.OriginalPreregistration)
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil || !bytes.Equal(a, grantRaw) || !bytes.Equal(b, preRaw) || !bytes.Equal(a, c) || !bytes.Equal(b, d) || !guestUUID(g.GrantID) || !guestUUID(p.PreregistrationID) || !guestUUID(p.ExecutorID) || !guestUUID(p.PolicyID) || !guestUUID(p.WorkflowID) || !guestUUID(p.LeaseOwner) || !hostFactoryHas([]string{"issued", "redeemed"}, g.State) || g.Slot < 1 || g.Slot > 64 || p.Generation < 1 || p.Fence < 1 || g.ExpiresAt.IsZero() || p.OriginalDeadline.IsZero() || p.ReservedAt.IsZero() || !p.OriginalDeadline.After(p.ReservedAt) || !g.ExpiresAt.After(p.ReservedAt) || g.ExpiresAt.Sub(p.ReservedAt) > 60*time.Second || p.OriginalCreateGrantID != g.GrantID || p.OriginalCreateRequestSHA256 != x.PlannedMutationRequestSHA256 || g.RequestSHA256 != x.PlannedMutationRequestSHA256 || g.BindingName != p.BindingName || g.Slot != p.Slot || g.ExpiresAt.After(p.OriginalDeadline) {
		return ErrHostFactorySourceRefused
	}
	return nil
}

// HostFactoryEnvelopeSchema selects only the reviewed signature namespace.
// It does not approve the public key supplied to the cryptographic functions.
func HostFactoryEnvelopeSchema(body any, signerRole, bindingSchema string) (string, error) {
	v := reflect.ValueOf(body)
	if v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return "", ErrHostFactorySourceRefused
		}
		v = v.Elem()
	}
	if !v.IsValid() || !hostFactoryKnown(v.Type()) {
		return "", ErrHostFactorySourceRefused
	}
	name := v.Type().Name()
	if name == "HostFactoryCallVectorChunk" || name == "HostFactoryCallVectorManifest" || name == "HostFactoryHandleCallInventory" || name == "HostFactoryFailureDiagnostic" {
		if !hostFactoryHas([]string{"host_exterior", "host_registrar", "host_worker", "factory_ordinary_worker"}, signerRole) {
			return "", ErrHostFactorySourceRefused
		}
		if (name == "HostFactoryCallVectorChunk" || name == "HostFactoryCallVectorManifest" || name == "HostFactoryHandleCallInventory") && v.FieldByName("OwnerRole").String() != signerRole {
			return "", ErrHostFactorySourceRefused
		}
		if bindingSchema == "original_host_factory_pre_authority_scope_v4" && signerRole != "factory_ordinary_worker" {
			return "HostFactorySignedEnvelope", nil
		}
		if hostFactoryHas([]string{"original_host_factory_source_approval_v4", "original_host_factory_root_preparation_v4", "factory_ordinary_source_binding_v4"}, bindingSchema) {
			if bindingSchema == "original_host_factory_source_approval_v4" && signerRole != "host_exterior" || bindingSchema == "original_host_factory_root_preparation_v4" && signerRole != "host_exterior" && signerRole != "host_registrar" || bindingSchema == "factory_ordinary_source_binding_v4" && signerRole != "host_exterior" && signerRole != "host_registrar" && signerRole != "factory_ordinary_worker" {
				return "", ErrHostFactorySourceRefused
			}
			return "HostFactoryRootSignedEnvelope", nil
		}
		return "", ErrHostFactorySourceRefused
	}
	for _, row := range hostFactorySignatureStages {
		if row[0] != name || row[2] != bindingSchema || row[3] != signerRole {
			continue
		}
		switch x := v.Interface().(type) {
		case model.HostFactoryNativeObservationRecord:
			if x.ObserverRole != signerRole || x.BindingSchema != bindingSchema {
				continue
			}
		case model.HostFactoryNativeObservationManifest:
			if x.ObserverRole != signerRole || x.BindingSchema != bindingSchema {
				continue
			}

		case model.HostFactoryBasalOwnerObservation:
			if x.Role != signerRole {
				continue
			}
		case model.HostFactoryBootstrapReturn:
			if x.Role != signerRole || x.BootstrapBindingSchema != bindingSchema {
				continue
			}
		case model.HostFactoryNativeLeaf:
			if x.ObserverRole != signerRole || x.BindingSchema != bindingSchema || bindingSchema == "factory_ordinary_source_binding_v4" && x.Role != "factory_ordinary_worker" || bindingSchema == "original_host_factory_pre_authority_scope_v4" && x.Role != "host_worker" || bindingSchema == "original_host_factory_root_preparation_v4" && (signerRole == "host_exterior" && x.Role != "host_registrar" || signerRole == "host_registrar" && x.Role != "host_exterior") {
				continue
			}
		}
		return row[1], nil
	}
	return "", ErrHostFactorySourceRefused
}

func hostFactoryEnvelopeBinding(body any, bindingSchema, bindingSHA string) bool {
	v := reflect.ValueOf(body)
	if v.Kind() == reflect.Pointer {
		v = v.Elem()
	}
	if !hostFactoryHex(bindingSHA, 64) {
		return false
	}
	for _, pair := range [][2]string{{"BindingSchema", "BindingSHA256"}, {"BootstrapBindingSchema", "BootstrapBindingSHA256"}} {
		if field := v.FieldByName(pair[0]); field.IsValid() {
			return field.String() == bindingSchema && v.FieldByName(pair[1]).String() == bindingSHA
		}
	}
	if bindingSchema == "original_host_factory_pre_authority_scope_v4" {
		if f := v.FieldByName("PreAuthorityScopeSHA256"); f.IsValid() {
			return f.String() == bindingSHA
		}
	}
	switch x := v.Interface().(type) {
	case model.HostFactorySourceApproval:
		raw, e := CanonicalHostFactory(x)
		return e == nil && bindingSchema == x.Schema && HostFactoryRawSHA256(raw) == bindingSHA
	case model.HostFactoryRootPreparation:
		return bindingSchema == "original_host_factory_source_approval_v4" && x.SourceApprovalSHA256 == bindingSHA
	case model.HostFactoryInitialEmptyRealmRead:
		return bindingSchema == "original_host_factory_root_preparation_v4" && x.RootPreparationSHA256 == bindingSHA
	case model.HostFactoryOriginalLeaseProvenance:
		return bindingSchema == "original_host_factory_root_preparation_v4" && x.RootPreparationSHA256 == bindingSHA
	case model.HostFactoryPreAuthorityScope:
		return bindingSchema == "original_host_factory_root_preparation_v4" // prior Root raw relation is checked by the immutable SQL consumer; body has no RootPreparationSHA field
	case model.HostFactoryRootCompletion:
		return bindingSchema == "original_host_factory_root_preparation_v4" && x.RootPreparationSHA256 == bindingSHA
	case model.HostFactoryChoiceReturn:
		// This existing closed return has no direct Scope field. The signature
		// domain binds the exact Scope digest; consumers independently join its
		// signed reservation and original choice bytes to that same Scope.
		return bindingSchema == "original_host_factory_pre_authority_scope_v4"
	case model.HostFactoryBasalOwnerObservation:
		return hostFactoryHas(hostFactoryEnums["BindingSchema"], bindingSchema) // approved private bootstrap joins the untrusted basal launch hints separately
	case model.FactoryOrdinaryGuardRead:
		return bindingSchema == "factory_ordinary_source_binding_v4" && x.OrdinarySourceBindingSHA256 == bindingSHA
	}
	return false
}

func hostFactoryDomain(schema, purpose, role, keyID, bindingSchema, bindingSHA string, body []byte) []byte {
	fields := []string{schema, purpose, role, keyID}
	if schema == "original_host_factory_root_signed_envelope_v4" {
		fields = append(fields, bindingSchema)
	}
	fields = append(fields, bindingSHA)
	p := append([]byte(strings.Join(fields, "\x00")), 0)
	return append(p, body...)
}

func SignHostFactoryEnvelope(body any, role, keyID, bindingSchema, bindingSHA256 string, privateKey ed25519.PrivateKey) ([]byte, error) {
	raw, err := CanonicalHostFactory(body)
	if err != nil || !guestUUID(keyID) || len(privateKey) != ed25519.PrivateKeySize || !hostFactoryEnvelopeBinding(body, bindingSchema, bindingSHA256) {
		return nil, ErrHostFactorySourceRefused
	}
	if !bytes.Equal(ed25519.NewKeyFromSeed(privateKey[:ed25519.SeedSize]), privateKey) {
		return nil, ErrHostFactorySourceRefused
	}
	kind, err := HostFactoryEnvelopeSchema(body, role, bindingSchema)
	if err != nil {
		return nil, err
	}
	v := reflect.ValueOf(body)
	if v.Kind() == reflect.Pointer {
		v = v.Elem()
	}
	purpose := v.FieldByName("Purpose").String()
	schema := "original_host_factory_signed_envelope_v4"
	if kind == "HostFactoryRootSignedEnvelope" {
		schema = "original_host_factory_root_signed_envelope_v4"
	}
	sig := ed25519.Sign(privateKey, hostFactoryDomain(schema, purpose, role, keyID, bindingSchema, bindingSHA256, raw))
	if kind == "HostFactoryRootSignedEnvelope" {
		return CanonicalHostFactory(model.HostFactoryRootSignedEnvelope{Schema: schema, Purpose: purpose, Role: role, KeyID: keyID, BindingSchema: bindingSchema, BindingSHA256: bindingSHA256, BodyBase64: base64.StdEncoding.EncodeToString(raw), SignatureBase64: base64.StdEncoding.EncodeToString(sig)})
	}
	return CanonicalHostFactory(model.HostFactorySignedEnvelope{Schema: schema, Purpose: purpose, Role: role, KeyID: keyID, PreAuthorityScopeSHA256: bindingSHA256, BodyBase64: base64.StdEncoding.EncodeToString(raw), SignatureBase64: base64.StdEncoding.EncodeToString(sig)})
}

func VerifyHostFactoryEnvelope(raw []byte, body any, role, keyID, bindingSchema, bindingSHA256 string, publicKey ed25519.PublicKey) error {
	if len(publicKey) != ed25519.PublicKeySize || !guestUUID(keyID) || !hostFactoryHex(bindingSHA256, 64) {
		return ErrHostFactorySourceRefused
	}
	v := reflect.ValueOf(body)
	if v.Kind() != reflect.Pointer || v.IsNil() || !hostFactoryKnown(v.Elem().Type()) {
		return ErrHostFactorySourceRefused
	}
	fresh := reflect.New(v.Elem().Type())
	kind := "HostFactoryRootSignedEnvelope"
	if bindingSchema == "original_host_factory_pre_authority_scope_v4" {
		kind = "HostFactorySignedEnvelope"
	}
	schema, purpose, storedRole, storedKey, storedBinding, storedSHA, encoded, sigText := "", "", "", "", "", "", "", ""
	if kind == "HostFactoryRootSignedEnvelope" {
		var e model.HostFactoryRootSignedEnvelope
		if DecodeHostFactory(raw, &e) != nil {
			return ErrHostFactorySourceRefused
		}
		schema, purpose, storedRole, storedKey, storedBinding, storedSHA, encoded, sigText = e.Schema, e.Purpose, e.Role, e.KeyID, e.BindingSchema, e.BindingSHA256, e.BodyBase64, e.SignatureBase64
	} else {
		var e model.HostFactorySignedEnvelope
		if DecodeHostFactory(raw, &e) != nil {
			return ErrHostFactorySourceRefused
		}
		schema, purpose, storedRole, storedKey, storedBinding, storedSHA, encoded, sigText = e.Schema, e.Purpose, e.Role, e.KeyID, bindingSchema, e.PreAuthorityScopeSHA256, e.BodyBase64, e.SignatureBase64
	}
	bodyRaw, e := base64.StdEncoding.DecodeString(encoded)
	sig, e2 := base64.StdEncoding.DecodeString(sigText)
	if e != nil || e2 != nil || storedRole != role || storedKey != keyID || storedBinding != bindingSchema || storedSHA != bindingSHA256 || !ed25519.Verify(publicKey, hostFactoryDomain(schema, purpose, role, keyID, bindingSchema, bindingSHA256, bodyRaw), sig) || DecodeHostFactory(bodyRaw, fresh.Interface()) != nil {
		return ErrHostFactorySourceRefused
	}
	actualKind, e := HostFactoryEnvelopeSchema(fresh.Interface(), role, bindingSchema)
	if e != nil || actualKind != kind || fresh.Elem().FieldByName("Purpose").String() != purpose || !hostFactoryEnvelopeBinding(fresh.Interface(), bindingSchema, bindingSHA256) {
		return ErrHostFactorySourceRefused
	}
	v.Elem().Set(fresh.Elem())
	return nil
}

func ValidateHostFactorySourceBinding(a model.HostFactorySourceApproval, s model.HostFactoryPreAuthorityScope) error {
	if ValidateHostFactory(a) != nil || ValidateHostFactory(s) != nil || a.FactoryRegistrySHA256 != s.FactoryRegistrySHA256 || a.FactorySourceClosureSHA256 != s.FactorySourceClosureSHA256 || a.ActualBuildSourceCommit != s.CoreActualSourceCommit || a.AllowedNamespace != s.Namespace || a.AllowedPolicyID != s.PolicyID || a.AllowedWorkflowID != s.WorkflowID || a.AllowedOriginalStepID != s.OriginalStepID || a.AllowedMutationBindingName != s.MutationBindingName || a.AllowedSlot != s.Slot || a.ScopeRootID != s.ScopeRootID || !hostFactoryHas(a.AllowedFactoryEntryClasses, s.FactoryEntryClass) || s.OriginalContextStartedAt.Before(a.ApprovedAt) || s.OriginalContextDeadline.After(a.OriginalApprovalDeadline) {
		return ErrHostFactorySourceRefused
	}
	return nil
}

func ValidateHostFactoryPendingSuccessor(previous, current model.HostFactoryCallVectorChunk) error {
	if ValidateHostFactory(previous) != nil || ValidateHostFactory(current) != nil || len(previous.OriginalCalls) != 1 || len(current.OriginalCalls) != 1 || previous.BindingSchema != current.BindingSchema || previous.BindingSHA256 != current.BindingSHA256 || previous.OwnerRole != current.OwnerRole || previous.OriginalOwnerID != current.OriginalOwnerID || previous.OwnerPrimitiveRawSHA256 != current.OwnerPrimitiveRawSHA256 || previous.Operation != current.Operation || previous.OriginalHandleID != current.OriginalHandleID || previous.FirstOrdinal != current.FirstOrdinal || previous.LastOrdinal != current.LastOrdinal || current.RecordedAt.Before(previous.RecordedAt) {
		return ErrHostFactorySourceRefused
	}
	a, b := previous.OriginalCalls[0], current.OriginalCalls[0]
	if a.OriginalState != "called_pending" || b.OriginalState != "returned" || a.SubjectOwnerID != b.SubjectOwnerID || a.OriginalCallID == nil || b.OriginalCallID == nil || *a.OriginalCallID != *b.OriginalCallID || !a.OriginalCalledAt.Equal(*b.OriginalCalledAt) || !a.OriginalOperationDeadline.Equal(b.OriginalOperationDeadline) {
		return ErrHostFactorySourceRefused
	}
	// The original request is fixed before the original native call. Only
	// output slots may become known on its sole returned successor.
	if (a.OriginalNativeReturn == nil) != (b.OriginalNativeReturn == nil) {
		return ErrHostFactorySourceRefused
	}
	if a.OriginalNativeReturn != nil {
		oldRequest, newRequest := *a.OriginalNativeReturn, *b.OriginalNativeReturn
		hostFactoryClearNativeOutputs(&oldRequest)
		hostFactoryClearNativeOutputs(&newRequest)
		if !reflect.DeepEqual(oldRequest, newRequest) {
			return ErrHostFactorySourceRefused
		}
	}
	return nil
}

func hostFactoryClearNativeOutputs(n *model.HostFactoryNativeCallReturn) {
	n.OriginalScalar, n.OriginalErrno, n.OriginalErrorPresent = nil, nil, nil
	n.OriginalStat, n.ReturnedDescriptors = nil, nil
	n.OriginalPollRevents, n.ReturnedPID, n.OriginalExitCode = nil, nil, nil
}

// The predecessor callback must return nil,0,nil ONLY for a verified immutable
// FIRST row matching current raw chunk/fact index/CallID. Absence, orphan,
// unknown or restored relation returns an error. This function proves no SQL
// existence, signer approval, native IO, or exterior lifetime on its own.
func ValidateHostFactoryCallVector(reference model.HostFactoryCallVectorReference, resolve func(string) ([]byte, error), predecessor func(string, uint32) ([]byte, uint32, error)) error {
	return hostFactoryWalkCallVector(reference, resolve, predecessor, false, nil)
}

func hostFactoryWalkCallVector(reference model.HostFactoryCallVectorReference, resolve func(string) ([]byte, error), predecessor func(string, uint32) ([]byte, uint32, error), allowSparse bool, retain func(model.HostFactoryPrimitiveIOReturn, model.HostFactoryCallVectorChunk) error) error {
	if ValidateHostFactory(reference) != nil || resolve == nil || predecessor == nil || reference.CollectionState != "complete_original_calls" || reference.OriginalCallCount == 0 || reference.ManifestRootSHA256 == nil {
		return ErrHostFactorySourceRefused
	}
	visited := map[string]bool{}
	callIDs := map[string]bool{}
	binding, ownerRole := "", ""
	boundSHA := ""
	visits := 0
	// Read the root once. The resolver may be an original native/SQL reader,
	// rather than a replayable in-memory map.
	root, e := resolve(*reference.ManifestRootSHA256)
	var rootManifest model.HostFactoryCallVectorManifest
	if e != nil || len(root) == 0 || len(root) > hostFactoryLimit || HostFactoryRawSHA256(root) != *reference.ManifestRootSHA256 || DecodeHostFactory(root, &rootManifest) != nil {
		return ErrHostFactorySourceRefused
	}
	var walk func(string, int) (uint64, uint64, uint64, time.Time, time.Time, error)
	walk = func(digest string, level int) (uint64, uint64, uint64, time.Time, time.Time, error) {
		if visited[digest] || !hostFactoryHex(digest, 64) || visits >= 69905 {
			return 0, 0, 0, time.Time{}, time.Time{}, ErrHostFactorySourceRefused
		}
		visited[digest] = true
		visits++
		raw := root
		var e error
		if digest != *reference.ManifestRootSHA256 {
			raw, e = resolve(digest)
		}
		if e != nil || len(raw) == 0 || len(raw) > hostFactoryLimit || HostFactoryRawSHA256(raw) != digest {
			return 0, 0, 0, time.Time{}, time.Time{}, ErrHostFactorySourceRefused
		}
		check := func(b, sha, role, id, primitive, operation, handle string) bool {
			if id != reference.OriginalOwnerID || operation != reference.Operation || handle != reference.OriginalHandleID || reference.OwnerPrimitiveRawSHA256 == nil || primitive != *reference.OwnerPrimitiveRawSHA256 {
				return false
			}
			if binding == "" {
				binding, boundSHA, ownerRole = b, sha, role
			}
			return b == binding && sha == boundSHA && role == ownerRole
		}
		if level == -1 {
			var c model.HostFactoryCallVectorChunk
			if DecodeHostFactory(raw, &c) != nil || !check(c.BindingSchema, c.BindingSHA256, c.OwnerRole, c.OriginalOwnerID, c.OwnerPrimitiveRawSHA256, c.Operation, c.OriginalHandleID) {
				return 0, 0, 0, time.Time{}, time.Time{}, ErrHostFactorySourceRefused
			}
			for i, p := range c.OriginalCalls {
				if p.OriginalState != "returned" || p.OriginalReturnedAt == nil || p.SubjectOwnerID != reference.SubjectOwnerID || p.OriginalCallID == nil || callIDs[*p.OriginalCallID] {
					return 0, 0, 0, time.Time{}, time.Time{}, ErrHostFactorySourceRefused
				}
				callIDs[*p.OriginalCallID] = true
				if retain != nil && retain(p, c) != nil {
					return 0, 0, 0, time.Time{}, time.Time{}, ErrHostFactorySourceRefused
				}
				prior, index, err := predecessor(digest, uint32(i))
				if err != nil {
					return 0, 0, 0, time.Time{}, time.Time{}, ErrHostFactorySourceRefused
				}
				if prior == nil {
					if index != 0 {
						return 0, 0, 0, time.Time{}, time.Time{}, ErrHostFactorySourceRefused
					}
				} else {
					var old model.HostFactoryCallVectorChunk
					if index != 0 || len(prior) == 0 || len(prior) > hostFactoryLimit || len(c.OriginalCalls) != 1 || HostFactoryRawSHA256(prior) == digest || DecodeHostFactory(prior, &old) != nil || ValidateHostFactoryPendingSuccessor(old, c) != nil {
						return 0, 0, 0, time.Time{}, time.Time{}, ErrHostFactorySourceRefused
					}
				}
			}
			return c.FirstOrdinal, c.LastOrdinal, uint64(len(c.OriginalCalls)), *c.OriginalCalls[0].OriginalCalledAt, *c.OriginalCalls[len(c.OriginalCalls)-1].OriginalReturnedAt, nil
		}
		var m model.HostFactoryCallVectorManifest
		if DecodeHostFactory(raw, &m) != nil || int(m.Level) != level || m.CollectionState != "complete_original_calls" || !check(m.BindingSchema, m.BindingSHA256, m.OwnerRole, m.OriginalOwnerID, m.OwnerPrimitiveRawSHA256, m.Operation, m.OriginalHandleID) {
			return 0, 0, 0, time.Time{}, time.Time{}, ErrHostFactorySourceRefused
		}
		first, last, count := uint64(0), uint64(0), uint64(0)
		var firstCall, lastReturn time.Time
		for _, child := range m.ChildBodySHAs {
			f, l, n, called, returned, e := walk(child, level-1)
			if e != nil || count > 0 && ((f <= last || !allowSparse && f != last+1) || called.Before(lastReturn)) {
				return 0, 0, 0, time.Time{}, time.Time{}, ErrHostFactorySourceRefused
			}
			if count == 0 {
				first = f
				firstCall = called
			}
			last = l
			lastReturn = returned
			count += n
			if count > 65536 {
				return 0, 0, 0, time.Time{}, time.Time{}, ErrHostFactorySourceRefused
			}
		}
		if first != m.FirstOrdinal || last != m.LastOrdinal || count != m.OriginalCallCount {
			return 0, 0, 0, time.Time{}, time.Time{}, ErrHostFactorySourceRefused
		}
		return first, last, count, firstCall, lastReturn, nil
	}
	first, last, count, _, _, e := walk(*reference.ManifestRootSHA256, int(rootManifest.Level))
	if e != nil || first != reference.FirstOrdinal || last != reference.LastOrdinal || count != reference.OriginalCallCount {
		return ErrHostFactorySourceRefused
	}
	return nil
}

// hostFactoryNativeIntrinsic validates declared original-return relationships.
// It performs no syscall and cannot install source/native approval.
func hostFactoryNativeIntrinsic(value any) error {
	fail := ErrHostFactorySourceRefused
	switch x := value.(type) {
	case model.HostFactoryNativeCallReturn:
		if !hostFactoryHas(hostFactoryEnums["NativeCallKind"], x.Kind) {
			return fail
		}
		// Check exact request slots even while the original owner is pending.
		// A requested flag is never an observed flag or an acquired endpoint.
		fd, parent, flags, mode, command, arg, pid := false, false, false, false, false, false, false
		switch x.Kind {
		case "unix_open":
			flags, mode = true, true
		case "unix_openat":
			fd, parent, flags, mode = true, true, true, true
		case "unix_mkdirat":
			fd, parent, mode = true, true, true
		case "unix_fstat", "unix_close", "original_file_close", "original_file_sync":
			fd = true
		case "fcntl_getfl", "fcntl_getfd", "fcntl_setfl":
			fd, command, arg = true, true, true
		case "fcntl_dupfd_cloexec":
			fd, parent, command, arg = true, true, true, true
		case "unix_getdents64":
			fd, arg = true, true
		case "unix_pidfd_open":
			flags, pid = true, true
		case "unix_poll":
			fd, flags, arg = true, true, true
		case "unix_pidfd_send_signal":
			fd, flags, arg = true, true, true
		case "original_os_pipe", "original_cmd_start", "original_cmd_wait":
		}
		if fd != (x.InputDescriptorNumber != nil) || parent != (x.ParentHandleID != nil) || flags != (x.RequestedFlags != nil) || mode != (x.RequestedMode != nil) || command != (x.RequestedFcntlCommand != nil) || arg != (x.RequestedArgument != nil) || pid != (x.RequestedPID != nil) {
			return fail
		}
		if command {
			want := map[string]int{"fcntl_getfl": 3, "fcntl_getfd": 1, "fcntl_setfl": 4, "fcntl_dupfd_cloexec": 1030}[x.Kind]
			if *x.RequestedFcntlCommand != want || *x.RequestedArgument < 0 || (x.Kind == "fcntl_getfl" || x.Kind == "fcntl_getfd") && *x.RequestedArgument != 0 {
				return fail
			}
		}
		if x.Kind == "unix_mkdirat" && *x.RequestedMode != 0700 || x.Kind == "unix_pidfd_open" && *x.RequestedFlags != 0 || x.Kind == "unix_getdents64" && (*x.RequestedArgument < 1 || *x.RequestedArgument > 65536) || x.Kind == "unix_poll" && (*x.RequestedFlags != 1 || *x.RequestedArgument != 0) || x.Kind == "unix_pidfd_send_signal" && (*x.RequestedFlags != 0 || *x.RequestedArgument < 1 || *x.RequestedArgument > 64) {
			return fail
		}
		outputsAbsent := x.OriginalScalar == nil && x.OriginalErrno == nil && x.OriginalStat == nil && x.ReturnedDescriptors == nil && x.OriginalPollRevents == nil && x.ReturnedPID == nil && x.OriginalExitCode == nil
		if x.OriginalErrorPresent == nil {
			if !outputsAbsent {
				return fail
			}
			return nil
		}
		if !*x.OriginalErrorPresent && (x.OriginalErrno == nil || *x.OriginalErrno != 0) || *x.OriginalErrorPresent && x.OriginalErrno != nil && *x.OriginalErrno == 0 {
			return fail
		}
		descriptor := x.Kind == "unix_open" || x.Kind == "unix_openat" || x.Kind == "unix_pidfd_open" || x.Kind == "fcntl_dupfd_cloexec"
		scalar := descriptor || x.Kind == "fcntl_getfl" || x.Kind == "fcntl_getfd" || x.Kind == "fcntl_setfl" || x.Kind == "unix_getdents64" || x.Kind == "unix_poll"
		if scalar != (x.OriginalScalar != nil) {
			return fail
		}
		if descriptor && !*x.OriginalErrorPresent {
			if *x.OriginalScalar < 0 || *x.OriginalScalar > 2147483647 || len(x.ReturnedDescriptors) != 1 || int64(x.ReturnedDescriptors[0].OriginalDescriptorNumber) != *x.OriginalScalar {
				return fail
			}
			if x.ParentHandleID != nil && x.ReturnedDescriptors[0].OriginalHandleID == *x.ParentHandleID {
				return fail
			}
		} else if x.Kind == "original_os_pipe" && !*x.OriginalErrorPresent {
			if len(x.ReturnedDescriptors) != 2 || x.ReturnedDescriptors[0].OriginalHandleID == x.ReturnedDescriptors[1].OriginalHandleID || x.ReturnedDescriptors[0].OriginalDescriptorNumber == x.ReturnedDescriptors[1].OriginalDescriptorNumber {
				return fail
			}
		} else if x.ReturnedDescriptors != nil {
			return fail
		}
		if x.Kind == "unix_fstat" {
			if (!*x.OriginalErrorPresent) != (x.OriginalStat != nil) {
				return fail
			}
		} else if x.OriginalStat != nil {
			return fail
		}
		if !*x.OriginalErrorPresent && scalar && *x.OriginalScalar < 0 {
			return fail
		}
		if !*x.OriginalErrorPresent && x.Kind == "fcntl_getfd" && *x.OriginalScalar > 1 {
			return fail
		}
		if !*x.OriginalErrorPresent && x.Kind == "unix_getdents64" && *x.OriginalScalar > *x.RequestedArgument {
			return fail
		}
		if !*x.OriginalErrorPresent && x.Kind == "unix_poll" && (*x.OriginalScalar > 1 || x.OriginalPollRevents == nil) {
			return fail
		}
		if x.Kind != "unix_poll" && x.OriginalPollRevents != nil || x.Kind != "original_cmd_start" && x.ReturnedPID != nil || x.Kind != "original_cmd_wait" && x.OriginalExitCode != nil {
			return fail
		}
		if !*x.OriginalErrorPresent && x.Kind == "original_cmd_start" && x.ReturnedPID == nil || !*x.OriginalErrorPresent && x.Kind == "original_cmd_wait" && (x.OriginalExitCode == nil || *x.OriginalExitCode != 0) {
			return fail
		}
	case model.HostFactoryBootstrapDescriptorSource:
		if !hostFactoryAcquisitionDeclared(x.OriginalHandleID, x.OriginalAcquisitionCallVector, x.OriginalInheritedFromHandleID, x.OriginalFstatCallVector) {
			return fail
		}
		return hostFactoryDescriptorVectors(x.OriginalHandleID, x.OwnerPrimitiveRawSHA256, x.OriginalFstatCallVector, x.OriginalGetflCallVector, x.OriginalGetfdCallVector, x.OriginalFstatCallID, x.OriginalGetflCallID, x.OriginalGetfdCallID)
	case model.HostFactoryDescriptorSource:
		if !hostFactoryAcquisitionDeclared(x.OriginalHandleID, x.OriginalAcquisitionCallVector, x.OriginalInheritedFromHandleID, x.OriginalFstatCallVector) {
			return fail
		}
		return hostFactoryDescriptorVectors(x.OriginalHandleID, "", x.OriginalFstatCallVector, x.OriginalGetflCallVector, x.OriginalGetfdCallVector, x.OriginalFstatCallID, x.OriginalGetflCallID, x.OriginalGetfdCallID)
	case model.HostFactoryNativeProcess:
		h, p, pin := x.OriginalHeldExecutableRead, x.OriginalProcessOwnerRead, x.OriginalSubjectNativePin
		exeRaw, e1 := json.Marshal(h.OriginalRead)
		nativeRaw, e2 := json.Marshal(x.NativeReadOperations[2])
		if e1 != nil || e2 != nil || !bytes.Equal(exeRaw, nativeRaw) || h.OriginalBeforeStat != h.OriginalAfterStat || h.OriginalBeforeStat.Device != x.Execution.ExecutableDevice || h.OriginalBeforeStat.Inode != x.Execution.ExecutableInode || h.OriginalBeforeStat.Mode != x.Execution.ExecutableMode || h.OriginalBeforeStat.UID != x.Execution.ExecutableUID || h.OriginalBeforeStat.GID != x.Execution.ExecutableGID || h.OriginalBeforeStat.LinkCount != x.Execution.ExecutableLinkCount || h.OriginalBeforeStat.Size != int64(x.Execution.OriginalExecutableReadBytes) {
			return fail
		}
		if p.SubjectBootID != x.HostBootID || p.SubjectPID != x.PID || p.SubjectStartTicks != x.StartTicks || p.OriginalStat.UID != x.UID || p.OriginalStat.GID != x.GID || pin.SubjectBootID != x.HostBootID || pin.SubjectPID != x.PID || pin.SubjectStartTicks != x.StartTicks {
			return fail
		}
		if h.SubjectOwnerID != pin.SubjectOwnerID || p.SubjectOwnerID != pin.SubjectOwnerID || h.OwnerPrimitiveRawSHA256 != pin.ObserverPrimitiveRawSHA256 || p.OwnerPrimitiveRawSHA256 != pin.ObserverPrimitiveRawSHA256 || pin.OriginalObservedAt.Before(x.OriginalNativeCloseReturnedAt) {
			return fail
		}
		for _, read := range x.NativeReadOperations {
			if read.SubjectOwnerID != pin.SubjectOwnerID || read.OwnerPrimitiveRawSHA256 != pin.ObserverPrimitiveRawSHA256 {
				return fail
			}
		}
		if !hostFactoryHas(x.NativeHandleInventorySHAs, h.OriginalHandleInventorySHA256) || !hostFactoryHas(x.NativeHandleInventorySHAs, p.OriginalHandleInventorySHA256) || !hostFactoryHas(x.NativeHandleInventorySHAs, pin.OriginalHandleInventorySHA256) {
			return fail
		}
	case model.HostFactoryHeldExecutableRead:
		if x.OriginalBeforeStat != x.OriginalAfterStat || x.OriginalBeforeStat.Mode&0170000 != 0100000 || x.OriginalBeforeStat.LinkCount != 1 || x.OriginalBeforeFstatCallID == x.OriginalAfterFstatCallID || x.OriginalRead.Operation != "executable_read" || x.OriginalRead.OriginalHandleID != x.OriginalHandleID || x.OriginalRead.OwnerPrimitiveRawSHA256 != x.OwnerPrimitiveRawSHA256 || x.OriginalRead.SubjectOwnerID != x.SubjectOwnerID {
			return fail
		}
		if x.OriginalFstatCallVector.OriginalHandleID != x.OriginalHandleID || x.OriginalFstatCallVector.OriginalCallCount != 2 {
			return fail
		}
		if x.OriginalBeforeStat.Size != x.OriginalRead.OriginalCount || !hostFactorySameDeclaredRefs(x.OriginalHandleID, x.SubjectOwnerID, x.OwnerPrimitiveRawSHA256, x.OriginalOpenCallVector, x.OriginalFstatCallVector) || x.OriginalOpenCallVector.Operation != "native_reader_open" || x.OriginalFstatCallVector.Operation != "native_reader_fstat" || !hostFactorySelectedCallID(x.OriginalBeforeFstatCallID, x.OriginalFstatCallVector) || !hostFactorySelectedCallID(x.OriginalAfterFstatCallID, x.OriginalFstatCallVector) {
			return fail
		}
		beforeOrdinal, _ := hostFactoryCallOrdinal(x.OriginalBeforeFstatCallID, x.OriginalHandleID)
		afterOrdinal, _ := hostFactoryCallOrdinal(x.OriginalAfterFstatCallID, x.OriginalHandleID)
		if beforeOrdinal >= x.OriginalRead.OriginalCallVector.FirstOrdinal || afterOrdinal <= x.OriginalRead.OriginalCallVector.LastOrdinal || afterOrdinal >= x.OriginalRead.OriginalCloseCallVector.FirstOrdinal {
			return fail
		}
	case model.HostFactoryProcessOwnerRead:
		if x.OriginalStat.Mode&0170000 != 0040000 || !hostFactoryOrdered(x.OriginalCalledAt, x.OriginalReturnedAt, x.OriginalCloseReturnedAt) {
			return fail
		}
		for _, v := range []model.HostFactoryCallVectorReference{x.OriginalOpenCallVector, x.OriginalFstatCallVector, x.OriginalCloseCallVector} {
			if v.OriginalHandleID != x.OriginalHandleID || v.SubjectOwnerID != x.SubjectOwnerID || v.OwnerPrimitiveRawSHA256 == nil || *v.OwnerPrimitiveRawSHA256 != x.OwnerPrimitiveRawSHA256 || v.CollectionState != "complete_original_calls" {
				return fail
			}
		}
		if x.OriginalOpenCallVector.Operation != "proc_owner_directory_open" || x.OriginalFstatCallVector.Operation != "proc_owner_directory_fstat" || x.OriginalCloseCallVector.Operation != "proc_owner_directory_close" || x.OriginalOpenCallVector.LastOrdinal >= x.OriginalFstatCallVector.FirstOrdinal || x.OriginalFstatCallVector.LastOrdinal >= x.OriginalCloseCallVector.FirstOrdinal {
			return fail
		}
	case model.HostFactoryNativeSubjectPin:
		if x.OriginalBeforePollCallID == x.OriginalAfterPollCallID || x.OriginalAlivePollCallVector.Operation != "native_subject_alive_poll" || x.OriginalAlivePollCallVector.OriginalHandleID != x.OriginalHandleID || x.OriginalFstatCallVector.OriginalHandleID != x.OriginalHandleID || x.OriginalAlivePollCallVector.OwnerPrimitiveRawSHA256 == nil || *x.OriginalAlivePollCallVector.OwnerPrimitiveRawSHA256 != x.ObserverPrimitiveRawSHA256 {
			return fail
		}
		if x.OriginalOpenCallVector == nil && x.OriginalBasalSelfPIDFDSourceSHA256 == nil || x.OriginalOpenCallVector != nil && x.OriginalBasalSelfPIDFDSourceSHA256 != nil {
			return fail
		}
		if !hostFactorySameDeclaredRefs(x.OriginalHandleID, x.SubjectOwnerID, x.ObserverPrimitiveRawSHA256, x.OriginalFstatCallVector, x.OriginalAlivePollCallVector) || !hostFactorySelectedCallID(x.OriginalBeforePollCallID, x.OriginalAlivePollCallVector) || !hostFactorySelectedCallID(x.OriginalAfterPollCallID, x.OriginalAlivePollCallVector) {
			return fail
		}
		beforeOrdinal, _ := hostFactoryCallOrdinal(x.OriginalBeforePollCallID, x.OriginalHandleID)
		afterOrdinal, _ := hostFactoryCallOrdinal(x.OriginalAfterPollCallID, x.OriginalHandleID)
		if beforeOrdinal >= afterOrdinal {
			return fail
		}
		if x.OriginalOpenCallVector == nil {
			if x.ObserverOwnerID != x.SubjectOwnerID || *x.OriginalBasalSelfPIDFDSourceSHA256 != x.ObserverPrimitiveRawSHA256 {
				return fail
			}
		} else if !hostFactorySameDeclaredRefs(x.OriginalHandleID, x.SubjectOwnerID, x.ObserverPrimitiveRawSHA256, *x.OriginalOpenCallVector) || !hostFactoryHas([]string{"worker_pidfd_pin", "registrar_pidfd_pin", "native_subject_pidfd_open"}, x.OriginalOpenCallVector.Operation) {
			return fail
		}
	case model.HostFactoryTaskDirectoryRead:
		if x.ParserClass != "linux_amd64_dirent64_v1" || x.OriginalRawBytes > 65536 || x.OriginalDirectoryStat.Mode&0170000 != 0040000 || !hostFactoryOrdered(x.OriginalCalledAt, x.OriginalReturnedAt, x.OriginalCloseReturnedAt) {
			return fail
		}
		last := 0
		for _, tid := range x.ParsedTIDs {
			if tid <= last {
				return fail
			}
			last = tid
		}
		for _, v := range []model.HostFactoryCallVectorReference{x.OriginalOpenCallVector, x.OriginalFstatCallVector, x.OriginalGetdentsCallVector, x.OriginalCloseCallVector} {
			if v.OriginalHandleID != x.OriginalHandleID || v.SubjectOwnerID != x.SubjectOwnerID || v.OwnerPrimitiveRawSHA256 == nil || *v.OwnerPrimitiveRawSHA256 != x.OwnerPrimitiveRawSHA256 || v.CollectionState != "complete_original_calls" {
				return fail
			}
		}
		if x.OriginalGetdentsCallVector.Operation != "task_inventory_getdents" || x.OriginalCloseCallVector.Operation != "native_reader_close" {
			return fail
		}
		if x.OriginalOpenCallVector.Operation != "native_reader_open" || x.OriginalFstatCallVector.Operation != "native_reader_fstat" || !hostFactorySelectedCallID(x.OriginalTerminalCallID, x.OriginalGetdentsCallVector) || x.OriginalSubjectStatBeforeRead.Operation != "stat_before_read" || x.OriginalSubjectStatAfterRead.Operation != "stat_after_read" || x.OriginalSubjectStatBeforeRead.SubjectOwnerID != x.SubjectOwnerID || x.OriginalSubjectStatAfterRead.SubjectOwnerID != x.SubjectOwnerID || x.OriginalSubjectStatBeforeRead.OwnerPrimitiveRawSHA256 != x.OwnerPrimitiveRawSHA256 || x.OriginalSubjectStatAfterRead.OwnerPrimitiveRawSHA256 != x.OwnerPrimitiveRawSHA256 {
			return fail
		}
		terminalOrdinal, _ := hostFactoryCallOrdinal(x.OriginalTerminalCallID, x.OriginalHandleID)
		if terminalOrdinal != x.OriginalGetdentsCallVector.LastOrdinal || x.OriginalFstatCallVector.LastOrdinal >= x.OriginalGetdentsCallVector.FirstOrdinal || x.OriginalGetdentsCallVector.LastOrdinal >= x.OriginalCloseCallVector.FirstOrdinal {
			return fail
		}
		if x.OriginalSubjectStatBeforeRead.OriginalCloseReturnedAt.After(x.OriginalCalledAt) || x.OriginalSubjectStatAfterRead.OriginalCalledAt.Before(x.OriginalCloseReturnedAt) || x.OriginalRawBytes == 0 && x.OriginalRawSHA256 != HostFactoryRawSHA256(nil) {
			return fail
		}
	case model.HostFactoryHandleCallInventory:
		if x.OriginalCallCount == 0 {
			if x.FirstOrdinal != 0 || x.LastOrdinal != 0 || len(x.OperationVectors) != 0 {
				return fail
			}
			return nil
		}
		if x.FirstOrdinal != 1 || x.OriginalCallCount > x.LastOrdinal || x.OwnerPrimitiveRawSHA256 == nil || x.CollectionState == "complete_original_calls" && x.OriginalCallCount != x.LastOrdinal {
			return fail
		}
		seen := map[string]bool{}
		last := uint64(0)
		for _, v := range x.OperationVectors {
			if seen[v.Operation] || v.OriginalHandleID != x.OriginalHandleID || v.OriginalOwnerID != x.OriginalOwnerID || v.FirstOrdinal <= last || v.OwnerPrimitiveRawSHA256 == nil || *v.OwnerPrimitiveRawSHA256 != *x.OwnerPrimitiveRawSHA256 {
				return fail
			}
			seen[v.Operation] = true
			last = v.FirstOrdinal
		}
	case model.HostFactorySourceAuditReturn:
		if x.Purpose != "source_audit_only_no_host_native_authority" || !hostFactoryHas(hostFactoryEnums["SourceAuditOperation"], x.Operation) {
			return fail
		}
		if x.OriginalState == "not_called" {
			if x.OriginalCalledAt != nil || x.OriginalReturnedAt != nil || x.OriginalErrorPresent != nil || x.OriginalCallID != nil || x.OriginalStatusCode != nil || x.OriginalCount != nil || x.OriginalSHA256 != nil || x.OriginalEOF != nil || x.OriginalHashState != "unknown_original_bytes" {
				return fail
			}
		} else if x.OriginalCalledAt == nil || x.OriginalCallID == nil {
			return fail
		}
		if x.OriginalState == "called_pending" && (x.OriginalReturnedAt != nil || x.OriginalErrorPresent != nil || x.OriginalStatusCode != nil || x.OriginalCount != nil || x.OriginalSHA256 != nil || x.OriginalEOF != nil || x.OriginalHashState != "unknown_original_bytes") || x.OriginalState == "returned" && (x.OriginalReturnedAt == nil || x.OriginalErrorPresent == nil || x.OriginalReturnedAt.Before(*x.OriginalCalledAt)) {
			return fail
		}
		if x.OriginalHashState != "actual_public_bytes" && x.OriginalSHA256 != nil {
			return fail
		}
		if x.OriginalCallID != nil && !strings.HasPrefix(*x.OriginalCallID, x.OriginalAuditHandleID+":") || x.OriginalStatusCode != nil && (*x.OriginalStatusCode < 100 || *x.OriginalStatusCode > 599) || x.OriginalCount != nil && (*x.OriginalCount < 0 || *x.OriginalCount > 65537) || x.RetainedPrefixBytes != nil && (*x.RetainedPrefixBytes < 0 || *x.RetainedPrefixBytes > 65536) {
			return fail
		}
		if x.OriginalHashState == "actual_public_bytes" && (x.OriginalSHA256 == nil || x.OriginalCount == nil || *x.OriginalCount == 0 && *x.OriginalSHA256 != HostFactoryRawSHA256(nil)) {
			return fail
		}
		if x.OriginalHashState == "private_withheld" && x.RetainedPrefixSHA256 != nil {
			return fail
		}
		byteOperation := x.Operation == "source_file_read" || x.Operation == "source_file_write" || x.Operation == "public_workflow_body_read" || x.Operation == "ordinary_authority_body_read"
		if !byteOperation && (x.OriginalCount != nil || x.OriginalSHA256 != nil || x.OriginalEOF != nil || x.OriginalReadScope != nil || x.RetainedPrefixBytes != nil || x.RetainedPrefixSHA256 != nil || x.OriginalHashState == "actual_public_bytes" || x.OriginalHashState == "private_withheld") {
			return fail
		}
		if x.OriginalHashState == "not_byte_operation" && (x.OriginalCount != nil || x.OriginalEOF != nil || x.OriginalReadScope != nil || x.RetainedPrefixBytes != nil || x.RetainedPrefixSHA256 != nil) {
			return fail
		}
		if x.OriginalReadScope != nil {
			if x.RetainedPrefixBytes == nil {
				return fail
			}
			switch *x.OriginalReadScope {
			case "no_original_body_read":
				if x.OriginalState != "not_called" || x.OriginalSHA256 != nil || x.OriginalCount != nil || *x.RetainedPrefixBytes != 0 || x.RetainedPrefixSHA256 != nil && *x.RetainedPrefixSHA256 != HostFactoryRawSHA256(nil) {
					return fail
				}
			case "complete_original_body_read":
				if x.OriginalState != "returned" || *x.OriginalErrorPresent || x.OriginalEOF == nil || !*x.OriginalEOF || x.OriginalCount == nil || *x.OriginalCount > 65536 || *x.RetainedPrefixBytes != *x.OriginalCount {
					return fail
				}
			case "incomplete_original_body_read":
				if x.OriginalState != "returned" || x.OriginalCount == nil || !*x.OriginalErrorPresent && *x.OriginalCount <= 65536 {
					return fail
				}
			default:
				return fail
			}
			if *x.OriginalReadScope != "no_original_body_read" {
				// Scope/count/EOF describe the actual original read independently
				// of public classification. Private workflow GETs and refused or
				// unknown POSTs retain those facts while ALL byte digests stay NULL.
				prefixCount := *x.OriginalCount
				if prefixCount > 65536 {
					prefixCount = 65536
				}
				if *x.RetainedPrefixBytes != prefixCount {
					return fail
				}
				if x.OriginalHashState == "actual_public_bytes" {
					if x.RetainedPrefixSHA256 == nil || *x.OriginalReadScope == "complete_original_body_read" && *x.RetainedPrefixSHA256 != *x.OriginalSHA256 {
						return fail
					}
				} else if x.RetainedPrefixSHA256 != nil {
					return fail
				}
			}
		}
	}
	return nil
}

func hostFactoryDescriptorVectors(handle, basal string, stat, getfl, getfd model.HostFactoryCallVectorReference, statID, getflID, getfdID string) error {
	if !strings.Contains(stat.Operation, "fstat") || statID == getflID || statID == getfdID || getflID == getfdID {
		return ErrHostFactorySourceRefused
	}
	for i, v := range []model.HostFactoryCallVectorReference{stat, getfl, getfd} {
		if v.OriginalHandleID != handle || v.OwnerPrimitiveRawSHA256 == nil || basal != "" && *v.OwnerPrimitiveRawSHA256 != basal || v.CollectionState != "complete_original_calls" || v.OriginalCallCount < 1 {
			return ErrHostFactorySourceRefused
		}
		id := []string{statID, getflID, getfdID}[i]
		parts := strings.Split(id, ":")
		if len(parts) != 2 || parts[0] != handle {
			return ErrHostFactorySourceRefused
		}
		ordinal, e := strconv.ParseUint(parts[1], 10, 64)
		if e != nil || ordinal < v.FirstOrdinal || ordinal > v.LastOrdinal {
			return ErrHostFactorySourceRefused
		}
	}
	if getfl.Operation != "fcntl_getfl" || getfd.Operation != "fcntl_getfd" {
		return ErrHostFactorySourceRefused
	}
	if stat.OriginalOwnerID != getfl.OriginalOwnerID || stat.OriginalOwnerID != getfd.OriginalOwnerID || stat.SubjectOwnerID != getfl.SubjectOwnerID || stat.SubjectOwnerID != getfd.SubjectOwnerID || *stat.OwnerPrimitiveRawSHA256 != *getfl.OwnerPrimitiveRawSHA256 || *stat.OwnerPrimitiveRawSHA256 != *getfd.OwnerPrimitiveRawSHA256 {
		return ErrHostFactorySourceRefused
	}
	return nil
}

func hostFactorySelectedCallID(id string, v model.HostFactoryCallVectorReference) bool {
	n, ok := hostFactoryCallOrdinal(id, v.OriginalHandleID)
	return ok && n >= v.FirstOrdinal && n <= v.LastOrdinal
}

func hostFactoryCallOrdinal(id, handle string) (uint64, bool) {
	parts := strings.Split(id, ":")
	if len(parts) != 2 || parts[0] != handle || hostFactoryString(id, "OriginalCallID") != nil {
		return 0, false
	}
	n, err := strconv.ParseUint(parts[1], 10, 64)
	return n, err == nil
}

func hostFactorySameDeclaredRefs(handle, subject, basal string, refs ...model.HostFactoryCallVectorReference) bool {
	owner := ""
	for _, r := range refs {
		if r.OriginalHandleID != handle || r.SubjectOwnerID != subject || r.OwnerPrimitiveRawSHA256 == nil || *r.OwnerPrimitiveRawSHA256 != basal || r.CollectionState != "complete_original_calls" || r.OriginalCallCount == 0 {
			return false
		}
		if owner == "" {
			owner = r.OriginalOwnerID
		} else if owner != r.OriginalOwnerID {
			return false
		}
	}
	return true
}

func hostFactoryAcquisitionDeclared(handle string, acquired *model.HostFactoryCallVectorReference, inherited *string, stat model.HostFactoryCallVectorReference) bool {
	if (acquired == nil) == (inherited == nil) {
		return false
	}
	if inherited != nil {
		return *inherited != handle
	}
	if acquired.CollectionState != "complete_original_calls" || acquired.OriginalCallCount == 0 || acquired.OriginalOwnerID != stat.OriginalOwnerID || acquired.SubjectOwnerID != stat.SubjectOwnerID || acquired.OwnerPrimitiveRawSHA256 == nil || stat.OwnerPrimitiveRawSHA256 == nil || *acquired.OwnerPrimitiveRawSHA256 != *stat.OwnerPrimitiveRawSHA256 {
		return false
	}
	rule, ok := hostFactoryOperations[acquired.Operation]
	// os.Pipe owns one acquisition call for two actual returned handles.
	// Its distinct writer is joined to ReturnedDescriptors by the consumer;
	// duplicating the acquisition call into the writer counter is forbidden.
	// The sealed gate's existing nonbyte operation owns one same-handle open.
	// Admitting its declared acquisition does not establish a native return.
	gateOpen := acquired.Operation == "gate_open_exclusive" && acquired.OriginalHandleID == handle && acquired.OriginalCallCount == 1
	return ok && (rule.kind == "native_descriptor" || strings.Contains(acquired.Operation, "pipe_create") || acquired.Operation == "gate_directory_duplicate" || acquired.Operation == "executable_anchor_duplicate" || gateOpen)
}

// ValidateHostFactoryHandleInventory checks the complete original handle union.
// Resolver/known FIRST relation checks establish byte/graph consistency only;
// source approval, signatures, native identity and current authority are separate.
func ValidateHostFactoryHandleInventory(value model.HostFactoryHandleCallInventory, resolve func(string) ([]byte, error), predecessor func(string, uint32) ([]byte, uint32, error)) error {
	if ValidateHostFactory(value) != nil || value.CollectionState != "complete_original_calls" || resolve == nil || predecessor == nil || value.OwnerPrimitiveRawSHA256 == nil {
		return ErrHostFactorySourceRefused
	}
	if value.OriginalCallCount == 0 {
		return nil
	} // empty graph consistency, never native absence/permission
	byOrdinal := map[uint64]model.HostFactoryPrimitiveIOReturn{}
	ids := map[string]bool{}
	for _, v := range value.OperationVectors {
		err := hostFactoryWalkCallVector(v, resolve, predecessor, true, func(p model.HostFactoryPrimitiveIOReturn, c model.HostFactoryCallVectorChunk) error {
			if c.BindingSchema != value.BindingSchema || c.BindingSHA256 != value.BindingSHA256 || c.OwnerRole != value.OwnerRole || c.OriginalOwnerID != value.OriginalOwnerID || p.OriginalCallOrdinal == nil || p.OriginalCallID == nil || ids[*p.OriginalCallID] {
				return ErrHostFactorySourceRefused
			}
			n := *p.OriginalCallOrdinal
			if n == 0 || n > value.LastOrdinal || p.OriginalOperationDeadline.After(value.OriginalOperationDeadline) {
				return ErrHostFactorySourceRefused
			}
			if _, exists := byOrdinal[n]; exists {
				return ErrHostFactorySourceRefused
			}
			byOrdinal[n] = p
			ids[*p.OriginalCallID] = true
			return nil
		})
		if err != nil {
			return err
		}
	}
	if uint64(len(byOrdinal)) != value.OriginalCallCount || value.OriginalCallCount != value.LastOrdinal || value.FirstOrdinal != 1 {
		return ErrHostFactorySourceRefused
	}
	var prior time.Time
	for n := uint64(1); n <= value.LastOrdinal; n++ {
		p, ok := byOrdinal[n]
		if !ok || p.OriginalCalledAt == nil || p.OriginalReturnedAt == nil || n > 1 && p.OriginalCalledAt.Before(prior) {
			return ErrHostFactorySourceRefused
		}
		prior = *p.OriginalReturnedAt
	}
	if prior.After(value.RecordedAt) {
		return ErrHostFactorySourceRefused
	}
	return nil
}

// DecodeHostFactoryTaskDirents parses ONLY the reviewed Linux/amd64 raw
// getdents64 buffers. It neither reads a directory nor establishes native EOF.
func DecodeHostFactoryTaskDirents(originalCallBuffers [][]byte) ([]int, error) {
	if originalCallBuffers == nil {
		return nil, ErrHostFactorySourceRefused
	}
	total := 0
	seen := map[int]bool{}
	tids := []int{}
	for _, raw := range originalCallBuffers {
		if len(raw) == 0 || len(raw) > 65536 || total > 65536-len(raw) {
			return nil, ErrHostFactorySourceRefused
		}
		total += len(raw)
		for at := 0; at < len(raw); {
			remaining := raw[at:]
			if len(remaining) < 24 {
				return nil, ErrHostFactorySourceRefused
			}
			reclen := int(binary.LittleEndian.Uint16(remaining[16:18]))
			if reclen < 24 || reclen%8 != 0 || reclen > len(remaining) {
				return nil, ErrHostFactorySourceRefused
			}
			record := remaining[:reclen]
			end := bytes.IndexByte(record[19:], 0)
			if end < 1 {
				return nil, ErrHostFactorySourceRefused
			}
			name := string(record[19 : 19+end])
			if strings.Contains(name, "/") {
				return nil, ErrHostFactorySourceRefused
			}
			if name != "." && name != ".." {
				if record[18] != 0 && record[18] != 4 || binary.LittleEndian.Uint64(record[:8]) == 0 {
					return nil, ErrHostFactorySourceRefused
				}
				n, e := strconv.ParseUint(name, 10, 31)
				if e != nil || n == 0 || strconv.FormatUint(n, 10) != name || seen[int(n)] || len(tids) >= 4096 {
					return nil, ErrHostFactorySourceRefused
				}
				seen[int(n)] = true
				tids = append(tids, int(n))
			}
			at += reclen
		}
	}
	sort.Ints(tids)
	return tids, nil
}

func hostFactoryNativeOperation(operation string, n model.HostFactoryNativeCallReturn) error {
	expected := ""
	switch {
	case operation == "task_inventory_getdents":
		expected = "unix_getdents64"
	case operation == "root_directory_create":
		expected = "unix_mkdirat"
	case operation == "initial_ledger_open_exclusive":
		expected = "unix_openat"
	case operation == "fcntl_getfl" || operation == "fcntl_getfd" || operation == "fcntl_setfl":
		expected = operation
	case strings.Contains(operation, "fstat"):
		expected = "unix_fstat"
	case strings.Contains(operation, "pipe_create"):
		expected = "original_os_pipe"
	case strings.HasSuffix(operation, "_start"):
		expected = "original_cmd_start"
	case strings.HasSuffix(operation, "_wait"):
		expected = "original_cmd_wait"
	case strings.HasSuffix(operation, "_poll") || operation == "native_subject_alive_poll":
		expected = "unix_poll"
	case strings.Contains(operation, "pidfd_signal"):
		expected = "unix_pidfd_send_signal"
	case strings.Contains(operation, "pidfd_pin") || operation == "native_subject_pidfd_open":
		expected = "unix_pidfd_open"
	case operation == "gate_directory_duplicate" || operation == "executable_anchor_duplicate":
		expected = "fcntl_dupfd_cloexec"
	case strings.HasSuffix(operation, "_openat"):
		expected = "unix_openat"
	case strings.HasSuffix(operation, "_open") || strings.HasSuffix(operation, "_open_exclusive"):
		if n.Kind != "unix_open" && n.Kind != "unix_openat" {
			return ErrHostFactorySourceRefused
		}
		expected = n.Kind
	case strings.HasSuffix(operation, "_sync"):
		expected = "original_file_sync"
	case strings.HasSuffix(operation, "_close"):
		if n.Kind != "original_file_close" && n.Kind != "unix_close" {
			return ErrHostFactorySourceRefused
		}
		expected = n.Kind
	}
	if expected == "" || n.Kind != expected || hostFactoryNativeIntrinsic(n) != nil {
		return ErrHostFactorySourceRefused
	}
	if operation == "initial_ledger_open_exclusive" && (n.RequestedMode == nil || *n.RequestedMode != 0600 || n.RequestedFlags == nil || *n.RequestedFlags != (1|64|128|2048|131072|524288)) {
		return ErrHostFactorySourceRefused
	}
	return nil
}

// hostFactoryRepresentationIntrinsic checks representation, never native
// ownership or completeness. Canonical bytes/crypto alone do not admit a realm.
func hostFactoryRepresentationIntrinsic(value any) error {
	fail := ErrHostFactorySourceRefused
	switch x := value.(type) {
	case model.HostFactoryNativeObservationReference:
		if !hostFactoryHas([]string{"process", "task_directory", "thread_children"}, x.ObservationKind) {
			return fail
		}
	case model.HostFactoryNativeObservationCollectionReference:
		if x.ObservationKind != "thread_children" || x.OriginalObservationCount < 1 || x.OriginalObservationCount > 4096 {
			return fail
		}
	case model.HostFactoryNativeObservationManifestReference:
		if x.FirstOrdinal < 1 || x.LastOrdinal < x.FirstOrdinal || x.LastOrdinal > 4096 || x.OriginalObservationCount != x.LastOrdinal-x.FirstOrdinal+1 {
			return fail
		}
	case model.HostFactoryNativeObservationRecord:
		if !hostFactoryHas([]string{"host_exterior", "host_registrar"}, x.ObserverRole) || !hostFactoryHas([]string{"host_exterior", "host_registrar", "host_worker", "factory_ordinary_worker"}, x.SubjectRole) || x.BindingSchema == "original_host_factory_source_approval_v4" {
			return fail
		}
		p, t, c := x.Process != nil, x.TaskDirectory != nil, x.ThreadChildren != nil
		if (p && (t || c)) || (t && c) || (!p && !t && !c) {
			return fail
		}
		if x.ObservationKind == "process" && !p || x.ObservationKind == "task_directory" && !t || x.ObservationKind == "thread_children" && !c {
			return fail
		}
		if c {
			t := x.ThreadChildren
			if t.ThreadStatBeforeSHA256 != t.OriginalThreadStatBeforeRead.OriginalSHA256 || t.ThreadStatAfterSHA256 != t.OriginalThreadStatAfterRead.OriginalSHA256 || !hostFactoryOrdered(t.OriginalThreadStatBeforeRead.OriginalCloseReturnedAt, t.OriginalChildrenRead.OriginalCalledAt, t.OriginalChildrenRead.OriginalCloseReturnedAt, t.OriginalThreadStatAfterRead.OriginalCalledAt, t.OriginalThreadStatAfterRead.OriginalCloseReturnedAt) {
				return fail
			}
			if x.OriginalCensusCollectionID == nil || x.OriginalCensusOrdinal == nil {
				return fail
			}
			for _, f := range []model.HostFactoryOriginalIOFact{x.ThreadChildren.OriginalThreadStatBeforeRead, x.ThreadChildren.OriginalChildrenRead, x.ThreadChildren.OriginalThreadStatAfterRead} {
				if f.SubjectOwnerID != x.SubjectOwnerID || f.OwnerPrimitiveRawSHA256 != x.ObserverPrimitiveRawSHA256 {
					return fail
				}
			}
		} else if x.OriginalCensusCollectionID != nil || x.OriginalCensusOrdinal != nil {
			return fail
		}
		if p {
			pin := x.Process.OriginalSubjectNativePin
			if pin.ObserverOwnerID != x.ObserverOwnerID || pin.SubjectOwnerID != x.SubjectOwnerID || pin.ObserverPrimitiveRawSHA256 != x.ObserverPrimitiveRawSHA256 {
				return fail
			}
		}
		if t && (x.TaskDirectory.SubjectOwnerID != x.SubjectOwnerID || x.TaskDirectory.OwnerPrimitiveRawSHA256 != x.ObserverPrimitiveRawSHA256) {
			return fail
		}
	case model.HostFactoryNativeObservationManifest:
		if x.ObservationKind != "thread_children" || !hostFactoryHas([]string{"host_exterior", "host_registrar"}, x.ObserverRole) || x.BindingSchema == "original_host_factory_source_approval_v4" || x.FirstOrdinal < 1 || x.LastOrdinal < x.FirstOrdinal || x.LastOrdinal > 4096 || x.OriginalObservationCount != x.LastOrdinal-x.FirstOrdinal+1 {
			return fail
		}
		if x.Level == 0 {
			if len(x.Observations) < 1 || len(x.Observations) > 16 || len(x.Children) != 0 || uint32(len(x.Observations)) != x.OriginalObservationCount {
				return fail
			}
			ids := map[string]bool{}
			for _, r := range x.Observations {
				if r.ObservationKind != x.ObservationKind || r.ObserverOwnerID != x.ObserverOwnerID || r.ObserverPrimitiveRawSHA256 != x.ObserverPrimitiveRawSHA256 || ids[r.ObservationID] {
					return fail
				}
				ids[r.ObservationID] = true
			}
		} else {
			if len(x.Children) < 1 || len(x.Children) > 16 || len(x.Observations) != 0 {
				return fail
			}
			next, total := x.FirstOrdinal, uint32(0)
			for _, r := range x.Children {
				if r.Level+1 != x.Level || r.FirstOrdinal != next {
					return fail
				}
				next = r.LastOrdinal + 1
				total += r.OriginalObservationCount
			}
			if next != x.LastOrdinal+1 || total != x.OriginalObservationCount {
				return fail
			}
		}
	}
	return nil
}

// These callbacks select ORIGINAL publications. They do not authorize source
// from a caller-supplied key or reconstruct an immutable row from its hash.
// Source9 owns approved observer inventory; Source13 owns raw/SQL/FIRST joins.
type hostFactoryNativeGraph struct {
	sourceProfile       *HostFactorySourceProfile
	sourceCallPurpose   func(string) (HostFactorySourceCallPurpose, bool, error)
	sourceExpectedStage string
	root, binding, sha  string
	deadline            time.Time
	original            func(string, string) ([]byte, []byte, error)
	observer            func(string, string, string, string, string, string) (ed25519.PublicKey, error)
	io                  func(string) ([]byte, error)
	prior               func(string, uint32) ([]byte, uint32, error)
	dirents             func(string) ([]byte, error)
	selectedInventory   func(string, model.HostFactoryCallVectorReference) ([]byte, error)
	records             map[string]model.HostFactoryNativeObservationRecord
	refs                map[string]model.HostFactoryNativeObservationReference
	manifests           map[string]bool
	inventory           map[string]model.HostFactoryHandleCallInventory
	chunks              map[string][]byte
	ordered             []model.HostFactoryNativeObservationRecord
}

func hostFactoryNewNativeGraph(root, binding, sha string, deadline time.Time, original func(string, string) ([]byte, []byte, error), observer func(string, string, string, string, string, string) (ed25519.PublicKey, error), io func(string) ([]byte, error), prior func(string, uint32) ([]byte, uint32, error), dirents func(string) ([]byte, error), selectedInventory func(string, model.HostFactoryCallVectorReference) ([]byte, error)) (*hostFactoryNativeGraph, error) {
	if !guestUUID(root) || !hostFactoryHas([]string{"original_host_factory_root_preparation_v4", "original_host_factory_pre_authority_scope_v4", "factory_ordinary_source_binding_v4"}, binding) || !hostFactoryHex(sha, 64) || deadline.IsZero() || original == nil || observer == nil || io == nil || prior == nil || dirents == nil || selectedInventory == nil {
		return nil, ErrHostFactorySourceRefused
	}
	_, off := deadline.Zone()
	if off != 0 {
		return nil, ErrHostFactorySourceRefused
	}
	return &hostFactoryNativeGraph{root: root, binding: binding, sha: sha, deadline: deadline, original: original, observer: observer, io: io, prior: prior, dirents: dirents, selectedInventory: selectedInventory, records: map[string]model.HostFactoryNativeObservationRecord{}, refs: map[string]model.HostFactoryNativeObservationReference{}, manifests: map[string]bool{}, inventory: map[string]model.HostFactoryHandleCallInventory{}, chunks: map[string][]byte{}}, nil
}
func (g *hostFactoryNativeGraph) readIO(sha string) ([]byte, error) {
	if raw, ok := g.chunks[sha]; ok {
		return append([]byte(nil), raw...), nil
	}
	raw, err := g.io(sha)
	if err != nil || len(raw) < 1 || len(raw) > hostFactoryLimit || HostFactoryRawSHA256(raw) != sha {
		return nil, ErrHostFactorySourceRefused
	}
	g.chunks[sha] = append([]byte(nil), raw...)
	return raw, nil
}
func (g *hostFactoryNativeGraph) signed(bodySHA, envelopeSHA string, target any, observerID, primitive string) error {
	raw, envelope, err := g.original(bodySHA, envelopeSHA)
	if err != nil || len(raw) < 1 || len(raw) > hostFactoryLimit || len(envelope) < 1 || len(envelope) > hostFactoryLimit || HostFactoryRawSHA256(raw) != bodySHA || HostFactoryRawSHA256(envelope) != envelopeSHA || DecodeHostFactory(raw, target) != nil {
		return ErrHostFactorySourceRefused
	}
	// Only known typed BODY can choose its fixed observer role and binding.
	v := reflect.ValueOf(target).Elem()
	role := v.FieldByName("ObserverRole").String()
	if v.FieldByName("FactoryRootID").String() != g.root || v.FieldByName("ObserverOwnerID").String() != observerID || v.FieldByName("ObserverPrimitiveRawSHA256").String() != primitive {
		return ErrHostFactorySourceRefused
	}
	actualBinding := v.FieldByName("BindingSchema").String()
	actualSHA := v.FieldByName("BindingSHA256").String()
	if !hostFactoryHas([]string{"original_host_factory_root_preparation_v4", "original_host_factory_pre_authority_scope_v4", "factory_ordinary_source_binding_v4"}, actualBinding) {
		return ErrHostFactorySourceRefused
	}

	keyID := ""
	if g.sourceProfile != nil {
		var err error
		keyID, err = g.sourceProfile.envelopeKey(envelope, actualBinding)
		if err != nil {
			return ErrHostFactorySourceRefused
		}
	} else if actualBinding == "original_host_factory_pre_authority_scope_v4" {
		var e model.HostFactorySignedEnvelope
		if DecodeHostFactory(envelope, &e) != nil {
			return ErrHostFactorySourceRefused
		}
		keyID = e.KeyID
	} else {
		var e model.HostFactoryRootSignedEnvelope
		if DecodeHostFactory(envelope, &e) != nil {
			return ErrHostFactorySourceRefused
		}
		keyID = e.KeyID
	}
	key, err := g.observer(role, keyID, observerID, primitive, actualBinding, actualSHA)
	if err != nil {
		return ErrHostFactorySourceRefused
	}
	if g.sourceProfile != nil {
		if _, err := g.sourceProfile.VerifyEnvelope(envelope, target, role, keyID, actualBinding, actualSHA, key); err != nil {
			return ErrHostFactorySourceRefused
		}
	} else if VerifyHostFactoryEnvelope(envelope, target, role, keyID, actualBinding, actualSHA, key) != nil {
		return ErrHostFactorySourceRefused
	}
	again, err := CanonicalHostFactory(target)
	if err != nil || !bytes.Equal(again, raw) {
		return ErrHostFactorySourceRefused
	}
	return nil
}
func (g *hostFactoryNativeGraph) observation(r model.HostFactoryNativeObservationReference) (model.HostFactoryNativeObservationRecord, error) {
	zero := model.HostFactoryNativeObservationRecord{}
	if ValidateHostFactory(r) != nil {
		return zero, ErrHostFactorySourceRefused
	}
	if old, ok := g.records[r.ObservationID]; ok {
		if !reflect.DeepEqual(g.refs[r.ObservationID], r) {
			return zero, ErrHostFactorySourceRefused
		}
		return old, nil
	}
	if len(g.records) >= 4128 {
		return zero, ErrHostFactorySourceRefused
	}
	var record model.HostFactoryNativeObservationRecord
	if g.signed(r.OriginalBodySHA256, r.OriginalEnvelopeSHA256, &record, r.ObserverOwnerID, r.ObserverPrimitiveRawSHA256) != nil || record.ObservationID != r.ObservationID || record.ObservationKind != r.ObservationKind || record.SubjectOwnerID != r.SubjectOwnerID || record.SubjectPrimitiveRawSHA256 != r.SubjectPrimitiveRawSHA256 {
		return zero, ErrHostFactorySourceRefused
	}
	if g.payloadIO(record) != nil {
		return zero, ErrHostFactorySourceRefused
	}
	g.records[r.ObservationID] = record
	g.refs[r.ObservationID] = r
	g.ordered = append(g.ordered, record)
	return record, nil
}
func (g *hostFactoryNativeGraph) collection(r model.HostFactoryNativeObservationCollectionReference) ([]model.HostFactoryNativeObservationRecord, error) {
	if ValidateHostFactory(r) != nil {
		return nil, ErrHostFactorySourceRefused
	}
	out := []model.HostFactoryNativeObservationRecord{}
	ids := map[string]bool{}
	var walk func(model.HostFactoryNativeObservationManifestReference, time.Time) error
	walk = func(ref model.HostFactoryNativeObservationManifestReference, parentRecordedAt time.Time) error {
		if ValidateHostFactory(ref) != nil || g.manifests[ref.OriginalBodySHA256] || len(g.manifests) >= 4369 {
			return ErrHostFactorySourceRefused
		}
		g.manifests[ref.OriginalBodySHA256] = true
		var node model.HostFactoryNativeObservationManifest
		if g.signed(ref.OriginalBodySHA256, ref.OriginalEnvelopeSHA256, &node, r.ObserverOwnerID, r.ObserverPrimitiveRawSHA256) != nil || !node.OriginalOperationDeadline.Equal(g.deadline) || node.CollectionID != r.CollectionID || node.BindingSchema != r.BindingSchema || node.BindingSHA256 != r.BindingSHA256 || node.ObservationKind != r.ObservationKind || node.Level != ref.Level || node.FirstOrdinal != ref.FirstOrdinal || node.LastOrdinal != ref.LastOrdinal || node.OriginalObservationCount != ref.OriginalObservationCount || node.RecordedAt.After(g.deadline) || node.RecordedAt.After(node.OriginalOperationDeadline) || node.RecordedAt.After(parentRecordedAt) {
			return ErrHostFactorySourceRefused
		}
		if node.Level == 0 {
			for i, obs := range node.Observations {
				if ids[obs.ObservationID] {
					return ErrHostFactorySourceRefused
				}
				ids[obs.ObservationID] = true
				rec, err := g.observation(obs)
				if err != nil || !rec.OriginalOperationDeadline.Equal(g.deadline) || rec.BindingSchema != node.BindingSchema || rec.BindingSHA256 != node.BindingSHA256 || rec.ObserverRole != node.ObserverRole || rec.OriginalCensusCollectionID == nil || *rec.OriginalCensusCollectionID != r.CollectionID || rec.OriginalCensusOrdinal == nil || *rec.OriginalCensusOrdinal != node.FirstOrdinal+uint32(i) || hostFactoryNativeRecordLastReturn(rec).After(node.RecordedAt) {
					return ErrHostFactorySourceRefused
				}
				if len(out) > 0 && rec.ThreadChildren.OriginalThreadStatBeforeRead.OriginalCalledAt.Before(hostFactoryNativeRecordLastReturn(out[len(out)-1])) {
					return ErrHostFactorySourceRefused
				}
				out = append(out, rec)
			}
		} else {
			for _, child := range node.Children {
				if walk(child, node.RecordedAt) != nil {
					return ErrHostFactorySourceRefused
				}
			}
		}
		return nil
	}
	// Root level is read from its original BODY, but cached through exact paired
	// resolver below so it is not a second native/SQL read with a new epoch.
	raw, env, err := g.original(r.ManifestRootBodySHA256, r.ManifestRootEnvelopeSHA256)
	var root model.HostFactoryNativeObservationManifest
	if err != nil || len(raw) < 1 || len(raw) > hostFactoryLimit || len(env) < 1 || len(env) > hostFactoryLimit || HostFactoryRawSHA256(raw) != r.ManifestRootBodySHA256 || HostFactoryRawSHA256(env) != r.ManifestRootEnvelopeSHA256 || DecodeHostFactory(raw, &root) != nil {
		return nil, ErrHostFactorySourceRefused
	}
	original := g.original
	g.original = func(a, b string) ([]byte, []byte, error) {
		if a == r.ManifestRootBodySHA256 && b == r.ManifestRootEnvelopeSHA256 {
			return append([]byte(nil), raw...), append([]byte(nil), env...), nil
		}
		return original(a, b)
	}
	defer func() { g.original = original }()
	if walk(model.HostFactoryNativeObservationManifestReference{OriginalBodySHA256: r.ManifestRootBodySHA256, OriginalEnvelopeSHA256: r.ManifestRootEnvelopeSHA256, Level: root.Level, FirstOrdinal: 1, LastOrdinal: r.OriginalObservationCount, OriginalObservationCount: r.OriginalObservationCount}, g.deadline) != nil || uint32(len(out)) != r.OriginalObservationCount {
		return nil, ErrHostFactorySourceRefused
	}
	return out, nil
}
func hostFactoryNativeRecordLastReturn(r model.HostFactoryNativeObservationRecord) time.Time {
	if r.Process != nil {
		return r.Process.OriginalSubjectNativePin.OriginalObservedAt
	}
	if r.TaskDirectory != nil {
		return r.TaskDirectory.OriginalSubjectStatAfterRead.OriginalCloseReturnedAt
	}
	if r.ThreadChildren != nil {
		return r.ThreadChildren.OriginalThreadStatAfterRead.OriginalCloseReturnedAt
	}
	return time.Time{}
}

// Exact whole originals are resolved once by immutable identity. On any missing,
// incomplete, foreign, late, oversize or unknown relation no graph is returned.
func ResolveHostFactoryNativeObservation(reference model.HostFactoryNativeObservationReference, factoryRootID, bindingSchema, bindingSHA256 string, originalDeadline time.Time, resolveOriginal func(string, string) ([]byte, []byte, error), trustedObserver func(string, string, string, string, string, string) (ed25519.PublicKey, error), resolveIO func(string) ([]byte, error), predecessor func(string, uint32) ([]byte, uint32, error), getdentsOriginal func(string) ([]byte, error), resolveInventory func(string, model.HostFactoryCallVectorReference) ([]byte, error)) (model.HostFactoryNativeObservationRecord, error) {
	g, e := hostFactoryNewNativeGraph(factoryRootID, bindingSchema, bindingSHA256, originalDeadline, resolveOriginal, trustedObserver, resolveIO, predecessor, getdentsOriginal, resolveInventory)
	if e != nil {
		return model.HostFactoryNativeObservationRecord{}, e
	}
	return g.observation(reference)
}
func ResolveHostFactoryNativeCollection(reference model.HostFactoryNativeObservationCollectionReference, factoryRootID string, originalDeadline time.Time, resolveOriginal func(string, string) ([]byte, []byte, error), trustedObserver func(string, string, string, string, string, string) (ed25519.PublicKey, error), resolveIO func(string) ([]byte, error), predecessor func(string, uint32) ([]byte, uint32, error), getdentsOriginal func(string) ([]byte, error), resolveInventory func(string, model.HostFactoryCallVectorReference) ([]byte, error)) ([]model.HostFactoryNativeObservationRecord, error) {
	g, e := hostFactoryNewNativeGraph(factoryRootID, reference.BindingSchema, reference.BindingSHA256, originalDeadline, resolveOriginal, trustedObserver, resolveIO, predecessor, getdentsOriginal, resolveInventory)
	if e != nil {
		return nil, e
	}
	return g.collection(reference)
}

func (g *hostFactoryNativeGraph) payloadIO(record model.HostFactoryNativeObservationRecord) error {
	fail := ErrHostFactorySourceRefused
	var payload any
	if record.Process != nil {
		payload = *record.Process
	}
	if record.TaskDirectory != nil {
		payload = *record.TaskDirectory
	}
	if record.ThreadChildren != nil {
		payload = *record.ThreadChildren
	}
	inventorySHAs := map[string]bool{}
	vectors := []model.HostFactoryCallVectorReference{}
	facts := []model.HostFactoryOriginalIOFact{}
	var scan func(reflect.Value, string)
	scan = func(v reflect.Value, name string) {
		if v.Kind() == reflect.Pointer {
			if !v.IsNil() {
				scan(v.Elem(), name)
			}
			return
		}
		if v.Type() == reflect.TypeOf(model.HostFactoryCallVectorReference{}) {
			vectors = append(vectors, v.Interface().(model.HostFactoryCallVectorReference))
			return
		}
		if v.Type() == reflect.TypeOf(model.HostFactoryOriginalIOFact{}) {
			facts = append(facts, v.Interface().(model.HostFactoryOriginalIOFact))
		}
		if v.Kind() == reflect.Struct {
			for i := 0; i < v.NumField(); i++ {
				if v.Type().Field(i).Type != reflect.TypeOf(time.Time{}) {
					scan(v.Field(i), v.Type().Field(i).Name)
				}
			}
		}
		if v.Kind() == reflect.Array || v.Kind() == reflect.Slice {
			for i := 0; i < v.Len(); i++ {
				scan(v.Index(i), name)
			}
		}
		if v.Kind() == reflect.String && (name == "NativeHandleInventorySHAs" || name == "OriginalHandleInventorySHA256") {
			inventorySHAs[v.String()] = true
		}
	}
	scan(reflect.ValueOf(payload), "")
	// Missing inventories cannot be guessed from samehandle/latest SQL state.
	// Resolve an immutable exact publication relation for EVERY selected vector,
	// including stat/children source handles with no inline inventory hash field.
	if len(vectors) > 20 {
		return fail
	}
	for _, v := range vectors {
		if v.OriginalOwnerID != record.ObserverOwnerID || v.OwnerPrimitiveRawSHA256 == nil || *v.OwnerPrimitiveRawSHA256 != record.ObserverPrimitiveRawSHA256 || v.SubjectOwnerID != record.SubjectOwnerID {
			return fail
		}
		raw, e := g.selectedInventory(record.ObservationID, v)
		var inv model.HostFactoryHandleCallInventory
		if e != nil || len(raw) < 1 || len(raw) > hostFactoryLimit || DecodeHostFactory(raw, &inv) != nil {
			return fail
		}
		exact := false
		for _, selected := range inv.OperationVectors {
			if reflect.DeepEqual(selected, v) {
				exact = true
				break
			}
		}
		if !exact {
			return fail
		}
		sha := HostFactoryRawSHA256(raw)
		if old, ok := g.chunks[sha]; ok && !bytes.Equal(old, raw) {
			return fail
		}
		g.chunks[sha] = append([]byte(nil), raw...)
		inventorySHAs[sha] = true
	}

	byHandle := map[string]model.HostFactoryHandleCallInventory{}
	calls := map[string]model.HostFactoryPrimitiveIOReturn{}
	for sha := range inventorySHAs {
		raw, e := g.readIO(sha)
		var inv model.HostFactoryHandleCallInventory
		if e != nil || DecodeHostFactory(raw, &inv) != nil || inv.OriginalOwnerID != record.ObserverOwnerID || inv.OwnerRole != record.ObserverRole || inv.OwnerPrimitiveRawSHA256 == nil || *inv.OwnerPrimitiveRawSHA256 != record.ObserverPrimitiveRawSHA256 || inv.RecordedAt.After(g.deadline) || ValidateHostFactoryHandleInventory(inv, g.readIO, g.prior) != nil {
			return fail
		}
		if prior, ok := byHandle[inv.OriginalHandleID]; ok && !reflect.DeepEqual(prior, inv) {
			return fail
		}
		byHandle[inv.OriginalHandleID] = inv
		for _, v := range inv.OperationVectors {
			if hostFactoryWalkCallVector(v, g.readIO, g.prior, true, func(p model.HostFactoryPrimitiveIOReturn, c model.HostFactoryCallVectorChunk) error {
				if p.OriginalCallID == nil || p.OriginalCalledAt == nil || p.OriginalReturnedAt == nil || p.OriginalReturnedAt.After(g.deadline) || p.OriginalReturnedAt.After(p.OriginalOperationDeadline) || c.RecordedAt.After(g.deadline) || p.OriginalNativeReturn != nil && (p.OriginalNativeReturn.OriginalErrorPresent == nil || *p.OriginalNativeReturn.OriginalErrorPresent) {
					return fail
				}
				if old, ok := calls[*p.OriginalCallID]; ok && !reflect.DeepEqual(old, p) {
					return fail
				}
				calls[*p.OriginalCallID] = p
				return nil
			}) != nil {
				return fail
			}
		}
	}
	for _, v := range vectors {
		inv, ok := byHandle[v.OriginalHandleID]
		if !ok || v.CollectionState != "complete_original_calls" || v.OriginalCallCount == 0 {
			return fail
		}
		exact := false
		for _, declared := range inv.OperationVectors {
			if reflect.DeepEqual(declared, v) {
				exact = true
				break
			}
		}
		if !exact {
			return fail
		}
	}
	if g.sourceSelectedPurposes(record, vectors, calls) != nil {
		return fail
	}
	// Exact source projections must join the SAME retained operation/Close facts.
	for _, f := range facts {
		sum := int64(0)
		var first, last time.Time
		singleSHA := ""
		count := 0
		if hostFactoryWalkCallVector(f.OriginalCallVector, g.readIO, g.prior, true, func(p model.HostFactoryPrimitiveIOReturn, c model.HostFactoryCallVectorChunk) error {
			if p.OriginalCount == nil || p.OriginalSHA256 == nil || p.OriginalEOF == nil || p.OwnerPrimitiveRawSHA256 == nil || *p.OwnerPrimitiveRawSHA256 != f.OwnerPrimitiveRawSHA256 || p.SubjectOwnerID != f.SubjectOwnerID {
				return fail
			}
			if count == 0 {
				first = *p.OriginalCalledAt
			}
			last = *p.OriginalReturnedAt
			sum += *p.OriginalCount
			singleSHA = *p.OriginalSHA256
			count++
			return nil
		}) != nil || sum != f.OriginalCount || !first.Equal(f.OriginalCalledAt) || !last.Equal(f.OriginalReturnedAt) || count == 1 && singleSHA != f.OriginalSHA256 {
			return fail
		}
		var closed time.Time
		if hostFactoryWalkCallVector(f.OriginalCloseCallVector, g.readIO, g.prior, true, func(p model.HostFactoryPrimitiveIOReturn, c model.HostFactoryCallVectorChunk) error {
			if p.OriginalReturnClass != "success" || p.OriginalReturnedAt == nil {
				return fail
			}
			closed = *p.OriginalReturnedAt
			return nil
		}) != nil || !closed.Equal(f.OriginalCloseReturnedAt) {
			return fail
		}
	}
	// Original syscall/stat/scalar values selected by CallID cannot be replaced
	// with requested flags or a fresh stat from a different opened descriptor.
	if record.Process != nil {
		p := record.Process
		h, o, pin := p.OriginalHeldExecutableRead, p.OriginalProcessOwnerRead, p.OriginalSubjectNativePin
		if !hostFactoryGraphAcquired(calls, h.OriginalOpenCallVector, h.OriginalHandleID, h.OriginalDescriptorNumber, 0) || !hostFactoryGraphAcquired(calls, o.OriginalOpenCallVector, o.OriginalHandleID, o.OriginalDescriptorNumber, 0) || !hostFactoryGraphClosed(calls, h.OriginalRead.OriginalCloseCallVector, h.OriginalDescriptorNumber) || !hostFactoryGraphClosed(calls, o.OriginalCloseCallVector, o.OriginalDescriptorNumber) || pin.OriginalOpenCallVector != nil && !hostFactoryGraphAcquired(calls, *pin.OriginalOpenCallVector, pin.OriginalHandleID, pin.OriginalDescriptorNumber, p.PID) {
			return fail
		}

		if !hostFactoryGraphStat(calls, h.OriginalBeforeFstatCallID, h.OriginalBeforeStat, h.OriginalDescriptorNumber) || !hostFactoryGraphStat(calls, h.OriginalAfterFstatCallID, h.OriginalAfterStat, h.OriginalDescriptorNumber) {
			return fail
		}
		if !hostFactoryGraphVectorStat(calls, o.OriginalFstatCallVector, o.OriginalStat, o.OriginalDescriptorNumber) || !hostFactoryGraphVectorStat(calls, pin.OriginalFstatCallVector, pin.OriginalStat, pin.OriginalDescriptorNumber) {
			return fail
		}
		for _, id := range []string{pin.OriginalBeforePollCallID, pin.OriginalAfterPollCallID} {
			c, ok := calls[id]
			if !ok || c.OriginalNativeReturn == nil || c.OriginalNativeReturn.InputDescriptorNumber == nil || *c.OriginalNativeReturn.InputDescriptorNumber != pin.OriginalDescriptorNumber || id == pin.OriginalBeforePollCallID && c.OriginalReturnedAt.After(p.OriginalNativeReadStartedAt) || id == pin.OriginalAfterPollCallID && c.OriginalCalledAt.Before(p.OriginalNativeCloseReturnedAt) || c.OriginalNativeReturn.Kind != "unix_poll" || c.OriginalNativeReturn.OriginalScalar == nil || *c.OriginalNativeReturn.OriginalScalar != 0 || c.OriginalNativeReturn.OriginalPollRevents == nil || *c.OriginalNativeReturn.OriginalPollRevents != 0 {
				return fail
			}
		}
	}
	if record.TaskDirectory != nil {
		t := record.TaskDirectory
		if !hostFactoryGraphAcquired(calls, t.OriginalOpenCallVector, t.OriginalHandleID, t.OriginalDescriptorNumber, 0) || !hostFactoryGraphClosed(calls, t.OriginalCloseCallVector, t.OriginalDescriptorNumber) {
			return fail
		}

		if !hostFactoryGraphVectorStat(calls, t.OriginalFstatCallVector, t.OriginalDirectoryStat, t.OriginalDescriptorNumber) {
			return fail
		}
		buffers := [][]byte{}
		all := []byte{}
		terminal := false
		if hostFactoryWalkCallVector(t.OriginalGetdentsCallVector, g.readIO, g.prior, true, func(p model.HostFactoryPrimitiveIOReturn, c model.HostFactoryCallVectorChunk) error {
			n := p.OriginalNativeReturn
			if terminal || n == nil || n.Kind != "unix_getdents64" || n.InputDescriptorNumber == nil || *n.InputDescriptorNumber != t.OriginalDescriptorNumber || n.OriginalScalar == nil || n.OriginalErrorPresent == nil || *n.OriginalErrorPresent || p.OriginalCount == nil || p.OriginalSHA256 == nil || p.OriginalEOF == nil || *p.OriginalEOF || p.OriginalCallID == nil || *n.OriginalScalar != *p.OriginalCount {
				return fail
			}
			raw, e := g.dirents(*p.OriginalCallID)
			if e != nil || raw == nil || len(raw) > hostFactoryLimit || int64(len(raw)) != *p.OriginalCount || HostFactoryRawSHA256(raw) != *p.OriginalSHA256 {
				return fail
			}
			if *p.OriginalCount == 0 {
				if *p.OriginalCallID != t.OriginalTerminalCallID || p.OriginalReturnClass != "native_zero_return" {
					return fail
				}
				terminal = true
				return nil
			}
			if p.OriginalReturnClass != "success" || len(all) > hostFactoryLimit-len(raw) {
				return fail
			}
			all = append(all, raw...)
			buffers = append(buffers, append([]byte(nil), raw...))
			return nil
		}) != nil || !terminal || uint64(len(all)) != t.OriginalRawBytes || HostFactoryRawSHA256(all) != t.OriginalRawSHA256 {
			return fail
		}
		tids, e := DecodeHostFactoryTaskDirents(buffers)
		if e != nil || !reflect.DeepEqual(tids, t.ParsedTIDs) {
			return fail
		}
	}
	if hostFactoryNativeRecordLastReturn(record).IsZero() || hostFactoryNativeRecordLastReturn(record).After(record.OriginalOperationDeadline) || hostFactoryNativeRecordLastReturn(record).After(g.deadline) {
		return fail
	}
	return nil
}
func hostFactoryGraphStat(calls map[string]model.HostFactoryPrimitiveIOReturn, id string, want model.HostFactoryNativeStatReturn, descriptor int) bool {
	p, ok := calls[id]
	return ok && p.OriginalNativeReturn != nil && p.OriginalNativeReturn.Kind == "unix_fstat" && p.OriginalNativeReturn.InputDescriptorNumber != nil && *p.OriginalNativeReturn.InputDescriptorNumber == descriptor && p.OriginalNativeReturn.OriginalStat != nil && *p.OriginalNativeReturn.OriginalStat == want
}
func hostFactoryGraphVectorStat(calls map[string]model.HostFactoryPrimitiveIOReturn, v model.HostFactoryCallVectorReference, want model.HostFactoryNativeStatReturn, descriptor int) bool {
	n := 0
	for _, p := range calls {
		if p.Operation == v.Operation && p.OriginalHandleID == v.OriginalHandleID && p.OriginalCallOrdinal != nil && *p.OriginalCallOrdinal >= v.FirstOrdinal && *p.OriginalCallOrdinal <= v.LastOrdinal {
			if p.OriginalCallID == nil || !hostFactoryGraphStat(calls, *p.OriginalCallID, want, descriptor) {
				return false
			}
			n++
		}
	}
	return uint64(n) == v.OriginalCallCount && n > 0
}

func ResolveHostFactoryNativeAggregate(value any, factoryRootID, bindingSchema, bindingSHA256 string, originalDeadline time.Time, resolveOriginal func(string, string) ([]byte, []byte, error), trustedObserver func(string, string, string, string, string, string) (ed25519.PublicKey, error), resolveIO func(string) ([]byte, error), predecessor func(string, uint32) ([]byte, uint32, error), getdentsOriginal func(string) ([]byte, error), resolveInventory func(string, model.HostFactoryCallVectorReference) ([]byte, error)) ([]model.HostFactoryNativeObservationRecord, error) {
	g, e := hostFactoryNewNativeGraph(factoryRootID, bindingSchema, bindingSHA256, originalDeadline, resolveOriginal, trustedObserver, resolveIO, predecessor, getdentsOriginal, resolveInventory)
	if e != nil || ValidateHostFactory(value) != nil || !hostFactoryEnvelopeBinding(value, bindingSchema, bindingSHA256) {
		return nil, ErrHostFactorySourceRefused
	}
	phaseReference, e := hostFactoryNativePhaseReference(value)
	if e != nil {
		return nil, e
	}
	phase, e := g.observation(phaseReference)
	if e != nil || !phase.OriginalOperationDeadline.Equal(originalDeadline) {
		return nil, ErrHostFactorySourceRefused
	}
	if g.aggregate(value) != nil {
		return nil, ErrHostFactorySourceRefused
	}
	// Every selected current observation belongs to this exact signed phase.
	// Earlier acquisition/IO/inventory deadlines remain their original values;
	// they do not change the captured deadline of a fresh observation record.
	for _, record := range g.ordered {
		if !record.OriginalOperationDeadline.Equal(originalDeadline) {
			return nil, ErrHostFactorySourceRefused
		}
	}
	return append([]model.HostFactoryNativeObservationRecord(nil), g.ordered...), nil
}
func (g *hostFactoryNativeGraph) process(ref model.HostFactoryNativeObservationReference, role string) (model.HostFactoryNativeProcess, error) {
	r, e := g.observation(ref)
	if e != nil || r.Process == nil || r.SubjectRole != role {
		return model.HostFactoryNativeProcess{}, ErrHostFactorySourceRefused
	}
	return *r.Process, nil
}
func (g *hostFactoryNativeGraph) aggregate(value any) error {
	fail := ErrHostFactorySourceRefused
	top := reflect.ValueOf(value)
	if top.Kind() == reflect.Pointer {
		top = top.Elem()
	}
	for i := 0; i < top.NumField(); i++ {
		if top.Field(i).Type() == reflect.TypeOf(time.Time{}) && top.Field(i).Interface().(time.Time).After(g.deadline) {
			return fail
		}
	}
	if v := reflect.ValueOf(value); v.Kind() == reflect.Pointer {
		value = v.Elem().Interface()
	}
	switch x := value.(type) {
	case model.HostFactoryOriginalStartReturn:
		exterior, e := g.process(x.Exterior, "host_exterior")
		if e != nil || exterior.PID == x.OriginalWorkerPID || exterior.OriginalSubjectNativePin.OriginalObservedAt.After(x.OriginalWorkerStartCalledAt) {
			return fail
		}
	case model.HostFactoryAliveNativeRead:
		w, e1 := g.process(x.Worker, "host_worker")
		a, e2 := g.process(x.Exterior, "host_exterior")
		r, e3 := g.process(x.Registrar, "host_registrar")
		if e1 != nil || e2 != nil || e3 != nil || w.PPID != a.PID || w.PID == a.PID || w.PID == r.PID || a.PID == r.PID || w.HostBootID != a.HostBootID || r.HostBootID != a.HostBootID || w.OriginalSubjectNativePin.OriginalObservedAt.After(x.ObservedAt) || a.OriginalSubjectNativePin.OriginalObservedAt.After(x.ObservedAt) || r.OriginalSubjectNativePin.OriginalObservedAt.After(x.ObservedAt) {
			return fail
		}
		for _, p := range []model.HostFactoryNativeProcess{w, a, r} {
			if p.OriginalNativeReadStartedAt.Before(x.OriginalReadStartedAt) || p.OriginalSubjectNativePin.OriginalObservedAt.After(x.OriginalReadCloseReturnedAt) {
				return fail
			}
		}
	case model.HostFactoryExteriorJoin:
		a, e := g.process(x.Exterior, "host_exterior")
		if e != nil || a.OriginalSubjectNativePin.OriginalObservedAt.After(x.RecordedAt) {
			return fail
		}
	case model.HostFactoryTerminalRead:
		a, e1 := g.process(x.ReaderBefore, "host_registrar")
		b, e2 := g.process(x.ReaderAfter, "host_registrar")
		c, e3 := g.process(x.ExteriorBefore, "host_exterior")
		d, e4 := g.process(x.ExteriorAfter, "host_exterior")
		if e1 != nil || e2 != nil || e3 != nil || e4 != nil || !hostFactorySameProcess(a, b) || !hostFactorySameProcess(c, d) || a.PID == c.PID || a.HostBootID != c.HostBootID || a.OriginalNativeCloseReturnedAt.After(x.OriginalReadStartedAt) || c.OriginalNativeCloseReturnedAt.After(x.OriginalReadStartedAt) || b.OriginalNativeReadStartedAt.Before(x.OriginalDirectoryCloseReturnedAt) || d.OriginalNativeReadStartedAt.Before(x.OriginalDirectoryCloseReturnedAt) || b.OriginalSubjectNativePin.OriginalObservedAt.After(x.ObservedAt) || d.OriginalSubjectNativePin.OriginalObservedAt.After(x.ObservedAt) {
			return fail
		}
	case model.HostFactoryNativeLeaf:
		r, e := g.observation(x.Process)
		t, e2 := g.observation(x.OriginalTaskInventoryRead)
		if e != nil || e2 != nil || r.Process == nil || t.TaskDirectory == nil || r.SubjectRole != x.Role || t.SubjectRole != x.Role || r.ObserverRole != x.ObserverRole || t.ObserverRole != x.ObserverRole || r.SubjectPrimitiveRawSHA256 != x.SubjectPrimitiveRawSHA256 || t.SubjectPrimitiveRawSHA256 != x.SubjectPrimitiveRawSHA256 {
			return fail
		}
		p, task := *r.Process, *t.TaskDirectory
		pin := p.OriginalSubjectNativePin
		if p.BootstrapReturnSHA256 != x.BootstrapReturnSHA256 || pin.ObserverPrimitiveRawSHA256 != x.ObserverPrimitiveRawSHA256 || task.OwnerPrimitiveRawSHA256 != x.ObserverPrimitiveRawSHA256 || task.SubjectOwnerID != pin.SubjectOwnerID || task.SubjectBootID != p.HostBootID || task.SubjectPID != p.PID || task.SubjectStartTicks != p.StartTicks || x.ObservedAt.Before(pin.OriginalObservedAt) || x.ObservedAt.Before(task.OriginalSubjectStatAfterRead.OriginalCloseReturnedAt) {
			return fail
		}
		if x.OriginalSubjectPinSource != nil {
			s := x.OriginalSubjectPinSource
			if s.OriginalHandleID != pin.OriginalHandleID || s.OriginalDescriptorNumber != pin.OriginalDescriptorNumber || s.Device != pin.OriginalStat.Device || s.Inode != pin.OriginalStat.Inode || s.Mode != pin.OriginalStat.Mode || s.UID != pin.OriginalStat.UID || s.GID != pin.OriginalStat.GID || s.LinkCount != pin.OriginalStat.LinkCount {
				return fail
			}
		}
		for _, op := range p.NativeReadOperations {
			if op.OwnerPrimitiveRawSHA256 != x.ObserverPrimitiveRawSHA256 {
				return fail
			}
		}
	case model.HostFactoryInitialEmptyRealmRead:
		a, e1 := g.process(x.ControlBefore, "host_exterior")
		b, e2 := g.process(x.ControlAfter, "host_exterior")
		c, e3 := g.process(x.RegistrarBefore, "host_registrar")
		d, e4 := g.process(x.RegistrarAfter, "host_registrar")
		if e1 != nil || e2 != nil || e3 != nil || e4 != nil || x.FactoryRootID != g.root || !hostFactorySameProcess(a, b) || !hostFactorySameProcess(c, d) || a.PID == c.PID || c.PPID != a.PID || a.HostBootID != c.HostBootID || x.ControlBefore.SubjectPrimitiveRawSHA256 != x.CoreBasalOwnerRawSHA256 || x.ControlAfter.SubjectPrimitiveRawSHA256 != x.CoreBasalOwnerRawSHA256 || x.RegistrarBefore.SubjectPrimitiveRawSHA256 != x.RegistrarBasalOwnerRawSHA256 || x.RegistrarAfter.SubjectPrimitiveRawSHA256 != x.RegistrarBasalOwnerRawSHA256 {
			return fail
		}
		return g.census(x.TaskInventoriesBefore[:], x.TaskInventoriesAfter[:], x.ThreadReads, []hostFactoryCensusProcess{hostFactoryCensusIdentity(a), hostFactoryCensusIdentity(c)}, []hostFactoryCensusProcess{hostFactoryCensusIdentity(b), hostFactoryCensusIdentity(d)}, [][]int{{c.PID}, {}}, x.OriginalReadStartedAt, x.OriginalReadReturnedAt, x.OriginalReadCloseReturnedAt, x.ObservedAt)
	case model.HostFactoryOriginalEmptyRealmRead:
		a, e1 := g.process(x.ControlProcessBefore, "host_exterior")
		b, e2 := g.process(x.ControlProcessAfter, "host_exterior")
		c, e3 := g.process(x.WorkerBefore, "host_worker")
		d, e4 := g.process(x.WorkerAfter, "host_worker")
		if e1 != nil || e2 != nil || e3 != nil || e4 != nil || !hostFactorySameProcess(a, b) || !hostFactorySameProcess(c, d) || c.PPID != a.PID || a.PID == c.PID || a.HostBootID != c.HostBootID {
			return fail
		}
		// The immutable prior AliveNativeRead/Root registrar lifetime is joined by
		// the source wrapper/SQL consumer. This BODY supplies registrar task identity
		// before+after and never manufactures a missing inline registrar process.
		reg, e := g.observation(x.TaskInventoriesBefore[1])
		if e != nil || reg.TaskDirectory == nil || reg.SubjectRole != "host_registrar" {
			return fail
		}
		t := reg.TaskDirectory
		registrar := hostFactoryCensusProcess{HostBootID: t.SubjectBootID, PID: t.SubjectPID, StartTicks: t.SubjectStartTicks}
		return g.census(x.TaskInventoriesBefore[:], x.TaskInventoriesAfter[:], x.ThreadReads, []hostFactoryCensusProcess{hostFactoryCensusIdentity(a), registrar, hostFactoryCensusIdentity(c)}, []hostFactoryCensusProcess{hostFactoryCensusIdentity(b), registrar, hostFactoryCensusIdentity(d)}, [][]int{{registrar.PID, c.PID}, {}, {}}, x.OriginalReadStartedAt, x.OriginalReadReturnedAt, x.OriginalReadCloseReturnedAt, x.ObservedAt)
	default:
		return fail
	}
	return nil
}
func (g *hostFactoryNativeGraph) census(before, after []model.HostFactoryNativeObservationReference, threads model.HostFactoryNativeObservationCollectionReference, processBefore, processAfter []hostFactoryCensusProcess, allowedChildren [][]int, started, returned, closed, observed time.Time) error {
	fail := ErrHostFactorySourceRefused
	if !hostFactoryOrdered(started, returned, closed, observed) || observed.After(g.deadline) || len(before) != len(after) || len(before) != len(processBefore) || len(before) != len(processAfter) || len(before) != len(allowedChildren) {
		return fail
	}
	roster := map[string]bool{}
	pidOwner := map[int]int{}
	expected := 0
	taskBefore := make([]model.HostFactoryTaskDirectoryRead, len(before))
	taskAfter := make([]model.HostFactoryTaskDirectoryRead, len(after))
	for i, ref := range before {
		b, e1 := g.observation(ref)
		a, e2 := g.observation(after[i])
		if e1 != nil || e2 != nil || b.TaskDirectory == nil || a.TaskDirectory == nil || b.SubjectOwnerID != a.SubjectOwnerID || b.SubjectRole != a.SubjectRole || b.SubjectPrimitiveRawSHA256 != a.SubjectPrimitiveRawSHA256 {
			return fail
		}
		bt, at := *b.TaskDirectory, *a.TaskDirectory
		p, q := processBefore[i], processAfter[i]
		if bt.OriginalSubjectStatBeforeRead.OriginalCalledAt.Before(started) || at.OriginalSubjectStatAfterRead.OriginalCloseReturnedAt.After(closed) || !p.ReadStarted.IsZero() && p.ReadStarted.Before(started) || !p.LastReturn.IsZero() && p.LastReturn.After(bt.OriginalSubjectStatBeforeRead.OriginalCalledAt) || !q.ReadStarted.IsZero() && q.ReadStarted.Before(at.OriginalSubjectStatAfterRead.OriginalCloseReturnedAt) || !q.LastReturn.IsZero() && q.LastReturn.After(observed) || bt.SubjectPID != p.PID || bt.SubjectStartTicks != p.StartTicks || bt.SubjectBootID != p.HostBootID || at.SubjectPID != q.PID || at.SubjectStartTicks != q.StartTicks || at.SubjectBootID != q.HostBootID || p.HostBootID != processBefore[0].HostBootID || !reflect.DeepEqual(bt.ParsedTIDs, at.ParsedTIDs) || len(bt.ParsedTIDs) == 0 || bt.OriginalSubjectStatAfterRead.OriginalCloseReturnedAt.After(returned) || at.OriginalSubjectStatBeforeRead.OriginalCalledAt.Before(bt.OriginalSubjectStatAfterRead.OriginalCloseReturnedAt) || at.OriginalSubjectStatAfterRead.OriginalCloseReturnedAt.After(closed) {
			return fail
		}
		if _, ok := pidOwner[p.PID]; ok {
			return fail
		}
		pidOwner[p.PID] = i
		taskBefore[i] = bt
		taskAfter[i] = at
		for _, tid := range bt.ParsedTIDs {
			key := strconv.Itoa(p.PID) + ":" + strconv.Itoa(tid)
			if roster[key] {
				return fail
			}
			roster[key] = true
			expected++
		}
	}
	if expected < 1 || expected > 4096 || uint32(expected) != threads.OriginalObservationCount {
		return fail
	}
	records, e := g.collection(threads)
	if e != nil {
		return fail
	}
	seen := map[string]bool{}
	childSeen := map[int]bool{}
	for _, r := range records {
		t := r.ThreadChildren
		if t == nil {
			return fail
		}
		i, ok := pidOwner[t.PID]
		if !ok {
			return fail
		}
		key := strconv.Itoa(t.PID) + ":" + strconv.Itoa(t.TID)
		if !roster[key] || seen[key] || r.SubjectOwnerID != before[i].SubjectOwnerID || r.SubjectPrimitiveRawSHA256 != before[i].SubjectPrimitiveRawSHA256 || t.OriginalThreadStatBeforeRead.OriginalCalledAt.Before(taskBefore[i].OriginalSubjectStatAfterRead.OriginalCloseReturnedAt) || t.OriginalThreadStatAfterRead.OriginalCloseReturnedAt.After(taskAfter[i].OriginalSubjectStatBeforeRead.OriginalCalledAt) {
			return fail
		}
		seen[key] = true
		for _, child := range t.ChildPIDs {
			found := false
			for _, allowed := range allowedChildren[i] {
				if child == allowed {
					found = true
					break
				}
			}
			if !found || childSeen[child] {
				return fail
			}
			childSeen[child] = true
		}
	}
	if len(seen) != len(roster) {
		return fail
	}
	for _, children := range allowedChildren {
		for _, pid := range children {
			if !childSeen[pid] {
				return fail
			}
		}
	}
	return nil
}

// Identity projection from an already resolved actual declared process, or from
// the actual registrar TaskDirectory identity in OriginalEMPTY. This private
// projection is NOT a NativeProcess and supplies no missing fields/native claim.
type hostFactoryCensusProcess struct {
	HostBootID              string
	PID                     int
	StartTicks              uint64
	ReadStarted, LastReturn time.Time
}

func hostFactoryCensusIdentity(p model.HostFactoryNativeProcess) hostFactoryCensusProcess {
	return hostFactoryCensusProcess{HostBootID: p.HostBootID, PID: p.PID, StartTicks: p.StartTicks, ReadStarted: p.OriginalNativeReadStartedAt, LastReturn: p.OriginalSubjectNativePin.OriginalObservedAt}
}

func hostFactoryGraphAcquired(calls map[string]model.HostFactoryPrimitiveIOReturn, v model.HostFactoryCallVectorReference, handle string, descriptor, pid int) bool {
	matched := false
	for _, p := range calls {
		if p.Operation != v.Operation || p.OriginalHandleID != v.OriginalHandleID || p.OriginalCallOrdinal == nil || *p.OriginalCallOrdinal < v.FirstOrdinal || *p.OriginalCallOrdinal > v.LastOrdinal {
			continue
		}
		n := p.OriginalNativeReturn
		if n == nil {
			return false
		}
		if pid != 0 && (n.Kind != "unix_pidfd_open" || n.RequestedPID == nil || *n.RequestedPID != pid) {
			return false
		}
		for _, d := range n.ReturnedDescriptors {
			if d.OriginalHandleID == handle && d.OriginalDescriptorNumber == descriptor {
				matched = true
			}
		}
	}
	return matched
}
func hostFactoryGraphClosed(calls map[string]model.HostFactoryPrimitiveIOReturn, v model.HostFactoryCallVectorReference, descriptor int) bool {
	count := uint64(0)
	for _, p := range calls {
		if p.Operation != v.Operation || p.OriginalHandleID != v.OriginalHandleID || p.OriginalCallOrdinal == nil || *p.OriginalCallOrdinal < v.FirstOrdinal || *p.OriginalCallOrdinal > v.LastOrdinal {
			continue
		}
		n := p.OriginalNativeReturn
		if n == nil || (n.Kind != "original_file_close" && n.Kind != "unix_close") || n.InputDescriptorNumber == nil || *n.InputDescriptorNumber != descriptor {
			return false
		}
		count++
	}
	return count > 0 && count == v.OriginalCallCount
}

// Fixed Source grammar selects one signed original phase-owner observation;
// never min(dates), latest row, unsigned clock metadata or caller bool. Source
// wrappers/SQL join its genuine phase/current lease and before-IO capture.
func hostFactoryNativePhaseReference(value any) (model.HostFactoryNativeObservationReference, error) {
	if v := reflect.ValueOf(value); v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return model.HostFactoryNativeObservationReference{}, ErrHostFactorySourceRefused
		}
		value = v.Elem().Interface()
	}
	switch x := value.(type) {
	case model.HostFactoryOriginalStartReturn:
		return x.Exterior, nil
	case model.HostFactoryAliveNativeRead:
		return x.Worker, nil
	case model.HostFactoryExteriorJoin:
		return x.Exterior, nil
	case model.HostFactoryTerminalRead:
		return x.ReaderBefore, nil
	case model.HostFactoryNativeLeaf:
		return x.Process, nil
	case model.HostFactoryInitialEmptyRealmRead:
		return x.ControlBefore, nil
	case model.HostFactoryOriginalEmptyRealmRead:
		return x.ControlProcessBefore, nil
	}
	return model.HostFactoryNativeObservationReference{}, ErrHostFactorySourceRefused
}

// This is an isolated Source grammar proposal. It installs no approved source,
// native authority or runtime registry. Default HostFactory APIs stay separate.
type HostFactorySourceProfile struct{ identity string }

type HostFactorySourceProfileManifest struct {
	Schema                     string                            `json:"schema"`
	BaseRuleSHA256             string                            `json:"base_rule_sha256"`
	ParentSourceDecisionSHA256 string                            `json:"parent_source_decision_sha256"`
	TupleKeyOrder              [7]string                         `json:"tuple_key_order"`
	ExactTuples                []HostFactorySourceOperationTuple `json:"exact_tuples"`
}

type HostFactorySourceOperationTuple struct {
	Operation     string  `json:"operation"`
	OwnerRole     string  `json:"owner_role"`
	SubjectRole   string  `json:"subject_role"`
	Stage         string  `json:"stage"`
	BindingSchema string  `json:"binding_schema"`
	EnvelopeType  string  `json:"envelope_type"`
	NativeKind    *string `json:"native_kind"`
}

type HostFactorySourceSignedEnvelope struct {
	Schema                  string `json:"schema"`
	Purpose                 string `json:"purpose"`
	Role                    string `json:"role"`
	KeyID                   string `json:"key_id"`
	PreAuthorityScopeSHA256 string `json:"pre_authority_scope_sha256"`
	SourceProfileSHA256     string `json:"source_profile_sha256"`
	OriginalPurposeBase64   string `json:"original_purpose_base64"`
	BodyBase64              string `json:"body_base64"`
	SignatureBase64         string `json:"signature_base64"`
}

type HostFactorySourcePurposeSet struct {
	Schema               string                         `json:"schema"`
	OriginalBodySHA256   string                         `json:"original_body_sha256"`
	OriginalCallPurposes []HostFactorySourceCallPurpose `json:"original_call_purposes"`
}

type HostFactorySourceCallPurpose struct {
	OriginalCallID string `json:"original_call_id"`
	SubjectRole    string `json:"subject_role"`
	Stage          string `json:"stage"`
}

// Callbacks expose immutable originals, not keys or permission from the wire.
// TrustedOwner must independently authenticate the compiled Source/Basal/binding.
// Predecessor nil,nil,0,nil is ONLY an independently verified SQL FIRST relation.
type HostFactorySourceResolvers struct {
	Original         func(bodySHA, envelopeSHA string) (body, envelope []byte, err error)
	TrustedOwner     func(role, keyID, ownerID, primitiveSHA, bindingSchema, bindingSHA string) (ed25519.PublicKey, error)
	IO               func(bodySHA string) (body, envelope []byte, err error)
	Predecessor      func(currentBodySHA string, factIndex uint32) (previousBody, previousEnvelope []byte, previousIndex uint32, err error)
	GetdentsOriginal func(originalCallID string) ([]byte, error)
	Inventory        func(observationID string, exactVector model.HostFactoryCallVectorReference) (body, envelope []byte, err error)
}

const hostFactorySourceEnvelopeSchema = "source_host_factory_signed_envelope_v1"
const hostFactorySourcePurposeSchema = "source_host_factory_original_call_purposes_v1"
const hostFactorySourceScope = "original_host_factory_pre_authority_scope_v4"
const hostFactorySourceProfileSHA = "d7e9eee68bb55faf70f9f524dbc777ef9389429bdfdd984ca9c9f6c45d01de6a"

var hostFactorySourceProfileV1 = &HostFactorySourceProfile{identity: hostFactorySourceProfileSHA}

// ProposedHostFactorySourceProfileV1 returns structural preparation grammar.
// Source9 separately requires a genuine approved compiled installation; its
// production and nativequalification registries currently remain EMPTY.
func ProposedHostFactorySourceProfileV1() *HostFactorySourceProfile {
	return hostFactorySourceProfileV1
}

func (p *HostFactorySourceProfile) Identity() (string, error) {
	if p != hostFactorySourceProfileV1 || p == nil || p.identity != hostFactorySourceProfileSHA {
		return "", ErrHostFactorySourceRefused
	}
	return hostFactorySourceProfileSHA, nil
}

func (p *HostFactorySourceProfile) Manifest() ([]byte, error) {
	if _, err := p.Identity(); err != nil {
		return nil, err
	}
	return []byte(hostFactorySourceProfileManifestRaw), nil
}

func hostFactorySourceType(t reflect.Type) bool {
	return t == reflect.TypeOf(HostFactorySourceProfileManifest{}) || t == reflect.TypeOf(HostFactorySourceOperationTuple{}) || t == reflect.TypeOf(HostFactorySourceSignedEnvelope{}) || t == reflect.TypeOf(HostFactorySourcePurposeSet{}) || t == reflect.TypeOf(HostFactorySourceCallPurpose{})
}

func (p *HostFactorySourceProfile) Validate(value any) error {
	if _, err := p.Identity(); err != nil {
		return err
	}
	v := reflect.ValueOf(value)
	if !v.IsValid() {
		return ErrHostFactorySourceRefused
	}
	if v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return ErrHostFactorySourceRefused
		}
		v = v.Elem()
	}
	if v.Type() == reflect.TypeOf(model.HostFactorySignedEnvelope{}) {
		// A legacy Scope envelope must never become a Source profile artifact.
		return ErrHostFactorySourceRefused
	}
	if !hostFactorySourceType(v.Type()) {
		return ValidateHostFactory(value)
	}
	raw, err := json.Marshal(value)
	if err != nil || len(raw) == 0 || len(raw) > hostFactoryLimit {
		return ErrHostFactorySourceRefused
	}
	switch x := v.Interface().(type) {
	case HostFactorySourceProfileManifest:
		if !bytes.Equal(raw, []byte(hostFactorySourceProfileManifestRaw)) {
			return ErrHostFactorySourceRefused
		}
	case HostFactorySourceOperationTuple:
		var m HostFactorySourceProfileManifest
		if json.Unmarshal([]byte(hostFactorySourceProfileManifestRaw), &m) != nil {
			return ErrHostFactorySourceRefused
		}
		for _, allowed := range m.ExactTuples {
			if reflect.DeepEqual(allowed, x) {
				return nil
			}
		}
		return ErrHostFactorySourceRefused
	case HostFactorySourceCallPurpose:
		if hostFactoryString(x.OriginalCallID, "OriginalCallID") != nil || !hostFactoryHas(hostFactoryEnums["Role"], x.SubjectRole) || !hostFactoryHas(hostFactoryDiagnosticStages, x.Stage) {
			return ErrHostFactorySourceRefused
		}
	case HostFactorySourcePurposeSet:
		if x.Schema != hostFactorySourcePurposeSchema || !hostFactoryHex(x.OriginalBodySHA256, 64) || x.OriginalCallPurposes == nil || len(x.OriginalCallPurposes) > 4096 {
			return ErrHostFactorySourceRefused
		}
		seen := map[string]bool{}
		for _, entry := range x.OriginalCallPurposes {
			if p.Validate(entry) != nil || seen[entry.OriginalCallID] {
				return ErrHostFactorySourceRefused
			}
			seen[entry.OriginalCallID] = true
		}
	case HostFactorySourceSignedEnvelope:
		if x.Schema != hostFactorySourceEnvelopeSchema || !hostFactoryIdentifier(x.Purpose, 128) || !hostFactoryHas([]string{"host_exterior", "host_registrar", "host_worker", "host_core_issuer"}, x.Role) || !guestUUID(x.KeyID) || !hostFactoryHex(x.PreAuthorityScopeSHA256, 64) || x.SourceProfileSHA256 != hostFactorySourceProfileSHA {
			return ErrHostFactorySourceRefused
		}
		body, e := hostFactorySourceBase64(x.BodyBase64)
		purposes, e2 := hostFactorySourceBase64(x.OriginalPurposeBase64)
		sig, e3 := hostFactorySourceBase64(x.SignatureBase64)
		var set HostFactorySourcePurposeSet
		if e != nil || e2 != nil || e3 != nil || len(sig) != ed25519.SignatureSize || p.Decode(purposes, &set) != nil || set.OriginalBodySHA256 != HostFactoryRawSHA256(body) {
			return ErrHostFactorySourceRefused
		}
	default:
		return ErrHostFactorySourceRefused
	}
	return nil
}

func (p *HostFactorySourceProfile) Canonical(value any) ([]byte, error) {
	if p.Validate(value) != nil {
		return nil, ErrHostFactorySourceRefused
	}
	raw, err := json.Marshal(value)
	if err != nil || len(raw) == 0 || len(raw) > hostFactoryLimit {
		return nil, ErrHostFactorySourceRefused
	}
	return raw, nil
}

func (p *HostFactorySourceProfile) Decode(raw []byte, target any) error {
	if _, err := p.Identity(); err != nil {
		return err
	}
	v := reflect.ValueOf(target)
	if v.Kind() != reflect.Pointer || v.IsNil() || len(raw) < 1 || len(raw) > hostFactoryLimit || !utf8.Valid(raw) {
		return ErrHostFactorySourceRefused
	}
	if !hostFactorySourceType(v.Elem().Type()) {
		if v.Elem().Type() == reflect.TypeOf(model.HostFactorySignedEnvelope{}) {
			return ErrHostFactorySourceRefused
		}
		return DecodeHostFactory(raw, target)
	}
	fresh := reflect.New(v.Elem().Type())
	if hostFactoryShape(raw, v.Elem().Type(), 0) != nil || json.Unmarshal(raw, fresh.Interface()) != nil || p.Validate(fresh.Interface()) != nil {
		return ErrHostFactorySourceRefused
	}
	again, err := json.Marshal(fresh.Interface())
	if err != nil || !bytes.Equal(raw, again) {
		return ErrHostFactorySourceRefused
	}
	v.Elem().Set(fresh.Elem())
	return nil
}

func hostFactorySourceBase64(text string) ([]byte, error) {
	raw, err := base64.StdEncoding.Strict().DecodeString(text)
	if err != nil || len(raw) < 1 || len(raw) > hostFactoryLimit || base64.StdEncoding.EncodeToString(raw) != text {
		return nil, ErrHostFactorySourceRefused
	}
	return raw, nil
}

func (p *HostFactorySourceProfile) ValidateOperation(operation, ownerRole, subjectRole, stage, bindingSchema, baseEnvelopeType string, nativeKind *string) error {
	if _, err := p.Identity(); err != nil {
		return err
	}
	var manifest HostFactorySourceProfileManifest
	if json.Unmarshal([]byte(hostFactorySourceProfileManifestRaw), &manifest) != nil {
		return ErrHostFactorySourceRefused
	}
	wanted := HostFactorySourceOperationTuple{operation, ownerRole, subjectRole, stage, bindingSchema, baseEnvelopeType, nativeKind}
	for _, allowed := range manifest.ExactTuples {
		if reflect.DeepEqual(wanted, allowed) {
			return nil
		}
	}
	if ValidateHostFactoryOperation(operation, ownerRole, subjectRole, stage, bindingSchema, baseEnvelopeType) != nil || !hostFactorySourceBaseKind(operation, nativeKind) {
		return ErrHostFactorySourceRefused
	}
	return nil
}

func hostFactorySourceBaseKind(operation string, kind *string) bool {
	r, ok := hostFactoryOperations[operation]
	if !ok {
		return false
	}
	native := r.kind == "nonbyte" || r.kind == "native_scalar" || r.kind == "native_stat" || r.kind == "native_descriptor" || r.kind == "native_directory_bytes"
	if !native {
		return kind == nil
	}
	if kind == nil || !hostFactoryHas(hostFactoryEnums["NativeCallKind"], *kind) {
		return false
	}
	expected := ""
	switch {
	case operation == "task_inventory_getdents":
		expected = "unix_getdents64"
	case operation == "root_directory_create":
		expected = "unix_mkdirat"
	case operation == "initial_ledger_open_exclusive" || strings.HasSuffix(operation, "_openat"):
		expected = "unix_openat"
	case operation == "fcntl_getfl" || operation == "fcntl_getfd" || operation == "fcntl_setfl":
		expected = operation
	case strings.Contains(operation, "fstat"):
		expected = "unix_fstat"
	case strings.Contains(operation, "pipe_create"):
		expected = "original_os_pipe"
	case strings.HasSuffix(operation, "_start"):
		expected = "original_cmd_start"
	case strings.HasSuffix(operation, "_wait"):
		expected = "original_cmd_wait"
	case strings.HasSuffix(operation, "_poll"):
		expected = "unix_poll"
	case strings.Contains(operation, "pidfd_signal"):
		expected = "unix_pidfd_send_signal"
	case strings.Contains(operation, "pidfd_pin") || operation == "native_subject_pidfd_open":
		expected = "unix_pidfd_open"
	case operation == "gate_directory_duplicate" || operation == "executable_anchor_duplicate":
		expected = "fcntl_dupfd_cloexec"
	case strings.HasSuffix(operation, "_open") || strings.HasSuffix(operation, "_open_exclusive"):
		return *kind == "unix_open" || *kind == "unix_openat"
	case strings.HasSuffix(operation, "_sync"):
		expected = "original_file_sync"
	case strings.HasSuffix(operation, "_close"):
		return *kind == "original_file_close" || *kind == "unix_close"
	}
	return expected != "" && expected == *kind
}

func (p *HostFactorySourceProfile) purposesForBody(body any, raw []byte, entries []HostFactorySourceCallPurpose) (HostFactorySourcePurposeSet, error) {
	set := HostFactorySourcePurposeSet{hostFactorySourcePurposeSchema, HostFactoryRawSHA256(raw), entries}
	if p.Validate(set) != nil {
		return HostFactorySourcePurposeSet{}, ErrHostFactorySourceRefused
	}
	v := reflect.ValueOf(body)
	if v.Kind() == reflect.Pointer {
		v = v.Elem()
	}
	chunk, isChunk := v.Interface().(model.HostFactoryCallVectorChunk)
	if !isChunk {
		if len(entries) != 0 {
			return HostFactorySourcePurposeSet{}, ErrHostFactorySourceRefused
		}
		return set, nil
	}
	if chunk.BindingSchema != hostFactorySourceScope || len(entries) != len(chunk.OriginalCalls) {
		return HostFactorySourcePurposeSet{}, ErrHostFactorySourceRefused
	}
	for index, fact := range chunk.OriginalCalls {
		entry := entries[index]
		var kind *string
		if fact.OriginalNativeReturn != nil {
			kind = &fact.OriginalNativeReturn.Kind
		}
		if fact.OriginalCallID == nil || entry.OriginalCallID != *fact.OriginalCallID || p.ValidateOperation(chunk.Operation, chunk.OwnerRole, entry.SubjectRole, entry.Stage, chunk.BindingSchema, "HostFactorySignedEnvelope", kind) != nil {
			return HostFactorySourcePurposeSet{}, ErrHostFactorySourceRefused
		}
	}
	return set, nil
}

func hostFactorySourceDomain(purpose, role, keyID, bindingSHA string, purposes, body []byte) []byte {
	fields := []string{hostFactorySourceEnvelopeSchema, purpose, role, keyID, hostFactorySourceScope, bindingSHA, hostFactorySourceProfileSHA}
	raw := append([]byte(strings.Join(fields, "\x00")), 0)
	raw = binary.BigEndian.AppendUint32(raw, uint32(len(purposes)))
	raw = append(raw, purposes...)
	return append(raw, body...)
}

func (p *HostFactorySourceProfile) SignEnvelope(body any, originalPurposes []HostFactorySourceCallPurpose, role, keyID, bindingSchema, bindingSHA256 string, privateKey ed25519.PrivateKey) ([]byte, error) {
	if _, err := p.Identity(); err != nil || originalPurposes == nil {
		return nil, ErrHostFactorySourceRefused
	}
	if bindingSchema != hostFactorySourceScope {
		if len(originalPurposes) != 0 {
			return nil, ErrHostFactorySourceRefused
		}
		return SignHostFactoryEnvelope(body, role, keyID, bindingSchema, bindingSHA256, privateKey)
	}
	raw, err := p.Canonical(body)
	kind, schemaErr := HostFactoryEnvelopeSchema(body, role, bindingSchema)
	if err != nil || schemaErr != nil || kind != "HostFactorySignedEnvelope" || !guestUUID(keyID) || len(privateKey) != ed25519.PrivateKeySize || !bytes.Equal(ed25519.NewKeyFromSeed(privateKey[:ed25519.SeedSize]), privateKey) || !hostFactoryEnvelopeBinding(body, bindingSchema, bindingSHA256) {
		return nil, ErrHostFactorySourceRefused
	}
	set, err := p.purposesForBody(body, raw, originalPurposes)
	if err != nil {
		return nil, err
	}
	purposeRaw, err := p.Canonical(set)
	if err != nil {
		return nil, err
	}
	v := reflect.ValueOf(body)
	if v.Kind() == reflect.Pointer {
		v = v.Elem()
	}
	purpose := v.FieldByName("Purpose").String()
	sig := ed25519.Sign(privateKey, hostFactorySourceDomain(purpose, role, keyID, bindingSHA256, purposeRaw, raw))
	return p.Canonical(HostFactorySourceSignedEnvelope{hostFactorySourceEnvelopeSchema, purpose, role, keyID, bindingSHA256, hostFactorySourceProfileSHA, base64.StdEncoding.EncodeToString(purposeRaw), base64.StdEncoding.EncodeToString(raw), base64.StdEncoding.EncodeToString(sig)})
}

func (p *HostFactorySourceProfile) VerifyEnvelope(raw []byte, body any, role, keyID, bindingSchema, bindingSHA256 string, publicKey ed25519.PublicKey) ([]HostFactorySourceCallPurpose, error) {
	if _, err := p.Identity(); err != nil {
		return nil, err
	}
	if bindingSchema != hostFactorySourceScope {
		if VerifyHostFactoryEnvelope(raw, body, role, keyID, bindingSchema, bindingSHA256, publicKey) != nil {
			return nil, ErrHostFactorySourceRefused
		}
		return []HostFactorySourceCallPurpose{}, nil
	}
	v := reflect.ValueOf(body)
	if v.Kind() != reflect.Pointer || v.IsNil() || !hostFactoryKnown(v.Elem().Type()) || len(publicKey) != ed25519.PublicKeySize || !guestUUID(keyID) || !hostFactoryHex(bindingSHA256, 64) {
		return nil, ErrHostFactorySourceRefused
	}
	var envelope HostFactorySourceSignedEnvelope
	if p.Decode(raw, &envelope) != nil || envelope.Role != role || envelope.KeyID != keyID || envelope.PreAuthorityScopeSHA256 != bindingSHA256 {
		return nil, ErrHostFactorySourceRefused
	}
	bodyRaw, e := hostFactorySourceBase64(envelope.BodyBase64)
	purposeRaw, e2 := hostFactorySourceBase64(envelope.OriginalPurposeBase64)
	sig, e3 := hostFactorySourceBase64(envelope.SignatureBase64)
	fresh := reflect.New(v.Elem().Type())
	var set HostFactorySourcePurposeSet
	if e != nil || e2 != nil || e3 != nil || !ed25519.Verify(publicKey, hostFactorySourceDomain(envelope.Purpose, role, keyID, bindingSHA256, purposeRaw, bodyRaw), sig) || p.Decode(bodyRaw, fresh.Interface()) != nil || p.Decode(purposeRaw, &set) != nil {
		return nil, ErrHostFactorySourceRefused
	}
	checked, err := p.purposesForBody(fresh.Interface(), bodyRaw, set.OriginalCallPurposes)
	kind, e4 := HostFactoryEnvelopeSchema(fresh.Interface(), role, bindingSchema)
	if err != nil || !reflect.DeepEqual(checked, set) || e4 != nil || kind != "HostFactorySignedEnvelope" || fresh.Elem().FieldByName("Purpose").String() != envelope.Purpose || !hostFactoryEnvelopeBinding(fresh.Interface(), bindingSchema, bindingSHA256) {
		return nil, ErrHostFactorySourceRefused
	}
	v.Elem().Set(fresh.Elem())
	return append([]HostFactorySourceCallPurpose{}, set.OriginalCallPurposes...), nil
}

func (p *HostFactorySourceProfile) ValidatePendingSuccessor(previous, current model.HostFactoryCallVectorChunk, previousPurposes, currentPurposes []HostFactorySourceCallPurpose) error {
	if _, err := p.Identity(); err != nil || ValidateHostFactoryPendingSuccessor(previous, current) != nil || previousPurposes == nil || currentPurposes == nil || !reflect.DeepEqual(previousPurposes, currentPurposes) {
		return ErrHostFactorySourceRefused
	}
	if previous.BindingSchema == hostFactorySourceScope {
		a, e := p.Canonical(previous)
		b, e2 := p.Canonical(current)
		if e != nil || e2 != nil {
			return ErrHostFactorySourceRefused
		}
		if _, e := p.purposesForBody(previous, a, previousPurposes); e != nil {
			return e
		}
		if _, e := p.purposesForBody(current, b, currentPurposes); e != nil {
			return e
		}
	} else if len(previousPurposes) != 0 {
		return ErrHostFactorySourceRefused
	}
	return nil
}

type hostFactorySourceOriginalIO struct {
	body, envelope []byte
	purposes       []HostFactorySourceCallPurpose
}

type hostFactorySourceIOReader struct {
	profile     *HostFactorySourceProfile
	originals   HostFactorySourceResolvers
	cache       map[string]hostFactorySourceOriginalIO
	callPurpose map[string]hostFactorySourceCallIdentity
}

type hostFactorySourceCallIdentity struct {
	binding, bindingSHA, owner, primitive, subject string
	scoped                                         bool
	purpose                                        HostFactorySourceCallPurpose
}

func (p *HostFactorySourceProfile) newIOReader(originals HostFactorySourceResolvers) (*hostFactorySourceIOReader, error) {
	if _, err := p.Identity(); err != nil || originals.IO == nil || originals.Predecessor == nil || originals.TrustedOwner == nil {
		return nil, ErrHostFactorySourceRefused
	}
	return &hostFactorySourceIOReader{profile: p, originals: originals, cache: map[string]hostFactorySourceOriginalIO{}, callPurpose: map[string]hostFactorySourceCallIdentity{}}, nil
}

func (r *hostFactorySourceIOReader) authenticate(body, envelope []byte, expectedSHA string) (hostFactorySourceOriginalIO, error) {
	zero := hostFactorySourceOriginalIO{}
	if len(body) < 1 || len(body) > hostFactoryLimit || len(envelope) < 1 || len(envelope) > hostFactoryLimit || !hostFactoryHex(expectedSHA, 64) || HostFactoryRawSHA256(body) != expectedSHA {
		return zero, ErrHostFactorySourceRefused
	}
	var header struct {
		Schema string `json:"schema"`
	}
	// The schema only selects a closed BODY type, never a profile or authority.
	if json.Unmarshal(body, &header) != nil {
		return zero, ErrHostFactorySourceRefused
	}
	var target any
	switch header.Schema {
	case hostFactorySchemas[reflect.TypeOf(model.HostFactoryCallVectorChunk{})]:
		target = new(model.HostFactoryCallVectorChunk)
	case hostFactorySchemas[reflect.TypeOf(model.HostFactoryCallVectorManifest{})]:
		target = new(model.HostFactoryCallVectorManifest)
	case hostFactorySchemas[reflect.TypeOf(model.HostFactoryHandleCallInventory{})]:
		target = new(model.HostFactoryHandleCallInventory)
	default:
		return zero, ErrHostFactorySourceRefused
	}
	if r.profile.Decode(body, target) != nil {
		return zero, ErrHostFactorySourceRefused
	}
	v := reflect.ValueOf(target).Elem()
	role, owner := v.FieldByName("OwnerRole").String(), v.FieldByName("OriginalOwnerID").String()
	primitiveField := v.FieldByName("OwnerPrimitiveRawSHA256")
	if primitiveField.Kind() == reflect.Pointer {
		if primitiveField.IsNil() {
			return zero, ErrHostFactorySourceRefused
		}
		primitiveField = primitiveField.Elem()
	}
	primitive := primitiveField.String()
	binding, bindingSHA := v.FieldByName("BindingSchema").String(), v.FieldByName("BindingSHA256").String()
	keyID, err := r.profile.envelopeKey(envelope, binding)
	if err != nil {
		return zero, err
	}
	key, err := r.originals.TrustedOwner(role, keyID, owner, primitive, binding, bindingSHA)
	if err != nil {
		return zero, ErrHostFactorySourceRefused
	}
	purposes, err := r.profile.VerifyEnvelope(envelope, target, role, keyID, binding, bindingSHA, key)
	again, canonicalErr := r.profile.Canonical(target)
	if err != nil || canonicalErr != nil || !bytes.Equal(again, body) {
		return zero, ErrHostFactorySourceRefused
	}
	value := hostFactorySourceOriginalIO{append([]byte(nil), body...), append([]byte(nil), envelope...), purposes}
	if old, ok := r.cache[expectedSHA]; ok && (!bytes.Equal(old.body, value.body) || !bytes.Equal(old.envelope, value.envelope) || !reflect.DeepEqual(old.purposes, value.purposes)) {
		return zero, ErrHostFactorySourceRefused
	}
	if chunk, ok := target.(*model.HostFactoryCallVectorChunk); ok {
		staged := map[string]hostFactorySourceCallIdentity{}
		for index, fact := range chunk.OriginalCalls {
			if fact.OriginalCallID == nil {
				return zero, ErrHostFactorySourceRefused
			}
			identity := hostFactorySourceCallIdentity{binding: binding, bindingSHA: bindingSHA, owner: owner, primitive: primitive, subject: fact.SubjectOwnerID, scoped: binding == hostFactorySourceScope}
			if identity.scoped {
				if index >= len(purposes) {
					return zero, ErrHostFactorySourceRefused
				}
				identity.purpose = purposes[index]
			}
			if old, known := r.callPurpose[*fact.OriginalCallID]; known && old != identity {
				// Pending/returned or another BODY cannot replace original purpose,
				// owner or namespace through last-writer cache semantics.
				return zero, ErrHostFactorySourceRefused
			}
			if old, known := staged[*fact.OriginalCallID]; known && old != identity {
				return zero, ErrHostFactorySourceRefused
			}
			staged[*fact.OriginalCallID] = identity
		}
		for id, identity := range staged {
			r.callPurpose[id] = identity
		}
	}
	r.cache[expectedSHA] = value
	return value, nil
}

func (p *HostFactorySourceProfile) envelopeKey(raw []byte, binding string) (string, error) {
	if binding == hostFactorySourceScope {
		var e HostFactorySourceSignedEnvelope
		if p.Decode(raw, &e) != nil {
			return "", ErrHostFactorySourceRefused
		}
		return e.KeyID, nil
	}
	var e model.HostFactoryRootSignedEnvelope
	if DecodeHostFactory(raw, &e) != nil || e.BindingSchema != binding {
		return "", ErrHostFactorySourceRefused
	}
	return e.KeyID, nil
}

func (r *hostFactorySourceIOReader) read(sha string) ([]byte, error) {
	if value, ok := r.cache[sha]; ok {
		return append([]byte(nil), value.body...), nil
	}
	body, env, err := r.originals.IO(sha)
	if err != nil {
		return nil, ErrHostFactorySourceRefused
	}
	value, err := r.authenticate(body, env, sha)
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), value.body...), nil
}

func (r *hostFactorySourceIOReader) prior(sha string, index uint32) ([]byte, uint32, error) {
	current, err := r.read(sha)
	if err != nil {
		return nil, 0, err
	}
	var now model.HostFactoryCallVectorChunk
	if r.profile.Decode(current, &now) != nil || int(index) >= len(now.OriginalCalls) {
		return nil, 0, ErrHostFactorySourceRefused
	}
	body, envelope, previousIndex, err := r.originals.Predecessor(sha, index)
	if err != nil {
		return nil, 0, ErrHostFactorySourceRefused
	}
	if body == nil && envelope == nil && previousIndex == 0 {
		// Caller has already verified the exact immutable SQL FIRST row.
		return nil, 0, nil
	}
	if body == nil || envelope == nil || previousIndex != 0 {
		return nil, 0, ErrHostFactorySourceRefused
	}
	previous, err := r.authenticate(body, envelope, HostFactoryRawSHA256(body))
	var old model.HostFactoryCallVectorChunk
	if err != nil || r.profile.Decode(previous.body, &old) != nil || r.profile.ValidatePendingSuccessor(old, now, previous.purposes, r.cache[sha].purposes) != nil {
		return nil, 0, ErrHostFactorySourceRefused
	}
	return append([]byte(nil), previous.body...), 0, nil
}

func (p *HostFactorySourceProfile) ValidateCallVector(reference model.HostFactoryCallVectorReference, originals HostFactorySourceResolvers) error {
	r, err := p.newIOReader(originals)
	if err != nil {
		return err
	}
	return ValidateHostFactoryCallVector(reference, r.read, r.prior)
}

func (p *HostFactorySourceProfile) ValidateHandleInventory(value model.HostFactoryHandleCallInventory, originals HostFactorySourceResolvers) error {
	r, err := p.newIOReader(originals)
	if err != nil {
		return err
	}
	// Authenticate this exact inventory publication as well as its children.
	// A caller-created typed inventory is not a signed original relation.
	raw, err := p.Canonical(value)
	if err != nil {
		return err
	}
	retained, err := r.read(HostFactoryRawSHA256(raw))
	if err != nil || !bytes.Equal(retained, raw) {
		return ErrHostFactorySourceRefused
	}
	return ValidateHostFactoryHandleInventory(value, r.read, r.prior)
}

func (p *HostFactorySourceProfile) newNativeGraph(root, binding, sha string, deadline time.Time, originals HostFactorySourceResolvers) (*hostFactoryNativeGraph, error) {
	r, err := p.newIOReader(originals)
	if err != nil || originals.Original == nil || originals.GetdentsOriginal == nil || originals.Inventory == nil {
		return nil, ErrHostFactorySourceRefused
	}
	inventory := func(observation string, ref model.HostFactoryCallVectorReference) ([]byte, error) {
		body, env, err := originals.Inventory(observation, ref)
		if err != nil {
			return nil, ErrHostFactorySourceRefused
		}
		value, err := r.authenticate(body, env, HostFactoryRawSHA256(body))
		if err != nil {
			return nil, err
		}
		return append([]byte(nil), value.body...), nil
	}
	g, err := hostFactoryNewNativeGraph(root, binding, sha, deadline, originals.Original, originals.TrustedOwner, r.read, r.prior, originals.GetdentsOriginal, inventory)
	if err != nil {
		return nil, err
	}
	g.sourceProfile = p
	g.sourceCallPurpose = func(id string) (HostFactorySourceCallPurpose, bool, error) {
		identity, known := r.callPurpose[id]
		if !known {
			return HostFactorySourceCallPurpose{}, false, ErrHostFactorySourceRefused
		}
		return identity.purpose, identity.scoped, nil
	}
	return g, nil
}

func (p *HostFactorySourceProfile) ResolveNativeObservation(reference model.HostFactoryNativeObservationReference, factoryRootID, bindingSchema, bindingSHA256 string, originalDeadline time.Time, originals HostFactorySourceResolvers) (model.HostFactoryNativeObservationRecord, error) {
	g, err := p.newNativeGraph(factoryRootID, bindingSchema, bindingSHA256, originalDeadline, originals)
	if err != nil {
		return model.HostFactoryNativeObservationRecord{}, err
	}
	return g.observation(reference)
}

func (p *HostFactorySourceProfile) ResolveNativeCollection(reference model.HostFactoryNativeObservationCollectionReference, factoryRootID string, originalDeadline time.Time, originals HostFactorySourceResolvers) ([]model.HostFactoryNativeObservationRecord, error) {
	g, err := p.newNativeGraph(factoryRootID, reference.BindingSchema, reference.BindingSHA256, originalDeadline, originals)
	if err != nil {
		return nil, err
	}
	return g.collection(reference)
}

func (p *HostFactorySourceProfile) ResolveNativeAggregate(value any, factoryRootID, bindingSchema, bindingSHA256 string, originalDeadline time.Time, originals HostFactorySourceResolvers) ([]model.HostFactoryNativeObservationRecord, error) {
	g, err := p.newNativeGraph(factoryRootID, bindingSchema, bindingSHA256, originalDeadline, originals)
	if err != nil || p.Validate(value) != nil || !hostFactoryEnvelopeBinding(value, bindingSchema, bindingSHA256) {
		return nil, ErrHostFactorySourceRefused
	}
	g.sourceExpectedStage = hostFactorySourceAggregateStage(value)
	phaseReference, err := hostFactoryNativePhaseReference(value)
	if err != nil {
		return nil, err
	}
	phase, err := g.observation(phaseReference)
	if err != nil || !phase.OriginalOperationDeadline.Equal(originalDeadline) || g.aggregate(value) != nil {
		return nil, ErrHostFactorySourceRefused
	}
	for _, record := range g.ordered {
		if !record.OriginalOperationDeadline.Equal(originalDeadline) {
			return nil, ErrHostFactorySourceRefused
		}
	}
	return append([]model.HostFactoryNativeObservationRecord(nil), g.ordered...), nil
}

func hostFactorySourceAggregateStage(value any) string {
	v := reflect.ValueOf(value)
	if v.Kind() == reflect.Pointer {
		v = v.Elem()
	}
	switch v.Interface().(type) {
	case model.HostFactoryOriginalStartReturn:
		return "worker_start"
	case model.HostFactoryAliveNativeRead:
		return "native_alive"
	case model.HostFactoryExteriorJoin:
		return "worker_exterior_join"
	case model.HostFactoryTerminalRead:
		return "terminal_read"
	case model.HostFactoryNativeLeaf:
		return "native_alive"
	case model.HostFactoryInitialEmptyRealmRead:
		return "initial_empty"
	case model.HostFactoryOriginalEmptyRealmRead:
		return "poststart_empty"
	}
	return ""
}

func (g *hostFactoryNativeGraph) sourceSelectedPurposes(record model.HostFactoryNativeObservationRecord, vectors []model.HostFactoryCallVectorReference, calls map[string]model.HostFactoryPrimitiveIOReturn) error {
	if g.sourceProfile == nil {
		return nil
	}
	if g.sourceCallPurpose == nil {
		return ErrHostFactorySourceRefused
	}
	check := func(id string, fresh bool) error {
		purpose, scoped, err := g.sourceCallPurpose(id)
		if err != nil {
			return ErrHostFactorySourceRefused
		}
		// Authentic legacy Root/ordinary originals have no new purpose metadata.
		// Their Source/Basal/ancestor custody remains independently mandatory.
		if scoped && (purpose.SubjectRole != record.SubjectRole || fresh && g.sourceExpectedStage != "" && purpose.Stage != g.sourceExpectedStage) {
			return ErrHostFactorySourceRefused
		}
		return nil
	}
	var pin *model.HostFactoryNativeSubjectPin
	if record.Process != nil {
		pin = &record.Process.OriginalSubjectNativePin
	}
	for _, ref := range vectors {
		fresh := true
		if pin != nil && (reflect.DeepEqual(ref, pin.OriginalFstatCallVector) || reflect.DeepEqual(ref, pin.OriginalAlivePollCallVector) || pin.OriginalOpenCallVector != nil && reflect.DeepEqual(ref, *pin.OriginalOpenCallVector)) {
			// These exact vectors preserve genuine prior acquisition/Fstat/polls.
			// Current IDs are selected below; do not trim whole original vectors.
			fresh = false
		}
		for id, fact := range calls {
			if fact.OriginalCallOrdinal != nil && fact.OriginalHandleID == ref.OriginalHandleID && fact.Operation == ref.Operation && *fact.OriginalCallOrdinal >= ref.FirstOrdinal && *fact.OriginalCallOrdinal <= ref.LastOrdinal {
				if check(id, fresh) != nil {
					return ErrHostFactorySourceRefused
				}
			}
		}
	}
	if pin != nil {
		if check(pin.OriginalBeforePollCallID, true) != nil || check(pin.OriginalAfterPollCallID, true) != nil {
			return ErrHostFactorySourceRefused
		}
		_, beforeScoped, e := g.sourceCallPurpose(pin.OriginalBeforePollCallID)
		_, afterScoped, e2 := g.sourceCallPurpose(pin.OriginalAfterPollCallID)
		if e != nil || e2 != nil || beforeScoped != afterScoped {
			return ErrHostFactorySourceRefused
		}
		if beforeScoped {
			// Fixed Source reader: SAME pin's actual beforePoll(n), Fstat(n+1),
			// afterPoll(n+2). Other original file IO uses other handles. No latest,
			// invented Fstat ID, resample or dropped prior calls can select it.
			n, ok := hostFactoryCallOrdinal(pin.OriginalBeforePollCallID, pin.OriginalHandleID)
			after, ok2 := hostFactoryCallOrdinal(pin.OriginalAfterPollCallID, pin.OriginalHandleID)
			if !ok || !ok2 || n > 65534 || after != n+2 {
				return ErrHostFactorySourceRefused
			}
			fstatID := pin.OriginalHandleID + ":" + strconv.FormatUint(n+1, 10)
			fact, known := calls[fstatID]
			if !known || fact.Operation != "native_subject_pidfd_fstat" || !hostFactorySelectedCallID(fstatID, pin.OriginalFstatCallVector) || !hostFactoryGraphStat(calls, fstatID, pin.OriginalStat, pin.OriginalDescriptorNumber) || check(fstatID, true) != nil {
				return ErrHostFactorySourceRefused
			}
		}
	}
	return nil
}

const hostFactorySourceProfileManifestRaw = `{"schema":"source_host_factory_operation_profile_manifest_v1","base_rule_sha256":"ed641019a2b70511914a45ac8e7ece55a2540fd4570f630e6e662dd416ff3ff5","parent_source_decision_sha256":"ce723f6ac59afa4229f65641f69e6daddefb719b3563ad6aa4c7c9dfa58841b8","tuple_key_order":["operation","owner_role","subject_role","stage","binding_schema","envelope_type","native_kind"],"exact_tuples":[{"operation":"native_subject_alive_poll","owner_role":"host_registrar","subject_role":"host_exterior","stage":"native_alive","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"unix_poll"},{"operation":"native_subject_pidfd_fstat","owner_role":"host_registrar","subject_role":"host_exterior","stage":"native_alive","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"unix_fstat"},{"operation":"proc_owner_directory_open","owner_role":"host_registrar","subject_role":"host_exterior","stage":"native_alive","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"unix_open"},{"operation":"proc_owner_directory_fstat","owner_role":"host_registrar","subject_role":"host_exterior","stage":"native_alive","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"unix_fstat"},{"operation":"proc_owner_directory_close","owner_role":"host_registrar","subject_role":"host_exterior","stage":"native_alive","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"original_file_close"},{"operation":"native_subject_alive_poll","owner_role":"host_registrar","subject_role":"host_registrar","stage":"native_alive","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"unix_poll"},{"operation":"native_subject_pidfd_fstat","owner_role":"host_registrar","subject_role":"host_registrar","stage":"native_alive","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"unix_fstat"},{"operation":"proc_owner_directory_open","owner_role":"host_registrar","subject_role":"host_registrar","stage":"native_alive","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"unix_open"},{"operation":"proc_owner_directory_fstat","owner_role":"host_registrar","subject_role":"host_registrar","stage":"native_alive","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"unix_fstat"},{"operation":"proc_owner_directory_close","owner_role":"host_registrar","subject_role":"host_registrar","stage":"native_alive","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"original_file_close"},{"operation":"native_subject_alive_poll","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_exterior_join","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"unix_poll"},{"operation":"native_subject_pidfd_fstat","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_exterior_join","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"unix_fstat"},{"operation":"native_reader_open","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_exterior_join","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"unix_open"},{"operation":"native_reader_fstat","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_exterior_join","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"unix_fstat"},{"operation":"native_reader_close","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_exterior_join","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"original_file_close"},{"operation":"boot_id_read","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_exterior_join","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":null},{"operation":"stat_before_read","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_exterior_join","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":null},{"operation":"executable_read","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_exterior_join","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":null},{"operation":"cmdline_read","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_exterior_join","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":null},{"operation":"proc_owner_directory_open","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_exterior_join","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"unix_open"},{"operation":"proc_owner_directory_fstat","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_exterior_join","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"unix_fstat"},{"operation":"proc_owner_directory_close","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_exterior_join","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"original_file_close"},{"operation":"stat_after_read","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_exterior_join","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":null},{"operation":"task_inventory_getdents","owner_role":"host_registrar","subject_role":"host_registrar","stage":"native_alive","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"unix_getdents64"},{"operation":"native_subject_alive_poll","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_start","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"unix_poll"},{"operation":"native_subject_pidfd_fstat","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_start","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"unix_fstat"},{"operation":"native_reader_open","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_start","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"unix_open"},{"operation":"native_reader_fstat","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_start","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"unix_fstat"},{"operation":"native_reader_close","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_start","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"original_file_close"},{"operation":"boot_id_read","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_start","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":null},{"operation":"stat_before_read","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_start","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":null},{"operation":"executable_read","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_start","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":null},{"operation":"cmdline_read","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_start","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":null},{"operation":"proc_owner_directory_open","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_start","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"unix_open"},{"operation":"proc_owner_directory_fstat","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_start","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"unix_fstat"},{"operation":"proc_owner_directory_close","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_start","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"original_file_close"},{"operation":"stat_after_read","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_start","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":null},{"operation":"native_subject_pidfd_open","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_start","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"unix_pidfd_open"},{"operation":"native_subject_pidfd_open","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_exterior_join","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"unix_pidfd_open"},{"operation":"native_subject_pidfd_open","owner_role":"host_registrar","subject_role":"host_exterior","stage":"native_alive","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"unix_pidfd_open"},{"operation":"native_subject_pidfd_open","owner_role":"host_registrar","subject_role":"host_registrar","stage":"native_alive","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"unix_pidfd_open"},{"operation":"control_reader_close","owner_role":"host_exterior","subject_role":"host_worker","stage":"worker_start","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"original_file_close"},{"operation":"bootstrap_reader_close","owner_role":"host_exterior","subject_role":"host_worker","stage":"worker_start","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"original_file_close"},{"operation":"control_reader_close","owner_role":"host_exterior","subject_role":"host_worker","stage":"cleanup","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"original_file_close"},{"operation":"descriptor_fstat","owner_role":"host_registrar","subject_role":"host_worker","stage":"terminal_read","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"unix_fstat"},{"operation":"fcntl_getfl","owner_role":"host_registrar","subject_role":"host_worker","stage":"terminal_read","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"fcntl_getfl"},{"operation":"fcntl_getfd","owner_role":"host_registrar","subject_role":"host_worker","stage":"terminal_read","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"fcntl_getfd"},{"operation":"proc_owner_directory_close","owner_role":"host_registrar","subject_role":"host_exterior","stage":"cleanup","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"original_file_close"},{"operation":"proc_owner_directory_close","owner_role":"host_registrar","subject_role":"host_registrar","stage":"cleanup","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"original_file_close"},{"operation":"gate_directory_close","owner_role":"host_worker","subject_role":"host_worker","stage":"cleanup","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"original_file_close"},{"operation":"proc_owner_directory_close","owner_role":"host_registrar","subject_role":"host_worker","stage":"cleanup","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"original_file_close"}]}`
