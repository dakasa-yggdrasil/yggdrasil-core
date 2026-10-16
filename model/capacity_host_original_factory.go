// Source-owned closed Host A records. Structural validation never supplies native authority.
package model

import "time"

// original_host_factory_pre_authority_scope_v4 | signed_original_body
type HostFactoryPreAuthorityScope struct {
	Schema                            string    `json:"schema"`
	Purpose                           string    `json:"purpose"`
	FactoryRealmID                    string    `json:"factory_realm_id"`
	FactoryAttemptID                  string    `json:"factory_attempt_id"`
	CreatorOwnerID                    string    `json:"creator_owner_id"`
	Namespace                         string    `json:"namespace"`
	PolicyID                          string    `json:"policy_id"`
	PolicyChecksum                    string    `json:"policy_checksum"`
	WorkflowID                        string    `json:"workflow_id"`
	WorkflowChecksum                  string    `json:"workflow_checksum"`
	OriginalStepID                    string    `json:"original_step_id"`
	OriginalStepTimeoutSeconds        int       `json:"original_step_timeout_seconds"`
	Generation                        int64     `json:"generation"`
	Fence                             int64     `json:"fence"`
	LeaseOwnerSHA256                  string    `json:"lease_owner_sha256"`
	ExecutorID                        string    `json:"executor_id"`
	MutationBindingName               string    `json:"mutation_binding_name"`
	Slot                              int       `json:"slot"`
	PlannedDesiredSpecSHA256          string    `json:"planned_desired_spec_sha256"`
	PlannedMutationRequestSHA256      string    `json:"planned_mutation_request_sha256"`
	ProfileManifestSHA256             string    `json:"profile_manifest_sha256"`
	FactoryRegistrySHA256             string    `json:"factory_registry_sha256"`
	FactorySourceClosureSHA256        string    `json:"factory_source_closure_sha256"`
	CoreActualSourceCommit            string    `json:"core_actual_source_commit"`
	BootstrapChallengeSetSHA256       string    `json:"bootstrap_challenge_set_sha256"`
	OriginalContextStartedAt          time.Time `json:"original_context_started_at"`
	OriginalContextDeadline           time.Time `json:"original_context_deadline"`
	OriginalLeaseExpiresAt            time.Time `json:"original_lease_expires_at"`
	ApprovedProvisioningBudgetSeconds int       `json:"approved_provisioning_budget_seconds"`
	ScopeRootID                       string    `json:"scope_root_id"`
	InitialEmptyRealmReadSHA256       string    `json:"initial_empty_realm_read_sha256"`
	OriginalLeaseProvenanceSHA256     string    `json:"original_lease_provenance_sha256"`
	StableOriginalTargetSHA256        string    `json:"stable_original_target_sha256"`
	FactoryEntryClass                 string    `json:"factory_entry_class"`
}

// original_host_factory_binary_execution_v4 | closed_nested_facts_not_standalone_authority
type HostFactoryBinaryExecution struct {
	ExecutionClass                    string    `json:"execution_class"`
	ScriptMode                        string    `json:"script_mode"`
	BuildReceiptSHA256                string    `json:"build_receipt_sha256"`
	ActualBinarySourceCommit          string    `json:"actual_binary_source_commit"`
	ExecutableSHA256                  string    `json:"executable_sha256"`
	ExecutableDevice                  uint64    `json:"executable_device"`
	ExecutableInode                   uint64    `json:"executable_inode"`
	ExecutableLinkCount               uint64    `json:"executable_link_count"`
	ExecutableUID                     uint32    `json:"executable_uid"`
	ExecutableGID                     uint32    `json:"executable_gid"`
	ExecutableMode                    uint32    `json:"executable_mode"`
	FixedArgvSHA256                   string    `json:"fixed_argv_sha256"`
	OriginalCmdlineReadSHA256         string    `json:"original_cmdline_read_sha256"`
	OriginalExecutableReadStartedAt   time.Time `json:"original_executable_read_started_at"`
	OriginalExecutableReadBytes       int       `json:"original_executable_read_bytes"`
	OriginalExecutableReadReturnedAt  time.Time `json:"original_executable_read_returned_at"`
	OriginalExecutableCloseReturnedAt time.Time `json:"original_executable_close_returned_at"`
	OriginalCmdlineReadBytes          int       `json:"original_cmdline_read_bytes"`
	OriginalCmdlineReadReturnedAt     time.Time `json:"original_cmdline_read_returned_at"`
	OriginalCmdlineCloseReturnedAt    time.Time `json:"original_cmdline_close_returned_at"`
}

// original_host_factory_native_process_v4 | closed_nested_facts_not_standalone_authority
type HostFactoryNativeProcess struct {
	HostBootID                    string                        `json:"host_boot_id"`
	PID                           int                           `json:"pid"`
	PPID                          int                           `json:"ppid"`
	StartTicks                    uint64                        `json:"start_ticks"`
	ProcessNonceSHA256            string                        `json:"process_nonce_sha256"`
	BootstrapReturnSHA256         string                        `json:"bootstrap_return_sha256"`
	UID                           uint32                        `json:"uid"`
	GID                           uint32                        `json:"gid"`
	Execution                     HostFactoryBinaryExecution    `json:"execution"`
	OriginalStatBeforeSHA256      string                        `json:"original_stat_before_sha256"`
	OriginalStatAfterSHA256       string                        `json:"original_stat_after_sha256"`
	OriginalNativeReadStartedAt   time.Time                     `json:"original_native_read_started_at"`
	OriginalNativeReadReturnedAt  time.Time                     `json:"original_native_read_returned_at"`
	OriginalNativeCloseReturnedAt time.Time                     `json:"original_native_close_returned_at"`
	NativeReadOperations          [5]HostFactoryOriginalIOFact  `json:"native_read_operations"`
	OriginalHeldExecutableRead    HostFactoryHeldExecutableRead `json:"original_held_executable_read"`
	OriginalProcessOwnerRead      HostFactoryProcessOwnerRead   `json:"original_process_owner_read"`
	NativeHandleInventorySHAs     []string                      `json:"native_handle_inventory_sh_as"`
	OriginalSubjectNativePin      HostFactoryNativeSubjectPin   `json:"original_subject_native_pin"`
}

// original_host_factory_descriptor_source_v4 | closed_nested_facts_not_standalone_authority
type HostFactoryDescriptorSource struct {
	Role                          string                          `json:"role"`
	OwnerNativeReceiptSHA256      string                          `json:"owner_native_receipt_sha256"`
	Device                        uint64                          `json:"device"`
	Inode                         uint64                          `json:"inode"`
	Type                          string                          `json:"type"`
	Mode                          uint32                          `json:"mode"`
	LinkCount                     uint64                          `json:"link_count"`
	UID                           uint32                          `json:"uid"`
	GID                           uint32                          `json:"gid"`
	Flags                         uint32                          `json:"flags"`
	OriginalDescriptorNumber      int                             `json:"original_descriptor_number"`
	DescriptorFlags               uint32                          `json:"descriptor_flags"`
	OriginalFstatReturnedAt       time.Time                       `json:"original_fstat_returned_at"`
	OriginalHandleID              string                          `json:"original_handle_id"`
	OriginalAcquisitionCallVector *HostFactoryCallVectorReference `json:"original_acquisition_call_vector"`
	OriginalInheritedFromHandleID *string                         `json:"original_inherited_from_handle_id"`
	OriginalFstatCallVector       HostFactoryCallVectorReference  `json:"original_fstat_call_vector"`
	OriginalFstatCallID           string                          `json:"original_fstat_call_id"`
	OriginalGetflCallVector       HostFactoryCallVectorReference  `json:"original_getfl_call_vector"`
	OriginalGetflCallID           string                          `json:"original_getfl_call_id"`
	OriginalGetfdCallVector       HostFactoryCallVectorReference  `json:"original_getfd_call_vector"`
	OriginalGetfdCallID           string                          `json:"original_getfd_call_id"`
}

// original_host_factory_original_start_return_v5 | signed_original_body
type HostFactoryOriginalStartReturn struct {
	Schema                                    string                                `json:"schema"`
	Purpose                                   string                                `json:"purpose"`
	PreAuthorityScopeSHA256                   string                                `json:"pre_authority_scope_sha256"`
	OriginalCommandHandleID                   string                                `json:"original_command_handle_id"`
	Exterior                                  HostFactoryNativeObservationReference `json:"exterior"`
	OriginalWorkerStartCalledAt               time.Time                             `json:"original_worker_start_called_at"`
	OriginalWorkerStartReturnedAt             time.Time                             `json:"original_worker_start_returned_at"`
	OriginalWorkerPID                         int                                   `json:"original_worker_pid"`
	ControlSource                             HostFactoryDescriptorSource           `json:"control_source"`
	BootstrapSource                           HostFactoryDescriptorSource           `json:"bootstrap_source"`
	StdoutSource                              HostFactoryDescriptorSource           `json:"stdout_source"`
	StderrSource                              HostFactoryDescriptorSource           `json:"stderr_source"`
	OriginalRedundantControlCloseReturnedAt   time.Time                             `json:"original_redundant_control_close_returned_at"`
	OriginalRedundantBootstrapCloseReturnedAt time.Time                             `json:"original_redundant_bootstrap_close_returned_at"`
	OriginalRedundantStdoutCloseReturnedAt    time.Time                             `json:"original_redundant_stdout_close_returned_at"`
	OriginalRedundantStderrCloseReturnedAt    time.Time                             `json:"original_redundant_stderr_close_returned_at"`
	OriginalPIDFDPinStartedAt                 time.Time                             `json:"original_pidfd_pin_started_at"`
	OriginalPIDFDPinReturnedAt                time.Time                             `json:"original_pidfd_pin_returned_at"`
	OriginalPIDFDSource                       HostFactoryDescriptorSource           `json:"original_pidfd_source"`
	WorkerPrimitiveRawSHA256                  string                                `json:"worker_primitive_raw_sha256"`
	OriginalBootstrapWriteReturnSHA256        string                                `json:"original_bootstrap_write_return_sha256"`
}

// original_host_factory_alive_native_read_v5 | signed_original_body
type HostFactoryAliveNativeRead struct {
	Schema                      string                                `json:"schema"`
	Purpose                     string                                `json:"purpose"`
	PreAuthorityScopeSHA256     string                                `json:"pre_authority_scope_sha256"`
	OriginalStartReturnSHA256   string                                `json:"original_start_return_sha256"`
	Worker                      HostFactoryNativeObservationReference `json:"worker"`
	Exterior                    HostFactoryNativeObservationReference `json:"exterior"`
	Registrar                   HostFactoryNativeObservationReference `json:"registrar"`
	RegistrarWorkerPIDFDSource  HostFactoryDescriptorSource           `json:"registrar_worker_pidfd_source"`
	RegistrarPinStartedAt       time.Time                             `json:"registrar_pin_started_at"`
	RegistrarPinReturnedAt      time.Time                             `json:"registrar_pin_returned_at"`
	OriginalReadStartedAt       time.Time                             `json:"original_read_started_at"`
	OriginalReadReturnedAt      time.Time                             `json:"original_read_returned_at"`
	OriginalReadCloseReturnedAt time.Time                             `json:"original_read_close_returned_at"`
	ObservedAt                  time.Time                             `json:"observed_at"`
}

// original_host_factory_alive_registration_v4 | signed_original_body
type HostFactoryAliveRegistration struct {
	Schema                        string    `json:"schema"`
	Purpose                       string    `json:"purpose"`
	PreAuthorityScopeSHA256       string    `json:"pre_authority_scope_sha256"`
	OriginalStartReturnSHA256     string    `json:"original_start_return_sha256"`
	AliveNativeReadSHA256         string    `json:"alive_native_read_sha256"`
	RegistrySourceApprovalSHA256  string    `json:"registry_source_approval_sha256"`
	CoreRegisteredAt              time.Time `json:"core_registered_at"`
	CoreActualSourceCommit        string    `json:"core_actual_source_commit"`
	OriginalLeaseProvenanceSHA256 string    `json:"original_lease_provenance_sha256"`
	PreparedCreatePlanSHA256      string    `json:"prepared_create_plan_sha256"`
	PostStartEmptyRealmReadSHA256 string    `json:"post_start_empty_realm_read_sha256"`
}

// original_host_factory_issued_attachment_v4 | signed_original_body
type HostFactoryIssuedAttachment struct {
	Schema                            string    `json:"schema"`
	Purpose                           string    `json:"purpose"`
	PreAuthorityScopeSHA256           string    `json:"pre_authority_scope_sha256"`
	AliveRegistrationSHA256           string    `json:"alive_registration_sha256"`
	OriginalCreateGrantID             string    `json:"original_create_grant_id"`
	OriginalCreateRequestSHA256       string    `json:"original_create_request_sha256"`
	OriginalGrantRecordSHA256         string    `json:"original_grant_record_sha256"`
	PreregistrationID                 string    `json:"preregistration_id"`
	OriginalPreregistrationWireSHA256 string    `json:"original_preregistration_wire_sha256"`
	OriginalProvisioningNonceSHA256   string    `json:"original_provisioning_nonce_sha256"`
	OriginalCreateGrantExpiresAt      time.Time `json:"original_create_grant_expires_at"`
	OriginalReservedAt                time.Time `json:"original_reserved_at"`
	OriginalProvisioningDeadline      time.Time `json:"original_provisioning_deadline"`
	AttachedAt                        time.Time `json:"attached_at"`
}

// original_host_factory_unissued_choice_reservation_v4 | signed_original_body
type HostFactoryUnissuedChoiceReservation struct {
	Schema                  string    `json:"schema"`
	Purpose                 string    `json:"purpose"`
	PreAuthorityScopeSHA256 string    `json:"pre_authority_scope_sha256"`
	AliveRegistrationSHA256 string    `json:"alive_registration_sha256"`
	ReservationID           string    `json:"reservation_id"`
	Choice                  string    `json:"choice"`
	ReservedAt              time.Time `json:"reserved_at"`
	OriginalChoiceDeadline  time.Time `json:"original_choice_deadline"`
}

// original_host_factory_unissued_choice_body_v4 | unsigned_canonical_gate_body_authenticated_by_later_ChoiceReturn
type HostFactoryUnissuedChoiceBody struct {
	Schema                  string `json:"schema"`
	Purpose                 string `json:"purpose"`
	PreAuthorityScopeSHA256 string `json:"pre_authority_scope_sha256"`
	AliveRegistrationSHA256 string `json:"alive_registration_sha256"`
	ChoiceReservationSHA256 string `json:"choice_reservation_sha256"`
	Choice                  string `json:"choice"`
}

// original_host_factory_choice_return_v4 | signed_original_body
type HostFactoryChoiceReturn struct {
	Schema                           string                      `json:"schema"`
	Purpose                          string                      `json:"purpose"`
	ChoiceBodySchema                 string                      `json:"choice_body_schema"`
	ChoiceBodySHA256                 string                      `json:"choice_body_sha256"`
	ChoiceReservationSHA256          string                      `json:"choice_reservation_sha256"`
	OriginalGateSource               HostFactoryDescriptorSource `json:"original_gate_source"`
	OriginalDirectorySource          HostFactoryDescriptorSource `json:"original_directory_source"`
	OriginalWriteStartedAt           time.Time                   `json:"original_write_started_at"`
	OriginalWriteReturnedAt          time.Time                   `json:"original_write_returned_at"`
	OriginalWrittenBytes             int                         `json:"original_written_bytes"`
	OriginalWrittenSHA256            string                      `json:"original_written_sha256"`
	OriginalFileSyncReturnedAt       time.Time                   `json:"original_file_sync_returned_at"`
	OriginalFileCloseReturnedAt      time.Time                   `json:"original_file_close_returned_at"`
	OriginalDirectorySyncReturnedAt  time.Time                   `json:"original_directory_sync_returned_at"`
	OriginalDirectoryCloseReturnedAt time.Time                   `json:"original_directory_close_returned_at"`
	ReturnSignerNativeReceiptSHA256  string                      `json:"return_signer_native_receipt_sha256"`
}

// original_host_factory_exterior_join_v5 | signed_original_body
type HostFactoryExteriorJoin struct {
	Schema                              string                                `json:"schema"`
	Purpose                             string                                `json:"purpose"`
	PreAuthorityScopeSHA256             string                                `json:"pre_authority_scope_sha256"`
	AliveRegistrationSHA256             string                                `json:"alive_registration_sha256"`
	OriginalStartReturnSHA256           string                                `json:"original_start_return_sha256"`
	ChoiceBodySHA256                    string                                `json:"choice_body_sha256"`
	ChoiceReturnSHA256                  string                                `json:"choice_return_sha256"`
	OriginalCommandHandleID             string                                `json:"original_command_handle_id"`
	WorkerHistoricalNativeReceiptSHA256 string                                `json:"worker_historical_native_receipt_sha256"`
	Exterior                            HostFactoryNativeObservationReference `json:"exterior"`
	OriginalWaitCode                    int                                   `json:"original_wait_code"`
	OriginalWaitReturnedAt              time.Time                             `json:"original_wait_returned_at"`
	OriginalStdoutReadStartedAt         time.Time                             `json:"original_stdout_read_started_at"`
	OriginalStdoutReadReturnedAt        time.Time                             `json:"original_stdout_read_returned_at"`
	OriginalStdoutBytes                 int                                   `json:"original_stdout_bytes"`
	OriginalStdoutSHA256                string                                `json:"original_stdout_sha256"`
	OriginalStdoutEOF                   bool                                  `json:"original_stdout_eof"`
	OriginalStdoutCloseReturnedAt       time.Time                             `json:"original_stdout_close_returned_at"`
	OriginalStderrReadStartedAt         time.Time                             `json:"original_stderr_read_started_at"`
	OriginalStderrReadReturnedAt        time.Time                             `json:"original_stderr_read_returned_at"`
	OriginalStderrBytes                 int                                   `json:"original_stderr_bytes"`
	OriginalStderrSHA256                string                                `json:"original_stderr_sha256"`
	OriginalStderrEOF                   bool                                  `json:"original_stderr_eof"`
	OriginalStderrCloseReturnedAt       time.Time                             `json:"original_stderr_close_returned_at"`
	OriginalPIDFDPollReturnedAt         time.Time                             `json:"original_pidfd_poll_returned_at"`
	OriginalPIDFDPollRevents            int                                   `json:"original_pidfd_poll_revents"`
	OriginalPIDFDCloseReturnedAt        time.Time                             `json:"original_pidfd_close_returned_at"`
	RecordedAt                          time.Time                             `json:"recorded_at"`
}

// original_host_factory_terminal_read_v5 | signed_original_body
type HostFactoryTerminalRead struct {
	Schema                              string                                `json:"schema"`
	Purpose                             string                                `json:"purpose"`
	PreAuthorityScopeSHA256             string                                `json:"pre_authority_scope_sha256"`
	AliveRegistrationSHA256             string                                `json:"alive_registration_sha256"`
	ChoiceBodySHA256                    string                                `json:"choice_body_sha256"`
	ChoiceReturnSHA256                  string                                `json:"choice_return_sha256"`
	ExteriorJoinSHA256                  string                                `json:"exterior_join_sha256"`
	HistoricalWorkerNativeReceiptSHA256 string                                `json:"historical_worker_native_receipt_sha256"`
	ReaderBefore                        HostFactoryNativeObservationReference `json:"reader_before"`
	ExteriorBefore                      HostFactoryNativeObservationReference `json:"exterior_before"`
	RegistrarOriginalPinSource          HostFactoryDescriptorSource           `json:"registrar_original_pin_source"`
	RegistrarOriginalPollReturnedAt     time.Time                             `json:"registrar_original_poll_returned_at"`
	RegistrarOriginalPollRevents        int                                   `json:"registrar_original_poll_revents"`
	RegistrarOriginalPinCloseReturnedAt time.Time                             `json:"registrar_original_pin_close_returned_at"`
	OriginalGateSource                  HostFactoryDescriptorSource           `json:"original_gate_source"`
	OriginalDirectorySource             HostFactoryDescriptorSource           `json:"original_directory_source"`
	OriginalReadStartedAt               time.Time                             `json:"original_read_started_at"`
	OriginalReadReturnedAt              time.Time                             `json:"original_read_returned_at"`
	OriginalReadBytes                   int                                   `json:"original_read_bytes"`
	OriginalReadSHA256                  string                                `json:"original_read_sha256"`
	OriginalFileCloseReturnedAt         time.Time                             `json:"original_file_close_returned_at"`
	OriginalDirectoryCloseReturnedAt    time.Time                             `json:"original_directory_close_returned_at"`
	ReaderAfter                         HostFactoryNativeObservationReference `json:"reader_after"`
	ExteriorAfter                       HostFactoryNativeObservationReference `json:"exterior_after"`
	ObservedAt                          time.Time                             `json:"observed_at"`
}

// original_host_factory_unissued_disposition_v4 | signed_original_body
type HostFactoryUnissuedDisposition struct {
	Schema                  string    `json:"schema"`
	Purpose                 string    `json:"purpose"`
	PreAuthorityScopeSHA256 string    `json:"pre_authority_scope_sha256"`
	AliveRegistrationSHA256 string    `json:"alive_registration_sha256"`
	ChoiceReservationSHA256 string    `json:"choice_reservation_sha256"`
	ChoiceBodySHA256        string    `json:"choice_body_sha256"`
	ChoiceReturnSHA256      string    `json:"choice_return_sha256"`
	ExteriorJoinSHA256      string    `json:"exterior_join_sha256"`
	TerminalReadSHA256      string    `json:"terminal_read_sha256"`
	FactoryRegistrySHA256   string    `json:"factory_registry_sha256"`
	Result                  string    `json:"result"`
	RecordedAt              time.Time `json:"recorded_at"`
}

// original_host_factory_issued_choice_reservation_v4 | signed_original_body
type HostFactoryIssuedChoiceReservation struct {
	Schema                  string    `json:"schema"`
	Purpose                 string    `json:"purpose"`
	PreAuthorityScopeSHA256 string    `json:"pre_authority_scope_sha256"`
	AliveRegistrationSHA256 string    `json:"alive_registration_sha256"`
	IssuedAttachmentSHA256  string    `json:"issued_attachment_sha256"`
	ReservationID           string    `json:"reservation_id"`
	Choice                  string    `json:"choice"`
	ReservedAt              time.Time `json:"reserved_at"`
	OriginalChoiceDeadline  time.Time `json:"original_choice_deadline"`
}

// original_host_factory_issued_choice_body_v4 | unsigned_canonical_gate_body_authenticated_by_later_ChoiceReturn
type HostFactoryIssuedChoiceBody struct {
	Schema                  string `json:"schema"`
	Purpose                 string `json:"purpose"`
	PreAuthorityScopeSHA256 string `json:"pre_authority_scope_sha256"`
	AliveRegistrationSHA256 string `json:"alive_registration_sha256"`
	IssuedAttachmentSHA256  string `json:"issued_attachment_sha256"`
	ChoiceReservationSHA256 string `json:"choice_reservation_sha256"`
	Choice                  string `json:"choice"`
}

// original_host_factory_issued_disposition_v4 | signed_original_body
type HostFactoryIssuedDisposition struct {
	Schema                  string    `json:"schema"`
	Purpose                 string    `json:"purpose"`
	PreAuthorityScopeSHA256 string    `json:"pre_authority_scope_sha256"`
	AliveRegistrationSHA256 string    `json:"alive_registration_sha256"`
	IssuedAttachmentSHA256  string    `json:"issued_attachment_sha256"`
	ChoiceReservationSHA256 string    `json:"choice_reservation_sha256"`
	ChoiceBodySHA256        string    `json:"choice_body_sha256"`
	ChoiceReturnSHA256      string    `json:"choice_return_sha256"`
	ExteriorJoinSHA256      string    `json:"exterior_join_sha256"`
	TerminalReadSHA256      string    `json:"terminal_read_sha256"`
	FactoryRegistrySHA256   string    `json:"factory_registry_sha256"`
	Result                  string    `json:"result"`
	RecordedAt              time.Time `json:"recorded_at"`
}

// original_host_factory_signed_envelope_v4 | signature_wrapper
type HostFactorySignedEnvelope struct {
	Schema                  string `json:"schema"`
	Purpose                 string `json:"purpose"`
	Role                    string `json:"role"`
	KeyID                   string `json:"key_id"`
	PreAuthorityScopeSHA256 string `json:"pre_authority_scope_sha256"`
	BodyBase64              string `json:"body_base64"`
	SignatureBase64         string `json:"signature_base64"`
}

// original_host_factory_bootstrap_return_v4 | signed_original_body
type HostFactoryBootstrapReturn struct {
	Schema                            string                               `json:"schema"`
	Purpose                           string                               `json:"purpose"`
	BootstrapBindingSchema            string                               `json:"bootstrap_binding_schema"`
	BootstrapBindingSHA256            string                               `json:"bootstrap_binding_sha256"`
	Role                              string                               `json:"role"`
	OwnerPrimitiveRawSHA256           string                               `json:"owner_primitive_raw_sha256"`
	OriginalBootstrapSource           HostFactoryBootstrapDescriptorSource `json:"original_bootstrap_source"`
	ProcessNonceSHA256                string                               `json:"process_nonce_sha256"`
	SegmentReturns                    [3]HostFactoryBootstrapSegmentReturn `json:"segment_returns"`
	OriginalEOFReturn                 HostFactoryDiagnosticIOFact          `json:"original_eof_return"`
	OriginalBootstrapCloseReturn      HostFactoryDiagnosticIOFact          `json:"original_bootstrap_close_return"`
	DerivedApprovedPublicKeySHA256    string                               `json:"derived_approved_public_key_sha256"`
	OriginalPrivateConsumerReturnedAt time.Time                            `json:"original_private_consumer_returned_at"`
}

// original_host_factory_native_leaf_v5 | signed_original_body
type HostFactoryNativeLeaf struct {
	Schema                     string                                `json:"schema"`
	Purpose                    string                                `json:"purpose"`
	BindingSchema              string                                `json:"binding_schema"`
	BindingSHA256              string                                `json:"binding_sha256"`
	Role                       string                                `json:"role"`
	Process                    HostFactoryNativeObservationReference `json:"process"`
	BootstrapReturnSHA256      string                                `json:"bootstrap_return_sha256"`
	ObservedAt                 time.Time                             `json:"observed_at"`
	SubjectPrimitiveRawSHA256  string                                `json:"subject_primitive_raw_sha256"`
	ObserverRole               string                                `json:"observer_role"`
	ObserverPrimitiveRawSHA256 string                                `json:"observer_primitive_raw_sha256"`
	OriginalSubjectPinSource   *HostFactoryBootstrapDescriptorSource `json:"original_subject_pin_source"`
	OriginalTaskInventoryRead  HostFactoryNativeObservationReference `json:"original_task_inventory_read"`
}

// original_host_factory_source_approval_v4 | signed_original_body
type HostFactorySourceApproval struct {
	Schema                        string    `json:"schema"`
	Purpose                       string    `json:"purpose"`
	FactoryRegistrySHA256         string    `json:"factory_registry_sha256"`
	FactorySourceClosureSHA256    string    `json:"factory_source_closure_sha256"`
	ApprovedPeerSourceCODE        string    `json:"approved_peer_source_code"`
	ActualBuildSourceCommit       string    `json:"actual_build_source_commit"`
	BuildReceiptSHA256            string    `json:"build_receipt_sha256"`
	SourceInputsSHA256            string    `json:"source_inputs_sha256"`
	MetadataEquivalenceRawSHA256  string    `json:"metadata_equivalence_raw_sha256"`
	CredentialRoleInventorySHA256 string    `json:"credential_role_inventory_sha256"`
	AllowedNamespace              string    `json:"allowed_namespace"`
	AllowedPolicyID               string    `json:"allowed_policy_id"`
	AllowedWorkflowID             string    `json:"allowed_workflow_id"`
	AllowedOriginalStepID         string    `json:"allowed_original_step_id"`
	AllowedMutationBindingName    string    `json:"allowed_mutation_binding_name"`
	AllowedSlot                   int       `json:"allowed_slot"`
	ScopeRootID                   string    `json:"scope_root_id"`
	ApprovedAt                    time.Time `json:"approved_at"`
	OriginalApprovalDeadline      time.Time `json:"original_approval_deadline"`
	AllowedFactoryEntryClasses    []string  `json:"allowed_factory_entry_classes"`
	AllowedAssessStepID           string    `json:"allowed_assess_step_id"`
	AllowedClaimStepID            string    `json:"allowed_claim_step_id"`
}

// original_host_factory_original_io_fact_v4 | closed_nested_facts_not_standalone_authority
type HostFactoryOriginalIOFact struct {
	Operation                 string                         `json:"operation"`
	OriginalHandleID          string                         `json:"original_handle_id"`
	OwnerPrimitiveRawSHA256   string                         `json:"owner_primitive_raw_sha256"`
	OriginalCalledAt          time.Time                      `json:"original_called_at"`
	OriginalReturnedAt        time.Time                      `json:"original_returned_at"`
	OriginalCount             int64                          `json:"original_count"`
	OriginalSHA256            string                         `json:"original_sha256"`
	OriginalReturnClass       string                         `json:"original_return_class"`
	OriginalCloseReturnedAt   time.Time                      `json:"original_close_returned_at"`
	SubjectOwnerID            string                         `json:"subject_owner_id"`
	OriginalOperationDeadline time.Time                      `json:"original_operation_deadline"`
	OriginalEOF               bool                           `json:"original_eof"`
	OriginalCallVector        HostFactoryCallVectorReference `json:"original_call_vector"`
	OriginalCloseCallVector   HostFactoryCallVectorReference `json:"original_close_call_vector"`
}

// original_host_factory_diagnostic_io_fact_v4 | closed_nested_facts_not_standalone_authority
type HostFactoryDiagnosticIOFact struct {
	Operation                 string                         `json:"operation"`
	OriginalHandleID          string                         `json:"original_handle_id"`
	OwnerPrimitiveRawSHA256   *string                        `json:"owner_primitive_raw_sha256"`
	OriginalState             string                         `json:"original_state"`
	OriginalCalledAt          *time.Time                     `json:"original_called_at"`
	OriginalReturnedAt        *time.Time                     `json:"original_returned_at"`
	OriginalCount             *int64                         `json:"original_count"`
	OriginalSHA256            *string                        `json:"original_sha256"`
	OriginalReturnClass       string                         `json:"original_return_class"`
	OriginalCloseState        string                         `json:"original_close_state"`
	OriginalCloseReturnedAt   *time.Time                     `json:"original_close_returned_at"`
	OriginalCloseClass        string                         `json:"original_close_class"`
	SubjectOwnerID            string                         `json:"subject_owner_id"`
	OriginalOperationDeadline time.Time                      `json:"original_operation_deadline"`
	OriginalHashState         string                         `json:"original_hash_state"`
	OriginalEOF               *bool                          `json:"original_eof"`
	OriginalCallVector        HostFactoryCallVectorReference `json:"original_call_vector"`
	OriginalCloseCallVector   HostFactoryCallVectorReference `json:"original_close_call_vector"`
}

// original_host_factory_failure_diagnostic_v4 | signed_original_body
type HostFactoryFailureDiagnostic struct {
	Schema                       string                           `json:"schema"`
	Purpose                      string                           `json:"purpose"`
	BindingSchema                string                           `json:"binding_schema"`
	BindingSHA256                string                           `json:"binding_sha256"`
	OriginalStage                string                           `json:"original_stage"`
	OriginalContextStartedAt     time.Time                        `json:"original_context_started_at"`
	OriginalContextDeadline      time.Time                        `json:"original_context_deadline"`
	OriginalOperationDeadline    time.Time                        `json:"original_operation_deadline"`
	FailureCode                  string                           `json:"failure_code"`
	OriginalRecordState          string                           `json:"original_record_state"`
	OriginalRecordSHA256         *string                          `json:"original_record_sha256"`
	OriginalRawBytes             *int                             `json:"original_raw_bytes"`
	Operations                   []HostFactoryCallVectorReference `json:"operations"`
	RecordedAt                   time.Time                        `json:"recorded_at"`
	FailureCollectionID          string                           `json:"failure_collection_id"`
	PartOrdinal                  uint32                           `json:"part_ordinal"`
	PreviousPartRawSHA256        *string                          `json:"previous_part_raw_sha256"`
	FinalPart                    bool                             `json:"final_part"`
	OriginalVectorReferenceCount uint32                           `json:"original_vector_reference_count"`
	RetentionState               string                           `json:"retention_state"`
}

// original_host_factory_artifact_source_v4 | closed_nested_facts_not_standalone_authority
type HostFactoryArtifactSource struct {
	Role                          string    `json:"role"`
	SourceDevice                  uint64    `json:"source_device"`
	SourceInode                   uint64    `json:"source_inode"`
	SourceUID                     uint32    `json:"source_uid"`
	SourceGID                     uint32    `json:"source_gid"`
	SourceMode                    uint32    `json:"source_mode"`
	SourceLinkCount               uint64    `json:"source_link_count"`
	OriginalSourceBytes           uint64    `json:"original_source_bytes"`
	OriginalSourceSHA256          string    `json:"original_source_sha256"`
	OriginalSourceReadStartedAt   time.Time `json:"original_source_read_started_at"`
	OriginalSourceReadReturnedAt  time.Time `json:"original_source_read_returned_at"`
	OriginalSourceCloseReturnedAt time.Time `json:"original_source_close_returned_at"`
}

// original_host_factory_prepared_create_plan_v4 | signed_original_body
type HostFactoryPreparedCreatePlan struct {
	Schema                        string                               `json:"schema"`
	Purpose                       string                               `json:"purpose"`
	BindingSchema                 string                               `json:"binding_schema"`
	BindingSHA256                 string                               `json:"binding_sha256"`
	OriginalCreateCommandHandleID string                               `json:"original_create_command_handle_id"`
	FactoryRegistrySHA256         string                               `json:"factory_registry_sha256"`
	FixedArgvSHA256               string                               `json:"fixed_argv_sha256"`
	SourcePreparationSHA256       string                               `json:"source_preparation_sha256"`
	OriginalArtifacts             [4]HostFactoryArtifactSource         `json:"original_artifacts"`
	PreparedAt                    time.Time                            `json:"prepared_at"`
	OwnerPrimitiveRawSHA256       string                               `json:"owner_primitive_raw_sha256"`
	StableOriginalTargetSHA256    string                               `json:"stable_original_target_sha256"`
	ExecutableStartAnchorSource   HostFactoryBootstrapDescriptorSource `json:"executable_start_anchor_source"`
}

// original_host_factory_native_thread_child_read_v4 | closed_nested_facts_not_standalone_authority
type HostFactoryNativeThreadChildRead struct {
	PID                          int                       `json:"pid"`
	TID                          int                       `json:"tid"`
	ThreadStartTicks             uint64                    `json:"thread_start_ticks"`
	OwnerNativeReceiptSHA256     string                    `json:"owner_native_receipt_sha256"`
	ThreadStatBeforeSHA256       string                    `json:"thread_stat_before_sha256"`
	OriginalChildrenRead         HostFactoryOriginalIOFact `json:"original_children_read"`
	ChildPIDs                    []int                     `json:"child_pi_ds"`
	ThreadStatAfterSHA256        string                    `json:"thread_stat_after_sha256"`
	OriginalThreadStatBeforeRead HostFactoryOriginalIOFact `json:"original_thread_stat_before_read"`
	OriginalThreadStatAfterRead  HostFactoryOriginalIOFact `json:"original_thread_stat_after_read"`
	NativeHandleInventorySHAs    []string                  `json:"native_handle_inventory_sh_as"`
}

// original_host_factory_original_empty_realm_read_v5 | signed_original_body
type HostFactoryOriginalEmptyRealmRead struct {
	Schema                               string                                          `json:"schema"`
	Purpose                              string                                          `json:"purpose"`
	PreAuthorityScopeSHA256              string                                          `json:"pre_authority_scope_sha256"`
	AliveNativeReadSHA256                string                                          `json:"alive_native_read_sha256"`
	ScopeRootID                          string                                          `json:"scope_root_id"`
	PreparedCreatePlanSHA256             string                                          `json:"prepared_create_plan_sha256"`
	RegistrySourceApprovalSHA256         string                                          `json:"registry_source_approval_sha256"`
	OriginalScopeLedgerSHA256            string                                          `json:"original_scope_ledger_sha256"`
	OriginalControlOperationLedgerSHA256 string                                          `json:"original_control_operation_ledger_sha256"`
	ControlProcessBefore                 HostFactoryNativeObservationReference           `json:"control_process_before"`
	WorkerBefore                         HostFactoryNativeObservationReference           `json:"worker_before"`
	ThreadReads                          HostFactoryNativeObservationCollectionReference `json:"thread_reads"`
	ControlProcessAfter                  HostFactoryNativeObservationReference           `json:"control_process_after"`
	WorkerAfter                          HostFactoryNativeObservationReference           `json:"worker_after"`
	OriginalReadStartedAt                time.Time                                       `json:"original_read_started_at"`
	OriginalReadReturnedAt               time.Time                                       `json:"original_read_returned_at"`
	OriginalReadCloseReturnedAt          time.Time                                       `json:"original_read_close_returned_at"`
	ObservedAt                           time.Time                                       `json:"observed_at"`
	InitialEmptyRealmReadSHA256          string                                          `json:"initial_empty_realm_read_sha256"`
	OriginalLeaseProvenanceSHA256        string                                          `json:"original_lease_provenance_sha256"`
	TaskInventoriesBefore                [3]HostFactoryNativeObservationReference        `json:"task_inventories_before"`
	TaskInventoriesAfter                 [3]HostFactoryNativeObservationReference        `json:"task_inventories_after"`
}

// original_host_factory_bootstrap_descriptor_source_v4 | closed_nested_actual_preclose_facts_not_native_leaf_or_standalone_authority
type HostFactoryBootstrapDescriptorSource struct {
	Role                          string                          `json:"role"`
	Device                        uint64                          `json:"device"`
	Inode                         uint64                          `json:"inode"`
	Type                          string                          `json:"type"`
	Mode                          uint32                          `json:"mode"`
	LinkCount                     uint64                          `json:"link_count"`
	UID                           uint32                          `json:"uid"`
	GID                           uint32                          `json:"gid"`
	Flags                         uint32                          `json:"flags"`
	OriginalDescriptorNumber      int                             `json:"original_descriptor_number"`
	DescriptorFlags               uint32                          `json:"descriptor_flags"`
	OriginalFstatReturnedAt       time.Time                       `json:"original_fstat_returned_at"`
	OwnerPrimitiveRawSHA256       string                          `json:"owner_primitive_raw_sha256"`
	OriginalHandleID              string                          `json:"original_handle_id"`
	OriginalAcquisitionCallVector *HostFactoryCallVectorReference `json:"original_acquisition_call_vector"`
	OriginalInheritedFromHandleID *string                         `json:"original_inherited_from_handle_id"`
	OriginalFstatCallVector       HostFactoryCallVectorReference  `json:"original_fstat_call_vector"`
	OriginalFstatCallID           string                          `json:"original_fstat_call_id"`
	OriginalGetflCallVector       HostFactoryCallVectorReference  `json:"original_getfl_call_vector"`
	OriginalGetflCallID           string                          `json:"original_getfl_call_id"`
	OriginalGetfdCallVector       HostFactoryCallVectorReference  `json:"original_getfd_call_vector"`
	OriginalGetfdCallID           string                          `json:"original_getfd_call_id"`
}

// original_host_factory_basal_call_return_v3 | actual_direct_syscall_return_no_owner_hash_dependency
type HostFactoryBasalCallReturn struct {
	Operation           string    `json:"operation"`
	OriginalCalledAt    time.Time `json:"original_called_at"`
	OriginalReturnedAt  time.Time `json:"original_returned_at"`
	OriginalScalar      int64     `json:"original_scalar"`
	OriginalReturnClass string    `json:"original_return_class"`
}

// original_host_factory_basal_owner_observation_v3 | canonical_actual_prefinal_owner_observation_not_final_native_leaf
type HostFactoryBasalOwnerObservation struct {
	Schema                    string                           `json:"schema"`
	Purpose                   string                           `json:"purpose"`
	FactoryRootID             string                           `json:"factory_root_id"`
	OriginalOwnerID           string                           `json:"original_owner_id"`
	Role                      string                           `json:"role"`
	SourceApprovalSHA256      string                           `json:"source_approval_sha256"`
	ActualBinarySourceCommit  string                           `json:"actual_binary_source_commit"`
	BuildReceiptSHA256        string                           `json:"build_receipt_sha256"`
	OriginalContextStartedAt  time.Time                        `json:"original_context_started_at"`
	OriginalContextDeadline   time.Time                        `json:"original_context_deadline"`
	OriginalSelfPIDFDHandleID string                           `json:"original_self_pidfd_handle_id"`
	Calls                     [8]HostFactoryBasalCallReturn    `json:"calls"`
	OriginalSelfPIDFDSource   HostFactoryBasalDescriptorSource `json:"original_self_pidfd_source"`
}

// original_host_factory_basal_descriptor_source_v3 | actual_direct_fstat_flags_results_no_owner_hash_or_future_native_leaf
type HostFactoryBasalDescriptorSource struct {
	Role                     string    `json:"role"`
	Device                   uint64    `json:"device"`
	Inode                    uint64    `json:"inode"`
	Type                     string    `json:"type"`
	Mode                     uint32    `json:"mode"`
	LinkCount                uint64    `json:"link_count"`
	UID                      uint32    `json:"uid"`
	GID                      uint32    `json:"gid"`
	Flags                    uint32    `json:"flags"`
	OriginalDescriptorNumber int       `json:"original_descriptor_number"`
	DescriptorFlags          uint32    `json:"descriptor_flags"`
	OriginalFstatReturnedAt  time.Time `json:"original_fstat_returned_at"`
}

// original_host_factory_root_preparation_v4 | signed_original_body
type HostFactoryRootPreparation struct {
	Schema                              string                               `json:"schema"`
	Purpose                             string                               `json:"purpose"`
	FactoryRootID                       string                               `json:"factory_root_id"`
	SourceApprovalSHA256                string                               `json:"source_approval_sha256"`
	CoreBasalOwnerRawSHA256             string                               `json:"core_basal_owner_raw_sha256"`
	FactoryRegistrySHA256               string                               `json:"factory_registry_sha256"`
	FactorySourceClosureSHA256          string                               `json:"factory_source_closure_sha256"`
	RootDirectorySource                 HostFactoryBootstrapDescriptorSource `json:"root_directory_source"`
	InitialControlLedgerSHA256          string                               `json:"initial_control_ledger_sha256"`
	InitialControlLedgerBytes           int                                  `json:"initial_control_ledger_bytes"`
	OriginalRootOperations              []HostFactoryDiagnosticIOFact        `json:"original_root_operations"`
	OriginalContextStartedAt            time.Time                            `json:"original_context_started_at"`
	OriginalContextDeadline             time.Time                            `json:"original_context_deadline"`
	FactoryEntryClass                   string                               `json:"factory_entry_class"`
	InitialProtectedAdmissionSHA256     string                               `json:"initial_protected_admission_sha256"`
	OriginalIssuerSigningKeySource      HostFactoryBootstrapDescriptorSource `json:"original_issuer_signing_key_source"`
	OriginalIssuerSigningKeyReadReturns [3]HostFactoryDiagnosticIOFact       `json:"original_issuer_signing_key_read_returns"`
	IssuerApprovedPublicKeySHA256       string                               `json:"issuer_approved_public_key_sha256"`
	OriginalHandleInventorySHAs         []string                             `json:"original_handle_inventory_sh_as"`
}

// original_host_factory_root_signed_envelope_v4 | ROOT_NAMESPACE_SIGNATURE_WRAPPER_INITIAL_AND_LATE_ROOT_PLUS_EXACT_ORDINARY_FACTUAL_GUARD_STAGES_NOT_PRE_SCOPE_TIME_LIMIT
type HostFactoryRootSignedEnvelope struct {
	Schema          string `json:"schema"`
	Purpose         string `json:"purpose"`
	Role            string `json:"role"`
	KeyID           string `json:"key_id"`
	BindingSchema   string `json:"binding_schema"`
	BindingSHA256   string `json:"binding_sha256"`
	BodyBase64      string `json:"body_base64"`
	SignatureBase64 string `json:"signature_base64"`
}

// original_host_factory_bootstrap_segment_return_v4 | closed_nonsecret_projection_of_actual_original_private_segment_returns
type HostFactoryBootstrapSegmentReturn struct {
	Operation                string                         `json:"operation"`
	OwnerPrimitiveRawSHA256  string                         `json:"owner_primitive_raw_sha256"`
	OriginalHandleID         string                         `json:"original_handle_id"`
	ExpectedBytes            int                            `json:"expected_bytes"`
	OriginalCallVector       HostFactoryCallVectorReference `json:"original_call_vector"`
	OriginalTotalBytes       int                            `json:"original_total_bytes"`
	OriginalSegmentHashState string                         `json:"original_segment_hash_state"`
	OriginalSegmentSHA256    *string                        `json:"original_segment_sha256"`
	OriginalReturnedAt       time.Time                      `json:"original_returned_at"`
}

// original_host_factory_bootstrap_write_return_v4 | signed_original_body
type HostFactoryBootstrapWriteReturn struct {
	Schema                    string                               `json:"schema"`
	Purpose                   string                               `json:"purpose"`
	BindingSchema             string                               `json:"binding_schema"`
	BindingSHA256             string                               `json:"binding_sha256"`
	RecipientOwnerID          string                               `json:"recipient_owner_id"`
	WriterPrimitiveRawSHA256  string                               `json:"writer_primitive_raw_sha256"`
	OriginalWriterSource      HostFactoryBootstrapDescriptorSource `json:"original_writer_source"`
	SegmentReturns            [3]HostFactoryBootstrapSegmentReturn `json:"segment_returns"`
	OriginalWriterCloseReturn HostFactoryDiagnosticIOFact          `json:"original_writer_close_return"`
}

// original_host_factory_initial_empty_realm_read_v5 | signed_original_body
type HostFactoryInitialEmptyRealmRead struct {
	Schema                       string                                          `json:"schema"`
	Purpose                      string                                          `json:"purpose"`
	FactoryRootID                string                                          `json:"factory_root_id"`
	RootPreparationSHA256        string                                          `json:"root_preparation_sha256"`
	SourceApprovalSHA256         string                                          `json:"source_approval_sha256"`
	CoreBasalOwnerRawSHA256      string                                          `json:"core_basal_owner_raw_sha256"`
	RegistrarBasalOwnerRawSHA256 string                                          `json:"registrar_basal_owner_raw_sha256"`
	InitialControlLedgerSHA256   string                                          `json:"initial_control_ledger_sha256"`
	ControlBefore                HostFactoryNativeObservationReference           `json:"control_before"`
	RegistrarBefore              HostFactoryNativeObservationReference           `json:"registrar_before"`
	ThreadReads                  HostFactoryNativeObservationCollectionReference `json:"thread_reads"`
	ControlAfter                 HostFactoryNativeObservationReference           `json:"control_after"`
	RegistrarAfter               HostFactoryNativeObservationReference           `json:"registrar_after"`
	OriginalReadStartedAt        time.Time                                       `json:"original_read_started_at"`
	OriginalReadReturnedAt       time.Time                                       `json:"original_read_returned_at"`
	OriginalReadCloseReturnedAt  time.Time                                       `json:"original_read_close_returned_at"`
	ObservedAt                   time.Time                                       `json:"observed_at"`
	TaskInventoriesBefore        [2]HostFactoryNativeObservationReference        `json:"task_inventories_before"`
	TaskInventoriesAfter         [2]HostFactoryNativeObservationReference        `json:"task_inventories_after"`
}

// original_host_factory_original_lease_provenance_v4 | signed_original_body
type HostFactoryOriginalLeaseProvenance struct {
	Schema                        string    `json:"schema"`
	Purpose                       string    `json:"purpose"`
	FactoryRootID                 string    `json:"factory_root_id"`
	RootPreparationSHA256         string    `json:"root_preparation_sha256"`
	InitialEmptyRealmReadSHA256   string    `json:"initial_empty_realm_read_sha256"`
	OriginalAssessmentSHA256      string    `json:"original_assessment_sha256"`
	OriginalProtectedInvocationID string    `json:"original_protected_invocation_id"`
	OriginalAssessStepID          string    `json:"original_assess_step_id"`
	OriginalClaimStepID           string    `json:"original_claim_step_id"`
	OriginalClaimIntentRawSHA256  string    `json:"original_claim_intent_raw_sha256"`
	ActualPolicyID                string    `json:"actual_policy_id"`
	ActualPolicyChecksum          string    `json:"actual_policy_checksum"`
	ActualWorkflowID              string    `json:"actual_workflow_id"`
	ActualWorkflowChecksum        string    `json:"actual_workflow_checksum"`
	OriginalProvisionStepID       string    `json:"original_provision_step_id"`
	Generation                    int64     `json:"generation"`
	Fence                         int64     `json:"fence"`
	LeaseOwnerSHA256              string    `json:"lease_owner_sha256"`
	ExecutorID                    string    `json:"executor_id"`
	OriginalLeaseExpiresAt        time.Time `json:"original_lease_expires_at"`
	OriginalClaimReturnedAt       time.Time `json:"original_claim_returned_at"`
	CurrentLeaseReadReturnedAt    time.Time `json:"current_lease_read_returned_at"`
	CoreActualSourceCommit        string    `json:"core_actual_source_commit"`
}

// factory_ordinary_source_binding_v4 | PRIVATE_EARLY_SOURCE_ONLY_BEFORE_WORKER_PREPARATION_NO_GRANT_REQUEST_OR_SETTLEMENT_PERMISSION
type FactoryOrdinarySourceBinding struct {
	Schema                        string    `json:"schema"`
	Purpose                       string    `json:"purpose"`
	FactoryRootID                 string    `json:"factory_root_id"`
	FactoryAttemptID              string    `json:"factory_attempt_id"`
	CreatorOwnerID                string    `json:"creator_owner_id"`
	SourceApprovalSHA256          string    `json:"source_approval_sha256"`
	OriginalLeaseProvenanceSHA256 string    `json:"original_lease_provenance_sha256"`
	StableOriginalTargetSHA256    string    `json:"stable_original_target_sha256"`
	PolicyID                      string    `json:"policy_id"`
	WorkflowID                    string    `json:"workflow_id"`
	OriginalStepID                string    `json:"original_step_id"`
	MutationBindingName           string    `json:"mutation_binding_name"`
	Slot                          int       `json:"slot"`
	ProfileManifestSHA256         string    `json:"profile_manifest_sha256"`
	OriginalContextDeadline       time.Time `json:"original_context_deadline"`
}

// factory_ordinary_bootstrap_frame_v4 | PRIVATE_EARLY_SOURCE_ONLY_BEFORE_WORKER_PREPARATION_NO_GRANT_REQUEST_OR_SETTLEMENT_PERMISSION
type FactoryOrdinaryBootstrapFrame struct {
	Schema                          string                       `json:"schema"`
	Purpose                         string                       `json:"purpose"`
	OrdinarySourceBinding           FactoryOrdinarySourceBinding `json:"ordinary_source_binding"`
	FactoryRegistrySHA256           string                       `json:"factory_registry_sha256"`
	SourcePreparationSHA256         string                       `json:"source_preparation_sha256"`
	SourceCredentialInventorySHA256 string                       `json:"source_credential_inventory_sha256"`
	CoreAuthorityOrigin             string                       `json:"core_authority_origin"`
	MutationPrincipalID             string                       `json:"mutation_principal_id"`
}

// factory_ordinary_credential_frame_v4 | PRIVATE_EARLY_SOURCE_ONLY_BEFORE_WORKER_PREPARATION_NO_GRANT_REQUEST_OR_SETTLEMENT_PERMISSION
type FactoryOrdinaryCredentialFrame struct {
	Schema                            string `json:"schema"`
	Purpose                           string `json:"purpose"`
	OrdinarySourceBindingSHA256       string `json:"ordinary_source_binding_sha256"`
	MutationPrincipalID               string `json:"mutation_principal_id"`
	OrdinaryGuardBearer               string `json:"ordinary_guard_bearer"`
	MutationBearer                    string `json:"mutation_bearer"`
	OriginalCredentialInventorySHA256 string `json:"original_credential_inventory_sha256"`
}

// factory_ordinary_grant_frame_v4 | private_original_bounded_Control_frame_no_callable_permission
type FactoryOrdinaryGrantFrame struct {
	Schema                           string                                           `json:"schema"`
	Purpose                          string                                           `json:"purpose"`
	OrdinarySourceBindingSHA256      string                                           `json:"ordinary_source_binding_sha256"`
	PreparedCreatePlanSHA256         string                                           `json:"prepared_create_plan_sha256"`
	OriginalGrant                    CapacityMutationGrant                            `json:"original_grant"`
	OriginalPreregistration          CapacityGuestOriginalProvisioningPreregistration `json:"original_preregistration"`
	OriginalGrantRecordRawBase64     string                                           `json:"original_grant_record_raw_base64"`
	OriginalPreregistrationRawBase64 string                                           `json:"original_preregistration_raw_base64"`
	PlannedMutationRequestSHA256     string                                           `json:"planned_mutation_request_sha256"`
}

// factory_ordinary_guard_read_v4 | closed_nonsecret_current_Source_only_exact_id_guard_read_no_Issue_or_permission
type FactoryOrdinaryGuardRead struct {
	Schema                           string    `json:"schema"`
	Purpose                          string    `json:"purpose"`
	OrdinarySourceBindingSHA256      string    `json:"ordinary_source_binding_sha256"`
	PreparedCreatePlanSHA256         string    `json:"prepared_create_plan_sha256"`
	GrantID                          string    `json:"grant_id"`
	PreregistrationID                string    `json:"preregistration_id"`
	OriginalGrantRawSHA256           string    `json:"original_grant_raw_sha256"`
	OriginalPreregistrationRawSHA256 string    `json:"original_preregistration_raw_sha256"`
	OriginalAttemptID                string    `json:"original_attempt_id"`
	OriginalRedeemRequestSHA256      string    `json:"original_redeem_request_sha256"`
	GrantState                       string    `json:"grant_state"`
	Generation                       int64     `json:"generation"`
	Fence                            int64     `json:"fence"`
	LeaseOwnerSHA256                 string    `json:"lease_owner_sha256"`
	ExecutorID                       string    `json:"executor_id"`
	OriginalGrantExpiresAt           time.Time `json:"original_grant_expires_at"`
	OriginalLeaseExpiresAt           time.Time `json:"original_lease_expires_at"`
	OriginalContextDeadline          time.Time `json:"original_context_deadline"`
	PolicyChecksum                   string    `json:"policy_checksum"`
	WorkflowChecksum                 string    `json:"workflow_checksum"`
	CoreActualSourceCommit           string    `json:"core_actual_source_commit"`
	ObservedAt                       time.Time `json:"observed_at"`
}

// factory_ordinary_dispatch_body_v4 | private_nonHost_dispatch_marker_accepted_only_by_same_local_onceuse_capsule_never_Host_API
type FactoryOrdinaryDispatchBody struct {
	Schema                          string `json:"schema"`
	Purpose                         string `json:"purpose"`
	OrdinarySourceBindingSHA256     string `json:"ordinary_source_binding_sha256"`
	PreparedCreatePlanSHA256        string `json:"prepared_create_plan_sha256"`
	GrantID                         string `json:"grant_id"`
	PreregistrationID               string `json:"preregistration_id"`
	OriginalAttemptID               string `json:"original_attempt_id"`
	OriginalRedeemRequestSHA256     string `json:"original_redeem_request_sha256"`
	OriginalRedeemResponseRawSHA256 string `json:"original_redeem_response_raw_sha256"`
	BeforeRedeemGuardReadSHA256     string `json:"before_redeem_guard_read_sha256"`
	AfterRedeemGuardReadSHA256      string `json:"after_redeem_guard_read_sha256"`
	WorkerPrimitiveRawSHA256        string `json:"worker_primitive_raw_sha256"`
}

// original_host_factory_root_completion_v4 | signed_original_body
type HostFactoryRootCompletion struct {
	Schema                         string                        `json:"schema"`
	Purpose                        string                        `json:"purpose"`
	RootPreparationSHA256          string                        `json:"root_preparation_sha256"`
	InitialEmptyRealmReadSHA256    *string                       `json:"initial_empty_realm_read_sha256"`
	OriginalLeaseProvenanceSHA256  *string                       `json:"original_lease_provenance_sha256"`
	FinalDispositionSHA256         *string                       `json:"final_disposition_sha256"`
	WorkerExteriorJoinSHA256       *string                       `json:"worker_exterior_join_sha256"`
	RegistrarExteriorReturnsSHA256 string                        `json:"registrar_exterior_returns_sha256"`
	OriginalBasalPinCloseReturns   []HostFactoryDiagnosticIOFact `json:"original_basal_pin_close_returns"`
	DiagnosticStageRawSHAs         []string                      `json:"diagnostic_stage_raw_sh_as"`
	OriginalCompletedAt            time.Time                     `json:"original_completed_at"`
	OriginalPublicWorkflowRunID    *string                       `json:"original_public_workflow_run_id"`
	OriginalHandleInventorySHAs    []string                      `json:"original_handle_inventory_sh_as"`
}

// original_host_factory_primitive_io_return_v2 | closed nested original facts
type HostFactoryPrimitiveIOReturn struct {
	Operation                 string                       `json:"operation"`
	OriginalHandleID          string                       `json:"original_handle_id"`
	OwnerPrimitiveRawSHA256   *string                      `json:"owner_primitive_raw_sha256"`
	OriginalState             string                       `json:"original_state"`
	OriginalCalledAt          *time.Time                   `json:"original_called_at"`
	OriginalReturnedAt        *time.Time                   `json:"original_returned_at"`
	OriginalCount             *int64                       `json:"original_count"`
	OriginalSHA256            *string                      `json:"original_sha256"`
	OriginalReturnClass       string                       `json:"original_return_class"`
	SubjectOwnerID            string                       `json:"subject_owner_id"`
	OriginalOperationDeadline time.Time                    `json:"original_operation_deadline"`
	OriginalHashState         string                       `json:"original_hash_state"`
	OriginalEOF               *bool                        `json:"original_eof"`
	OriginalCallOrdinal       *uint64                      `json:"original_call_ordinal"`
	OriginalCallID            *string                      `json:"original_call_id"`
	OriginalNativeReturn      *HostFactoryNativeCallReturn `json:"original_native_return"`
}

// original_host_factory_call_vector_reference_v2 | closed nested original facts
type HostFactoryCallVectorReference struct {
	Operation               string  `json:"operation"`
	OriginalHandleID        string  `json:"original_handle_id"`
	OriginalOwnerID         string  `json:"original_owner_id"`
	OwnerPrimitiveRawSHA256 *string `json:"owner_primitive_raw_sha256"`
	SubjectOwnerID          string  `json:"subject_owner_id"`
	FirstOrdinal            uint64  `json:"first_ordinal"`
	LastOrdinal             uint64  `json:"last_ordinal"`
	OriginalCallCount       uint64  `json:"original_call_count"`
	ManifestRootSHA256      *string `json:"manifest_root_sha256"`
	CollectionState         string  `json:"collection_state"`
}

// original_host_factory_call_vector_chunk_v2 | SIGNED_ORIGINAL_NONSECRET_IO_VECTOR_CHUNK_NO_NATIVE_AUTHORITY
type HostFactoryCallVectorChunk struct {
	Schema                  string                         `json:"schema"`
	Purpose                 string                         `json:"purpose"`
	BindingSchema           string                         `json:"binding_schema"`
	BindingSHA256           string                         `json:"binding_sha256"`
	OwnerRole               string                         `json:"owner_role"`
	OriginalOwnerID         string                         `json:"original_owner_id"`
	OwnerPrimitiveRawSHA256 string                         `json:"owner_primitive_raw_sha256"`
	Operation               string                         `json:"operation"`
	OriginalHandleID        string                         `json:"original_handle_id"`
	FirstOrdinal            uint64                         `json:"first_ordinal"`
	LastOrdinal             uint64                         `json:"last_ordinal"`
	OriginalCalls           []HostFactoryPrimitiveIOReturn `json:"original_calls"`
	RecordedAt              time.Time                      `json:"recorded_at"`
}

// original_host_factory_call_vector_manifest_v2 | SIGNED_BOUNDED_MERKLE_ORIGINAL_RETURN_MANIFEST_NO_REEXECUTION_OR_NATIVE_AUTHORITY
type HostFactoryCallVectorManifest struct {
	Schema                  string   `json:"schema"`
	Purpose                 string   `json:"purpose"`
	BindingSchema           string   `json:"binding_schema"`
	BindingSHA256           string   `json:"binding_sha256"`
	OwnerRole               string   `json:"owner_role"`
	OriginalOwnerID         string   `json:"original_owner_id"`
	OwnerPrimitiveRawSHA256 string   `json:"owner_primitive_raw_sha256"`
	Operation               string   `json:"operation"`
	OriginalHandleID        string   `json:"original_handle_id"`
	Level                   uint32   `json:"level"`
	FirstOrdinal            uint64   `json:"first_ordinal"`
	LastOrdinal             uint64   `json:"last_ordinal"`
	OriginalCallCount       uint64   `json:"original_call_count"`
	ChildBodySHAs           []string `json:"child_body_sh_as"`
	CollectionState         string   `json:"collection_state"`
}

// original_host_factory_native_stat_return_v1 | closed_nested_actual_original_returns_not_standalone_authority
type HostFactoryNativeStatReturn struct {
	Device    uint64 `json:"device"`
	Inode     uint64 `json:"inode"`
	Mode      uint32 `json:"mode"`
	LinkCount uint64 `json:"link_count"`
	UID       uint32 `json:"uid"`
	GID       uint32 `json:"gid"`
	Size      int64  `json:"size"`
}

// original_host_factory_native_acquired_descriptor_v1 | closed_nested_actual_original_returns_not_standalone_authority
type HostFactoryNativeAcquiredDescriptor struct {
	OriginalHandleID         string `json:"original_handle_id"`
	OriginalDescriptorNumber int    `json:"original_descriptor_number"`
}

// original_host_factory_native_call_return_v1 | closed_nested_actual_original_returns_not_standalone_authority
type HostFactoryNativeCallReturn struct {
	Kind                  string                                `json:"kind"`
	InputDescriptorNumber *int                                  `json:"input_descriptor_number"`
	ParentHandleID        *string                               `json:"parent_handle_id"`
	RequestedFlags        *uint32                               `json:"requested_flags"`
	RequestedMode         *uint32                               `json:"requested_mode"`
	RequestedFcntlCommand *int                                  `json:"requested_fcntl_command"`
	RequestedArgument     *int64                                `json:"requested_argument"`
	RequestedPID          *int                                  `json:"requested_pid"`
	OriginalScalar        *int64                                `json:"original_scalar"`
	OriginalErrno         *uint32                               `json:"original_errno"`
	OriginalErrorPresent  *bool                                 `json:"original_error_present"`
	OriginalStat          *HostFactoryNativeStatReturn          `json:"original_stat"`
	ReturnedDescriptors   []HostFactoryNativeAcquiredDescriptor `json:"returned_descriptors"`
	OriginalPollRevents   *uint32                               `json:"original_poll_revents"`
	ReturnedPID           *int                                  `json:"returned_pid"`
	OriginalExitCode      *int                                  `json:"original_exit_code"`
}

// original_host_factory_handle_call_inventory_v1 | SIGNED_ORIGINAL_HANDLE_CALL_COVERAGE_NOT_NATIVE_AUTHORITY
type HostFactoryHandleCallInventory struct {
	Schema                    string                           `json:"schema"`
	Purpose                   string                           `json:"purpose"`
	BindingSchema             string                           `json:"binding_schema"`
	BindingSHA256             string                           `json:"binding_sha256"`
	OwnerRole                 string                           `json:"owner_role"`
	OriginalOwnerID           string                           `json:"original_owner_id"`
	OwnerPrimitiveRawSHA256   *string                          `json:"owner_primitive_raw_sha256"`
	OriginalHandleID          string                           `json:"original_handle_id"`
	OriginalAcquisitionState  string                           `json:"original_acquisition_state"`
	FirstOrdinal              uint64                           `json:"first_ordinal"`
	LastOrdinal               uint64                           `json:"last_ordinal"`
	OriginalCallCount         uint64                           `json:"original_call_count"`
	OperationVectors          []HostFactoryCallVectorReference `json:"operation_vectors"`
	CollectionState           string                           `json:"collection_state"`
	OriginalOperationDeadline time.Time                        `json:"original_operation_deadline"`
	RecordedAt                time.Time                        `json:"recorded_at"`
}

// original_host_factory_held_executable_read_v1 | closed_nested_actual_original_returns_not_standalone_authority
type HostFactoryHeldExecutableRead struct {
	OriginalHandleID              string                         `json:"original_handle_id"`
	OwnerPrimitiveRawSHA256       string                         `json:"owner_primitive_raw_sha256"`
	SubjectOwnerID                string                         `json:"subject_owner_id"`
	OriginalDescriptorNumber      int                            `json:"original_descriptor_number"`
	OriginalBeforeStat            HostFactoryNativeStatReturn    `json:"original_before_stat"`
	OriginalAfterStat             HostFactoryNativeStatReturn    `json:"original_after_stat"`
	OriginalOpenCallVector        HostFactoryCallVectorReference `json:"original_open_call_vector"`
	OriginalFstatCallVector       HostFactoryCallVectorReference `json:"original_fstat_call_vector"`
	OriginalBeforeFstatCallID     string                         `json:"original_before_fstat_call_id"`
	OriginalAfterFstatCallID      string                         `json:"original_after_fstat_call_id"`
	OriginalRead                  HostFactoryOriginalIOFact      `json:"original_read"`
	OriginalHandleInventorySHA256 string                         `json:"original_handle_inventory_sha256"`
}

// original_host_factory_process_owner_read_v1 | closed_nested_actual_original_returns_not_standalone_authority
type HostFactoryProcessOwnerRead struct {
	SubjectOwnerID                string                         `json:"subject_owner_id"`
	SubjectBootID                 string                         `json:"subject_boot_id"`
	SubjectPID                    int                            `json:"subject_pid"`
	SubjectStartTicks             uint64                         `json:"subject_start_ticks"`
	OriginalHandleID              string                         `json:"original_handle_id"`
	OwnerPrimitiveRawSHA256       string                         `json:"owner_primitive_raw_sha256"`
	OriginalDescriptorNumber      int                            `json:"original_descriptor_number"`
	OriginalStat                  HostFactoryNativeStatReturn    `json:"original_stat"`
	OriginalOpenCallVector        HostFactoryCallVectorReference `json:"original_open_call_vector"`
	OriginalFstatCallVector       HostFactoryCallVectorReference `json:"original_fstat_call_vector"`
	OriginalCloseCallVector       HostFactoryCallVectorReference `json:"original_close_call_vector"`
	OriginalHandleInventorySHA256 string                         `json:"original_handle_inventory_sha256"`
	OriginalCalledAt              time.Time                      `json:"original_called_at"`
	OriginalReturnedAt            time.Time                      `json:"original_returned_at"`
	OriginalCloseReturnedAt       time.Time                      `json:"original_close_returned_at"`
}

// original_host_factory_task_directory_read_v1 | closed_nested_actual_original_returns_not_standalone_authority
type HostFactoryTaskDirectoryRead struct {
	SubjectOwnerID                string                         `json:"subject_owner_id"`
	SubjectBootID                 string                         `json:"subject_boot_id"`
	SubjectPID                    int                            `json:"subject_pid"`
	SubjectStartTicks             uint64                         `json:"subject_start_ticks"`
	OwnerPrimitiveRawSHA256       string                         `json:"owner_primitive_raw_sha256"`
	OriginalHandleID              string                         `json:"original_handle_id"`
	OriginalDescriptorNumber      int                            `json:"original_descriptor_number"`
	OriginalDirectoryStat         HostFactoryNativeStatReturn    `json:"original_directory_stat"`
	OriginalSubjectStatBeforeRead HostFactoryOriginalIOFact      `json:"original_subject_stat_before_read"`
	OriginalSubjectStatAfterRead  HostFactoryOriginalIOFact      `json:"original_subject_stat_after_read"`
	OriginalOpenCallVector        HostFactoryCallVectorReference `json:"original_open_call_vector"`
	OriginalFstatCallVector       HostFactoryCallVectorReference `json:"original_fstat_call_vector"`
	OriginalGetdentsCallVector    HostFactoryCallVectorReference `json:"original_getdents_call_vector"`
	OriginalCloseCallVector       HostFactoryCallVectorReference `json:"original_close_call_vector"`
	OriginalRawBytes              uint64                         `json:"original_raw_bytes"`
	OriginalRawSHA256             string                         `json:"original_raw_sha256"`
	OriginalTerminalCallID        string                         `json:"original_terminal_call_id"`
	ParsedTIDs                    []int                          `json:"parsed_tids"`
	ParserClass                   string                         `json:"parser_class"`
	OriginalCalledAt              time.Time                      `json:"original_called_at"`
	OriginalReturnedAt            time.Time                      `json:"original_returned_at"`
	OriginalCloseReturnedAt       time.Time                      `json:"original_close_returned_at"`
	OriginalHandleInventorySHA256 string                         `json:"original_handle_inventory_sha256"`
}

// original_host_factory_source_audit_return_v1 | UNSIGNED_SOURCE_AUDIT_ONLY_PRIVATE_OR_ALLOWLISTED_PUBLIC_PROJECTION_NO_HOST_ENVELOPE_OR_EFFECT_PERMISSION
type HostFactorySourceAuditReturn struct {
	Schema                    string     `json:"schema"`
	Purpose                   string     `json:"purpose"`
	FactoryRootID             string     `json:"factory_root_id"`
	OriginalAuditHandleID     string     `json:"original_audit_handle_id"`
	OriginalCallID            *string    `json:"original_call_id"`
	Operation                 string     `json:"operation"`
	OriginalState             string     `json:"original_state"`
	OriginalCalledAt          *time.Time `json:"original_called_at"`
	OriginalReturnedAt        *time.Time `json:"original_returned_at"`
	OriginalOperationDeadline time.Time  `json:"original_operation_deadline"`
	OriginalErrorPresent      *bool      `json:"original_error_present"`
	OriginalStatusCode        *int       `json:"original_status_code"`
	OriginalCount             *int64     `json:"original_count"`
	OriginalSHA256            *string    `json:"original_sha256"`
	OriginalHashState         string     `json:"original_hash_state"`
	OriginalEOF               *bool      `json:"original_eof"`
	OriginalReadScope         *string    `json:"original_read_scope"`
	RetainedPrefixBytes       *int64     `json:"retained_prefix_bytes"`
	RetainedPrefixSHA256      *string    `json:"retained_prefix_sha256"`
	FailureCode               *string    `json:"failure_code"`
}

// original_host_factory_native_subject_pin_v1 | closed_actual_independent_PIDFD_Fstat_Poll_source_no_observed_flags_claim
type HostFactoryNativeSubjectPin struct {
	OriginalHandleID                   string                          `json:"original_handle_id"`
	ObserverOwnerID                    string                          `json:"observer_owner_id"`
	ObserverPrimitiveRawSHA256         string                          `json:"observer_primitive_raw_sha256"`
	SubjectOwnerID                     string                          `json:"subject_owner_id"`
	SubjectBootID                      string                          `json:"subject_boot_id"`
	SubjectPID                         int                             `json:"subject_pid"`
	SubjectStartTicks                  uint64                          `json:"subject_start_ticks"`
	OriginalDescriptorNumber           int                             `json:"original_descriptor_number"`
	OriginalStat                       HostFactoryNativeStatReturn     `json:"original_stat"`
	OriginalOpenCallVector             *HostFactoryCallVectorReference `json:"original_open_call_vector"`
	OriginalFstatCallVector            HostFactoryCallVectorReference  `json:"original_fstat_call_vector"`
	OriginalAlivePollCallVector        HostFactoryCallVectorReference  `json:"original_alive_poll_call_vector"`
	OriginalBeforePollCallID           string                          `json:"original_before_poll_call_id"`
	OriginalAfterPollCallID            string                          `json:"original_after_poll_call_id"`
	OriginalHandleInventorySHA256      string                          `json:"original_handle_inventory_sha256"`
	OriginalBasalSelfPIDFDSourceSHA256 *string                         `json:"original_basal_self_pidfd_source_sha256"`
	OriginalObservedAt                 time.Time                       `json:"original_observed_at"`
}

// PROPOSED isolated literal; actual accepted58 Source remains unchanged.
// This reference alone carries NO native permission or completeness.
type HostFactoryNativeObservationReference struct {
	ObservationID              string `json:"observation_id"`
	ObservationKind            string `json:"observation_kind"`
	OriginalBodySHA256         string `json:"original_body_sha256"`
	OriginalEnvelopeSHA256     string `json:"original_envelope_sha256"`
	ObserverOwnerID            string `json:"observer_owner_id"`
	ObserverPrimitiveRawSHA256 string `json:"observer_primitive_raw_sha256"`
	SubjectOwnerID             string `json:"subject_owner_id"`
	SubjectPrimitiveRawSHA256  string `json:"subject_primitive_raw_sha256"`
}

// One complete actual original payload, never slices of its returned facts.
// EXACTLY one pointer is nonnull. The original identifier is reserved BEFORE
// observation IO; NULL/pending/oversized output remains retained/HOLD elsewhere.
type HostFactoryNativeObservationRecord struct {
	Schema                     string                            `json:"schema"`
	Purpose                    string                            `json:"purpose"`
	FactoryRootID              string                            `json:"factory_root_id"`
	BindingSchema              string                            `json:"binding_schema"`
	BindingSHA256              string                            `json:"binding_sha256"`
	ObservationID              string                            `json:"observation_id"`
	ObservationKind            string                            `json:"observation_kind"`
	ObserverRole               string                            `json:"observer_role"`
	ObserverOwnerID            string                            `json:"observer_owner_id"`
	ObserverPrimitiveRawSHA256 string                            `json:"observer_primitive_raw_sha256"`
	SubjectRole                string                            `json:"subject_role"`
	SubjectOwnerID             string                            `json:"subject_owner_id"`
	SubjectPrimitiveRawSHA256  string                            `json:"subject_primitive_raw_sha256"`
	OriginalOperationDeadline  time.Time                         `json:"original_operation_deadline"`
	OriginalCensusCollectionID *string                           `json:"original_census_collection_id"`
	OriginalCensusOrdinal      *uint32                           `json:"original_census_ordinal"`
	Process                    *HostFactoryNativeProcess         `json:"process"`
	TaskDirectory              *HostFactoryTaskDirectoryRead     `json:"task_directory"`
	ThreadChildren             *HostFactoryNativeThreadChildRead `json:"thread_children"`
}

// A complete original source-owned ordered census of WHOLE thread returns.
// Count cannot be established by signature/hash or caller completeness flags.
type HostFactoryNativeObservationCollectionReference struct {
	CollectionID               string `json:"collection_id"`
	ObservationKind            string `json:"observation_kind"`
	BindingSchema              string `json:"binding_schema"`
	BindingSHA256              string `json:"binding_sha256"`
	ObserverOwnerID            string `json:"observer_owner_id"`
	ObserverPrimitiveRawSHA256 string `json:"observer_primitive_raw_sha256"`
	OriginalObservationCount   uint32 `json:"original_observation_count"`
	ManifestRootBodySHA256     string `json:"manifest_root_body_sha256"`
	ManifestRootEnvelopeSHA256 string `json:"manifest_root_envelope_sha256"`
}

// Child references select exact original signed manifest nodes and ranges.
// Original observations stay whole; manifest boundaries partition REFERENCES.
type HostFactoryNativeObservationManifestReference struct {
	OriginalBodySHA256       string `json:"original_body_sha256"`
	OriginalEnvelopeSHA256   string `json:"original_envelope_sha256"`
	Level                    uint32 `json:"level"`
	FirstOrdinal             uint32 `json:"first_ordinal"`
	LastOrdinal              uint32 `json:"last_ordinal"`
	OriginalObservationCount uint32 `json:"original_observation_count"`
}

// Level0 has1..16 Observations, nochildren. Levels1..3 have1..16 Children,
// noobservations, fixeddescending level and exact contiguous nonoverlapping
// ranges. Count/root UUID/observer/binding/deadline remain SAME across allnodes.
type HostFactoryNativeObservationManifest struct {
	Schema                     string                                          `json:"schema"`
	Purpose                    string                                          `json:"purpose"`
	FactoryRootID              string                                          `json:"factory_root_id"`
	BindingSchema              string                                          `json:"binding_schema"`
	BindingSHA256              string                                          `json:"binding_sha256"`
	CollectionID               string                                          `json:"collection_id"`
	ObservationKind            string                                          `json:"observation_kind"`
	ObserverRole               string                                          `json:"observer_role"`
	ObserverOwnerID            string                                          `json:"observer_owner_id"`
	ObserverPrimitiveRawSHA256 string                                          `json:"observer_primitive_raw_sha256"`
	Level                      uint32                                          `json:"level"`
	FirstOrdinal               uint32                                          `json:"first_ordinal"`
	LastOrdinal                uint32                                          `json:"last_ordinal"`
	OriginalObservationCount   uint32                                          `json:"original_observation_count"`
	Observations               []HostFactoryNativeObservationReference         `json:"observations"`
	Children                   []HostFactoryNativeObservationManifestReference `json:"children"`
	OriginalOperationDeadline  time.Time                                       `json:"original_operation_deadline"`
	RecordedAt                 time.Time                                       `json:"recorded_at"`
}
