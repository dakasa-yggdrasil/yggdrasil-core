#!/usr/bin/env bash
# GitHub Actions source recipe only. Grammar tests and readonly verifiers never
# supply the original native Core owner. Every invocation keeps its own files.
set -euo pipefail
[[ "${GITHUB_ACTIONS:-}" == "true" ]] || { echo 'This test recipe is GitHub Actions only' >&2; exit 1; }
[[ -n "${RUNNER_TEMP:-}" ]] || { echo 'External CI artifact directory required' >&2; exit 1; }
case "${1:-}" in
  source|native|native-hold|bytes|native-decode|native-owners|transferred) guest_corpus_mode="$1" ;;
  *) echo 'Use source, native, native-hold, bytes, native-decode, native-owners or transferred' >&2; exit 1 ;;
esac
export GOWORK=off
guest_artifact_dir=$(mktemp -d "$RUNNER_TEMP/capacity-guest-original-$guest_corpus_mode.XXXXXX")
guest_corpus_path="$guest_artifact_dir/test.jsonl"
guest_go_stderr="$guest_artifact_dir/go-test.stderr"
guest_tee_stderr="$guest_artifact_dir/tee.stderr"
guest_census_path="$guest_artifact_dir/census.json"
guest_census_stdout="$guest_artifact_dir/census.stdout"
guest_census_stderr="$guest_artifact_dir/census.stderr"
: > "$guest_corpus_path"
: > "$guest_go_stderr"
: > "$guest_tee_stderr"
printf '%s\n' '{"schema":"guest_original_ci_case_census_v1","status":"collector_not_finished"}' > "$guest_census_path"
printf 'Original Guest CI artifact directory: %s\n' "$guest_artifact_dir"
guest_preflight_error=""
guest_go_started=false
guest_go_exit=not_started
guest_tee_exit=not_started
if [[ "$guest_corpus_mode" == "source" || "$guest_corpus_mode" == "native" || "$guest_corpus_mode" == "native-hold" ]] && [[ -z "${DB_URL:-}" ]]; then
  guest_preflight_error='Same ephemeral PostgreSQL DB_URL is mandatory'
elif [[ "$guest_corpus_mode" == "native" || "$guest_corpus_mode" == "native-hold" ]] && [[ "${REQUIRE_CAPACITY_GUEST_NATIVE_CORPUS:-}" != "true" || ! -s "${CAPACITY_GUEST_NATIVE_CORPUS_FILE:-}" ]]; then
  guest_preflight_error='Actual native command corpus is mandatory before readonly verification'
fi
# errexit must not discard the original pipeline statuses or skip the census.
set +e
if [[ -z "$guest_preflight_error" ]]; then
  export REQUIRE_CAPACITY_GUEST_ORIGINAL_POSTGRES=true
  guest_go_started=true
  case "$guest_corpus_mode" in
    source)
      go test -json -p 1 -count=1 -timeout=3m ./controllers/httpapi ./repository ./manifest -run '^(TestCapacityGuestOriginal(Auth|Inventory|ClosedRegistration|CanonicalResponse|ManifestPayload|ManifestPublicBoundary|PublicWorkflowAdmission|BootstrapBoundary)|TestCapacityGuestOriginalPostgres|TestWorkflowGuestOriginalGraph)$' 2>"$guest_go_stderr" | tee "$guest_corpus_path" 2>"$guest_tee_stderr"
      guest_pipeline_status=("${PIPESTATUS[@]}")
      ;;
    native)
      go test -json -tags nativequalification -p 1 -count=1 -timeout=3m ./repository ./controllers/httpapi ./controllers/message -run '^TestCapacityGuestOriginal(NativeCorpusPostgres|HTTPCallbacksPostgres|WorkflowNativeReadsPostgres)$' 2>"$guest_go_stderr" | tee "$guest_corpus_path" 2>"$guest_tee_stderr"
      guest_pipeline_status=("${PIPESTATUS[@]}")
      ;;
    native-hold)
      go test -json -tags nativequalification -p 1 -count=1 -timeout=3m ./repository -run '^TestCapacityGuestOriginalNativeHoldCorpusPostgres$' 2>"$guest_go_stderr" | tee "$guest_corpus_path" 2>"$guest_tee_stderr"
      guest_pipeline_status=("${PIPESTATUS[@]}")
      ;;
    bytes)
      go test -json -p 1 -count=1 -timeout=3m ./internal/capacity -run '^(TestGuestOriginalClosedBytes|TestGuestOriginalHTTPBoundedFacts|TestGuestOriginalHTTPClosedFactFields)$' 2>"$guest_go_stderr" | tee "$guest_corpus_path" 2>"$guest_tee_stderr"
      guest_pipeline_status=("${PIPESTATUS[@]}")
      ;;
    native-decode)
      go test -json -tags nativequalification -p 1 -count=1 -timeout=3m ./internal/capacitynativeqemu -run '^(TestOriginalNativeQEMUClosedSourceBytes|TestOriginalNativeQEMUMetadataDecoderSeparate)$' 2>"$guest_go_stderr" | tee "$guest_corpus_path" 2>"$guest_tee_stderr"
      guest_pipeline_status=("${PIPESTATUS[@]}")
      ;;
    native-owners)
      go test -json -tags nativequalification -p 1 -count=1 -timeout=3m ./controllers/httpapi ./cmd/native-guest-lifecycle-fixture -run '^(TestCapacityGuestOriginalAsyncOwner|TestOriginalNativeHTTPReturnedOwners)$' 2>"$guest_go_stderr" | tee "$guest_corpus_path" 2>"$guest_tee_stderr"
      guest_pipeline_status=("${PIPESTATUS[@]}")
      ;;
    transferred)
      go test -json -p 1 -count=1 -timeout=3m ./internal/capacity -run '^(TestGuestOriginalProvisioningBudgetPrecedesCreateAndNeverDefaults|TestGuestOriginalProvisioningStoredBudgetCannotRenewAfterCreate|TestVMRetirementKeepsOriginalUncertaintyAndQuiescenceSeparate|TestGuestOriginalRetirementFirstDeadline)$' 2>"$guest_go_stderr" | tee "$guest_corpus_path" 2>"$guest_tee_stderr"
      guest_pipeline_status=("${PIPESTATUS[@]}")
      ;;
  esac
  guest_go_exit="${guest_pipeline_status[0]}"
  guest_tee_exit="${guest_pipeline_status[1]}"
fi
python3 - "$guest_corpus_mode" "$guest_corpus_path" "$guest_census_path" "$guest_go_stderr" "$guest_tee_stderr" "$guest_go_started" "$guest_go_exit" "$guest_tee_exit" "$guest_preflight_error" >"$guest_census_stdout" 2>"$guest_census_stderr" <<'PY'
import json
import sys
from collections import Counter
from pathlib import Path

mode, source, target, go_stderr, tee_stderr, started, go_exit, tee_exit, preflight_error = sys.argv[1:]
events, malformed = [], []
try:
    lines = Path(source).read_text().splitlines()
except (OSError, UnicodeError) as exc:
    lines = []
    malformed.append({'line': None, 'error': type(exc).__name__})
for number, line in enumerate(lines, 1):
    if not line.strip():
        continue
    try:
        event = json.loads(line)
        if not isinstance(event, dict):
            raise ValueError('event object required')
        for key in ('Action', 'Package', 'ImportPath', 'Test'):
            if key in event and not isinstance(event[key], str):
                raise ValueError('event text field required')
        events.append(event)
    except (ValueError, TypeError) as exc:
        malformed.append({'line': number, 'error': type(exc).__name__})
if mode == 'native':
    groups = {'TestCapacityGuestOriginalNativeCorpusPostgres': (), 'TestCapacityGuestOriginalHTTPCallbacksPostgres': (), 'TestCapacityGuestOriginalWorkflowNativeReadsPostgres': ()}
    packages = {'github.com/dakasa-yggdrasil/yggdrasil-core/repository', 'github.com/dakasa-yggdrasil/yggdrasil-core/controllers/httpapi', 'github.com/dakasa-yggdrasil/yggdrasil-core/controllers/message'}
elif mode == 'native-hold':
    groups = {'TestCapacityGuestOriginalNativeHoldCorpusPostgres': ()}
    packages = {'github.com/dakasa-yggdrasil/yggdrasil-core/repository'}
elif mode == 'bytes':
    groups = {'TestGuestOriginalClosedBytes': (
        'canonical_binary_roundtrip', 'canonical_more_than_array_limit',
        'bounded_large_body_preserves_bytes', 'nil_bytes_are_not_retained_empty',
        'retained_empty_remains_empty', 'partial_metadata_keeps_empty_body_and_hash',
        'partial_transport_never_decodes_complete', 'canceled_transport_never_decodes_complete',
        'named_byte_slice_is_not_specialcase', 'exact_byte_alias_retains_specialcase',
        'null_body', 'numeric_array', 'number_body', 'object_body', 'bool_body',
        'unpadded', 'nonzero_pad_bits', 'url_alphabet', 'embedded_lf', 'embedded_cr',
        'embedded_tab', 'json_literal_newline', 'encoded_oversize', 'missing_body',
        'uppercase_alias', 'duplicate_body', 'unknown_field', 'raw_wire_oversize',
        'trailing_object'),
        'TestGuestOriginalHTTPBoundedFacts': (
            'actual_complete_read', 'actual_empty_eof', 'actual_cap_plus_one_before_prefix',
            'actual_partial_read_error', 'no_read_do_refusal', 'no_read_preflight_refusal',
            'actual_close_refusal_after_eof', 'actual_context_refusal_after_eof'),
        'TestGuestOriginalHTTPClosedFactFields': (
            'exact_three_fields', 'missing_scope', 'missing_prefix_count', 'missing_prefix_hash',
            'scope_case_alias', 'prefix_count_alias', 'prefix_hash_alias', 'unknown_fact', 'duplicate_scope'),
    }
    packages = {'github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity'}
elif mode == 'native-decode':
    groups = {
        'TestOriginalNativeQEMUClosedSourceBytes': (
            'complete_struct_requires_explicit_false', 'typed_wire_is_not_original_native_proof',
            'omitted_singlestep', 'null_singlestep', 'singlestep_alias',
            'singlestep_fold_duplicate', 'singlestep_duplicate', 'unknown_nested_status',
            'unknown_nested_lifetime', 'unknown_nested_peer', 'omitted_original_close',
            'null_original_io', 'omitted_original_io', 'uuid_case_alias', 'trailing_record',
            'root_array', 'root_null', 'wire_oversize',
            'independent_omitted_nested_singlestep', 'independent_unknown_nested',
            'independent_alias_native_tuple'),
        'TestOriginalNativeQEMUMetadataDecoderSeparate': (
            'unknown_qmp_metadata_is_read_only_shape', 'map_duplicate_key',
            'map_fold_duplicate_key', 'map_nested_fold_duplicate', 'map_trailing_record',
            'same_metadata_cannot_decode_privileged_source'),
    }
    packages = {'github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacitynativeqemu'}
elif mode == 'native-owners':
    groups = {'TestCapacityGuestOriginalAsyncOwner': (
        'default_parent_is_unchanged', 'same_first_deadline_is_inherited',
        'join_waits_same_original_goroutine_return', 'expired_owner_refuses_before_launch',
        'sealed_owner_refuses_before_launch', 'original_error_is_retained',
        'all_original_returns_are_required_once', 'original_cancellation_does_not_join_pending_return'),
        'TestOriginalNativeHTTPReturnedOwners': (
            'serve_close_does_not_join_original_handler',
            'same_handler_return_is_required_after_shutdown'),
    }
    packages = {'github.com/dakasa-yggdrasil/yggdrasil-core/controllers/httpapi',
                'github.com/dakasa-yggdrasil/yggdrasil-core/cmd/native-guest-lifecycle-fixture'}
elif mode == 'transferred':
    groups = {
        'TestGuestOriginalProvisioningBudgetPrecedesCreateAndNeverDefaults': (
            'explicit_original_budget', 'shorter_original_context_wins',
            'no_original_context_deadline', 'canceled_original_context', 'zero_budget',
            'negative_budget', 'unbounded_budget', 'missing_step_id', 'foreign_step_id',
            'foreign_operation', 'foreign_kind', 'implicit_timeout', 'shorter_step_timeout',
            'unbounded_step_timeout', 'repeating_original', 'foreach_original'),
        'TestGuestOriginalProvisioningStoredBudgetCannotRenewAfterCreate': (
            'immutable_original_budget', 'stored_shorter_context', 'deadline_renewed',
            'deadline_reduced_without_original_context', 'profile_changed_after_create',
            'workflow_changed_after_create', 'missing_context', 'missing_reservation',
            'missing_nonce', 'foreign_original_request', 'foreign_original_policy',
            'foreign_original_workflow', 'foreign_source', 'zero_original_fence',
            'zero_original_generation', 'missing_original_executor'),
        'TestGuestOriginalRetirementFirstDeadline': (
            'actor_thirty_seconds_precedes_long_source_and_lease',
            'shorter_original_context_is_literal', 'shorter_current_lease_is_literal',
            'no_context_deadline', 'canceled_original_context', 'expired_current_lease',
            'missing_original_issued_at'),
        'TestVMRetirementKeepsOriginalUncertaintyAndQuiescenceSeparate': (
            'accepted-original-known-resources', 'uncertain-original-even-all-absent',
            'lost-original-transport', 'unknown-main-action', 'foreign-main-action',
            'running-main-action', 'error-main-action', 'foreign-resource', 'foreign-created-at',
            'foreign-grant', 'foreign-grant-state', 'foreign-binding', 'protected-ordinary-slot',
            'unknown-auxiliary-inventory', 'missing-owned-auxiliary', 'foreign-auxiliary',
            'present-auxiliary', 'duplicate-auxiliary', 'unexpected-successor',
            'incomplete-server-absence', 'server-still-present', 'retained-hold-reason',
            'fake-provider-quiescence', 'fake-provider-fencing', 'fake-invoice', 'stale-read',
            'reversed-read-window', 'missing-exposure', 'foreign-exposure-resource',
            'foreign-exposure-end', 'invoice-exposure-basis', 'foreign-exposure-currency',
            'negative-exposure-ceiling'),
    }
    packages = {'github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity'}
else:
    groups = {
        'TestCapacityGuestOriginalAuth': (
            'unconfigured_private_route', 'human_session_cannot_enter_guest',
            'actor_cannot_read_public_health', 'actor_cannot_dispatch_workflow',
            'actor_cannot_publish_events', 'actor_cannot_write_manifest',
            'actor_cannot_confirm_installation', 'human_cannot_confirm_installation',
            'actor_cannot_use_provisioner_path', 'provisioner_cannot_use_actor_path',
            'dot_segment_refused_before_mux_redirect', 'escaped_path_refused',
            'expired_credential_still_claims_public_route',
            'revoked_credential_still_claims_public_route',
            'disabled_credential_still_claims_workflow_route',
            'plaintext_transport_refused', 'ambiguous_bearers_do_not_fall_through',
            'guest_cannot_become_original_canary', 'guest_cannot_become_directory_reader',
            'database_unavailable_retains_private_claim'),
        'TestCapacityGuestOriginalInventory': (
            'unset_is_default_off', 'blank', 'whitespace', 'null', 'empty', 'object',
            'unknown', 'trailing', 'unscoped_role', 'wildcard_member', 'member_path',
            'member_space', 'slot_zero', 'slot_above_bound', 'profile_not_digest',
            'missing_rotation', 'missing_expiry', 'independent_actor_and_provisioner',
            'duplicate_identity_or_digest', 'collision_workflow', 'collision_event',
            'collision_directory', 'collision_mutation',
            'collision_YGGDRASIL_WORKFLOW_RUN_TOKEN', 'collision_YGGDRASIL_EVENT_PUBLISH_TOKEN',
            'collision_YGGDRASIL_DEPLOY_TOKEN', 'collision_YGGDRASIL_AUTH_ADMIN_TOKEN'),
        'TestCapacityGuestOriginalClosedRegistration': (
            'empty', 'null', 'trailing', 'missing_false', 'caller_authority', 'duplicate'),
        'TestCapacityGuestOriginalCanonicalResponse': (),
        'TestWorkflowGuestOriginalGraph': (
            'complete_declared_source_graph', 'unknown_operation', 'empty_operation',
            'invalid_rbac_selector', 'unknown_dependency', 'self_dependency', 'cycle',
            'duplicate_step', 'integration_instance_on_guest', 'integration_family_on_guest',
            'integration_provider_on_guest', 'negative_timeout',
            'authorization_required_provision_original_guest',
            'authorization_required_qualify_original_guest_echo',
            'authorization_required_retire_original_guest',
            'authorization_required_finish_original_guest_retirement', 'malformed_literal_json'),
        'TestCapacityGuestOriginalManifestPayload': (
            'duplicate_outer_binding', 'duplicate_nested_mode', 'duplicate_nested_profile',
            'case_outer_binding', 'case_nested_mode', 'fold_duplicate_nested_mode',
            'null_binding', 'null_nested_profile', 'unknown_nested_authority',
            'literal_binding_shape_preserved', 'absent_binding_remains_default_off',
            'other_kind_keeps_generic_normalization'),
        'TestCapacityGuestOriginalManifestPublicBoundary': (
            'duplicate_outer_before_sql', 'duplicate_nested_before_sql',
            'production_anonymous_refused', 'workflow_principal_cannot_write_policy'),
        'TestCapacityGuestOriginalPublicWorkflowAdmission': (
            'complete_graph_reaches_durable_boundary', 'unknown_guest_operation_before_insert',
            'missing_authorization_refused', 'wrong_principal_scope_refused', 'rbac_denial_refused'),
        'TestCapacityGuestOriginalBootstrapBoundary': (
            'anonymous_refused', 'workflow_token_is_not_deploy', 'dedicated_deploy_keeps_legacy_gone'),
        'TestCapacityGuestOriginalPostgres': (
            'public_observe_redacted_private_lease_exact',
            'claimed_complete_production_roster_registry_hold_before_reservation',
            'canonical_bytes_survive_native_timestamp_representation',
            'legacy_missing_bytes', 'jsonb_differs_from_original_bytes',
            'native_deadline_differs_from_original', 'profile_hash_not_original',
            'binding_bytes_missing', 'legacy_enrollment_without_receipt',
            'provider_off_without_original_guest_joins',
            'failed_create_without_never_started_producer',
            'native_tuple_uses_resource_created_at',
            'before_start_challenges_have_independent_original_identity',
            'possible_send_is_permanent_after_deadline',
            'scoped_original_tables_keep_immutable_triggers',
            'unknown_original_is_not_a_retry_identity'),
    }
    expected = set(groups)
    expected.update(root + '/' + child for root, children in groups.items() for child in children)
    packages = {'github.com/dakasa-yggdrasil/yggdrasil-core/controllers/httpapi',
                'github.com/dakasa-yggdrasil/yggdrasil-core/repository',
                'github.com/dakasa-yggdrasil/yggdrasil-core/manifest'}
# Keep original source70 preserved within source118 independent of the additional byte/grammar roots.
expected = set(groups)
expected.update(root + '/' + child for root, children in groups.items() for child in children)
ran = Counter(e.get('Test') for e in events if e.get('Action') == 'run' and isinstance(e.get('Test'), str))
passed = Counter(e.get('Test') for e in events if e.get('Action') == 'pass' and isinstance(e.get('Test'), str))
package_census = {package: {
    'start': sum(e.get('Package') == package and e.get('Action') == 'start' and not e.get('Test') for e in events),
    'pass': sum(e.get('Package') == package and e.get('Action') == 'pass' and not e.get('Test') for e in events),
} for package in sorted(packages)}
failures = [{k: e[k] for k in ('Package', 'ImportPath', 'Test', 'Action') if k in e}
            for e in events if e.get('Action') in ('fail', 'skip', 'build-fail')]
unexpected_packages = sorted({str(e.get('Package', e.get('ImportPath', '<missing>')))
                              for e in events if e.get('Package') not in packages})
case_complete = set(ran) == expected and set(passed) == expected and all(ran[n] == 1 and passed[n] == 1 for n in expected)
package_complete = all(c['start'] == 1 and c['pass'] == 1 for c in package_census.values())
go_code = int(go_exit) if started == 'true' else None
tee_code = int(tee_exit) if started == 'true' else None
verdict = 'PASS' if started == 'true' and go_code == 0 and tee_code == 0 and not preflight_error and not malformed and not failures and not unexpected_packages and case_complete and package_complete else 'FAIL'
summary = {
    'schema': 'guest_original_ci_case_census_v1', 'mode': mode, 'status': verdict,
    'test_process_started': started == 'true', 'test_process_exit_code': go_code,
    'tee_process_exit_code': tee_code, 'preflight_error': preflight_error or None,
    'expected_case_count': len(expected), 'expected_cases': sorted(expected),
    'run_counts': dict(sorted(ran.items())), 'pass_counts': dict(sorted(passed.items())),
    'missing_run': sorted(expected - set(ran)), 'missing_pass': sorted(expected - set(passed)),
    'unexpected_run': sorted(set(ran) - expected), 'unexpected_pass': sorted(set(passed) - expected),
    'repeated_run': {n: v for n, v in ran.items() if v != 1},
    'repeated_pass': {n: v for n, v in passed.items() if v != 1},
    'package_census': package_census, 'unexpected_packages': unexpected_packages,
    'failure_or_skip_events': failures, 'malformed_json_lines': malformed,
    'original_jsonl_path': source, 'go_test_stderr_path': go_stderr,
    'tee_stderr_path': tee_stderr,
}
# Commit a durable census before the shell returns any failing gate status.
output = Path(target)
staged = output.with_suffix('.tmp')
staged.write_text(json.dumps(summary, indent=2, sort_keys=True) + '\n')
staged.replace(output)
print(json.dumps({'status': verdict, 'expected_cases': len(expected),
                  'test_exit': go_code, 'tee_exit': tee_code, 'census': target}))
raise SystemExit(0 if verdict == 'PASS' else 1)
PY
guest_census_exit=$?
set -e
cat "$guest_census_stdout"
if [[ "$guest_go_started" != "true" || "$guest_go_exit" != "0" || "$guest_tee_exit" != "0" || "$guest_census_exit" != "0" ]]; then
  [[ -z "$guest_preflight_error" ]] || printf '%s\n' "$guest_preflight_error" >&2
  cat "$guest_go_stderr" "$guest_tee_stderr" "$guest_census_stderr" >&2
  printf 'Original Guest CI failed; retained artifact directory: %s\n' "$guest_artifact_dir" >&2
  if [[ "$guest_go_started" == "true" && "$guest_go_exit" != "0" ]]; then exit "$guest_go_exit"; fi
  if [[ "$guest_go_started" == "true" && "$guest_tee_exit" != "0" ]]; then exit "$guest_tee_exit"; fi
  if [[ "$guest_census_exit" != "0" ]]; then exit "$guest_census_exit"; fi
  exit 1
fi
