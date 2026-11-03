"""Actual G8 CLI/backend definitions; native Linux facts are simulated in CI.

The unchanged G7 failure corpus is deliberately reused against the G8 functions,
without modifying its files or claiming service effects/physical qualification.
"""
import contextlib
import copy
import io
import json
from pathlib import Path
import tempfile
import sys
import types
import unittest
from unittest.mock import Mock, patch

import test_g7pair_cutover as old
import test_g8pair_tools as tools


cut = tools.load_tool('g8cut')
EXPECTED_NATIVE = old.EXPECTED_NATIVE


class G8CutoverTests(unittest.TestCase):
    def assert_prefix(self, backend, length):
        return old.G7CutoverTests.assert_prefix(self, backend, length)

    def reuse(self, name):
        # Reuse established adversarial inputs, while send_once/swap_once,
        # Backend and all production guards being called belong to actual G8.
        with patch.object(old, 'cut', cut):
            getattr(old.G7CutoverTests, name)(self)

    def test_real_g8_swap_success_has_only_the_six_forward_native_submissions(self):
        self.reuse('test_real_cli_success_uses_only_six_fixed_native_submissions')

    def test_native_boundary_refuses_unknown_restart_reset_cold_or_hub(self):
        self.reuse('test_closed_native_boundary_refuses_unknown_or_changed_effect')

    def test_all_six_native_timeouts_retain_original_uncertainty_without_retry(self):
        self.reuse('test_native_timeout_retains_possible_and_uncertain_original_return')

    def test_all_six_nonzero_native_returns_stop_at_the_original_prefix(self):
        self.reuse('test_native_nonzero_is_failure_without_forward_or_compensating_actions')

    def test_all_six_possible_send_write_failures_prevent_that_submission(self):
        self.reuse('test_possible_send_persistence_failure_prevents_that_native_call')

    def test_all_six_return_write_failures_preserve_possible_without_replay(self):
        self.reuse('test_return_persistence_failure_keeps_possible_without_replay')

    def test_every_guard_cas_readiness_and_qualification_failure_holds_its_prefix(self):
        self.reuse('test_guard_cas_readiness_and_qualification_failures_hold_at_exact_prefix')

    def test_uncertain_attempt_and_failed_hold_record_cannot_trigger_cleanup(self):
        self.reuse('test_uncertain_attempt_cannot_reenter_or_replace_original_claim')
        self.reuse('test_hold_record_failure_never_triggers_a_cleanup_or_retry')

    def test_real_g8_exclusive_writer_and_global_claim_survive_a_second_directory(self):
        self.reuse('test_real_once_writer_is_exclusive_durable_and_never_overwrites')
        self.reuse('test_real_backend_global_claim_survives_another_evidence_directory')

    def test_real_absence_guard_accepts_only_old_or_zero_execmainpid_with_no_process(self):
        self.reuse('test_real_absence_guard_accepts_retained_terminal_pid_and_refuses_live_identity')

    def test_real_type_simple_exec_wait_preserves_one_pid_invocation_ticks_and_deadline(self):
        self.reuse('test_real_type_simple_wait_handles_only_one_bounded_fork_exec_lifetime')

    def test_real_shared_parent_and_close_never_chmod_or_submit_cleanup(self):
        self.reuse('test_real_shared_parent_accepts_0755_without_chmod_and_refuses_writes_or_links')
        self.reuse('test_actual_backend_close_only_joins_read_observers')

    def test_actual_g8_entry_uses_real_once_sequence_inside_custody(self):
        with patch.object(old, 'cut', cut):
            backend = old.NativeBoundary()
        backend.require_custody, backend.custody_active = True, False
        backend.close = lambda: backend.events.append(('close', 'readers-only'))
        manifest = tools.declared_manifest()
        staged = {'source_roster': {name: manifest['files']['source/' + name] for name in cut.C.MODULES},
                  'units': {cut.CTRL: manifest['controller_unit_sha256'],
                            cut.COLD: manifest['files']['units/' + cut.COLD],
                            cut.GUARD: manifest['files']['units/' + cut.GUARD]}, 'standing_sha256': '3' * 64}
        path = Path('/declared-CI-qualification/QUALIFIED.json')
        original = b'{"declared_CI_check_once":true}\n'
        qualification = {'schema': 'g8_no_apply_qualification_v1', 'manifest_sha256': '1' * 64,
                         'controller_config_sha256': cut.C.HEAD_CONFIG_SHA, 'core_overlap': {'fixture_only': True},
                         'standing_sha256': '3' * 64, 'native_apply': False,
                         'actual_new_controller120_or_live_acceptance': False, 'observed_monotonic': 1,
                         'boot_id': manifest['expected_controller_identity']['boot_id'],
                         'original_check_once_ref': {'path': str(path.parent / 'CHECK-ONCE.json'), 'sha256': cut.C.sha(original)}}
        raw = cut.C.wire(qualification)
        def read(selected, *_):
            selected = Path(selected)
            if selected == path:
                return raw
            if selected == path.parent / 'CHECK-ONCE.json':
                return original
            if selected == Path(cut.__file__):
                return selected.read_bytes()
            raise AssertionError('unexpected native read in G8 entry test')
        @contextlib.contextmanager
        def custody():
            self.assertFalse(backend.custody_active)
            backend.custody_active = True
            try:
                yield [('declared-CI-custody', 1, 2)]
            finally:
                backend.custody_active = False
        argv = ['g8cut.py', 'swap-once', '--package', str(tools.TOOLS.parent),
                '--expected-manifest-sha256', '1' * 64, '--evidence-dir', str(cut.C.STATE / 'swap-once-CI'),
                '--stage-receipt', '/declared-stage.json', '--expected-stage-receipt-sha256', '2' * 64,
                '--qualification-receipt', str(path), '--expected-qualification-receipt-sha256', cut.C.sha(raw), '--execute-once']
        with patch.object(old, 'cut', cut), patch.object(sys, 'argv', argv), \
                patch.object(cut.os, 'geteuid', return_value=0), \
                patch.object(cut.C, 'package', return_value=(tools.TOOLS.parent, manifest)), \
                patch.object(cut.C, 'private_dir'), patch.object(cut.C, 'read', side_effect=read), \
                patch.object(cut.C, 'once', side_effect=AssertionError('no direct CLI mutation')), \
                patch.object(cut.signal, 'signal'), patch.object(cut, 'custody', side_effect=custody), \
                patch.object(cut, 'load_staged', return_value=staged), \
                patch.object(cut, 'Backend', return_value=backend) as factory, \
                patch.object(cut, 'swap_once', wraps=cut.swap_once) as swap, \
                patch.object(cut, 'native', side_effect=AssertionError('no native CI action')) as native, \
                contextlib.redirect_stdout(io.StringIO()) as output:
            cut.main()
            factory.assert_called_once()
            swap.assert_called_once_with(backend)
            native.assert_not_called()
        self.assertEqual(backend.native_calls, [args for _, args in EXPECTED_NATIVE])
        self.assertFalse(backend.custody_active)
        self.assertEqual(backend.events[-1], ('close', 'readers-only'))
        self.assertTrue(cut.C.loads(output.getvalue())['fixture_simulated'])

    def test_actual_g8_parser_has_no_legacy_retry_reset_rollback_or_resume_mode(self):
        self.reuse('test_actual_cli_parser_refuses_legacy_replay_reset_and_rollback')

    def test_real_backend_rejects_g8_config_and_runtime_drift_before_any_effect(self):
        _, _, config = tools.controller_inputs()
        guardian = tools.source.g8
        runtime = {cut.C.RUNTIME / name: ('declared-CI-runtime-' + name).encode() for name in guardian.RUNTIME_HASHES}
        hash_boundary = {runtime[cut.C.RUNTIME / name]: pin for name, pin in guardian.RUNTIME_HASHES.items()}
        original_sha = cut.C.sha
        manifest = {'expected_controller_identity': {}, 'expected_guardian_identity': {},
                    'files': {'source/network_guardian.py': tools.source.digest(Path(guardian.__file__).read_bytes())}}
        for drift in (None, 'config', 'runtime'):
            backend = cut.Backend(Path('/declared-CI'), manifest, '1' * 64, Path('/declared-run'), {}, [], {})
            bodies = {cut.C.NEW_CONFIG: config, **runtime}
            if drift == 'config':
                bodies[cut.C.NEW_CONFIG] += b' '
            elif drift == 'runtime':
                bodies[next(iter(runtime))] += b'drift'
            def read(path, *args):
                if path == cut.C.NEW_CONFIG:
                    self.assertEqual(args, (32768, 0o600))
                return bodies[path]
            def iterdir(path):
                self.assertEqual(path, cut.C.RUNTIME)
                return iter(runtime)
            with self.subTest(drift=drift), patch.object(cut.C, 'read', side_effect=read), \
                    patch.object(cut.C, 'sha', side_effect=lambda raw: hash_boundary.get(raw, original_sha(raw))), \
                    patch.object(cut.C, 'load_guardian', return_value=guardian), patch.object(Path, 'iterdir', iterdir), \
                    patch.object(cut.C, 'once', side_effect=AssertionError('no preflight file write')) as once, \
                    patch.object(cut, 'native', side_effect=AssertionError('no preflight native call')) as native:
                if drift is None:
                    backend.controller_inputs()
                else:
                    with self.assertRaises(cut.Hold):
                        backend.preconditions()
                once.assert_not_called()
                native.assert_not_called()

    def test_real_protected_reader_requires_exact_same_files_and_one_inherited_budget_marker(self):
        # Declared CI file bodies, not substitutions for actual Root authority
        # bytes. The real reader/hash/count guard is executed in a temp ledger.
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            refs = []
            for original in tools.protected_refs():
                p = root / Path(original).name
                raw = ('declared-CI-file-body:' + p.name).encode()
                p.write_bytes(raw)
                refs.append({'path': str(p), 'sha256': cut.C.sha(raw)})
            manifest = {'expected_controller_identity': {'boot_id': '2b7e9be2-e45a-4cd5-86f2-6f0a3372576d'},
                        'expected_guardian_identity': {}, 'protected_refs': refs}
            backend = cut.Backend(root, manifest, '1' * 64, root, {}, [], {})
            with patch.object(cut.C, 'LEDGER', root), \
                    patch.object(cut.C, 'read', side_effect=lambda p, *_: Path(p).read_bytes()), \
                    patch.object(cut, 'native', side_effect=AssertionError('no budget mutation')) as native:
                before = backend.protected()
                self.assertEqual(len(before), 39)
                marker = next(root.glob('*-RECOVERY-*-POSSIBLE-START.PUBLIC.json'))
                extra = root / ('2b7e9be2-e45a-4cd5-86f2-6f0a3372576d-RECOVERY-extra-POSSIBLE-START.PUBLIC.json')
                extra.write_bytes(b'declared second marker')
                with self.assertRaisesRegex(cut.Hold, 'ONE_OF_THREE'):
                    backend.protected()
                extra.unlink()
                marker.write_bytes(b'drift')
                with self.assertRaisesRegex(cut.Hold, 'UNCHANGED_ACTUAL_ORIGINAL_PROTECTED_REF'):
                    backend.protected()
                native.assert_not_called()

    def test_real_final_closure_refuses_any_changed_controller_or_guardian_lifetime(self):
        self.reuse('test_actual_backend_final_closure_rechecks_both_physical_processes')

    def test_own_daemon_return_is_required_before_any_independent_assessor(self):
        backend = cut.Backend(Path('/declared-CI'), {'expected_controller_identity': {'pid': 1, 'InvocationID': '1' * 32},
                    'expected_guardian_identity': {'pid': 2, 'InvocationID': '2' * 32},
                    'files': {'source/network_guardian.py': '3' * 64}}, '1' * 64, Path('/declared-run'), {}, [], {})
        backend.new_controller = {'boot_id': 'declared-boot', 'pid': 3, 'start_ticks': 30,
                                  'InvocationID': '3' * 32, 'ExecMainStartTimestampMonotonic': '300'}
        guardian = {**backend.new_controller, 'pid': 4, 'InvocationID': '4' * 32}
        backend.standing_pin = '4' * 64
        clock = types.SimpleNamespace(now=0)
        with patch.object(cut, 'wait_exec_identity', return_value=guardian), \
                patch.object(cut, 'physical_identity', side_effect=lambda unit, _: backend.new_controller if unit == cut.CTRL else guardian), \
                patch.object(Path, 'exists', return_value=False), \
                patch.object(cut.C, 'load_guardian', side_effect=AssertionError('no assessor before daemon return')) as assessor, \
                patch.object(cut.time, 'monotonic', side_effect=lambda: clock.now), \
                patch.object(cut.time, 'sleep', side_effect=lambda n: setattr(clock, 'now', clock.now+n)), \
                patch.object(cut, 'native', side_effect=AssertionError('no extra START')) as native:
            with self.assertRaisesRegex(cut.Hold, 'NEW_OWN120_AND_DAEMON_CURRENT15_CEILING'):
                backend.wait_new_guardian()
            self.assertEqual(clock.now, 240)
            assessor.assert_not_called()
            native.assert_not_called()

    def test_real_wait_requires_new_epoch_own15_full120_and_independent_all_four(self):
        for variant in ('wrong-own-source', 'wrong-own-standing', 'wrong-own-controller',
                        'own15-false', 'own-kernel-false', 'missing-full120', 'independent15-false'):
            manifest = {'expected_controller_identity': {'pid': 1, 'InvocationID': '1' * 32},
                        'expected_guardian_identity': {'pid': 2, 'InvocationID': '2' * 32},
                        'files': {'source/network_guardian.py': '3' * 64}}
            backend = cut.Backend(Path('/declared-CI'), manifest, '1' * 64, Path('/declared-run'), {}, [], {})
            backend.new_controller = {'boot_id': 'declared-boot', 'pid': 3, 'start_ticks': 30,
                                      'InvocationID': '3' * 32, 'ExecMainStartTimestampMonotonic': '300'}
            guard = {**backend.new_controller, 'pid': 4, 'InvocationID': '4' * 32}
            backend.standing_pin = '4' * 64
            full = {**backend.new_controller,
                    'cmdline_sha256': cut.C.sha(b'\0'.join(x.encode() for x in cut.controller_argv(cut.C.NEW_CONFIG)) + b'\0'),
                    'initial_R42_admitted_lifetime': False}
            own = {'schema': 'Root_owning_finite512_current15_readonly_observation_v1',
                   'source_sha256': '3' * 64, 'standing_config_sha256': '4' * 64,
                   'identity': full, 'measurement': {'qualified_15_seconds': True, 'all_requested_rows_accounted_for': True},
                   'kernel': {'all_four_backends_and_reverse_sources_positive': True}}
            observation = {key: copy.deepcopy(own[key]) for key in ('identity', 'measurement', 'kernel')}
            if variant == 'wrong-own-source':
                own['source_sha256'] = tools.source.G7_SOURCE
            elif variant == 'wrong-own-standing':
                own['standing_config_sha256'] = tools.source.G7_STANDING
            elif variant == 'wrong-own-controller':
                own['identity'] = {**full, 'pid': 999}
            elif variant == 'own15-false':
                own['measurement']['qualified_15_seconds'] = False
            elif variant == 'own-kernel-false':
                own['kernel']['all_four_backends_and_reverse_sources_positive'] = False
            elif variant == 'independent15-false':
                observation['measurement']['qualified_15_seconds'] = False
            owner = types.SimpleNamespace(identity=Mock(return_value=full),
                    original_qualification_measurement=Mock(return_value=None if variant == 'missing-full120' else {'declared_verified120': True}),
                    current15_readonly=Mock(return_value=(observation, b'prefix', b'suffix', [])))
            G = types.SimpleNamespace(Owner=Mock(return_value=owner))
            pub = cut.C.LEDGER / (guard['boot_id'] + '-GUARDIAN-' + guard['InvocationID'] + '-FIRST-CURRENT15-RETURN.PUBLIC.json')
            def exists(path):
                return path == pub
            with self.subTest(variant=variant), patch.object(cut, 'wait_exec_identity', return_value=guard), \
                    patch.object(cut, 'physical_identity', side_effect=lambda unit, _: backend.new_controller if unit == cut.CTRL else guard), \
                    patch.object(Path, 'exists', exists), patch.object(cut.C, 'read', return_value=cut.C.wire(own)), \
                    patch.object(cut.C, 'load_guardian', return_value=G), \
                    patch.object(cut.C, 'once', side_effect=AssertionError('no independent result after refused proof')) as once, \
                    patch.object(cut, 'native', side_effect=AssertionError('no second START')) as native:
                with self.assertRaises(cut.Hold):
                    backend.wait_new_guardian()
                if variant.startswith('wrong-own') or variant in ('own15-false', 'own-kernel-false'):
                    G.Owner.assert_not_called()
                elif variant == 'missing-full120':
                    owner.current15_readonly.assert_not_called()
                once.assert_not_called()
                native.assert_not_called()
