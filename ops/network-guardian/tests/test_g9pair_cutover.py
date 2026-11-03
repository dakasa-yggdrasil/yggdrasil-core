"""Run actual G9 CLI/sequencer/Backend definitions with simulated native I/O.

These are ordering, custody and refusal tests. They cannot qualify a service,
network window, actual publication, production lock or cloud operation.
"""
import contextlib
import io
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

import test_g7pair_cutover as old
import test_g9pair_tools as tools


cut = tools.load_tool('g9cut')


class G9CutoverTests(unittest.TestCase):
    def assert_prefix(self, backend, length):
        return old.G7CutoverTests.assert_prefix(self, backend, length)

    def reuse(self, name):
        with tools.declared_binding(cut.C), patch.object(old, 'cut', cut):
            getattr(old.G7CutoverTests, name)(self)

    def test_unbound_swap_and_cli_refuse_before_custody_or_native_effect(self):
        with patch.object(cut.C, 'PROPOSAL_BOUND', False), patch.object(cut, 'Backend') as backend, \
                patch.object(cut, 'custody') as custody, patch.object(cut, 'native') as native:
            with self.assertRaises(cut.C.Hold):
                cut.swap_once(backend)
            with self.assertRaises(cut.C.Hold):
                cut.main()
            backend.assert_not_called()
            self.assertEqual(backend.mock_calls, [])
            custody.assert_not_called()
            native.assert_not_called()

    def test_all_six_possible_send_ack_failure_and_guard_positions_never_retry(self):
        for name in ('test_real_cli_success_uses_only_six_fixed_native_submissions',
                     'test_closed_native_boundary_refuses_unknown_or_changed_effect',
                     'test_native_timeout_retains_possible_and_uncertain_original_return',
                     'test_native_nonzero_is_failure_without_forward_or_compensating_actions',
                     'test_possible_send_persistence_failure_prevents_that_native_call',
                     'test_return_persistence_failure_keeps_possible_without_replay',
                     'test_guard_cas_readiness_and_qualification_failures_hold_at_exact_prefix',
                     'test_uncertain_attempt_cannot_reenter_or_replace_original_claim',
                     'test_hold_record_failure_never_triggers_a_cleanup_or_retry'):
            with self.subTest(corpus=name):
                self.reuse(name)

    def test_real_exclusive_global_claim_and_readonly_close_survive_other_directory(self):
        for name in ('test_real_once_writer_is_exclusive_durable_and_never_overwrites',
                     'test_real_backend_global_claim_survives_another_evidence_directory',
                     'test_actual_backend_close_only_joins_read_observers'):
            with self.subTest(corpus=name):
                self.reuse(name)

    def test_real_pid_absence_bounded_exec_and_both_final_physical_identities(self):
        for name in ('test_real_absence_guard_accepts_retained_terminal_pid_and_refuses_live_identity',
                     'test_real_type_simple_wait_handles_only_one_bounded_fork_exec_lifetime',
                     'test_actual_backend_final_closure_rechecks_both_physical_processes',
                     'test_real_shared_parent_accepts_0755_without_chmod_and_refuses_writes_or_links'):
            with self.subTest(corpus=name):
                self.reuse(name)

    def test_actual_g9_main_routes_through_custody_same_backend_and_real_once_sequence(self):
        with tools.declared_binding(cut.C), patch.object(old, 'cut', cut):
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
            qualification = {'schema': 'g9_no_apply_qualification_v1', 'manifest_sha256': '1' * 64,
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
                raise AssertionError('unexpected native read in declared CLI boundary')

            @contextlib.contextmanager
            def custody():
                self.assertFalse(backend.custody_active)
                backend.custody_active = True
                try:
                    yield [('declared-CI-custody', 1, 2)]
                finally:
                    backend.custody_active = False

            argv = ['g9cut.py', 'swap-once', '--package', str(tools.TOOLS.parent),
                    '--expected-manifest-sha256', '1' * 64, '--evidence-dir', str(cut.C.STATE / 'swap-once-CI'),
                    '--stage-receipt', '/declared-stage.json', '--expected-stage-receipt-sha256', '2' * 64,
                    '--qualification-receipt', str(path), '--expected-qualification-receipt-sha256', cut.C.sha(raw), '--execute-once']
            with patch.object(sys, 'argv', argv), patch.object(cut.os, 'geteuid', return_value=0), \
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
            self.assertEqual(backend.native_calls, [args for _, args in old.EXPECTED_NATIVE])
            self.assertFalse(backend.custody_active)
            self.assertEqual(backend.events[-1], ('close', 'readers-only'))
            self.assertTrue(cut.C.loads(output.getvalue())['fixture_simulated'])
