"""Exercise the actual versioned cutover with simulated native acknowledgements.

These tests prove sequencing/failure containment, never a real controller120,
daemon current15, service action, production lock or installed file identity.
"""
import copy
import contextlib
import io
from pathlib import Path
import stat
import tempfile
import sys
import types
import unittest
from unittest.mock import Mock, patch

import test_g7pair_tools as tools


cut = tools.load_tool('g7cut')
EXPECTED_NATIVE = (
    ('STOP-OLD-GUARDIAN', ['/usr/bin/systemctl', 'stop', cut.GUARD]),
    ('RELOAD-CONTROLLER-DEFINITION', ['/usr/bin/systemctl', 'daemon-reload']),
    ('STOP-OLD-CONTROLLER', ['/usr/bin/systemctl', 'stop', cut.CTRL]),
    ('START-NEW-CONTROLLER', ['/usr/bin/systemctl', 'start', cut.CTRL]),
    ('RELOAD-FUTURE-UNITS', ['/usr/bin/systemctl', 'daemon-reload']),
    ('START-NEW-GUARDIAN', ['/usr/bin/systemctl', 'start', cut.GUARD]),
)
METHODS = ('preconditions', 'claim_once', 'quiescent_guardian', 'assert_old_guardian_absent',
           'cas_controller_once', 'verify_controller_definition', 'fresh_window',
           'assert_old_controller_absent', 'controller_inputs', 'wait_new_controller', 'cas_future_units_once',
           'install_standing_once', 'wait_new_guardian', 'final_closure')


class NativeBoundary:
    """Keep original simulated receipts; duplicate names never overwrite history."""
    def __init__(self, fail_step=None, fail_record=None, native_failure=None):
        self.fail_step, self.fail_record, self.native_failure = fail_step, fail_record, native_failure
        self.records, self.native_calls, self.events = {}, [], []

    def record_once(self, name, value):
        self.events.append(('record-attempt', name))
        if name in self.records:
            raise FileExistsError(name)
        if name == self.fail_record:
            raise OSError('simulated durable record failure')
        self.records[name] = copy.deepcopy(value)
        self.events.append(('durable-record', name))

    def native(self, argv, seconds):
        if getattr(self, 'require_custody', False):
            assert self.custody_active
        index = len(self.native_calls)
        name, expected = EXPECTED_NATIVE[index]
        assert seconds == (20, 30, 20, 20, 30, 30)[index]
        assert argv == expected and name + '-POSSIBLE-SEND.json' in self.records
        assert self.events[-1] == ('durable-record', name + '-POSSIBLE-SEND.json')
        self.native_calls.append(copy.deepcopy(argv))
        self.events.append(('native', name))
        if self.native_failure == (index, 'timeout'):
            raise TimeoutError('simulated uncertain native transport')
        code = 17 if self.native_failure == (index, 'nonzero') else 0
        return types.SimpleNamespace(returncode=code, stdout=b'declared-CI-native-output', stderr=b'')

    def step(self, name):
        self.events.append(('guard', name))
        if name == self.fail_step:
            raise cut.Hold('SIMULATED_GUARD_' + name)
        if name == 'claim_once':
            self.record_once('CLAIMED.json', {'fixture_only': True})
        if name == 'final_closure':
            return {'fixture_simulated': True, 'production_authority': False}


for _method in METHODS:
    setattr(NativeBoundary, _method, lambda self, name=_method: self.step(name))


class G7CutoverTests(unittest.TestCase):
    def assert_prefix(self, backend, length):
        self.assertEqual(backend.native_calls, [argv for _, argv in EXPECTED_NATIVE[:length]])
        self.assertNotIn('RETURN.json', backend.records)
        self.assertFalse(any('restart' in argv or 'reset-failed' in argv for argv in backend.native_calls))
        self.assertFalse(any(cut.COLD in argv or cut.HUB in argv for argv in backend.native_calls))

    def test_real_cli_success_uses_only_six_fixed_native_submissions(self):
        self.assertEqual(cut.NATIVE_SEQUENCE, EXPECTED_NATIVE)
        backend = NativeBoundary()
        result = cut.swap_once(backend)
        self.assertEqual(result, {'fixture_simulated': True, 'production_authority': False})
        self.assertEqual(backend.native_calls, [argv for _, argv in EXPECTED_NATIVE])
        self.assertEqual([event[1] for event in backend.events if event[0] == 'guard'], list(METHODS))
        self.assertEqual(backend.records['RETURN.json']['status'], 'CONFIG_SWAP_OK')
        self.assertFalse(backend.records['RETURN.json']['automatic_replay'])
        self.assertFalse(backend.records['RETURN.json']['Guest_or_Core_business_authority'])
        for name, _ in EXPECTED_NATIVE:
            self.assertTrue(backend.records[name + '-POSSIBLE-SEND.json']['native_return_is_not_qualification'])
            receipt = backend.records[name + '-NATIVE-RETURN.json']
            self.assertEqual(receipt['exit_code'], 0)
            self.assertNotIn('stdout', receipt)

    def test_closed_native_boundary_refuses_unknown_or_changed_effect(self):
        backend = NativeBoundary()
        for name, argv in (('UNKNOWN', EXPECTED_NATIVE[0][1]),
                           (EXPECTED_NATIVE[0][0], ['/usr/bin/systemctl', 'restart', cut.GUARD]),
                           (EXPECTED_NATIVE[0][0], ['/usr/bin/systemctl', 'stop', cut.COLD])):
            with self.subTest(name=name, argv=argv), self.assertRaises(cut.Hold):
                cut.send_once(backend, name, argv)
        self.assertEqual(backend.records, {})
        self.assertEqual(backend.native_calls, [])

    def test_native_timeout_retains_possible_and_uncertain_original_return(self):
        for index, (name, _) in enumerate(EXPECTED_NATIVE):
            backend = NativeBoundary(native_failure=(index, 'timeout'))
            with self.subTest(effect=name), self.assertRaises(cut.Hold):
                cut.swap_once(backend)
            self.assert_prefix(backend, index + 1)
            original = backend.records[name + '-NATIVE-RETURN.json']
            self.assertTrue(original['acknowledgement_uncertain'])
            self.assertFalse(original['retry'])
            self.assertFalse(backend.records['HOLD.json']['automatic_replay'])

    def test_native_nonzero_is_failure_without_forward_or_compensating_actions(self):
        for index, (name, _) in enumerate(EXPECTED_NATIVE):
            backend = NativeBoundary(native_failure=(index, 'nonzero'))
            with self.subTest(effect=name), self.assertRaises(cut.Hold):
                cut.swap_once(backend)
            self.assert_prefix(backend, index + 1)
            self.assertEqual(backend.records[name + '-NATIVE-RETURN.json']['exit_code'], 17)
            self.assertNotIn('acknowledgement_uncertain', backend.records[name + '-NATIVE-RETURN.json'])

    def test_possible_send_persistence_failure_prevents_that_native_call(self):
        for index, (name, _) in enumerate(EXPECTED_NATIVE):
            backend = NativeBoundary(fail_record=name + '-POSSIBLE-SEND.json')
            with self.subTest(effect=name), self.assertRaises(OSError):
                cut.swap_once(backend)
            self.assert_prefix(backend, index)
            self.assertNotIn(name + '-POSSIBLE-SEND.json', backend.records)

    def test_return_persistence_failure_keeps_possible_without_replay(self):
        for index, (name, _) in enumerate(EXPECTED_NATIVE):
            backend = NativeBoundary(fail_record=name + '-NATIVE-RETURN.json')
            with self.subTest(effect=name), self.assertRaises(OSError):
                cut.swap_once(backend)
            self.assert_prefix(backend, index + 1)
            self.assertIn(name + '-POSSIBLE-SEND.json', backend.records)
            self.assertNotIn(name + '-NATIVE-RETURN.json', backend.records)

    def test_guard_cas_readiness_and_qualification_failures_hold_at_exact_prefix(self):
        counts = (0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 4, 6, 6)
        for method, count in zip(METHODS, counts):
            backend = NativeBoundary(fail_step=method)
            with self.subTest(guard=method), self.assertRaises(cut.Hold):
                cut.swap_once(backend)
            self.assert_prefix(backend, count)
            self.assertTrue(backend.records['HOLD.json']['actual_process_unit_and_receipt_reconciliation_required'])
            guards = [name for kind, name in backend.events if kind == 'guard']
            self.assertEqual(guards[-1], method)

    def test_uncertain_attempt_cannot_reenter_or_replace_original_claim(self):
        backend = NativeBoundary(native_failure=(0, 'timeout'))
        with self.assertRaises(cut.Hold):
            cut.swap_once(backend)
        original = copy.deepcopy(backend.records)
        with self.assertRaises(FileExistsError):
            cut.swap_once(backend)
        self.assert_prefix(backend, 1)
        self.assertEqual(backend.records, original)

    def test_hold_record_failure_never_triggers_a_cleanup_or_retry(self):
        backend = NativeBoundary(native_failure=(0, 'timeout'), fail_record='HOLD.json')
        with self.assertRaises(OSError):
            cut.swap_once(backend)
        self.assert_prefix(backend, 1)
        self.assertIn(EXPECTED_NATIVE[0][0] + '-POSSIBLE-SEND.json', backend.records)
        self.assertTrue(backend.records[EXPECTED_NATIVE[0][0] + '-NATIVE-RETURN.json']['acknowledgement_uncertain'])

    def test_real_once_writer_is_exclusive_durable_and_never_overwrites(self):
        # Execute the real generic writer in a CI temp directory. Only the
        # root-owned readback custody check is replaced; production paths and
        # units are never touched. Actual O_EXCL/fsync/mode semantics remain.
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'POSSIBLE-SEND.json'
            raw = b'{"declared_CI_only":true}\n'
            native_fsync = cut.C.os.fsync
            with patch.object(cut.C, 'read', side_effect=lambda p, *_: Path(p).read_bytes()), \
                    patch.object(cut.C.os, 'fsync', wraps=native_fsync) as sync:
                cut.C.once(path, raw)
                self.assertGreaterEqual(sync.call_count, 2)
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                with self.assertRaises(FileExistsError):
                    cut.C.once(path, b'replacement')
                self.assertEqual(path.read_bytes(), raw)
                other = Path(folder) / 'other'
                other.write_bytes(b'original')
                link = Path(folder) / 'link'
                link.symlink_to(other)
                with self.assertRaises(FileExistsError):
                    cut.C.once(link, b'replacement')
                self.assertEqual(other.read_bytes(), b'original')

    def test_real_backend_global_claim_survives_another_evidence_directory(self):
        # Actual Backend claim/receipt methods and actual exclusive writer;
        # only the root-owned readback boundary is simulated in a CI temp dir.
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            first, second = root / 'first', root / 'second'
            first.mkdir(mode=0o700)
            second.mkdir(mode=0o700)
            manifest = {'expected_controller_identity': {'declared': 'old-controller'},
                        'expected_guardian_identity': {'declared': 'old-guardian'}}
            with patch.object(cut.C, 'STATE', root), \
                    patch.object(cut.C, 'read', side_effect=lambda path, *_: Path(path).read_bytes()), \
                    patch.object(cut, 'native', side_effect=AssertionError('no native action in claim test')) as native:
                one = cut.Backend(root, manifest, '1' * 64, first, {}, [], {})
                two = cut.Backend(root, manifest, '1' * 64, second, {}, [], {})
                one.claim_once()
                claim = root / ('SWAP-' + '1' * 64 + '-POSSIBLE.json')
                original = claim.read_bytes()
                with self.assertRaises(FileExistsError):
                    two.claim_once()
                self.assertEqual(claim.read_bytes(), original)
                self.assertEqual(cut.C.loads(original)['run'], str(first))
                one.record_once('DECLARED-POSSIBLE-SEND.json', {'fixture_only': True})
                with self.assertRaises(FileExistsError):
                    one.record_once('DECLARED-POSSIBLE-SEND.json', {'replacement': True})
                with self.assertRaises(cut.Hold):
                    one.record_once('../outside.json', {'fixture_only': True})
                native.assert_not_called()

    def test_actual_cli_entry_uses_custody_same_swap_once_and_backend(self):
        backend = NativeBoundary()
        backend.require_custody, backend.custody_active = True, False
        backend.close = lambda: backend.events.append(('close', 'readers-only'))
        manifest = tools.declared_manifest()
        folder = tools.TOOLS.parent
        staged = {'source_roster': {name: manifest['files']['source/' + name] for name in cut.C.MODULES},
                  'units': {cut.CTRL: manifest['controller_unit_sha256'],
                            cut.COLD: manifest['files']['units/' + cut.COLD],
                            cut.GUARD: manifest['files']['units/' + cut.GUARD]},
                  'standing_sha256': '3' * 64}
        qualification_path = Path('/declared-CI-qualification/QUALIFIED.json')
        original_check = b'{"declared_CI_check_once":true}\n'
        qualification = {'schema': 'g7_no_apply_qualification_v1', 'manifest_sha256': '1' * 64,
                         'controller_config_sha256': cut.C.G7_CONFIG_SHA, 'core_overlap': {'fixture_only': True},
                         'standing_sha256': staged['standing_sha256'], 'native_apply': False,
                         'actual_new_controller120_or_live_acceptance': False, 'observed_monotonic': 1,
                         'boot_id': manifest['expected_controller_identity']['boot_id'],
                         'original_check_once_ref': {'path': str(qualification_path.parent / 'CHECK-ONCE.json'),
                                                     'sha256': cut.C.sha(original_check)}}
        qualification_raw = cut.C.wire(qualification)

        def read(path, *_):
            path = Path(path)
            if path == qualification_path:
                return qualification_raw
            if path == Path(qualification['original_check_once_ref']['path']):
                return original_check
            if path == Path(cut.__file__):
                return path.read_bytes()
            raise AssertionError('unexpected native file read in CLI routing test')

        @contextlib.contextmanager
        def custody():
            self.assertFalse(backend.custody_active)
            backend.custody_active = True
            try:
                yield [('declared-CI-custody', 1, 2)]
            finally:
                backend.custody_active = False

        args = ['g7cut.py', 'swap-once', '--package', str(folder),
                '--expected-manifest-sha256', '1' * 64,
                '--evidence-dir', str(cut.C.STATE / 'swap-once-declared-CI'),
                '--stage-receipt', '/declared-stage.json',
                '--expected-stage-receipt-sha256', '2' * 64,
                '--qualification-receipt', str(qualification_path),
                '--expected-qualification-receipt-sha256', cut.C.sha(qualification_raw), '--execute-once']
        with patch.object(sys, 'argv', args), \
                patch.object(cut.os, 'geteuid', return_value=0), \
                patch.object(cut.C, 'package', return_value=(folder, manifest)), \
                patch.object(cut.C, 'private_dir'), \
                patch.object(cut.C, 'read', side_effect=read), \
                patch.object(cut.C, 'once', side_effect=AssertionError('unexpected direct CLI write')), \
                patch.object(cut.signal, 'signal'), \
                patch.object(cut, 'custody', side_effect=custody), \
                patch.object(cut, 'load_staged', return_value=staged), \
                patch.object(cut, 'Backend', return_value=backend) as factory, \
                patch.object(cut, 'swap_once', wraps=cut.swap_once) as swap, \
                patch.object(cut, 'native', side_effect=AssertionError('no real native I/O in CLI test')) as native, \
                contextlib.redirect_stdout(io.StringIO()) as out:
            cut.main()
            factory.assert_called_once()
            swap.assert_called_once_with(backend)
            native.assert_not_called()
        self.assertEqual(backend.native_calls, [argv for _, argv in EXPECTED_NATIVE])
        self.assertFalse(backend.custody_active)
        self.assertEqual(backend.events[-1], ('close', 'readers-only'))
        self.assertTrue(cut.C.loads(out.getvalue())['fixture_simulated'])

    def test_actual_cli_parser_refuses_legacy_replay_reset_and_rollback(self):
        with patch.object(cut, 'native', side_effect=AssertionError('no native parser action')) as native, \
                patch.object(cut.C, 'package', side_effect=AssertionError('no package read before closed parser')) as package, \
                contextlib.redirect_stderr(io.StringIO()):
            for mode in ('rollback', 'restore', 'reset', 'resume', 'restart', 'retry', 'swap'):
                with self.subTest(mode=mode), patch.object(sys, 'argv', ['g7cut.py', mode]):
                    with self.assertRaises(SystemExit) as result:
                        cut.main()
                    self.assertEqual(result.exception.code, 2)
            native.assert_not_called()
            package.assert_not_called()

    def test_actual_backend_close_only_joins_read_observers(self):
        manifest = {'expected_controller_identity': {}, 'expected_guardian_identity': {}}
        backend = cut.Backend(Path('/declared-CI'), manifest, '1' * 64,
                              Path('/declared-CI-run'), {}, [], {})
        backend.probe = types.SimpleNamespace(close=Mock())
        backend.journal = types.SimpleNamespace(close=Mock())
        with patch.object(cut, 'native', side_effect=AssertionError('no cleanup native effect')) as native, \
                patch.object(cut.C, 'once', side_effect=AssertionError('no cleanup state rewrite')) as once:
            backend.close()
            native.assert_not_called()
            once.assert_not_called()
        backend.probe.close.assert_called_once_with()
        backend.journal.close.assert_called_once_with()

    def test_actual_backend_final_closure_rechecks_both_physical_processes(self):
        manifest = {'expected_controller_identity': {}, 'expected_guardian_identity': {},
                    'files': {'source/network_guardian.py': '1' * 64}}
        for changed in ('controller', 'guardian'):
            backend = cut.Backend(Path('/declared-CI'), manifest, '1' * 64,
                                  Path('/declared-CI-run'), {}, [], {})
            backend.files = Mock()
            backend.new_controller = {'declared': 'new-controller'}
            backend.new_guardian = {'declared': 'new-guardian'}
            identities = ([{'different': 'controller'}] if changed == 'controller'
                          else [backend.new_controller, {'different': 'guardian'}])
            with self.subTest(changed=changed), \
                    patch.object(cut, 'physical_identity', side_effect=identities) as identity, \
                    patch.object(cut, 'native', side_effect=AssertionError('no closure native effect')) as native:
                with self.assertRaisesRegex(cut.Hold, 'SAME_NEW_PHYSICAL_LIFETIMES'):
                    backend.final_closure()
                backend.files.assert_called_once_with(successor=True)
                self.assertEqual(identity.call_count, 1 if changed == 'controller' else 2)
                native.assert_not_called()

    def test_real_absence_guard_accepts_retained_terminal_pid_and_refuses_live_identity(self):
        for unit in (cut.CTRL, cut.GUARD):
            old = {'pid': 200}
            proc = Path('/proc/200')
            group = Path('/sys/fs/cgroup/system.slice') / unit / 'cgroup.procs'
            variants = (
                ('retained-terminal', '200', '0', False, b'', True),
                ('zero-terminal', '0', '0', False, b'', True),
                ('foreign-terminal', '201', '0', False, b'', False),
                ('live-main', '200', '200', False, b'', False),
                ('still-active', '200', '0', False, b'', False),
                ('old-pid-exists', '200', '0', True, b'', False),
                ('nonempty-cgroup', '200', '0', False, b'201\n', False),
            )
            for label, exec_pid, main_pid, exists_old, members, accepted in variants:
                props = {'ActiveState': 'inactive', 'SubState': 'dead', 'Result': 'success',
                         'MainPID': main_pid, 'ExecMainPID': exec_pid}
                if label == 'still-active':
                    props['ActiveState'] = 'active'

                def exists(path):
                    if path == proc:
                        return exists_old
                    if path == group:
                        return True
                    raise AssertionError('unexpected native identity read')

                with self.subTest(unit=unit, variant=label), \
                        patch.object(cut, 'properties', return_value=props), \
                        patch.object(Path, 'exists', exists), \
                        patch.object(cut, 'proc_bytes', return_value=members) as read_group, \
                        patch.object(cut, 'native', side_effect=AssertionError('no actual native I/O')) as native:
                    if accepted:
                        cut.assert_absent(unit, old)
                        read_group.assert_called_once_with(group, 65536)
                    else:
                        with self.assertRaises(cut.Hold):
                            cut.assert_absent(unit, old)
                    native.assert_not_called()

    def test_real_controller_inputs_and_preconditions_refuse_config_or_runtime_drift(self):
        _, _, config = tools.controller_inputs()
        guardian = tools.source.g7
        pins = guardian.RUNTIME_HASHES
        runtime = {cut.C.RUNTIME / name: ('declared-CI-runtime-' + name).encode() for name in pins}
        declared_hashes = {runtime[cut.C.RUNTIME / name]: pin for name, pin in pins.items()}
        manifest = {'expected_controller_identity': {}, 'expected_guardian_identity': {},
                    'files': {'source/network_guardian.py': tools.source.digest(Path(guardian.__file__).read_bytes())}}
        original_sha = cut.C.sha
        for drift in (None, 'config', 'runtime'):
            backend = cut.Backend(Path('/declared-CI'), manifest, '1' * 64,
                                  Path('/declared-CI-run'), {}, [], {})
            bodies = {cut.C.NEW_CONFIG: config, **runtime}
            if drift == 'config':
                bodies[cut.C.NEW_CONFIG] += b' '
            elif drift == 'runtime':
                bodies[next(iter(runtime))] += b'drift'

            def read(path, *args):
                path = Path(path)
                if path == cut.C.NEW_CONFIG:
                    self.assertEqual(args, (32768, 0o600))
                if path not in bodies:
                    raise AssertionError('unexpected native file read before controller drift refusal')
                return bodies[path]

            def iterdir(path):
                self.assertEqual(path, cut.C.RUNTIME)
                return iter(runtime)

            with self.subTest(drift=drift), \
                    patch.object(cut.C, 'read', side_effect=read), \
                    patch.object(cut.C, 'sha', side_effect=lambda raw: declared_hashes.get(raw, original_sha(raw))), \
                    patch.object(cut.C, 'load_guardian', return_value=guardian), \
                    patch.object(Path, 'iterdir', iterdir), \
                    patch.object(cut.C, 'once', side_effect=AssertionError('no preflight mutation')) as once, \
                    patch.object(cut, 'native', side_effect=AssertionError('no preflight native effect')) as native:
                if drift is None:
                    backend.controller_inputs()
                else:
                    reason = ('FRESH_EXACT_G7_CONTROLLER_CONFIG' if drift == 'config'
                              else 'FRESH_EXACT_IMMUTABLE_RUNTIME14')
                    with self.assertRaisesRegex(cut.Hold, reason):
                        backend.preconditions()
                native.assert_not_called()
                once.assert_not_called()

    def test_real_type_simple_wait_handles_only_one_bounded_fork_exec_lifetime(self):
        boot = '2b7e9be2-e45a-4cd5-86f2-6f0a3372576d'
        old = {'boot_id': boot, 'pid': 200, 'start_ticks': 100,
               'InvocationID': '1' * 32, 'ExecMainStartTimestampMonotonic': '1000'}
        for unit in (cut.CTRL, cut.GUARD):
            argv = (cut.controller_argv(cut.C.NEW_CONFIG) if unit == cut.CTRL
                    else cut.guardian_argv(cut.C.NEW_SOURCE, '3' * 64))
            command = b'\0'.join(item.encode() for item in argv) + b'\0'
            base = {'LoadState': 'loaded', 'FragmentPath': str(cut.C.UNIT_DIR / unit),
                    'DropInPaths': str(cut.C.DROPIN) if unit == cut.CTRL else '',
                    'Restart': 'no' if unit == cut.CTRL else 'on-failure', 'NRestarts': '0',
                    'Result': 'success', 'InvocationID': '2' * 32,
                    'ExecMainStartTimestampMonotonic': '2000'}
            pending = {**base, 'ActiveState': 'activating', 'SubState': 'start',
                       'MainPID': '0', 'ExecMainPID': str(old['pid'])}
            running = {**base, 'ActiveState': 'active', 'SubState': 'running',
                       'MainPID': '300', 'ExecMainPID': '300'}
            for variant in ('ready', 'failed', 'pid-changed', 'invocation-changed',
                            'startticks-changed', 'restarted', 'never-exec', 'short-original-deadline'):
                clock = types.SimpleNamespace(now=10.0)
                rows = [pending, running, running]
                if variant == 'failed':
                    rows = [{**pending, 'ActiveState': 'failed', 'SubState': 'failed', 'Result': 'exit-code'}]
                elif variant == 'pid-changed':
                    rows = [running, {**running, 'MainPID': '301', 'ExecMainPID': '301'}]
                elif variant == 'invocation-changed':
                    rows = [running, {**running, 'InvocationID': '3' * 32}]
                elif variant == 'startticks-changed':
                    rows = [running, running]
                elif variant == 'restarted':
                    rows = [{**pending, 'NRestarts': '1'}]
                elif variant in ('never-exec', 'short-original-deadline'):
                    rows = [pending]
                state = {'calls': 0, 'cmd': 0, 'stat': 0}

                def props(selected, seconds=8):
                    self.assertEqual(selected, unit)
                    self.assertGreater(seconds, 0)
                    self.assertLessEqual(seconds, .5)
                    value = rows[min(state['calls'], len(rows) - 1)]
                    state['calls'] += 1
                    return value

                def proc(path, cap=4096):
                    if str(path).endswith('/stat'):
                        state['stat'] += 1
                        ticks = 1235 if variant == 'startticks-changed' and state['stat'] > 1 else 1234
                        return str(path).split('/')[2].encode() + b' (declared-CI) ' + b' '.join([b'S'] + [b'0'] * 18 + [str(ticks).encode()])
                    if str(path).endswith('/cmdline'):
                        state['cmd'] += 1
                        return command if variant == 'ready' and state['cmd'] >= 2 else b'pending-exec\0'
                    raise AssertionError('unexpected proc read')

                def boot_read(path, *args, **kwargs):
                    self.assertEqual(path, Path('/proc/sys/kernel/random/boot_id'))
                    return boot + '\n'

                ceiling = 10.01 if variant == 'short-original-deadline' else 20.0
                with self.subTest(unit=unit, variant=variant), \
                        patch.object(cut, 'properties', side_effect=props), \
                        patch.object(cut, 'proc_bytes', side_effect=proc), \
                        patch.object(Path, 'read_text', boot_read), \
                        patch.object(cut.time, 'monotonic', side_effect=lambda: clock.now), \
                        patch.object(cut.time, 'sleep', side_effect=lambda seconds: setattr(clock, 'now', clock.now + seconds)), \
                        patch.object(cut, 'native', side_effect=AssertionError('no second START or real native I/O')) as native:
                    if variant == 'ready':
                        actual = cut.wait_exec_identity(unit, argv, ceiling, old)
                        self.assertEqual(actual, {'boot_id': boot, 'pid': 300, 'start_ticks': 1234,
                                                 'InvocationID': '2' * 32, 'ExecMainStartTimestampMonotonic': '2000'})
                    else:
                        with self.assertRaises(cut.Hold):
                            cut.wait_exec_identity(unit, argv, ceiling, old)
                    self.assertLessEqual(clock.now, min(ceiling, 12.0) + .001)
                    native.assert_not_called()

    def test_real_shared_parent_accepts_0755_without_chmod_and_refuses_writes_or_links(self):
        path = Path('/declared-root-shared-parent')
        for mode, uid, linked, accepted in ((0o755, 0, False, True), (0o700, 0, False, True),
                                           (0o775, 0, False, False), (0o777, 0, False, False),
                                           (0o755, 1000, False, False), (0o755, 0, True, False)):
            facts = types.SimpleNamespace(st_mode=(stat.S_IFLNK if linked else stat.S_IFDIR) | mode,
                                          st_uid=uid)
            with self.subTest(mode=oct(mode), uid=uid, linked=linked), \
                    patch.object(Path, 'lstat', return_value=facts), \
                    patch.object(Path, 'is_symlink', return_value=linked), \
                    patch.object(cut.C.os, 'chmod', side_effect=AssertionError('never chmod shared parent')) as chmod:
                if accepted:
                    cut.C.shared_parent(path)
                else:
                    with self.assertRaises(cut.Hold):
                        cut.C.shared_parent(path)
                chmod.assert_not_called()


if __name__ == '__main__':
    unittest.main()
