"""CI-only exact-byte qualification replay; native boundaries are simulated.

The PUBLIC fixture is historical. Simulated monotonic time lets the original
math be recomputed without calling its past observations current health.
No service, host, provider, database or kernel operation is executed.
"""
import ast
import copy
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / 'g6pair-boot-v2'
SOURCE = PACKAGE / 'source'
FIXTURE = Path(__file__).parent / 'fixtures/g6-real-newboot'


def load(name):
    spec = importlib.util.spec_from_file_location(name, SOURCE / (name + '.py'))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


guardian = load('network_guardian')
helper = load('qualification_initializer')
reader = load('current15_bounded_reader')
coverage = load('coverage')
journal = load('journal_contract')
tail = load('current15_bounded_tail_contract')


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def require(ok, guard):
    if not ok:
        raise RuntimeError(guard)


class Replay:
    def __init__(self):
        self.manifest = json.loads((FIXTURE / 'MANIFEST.json').read_bytes())
        self.files = {}
        for name, facts in self.manifest['files'].items():
            compressed = (FIXTURE / (name + '.gz')).read_bytes()
            require(digest(compressed) == facts['gzip_sha256'], 'EXACT_COMPRESSED_FIXTURE')
            raw = gzip.decompress(compressed)
            require(len(raw) == facts['bytes'] and digest(raw) == facts['sha256'],
                    'EXACT_DECOMPRESSED_PUBLIC_ORIGINAL_BYTES')
            self.files[guardian.LEDGER / name] = raw
        self.qualified = next(p for p in self.files if p.name.endswith('-QUALIFIED.PUBLIC.json'))
        self.value = json.loads(self.files[self.qualified])
        self.identity = copy.deepcopy(self.value['identity'])
        self.actual_identity = copy.deepcopy(self.identity)
        self.reads = []
        self.owner = types.SimpleNamespace(
            boot=self.identity['boot_id'], coverage=coverage, journal_contract=journal,
            authorities=frozenset({(guardian.G6_PREDECESSOR_SOURCE_SHA,
                                    guardian.G6_PREDECESSOR_CONFIG_SHA)}),
            identity=lambda: copy.deepcopy(self.actual_identity),
            key=lambda value: digest(guardian.wire(value)))
        self.g = types.SimpleNamespace(
            require=require, LEDGER=guardian.LEDGER, read=self.read,
            sha=digest, loads=guardian.loads)

    def read(self, path, cap, mode):
        self.reads.append((path, cap, mode))
        raw = self.files[path]
        require(len(raw) <= cap and mode == 0o600, 'BOUNDED_ROOT_ONLY_PROOF_READ')
        return raw

    def save(self):
        self.files[self.qualified] = guardian.wire(self.value)

    def replace_journal(self, field, mutate):
        path = Path(self.value[field]['path'])
        rows = [json.loads(row) for row in self.files[path].splitlines()]
        mutate(rows)
        self.files[path] = b''.join(guardian.wire(row) for row in rows)
        self.value[field]['sha256'] = digest(self.files[path])
        self.save()

    def extract(self):
        with patch.object(Path, 'exists', lambda path: path in self.files), \
                patch.object(helper.time, 'monotonic', return_value=self.value['finished'] + 1):
            return helper.extract(self.owner, self.g, self.identity)


class InitializerTests(unittest.TestCase):
    def kernel_read(self, measurement):
        """Run the unchanged Owner.kernel; simulate only native I/O/AST boundary."""
        replay = Replay()
        handles = replay.value['measurement']['initial_original_structure_handles']
        owned = []
        for row in sorted(handles, key=lambda row: (row['key'][0], row['key'][1],
                         int(row['key'][2]) if len(row['key']) == 3 else -1)):
            kind, name, *ordinal = row['key']
            owned.append({kind: {'chain' if kind == 'rule' else 'name': name,
                                 'handle': row['handle']}})
        guard = b'def ruleset_mark_preflight(rows):\n require(type(rows) is list,"SIMULATED_NATIVE_LIST_BOUNDARY")\n'
        compiler = types.SimpleNamespace(
            _objects=lambda raw: (owned, owned), _structure=lambda rows, keep_handles: b'native-structure',
            AST47=replay.value['measurement']['compiled_native_ast_sha256'])
        native_owner = types.SimpleNamespace(
            C=compiler, call=lambda *args: b'simulated-native-public-read',
            coverage=types.SimpleNamespace(kernel_text=lambda raw: replay.value['kernel']))
        with patch.object(guardian, 'read', return_value=guard), \
                patch.dict(guardian.RUNTIME_HASHES, {'nft_owner.py': digest(guard)}), \
                patch.object(guardian, 'sha', side_effect=lambda raw:
                             compiler.AST47 if raw == b'native-structure' else digest(raw)), \
                patch.object(guardian.time, 'monotonic', return_value=replay.value['kernel_observed']):
            return guardian.Owner.kernel(native_owner, measurement)

    def test_actual_newboot_original_recomputes_exact_initializer(self):
        replay = Replay()
        result = replay.extract()
        self.assertEqual(result['measurement'],
                         {key: replay.value['measurement'][key] for key in helper.INITIALIZER_FIELDS})
        self.assertEqual(result['identity'], replay.identity)
        self.assertEqual(result['authority']['source_sha256'], guardian.G6_PREDECESSOR_SOURCE_SHA)
        self.assertEqual(result['original_qualification_ref']['sha256'],
                         '21e4697326aa0e74b1e169a897870b10e4668328ca04d497900a2f297bc99a31')
        self.assertTrue(result['historical_original120_proof_verified'])
        self.assertFalse(result['current_health_or_new_epoch_authority'])
        self.assertNotIn('current_continuous_window', result['measurement'])
        self.assertEqual(len(result['measurement']['initial_original_structure_handles']), 47)
        self.assertEqual(result['measurement']['initial_structure_proof_kind'], 'original_owned_read_adoption')

    def test_cache_rehashes_every_consumed_ref_and_never_aliases_health(self):
        replay = Replay()
        with patch.object(coverage, 'journal', wraps=coverage.journal) as recompute:
            first = replay.extract()
            first['measurement']['initial_original_structure_handles'][0]['handle'] = -1
            replay.reads.clear()
            second = replay.extract()
            self.assertEqual(recompute.call_count, 1)
            self.assertEqual(len(replay.reads), 3)
            self.assertGreater(second['measurement']['initial_original_structure_handles'][0]['handle'], 0)
            replay.value['measurement'] = {'forged_saved_flag': True}
            replay.save()
            third = replay.extract()
            self.assertEqual(recompute.call_count, 2)
            self.assertEqual(second['measurement'], third['measurement'])
        self.assertFalse(third['current_health_or_new_epoch_authority'])

    def test_missing_original_has_no_initializer_authority(self):
        replay = Replay()
        del replay.files[replay.qualified]
        self.assertIsNone(replay.extract())

    def test_wrong_current_identity_and_race_are_refused(self):
        for field, value in [('boot_id', guardian.INITIAL_BOOT), ('pid', 24997),
                             ('start_ticks', 62246), ('InvocationID', '0' * 32),
                             ('cmdline_sha256', '0' * 64),
                             ('ExecMainStartTimestampMonotonic', '622455096')]:
            with self.subTest(field=field):
                replay = Replay()
                replay.actual_identity[field] = value
                with self.assertRaisesRegex(RuntimeError, 'SAME_PHYSICAL_LIFETIME_BEFORE'):
                    replay.extract()
        replay = Replay()
        replay.owner.identity = unittest.mock.Mock(side_effect=[replay.identity, {}])
        with self.assertRaisesRegex(RuntimeError, 'SAME_PHYSICAL_LIFETIME_AFTER'):
            replay.extract()

    def test_wrong_original_identity_or_authority_pair_is_refused(self):
        cases = [('identity', {}), ('source_sha256', '0' * 64),
                 ('standing_config_sha256', '0' * 64)]
        for field, value in cases:
            with self.subTest(field=field):
                replay = Replay()
                replay.value[field] = value
                replay.save()
                with self.assertRaisesRegex(RuntimeError, 'SAME_AUTHENTICATED_ORIGINAL'):
                    replay.extract()
        replay = Replay()
        replay.owner.authorities = frozenset({(guardian.G6_PREDECESSOR_SOURCE_SHA, '0' * 64),
                                              ('0' * 64, guardian.G6_PREDECESSOR_CONFIG_SHA)})
        with self.assertRaises(RuntimeError):
            replay.extract()

    def test_fixed_references_and_all_consumed_bytes_are_mandatory(self):
        for field in ('original_prefix_ref', 'original_suffix_ref'):
            for corruption in ('path', 'sha256', 'extra', 'body'):
                with self.subTest(field=field, corruption=corruption):
                    replay = Replay()
                    ref = replay.value[field]
                    if corruption == 'body':
                        replay.files[Path(ref['path'])] += b' '
                    elif corruption == 'extra':
                        ref['other'] = True
                    elif corruption == 'path':
                        ref['path'] += '.foreign'
                    else:
                        ref['sha256'] = '0' * 64
                    replay.save()
                    with self.assertRaises(RuntimeError):
                        replay.extract()

    def test_every_prefix_row_must_belong_to_same_boot_pid_and_invocation(self):
        for key, value in [('_BOOT_ID', '0' * 32), ('_PID', '99999'),
                           ('_SYSTEMD_INVOCATION_ID', '0' * 32)]:
            with self.subTest(key=key):
                replay = Replay()
                replay.replace_journal('original_prefix_ref', lambda rows: rows[0].update({key: value}))
                with self.assertRaisesRegex(RuntimeError, 'SAME_ORIGINAL_JOURNAL'):
                    replay.extract()

    def test_recomputed_original120_and_transport_cannot_be_saved_booleans(self):
        replay = Replay()
        replay.value['start'] -= 200
        replay.value['end'] -= 200
        replay.value['network_original120_and_current15'] = True
        replay.save()
        with self.assertRaises(RuntimeError):
            replay.extract()
        for field, value in [('periodic_transport_samples', []), ('kernel_observed', -1),
                             ('original_work_deadline', 1)]:
            with self.subTest(field=field):
                replay = Replay()
                replay.value[field] = value
                replay.save()
                with self.assertRaises(RuntimeError):
                    replay.extract()

    def test_read_adoption_cannot_masquerade_as_echo_or_mutation(self):
        for field, value in [('original_native_echo_handles', []), ('applied', True),
                             ('native_mutations', 1), ('compiled_native_ast_sha256', '0' * 64)]:
            with self.subTest(field=field):
                replay = Replay()
                def corrupt(rows):
                    for row in rows:
                        body = json.loads(row['MESSAGE'])
                        if body.get('schema') == 'capacity_owned_nft_original_read_adoption_v1':
                            body[field] = value
                            row['MESSAGE'] = json.dumps(body)
                            return
                    raise AssertionError('Actual fixture must retain the original adoption')
                replay.replace_journal('original_prefix_ref', corrupt)
                guard = ('SOURCE_COMPILED_47_READ_ADOPTION_AST'
                         if field == 'compiled_native_ast_sha256'
                         else 'HONEST_READ_ADOPTION_ZERO_MUTATIONS_ZERO_COVERAGE')
                with self.assertRaisesRegex(coverage.Held, '^' + guard + '$'):
                    replay.extract()

    def test_unchanged_native_kernel_rejects_foreign_handles_AST_and_echo_alias(self):
        measurement = Replay().extract()['measurement']
        self.assertTrue(self.kernel_read(measurement)[0]['all_four_backends_and_reverse_sources_positive'])
        for corruption in ('handle', 'AST', 'echo'):
            with self.subTest(corruption=corruption):
                changed = copy.deepcopy(measurement)
                if corruption == 'handle':
                    changed['initial_original_structure_handles'][0]['handle'] += 1000
                elif corruption == 'AST':
                    changed['compiled_native_ast_sha256'] = '0' * 64
                else:
                    changed['initial_structure_proof_kind'] = 'original_native_apply_echo'
                with self.assertRaises(RuntimeError):
                    self.kernel_read(changed)

    def test_owning_reader_joins_current_initializer_native_kernel_and_fresh_tail(self):
        replay = Replay()
        owner = replay.owner
        owner.original_qualification_measurement = lambda identity: replay.extract()
        owner.proof_original = unittest.mock.Mock(side_effect=AssertionError('old boot anchor'))
        owner.current_read_capture = None
        owner.static = lambda: 'same-seal'
        owner.wg_snapshot = lambda seal: 'same-public-WG'
        owner.transport = lambda: replay.value['periodic_transport_samples'][-1]['transport']
        owner.journal_argv = lambda identity: ['simulated-readonly-journal']
        owner.deadline = replay.value['original_work_deadline']
        owner.kernel = self.kernel_read
        calls = []
        def read(role, argv, **bounds):
            calls.append((role, argv, bounds))
            field = 'original_prefix_ref' if role.endswith('finite512-tail') else 'original_suffix_ref'
            return replay.files[Path(replay.value[field]['path'])]
        owner.call = read
        g = types.SimpleNamespace(require=require, loads=guardian.loads, tail=tail,
                                  INITIAL_BOOT=guardian.INITIAL_BOOT)
        with patch.object(reader.time, 'monotonic', side_effect=[replay.value['kernel_observed'],
                                                               replay.value['finished']]):
            result, _, _, _ = reader.observe(owner, g)
        self.assertEqual(result['identity'], replay.identity)
        self.assertEqual(result['initializer47_provenance']['authority']['source_sha256'],
                         guardian.G6_PREDECESSOR_SOURCE_SHA)
        self.assertTrue(result['measurement']['qualified_15_seconds'])
        self.assertEqual(result['service_kernel_Controller_Hub_Core_or_Guest_mutations'], 0)
        self.assertFalse(result['full_lifetime_unobserved_continuity_or_new120_qualified'])
        self.assertEqual(len(calls), 2)
        self.assertIn('--lines=512', calls[0][1])
        self.assertTrue(any(arg.startswith('--after-cursor=') for arg in calls[1][1]))
        self.assertTrue(all(row[2] == {'cap': 8 << 20, 'seconds': 8} for row in calls))
        self.assertIsNone(owner.current_read_capture)
        owner.proof_original.assert_not_called()
        owner.deadline += 2000
        with patch.object(reader.time, 'monotonic', side_effect=[replay.value['kernel_observed'],
                                                               replay.value['finished'] + 1000]):
            with self.assertRaisesRegex(RuntimeError, 'FINITE_ORIGINAL_CURRENT15'):
                reader.observe(owner, g)
        self.assertIsNone(owner.current_read_capture)

    def test_dedicated_g6_predecessor_requires_same_closed_authority_and_controller(self):
        config = {
            'g6_predecessor_guardian_source_sha256': guardian.G6_PREDECESSOR_SOURCE_SHA,
            'g6_predecessor_standing_config_sha256': guardian.G6_PREDECESSOR_CONFIG_SHA,
            'new_controller_config_sha256': guardian.G6_CONTROLLER_CONFIG_SHA,
            'r13_predecessor_standing_config_sha256': '1' * 64,
        }
        shared = ('hub_source_sha256', 'hub_boot_config_sha256', 'hub_unit_sha256',
                  'R43_proofs', 'Core262_context_ref', 'proof_index_ref', 'context_sources')
        config.update({key: 'same-original-reference' for key in shared})
        prior = {**{key: config[key] for key in shared},
                 'schema': guardian.G6_PREDECESSOR_SCHEMA,
                 'guardian_source_sha256': guardian.G6_PREDECESSOR_SOURCE_SHA,
                 'new_controller_config_sha256': guardian.G6_CONTROLLER_CONFIG_SHA,
                 'predecessor_guardian_source_sha256': guardian.PREDECESSOR_SOURCE_SHA,
                 'predecessor_standing_config_sha256': guardian.PREDECESSOR_CONFIG_SHA,
                 'r13_predecessor_guardian_source_sha256': guardian.R13_PREDECESSOR_SOURCE_SHA,
                 'r13_predecessor_standing_config_sha256': '1' * 64,
                 'pair_predecessor_standing_configs': guardian.pair_predecessor_refs()}
        # Exact installed standing SHA is a root-owned read boundary; this
        # synthetic config cannot be installed or acquire real authority.
        with patch.object(guardian, 'read', side_effect=lambda path, cap, mode:
                          guardian.wire(prior) if path == guardian.G6_PREDECESSOR_CONFIG
                          and cap == 32768 and mode == 0o600 else b'wrong-boundary'), \
                patch.object(guardian, 'sha', return_value=guardian.G6_PREDECESSOR_CONFIG_SHA):
            self.assertEqual(guardian.g6_predecessor_standing(config),
                             (guardian.G6_PREDECESSOR_SOURCE_SHA, guardian.G6_PREDECESSOR_CONFIG_SHA))
            for key in ('g6_predecessor_guardian_source_sha256',
                        'g6_predecessor_standing_config_sha256', 'new_controller_config_sha256',
                        'hub_source_sha256', 'proof_index_ref'):
                changed = {**config, key: '0' * 64}
                with self.subTest(key=key), self.assertRaises(RuntimeError):
                    guardian.g6_predecessor_standing(changed)
        with patch.object(guardian, 'read', return_value=b'corrupt installed standing'):
            with self.assertRaisesRegex(RuntimeError, 'EXACT_INSTALLED_G6_STANDING_CONFIG'):
                guardian.g6_predecessor_standing(config)

    def test_initial_boot_selects_unchanged_historical_R43_branch(self):
        old = {'initial_original_structure_handles': ['original, never relabelled']}
        owner = types.SimpleNamespace(
            boot=guardian.INITIAL_BOOT, Core262_context={'network_R43_return_ref': {'path': 'R43'}},
            proof_original=lambda ref: guardian.wire({'new120_return': {'measurement': old}}),
            original_qualification_measurement=unittest.mock.Mock(side_effect=AssertionError('new branch')))
        measured, provenance = reader.initializer(owner, guardian, {})
        self.assertEqual(measured, old)
        self.assertEqual(provenance['kind'], 'same_initial_boot_R43_original')
        owner.original_qualification_measurement.assert_not_called()

    def test_newboot_selects_only_authenticated_current_lifetime(self):
        replay = Replay()
        proof = replay.extract()
        replay.owner.original_qualification_measurement = lambda identity: proof
        measured, provenance = reader.initializer(replay.owner, guardian, replay.identity)
        self.assertEqual(measured, proof['measurement'])
        self.assertEqual(provenance['original_qualification_ref'], proof['original_qualification_ref'])
        self.assertNotIn('measurement', provenance)
        replay.owner.original_qualification_measurement = lambda identity: None
        with self.assertRaises(RuntimeError):
            reader.initializer(replay.owner, guardian, replay.identity)

    def test_fresh_current15_keeps_original_tail_guards_and_expiry(self):
        replay = Replay()
        prefix = replay.files[Path(replay.value['original_prefix_ref']['path'])]
        suffix = replay.files[Path(replay.value['original_suffix_ref']['path'])]
        measured = tail.measure(prefix, suffix, replay.identity, replay.owner.boot,
                                replay.value['kernel_observed'], replay.value['finished'], coverage, journal)
        self.assertTrue(measured['qualified_15_seconds'])
        self.assertEqual(measured['requested_tail_maximum_rows'], 512)
        expired = tail.measure(prefix, suffix, replay.identity, replay.owner.boot,
                               replay.value['kernel_observed'], replay.value['finished'] + 1000, coverage, journal)
        self.assertFalse(expired['qualified_15_seconds'])
        self.assertIsNone(expired['current_continuous_window'])
        with self.assertRaises(RuntimeError):
            tail.measure(prefix * 4, suffix, replay.identity, replay.owner.boot,
                         replay.value['kernel_observed'], replay.value['finished'], coverage, journal)


class PackageTests(unittest.TestCase):
    def test_exact_package_and_all_embedded_helper_hashes(self):
        manifest = json.loads((PACKAGE / 'PACKAGE.json').read_bytes())
        expected = {str(path.relative_to(PACKAGE)): digest(path.read_bytes())
                    for folder in ('source', 'units') for path in (PACKAGE / folder).iterdir()
                    if path.is_file()}
        self.assertEqual(expected, manifest['files'])
        self.assertEqual(len(expected), 10)
        for constant, name in [('COVERAGE_SHA', 'coverage.py'), ('JOURNAL_SHA', 'journal_contract.py'),
                               ('CURRENT_TAIL_SHA', 'current15_bounded_tail_contract.py'),
                               ('PROOF_CACHE_SHA', 'proof_cache.py'), ('INITIAL_COLD_SHA', 'initial_boot_Cold_read_adoption.py'),
                               ('CURRENT_READER_SHA', 'current15_bounded_reader.py'),
                               ('QUALIFICATION_INITIALIZER_SHA', 'qualification_initializer.py')]:
            self.assertEqual(getattr(guardian, constant), expected['source/' + name])
        for path in (PACKAGE / 'units').iterdir():
            text = path.read_text()
            self.assertIn(str(guardian.SELF), text)
            self.assertIn('--source-sha256 ' + expected['source/network_guardian.py'], text)
        self.assertEqual(guardian.G6_PREDECESSOR_SOURCE_SHA, manifest['predecessor']['source_sha256'])
        self.assertEqual(guardian.G6_PREDECESSOR_CONFIG_SHA, manifest['predecessor']['standing_config_sha256'])
        self.assertEqual(guardian.G6_CONTROLLER_CONFIG_SHA, manifest['unchanged_controller_config_sha256'])
        source = (SOURCE / 'network_guardian.py').read_text()
        tree = ast.parse(source)
        owner = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == 'Owner')
        for name, sha in manifest['unchanged_owner_methods_sha256'].items():
            node = next(node for node in owner.body if isinstance(node, ast.FunctionDef) and node.name == name)
            self.assertEqual(digest(ast.get_source_segment(source, node).encode()), sha, name)
        for name in ('PAIR_CHAIN', 'PAIR_STANDING_CHAIN'):
            node = next(node for node in tree.body if isinstance(node, ast.Assign)
                        and any(isinstance(target, ast.Name) and target.id == name for target in node.targets))
            self.assertEqual(digest(ast.get_source_segment(source, node).encode()),
                             manifest['unchanged_assignments_sha256'][name])


if __name__ == '__main__':
    unittest.main()
