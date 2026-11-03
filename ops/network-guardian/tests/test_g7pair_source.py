"""CI-only G7 package/authority checks; every native I/O boundary is simulated.

The existing exact PUBLIC gzip fixture remains historical original120 evidence.
Neither replay nor synthetic standing data grants current health or native power.
"""
import ast
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import types
import unittest
from unittest.mock import patch

import test_current15_initializer as old_tests


ROOT = Path(__file__).resolve().parents[1]
OLD = ROOT / 'g6pair-boot-v2'
NEW = ROOT / 'g7pair'
CANONICAL_SOURCE = '6c2cc19f1f962d9d8eaec0cd5e6f813bf49004f8ff6fef9c9fe9f8f0310d8f1b'
CANONICAL_STANDING = 'be5b25495056bd25e1512827b5ccbe7236f84928b4d20515f5000383771dcc79'
BOOT_V2_SOURCE = 'f3152cc6d8c5d7edee2e5349db17fac4b8650a18423dfc207c04fcc116955e6d'
BOOT_V2_STANDING = 'faa6b2cb3132ce2e0ee4304bd833d7f0f999850244014d355f1c33ed176ebb83'
G6_CONFIG = '8b74f1de7e49e44b4ad140b59767e441cc6adaf6c0689d684ecdc301bcee6c5e'
G7_CONFIG = 'd68912a7e24b68e6cc51faeedba4c0987c65b2a14d439d18483706bd3fd18fbf'
G6_DIGEST = 'sha256:750d5e46aee679075c2b88c163d22036093cf893edbe16bb5c2ca484f4275838'
G7_DIGEST = 'sha256:f809040367a1c6c9fea0e8f4b31486970f03ed68a979a5bdcd412ed95bd70dcb'
HELPERS = {
    'coverage.py': 'COVERAGE_SHA',
    'journal_contract.py': 'JOURNAL_SHA',
    'current15_bounded_tail_contract.py': 'CURRENT_TAIL_SHA',
    'proof_cache.py': 'PROOF_CACHE_SHA',
    'initial_boot_Cold_read_adoption.py': 'INITIAL_COLD_SHA',
    'current15_bounded_reader.py': 'CURRENT_READER_SHA',
    'qualification_initializer.py': 'QUALIFICATION_INITIALIZER_SHA',
}
OWNER_METHODS = {
    'actual_R42_anchor', 'boot_start_service_once', 'boot_terminal_predecessor',
    'bootstrap_never_started', 'call', 'cold_guard', 'cold_restore',
    'current15_context', 'current15_readonly', 'failed', 'full_journal',
    'hub_seal', 'identity', 'initial_boot_read_adoption', 'joined_unit',
    'journal_argv', 'kernel', 'key', 'maintenance', 'never_started',
    'properties', 'qualify_new_lifetime', 'recover_terminal',
    'successful_boot_unit', 'terminal_after_own_START', 'transport', 'watch',
    'wg', 'wg_snapshot', 'original_qualification_measurement',
    'original_qualification_exists',
}
SHARED_STANDING = ('hub_source_sha256', 'hub_boot_config_sha256', 'hub_unit_sha256',
                   'R43_proofs', 'Core262_context_ref', 'proof_index_ref', 'context_sources')


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def load_source(name):
    path = NEW / 'source' / (name + '.py')
    spec = importlib.util.spec_from_file_location('g7pair_test_' + name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


g6 = old_tests.guardian
g7 = load_source('network_guardian')


def source_parts(package):
    raw = (package / 'source/network_guardian.py').read_text()
    tree = ast.parse(raw)
    owner = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == 'Owner')
    methods = {n.name: ast.get_source_segment(raw, n) for n in owner.body
               if isinstance(n, ast.FunctionDef)}
    assignments = {target.id: ast.get_source_segment(raw, node)
                   for node in tree.body if isinstance(node, ast.Assign)
                   for target in node.targets if isinstance(target, ast.Name)}
    return raw, tree, owner, methods, assignments


def standing(module):
    """Declared shape fixture only; no installed standing hash is manufactured."""
    value = {key: '1' * 64 for key in module.FIELDS}
    ref = {'path': '/declared-public-CI-reference', 'sha256': '2' * 64}
    value.update({
        'schema': module.SCHEMA,
        'Root_review': ('Declared CI fixture; no installed/native/current authority. ' * 4),
        'guardian_source_sha256': digest(Path(module.__file__).read_bytes()),
        'predecessor_guardian_source_sha256': module.PREDECESSOR_SOURCE_SHA,
        'predecessor_standing_config_sha256': module.PREDECESSOR_CONFIG_SHA,
        'r13_predecessor_guardian_source_sha256': module.R13_PREDECESSOR_SOURCE_SHA,
        'g6_predecessor_guardian_source_sha256': CANONICAL_SOURCE,
        'g6_predecessor_standing_config_sha256': CANONICAL_STANDING,
        'new_controller_config_sha256': G6_CONFIG if module is g6 else G7_CONFIG,
        'pair_predecessor_standing_configs': module.pair_predecessor_refs(),
        'R43_proofs': {**{key: copy.deepcopy(ref) for key in
                          ('return_ref', 'original_SSM_caller_ref', 'request_ref', 'recipe_ref')},
                       'stage_caller_refs': []},
        'Core262_context_ref': copy.deepcopy(ref),
        'proof_index_ref': {**ref, 'path': str(module.PREDECESSOR_HERE / 'PROOF-INDEX.PUBLIC.json')},
        'context_sources': {key: copy.deepcopy(ref) for key in
                            ('network_anchor_source_ref', 'network_qualification_source_ref',
                             'Core_context_source_ref', 'Root_factual_Source_review_ref')},
    })
    if module is g7:
        value['g6_boot_v2_predecessor_guardian_source_sha256'] = BOOT_V2_SOURCE
        value['g6_boot_v2_predecessor_standing_config_sha256'] = BOOT_V2_STANDING
    return value


def canonical_prior(config):
    return {
        **{key: copy.deepcopy(config[key]) for key in SHARED_STANDING},
        'schema': g7.G6_PREDECESSOR_SCHEMA,
        'guardian_source_sha256': CANONICAL_SOURCE,
        'new_controller_config_sha256': G6_CONFIG,
        'predecessor_guardian_source_sha256': g7.PREDECESSOR_SOURCE_SHA,
        'predecessor_standing_config_sha256': g7.PREDECESSOR_CONFIG_SHA,
        'r13_predecessor_guardian_source_sha256': g7.R13_PREDECESSOR_SOURCE_SHA,
        'r13_predecessor_standing_config_sha256': config['r13_predecessor_standing_config_sha256'],
        'pair_predecessor_standing_configs': g7.pair_predecessor_refs(),
    }


def installed_read(module, path, value, expected_hash):
    """Simulate private root file/hash custody; test actual body validators."""
    raw = module.wire(value)

    def read(selected, cap, mode=None):
        if (hasattr(module, 'G6_BOOT_V2_PREDECESSOR_CONFIG')
                and path == module.G6_BOOT_V2_PREDECESSOR_CONFIG
                and selected == module.G6_BOOT_V2_PREDECESSOR_HERE / 'network_guardian.py'):
            if cap != 1 << 20 or mode is not None:
                raise AssertionError('unexpected predecessor-source boundary')
            return (OLD / 'source/network_guardian.py').read_bytes()
        if selected != path or cap != 32768 or mode != 0o600:
            raise AssertionError('unexpected installed-read boundary')
        return raw

    return (patch.object(module, 'read', side_effect=read),
            patch.object(module, 'sha', side_effect=lambda body:
                         expected_hash if body == raw else digest(body)))


class G7SourceTests(unittest.TestCase):
    def test_explicit_old_and_new_operational_packages(self):
        self.assertEqual(Path(g6.__file__), OLD / 'source/network_guardian.py')
        self.assertEqual(Path(g7.__file__), NEW / 'source/network_guardian.py')
        self.assertEqual(digest(Path(g6.__file__).read_bytes()), BOOT_V2_SOURCE)
        self.assertEqual(str(g7.HERE), '/opt/dakasa/capacity-network/network-boot-recovery-r13-g7pair-source-v1')
        self.assertEqual(str(g7.CONFIG), '/etc/dakasa/capacity-network/network-recovery.r13-g7pair.production.json')
        self.assertEqual(g7.SCHEMA, 'Root_standing_R13_g7pair_successor_Core262_R43_network_boot_terminal_recovery_v1')
        for package, module in ((OLD, g6), (NEW, g7)):
            with self.subTest(package=package.name):
                manifest = json.loads((package / 'PACKAGE.json').read_bytes())
                actual = {str(p.relative_to(package)): digest(p.read_bytes())
                          for folder in ('source', 'units') for p in (package / folder).iterdir()
                          if p.is_file()}
                self.assertEqual(len(actual), 10)
                self.assertEqual(actual, manifest['files'])
                self.assertEqual(manifest['installed_source_directory'], str(module.HERE))
                self.assertEqual(manifest['standing_config_path'], str(module.CONFIG))
                checksum_rows = [line.split() for line in (package / 'SHA256SUMS').read_text().splitlines()]
                self.assertTrue(all(len(row) == 2 for row in checksum_rows))
                checksum_pins = {name: pin for pin, name in checksum_rows}
                self.assertEqual(len(checksum_pins), len(checksum_rows))
                self.assertEqual(checksum_pins, {**actual, 'PACKAGE.json': digest((package / 'PACKAGE.json').read_bytes())})
        manifest = json.loads((NEW / 'PACKAGE.json').read_bytes())
        self.assertEqual(manifest['schema'], 'owned_network_guardian_g7pair_source_package_v1')
        self.assertEqual(manifest['base_Core_source'], 'c9f260432ce5a10886df0385c958ec7d643648df')
        self.assertEqual(manifest['amd64_Core_manifest_digest'], G7_DIGEST)
        self.assertEqual(manifest['controller_config_sha256'], G7_CONFIG)
        self.assertEqual(manifest['historical_g6_controller_config_sha256'], G6_CONFIG)
        old_manifest = json.loads((OLD / 'PACKAGE.json').read_bytes())
        self.assertEqual(manifest['historical_g6_controller_unit_sha256'],
                         old_manifest['unchanged_controller_unit_sha256'])
        self.assertEqual(manifest['controller_unit_sha256'],
                         '85b8dcd254d46755fdbd568d7d01c2c2cf2d7e309bf3b0b7ac751ef9cb680ec9')
        self.assertEqual(manifest['predecessors'], {
            'canonical_g6': {'source_sha256': CANONICAL_SOURCE,
                             'standing_config_sha256': CANONICAL_STANDING,
                             'controller_config_sha256': G6_CONFIG},
            'g6_boot_v2': {'source_sha256': BOOT_V2_SOURCE,
                           'standing_config_sha256': BOOT_V2_STANDING,
                           'controller_config_sha256': G6_CONFIG}})

    def test_exact_seven_helpers_and_31_owner_methods(self):
        old = json.loads((OLD / 'PACKAGE.json').read_bytes())
        new = json.loads((NEW / 'PACKAGE.json').read_bytes())
        old_parts, new_parts = source_parts(OLD), source_parts(NEW)
        self.assertEqual(len(OWNER_METHODS), 31)
        self.assertEqual(set(old['unchanged_owner_methods_sha256']) |
                         {'original_qualification_measurement', 'original_qualification_exists'}, OWNER_METHODS)
        for name in OWNER_METHODS:
            with self.subTest(method=name):
                self.assertEqual(new_parts[3][name], old_parts[3][name])
                if name in old['unchanged_owner_methods_sha256']:
                    self.assertEqual(digest(new_parts[3][name].encode()), old['unchanged_owner_methods_sha256'][name])
        for name, constant in HELPERS.items():
            with self.subTest(helper=name):
                raw = (NEW / 'source' / name).read_bytes()
                self.assertEqual(raw, (OLD / 'source' / name).read_bytes())
                self.assertEqual(digest(raw), getattr(g7, constant))
                self.assertEqual(getattr(g7, constant), getattr(g6, constant))
        self.assertEqual(new_parts[4]['PAIR_STANDING_CHAIN'], old_parts[4]['PAIR_STANDING_CHAIN'])
        self.assertEqual(new['unchanged_owner_methods_sha256'],
                         {name: digest(new_parts[3][name].encode()) for name in OWNER_METHODS})
        self.assertEqual(new['unchanged_helpers_sha256'],
                         {'source/' + name: old['files']['source/' + name] for name in HELPERS})
        self.assertEqual(new['unchanged_assignments_sha256'],
                         {'PAIR_STANDING_CHAIN': old['unchanged_assignments_sha256']['PAIR_STANDING_CHAIN']})
        self.assertEqual(new['historical_g6_pair_chain_ast_sha256'],
                         old['unchanged_assignments_sha256']['PAIR_CHAIN'])
        self.assertEqual(new['pair_chain_ast_sha256'], digest(new_parts[4]['PAIR_CHAIN'].encode()))

    def test_pair_chain_freezes_g6_and_appends_exact_g7(self):
        self.assertEqual(g7.PAIR_STANDING_CHAIN, g6.PAIR_STANDING_CHAIN)
        self.assertEqual([row[0] for row in g7.PAIR_STANDING_CHAIN], ['f5pair', 'g2pair', 'g3pair', 'g4pair', 'g5pair'])
        self.assertEqual(g7.PAIR_CHAIN[:-2], g6.PAIR_CHAIN[:-1])
        self.assertEqual(g7.PAIR_CHAIN[-2], ('g6pair', g6.G6_CORE_IMAGE_PAIRS, g6.NEW_CONFIG, G6_CONFIG))
        self.assertEqual(g7.PAIR_CHAIN[-1], ('g7pair', g7.G7_CORE_IMAGE_PAIRS, g7.NEW_CONFIG, None))
        self.assertEqual(g7.CORE_G6, g7.CORE_IMAGE_REF + G6_DIGEST)
        self.assertEqual(g7.CORE_G7, g7.CORE_IMAGE_REF + G7_DIGEST)
        self.assertEqual(g7.G7_CORE_IMAGE_PAIRS, [
            {'image': g7.CORE_G6, 'image_id': g7.CORE_G6},
            {'image': g7.CORE_G7, 'image_id': g7.CORE_G7}])
        self.assertEqual(g6.G6_CONTROLLER_CONFIG_SHA, G6_CONFIG)
        self.assertEqual(g7.G6_CONTROLLER_CONFIG_SHA, G6_CONFIG)
        self.assertEqual(g7.G7_CONTROLLER_CONFIG_SHA, G7_CONFIG)
        self.assertEqual(g7.HEAD_NEW_CORE_DIGEST, G7_DIGEST)

    def test_future_units_only_change_source_namespace_and_pin(self):
        old_sha, new_sha = digest(Path(g6.__file__).read_bytes()), digest(Path(g7.__file__).read_bytes())
        for path in (OLD / 'units').iterdir():
            with self.subTest(unit=path.name):
                expected = path.read_bytes().replace(str(g6.HERE).encode(), str(g7.HERE).encode()).replace(old_sha.encode(), new_sha.encode())
                self.assertEqual((NEW / 'units' / path.name).read_bytes(), expected)

    def test_closed_g7_standing_accepts_two_distinct_predecessors(self):
        value = standing(g7)
        g7.validate(value)
        self.assertEqual(set(value) - g6.FIELDS, {
            'g6_boot_v2_predecessor_guardian_source_sha256',
            'g6_boot_v2_predecessor_standing_config_sha256'})
        self.assertEqual((value['g6_predecessor_guardian_source_sha256'], value['g6_predecessor_standing_config_sha256']),
                         (CANONICAL_SOURCE, CANONICAL_STANDING))
        self.assertEqual((value['g6_boot_v2_predecessor_guardian_source_sha256'], value['g6_boot_v2_predecessor_standing_config_sha256']),
                         (BOOT_V2_SOURCE, BOOT_V2_STANDING))
        g6.validate(standing(g6))
        with self.assertRaises(RuntimeError):
            g6.validate(value)

    def test_standing_refuses_mixed_missing_extra_and_wrong_pair(self):
        base = standing(g7)
        for key in ('g6_predecessor_guardian_source_sha256', 'g6_predecessor_standing_config_sha256',
                    'g6_boot_v2_predecessor_guardian_source_sha256', 'g6_boot_v2_predecessor_standing_config_sha256',
                    'new_controller_config_sha256'):
            for variant in ('missing', 'zero', 'mixed'):
                with self.subTest(key=key, variant=variant):
                    bad = copy.deepcopy(base)
                    if variant == 'missing':
                        del bad[key]
                    elif variant == 'zero':
                        bad[key] = '0' * 64
                    else:
                        bad[key] = {'g6_predecessor_guardian_source_sha256': BOOT_V2_SOURCE,
                                    'g6_predecessor_standing_config_sha256': BOOT_V2_STANDING,
                                    'g6_boot_v2_predecessor_guardian_source_sha256': CANONICAL_SOURCE,
                                    'g6_boot_v2_predecessor_standing_config_sha256': CANONICAL_STANDING,
                                    'new_controller_config_sha256': G6_CONFIG}[key]
                    with self.assertRaises(RuntimeError):
                        g7.validate(bad)
        for prefix in (base['pair_predecessor_standing_configs'][:-1],
                       base['pair_predecessor_standing_configs'] + [{'generation': 'g6pair'}]):
            bad = copy.deepcopy(base)
            bad['pair_predecessor_standing_configs'] = prefix
            with self.assertRaises(RuntimeError):
                g7.validate(bad)
        with self.assertRaises(RuntimeError):
            g7.validate({**base, 'invented_ancestry_authority': CANONICAL_SOURCE})

    def test_canonical_g6_reader_keeps_historical_controller_pin(self):
        value = standing(g7)
        prior = canonical_prior(value)
        for changed in (None, 'new_controller_config_sha256', 'guardian_source_sha256', 'pair_predecessor_standing_configs'):
            old = copy.deepcopy(prior)
            if changed:
                old[changed] = G7_CONFIG if changed == 'new_controller_config_sha256' else 'wrong'
            reads, hashes = installed_read(g7, g7.G6_PREDECESSOR_CONFIG, old, CANONICAL_STANDING)
            with self.subTest(changed=changed), reads, hashes:
                if changed:
                    with self.assertRaises(RuntimeError):
                        g7.g6_predecessor_standing(value)
                else:
                    self.assertEqual(g7.g6_predecessor_standing(value), (CANONICAL_SOURCE, CANONICAL_STANDING))
        with patch.object(g7, 'read', return_value=b'wrong installed original'):
            with self.assertRaises(RuntimeError):
                g7.g6_predecessor_standing(value)

    def test_actual_boot_v2_reader_requires_entire_original_ancestry(self):
        value = standing(g7)
        prior = standing(g6)
        prior.update({key: copy.deepcopy(value[key]) for key in SHARED_STANDING})
        prior['r13_predecessor_standing_config_sha256'] = value['r13_predecessor_standing_config_sha256']
        for changed in (None, 'new_controller_config_sha256', 'g6_predecessor_guardian_source_sha256',
                        'g6_predecessor_standing_config_sha256', 'guardian_source_sha256', 'hub_unit_sha256',
                        'pair_predecessor_standing_configs', 'proof_index_ref', 'schema',
                        'missing_field', 'extra_field'):
            old = copy.deepcopy(prior)
            if changed == 'missing_field':
                del old['Root_review']
            elif changed == 'extra_field':
                old['invented_ancestry_authority'] = 'wrong'
            elif changed:
                old[changed] = G7_CONFIG if changed == 'new_controller_config_sha256' else 'wrong'
            reads, hashes = installed_read(g7, g7.G6_BOOT_V2_PREDECESSOR_CONFIG, old, BOOT_V2_STANDING)
            with self.subTest(changed=changed), reads, hashes:
                if changed:
                    with self.assertRaises(RuntimeError):
                        g7.g6_boot_v2_predecessor_standing(value)
                else:
                    self.assertEqual(g7.g6_boot_v2_predecessor_standing(value), (BOOT_V2_SOURCE, BOOT_V2_STANDING))
        with patch.object(g7, 'read', return_value=b'wrong installed boot-v2'):
            with self.assertRaises(RuntimeError):
                g7.g6_boot_v2_predecessor_standing(value)
        reads, _ = installed_read(g7, g7.G6_BOOT_V2_PREDECESSOR_CONFIG, prior, BOOT_V2_STANDING)
        with reads:
            with self.assertRaisesRegex(RuntimeError, 'EXACT_INSTALLED_G6_BOOT_V2_STANDING_CONFIG'):
                g7.g6_boot_v2_predecessor_standing(value)

    def test_owner_wires_both_authorities_and_revalidates_them(self):
        _, _, owner, _, _ = source_parts(NEW)
        init = next(n for n in owner.body if isinstance(n, ast.FunctionDef) and n.name == '__init__')
        authorities = next(n for n in ast.walk(init) if isinstance(n, ast.Assign)
                           and any(isinstance(t, ast.Attribute) and t.attr == 'authorities' for t in n.targets))
        static = next(n for n in owner.body if isinstance(n, ast.FunctionDef) and n.name == 'static')
        for node in (authorities, static):
            calls = {n.func.id for n in ast.walk(node) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
            self.assertTrue({'g6_predecessor_standing', 'g6_boot_v2_predecessor_standing'} <= calls)

    def test_g7_replays_original120_as_historical_only(self):
        helper = load_source('qualification_initializer')
        replay = old_tests.Replay()
        replay.owner.authorities = frozenset({(CANONICAL_SOURCE, CANONICAL_STANDING),
                                              (BOOT_V2_SOURCE, BOOT_V2_STANDING)})

        def module(path, expected):
            self.assertEqual(path, g7.HERE / 'qualification_initializer.py')
            self.assertEqual(expected, digest((NEW / 'source/qualification_initializer.py').read_bytes()))
            return helper

        with patch.object(g7, 'module', side_effect=module), \
                patch.object(g7, 'read', side_effect=replay.read), \
                patch.object(Path, 'exists', lambda path: path in replay.files), \
                patch.object(helper.time, 'monotonic', return_value=replay.value['finished'] + 1):
            result = g7.Owner.original_qualification_measurement(replay.owner, replay.identity)
        self.assertTrue(result['historical_original120_proof_verified'])
        self.assertFalse(result['current_health_or_new_epoch_authority'])
        self.assertEqual(result['authority']['source_sha256'], CANONICAL_SOURCE)
        self.assertEqual(result['original_qualification_ref']['sha256'],
                         '21e4697326aa0e74b1e169a897870b10e4668328ca04d497900a2f297bc99a31')
        self.assertNotIn('current_continuous_window', result['measurement'])
        mixed = old_tests.Replay()
        mixed.owner.authorities = frozenset({(CANONICAL_SOURCE, BOOT_V2_STANDING),
                                             (BOOT_V2_SOURCE, CANONICAL_STANDING)})
        g = types.SimpleNamespace(require=g7.require, LEDGER=g7.LEDGER, read=mixed.read,
                                  sha=digest, loads=g7.loads)
        with patch.object(Path, 'exists', lambda path: path in mixed.files), \
                patch.object(helper.time, 'monotonic', return_value=mixed.value['finished'] + 1):
            with self.assertRaises(RuntimeError):
                helper.extract(mixed.owner, g, mixed.identity)


if __name__ == '__main__':
    unittest.main()
