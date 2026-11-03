"""CI-only G8 Source checks against exact public historical bytes.

File reads are simulated; historical SHA calculations and body validators are
real. No fixture, replay or synthetic current standing grants native health.
"""
import ast
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import test_current15_initializer as initializer
import test_g7pair_source as prior


ROOT = Path(__file__).resolve().parents[1]
NEW = ROOT / 'g8pair'
OLD = ROOT / 'g7pair'
STANDINGS = Path(__file__).parent / 'fixtures/historical-standing-g6-g7'
CONFIGS = Path(__file__).parent / 'fixtures/public-controller-g8pair'
SOURCE_R = 'd451ac07c6e412bd2eae06f648935799e046ea31'
G8_CONFIG = '42b9d05dac25610678ebce295335ead8b6086a87527fcd5ad030413a37a2a1a5'
G8_DIGEST = 'sha256:0970e1188ceb5fa3ba52a1a11337f5fae7ac0657a66a69e08d24f9888f813826'
G7_SOURCE = '2379e9cb0fcf36faf7dfe58e930d0eb6ae97ba4d177db6610a23583d0a00a8aa'
G7_STANDING = 'dd7d449ea8fdba60a43d6badb138ea9496e1342572f90633e62d7b87d9b44866'
HISTORY = {
    'canonical_g6': ('canonical-g6.PUBLIC.json', prior.CANONICAL_SOURCE, prior.CANONICAL_STANDING, 19),
    'g6_boot_v2': ('g6-boot-v2.PUBLIC.json', prior.BOOT_V2_SOURCE, prior.BOOT_V2_STANDING, 21),
    'g7pair': ('g7pair.PUBLIC.json', G7_SOURCE, G7_STANDING, 23),
}


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def load_source(name):
    path = NEW / 'source' / (name + '.py')
    spec = importlib.util.spec_from_file_location('g8pair_source_test_' + name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


g8 = load_source('network_guardian')


def history_bytes(role):
    filename, _, pin, count = HISTORY[role]
    raw = (STANDINGS / filename).read_bytes()
    if digest(raw) != pin or len(json.loads(raw)) != count:
        raise AssertionError('exact public historical standing changed: ' + role)
    return raw


def current_standing():
    """Declared G8 shape cloned from actual G7 facts; no installed hash claim."""
    value = copy.deepcopy(json.loads(history_bytes('g7pair')))
    package = json.loads((NEW / 'PACKAGE.json').read_bytes())
    value.update({
        'schema': g8.SCHEMA,
        'guardian_source_sha256': digest((NEW / 'source/network_guardian.py').read_bytes()),
        'controller_unit_sha256': package['controller_unit_sha256'],
        'cold_unit_sha256': package['files']['units/' + g8.COLD],
        'guardian_unit_sha256': package['files']['units/' + g8.GUARDIAN],
        'new_controller_config_sha256': G8_CONFIG,
        'Root_review': 'Declared CI G8 shape only, without native authority or current health. ' * 4,
        'g7_predecessor_guardian_source_sha256': G7_SOURCE,
        'g7_predecessor_standing_config_sha256': G7_STANDING,
    })
    return value


def historical_reads(changed_role=None, replacement=None):
    """Map actual public bytes to expected installed paths, never fake their SHA."""
    values = {
        g8.G6_PREDECESSOR_CONFIG: history_bytes('canonical_g6'),
        g8.G6_BOOT_V2_PREDECESSOR_CONFIG: history_bytes('g6_boot_v2'),
        g8.G7_PREDECESSOR_CONFIG: history_bytes('g7pair'),
        g8.G6_BOOT_V2_PREDECESSOR_HERE / 'network_guardian.py':
            (prior.OLD / 'source/network_guardian.py').read_bytes(),
        g8.G7_PREDECESSOR_HERE / 'network_guardian.py':
            (OLD / 'source/network_guardian.py').read_bytes(),
    }
    if changed_role:
        path = {'canonical_g6': g8.G6_PREDECESSOR_CONFIG,
                'g6_boot_v2': g8.G6_BOOT_V2_PREDECESSOR_CONFIG,
                'g7pair': g8.G7_PREDECESSOR_CONFIG}[changed_role]
        values[path] = replacement

    def read(path, cap, mode=None):
        if path not in values:
            raise AssertionError('unexpected historical read: ' + str(path))
        source = path.name == 'network_guardian.py'
        if (cap, mode) != ((1 << 20, None) if source else (32768, 0o600)):
            raise AssertionError('changed source/standing custody boundary')
        return values[path]
    return patch.object(g8, 'read', side_effect=read)


class G8SourceTests(unittest.TestCase):
    def test_actual_package_pins_source8_units2_and_r4_image(self):
        package = json.loads((NEW / 'PACKAGE.json').read_bytes())
        actual = {str(path.relative_to(NEW)): digest(path.read_bytes())
                  for folder in ('source', 'units') for path in (NEW / folder).iterdir() if path.is_file()}
        self.assertEqual(len(actual), 10)
        self.assertEqual(package['files'], actual)
        self.assertEqual(package['schema'], 'owned_network_guardian_g8pair_source_package_v1')
        self.assertEqual(package['base_Core_source'], SOURCE_R)
        self.assertEqual(package['amd64_Core_manifest_digest'], G8_DIGEST)
        self.assertEqual(package['controller_config_sha256'], G8_CONFIG)
        self.assertEqual(package['historical_g7_controller_config_sha256'], prior.G7_CONFIG)
        self.assertEqual(package['historical_g6_controller_config_sha256'], prior.G6_CONFIG)
        self.assertEqual(package['installed_source_directory'], str(g8.HERE))
        self.assertEqual(package['standing_config_path'], str(g8.CONFIG))
        self.assertEqual(package['predecessors'], {
            role: {'source_sha256': source, 'standing_config_sha256': standing,
                   'controller_config_sha256': prior.G7_CONFIG if role == 'g7pair' else prior.G6_CONFIG}
            for role, (_, source, standing, _) in HISTORY.items()})
        rows = [line.split() for line in (NEW / 'SHA256SUMS').read_text().splitlines()]
        self.assertTrue(all(len(row) == 2 for row in rows))
        self.assertEqual(len(rows), len({row[1] for row in rows}))
        self.assertEqual({name: pin for pin, name in rows},
                         {**actual, 'PACKAGE.json': digest((NEW / 'PACKAGE.json').read_bytes())})

    def test_seven_helper_bytes_and_31_owner_segments_are_frozen(self):
        old = prior.source_parts(OLD)
        new = prior.source_parts(NEW)
        package = json.loads((NEW / 'PACKAGE.json').read_bytes())
        self.assertEqual(set(package['unchanged_owner_methods_sha256']), prior.OWNER_METHODS)
        self.assertEqual(len(prior.OWNER_METHODS), 31)
        for name in prior.OWNER_METHODS:
            with self.subTest(method=name):
                self.assertEqual(new[3][name], old[3][name])
                self.assertEqual(digest(new[3][name].encode()), package['unchanged_owner_methods_sha256'][name])
        for name, constant in prior.HELPERS.items():
            with self.subTest(helper=name):
                raw = (NEW / 'source' / name).read_bytes()
                self.assertEqual(raw, (OLD / 'source' / name).read_bytes())
                self.assertEqual(raw, (prior.OLD / 'source' / name).read_bytes())
                self.assertEqual(digest(raw), getattr(g8, constant))
        self.assertEqual(new[4]['PAIR_STANDING_CHAIN'], old[4]['PAIR_STANDING_CHAIN'])
        self.assertEqual(g8.PAIR_STANDING_CHAIN, prior.g7.PAIR_STANDING_CHAIN)

    def test_pair_chain_freezes_g7_and_appends_only_exact_g8(self):
        expected = [*prior.g7.PAIR_CHAIN[:-1],
                    ('g7pair', prior.g7.G7_CORE_IMAGE_PAIRS, prior.g7.NEW_CONFIG, prior.G7_CONFIG)]
        self.assertEqual(list(g8.PAIR_CHAIN[:-1]), expected)
        self.assertEqual(g8.PAIR_CHAIN[-1], ('g8pair', g8.G8_CORE_IMAGE_PAIRS, g8.NEW_CONFIG, None))
        self.assertEqual(g8.G8_CORE_IMAGE_PAIRS, [
            {'image': g8.CORE_G7, 'image_id': g8.CORE_G7},
            {'image': g8.CORE_G8, 'image_id': g8.CORE_G8}])
        self.assertTrue(g8.CORE_G7.endswith(prior.G7_DIGEST))
        self.assertTrue(g8.CORE_G8.endswith(G8_DIGEST))
        self.assertEqual(g8.G6_CONTROLLER_CONFIG_SHA, prior.G6_CONFIG)
        self.assertEqual(g8.G7_CONTROLLER_CONFIG_SHA, prior.G7_CONFIG)
        self.assertEqual(g8.G8_CONTROLLER_CONFIG_SHA, G8_CONFIG)

    def test_actual_historical_closed_rosters_are_19_21_23_and_current25(self):
        literal_sets = (g8.HISTORICAL_G6_FIELDS, g8.HISTORICAL_F315_FIELDS, g8.HISTORICAL_G7_FIELDS)
        for (role, (_, source, _, count)), fields in zip(HISTORY.items(), literal_sets):
            with self.subTest(role=role):
                value = json.loads(history_bytes(role))
                self.assertEqual(set(value), fields)
                self.assertEqual(len(fields), count)
                self.assertEqual(value['guardian_source_sha256'], source)
        self.assertEqual(set(current_standing()), g8.FIELDS)
        self.assertEqual(len(g8.FIELDS), 25)
        self.assertEqual(set(json.loads(history_bytes('g6_boot_v2'))), prior.g6.FIELDS)
        self.assertEqual(set(json.loads(history_bytes('g7pair'))), prior.g7.FIELDS)

    def test_current_standing_accepts_three_distinct_historical_authorities(self):
        value = current_standing()
        g8.validate(value)
        with historical_reads():
            self.assertEqual(g8.g6_predecessor_standing(value), HISTORY['canonical_g6'][1:3])
            self.assertEqual(g8.g6_boot_v2_predecessor_standing(value), HISTORY['g6_boot_v2'][1:3])
            self.assertEqual(g8.g7_predecessor_standing(value), HISTORY['g7pair'][1:3])

    def test_closed_current_standing_refuses_missing_extra_mixed_and_old_heads(self):
        base = current_standing()
        for key in g8.FIELDS:
            value = copy.deepcopy(base)
            del value[key]
            with self.subTest(missing=key), self.assertRaises(RuntimeError):
                g8.validate(value)
        for key, wrong in (
                ('new_controller_config_sha256', prior.G7_CONFIG),
                ('new_controller_config_sha256', prior.G6_CONFIG),
                ('g6_predecessor_guardian_source_sha256', G7_SOURCE),
                ('g6_predecessor_standing_config_sha256', prior.BOOT_V2_STANDING),
                ('g6_boot_v2_predecessor_guardian_source_sha256', prior.CANONICAL_SOURCE),
                ('g6_boot_v2_predecessor_standing_config_sha256', G7_STANDING),
                ('g7_predecessor_guardian_source_sha256', prior.BOOT_V2_SOURCE),
                ('g7_predecessor_standing_config_sha256', prior.CANONICAL_STANDING)):
            with self.subTest(key=key, wrong=wrong), self.assertRaises(RuntimeError):
                g8.validate({**base, key: wrong})
        with self.assertRaises(RuntimeError):
            g8.validate({**base, 'unapproved_authority': '1' * 64})

    def test_actual_historical_readers_reject_changed_bytes_and_cross_epoch_config(self):
        methods = {'canonical_g6': g8.g6_predecessor_standing,
                   'g6_boot_v2': g8.g6_boot_v2_predecessor_standing,
                   'g7pair': g8.g7_predecessor_standing}
        for role, method in methods.items():
            raw = history_bytes(role)
            value = json.loads(raw)
            variants = [raw + b' ', g8.wire({**value, 'unapproved_future_field': '1' * 64})]
            missing = copy.deepcopy(value)
            del missing['Root_review']
            variants.append(g8.wire(missing))
            for replacement in variants:
                with self.subTest(role=role, replacement_sha=digest(replacement)), historical_reads(role, replacement):
                    with self.assertRaises(RuntimeError):
                        method(current_standing())
            bad = current_standing()
            bad['new_controller_config_sha256'] = prior.G7_CONFIG
            with self.subTest(role=role, old_head=True), historical_reads(), self.assertRaises(RuntimeError):
                method(bad)

    def test_owner_installs_and_revalidates_all_three_authority_axes(self):
        _, _, owner, _, _ = prior.source_parts(NEW)
        init = next(n for n in owner.body if isinstance(n, ast.FunctionDef) and n.name == '__init__')
        authority = next(n for n in ast.walk(init) if isinstance(n, ast.Assign)
                         and any(isinstance(t, ast.Attribute) and t.attr == 'authorities' for t in n.targets))
        static = next(n for n in owner.body if isinstance(n, ast.FunctionDef) and n.name == 'static')
        for part in (authority, static):
            calls = {n.func.id for n in ast.walk(part) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
            self.assertTrue({'g6_predecessor_standing', 'g6_boot_v2_predecessor_standing',
                             'g7_predecessor_standing'} <= calls)

    def test_historical_original120_replay_never_becomes_current_epoch_health(self):
        helper = load_source('qualification_initializer')
        replay = initializer.Replay()
        replay.owner.authorities = frozenset((row[1], row[2]) for row in HISTORY.values())
        def module(path, expected):
            self.assertEqual(path, g8.HERE / 'qualification_initializer.py')
            self.assertEqual(expected, digest((NEW / 'source/qualification_initializer.py').read_bytes()))
            return helper
        with patch.object(g8, 'module', side_effect=module), patch.object(g8, 'read', side_effect=replay.read), \
                patch.object(Path, 'exists', lambda path: path in replay.files), \
                patch.object(helper.time, 'monotonic', return_value=replay.value['finished'] + 1):
            result = g8.Owner.original_qualification_measurement(replay.owner, replay.identity)
        self.assertTrue(result['historical_original120_proof_verified'])
        self.assertFalse(result['current_health_or_new_epoch_authority'])
        self.assertEqual(result['authority']['source_sha256'], prior.CANONICAL_SOURCE)
        self.assertNotIn('current_continuous_window', result['measurement'])

    def test_future_cold_and_guardian_units_only_change_namespace_and_source_pin(self):
        old_sha = digest((OLD / 'source/network_guardian.py').read_bytes())
        new_sha = digest((NEW / 'source/network_guardian.py').read_bytes())
        for name in (g8.COLD, g8.GUARDIAN):
            expected = (OLD / 'units' / name).read_text().replace('g7pair', 'g8pair').replace(old_sha, new_sha)
            self.assertEqual((NEW / 'units' / name).read_text(), expected)

    def test_actual_g8_initializer_refuses_half120_or_changed_physical_epoch(self):
        helper = load_source('qualification_initializer')
        for variant in ('half-window60', 'pid', 'start_ticks', 'InvocationID', 'boot_id'):
            replay = initializer.Replay()
            replay.owner.authorities = frozenset((row[1], row[2]) for row in HISTORY.values())
            if variant == 'half-window60':
                replay.value['end'] = replay.value['start'] + 60
                replay.save()
            else:
                replay.actual_identity[variant] = (999999 if variant in ('pid', 'start_ticks') else 'foreign-epoch')
            def module(path, expected):
                self.assertEqual(path, g8.HERE / 'qualification_initializer.py')
                self.assertEqual(expected, digest((NEW / 'source/qualification_initializer.py').read_bytes()))
                return helper
            with self.subTest(variant=variant), patch.object(g8, 'module', side_effect=module), \
                    patch.object(g8, 'read', side_effect=replay.read), \
                    patch.object(Path, 'exists', lambda path: path in replay.files), \
                    patch.object(helper.time, 'monotonic', return_value=replay.value['finished'] + 1):
                with self.assertRaises(RuntimeError):
                    g8.Owner.original_qualification_measurement(replay.owner, replay.identity)
