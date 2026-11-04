"""G9 CI operands: real validators, simulated installed reads, no host authority.

Declared binding constants belong only to isolated test modules. Historical
standing hashes remain actual pins; missing public fixtures fail, never skip.
"""
import ast
import contextlib
import copy
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import test_g7pair_source as prefix
import test_g8pair_source as old


ROOT = old.ROOT
NEW = ROOT / 'g9pair'
OLD = ROOT / 'g8pair'
G8_SOURCE = '8259638127d811079d6a461d3bd7407f8a53ff3ebb75e8061bf8538dcf6508b9'
G8_STANDING = 'a02690f5e7a8c000478ceca6c4f4715e7b589814bf93fc5cbefe3bd9126e08d3'
G8_CONFIG = old.G8_CONFIG
G8_FIXTURE = Path(__file__).parent / 'fixtures/historical-standing-g8/g8pair.PUBLIC.json'
digest = old.digest


def load_source(name):
    path = NEW / 'source' / (name + '.py')
    spec = importlib.util.spec_from_file_location('g9_source_declared_CI_' + name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


g9 = load_source('network_guardian')


def controller_operand():
    """A declared CI image/config, never a qualified release or Root approval."""
    raw = (old.CONFIGS / 'controller.r13-netlink-g8pair.production.json').read_bytes()
    if digest(raw) != G8_CONFIG:
        raise AssertionError('actual public G8 controller changed')
    value = json.loads(raw)
    new_digest = digest(b'declared G9 CI image; not a production manifest')
    image = g9.CORE_IMAGE_REF + 'sha256:' + new_digest
    value['core_container_images'] = [
        {'image': g9.CORE_G8, 'image_id': g9.CORE_G8},
        {'image': image, 'image_id': image}]
    value['root_review_attestation'] = 'Declared CI review of pure configuration operands only; no native qualification. ' * 3
    return new_digest, g9.wire(value)


@contextlib.contextmanager
def source_binding():
    new_digest, raw = controller_operand()
    image = g9.CORE_IMAGE_REF + 'sha256:' + new_digest
    pairs = [{'image': g9.CORE_G8, 'image_id': g9.CORE_G8}, {'image': image, 'image_id': image}]
    chain = (*g9.PAIR_CHAIN[:-1], ('g9pair', pairs, g9.NEW_CONFIG, None))
    with patch.multiple(g9, PROPOSAL_BOUND=True, HEAD_NEW_CORE_DIGEST='sha256:' + new_digest,
                        CORE_G9=image, G9_CONTROLLER_CONFIG_SHA=digest(raw),
                        G9_CORE_IMAGE_PAIRS=pairs, PAIR_CHAIN=chain,
                        ALLOWED_CORE_IMAGE_PAIRS=tuple(row[1] for row in chain)):
        yield raw


def history(role):
    if role != 'g8pair':
        return old.history_bytes(role)
    raw = G8_FIXTURE.read_bytes()
    if digest(raw) != G8_STANDING or len(json.loads(raw)) != 25:
        raise AssertionError('exact actual public G8 standing required')
    custody = json.loads((G8_FIXTURE.parent / 'ROOT-READ-CUSTODY.PUBLIC.json').read_bytes())
    if (custody['raw_sha256'], custody['raw_bytes'], custody['fields'], custody['status'], custody['response_code']) != (G8_STANDING, 7853, 25, 'Success', 0):
        raise AssertionError('actual read-only G8 capture custody changed')
    return raw


def current_standing():
    """Declared current shape; unit/file hashes are real, not installed facts."""
    value = copy.deepcopy(json.loads(history('g8pair')))
    value.update(schema=g9.SCHEMA,
                 guardian_source_sha256=digest((NEW / 'source/network_guardian.py').read_bytes()),
                 new_controller_config_sha256=g9.G9_CONTROLLER_CONFIG_SHA,
                 cold_unit_sha256=digest((NEW / 'units' / g9.COLD).read_bytes()),
                 guardian_unit_sha256=digest((NEW / 'units' / g9.GUARDIAN).read_bytes()),
                 Root_review='Declared CI standing shape only; no current health or native authority. ' * 4,
                 g8_predecessor_guardian_source_sha256=G8_SOURCE,
                 g8_predecessor_standing_config_sha256=G8_STANDING)
    return value


def historical_reads(changed=None, replacement=None):
    paths = {'canonical_g6': g9.G6_PREDECESSOR_CONFIG,
             'g6_boot_v2': g9.G6_BOOT_V2_PREDECESSOR_CONFIG,
             'g7pair': g9.G7_PREDECESSOR_CONFIG, 'g8pair': g9.G8_PREDECESSOR_CONFIG}
    values = {path: history(role) for role, path in paths.items()}
    values.update({g9.G6_BOOT_V2_PREDECESSOR_HERE / 'network_guardian.py':
                   (prefix.OLD / 'source/network_guardian.py').read_bytes(),
                   g9.G7_PREDECESSOR_HERE / 'network_guardian.py':
                   (old.OLD / 'source/network_guardian.py').read_bytes(),
                   g9.G8_PREDECESSOR_HERE / 'network_guardian.py':
                   (OLD / 'source/network_guardian.py').read_bytes()})
    if changed:
        values[paths[changed]] = replacement

    def read(path, cap, mode=None):
        if path not in values:
            raise AssertionError('unexpected installed read: ' + str(path))
        expected = (1 << 20, None) if path.name == 'network_guardian.py' else (32768, 0o600)
        if (cap, mode) != expected:
            raise AssertionError('historical raw read boundary changed')
        return values[path]
    return patch.object(g9, 'read', side_effect=read)


class G9SourceTests(unittest.TestCase):
    def test_unbound_entrypoints_refuse_before_any_installed_read_or_ledger_write(self):
        with patch.object(g9, 'PROPOSAL_BOUND', False), patch.object(g9, 'read') as read, \
                patch.object(g9, 'directory') as directory:
            for call in (lambda: g9.Owner('1' * 64), lambda: g9.validate({}),
                         g9.pair_chain_digests, g9.read_pair_chain):
                with self.subTest(call=call), self.assertRaisesRegex(RuntimeError, 'G9_CONCRETE_QUALIFIED_BINDING_REQUIRED'):
                    call()
            read.assert_not_called()
            directory.assert_not_called()

    def test_31_owner_methods_seven_helpers_and_historical_prefix_are_exact(self):
        before, after = prefix.source_parts(OLD), prefix.source_parts(NEW)
        self.assertEqual(set(before[3]), set(after[3]))
        for name in prefix.OWNER_METHODS:
            with self.subTest(method=name):
                self.assertEqual(before[3][name], after[3][name])
        self.assertEqual(len(prefix.OWNER_METHODS), 31)
        for name, constant in prefix.HELPERS.items():
            with self.subTest(helper=name):
                raw = (NEW / 'source' / name).read_bytes()
                self.assertEqual(raw, (OLD / 'source' / name).read_bytes())
                self.assertEqual(digest(raw), getattr(g9, constant))
        self.assertEqual(before[4]['PAIR_STANDING_CHAIN'], after[4]['PAIR_STANDING_CHAIN'])
        for name in ('HISTORICAL_G6_FIELDS', 'HISTORICAL_F315_FIELDS', 'HISTORICAL_G7_FIELDS'):
            self.assertEqual(before[4][name], after[4][name])

    def test_chain_freezes_actual_g8_and_appends_only_new_g9_head(self):
        expected = [*old.g8.PAIR_CHAIN[:-1],
                    ('g8pair', old.g8.G8_CORE_IMAGE_PAIRS, old.g8.NEW_CONFIG, G8_CONFIG)]
        self.assertEqual(list(g9.PAIR_CHAIN[:-1]), expected)
        self.assertEqual(g9.CORE_G8, old.g8.CORE_G8)
        with source_binding():
            images = g9.pair_chain_digests()
            self.assertEqual(images[-2:], [g9.CORE_G8, g9.CORE_G9])
            self.assertEqual(g9.PAIR_CHAIN[-1], ('g9pair', g9.G9_CORE_IMAGE_PAIRS, g9.NEW_CONFIG, None))

    def test_four_actual_literal_rosters_and_current27_are_independent(self):
        for role, fields, count in (
                ('canonical_g6', g9.HISTORICAL_G6_FIELDS, 19),
                ('g6_boot_v2', g9.HISTORICAL_F315_FIELDS, 21),
                ('g7pair', g9.HISTORICAL_G7_FIELDS, 23),
                ('g8pair', g9.HISTORICAL_G8_FIELDS, 25)):
            with self.subTest(role=role):
                self.assertEqual(len(fields), count)
                self.assertEqual(set(json.loads(history(role))), fields)
        self.assertEqual(g9.HISTORICAL_G8_FIELDS, old.g8.FIELDS)
        with source_binding():
            value = current_standing()
            self.assertEqual(set(value), g9.FIELDS)
            self.assertEqual(len(g9.FIELDS), 27)
            g9.validate(value)

    def test_all_four_raw_authorities_accept_and_refuse_changed_bytes_or_mixed_axes(self):
        readers = {'canonical_g6': g9.g6_predecessor_standing,
                   'g6_boot_v2': g9.g6_boot_v2_predecessor_standing,
                   'g7pair': g9.g7_predecessor_standing, 'g8pair': g9.g8_predecessor_standing}
        with source_binding():
            value = current_standing()
            with historical_reads():
                for role, method in readers.items():
                    self.assertEqual(method(value)[1], digest(history(role)))
            for role, method in readers.items():
                with self.subTest(role=role), historical_reads(role, history(role) + b' '), self.assertRaises(RuntimeError):
                    method(value)
            for key in g9.FIELDS:
                broken = copy.deepcopy(value)
                del broken[key]
                with self.subTest(missing=key), self.assertRaises(RuntimeError):
                    g9.validate(broken)
            for key, wrong in (('new_controller_config_sha256', G8_CONFIG),
                               ('g8_predecessor_guardian_source_sha256', old.G7_SOURCE),
                               ('g8_predecessor_standing_config_sha256', old.G7_STANDING),
                               ('g7_predecessor_standing_config_sha256', G8_STANDING)):
                with self.subTest(key=key), self.assertRaises(RuntimeError):
                    g9.validate({**value, key: wrong})
            with self.assertRaises(RuntimeError):
                g9.validate({**value, 'unapproved_authority': '1' * 64})

    def test_owner_wiring_and_future_units_add_only_the_fourth_authority(self):
        _, _, owner, _, _ = prefix.source_parts(NEW)
        init = next(n for n in owner.body if isinstance(n, ast.FunctionDef) and n.name == '__init__')
        self.assertEqual(ast.unparse(init.body[0]), 'require_bound()')
        for method in (init, next(n for n in owner.body if isinstance(n, ast.FunctionDef) and n.name == 'static')):
            calls = {n.func.id for n in ast.walk(method) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
            self.assertTrue({'g6_predecessor_standing', 'g6_boot_v2_predecessor_standing',
                             'g7_predecessor_standing', 'g8_predecessor_standing'} <= calls)
        new_sha = digest((NEW / 'source/network_guardian.py').read_bytes())
        for name in (g9.COLD, g9.GUARDIAN):
            expected = (OLD / 'units' / name).read_text().replace('g8pair', 'g9pair').replace(G8_SOURCE, new_sha)
            self.assertEqual((NEW / 'units' / name).read_text(), expected)
