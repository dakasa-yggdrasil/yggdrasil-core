"""CI of the real versioned tools; configuration fixtures are public history."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import test_g7pair_source as source


TOOLS = source.NEW / 'tools'
FIXTURE = Path(__file__).parent / 'fixtures/public-controller-pair-chain'


def load_tool(name):
    spec = importlib.util.spec_from_file_location('g7pair_tools_test_' + name, TOOLS / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


contract = load_tool('pair_change_contract')
derive = load_tool('derive_g7pair_controller_config')
standing_derive = load_tool('derive_standing_config')


def controller_inputs():
    manifest = json.loads((FIXTURE / 'MANIFEST.json').read_bytes())
    raw = {}
    for name, facts in manifest['files'].items():
        body = (FIXTURE / name).read_bytes()
        if len(body) != facts['bytes'] or source.digest(body) != facts['sha256']:
            raise AssertionError('exact public controller fixture changed')
        raw[name] = body
    r42 = raw['controller.r42-cold-unknown184014.production.json']
    prefix = [raw[path.name] for _, _, path, _ in derive.PAIR_CHAIN[:-1]]
    expected = raw['controller.r13-netlink-g7pair.production.json']
    return r42, prefix, expected


def declared_derivation():
    """Simulated input pins, independent of any installed standing or authority."""
    expected = {
        'source_sha256': source.digest((source.NEW / 'source/network_guardian.py').read_bytes()),
        'unit_sha256': {unit: '1' * 64 for unit in contract.UNITS},
        'controller_prefix_sha256': {generation: pin for generation, _, _, pin in derive.PAIR_CHAIN[:-1]},
        'ancestry_input_sha256': {key: '2' * 64 for key in (
            'predecessor_standing_config_sha256', 'r13_predecessor_standing_config_sha256',
            'r42_controller_config_sha256', 'r13_base_controller_config_sha256',
            'hub_source_sha256', 'hub_boot_config_sha256', 'hub_unit_sha256')},
    }
    expected['ancestry_input_sha256']['hub_unit_sha256'] = expected['unit_sha256'][contract.HUB]
    expected['ancestry_input_sha256']['r13_base_controller_config_sha256'] = expected['controller_prefix_sha256']['base']
    inputs = {
        'successor_guardian_source_sha256': expected['source_sha256'],
        'head_generation': 'g7pair', 'head_core_digest': source.G7_DIGEST,
        'head_controller_config_sha256': source.G7_CONFIG,
        'historical_g6_controller_config_sha256': source.G6_CONFIG,
        'pair_predecessor_standing_config_sha256': dict(contract.PREFIX_STANDINGS),
        'g6_predecessor_guardian_source_sha256': source.CANONICAL_SOURCE,
        'g6_predecessor_standing_config_sha256': source.CANONICAL_STANDING,
        'g6_boot_v2_predecessor_guardian_source_sha256': source.BOOT_V2_SOURCE,
        'g6_boot_v2_predecessor_standing_config_sha256': source.BOOT_V2_STANDING,
        'pair_chain_controller_config_sha256': {**expected['controller_prefix_sha256'], 'g7pair': source.G7_CONFIG},
        **expected['unit_sha256'], **expected['ancestry_input_sha256'],
    }
    output = {'schema': contract.DERIVATION_SCHEMA, 'hub_profile': 'r13', 'units_source': 'staged',
              'standing_config_sha256': '3' * 64, 'standing_config_written': True,
              'input_sha256': inputs, 'review_text_printed': False, 'private_files_read': False}
    return output, expected


def declared_manifest():
    """Transient validator operands; these simulated CI rows are never artifacts."""
    runtime = json.loads((source.NEW / 'PACKAGE.json').read_bytes())
    commit = 'a' * 40
    identity = {'boot_id': '2b7e9be2-e45a-4cd5-86f2-6f0a3372576d', 'pid': 10,
                'start_ticks': 100, 'InvocationID': '1' * 32,
                'ExecMainStartTimestampMonotonic': '1000'}
    return {
        'schema': contract.PACKAGE_SCHEMA, 'source_commit': commit,
        'source_R': 'c9f260432ce5a10886df0385c958ec7d643648df',
        'amd64_D': source.G7_DIGEST.removeprefix('sha256:'),
        'runtime_package_sha256': source.digest((source.NEW / 'PACKAGE.json').read_bytes()),
        'files': runtime['files'],
        'tools': {name: source.digest((TOOLS / name).read_bytes()) for name in contract.TOOLS},
        'controller_unit_sha256': runtime['controller_unit_sha256'],
        'root_controller_review_sha256': '1' * 64, 'root_standing_review_sha256': '2' * 64,
        'continuity_peer_ipv4': '10.200.24.145',
        'expected_controller_identity': identity,
        'expected_guardian_identity': {**identity, 'pid': 20, 'InvocationID': '2' * 32},
        # Exact PUBLIC name/hash metadata from Root's read-only snapshot
        # 505e5d08-f733-4c87-8d0b-a2ecd28177ae (recorded in scratch).
        # Metadata is historical fixture input, never current health evidence.
        'protected_refs': [
            {'path': str(contract.LEDGER / ('2b7e9be2-e45a-4cd5-86f2-6f0a3372576d-GUARDIAN-'
                                           '651c798b400048929e705c00f8185931-FIRST-CURRENT15-READ-000.PUBLIC')),
             'sha256': 'b4e72700d714bafa9a32615b17c77891beb947d43d4513aadc5e933894cff731'},
            {'path': str(contract.LEDGER / ('2b7e9be2-e45a-4cd5-86f2-6f0a3372576d-GUARDIAN-'
                                           '651c798b400048929e705c00f8185931-FIRST-CURRENT15-READ-001.PUBLIC')),
             'sha256': 'b4e72700d714bafa9a32615b17c77891beb947d43d4513aadc5e933894cff731'},
            {'path': str(contract.LEDGER / ('100b6c2d207cb8e39a6b52839c7cddca65bd8e0dde90f86386cf57e686d05a92-'
                                           'QUALIFIED.PUBLIC.json')),
             'sha256': '21e4697326aa0e74b1e169a897870b10e4668328ca04d497900a2f297bc99a31'}],
        'ci_attestation': {'schema': 'guardian_g7_exact_source_ci_v1', 'commit': commit,
                           'reviewed_by_root': True, 'runs': [
                               {'id': n + 1, 'name': name,
                                'event': event, 'head_sha': commit,
                                'status': 'completed', 'conclusion': 'success', 'attempt': 1}
                               for n, (name, event) in enumerate(sorted(contract.REQUIRED_CI))]},
    }


class G7ToolTests(unittest.TestCase):
    def test_public_config_fixture_closed_keys_and_exact_pins(self):
        manifest = json.loads((FIXTURE / 'MANIFEST.json').read_bytes())
        self.assertEqual(len(manifest['files']), 9)
        controller_inputs()
        for name, facts in manifest['files'].items():
            with self.subTest(file=name):
                raw = (FIXTURE / name).read_bytes()
                value = json.loads(raw)
                self.assertEqual(set(value), derive.FIELDS)
                self.assertIs(type(value['execute']), bool)
                self.assertIn('https://', value['eks_endpoint'])
                self.assertNotIn(b'PRIVATE KEY', raw)
                self.assertTrue(facts['closed_public_8_keys'])
        self.assertEqual(source.digest((FIXTURE / 'controller.r13-netlink-g6pair.production.json').read_bytes()), source.G6_CONFIG)
        self.assertEqual(source.digest((FIXTURE / 'controller.r13-netlink-g7pair.production.json').read_bytes()), source.G7_CONFIG)

    def test_actual_tools_and_both_guardians_derive_exact_root_bytes(self):
        r42, prefix, expected = controller_inputs()
        review = json.loads(expected)['root_review_attestation']
        actual = derive.derive(r42, prefix, review)
        self.assertEqual(actual, expected)
        self.assertEqual(len(actual), 5175)
        self.assertEqual(source.digest(actual), source.G7_CONFIG)
        self.assertEqual(source.g7.pair_chain_controller_config_pure(r42, [*prefix, actual]), expected)
        self.assertEqual(source.g6.pair_chain_controller_config_pure(r42, prefix), prefix[-1])
        old, new = json.loads(prefix[-1]), json.loads(actual)
        self.assertEqual({key for key in old if old[key] != new[key]},
                         {'core_container_images', 'root_review_attestation'})

    def test_config_derivation_refuses_prefix_hash_order_review_and_head_mix(self):
        r42, prefix, expected = controller_inputs()
        review = json.loads(expected)['root_review_attestation']
        for index in range(len(prefix)):
            wrong = list(prefix)
            wrong[index] += b' '
            with self.subTest(prefix=index), self.assertRaises(derive.Refused):
                derive.derive(r42, wrong, review)
        for wrong in (prefix[:-1], list(reversed(prefix)), [*prefix, prefix[-1]]):
            with self.assertRaises(derive.Refused):
                derive.derive(r42, wrong, review)
        for wrong_review in (json.loads(prefix[-1])['root_review_attestation'], 'arbitrary non-Root config review ' * 8):
            with self.assertRaises(derive.Refused):
                derive.derive(r42, prefix, wrong_review)
        with self.assertRaises(derive.Refused):
            derive.derive(r42 + b' ', prefix, review)

    def test_descriptor_preserves_actual_old_roster_and_dual_ancestry(self):
        old = json.loads((source.OLD / 'PACKAGE.json').read_bytes())
        self.assertEqual(set(contract.MODULES), {'network_guardian.py', *source.HELPERS})
        self.assertEqual(len(contract.MODULES), 8)
        self.assertEqual(contract.HELPERS, {name: old['files']['source/' + name] for name in source.HELPERS})
        self.assertEqual(contract.OLD_UNIT_SHAS[contract.COLD], old['files']['units/' + contract.COLD])
        self.assertEqual(contract.OLD_UNIT_SHAS[contract.GUARD], old['files']['units/' + contract.GUARD])
        self.assertEqual(contract.OLD_UNIT_SHAS[contract.CTRL], old['unchanged_controller_unit_sha256'])
        self.assertEqual(contract.ANCESTORS, {
            'g6_predecessor_guardian_source_sha256': source.CANONICAL_SOURCE,
            'g6_predecessor_standing_config_sha256': source.CANONICAL_STANDING,
            'g6_boot_v2_predecessor_guardian_source_sha256': source.BOOT_V2_SOURCE,
            'g6_boot_v2_predecessor_standing_config_sha256': source.BOOT_V2_STANDING})
        self.assertEqual(contract.PREFIX_STANDINGS, {row[0]: row[4] for row in source.g7.PAIR_STANDING_CHAIN})
        self.assertEqual(contract.G6_CONFIG_SHA, source.G6_CONFIG)
        self.assertEqual(contract.G7_CONFIG_SHA, source.G7_CONFIG)
        self.assertEqual('sha256:' + contract.NEW_DIGEST, source.G7_DIGEST)
        self.assertEqual(set(contract.TOOLS), {'pair_change_contract.py', 'derive_g7pair_controller_config.py',
                                             'derive_standing_config.py', 'g7cut.py'})
        checksum_rows = [line.split() for line in (TOOLS / 'SHA256SUMS').read_text().splitlines()]
        self.assertTrue(all(len(row) == 2 for row in checksum_rows))
        checksum_pins = {name: pin for pin, name in checksum_rows}
        self.assertEqual(len(checksum_pins), len(checksum_rows))
        self.assertEqual(checksum_pins, {name: source.digest((TOOLS / name).read_bytes()) for name in contract.TOOLS})
        actual_cli = load_tool('g7cut')
        declared_source = b'DECLARED_SOURCE_BYTES = "CI-only exact .py loader operand"\n'
        for loader in (lambda: actual_cli.sibling('pair_change_contract'), standing_derive._contract):
            with patch.object(Path, 'read_bytes', return_value=declared_source) as read:
                loaded = loader()
                self.assertEqual(loaded.DECLARED_SOURCE_BYTES, 'CI-only exact .py loader operand')
                self.assertEqual(Path(loaded.__file__), TOOLS / 'pair_change_contract.py')
                read.assert_called_once_with()

    def test_actual_closed_standing_output_accepts_staged_and_live(self):
        value, expected = declared_derivation()
        for mode in ('staged', 'live'):
            with self.subTest(mode=mode):
                value['units_source'] = mode
                self.assertEqual(contract.validate_standing_output(value, expected, mode), '3' * 64)

    def test_actual_standing_deriver_uses_real_source_builder_and_closed_delta(self):
        _, _, controller_raw = controller_inputs()
        runtime = json.loads((source.NEW / 'PACKAGE.json').read_bytes())
        old = source.standing(source.g6)
        # Declared public bytes, never an installed Hub seal or private fixture.
        hub_raw = b'declared-CI-public-Hub-schema-operand-without-native-authority'
        old['hub_boot_config_sha256'] = source.digest(hub_raw)
        units = {contract.CTRL: runtime['controller_unit_sha256'],
                 contract.COLD: runtime['files']['units/' + contract.COLD],
                 contract.GUARD: runtime['files']['units/' + contract.GUARD],
                 contract.HUB: old['hub_unit_sha256']}
        original = copy.deepcopy(old)
        review = 'Declared new G7 CI review; no native operation or installed authority. ' * 4
        value = standing_derive.build(source.g7, runtime, old, controller_raw, hub_raw, review, units)
        self.assertEqual(old, original)
        self.assertEqual(set(value) - set(old), {
            'g6_boot_v2_predecessor_guardian_source_sha256',
            'g6_boot_v2_predecessor_standing_config_sha256'})
        self.assertEqual({key for key in old if old[key] != value[key]},
                         {'schema', 'guardian_source_sha256', 'controller_unit_sha256',
                          'cold_unit_sha256', 'guardian_unit_sha256',
                          'new_controller_config_sha256', 'Root_review'})
        self.assertTrue(all(value[key] == old[key] for key in source.SHARED_STANDING))
        for key, wrong in (('guardian_source_sha256', source.CANONICAL_SOURCE),
                           ('new_controller_config_sha256', source.G7_CONFIG),
                           ('g6_predecessor_standing_config_sha256', source.BOOT_V2_STANDING)):
            bad = copy.deepcopy(old)
            bad[key] = wrong
            with self.subTest(old_field=key), self.assertRaises(standing_derive.C.Hold):
                standing_derive.build(source.g7, runtime, bad, controller_raw, hub_raw, review, units)
        for wrong_controller, wrong_hub, wrong_review in (
                (controller_raw + b' ', hub_raw, review),
                (controller_raw, hub_raw + b'changed', review),
                (controller_raw, hub_raw, old['Root_review'])):
            with self.assertRaises(standing_derive.C.Hold):
                standing_derive.build(source.g7, runtime, old, wrong_controller, wrong_hub, wrong_review, units)

    def test_closed_manifest_accepts_exact_source8_units2_tools4_shape(self):
        value = declared_manifest()
        self.assertIs(contract.validate_manifest(value), value)
        self.assertEqual(len(value['files']), 10)
        self.assertEqual(len(value['tools']), 4)
        for raw in (b'{"key":1,"key":2}', b'{"key":NaN}', b'{"key":Infinity}', b'{"key":1e999}'):
            with self.subTest(raw=raw), self.assertRaises(contract.Hold):
                contract.loads(raw)

    def test_manifest_refuses_old_seven_modules_wrong_helpers_and_mixed_identity(self):
        value = declared_manifest()
        mutations = [
            lambda v: v['files'].pop('source/qualification_initializer.py'),
            lambda v: v['files'].update({'source/unreviewed.py': '3' * 64}),
            lambda v: v['files'].update({'source/current15_bounded_reader.py': '3' * 64}),
            lambda v: v['tools'].pop('g7cut.py'),
            lambda v: v['tools'].update({'legacy_retry.py': '3' * 64}),
            lambda v: v.update({'amd64_D': source.G6_DIGEST.removeprefix('sha256:')}),
            lambda v: v.update({'continuity_peer_ipv4': '8.8.8.8'}),
            lambda v: v['expected_guardian_identity'].update({'pid': v['expected_controller_identity']['pid']}),
            lambda v: v['expected_guardian_identity'].update({'boot_id': '00000000-0000-0000-0000-000000000000'}),
            lambda v: v['protected_refs'][0].update({'path': '/tmp/foreign-unowned.json'}),
            lambda v: v['protected_refs'][0].update({'path': str(contract.LEDGER / 'foreign.PUBLIC.json.bak')}),
            lambda v: v['ci_attestation']['runs'][0].update({'head_sha': 'b' * 40}),
            lambda v: v['ci_attestation']['runs'][0].update({'conclusion': 'failure'}),
            lambda v: v['ci_attestation']['runs'].pop(),
            lambda v: v['ci_attestation']['runs'][0].update({'name': 'unreviewed-workflow'}),
            lambda v: v['ci_attestation']['runs'][0].update({'attempt': True}),
            lambda v: v['ci_attestation']['runs'][0].update({'attempt': 0}),
        ]
        for index, mutate in enumerate(mutations):
            changed = copy.deepcopy(value)
            mutate(changed)
            with self.subTest(mutation=index), self.assertRaises(contract.Hold):
                contract.validate_manifest(changed)

    def test_output_refuses_ancestry_prefix_controller_roster_and_unit_mix(self):
        value, expected = declared_derivation()
        mutations = [
            lambda v: v.update({'unknown_output': True}),
            lambda v: v.update({'units_source': 'live'}),
            lambda v: v.update({'standing_config_sha256': '0' * 64}),
            lambda v: v.update({'standing_config_written': False}),
            lambda v: v.update({'private_files_read': True}),
            lambda v: v.update({'review_text_printed': True}),
        ]
        for key in contract.ANCESTORS:
            mutations += [lambda v, k=key: v['input_sha256'].pop(k),
                          lambda v, k=key: v['input_sha256'].update({k: '0' * 64})]
        mutations += [
            lambda v: v['input_sha256'].update({'head_core_digest': source.G6_DIGEST}),
            lambda v: v['input_sha256'].update({'head_controller_config_sha256': source.G6_CONFIG}),
            lambda v: v['input_sha256'].update({'historical_g6_controller_config_sha256': source.G7_CONFIG}),
            lambda v: v['input_sha256']['pair_predecessor_standing_config_sha256'].pop('g5pair'),
            lambda v: v['input_sha256']['pair_predecessor_standing_config_sha256'].update({'g6pair': source.CANONICAL_STANDING}),
            lambda v: v['input_sha256']['pair_chain_controller_config_sha256'].update({'g6pair': source.G7_CONFIG}),
            lambda v: v['input_sha256'].update({contract.COLD: contract.OLD_UNIT_SHAS[contract.COLD]}),
            lambda v: v['input_sha256'].update({contract.GUARD: contract.OLD_UNIT_SHAS[contract.GUARD]}),
        ]
        for index, mutate in enumerate(mutations):
            changed = copy.deepcopy(value)
            mutate(changed)
            with self.subTest(mutation=index), self.assertRaises(contract.Hold):
                contract.validate_standing_output(changed, expected, 'staged')
        for key in expected:
            changed = copy.deepcopy(expected)
            del changed[key]
            with self.subTest(expected_missing=key), self.assertRaises(contract.Hold):
                contract.validate_standing_output(value, changed, 'staged')
        for field, input_key in ((contract.HUB, contract.HUB),
                                  ('r13_base_controller_config_sha256', 'r13_base_controller_config_sha256')):
            changed_expected, changed_value = copy.deepcopy(expected), copy.deepcopy(value)
            if field == contract.HUB:
                changed_expected['unit_sha256'][field] = '4' * 64
            else:
                changed_expected['ancestry_input_sha256'][field] = '4' * 64
            changed_value['input_sha256'][input_key] = '4' * 64
            with self.subTest(contradictory_join=field), self.assertRaises(contract.Hold):
                contract.validate_standing_output(changed_value, changed_expected, 'staged')


if __name__ == '__main__':
    unittest.main()
