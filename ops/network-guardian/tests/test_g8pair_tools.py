"""CI of actual G8 derivers/contracts using public configuration history only."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

import test_g7pair_tools as prior
import test_g8pair_source as source


TOOLS = source.NEW / 'tools'
REQUIRED_CI = frozenset({
    ('Capacity intent PostgreSQL protocol', 'pull_request'),
    ('Capacity source-owned HTTP qualification', 'pull_request'),
    ('Context Freshness (ADR + durable context)', 'pull_request'),
    ('Docs freshness', 'pull_request'),
    ('Failed installed Guest administrative HTTP Source', 'pull_request'),
    ('Failed serving Guest Source and PostgreSQL', 'pull_request'),
    ('Guest historical unknown read recovery', 'pull_request'),
    ('Installed Guest reconciliation Source', 'pull_request'),
    ('Native OIDC protocol integration', 'pull_request'),
    ('Original Guest Core source and PostgreSQL gates', 'pull_request'),
    ('Original Guest Core source and PostgreSQL gates', 'push'),
    ('Original and native denied disposition Source', 'pull_request'),
    ('Owned Network Guardian', 'pull_request'),
    ('Partial Guest native OFF reconciliation Source', 'pull_request'),
    ('Protected native capacity API qualification', 'pull_request'),
    ('Service contract', 'pull_request'), ('Service contract', 'push'),
    ('template-go-api CI', 'pull_request'),
})


def load_tool(name):
    path = TOOLS / (name + '.py')
    spec = importlib.util.spec_from_file_location('g8pair_tools_test_' + name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


contract = load_tool('pair_change_contract')
derive = load_tool('derive_g8pair_controller_config')
standing_derive = load_tool('derive_standing_config')


def controller_inputs():
    r42, prefix, g7raw = prior.controller_inputs()
    path = source.CONFIGS / 'controller.r13-netlink-g8pair.production.json'
    manifest = json.loads((source.CONFIGS / 'MANIFEST.PUBLIC.json').read_bytes())
    raw = path.read_bytes()
    facts = manifest['files'][path.name]
    if len(raw) != facts['bytes'] or source.digest(raw) != facts['sha256'] or facts['sha256'] != source.G8_CONFIG:
        raise AssertionError('actual Root public G8 controller bytes changed')
    return r42, [*prefix, g7raw], raw


def protected_refs():
    value = json.loads((source.STANDINGS / 'PROTECTED-REFERENCES.PUBLIC.json').read_bytes())
    return dict(value['expected_complete_map'])


def declared_manifest():
    """Transient CI validator inputs, never a claim of actual CI/installed state."""
    value = copy.deepcopy(prior.declared_manifest())
    package = json.loads((source.NEW / 'PACKAGE.json').read_bytes())
    commit = value['source_commit']
    value.update({'schema': contract.PACKAGE_SCHEMA, 'source_R': source.SOURCE_R,
                  'amd64_D': source.G8_DIGEST.removeprefix('sha256:'),
                  'runtime_package_sha256': source.digest((source.NEW / 'PACKAGE.json').read_bytes()),
                  'files': package['files'], 'controller_unit_sha256': package['controller_unit_sha256'],
                  'tools': {name: source.digest((TOOLS / name).read_bytes()) for name in contract.TOOLS},
                  'protected_refs': [{'path': path, 'sha256': pin} for path, pin in sorted(protected_refs().items())],
                  'ci_attestation': {'schema': 'guardian_g8_exact_source_ci_v1', 'commit': commit,
                                     'reviewed_by_root': True, 'runs': [
                                         {'id': n + 1, 'name': name, 'event': event, 'head_sha': commit,
                                          'status': 'completed', 'conclusion': 'success', 'attempt': 1}
                                         for n, (name, event) in enumerate(sorted(REQUIRED_CI))]}})
    return value


def declared_derivation():
    value, expected = copy.deepcopy(prior.declared_derivation())
    expected['source_sha256'] = source.digest((source.NEW / 'source/network_guardian.py').read_bytes())
    expected['controller_prefix_sha256'] = {generation: pin for generation, _, _, pin in derive.PAIR_CHAIN[:-1]}
    expected['ancestry_input_sha256']['r13_base_controller_config_sha256'] = expected['controller_prefix_sha256']['base']
    inputs = {'successor_guardian_source_sha256': expected['source_sha256'],
              'head_generation': 'g8pair', 'head_core_digest': source.G8_DIGEST,
              'head_controller_config_sha256': source.G8_CONFIG,
              'historical_g6_controller_config_sha256': source.prior.G6_CONFIG,
              'pair_predecessor_standing_config_sha256': dict(contract.PREFIX_STANDINGS),
              'g6_predecessor_guardian_source_sha256': source.prior.CANONICAL_SOURCE,
              'g6_predecessor_standing_config_sha256': source.prior.CANONICAL_STANDING,
              'g6_boot_v2_predecessor_guardian_source_sha256': source.prior.BOOT_V2_SOURCE,
              'g6_boot_v2_predecessor_standing_config_sha256': source.prior.BOOT_V2_STANDING,
              'g7_predecessor_guardian_source_sha256': source.G7_SOURCE,
              'g7_predecessor_standing_config_sha256': source.G7_STANDING,
              'pair_chain_controller_config_sha256': {**expected['controller_prefix_sha256'], 'g8pair': source.G8_CONFIG},
              **expected['unit_sha256'], **expected['ancestry_input_sha256']}
    value.update(schema=contract.DERIVATION_SCHEMA, input_sha256=inputs)
    return value, expected


class G8ToolTests(unittest.TestCase):
    def test_public_g8_fixture_has_exact_closed_eight_keys_and_root_hash(self):
        _, _, raw = controller_inputs()
        value = json.loads(raw)
        self.assertEqual(set(value), {'schema', 'execute', 'source_files_sha256', 'eks_endpoint',
                                     'eks_public_ca_base64', 'core_service_uid', 'core_container_images', 'root_review_attestation'})
        self.assertEqual(source.digest(raw), source.G8_CONFIG)
        self.assertEqual(len(raw), 5705)
        self.assertNotIn(b'PRIVATE KEY', raw)

    def test_actual_deriver_and_g8_source_reproduce_exact_root_controller_bytes(self):
        r42, prefix, expected = controller_inputs()
        actual = derive.derive(r42, prefix, json.loads(expected)['root_review_attestation'])
        self.assertEqual(actual, expected)
        self.assertEqual(source.g8.pair_chain_controller_config_pure(r42, [*prefix, actual]), expected)
        self.assertEqual(source.prior.g7.pair_chain_controller_config_pure(r42, prefix), prefix[-1])
        self.assertEqual({key for key in json.loads(prefix[-1]) if json.loads(prefix[-1])[key] != json.loads(actual)[key]},
                         {'core_container_images', 'root_review_attestation'})

    def test_config_deriver_refuses_every_historical_mix_and_wrong_review(self):
        r42, prefix, expected = controller_inputs()
        review = json.loads(expected)['root_review_attestation']
        for index in range(len(prefix)):
            wrong = list(prefix)
            wrong[index] += b' '
            with self.subTest(index=index), self.assertRaises(derive.Refused):
                derive.derive(r42, wrong, review)
        for wrong in (prefix[:-1], list(reversed(prefix)), [*prefix, prefix[-1]]):
            with self.assertRaises(derive.Refused):
                derive.derive(r42, wrong, review)
        for wrong in (json.loads(prefix[-1])['root_review_attestation'], 'unapproved declared review ' * 10):
            with self.assertRaises(derive.Refused):
                derive.derive(r42, prefix, wrong)
        with self.assertRaises(derive.Refused):
            derive.derive(r42 + b' ', prefix, review)

    def test_contract_preserves_three_authorities_helpers_and_exact_39_original_refs(self):
        self.assertEqual(set(contract.MODULES), {'network_guardian.py', *source.prior.HELPERS})
        self.assertEqual(contract.HELPERS, {name: source.digest((source.OLD / 'source' / name).read_bytes())
                                           for name in source.prior.HELPERS})
        old = json.loads((source.OLD / 'PACKAGE.json').read_bytes())
        self.assertEqual(contract.OLD_UNIT_SHAS[contract.CTRL], old['controller_unit_sha256'])
        for name in (contract.COLD, contract.GUARD):
            self.assertEqual(contract.OLD_UNIT_SHAS[name], old['files']['units/' + name])
        self.assertEqual(contract.ANCESTORS, {key: current for key, current in source.current_standing().items()
                         if key.startswith(('g6_predecessor_', 'g6_boot_v2_predecessor_', 'g7_predecessor_'))})
        self.assertEqual(contract.PREFIX_STANDINGS, {row[0]: row[4] for row in source.prior.g7.PAIR_STANDING_CHAIN})
        self.assertEqual(contract.EXPECTED_INHERITED_REFS, protected_refs())
        self.assertEqual(len(protected_refs()), 39)
        self.assertEqual(len([p for p in protected_refs() if '-RECOVERY-' in p and p.endswith('-POSSIBLE-START.PUBLIC.json')]), 1)
        self.assertEqual(contract.HEAD_CONFIG_SHA, source.G8_CONFIG)
        self.assertEqual(contract.G7_CONFIG_SHA, source.prior.G7_CONFIG)
        self.assertEqual(contract.G6_CONFIG_SHA, source.prior.G6_CONFIG)

    def test_actual_standing_builder_adds_only_g7_axis_and_seven_head_fields(self):
        _, _, raw = controller_inputs()
        package = json.loads((source.NEW / 'PACKAGE.json').read_bytes())
        old = json.loads(source.history_bytes('g7pair'))
        # Only this pure build test uses a declared Hub body; no actual Hub
        # config or installed standing hash is substituted or claimed.
        hub = b'declared-public-CI-Hub-body-without-native-authority'
        old['hub_boot_config_sha256'] = source.digest(hub)
        units = {contract.CTRL: package['controller_unit_sha256'], contract.HUB: old['hub_unit_sha256'],
                 contract.COLD: package['files']['units/' + contract.COLD],
                 contract.GUARD: package['files']['units/' + contract.GUARD]}
        original = copy.deepcopy(old)
        review = 'Declared G8 Source build CI fixture; no installed/native approval. ' * 4
        value = standing_derive.build(source.g8, package, old, raw, hub, review, units)
        self.assertEqual(old, original)
        self.assertEqual(set(value) - set(old), {'g7_predecessor_guardian_source_sha256', 'g7_predecessor_standing_config_sha256'})
        self.assertEqual({key for key in old if old[key] != value[key]},
                         {'schema', 'guardian_source_sha256', 'controller_unit_sha256', 'cold_unit_sha256',
                          'guardian_unit_sha256', 'new_controller_config_sha256', 'Root_review'})
        for wrong in (raw + b' ', controller_inputs()[1][-1]):
            with self.assertRaises(standing_derive.C.Hold):
                standing_derive.build(source.g8, package, old, wrong, hub, review, units)

    def test_closed_derivation_output_accepts_staged_and_live_and_refuses_axis_mix(self):
        value, expected = declared_derivation()
        for mode in ('staged', 'live'):
            operand = copy.deepcopy(value)
            operand['units_source'] = mode
            self.assertEqual(contract.validate_standing_output(operand, expected, mode), '3' * 64)
        for key in contract.ANCESTORS:
            wrong = copy.deepcopy(value)
            wrong['input_sha256'][key] = '4' * 64
            with self.subTest(axis=key), self.assertRaises(contract.Hold):
                contract.validate_standing_output(wrong, expected, 'staged')
        for change in ('missing-g7', 'wrong-g7', 'wrong-head', 'extra-prefix', 'wrong-unit', 'wrong-hub'):
            wrong = copy.deepcopy(value)
            if change == 'missing-g7':
                del wrong['input_sha256']['pair_chain_controller_config_sha256']['g7pair']
            elif change == 'wrong-g7':
                wrong['input_sha256']['pair_chain_controller_config_sha256']['g7pair'] = source.prior.G6_CONFIG
            elif change == 'wrong-head':
                wrong['input_sha256']['head_controller_config_sha256'] = source.prior.G7_CONFIG
            elif change == 'extra-prefix':
                wrong['input_sha256']['pair_predecessor_standing_config_sha256']['g7pair'] = source.G7_STANDING
            elif change == 'wrong-unit':
                wrong['input_sha256'][contract.COLD] = contract.OLD_UNIT_SHAS[contract.COLD]
            else:
                wrong['input_sha256']['hub_unit_sha256'] = '5' * 64
            with self.subTest(change=change), self.assertRaises(contract.Hold):
                contract.validate_standing_output(wrong, expected, 'staged')

    def test_closed_manifest_accepts_only_exact_runtime_tools_refs_and_ci_roster(self):
        value = declared_manifest()
        self.assertEqual(contract.validate_manifest(value), value)
        self.assertEqual(contract.REQUIRED_CI, REQUIRED_CI)
        self.assertEqual(len(REQUIRED_CI), 18)
        rows = [line.split() for line in (TOOLS / 'SHA256SUMS').read_text().splitlines()]
        self.assertEqual(len(rows), 4)
        self.assertEqual({name: pin for pin, name in rows},
                         {name: source.digest((TOOLS / name).read_bytes()) for name in contract.TOOLS})

    def test_manifest_refuses_ref_loss_duplicates_and_future_or_foreign_authority(self):
        for change in ('missing', 'duplicate', 'wrong-sha', 'foreign-path', 'old37', 'old-runtime', 'extra-module', 'old-source-R'):
            value = declared_manifest()
            if change == 'missing':
                value['protected_refs'].pop()
            elif change == 'duplicate':
                value['protected_refs'][-1] = copy.deepcopy(value['protected_refs'][0])
            elif change == 'wrong-sha':
                value['protected_refs'][0]['sha256'] = '9' * 64
            elif change == 'foreign-path':
                value['protected_refs'][0]['path'] = '/tmp/foreign.PUBLIC.json'
            elif change == 'old37':
                value['protected_refs'] = value['protected_refs'][:-2]
            elif change == 'old-runtime':
                del value['files']['source/qualification_initializer.py']
            elif change == 'extra-module':
                value['files']['source/invented.py'] = '9' * 64
            else:
                value['source_R'] = 'c9f260432ce5a10886df0385c958ec7d643648df'
            with self.subTest(change=change), self.assertRaises(contract.Hold):
                contract.validate_manifest(value)

    def test_manifest_refuses_missing_wrong_event_dirty_head_and_unsuccessful_ci(self):
        for change in ('missing', 'duplicate-id', 'wrong-event', 'wrong-head', 'failure', 'zero-attempt', 'unreviewed'):
            value = declared_manifest()
            runs = value['ci_attestation']['runs']
            if change == 'missing':
                runs.pop()
            elif change == 'duplicate-id':
                runs[-1]['id'] = runs[0]['id']
            elif change == 'wrong-event':
                runs[0]['event'] = 'workflow_dispatch'
            elif change == 'wrong-head':
                runs[0]['head_sha'] = 'b' * 40
            elif change == 'failure':
                runs[0]['conclusion'] = 'failure'
            elif change == 'zero-attempt':
                runs[0]['attempt'] = 0
            else:
                value['ci_attestation']['reviewed_by_root'] = False
            with self.subTest(change=change), self.assertRaises(contract.Hold):
                contract.validate_manifest(value)
