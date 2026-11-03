"""Real G9 pure functions under explicitly declared CI-only bindings."""
import contextlib
import copy
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import test_g8pair_tools as old
import test_g9pair_source as source


TOOLS = source.NEW / 'tools'


def load_tool(name):
    path = TOOLS / (name + '.py')
    spec = importlib.util.spec_from_file_location('g9_tool_declared_CI_' + name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


contract = load_tool('pair_change_contract')
derive = load_tool('derive_g9pair_controller_config')
standing = load_tool('derive_standing_config')
G8_REFS = {
    '/var/lib/dakasa-capacity-network-recovery/d323cc228bec43596ac73c99cc473298896b8f2d88b06219aa69a549633925b3-QUALIFIED.PUBLIC.json':
    '68f5b3bcd33a9ab8e1ad29f3fdbf52a83166b694b81f5bce474e2fe85afecce3',
    '/var/lib/dakasa-capacity-network-recovery/2b7e9be2-e45a-4cd5-86f2-6f0a3372576d-GUARDIAN-a1826878088e4dbaa5e7adfb67cba5c6-FIRST-CURRENT15-RETURN.PUBLIC.json':
    'e406648a4ecd503ff8231e5fde8d6969a091fe9327c4e8e0927815eb929711c4',
}


@contextlib.contextmanager
def declared_binding(*contracts):
    """Patch inputs only, not any validator, hash, I/O or effect predicate."""
    new_digest, raw = source.controller_operand()
    selected = {id(c): c for c in (contract, standing.C, *contracts)}
    with contextlib.ExitStack() as stack:
        stack.enter_context(source.source_binding())
        for c in selected.values():
            stack.enter_context(patch.multiple(c, PROPOSAL_BOUND=True, NEW_DIGEST=new_digest,
                G9_CONFIG_SHA=source.digest(raw), HEAD_CONFIG_SHA=source.digest(raw),
                OLD_CORE_GENERATION=272, OLD_CORE_POD_UID='11111111-1111-4111-8111-111111111111',
                EXPECTED_G8_PROOF_REFS=dict(G8_REFS),
                ROOT_G8_REF_ACCEPTANCE_SHA=source.digest(b'declared CI reference review; no Root approval')))
        pairs = source.g9.G9_CORE_IMAGE_PAIRS
        stack.enter_context(patch.multiple(derive, PROPOSAL_BOUND=True,
            HEAD_NEW_CORE_DIGEST='sha256:' + new_digest, CORE_G9=source.g9.CORE_G9,
            G9_CONFIG_SHA=source.digest(raw), G9_CORE_IMAGE_PAIRS=pairs,
            PAIR_CHAIN=(*derive.PAIR_CHAIN[:-1], ('g9pair', pairs, derive.G9_CONFIG, None))))
        yield raw


def controller_inputs():
    r42, prefix, last = old.controller_inputs()
    return r42, [*prefix, last]


def protected_refs():
    return {**old.protected_refs(), **G8_REFS}


def declared_manifest():
    """Validator data only; no actual package, CI success or native receipt."""
    value = copy.deepcopy(old.declared_manifest())
    value.update(schema=contract.PACKAGE_SCHEMA, source_R=contract.SOURCE_R,
                 amd64_D=contract.NEW_DIGEST,
                 runtime_package_sha256=source.digest(b'declared CI package envelope'),
                 files={str(p.relative_to(source.NEW)): source.digest(p.read_bytes())
                        for folder in ('source', 'units') for p in (source.NEW / folder).iterdir() if p.is_file()},
                 tools={name: source.digest((TOOLS / name).read_bytes()) for name in contract.TOOLS},
                 controller_unit_sha256=source.digest(b'declared CI future controller unit'),
                 protected_refs=[{'path': path, 'sha256': pin} for path, pin in sorted(protected_refs().items())])
    value['ci_attestation'].update(schema='guardian_g9_exact_source_ci_v1')
    return value


class G9ToolTests(unittest.TestCase):
    def test_unbound_derivers_and_package_fail_without_filesystem_access(self):
        with patch.object(derive, 'PROPOSAL_BOUND', False), patch.object(derive, 'read_private') as read:
            with self.assertRaisesRegex(derive.Refused, 'G9_RELEASE_AND_ROOT_CONFIG_NOT_BOUND'):
                derive.derive(b'{}', [], 'declared review ' * 12)
            read.assert_not_called()
        with patch.object(contract, 'PROPOSAL_BOUND', False), patch.object(contract, 'read') as read:
            with self.assertRaises(contract.Hold):
                contract.package(Path('/never-read'), '1' * 64)
            read.assert_not_called()

    def test_actual_deriver_and_guardian_agree_with_exact_declared_two_field_delta(self):
        r42, prefix = controller_inputs()
        with declared_binding() as expected:
            actual = derive.derive(r42, prefix, json.loads(expected)['root_review_attestation'])
            self.assertEqual(actual, expected)
            self.assertEqual(source.g9.pair_chain_controller_config_pure(r42, [*prefix, actual]), expected)
            old_value, new_value = json.loads(prefix[-1]), json.loads(actual)
            self.assertEqual({k for k in old_value if old_value[k] != new_value[k]},
                             {'core_container_images', 'root_review_attestation'})

    def test_real_deriver_refuses_changed_prefix_order_reviews_and_zero_or_reused_head(self):
        r42, prefix = controller_inputs()
        with declared_binding() as expected:
            review = json.loads(expected)['root_review_attestation']
            for index in range(len(prefix)):
                changed = list(prefix)
                changed[index] += b' '
                with self.subTest(link=index), self.assertRaises(derive.Refused):
                    derive.derive(r42, changed, review)
            for changed in (prefix[:-1], list(reversed(prefix)), [*prefix, prefix[-1]]):
                with self.assertRaises(derive.Refused):
                    derive.derive(r42, changed, review)
            with self.assertRaises(derive.Refused):
                derive.derive(r42, prefix, json.loads(prefix[-1])['root_review_attestation'])
            for image in (source.g9.CORE_G7, derive.CORE_IMAGE_REF + 'sha256:' + '0' * 64):
                pairs = [derive.G8_CORE_IMAGE_PAIRS[-1], {'image': image, 'image_id': image}]
                with self.subTest(image=image), patch.object(derive, 'PAIR_CHAIN', (*derive.PAIR_CHAIN[:-1],
                        ('g9pair', pairs, derive.G9_CONFIG, None))), self.assertRaises(derive.Refused):
                    derive.derive(r42, prefix, review)

    def test_four_ancestry_axes_and_41_ref_union_cannot_replace_old_bytes(self):
        self.assertEqual(len(contract.ANCESTORS), 8)
        self.assertEqual(contract.EXPECTED_INHERITED_REFS, old.protected_refs())
        self.assertEqual(len(old.protected_refs()), 39)
        with declared_binding():
            self.assertEqual(contract.protected_ref_union(), protected_refs())
            self.assertEqual(len(contract.protected_ref_union()), 41)
            path = next(iter(contract.EXPECTED_INHERITED_REFS))
            clash = {path: '9' * 64, next(iter(G8_REFS)): next(iter(G8_REFS.values()))}
            with patch.object(contract, 'EXPECTED_G8_PROOF_REFS', clash), self.assertRaises(contract.Hold):
                contract.protected_ref_union()

    def test_closed_manifest_requires_all_actual_test_file_pins_refs_and_ci_events(self):
        with declared_binding():
            value = declared_manifest()
            contract.validate_manifest(value)
            self.assertEqual(contract.REQUIRED_CI, old.REQUIRED_CI)
            for change in ('old39', 'duplicate-ref', 'wrong-head', 'failed-ci', 'missing-ci', 'foreign-axis-helper'):
                value = declared_manifest()
                if change == 'old39':
                    value['protected_refs'] = value['protected_refs'][:-2]
                elif change == 'duplicate-ref':
                    value['protected_refs'][-1] = copy.deepcopy(value['protected_refs'][0])
                elif change == 'wrong-head':
                    value['ci_attestation']['runs'][0]['head_sha'] = 'b' * 40
                elif change == 'failed-ci':
                    value['ci_attestation']['runs'][0]['conclusion'] = 'failure'
                elif change == 'missing-ci':
                    value['ci_attestation']['runs'].pop()
                else:
                    value['files']['source/coverage.py'] = '9' * 64
                with self.subTest(change=change), self.assertRaises(contract.Hold):
                    contract.validate_manifest(value)

    def test_real_standing_builder_changes_only_two_new_axes_and_seven_head_fields(self):
        with declared_binding() as raw:
            previous = json.loads(source.history('g8pair'))
            hub = b'declared CI Hub body only; not an actual native seal'
            previous['hub_boot_config_sha256'] = source.digest(hub)
            m = declared_manifest()
            units = {contract.CTRL: m['controller_unit_sha256'], contract.HUB: previous['hub_unit_sha256'],
                     contract.COLD: m['files']['units/' + contract.COLD],
                     contract.GUARD: m['files']['units/' + contract.GUARD]}
            value = standing.build(source.g9, m, previous, raw, hub, 'Declared CI standing review. ' * 8, units)
            self.assertEqual(set(value) - set(previous), {'g8_predecessor_guardian_source_sha256',
                                                        'g8_predecessor_standing_config_sha256'})
            self.assertEqual({k for k in previous if previous[k] != value[k]},
                {'schema', 'guardian_source_sha256', 'controller_unit_sha256', 'cold_unit_sha256',
                 'guardian_unit_sha256', 'new_controller_config_sha256', 'Root_review'})
            self.assertTrue(all(value[k] == v for k, v in contract.ANCESTORS.items()))
