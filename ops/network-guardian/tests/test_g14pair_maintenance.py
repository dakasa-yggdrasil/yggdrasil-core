"""Declared G14 operands only; no OCI, approval or native lifetime claim."""
import ast
import contextlib
import copy
import json
from pathlib import Path
import unittest
from unittest.mock import patch
from types import SimpleNamespace

import test_g13pair_maintenance as historical

ROOT = historical.ROOT
NEW = ROOT / 'g14pair'
load, digest = historical.load, historical.digest
G = load(NEW / 'source/network_guardian.py')
C = load(NEW / 'tools/pair_change_contract.py')
D = load(NEW / 'tools/derive_g14pair_controller_config.py')
S = load(NEW / 'tools/derive_standing_config.py', True)
CUT = load(NEW / 'tools/g14cut.py', True)


def source_span(path, owner, name):
    raw = path.read_text()
    tree = ast.parse(raw)
    parent = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == owner)
    node = next(node for node in parent.body if isinstance(node, ast.FunctionDef) and node.name == name)
    return ''.join(raw.splitlines(keepends=True)[node.lineno - 1:node.end_lineno])


def g13_operand():
    value = copy.deepcopy(historical.g12_operand())
    package = json.loads((historical.NEW / 'PACKAGE.json').read_bytes())
    value.update(schema=historical.G.SCHEMA,
                 g12_predecessor_guardian_source_sha256=G.G12_PREDECESSOR_SOURCE_SHA,
                 g12_predecessor_standing_config_sha256=G.G12_PREDECESSOR_CONFIG_SHA,
                 guardian_source_sha256=G.G13_PREDECESSOR_SOURCE_SHA,
                 new_controller_config_sha256=G.G13_CONTROLLER_CONFIG_SHA,
                 controller_unit_sha256=package['controller_unit_sha256'],
                 cold_unit_sha256=package['files']['units/' + G.COLD],
                 guardian_unit_sha256=package['files']['units/' + G.GUARDIAN],
                 Root_review='Declared G13 prior standing operand; never installed-state evidence. ' * 3)
    return value


@contextlib.contextmanager
def binding():
    """Bind only declared CI operands, keeping actual production validators."""
    new_digest = digest(b'declared G14 image; not an OCI artifact')
    image = G.CORE_IMAGE_REF + 'sha256:' + new_digest
    pairs = [{'image': G.CORE_G13, 'image_id': G.CORE_G13}, {'image': image, 'image_id': image}]
    chain = (*G.PAIR_CHAIN[:-1], ('g14pair', pairs, G.NEW_CONFIG, None))
    standing_sha = digest(G.wire(g13_operand()))
    head_sha = digest(b'declared G14 controller data')
    with contextlib.ExitStack() as stack:
        stack.enter_context(patch.multiple(G, PROPOSAL_BOUND=True, HEAD_CORE_SOURCE='c' * 40,
            HEAD_NEW_CORE_DIGEST='sha256:' + new_digest, CORE_G14=image, G14_CORE_IMAGE_PAIRS=pairs,
            G14_CONTROLLER_CONFIG_SHA=head_sha, G13_PREDECESSOR_CONFIG_SHA=standing_sha,
            PAIR_CHAIN=chain, ALLOWED_CORE_IMAGE_PAIRS=tuple(row[1] for row in chain)))
        for contract in {id(value): value for value in (C, S.C, CUT.C)}.values():
            stack.enter_context(patch.multiple(contract, PROPOSAL_BOUND=True, SOURCE_R='c' * 40,
                NEW_DIGEST=new_digest, G14_CONFIG_SHA=head_sha, HEAD_CONFIG_SHA=head_sha,
                OLD_CORE_UID='22222222-2222-4222-8222-222222222222', OLD_CORE_GENERATION=277, OLD_CORE_POD_UID='11111111-1111-4111-8111-111111111111',
                ACTUAL_PREDECESSOR_STANDING_SHA=standing_sha,
                ANCESTORS={**contract.ANCESTORS, 'g13_predecessor_standing_config_sha256': standing_sha},
                REQUIRED_CI=frozenset({('Owned Network Guardian', 'pull_request')})))
        yield


class G14MaintenanceTests(unittest.TestCase):
    def test_forced_unbound_entrypoints_refuse_before_io(self):
        with patch.object(G, 'PROPOSAL_BOUND', False), patch.object(G, 'read') as read:
            for call in (G.require_bound, G.pair_chain_digests, G.main, lambda: G.Owner('1' * 64)):
                with self.subTest(entrypoint=repr(call)), self.assertRaises(RuntimeError): call()
            read.assert_not_called()
        with patch.object(C, 'PROPOSAL_BOUND', False), patch.object(C, 'read') as read, \
                patch.object(C, 'private_dir') as directory:
            with self.assertRaises(C.Hold): C.package('/never-read', '1' * 64)
            read.assert_not_called(); directory.assert_not_called()
        with patch.object(D, 'PROPOSAL_BOUND', False), patch.object(D, 'read_private') as read, \
                patch.object(D.os.path, 'lexists') as exists:
            for call in (D.main, lambda: D.derive(b'{}', [], 'declared'),
                         lambda: D.guardian_cross_check(b'{}', [], b'{}', '1' * 64),
                         lambda: D.write_new(Path('/never-write'), b'{}')):
                with self.subTest(entrypoint=repr(call)), self.assertRaises(D.Refused): call()
            read.assert_not_called(); exists.assert_not_called()
        with patch.object(CUT.C, 'PROPOSAL_BOUND', False), patch.object(CUT, 'native') as native, \
                patch.object(CUT, 'custody') as custody:
            for call in (CUT.main, CUT.core_overlap, lambda: CUT.swap_once(object()),
                         lambda: CUT.send_once(object(), *CUT.NATIVE_SEQUENCE[0]),
                         lambda: CUT.stage(None, None, None, None),
                         lambda: CUT.qualify(None, None, None, None, None)):
                with self.subTest(entrypoint=repr(call)), self.assertRaises(CUT.C.Hold): call()
            native.assert_not_called(); custody.assert_not_called()
        for path in (NEW / 'tools/derive_standing_config.py', NEW / 'tools/g14cut.py'):
            raw = path.read_bytes().replace(b'PROPOSAL_BOUND = True\n', b'PROPOSAL_BOUND = False\n', 1)
            with self.subTest(import_guard=path.name), patch.object(Path, 'read_bytes') as read:
                with self.assertRaisesRegex(RuntimeError, 'UNBOUND_BEFORE_SOURCE_IO'):
                    exec(compile(raw, str(path), 'exec'), {'__file__': str(path), '__name__': 'inert_G14_CI'})
                read.assert_not_called()

    def test_exact_seven_helpers_31_methods_and_fixed_g13_prefix(self):
        package = json.loads((historical.NEW / 'PACKAGE.json').read_bytes())
        self.assertEqual(len(package['unchanged_helpers_sha256']), 7)
        self.assertEqual(len(package['unchanged_owner_methods_sha256']), 31)
        for name, pin in package['unchanged_helpers_sha256'].items():
            self.assertEqual((NEW / name).read_bytes(), (historical.NEW / name).read_bytes())
            self.assertEqual(digest((NEW / name).read_bytes()), pin)
        for name in package['unchanged_owner_methods_sha256']:
            self.assertEqual(source_span(NEW / 'source/network_guardian.py', 'Owner', name),
                             source_span(historical.NEW / 'source/network_guardian.py', 'Owner', name))
        self.assertEqual(G.PAIR_CHAIN[:-2], historical.G.PAIR_CHAIN[:-1])
        self.assertEqual(G.PAIR_CHAIN[-2][:2], historical.G.PAIR_CHAIN[-1][:2])
        self.assertEqual(G.PAIR_CHAIN[-2][2:], (historical.G.NEW_CONFIG, historical.G.G13_CONTROLLER_CONFIG_SHA))
        self.assertEqual(G.PAIR_CHAIN[-1][1][0], G.PAIR_CHAIN[-2][1][-1])
        self.assertEqual(G.PAIR_STANDING_CHAIN, historical.G.PAIR_STANDING_CHAIN)
        self.assertEqual(G.RUNTIME_HASHES, historical.G.RUNTIME_HASHES)
        self.assertEqual((C.G12_SOURCE_SHA, C.G12_STANDING_SHA),
                         (historical.C.ACTUAL_PREDECESSOR_SOURCE_SHA, historical.C.ACTUAL_PREDECESSOR_STANDING_SHA))
        self.assertEqual(C.ANCESTORS['g12_predecessor_guardian_source_sha256'], C.G12_SOURCE_SHA)
        self.assertEqual(C.ANCESTORS['g12_predecessor_standing_config_sha256'], C.G12_STANDING_SHA)
        self.assertEqual((C.ACTUAL_PREDECESSOR_SOURCE_SHA, C.ACTUAL_PREDECESSOR_STANDING_SHA),
                         (G.G13_PREDECESSOR_SOURCE_SHA, G.G13_PREDECESSOR_CONFIG_SHA))

    def test_controller_derivation_requires_every_prefix_and_r4_overlap(self):
        r42, prefix = historical.historical.historical.historical.old_tools.controller_inputs()
        previous = D.strict_loads(prefix[-1]); added = []
        for generation, pairs in (('G9', D.G9_CORE_IMAGE_PAIRS), ('G10', D.G10_CORE_IMAGE_PAIRS), ('G11', D.G11_CORE_IMAGE_PAIRS), ('G12', D.G12_CORE_IMAGE_PAIRS), ('G13', D.G13_CORE_IMAGE_PAIRS)):
            previous = copy.deepcopy(previous)
            previous.update(core_container_images=pairs,
                root_review_attestation=('Declared ' + generation + ' CI predecessor; no Root approval. ') * 3)
            added.append(D.canonical(previous))
        review = 'Declared G14 CI controller operand; no actual installed config or Root approval. ' * 3
        with binding():
            expected = copy.deepcopy(previous)
            expected.update(core_container_images=G.G14_CORE_IMAGE_PAIRS, root_review_attestation=review)
            chain = (*D.PAIR_CHAIN[:-6],
                ('g9pair', D.G9_CORE_IMAGE_PAIRS, D.G9_CONFIG, digest(added[0])),
                ('g10pair', D.G10_CORE_IMAGE_PAIRS, D.G10_CONFIG, digest(added[1])),
                ('g11pair', D.G11_CORE_IMAGE_PAIRS, D.G11_CONFIG, digest(added[2])),
                ('g12pair', D.G12_CORE_IMAGE_PAIRS, D.G12_CONFIG, digest(added[3])),
                ('g13pair', D.G13_CORE_IMAGE_PAIRS, D.G13_CONFIG, digest(added[4])),
                ('g14pair', G.G14_CORE_IMAGE_PAIRS, D.G14_CONFIG, None))
            with patch.multiple(D, PROPOSAL_BOUND=True, HEAD_NEW_CORE_DIGEST=G.HEAD_NEW_CORE_DIGEST,
                    CORE_G14=G.CORE_G14, G14_CORE_IMAGE_PAIRS=G.G14_CORE_IMAGE_PAIRS,
                    G14_CONFIG_SHA=digest(D.canonical(expected)), PAIR_CHAIN=chain):
                all_prefix = [*prefix, *added]
                self.assertEqual(D.strict_loads(D.derive(r42, all_prefix, review)), expected)
                self.assertEqual({key for key in previous if previous[key] != expected[key]},
                                 {'core_container_images', 'root_review_attestation'})
                for index in range(len(all_prefix)):
                    wrong = list(all_prefix); wrong[index] += b' '
                    with self.subTest(prefix=index), self.assertRaises(D.Refused): D.derive(r42, wrong, review)
                with self.assertRaises(D.Refused): D.derive(r42, all_prefix, previous['root_review_attestation'])
                for pairs in ([D.G13_CORE_IMAGE_PAIRS[0], G.G14_CORE_IMAGE_PAIRS[1]], D.G13_CORE_IMAGE_PAIRS):
                    with patch.object(D, 'PAIR_CHAIN', (*chain[:-1], ('g14pair', pairs, D.G14_CONFIG, None))):
                        with self.assertRaises(D.Refused): D.derive(r42, all_prefix, review)

    def test_standing_adds_only_g13_axis_and_retains_g12_literal(self):
        controller_raw, hub_raw = b'{"declared":"G14 controller"}\n', b'{"declared":"same Hub"}\n'
        with binding(), patch.object(G, 'G14_CONTROLLER_CONFIG_SHA', digest(controller_raw)), \
                patch.object(S.C, 'HEAD_CONFIG_SHA', digest(controller_raw)):
            old = g13_operand(); old['hub_boot_config_sha256'] = digest(hub_raw)
            units = {S.C.CTRL: digest(b'declared G14 controller unit'), S.C.HUB: old['hub_unit_sha256'],
                     S.C.COLD: digest((NEW / 'units' / G.COLD).read_bytes()),
                     S.C.GUARD: digest((NEW / 'units' / G.GUARDIAN).read_bytes())}
            manifest = {'files': {'source/network_guardian.py': digest(b'declared G14 Source')}}
            value = S.build(G, manifest, old, controller_raw, hub_raw, 'Declared G14 standing review; no Root approval. ' * 4, units)
            self.assertEqual(set(value) - set(old), {'g13_predecessor_guardian_source_sha256', 'g13_predecessor_standing_config_sha256'})
            self.assertEqual({key for key in old if old[key] != value[key]},
                {'schema', 'guardian_source_sha256', 'controller_unit_sha256', 'cold_unit_sha256', 'guardian_unit_sha256', 'new_controller_config_sha256', 'Root_review'})
            self.assertEqual(value['g12_predecessor_guardian_source_sha256'], C.G12_SOURCE_SHA)
            self.assertEqual(value['g12_predecessor_standing_config_sha256'], C.G12_STANDING_SHA)
            # Exercise the real staged/live output validator with every fixed prefix.
            prefix = {name: pin for name, _, _, pin in G.PAIR_CHAIN[:-1]}
            ancestry = {name: old[name] for name in ('predecessor_standing_config_sha256',
                'r13_predecessor_standing_config_sha256','hub_source_sha256','hub_boot_config_sha256','hub_unit_sha256')}
            ancestry.update(r42_controller_config_sha256=G.R42_CONFIG_SHA,
                            r13_base_controller_config_sha256=G.BASE_CONFIG_SHA)
            expected = {'source_sha256': manifest['files']['source/network_guardian.py'],
                        'unit_sha256': units, 'controller_prefix_sha256': prefix,
                        'ancestry_input_sha256': ancestry}
            output = {'schema': S.C.DERIVATION_SCHEMA, 'hub_profile': 'r13', 'units_source': 'staged',
                'standing_config_sha256': digest(S.C.wire(value)), 'standing_config_written': True,
                'review_text_printed': False, 'private_files_read': False,
                'input_sha256': {'successor_guardian_source_sha256': expected['source_sha256'],
                    'head_generation': 'g14pair', 'head_core_digest': 'sha256:'+S.C.NEW_DIGEST,
                    'head_controller_config_sha256': S.C.HEAD_CONFIG_SHA,
                    'historical_g6_controller_config_sha256': S.C.G6_CONFIG_SHA,
                    'pair_predecessor_standing_config_sha256': S.C.PREFIX_STANDINGS, **S.C.ANCESTORS,
                    'pair_chain_controller_config_sha256': {**prefix,'g14pair': S.C.HEAD_CONFIG_SHA},
                    **units, **ancestry}}
            S.C.validate_standing_output(output, expected, 'staged')
            for fault in ('missing_g13','foreign_g13'):
                bad = copy.deepcopy(expected)
                if fault == 'missing_g13': del bad['controller_prefix_sha256']['g13pair']
                else: bad['controller_prefix_sha256']['g13pair'] = digest(b'foreign G12')
                with self.subTest(standing_prefix=fault), self.assertRaises(S.C.Hold):
                    S.C.validate_standing_output(output, bad, 'staged')
            for key in ('guardian_source_sha256', 'new_controller_config_sha256', 'g12_predecessor_guardian_source_sha256'):
                wrong = copy.deepcopy(old); wrong[key] = digest(b'foreign')
                with self.subTest(old_axis=key), self.assertRaises(S.C.Hold): S.build(G, manifest, wrong, controller_raw, hub_raw, 'Declared review. ' * 20, units)

    def test_g13_predecessor_requires_original_source_and_standing_bytes(self):
        actual_source = (historical.NEW / 'source/network_guardian.py').read_bytes()
        with binding():
            prior = g13_operand(); raw = G.wire(prior)
            value = {**prior, 'schema': G.SCHEMA, 'new_controller_config_sha256': G.G14_CONTROLLER_CONFIG_SHA,
                'g13_predecessor_guardian_source_sha256': G.G13_PREDECESSOR_SOURCE_SHA,
                'g13_predecessor_standing_config_sha256': digest(raw)}
            def read(path, *_):
                self.assertIn(path, (G.G13_PREDECESSOR_HERE / 'network_guardian.py', G.G13_PREDECESSOR_CONFIG))
                return actual_source if path == G.G13_PREDECESSOR_HERE / 'network_guardian.py' else raw
            with patch.object(G, 'read', side_effect=read):
                self.assertEqual(G.g13_predecessor_standing(value), (G.G13_PREDECESSOR_SOURCE_SHA, digest(raw)))
                for key in ('g13_predecessor_guardian_source_sha256', 'g13_predecessor_standing_config_sha256', 'new_controller_config_sha256', 'g12_predecessor_standing_config_sha256', 'hub_unit_sha256'):
                    wrong = copy.deepcopy(value); wrong[key] = digest(b'foreign')
                    with self.subTest(axis=key), self.assertRaises(RuntimeError): G.g13_predecessor_standing(wrong)
            for source_changed in (False, True):
                def changed_read(path, *_):
                    is_source = path == G.G13_PREDECESSOR_HERE / 'network_guardian.py'
                    original = actual_source if is_source else raw
                    return original + b' ' if is_source == source_changed else original
                with self.subTest(source_changed=source_changed), patch.object(G, 'read', side_effect=changed_read), self.assertRaises(RuntimeError):
                    G.g13_predecessor_standing(value)

    def test_protected43_budget_cold_hub_and_six_commands_are_unchanged(self):
        with binding(): self.assertEqual(C.protected_ref_union(), historical.C.protected_ref_union())
        self.assertEqual(CUT.NATIVE_SEQUENCE, historical.CUT.NATIVE_SEQUENCE)
        self.assertEqual(len(CUT.NATIVE_SEQUENCE), 6)
        for name in ('protected', 'final_closure'):
            self.assertEqual(source_span(NEW / 'tools/g14cut.py', 'Backend', name),
                             source_span(historical.NEW / 'tools/g13cut.py', 'Backend', name))
        protected = source_span(NEW / 'tools/g14cut.py', 'Backend', 'protected')
        self.assertIn('len(markers) == 1', protected)
        closure = source_span(NEW / 'tools/g14cut.py', 'Backend', 'final_closure')
        self.assertIn('self.protected() == self.protected_before', closure)
        self.assertIn('COLD_HUB_SAME_ORIGINAL_COMPLETED_LIFETIMES_NO_EXECUTION', closure)
        # Real core_overlap validator with declared GET-only operands: R3 is
        # the sole current overlap, and the historical R2 must be refused.
        with binding():
            image = CUT.C.IMAGE_PREFIX + CUT.C.OLD_DIGEST
            dep = {'metadata': {'uid': CUT.C.OLD_CORE_UID, 'generation': 277,
                    'annotations': {'dakasa.io/core-source-commit': CUT.C.OLD_CORE_SOURCE}},
                'spec': {'replicas': 1, 'template': {'spec': {'containers': [{'name': 'core', 'image': image}]}}},
                'status': {'observedGeneration': 277, 'readyReplicas': 1, 'availableReplicas': 1, 'updatedReplicas': 1}}
            pod = {'metadata': {'uid': CUT.C.OLD_CORE_POD_UID, 'name': 'declared-core'},
                'spec': {'containers': [{'name': 'core', 'image': image}]},
                'status': {'phase': 'Running', 'podIP': '192.0.2.10', 'containerStatuses': [{'name': 'core',
                    'ready': True, 'restartCount': 0, 'state': {'running': {'startedAt': 'declared'}},
                    'imageID': image, 'containerID': 'containerd://declared'}]}}
            replies = [SimpleNamespace(returncode=0, stdout=C.wire(dep)), SimpleNamespace(returncode=0, stdout=C.wire({'items': [pod]}))]
            with patch.object(CUT, 'native', side_effect=replies) as calls:
                self.assertEqual(CUT.core_overlap()['deployment_uid'], CUT.C.OLD_CORE_UID)
                self.assertEqual(calls.call_count, 2)
            with patch.object(CUT.C, 'OLD_DIGEST', '8e6d44d86bbae4463652d4bf9b3583241483a0813a4d34c7254b9c2e56dccafc'), patch.object(CUT, 'native', side_effect=replies):
                with self.assertRaises(CUT.C.Hold): CUT.core_overlap()



if __name__ == '__main__':
    unittest.main()
