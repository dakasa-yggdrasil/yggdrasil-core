"""Declared G15 operands only; no OCI, approval or native lifetime claim."""
import ast
import contextlib
import copy
import json
from pathlib import Path
import unittest
import subprocess
import sys
from unittest.mock import patch
from types import SimpleNamespace

import test_g14pair_maintenance as historical

ROOT = historical.ROOT
NEW = ROOT / 'g15pair'
load, digest = historical.load, historical.digest
G = load(NEW / 'source/network_guardian.py')
C = load(NEW / 'tools/pair_change_contract.py')
D = load(NEW / 'tools/derive_g15pair_controller_config.py')
S = load(NEW / 'tools/derive_standing_config.py', True)
CUT = load(NEW / 'tools/g15cut.py', True)


def source_span(path, owner, name):
    raw = path.read_text()
    tree = ast.parse(raw)
    parent = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == owner)
    node = next(node for node in parent.body if isinstance(node, ast.FunctionDef) and node.name == name)
    return ''.join(raw.splitlines(keepends=True)[node.lineno - 1:node.end_lineno])


def g14_operand():
    value = copy.deepcopy(historical.g13_operand())
    package = json.loads((historical.NEW / 'PACKAGE.json').read_bytes())
    value.update(schema=historical.G.SCHEMA,
                 g13_predecessor_guardian_source_sha256=G.G13_PREDECESSOR_SOURCE_SHA,
                 g13_predecessor_standing_config_sha256=G.G13_PREDECESSOR_CONFIG_SHA,
                 guardian_source_sha256=G.G14_PREDECESSOR_SOURCE_SHA,
                 new_controller_config_sha256=G.G14_CONTROLLER_CONFIG_SHA,
                 controller_unit_sha256=package['controller_unit_sha256'],
                 cold_unit_sha256=package['files']['units/' + G.COLD],
                 guardian_unit_sha256=package['files']['units/' + G.GUARDIAN],
                 Root_review='Declared G14 prior standing operand; never installed-state evidence. ' * 3)
    return value

DECLARED_G16_SOURCE = b'Declared G16 predecessor Source operand; not an installed artifact.'
DECLARED_G17_SOURCE = b'Declared G17 predecessor Source operand; not an installed artifact.'
DECLARED_G18_SOURCE = b'Declared G18 predecessor Source operand; not an installed artifact.'
DECLARED_G19_SOURCE = b'Declared G19 predecessor Source operand; not an installed artifact.'
DECLARED_G20_SOURCE = b'Declared G20 predecessor Source operand; not an installed artifact.'
DECLARED_G21_SOURCE = b'Declared G21 predecessor Source operand; not an installed artifact.'


def g15_operand():
    value = g14_operand()
    value.update(schema=G.SCHEMA,
                 g14_predecessor_guardian_source_sha256=G.G14_PREDECESSOR_SOURCE_SHA,
                 g14_predecessor_standing_config_sha256=G.G14_PREDECESSOR_CONFIG_SHA,
                 guardian_source_sha256=G.G15_PREDECESSOR_SOURCE_SHA,
                 new_controller_config_sha256=G.G15_CONTROLLER_CONFIG_SHA,
                 controller_unit_sha256='cd4ef325410d157c31cfe9ec0f2c1a4f842cc7761c29551895325e8a79386623',
                 cold_unit_sha256='fb1b3c49e89938e0f1a34e6e82edeef1a264cc98fa95f2e3864fe5b2fd4a8561',
                 guardian_unit_sha256='5aaa41b31b482fe758febf128328730b88fc4a6cdb7f8f7cf5b6d01766910390',
                 Root_review='Declared prior G15 standing; no installed-state evidence. ' * 4)
    return value


def g16_operand():
    value = g15_operand()
    value.update(g15_predecessor_guardian_source_sha256=G.G15_PREDECESSOR_SOURCE_SHA,
                 g15_predecessor_standing_config_sha256=G.G15_PREDECESSOR_CONFIG_SHA,
                 guardian_source_sha256=G.G16_PREDECESSOR_SOURCE_SHA,
                 new_controller_config_sha256=G.G16_CONTROLLER_CONFIG_SHA,
                 controller_unit_sha256='c7f9bb7557013464237b679ebcde507af60ed20b794ea5ed15679fa73060823b',
                 cold_unit_sha256='b60c1ad3307a4bbcf0b324119ae272cc270c7d68d1e51363ae0a6b5aefe308e2',
                 guardian_unit_sha256='b7d3e0d9a2bf9ad7d91796ec6cc810ada0ccd03086016056391373a3f2bb8f1a',
                 Root_review='Declared prior G16 standing; no installed-state evidence. ' * 4)
    return value



def g17_operand():
    value = g16_operand()
    value.update(g16_predecessor_guardian_source_sha256=G.G16_PREDECESSOR_SOURCE_SHA,
                 g16_predecessor_standing_config_sha256=G.G16_PREDECESSOR_CONFIG_SHA,
                 guardian_source_sha256=G.G17_PREDECESSOR_SOURCE_SHA,
                 new_controller_config_sha256=G.G17_CONTROLLER_CONFIG_SHA,
                 controller_unit_sha256='b71682b08f04e0e057b839dd06e2c2dad3674b91f4d34fc968e1c7b8ab999149',
                 cold_unit_sha256='cea597842b8648e3d763f530b0cafe4f9f2ea4b34b0c30c00503d9926f0d9584',
                 guardian_unit_sha256='b9b087825a3be2052693608b32c4a80dcbc4cb96ce4b03df96d183b4d973a437',
                 Root_review='Declared prior G17 standing; no installed-state evidence. ' * 4)
    return value


def g18_operand():
    value = g17_operand()
    value.update(g17_predecessor_guardian_source_sha256=G.G17_PREDECESSOR_SOURCE_SHA,
                 g17_predecessor_standing_config_sha256=G.G17_PREDECESSOR_CONFIG_SHA,
                 guardian_source_sha256=G.G18_PREDECESSOR_SOURCE_SHA,
                 new_controller_config_sha256=G.G18_CONTROLLER_CONFIG_SHA,
                 controller_unit_sha256='253cb7270f401b96e6d8149c98cb2b467197701a37482193a4c1851b92a0f318',
                 cold_unit_sha256='13ed8beaf73ffea86329429c5f2f51218c743b22fdc7e27e81ef2cc011d45a7e',
                 guardian_unit_sha256='278168ae96d0fceee88ce09cf5c4211be4424692dcedfad49dd666c4ab1424be',
                 Root_review='Declared prior G18 standing; no installed-state evidence. ' * 4)
    return value


def g19_operand():
    value = g18_operand()
    value.update(g18_predecessor_guardian_source_sha256=G.G18_PREDECESSOR_SOURCE_SHA,
                 g18_predecessor_standing_config_sha256=G.G18_PREDECESSOR_CONFIG_SHA,
                 guardian_source_sha256=G.G19_PREDECESSOR_SOURCE_SHA,
                 new_controller_config_sha256=G.G19_CONTROLLER_CONFIG_SHA,
                 controller_unit_sha256='aa642a595105b43161ad0fa736acfa5a167d0dbf490527247695607ad97222c6',
                 cold_unit_sha256='0de44ac60069b4daa65341910c98b3f19a067496640c2ddf7e27d27c56f320ff',
                 guardian_unit_sha256='c1c7fad3775cca296fd938a0f5ad5d0bff3669e196625ee10f153b2e7e494ee6',
                 Root_review='Declared prior G19 standing; no installed-state evidence. ' * 4)
    return value

def g20_operand():
    value = g19_operand()
    value.update(g19_predecessor_guardian_source_sha256=G.G19_PREDECESSOR_SOURCE_SHA,
                 g19_predecessor_standing_config_sha256=G.G19_PREDECESSOR_CONFIG_SHA,
                 guardian_source_sha256=G.G20_PREDECESSOR_SOURCE_SHA,
                 new_controller_config_sha256=G.G20_CONTROLLER_CONFIG_SHA,
                 controller_unit_sha256='49690de6c6c011b4adc822083ff0baaa053c7d0e087b39b453958bdc423ad8c3',
                 cold_unit_sha256='530cadf65750c12edda2138b142ee8fcf551879044bf7dda95ac56ea6fc27602',
                 guardian_unit_sha256='33e6ba23e6b99572d877e11c865b383d47f3d8e74d4452cd8a16adcfd093c644',
                 Root_review='Declared prior G20 standing; no installed-state evidence. ' * 4)
    return value



def g21_operand():
    value = g20_operand()
    value.update(g20_predecessor_guardian_source_sha256=G.G20_PREDECESSOR_SOURCE_SHA,
                 g20_predecessor_standing_config_sha256=G.G20_PREDECESSOR_CONFIG_SHA,
                 guardian_source_sha256=G.G21_PREDECESSOR_SOURCE_SHA,
                 new_controller_config_sha256=G.G21_CONTROLLER_CONFIG_SHA,
                 controller_unit_sha256=C.OLD_UNIT_SHAS[C.CTRL],
                 cold_unit_sha256=C.OLD_UNIT_SHAS[C.COLD],
                 guardian_unit_sha256=C.OLD_UNIT_SHAS[C.GUARD],
                 Root_review='Declared prior G21 standing; no installed-state evidence. ' * 4)
    return value


def method_ast(path, owner, name):
    parent = next(n for n in ast.parse(path.read_text()).body if isinstance(n, ast.ClassDef) and n.name == owner)
    return ast.dump(next(n for n in parent.body if isinstance(n, ast.FunctionDef) and n.name == name), include_attributes=False)


@contextlib.contextmanager
def binding():
    """Bind declared CI operands; retain whole C19/C20/C21 and production validators."""
    new_digest = digest(b'declared replacement Core12 image; not an OCI artifact')
    image = G.CORE_IMAGE_REF + 'sha256:' + new_digest
    pairs = [{'image': G.CORE_G21, 'image_id': G.CORE_G21}, {'image': image, 'image_id': image}]
    chain = (*G.PAIR_CHAIN[:-1], ('g22pair', pairs, G.NEW_CONFIG, None))
    prior19 = g19_operand(); prior19['guardian_source_sha256'] = digest(DECLARED_G19_SOURCE)
    standing19_sha = digest(G.wire(prior19))
    head_sha = digest(b'declared G22 controller data')
    with contextlib.ExitStack() as stack:
        stack.enter_context(patch.multiple(G, G19_PREDECESSOR_CONFIG_SHA=standing19_sha,
            G19_PREDECESSOR_SOURCE_SHA=digest(DECLARED_G19_SOURCE)))
        prior20 = g20_operand(); prior20['guardian_source_sha256'] = digest(DECLARED_G20_SOURCE)
        standing20_sha = digest(G.wire(prior20))
        stack.enter_context(patch.multiple(G, G20_PREDECESSOR_CONFIG_SHA=standing20_sha,
            G20_PREDECESSOR_SOURCE_SHA=digest(DECLARED_G20_SOURCE)))
        prior = g21_operand(); prior['guardian_source_sha256'] = digest(DECLARED_G21_SOURCE)
        standing_sha = digest(G.wire(prior))
        stack.enter_context(patch.multiple(G, PROPOSAL_BOUND=True, HEAD_CORE_SOURCE='c' * 40,
            HEAD_NEW_CORE_DIGEST='sha256:' + new_digest, CORE_G22=image, G22_CORE_IMAGE_PAIRS=pairs,
            G22_CONTROLLER_CONFIG_SHA=head_sha, G21_PREDECESSOR_CONFIG_SHA=standing_sha,
            G21_PREDECESSOR_SOURCE_SHA=digest(DECLARED_G21_SOURCE),
            PAIR_CHAIN=chain, ALLOWED_CORE_IMAGE_PAIRS=tuple(row[1] for row in chain)))
        for contract in {id(value): value for value in (C, S.C, CUT.C)}.values():
            stack.enter_context(patch.multiple(contract, PROPOSAL_BOUND=True, SOURCE_R='c' * 40,
                NEW_DIGEST=new_digest, G22_CONFIG_SHA=head_sha, HEAD_CONFIG_SHA=head_sha,
                OLD_CORE_UID='22222222-2222-4222-8222-222222222222', OLD_CORE_GENERATION=284, OLD_CORE_POD_UID='11111111-1111-4111-8111-111111111111', OLD_CORE_CONTAINER_ID='containerd://declared',
                ACTUAL_PREDECESSOR_SOURCE_SHA=digest(DECLARED_G21_SOURCE), ACTUAL_PREDECESSOR_STANDING_SHA=standing_sha,
                ANCESTORS={**contract.ANCESTORS,
                    'g19_predecessor_guardian_source_sha256': digest(DECLARED_G19_SOURCE), 'g19_predecessor_standing_config_sha256': standing19_sha,
                    'g20_predecessor_guardian_source_sha256': digest(DECLARED_G20_SOURCE), 'g20_predecessor_standing_config_sha256': standing20_sha,
                    'g21_predecessor_guardian_source_sha256': digest(DECLARED_G21_SOURCE), 'g21_predecessor_standing_config_sha256': standing_sha},
                REQUIRED_CI=frozenset({('Owned Network Guardian', 'pull_request')})))
        yield

class G15MaintenanceTests(unittest.TestCase):
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
        for path in (NEW / 'tools/derive_standing_config.py', NEW / 'tools/g15cut.py'):
            raw = path.read_bytes()
            tree = ast.parse(raw)
            bindings = [(index, node) for index, node in enumerate(tree.body)
                        if isinstance(node, ast.Assign) and len(node.targets) == 1
                        and isinstance(node.targets[0], ast.Name)
                        and node.targets[0].id == 'PROPOSAL_BOUND']
            self.assertEqual(len(bindings), 1)
            index, binding = bindings[0]
            self.assertEqual(binding.lineno, binding.end_lineno)
            self.assertIsInstance(binding.value, ast.Constant)
            self.assertIs(type(binding.value.value), bool)
            lines = raw.splitlines(keepends=True)
            lines[binding.lineno - 1] = b'PROPOSAL_BOUND = False\n'
            raw = b''.join(lines)
            forced = ast.parse(raw).body[index]
            self.assertIsInstance(forced, ast.Assign)
            self.assertIs(forced.value.value, False)
            with self.subTest(import_guard=path.name), patch.object(Path, 'read_bytes') as read:
                with self.assertRaisesRegex(RuntimeError, 'UNBOUND_BEFORE_SOURCE_IO'):
                    exec(compile(raw, str(path), 'exec'), {'__file__': str(path), '__name__': 'inert_G15_CI'})
                read.assert_not_called()

        from g21_compiler_operands import exercise_g21_compiler_binding
        exercise_g21_compiler_binding(self, ROOT)

    def test_exact_seven_helpers_31_methods_and_fixed_g14_prefix(self):
        package = json.loads((historical.NEW / 'PACKAGE.json').read_bytes())
        self.assertEqual(len(package['unchanged_helpers_sha256']), 7)
        self.assertEqual(len(package['unchanged_owner_methods_sha256']), 31)
        for name, pin in package['unchanged_helpers_sha256'].items():
            self.assertEqual((NEW / name).read_bytes(), (historical.NEW / name).read_bytes())
            self.assertEqual(digest((NEW / name).read_bytes()), pin)
        for name in package['unchanged_owner_methods_sha256']:
            self.assertEqual(method_ast(NEW / 'source/network_guardian.py', 'Owner', name),
                             method_ast(historical.NEW / 'source/network_guardian.py', 'Owner', name))
        self.assertEqual(G.PAIR_CHAIN[:-9], historical.G.PAIR_CHAIN[:-1])
        self.assertEqual(G.PAIR_CHAIN[-9][:2], historical.G.PAIR_CHAIN[-1][:2])
        self.assertEqual(G.PAIR_CHAIN[-9][2:], (historical.G.NEW_CONFIG, historical.G.G14_CONTROLLER_CONFIG_SHA))
        self.assertEqual(G.PAIR_CHAIN[-8], ('g15pair', G.G15_CORE_IMAGE_PAIRS, Path('/etc/dakasa/capacity-network/controller.r13-netlink-g15pair.production.json'), C.G15_CONFIG_SHA))
        self.assertEqual(G.PAIR_CHAIN[-7], ('g16pair', G.G16_CORE_IMAGE_PAIRS, Path('/etc/dakasa/capacity-network/controller.r13-netlink-g16pair.production.json'), C.G16_CONFIG_SHA))
        self.assertEqual(G.PAIR_CHAIN[-6], ('g17pair', G.G17_CORE_IMAGE_PAIRS, Path('/etc/dakasa/capacity-network/controller.r13-netlink-g17pair.production.json'), C.G17_CONFIG_SHA))
        self.assertEqual(G.PAIR_CHAIN[-5], ('g18pair', G.G18_CORE_IMAGE_PAIRS, Path('/etc/dakasa/capacity-network/controller.r13-netlink-g18pair.production.json'), C.G18_CONFIG_SHA))
        self.assertEqual(G.PAIR_CHAIN[-4], ('g19pair', G.G19_CORE_IMAGE_PAIRS, Path('/etc/dakasa/capacity-network/controller.r13-netlink-g19pair.production.json'), C.G19_CONFIG_SHA))
        self.assertEqual(G.PAIR_CHAIN[-3], ('g20pair', G.G20_CORE_IMAGE_PAIRS, Path('/etc/dakasa/capacity-network/controller.r13-netlink-g20pair.production.json'), C.G20_CONFIG_SHA))
        self.assertEqual(G.PAIR_CHAIN[-2], ('g21pair', G.G21_CORE_IMAGE_PAIRS, C.OLD_CONFIG, C.G21_CONFIG_SHA))
        self.assertEqual(C.G18_CONFIG_SHA, 'd8ed4b268c112fc396860b57f57b36090dcc8b63f768a3a47b291984aa6eab1a')
        self.assertEqual(G.PAIR_CHAIN[-1][0], 'g22pair')
        self.assertEqual(G.PAIR_CHAIN[-1][1][0], G.PAIR_CHAIN[-2][1][-1])
        self.assertNotEqual(G.PAIR_CHAIN[-1][1][0], G.PAIR_CHAIN[-2][1][0])
        for name in ('HISTORICAL_G6_FIELDS','HISTORICAL_F315_FIELDS','HISTORICAL_G7_FIELDS','HISTORICAL_G8_FIELDS','HISTORICAL_G9_FIELDS'):
            actual, original = getattr(G,name), getattr(historical.G,name)
            self.assertEqual(actual, original)
            self.assertEqual(G.wire(sorted(actual)), historical.G.wire(sorted(original)))
        self.assertEqual(G.HISTORICAL_G14_FIELDS, frozenset(historical.G.FIELDS))
        self.assertEqual(G.HISTORICAL_G15_FIELDS, G.HISTORICAL_G14_FIELDS | {'g14_predecessor_guardian_source_sha256','g14_predecessor_standing_config_sha256'})
        self.assertEqual(G.HISTORICAL_G16_FIELDS, G.HISTORICAL_G15_FIELDS | {'g15_predecessor_guardian_source_sha256','g15_predecessor_standing_config_sha256'})
        self.assertEqual(G.HISTORICAL_G17_FIELDS, G.HISTORICAL_G16_FIELDS | {'g16_predecessor_guardian_source_sha256','g16_predecessor_standing_config_sha256'})
        self.assertEqual(G.HISTORICAL_G18_FIELDS, G.HISTORICAL_G17_FIELDS | {'g17_predecessor_guardian_source_sha256','g17_predecessor_standing_config_sha256'})
        self.assertEqual(G.HISTORICAL_G19_FIELDS, G.HISTORICAL_G18_FIELDS | {'g18_predecessor_guardian_source_sha256','g18_predecessor_standing_config_sha256'})
        self.assertEqual(G.HISTORICAL_G20_FIELDS, G.HISTORICAL_G19_FIELDS | {'g19_predecessor_guardian_source_sha256','g19_predecessor_standing_config_sha256'})
        self.assertEqual(G.HISTORICAL_G21_FIELDS, G.HISTORICAL_G20_FIELDS | {'g20_predecessor_guardian_source_sha256','g20_predecessor_standing_config_sha256'})
        self.assertEqual(G.PAIR_STANDING_CHAIN, historical.G.PAIR_STANDING_CHAIN)
        self.assertEqual(G.RUNTIME_HASHES, historical.G.RUNTIME_HASHES)
        self.assertEqual((C.G13_SOURCE_SHA, C.G13_STANDING_SHA),
                         (historical.C.ACTUAL_PREDECESSOR_SOURCE_SHA, historical.C.ACTUAL_PREDECESSOR_STANDING_SHA))
        self.assertEqual(C.ANCESTORS['g13_predecessor_guardian_source_sha256'], C.G13_SOURCE_SHA)
        self.assertEqual(C.ANCESTORS['g13_predecessor_standing_config_sha256'], C.G13_STANDING_SHA)
        deriver = ast.parse((NEW / 'tools/derive_standing_config.py').read_text())
        derive = next(n for n in deriver.body if isinstance(n, ast.FunctionDef) and n.name == 'derive')
        archival_calls = [n for n in ast.walk(derive) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                          and isinstance(n.func.value, ast.Name) and n.func.value.id == 'G'
                          and (n.func.attr.endswith('_predecessor_standing') or n.func.attr == 'pair_predecessor_standings')]
        self.assertEqual(len(archival_calls), 13)
        self.assertTrue(all(len(n.args) == 1 and isinstance(n.args[0], ast.Name) and n.args[0].id == 'predecessor'
                            for n in archival_calls))

        self.assertEqual((C.ACTUAL_PREDECESSOR_SOURCE_SHA, C.ACTUAL_PREDECESSOR_STANDING_SHA),
                         (G.G21_PREDECESSOR_SOURCE_SHA, G.G21_PREDECESSOR_CONFIG_SHA))

        # Real root-owned file I/O and the inherited default cap are exercised
        # together in a CI-only child. No custody/read/cap mock or fallback.
        source_path = NEW / 'source/network_guardian.py'
        source_raw = source_path.read_bytes()
        self.assertLessEqual(len(source_raw), G.read.__defaults__[0])
        self.assertEqual(G.read.__defaults__, (131072, None))
        current_package = json.loads((NEW / 'PACKAGE.json').read_bytes())
        self.assertEqual(current_package['files']['source/network_guardian.py'], digest(source_raw))
        binding_names = {'PROPOSAL_BOUND', 'HEAD_CORE_SOURCE', 'HEAD_NEW_CORE_DIGEST',
                         'G22_CONTROLLER_CONFIG_SHA'}
        literals = {}
        for node in ast.parse(source_raw).body:
            if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and
                    target.id in binding_names for target in node.targets):
                self.assertEqual(len(node.targets), 1)
                self.assertIsInstance(node.targets[0], ast.Name)
                name = node.targets[0].id
                self.assertNotIn(name, literals)
                self.assertIsInstance(node.value, ast.Constant)
                literals[name] = node.value.value
        self.assertEqual(set(literals), binding_names)
        self.assertIs(type(literals['PROPOSAL_BOUND']), bool)
        for name, value in literals.items():
            self.assertIs(type(getattr(G, name)), type(value))
            self.assertEqual(getattr(G, name), value)
        self.assertIs(current_package['source_bound'], literals['PROPOSAL_BOUND'])
        self.assertIs(current_package['proposal_bound'], literals['PROPOSAL_BOUND'])
        if literals['PROPOSAL_BOUND'] is False:
            self.assertEqual(literals, {'PROPOSAL_BOUND': False, 'HEAD_CORE_SOURCE': None,
                'HEAD_NEW_CORE_DIGEST': None, 'G22_CONTROLLER_CONFIG_SHA': None})
            self.assertIs(type(current_package['prepared_Guardian_bytes']), int)
            self.assertEqual(current_package['prepared_Guardian_bytes'], len(source_raw))
            self.assertIsNone(current_package['bound_Guardian_bytes'])
            # Predict every final fixed-width Source binding without running it.
            bound_raw = source_raw
            for old, new in ((b'PROPOSAL_BOUND=False', b'PROPOSAL_BOUND=True'),
                             (b'HEAD_CORE_SOURCE=None', b"HEAD_CORE_SOURCE='" + b'c' * 40 + b"'"),
                             (b'HEAD_NEW_CORE_DIGEST=None', b"HEAD_NEW_CORE_DIGEST='sha256:" + b'd' * 64 + b"'"),
                             (b'G22_CONTROLLER_CONFIG_SHA=None', b"G22_CONTROLLER_CONFIG_SHA='" + b'e' * 64 + b"'")):
                self.assertEqual(bound_raw.count(old), 1)
                bound_raw = bound_raw.replace(old, new, 1)
            ast.parse(bound_raw)
            self.assertLessEqual(len(bound_raw), G.read.__defaults__[0])
        else:
            core_source = literals['HEAD_CORE_SOURCE']
            core_digest = literals['HEAD_NEW_CORE_DIGEST']
            config_sha = literals['G22_CONTROLLER_CONFIG_SHA']
            for value, pattern, placeholder in (
                    (core_source, r'\A[a-f0-9]{40}\Z', '0' * 40),
                    (core_digest, r'\Asha256:[a-f0-9]{64}\Z', 'sha256:' + '0' * 64),
                    (config_sha, r'\A[a-f0-9]{64}\Z', '0' * 64)):
                self.assertIs(type(value), str)
                self.assertRegex(value, pattern)
                self.assertNotEqual(value, placeholder)
            self.assertIs(C.PROPOSAL_BOUND, True)
            self.assertIs(D.PROPOSAL_BOUND, True)
            self.assertEqual(core_source, C.SOURCE_R)
            self.assertEqual(core_digest, 'sha256:' + C.NEW_DIGEST)
            self.assertEqual(core_digest, D.HEAD_NEW_CORE_DIGEST)
            self.assertEqual(config_sha, C.G22_CONFIG_SHA)
            self.assertEqual(config_sha, C.HEAD_CONFIG_SHA)
            self.assertEqual(config_sha, D.G22_CONFIG_SHA)
            self.assertEqual(G.CORE_G22, G.CORE_IMAGE_REF + core_digest)
            self.assertEqual(D.CORE_G22, G.CORE_G22)
            self.assertEqual(current_package['base_Core_source'], core_source)
            self.assertEqual(current_package['amd64_Core_manifest_digest'], core_digest)
            self.assertEqual(current_package['controller_config_sha256'], config_sha)
            proposal = D.strict_loads((NEW / 'proposal/CONTROLLER.PROPOSAL.json').read_bytes())
            review = (NEW / 'proposal/ROOT-CONTROLLER-REVIEW.txt').read_bytes().decode()
            self.assertEqual(proposal['root_review_attestation'], review.removesuffix('\n'))
            proposal_sha = digest(D.canonical(proposal))
            self.assertEqual(proposal_sha, G.G22_CONTROLLER_CONFIG_SHA)
            self.assertEqual(proposal_sha, C.G22_CONFIG_SHA)
            self.assertEqual(proposal_sha, D.G22_CONFIG_SHA)
            self.assertIs(type(current_package['bound_Guardian_bytes']), int)
            self.assertEqual(current_package['bound_Guardian_bytes'], len(source_raw))
        program = r"""
import hashlib,json,os,tempfile,types
from pathlib import Path
import sys
raw=Path(sys.argv[1]).read_bytes()
assert hashlib.sha256(raw).hexdigest()==sys.argv[2]
assert os.geteuid()==0
with tempfile.TemporaryDirectory(prefix='g15-default-read-') as name:
    root=Path(name);source=root/'network_guardian.py';source.write_bytes(raw);source.chmod(0o600)
    module=types.ModuleType('g15_real_default_read_CI');module.__file__=str(source)
    exec(compile(raw,str(source),'exec'),module.__dict__)
    assert module.read.__defaults__==(131072,None)
    assert module.read(source)==raw
    oversized=root/'oversized';oversized.write_bytes(b'x'*131073);oversized.chmod(0o600)
    try:module.read(oversized)
    except RuntimeError as error:assert str(error)=='BOUNDED_FULL_FILE'
    else:raise AssertionError('oversized operand was accepted')
    print(json.dumps({'Source_sha256':sys.argv[2],'Source_bytes':len(raw),'uid':os.geteuid(),
        'default_cap':131072,'oversized_bytes':131073,'oversized_refused':True},sort_keys=True))
"""
        result = subprocess.run(['sudo', '-n', sys.executable, '-I', '-B', '-c', program,
                                 str(source_path), digest(source_raw)], capture_output=True, text=True, timeout=8)
        print('G15-DEFAULT-READ-REGRESSION', result.stdout, result.stderr, flush=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        evidence = json.loads(result.stdout)
        self.assertEqual(evidence['Source_sha256'], digest(source_raw))
        self.assertEqual(evidence['Source_bytes'], len(source_raw))
        self.assertEqual((evidence['uid'], evidence['default_cap'], evidence['oversized_bytes'], evidence['oversized_refused']),
                         (0, 131072, 131073, True))

    def test_controller_derivation_requires_every_prefix_and_r5_overlap(self):
        r42, prefix = historical.historical.historical.historical.historical.old_tools.controller_inputs()
        previous = D.strict_loads(prefix[-1]); added = []
        generations = [('G9', D.G9_CORE_IMAGE_PAIRS), ('G10', D.G10_CORE_IMAGE_PAIRS),
            ('G11', D.G11_CORE_IMAGE_PAIRS), ('G12', D.G12_CORE_IMAGE_PAIRS),
            ('G13', D.G13_CORE_IMAGE_PAIRS), ('G14', D.G14_CORE_IMAGE_PAIRS),
            ('G15', D.G15_CORE_IMAGE_PAIRS), ('G16', D.G16_CORE_IMAGE_PAIRS),
            ('G17', D.G17_CORE_IMAGE_PAIRS), ('G18', D.G18_CORE_IMAGE_PAIRS),
            ('G19', D.G19_CORE_IMAGE_PAIRS), ('G20', D.G20_CORE_IMAGE_PAIRS), ('G21', D.G21_CORE_IMAGE_PAIRS)]
        for generation, pairs in generations:
            previous = copy.deepcopy(previous)
            previous.update(core_container_images=pairs,
                root_review_attestation=('Declared '+generation+' CI predecessor; no Root approval. ')*3)
            added.append(D.canonical(previous))
        review = 'Declared G22 CI controller operand; no installed-state authority. '*3
        with binding():
            # This pure Guardian check retains C19 [D8,ed5] and overlaps its actual ed5 tail.
            self.assertEqual(G.pair_chain_digests()[-1], G.CORE_G22)
            original_chain = G.PAIR_CHAIN
            malformed = [('g22pair', [G.G18_CORE_IMAGE_PAIRS[-1], G.G22_CORE_IMAGE_PAIRS[1]], G.NEW_CONFIG, None),
                         ('g19pair', G.G22_CORE_IMAGE_PAIRS, G.NEW_CONFIG, None)]
            for head in malformed:
                with self.subTest(Guardian_head=head[0], first=head[1][0]), patch.object(G,'PAIR_CHAIN',(*original_chain[:-1],head)), self.assertRaises(RuntimeError):
                    G.pair_chain_digests()
            wrong_prefix=(*original_chain[:-4],('g19pair',G.G19_CORE_IMAGE_PAIRS,original_chain[-4][2],digest(b'foreign C19')),*original_chain[-3:])
            with patch.object(G,'PAIR_CHAIN',wrong_prefix), self.assertRaises(RuntimeError):
                G.pair_chain_digests()
            wrong_c20=(*original_chain[:-3],('g20pair',G.G20_CORE_IMAGE_PAIRS,original_chain[-3][2],digest(b'foreign C20')),*original_chain[-2:])
            with patch.object(G,'PAIR_CHAIN',wrong_c20), self.assertRaisesRegex(RuntimeError,'G21_EXACT_C20_RETAINS_CORE10'):
                G.pair_chain_digests()
            wrong_c21=(*original_chain[:-2],('g21pair',G.G21_CORE_IMAGE_PAIRS,C.OLD_CONFIG,digest(b'foreign C21')),original_chain[-1])
            with patch.object(G,'PAIR_CHAIN',wrong_c21), self.assertRaisesRegex(RuntimeError,'G22_EXACT_C21_RETAINS_CORE11'):
                G.pair_chain_digests()
            seen={p['image'] for _,pairs,_,_ in original_chain[:-1] for p in pairs}
            for old_image in sorted(seen):
                pairs=[dict(G.G21_CORE_IMAGE_PAIRS[-1]),{'image':old_image,'image_id':old_image}]
                with self.subTest(readmitted=old_image), patch.multiple(G,
                        HEAD_NEW_CORE_DIGEST='sha256:'+old_image.rsplit(':',1)[-1],
                        CORE_G22=old_image,G22_CORE_IMAGE_PAIRS=pairs,
                        PAIR_CHAIN=(*original_chain[:-1],('g22pair',pairs,G.NEW_CONFIG,None))), self.assertRaises(RuntimeError):
                    G.pair_chain_digests()
            expected = copy.deepcopy(previous)
            expected.update(core_container_images=G.G22_CORE_IMAGE_PAIRS, root_review_attestation=review)
            chain = (*D.PAIR_CHAIN[:-len(generations)-1],
                *((name.lower()+'pair', pairs, next(row[2] for row in D.PAIR_CHAIN if row[0]==name.lower()+'pair'),digest(raw))
                  for (name,pairs),raw in zip(generations,added)),
                ('g22pair',G.G22_CORE_IMAGE_PAIRS,G.NEW_CONFIG,None))
            with patch.multiple(D, PROPOSAL_BOUND=True, HEAD_NEW_CORE_DIGEST=G.HEAD_NEW_CORE_DIGEST,
                    CORE_G22=G.CORE_G22,G22_CORE_IMAGE_PAIRS=G.G22_CORE_IMAGE_PAIRS,
                    G19_CONFIG_SHA=digest(added[-3]), G20_CONFIG_SHA=digest(added[-2]), G21_CONFIG_SHA=digest(added[-1]),
                    G22_CONFIG_SHA=digest(D.canonical(expected)),PAIR_CHAIN=chain):
                all_prefix=[*prefix,*added]
                self.assertEqual(D.strict_loads(D.derive(r42,all_prefix,review)),expected)
                self.assertEqual({k for k in previous if previous[k]!=expected[k]},
                                 {'core_container_images','root_review_attestation'})
                for index in range(len(all_prefix)):
                    wrong=list(all_prefix);wrong[index]+=b' '
                    with self.subTest(prefix=index),self.assertRaises(D.Refused):D.derive(r42,wrong,review)
                with self.assertRaises(D.Refused):D.derive(r42,all_prefix,previous['root_review_attestation'])
                bad_heads=[('g22pair',[D.G18_CORE_IMAGE_PAIRS[-1],G.G22_CORE_IMAGE_PAIRS[1]]),
                           ('g22pair',[D.G19_CORE_IMAGE_PAIRS[0],G.G22_CORE_IMAGE_PAIRS[1]]),
                           ('g22pair',D.G19_CORE_IMAGE_PAIRS),('g19pair',G.G22_CORE_IMAGE_PAIRS)]
                for name,pairs in bad_heads:
                    altered={**previous,'core_container_images':pairs,'root_review_attestation':review}
                    # Match the output hash so the overlap invariant itself must refuse.
                    with self.subTest(deriver_head=name,pairs=pairs), patch.multiple(D,
                            G22_CONFIG_SHA=digest(D.canonical(altered)),
                            PAIR_CHAIN=(*chain[:-1],(name,pairs,G.NEW_CONFIG,None))),self.assertRaises(D.Refused):
                        D.derive(r42,all_prefix,review)
    def test_standing_adds_only_g14_axis_and_retains_g13_literal(self):
        controller_raw, hub_raw = b'{"declared":"G15 controller"}\n', b'{"declared":"same Hub"}\n'
        with binding(), patch.object(G, 'G22_CONTROLLER_CONFIG_SHA', digest(controller_raw)), \
                patch.object(S.C, 'HEAD_CONFIG_SHA', digest(controller_raw)):
            old = g21_operand(); old['hub_boot_config_sha256'] = digest(hub_raw)
            units = {S.C.CTRL: digest(b'declared G15 controller unit'), S.C.HUB: old['hub_unit_sha256'],
                     S.C.COLD: digest((NEW / 'units' / G.COLD).read_bytes()),
                     S.C.GUARD: digest((NEW / 'units' / G.GUARDIAN).read_bytes())}
            manifest = {'files': {'source/network_guardian.py': digest(b'declared G15 Source')}}
            value = S.build(G, manifest, old, controller_raw, hub_raw, 'Declared G15 standing review; no Root approval. ' * 4, units)
            self.assertEqual(set(value) - set(old), {'g21_predecessor_guardian_source_sha256', 'g21_predecessor_standing_config_sha256'})
            self.assertEqual({key for key in old if old[key] != value[key]},
                {'guardian_source_sha256', 'controller_unit_sha256', 'cold_unit_sha256', 'guardian_unit_sha256', 'new_controller_config_sha256', 'Root_review'})
            self.assertEqual(value['g13_predecessor_guardian_source_sha256'], C.G13_SOURCE_SHA)
            self.assertEqual(value['g13_predecessor_standing_config_sha256'], C.G13_STANDING_SHA)
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
                    'head_generation': 'g22pair', 'head_core_digest': 'sha256:'+S.C.NEW_DIGEST,
                    'head_controller_config_sha256': S.C.HEAD_CONFIG_SHA,
                    'historical_g6_controller_config_sha256': S.C.G6_CONFIG_SHA,
                    'pair_predecessor_standing_config_sha256': S.C.PREFIX_STANDINGS, **S.C.ANCESTORS,
                    'pair_chain_controller_config_sha256': {**prefix,'g22pair': S.C.HEAD_CONFIG_SHA},
                    **units, **ancestry}}
            S.C.validate_standing_output(output, expected, 'staged')
            for fault in ('missing_g14','foreign_g14','missing_g15','foreign_g15','missing_g16','foreign_g16','missing_g17','foreign_g17','missing_g18','foreign_g18','missing_g19','foreign_g19','missing_g20','foreign_g20','missing_g21','foreign_g21'):
                bad = copy.deepcopy(expected)
                key = fault.split('_', 1)[1] + 'pair'
                if fault.startswith('missing'): del bad['controller_prefix_sha256'][key]
                else: bad['controller_prefix_sha256'][key] = digest(b'foreign prefix')
                with self.subTest(standing_prefix=fault), self.assertRaises(S.C.Hold):
                    S.C.validate_standing_output(output, bad, 'staged')
            for key in ('guardian_source_sha256', 'new_controller_config_sha256', 'g13_predecessor_guardian_source_sha256'):
                wrong = copy.deepcopy(old); wrong[key] = digest(b'foreign')
                with self.subTest(old_axis=key), self.assertRaises(S.C.Hold): S.build(G, manifest, wrong, controller_raw, hub_raw, 'Declared review. ' * 20, units)

    def test_g14_predecessor_requires_original_source_and_standing_bytes(self):
        # S22 authenticates whole S21, S20, S19, S18, S17 and S16; no historical relabelling.
        with binding(), contextlib.ExitStack() as stack:
            for generation in (16, 17, 18):
                raw_source = globals()['DECLARED_G'+str(generation)+'_SOURCE']
                stack.enter_context(patch.object(G, 'G'+str(generation)+'_PREDECESSOR_SOURCE_SHA', digest(raw_source)))
            prior16=g16_operand();raw16=G.wire(prior16)
            stack.enter_context(patch.object(G,'G16_PREDECESSOR_CONFIG_SHA',digest(raw16)))
            prior17=g17_operand();raw17=G.wire(prior17)
            stack.enter_context(patch.object(G,'G17_PREDECESSOR_CONFIG_SHA',digest(raw17)))
            prior18=g18_operand();raw18=G.wire(prior18)
            stack.enter_context(patch.object(G,'G18_PREDECESSOR_CONFIG_SHA',digest(raw18)))
            prior19=g19_operand();raw19=G.wire(prior19)
            stack.enter_context(patch.object(G,'G19_PREDECESSOR_CONFIG_SHA',digest(raw19)))
            value={**prior19,'new_controller_config_sha256':G.G20_CONTROLLER_CONFIG_SHA,
                'g19_predecessor_guardian_source_sha256':G.G19_PREDECESSOR_SOURCE_SHA,
                'g19_predecessor_standing_config_sha256':digest(raw19)}
            prior20=g20_operand();raw20=G.wire(prior20)
            stack.enter_context(patch.object(G,'G20_PREDECESSOR_CONFIG_SHA',digest(raw20)))
            value21={**prior20,'new_controller_config_sha256':G.G21_CONTROLLER_CONFIG_SHA,
                'g20_predecessor_guardian_source_sha256':G.G20_PREDECESSOR_SOURCE_SHA,
                'g20_predecessor_standing_config_sha256':digest(raw20)}
            prior21=g21_operand();raw21=G.wire(prior21)
            stack.enter_context(patch.object(G,'G21_PREDECESSOR_CONFIG_SHA',digest(raw21)))
            value22={**prior21,'new_controller_config_sha256':G.G22_CONTROLLER_CONFIG_SHA,
                'g21_predecessor_guardian_source_sha256':G.G21_PREDECESSOR_SOURCE_SHA,
                'g21_predecessor_standing_config_sha256':digest(raw21)}
            originals={}
            for generation,raw in ((16,raw16),(17,raw17),(18,raw18),(19,raw19),(20,raw20),(21,raw21)):
                originals[getattr(G,'G'+str(generation)+'_PREDECESSOR_HERE')/'network_guardian.py']=globals()['DECLARED_G'+str(generation)+'_SOURCE']
                originals[getattr(G,'G'+str(generation)+'_PREDECESSOR_CONFIG')]=raw
            def read(path,*_):
                self.assertIn(path,originals);return originals[path]
            with patch.object(G,'read',side_effect=read):
                self.assertEqual(G.g21_predecessor_config(value22),prior21)
                for key in ('g21_predecessor_guardian_source_sha256','g21_predecessor_standing_config_sha256',
                        'new_controller_config_sha256','g20_predecessor_guardian_source_sha256','hub_unit_sha256'):
                    wrong=copy.deepcopy(value22);wrong[key]=digest(b'foreign g21')
                    with self.subTest(g21_axis=key),self.assertRaises(RuntimeError):G.g21_predecessor_config(wrong)
                for changed_key in ('controller_unit_sha256','cold_unit_sha256','guardian_unit_sha256','foreign_field'):
                    changed=copy.deepcopy(prior21);changed[changed_key]=digest(b'foreign M13 unit or field')
                    changed_raw=G.wire(changed);wrong={**value22,'g21_predecessor_standing_config_sha256':digest(changed_raw)}
                    with self.subTest(g21_unit=changed_key),patch.object(G,'G21_PREDECESSOR_CONFIG_SHA',digest(changed_raw)), \
                            patch.object(G,'read',side_effect=lambda path,*_:changed_raw if path==G.G21_PREDECESSOR_CONFIG else originals[path]),self.assertRaisesRegex(RuntimeError,'G21_WHOLE_PREFIX'):
                        G.g21_predecessor_config(wrong)
                self.assertEqual(G.g20_predecessor_config(value21),prior20)
                for key in ('g20_predecessor_guardian_source_sha256','g20_predecessor_standing_config_sha256',
                        'new_controller_config_sha256','g19_predecessor_guardian_source_sha256','hub_unit_sha256'):
                    wrong=copy.deepcopy(value21);wrong[key]=digest(b'foreign g20')
                    with self.subTest(g20_axis=key),self.assertRaises(RuntimeError):G.g20_predecessor_config(wrong)
                for changed_key in ('controller_unit_sha256','cold_unit_sha256','guardian_unit_sha256'):
                    changed=copy.deepcopy(prior20);changed[changed_key]=digest(b'foreign M12 unit')
                    changed_raw=G.wire(changed);wrong={**value21,'g20_predecessor_standing_config_sha256':digest(changed_raw)}
                    with self.subTest(g20_unit=changed_key),patch.object(G,'G20_PREDECESSOR_CONFIG_SHA',digest(changed_raw)), \
                            patch.object(G,'read',side_effect=lambda path,*_:changed_raw if path==G.G20_PREDECESSOR_CONFIG else originals[path]),self.assertRaisesRegex(RuntimeError,'G20_WHOLE_PREFIX'):
                        G.g20_predecessor_config(wrong)
                changed=copy.deepcopy(prior20);changed['foreign_field']=True
                changed_raw=G.wire(changed);wrong={**value21,'g20_predecessor_standing_config_sha256':digest(changed_raw)}
                with patch.object(G,'G20_PREDECESSOR_CONFIG_SHA',digest(changed_raw)), \
                        patch.object(G,'read',side_effect=lambda path,*_:changed_raw if path==G.G20_PREDECESSOR_CONFIG else originals[path]),self.assertRaisesRegex(RuntimeError,'G20_WHOLE_PREFIX'):
                    G.g20_predecessor_config(wrong)
                self.assertEqual(G.g19_predecessor_config(value),prior19)
                self.assertEqual(G.g18_predecessor_config(prior19),prior18)
                self.assertEqual(G.g17_predecessor_config(prior18),prior17)
                self.assertEqual(G.g16_predecessor_config(prior17),prior16)
                with self.assertRaisesRegex(RuntimeError,'G18_C19_PREFIX'):G.g18_predecessor_config(value)
                with self.assertRaisesRegex(RuntimeError,'G17_C18_PREFIX'):G.g17_predecessor_config(value)
                with self.assertRaisesRegex(RuntimeError,'G16_C17_PREFIX'):G.g16_predecessor_config(value)
                with self.assertRaisesRegex(RuntimeError,'EXACT_G15_AUTHORITY_AND_C16'):G.g15_predecessor_standing(value)
                for key in ('g19_predecessor_guardian_source_sha256','g19_predecessor_standing_config_sha256',
                        'new_controller_config_sha256','g13_predecessor_standing_config_sha256','hub_unit_sha256',
                        'g18_predecessor_guardian_source_sha256','g17_predecessor_guardian_source_sha256','g16_predecessor_guardian_source_sha256'):
                    wrong=copy.deepcopy(value);wrong[key]=digest(b'foreign')
                    with self.subTest(axis=key),self.assertRaises(RuntimeError):G.g19_predecessor_config(wrong)
                for changed_key in ('controller_unit_sha256','cold_unit_sha256','guardian_unit_sha256'):
                    changed=copy.deepcopy(prior19);changed[changed_key]=digest(b'foreign unit')
                    changed_raw=G.wire(changed);wrong={**value,'g19_predecessor_standing_config_sha256':digest(changed_raw)}
                    with self.subTest(unit=changed_key),patch.object(G,'G19_PREDECESSOR_CONFIG_SHA',digest(changed_raw)), \
                            patch.object(G,'read',side_effect=lambda path,*_:changed_raw if path==G.G19_PREDECESSOR_CONFIG else originals[path]),self.assertRaisesRegex(RuntimeError,'G19_WHOLE_PREFIX'):
                        G.g19_predecessor_config(wrong)
                changed=copy.deepcopy(prior19);changed['foreign_field']=True
                changed_raw=G.wire(changed);wrong={**value,'g19_predecessor_standing_config_sha256':digest(changed_raw)}
                with patch.object(G,'G19_PREDECESSOR_CONFIG_SHA',digest(changed_raw)), \
                        patch.object(G,'read',side_effect=lambda path,*_:changed_raw if path==G.G19_PREDECESSOR_CONFIG else originals[path]),self.assertRaisesRegex(RuntimeError,'G19_WHOLE_PREFIX'):
                    G.g19_predecessor_config(wrong)
            for changed in originals:
                def changed_read(path,*_):
                    return originals[path]+b' ' if path==changed else originals[path]
                with self.subTest(changed=changed),patch.object(G,'read',side_effect=changed_read),self.assertRaises(RuntimeError):
                    prior=G.g21_predecessor_config(value22);prior=G.g20_predecessor_config(prior);prior=G.g19_predecessor_config(prior);prior=G.g18_predecessor_config(prior);prior=G.g17_predecessor_config(prior);G.g16_predecessor_config(prior)
    def test_protected43_budget_cold_hub_and_six_commands_are_unchanged(self):
        with binding(): self.assertEqual(C.protected_ref_union(), historical.C.protected_ref_union())
        self.assertEqual(CUT.NATIVE_SEQUENCE, historical.CUT.NATIVE_SEQUENCE)
        self.assertEqual(len(CUT.NATIVE_SEQUENCE), 6)
        for name in ('protected', 'final_closure'):
            self.assertEqual(source_span(NEW / 'tools/g15cut.py', 'Backend', name),
                             source_span(historical.NEW / 'tools/g14cut.py', 'Backend', name))
        protected = source_span(NEW / 'tools/g15cut.py', 'Backend', 'protected')
        self.assertIn('len(markers) == 1', protected)
        closure = source_span(NEW / 'tools/g15cut.py', 'Backend', 'final_closure')
        self.assertIn('self.protected() == self.protected_before', closure)
        self.assertIn('COLD_HUB_SAME_ORIGINAL_COMPLETED_LIFETIMES_NO_EXECUTION', closure)
        # Current overlap is 8d79/Core11; historical digests are refused.
        with binding():
            image = CUT.C.IMAGE_PREFIX + CUT.C.OLD_DIGEST
            dep = {'metadata': {'uid': CUT.C.OLD_CORE_UID, 'generation': CUT.C.OLD_CORE_GENERATION,
                    'annotations': {'dakasa.io/core-source-commit': CUT.C.OLD_CORE_SOURCE}},
                'spec': {'replicas': 1, 'template': {'spec': {'containers': [{'name': 'core', 'image': image}]}}},
                'status': {'observedGeneration': CUT.C.OLD_CORE_GENERATION, 'readyReplicas': 1, 'availableReplicas': 1, 'updatedReplicas': 1}}
            pod = {'metadata': {'uid': CUT.C.OLD_CORE_POD_UID, 'name': 'declared-core'},
                'spec': {'containers': [{'name': 'core', 'image': image}]},
                'status': {'phase': 'Running', 'podIP': '192.0.2.10', 'containerStatuses': [{'name': 'core',
                    'ready': True, 'restartCount': 0, 'state': {'running': {'startedAt': 'declared'}},
                    'imageID': image, 'containerID': 'containerd://declared'}]}}
            replies = [SimpleNamespace(returncode=0, stdout=C.wire(dep)), SimpleNamespace(returncode=0, stdout=C.wire({'items': [pod]}))]
            with patch.object(CUT, 'native', side_effect=replies) as calls:
                self.assertEqual(CUT.core_overlap()['deployment_uid'], CUT.C.OLD_CORE_UID)
                self.assertEqual(calls.call_count, 2)
            wrong_pod = copy.deepcopy(pod)
            wrong_pod['status']['containerStatuses'][0]['containerID'] = 'containerd://foreign'
            with patch.object(CUT, 'native', side_effect=[replies[0], SimpleNamespace(returncode=0, stdout=C.wire({'items': [wrong_pod]}))]):
                with self.assertRaises(CUT.C.Hold): CUT.core_overlap()

            for previous_digest in ('8dcf22ae1aa0e16c5cace160c4d71398363e460ac54f6ca80a9c32ffbda5cac9',
                                    'ed5ee3a2a5e90e54acc3cc2492fcc302a85e1b7adb6f545c605c5bfe2a730b42',
                                    '311e5c19868a67f900b318e059a806e45e5dd217d0c411a03bcd598f6f10d5ce',
                                    '85be238c7f5b15760f7eb903646cc48f6b4b86a6995d0a4727a1ba0d86d06876',
                                    '35195e4ddff2a69f2ae7fca8f24b43177c61c49f12117a4fe4925a43e9cd6fde',
                                    '8e6d44d86bbae4463652d4bf9b3583241483a0813a4d34c7254b9c2e56dccafc',
                                    '9b6e2a5d06eed90b7b44d059d3f78a405a21430a7b104f17498c904f499bdd97'):
                previous_image = CUT.C.IMAGE_PREFIX + previous_digest
                previous_dep, previous_pod = copy.deepcopy(dep), copy.deepcopy(pod)
                previous_dep['spec']['template']['spec']['containers'][0]['image'] = previous_image
                previous_pod['spec']['containers'][0]['image'] = previous_image
                previous_pod['status']['containerStatuses'][0]['imageID'] = previous_image
                previous_replies = [SimpleNamespace(returncode=0, stdout=C.wire(previous_dep)),
                                    SimpleNamespace(returncode=0, stdout=C.wire({'items': [previous_pod]}))]
                with self.subTest(previous_digest=previous_digest), patch.object(CUT.C, 'OLD_DIGEST', previous_digest), patch.object(CUT, 'native', side_effect=previous_replies):
                    with self.assertRaisesRegex(CUT.C.Hold, 'EXACT_CURRENT_R11_OVERLAP_DIGEST'): CUT.core_overlap()

        class OnceBackend:
            def __init__(self, fail=None):self.claimed=False;self.records={};self.calls=[];self.fail=fail
            def record_once(self,name,value):
                if name in self.records:raise FileExistsError(name)
                self.records[name]=value
            def preconditions(self):pass
            def claim_once(self):
                if self.claimed:raise FileExistsError('same new semantic claim')
                self.claimed=True
            def native(self,argv,seconds):
                self.calls.append(tuple(argv))
                if argv==self.fail:raise TimeoutError('declared lost acknowledgement')
                return SimpleNamespace(returncode=0,stdout=b'DECLARED',stderr=b'')
            def __getattr__(self,name):
                if name=='final_closure':return lambda:{'declared_CI_only':True}
                if name in {'quiescent_guardian','assert_old_guardian_absent','cas_controller_once',
                    'verify_controller_definition','fresh_window','assert_old_controller_absent',
                    'controller_inputs','wait_new_controller','cas_future_units_once',
                    'install_standing_once','wait_new_guardian'}:return lambda:None
                raise AttributeError(name)
        with binding():
            backend=OnceBackend();CUT.swap_once(backend)
            self.assertEqual(backend.calls,[tuple(argv)for _,argv in CUT.NATIVE_SEQUENCE])
            self.assertEqual(backend.records['RETURN.json']['schema'],'g15_pair_swap_return_v1')
            with self.assertRaises(FileExistsError):CUT.swap_once(backend)
            self.assertEqual(len(backend.calls),6)
            for _,argv in CUT.NATIVE_SEQUENCE:
                failed=OnceBackend(argv)
                with self.subTest(uncertain=argv),self.assertRaises(CUT.Hold):CUT.swap_once(failed)
                count=len(failed.calls)
                self.assertIn('HOLD.json',failed.records)
                with self.assertRaises(FileExistsError):CUT.swap_once(failed)
                self.assertEqual(len(failed.calls),count)
