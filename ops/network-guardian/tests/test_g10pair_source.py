"""Additive G10 protocol cases; declared data never certify a native lifetime."""
import ast
import contextlib
import copy
import hashlib
import json
from pathlib import Path
import types
import unittest
from unittest.mock import patch

import test_g9pair_source as old
import test_g9pair_tools as old_tools

ROOT = old.ROOT
NEW = ROOT / 'g10pair'


def load(path, allow_definition_read=False):
    raw = path.read_bytes()
    if allow_definition_read:
        # Enable only the import-time definition loader in this isolated module.
        # The loaded contract itself remains False; no runtime validator is bypassed.
        raw = raw.replace(b'PROPOSAL_BOUND = False\n', b'PROPOSAL_BOUND = True\n', 1)
    module = types.ModuleType('declared_g10_CI_' + path.stem)
    module.__file__ = str(path)
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


G = load(NEW / 'source/network_guardian.py')
C = load(NEW / 'tools/pair_change_contract.py')
D = load(NEW / 'tools/derive_g10pair_controller_config.py')
S = load(NEW / 'tools/derive_standing_config.py', True)
CUT = load(NEW / 'tools/g10cut.py', True)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def g9_operand():
    v = old.current_standing()
    package = json.loads((old.NEW / 'PACKAGE.json').read_bytes())
    v.update(guardian_source_sha256=G.G9_PREDECESSOR_SOURCE_SHA,
             new_controller_config_sha256=G.G9_CONTROLLER_CONFIG_SHA,
             controller_unit_sha256=package['controller_unit_sha256'],
             cold_unit_sha256=package['files']['units/' + G.COLD],
             guardian_unit_sha256=package['files']['units/' + G.GUARDIAN],
             Root_review='Declared CI G9 authority shape, not an installed standing or Root approval. ' * 3)
    return v


def head_operand():
    v = copy.deepcopy(g9_operand())
    v.update(schema=G.SCHEMA, guardian_source_sha256=digest((NEW / 'source/network_guardian.py').read_bytes()),
             controller_unit_sha256=digest(b'declared controller unit'),
             cold_unit_sha256=digest((NEW / 'units' / G.COLD).read_bytes()),
             guardian_unit_sha256=digest((NEW / 'units' / G.GUARDIAN).read_bytes()),
             new_controller_config_sha256=G.G10_CONTROLLER_CONFIG_SHA,
             Root_review='Declared CI G10 shape only; never actual qualification or publication authority. ' * 3,
             g9_predecessor_guardian_source_sha256=G.G9_PREDECESSOR_SOURCE_SHA,
             g9_predecessor_standing_config_sha256=G.G9_PREDECESSOR_CONFIG_SHA)
    return v


@contextlib.contextmanager
def binding(*contracts):
    d = digest(b'declared G10 compiler image, not an OCI artifact')
    image = G.CORE_IMAGE_REF + 'sha256:' + d
    pairs = [{'image': G.CORE_G9, 'image_id': G.CORE_G9}, {'image': image, 'image_id': image}]
    chain = (*G.PAIR_CHAIN[:-1], ('g10pair', pairs, G.NEW_CONFIG, None))
    standing_sha = digest(G.wire(g9_operand()))
    head_sha = digest(b'declared G10 controller data')
    with contextlib.ExitStack() as st:
        st.enter_context(patch.multiple(G, PROPOSAL_BOUND=True, HEAD_CORE_SOURCE='c' * 40,
            HEAD_NEW_CORE_DIGEST='sha256:' + d, CORE_G10=image, G10_CORE_IMAGE_PAIRS=pairs,
            G10_CONTROLLER_CONFIG_SHA=head_sha, G9_PREDECESSOR_CONFIG_SHA=standing_sha,
            PAIR_CHAIN=chain, ALLOWED_CORE_IMAGE_PAIRS=tuple(v[1] for v in chain)))
        for c in {id(x): x for x in (C, S.C, CUT.C, *contracts)}.values():
            st.enter_context(patch.multiple(c, PROPOSAL_BOUND=True, SOURCE_R='c' * 40,
                NEW_DIGEST=d, G10_CONFIG_SHA=head_sha, HEAD_CONFIG_SHA=head_sha,
                OLD_CORE_GENERATION=273, OLD_CORE_POD_UID='11111111-1111-4111-8111-111111111111',
                ACTUAL_PREDECESSOR_STANDING_SHA=standing_sha,
                ANCESTORS={**c.ANCESTORS, 'g9_predecessor_standing_config_sha256':standing_sha},
                EXPECTED_G9_PROOF_REFS={str(c.LEDGER / 'declared-g9-QUALIFIED.PUBLIC.json'): digest(b'G9 full120'),
                                        str(c.LEDGER / 'declared-g9-FIRST-CURRENT15-RETURN.PUBLIC.json'): digest(b'G9 own15')},
                ROOT_G9_REF_ACCEPTANCE_SHA=digest(b'declared review only'),
                REQUIRED_CI=frozenset({('Owned Network Guardian', 'pull_request')})))
        yield


def source_span(path, owner, name):
    raw = path.read_text(); tree = ast.parse(raw)
    if owner:
        tree = next(x for x in tree.body if isinstance(x, ast.ClassDef) and x.name == owner)
    node = next(x for x in tree.body if isinstance(x, ast.FunctionDef) and x.name == name)
    return ''.join(raw.splitlines(True)[node.lineno-1:node.end_lineno])


class G10SourceTests(unittest.TestCase):
    def test_all_unbound_entrypoints_refuse_before_source_or_native_io(self):
        with patch.object(G, 'PROPOSAL_BOUND', False), patch.object(C, 'PROPOSAL_BOUND', False), \
                patch.object(G, 'read') as read, patch.object(C, 'read') as cread:
            for call in (G.require_bound, G.pair_chain_digests, lambda: G.Owner('1' * 64),
                         lambda: C.package('/never-read', '1' * 64)):
                with self.assertRaises(RuntimeError):
                    call()
            read.assert_not_called(); cread.assert_not_called()
        for path in (NEW/'tools/derive_standing_config.py', NEW/'tools/g10cut.py'):
            raw = path.read_bytes().replace(b'PROPOSAL_BOUND = True\n', b'PROPOSAL_BOUND = False\n', 1)
            with patch.object(Path, 'read_bytes') as read:
                with self.assertRaisesRegex(RuntimeError, 'UNBOUND_BEFORE_SOURCE_IO'):
                    exec(compile(raw, str(path), 'exec'), {'__file__': str(path), '__name__': 'inert_CI'})
                read.assert_not_called()

    def test_exact_seven_helpers_31_owner_methods_and_historical_prefix(self):
        package = json.loads((old.NEW / 'PACKAGE.json').read_bytes())
        for name, pin in package['unchanged_helpers_sha256'].items():
            self.assertEqual((NEW/name).read_bytes(), (old.NEW/name).read_bytes())
            self.assertEqual(digest((NEW/name).read_bytes()), pin)
        for name in package['unchanged_owner_methods_sha256']:
            self.assertEqual(source_span(NEW/'source/network_guardian.py', 'Owner', name),
                             source_span(old.NEW/'source/network_guardian.py', 'Owner', name))
        self.assertEqual(G.PAIR_STANDING_CHAIN, old.g9.PAIR_STANDING_CHAIN)
        self.assertEqual(G.RUNTIME_HASHES, old.g9.RUNTIME_HASHES)

    def test_pair_appends_only_one_new_image_and_never_readmits(self):
        self.assertEqual(G.PAIR_CHAIN[:-2], old.g9.PAIR_CHAIN[:-1])
        self.assertEqual(G.PAIR_CHAIN[-2][:2], old.g9.PAIR_CHAIN[-1][:2])
        self.assertEqual(G.PAIR_CHAIN[-2][3], old.g9.G9_CONTROLLER_CONFIG_SHA)
        with binding():
            self.assertEqual(G.pair_chain_digests()[-2:], [G.CORE_G9, G.CORE_G10])
            for bad in (G.CORE_G8, G.CORE_G9):
                pairs = [dict(G.G10_CORE_IMAGE_PAIRS[0]), {'image': bad, 'image_id': bad}]
                with patch.object(G, 'PAIR_CHAIN', (*G.PAIR_CHAIN[:-1], ('g10pair', pairs, G.NEW_CONFIG, None))):
                    with self.assertRaises(RuntimeError):
                        G.pair_chain_digests()

    def test_fifth_authority_full_bytes_prefix_and_mixed_axes(self):
        raw = G.wire(g9_operand())
        actual_source = (old.NEW/'source/network_guardian.py').read_bytes()
        self.assertEqual(digest(actual_source), G.G9_PREDECESSOR_SOURCE_SHA)
        def read(path, *_):
            return actual_source if path == G.G9_PREDECESSOR_HERE/'network_guardian.py' else raw
        with binding(), patch.object(G, 'read', side_effect=read):
            value = head_operand()
            self.assertEqual(G.g9_predecessor_standing(value), (G.G9_PREDECESSOR_SOURCE_SHA, digest(raw)))
            for key in ('g9_predecessor_guardian_source_sha256', 'g9_predecessor_standing_config_sha256',
                        'new_controller_config_sha256', 'hub_unit_sha256', 'proof_index_ref'):
                wrong = copy.deepcopy(value); wrong[key] = 'wrong'
                with self.subTest(key=key), self.assertRaises(RuntimeError):
                    G.g9_predecessor_standing(wrong)
            with patch.object(G, 'read', return_value=raw+b' '), self.assertRaises(RuntimeError):
                G.g9_predecessor_standing(value)

    def test_closed_29_fields_preserve_all_five_axes(self):
        self.assertEqual(G.HISTORICAL_G9_FIELDS, old.g9.FIELDS)
        self.assertEqual(G.FIELDS - G.HISTORICAL_G9_FIELDS,
                         {'g9_predecessor_guardian_source_sha256', 'g9_predecessor_standing_config_sha256'})
        self.assertEqual(len(G.FIELDS), 29)
        with binding():
            v = head_operand(); G.validate(v)
            for key in ('g6_predecessor_guardian_source_sha256', 'g6_boot_v2_predecessor_standing_config_sha256',
                        'g7_predecessor_guardian_source_sha256', 'g8_predecessor_standing_config_sha256',
                        'g9_predecessor_standing_config_sha256'):
                wrong=copy.deepcopy(v); wrong[key]='1'*64
                with self.subTest(key=key), self.assertRaises(RuntimeError):
                    G.validate(wrong)

    def test_ref_union_retains_all41_without_overwrite_or_budget_reset(self):
        with binding():
            refs=C.protected_ref_union()
            self.assertEqual(len(refs),43)
            self.assertTrue(all(refs[k] == v for k,v in old_tools.protected_refs().items()))
            name=next(iter(C.EXPECTED_INHERITED_REFS))
            for pin in (C.EXPECTED_INHERITED_REFS[name], digest(b'replacement')):
                with patch.object(C,'EXPECTED_G9_PROOF_REFS',{name:pin,'/declared/other':digest(b'other')}):
                    with self.assertRaises(C.Hold): C.protected_ref_union()
