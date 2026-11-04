"""Declared G11 maintenance operands; no native lifetime or approval is inferred."""
import contextlib
import copy
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import test_g10pair_source as historical
import test_g10pair_core_cas as historical_cas


ROOT = historical.ROOT
NEW = ROOT / 'g11pair'
load, digest = historical.load, historical.digest
G = load(NEW / 'source/network_guardian.py')
C = load(NEW / 'tools/pair_change_contract.py')
D = load(NEW / 'tools/derive_g11pair_controller_config.py')
S = load(NEW / 'tools/derive_standing_config.py', True)
CUT = load(NEW / 'tools/g11cut.py', True)
cas = load(ROOT / 'rollout/core_image_cas_once_g11.py')


def g10_operand():
    value = historical.head_operand()
    package = json.loads((historical.NEW / 'PACKAGE.json').read_bytes())
    value.update(guardian_source_sha256=G.G10_PREDECESSOR_SOURCE_SHA,
                 new_controller_config_sha256=G.G10_CONTROLLER_CONFIG_SHA,
                 controller_unit_sha256=package['controller_unit_sha256'],
                 cold_unit_sha256=package['files']['units/' + G.COLD],
                 guardian_unit_sha256=package['files']['units/' + G.GUARDIAN],
                 Root_review='Declared G10 CI standing operand; never an installed standing or Root approval. ' * 3)
    return value


def head_operand():
    value = copy.deepcopy(g10_operand())
    value.update(schema=G.SCHEMA,
                 guardian_source_sha256=digest((NEW / 'source/network_guardian.py').read_bytes()),
                 controller_unit_sha256=digest(b'declared G11 controller unit'),
                 cold_unit_sha256=digest((NEW / 'units' / G.COLD).read_bytes()),
                 guardian_unit_sha256=digest((NEW / 'units' / G.GUARDIAN).read_bytes()),
                 new_controller_config_sha256=G.G11_CONTROLLER_CONFIG_SHA,
                 Root_review='Declared G11 CI standing shape; never qualification or publication authority. ' * 3,
                 g10_predecessor_guardian_source_sha256=G.G10_PREDECESSOR_SOURCE_SHA,
                 g10_predecessor_standing_config_sha256=G.G10_PREDECESSOR_CONFIG_SHA)
    return value


@contextlib.contextmanager
def binding():
    """Bind declared inputs only; all production predicates remain in place."""
    new_digest = digest(b'declared G11 compiler image, not an OCI artifact')
    image = G.CORE_IMAGE_REF + 'sha256:' + new_digest
    pairs = [{'image': G.CORE_G10, 'image_id': G.CORE_G10}, {'image': image, 'image_id': image}]
    chain = (*G.PAIR_CHAIN[:-1], ('g11pair', pairs, G.NEW_CONFIG, None))
    standing_sha = digest(G.wire(g10_operand()))
    head_sha = digest(b'declared G11 controller data')
    with contextlib.ExitStack() as stack:
        stack.enter_context(patch.multiple(G, PROPOSAL_BOUND=True, HEAD_CORE_SOURCE='c' * 40,
            HEAD_NEW_CORE_DIGEST='sha256:' + new_digest, CORE_G11=image, G11_CORE_IMAGE_PAIRS=pairs,
            G11_CONTROLLER_CONFIG_SHA=head_sha, G10_PREDECESSOR_CONFIG_SHA=standing_sha,
            PAIR_CHAIN=chain, ALLOWED_CORE_IMAGE_PAIRS=tuple(row[1] for row in chain)))
        for contract in {id(value): value for value in (C, S.C, CUT.C)}.values():
            stack.enter_context(patch.multiple(contract, PROPOSAL_BOUND=True, SOURCE_R='c' * 40,
                NEW_DIGEST=new_digest, G11_CONFIG_SHA=head_sha, HEAD_CONFIG_SHA=head_sha,
                OLD_CORE_GENERATION=274, OLD_CORE_POD_UID='11111111-1111-4111-8111-111111111111',
                ACTUAL_PREDECESSOR_STANDING_SHA=standing_sha,
                ANCESTORS={**contract.ANCESTORS, 'g10_predecessor_standing_config_sha256': standing_sha},
                REQUIRED_CI=frozenset({('Owned Network Guardian', 'pull_request')})))
        yield


def seal_row(row):
    raw = cas.canonical(row['original_record'])
    row.update(record_sha256=cas.sha(raw), original_wire='\\x' + raw.hex())


def known_operand():
    """Extend the declared five-row f30 fixture; retain all five original wires."""
    value, config = historical_cas.known_operand()
    intent = json.loads(value['intent_pgtext'])
    intent.update(fencing_token=31, lease_owner='3ec9cd58-b752-4877-9031-d997661d3c5f',
                  lease_executor_id='6f0c459a-c6b9-4c18-bc55-f51d6244f4e5', lease_expires_at=cas.LEASE)
    intent['retirement_forward']['id'] = cas.CURRENT_CHILD
    value['intent_pgtext'] = cas.canonical(intent).decode()
    failed = json.loads(value['failed_run_pgtext'])
    failed.update(id=cas.FAILED, finished_at='2026-11-04T10:22:15.100000Z')
    value.update(observed_at_pg='2026-11-04T11:00:00Z', failed_run_pgtext=cas.canonical(failed).decode())
    value['dispatch'][0].update(id='a0d73637-9be9-46f5-ad27-d5f730e3c495', run_id=cas.FAILED,
                                returned_at=failed['finished_at'], finalization_ack_at='2026-11-04T10:22:15.113019Z')
    retained = {(row['id'], row['stage']): row for row in value['forwards']}
    parent_sha = retained[(cas.CHILD, 'admitted')]['record_sha256']
    for stage in ('requested', 'admitted'):
        row = copy.deepcopy(retained[(cas.CHILD, stage)])
        row['id'] = cas.CURRENT_CHILD
        record = row['original_record']
        record.update(id=cas.CURRENT_CHILD, parent_admission_id=cas.CHILD, parent_admission_sha256=parent_sha)
        if stage == 'admitted':
            record.update(generation=14, fence=31, lease_owner=intent['lease_owner'],
                          executor_id=intent['lease_executor_id'], run_id=cas.FAILED, destroy_grant_id=cas.DESTROY)
        seal_row(row)
        value['forwards'].append(row)
    config.update(current_intent_sha256=cas.sha(value['intent_pgtext'].encode()),
                  failed_run_sha256=cas.sha(value['failed_run_pgtext'].encode()))
    return value, config


class G11MaintenanceTests(unittest.TestCase):
    def test_forced_unbound_entrypoints_refuse_before_io(self):
        self.assertEqual((cas.OLD_SOURCE, C.OLD_CORE_SOURCE), ('d7d7adcff71807e60b782f50c8473bbb5981b9c9',) * 2)
        self.assertEqual((cas.GENERATION, C.OLD_CORE_GENERATION), (274, 274))
        self.assertEqual((cas.OLD_POD, C.OLD_CORE_POD_UID), ('f352ab92-7ff4-4f08-9699-46037ca64375',) * 2)
        # Declared current-R1 objects exercise the actual reachable guard;
        # the image, deployment and Pod validators are not patched or mirrored.
        image = C.IMAGE_PREFIX + '4fa5525f3b4bdac22a83260bac4fdd655106720b73ede11300f6f034451a6181'
        deployment = {'apiVersion': 'apps/v1', 'kind': 'Deployment',
            'metadata': {'namespace': 'dakasa', 'name': 'yggdrasil', 'uid': cas.UID,
                         'generation': 274, 'resourceVersion': '1',
                         'annotations': {'dakasa.io/core-source-commit': C.OLD_CORE_SOURCE}},
            'spec': {'replicas': 1, 'template': {'spec': {'containers': [{'name': 'core', 'image': image}]}}},
            'status': {'observedGeneration': 274, 'readyReplicas': 1, 'updatedReplicas': 1, 'availableReplicas': 1}}
        pod = {'metadata': {'uid': cas.OLD_POD, 'name': 'declared-current-r1'},
               'spec': {'containers': [{'name': 'core', 'image': image}]},
               'status': {'phase': 'Running', 'podIP': '192.0.2.1', 'containerStatuses': [{
                   'name': 'core', 'ready': True, 'restartCount': 0,
                   'state': {'running': {'startedAt': '2026-11-04T09:45:44Z'}},
                   'imageID': image, 'containerID': 'containerd://' + 'a' * 64}]}}
        current = cas.core_before(deployment, {'items': [pod]}, C)
        self.assertEqual((current['generation'], current['pod_uid'], current['image'], current['containerID']),
                         (274, cas.OLD_POD, image, 'containerd://' + 'a' * 64))
        with patch.object(C, 'OLD_DIGEST', '7f86e55cebd3dfcd3e1e027d8ddb573358ba8b42753348bfbda108bf6d39a0b6'):
            with self.assertRaisesRegex(cas.Hold, 'EXACT_CURRENT_R1_AMD64'):
                cas.core_before(deployment, {'items': [pod]}, C)
        for axis in ('source', 'deployment_image', 'pod_uid', 'pod_image', 'image_id'):
            wrong_d, wrong_p = copy.deepcopy(deployment), copy.deepcopy(pod)
            if axis == 'source': wrong_d['metadata']['annotations']['dakasa.io/core-source-commit'] = '0' * 40
            elif axis == 'deployment_image': wrong_d['spec']['template']['spec']['containers'][0]['image'] = C.IMAGE_PREFIX + '1' * 64
            elif axis == 'pod_uid': wrong_p['metadata']['uid'] = '11111111-1111-4111-8111-111111111111'
            elif axis == 'pod_image': wrong_p['spec']['containers'][0]['image'] = C.IMAGE_PREFIX + '1' * 64
            else: wrong_p['status']['containerStatuses'][0]['imageID'] = C.IMAGE_PREFIX + '1' * 64
            with self.subTest(current_r1_axis=axis), self.assertRaises(cas.Hold):
                cas.core_before(wrong_d, {'items': [wrong_p]}, C)
        # Force False even after a later release binds these modules.
        with patch.object(G, 'PROPOSAL_BOUND', False), patch.object(C, 'PROPOSAL_BOUND', False), \
                patch.object(G, 'read') as read, patch.object(C, 'read') as contract_read:
            for call in (G.require_bound, G.pair_chain_digests, lambda: G.Owner('1' * 64),
                         lambda: C.package('/never-read', '1' * 64)):
                with self.subTest(entrypoint=repr(call)), self.assertRaises(RuntimeError):
                    call()
            read.assert_not_called(); contract_read.assert_not_called()
        with patch.object(D, 'PROPOSAL_BOUND', False), patch.object(D, 'read_private') as read:
            with self.assertRaises(D.Refused): D.derive(b'{}', [], 'declared')
            read.assert_not_called()
        with patch.object(CUT.C, 'PROPOSAL_BOUND', False), patch.object(CUT, 'native') as native, \
                patch.object(CUT, 'custody') as custody:
            with self.assertRaises(CUT.C.Hold): CUT.send_once(object(), *CUT.NATIVE_SEQUENCE[0])
            with self.assertRaises(CUT.C.Hold): CUT.main()
            native.assert_not_called(); custody.assert_not_called()
        with patch.object(cas, 'PROPOSAL_BOUND', False), patch.object(cas, 'read') as read, \
                patch.object(cas, 'load_tools') as tools, patch.object(cas, 'API') as api:
            with self.assertRaises(cas.Hold): cas.main()
            read.assert_not_called(); tools.assert_not_called(); api.assert_not_called()
        for path in (NEW / 'tools/derive_standing_config.py', NEW / 'tools/g11cut.py'):
            raw = path.read_bytes().replace(b'PROPOSAL_BOUND = True\n', b'PROPOSAL_BOUND = False\n', 1)
            with self.subTest(import_guard=path.name), patch.object(Path, 'read_bytes') as read:
                with self.assertRaisesRegex(RuntimeError, 'UNBOUND_BEFORE_SOURCE_IO'):
                    exec(compile(raw, str(path), 'exec'), {'__file__': str(path), '__name__': 'inert_G11_CI'})
                read.assert_not_called()

    def test_controller_derivation_extends_exact_g10_prefix(self):
        r42, prefix = historical.old_tools.controller_inputs()
        previous = D.strict_loads(prefix[-1])
        added = []
        for generation, pairs in (('G9', D.G9_CORE_IMAGE_PAIRS), ('G10', D.G10_CORE_IMAGE_PAIRS)):
            previous = copy.deepcopy(previous)
            previous.update(core_container_images=pairs,
                            root_review_attestation=('Declared prior ' + generation + ' CI config; no installed config claim. ') * 3)
            added.append(D.canonical(previous))
        review = 'Declared new G11 CI controller operand; no Root approval or native adoption. ' * 3
        with binding():
            expected = copy.deepcopy(previous)
            expected.update(core_container_images=G.G11_CORE_IMAGE_PAIRS, root_review_attestation=review)
            chain = (*D.PAIR_CHAIN[:-3],
                     ('g9pair', D.G9_CORE_IMAGE_PAIRS, D.G9_CONFIG, digest(added[0])),
                     ('g10pair', D.G10_CORE_IMAGE_PAIRS, D.G10_CONFIG, digest(added[1])),
                     ('g11pair', G.G11_CORE_IMAGE_PAIRS, D.G11_CONFIG, None))
            with patch.multiple(D, PROPOSAL_BOUND=True, HEAD_NEW_CORE_DIGEST=G.HEAD_NEW_CORE_DIGEST,
                    CORE_G11=G.CORE_G11, G11_CORE_IMAGE_PAIRS=G.G11_CORE_IMAGE_PAIRS,
                    G11_CONFIG_SHA=digest(D.canonical(expected)), PAIR_CHAIN=chain):
                all_prefix = [*prefix, *added]
                self.assertEqual(D.strict_loads(D.derive(r42, all_prefix, review)), expected)
                self.assertEqual({key for key in previous if previous[key] != expected[key]},
                                 {'core_container_images', 'root_review_attestation'})
                for index in range(len(all_prefix)):
                    changed = list(all_prefix); changed[index] += b' '
                    with self.subTest(predecessor=index), self.assertRaises(D.Refused):
                        D.derive(r42, changed, review)
                with self.assertRaises(D.Refused):
                    D.derive(r42, all_prefix, previous['root_review_attestation'])

    def test_standing_derivation_retains_g10_and_all_ancestor_axes(self):
        controller_raw = b'{"declared":"G11 CI controller"}\n'
        hub_raw = b'{"declared":"unchanged CI hub"}\n'
        with binding(), patch.object(G, 'G11_CONTROLLER_CONFIG_SHA', digest(controller_raw)), \
                patch.object(S.C, 'HEAD_CONFIG_SHA', digest(controller_raw)):
            old = g10_operand(); old['hub_boot_config_sha256'] = digest(hub_raw)
            units = {S.C.CTRL: digest(b'declared G11 controller'), S.C.HUB: old['hub_unit_sha256'],
                     S.C.COLD: digest(b'declared G11 cold unit'), S.C.GUARD: digest(b'declared G11 guardian unit')}
            manifest = {'files': {'source/network_guardian.py': digest(b'declared G11 source')}}
            value = S.build(G, manifest, old, controller_raw, hub_raw,
                            'Declared G11 standing review; never generated actual Root approval. ' * 4, units)
            self.assertEqual(set(value) - set(old),
                             {'g10_predecessor_guardian_source_sha256', 'g10_predecessor_standing_config_sha256'})
            self.assertEqual({key for key in old if old[key] != value[key]},
                             {'schema', 'guardian_source_sha256', 'controller_unit_sha256', 'cold_unit_sha256',
                              'guardian_unit_sha256', 'new_controller_config_sha256', 'Root_review'})
            for key in ('guardian_source_sha256', 'new_controller_config_sha256',
                        'g9_predecessor_guardian_source_sha256', 'g9_predecessor_standing_config_sha256',
                        'g6_boot_v2_predecessor_standing_config_sha256'):
                wrong = copy.deepcopy(old); wrong[key] = '1' * 64
                with self.subTest(axis=key), self.assertRaises(S.C.Hold):
                    S.build(G, manifest, wrong, controller_raw, hub_raw, 'Declared review. ' * 12, units)

    def test_runtime_g10_predecessor_requires_full_bytes_and_mixed_axes_refuse(self):
        raw = G.wire(g10_operand())
        actual_source = (historical.NEW / 'source/network_guardian.py').read_bytes()
        self.assertEqual(digest(actual_source), G.G10_PREDECESSOR_SOURCE_SHA)
        self.assertEqual(G.HISTORICAL_G10_FIELDS, historical.G.FIELDS)
        def read(path, *_):
            return actual_source if path == G.G10_PREDECESSOR_HERE / 'network_guardian.py' else raw
        with binding(), patch.object(G, 'read', side_effect=read):
            value = head_operand()
            self.assertEqual(G.g10_predecessor_standing(value), (G.G10_PREDECESSOR_SOURCE_SHA, digest(raw)))
            for key in ('g10_predecessor_guardian_source_sha256', 'g10_predecessor_standing_config_sha256',
                        'g9_predecessor_standing_config_sha256', 'g6_boot_v2_predecessor_guardian_source_sha256',
                        'new_controller_config_sha256', 'hub_unit_sha256', 'proof_index_ref'):
                wrong = copy.deepcopy(value); wrong[key] = 'wrong'
                with self.subTest(axis=key), self.assertRaises(RuntimeError): G.g10_predecessor_standing(wrong)
            for source_changed in (False, True):
                def changed_read(path, *_):
                    is_source = path == G.G10_PREDECESSOR_HERE / 'network_guardian.py'
                    original = actual_source if is_source else raw
                    return original + b' ' if is_source == source_changed else original
                with self.subTest(source_changed=source_changed), patch.object(G, 'read', side_effect=changed_read), \
                        self.assertRaises(RuntimeError): G.g10_predecessor_standing(value)

    def test_protected_union_preserves_all_43_no_reset(self):
        inherited = historical.C.protected_ref_union()
        self.assertEqual(len(inherited), 43)
        with binding():
            self.assertEqual(C.protected_ref_union(), inherited)
            name = next(iter(C.EXPECTED_INHERITED_REFS))
            for pin in (C.EXPECTED_INHERITED_REFS[name], digest(b'replacement')):
                with patch.object(C, 'EXPECTED_G9_PROOF_REFS', {name: pin, '/declared/other': digest(b'other')}):
                    with self.assertRaises(C.Hold): C.protected_ref_union()

    def test_known_seven_row_child_preserves_original_bytes_and_ancestry(self):
        historical_value, _ = historical_cas.known_operand()
        value, config = known_operand()
        original = cas.canonical(value)
        self.assertEqual(value['forwards'][:5], historical_value['forwards'])
        self.assertEqual(len(value['forwards']), 7)
        self.assertTrue(cas.validate_known_child(value, config, json.loads))
        self.assertEqual(cas.canonical(value), original)
        # Actual PG five-digit spelling must reach the real whole-child guard
        # unchanged; parsing cannot rewrite the archived PG text or its SHA.
        actual_pg = '2026-11-04T10:22:17.49656+00:00'
        six_digits = '2026-11-04T10:22:17.496560+00:00'
        self.assertEqual(cas.utc(actual_pg), cas.utc(six_digits))
        self.assertEqual(cas.utc(actual_pg).microsecond, 496560)
        failed = json.loads(value['failed_run_pgtext'])
        failed['finished_at'] = actual_pg
        value['failed_run_pgtext'] = cas.canonical(failed).decode()
        value['dispatch'][0].update(returned_at=actual_pg, finalization_ack_at='2026-11-04T10:22:17.518138+00:00')
        config['failed_run_sha256'] = cas.sha(value['failed_run_pgtext'].encode())
        actual_wire = cas.canonical(value)
        self.assertTrue(cas.validate_known_child(value, config, json.loads))
        self.assertEqual(cas.canonical(value), actual_wire)
        for digits, microseconds in (('1', 100000), ('12', 120000), ('123', 123000),
                ('1234', 123400), ('12345', 123450), ('123456', 123456),
                ('1234567', 123456), ('12345678', 123456), ('123456789', 123456)):
            with self.subTest(fractional_digits=len(digits)):
                expected = cas.datetime.datetime(2026, 11, 4, 10, 22, 17, microseconds,
                                                 tzinfo=cas.datetime.timezone.utc)
                self.assertEqual(cas.utc('2026-11-04T10:22:17.' + digits + '+00:00'), expected)
                self.assertEqual(cas.utc('2026-11-04T10:22:17.' + digits + 'Z'), expected)
        whole_second = cas.datetime.datetime(2026, 11, 4, 10, 22, 17, tzinfo=cas.datetime.timezone.utc)
        self.assertEqual(cas.utc('2026-11-04T10:22:17Z'), whole_second)
        self.assertEqual(cas.utc('2026-11-04T10:22:17+00:00'), whole_second)
        self.assertEqual(cas.utc('2026-11-04T12:22:17.49656+02:00'), cas.utc(actual_pg))
        self.assertEqual(cas.utc('2026-11-04T05:22:17.49656-05:00'), cas.utc(actual_pg))
        for malformed in ('2026-11-04T10:22:17.49656', '2026-11-04T10:22:17.1234567890Z',
                '2026-11-04 10:22:17Z', '2026-11-04T10:22:17,Z',
                '2026-11-04T10:22:17+0000', '2026-11-04T10:22:17+0:00'):
            with self.subTest(malformed_timestamp=malformed), self.assertRaisesRegex(cas.Hold, 'ACTUAL_ZONED_TIMESTAMP'):
                cas.utc(malformed)

    def test_known_seven_row_child_rejects_old_frame_and_retained_epoch_drift(self):
        value, config = known_operand(); value['forwards'] = value['forwards'][:5]
        with self.assertRaisesRegex(cas.Hold, 'EXACT_ROOT_THREE_ANCESTOR_TWO_CURRENT_TWO'):
            cas.validate_known_child(value, config, json.loads)
        for stage in ('requested', 'admitted'):
            value, config = known_operand()
            row = next(row for row in value['forwards'] if row['id'] == cas.CURRENT_CHILD and row['stage'] == stage)
            row['original_record']['parent_admission_id'] = cas.PARENT
            seal_row(row)
            with self.subTest(join_stage=stage), self.assertRaisesRegex(cas.Hold, 'EXACT_CURRENT_CHILD_JOINS_RETAINED_8B'):
                cas.validate_known_child(value, config, json.loads)
        # Re-seal both the ancestor and its descendant joins, so refusal proves
        # semantic f30 custody rather than merely catching stale hashes.
        for key, replacement in (('generation', 15), ('fence', 31),
                ('lease_owner', '3ec9cd58-b752-4877-9031-d997661d3c5f'),
                ('executor_id', '6f0c459a-c6b9-4c18-bc55-f51d6244f4e5'),
                ('run_id', cas.FAILED), ('destroy_grant_id', cas.PARENT)):
            value, config = known_operand()
            ancestor = next(row for row in value['forwards'] if row['id'] == cas.CHILD and row['stage'] == 'admitted')
            ancestor['original_record'][key] = replacement
            seal_row(ancestor)
            for row in value['forwards']:
                if row['id'] == cas.CURRENT_CHILD:
                    row['original_record']['parent_admission_sha256'] = ancestor['record_sha256']
                    seal_row(row)
            with self.subTest(retained_claim=key), self.assertRaisesRegex(cas.Hold, 'RETAINED_8B_F30_ORIGINAL_NEVER_RELABELLED'):
                cas.validate_known_child(value, config, json.loads)
