"""G9 held-image admission CI: real SQL on a disposable local PG16 service.

Declared rows and native JSON are not signatures, cloud observations or full
Goose qualification. The query, private validators and read-only custody are
real. All production effects remain forbidden at these test boundaries.
"""
import ast
import base64
import contextlib
import copy
import datetime
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import time
import types
import unittest
from unittest.mock import Mock, patch

import test_g8pair_core_cas as old
import test_g9pair_tools as tools


CAS_PATH = tools.source.ROOT / 'rollout/core_image_cas_once_g9.py'
spec = importlib.util.spec_from_file_location('g9_held_image_declared_CI', CAS_PATH)
cas = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cas)
cut = tools.load_tool('g9cut')


def uid(n):
    return '11111111-1111-4111-8111-' + str(n).zfill(12)


def declared_held():
    pin = tools.source.digest(b'declared CI pin, replaced with real PG row hashes below')
    scope = tools.source.digest(b'declared CI physical scope')
    members = []
    for slot in (1, 2, 3):
        members.append({'slot': slot, 'resource_id': 'i-' + str(slot).zfill(17),
            'resource_created_at': '2020-01-01T00:00:00Z', 'preregistration_id': uid(10 + slot),
            'create_grant_id': uid(20 + slot), 'enrollment_sha256': pin,
            'slot_revision': 1, 'slot_record_sha256': pin,
            'tags': {'Name': 'declared-ci-slot-' + str(slot), 'yggdrasil.io/intent': uid(20 + slot),
                     'yggdrasil.io/owner': 'declared-ci-owner', 'yggdrasil.io/profile': 'notify-aws-elastic',
                     'yggdrasil.io/scope': base64.b32encode(bytes.fromhex(scope)).decode().lower().rstrip('='),
                     'yggdrasil.io/slot': str(slot), 'yggdrasil.io/spec': 'declared-ci-spec'}})
    return {'schema': 'root_exact_held_partial_poweroff_image_rollout_v1',
        'namespace': 'dakasa-production', 'environment': 'production', 'domain': 'notify',
        'dimension': 'original_notify_aws_vm_members', 'generation': 14, 'fence': 28,
        'preregistration_id': members[2]['preregistration_id'], 'retirement_request_id': uid(30),
        'original_run_id': uid(31), 'policy_id': uid(32), 'workflow_id': uid(33),
        'policy_checksum': pin, 'workflow_checksum': pin, 'lease_owner': uid(34), 'executor_id': uid(35),
        'intent_pgtext_sha256': pin, 'original_frame_sha256': pin, 'original_caller_sha256': pin,
        'native_tuple': {'provider': 'aws', **{k: members[2][k] for k in ('resource_id', 'resource_created_at', 'slot')}},
        'history': {'rows': 3, 'sha256': pin}, 'catalog': {'rows': 8, 'sha256': pin},
        'physical_profile': {'integration_instance_id': uid(36), 'scope_checksum': scope,
                             'profile_name': 'notify-aws-elastic'}, 'native_members': members,
        'historical_survivors': [{'slot': slot, 'read_challenge_id': uid(40 + slot),
            'publication_challenge_id': uid(50 + slot), 'read_return_sha256': pin,
            'publication_return_sha256': pin, 'frame_sha256': pin} for slot in (1, 2)],
        'Root_review_ref': {'path': '/var/lib/dakasa-core-rollout/declared-CI/review.json', 'sha256': pin},
        'native_observation_ref': {'path': '/var/lib/dakasa-core-rollout/declared-CI/native.json', 'sha256': pin}}


def native_operand(expected, variant=None):
    """Declared AWS bodies with real byte hashes and the CI host's own clock."""
    e = copy.deepcopy(expected)
    owner, scope = (e['native_members'][0]['tags'][key] for key in ('yggdrasil.io/owner', 'yggdrasil.io/scope'))
    request = {'service': 'ec2', 'operation': 'DescribeInstances', 'region': 'us-east-1', 'filters': [
        {'Name': 'tag:yggdrasil.io/owner', 'Values': [owner]},
        {'Name': 'tag:yggdrasil.io/profile', 'Values': ['notify-aws-elastic']},
        {'Name': 'tag:yggdrasil.io/scope', 'Values': [scope]},
        {'Name': 'instance-state-name', 'Values': ['pending', 'running', 'shutting-down', 'stopping', 'stopped']}]}
    instances = [{'InstanceId': m['resource_id'], 'LaunchTime': m['resource_created_at'],
                  'Tags': [{'Key': k, 'Value': v} for k, v in m['tags'].items()],
                  'State': {'Name': 'stopped' if m['slot'] == 3 else 'running'}} for m in e['native_members']]
    if variant == 'pending':
        instances[2]['State']['Name'] = 'stopping'
    elif variant == 'foreign-birth':
        instances[0]['LaunchTime'] = '2020-01-02T00:00:00Z'
    elif variant == 'extra-member':
        instances.append(copy.deepcopy(instances[0]))
    elif variant == 'narrow-query':
        request['filters'] = [{'Name': 'instance-id', 'Values': [instances[2]['InstanceId']]}]
    bodies = {}
    descriptor = {'schema': 'root_same_boot_complete_aws_profile_native_readonly_v1',
        'observation_id': uid(80), 'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
        'started_monotonic_ns': time.monotonic_ns() - 1000000000,
        'returned_monotonic_ns': time.monotonic_ns() - 500000000,
        'held_intent_pgtext_sha256': e['intent_pgtext_sha256'], 'account': '153828470928', 'region': 'us-east-1'}
    clock = datetime.datetime.now(datetime.timezone.utc)
    descriptor['started_at'] = (clock - datetime.timedelta(seconds=1)).isoformat().replace('+00:00', 'Z')
    descriptor['returned_at'] = (clock - datetime.timedelta(seconds=0.5)).isoformat().replace('+00:00', 'Z')
    if variant == 'stale':
        for k in ('started_monotonic_ns', 'returned_monotonic_ns'):
            descriptor[k] -= 120000000000
        for k in ('started_at', 'returned_at'):
            descriptor[k] = (cas.utc_time(descriptor[k]) - datetime.timedelta(seconds=120)).isoformat().replace('+00:00', 'Z')
    elif variant == 'foreign-boot':
        descriptor['boot_id'] = uid(81)
    for key, value in (('request_ref', request),
                       ('identity_ref', {'UserId': 'declared-CI-only', 'Account': '153828470928',
                                         'Arn': 'arn:aws:iam::153828470928:role/declared-CI'}),
                       ('fleet_ref', {'Reservations': [{'OwnerId': '153828470928', 'Instances': instances}]})):
        path = '/var/lib/dakasa-core-rollout/declared-CI/' + key + '.json'
        bodies[path] = cut.C.wire(value)
        descriptor[key] = {'path': path, 'sha256': cas.sha(bodies[path])}
    bodies[e['Root_review_ref']['path']] = b'declared CI review; not a Root authorization'
    e['Root_review_ref']['sha256'] = cas.sha(bodies[e['Root_review_ref']['path']])
    bodies[e['native_observation_ref']['path']] = cut.C.wire(descriptor)
    e['native_observation_ref']['sha256'] = cas.sha(bodies[e['native_observation_ref']['path']])
    return e, bodies


@contextlib.contextmanager
def binding(expected=None):
    with tools.declared_binding(cut.C), patch.multiple(cas, PROPOSAL_BOUND=True,
            SOURCE_PIN=tools.source.digest((tools.source.NEW / 'source/network_guardian.py').read_bytes()),
            GENERATION=272, OLD_POD=uid(90),
            TOOL_PINS={name: tools.source.digest((tools.TOOLS / name).read_bytes()) for name in cut.C.TOOLS},
            ROOT_ROLLOUT_MODE='steady' if expected is None else 'exact_held_partial_poweroff_original',
            HELD_ORIGINAL_IDENTITY=cas.HELD_ORIGINAL_IDENTITY if expected is None else cas.held_identity(expected)):
        yield


@contextlib.contextmanager
def declared_private_input(raw, *, mode=0o600, owner=0, variant=None):
    """Map one declared Brain path to a real CI file, retaining real read guards.

    Only the mount path and root uid are declared transport/custody operands.
    Real open/no-follow, mode/nlink/type, bounded reads, stable stat, raw SHA,
    closed JSON and fixed-identity validation remain the production definitions.
    """
    with tempfile.TemporaryDirectory() as folder:
        local = Path(folder) / 'input.json'
        if variant == 'directory':
            local.mkdir(mode=mode)
        elif variant != 'missing':
            local.write_bytes(raw)
            local.chmod(mode)
            if variant == 'hardlink':
                os.link(local, Path(folder) / 'other-link')
            elif variant == 'symlink':
                target = Path(folder) / 'target.json'
                local.rename(target)
                local.symlink_to(target)
        selected = Path('/var/lib/dakasa-core-rollout/declared-CI/HELD-ADMISSION.json')
        real_open, real_fstat = os.open, os.fstat

        def mapped_open(path, flags, *args, **kwargs):
            return real_open(local if Path(path) == selected else path, flags, *args, **kwargs)

        def declared_stat(fd):
            actual = real_fstat(fd)
            fields = {name: getattr(actual, name) for name in dir(actual) if name.startswith('st_')}
            fields['st_uid'] = owner
            return types.SimpleNamespace(**fields)

        with patch.object(cas.os, 'open', side_effect=mapped_open), \
                patch.object(cas.os, 'fstat', side_effect=declared_stat):
            yield selected


class G9CASTests(unittest.TestCase):
    def test_production_fixed_identity_matches_selected_actual_historical_public_projection(self):
        path = tools.source.ROOT / 'tests/fixtures/held-original-g9/identity.PUBLIC.json'
        raw = path.read_bytes()
        self.assertEqual(cas.sha(raw), '950ff4a5a22145bafd7ceb6b8644c3075a9def04806d9a39a8e0582d3cb8b3cb')
        fixture = cut.C.loads(raw)
        self.assertEqual(fixture['schema'], 'g9_historical_immutable_identity_static_source_fixture_v1')
        self.assertFalse(fixture['native_authorization'])
        self.assertFalse(fixture['dynamic_history_catalog_revisions_and_clocks_included'])
        self.assertEqual(fixture['custody'], {
            'ssm_command_id': 'df473628-015d-4094-a80b-283794251405',
            'ssm_original_sha256': '7dcb4d9e19f9b16cd4fdb5d75411898e26e14b56c42011ec2b2083f627b14995',
            'projection_sha256': '446c4b16605b298b7118da5f7bb204298fa4900302d763b625da199eab749cc0',
            'historical_native_tag_body_sha256': '7d50af03273fd375669ddced378856377e5737630705adfc230a78ae2ae6a742'})
        self.assertEqual(cas.HELD_ORIGINAL_IDENTITY, fixture['identity'])
        cas.validate_held_identity(fixture['identity'])
        for key in ('history', 'catalog', 'Root_review_ref', 'native_observation_ref'):
            self.assertNotIn(key, fixture['identity'])
        self.assertTrue(all('slot_revision' not in m and 'slot_record_sha256' not in m
                            for m in fixture['identity']['native_members']))
        tree = ast.parse(CAS_PATH.read_text())
        self.assertFalse(any(isinstance(n, ast.Global) for n in ast.walk(tree)))
        self.assertNotIn('EXPECTED_HELD_ORIGINAL', CAS_PATH.read_text())

    def test_unbound_dispatcher_refuses_before_db_native_or_api(self):
        with patch.object(cas, 'PROPOSAL_BOUND', False), patch.object(cut.subprocess, 'run') as db, \
                patch.object(cas.API, 'request') as api:
            with self.assertRaises(cas.Hold):
                cas.database_preflight(cut, Path('/never-created'))
            db.assert_not_called()
            api.assert_not_called()

    def test_old_steady_query_and_success_predicate_only_extend_schema90(self):
        def part(path, name):
            text = path.read_text()
            tree = ast.parse(text)
            node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == name)
            return ast.get_source_segment(text, node)
        previous = part(old.CAS_PATH, 'database_preflight')
        current = part(CAS_PATH, 'database_steady_preflight').replace('def database_steady_preflight(', 'def database_preflight(')
        current = current.replace("'migration90_applied',(SELECT count(*) FROM goose_db_version WHERE version_id=90 AND is_applied),\n", '')
        current = current.replace("'schema':90", "'schema':89").replace(", 'migration90_applied':1", '').replace(",'migration90_applied':1", '')
        current = current.replace('FRESH_SCHEMA90_VALID_INDEX_SCOPED_QUIET_STEADY_NO_LEASE', 'FRESH_SCHEMA89_VALID_INDEX_SCOPED_QUIET_STEADY_NO_LEASE')
        self.assertEqual(current, previous)

    def test_held_shape_refuses_other_epoch_foreign_roster_and_incomplete_pins(self):
        e = declared_held()
        cas.validate_held_original(e)
        for key in e:
            changed = copy.deepcopy(e)
            del changed[key]
            with self.subTest(missing=key), self.assertRaises(cas.Hold):
                cas.validate_held_original(changed)
        for variant in ('epoch', 'tail', 'duplicate', 'missing-history', 'bad-tags', 'foreign-survivor', 'extra-key'):
            changed = copy.deepcopy(e)
            if variant == 'epoch':
                changed['fence'] = 29
            elif variant == 'tail':
                changed['native_tuple']['slot'] = 2
            elif variant == 'duplicate':
                changed['native_members'][1] = copy.deepcopy(changed['native_members'][0])
            elif variant == 'missing-history':
                changed['history']['rows'] = 0
            elif variant == 'bad-tags':
                changed['native_members'][0]['tags']['yggdrasil.io/intent'] = uid(99)
            elif variant == 'foreign-survivor':
                changed['historical_survivors'][0]['slot'] = 3
            else:
                changed['caller200'] = True
            with self.subTest(variant=variant), self.assertRaises(cas.Hold):
                cas.validate_held_original(changed)

    def test_native_readonly_proof_requires_complete_exact_off_running_and_real_fresh_clocks(self):
        for variant in (None, 'pending', 'foreign-birth', 'extra-member', 'narrow-query', 'stale', 'foreign-boot'):
            e, bodies = native_operand(declared_held(), variant)
            with self.subTest(variant=variant), patch.object(cas, 'read', side_effect=lambda p, *_: bodies[str(p)]), \
                    patch.object(cas.API, 'request') as api:
                if variant is None:
                    value = cas.validate_held_native_observation(e, cut.C.loads)
                    self.assertFalse(value['retirement_authority'])
                    self.assertFalse(value['historical_useful_provenance_is_fresh_business_authority'])
                else:
                    with self.assertRaises(cas.Hold):
                        cas.validate_held_native_observation(e, cut.C.loads)
                api.assert_not_called()

    def test_real_late_loader_preserves_raw_bytes_and_separates_fixed_identity_from_fresh_snapshots(self):
        e = declared_held()
        fixed = cas.held_identity(e)
        late = copy.deepcopy(e)
        late['history'] = {'rows': 4, 'sha256': cas.sha(b'declared later history')}
        late['catalog'] = {'rows': 9, 'sha256': cas.sha(b'declared later catalog')}
        late['native_members'][0]['slot_revision'] = 2
        late['native_members'][0]['slot_record_sha256'] = cas.sha(b'declared later same-member row')
        raw = cut.C.wire(late)
        with binding(e), declared_private_input(raw) as path, \
                patch.object(cas.API, 'request') as api, patch.object(cut.subprocess, 'run') as db:
            loaded, original = cas.load_held_admission(cut.C, path, cas.sha(raw))
            self.assertEqual(original, raw)
            self.assertEqual(loaded, late)
            self.assertEqual(cas.held_identity(loaded), fixed)
            self.assertEqual(cas.HELD_ORIGINAL_IDENTITY, fixed)
            self.assertIsNot(loaded, late)
            api.assert_not_called()
            db.assert_not_called()

    def test_real_late_loader_refuses_missing_malformed_hash_path_mode_and_other_original(self):
        e = declared_held()
        raw = cut.C.wire(e)
        variants = ('missing', 'symlink', 'hardlink', 'directory', 'mode', 'owner', 'oversize',
                    'malformed', 'null', 'duplicate', 'trailing', 'unknown', 'missing-key',
                    'wrong-sha', 'malformed-sha', 'relative-path', 'foreign-path', 'parent-path', 'other-original')
        for variant in variants:
            changed = copy.deepcopy(e)
            body = raw
            if variant == 'oversize':
                body = b' ' * ((128 << 10) + 1)
            elif variant == 'malformed':
                body = b'{original malformed bytes'
            elif variant == 'null':
                body = b'null'
            elif variant == 'duplicate':
                body = raw.rstrip()[:-1] + b',"schema":"root_exact_held_partial_poweroff_image_rollout_v1"}'
            elif variant == 'trailing':
                body = raw + b'{}'
            elif variant == 'unknown':
                changed['retirement_authority'] = True
                body = cut.C.wire(changed)
            elif variant == 'missing-key':
                del changed['native_observation_ref']
                body = cut.C.wire(changed)
            elif variant == 'other-original':
                changed['original_run_id'] = uid(200)
                body = cut.C.wire(changed)
            with self.subTest(variant=variant), binding(e), \
                    declared_private_input(body, mode=0o644 if variant == 'mode' else 0o600,
                                           owner=1001 if variant == 'owner' else 0, variant=variant) as path, \
                    patch.object(cas.API, 'request') as api, patch.object(cut.subprocess, 'run') as db:
                selected = {'relative-path': Path('HELD-ADMISSION.json'),
                            'foreign-path': Path('/tmp/HELD-ADMISSION.json'),
                            'parent-path': Path('/var/lib/dakasa-core-rollout/../HELD-ADMISSION.json')}.get(variant, path)
                pin = cas.sha(b'different original bytes') if variant == 'wrong-sha' else cas.sha(body)
                if variant == 'malformed-sha':
                    pin = 'not-a-sha256'
                with self.assertRaises((cas.Hold, cut.C.Hold, OSError, ValueError)):
                    cas.load_held_admission(cut.C, selected, pin)
                api.assert_not_called()
                db.assert_not_called()

    def test_real_cli_rejects_missing_or_invalid_late_input_before_package_and_api(self):
        e = declared_held()
        raw = cut.C.wire(e)
        for variant in ('both-missing', 'sha-missing', 'file-missing', 'malformed', 'other-original'):
            changed = copy.deepcopy(e)
            changed['original_run_id'] = uid(201)
            body = b'{bad' if variant == 'malformed' else cut.C.wire(changed) if variant == 'other-original' else raw
            with self.subTest(variant=variant), binding(e), declared_private_input(body) as path:
                argv = ['core_image_cas_once_g9.py', '--package', '/declared-CI-package',
                        '--expected-ops-source', '1' * 40, '--expected-manifest-sha256', '2' * 64,
                        '--g9-swap-return', str(cas.ROOT / 'swap-once-CI/RETURN.json'),
                        '--expected-g9-swap-return-sha256', '3' * 64,
                        '--evidence-dir', str(cas.ROOT / 'core-image-cas-CI'), '--execute-core-image-cas-once']
                if variant != 'both-missing':
                    if variant != 'file-missing':
                        argv += ['--held-admission', str(path)]
                    if variant != 'sha-missing':
                        argv += ['--expected-held-admission-sha256', cas.sha(body)]
                with patch.object(sys, 'argv', argv), patch.object(cas.os, 'geteuid', return_value=0), \
                        patch.object(cas.sys, 'platform', 'linux'), patch.object(cas, 'load_tools', return_value=cut), \
                        patch.object(cut.C, 'package') as package, patch.object(cas, 'API') as api, \
                        patch.object(cas, 'database_preflight') as db, patch.object(cas, 'operation_lock') as lock:
                    with self.assertRaises((cas.Hold, cut.C.Hold, OSError, ValueError)):
                        cas.main()
                    package.assert_not_called()
                    api.assert_not_called()
                    db.assert_not_called()
                    lock.assert_not_called()

    def test_dispatcher_passes_explicit_held_object_and_rejects_it_in_unchanged_steady_mode(self):
        e = declared_held()
        with binding(e), patch.object(cas, 'database_held_preflight', return_value={'declared': True}) as held, \
                patch.object(cas, 'database_steady_preflight') as steady:
            self.assertEqual(cas.database_preflight(cut, Path('/declared-CI'), e), {'declared': True})
            self.assertIs(held.call_args.args[2], e)
            with self.assertRaises(cas.Hold):
                cas.database_preflight(cut, Path('/declared-CI'))
            held.assert_called_once()
            steady.assert_not_called()
        with binding(), patch.object(cas, 'database_steady_preflight', return_value={'steady': True}) as steady, \
                patch.object(cas, 'database_held_preflight') as held:
            self.assertEqual(cas.database_preflight(cut, Path('/declared-CI')), {'steady': True})
            steady.assert_called_once_with(cut, Path('/declared-CI'))
            with self.assertRaises(cas.Hold):
                cas.database_preflight(cut, Path('/declared-CI'), e)
            with declared_private_input(cut.C.wire(e)) as path, self.assertRaises(cas.Hold):
                cas.load_held_admission(cut.C, path, cas.sha(cut.C.wire(e)))
            held.assert_not_called()

    def test_real_cli_uses_one_loaded_object_before_api_and_at_both_patch_readback_boundaries(self):
        """Actual parser/loader/CAS routing with simulated DB/API/native facts.

        Real SQL is exercised separately below, never replaced in PG tests.
        This test proves object custody/order, not a native rollout admission.
        """
        e = declared_held()
        raw = cut.C.wire(e)
        events, loaded = [], []
        with tempfile.TemporaryDirectory() as folder, binding(e), declared_private_input(raw) as admission:
            root = Path(folder)
            returned_path = root / 'swap-once-declared-CI' / 'RETURN.json'
            returned_path.parent.mkdir()
            returned_path.write_bytes(cut.C.wire({'declared_CI_swap_not_native': True}))
            returned_path.chmod(0o600)
            manifest = tools.declared_manifest()
            manifest['source_commit'] = '1' * 40
            with patch.object(old, 'cas', cas), patch.object(old, 'cut', cut):
                before, pods = old.core_preimage()
            old_tuple = cas.core_before(before, pods, cut.C)
            protected = cas.required_protected_refs()
            ctrl, guard = (copy.deepcopy(manifest[k]) for k in ('expected_controller_identity', 'expected_guardian_identity'))
            original = {'core': old_tuple, 'controller': ctrl, 'guardian': guard, 'protected_refs': protected}
            previous = returned_path.parent / 'BEFORE.json'
            previous.write_bytes(cut.C.wire(original))
            previous.chmod(0o600)
            manifest_sha = '2' * 64
            claim = {'schema': 'g9_once_only_swap_claim_v1', 'manifest_sha256': manifest_sha,
                     'old_controller': ctrl, 'old_guardian': guard,
                     'run': str(returned_path.parent), 'automatic_replay': False}
            claim_path = root / ('SWAP-' + manifest_sha + '-POSSIBLE.json')
            claim_path.write_bytes(cut.C.wire(claim))
            claim_path.chmod(0o600)
            lock_path = root / 'operation.lock'
            lock_path.write_bytes(b'declared-CI-inode')
            lock_stat = lock_path.stat()
            after = copy.deepcopy(before)
            after['spec']['template']['spec']['containers'][0]['image'] = cut.C.IMAGE_PREFIX + cut.C.NEW_DIGEST
            after['metadata']['generation'] += 1
            after['metadata']['resourceVersion'] = '101'
            after['metadata']['annotations'].update({'dakasa.io/core-source-commit': cas.CORE_R,
                                                    'kubernetes.io/change-cause': cas.CHANGE_CAUSE})
            run = root / 'core-image-cas-declared-CI'
            native_load = cas.load_held_admission

            def load(*args):
                value = native_load(*args)
                loaded.append(value[0])
                events.append('load')
                return value

            def require_object(value):
                self.assertIs(value, loaded[0])
                self.assertEqual(value, e)
                self.assertEqual(cut.C.wire(value), raw)

            def database(selected_cut, selected_run, value):
                self.assertIs(selected_cut, cut)
                self.assertEqual(selected_run, run)
                require_object(value)
                events.append('database')

            def current(selected_cut, selected_run, value, phase):
                self.assertIs(selected_cut, cut)
                self.assertEqual(selected_run, run)
                require_object(value)
                events.append(phase)

            def native(value, loads):
                require_object(value)
                self.assertIs(loads, cut.C.loads)
                events.append('native-readonly')

            def request(method, uri, body=None):
                if method == 'GET':
                    value = pods if uri == cas.PODS_URI else before
                else:
                    self.assertEqual(method, 'PATCH')
                    value = after
                    if 'dryRun=All' not in uri:
                        self.assertTrue((run / 'POSSIBLE-SEND.json').is_file())
                        self.assertTrue((root / ('CORE-IMAGE-0970-TO-' + cut.C.NEW_DIGEST + '-POSSIBLE.json')).is_file())
                        events.append('patch')
                return 200, cut.C.wire(value), {'audit_id': 'declared-CI-only', 'date': 'declared-CI-only'}

            api = types.SimpleNamespace(request=Mock(side_effect=request))

            def client(selected_cut):
                self.assertIs(selected_cut, cut)
                self.assertEqual(events, ['load'])
                self.assertEqual((run / 'HELD-ADMISSION.INPUT.json').read_bytes(), raw)
                self.assertEqual(cut.C.loads((run / 'HELD-ADMISSION.INPUT-SHA256.json').read_bytes())['sha256'], cas.sha(raw))
                events.append('api')
                return api

            def private_dir(path, create=False):
                if create:
                    Path(path).mkdir(mode=0o700)

            argv = ['core_image_cas_once_g9.py', '--package', str(tools.TOOLS.parent),
                    '--expected-ops-source', manifest['source_commit'], '--expected-manifest-sha256', manifest_sha,
                    '--g9-swap-return', str(returned_path), '--expected-g9-swap-return-sha256', cas.sha(returned_path.read_bytes()),
                    '--evidence-dir', str(run), '--held-admission', str(admission),
                    '--expected-held-admission-sha256', cas.sha(raw), '--execute-core-image-cas-once']
            backend = types.SimpleNamespace(files=Mock(), protected=Mock(return_value=protected))
            with contextlib.ExitStack() as stack:
                stack.enter_context(patch.object(sys, 'argv', argv))
                stack.enter_context(patch.object(cas.os, 'geteuid', return_value=0))
                stack.enter_context(patch.object(cas.sys, 'platform', 'linux'))
                stack.enter_context(patch.object(cas, 'ROOT', root))
                stack.enter_context(patch.object(cas, 'OPLOCK', lock_path))
                stack.enter_context(patch.object(cas, 'load_tools', return_value=cut))
                stack.enter_context(patch.object(cut.C, 'package', return_value=(tools.TOOLS.parent, manifest)))
                stack.enter_context(patch.object(cut.C, 'private_dir', side_effect=private_dir))
                loader = stack.enter_context(patch.object(cas, 'load_held_admission', side_effect=load))
                stack.enter_context(patch.object(cas, 'operation_lock', return_value=contextlib.nullcontext((lock_stat.st_dev, lock_stat.st_ino))))
                factory = stack.enter_context(patch.object(cas, 'API', side_effect=client))
                database_call = stack.enter_context(patch.object(cas, 'database_preflight', side_effect=database))
                current_call = stack.enter_context(patch.object(cas, 'held_current_preimage', side_effect=current))
                native_call = stack.enter_context(patch.object(cas, 'validate_held_native_observation', side_effect=native))
                stack.enter_context(patch.object(cas, 'g9_acceptance', return_value=(backend, protected, ctrl, guard, time.monotonic())))
                stack.enter_context(patch.object(cut, 'physical_identity', side_effect=[ctrl, guard]))
                stack.enter_context(patch.object(cas.signal, 'signal'))
                stack.enter_context(patch.object(cas.signal, 'alarm'))
                output = stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
                cas.main()
                loader.assert_called_once_with(cut.C, admission, cas.sha(raw))
                factory.assert_called_once_with(cut)
                database_call.assert_called_once()
                self.assertEqual(current_call.call_count, 2)
                native_call.assert_called_once()
            self.assertEqual(events, ['load', 'api', 'database', 'PRESEND', 'native-readonly', 'patch', 'AFTER-ACK'])
            self.assertEqual(len(loaded), 1)
            self.assertEqual(loaded[0], e)
            self.assertEqual(len(api.request.call_args_list), 6)
            self.assertEqual([call.args[0] for call in api.request.call_args_list], ['GET', 'GET', 'PATCH', 'GET', 'GET', 'PATCH'])
            result = cut.C.loads(output.getvalue())
            self.assertEqual(result['status'], 'PATCH_ACKNOWLEDGED_ACCEPTANCE_PENDING')
            self.assertFalse(result['new_pod_readiness_proven'])
            self.assertFalse(result['post_rollout_G9_and_E2E_acceptance_proven'])
            self.assertFalse((run / 'HOLD.PUBLIC.json').exists())


# Relevant columns are declared fixture DDL, not the production migration set.
# Full migration/trigger/crypto qualification remains in the separate Core CI.
DDL = '''
CREATE TABLE manifests(id uuid PRIMARY KEY,kind text,namespace text,name text,version bigint,active bool,checksum text,spec jsonb);
CREATE TABLE workflow_runs(id uuid PRIMARY KEY,workflow_id uuid,workflow_namespace text,workflow_name text,status text,finished_at timestamptz,result jsonb);
CREATE INDEX workflow_runs_workflow_id_idx ON workflow_runs(workflow_id);
CREATE TABLE goose_db_version(id bigint PRIMARY KEY,version_id bigint,is_applied bool,tstamp timestamptz);
CREATE TABLE capacity_intents(namespace text,environment text,domain text,dimension text,intent jsonb);
CREATE TABLE capacity_mutation_grants(id uuid PRIMARY KEY,namespace text,environment text,domain text,dimension text,integration_instance_id uuid,scope_checksum text,profile_name text,slot int,state text,grant_record jsonb,original_disposition_id uuid,failed_original_disposition_id uuid,native_denied_disposition_id uuid,enrolled_failed_disposition_id uuid);
CREATE TABLE capacity_resource_slots(namespace text,environment text,domain text,dimension text,integration_instance_id uuid,scope_checksum text,profile_name text,slot int,resource_id text,revision bigint,slot_record jsonb);
CREATE TABLE capacity_vm_provisioning_preregistrations(id uuid PRIMARY KEY,create_grant_id uuid);
CREATE TABLE capacity_vm_original_enrollments(preregistration_id uuid,enrollment_sha256 text,enrollment_record jsonb);
CREATE TABLE capacity_guest_original_create_witnesses(preregistration_id uuid,original_record jsonb);
CREATE TABLE capacity_vm_retirement_intents(id uuid,preregistration_id uuid,original_deadline timestamptz,intent_record jsonb);
CREATE TABLE capacity_guest_original_retirement_contexts(intent_id uuid,original_context_deadline timestamptz,executor_id uuid,core_actual_source_commit text);
CREATE TABLE capacity_guest_original_caller_returns(intent_id uuid,return_sha256 text,original_record jsonb);
CREATE TABLE capacity_guest_original_caller_attempts(intent_id uuid,original_record jsonb);
CREATE TABLE capacity_vm_retirement_original_returns(intent_id uuid,sequence int,original_record jsonb);
CREATE TABLE capacity_guest_original_authority_reads(id uuid,intent_id uuid,phase text,ordinal int);
CREATE TABLE capacity_guest_original_authority_returns(read_id uuid,original_record jsonb);
CREATE TABLE capacity_guest_original_authority_transport_returns(read_id uuid,native_stage text,original_record jsonb);
CREATE TABLE capacity_vm_retirement_delete_bindings(intent_id uuid);
CREATE TABLE capacity_guest_retirement_forwards(retirement_request_id uuid);
CREATE TABLE capacity_dispatch_jobs(run_id uuid,realm text,environment text,domain text,dimension text,state text,return_status text,returned_at timestamptz,finalization_ack_at timestamptz,envelope text);
CREATE TABLE capacity_guest_notify_canary_challenges(id uuid,preregistration_id uuid,record_challenge_id uuid,phase text,policy_id uuid,workflow_id uuid,generation bigint,fence bigint,lease_owner text,executor_id text,original_record jsonb,original_wire bytea,challenge_sha256 text);
CREATE TABLE capacity_guest_notify_canary_returns(challenge_id uuid,outcome text,return_sha256 text,original_wire bytea,business_observation jsonb,original_transport jsonb,recorded_at timestamptz);
CREATE TABLE capacity_guest_notify_canary_nonces(challenge_id uuid,final_challenge_wire bytea,final_challenge_sha256 text);
'''

# Declared relevant-column ledgers, with exact Source pure validators only.
TERMINAL_DDL = "\nALTER TABLE workflow_runs ADD COLUMN workflow_version bigint,ADD COLUMN inputs jsonb,ADD COLUMN metadata jsonb,ADD COLUMN started_at timestamptz,ADD COLUMN error text,ADD COLUMN updated_at timestamptz;\nALTER TABLE capacity_dispatch_jobs ADD COLUMN id uuid,ADD COLUMN protocol text,ADD COLUMN source_tick text,ADD COLUMN envelope_sha256 text,ADD COLUMN fencing_token bigint,ADD COLUMN lease_owner uuid,ADD COLUMN lease_expires_at timestamptz,ADD COLUMN started_at timestamptz,ADD COLUMN pending_wake_count integer,ADD COLUMN return_error text,ADD COLUMN finalization_error text,ADD COLUMN failed_original_disposition_id uuid,ADD COLUMN native_denied_disposition_id uuid,ADD COLUMN enrolled_failed_disposition_id uuid,ADD COLUMN abandoned_disposition_id uuid,ADD COLUMN finalization_lost_disposition_id uuid,ADD COLUMN unknown_maintenance_disposition_id uuid,ADD COLUMN rejected_at timestamptz,ADD COLUMN rejection_reason text,ADD COLUMN rejection_issuer text,ADD COLUMN superseded_policy_id uuid,ADD COLUMN superseded_policy_checksum text,ADD COLUMN superseding_policy_id uuid,ADD COLUMN superseding_policy_checksum text;\nALTER TABLE capacity_vm_provisioning_preregistrations ADD COLUMN original_wire bytea,ADD COLUMN binding_wire bytea,ADD COLUMN original_deadline timestamptz,ADD COLUMN preregistration_record jsonb;\nALTER TABLE capacity_guest_original_create_witnesses ADD COLUMN original_wire bytea;\nALTER TABLE capacity_vm_original_enrollments ADD COLUMN registration_wire bytea,ADD COLUMN receipt_wire bytea;\nCREATE TABLE capacity_dispatch_prestart_rejections(job_id uuid,run_id uuid,envelope_sha256 text,fencing_token bigint,reason text,issuer text,recorded_at timestamptz,superseded_policy_id uuid,superseded_policy_checksum text,superseding_policy_id uuid,superseding_policy_checksum text);\nCREATE TABLE capacity_failed_original_dispositions(id uuid,grant_id uuid,preregistration_id uuid,job_id uuid,run_id uuid,original_grant_sha256 text,original_preregistration_sha256 text,original_dispatch_sha256 text,original_run_sha256 text,disposition_sha256 text,original_wire bytea,disposition_record jsonb,closed_generation bigint,closed_fencing_token bigint,recorded_at timestamptz,original_witness_sha256 text);\nCREATE TABLE capacity_native_denied_dispositions(id uuid,grant_id uuid,preregistration_id uuid,job_id uuid,run_id uuid,original_grant_sha256 text,original_preregistration_sha256 text,original_dispatch_sha256 text,original_run_sha256 text,disposition_sha256 text,original_wire bytea,disposition_record jsonb,closed_generation bigint,closed_fencing_token bigint,recorded_at timestamptz);\nCREATE TABLE capacity_enrolled_failed_original_dispositions(id uuid,grant_id uuid,preregistration_id uuid,job_id uuid,run_id uuid,original_grant_sha256 text,original_preregistration_sha256 text,original_dispatch_sha256 text,original_run_sha256 text,disposition_sha256 text,original_wire bytea,disposition_record jsonb,closed_generation bigint,closed_fencing_token bigint,recorded_at timestamptz,original_witness_sha256 text,original_registration_sha256 text,original_receipt_sha256 text,original_enrollment_sha256 text);\nCREATE TABLE capacity_dispatch_abandoned_dispositions(id uuid,job_id uuid,run_id uuid,original_dispatch_sha256 text,original_run_sha256 text,executor_barrier text,disposing_core_process_started_at timestamptz,disposing_core_hostname text,disposing_core_pid int,disposing_core_source_commit text,recorded_at timestamptz,issuer text,historical_return text,provider_mutation_evidence jsonb,realm text,environment text,domain text,dimension text,envelope_sha256 text,fencing_token bigint,lease_owner uuid,lease_expires_at timestamptz,started_at timestamptz,pending_wake_count int,minimum_lease_age_seconds int,run_status text,run_error text,reason text);\nCREATE TABLE capacity_dispatch_finalization_lost_dispositions(id uuid,job_id uuid,run_id uuid,original_dispatch_sha256 text,original_run_sha256 text,executor_barrier text,disposing_core_process_started_at timestamptz,disposing_core_hostname text,disposing_core_pid int,disposing_core_source_commit text,recorded_at timestamptz,issuer text,historical_return text,provider_mutation_evidence jsonb,realm text,environment text,domain text,dimension text,envelope_sha256 text,fencing_token bigint,lease_owner uuid,lease_expires_at timestamptz,started_at timestamptz,pending_wake_count int,minimum_lease_age_seconds int,run_status text,run_error text,reason text,return_observation text,operator_evidence text,operator_evidence_sha256 text);\nCREATE TABLE capacity_dispatch_unknown_maintenance_dispositions(id uuid,job_id uuid,run_id uuid,original_dispatch_sha256 text,original_run_sha256 text,executor_barrier text,disposing_core_process_started_at timestamptz,disposing_core_hostname text,disposing_core_pid int,disposing_core_source_commit text,recorded_at timestamptz,issuer text,historical_return text,provider_mutation_evidence jsonb,original_returned_at timestamptz,current_members_sha256 text,reason text);\nCREATE FUNCTION public.native_denied_original_ack_matches(d jsonb,original_state text,ack timestamptz,returned timestamptz,lease_end timestamptz,return_status text)\nRETURNS boolean LANGUAGE sql STABLE AS $$\n SELECT coalesce(CASE d->>'schema'\n WHEN 'original_native_authorization_denied_terminal_disposition_v1' THEN\n  original_state='unknown' AND ack IS NULL\n  AND d->'original_unknown_ACK_preserved' IS NOT DISTINCT FROM 'true'::jsonb\n  AND NOT(d ?| ARRAY['original_dispatch_state','original_finalization_ack_at','original_failed_workflow_ACK_preserved'])\n WHEN 'original_native_authorization_denied_failed_returned_ack_terminal_disposition_v2' THEN\n  original_state='returned' AND ack IS NOT NULL AND returned IS NOT NULL AND lease_end IS NOT NULL\n  AND ack>=returned AND ack<lease_end AND return_status='failed'\n  AND d->'original_unknown_ACK_preserved' IS NOT DISTINCT FROM 'false'::jsonb\n  AND d->>'original_dispatch_state' IS NOT DISTINCT FROM 'returned'\n  AND d->'original_failed_workflow_ACK_preserved' IS NOT DISTINCT FROM 'true'::jsonb\n  AND jsonb_typeof(d->'original_finalization_ack_at') IS NOT DISTINCT FROM 'string'\n  AND (d->>'original_finalization_ack_at')::timestamptz IS NOT DISTINCT FROM ack\n ELSE false END,false);\n$$;\nCREATE FUNCTION public.finalization_lost_dispatch_effect_scan_tolerable(scan jsonb) RETURNS boolean LANGUAGE sql IMMUTABLE AS $$\nSELECT jsonb_typeof(scan)='object'\n AND scan->>'schema'='finalization_lost_dispatch_effect_scan_v1'\n AND scan->>'base_schema'='abandoned_started_dispatch_effect_scan_v2'\n AND scan->'clock_skew_margin_seconds'='30'::jsonb\n AND scan->'provider_read_performed'='false'::jsonb\n AND scan->'provider_quiescence_proved'='false'::jsonb\n AND jsonb_typeof(scan->'intents_updated_since_start')='number'\n AND jsonb_typeof(scan->'resource_slots_updated_since_start')='number'\n AND (scan->>'intents_updated_since_start')::numeric<=1\n AND scan->'intents_updated_since_start'=scan->'pure_assessment_intent_updates'\n AND scan->'resource_slots_updated_since_start'=scan->'observation_refresh_slot_updates'\n AND NOT EXISTS(SELECT 1 FROM jsonb_each(scan) e\n   WHERE e.key NOT IN('schema','base_schema','clock_skew_margin_seconds','intents_updated_since_start','resource_slots_updated_since_start','pure_assessment_intent_updates','observation_refresh_slot_updates')\n     AND e.value NOT IN('0'::jsonb,'false'::jsonb))\n$$;\nCREATE OR REPLACE FUNCTION public.unknown_maintenance_dispatch_effect_scan_tolerable(scan jsonb)\nRETURNS boolean LANGUAGE sql IMMUTABLE AS $$\nSELECT COALESCE(jsonb_typeof(scan)='object' AND scan->>'schema'='unknown_maintenance_dispatch_effect_scan_v1'\n AND scan->'policy_epoch_valid'='true'::jsonb AND scan->'refresh_only_result'='true'::jsonb\n AND scan->'invalid_maintenance_canary_rows'='0'::jsonb\n AND jsonb_typeof(scan->'current_members')='array' AND jsonb_array_length(scan->'current_members') BETWEEN 1 AND 8\n AND scan->'current_member_count'=to_jsonb(jsonb_array_length(scan->'current_members'))\n AND scan->>'current_members_sha256'=encode(sha256(convert_to((scan->'current_members')::text,'UTF8')),'hex')\n AND NOT EXISTS(SELECT 1 FROM jsonb_each(scan->'base') e WHERE e.key IN('canary_challenges_since_start','canary_nonces_since_start','canary_possible_sends_since_start','canary_returns_since_start')\n   AND (jsonb_typeof(e.value)<>'number' OR (e.value::text)::numeric<0 OR trunc((e.value::text)::numeric)<>(e.value::text)::numeric))\n AND public.finalization_lost_dispatch_effect_scan_tolerable((scan->'base') || jsonb_build_object(\n  'canary_challenges_since_start',0,'canary_nonces_since_start',0,'canary_possible_sends_since_start',0,'canary_returns_since_start',0)),false)\n$$;"
DDL += TERMINAL_DDL
TERMINAL_ZERO83 = {'schema': 'abandoned_started_dispatch_effect_scan_v2', 'clock_skew_margin_seconds': 30, 'grants_created_or_updated_since_start': 0, 'open_undisposed_grants': 0, 'preregistrations_since_start': 0, 'create_witnesses_since_start': 0, 'enrollments_since_start': 0, 'installations_since_start': 0, 'qualification_probe_challenges_since_start': 0, 'qualification_native_source_returns_since_start': 0, 'source_recovery_cleanup_challenges_since_start': 0, 'source_recovery_cleanup_effect_permits_since_start': 0, 'partial_nativeoff_reconciliations_since_start': 0, 'partial_nativeoff_reads_since_start': 0, 'prejournal_refusal_recoveries_since_start': 0, 'presend_retirement_recoveries_since_start': 0, 'retirement_intents_since_start': 0, 'retirement_contexts_since_start': 0, 'retirement_original_returns_since_start': 0, 'retirement_delete_bindings_since_start': 0, 'retirement_native_readbacks_since_start': 0, 'caller_possible_sends_since_start': 0, 'caller_returns_since_start': 0, 'runtime_snapshot_challenges_since_start': 0, 'runtime_snapshot_returns_since_start': 0, 'authority_reads_since_start': 0, 'authority_returns_since_start': 0, 'authority_transport_returns_since_start': 0, 'native_poweroff_reads_since_start': 0, 'canary_challenges_since_start': 0, 'canary_nonces_since_start': 0, 'canary_possible_sends_since_start': 0, 'canary_returns_since_start': 0, 'intents_updated_since_start': 0, 'notify_window_markers_for_job': 0, 'intent_events_since_start': 0, 'native_commands_since_start': 0, 'native_lifetimes_updated_since_start': 0, 'native_lifetime_archives_since_start': 0, 'native_pod_checkpoints_since_start': 0, 'executor_activity_updated_since_start': 0, 'resource_slots_updated_since_start': 0, 'provider_read_performed': False, 'provider_quiescence_proved': False}
TERMINAL_RECORD_KEYS = {'failed_disposed': ['schema', 'id', 'grant_id', 'preregistration_id', 'job_id', 'run_id', 'issuer', 'original_grant_sha256', 'original_preregistration_sha256', 'original_witness_sha256', 'original_dispatch_sha256', 'original_run_sha256', 'original_binding_sha256', 'original_settlement_sha256', 'original_policy_sha256', 'original_workflow_sha256', 'original_generation', 'original_fencing_token', 'closed_generation', 'closed_fencing_token', 'original_deadline', 'recorded_at', 'historical_core_source_commit', 'observation', 'observation_sha256', 'original_accepted_unchanged', 'original_witness_preserved', 'original_unknown_ACK_preserved', 'historical_writer_start_state', 'serving_or_business_or_savings_authority'], 'enrolled_failed_disposed': ['schema', 'id', 'grant_id', 'preregistration_id', 'job_id', 'run_id', 'issuer', 'original_grant_sha256', 'original_preregistration_sha256', 'original_witness_sha256', 'original_dispatch_sha256', 'original_run_sha256', 'original_binding_sha256', 'original_settlement_sha256', 'original_policy_sha256', 'original_workflow_sha256', 'original_generation', 'original_fencing_token', 'closed_generation', 'closed_fencing_token', 'original_deadline', 'recorded_at', 'historical_core_source_commit', 'observation', 'observation_sha256', 'original_accepted_unchanged', 'original_witness_preserved', 'original_unknown_ACK_preserved', 'historical_writer_start_state', 'serving_or_business_or_savings_authority', 'original_registration_sha256', 'original_receipt_sha256', 'original_enrollment_sha256', 'original_enrollment_preserved', 'Guest_quiescence_proved', 'installation_or_serving_authority'], 'native_v2': ['schema', 'id', 'grant_id', 'preregistration_id', 'job_id', 'run_id', 'issuer', 'original_grant_sha256', 'original_preregistration_sha256', 'original_settlement_sha256', 'original_binding_sha256', 'original_policy_sha256', 'original_workflow_sha256', 'original_dispatch_sha256', 'original_run_sha256', 'original_generation', 'original_fencing_token', 'closed_generation', 'closed_fencing_token', 'original_deadline', 'historical_core_source_commit', 'observation', 'observation_sha256', 'recorded_at', 'original_uncertain_and_NULL_identities_unchanged', 'original_unknown_ACK_preserved', 'original_dispatch_state', 'original_finalization_ack_at', 'original_failed_workflow_ACK_preserved', 'witness_enrollment_installation_absent', 'serving_or_business_or_savings_authority'], 'native_v1': ['schema', 'id', 'grant_id', 'preregistration_id', 'job_id', 'run_id', 'issuer', 'original_grant_sha256', 'original_preregistration_sha256', 'original_settlement_sha256', 'original_binding_sha256', 'original_policy_sha256', 'original_workflow_sha256', 'original_dispatch_sha256', 'original_run_sha256', 'original_generation', 'original_fencing_token', 'closed_generation', 'closed_fencing_token', 'original_deadline', 'historical_core_source_commit', 'observation', 'observation_sha256', 'recorded_at', 'original_uncertain_and_NULL_identities_unchanged', 'original_unknown_ACK_preserved', 'witness_enrollment_installation_absent', 'serving_or_business_or_savings_authority']}


class G9CASPostgresTests(unittest.TestCase):
    setUpClass = classmethod(old.G8CASPostgresTests.setUpClass.__func__)
    pg = old.G8CASPostgresTests.pg

    def setUp(self):
        self.pg('DROP SCHEMA public CASCADE; CREATE SCHEMA public; CREATE EXTENSION pgcrypto;' + DDL)

    def seed(self, *, original_status='failed', final_ack=True, live_lease=False, other_held=False):
        e = declared_held()
        statements = []

        def value(v):
            if v is None:
                return 'NULL'
            if isinstance(v, bytes):
                return "decode('" + v.hex() + "','hex')"
            if isinstance(v, bool):
                return 'true' if v else 'false'
            if isinstance(v, (dict, list)):
                return "'" + json.dumps(v).replace("'", "''") + "'::jsonb"
            if isinstance(v, int):
                return str(v)
            return "'" + str(v).replace("'", "''") + "'"

        def insert(table, **row):
            statements.append('INSERT INTO ' + table + '(' + ','.join(row) + ') VALUES(' + ','.join(value(v) for v in row.values()) + ');')

        self.value, self.insert = value, insert
        scope = {'namespace': e['namespace'], 'environment': e['environment'], 'domain': e['domain'], 'dimension': e['dimension']}
        physical = e['physical_profile']
        binding_row = {**physical, 'integration_checksum': 'declared-instance', 'integration_type_id': uid(37), 'integration_type_checksum': 'declared-type'}
        for mid, kind, ns, name, version, active, check, spec_value in (
                (e['workflow_id'], 'workflow', e['namespace'], 'notify-aws-elastic-capacity', 2, True, e['workflow_checksum'], {}),
                (uid(1), 'workflow', e['namespace'], 'notify-aws-elastic-capacity', 1, False, 'old', {}),
                (uid(2), 'workflow', e['namespace'], 'notify-hetzner-elastic-capacity', 1, True, 'hz', {}),
                (uid(3), 'workflow', 'foreign', 'notify-aws-elastic-capacity', 1, True, 'foreign', {}),
                (e['policy_id'], 'capacity_policy', e['namespace'], 'notify-aws-elastic-capacity', 1, True, e['policy_checksum'],
                 {'workflow': {'namespace': e['namespace'], 'name': 'notify-aws-elastic-capacity'}, 'mutation_bindings': [binding_row]}),
                (uid(4), 'capacity_policy', e['namespace'], 'notify-hetzner-elastic-capacity', 1, True, 'hz-policy',
                 {'workflow': {'namespace': e['namespace'], 'name': 'notify-hetzner-elastic-capacity'}, 'mutation_bindings': []}),
                (physical['integration_instance_id'], 'integration_instance', e['namespace'], 'declared-instance', 1, True, 'declared-instance', {}),
                (uid(37), 'integration_type', e['namespace'], 'declared-type', 1, True, 'declared-type', {})):
            insert('manifests', id=mid, kind=kind, namespace=ns, name=name, version=version, active=active, checksum=check, spec=spec_value)
        for n, version in enumerate((88, 89, 90), 1):
            insert('goose_db_version', id=n, version_id=version, is_applied=True, tstamp='2020-01-01T00:00:00Z')
        intent = {'generation': 14, 'fencing_token': 28, 'phase': 'draining', 'policy_id': e['policy_id'],
            'policy_checksum': e['policy_checksum'], 'lease_owner': e['lease_owner'], 'lease_executor_id': e['executor_id'],
            'lease_expires_at': '2999-01-01T00:00:00Z' if live_lease else '2020-01-01T00:01:00Z', 'baseline_snapshot': {'units': 3},
            'decision': {'units': 2, 'profile': 'notify-aws-elastic'}}
        insert('capacity_intents', **scope, intent=intent)
        insert('capacity_intents', **{**scope, 'dimension': 'original_notify_hetzner_vm_members'},
               intent={'phase': 'pending', 'lease_owner': uid(150)} if other_held else {'phase': 'promoted'})
        for m in e['native_members']:
            tuple_value = {'provider': 'aws', 'resource_id': m['resource_id'], 'resource_created_at': m['resource_created_at'], 'slot': m['slot']}
            enrollment = {'statement': {'tuple': tuple_value, 'writers': [{'id': 'declared-notify-writer'}]}}
            m['enrollment_sha256'] = cas.sha(cut.C.wire(enrollment))
            insert('capacity_resource_slots', **scope, **physical, slot=m['slot'], resource_id=m['resource_id'], revision=1,
                   slot_record={'resource_id': m['resource_id'], 'resource_created_at': m['resource_created_at'], 'tombstone': False})
            insert('capacity_mutation_grants', **scope, **physical, id=m['create_grant_id'], slot=m['slot'], state='confirmed', grant_record={})
            insert('capacity_vm_provisioning_preregistrations', id=m['preregistration_id'], create_grant_id=m['create_grant_id'])
            insert('capacity_vm_original_enrollments', preregistration_id=m['preregistration_id'], enrollment_sha256=m['enrollment_sha256'], enrollment_record=enrollment)
            insert('capacity_guest_original_create_witnesses', preregistration_id=m['preregistration_id'], original_record={'tuple': tuple_value})
            if m['slot'] == 3:
                continue
            selected = e['historical_survivors'][m['slot'] - 1]
            transport = {'Status': 200, 'ResponseBodyScope': 'complete_original_body_read',
                'PreflightFailed': False, 'DoFailed': False, 'ReadFailed': False, 'CloseFailed': False,
                'OriginalContextFailed': False, 'StartedAt': '2020-01-01T00:00:05Z', 'DriverReturnedAt': '2020-01-01T00:00:06Z'}
            original_record = {'usage_class': 'before_retirement_floor', 'enrollment_sha256': m['enrollment_sha256'], 'tuple': tuple_value}
            for phase, cid in (('publish', selected['publication_challenge_id']), ('read', selected['read_challenge_id'])):
                challenge = cut.C.wire({'declared-phase': phase, 'slot': m['slot']})
                insert('capacity_guest_notify_canary_challenges', id=cid, preregistration_id=m['preregistration_id'],
                    record_challenge_id=selected['publication_challenge_id'], phase=phase, policy_id=e['policy_id'], workflow_id=e['workflow_id'],
                    generation=14, fence=28, lease_owner=e['lease_owner'], executor_id=e['executor_id'],
                    original_record=original_record, original_wire=challenge, challenge_sha256=cas.sha(challenge))
                body = cut.C.wire({'declared-return': phase, 'slot': m['slot']})
                selected['read_return_sha256' if phase == 'read' else 'publication_return_sha256'] = cas.sha(body)
                insert('capacity_guest_notify_canary_returns', challenge_id=cid, outcome='accepted', return_sha256=cas.sha(body), original_wire=body,
                    business_observation={'creation_freshness_class': 'original_challenge_publish_consume_read_v2', 'creation_upper_bound_seconds': 5},
                    original_transport=transport, recorded_at='2020-01-01T00:00:06Z')
                nonce = cut.C.wire({'declared-nonce': cid})
                insert('capacity_guest_notify_canary_nonces', challenge_id=cid, final_challenge_wire=nonce, final_challenge_sha256=cas.sha(nonce))
        original_intent = {'generation': 14, 'fence': 28, 'lease_owner': e['lease_owner'], 'policy_id': e['policy_id'],
            'policy_checksum': e['policy_checksum'], 'workflow_id': e['workflow_id'], 'workflow_checksum': e['workflow_checksum'],
            'tuple': e['native_tuple'], 'slot': 3}
        insert('capacity_vm_retirement_intents', id=e['retirement_request_id'], preregistration_id=e['preregistration_id'], original_deadline='2020-01-01T00:00:30Z', intent_record=original_intent)
        insert('capacity_guest_original_retirement_contexts', intent_id=e['retirement_request_id'], original_context_deadline='2020-01-01T00:00:30Z', executor_id=e['executor_id'], core_actual_source_commit=cas.OLD_SOURCE)
        insert('capacity_guest_original_caller_returns', intent_id=e['retirement_request_id'], return_sha256=e['original_caller_sha256'],
            original_record={'status': 0, 'do_failed': True, 'original_context_failed': True, 'body_persisted': False})
        insert('capacity_guest_original_caller_attempts', intent_id=e['retirement_request_id'], original_record={'declared-attempt': True})
        for n in range(4):
            insert('capacity_vm_retirement_original_returns', intent_id=e['retirement_request_id'], sequence=n + 1, original_record={'declared-sequence': n + 1})
            insert('capacity_guest_original_authority_reads', id=uid(60 + n), intent_id=e['retirement_request_id'], phase='before_start' if n < 2 else 'before_poweroff', ordinal=n % 2 + 1)
            insert('capacity_guest_original_authority_returns', read_id=uid(60 + n), original_record={'declared-authorized': True})
            if n < 3:
                insert('capacity_guest_original_authority_transport_returns', read_id=uid(60 + n), native_stage='journal', original_record={'declared-returned': True})
        insert('workflow_runs', id=e['original_run_id'], workflow_id=e['workflow_id'], workflow_namespace=e['namespace'], workflow_name='notify-aws-elastic-capacity',
            status=original_status, finished_at=None if original_status == 'running' else '2020-01-01T00:00:31Z',
            result={'steps': [{'metadata': {'generation': 14, 'fencing_token': 28, 'lease_owner': e['lease_owner']}}]})
        insert('capacity_dispatch_jobs', run_id=e['original_run_id'], realm=e['namespace'], environment=e['environment'], domain=e['domain'], dimension=e['dimension'],
            state='returned', return_status='failed', returned_at='2020-01-01T00:00:31Z',
            finalization_ack_at='2020-01-01T00:00:32Z' if final_ack else None, envelope=json.dumps({'workflow': {'id': e['workflow_id']}}))
        self.pg('\n'.join(statements))
        pins = json.loads(self.pg("SELECT jsonb_build_object('intent',(SELECT encode(digest(intent::text,'sha256'),'hex') FROM capacity_intents WHERE dimension='original_notify_aws_vm_members'),'history',(SELECT encode(digest(jsonb_agg(to_jsonb(v) ORDER BY id)::text,'sha256'),'hex') FROM goose_db_version v),'catalog',(SELECT encode(digest(jsonb_agg(to_jsonb(m) ORDER BY kind,namespace,name,version,id)::text,'sha256'),'hex') FROM manifests m),'slots',(SELECT jsonb_object_agg(slot,encode(digest(slot_record::text,'sha256'),'hex')) FROM capacity_resource_slots));").stdout)
        e['intent_pgtext_sha256'], e['history']['sha256'], e['catalog']['sha256'] = pins['intent'], pins['history'], pins['catalog']
        for m in e['native_members']:
            m['slot_record_sha256'] = pins['slots'][str(m['slot'])]
        sql = cas.held_database_sql(e)
        frame = cas.held_original_frame_sql("'" + e['retirement_request_id'] + "'")
        e['original_frame_sha256'] = self.pg("SELECT encode(digest((" + frame + "),'sha256'),'hex');").stdout.decode().strip()
        ctes = sql.split('\nSELECT jsonb_build_object(', 1)[0]
        rows = json.loads(self.pg(ctes + "\nSELECT jsonb_agg(jsonb_build_object('slot',(h->>'slot')::int,'pin',encode(digest(frame_text,'sha256'),'hex')) ORDER BY h->>'slot') FROM historical_useful; COMMIT;").stdout)
        self.assertEqual(len(rows), 2)
        for h, actual in zip(e['historical_survivors'], rows):
            self.assertEqual(h['slot'], actual['slot'])
            h['frame_sha256'] = actual['pin']
        self.expected = e

    def snapshot(self):
        tables = re.findall(r'CREATE TABLE (\w+)\(', DDL)
        expressions = ["'" + t + "',(SELECT encode(digest(COALESCE(jsonb_agg(to_jsonb(x) ORDER BY to_jsonb(x)::text),'[]'::jsonb)::text,'sha256'),'hex') FROM " + t + ' x)' for t in tables]
        return self.pg('SELECT jsonb_build_object(' + ','.join(expressions) + ');').stdout

    def observe(self, accepted, field=None, expected_value=None, phase=None):
        e, bodies = native_operand(self.expected)
        before = self.snapshot()
        captured = []

        def transport(argv, **kwargs):
            self.assertEqual(argv[:len(cut.KUBE)], cut.KUBE)
            self.assertEqual(kwargs['timeout'], 12)
            result = self.pg(kwargs['input'].decode())
            captured.append(json.loads(result.stdout))
            return result

        with tempfile.TemporaryDirectory() as folder, binding(e), \
                patch.object(cas, 'read', side_effect=lambda p, *_: bodies[str(p)]), \
                patch.object(cut.C, 'read', side_effect=lambda p, *_: Path(p).read_bytes()), \
                patch.object(cut.subprocess, 'run', side_effect=transport) as db, \
                patch.object(cas.API, 'request', side_effect=AssertionError('no native API')) as api:
            call = (lambda: cas.held_current_preimage(cut, Path(folder), e, phase)) if phase else (lambda: cas.database_preflight(cut, Path(folder), e))
            if accepted:
                call()
            else:
                with self.assertRaises(cas.Hold):
                    call()
            db.assert_called_once()
            api.assert_not_called()
            if field:
                self.assertEqual(captured[0][field], expected_value)
            stdout = Path(folder) / ('HELD-CURRENT-' + phase + '.stdout' if phase else 'DB-HELD-READONLY.stdout')
            self.assertEqual(json.loads(stdout.read_bytes()), captured[0])
        self.assertEqual(self.snapshot(), before, 'read-only gate changed declared original rows')
        return captured[0]

    def test_real_held_positive_preserves_whole_originals_and_keeps_history_not_fresh(self):
        self.seed()
        value = self.observe(True)
        self.assertEqual(value['readonly'], 'on')
        self.assertTrue(value['history_exact'] and value['catalog_exact'] and value['original_frame_exact'])
        self.assertEqual(value['historical_useful_survivors'], 2)
        self.observe(True, phase='PRESEND')
        self.observe(True, phase='AFTER-ACK')

    def test_overlap_deduplicates_catalog_uuid_and_logical_run_identity(self):
        self.seed()
        self.pg("INSERT INTO workflow_runs(id,workflow_id,workflow_namespace,workflow_name,status) VALUES('" + uid(100) + "','" + self.expected['workflow_id'] + "','dakasa-production','notify-aws-elastic-capacity','running');")
        self.observe(False, 'busy_runs', 1)

    def test_historical_uuid_with_foreign_logical_identity_is_still_busy(self):
        self.seed()
        self.pg("INSERT INTO workflow_runs(id,workflow_id,workflow_namespace,workflow_name,status) VALUES('" + uid(101) + "','" + uid(1) + "','foreign','other-name','running');")
        self.observe(False, 'busy_runs', 1)

    def test_null_uuid_logical_match_and_unfinished_terminal_are_both_counted(self):
        self.seed()
        self.pg("INSERT INTO workflow_runs(id,workflow_namespace,workflow_name,status) VALUES('" + uid(102) + "','dakasa-production','notify-hetzner-elastic-capacity','succeeded');")
        self.observe(False, 'busy_runs', 1)

        with self.subTest(psql_count='same-UUID-logical-union-and-null-set'):
            # The actual psql stdin path executes the production \gset, not a
            # test-side replacement of its variable, predicate or SQL result.
            self.pg("INSERT INTO workflow_runs(id,workflow_id,workflow_namespace,workflow_name,status,finished_at) VALUES"
                    "('" + uid(110) + "','" + self.expected['workflow_id'] + "','dakasa-production','notify-aws-elastic-capacity','running',NULL),"
                    "('" + uid(111) + "','" + self.expected['workflow_id'] + "','foreign','other-name','running',NULL),"
                    "('" + uid(112) + "',NULL,'dakasa-production','notify-aws-elastic-capacity',NULL,'2020-01-01T00:00:00Z'),"
                    "('" + uid(113) + "',NULL,'dakasa-production','notify-aws-elastic-capacity','failed','2020-01-01T00:00:00Z'),"
                    "('" + uid(114) + "',NULL,'foreign','other-name','running',NULL);")
            # Defensive NULL status belongs to the declared relevant-column
            # fixture. It is not a claim that production DDL permits that row.
            value = self.observe(False, 'busy_runs', 4)
            self.assertEqual(value['busy_runs'], 4, 'overlap must remain one ID and closed/foreign rows excluded')

        with self.subTest(psql_count='whole-catalog-mismatch-still-refuses'):
            self.setUp()
            self.seed()
            original = self.expected['catalog']['sha256']
            try:
                self.expected['catalog']['sha256'] = 'f' * 64 if original != 'f' * 64 else 'e' * 64
                value = self.observe(False, 'catalog_exact', False)
                self.assertEqual(value['busy_runs'], 0, 'catalog refusal must not borrow an unrelated busy row')
            finally:
                self.expected['catalog']['sha256'] = original

        with self.subTest(psql_count='first-select-error-aborts-before-final-JSON'):
            self.setUp()
            self.seed()
            # Declare a missing-relation negative before the actual read-only
            # guard. Retain the original rows under a different fixture name.
            self.pg('ALTER TABLE workflow_runs RENAME TO declared_missing_workflow_runs;')
            before = self.pg("SELECT encode(sha256(convert_to(COALESCE(jsonb_agg(to_jsonb(w) ORDER BY id),'[]'::jsonb)::text,'UTF8')),'hex') FROM declared_missing_workflow_runs w;").stdout
            result = old.REAL_RUN(['docker', 'exec', '-i', self.container, 'psql', '-X', '-q', '-v', 'ON_ERROR_STOP=1',
                                   '-U', 'guardian_ci', '-d', 'yggdrasil', '-At'],
                                  input=cas.held_database_sql(self.expected).encode(), capture_output=True, timeout=12)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, b'', 'failed first SELECT must not emit any accepted guard projection')
            self.assertIn(b'workflow_runs', result.stderr)
            self.assertEqual(self.pg("SELECT encode(sha256(convert_to(COALESCE(jsonb_agg(to_jsonb(w) ORDER BY id),'[]'::jsonb)::text,'UTF8')),'hex') FROM declared_missing_workflow_runs w;").stdout,
                             before, 'failed read-only query changed declared original rows')

    def test_malformed_nonterminal_state_never_counts_as_a_closed_run(self):
        self.seed()
        self.pg("INSERT INTO workflow_runs(id,workflow_namespace,workflow_name,status,finished_at) VALUES('" + uid(105) + "','dakasa-production','notify-aws-elastic-capacity','malformed-declared-CI-state','2020-01-01T00:00:00Z');")
        with self.subTest(defensive_relevant_column_state='unknown-text'):
            self.observe(False, 'busy_runs', 1)
        # Defensive relevant-column fixture state, not a claim that production
        # DDL permits NULL status. A finish timestamp cannot make it terminal.
        self.pg("INSERT INTO workflow_runs(id,workflow_namespace,workflow_name,status,finished_at) VALUES('" + uid(106) + "','dakasa-production','notify-aws-elastic-capacity',NULL,'2020-01-01T00:00:00Z');")
        with self.subTest(defensive_relevant_column_state='null-status-with-finish'):
            self.observe(False, 'busy_runs', 2)

    def test_known_closed_foreign_scope_run_does_not_block(self):
        self.seed()
        self.pg("INSERT INTO workflow_runs(id,workflow_id,workflow_namespace,workflow_name,status) VALUES('" + uid(103) + "','" + uid(3) + "','foreign','notify-aws-elastic-capacity','running');")
        self.observe(True, 'busy_runs', 0)

    def test_other_live_dispatch_blocks_without_rewriting_original_return(self):
        self.seed()
        self.pg("INSERT INTO capacity_dispatch_jobs(realm,environment,domain,dimension,state) VALUES('dakasa-production','production','notify','original_notify_hetzner_vm_members','unknown');")
        self.observe(False, 'busy_jobs', 1)

    def test_physical_alias_grant_in_foreign_realm_is_unresolved_authority(self):
        self.seed()
        p = self.expected['physical_profile']
        self.pg("INSERT INTO capacity_mutation_grants(id,namespace,environment,domain,dimension,integration_instance_id,scope_checksum,profile_name,state) VALUES('" + uid(104) + "','foreign','other','other','other','" + p['integration_instance_id'] + "','" + p['scope_checksum'] + "','" + p['profile_name'] + "','redeemed');")
        self.observe(False, 'native_authority', 1)

    def test_all_four_historical_disposition_pointers_remove_only_their_own_authority(self):
        self.seed()
        p = self.expected['physical_profile']
        columns = ('original_disposition_id', 'failed_original_disposition_id', 'native_denied_disposition_id', 'enrolled_failed_disposition_id')
        for n, column in enumerate(columns):
            self.pg("INSERT INTO capacity_mutation_grants(id,namespace,environment,domain,dimension,integration_instance_id,scope_checksum,profile_name,state," + column + ") VALUES('" + uid(110 + n) + "','foreign','other','other','other','" + p['integration_instance_id'] + "','" + p['scope_checksum'] + "','" + p['profile_name'] + "','settled','" + uid(120 + n) + "');")
        self.observe(True, 'native_authority', 0)

    def test_entire_catalog_including_inactive_versions_is_pinned(self):
        self.seed()
        self.pg("INSERT INTO manifests(id,kind,namespace,name,version,active,checksum,spec) VALUES('" + uid(130) + "','workflow','unrelated','inactive',1,false,'declared-extra','{}');")
        self.observe(False, 'catalog_exact', False)

    def test_entire_goose_history_rejects_an_added_unapplied_row(self):
        self.seed()
        self.pg("INSERT INTO goose_db_version VALUES(4,91,false,'2020-01-01T00:00:00Z');")
        self.observe(False, 'history_exact', False)

    def test_current_held_pgtext_drift_is_refused_at_both_readback_phases(self):
        self.seed()
        self.pg("UPDATE capacity_intents SET intent=intent||'{\"unreviewed_extra\":true}'::jsonb WHERE dimension='original_notify_aws_vm_members';")
        self.observe(False, 'intent_exact', False, phase='PRESEND')
        self.observe(False, 'intent_exact', False, phase='AFTER-ACK')

    def test_other_run_id_cannot_replace_the_known_failed_original(self):
        self.seed()
        self.expected['original_run_id'] = uid(140)
        self.observe(False, 'closed_original_run', 0)

    def test_live_original_run_cannot_be_adopted_as_a_closed_failure(self):
        self.seed(original_status='running')
        self.observe(False, 'closed_original_run', 0)

    def test_missing_original_finalization_ack_never_becomes_an_ack(self):
        self.seed(final_ack=False)
        self.observe(False, 'closed_original_run', 0)

    def test_unexpired_original_capacity_lease_refuses_the_exception(self):
        self.seed(live_lease=True)
        self.observe(False, 'held_unchanged_expired', 0)

    def test_second_held_dimension_keeps_ordinary_steady_restrictions(self):
        self.seed(other_held=True)
        self.observe(False, 'other_nonsteady', 1)

    def test_foreign_native_tuple_cannot_replace_original_membership(self):
        self.seed()
        self.expected['native_tuple']['resource_id'] = 'i-99999999999999999'
        self.expected['native_members'][2]['resource_id'] = 'i-99999999999999999'
        self.observe(False, 'current_physical_members', 2)

    def test_wrong_whole_original_frame_pin_refuses_both_actual_readback_phases(self):
        self.seed()
        self.expected['original_frame_sha256'] = cas.sha(b'foreign declared frame pin')
        self.observe(False, 'frame_exact', False, phase='PRESEND')
        self.observe(False, 'frame_exact', False, phase='AFTER-ACK')

    def test_index89_requires_valid_full_nonunique_btree_workflow_id(self):
        self.seed()
        for ddl in ('', 'CREATE UNIQUE INDEX workflow_runs_workflow_id_idx ON workflow_runs(workflow_id);',
                    "CREATE INDEX workflow_runs_workflow_id_idx ON workflow_runs(workflow_id) WHERE status='running';",
                    'CREATE INDEX workflow_runs_workflow_id_idx ON workflow_runs(id);'):
            self.pg('DROP INDEX IF EXISTS workflow_runs_workflow_id_idx;' + ddl)
            with self.subTest(index=ddl):
                self.observe(False, 'index89_valid', False)

    # Declared relevant-column receipts exercise the actual SQL matcher only.
    # They are not signed/provider records or a production admission proof.
    def terminal_insert(self, table, row):
        self.pg('INSERT INTO ' + table + '(' + ','.join(row) + ') VALUES(' +
                ','.join(self.value(v) for v in row.values()) + ');')

    def terminal_hash_row(self, table, row_id):
        return self.pg("SELECT encode(sha256(convert_to(to_jsonb(w)::text,'UTF8')),'hex') FROM " +
                       table + " w WHERE id='" + row_id + "';").stdout.decode().strip()

    def terminal_seed(self, kind, defect=None):
        """Construct each operand before its first INSERT; never patch originals."""
        self.seed()
        e = self.expected
        job_id, run_id, disposition_id, grant_id, pre_id = (uid(n) for n in range(1000, 1005))
        declared_current_unknown = defect == 'declared_known_HZ_unknown_class'
        if declared_current_unknown:
            # Only public IDs/error class are retained. All times/lease/other
            # operands below remain declared CI data, never a real receipt.
            job_id = '9e6d3b13-b887-4822-9532-3c133d8df58f'
            run_id = '51540911-1389-41b5-a8a4-5cc1b3ee7493'
        started, returned, expires, recorded = ('2020-01-01T00:00:00Z', '2020-01-01T00:00:20Z',
                                               '2020-01-01T00:01:00Z', '2020-01-01T00:20:00Z')
        state = {'native_v1': 'native_denied_disposed', 'native_v2': 'native_denied_disposed'}.get(kind, kind)
        workflow = {'id': e['workflow_id'], 'namespace': e['namespace'],
                    'name': 'notify-aws-elastic-capacity', 'version': 2}
        dimension = e['dimension']
        if declared_current_unknown:
            dimension = 'original_notify_hetzner_vm_members'
            workflow.update(id=uid(2), name='notify-hetzner-elastic-capacity', version=1)
        envelope = {'job_id': job_id, 'run_id': run_id, 'protocol': 'capacity_dispatch_prestart_v1',
                    'realm': e['namespace'], 'environment': 'production', 'domain': 'notify',
                    'dimension': dimension, 'source_tick': 'declared-terminal-CI',
                    'workflow': workflow, 'policy': {'id': e['policy_id'], 'checksum': e['policy_checksum']},
                    'inputs': {'declared': True}, 'metadata': {'declared': True}}
        envelope_wire = cut.C.wire(envelope).decode()
        pointer = {'failed_disposed': 'failed_original_disposition_id',
                   'native_v1': 'native_denied_disposition_id', 'native_v2': 'native_denied_disposition_id',
                   'enrolled_failed_disposed': 'enrolled_failed_disposition_id',
                   'abandoned_disposed': 'abandoned_disposition_id',
                   'finalization_lost_disposed': 'finalization_lost_disposition_id',
                   'unknown_maintenance_disposed': 'unknown_maintenance_disposition_id'}.get(kind)
        j = {'id': job_id, 'run_id': run_id, 'protocol': envelope['protocol'], 'realm': e['namespace'],
             'environment': 'production', 'domain': 'notify', 'dimension': dimension,
             'source_tick': envelope['source_tick'], 'envelope': envelope_wire,
             'envelope_sha256': cas.sha(envelope_wire.encode()), 'state': state,
             'fencing_token': 28, 'lease_owner': e['lease_owner'], 'lease_expires_at': expires,
             'started_at': started, 'returned_at': returned, 'return_status': 'failed',
             'pending_wake_count': 1, 'finalization_ack_at': None}
        w = {'id': run_id, 'workflow_id': workflow['id'], 'workflow_namespace': workflow['namespace'],
             'workflow_name': workflow['name'], 'workflow_version': workflow['version'], 'inputs': envelope['inputs'],
             'metadata': envelope['metadata'], 'started_at': started, 'finished_at': returned,
             'status': 'failed', 'result': {'status': 'failed', 'workflow': workflow}, 'error': None}
        if pointer:
            j[pointer] = disposition_id
        if kind == 'prestart_rejected':
            j.update(started_at=None, returned_at=None, return_status=None, rejected_at=recorded,
                     rejection_reason='policy_superseded_before_start', rejection_issuer='collaborator:' + uid(1010),
                     superseded_policy_id=uid(1011), superseding_policy_id=uid(1012),
                     superseded_policy_checksum='a' * 64, superseding_policy_checksum='b' * 64)
            w.update(started_at=None, finished_at=recorded, status='cancelled', result=None,
                     error='policy_superseded_before_start')
        elif kind in ('abandoned_disposed', 'finalization_lost_disposed'):
            error = ('abandoned_started_dispatch_disposed: historical outcome unknown' if kind == 'abandoned_disposed'
                     else 'finalization_lost_disposed: return observed but not recorded; historical outcome unknown')
            j.update(returned_at=None, return_status=None)
            w.update(finished_at=recorded, result=None, error=error)
        elif kind == 'unknown_maintenance_disposed':
            j['return_error'] = w['error'] = 'capacity dispatch original deadline exceeded'
        elif kind in ('returned', 'unknown', None):
            j['finalization_ack_at'] = '2020-01-01T00:00:21Z' if kind == 'returned' else None
        elif kind == 'native_v2':
            j['finalization_ack_at'] = '2020-01-01T00:00:21Z'
        if declared_current_unknown:
            j['return_error'] = j['finalization_error'] = w['error'] = 'capacity dispatch original context refused'
        if defect == 'native_v1_has_ack':
            j['finalization_ack_at'] = '2020-01-01T00:00:21Z'
        elif defect == 'native_v2_missing_ack':
            j['finalization_ack_at'] = None
        if defect == 'foreign_pointer':
            j[pointer] = uid(1020)
        elif defect == 'multiple_pointer':
            j['abandoned_disposition_id'] = uid(1021)
        elif defect == 'rejection_metadata':
            j['rejected_at'] = recorded
        elif defect == 'foreign_workflow':
            w['workflow_id'] = uid(1022)
        elif defect == 'null_workflow_positive':
            w['workflow_id'] = None  # Original reader permits NULL if logical/result identities match.
        elif defect == 'unfinished':
            w['finished_at'] = None
        elif defect == 'raw_envelope':
            j['envelope'] = '{not-json'
            j['envelope_sha256'] = cas.sha(j['envelope'].encode())
        elif defect == 'envelope_hash':
            j['envelope_sha256'] = 'f' * 64
        self.terminal_insert('workflow_runs', w)
        self.terminal_insert('capacity_dispatch_jobs', j)
        run_sha = self.terminal_hash_row('workflow_runs', run_id)  # Full physical row, not a CTE projection.
        if kind in ('returned', 'unknown', None) or defect == 'missing_ledger':
            return job_id
        if kind == 'prestart_rejected':
            d = {k: j[k] for k in ('envelope_sha256', 'fencing_token', 'superseded_policy_id',
                  'superseding_policy_id', 'superseded_policy_checksum', 'superseding_policy_checksum')}
            d.update(job_id=job_id, run_id=run_id, reason=j['rejection_reason'], issuer=j['rejection_issuer'], recorded_at=recorded)
            self.terminal_insert('capacity_dispatch_prestart_rejections', d)
            return job_id
        if kind in ('abandoned_disposed', 'finalization_lost_disposed', 'unknown_maintenance_disposed'):
            scan = copy.deepcopy(TERMINAL_ZERO83)
            if kind != 'abandoned_disposed':
                scan.update(schema='finalization_lost_dispatch_effect_scan_v1',
                            base_schema='abandoned_started_dispatch_effect_scan_v2',
                            pure_assessment_intent_updates=0, observation_refresh_slot_updates=0)
            if defect == 'overflow_int64':
                scan['resource_slots_updated_since_start'] = scan['observation_refresh_slot_updates'] = 9223372036854775808
            if defect == 'missing_scan_key':
                del scan['authority_reads_since_start']
            if defect == 'bad_scan':
                scan['provider_read_performed'] = True
            d = {'id': disposition_id, 'job_id': job_id, 'run_id': run_id,
                 'original_dispatch_sha256': 'a' * 64, 'original_run_sha256': run_sha,
                 'executor_barrier': 'disposing_core_process_started_after_lease_expiry_v1',
                 'disposing_core_process_started_at': '2020-01-01T00:02:00Z',
                 'disposing_core_hostname': 'declared-ci', 'disposing_core_pid': 123,
                 'disposing_core_source_commit': cas.OLD_SOURCE, 'recorded_at': recorded,
                 'issuer': 'collaborator:' + uid(1010), 'historical_return': 'unknown',
                 'provider_mutation_evidence': scan}
            if kind == 'unknown_maintenance_disposed':
                members = [{'declared_historical_member': True}]
                members_sha = self.pg("SELECT encode(sha256(convert_to((" + self.value(members) + ")::text,'UTF8')),'hex');").stdout.decode().strip()
                d.update(original_returned_at=returned, current_members_sha256=members_sha,
                         reason='unknown_failed_maintenance_dispatch_disposed',
                         provider_mutation_evidence={'schema': 'unknown_maintenance_dispatch_effect_scan_v1',
                          'base': scan, 'current_members': members, 'current_members_sha256': members_sha,
                          'current_member_count': 1, 'policy_epoch_valid': True, 'refresh_only_result': True,
                          'invalid_maintenance_canary_rows': 0})
                if defect == 'wrong_run_hash':
                    d['original_run_sha256'] = 'f' * 64
                if defect == 'wrong_members_hash':
                    d['current_members_sha256'] = 'f' * 64
                table = 'capacity_dispatch_unknown_maintenance_dispositions'
            else:
                d.update({k: j[k] for k in ('realm', 'environment', 'domain', 'dimension', 'envelope_sha256',
                          'fencing_token', 'lease_owner', 'lease_expires_at', 'started_at', 'pending_wake_count')})
                d.update(minimum_lease_age_seconds=900, run_status='failed', run_error=w['error'],
                         reason='abandoned_started_dispatch_disposed' if kind == 'abandoned_disposed'
                         else 'finalization_lost_started_dispatch_disposed')
                if defect == 'foreign_scope':
                    d['dimension'] = 'foreign'
                if defect == 'foreign_epoch':
                    d['fencing_token'] = 29
                if kind == 'finalization_lost_disposed':
                    evidence = 'declared opaque evidence\n'
                    d.update(return_observation='observed_by_operator_evidence_not_recorded',
                             operator_evidence=evidence, operator_evidence_sha256=cas.sha(evidence.encode()))
                    if defect == 'wrong_evidence_hash':
                        d['operator_evidence_sha256'] = 'f' * 64
                table = ('capacity_dispatch_abandoned_dispositions' if kind == 'abandoned_disposed'
                         else 'capacity_dispatch_finalization_lost_dispositions')
            if defect == 'foreign_job':
                d['job_id'] = uid(1023)
            if defect == 'foreign_run':
                d['run_id'] = uid(1024)
            self.terminal_insert(table, d)
            return job_id
        # Three grant-backed branches. Construct raw originals before ledger INSERT.
        prereg_wire = cut.C.wire({'schema': 'declared-relevant-preregistration-CI', 'id': pre_id})
        binding_wire = cut.C.wire({'schema': 'declared-relevant-binding-CI'})
        witness_wire, registration_wire, receipt_wire = (cut.C.wire({'declared-original': v}) for v in ('witness', 'registration', 'receipt'))
        grant = {'generation': 14, 'fencing_token': 28, 'policy_id': e['policy_id'],
                 'policy_checksum': e['policy_checksum'], 'workflow_id': e['workflow_id']}
        g = {'id': grant_id, 'namespace': e['namespace'], 'environment': 'production', 'domain': 'notify',
             'dimension': e['dimension'], **e['physical_profile'], 'slot': 8, 'state': 'settled',
             'grant_record': grant, pointer: disposition_id}
        if defect == 'foreign_scope':
            g['namespace'] = 'foreign'
        self.terminal_insert('capacity_mutation_grants', g)
        self.terminal_insert('capacity_vm_provisioning_preregistrations', {'id': pre_id, 'create_grant_id': grant_id,
                             'original_wire': prereg_wire, 'binding_wire': binding_wire,
                             'original_deadline': '2020-01-01T00:00:30Z',
                             'preregistration_record': {'core_source_commit': cas.OLD_SOURCE}})
        grant_sha = self.pg("SELECT encode(sha256(convert_to(grant_record::text,'UTF8')),'hex') FROM capacity_mutation_grants WHERE id='" + grant_id + "';").stdout.decode().strip()
        if kind in ('failed_disposed', 'enrolled_failed_disposed'):
            self.terminal_insert('capacity_guest_original_create_witnesses', {'preregistration_id': pre_id, 'original_wire': witness_wire})
        if kind == 'enrolled_failed_disposed':
            self.terminal_insert('capacity_vm_original_enrollments', {'preregistration_id': pre_id,
                'enrollment_sha256': 'e' * 64, 'registration_wire': registration_wire, 'receipt_wire': receipt_wire})
        keys = TERMINAL_RECORD_KEYS[kind]
        record = {key: 'a' * 64 for key in keys}
        record.update(id=disposition_id, grant_id=grant_id, preregistration_id=pre_id, job_id=job_id,
                      run_id=run_id, issuer='collaborator:' + uid(1010), original_grant_sha256=grant_sha,
                      original_preregistration_sha256=cas.sha(prereg_wire), original_run_sha256=run_sha,
                      original_dispatch_sha256='a' * 64, original_binding_sha256=cas.sha(binding_wire),
                      original_generation=14, original_fencing_token=28, closed_generation=15,
                      closed_fencing_token=29, original_deadline='2020-01-01T00:00:30Z',
                      recorded_at=recorded, historical_core_source_commit=cas.OLD_SOURCE,
                      observation={'schema': 'declared-CI-observation-not-provider-proof'},
                      observation_sha256='a' * 64, serving_or_business_or_savings_authority=False,
                      schema={'failed_disposed': 'failed_original_guest_terminal_disposition_v1',
                              'enrolled_failed_disposed': 'enrolled_failed_original_guest_terminal_disposition_v1',
                              'native_v1': 'original_native_authorization_denied_terminal_disposition_v1',
                              'native_v2': 'original_native_authorization_denied_failed_returned_ack_terminal_disposition_v2'}[kind])
        if kind in ('failed_disposed', 'enrolled_failed_disposed'):
            record.update(original_witness_sha256=cas.sha(witness_wire), original_accepted_unchanged=True,
                          original_witness_preserved=True, original_unknown_ACK_preserved=True,
                          historical_writer_start_state='unknown')
        else:
            record.update(original_uncertain_and_NULL_identities_unchanged=True,
                          original_unknown_ACK_preserved=kind == 'native_v1', witness_enrollment_installation_absent=True)
            if kind == 'native_v2':
                record.update(original_dispatch_state='returned', original_finalization_ack_at='2020-01-01T00:00:21Z',
                              original_failed_workflow_ACK_preserved=True)
                if defect == 'native_v2_ack_differs':
                    record['original_finalization_ack_at'] = '2020-01-01T00:00:22Z'
        if kind == 'enrolled_failed_disposed':
            record.update(original_registration_sha256=cas.sha(registration_wire), original_receipt_sha256=cas.sha(receipt_wire),
                          original_enrollment_sha256='e' * 64, original_enrollment_preserved=True,
                          Guest_quiescence_proved=False, installation_or_serving_authority=False)
        if defect == 'foreign_epoch':
            record['original_generation'] = 13
        if defect == 'missing_record_key':
            del record['original_binding_sha256']
        if defect == 'extra_record_key':
            record['undeclared_extra'] = 0
        body = cut.C.wire(record)
        if defect == 'malformed_wire':
            body = b'{not-json'
        if defect == 'duplicate_wire_key':
            body = b'{"schema":' + json.dumps(record['schema']).encode() + b',' + body[1:]
        d = {'id': disposition_id, 'grant_id': grant_id, 'preregistration_id': pre_id, 'job_id': job_id,
             'run_id': run_id, 'original_grant_sha256': grant_sha, 'original_preregistration_sha256': cas.sha(prereg_wire),
             'original_dispatch_sha256': 'a' * 64, 'original_run_sha256': run_sha,
             'disposition_sha256': cas.sha(body), 'original_wire': body, 'disposition_record': record,
             'closed_generation': 15, 'closed_fencing_token': 29, 'recorded_at': recorded}
        if kind in ('failed_disposed', 'enrolled_failed_disposed'):
            d['original_witness_sha256'] = cas.sha(witness_wire)
        if kind == 'enrolled_failed_disposed':
            d.update(original_registration_sha256=cas.sha(registration_wire), original_receipt_sha256=cas.sha(receipt_wire), original_enrollment_sha256='e' * 64)
        if defect == 'foreign_job':
            d['job_id'] = uid(1023)
        if defect == 'foreign_run':
            d['run_id'] = uid(1024)
        if defect == 'foreign_grant':
            d['grant_id'] = uid(1025)
        if defect == 'wrong_record_hash':
            d['disposition_sha256'] = 'f' * 64
        table = {'failed_disposed': 'capacity_failed_original_dispositions',
                 'enrolled_failed_disposed': 'capacity_enrolled_failed_original_dispositions',
                 'native_v1': 'capacity_native_denied_dispositions', 'native_v2': 'capacity_native_denied_dispositions'}[kind]
        self.terminal_insert(table, d)
        return job_id

    def terminal_observe_actual_sql(self, busy, allow_json_hold=False, full_held=False):
        before = self.snapshot()
        sql = (cas.held_database_sql(self.expected) if full_held else
               "BEGIN READ ONLY; SET LOCAL statement_timeout='8000ms'; WITH " +
               cas.retained_dispatch_terminal_ctes(89) +
               " SELECT jsonb_build_object('busy_jobs',(SELECT count(*) FROM dispatch_candidates j WHERE NOT EXISTS(SELECT 1 FROM dispatch_terminal_witnesses d WHERE d.job_id=j.id))); COMMIT;")
        result = old.REAL_RUN(['docker', 'exec', '-i', self.container, 'psql', '-X', '-q', '-v', 'ON_ERROR_STOP=1',
                             '-U', 'guardian_ci', '-d', 'yggdrasil', '-At'], input=sql.encode(), capture_output=True, timeout=12)
        if result.returncode:
            self.assertTrue(allow_json_hold and busy > 0, result.stderr.decode(errors='replace'))
            self.assertRegex(result.stderr.decode(errors='replace'), r'(?i)(json|invalid|syntax|encoding)')
        else:
            value = json.loads(result.stdout)
            self.assertEqual(value['busy_jobs'], busy)
        self.assertEqual(self.snapshot(), before, 'actual terminal SQL wrote original/ledger rows')

    def test_actual_retained_terminal_contract_and_fail_closed_cases(self):
        """One new PG method; subcases do not replace any original20 intent."""
        positive = ('prestart_rejected', 'failed_disposed', 'native_v1', 'native_v2',
                    'enrolled_failed_disposed', 'abandoned_disposed',
                    'finalization_lost_disposed', 'unknown_maintenance_disposed', 'returned')
        for kind in positive:
            with self.subTest(actual_terminal_positive=kind):
                self.setUp()
                self.terminal_seed(kind)
                self.terminal_observe_actual_sql(0)
                self.terminal_observe_actual_sql(0, full_held=True)
                if kind in ('native_v2', 'unknown_maintenance_disposed'):
                    self.observe(True, 'busy_jobs', 0)  # Existing real-DB custody + full Python gate.
        with self.subTest(nullable_workflow_positive='logical-and-result-identities-exact'):
            self.setUp()
            self.terminal_seed('failed_disposed', 'null_workflow_positive')
            self.terminal_observe_actual_sql(0)
        negative = [('unknown', None), (None, None)]
        negative.append(('unknown', 'declared_known_HZ_unknown_class'))
        negative += [('failed_disposed', d) for d in ('foreign_pointer', 'multiple_pointer', 'rejection_metadata',
                     'foreign_workflow', 'unfinished', 'raw_envelope', 'envelope_hash', 'missing_ledger',
                     'foreign_job', 'foreign_run', 'foreign_scope', 'foreign_epoch', 'foreign_grant',
                     'missing_record_key', 'extra_record_key', 'malformed_wire', 'duplicate_wire_key', 'wrong_record_hash')]
        negative += [('abandoned_disposed', d) for d in ('foreign_scope', 'foreign_epoch', 'missing_scan_key', 'bad_scan')]
        negative += [('finalization_lost_disposed', d) for d in ('wrong_evidence_hash', 'overflow_int64')]
        negative += [('unknown_maintenance_disposed', d) for d in ('wrong_run_hash', 'wrong_members_hash', 'bad_scan')]
        negative += [('native_v1', 'native_v1_has_ack'), ('native_v2', 'native_v2_missing_ack'),
                     ('native_v2', 'native_v2_ack_differs')]
        for kind, defect in negative:
            with self.subTest(actual_terminal_refusal=kind, defect=defect):
                self.setUp()
                self.terminal_seed(kind, defect)
                self.terminal_observe_actual_sql(1, allow_json_hold=defect in ('raw_envelope', 'malformed_wire'))
        self.assertEqual(len(re.findall(r'CREATE TABLE (\w+)\(', DDL)), 30)
