"""Actual R6 image-only admission functions with declared CI custody operands.

No database or native qualification is claimed here. The separate PG tests run
actual SQL. This file exercises private reads and the real CLI with simulated
external facts; it never exports an alternate production admission mechanism.
"""
import contextlib
import copy
import datetime
import io
import os
from pathlib import Path
import sys
import tempfile
import time
import types
import unittest
from unittest.mock import Mock, patch

import test_g9pair_core_cas as base


cas = base.cas
cut = base.cut


def projection():
    identity = cas.HTTP_MAINTENANCE_HELD_IDENTITY
    members = 'c' * 64
    return {
        'observed_at_pg': '2026-11-03T12:00:00+00:00',
        'job_id': identity['job_id'], 'run_id': identity['run_id'],
        'original_dispatch_sha256': 'd' * 64, 'original_run_sha256': 'e' * 64,
        'cas': {'job_id': identity['job_id'], 'expected_run_id': identity['run_id'],
                'expected_envelope_sha256': 'a' * 64, 'expected_fencing_token': 3,
                'expected_lease_owner': base.uid(71), 'expected_pending_wake_count': 1,
                'expected_returned_at': '2026-11-03T04:28:06.051826Z',
                'expected_run_sha256': 'e' * 64, 'expected_members_sha256': members},
        'effect_scan': {'schema': 'recorded_http_maintenance_dispatch_effect_scan_v1',
                        'base': {'declared_CI_not_database_proof': True},
                        'current_members': [], 'current_members_sha256': members,
                        'current_member_count': 1, 'policy_epoch_valid': True,
                        'refresh_only_result': True, 'invalid_maintenance_canary_rows': 0},
        'admission': True,
    }


def private_operands(value=None, *, query=b'SELECT $1::uuid;\n'):
    """Declared raw operands only; the compiled query digest is bound in CI."""
    prefix = '/var/lib/dakasa-core-rollout/declared-r6-CI/'
    paths = {name: Path(prefix + name) for name in
             ('HTTP-UPGRADE.json', 'QUERY.sql', 'PROJECTION.json', 'ROOT-REVIEW.json')}
    selected_projection = projection() if value is None else value
    raw_projection = cut.C.wire(selected_projection)
    # These are declared CI reviewer operands, never a Root approval artifact.
    identity = {key: item for key, item in selected_projection.items() if key != 'observed_at_pg'}
    review = cut.C.wire({'schema': 'root_goose91_HTTP_HELD_upgrade_review_v1',
                         'reviewed_by_root': True, 'unknown_state': 'UNKNOWN',
                         'identity_sha256': cas.sha(cut.C.wire(identity)),
                         'pre91_query_sha256': cas.sha(query)})
    data = {paths['QUERY.sql']: query, paths['PROJECTION.json']: raw_projection,
            paths['ROOT-REVIEW.json']: review}
    envelope = {'schema': 'root_exact_recorded_http_maintenance_image_upgrade_v1',
                'identity': copy.deepcopy(cas.HTTP_MAINTENANCE_HELD_IDENTITY),
                **{key: {'path': str(paths[name]), 'sha256': cas.sha(data[paths[name]])}
                   for key, name in [('query_ref', 'QUERY.sql'),
                                     ('projection_ref', 'PROJECTION.json'),
                                     ('Root_review_ref', 'ROOT-REVIEW.json')]}}
    selected = paths['HTTP-UPGRADE.json']
    data[selected] = cut.C.wire(envelope)
    return selected, envelope, data


@contextlib.contextmanager
def private_mount(data, *, mode=0o600, owner=0, variant=None):
    """Real CI file descriptors, with only Brain paths/root ownership declared."""
    with tempfile.TemporaryDirectory() as folder:
        mapped = {}
        for index, (selected, raw) in enumerate(data.items()):
            local = Path(folder) / str(index)
            if variant == 'directory':
                local.mkdir(mode=mode)
            elif variant != 'missing':
                local.write_bytes(raw)
                local.chmod(mode)
                if variant == 'hardlink':
                    os.link(local, Path(folder) / (str(index) + '-link'))
                elif variant == 'symlink':
                    target = Path(folder) / (str(index) + '-target')
                    local.rename(target)
                    local.symlink_to(target)
            mapped[Path(selected)] = local
        real_open, real_fstat = os.open, os.fstat

        def opened(path, flags, *args, **kwargs):
            return real_open(mapped.get(Path(path), path), flags, *args, **kwargs)

        def observed(fd):
            actual = real_fstat(fd)
            fields = {name: getattr(actual, name) for name in dir(actual) if name.startswith('st_')}
            fields['st_uid'] = owner
            return types.SimpleNamespace(**fields)

        with patch.object(cas.os, 'open', side_effect=opened), \
                patch.object(cas.os, 'fstat', side_effect=observed):
            yield


@contextlib.contextmanager
def bound_http(expected, query):
    with base.binding(expected), patch.multiple(cas, HTTP_MAINTENANCE_UPGRADE_BOUND=True,
                                               HTTP_MAINTENANCE_PRE91_QUERY_SHA256=cas.sha(query)):
        yield


def argv(package, returned, run, held, held_raw):
    return ['core_image_cas_once_g9.py', '--package', str(package),
            '--expected-ops-source', '1' * 40, '--expected-manifest-sha256', '2' * 64,
            '--g9-swap-return', str(returned), '--expected-g9-swap-return-sha256', '3' * 64,
            '--evidence-dir', str(run), '--held-admission', str(held),
            '--expected-held-admission-sha256', cas.sha(held_raw), '--execute-core-image-cas-once']


class R6CASPrivateInputTests(unittest.TestCase):
    def test_fixed_public_identity_and_unbound_refusal_before_private_io(self):
        self.assertEqual(cas.HTTP_MAINTENANCE_HELD_IDENTITY, {
            'job_id': '9e6d3b13-b887-4822-9532-3c133d8df58f',
            'run_id': '51540911-1389-41b5-a8a4-5cc1b3ee7493',
            'realm': 'dakasa-production', 'environment': 'production', 'domain': 'notify',
            'dimension': 'original_notify_hetzner_vm_members',
            'error': 'capacity dispatch original context refused'})
        for version in (90, 88, 92, 93, True, '91', None):
            with self.subTest(schema_version=version), self.assertRaises(cas.Hold):
                cas.retained_dispatch_terminal_ctes(version)
        with base.binding(base.declared_held()), \
                patch.object(cas, 'HTTP_MAINTENANCE_UPGRADE_BOUND', False), \
                patch.object(cas, 'read') as read:
            with self.assertRaises(cas.Hold):
                cas.load_http_maintenance_upgrade(cut.C, Path('/never-read'), 'a' * 64)
            read.assert_not_called()
        # Declared transport operands exercise the real response guard. They do
        # not insert a Goose row or assert that any database was migrated.
        e = base.declared_held()
        value = {'database': 'yggdrasil', 'readonly': 'on', 'schema': 92,
                 'migration88_applied': 1, 'migration89_applied': 1,
                 'migration90_applied': 1, 'migration91_applied': 1,
                 'migration92_applied': 1, 'history_max_version': 92, 'index92_valid': True,
                 'history_rows': e['history']['rows'], 'history_exact': True,
                 'catalog_rows': e['catalog']['rows'], 'catalog_exact': True,
                 'index89_valid': True, 'active_latest_policies': 2,
                 'current_original_catalog': 1, 'current_original_binding': 1,
                 'current_physical_members': 3, 'physical_profile_slot_count': 3,
                 'historical_useful_survivors': 2, 'forward_table_present': True,
                 'held_count': 1, 'held_unchanged_expired': 1, 'known_original': 1,
                 'closed_original_run': 1, 'original_frame_exact': True,
                 'original_row_count': 4, 'original_failed_caller': 1,
                 'authority_reads': 4, 'authority_returns': 4,
                 'journal_transports': 3, 'delete_bindings': 0,
                 'forward_admissions': 0, 'other_leases': 0,
                 'other_nonsteady': 0, 'busy_jobs': 1, 'busy_runs': 0,
                 'native_authority': 0}
        original = copy.deepcopy(value)
        self.assertIs(cas.validate_r6_held_database(value, e), value)
        self.assertEqual(value, original)
        for key, wrong in (('schema', 91), ('schema', 93),
                           ('history_max_version', 91), ('history_max_version', 93),
                           ('migration92_applied', 0), ('migration92_applied', 2),
                           ('index92_valid', False), ('index89_valid', False),
                           ('history_exact', False), ('catalog_exact', False),
                           ('migration88_applied', 0), ('migration91_applied', 0),
                           ('busy_jobs', 0), ('busy_runs', 1)):
            with self.subTest(declared_response_field=key, refused_value=wrong):
                bad = {**value, key: wrong}
                with self.assertRaises(cas.Hold):
                    cas.validate_r6_held_database(bad, e)
                self.assertEqual(value, original)

    def test_projection_closes_identity_cas_digest_types_and_scan_envelope(self):
        value = projection()
        self.assertIs(cas.validate_http_maintenance_projection(value), value)
        mutations = {
            'extra_top_field': lambda x: x.update(authority=True),
            'alternate_job': lambda x: x.update(job_id=base.uid(72)),
            'alternate_run': lambda x: x.update(run_id=base.uid(73)),
            'refused_admission': lambda x: x.update(admission=False),
            'nonboolean_admission': lambda x: x.update(admission=1),
            'non_utc_clock': lambda x: x.update(observed_at_pg='2026-11-03T12:00:00'),
            'extra_cas_field': lambda x: x['cas'].update(authority=True),
            'foreign_cas_job': lambda x: x['cas'].update(job_id=base.uid(74)),
            'foreign_cas_run': lambda x: x['cas'].update(expected_run_id=base.uid(75)),
            'zero_owner': lambda x: x['cas'].update(expected_lease_owner='00000000-0000-0000-0000-000000000000'),
            'bool_fence': lambda x: x['cas'].update(expected_fencing_token=True),
            'overflow_fence': lambda x: x['cas'].update(expected_fencing_token=9007199254740992),
            'zero_wakes': lambda x: x['cas'].update(expected_pending_wake_count=0),
            'overflow_wakes': lambda x: x['cas'].update(expected_pending_wake_count=33),
            'bool_wakes': lambda x: x['cas'].update(expected_pending_wake_count=True),
            'bad_envelope_digest': lambda x: x['cas'].update(expected_envelope_sha256='short'),
            'foreign_whole_run': lambda x: x.update(original_run_sha256='f' * 64),
            'bad_whole_dispatch': lambda x: x.update(original_dispatch_sha256='short'),
            'old_scan_schema': lambda x: x['effect_scan'].update(schema='unknown_maintenance_dispatch_effect_scan_v1'),
            'foreign_members': lambda x: x['effect_scan'].update(current_members_sha256='f' * 64),
            'extra_scan_field': lambda x: x['effect_scan'].update(authority=True),
        }
        for name, change in mutations.items():
            with self.subTest(name=name):
                changed = copy.deepcopy(value)
                change(changed)
                with self.assertRaises(cas.Hold):
                    cas.validate_http_maintenance_projection(changed)
        # This is intentionally a shape validator, not a Python copy of SQL/Go94.
        self.assertEqual(value['effect_scan']['base'], {'declared_CI_not_database_proof': True})

    def test_actual_loader_reads_all_four_private_files_and_preserves_raw_projection(self):
        selected, envelope, data = private_operands()
        with bound_http(base.declared_held(), data[Path(envelope['query_ref']['path'])]), private_mount(data):
            bundle, raw = cas.load_http_maintenance_upgrade(cut.C, selected, cas.sha(data[selected]))
        self.assertEqual(set(bundle), {'input', 'projection', 'query'})
        self.assertEqual(raw, data[selected])
        self.assertEqual(bundle['input'], envelope)
        self.assertEqual(cut.C.wire(bundle['projection']), data[Path(envelope['projection_ref']['path'])])
        self.assertEqual(bundle['projection']['observed_at_pg'], '2026-11-03T12:00:00+00:00')
        self.assertEqual(bundle['query'], data[Path(envelope['query_ref']['path'])])

    def test_loader_refuses_real_custody_hash_closed_json_and_alternate_identity(self):
        selected, envelope, original = private_operands()
        query = original[Path(envelope['query_ref']['path'])]
        variants = ('mode', 'owner', 'missing', 'directory', 'symlink', 'hardlink', 'oversize',
                    'input_sha', 'malformed', 'duplicate', 'extra_field', 'alternate_identity',
                    'query_sha', 'projection_sha', 'review_sha', 'compiled_query_sha', 'query_parameter',
                    'reference_extra_field', 'reference_outside_brain', 'reference_bad_digest',
                    'false_review', 'wrong_review_identity', 'extra_review_key')
        for variant in variants:
            with self.subTest(variant=variant):
                data, changed = dict(original), copy.deepcopy(envelope)
                if variant == 'oversize':
                    data[selected] = b' ' * ((128 << 10) + 1)
                elif variant == 'malformed':
                    data[selected] = b'{'
                elif variant == 'duplicate':
                    data[selected] = b'{"schema":"one","schema":"two"}'
                elif variant == 'extra_field':
                    changed['authority'] = True
                    data[selected] = cut.C.wire(changed)
                elif variant == 'alternate_identity':
                    changed['identity']['job_id'] = base.uid(79)
                    data[selected] = cut.C.wire(changed)
                elif variant in ('false_review', 'wrong_review_identity', 'extra_review_key'):
                    key = Path(envelope['Root_review_ref']['path'])
                    review = cut.C.loads(data[key])
                    if variant == 'false_review':
                        review['reviewed_by_root'] = False
                    elif variant == 'wrong_review_identity':
                        review['identity_sha256'] = 'f' * 64
                    else:
                        review['authority'] = True
                    data[key] = cut.C.wire(review)
                    changed['Root_review_ref']['sha256'] = cas.sha(data[key])
                    data[selected] = cut.C.wire(changed)
                elif variant.startswith('reference_'):
                    if variant == 'reference_extra_field':
                        changed['query_ref']['authority'] = True
                    elif variant == 'reference_outside_brain':
                        changed['query_ref']['path'] = '/tmp/not-Brain-private-query.sql'
                    else:
                        changed['query_ref']['sha256'] = 'short'
                    data[selected] = cut.C.wire(changed)
                elif variant in ('query_sha', 'projection_sha', 'review_sha'):
                    key = {'query_sha': 'query_ref', 'projection_sha': 'projection_ref', 'review_sha': 'Root_review_ref'}[variant]
                    data[Path(envelope[key]['path'])] += b' '
                elif variant == 'query_parameter':
                    data[Path(envelope['query_ref']['path'])] = b'SELECT $1::uuid,$1::uuid;\n'
                    changed['query_ref']['sha256'] = cas.sha(data[Path(envelope['query_ref']['path'])])
                    data[selected] = cut.C.wire(changed)
                compiled = data[Path(envelope['query_ref']['path'])] if variant == 'query_parameter' else query
                expected = 'f' * 64 if variant == 'input_sha' else cas.sha(data[selected])
                with contextlib.ExitStack() as stack:
                    stack.enter_context(bound_http(base.declared_held(), compiled))
                    if variant == 'compiled_query_sha':
                        stack.enter_context(patch.object(cas, 'HTTP_MAINTENANCE_PRE91_QUERY_SHA256', 'f' * 64))
                    stack.enter_context(private_mount(data, mode=0o644 if variant == 'mode' else 0o600,
                                                     owner=1001 if variant == 'owner' else 0,
                                                     variant=variant if variant in ('missing','directory','symlink','hardlink') else None))
                    with self.assertRaises((cas.Hold, cut.C.Hold, OSError, ValueError)):
                        cas.load_http_maintenance_upgrade(cut.C, selected, expected)

    def test_actual_current_preimage_requires_one_exact_held_and_no_unrelated_job(self):
        query = b'SELECT $1::uuid;\n'
        bundle = {'projection': projection(), 'query': query}
        counts = {'total_jobs': 1, 'held_jobs': 1, 'unrelated_jobs': 0}

        def fresh():
            actual = copy.deepcopy(bundle['projection'])
            actual['observed_at_pg'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
            return actual

        with bound_http(base.declared_held(), query):
            for phase in ('PREFLIGHT', 'PRESEND', 'AFTER-ACK'):
                answers = [counts] if phase == 'PREFLIGHT' else [fresh(), counts]
                with self.subTest(phase=phase), patch.object(cas, 'http_upgrade_db_read', side_effect=answers) as transport:
                    result = cas.http_maintenance_current_preimage(cut, Path('/declared-CI'), bundle, phase)
                    self.assertEqual(result, counts)
                    calls = transport.call_args_list
                    self.assertEqual(len(calls), 1 if phase == 'PREFLIGHT' else 2)
                    if phase != 'PREFLIGHT':
                        self.assertEqual(calls[0].args[:3], (cut, Path('/declared-CI'), 'DB-R6-HTTP-CANONICAL-' + phase))
                        self.assertIn(cas.HTTP_MAINTENANCE_HELD_IDENTITY['job_id'], calls[0].args[3])
                        self.assertNotIn('$1::uuid', calls[0].args[3])
                    self.assertEqual(calls[-1].args[:3], (cut, Path('/declared-CI'), 'DB-R6-HTTP-' + phase))
                    self.assertEqual(calls[-1].args[3], cas.http_maintenance_counts_sql(bundle['projection'], 91))
            for wrong in ({'total_jobs': 2, 'held_jobs': 1, 'unrelated_jobs': 1},
                          {'total_jobs': 1, 'held_jobs': 0, 'unrelated_jobs': 1},
                          {'total_jobs': 0, 'held_jobs': 0, 'unrelated_jobs': 0}):
                with self.subTest(counts=wrong), patch.object(cas, 'http_upgrade_db_read', side_effect=[fresh(), wrong]) as transport:
                    with self.assertRaises(cas.Hold):
                        cas.http_maintenance_current_preimage(cut, Path('/declared-CI'), bundle, 'PRESEND')
                    self.assertEqual(transport.call_count, 2)
            for defect in ('canonical_drift', 'stale_pg_clock', 'future_pg_clock'):
                actual = fresh()
                if defect == 'canonical_drift':
                    actual['original_dispatch_sha256'] = 'f' * 64
                else:
                    seconds = -16 if defect == 'stale_pg_clock' else 5
                    actual['observed_at_pg'] = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=seconds)).isoformat()
                with self.subTest(canonical=defect), patch.object(cas, 'http_upgrade_db_read', return_value=actual) as transport:
                    with self.assertRaises(cas.Hold):
                        cas.http_maintenance_current_preimage(cut, Path('/declared-CI'), bundle, 'PRESEND')
                    transport.assert_called_once()
                    self.assertEqual(transport.call_args.args[2], 'DB-R6-HTTP-CANONICAL-PRESEND')
            with patch.object(cas, 'http_upgrade_db_read') as transport:
                with self.assertRaises(cas.Hold):
                    cas.http_maintenance_current_preimage(cut, Path('/declared-CI'), bundle, 'OTHER')
                transport.assert_not_called()


class R6CASCLITests(unittest.TestCase):
    def test_actual_parser_requires_both_http_flags_and_the_original_s3_admission_before_api(self):
        e = base.declared_held()
        raw = cut.C.wire(e)
        selected, envelope, data = private_operands()
        for variant in ('missing_file', 'missing_sha', 'missing_s3', 'unbound', 'wrong_sha'):
            with self.subTest(variant=variant), base.declared_private_input(raw) as held:
                command = argv(base.tools.TOOLS.parent, cas.ROOT / 'swap-once-CI/RETURN.json',
                               cas.ROOT / 'core-image-cas-CI', held, raw)
                if variant == 'missing_s3':
                    index = command.index('--held-admission')
                    del command[index:index + 4]
                if variant != 'missing_file':
                    command += ['--http-maintenance-upgrade-admission', str(selected)]
                if variant != 'missing_sha':
                    command += ['--expected-http-maintenance-upgrade-admission-sha256',
                                'f' * 64 if variant == 'wrong_sha' else cas.sha(data[selected])]
                with contextlib.ExitStack() as stack:
                    stack.enter_context(bound_http(e, data[Path(envelope['query_ref']['path'])]))
                    stack.enter_context(private_mount(data))
                    stack.enter_context(patch.object(sys, 'argv', command))
                    stack.enter_context(patch.object(cas.os, 'geteuid', return_value=0))
                    stack.enter_context(patch.object(cas.sys, 'platform', 'linux'))
                    stack.enter_context(patch.object(cas, 'load_tools', return_value=cut))
                    if variant == 'unbound':
                        stack.enter_context(patch.object(cas, 'HTTP_MAINTENANCE_UPGRADE_BOUND', False))
                    package = stack.enter_context(patch.object(cut.C, 'package'))
                    api = stack.enter_context(patch.object(cas, 'API'))
                    lock = stack.enter_context(patch.object(cas, 'operation_lock'))
                    database = stack.enter_context(patch.object(cas, 'database_r6_held_preflight'))
                    with self.assertRaises((cas.Hold, cut.C.Hold, OSError, ValueError)):
                        cas.main()
                    package.assert_not_called()
                    api.assert_not_called()
                    lock.assert_not_called()
                    database.assert_not_called()

    def test_actual_cli_retains_one_http_input_before_api_and_reuses_the_object_at_all_boundaries(self):
        e = base.declared_held()
        held_raw = cut.C.wire(e)
        selected, envelope, data = private_operands()
        events, held_values, upgrades = [], [], []
        query = data[Path(envelope['query_ref']['path'])]
        with tempfile.TemporaryDirectory() as folder, bound_http(e, query), \
                base.declared_private_input(held_raw) as held, private_mount(data):
            root = Path(folder)
            returned = root / 'swap-once-declared-CI/RETURN.json'
            returned.parent.mkdir()
            returned.write_bytes(cut.C.wire({'declared_CI_swap_not_native': True}))
            returned.chmod(0o600)
            manifest = base.tools.declared_manifest()
            manifest['source_commit'] = '1' * 40
            with patch.object(base.old, 'cas', cas), patch.object(base.old, 'cut', cut):
                before, pods = base.old.core_preimage()
            protected = cas.required_protected_refs()
            ctrl, guard = (copy.deepcopy(manifest[k]) for k in ('expected_controller_identity','expected_guardian_identity'))
            original = {'core': cas.core_before(before, pods, cut.C), 'controller': ctrl,
                        'guardian': guard, 'protected_refs': protected}
            previous = returned.parent / 'BEFORE.json'
            previous.write_bytes(cut.C.wire(original))
            previous.chmod(0o600)
            claim = {'schema': 'g9_once_only_swap_claim_v1', 'manifest_sha256': '2' * 64,
                     'old_controller': ctrl, 'old_guardian': guard,
                     'run': str(returned.parent), 'automatic_replay': False}
            claim_path = root / ('SWAP-' + '2' * 64 + '-POSSIBLE.json')
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
            load_s3, load_http = cas.load_held_admission, cas.load_http_maintenance_upgrade
            current_http = cas.http_maintenance_current_preimage

            def s3_loader(*args):
                result = load_s3(*args)
                held_values.append(result[0])
                events.append('load-s3')
                return result

            def http_loader(*args):
                result = load_http(*args)
                upgrades.append(result[0])
                events.append('load-http')
                return result

            def database(selected_cut, selected_run, value, upgrade):
                self.assertIs(selected_cut, cut)
                self.assertEqual(selected_run, run)
                self.assertIs(value, held_values[0])
                self.assertIs(upgrade, upgrades[0])
                events.append('database-r6')

            def http_current(selected_cut, selected_run, value, phase):
                self.assertIs(value, upgrades[0])
                events.append('http-' + phase)
                return current_http(selected_cut, selected_run, value, phase)

            def s3_current(selected_cut, selected_run, value, phase):
                self.assertIs(value, held_values[0])
                events.append('s3-' + phase)

            def native(value, loads):
                self.assertIs(value, held_values[0])
                self.assertIs(loads, cut.C.loads)
                events.append('native-readonly')

            def counts_transport(selected_cut, selected_run, name, sql):
                self.assertIs(selected_cut, cut)
                self.assertEqual(selected_run, run)
                if name.startswith('DB-R6-HTTP-CANONICAL-'):
                    phase = name.removeprefix('DB-R6-HTTP-CANONICAL-')
                    events.append('canonical-' + phase)
                    actual = copy.deepcopy(upgrades[0]['projection'])
                    actual['observed_at_pg'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
                    return actual
                phase = name.removeprefix('DB-R6-HTTP-')
                self.assertIn(phase, ('PRESEND','AFTER-ACK'))
                events.append('counts-' + phase)
                return {'total_jobs':1,'held_jobs':1,'unrelated_jobs':0}

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
                self.assertEqual(events, ['load-s3','load-http'])
                self.assertEqual((run / 'HELD-ADMISSION.INPUT.json').read_bytes(), held_raw)
                self.assertEqual((run / 'HTTP-MAINTENANCE-UPGRADE.INPUT.json').read_bytes(), data[selected])
                meta = cut.C.loads((run / 'HTTP-MAINTENANCE-UPGRADE.INPUT-SHA256.json').read_bytes())
                self.assertEqual(meta['sha256'], cas.sha(data[selected]))
                self.assertFalse(meta['steady_or_business_or_retirement_authority'])
                events.append('api')
                return api

            def private_dir(path, create=False):
                if create:
                    Path(path).mkdir(mode=0o700)

            command = argv(base.tools.TOOLS.parent, returned, run, held, held_raw)
            command[command.index('--expected-g9-swap-return-sha256') + 1] = cas.sha(returned.read_bytes())
            command += ['--http-maintenance-upgrade-admission', str(selected),
                        '--expected-http-maintenance-upgrade-admission-sha256', cas.sha(data[selected])]
            backend = types.SimpleNamespace(files=Mock(), protected=Mock(return_value=protected))
            with contextlib.ExitStack() as stack:
                for obj, name, value in [(sys,'argv',command),(cas.os,'geteuid',lambda:0),
                                         (cas.sys,'platform','linux'),(cas,'ROOT',root),(cas,'OPLOCK',lock_path)]:
                    stack.enter_context(patch.object(obj, name, value))
                stack.enter_context(patch.object(cas,'load_tools',return_value=cut))
                stack.enter_context(patch.object(cut.C,'package',return_value=(base.tools.TOOLS.parent,manifest)))
                stack.enter_context(patch.object(cut.C,'private_dir',side_effect=private_dir))
                stack.enter_context(patch.object(cas,'load_held_admission',side_effect=s3_loader))
                stack.enter_context(patch.object(cas,'load_http_maintenance_upgrade',side_effect=http_loader))
                stack.enter_context(patch.object(cas,'operation_lock',return_value=contextlib.nullcontext((lock_stat.st_dev,lock_stat.st_ino))))
                stack.enter_context(patch.object(cas,'API',side_effect=client))
                db = stack.enter_context(patch.object(cas,'database_r6_held_preflight',side_effect=database))
                normal = stack.enter_context(patch.object(cas,'database_preflight'))
                stack.enter_context(patch.object(cas,'held_current_preimage',side_effect=s3_current))
                current = stack.enter_context(patch.object(cas,'http_maintenance_current_preimage',side_effect=http_current))
                counts = stack.enter_context(patch.object(cas,'http_upgrade_db_read',side_effect=counts_transport))
                stack.enter_context(patch.object(cas,'validate_held_native_observation',side_effect=native))
                stack.enter_context(patch.object(cas,'g9_acceptance',return_value=(backend,protected,ctrl,guard,time.monotonic())))
                stack.enter_context(patch.object(cut,'physical_identity',side_effect=[ctrl,guard]))
                stack.enter_context(patch.object(cas.signal,'signal'))
                stack.enter_context(patch.object(cas.signal,'alarm'))
                output = stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
                cas.main()
                db.assert_called_once()
                normal.assert_not_called()
                self.assertEqual(current.call_count,2)
                self.assertEqual(counts.call_count,4)
            self.assertEqual(events,['load-s3','load-http','api','database-r6','s3-PRESEND',
                                     'http-PRESEND','canonical-PRESEND','counts-PRESEND','native-readonly','patch',
                                     's3-AFTER-ACK','http-AFTER-ACK','canonical-AFTER-ACK','counts-AFTER-ACK'])
            self.assertEqual(len(held_values),1)
            self.assertEqual(len(upgrades),1)
            self.assertEqual([call.args[0] for call in api.request.call_args_list],['GET','GET','PATCH','GET','GET','PATCH'])
            result = cut.C.loads(output.getvalue())
            self.assertEqual(result['status'],'PATCH_ACKNOWLEDGED_ACCEPTANCE_PENDING')
            self.assertFalse(result['new_pod_readiness_proven'])
            self.assertFalse(result['post_rollout_G9_and_E2E_acceptance_proven'])
            self.assertFalse((run/'HOLD.PUBLIC.json').exists())
