"""CI-only declared restoration lineage operands; never Native/Root acceptance."""
from pathlib import Path
import copy
import hashlib
import importlib.util
import json
import unittest

from test_schema98_rollout import installed_operand98

HERE = Path(__file__).resolve().parent
HELPER = HERE.parent / 'rollout' / 'restore98_recovered_g44.py'
spec = importlib.util.spec_from_file_location('ci_real_restore98_same_epoch', HELPER)
R = importlib.util.module_from_spec(spec)
spec.loader.exec_module(R)


def wire(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def bytea(raw):
    return '\\x' + raw.hex()


def uid(number):
    return '00000000-0000-4000-8000-%012d' % number


def declared_restoration():
    """Reuse the existing declared G44 eight-installation fixture, no native claims."""
    _, case, original = installed_operand98()
    original = copy.deepcopy(original)
    job, run, intent = (original[name] for name in ('job', 'run', 'intent'))
    job['created_at'] = '2026-11-11T10:04:07Z'
    job['updated_at'] = job['returned_at']
    members = []
    for proof in original['proofs']:
        pre = proof['preregistration']
        installation = json.loads(bytes.fromhex(proof['installation']['original_wire'][2:]))
        members.append({
            'slot': proof['slot_record']['slot'],
            'preregistration_id': pre['id'],
            'create_grant_id': pre['create_grant_id'],
            'tuple': copy.deepcopy(proof['witness']['original_record']['tuple']),
            'request_sha256': pre['preregistration_record']['original_create_request_sha256'],
            'preregistration_sha256': digest(bytes.fromhex(pre['original_wire'][2:])),
            'witness_sha256': proof['witness']['witness_sha256'],
            'enrollment_sha256': proof['enrollment']['enrollment_sha256'],
            'installation_sha256': proof['installation']['confirmation_sha256'],
            'receipt_sha256': installation['original_receipt_sha256'],
        })
    dispatch_raw, run_raw, intent_raw, members_raw = (wire(value) for value in (job, run, intent, members))
    record = {
        'schema': 'unknown_installed_provision_timeout_disposition_v1',
        'id': uid(900), 'job_id': job['id'], 'run_id': run['id'],
        'policy_id': case['policy_id'], 'policy_checksum': case['policy_checksum'],
        'generation': 44, 'fencing_token': 85,
        'lease_owner': intent['lease_owner'], 'executor_id': intent['lease_executor_id'],
        'preregistration_id': '096c3054-fe8d-4a8d-afc8-fdff2bc9f241',
        'create_grant_id': '8062bc1c-888f-46cf-ace7-11c7027aed1f',
        'original_dispatch_sha256': digest(dispatch_raw),
        'original_run_sha256': digest(run_raw),
        'original_intent_sha256': digest(intent_raw),
        'members_sha256': digest(members_raw),
        'original_deadline': job['lease_expires_at'],
        'original_intent_lease_expires_at': intent['lease_expires_at'],
        'original_returned_at': job['returned_at'],
        'recorded_at': '2026-11-11T13:00:00Z', 'members': members,
    }
    record_raw = wire(record)
    disposition = {
        'id': record['id'], 'job_id': record['job_id'], 'run_id': record['run_id'],
        'original_record': record, 'original_wire': bytea(record_raw),
        'original_dispatch_wire': bytea(dispatch_raw), 'original_run_wire': bytea(run_raw),
        'original_intent_wire': bytea(intent_raw), 'members_wire': bytea(members_raw),
        'recorded_at': record['recorded_at'],
    }
    current_job = copy.deepcopy(job)
    current_job.update(state='installed_timeout_disposed', updated_at='2026-11-11T13:00:00Z')
    ready_job = copy.deepcopy(job)
    ready_job.update(
        id=uid(910), run_id=uid(911), state='returned', return_status='succeeded',
        return_error='', finalization_error='', finalization_ack_at='2026-11-11T13:00:03Z',
        created_at='2026-11-11T13:00:01Z', started_at='2026-11-11T13:00:01Z',
        returned_at='2026-11-11T13:00:03Z', updated_at='2026-11-11T13:00:03Z')
    ready_env = json.loads(job['envelope'])
    ready_env.update(job_id=ready_job['id'], run_id=ready_job['run_id'],
                     source_tick=ready_job['created_at'])
    ready_env['metadata'] = {**ready_env['metadata'],
                             'capacity_dispatch_job_id': ready_job['id'],
                             'scheduled_for': ready_job['created_at']}
    for key in ('inputs', 'metadata'):
        ready_env[key + '_sha256'] = digest(
            json.dumps(ready_env[key], sort_keys=True, separators=(',', ':')).encode())
    ready_job['envelope'] = wire(ready_env).decode()
    ready_job['envelope_sha256'] = digest(ready_job['envelope'].encode())
    ready_job['lease_expires_at'] = '2026-11-11T13:05:01Z'
    ready_run = {
        'id': ready_job['run_id'], 'status': 'succeeded', 'error': '',
        'started_at': ready_job['started_at'], 'finished_at': ready_job['returned_at'],
    }
    current = copy.deepcopy(intent)
    current.update(
        phase='promoted', generation=44, fencing_token=86, lease_owner='',
        lease_executor_id='', lease_expires_at=None, retirement_forward=None,
        updated_at='2026-11-11T13:00:03Z')
    current['decision'].update(profile=members[0]['tuple']['profile'], reason='declared_saved_expansion')
    current['installed_guest_reconcile'] = {
        'installed_provision_timeout_disposition_id': record['id'],
        'original_job_id': job['id'], 'original_run_id': run['id'],
        'original_run_sha256': record['original_run_sha256'],
        'original_generation': 44, 'original_fence': 85,
        'new_fence': 86, 'new_run_id': ready_run['id'],
        'original_failure_preserved': True,
        'original_quiescence_or_no_effect_claimed': False,
    }
    current_slots = []
    for member in original['members']:
        row = copy.deepcopy(member)
        row.update(revision=1, updated_at='2026-11-11T13:00:03Z')
        row['slot_record'].update(observed_at='2026-11-11T13:00:03Z', receipt_ref='declared-original-observation')
        current_slots.append({'row': row, 'slot_record_wire': wire(row['slot_record']).decode()})
    saved = {
        'schema': 'recovered_installed_G44_originals_readonly_v1',
        'observed_at': '2026-11-11T13:00:04Z',
        'disposition': disposition, 'current_job': current_job,
        'current_run': copy.deepcopy(run), 'readiness_job': ready_job,
        'readiness_run': ready_run, 'current_intent_wire': wire(current).decode(),
        'member_grants': [copy.deepcopy(proof['grant']) for proof in original['proofs']],
        'current_slots': current_slots, 'predicate_valid': True,
    }
    saved_raw = wire(saved)
    saved_ref = {'path': '/declared-ci/saved-real-promotion.original.json', 'sha256': digest(saved_raw)}
    expected = {
        'schema': 'root_failed_A5_recovered_G44_originals_v1',
        'disposition_id': record['id'], 'disposition_sha256': digest(record_raw),
        **{key: record[key] for key in (
            'original_dispatch_sha256', 'original_run_sha256', 'original_intent_sha256', 'members_sha256')},
        'snapshot_ref': {'path': '/declared-ci/current-policy.original.json', 'sha256': 'f' * 64},
        'saved_recovery_original_ref': saved_ref,
    }
    value = copy.deepcopy(saved)
    value['same_epoch_lineage'] = {
        'schema': 'same_G44_ordinary_refresh_lineage_v1',
        'anchor_job_id': ready_job['id'], 'anchor_run_id': ready_run['id'],
        'anchor_created_at': ready_job['created_at'],
        'jobs_wire': wire([]).decode(), 'job_count': 0, 'job_ids': [],
        'runs_wire': wire([]).decode(), 'run_count': 0, 'run_ids': [],
        'vm_grant_changes_wire': wire([]).decode(), 'vm_grant_change_count': 0,
    }
    return {
        'saved': saved, 'value': value, 'expected': expected,
        'blobs': {saved_ref['path']: saved_raw},
        'originals': original,
    }


def read_original(operand):
    def read_ref(reference):
        raw = operand['blobs'][reference['path']]
        if digest(raw) != reference['sha256']:
            raise AssertionError('declared original SHA mismatch')
        return raw
    return read_ref


def policy_for(value):
    intent = json.loads(value['current_intent_wire'])
    slots = [{
        **{key: item['row'][key] for key in (
            'slot', 'resource_id', 'namespace', 'environment', 'domain', 'dimension')},
        'slot_record_sha256': digest(item['slot_record_wire'].encode()),
    } for item in value['current_slots']]
    identity = {
        'generation': intent['generation'], 'fence': intent['fencing_token'],
        'phase': intent['phase'], 'policy_id': intent['policy_id'],
        'policy_checksum': intent['policy_checksum'],
        'retirement_forward': intent.get('retirement_forward'),
        'intent_sha256': digest(value['current_intent_wire'].encode()),
    }
    return {'at': value['observed_at'], 'owned_slots': slots, 'intent_identity': [identity]}


def baseline_for(value):
    policy = policy_for(value)
    identity = policy['intent_identity'][0]
    baseline = {
        'clean_cycle_status': 'FAILED_CLEAN_CYCLE', 'recovery_only': True,
        'schema': 'root_operational_restore_all_current_members_baseline_v1',
        'reviewed_by_root': False, 'action': 'aws-restore-original-after-failed-a5-window98',
        'source': 'c' * 40, 'ops_source': 'd' * 40, 'database_schema': 98,
        'native_count': 8, 'useful_count': 8, 'marker_free': True,
        'ordinary_promoted_unleased_clear': True, 'current_epoch_useful_accepted': True,
        'native_resource_ids': sorted(slot['resource_id'] for slot in policy['owned_slots']),
        'policy_id': identity['policy_id'], 'policy_checksum': identity['policy_checksum'],
        'intent_sha256': identity['intent_sha256'],
        'owned_slot_roster_sha256': digest(wire(policy['owned_slots'])),
        'full_profile_native_ref': None, 'useful_refs': [],
        'coverage30_ref': None, 'demand300_ref': None,
        'second_member_first_useful_at': None, 'observed_at_pg': policy['at'],
    }
    assert len(baseline) == 24
    return baseline


def set_lineage(operand, jobs, runs, grants=None):
    line = operand['value']['same_epoch_lineage']
    grants = [] if grants is None else grants
    line.update(
        jobs_wire=wire(jobs).decode(), job_count=len(jobs),
        job_ids=[job['id'] for job in jobs],
        runs_wire=wire(runs).decode(), run_count=len(runs),
        run_ids=[run['id'] for run in runs],
        vm_grant_changes_wire=wire(grants).decode(),
        vm_grant_change_count=len(grants))


def readonly_refresh(operand):
    """A declared ordinary same-epoch refresh, with every original row retained."""
    operand = copy.deepcopy(operand)
    value = operand['value']
    intent = json.loads(value['current_intent_wire'])
    intent.pop('installed_guest_reconcile')
    intent['decision'].update(action='hold', units=8, reason='within_envelope')
    intent['updated_at'] = '2026-11-11T13:00:19Z'
    value['current_intent_wire'] = wire(intent).decode()
    value['observed_at'] = '2026-11-11T13:00:20Z'
    for item in value['current_slots']:
        item['row']['revision'] += 1
        item['row']['updated_at'] = '2026-11-11T13:00:18Z'
        item['row']['slot_record'].update(
            observed_at='2026-11-11T13:00:18Z',
            receipt_ref='declared-readonly-refresh-observation')
        item['slot_record_wire'] = wire(item['row']['slot_record']).decode()
    anchor = operand['saved']['readiness_job']
    job = copy.deepcopy(anchor)
    job.update(id=uid(920), run_id=uid(921),
               created_at='2026-11-11T13:00:10Z', started_at='2026-11-11T13:00:11Z',
               returned_at='2026-11-11T13:00:18Z', finalization_ack_at='2026-11-11T13:00:18Z',
               updated_at='2026-11-11T13:00:18Z', lease_expires_at='2026-11-11T13:05:11Z')
    envelope = json.loads(anchor['envelope'])
    envelope.update(job_id=job['id'], run_id=job['run_id'], source_tick=job['created_at'])
    envelope['metadata'].update(
        capacity_dispatch_job_id=job['id'], scheduled_for=job['created_at'])
    for key in ('inputs', 'metadata'):
        envelope[key + '_sha256'] = digest(
            json.dumps(envelope[key], sort_keys=True, separators=(',', ':')).encode())
    job['envelope'] = wire(envelope).decode()
    job['envelope_sha256'] = digest(job['envelope'].encode())
    ids = (
        'plan-original-guest', 'provision-original-notify', 'retire-original-guest',
        'refresh-original-membership', 'complete-original-provision',
        'finish-original-retirement', 'complete-original-retirement')
    operations = (
        'capacity.plan_original_guest', 'capacity.provision_original_guest',
        'capacity.retire_original_guest', 'capacity.complete_original_guest',
        'capacity.complete_original_guest', 'capacity.finish_original_guest_retirement',
        'capacity.complete_original_guest')
    steps = []
    for number, (identity, operation) in enumerate(zip(ids, operations)):
        active = number in (0, 3)
        steps.append({
            'id': identity, 'kind': 'yggdrasil', 'operation': operation,
            'capability': operation, 'status': 'succeeded' if active else 'skipped',
            'attempts': 1 if active else 0,
            'started_at': '2026-11-11T13:00:12Z',
            'finished_at': '2026-11-11T13:00:12Z', 'metadata': {},
        })
    steps[0]['metadata'] = {
        'mode': 'refresh', 'reason': intent['decision']['reason'], 'slot': 0,
        'generation': 44, 'fencing_token': 86, 'lease_owner': '',
        'preregistration_id': '',
    }
    steps[3]['metadata'] = {'mode': 'refresh', 'members': 8, 'provider_mutations': False}
    run = {
        'id': job['run_id'], 'status': 'succeeded', 'error': '',
        'created_at': job['created_at'], 'updated_at': job['returned_at'],
        'started_at': job['started_at'], 'finished_at': '2026-11-11T13:00:17Z',
        'workflow_id': envelope['workflow']['id'],
        'workflow_namespace': envelope['workflow']['namespace'],
        'workflow_name': envelope['workflow']['name'],
        'workflow_version': envelope['workflow']['version'],
        'metadata': copy.deepcopy(envelope['metadata']),
        'inputs': copy.deepcopy(envelope['inputs']),
        'result': {
            'status': 'succeeded',
            'workflow': {'kind': 'workflow', **{
                key: envelope['workflow'][key] for key in ('id', 'namespace', 'name', 'version')}},
            'metadata': copy.deepcopy(envelope['metadata']), 'steps': steps,
        },
    }
    set_lineage(operand, [job], [run])
    return operand


def change_current(operand, change):
    current = json.loads(operand['value']['current_intent_wire'])
    change(current)
    operand['value']['current_intent_wire'] = wire(current).decode()


def change_saved(operand, change):
    """Reseal a DECLARED negative input; no actual saved original is rewritten."""
    reference = operand['expected']['saved_recovery_original_ref']
    saved = json.loads(operand['blobs'][reference['path']])
    change(saved)
    raw = wire(saved)
    reference['sha256'] = digest(raw)
    operand['blobs'][reference['path']] = raw


class Restore98SameEpochLineageTests(unittest.TestCase):
    def evaluate(self, operand):
        return R.recovered_current(
            operand['value'], operand['expected'], policy_for(operand['value']),
            read_original(operand))

    def refused(self, operand):
        with self.assertRaises(R.Hold):
            self.evaluate(operand)

    def test_full_saved_marker_original_is_preserved(self):
        operand = declared_restoration()
        before = copy.deepcopy(operand)
        strict = R.saved_recovery(operand['expected'], read_original(operand))
        current = self.evaluate(operand)
        self.assertEqual(strict['member_count'], 8)
        self.assertTrue(strict['historical_run_failed'])
        self.assertIsNone(strict['historical_finalization_ack_at'])
        self.assertEqual(current['current_generation'], 44)
        self.assertEqual(current['current_fence'], 86)
        self.assertFalse(current['current_marker_absent'])
        self.assertEqual(current['intervening_readonly_jobs'], 0)
        self.assertEqual(operand, before)
        baseline = baseline_for(operand['value'])
        self.assertEqual(R.from_baseline_current(
            operand['value'], operand['expected'], baseline, read_original(operand)), current)
        sql = R.recovery_sql(operand['expected'], read_original(operand))
        self.assertIn("'" + operand['saved']['readiness_run']['id'] + "'::uuid", sql)
        self.assertIn('line_jobs AS MATERIALIZED', sql)
        self.assertIn('line_runs AS MATERIALIZED', sql)
        self.assertIn('grant_changes AS MATERIALIZED', sql)
        self.assertNotRegex(sql.upper(), r'\b(?:INSERT|UPDATE|DELETE|ALTER|DROP|CREATE|TRUNCATE|CALL|DO)\b')

    def test_marker_removed_same44_same_fence_with_readonly_refresh_ack(self):
        operand = readonly_refresh(declared_restoration())
        original = copy.deepcopy(operand)
        result = self.evaluate(operand)
        self.assertTrue(result['current_marker_absent'])
        self.assertEqual(result['intervening_readonly_jobs'], 1)
        self.assertEqual(result['readiness_run_id'], operand['saved']['readiness_run']['id'])
        self.assertEqual((result['current_generation'], result['current_fence']), (44, 86))
        self.assertEqual(result['member_count'], 8)
        line = operand['value']['same_epoch_lineage']
        run = json.loads(line['runs_wire'])[0]
        envelope = json.loads(json.loads(line['jobs_wire'])[0]['envelope'])
        self.assertEqual(set(run['result']['workflow']), {'kind', 'id', 'namespace', 'name', 'version'})
        self.assertEqual(set(envelope['workflow']), {'id', 'namespace', 'name', 'version', 'checksum'})
        baseline = baseline_for(operand['value'])
        self.assertEqual(R.from_baseline_current(
            operand['value'], operand['expected'], baseline, read_original(operand)), result)
        self.assertEqual(operand, original)
        self.assertEqual(operand['value']['member_grants'], operand['saved']['member_grants'])
        self.assertEqual(operand['value']['current_run'], operand['saved']['current_run'])
        self.assertEqual(operand['value']['disposition'], operand['saved']['disposition'])
        self.assertNotIn('installed_guest_reconcile', json.loads(
            operand['value']['current_intent_wire']))

    def test_missing_or_failed_ack_never_becomes_success(self):
        for field, value in (
                ('finalization_ack_at', None), ('state', 'unknown'),
                ('return_status', 'failed'), ('return_error', 'declared original failure'),
                ('finalization_error', 'declared ACK failure')):
            with self.subTest(saved_readiness_field=field):
                operand = declared_restoration()
                change_saved(operand, lambda saved: saved['readiness_job'].__setitem__(field, value))
                self.refused(operand)
        for field, value in (
                ('finalization_ack_at', None),
                ('finalization_ack_at', '2026-11-11T13:05:12Z'),
                ('state', 'unknown'), ('return_status', 'failed'),
                ('return_error', 'declared failed return'),
                ('finalization_error', 'declared failed ACK')):
            with self.subTest(intervening_field=field):
                operand = readonly_refresh(declared_restoration())
                line = operand['value']['same_epoch_lineage']
                jobs, runs = json.loads(line['jobs_wire']), json.loads(line['runs_wire'])
                jobs[0][field] = value
                set_lineage(operand, jobs, runs)
                self.refused(operand)
        operand = readonly_refresh(declared_restoration())
        line = operand['value']['same_epoch_lineage']
        jobs, runs = json.loads(line['jobs_wire']), json.loads(line['runs_wire'])
        runs[0]['status'] = 'failed'
        set_lineage(operand, jobs, runs)
        self.refused(operand)

    def test_foreign_epoch_policy_profile_or_physical_tuple_refused(self):
        vectors = (
            ('generation', 45), ('generation', True), ('fencing_token', 87),
            ('policy_id', uid(999)), ('policy_checksum', 'e' * 64),
            ('phase', 'preparing'), ('lease_owner', uid(998)),
            ('lease_executor_id', uid(997)), ('recovery_only', True),
            ('retirement_forward', {'schema': 'declared-foreign-forward'}),
        )
        for field, value in vectors:
            with self.subTest(field=field):
                operand = readonly_refresh(declared_restoration())
                change_current(operand, lambda current: current.__setitem__(field, value))
                self.refused(operand)
        operand = readonly_refresh(declared_restoration())
        change_current(operand, lambda current: current['decision'].__setitem__('profile', 'foreign'))
        self.refused(operand)
        for field, value in (
                ('resource_id', 'i-declared-foreign'), ('integration_instance_id', uid(996)),
                ('scope_checksum', 'd' * 64), ('profile_name', 'foreign')):
            with self.subTest(physical_field=field):
                operand = readonly_refresh(declared_restoration())
                item = operand['value']['current_slots'][0]
                item['row'][field] = value
                if field == 'resource_id':
                    item['row']['slot_record']['resource_id'] = value
                    item['slot_record_wire'] = wire(item['row']['slot_record']).decode()
                self.refused(operand)
        operand = readonly_refresh(declared_restoration())
        operand['value']['member_grants'][0]['grant_record']['settlement']['resource_id'] = 'foreign'
        self.refused(operand)

    def test_provision_delete_and_missing_extra_lineage_refused(self):
        for active_step in (1, 2, 4, 5, 6):
            with self.subTest(forbidden_active_step=active_step):
                operand = readonly_refresh(declared_restoration())
                line = operand['value']['same_epoch_lineage']
                jobs, runs = json.loads(line['jobs_wire']), json.loads(line['runs_wire'])
                step = runs[0]['result']['steps'][active_step]
                step.update(status='succeeded', attempts=1)
                set_lineage(operand, jobs, runs)
                self.refused(operand)
        for mutation in ('missing_step', 'extra_step', 'provider_mutations',
                         'wrong_kind', 'wrong_operation', 'wrong_capability'):
            with self.subTest(step_mutation=mutation):
                operand = readonly_refresh(declared_restoration())
                line = operand['value']['same_epoch_lineage']
                jobs, runs = json.loads(line['jobs_wire']), json.loads(line['runs_wire'])
                steps = runs[0]['result']['steps']
                if mutation == 'missing_step':
                    steps.pop()
                elif mutation == 'extra_step':
                    steps.append(copy.deepcopy(steps[-1]))
                elif mutation == 'provider_mutations':
                    steps[3]['metadata']['provider_mutations'] = True
                elif mutation == 'wrong_kind':
                    steps[0]['kind'] = 'core'
                elif mutation == 'wrong_operation':
                    steps[3]['operation'] = 'capacity.provision_original_guest'
                else:
                    steps[3]['capability'] = 'destroy_vm'
                set_lineage(operand, jobs, runs)
                self.refused(operand)
        for mutation in ('missing_frame', 'missing_jobs', 'missing_run', 'extra_run',
                         'duplicate_job', 'wrong_count', 'extra_vm_grant'):
            with self.subTest(lineage_mutation=mutation):
                operand = readonly_refresh(declared_restoration())
                line = operand['value']['same_epoch_lineage']
                jobs, runs = json.loads(line['jobs_wire']), json.loads(line['runs_wire'])
                if mutation == 'missing_frame':
                    del operand['value']['same_epoch_lineage']
                elif mutation == 'missing_jobs':
                    set_lineage(operand, [], [])
                elif mutation == 'missing_run':
                    set_lineage(operand, jobs, [])
                elif mutation == 'extra_run':
                    extra = copy.deepcopy(runs[0]); extra['id'] = uid(995)
                    set_lineage(operand, jobs, [*runs, extra])
                elif mutation == 'duplicate_job':
                    set_lineage(operand, [*jobs, copy.deepcopy(jobs[0])], runs)
                elif mutation == 'wrong_count':
                    line['job_count'] += 1
                else:
                    set_lineage(operand, jobs, runs, [copy.deepcopy(
                        operand['value']['member_grants'][0])])
                self.refused(operand)
