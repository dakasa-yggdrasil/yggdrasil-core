"""INERT artifact/SQL composition for the failed-A5 policy restoration only.

No main, connection, query execution, provider operation, acknowledgment, claim,
or acceptance is implemented here. The caller supplies its existing bounded
reader and qualified catalog definitions. An old UNKNOWN is never a success.
"""
import base64, copy, datetime, hashlib, json, re, types
from pathlib import Path

SOURCE_BOUND = False
QUALIFIED_SOURCE = None
HISTORICAL_A5_SOURCE = '0764e6b267d3d6ddbfb4d7a4b9fb4024018bf89f'
HISTORICAL_A5_OPS = 'b6a1d90e0c6e61b01c12c8fb7504afeec9de4f94'
HISTORICAL_A5_IMAGE = '9b6e2a5d06eed90b7b44d059d3f78a405a21430a7b104f17498c904f499bdd97'
ROOT97_SHA = '896eb09327ecdabb823957c37266774e94ab72b3afd2875a1775d30536e754c9'
CORE8_ROOT9_SHA = 'cc63c80fc443bdc4975d49314eaa3257cf35a71844f5410ffee27c503d76c749'
G44_JOB = '37edd909-fd96-46cc-bdc7-710a2573f5bf'
G44_RUN = 'ef7dfb2d-c681-4574-a463-4d4a1c30e126'
G44_PRE = '096c3054-fe8d-4a8d-afc8-fdff2bc9f241'
G44_GRANT = '8062bc1c-888f-46cf-ace7-11c7027aed1f'
G44_POLICY = 'e13fb194-e0d8-4673-88bc-0613f9feccce'
G44_POLICY_SHA = '064ab82be57e49b5fc09bce751876545d279df23828279ae16bbe7881fa071fe'
PROTECTED_S1 = 'i-070b5767a35c7f0d5'

class Hold(RuntimeError): pass

def need(value, guard):
    if not value: raise Hold(guard)

def sha(raw): return hashlib.sha256(raw).hexdigest()

def wire(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)+'\n').encode()

def loads(raw):
    def unique(rows):
        value = {}
        for key, item in rows:
            need(key not in value, 'NO_DUPLICATE98_RECOVERY_KEY')
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(Hold('FINITE98_RECOVERY_JSON')))

def closed(value, fields, guard):
    need(type(value) is dict and set(value) == set(fields.split()), guard)

def digest(value):
    return type(value) is str and re.fullmatch('[a-f0-9]{64}', value) is not None and value != '0'*64

def stamp(value):
    need(type(value) is str and re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?(?:Z|[+-]\d\d:\d\d)', value), 'ORIGINAL98_TIMESTAMP')
    value = re.sub(r'\.(\d{1,9})(?=Z$|[+-]\d\d:\d\d$)', lambda m:'.'+(m[1]+'000000')[:6], value)
    return datetime.datetime.fromisoformat(value.replace('Z', '+00:00'))

def pg_bytes(value):
    need(type(value) is str and re.fullmatch(r'\\x(?:[a-f0-9]{2})*', value) is not None,
         'EXACT_POSTGRES_BYTEA_HEX_NOT_BASE64_ALIAS')
    raw = bytes.fromhex(value[2:])
    need(0 < len(raw) <= 1 << 20, 'WHOLE98_SAVED_WIRE_WITHIN_EXISTING_1M')
    return raw

def checked_ref(value, read_ref):
    closed(value, 'path sha256', 'CLOSED98_RESTORE_REF')
    need(type(value['path']) is str and Path(value['path']).is_absolute()
         and '..' not in Path(value['path']).parts and digest(value['sha256']), 'ABSOLUTE98_RESTORE_REF')
    raw = read_ref(value)
    need(type(raw) is bytes and sha(raw) == value['sha256'], 'WHOLE98_RESTORE_REFERENCE')
    return raw

def definitions(context, read_ref):
    """Use the separately qualified current98 definitions, never the PRE-CAS case."""
    closed(context, 'goose98_acceptance catalog98_ref history98_ref original_refs_local deparse_carrier_ref migration98_ref helper_source_ref source_ci_ref historical_root97_ref legacy_catalog_sql_ref', 'CLOSED10_RESTORE_SCHEMA98_CONTEXT')
    source_raw = checked_ref(context['helper_source_ref'], read_ref)
    module = types.ModuleType('reviewed_restore_catalog98_definitions')
    module.__file__ = context['helper_source_ref']['path']
    exec(compile(source_raw, module.__file__, 'exec'), module.__dict__)
    need(module.SOURCE_BOUND is False and module.QUALIFIED_SOURCE is None,
         'PURE98_DEFINITIONS_WITHOUT_AN_EFFECT_ENTRY_POINT')
    return module

def artifacts(context, read_ref, historical97, current_source, current_image, ops_source):
    h = definitions(context, read_ref)
    raw97 = checked_ref(context['historical_root97_ref'], read_ref)
    need(sha(raw97) == ROOT97_SHA and loads(raw97) == historical97['receipt'], 'ROOT97_896_IMMUTABLE_NOT_CURRENT98')
    raw98 = checked_ref(context['goose98_acceptance'], read_ref)
    root = loads(raw98)
    mapping = loads(checked_ref(context['original_refs_local'], read_ref))
    roles = 'migration_result before_catalog after_catalog source_ci qualified_image'.split()
    closed(root['original_refs'], ' '.join(roles), 'ROOT98_FIVE_ORIGINAL_ROLES')
    closed(mapping, ' '.join(roles), 'ROOT98_SEPARATE_FIVE_ROLE_CUSTODY')
    def original(reference):
        matches = [v for v in mapping.values() if type(v) is dict and v.get('original_ref') == reference]
        need(len(matches) == 1, 'ONE98_ORIGINAL_TO_LOCAL_CUSTODY')
        entry = matches[0]
        closed(entry, 'original_ref local_ref bytes', 'ROOT98_EXACT_CUSTODY_ENTRY')
        need(entry['original_ref']['path'] != entry['local_ref']['path']
             and entry['original_ref']['sha256'] == entry['local_ref']['sha256']
             and type(entry['bytes']) is int and entry['bytes'] > 1, 'ROOT98_NO_NATIVE_LOCAL_PATH_ALIAS')
        raw = checked_ref(entry['local_ref'], read_ref)
        need(len(raw) == entry['bytes'], 'ROOT98_COMPLETE_LOCAL_COPY_BYTES')
        return raw
    before = loads(original(root['original_refs']['before_catalog']))
    after = loads(original(root['original_refs']['after_catalog']))
    prior = h.projection97_98(before)
    need(prior == historical97['catalog97'], 'ROOT98_BEFORE_IS_WHOLE_AUTHENTICATED97_PROJECTION')
    sql = checked_ref(context['migration98_ref'], read_ref).decode()
    carrier = loads(checked_ref(context['deparse_carrier_ref'], read_ref))
    defs = h.constraint98_definitions(prior, carrier, lambda r: checked_ref(r, read_ref), current_source, sql)
    h.catalog98_delta(prior, before, after, h.migration98_functions(sql), defs)
    projection_raw = checked_ref(context['catalog98_ref'], read_ref)
    projection = h.catalog98_projection(after)
    need(loads(projection_raw) == projection, 'ROOT98_WHOLE_CATALOG8_NOT_RELABELED97')
    history_raw = checked_ref(context['history98_ref'], read_ref)
    need(history_raw == after['legacy']['complete_history_wire'].encode(), 'ROOT98_ORIGINAL98_HISTORY_WIRE')
    need(context['source_ci_ref']['sha256'] == root['original_refs']['source_ci']['sha256']
         and checked_ref(context['source_ci_ref'], read_ref) == original(root['original_refs']['source_ci']), 'ROOT98_SOURCE_CI_WHOLE_SAME_HASH_CUSTODY')
    h.root98_overlay(raw98, raw97, {
        'current_ops_source': ops_source, 'business_source': current_source, 'amd64_D': current_image,
        'complete_history_sha256': sha(history_raw), 'prior97_history_sha256': sha(before['legacy']['complete_history_wire'].encode()),
        'catalog98_sha256': sha(projection_raw), 'index92_definition_sha256': sha(projection['index92_definition'].encode()),
        'catalog90_91_sha256': sha(wire({k: projection[k] for k in ('catalog90', 'catalog91')}))}, original)
    return {'helper': h, 'receipt': root, 'before': before, 'after': after, 'projection': projection,
            'history': history_raw.decode(), 'definitions': defs, 'context': context}

def current(policy, bundle, live_catalog):
    facts, root, h = policy['schema_facts'], bundle['receipt'], bundle['helper']
    need(facts['database'] == 'yggdrasil' and facts['readonly'] == 'on'
         and type(facts['history_max_version']) is int and facts['history_max_version'] == 98
         and facts['latest_versions'] == [0]+[x for x in range(1, 99) if x != 40]
         and all(type(facts[k]) is int and facts[k] == 1 for k in ('rows90', 'rows91', 'rows92'))
         and policy['index89_valid'] is True and policy['index92_valid'] is True, 'CURRENT98_REAL_READONLY_HEAD_AND_INDEXES')
    need(type(facts['complete_history_wire']) is str and facts['complete_history_wire'] == bundle['history']
         and sha(facts['complete_history_wire'].encode()) == root['complete_history_sha256']
         and {k: facts[k] for k in ('catalog90', 'catalog91')} == {k: bundle['projection'][k] for k in ('catalog90', 'catalog91')}
         and sha(policy['index92_definition'].encode()) == root['index92_definition_sha256'], 'CURRENT98_FULL_HISTORY_AND_CATALOG')
    need(h.catalog98_projection(live_catalog) == bundle['projection']
         and live_catalog['legacy']['complete_history_wire'] == bundle['history'], 'CURRENT98_FRESH_FULL_CATALOG_MATCHES_ROOT98')
    h.structural98(live_catalog['structural98'], bundle['definitions'])
    need(all(type(facts[k]) is int and facts[k] == 0 and live_catalog['legacy'][k] == 0
             for k in ('other_migrators_ddl', 'other_cic', 'ddl_locks')), 'UNCHANGED_NO_OTHER_DDL_GUARD')
    return {'database_schema':98, 'complete_history_sha256':root['complete_history_sha256'], 'schema98_catalog_sha256':root['catalog98_sha256']}

RECOVERED_G44_SQL = r"""WITH d AS MATERIALIZED (
 SELECT * FROM public.capacity_dispatch_installed_provision_timeout_dispositions
 WHERE job_id='37edd909-fd96-46cc-bdc7-710a2573f5bf'::uuid
 AND run_id='ef7dfb2d-c681-4574-a463-4d4a1c30e126'::uuid
), j AS MATERIALIZED (SELECT j.* FROM public.capacity_dispatch_jobs j JOIN d ON d.job_id=j.id),
w AS MATERIALIZED (SELECT w.* FROM public.workflow_runs w JOIN d ON d.run_id=w.id),
i AS MATERIALIZED (SELECT i.intent FROM public.capacity_intents i JOIN j ON
 (i.namespace,i.environment,i.domain,i.dimension)=(j.realm,j.environment,j.domain,j.dimension)),
ready_run AS MATERIALIZED (SELECT w.* FROM public.workflow_runs w,i
 WHERE w.id=(i.intent#>>'{installed_guest_reconcile,new_run_id}')::uuid),
ready_job AS MATERIALIZED (SELECT j.* FROM public.capacity_dispatch_jobs j JOIN ready_run w ON j.run_id=w.id),
g AS MATERIALIZED (SELECT (m->>'slot')::integer AS ordinal,to_jsonb(g) AS value FROM d
 CROSS JOIN LATERAL jsonb_array_elements(d.original_record->'members') m
 JOIN public.capacity_mutation_grants g ON g.id=(m->>'create_grant_id')::uuid)
SELECT jsonb_build_object('schema','recovered_installed_G44_originals_readonly_v1',
 'observed_at',clock_timestamp(),'disposition',(SELECT to_jsonb(d) FROM d),
 'current_job',(SELECT to_jsonb(j) FROM j),'current_run',(SELECT to_jsonb(w) FROM w),
 'readiness_job',(SELECT to_jsonb(j) FROM ready_job j),'readiness_run',(SELECT to_jsonb(w) FROM ready_run w),
 'current_intent_wire',(SELECT intent::text FROM i),'member_grants',(SELECT coalesce(jsonb_agg(value ORDER BY ordinal),'[]'::jsonb) FROM g),
 'current_slots',(SELECT coalesce(jsonb_agg(jsonb_build_object('row',to_jsonb(s),'slot_record_wire',s.slot_record::text) ORDER BY s.slot),'[]'::jsonb)
 FROM public.capacity_resource_slots s,j WHERE (s.namespace,s.environment,s.domain,s.dimension)=(j.realm,j.environment,j.domain,j.dimension)
 AND s.resource_id<>'' AND s.slot_record->'tombstone'='false'::jsonb),
 'predicate_valid',(SELECT public.installed_provision_timeout_valid(original_record,original_dispatch_wire,original_run_wire,original_intent_wire,members_wire) FROM d))"""

def recovered(value, expected, policy):
    closed(expected, 'schema disposition_id disposition_sha256 original_dispatch_sha256 original_run_sha256 original_intent_sha256 members_sha256 snapshot_ref saved_recovery_original_ref', 'CLOSED9_EXACT_INSTALLED_TIMEOUT_RECOVERY')
    need(expected['schema'] == 'root_failed_A5_recovered_G44_originals_v1'
         and all(digest(expected[k]) for k in ('disposition_sha256','original_dispatch_sha256','original_run_sha256','original_intent_sha256','members_sha256')),
         'EXPLICIT_TYPED_G44_RECOVERY_NOT_A_FAILED_FILTER')
    closed(value, 'schema observed_at disposition current_job current_run readiness_job readiness_run current_intent_wire member_grants current_slots predicate_valid', 'WHOLE11_RECOVERED_G44_SNAPSHOT')
    need(value['schema'] == 'recovered_installed_G44_originals_readonly_v1' and value['predicate_valid'] is True,
         'QUALIFIED98_PURE_DB_PROOF_REQUIRED')
    stamp(value['observed_at'])
    d = value['disposition']
    closed(d, 'id job_id run_id original_record original_wire original_dispatch_wire original_run_wire original_intent_wire members_wire recorded_at', 'EXACT10_IMMUTABLE_M98_LEDGER_ROW')
    raw, dr, wr, ir, mr = (pg_bytes(d[k]) for k in ('original_wire','original_dispatch_wire','original_run_wire','original_intent_wire','members_wire'))
    r, oldjob, oldrun, oldintent, members = (loads(b) for b in (raw, dr, wr, ir, mr))
    closed(r, 'schema id job_id run_id policy_id policy_checksum generation fencing_token lease_owner executor_id preregistration_id create_grant_id original_dispatch_sha256 original_run_sha256 original_intent_sha256 members_sha256 original_deadline original_intent_lease_expires_at original_returned_at recorded_at members', 'CLOSED21_M98_DISPOSITION_ORIGINAL')
    need(sha(raw) == expected['disposition_sha256'] and r == d['original_record']
         and r['schema'] == 'unknown_installed_provision_timeout_disposition_v1'
         and r['id'] == d['id'] == expected['disposition_id']
         and r['job_id'] == d['job_id'] == oldjob['id'] == G44_JOB
         and r['run_id'] == d['run_id'] == oldrun['id'] == oldjob['run_id'] == G44_RUN
         and r['policy_id'] == G44_POLICY and r['policy_checksum'] == G44_POLICY_SHA
         and type(r['generation']) is int and r['generation'] == 44
         and type(r['fencing_token']) is int and r['fencing_token'] == 85
         and r['preregistration_id'] == G44_PRE and r['create_grant_id'] == G44_GRANT, 'EXACT_OLD_G44_JOB_RUN_POLICY_AND_INSTALLED_S8')
    for key, b in (('original_dispatch_sha256',dr),('original_run_sha256',wr),('original_intent_sha256',ir),('members_sha256',mr)):
        need(sha(b) == r[key] == expected[key], 'FULL_ORIGINAL_M98_FIVE_WIRE_DIGEST_DOMAIN_'+key)
    need(oldjob['state'] == 'unknown' and oldjob['finalization_ack_at'] is None
         and oldrun['status'] == 'failed' and oldrun['finished_at'] is not None
         and value['current_run'] == oldrun, 'HISTORICAL_UNKNOWN_FAILED_NO_ACK_WHOLE_RUN_RETAINED')
    current_job = copy.deepcopy(value['current_job']); original_job = copy.deepcopy(oldjob)
    need(current_job['state'] == 'installed_timeout_disposed' and current_job['finalization_ack_at'] is None,
         'DISTINCT_TYPED_TERMINAL_NOT_ACK_OR_SUCCESS')
    for row in (current_job, original_job): row.pop('state'); row.pop('updated_at')
    need(current_job == original_job, 'ALL_OTHER_HISTORICAL_JOB_FIELDS_IMMUTABLE')
    need(type(members) is list and len(members) == 8 and members == r['members']
         and [m['slot'] for m in members] == list(range(1,9))
         and len({m['create_grant_id'] for m in members}) == 8
         and type(value['member_grants']) is list and len(value['member_grants']) == 8, 'FULL_EIGHT_INSTALLED_MEMBERS_NO_FIELD_DROP')
    slots = policy['owned_slots']
    need(type(slots) is list and [s['slot'] for s in slots] == list(range(1,9))
         and slots[0]['resource_id'] == PROTECTED_S1 and type(value['current_slots']) is list
         and len(value['current_slots']) == 8, 'ALL8_CURRENT_PHYSICAL_ROSTER_AND_ORIGINAL_S1')
    for member, grant, slot, physical in zip(members, value['member_grants'], slots, value['current_slots']):
        closed(physical, 'row slot_record_wire', 'WHOLE_CURRENT_SLOT_AND_PG_WIRE')
        row, slot_wire = physical['row'], physical['slot_record_wire']
        need(type(slot_wire) is str and loads(slot_wire) == row['slot_record']
             and sha(slot_wire.encode()) == slot['slot_record_sha256']
             and all(row[k] == slot[k] for k in ('slot','resource_id','namespace','environment','domain','dimension')),
             'WHOLE_CURRENT_SLOT_RECORD_EXACT_E70_DIGEST_DOMAIN')
        closed(member, 'slot preregistration_id create_grant_id tuple request_sha256 preregistration_sha256 witness_sha256 enrollment_sha256 installation_sha256 receipt_sha256', 'EXACT10_IMMUTABLE_MEMBER')
        tup = member['tuple']; closed(tup, 'provider integration_instance_id instance_checksum integration_type_id type_checksum scope_checksum profile_checksum profile slot resource_id resource_created_at', 'EXACT11_PHYSICAL_TUPLE')
        need(type(member['slot']) is int and member['slot'] == tup['slot'] == slot['slot']
             and tup['provider'] == 'aws' and tup['resource_id'] == slot['resource_id']
             and tup['resource_created_at'] == row['slot_record']['resource_created_at']
             and tup['integration_instance_id'] == row['integration_instance_id']
             and tup['scope_checksum'] == row['scope_checksum'] and tup['profile'] == row['profile_name']
             and grant['id'] == member['create_grant_id'] and grant['state'] == 'confirmed'
             and 'authority_kind' not in grant['grant_record'], 'SAME_EIGHT_CONFIRMED_ORIGINAL_CREATE_AND_PHYSICAL_IDENTITIES')
        g = grant['grant_record']; settlement = g['settlement']
        need(g['grant']['grant_id'] == grant['id'] and g['grant']['state'] == 'confirmed'
             and g['grant']['request_sha256'] == member['request_sha256']
             and settlement['outcome'] == 'accepted' and settlement['transport_completed'] is True
             and settlement['resource_id'] == tup['resource_id'] and settlement['resource_created_at'] == tup['resource_created_at'],
             'ALL8_WHOLE_PAID_SDK_SETTLEMENT_RECORDS_AUTHENTICATED_BY_M98')
    need(type(value['current_intent_wire']) is str, 'WHOLE_CURRENT_PG_INTENT_WIRE')
    current = loads(value['current_intent_wire'])
    marker = current.get('installed_guest_reconcile')
    need(type(marker) is dict and marker.get('installed_provision_timeout_disposition_id') == d['id']
         and marker['original_job_id'] == G44_JOB and marker['original_run_id'] == G44_RUN
         and marker['original_run_sha256'] == r['original_run_sha256']
         and marker['original_generation'] == 44 and marker['original_fence'] == 85
         and marker['original_failure_preserved'] is True and marker['original_quiescence_or_no_effect_claimed'] is False
         and current['phase'] == 'promoted' and current.get('lease_owner','') == ''
         and current.get('lease_executor_id','') == '' and current.get('lease_expires_at') is None
         and type(current['generation']) is int and current['generation'] == 44
         and type(current['fencing_token']) is int and current['fencing_token'] == marker['new_fence'] > 85,
         'REAL_TYPED_FRESH_READINESS_PROMOTED_NOT_ORIGINAL_UNKNOWN_OR_PRECAS_CASE')
    need(len(policy['intent_identity']) == 1
         and policy['intent_identity'][0]['intent_sha256'] == sha(value['current_intent_wire'].encode()),
         'EXACT_ORIGINAL_PG_INTENT_DIGEST_NO_JSON_RECODE')
    identity = policy['intent_identity'][0]
    need(identity['generation'] == current['generation'] and identity['fence'] == current['fencing_token']
         and identity['phase'] == 'promoted' and identity['retirement_forward'] is None
         and current['policy_id'] == identity['policy_id'] == G44_POLICY
         and current['policy_checksum'] == identity['policy_checksum'] == G44_POLICY_SHA,
         'SAME_CURRENT_POLICY_READINESS_EPOCH_AS_FRESH_E70')
    ready_job, ready_run = value['readiness_job'], value['readiness_run']
    need(type(ready_job) is dict and type(ready_run) is dict
         and ready_run['id'] == ready_job['run_id'] == marker['new_run_id'] != G44_RUN
         and ready_job['id'] != G44_JOB and ready_job['state'] == 'returned'
         and ready_job['return_status'] == ready_run['status'] == 'succeeded'
         and ready_job['returned_at'] is not None and ready_job['finalization_ack_at'] is not None
         and ready_run['finished_at'] is not None
         and all(ready_job[k] == oldjob[k] for k in ('realm','environment','domain','dimension')),
         'GENUINE_DISTINCT_CURRENT_READINESS_SUCCEEDED_AND_ACKED_NOT_OLD_FAILURE_RELABELED')
    need(abs((stamp(policy['at'])-stamp(value['observed_at'])).total_seconds()) <= 15,
         'SAME_FRESH15_POLICY_AND_TYPED_READINESS_ORIGINAL_NOT_RETIMED')
    return {'schema':'verified_recovered_G44_readiness_join_v1','job_id':G44_JOB,'run_id':G44_RUN,
            'disposition_id': d['id'], 'disposition_sha256': sha(raw), 'historical_run_failed': True,
            'historical_finalization_ack_at': None, 'current_generation': current['generation'],
            'current_fence': current['fencing_token'], 'current_phase': 'promoted', 'member_count': 8,
            'readiness_run_id':ready_run['id']}

def from_baseline(value, expected, baseline):
    """Project E70 identity from whole saved proof; never replace an original."""
    current = loads(value['current_intent_wire'])
    slots = []
    for item in value['current_slots']:
        row = item['row']
        slots.append({**{k:row[k] for k in ('slot','resource_id','namespace','environment','domain','dimension')},
                      'slot_record_sha256':sha(item['slot_record_wire'].encode())})
    need(sha(wire(slots)) == baseline['owned_slot_roster_sha256']
         and sorted(x['resource_id'] for x in slots) == baseline['native_resource_ids']
         and sha(value['current_intent_wire'].encode()) == baseline['intent_sha256']
         and baseline['policy_id'] == current['policy_id']
         and baseline['policy_checksum'] == current['policy_checksum'], 'EXACT_BASELINE_E70_AND_WHOLE_TYPED_SNAPSHOT_JOIN')
    identity = {'generation':current['generation'],'fence':current['fencing_token'],
                'phase':current['phase'],'policy_id':current['policy_id'],'policy_checksum':current['policy_checksum'],
                'retirement_forward':current.get('retirement_forward'),
                'intent_sha256':sha(value['current_intent_wire'].encode())}
    return recovered(value, expected, {'at':baseline['observed_at_pg'], 'owned_slots':slots, 'intent_identity':[identity]})

def saved_recovery(expected, read_ref):
    """The separately retained real promotion original is never inferred later."""
    value=loads(checked_ref(expected['saved_recovery_original_ref'],read_ref))
    need(type(value)is dict and value.get('schema')=='recovered_installed_G44_originals_readonly_v1',
         'WHOLE_SEPARATE_REAL_PROMOTION_ORIGINAL_REQUIRED')
    current=loads(value['current_intent_wire'])
    slots=[{**{k:item['row'][k]for k in('slot','resource_id','namespace','environment','domain','dimension')},
            'slot_record_sha256':sha(item['slot_record_wire'].encode())}for item in value['current_slots']]
    baseline={'owned_slot_roster_sha256':sha(wire(slots)), 'native_resource_ids':sorted(s['resource_id']for s in slots),
              'intent_sha256':sha(value['current_intent_wire'].encode()),'policy_id':current['policy_id'],
              'policy_checksum':current['policy_checksum'],'observed_at_pg':value['observed_at']}
    return from_baseline(value,expected,baseline)

G44_TERMINAL_UNION = r"""
 UNION
 SELECT j.id FROM dispatch_candidates j JOIN dispatch_original_identity ji ON ji.id=j.id
 JOIN public.capacity_dispatch_installed_provision_timeout_dispositions d ON (d.job_id,d.run_id)=(j.id,j.run_id)
 JOIN public.workflow_runs w ON w.id=d.run_id
 WHERE j.id='37edd909-fd96-46cc-bdc7-710a2573f5bf'::uuid
 AND j.run_id='ef7dfb2d-c681-4574-a463-4d4a1c30e126'::uuid
 AND j.state='installed_timeout_disposed' AND j.finalization_ack_at IS NULL
 AND w.status='failed' AND w.finished_at IS NOT NULL
 AND d.original_record=convert_from(d.original_wire,'UTF8')::jsonb
 AND d.original_record->>'schema'='unknown_installed_provision_timeout_disposition_v1'
 AND d.original_record->'generation'='44'::jsonb AND d.original_record->'fencing_token'='85'::jsonb
 AND d.original_record->>'preregistration_id'='096c3054-fe8d-4a8d-afc8-fdff2bc9f241'
 AND d.original_record->>'create_grant_id'='8062bc1c-888f-46cf-ace7-11c7027aed1f'
 AND (to_jsonb(j)-'state'-'updated_at')=(convert_from(d.original_dispatch_wire,'UTF8')::jsonb-'state'-'updated_at')
 AND to_jsonb(w)=convert_from(d.original_run_wire,'UTF8')::jsonb
 AND public.installed_provision_timeout_valid(d.original_record,d.original_dispatch_wire,d.original_run_wire,d.original_intent_wire,d.members_wire) IS TRUE
"""

def e70_sql(original):
    """Add exactly one typed G44 terminal witness; preserve the old eight paths."""
    boundary='\n),\npolicies AS MATERIALIZED('
    need(type(original) is str and original.count(boundary) == 1
         and original.count('dispatch_terminal_witnesses AS MATERIALIZED (') == 1,
         'ONE_QUALIFIED_E70_TERMINAL_CTE_BOUNDARY')
    old="c.conname IN('capacity_dispatch_jobs_state_v8_check','capacity_dispatch_jobs_lifecycle_v8_check','capacity_dispatch_jobs_state_v9_check','capacity_dispatch_jobs_lifecycle_v9_check')"
    need(original.count(old) == 1, 'ONE_CURRENT_E70_DISPATCH_CHECK_SELECTOR')
    result=original.replace(boundary,G44_TERMINAL_UNION+boundary,1)
    result=result.replace(old,old[:-1]+",'capacity_dispatch_jobs_state_v10_check','capacity_dispatch_jobs_lifecycle_v10_check')",1)
    need(result.replace(G44_TERMINAL_UNION,'',1).replace(old[:-1]+",'capacity_dispatch_jobs_state_v10_check','capacity_dispatch_jobs_lifecycle_v10_check')",old,1)==original,
         'WHOLE_OLD_E70_INVERSE_NO_GENERIC_FAILED_FILTER')
    return result

def catalog_sql(context, read_ref, qualified97):
    h=definitions(context, read_ref)
    legacy=checked_ref(context['legacy_catalog_sql_ref'],read_ref)
    need(sha(legacy)==qualified97.LEGACY_CATALOG_SHA,'EXACT_UNCHANGED_QUALIFIED_C9_SQL_SOURCE')
    return h.catalog98_select(legacy.decode(),base_select=qualified97.catalog97_select)

def policy_sql(original_e70, current_catalog_sql):
    return ('WITH ordinary AS ('+e70_sql(original_e70)+'), current98 AS ('+current_catalog_sql
            +'), recovered98 AS ('+RECOVERED_G44_SQL+") SELECT (SELECT * FROM ordinary)::jsonb"
            +" || jsonb_build_object('schema98_catalog',(SELECT * FROM current98),'installed_timeout_recovery',(SELECT * FROM recovered98))")

def historical97_state(state, bundle):
    """An explicitly historical validation view, never a current database label."""
    result=copy.deepcopy(state)
    facts=copy.deepcopy(bundle['after']['legacy'])
    rows=loads(bundle['history97'])
    last={}
    for row in rows:
        if row['version_id'] not in last or row['id']>last[row['version_id']]['id']: last[row['version_id']]=row
    facts['latest_versions']=sorted(k for k,v in last.items() if v['is_applied'] is True)
    facts['history_max_version']=max(facts['latest_versions'])
    for version in (90,91,92): facts['rows'+str(version)]=sum(row['version_id']==version for row in rows)
    result['schema_facts']=facts
    result['schema96_catalog']=bundle['after']
    result['index92_definition']=bundle['after']['supplement']['index92_definition']
    result['index92_valid']=bundle['after']['supplement']['index92_valid']
    return result

def native_context(local, adapter, read_ref):
    """Validate saved Native DATA maps through same-byte local mirrors only."""
    closed(adapter,'schema context native_map_mirrors','EXPLICIT98_NATIVE_CONTEXT_ADAPTER')
    need(adapter['schema']=='restore98_native_context_same_originals_v1','EXPLICIT98_CONTEXT_NOT_A_NATIVE_PATH_ALIAS')
    native=adapter['context'];closed(native,' '.join(local),'SAME10_LOCAL_AND_NATIVE_CONTEXT_ROLES')
    for role in ('goose98_acceptance','catalog98_ref','history98_ref','migration98_ref','helper_source_ref','source_ci_ref','historical_root97_ref','legacy_catalog_sql_ref'):
        closed(native[role],'path sha256','CLOSED_NATIVE98_CONTEXT_REFERENCE')
        need(Path(native[role]['path']).is_absolute()and '..'not in Path(native[role]['path']).parts
             and native[role]['sha256']==local[role]['sha256'],'SAME_WHOLE_ORIGINALS_DIFFERENT_CUSTODY_PATHS')
    mirrors=adapter['native_map_mirrors'];closed(mirrors,'original_refs_local deparse_carrier_ref','TWO_DATA_MAP_ROLES_DIFFER_FROM_ORIGINAL_BYTES')
    decoded={}
    for role in mirrors:
        entry=mirrors[role];closed(entry,'native_ref local_ref','EXPLICIT_WHOLE_NATIVE_MAP_LOCAL_MIRROR')
        need(entry['native_ref']==native[role]and entry['local_ref']['path']!=entry['native_ref']['path']
             and entry['local_ref']['sha256']==entry['native_ref']['sha256'],'DATA_MAP_NO_NATIVE_LOCAL_ALIAS')
        decoded[role]=loads(checked_ref(entry['local_ref'],read_ref))
    oldmap=loads(checked_ref(local['original_refs_local'],read_ref));newmap=decoded['original_refs_local']
    roles='migration_result before_catalog after_catalog source_ci qualified_image'
    closed(oldmap,roles,'LOCAL98_ORIGINALS_MAP5');closed(newmap,roles,'NATIVE98_ORIGINALS_MAP5')
    for role in oldmap:
        a,b=oldmap[role],newmap[role]
        closed(b,'original_ref local_ref bytes','NATIVE98_FIVE_ROLE_CUSTODY_ENTRY')
        need(b['original_ref']==a['original_ref']and b['bytes']==a['bytes']
             and b['local_ref']['sha256']==a['local_ref']['sha256']==b['original_ref']['sha256']
             and b['local_ref']['path']!=b['original_ref']['path'],'SAME_FIVE_WHOLE_ORIGINALS_WITH_EXPLICIT_NATIVE_COPIES')
    oldcarrier=loads(checked_ref(local['deparse_carrier_ref'],read_ref));newcarrier=decoded['deparse_carrier_ref']
    closed(oldcarrier,'artifact_ref before97_ref after98_ref','LOCAL98_PG_CARRIER3')
    closed(newcarrier,'artifact_ref before97_ref after98_ref','NATIVE98_PG_CARRIER3')
    for role in oldcarrier:
        closed(newcarrier[role],'path sha256','NATIVE98_PG_ORIGINAL_REFERENCE')
        need(Path(newcarrier[role]['path']).is_absolute()and newcarrier[role]['sha256']==oldcarrier[role]['sha256'],
             'SAME_THREE_RAW_CI_PG_ORIGINALS_WITHOUT_NATIVE_READ')
    return native

# V3 is deliberately additive. The strict first-promotion predicate above is
# still the authority for the saved original, including its real typed marker.
def saved_bundle(expected, read_ref):
    summary = saved_recovery(expected, read_ref)
    raw = checked_ref(expected['saved_recovery_original_ref'], read_ref)
    need(0 < len(raw) <= 8 << 20, 'SAVED_PROMOTION_WHOLE8M')
    return loads(raw), summary

def recovery_sql(expected, read_ref):
    saved, _ = saved_bundle(expected, read_ref)
    run_id = saved['readiness_run']['id']
    need(type(run_id) is str and re.fullmatch('[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}', run_id),
         'EXACT_SAVED_READINESS_UUID')
    selector = "w.id=(i.intent#>>'{installed_guest_reconcile,new_run_id}')::uuid"
    replacement = "w.id='"+run_id+"'::uuid"
    need(RECOVERED_G44_SQL.count(selector) == 1, 'ONE_READY_RUN_SELECTOR')
    base = RECOVERED_G44_SQL.replace(selector, replacement, 1)
    need(base.replace(replacement, selector, 1) == RECOVERED_G44_SQL, 'WHOLE_READY_SELECTOR_INVERSE')
    # Independent run selection prevents an unbound run from disappearing behind
    # an incomplete jobs join. All normal VM grants, in every state, are included.
    extra = r"""
, anchor AS MATERIALIZED (SELECT * FROM public.capacity_dispatch_jobs WHERE run_id='@RUN@'::uuid),
line_jobs AS MATERIALIZED (
 SELECT j.* FROM public.capacity_dispatch_jobs j,anchor a
 WHERE (j.realm,j.environment,j.domain,j.dimension)=(a.realm,a.environment,a.domain,a.dimension)
 AND j.id<>a.id AND j.id<>'37edd909-fd96-46cc-bdc7-710a2573f5bf'::uuid
 AND (j.created_at>=a.created_at OR j.updated_at>=a.created_at
      OR j.state IN('queued','started','unknown') OR (j.state='returned' AND j.finalization_ack_at IS NULL))),
line_runs AS MATERIALIZED (
 SELECT w.* FROM public.workflow_runs w,anchor a
 WHERE (w.workflow_id=(a.envelope::jsonb#>>'{workflow,id}')::uuid
 OR (w.workflow_namespace,w.workflow_name)=(a.envelope::jsonb#>>'{workflow,namespace}',a.envelope::jsonb#>>'{workflow,name}'))
 AND w.id<>a.run_id AND w.id<>'ef7dfb2d-c681-4574-a463-4d4a1c30e126'::uuid
 AND (w.created_at>=a.created_at OR w.updated_at>=a.created_at OR w.finished_at IS NULL)),
grant_changes AS MATERIALIZED (
 SELECT g.* FROM public.capacity_mutation_grants g,anchor a
 WHERE NOT(g.grant_record?'authority_kind')
 AND ((g.namespace,g.environment,g.domain,g.dimension)=(a.realm,a.environment,a.domain,a.dimension)
 OR EXISTS(SELECT 1 FROM recovered_current rc CROSS JOIN LATERAL
 jsonb_array_elements(rc.value#>'{disposition,original_record,members}') m
 WHERE (g.integration_instance_id::text,g.scope_checksum,g.profile_name)=
 (m#>>'{tuple,integration_instance_id}',m#>>'{tuple,scope_checksum}',m#>>'{tuple,profile}')))
 AND g.updated_at>=a.created_at)
 SELECT (SELECT * FROM recovered_current)::jsonb ||
 jsonb_build_object('same_epoch_lineage',jsonb_build_object(
 'schema','same_G44_ordinary_refresh_lineage_v1',
 'anchor_job_id',(SELECT id FROM anchor),'anchor_run_id',(SELECT run_id FROM anchor),
 'anchor_created_at',(SELECT created_at FROM anchor),
 'jobs_wire',(SELECT coalesce(json_agg(row_to_json(j) ORDER BY j.created_at,j.id),'[]'::json)::text FROM line_jobs j),
 'job_count',(SELECT count(*) FROM line_jobs),
 'job_ids',(SELECT coalesce(jsonb_agg(id ORDER BY created_at,id),'[]'::jsonb) FROM line_jobs),
 'runs_wire',(SELECT coalesce(json_agg(row_to_json(w) ORDER BY w.created_at,w.id),'[]'::json)::text FROM line_runs w),
 'run_count',(SELECT count(*) FROM line_runs),
 'run_ids',(SELECT coalesce(jsonb_agg(id ORDER BY created_at,id),'[]'::jsonb) FROM line_runs),
 'vm_grant_changes_wire',(SELECT coalesce(json_agg(row_to_json(g) ORDER BY g.updated_at,g.id),'[]'::json)::text FROM grant_changes g),
 'vm_grant_change_count',(SELECT count(*) FROM grant_changes)))
"""
    return 'WITH recovered_current(value) AS ('+base+')'+extra.replace('@RUN@', run_id)

def canonical_dispatch(value):
    # These two dispatch domains use Go json.Marshal, without a trailing LF.
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()

def ordinary_refresh(job, run, anchor, intent, observed):
    need(job['state'] == 'returned' and job['return_status'] == run['status'] == 'succeeded'
         and job['run_id'] == run['id'] and not job.get('return_error')
         and not job.get('finalization_error') and not run.get('error'),
         'EACH_INTERVENING_JOB_RUN_SUCCEEDED_WITHOUT_ERROR')
    times = [stamp(job[k]) for k in ('created_at','started_at','returned_at','finalization_ack_at','lease_expires_at')]
    need(times[0] <= times[1] <= times[2] <= times[3] <= times[4]
         and times[3] <= observed and stamp(run['finished_at']) <= times[2]
         and times[1] <= stamp(run['started_at']) <= stamp(run['finished_at']),
         'REAL_ORIGINAL_DISPATCH_DEADLINE_ACK_AND_RUN_TIMES')
    raw = job['envelope']
    need(type(raw) is str and sha(raw.encode()) == job['envelope_sha256'], 'WHOLE_INTERVENING_DISPATCH_ENVELOPE')
    env, old = loads(raw), loads(anchor['envelope'])
    need(env['job_id'] == job['id'] and env['run_id'] == run['id']
         and env['metadata']['capacity_dispatch_job_id'] == job['id']
         and env['metadata']['triggered_by'] == 'workflow_scheduler',
         'EXACT_INTERVENING_JOB_RUN_METADATA_JOIN')
    for key in ('inputs','metadata'):
        need(sha(canonical_dispatch(env[key])) == env[key+'_sha256'], 'ORIGINAL_DISPATCH_CANONICAL_'+key)
    def authority(e):
        e = copy.deepcopy(e)
        for key in ('job_id','run_id','source_tick','metadata_sha256'): e.pop(key, None)
        for key in ('capacity_dispatch_job_id','scheduled_for'): e['metadata'].pop(key, None)
        return e
    need(authority(env) == authority(old)
         and all(job[k] == anchor[k] for k in ('realm','environment','domain','dimension'))
         and run['workflow_namespace'] == env['workflow']['namespace']
         and run['workflow_name'] == env['workflow']['name']
         and run['workflow_version'] == env['workflow']['version']
         and run['metadata'] == env['metadata'] and (run.get('inputs') or {}) == env['inputs'],
         'EXACT_SAME_AUTHORITY_WORKFLOW_POLICY_INPUTS_AND_FULL_SCOPE')
    result = run['result']
    need(result['status'] == 'succeeded' and not result.get('error')
         and result['workflow'] == {'kind':'workflow',**{k:env['workflow'][k] for k in ('id','namespace','name','version')}}
         and result.get('metadata',{}) == env['metadata'], 'EXACT_SUCCESSFUL_WORKFLOW_RESULT')
    ids = ['plan-original-guest','provision-original-notify','retire-original-guest',
           'refresh-original-membership','complete-original-provision',
           'finish-original-retirement','complete-original-retirement']
    steps = result['steps']
    need(type(steps) is list and [s['id'] for s in steps] == ids, 'WHOLE_SEVEN_ORDERED_ORDINARY_STEPS')
    previous = stamp(run['started_at'])
    operations = ('capacity.plan_original_guest','capacity.provision_original_guest','capacity.retire_original_guest',
                  'capacity.complete_original_guest','capacity.complete_original_guest',
                  'capacity.finish_original_guest_retirement','capacity.complete_original_guest')
    for n, step in enumerate(steps):
        need(step['kind'] == 'yggdrasil' and step['operation'] == operations[n]
             and step['capability'] == operations[n] and not step.get('error')
             and step.get('integration_instance') is None and step.get('integration_type') is None,
             'NO_INTERVENING_PROVIDER_ADAPTER_STEP')
        start, finish = stamp(step['started_at']), stamp(step['finished_at'])
        need(previous <= start <= finish <= stamp(run['finished_at']), 'ORDERED_ORIGINAL_STEP_CLOCKS')
        previous = finish
        if n in (0,3):
            need(step['status'] == 'succeeded' and type(step['attempts']) is int and step['attempts'] == 1,
                 'ONLY_PLAN_AND_READONLY_REFRESH_ACTIVE')
        else:
            condition = '{{ steps.plan-original-guest.metadata.mode }} == ' + ('provision' if n in (1,4) else 'retire')
            need(step['status'] == 'skipped' and type(step.get('attempts',0)) is int
                 and step.get('attempts',0) == 0
                 and step.get('metadata') == {'condition':condition,'skip_reason':'condition'},
                 'NO_PROVISION_RETIRE_DELETE_COMPLETION_STEP')
    p = steps[0]['metadata']
    closed(p, 'mode reason slot generation fencing_token lease_owner preregistration_id', 'CLOSED_ORDINARY_REFRESH_PLAN')
    need(p['mode'] == 'refresh' and type(p['slot']) is int and p['slot'] == 0
         and type(p['generation']) is int and p['generation'] == 44
         and type(p['fencing_token']) is int and p['fencing_token'] == intent['fencing_token']
         and p['lease_owner'] == p['preregistration_id'] == ''
         and p['reason'] in ('within_envelope','up_window_pending','down_window_pending',
                            'cooldown','capacity_boundary','validated_profile_unavailable'),
         'SAME44_SAMEFENCE_ORDINARY_HOLD_NOT_A_RECOVERY_OR_MUTATION')
    closed(steps[3]['metadata'], 'mode members provider_mutations', 'CLOSED_READONLY_REFRESH_RETURN')
    m = steps[3]['metadata']
    need(m['mode'] == 'refresh' and type(m['members']) is int and m['members'] == 8
         and m['provider_mutations'] is False, 'ALL8_READONLY_REFRESH_NO_PROVIDER_MUTATION')

def recovered_current(value, expected, policy, read_ref):
    saved, summary = saved_bundle(expected, read_ref)
    closed(value, ' '.join(saved)+' same_epoch_lineage', 'WHOLE12_FRESH_RECOVERY_WITH_COMPLETE_LINEAGE')
    need(value['schema'] == saved['schema'] and value['predicate_valid'] is True, 'SAME_M98_READ_PROOF')
    for key in ('disposition','current_job','current_run','readiness_job','readiness_run','member_grants'):
        need(value[key] == saved[key], 'IMMUTABLE_SAVED_PROMOTION_JOIN_'+key)
    current, old = loads(value['current_intent_wire']), loads(saved['current_intent_wire'])
    need(type(current['generation']) is int and current['generation'] == old['generation'] == 44
         and type(current['fencing_token']) is int and current['fencing_token'] == old['fencing_token']
         and current['phase'] == 'promoted' and current.get('lease_owner','') == ''
         and current.get('lease_executor_id','') == '' and current.get('lease_expires_at') is None
         and current['policy_id'] == old['policy_id'] == G44_POLICY
         and current['policy_checksum'] == old['policy_checksum'] == G44_POLICY_SHA
         and current['decision']['profile'] == old['decision']['profile']
         and current.get('retirement_forward') is None and current.get('recovery_only',False) is False
         and not current.get('failed_expansion_terminal_reconcile')
         and not current.get('provider_floor_reconcile'),
         'ONLY_SAME44_SAME_SAVED_FENCE_PROMOTED_UNLEASED_POLICY')
    need(type(value['current_slots']) is list and len(value['current_slots']) == 8, 'FULL_CURRENT8_SLOT_ROWS')
    for before, after in zip(saved['current_slots'], value['current_slots']):
        closed(after,'row slot_record_wire','FULL_CURRENT_SLOT_WIRE')
        a, b = copy.deepcopy(before['row']), copy.deepcopy(after['row'])
        need(type(b['revision']) is int and b['revision'] >= a['revision']
             and stamp(b['updated_at']) >= stamp(a['updated_at'])
             and loads(after['slot_record_wire']) == b['slot_record'], 'FRESH_SLOT_REVISION_AND_WIRE')
        aa, bb = a.pop('slot_record'), b.pop('slot_record')
        for k in ('revision','updated_at'): a.pop(k); b.pop(k)
        for k in ('observed_at','receipt_ref'): aa.pop(k,None); bb.pop(k,None)
        need(a == b and aa == bb, 'SAME_EIGHT_FULL_PHYSICAL_TUPLES_ONLY_READ_OBSERVATION_CHANGED')
    identity = policy['intent_identity']
    slots = [{**{k:x['row'][k] for k in ('slot','resource_id','namespace','environment','domain','dimension')},
              'slot_record_sha256':sha(x['slot_record_wire'].encode())} for x in value['current_slots']]
    need(slots == policy['owned_slots'] and len(identity) == 1
         and identity[0]['intent_sha256'] == sha(value['current_intent_wire'].encode())
         and all(identity[0][k] == v for k,v in {
             'generation':44,'fence':old['fencing_token'],'phase':'promoted','policy_id':G44_POLICY,
             'policy_checksum':G44_POLICY_SHA,'retirement_forward':None}.items()),
         'FRESH_E70_FULL_SLOT_AND_INTENT_PG_WIRE_JOINS')
    observed = stamp(value['observed_at'])
    need(stamp(saved['observed_at']) <= observed
         and abs((stamp(policy['at'])-observed).total_seconds()) <= 15, 'FRESH15_AND_NO_PRE_SAVED_ORIGINAL')
    line = value['same_epoch_lineage']
    closed(line,'schema anchor_job_id anchor_run_id anchor_created_at jobs_wire job_count job_ids runs_wire run_count run_ids vm_grant_changes_wire vm_grant_change_count','CLOSED12_COMPLETE_SAME_EPOCH_LINEAGE')
    anchor = saved['readiness_job']
    need(line['schema'] == 'same_G44_ordinary_refresh_lineage_v1'
         and line['anchor_job_id'] == anchor['id'] and line['anchor_run_id'] == anchor['run_id']
         and stamp(line['anchor_created_at']) == stamp(anchor['created_at']), 'EXACT_SAVED_READINESS_ANCHOR')
    arrays = {}
    for noun in ('jobs','runs','vm_grant_changes'):
        raw = line[noun+'_wire']
        need(type(raw) is str and 0 < len(raw.encode()) <= 8 << 20, 'WHOLE_BOUNDED_LINEAGE_WIRE')
        rows = loads(raw); count = line[{'jobs':'job','runs':'run','vm_grant_changes':'vm_grant_change'}[noun]+'_count']
        need(type(rows) is list and type(count) is int and len(rows) == count <= 512, 'COMPLETE_FINITE_LINEAGE_COUNT')
        arrays[noun] = rows
    jobs, runs = arrays['jobs'], arrays['runs']
    need(not arrays['vm_grant_changes'] and [j['id'] for j in jobs] == line['job_ids']
         and [r['id'] for r in runs] == line['run_ids']
         and len({j['id'] for j in jobs}) == len(jobs)
         and len({r['id'] for r in runs}) == len(runs)
         and len(jobs) == len(runs) and {j['run_id'] for j in jobs} == {r['id'] for r in runs},
         'ALL_INDEPENDENT_JOB_RUN_IDS_ONE_TO_ONE_NO_VM_GRANT_CHANGE')
    byrun = {r['id']:r for r in runs}
    for job in jobs:
        need(job['id'] not in (G44_JOB,anchor['id']) and job['run_id'] not in (G44_RUN,anchor['run_id'])
             and stamp(anchor['created_at']) <= stamp(job['created_at']) <= observed,
             'NO_OLD_UNRESOLVED_OR_HIDDEN_LINEAGE_JOB')
        ordinary_refresh(job, byrun[job['run_id']], anchor, current, observed)
    marker = current.get('installed_guest_reconcile')
    if marker is not None:
        need(marker == old['installed_guest_reconcile'], 'EXACT_RETAINED_TYPED_MARKER')
        recovered({k:v for k,v in value.items() if k != 'same_epoch_lineage'}, expected, policy)
    else:
        need(len(jobs) > 0 and current['decision']['action'] == 'hold'
             and type(current['decision']['units']) is int and current['decision']['units'] == 8,
             'MARKER_OMISSION_ONLY_AFTER_PROVEN_ORDINARY_HOLD_REFRESH')
    return {**summary, 'current_marker_absent':marker is None, 'intervening_readonly_jobs':len(jobs)}

def from_baseline_current(value, expected, baseline, read_ref):
    current = loads(value['current_intent_wire'])
    slots = [{**{k:x['row'][k] for k in ('slot','resource_id','namespace','environment','domain','dimension')},
              'slot_record_sha256':sha(x['slot_record_wire'].encode())} for x in value['current_slots']]
    need(sha(wire(slots)) == baseline['owned_slot_roster_sha256']
         and sorted(x['resource_id'] for x in slots) == baseline['native_resource_ids']
         and sha(value['current_intent_wire'].encode()) == baseline['intent_sha256']
         and baseline['policy_id'] == current['policy_id']
         and baseline['policy_checksum'] == current['policy_checksum'], 'EXACT_CURRENT_BASELINE_FULL_ROSTER_AND_PG_INTENT')
    identity = {'generation':current['generation'],'fence':current['fencing_token'],'phase':current['phase'],
                'policy_id':current['policy_id'],'policy_checksum':current['policy_checksum'],
                'retirement_forward':current.get('retirement_forward'),'intent_sha256':baseline['intent_sha256']}
    return recovered_current(value, expected, {'at':baseline['observed_at_pg'],'owned_slots':slots,'intent_identity':[identity]}, read_ref)

def native_context_current(local, adapter, read_ref):
    closed(adapter,'schema context native_map_mirrors native_saved_recovery_original_ref','EXPLICIT4_NATIVE_CONTEXT_AND_SAVED_ORIGINAL')
    return native_context(local,{k:adapter[k] for k in ('schema','context','native_map_mirrors')},read_ref)

def native_recovery_current(expected, adapter, read_ref):
    closed(adapter,'schema context native_map_mirrors native_saved_recovery_original_ref','EXPLICIT4_NATIVE_CONTEXT_AND_SAVED_ORIGINAL')
    saved_bundle(expected, read_ref)
    ref = adapter['native_saved_recovery_original_ref']
    closed(ref,'path sha256','CLOSED_NATIVE_SAVED_PROMOTION_REF')
    need(Path(ref['path']).is_absolute() and '..' not in Path(ref['path']).parts
         and ref['path'] != expected['saved_recovery_original_ref']['path']
         and ref['sha256'] == expected['saved_recovery_original_ref']['sha256'], 'SAME_COMPLETE_PROMOTION_ORIGINAL_EXPLICIT_NATIVE_CUSTODY')
    return {**expected,'saved_recovery_original_ref':ref}

def policy_sql_current(original_e70, current_catalog_sql, expected, read_ref):
    return ('WITH ordinary AS ('+e70_sql(original_e70)+'), current98 AS ('+current_catalog_sql
            +'), recovered98 AS ('+recovery_sql(expected,read_ref)+") SELECT (SELECT * FROM ordinary)::jsonb"
            +" || jsonb_build_object('schema98_catalog',(SELECT * FROM current98),'installed_timeout_recovery',(SELECT * FROM recovered98))")
