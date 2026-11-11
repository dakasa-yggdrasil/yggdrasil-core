#!/usr/bin/env python3
"""INERT pure schema99 restoration and explicit pre-action continuation DATA.
No entry point, SQL execution, business authority or original-clock replacement.
"""
import base64
import copy
import hashlib
import json
from pathlib import Path
import re
import types

SOURCE_BOUND = False
QUALIFIED_SOURCE = None
M99 = 'bbfecef9888c27eacda8c732bcfe28e606d566decadf56ecc65acfb687020a41'
ROOT98_SHA = 'a27138d1f2e9a2b9eb9db916f7bd658040f4621a42bce9bcab602f6667f2a947'
RESTORE98_SHA = 'c3a4ec57a3a430e45c47bbe5a6e8afd400560527f97b09d99a3819e9bd80fed0'
HISTORICAL_SOURCE98 = '9f0266de7a2982352b7ff8fd627e73ceba12c896'
HISTORICAL_IMAGE98 = 'ed5ee3a2a5e90e54acc3cc2492fcc302a85e1b7adb6f545c605c5bfe2a730b42'
HISTORICAL_OPS98 = 'bb18f0b0bbf2bafb7d337a8dba0797d9237140b9'
CAP = 8 << 20
ROLES = 'migration_result before_catalog after_catalog source_ci qualified_image'

class Hold(RuntimeError):
    pass

def need(value, tag):
    if not value:
        raise Hold(tag)

def closed(value, keys, tag):
    need(type(value) is dict and set(value) == set(keys.split()), tag)
    return value

def sha(value):
    return hashlib.sha256(value).hexdigest()

def wire(value):
    return (json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False)+'\n').encode()

def loads(raw):
    def pairs(items):
        value={}
        for key,item in items:
            need(key not in value,'NO99_DUPLICATE_JSON_KEYS');value[key]=item
        return value
    return json.loads(raw,object_pairs_hook=pairs,
                      parse_constant=lambda _:(_ for _ in ()).throw(Hold('FINITE99_JSON')))

def original(ref, read_ref):
    closed(ref,'path sha256','CLOSED99_WHOLE_ORIGINAL_REF')
    need(type(ref['path']) is str and Path(ref['path']).is_absolute()
         and '..' not in Path(ref['path']).parts and type(ref['sha256']) is str
         and re.fullmatch('[a-f0-9]{64}',ref['sha256']), 'EXACT99_ABSOLUTE_ORIGINAL_REF')
    raw=read_ref(ref)
    need(type(raw) is bytes and 0<len(raw)<=CAP and sha(raw)==ref['sha256'],
         'WHOLE99_ORIGINAL_BYTES_AND_HASH')
    return raw

def definitions99(context, read_ref):
    ref=context['helper_source_ref'];raw=original(ref,read_ref)
    module=types.ModuleType('qualified_restore99_catalog_definitions');module.__file__=ref['path']
    exec(compile(raw,module.__file__,'exec'),module.__dict__)
    need(module.SOURCE_BOUND is False and module.QUALIFIED_SOURCE is None and module.M99==M99,
         'PURE99_QUALIFIED_SOURCE_NOT_AN_ACTIVATED_OPERATOR')
    ref=context['restore98_source_ref'];raw=original(ref,read_ref)
    need(sha(raw)==RESTORE98_SHA,'EXACT_OLD98_CONDITIONAL_SKIP_DEFINITIONS')
    old=types.ModuleType('qualified_restore98_historical_definitions');old.__file__=ref['path']
    exec(compile(raw,old.__file__,'exec'),old.__dict__)
    need(old.SOURCE_BOUND is False and old.QUALIFIED_SOURCE is None,'OLD98_PURE_DEFINITIONS')
    return module,old

def artifacts99(context, read_ref, historical97, current_source, current_image, ops_source):
    closed(context,'schema historical98_context goose99_acceptance catalog99_ref history99_ref original_refs_local deparse_carrier_ref migration99_ref helper_source_ref source_ci_ref restore98_source_ref preaction_preimage_ref preaction_case',
           'CLOSED13_RESTORE99_CONTEXT_NOT_A_RELABELED98')
    need(context['schema']=='restore99_preaction_continuation_context_v1','EXPLICIT99_CONTEXT')
    helper,old=definitions99(context,read_ref)
    prior=old.artifacts(context['historical98_context'],read_ref,historical97,
                        HISTORICAL_SOURCE98,HISTORICAL_IMAGE98,HISTORICAL_OPS98)
    raw98=original(context['historical98_context']['goose98_acceptance'],read_ref)
    need(sha(raw98)==ROOT98_SHA,'IMMUTABLE98_ROOT_NOT_CURRENT99')
    raw99=original(context['goose99_acceptance'],read_ref);receipt=loads(raw99)
    mapping=loads(original(context['original_refs_local'],read_ref))
    closed(mapping,ROLES,'CLOSED99_FIVE_WHOLE_ORIGINAL_CUSTODY_MAP')
    def read_original(ref):
        matches=[row for row in mapping.values() if type(row)is dict and row.get('original_ref')==ref]
        need(len(matches)==1,'ONE99_ORIGINAL_TO_LOCAL_CUSTODY')
        row=closed(matches[0],'original_ref local_ref bytes','CLOSED99_CUSTODY_ROW')
        need(row['original_ref']['path']!=row['local_ref']['path']
             and row['original_ref']['sha256']==row['local_ref']['sha256']
             and type(row['bytes'])is int and row['bytes']>1,'NO99_NATIVE_LOCAL_PATH_ALIAS')
        raw=original(row['local_ref'],read_ref);need(len(raw)==row['bytes'],'WHOLE99_CUSTODY_SIZE')
        return raw
    before=loads(read_original(receipt['original_refs']['before_catalog']))
    after=loads(read_original(receipt['original_refs']['after_catalog']))
    sql_raw=original(context['migration99_ref'],read_ref);need(sha(sql_raw)==M99,'EXACT99_SQL_SOURCE')
    carrier=loads(original(context['deparse_carrier_ref'],read_ref))
    defs=helper.constraint99_definitions(prior['projection'],carrier,
        lambda r:original(r,read_ref),current_source,sql_raw.decode())
    expected=helper.catalog99_delta(prior['projection'],before,after,
                                   helper.migration99_functions(sql_raw.decode()),defs)
    projection_raw=original(context['catalog99_ref'],read_ref)
    need(loads(projection_raw)==expected==helper.catalog99_projection(after),'WHOLE99_CATALOG9')
    history_raw=original(context['history99_ref'],read_ref)
    need(history_raw==after['legacy']['complete_history_wire'].encode(),'WHOLE99_HISTORY_WIRE')
    helper.root99_overlay(raw99,raw98,{
        'current_ops_source':ops_source,'business_source':current_source,'amd64_D':current_image,
        'complete_history_sha256':sha(history_raw),'prior98_history_sha256':sha(prior['history'].encode()),
        'catalog99_sha256':sha(projection_raw),'index92_definition_sha256':sha(expected['index92_definition'].encode()),
        'catalog90_91_sha256':sha(wire({k:expected[k]for k in('catalog90','catalog91')}))},read_original)
    need(context['source_ci_ref']['sha256']==receipt['original_refs']['source_ci']['sha256']
         and original(context['source_ci_ref'],read_ref)==read_original(receipt['original_refs']['source_ci']),
         'SAME99_WHOLE_SOURCE_CI_ORIGINAL')
    preimage=loads(original(context['preaction_preimage_ref'],read_ref))
    helper.validate_preaction99(preimage,context['preaction_case'])
    return {'helper':helper,'old':old,'prior98':prior,'receipt':receipt,'projection':expected,
            'history':history_raw.decode(),'definitions':defs,'context':context,
            'preaction_preimage':preimage}

def current99(policy,bundle,live_catalog):
    facts,root,h=policy['schema_facts'],bundle['receipt'],bundle['helper']
    need(facts['database']=='yggdrasil' and facts['readonly']=='on'
         and type(facts['history_max_version'])is int and facts['history_max_version']==99
         and facts['latest_versions']==[0]+[x for x in range(1,100)if x!=40]
         and all(type(facts[k])is int and facts[k]==1 for k in('rows90','rows91','rows92'))
         and policy['index89_valid']is True and policy['index92_valid']is True,'CURRENT99_HEAD_AND_INDEXES')
    need(facts['complete_history_wire']==bundle['history']
         and sha(facts['complete_history_wire'].encode())==root['complete_history_sha256']
         and {k:facts[k]for k in('catalog90','catalog91')}=={k:bundle['projection'][k]for k in('catalog90','catalog91')}
         and sha(policy['index92_definition'].encode())==root['index92_definition_sha256'],
         'CURRENT99_HISTORY_AND_CATALOG_NOT_RETYPED98')
    need(h.catalog99_projection(live_catalog)==bundle['projection']
         and live_catalog['legacy']['complete_history_wire']==bundle['history'],'CURRENT99_WHOLE_LIVE_PROJECTION')
    h.structural99(live_catalog['structural99'],bundle['definitions'])
    need(all(type(facts[k])is int and facts[k]==live_catalog['legacy'][k]==0
             for k in('other_migrators_ddl','other_cic','ddl_locks')),'UNCHANGED99_NO_OTHER_DDL')
    return {'database_schema':99,'complete_history_sha256':root['complete_history_sha256'],
            'schema99_catalog_sha256':root['catalog99_sha256']}

def pg_bytes(value):
    need(type(value)is str and re.fullmatch(r'\\x(?:[a-f0-9]{2})+',value),'CANONICAL99_PG_BYTEA')
    return bytes.fromhex(value[2:])

def uuid99(value):
    return type(value)is str and re.fullmatch('[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}',value) is not None and value!='00000000-0000-0000-0000-000000000000'

def chain99(rows, case, recovered_value, preimage, helper):
    need(type(rows)is list and 1<=len(rows)<=512,'BOUNDED_COMPLETE99_RECEIPT_CHAIN')
    before=loads(preimage['records_wire'])
    anchor=recovered_value['disposition']
    anchor_record=anchor['original_record']
    byjob={}
    for item in rows:
        closed(item,'row predicate_valid job run successor_job successor_run','WHOLE99_RECEIPT_AND_CAUSAL_ROWS')
        need(item['predicate_valid']is True,'QUALIFIED99_HISTORICAL_SQL_PREDICATE')
        d=closed(item['row'],'id job_id run_id successor_job_id successor_run_id original_record original_wire original_dispatch_wire original_run_wire original_intent_wire members_wire evidence_wire recorded_at','CLOSED13_M99_LEDGER_ROW')
        raw,dr,wr,ir,mr,er=(pg_bytes(d[k])for k in('original_wire','original_dispatch_wire','original_run_wire','original_intent_wire','members_wire','evidence_wire'))
        r,j,w,i,m,e=(loads(x)for x in(raw,dr,wr,ir,mr,er))
        closed(r,'schema id job_id run_id successor_job_id successor_run_id root_anchor_id policy_id policy_checksum generation fencing_token original_dispatch_sha256 original_run_sha256 original_intent_sha256 members_sha256 evidence_sha256 original_deadline original_returned_at recorded_at','CLOSED19_M99_RECORD')
        need(r==d['original_record'] and r['schema']=='unknown_preaction_failed_plan_disposition_v1'
             and all(uuid99(r[k])for k in('id','job_id','run_id','successor_job_id','successor_run_id','root_anchor_id','policy_id'))
             and all(r[k]==d[k]for k in('id','job_id','run_id','successor_job_id','successor_run_id'))
             and r['root_anchor_id']==anchor['id']==case['root_anchor_id']
             and r['policy_id']==anchor_record['policy_id']==case['policy_id']
             and r['policy_checksum']==anchor_record['policy_checksum']==case['policy_checksum']
             and type(r['generation'])is int and r['generation']==anchor_record['generation']
             and type(r['fencing_token'])is int and r['fencing_token']==anchor_record['fencing_token'],
             'SAME_M98_ROOT_AND_CLOSED99_ORIGINAL_IDENTITY')
        for name,data in(('original_dispatch_sha256',dr),('original_run_sha256',wr),('original_intent_sha256',ir),('members_sha256',mr),('evidence_sha256',er)):
            need(sha(data)==r[name],'EXACT99_ORIGINAL_HASH_DOMAIN_'+name)
        need(ir==pg_bytes(anchor['original_intent_wire']) and mr==pg_bytes(anchor['members_wire']),
             'EXACT_M98_ANCHOR_INTENT_AND_MEMBERS_NOT_NEW_CLAIM')
        helper.preaction_scan99(e)
        need(j['id']==r['job_id'] and j['run_id']==w['id']==r['run_id']
             and j['state']=='unknown' and j['finalization_ack_at']is None
             and j['return_status']==w['status']=='failed'
             and item['run']==w,'OLD_UNKNOWN_FAILED_RUN_WHOLE_PRESERVED')
        stamp=helper.preaction_stamp99
        need(stamp(j['started_at'])==stamp(w['started_at'])<stamp(j['lease_expires_at'])
             and stamp(j['returned_at'])==stamp(w['finished_at'])>=stamp(j['started_at'])
             and stamp(r['original_deadline'])==stamp(j['lease_expires_at'])
             and stamp(r['original_returned_at'])==stamp(j['returned_at'])
             and stamp(r['recorded_at'])==stamp(d['recorded_at'])==stamp(item['job']['updated_at'])
             and stamp(r['recorded_at'])>=max(stamp(j['lease_expires_at']),stamp(j['returned_at']))
             and stamp(anchor['recorded_at'])<=stamp(j['started_at']),
             'INDEPENDENT99_ORIGINAL_RETURN_AND_RECEIPT_CLOCKS')
        env=loads(j['envelope']);next_env=loads(item['successor_job']['envelope'])
        need(sha(j['envelope'].encode())==j['envelope_sha256']
             and env['job_id']==j['id'] and env['run_id']==w['id']
             and env['metadata']==w['metadata'] and env['inputs']==w['inputs'],
             'WHOLE99_FAILED_ENVELOPE_AND_RUN_CAUSAL_JOIN')
        def authority(value):
            value=copy.deepcopy(value)
            for key in('job_id','run_id','source_tick','metadata_sha256'):value.pop(key,None)
            for key in('scheduled_for','capacity_dispatch_job_id'):value['metadata'].pop(key,None)
            return value
        need(authority(env)==authority(next_env)
             and sha(item['successor_job']['envelope'].encode())==item['successor_job']['envelope_sha256']
             and next_env['job_id']==r['successor_job_id'] and next_env['run_id']==r['successor_run_id'],
             'EXPLICIT99_SUCCESSOR_RETAINS_EXACT_AUTHORITY')
        actual,old=copy.deepcopy(item['job']),copy.deepcopy(j)
        need(actual['state']=='preaction_plan_disposed' and actual['finalization_ack_at']is None,
             'DISTINCT_M99_TERMINAL_NOT_ACK')
        for row in(actual,old):row.pop('state');row.pop('updated_at')
        need(actual==old,'ALL_OTHER_M99_ORIGINAL_DISPATCH_FIELDS_RETAINED')
        need(item['successor_job']['id']==r['successor_job_id']
             and item['successor_job']['run_id']==item['successor_run']['id']==r['successor_run_id']
             and r['successor_job_id']!=r['job_id'] and r['successor_run_id']!=r['run_id'],
             'EXPLICIT99_REAL_SUCCESSOR_NOT_REPLAY')
        need(r['job_id']not in byjob,'NO99_DUPLICATE_ORIGINAL_JOB')
        byjob[r['job_id']]=(r,item,j,w)
    cursor=case['job_id'];visited=set();previous=None
    ready=recovered_value['readiness_job']
    while cursor!=ready['id']:
        need(cursor in byjob and cursor not in visited,'COMPLETE99_NONCYCLIC_CHAIN_TO_ACTUAL_READINESS')
        r,item,j,w=byjob[cursor];visited.add(cursor)
        if previous is None:
            need(r['run_id']==case['run_id'] and w==before['run'],'FIRST99_FAILED_PLAN_ORIGINAL_RUN')
            original,actual=copy.deepcopy(before['job']),copy.deepcopy(j)
            need(type(actual['pending_wake_count'])is int and type(original['pending_wake_count'])is int
                 and original['pending_wake_count']<=actual['pending_wake_count']<=32,
                 'ONLY_LEGITIMATE_BOUNDED_WAKE_COALESCING_BEFORE_DISPOSITION')
            for row in(original,actual):row.pop('pending_wake_count');row.pop('updated_at')
            need(original==actual,'FIRST99_ORIGINAL_AUTHORITY_AND_RETURN_UNCHANGED')
        else:
            need(previous['successor_run_id']==r['run_id']
                 and helper.preaction_stamp99(previous['recorded_at'])<=helper.preaction_stamp99(j['started_at']),
                 'ORDERED_DISTINCT99_RETRY_SUCCESSOR')
        previous=r;cursor=r['successor_job_id']
    need(len(visited)==len(rows) and previous is not None
         and previous['successor_run_id']==ready['run_id']
         and recovered_value['current_intent_wire'] is not None,'ALL99_ROWS_ACCOUNTED_EXACT_READY_SUCCESSOR')
    return {'root_anchor_id':anchor['id'],'first_failed_plan_job_id':case['job_id'],
            'preaction_job_ids':sorted(visited),'readiness_job_id':ready['id'],
            'readiness_run_id':ready['run_id'],'receipt_count':len(rows),
            'unknown_returns_and_all_original_ACK_absence_preserved':True}

def promotion99(value, case, preimage, old, helper, original_ref, component_ref):
    closed(value,'schema observed_at installed_recovery preaction_dispositions','WHOLE99_CONTINUATION_SNAPSHOT')
    need(value['schema']=='recovered_preaction_plan_continuation_v1','EXPLICIT99_CONTINUATION_NOT_OLD337')
    v=value['installed_recovery']
    closed(v,'schema observed_at disposition current_job current_run readiness_job readiness_run current_intent_wire member_grants current_slots predicate_valid','WHOLE_M98_READINESS_COMPONENT')
    d=v['disposition'];r=loads(pg_bytes(d['original_wire']))
    expected={'schema':'root_failed_A5_recovered_G44_originals_v1','disposition_id':d['id'],
              'disposition_sha256':sha(pg_bytes(d['original_wire'])),
              **{k:r[k]for k in('original_dispatch_sha256','original_run_sha256','original_intent_sha256','members_sha256')},
              'snapshot_ref':component_ref,'saved_recovery_original_ref':component_ref}
    current=loads(v['current_intent_wire'])
    slots=[{**{k:x['row'][k]for k in('slot','resource_id','namespace','environment','domain','dimension')},
            'slot_record_sha256':sha(x['slot_record_wire'].encode())}for x in v['current_slots']]
    identity={'generation':current['generation'],'fence':current['fencing_token'],'phase':current['phase'],
              'policy_id':current['policy_id'],'policy_checksum':current['policy_checksum'],
              'retirement_forward':current.get('retirement_forward'),'intent_sha256':sha(v['current_intent_wire'].encode())}
    summary=old.recovered(v,expected,{'at':v['observed_at'],'owned_slots':slots,'intent_identity':[identity]})
    chain=chain99(value['preaction_dispositions'],case,v,preimage,helper)
    return {'installed_timeout_recovery':expected,'installed_summary':summary,'preaction_chain':chain,
            'whole_continuation_original_ref':original_ref,'Root_acceptance_created':False}

def member_wire99(raw, name):
    """Extract the actual JSON member bytes; never serialize a replacement."""
    value=loads(raw)
    need(type(value)is dict and name in value,'ACTUAL99_COMPONENT_PRESENT')
    text=raw.decode('UTF-8');decoder=json.JSONDecoder();position=0
    def space(index):
        while index<len(text) and text[index] in ' \t\r\n':index+=1
        return index
    position=space(position);need(text[position]=='{','WHOLE99_OBJECT');position+=1
    while True:
        position=space(position)
        need(position<len(text) and text[position]!='}','ACTUAL99_COMPONENT_NOT_SYNTHESIZED')
        key,position=decoder.raw_decode(text,position);position=space(position)
        need(text[position]==':','ACTUAL99_MEMBER_SEPARATOR');position=space(position+1)
        start=position;_,position=decoder.raw_decode(text,position)
        if key==name:
            result=text[start:position].encode('UTF-8')
            need(loads(result)==value[name],'EXACT99_LEXICAL_COMPONENT_EQUALS_WHOLE_MEMBER')
            return result
        position=space(position)
        need(text[position]==',','ACTUAL99_COMPONENT_FOUND_BEFORE_END');position+=1

def saved99(expected, bundle, read_ref):
    closed(expected,'schema whole_continuation_original_ref installed_timeout_recovery',
           'CLOSED3_SAVED99_CONTINUATION_BINDING')
    need(expected['schema']=='root_saved_preaction_continuation_originals_v1','EXPLICIT99_SAVED_ORIGINAL')
    outer=original(expected['whole_continuation_original_ref'],read_ref)
    component_ref=expected['installed_timeout_recovery']['saved_recovery_original_ref']
    component=original(component_ref,read_ref)
    need(component==member_wire99(outer,'installed_recovery'),
         'SAVED_M98_COMPONENT_IS_ACTUAL_OUTER_MEMBER_BYTES')
    result=promotion99(loads(outer),bundle['context']['preaction_case'],bundle['preaction_preimage'],
        bundle['old'],bundle['helper'],expected['whole_continuation_original_ref'],component_ref)
    need(result['installed_timeout_recovery']==expected['installed_timeout_recovery'],
         'SAME_CLOSED99_COMPONENT_RECOVERY_BINDINGS')
    bundle['old'].saved_recovery(expected['installed_timeout_recovery'],read_ref)
    return loads(outer),result

def recovered_current99(value, expected, policy, bundle, read_ref):
    """Account typed ancestors, then use the unchanged ordinary98 predicates."""
    saved,summary=saved99(expected,bundle,read_ref)
    closed(value,'schema observed_at installed_recovery preaction_dispositions',
           'WHOLE99_CURRENT_CONTINUATION_AND_ALL_TYPED_ORIGINALS')
    need(value['schema']==saved['schema'] and value['preaction_dispositions']==saved['preaction_dispositions'],
         'ALL99_IMMUTABLE_RECEIPTS_AND_EXPLICIT_SUCCESSOR_ROWS_RETAINED')
    current=value['installed_recovery'];before=saved['installed_recovery']
    closed(current,' '.join(before)+' same_epoch_lineage','WHOLE_CURRENT99_M98_COMPONENT_AND_LINEAGE')
    chain=chain99(value['preaction_dispositions'],bundle['context']['preaction_case'],current,
                  bundle['preaction_preimage'],bundle['helper'])
    line=current['same_epoch_lineage']
    old=bundle['old']
    old.closed(line,'schema anchor_job_id anchor_run_id anchor_created_at jobs_wire job_count job_ids runs_wire run_count run_ids vm_grant_changes_wire vm_grant_change_count',
               'CLOSED99_UNFILTERED_ORIGINAL_LINEAGE12')
    jobs=loads(line['jobs_wire']);runs=loads(line['runs_wire'])
    need(type(jobs)is list and type(runs)is list and type(line['job_count'])is int
         and type(line['run_count'])is int and len(jobs)==line['job_count']<=512
         and len(runs)==line['run_count']<=512
         and [j['id']for j in jobs]==line['job_ids'] and [w['id']for w in runs]==line['run_ids']
         and len({j['id']for j in jobs})==len(jobs) and len({w['id']for w in runs})==len(runs),
         'EXACT99_COMPLETE_UNFILTERED_LINEAGE_COUNTS_AND_IDS')
    typed={x['job']['id']:x for x in value['preaction_dispositions']}
    typed_runs={x['run']['id']:x for x in value['preaction_dispositions']}
    need(set(typed)==set(chain['preaction_job_ids']),'ONLY_AUTHENTICATED99_TYPED_ANCESTORS')
    for j in jobs:
        if j['id']in typed:need(j==typed[j['id']]['job'],'EXACT99_LINEAGE_TYPED_JOB_WHOLE_ROW')
    for w in runs:
        if w['id']in typed_runs:need(w==typed_runs[w['id']]['run'],'EXACT99_LINEAGE_TYPED_RUN_WHOLE_ROW')
    # This is an explicit derived pure validation view, not an original wire.
    # Every omitted pair above is retained and authenticated in the actual
    # whole outer snapshot and its six original receipt domains.
    remaining_jobs=[j for j in jobs if j['id']not in typed]
    remaining_runs=[w for w in runs if w['id']not in typed_runs]
    projection=copy.deepcopy(current);derived=projection['same_epoch_lineage']
    derived.update(jobs_wire=wire(remaining_jobs).decode(),job_count=len(remaining_jobs),
        job_ids=[j['id']for j in remaining_jobs],runs_wire=wire(remaining_runs).decode(),
        run_count=len(remaining_runs),run_ids=[w['id']for w in remaining_runs])
    ordinary=old.recovered_current(projection,expected['installed_timeout_recovery'],policy,read_ref)
    return {**ordinary,'preaction_chain':chain,'authenticated_typed_ancestor_count':len(typed),
            'unfiltered_lineage_job_count':len(jobs),'unfiltered_lineage_run_count':len(runs),
            'ordinary_predicate_projection_is_derived':True,
            'whole_continuation_original_ref':expected['whole_continuation_original_ref']}

def from_baseline_current99(value,expected,baseline,bundle,read_ref):
    v=value['installed_recovery'];current=loads(v['current_intent_wire'])
    slots=[{**{k:x['row'][k]for k in('slot','resource_id','namespace','environment','domain','dimension')},
            'slot_record_sha256':sha(x['slot_record_wire'].encode())}for x in v['current_slots']]
    need(sha(wire(slots))==baseline['owned_slot_roster_sha256']
         and sorted(x['resource_id']for x in slots)==baseline['native_resource_ids']
         and sha(v['current_intent_wire'].encode())==baseline['intent_sha256']
         and baseline['policy_id']==current['policy_id']
         and baseline['policy_checksum']==current['policy_checksum'],'EXACT99_CURRENT_BASELINE_FULL_ORIGINALS')
    identity={'generation':current['generation'],'fence':current['fencing_token'],'phase':current['phase'],
        'policy_id':current['policy_id'],'policy_checksum':current['policy_checksum'],
        'retirement_forward':current.get('retirement_forward'),'intent_sha256':baseline['intent_sha256']}
    return recovered_current99(value,expected,{'at':baseline['observed_at_pg'],'owned_slots':slots,
        'intent_identity':[identity]},bundle,read_ref)

def continuation_sql99(old, expected=None, read_ref=None):
    installed_sql=old.RECOVERED_G44_SQL
    if expected is not None:
        need(callable(read_ref),'SAVED99_READER_REQUIRED_FOR_FIXED_READINESS_LINEAGE')
        installed_sql=old.recovery_sql(expected['installed_timeout_recovery'],read_ref)
    return ("WITH installed(value) AS ("+installed_sql+"), proofs AS MATERIALIZED ("
        "SELECT jsonb_build_object('row',to_jsonb(d),'predicate_valid',public.preaction_failed_plan_valid("
        "d.original_record,d.original_dispatch_wire,d.original_run_wire,d.original_intent_wire,d.members_wire,d.evidence_wire),"
        "'job',to_jsonb(j),'run',to_jsonb(w),'successor_job',to_jsonb(s),'successor_run',to_jsonb(sw)) AS v,d.recorded_at,d.id "
        "FROM public.capacity_dispatch_preaction_plan_dispositions d JOIN public.capacity_dispatch_jobs j ON j.id=d.job_id "
        "JOIN public.workflow_runs w ON w.id=d.run_id JOIN public.capacity_dispatch_jobs s ON s.id=d.successor_job_id "
        "JOIN public.workflow_runs sw ON sw.id=d.successor_run_id CROSS JOIN installed x "
        "WHERE d.original_record->>'root_anchor_id'=x.value#>>'{disposition,id}') "
        "SELECT jsonb_build_object('schema','recovered_preaction_plan_continuation_v1','observed_at',clock_timestamp(),"
        "'installed_recovery',(SELECT value FROM installed),'preaction_dispositions',"
        "(SELECT coalesce(jsonb_agg(v ORDER BY recorded_at,id),'[]'::jsonb)FROM proofs))")

def policy_sql_current99(original_e70,current_catalog_sql,expected,bundle,read_ref):
    saved99(expected,bundle,read_ref)
    return ('WITH ordinary AS ('+bundle['old'].e70_sql(original_e70)+'), current99 AS ('+current_catalog_sql
        +'), continuation99 AS ('+continuation_sql99(bundle['old'],expected,read_ref)
        +") SELECT (SELECT * FROM ordinary)::jsonb || jsonb_build_object('schema99_catalog',(SELECT * FROM current99),"
        +"'preaction_continuation_recovery',(SELECT * FROM continuation99))")
