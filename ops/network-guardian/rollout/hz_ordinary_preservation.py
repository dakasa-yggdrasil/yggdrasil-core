"""Pure Source proof for the fixed current HZ epoch; no I/O or action entrypoint.

The owning qualified caller supplies its existing bounded private reader. These
functions preserve genuine complete originals and grant no provider authority.
"""
import datetime
import hashlib
import json
from pathlib import Path
import re

SOURCE_BOUND=False
QUALIFIED_SOURCE=None
CAP=16<<20
KNOWN_BASELINE_SHA='eb133e4d78be2ac29040bed388b6a95fc0cd261521010c92778e5563b129914e'
KNOWN_ROOT_SHA='a1b657b53f847f27cb047499f21e32e5bc627fe262c9c48c4e921ed921e5284b'
FIXED_CURRENT_SQL_SHA='3de7311f0ab1fe56e6eb1e5f4c0c18d7dff1d73dab463c750ca504f97eec54ff'

class Hold(RuntimeError):pass

def need(condition,reason):
    if not condition:raise Hold(reason)

def sha(raw):return hashlib.sha256(raw).hexdigest()


def same(left,right):
    return json.dumps(left,sort_keys=True,separators=(',',':'),allow_nan=False)==json.dumps(right,sort_keys=True,separators=(',',':'),allow_nan=False)

def closed(value,keys,reason):
    need(type(value) is dict and set(value)==set(keys.split()),reason)

def loads(raw):
    def unique(rows):
        out={}
        for key,value in rows:
            need(key not in out,'NO_DUPLICATE_HZ_ORIGINAL_KEY');out[key]=value
        return out
    return json.loads(raw,object_pairs_hook=unique,parse_constant=lambda _:(_ for _ in ()).throw(Hold('FINITE_HZ_ORIGINAL_JSON')))

def stamp_ns(value):
    need(type(value) is str, 'ORIGINAL_TYPED_TIMESTAMP')
    match = re.fullmatch(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?(Z|[+-](?:[01]\d|2[0-3]):[0-5]\d)', value)
    need(match is not None, 'ORIGINAL_RFC3339_NANO_TIMEZONE')
    base, fraction, zone = match.groups()
    at = datetime.datetime.fromisoformat(base+('+00:00' if zone == 'Z' else zone))
    delta = at-datetime.datetime(1970,1,1,tzinfo=datetime.timezone.utc)
    return (delta.days*86400+delta.seconds)*1000000000+int((fraction or '').ljust(9,'0') or '0')


HZ_CURRENT_SQL = "WITH\n current_intent AS MATERIALIZED (SELECT * FROM public.capacity_intents WHERE namespace='dakasa-production' AND environment='production' AND domain='notify' AND dimension='original_notify_hetzner_vm_members'),\n slots AS MATERIALIZED (SELECT * FROM public.capacity_resource_slots WHERE namespace='dakasa-production' AND environment='production' AND domain='notify' AND dimension='original_notify_hetzner_vm_members'),\n grants AS MATERIALIZED (SELECT * FROM public.capacity_mutation_grants WHERE namespace='dakasa-production' AND environment='production' AND domain='notify' AND dimension='original_notify_hetzner_vm_members'),\n members AS MATERIALIZED (\n SELECT p.id FROM public.capacity_vm_provisioning_preregistrations p\n JOIN grants g ON g.id=p.create_grant_id\n JOIN public.capacity_guest_original_create_witnesses w ON w.preregistration_id=p.id\n WHERE w.original_record->'tuple'->>'resource_id'='174243510')\nSELECT jsonb_build_object(\n 'schema','Root_HZ_current_full_records_and_immutable_S1_origins_v1',\n 'observed_at',clock_timestamp(),'window_lo','2026-11-11T18:00:24Z','window_hi','2026-11-11T18:16:24Z',\n 'expected',jsonb_build_object('generation',10,'fence',24,'phase','promoted','policy_id','11f93535-0e01-4cb0-8f3b-a8fb7c14c93d','policy_checksum','721cf2f748f28bfea44503f148618b1f0b9ba3146c23699ec7cd4d11c167354f','resource_id','174243510'),\n 'intent',COALESCE((SELECT jsonb_agg(jsonb_build_object('row_wire',row_to_json(i)::text,'intent_text',i.intent::text,'intent_sha256',encode(sha256(convert_to(i.intent::text,'UTF8')),'hex')) ORDER BY i.namespace,i.dimension)FROM current_intent i),'[]'::jsonb),\n 'slots',COALESCE((SELECT jsonb_agg(jsonb_build_object('row_wire',row_to_json(s)::text,'slot_record_text',s.slot_record::text,'slot_record_sha256',encode(sha256(convert_to(s.slot_record::text,'UTF8')),'hex')) ORDER BY s.slot,s.resource_id)FROM slots s),'[]'::jsonb),\n 'grants_all_states',COALESCE((SELECT jsonb_agg(jsonb_build_object('row_wire',row_to_json(g)::text,'grant_record_text',g.grant_record::text) ORDER BY g.id)FROM grants g),'[]'::jsonb),\n 'preregistrations',COALESCE((SELECT jsonb_agg(jsonb_build_object('row_wire',row_to_json(p)::text,'original_wire_sha256',encode(sha256(p.original_wire),'hex'),'binding_wire_sha256',encode(sha256(p.binding_wire),'hex'))ORDER BY p.id)FROM public.capacity_vm_provisioning_preregistrations p JOIN members m ON m.id=p.id),'[]'::jsonb),\n 'witnesses',COALESCE((SELECT jsonb_agg(jsonb_build_object('row_wire',row_to_json(w)::text,'original_wire_sha256',encode(sha256(w.original_wire),'hex'))ORDER BY w.preregistration_id)FROM public.capacity_guest_original_create_witnesses w JOIN members m ON m.id=w.preregistration_id),'[]'::jsonb),\n 'enrollments',COALESCE((SELECT jsonb_agg(jsonb_build_object('row_wire',row_to_json(e)::text,'registration_wire_sha256',encode(sha256(e.registration_wire),'hex'),'receipt_wire_sha256',encode(sha256(e.receipt_wire),'hex'))ORDER BY e.preregistration_id)FROM public.capacity_vm_original_enrollments e JOIN members m ON m.id=e.preregistration_id),'[]'::jsonb),\n 'installations',COALESCE((SELECT jsonb_agg(jsonb_build_object('row_wire',row_to_json(i)::text,'original_wire_sha256',encode(sha256(i.original_wire),'hex'))ORDER BY i.preregistration_id)FROM public.capacity_guest_original_installations i JOIN members m ON m.id=i.preregistration_id),'[]'::jsonb))\n"

def preserve_full(baseline,current,e70):
    keys=set(('schema','observed_at','window_lo','window_hi','expected','intent','slots',
              'grants_all_states','preregistrations','witnesses','enrollments','installations'))
    need(type(baseline)is dict and type(current)is dict and set(baseline)==set(current)==keys,
         'whole fixed current HZ twelve-field original')
    need(baseline['schema']==current['schema']=='Root_HZ_current_full_records_and_immutable_S1_origins_v1'
         and same(baseline['expected'],current['expected']),'same Root-reviewed HZ current query expectations')
    for key in('grants_all_states','preregistrations','witnesses','enrollments','installations'):
        need(type(current[key])is list and same(current[key],baseline[key]),
             'all complete current HZ '+key+' originals unchanged')
    need(all(len(current[key])==1 for key in('preregistrations','witnesses','enrollments','installations')),
         'one actual S1 immutable origin set')
    need(type(current['intent'])is list and len(current['intent'])==len(baseline['intent'])==1,
         'one actual whole HZ intent')
    old_i,new_i=baseline['intent'][0],current['intent'][0]
    for item in(old_i,new_i):
        need(type(item)is dict and set(item)=={'row_wire','intent_text','intent_sha256'}
             and sha(item['intent_text'].encode())==item['intent_sha256'],'complete HZ intent wire and PG text SHA')
    old_row,new_row=loads(old_i['row_wire']),loads(new_i['row_wire'])
    old_intent,new_intent=loads(old_i['intent_text']),loads(new_i['intent_text'])
    need(same(old_row['intent'],old_intent) and same(new_row['intent'],new_intent),'whole HZ row intent equals original PG token')
    need(same({k:v for k,v in old_row.items()if k not in('intent','updated_at')},
         {k:v for k,v in new_row.items()if k not in('intent','updated_at')}),
         'all fixed HZ intent table identity columns')
    need(same({k:v for k,v in old_intent.items()if k not in('assessment','decision','updated_at')},
         {k:v for k,v in new_intent.items()if k not in('assessment','decision','updated_at')}),
         'full HZ epoch lease executor policy identity fixed')
    need(stamp_ns(new_row['updated_at'])>=stamp_ns(old_row['updated_at'])
         and stamp_ns(new_intent['updated_at'])>=stamp_ns(old_intent['updated_at']),
         'ordinary HZ intent observation timestamps do not go backwards')
    need(new_i['intent_sha256']==e70['intent_identity'][0]['intent_sha256'],
         'hot E70 intent SHA joins full freshly captured HZ intent')
    need(type(current['slots'])is list and len(current['slots'])==len(baseline['slots']),
         'all active and inactive HZ slot rows retained')
    selected=0
    for old,new in zip(baseline['slots'],current['slots']):
        need(type(old)is dict and type(new)is dict
             and set(old)==set(new)=={'row_wire','slot_record_text','slot_record_sha256'},
             'whole current HZ slot original')
        old_row,new_row=loads(old['row_wire']),loads(new['row_wire'])
        old_record,new_record=loads(old['slot_record_text']),loads(new['slot_record_text'])
        need(same(old_row['slot_record'],old_record) and same(new_row['slot_record'],new_record)
             and sha(old['slot_record_text'].encode())==old['slot_record_sha256']
             and sha(new['slot_record_text'].encode())==new['slot_record_sha256'],
             'whole HZ slot row record equals exact PG token and SHA')
        active=old_row['resource_id']=='174243510'and old_row['slot']==1
        if not active:
            need(same(new,old),'inactive tombstone HZ slot whole original unchanged')
            continue
        selected+=1
        need(same({k:v for k,v in old_row.items()if k not in('slot_record','revision','updated_at')},
             {k:v for k,v in new_row.items()if k not in('slot_record','revision','updated_at')}),
             'full HZ physical slot table tuple fixed')
        need(same({k:v for k,v in old_record.items()if k not in('observed_at','receipt_ref')},
             {k:v for k,v in new_record.items()if k not in('observed_at','receipt_ref')}),
             'full HZ resource birth CREATE preregistration witness enrollment installation tuple fixed')
        need(type(old_row['revision'])is int and type(new_row['revision'])is int
             and new_row['revision']>=old_row['revision']
             and stamp_ns(new_row['updated_at'])>=stamp_ns(old_row['updated_at'])
             and stamp_ns(new_record['observed_at'])>=stamp_ns(old_record['observed_at']),
             'ordinary HZ slot observation and revision do not go backwards')
        need(new['slot_record_sha256']==e70['owned_slots'][0]['slot_record_sha256'],
             'hot E70 slot SHA joins full freshly captured HZ slot')
    need(selected==1 and len(e70['owned_slots'])==1,'one actual active S1 within full retained HZ roster')
    return {'fresh_intent_sha256':new_i['intent_sha256'],
            'all_slots':len(current['slots']),'all_grants':len(current['grants_all_states']),
            'immutable_origin_sets':1,'all_original_arrays_preserved':True}


def query(ordinary_sql):
    need(type(ordinary_sql) is str and ordinary_sql.strip(), 'EXACT99_EXISTING_E70_HZ_QUERY')
    body=ordinary_sql.strip().removesuffix(';')
    return ('WITH ordinary AS MATERIALIZED ('+body+'), current_full AS MATERIALIZED ('
            +HZ_CURRENT_SQL.strip().removesuffix(';')+") SELECT jsonb_build_object('ordinary',(SELECT * FROM ordinary),'current',(SELECT * FROM current_full))")


def validate_current_full(value,e70):
    # This validates the first fresh baseline too; the expected envelope alone
    # is never substituted for the actual current intent/physical records.
    preserve_full(value,value,e70)
    expected={'generation':10,'fence':24,'phase':'promoted',
        'policy_id':'11f93535-0e01-4cb0-8f3b-a8fb7c14c93d',
        'policy_checksum':'721cf2f748f28bfea44503f148618b1f0b9ba3146c23699ec7cd4d11c167354f',
        'resource_id':'174243510'}
    need(same(value['expected'],expected) and len(value['slots'])==2
         and len(value['grants_all_states'])==10, 'EXACT99_SAME_HZ_G10_F24_TWO_SLOTS_TEN_GRANTS')
    row=loads(value['intent'][0]['row_wire']);intent=loads(value['intent'][0]['intent_text'])
    scope={'namespace':'dakasa-production','environment':'production','domain':'notify',
           'dimension':'original_notify_hetzner_vm_members'}
    need(all(row.get(k)==v and intent.get(k)==v for k,v in scope.items())
         and intent.get('generation')==10 and type(intent.get('generation')) is int
         and intent.get('fencing_token')==24 and type(intent.get('fencing_token')) is int
         and intent.get('phase')=='promoted' and intent.get('policy_id')==expected['policy_id']
         and intent.get('policy_checksum')==expected['policy_checksum'], 'EXACT99_ACTUAL_HZ_INTENT_NOT_ONLY_EXPECTED_ENVELOPE')
    active=[]
    for saved in value['slots']:
        slot=loads(saved['row_wire'])
        if slot.get('resource_id')=='174243510' and slot.get('slot')==1:active.append(slot)
    need(len(active)==1 and all(active[0].get(k)==v for k,v in scope.items()), 'EXACT99_ACTUAL_HZ_S1_SCOPE')
    record=active[0]['slot_record']
    need(record.get('tombstone') is False and record.get('resource_id')=='174243510'
         and stamp_ns(record.get('resource_created_at'))==stamp_ns('2026-11-03T01:40:09Z')
         and record.get('desired_spec_sha256')=='0f90e29d6a426866194811b413eb0738fe40b66fedd39d82482e2ca4ddcdc7cc',
         'EXACT99_EXISTING_HZ_S1_BIRTH_SPEC_AND_PHYSICAL_IDENTITY')

def original(ref,reader):
    closed(ref,'path sha256','CLOSED_HZ_ORIGINAL_REFERENCE')
    need(type(ref['path']) is str and Path(ref['path']).is_absolute() and '..' not in Path(ref['path']).parts
         and type(ref['sha256']) is str and re.fullmatch('[a-f0-9]{64}',ref['sha256']) is not None
         and ref['sha256']!='0'*64,'ABSOLUTE_HZ_WHOLE_ORIGINAL_REFERENCE')
    raw=reader(ref)
    need(type(raw) is bytes and 0<len(raw)<=CAP and sha(raw)==ref['sha256'],'WHOLE_HZ_ORIGINAL_REF_BYTES_NOT_HASH_RECONSTRUCTION')
    return raw


def inputs(context,read_ref):
    closed(context,'helper_source_ref fixed_current_sql_ref known_baseline_ref known_root_ref policy_state_full_ref',
           'CLOSED5_KNOWN_HZ_PRESERVATION_CONTEXT')
    # The caller authenticates helper_source_ref before loading these pure defs.
    closed(context['helper_source_ref'],'path sha256','CLOSED_HZ_HELPER_SOURCE_REFERENCE')
    need(context['known_baseline_ref']['sha256']==KNOWN_BASELINE_SHA
         and context['known_root_ref']['sha256']==KNOWN_ROOT_SHA
         and context['fixed_current_sql_ref']['sha256']==FIXED_CURRENT_SQL_SHA,
         'GENUINE_ACCEPTED_HZ_CURRENT_BASELINE_AND_ROOT_REVIEW')
    root=loads(original(context['known_root_ref'],read_ref))
    need(type(root) is dict and len(root)>1,'WHOLE_ACCEPTED_HZ_ROOT_RECORD')
    baseline=loads(original(context['known_baseline_ref'],read_ref))
    policy_full=loads(original(context['policy_state_full_ref'],read_ref))
    sql=original(context['fixed_current_sql_ref'],read_ref)
    need(sql==HZ_CURRENT_SQL.encode(),'EXACT_ACCEPTED_HZ_CURRENT_SQL_BYTES')
    return {'known_baseline':baseline,'policy_state_full':policy_full,'fixed_current_sql':sql.decode()}


def same_e70(before,current,before_full,current_full):
    keys='intent_identity owned_slots active_policies policy_catalog_wire'
    closed(before,keys,'CLOSED_HZ_BEFORE_E70_PROJECTION4');closed(current,keys,'CLOSED_HZ_CURRENT_E70_PROJECTION4')
    validate_current_full(before_full,before);validate_current_full(current_full,current)
    preserve_full(before_full,current_full,current)
    need(stamp_ns(current_full['observed_at'])>=stamp_ns(before_full['observed_at']),'MONOTONIC99_FRESH_HZ_READ_OBSERVATIONS')
    need(same(current['active_policies'],before['active_policies']) and current['policy_catalog_wire']==before['policy_catalog_wire'],
         'ENTIRE99_HZ_ACTIVE_POLICIES_AND_CATALOG_UNCHANGED')
    for role,field in (('intent_identity','intent_sha256'),('owned_slots','slot_record_sha256')):
        need(type(before[role]) is list and type(current[role]) is list and len(before[role])==len(current[role])==1
             and type(before[role][0]) is dict and type(current[role][0]) is dict
             and field in before[role][0] and field in current[role][0]
             and same({k:v for k,v in before[role][0].items() if k!=field},
                {k:v for k,v in current[role][0].items() if k!=field}),'ENTIRE99_HZ_IDENTITY_EXCEPT_JOINED_OBSERVATION_SHA_'+role)
    return True


def same_database(before,current):
    closed(before,'aws hetzner','CLOSED99_BEFORE_PROVIDER_SNAPSHOT')
    closed(current,'aws hetzner','CLOSED99_CURRENT_PROVIDER_SNAPSHOT')
    need(same(current['aws'],before['aws']),'ENTIRE99_AWS_PROVIDER_PREIMAGE_UNCHANGED')
    old,new=before['hetzner'],current['hetzner']
    keys='jobs_busy runs_busy forward_unreturned_reads live_unreturned_canaries intent_count intent_busy pending_authority forward_markers intent_identity owned_slots active_policies policy_catalog_wire hz_current_full'
    closed(old,keys,'CLOSED99_OLD_HZ_FULL_SNAPSHOT');closed(new,keys,'CLOSED99_NEW_HZ_FULL_SNAPSHOT')
    need(same({k:v for k,v in old.items() if k not in ('intent_identity','owned_slots','active_policies','policy_catalog_wire','hz_current_full')},
         {k:v for k,v in new.items() if k not in ('intent_identity','owned_slots','active_policies','policy_catalog_wire','hz_current_full')}),
         'ENTIRE99_HZ_BUSY_LANES_UNCHANGED')
    projected=lambda value:{k:value[k] for k in ('intent_identity','owned_slots','active_policies','policy_catalog_wire')}
    return same_e70(projected(old),projected(new),old['hz_current_full'],new['hz_current_full'])
