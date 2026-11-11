"""Pure schema99 catalog DATA; no operator, network, SQL execution or approval.

base_select is the independently authenticated existing catalog98_select callable.
CI originals and Source SQL are whole custody inputs, never reconstructed deparse.
"""
import copy
import datetime
import hashlib
import json
import re
from pathlib import PurePosixPath

SOURCE_BOUND = False
QUALIFIED_SOURCE = None
M99 = 'bbfecef9888c27eacda8c732bcfe28e606d566decadf56ecc65acfb687020a41'
ROOT98_SHA = 'a27138d1f2e9a2b9eb9db916f7bd658040f4621a42bce9bcab602f6667f2a947'
CURRENT_CORE9 = '9f0266de7a2982352b7ff8fd627e73ceba12c896'
CAP = 8 * 1024 * 1024
TABLE99 = 'capacity_dispatch_preaction_plan_dispositions'
LOOKUP99 = 'capacity_dispatch_failed_workflow_returned_idx'
OLD8 = 'catalog90 catalog91 columns90_91 functions93 index92_definition index92_valid schema94 schema98'
FUNCTIONS99 = (
 'preaction_failed_plan_timestamp_ns', 'preaction_failed_plan_graph_valid',
 'preaction_failed_plan_effect_scan', 'preaction_failed_plan_effect_scan_tolerable',
 'preaction_failed_plan_valid', 'guard_preaction_failed_plan_insert',
 'check_preaction_failed_plan_transition', 'guard_preaction_failed_plan_job_insert',
 'immutable_preaction_failed_plan', 'guard_preaction_failed_plan_workflow',
 'require_preaction_failed_plan_links', 'guard_capacity_dispatch_job')
FUNCTIONS98_RETAINED = (
 'installed_provision_timeout_valid', 'guard_installed_provision_timeout_insert',
 'check_installed_provision_timeout_transition', 'guard_capacity_dispatch_job',
 'guard_installed_provision_timeout_job_insert', 'immutable_installed_provision_timeout',
 'guard_installed_provision_timeout_workflow', 'require_installed_provision_timeout_links',
 'guard_installed_timeout_origin')
TABLES98_RETAINED = (
 'capacity_dispatch_jobs', 'capacity_dispatch_installed_provision_timeout_dispositions',
 'capacity_guest_retirement_forwards', 'capacity_guest_retirement_forward_reads',
 'capacity_intents', 'capacity_guest_authority_issues', 'workflow_runs')
OLD_CHECKS99 = ('capacity_dispatch_jobs_lifecycle_v10_check', 'capacity_dispatch_jobs_state_v10_check')
NEW_CHECKS99 = ('capacity_dispatch_jobs_lifecycle_v11_check', 'capacity_dispatch_jobs_state_v11_check')
TRIGGERS99 = (
 ('capacity_dispatch_preaction_plan_dispositions','preaction_failed_plan_insert'),
 ('capacity_dispatch_preaction_plan_dispositions','preaction_failed_plan_immutable'),
 ('capacity_dispatch_preaction_plan_dispositions','preaction_failed_plan_complete_links'),
 ('capacity_dispatch_jobs','preaction_failed_plan_job_insert'),
 ('workflow_runs','preaction_failed_plan_workflow_immutable'))
COLUMNS99 = (
 ('id','uuid'),('job_id','uuid'),('run_id','uuid'),('successor_job_id','uuid'),('successor_run_id','uuid'),
 ('original_record','jsonb'),('original_wire','bytea'),('original_dispatch_wire','bytea'),
 ('original_run_wire','bytea'),('original_intent_wire','bytea'),('members_wire','bytea'),
 ('evidence_wire','bytea'),('recorded_at','timestamp with time zone'))


def need99(condition, reason):
    if not condition:
        raise RuntimeError(reason)


def closed99(value, keys, reason):
    need99(type(value) is dict and set(value) == set(keys.split()), reason)
    return value


def same99(left, right):
    return json.dumps(left,sort_keys=True,separators=(',',':'),allow_nan=False) == json.dumps(
        right,sort_keys=True,separators=(',',':'),allow_nan=False)


def sha99(raw):
    need99(type(raw) is bytes,'WHOLE99_BYTES')
    return hashlib.sha256(raw).hexdigest()


def loads99(raw):
    def pairs(items):
        result = {}
        for key,value in items:
            need99(key not in result,'NO_DUPLICATE99_JSON_KEY')
            result[key] = value
        return result
    def reject(value):
        raise RuntimeError('NO_NONFINITE99_JSON_'+value)
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=reject)


def digest99(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{64}',value) is not None and value != '0'*64


def source99(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{40}',value) is not None and value != '0'*40


def original99(ref, read_ref, with_size=False):
    closed99(ref,'path sha256 bytes' if with_size else 'path sha256','CLOSED99_ORIGINAL_REF')
    need99(type(ref['path']) is str and PurePosixPath(ref['path']).is_absolute()
           and '..' not in PurePosixPath(ref['path']).parts and digest99(ref['sha256']),'ABSOLUTE99_WHOLE_REF')
    raw = read_ref(ref)
    need99(type(raw) is bytes and 1 < len(raw) <= CAP and sha99(raw) == ref['sha256'],'COMPLETE99_ORIGINAL')
    if with_size:
        need99(type(ref['bytes']) is int and ref['bytes'] == len(raw),'ACTUAL99_ORIGINAL_SIZE')
    return raw


def projection98_99(value):
    legacy,supplement = value['legacy'],value['supplement']
    result = {'catalog90':legacy['catalog90'],'catalog91':legacy['catalog91'],
              **{k:supplement[k] for k in ('columns90_91','functions93','index92_definition','index92_valid')},
              'schema94':value['schema94'],'schema98':value['schema98']}
    closed99(result,OLD8,'WHOLE99_PREDECESSOR8')
    return result


def catalog99_projection(value):
    supplement99(value['schema99'])
    return {**projection98_99(value),'schema99':value['schema99']}


def rows99(rows,kind,full=False):
    shapes = {
      'functions':'name arguments definition',
      'constraints':'table name kind validated definition',
      'triggers':'table name enabled definition',
      'columns':'table name number type not_null has_default',
      'indexes':'table name definition predicate expressions valid ready live primary unique keys key_count method'}
    need99(type(rows) is list,'COMPLETE99_'+kind)
    keys=[]
    for row in rows:
        closed99(row,shapes[kind],'CLOSED99_'+kind+'_ROW')
        need99(type(row['name']) is str and row['name'],'NAMED99_ROW')
        key = (row['name'],row['arguments']) if kind=='functions' else (row['table'],row['name'])
        keys.append(key)
        if kind in ('functions','constraints','triggers','indexes'):
            need99(type(row['definition']) is str and row['definition'],'WHOLE99_PG_DEFINITION')
        if kind=='constraints':
            need99(row['validated'] is True and row['kind'] in ('c','p','u','f','x','t'),'VALIDATED99_CONSTRAINT')
        if kind=='triggers':
            need99(row['enabled']=='O','ENABLED99_TRIGGER')
        if kind=='columns':
            need99(type(row['number']) is int and row['number']>0 and type(row['type']) is str
                   and type(row['not_null']) is bool and type(row['has_default']) is bool,'TYPED99_COLUMN')
        if kind=='indexes':
            need99(all(type(row[k]) is bool for k in ('valid','ready','live','primary','unique'))
                   and all(row[k] is True for k in ('valid','ready','live'))
                   and type(row['key_count']) is int and row['key_count']>0
                   and type(row['keys']) is str and type(row['method']) is str,'VALID99_TYPED_INDEX')
    need99(len(keys)==len(set(keys)),'NO_DUPLICATE99_'+kind)
    ordering = (lambda r:(r['name'],r['arguments'])) if kind=='functions' else (
        (lambda r:(r['table'],r['number'])) if kind=='columns' else (lambda r:(r['table'],r['name'])))
    need99(rows==sorted(rows,key=ordering),'DECLARED99_QUERY_ORDER_'+kind)
    return rows


def supplement99(value):
    closed99(value,'functions constraints triggers columns indexes','CLOSED99_FIVE_CATALOG_ARRAYS')
    for kind,rows in value.items():
        rows99(rows,kind)
    return value


def selected99(catalog):
    return {
      'functions':[r for r in catalog['functions'] if r['name'] in FUNCTIONS99],
      'constraints':[r for r in catalog['constraints'] if r['table']==TABLE99],
      'triggers':[r for r in catalog['triggers'] if (r['table'],r['name']) in TRIGGERS99],
      'columns':[r for r in catalog['columns'] if r['table']==TABLE99],
      'indexes':[r for r in catalog['indexes'] if r['table']==TABLE99 or r['name']==LOOKUP99]}


def retained98(catalog):
    return {
      'functions':[r for r in catalog['functions'] if r['name'] in FUNCTIONS98_RETAINED],
      'constraints':[r for r in catalog['constraints'] if r['table'] in TABLES98_RETAINED],
      'triggers':[r for r in catalog['triggers'] if r['table'] in TABLES98_RETAINED],
      'columns':[{k:r[k] for k in ('table','name','number','type','not_null')}
                 for r in catalog['columns'] if r['table'] in ('capacity_dispatch_jobs',
                     'capacity_dispatch_installed_provision_timeout_dispositions')]}


def migration99_functions(sql):
    need99(type(sql) is str and sha99(sql.encode())==M99,'EXACT99_MIGRATION_SOURCE')
    up,down=sql.split('-- +goose Down',1)
    pattern=r'CREATE OR REPLACE FUNCTION public\.([a-z_]+)\((.*?)\)\s*RETURNS\s+(.*?)\s+LANGUAGE\s+(plpgsql|sql)(.*?)\s*AS\s+\$\$(.*?)\$\$;'
    def collect(text):
        result={}
        for name,args,returns,language,options,body in re.findall(pattern,text,re.S):
            need99(name not in result,'ONE99_SOURCE_FUNCTION')
            normalized=re.sub(r'\s+',' ',options.strip())
            utc="timezone='UTC'" in normalized
            options_without_utc=normalized.replace("SET timezone='UTC'",'').strip()
            need99(options_without_utc in ('','STABLE','IMMUTABLE'),'EXACT99_SOURCE_ATTRIBUTES')
            result[name]={'arguments':args,'result':returns.strip(),'language':language,'body':body,
                          'volatility':options_without_utc or 'VOLATILE','utc':utc}
        return result
    result,previous=collect(up),collect(down)
    need99(set(result)==set(FUNCTIONS99) and set(previous)=={'guard_capacity_dispatch_job'},'EXACT99_SOURCE_TWELVE_AND_INVERSE')
    result['guard_capacity_dispatch_job']['prior']=previous['guard_capacity_dispatch_job']
    return result


def pg_function99(row,spec):
    match=re.fullmatch(r'CREATE OR REPLACE FUNCTION public\.([a-z_]+)\((.*?)\)\s+RETURNS\s+(.*?)\s+LANGUAGE\s+(plpgsql|sql)(.*?)\s+AS (\$[A-Za-z_0-9]*\$)(.*?)\6\s*;?\s*',row['definition'],re.S)
    need99(match is not None and match.group(1)==row['name'],'FULL99_PG_FUNCTION_DEPARSE')
    normal=lambda v:re.sub(r'\s+',' ',v.replace('public.','').replace(',',', ')).strip()
    need99(normal(row['arguments'])==normal(spec['arguments'])==normal(match.group(2))
           and normal(match.group(3))==normal(spec['result']) and match.group(4)==spec['language']
           and match.group(7)==spec['body'],'EXACT99_SOURCE_BODY_SIGNATURE_LANGUAGE')
    expected='' if spec['volatility']=='VOLATILE' else spec['volatility']
    if spec['utc']:
        expected+=(' ' if expected else '')+'SET "TimeZone" TO \'UTC\''
    need99(re.sub(r'\s+',' ',match.group(5).strip())==expected,'EXACT99_SOURCE_PG_ATTRIBUTES')


def history99(before_wire,after_wire):
    need99(type(before_wire) is str and type(after_wire) is str,'WHOLE99_HISTORY_WIRES')
    before,after=loads99(before_wire),loads99(after_wire)
    need99(type(before) is list and before and type(after) is list
           and type(before[-1].get('version_id')) is int and before[-1]['version_id']==98
           and before[-1].get('is_applied') is True and len(after)==len(before)+1
           and same99(after[:-1],before) and type(after[-1].get('version_id')) is int
           and after[-1]['version_id']==99 and after[-1].get('is_applied') is True
           and type(after[-1].get('id')) is int and after[-1]['id']>before[-1]['id']
           and not any(r.get('version_id')==99 for r in before),'SOLE99_APPEND_ALL98_ROWS')


def catalog99_expected(before,after):
    """Complete actual CI arrays: exactly Source-owned additions/replacements."""
    for kind in ('functions','constraints','triggers','columns','indexes'):
        rows99(before[kind],kind,True);rows99(after[kind],kind,True)
    key=lambda r:(r['table'],r['name'])
    for kind in ('triggers','columns','indexes'):
        new={key(r):r for r in after[kind]}
        need99(all(same99(r,new.get(key(r))) for r in before[kind]),'ALL99_RETAINED_'+kind)
        added=[r for r in after[kind] if key(r) not in {key(x) for x in before[kind]}]
        expected=selected99(after)[kind]
        need99(same99(added,expected),'EXACT99_ONLY_SOURCE_NEW_'+kind)
    oldc={key(r):r for r in before['constraints']}
    newc={key(r):r for r in after['constraints']}
    for name in OLD_CHECKS99:
        need99(('capacity_dispatch_jobs',name) in oldc and ('capacity_dispatch_jobs',name) not in newc,'EXACT99_REMOVE_V10')
        del oldc[('capacity_dispatch_jobs',name)]
    for name in NEW_CHECKS99:
        need99(('capacity_dispatch_jobs',name) not in oldc and ('capacity_dispatch_jobs',name) in newc,'EXACT99_ADD_V11')
        del newc[('capacity_dispatch_jobs',name)]
    for row in selected99(after)['constraints']:
        need99(key(row) not in oldc,'NEW99_TABLE_NOT_PREEXISTING')
        del newc[key(row)]
    need99(oldc.keys()==newc.keys() and all(same99(oldc[k],newc[k]) for k in oldc),'ALL99_OTHER_CONSTRAINTS_IDENTICAL')
    selected=selected99(after)
    need99(len(selected['triggers'])==5 and {(r['table'],r['name']) for r in selected['triggers']}==set(TRIGGERS99),
           'EXACT99_FIVE_TRIGGER_IDENTITIES')
    need99([(r['name'],r['type']) for r in selected['columns']]==list(COLUMNS99)
           and [r['number'] for r in selected['columns']]==list(range(1,14))
           and all(r['not_null'] is True and r['has_default'] is False for r in selected['columns']),
           'EXACT99_THIRTEEN_COLUMNS_NO_DEFAULTS')
    constraints=selected['constraints']
    need99(len(constraints)==19 and sum(r['kind']=='c' for r in constraints)==9 and sum(r['kind']=='p' for r in constraints)==1
           and sum(r['kind']=='u' for r in constraints)==4 and sum(r['kind']=='f' for r in constraints)==4
           and [r for r in constraints if r['kind']=='t']==[{'table':TABLE99,'name':'preaction_failed_plan_complete_links',
               'kind':'t','validated':True,'definition':'TRIGGER DEFERRABLE INITIALLY DEFERRED'}]
           and sum('DEFERRABLE INITIALLY DEFERRED' in r['definition'] for r in constraints)==3,
           'EXACT99_FIVE_IDENTITIES_FOUR_FK_AND_DEFERRED_LINK_TRIGGER')
    unique=[r for r in selected['indexes'] if r['table']==TABLE99]
    need99(len(unique)==5 and {r['keys'] for r in unique}=={'1','2','3','4','5'}
           and all(r['unique'] is True and r['method']=='btree' and r['key_count']==1
                   and r['predicate'] is None and r['expressions'] is None
                   and r['primary']==(r['keys']=='1') for r in unique),'EXACT99_FIVE_LIVE_UNIQUE_IDENTITIES')
    partial=[r for r in selected['indexes'] if r['name']==LOOKUP99]
    need99(len(partial)==1 and partial[0]['table']=='capacity_dispatch_jobs'
           and partial[0]['unique'] is False and partial[0]['primary'] is False
           and partial[0]['method']=='btree' and partial[0]['key_count']==2
           and partial[0]['keys'].split()[0]=='0' and len(partial[0]['keys'].split())==2
           and type(partial[0]['expressions']) is str and 'workflow' in partial[0]['expressions']
           and 'envelope' in partial[0]['expressions'] and type(partial[0]['predicate']) is str
           and all(x in partial[0]['predicate'] for x in ('returned','failed','returned_at IS NOT NULL','finalization_ack_at IS NOT NULL')),
           'EXACT99_PARTIAL_LOOKUP_TYPED_PREDICATE')
    return selected


def constraint99_definitions(prior98catalog8,carrier,read_ref,expected_source,source_sql):
    closed99(prior98catalog8,OLD8,'WHOLE99_PRIOR98_CATALOG8')
    closed99(carrier,'artifact_ref before98_ref after99_ref','CLOSED99_CI_CARRIER3')
    raw={k:original99(ref,read_ref) for k,ref in carrier.items()}
    artifact=loads99(raw['artifact_ref'])
    closed99(artifact,'schema source_commit postgres_major fixture_only native_authority before98_ref after99_ref migration99_sha256 history_sole99_append old_public_functions_changed new_table_columns new_table_unique_indexes lookup_index all_constraints_validated','ACTUAL99_CI_ARTIFACT14')
    need99(artifact['schema']=='preaction_failed_plan_schema99_pg_catalog_v1'
           and source99(expected_source) and artifact['source_commit']==expected_source
           and type(artifact['postgres_major']) is int and artifact['postgres_major'] in (16,17)
           and artifact['fixture_only'] is True and artifact['native_authority'] is False
           and artifact['migration99_sha256']==M99 and artifact['history_sole99_append'] is True
           and artifact['old_public_functions_changed']==['guard_capacity_dispatch_job']
           and type(artifact['new_table_columns']) is int and artifact['new_table_columns']==13
           and type(artifact['new_table_unique_indexes']) is int and artifact['new_table_unique_indexes']==5
           and artifact['all_constraints_validated'] is True,'QUALIFIED99_SOURCE_FIXTURE_FACTS')
    views={}
    for key in ('before98_ref','after99_ref'):
        ref=artifact[key];closed99(ref,'path sha256 bytes','ACTUAL99_CI_CANONICAL_REF')
        need99(type(ref['path']) is str and PurePosixPath(ref['path']).is_absolute()
               and type(ref['bytes']) is int and ref['bytes']==len(raw[key])
               and ref['sha256']==sha99(raw[key])==carrier[key]['sha256'],'WHOLE99_CI_COPY_NOT_ALIAS')
        value=loads99(raw[key])
        closed99(value,'server_version_num history_wire functions constraints triggers columns indexes','WHOLE99_CI_CATALOG8')
        need99(type(value['server_version_num']) is int
               and value['server_version_num']//10000==artifact['postgres_major'],'ACTUAL99_PG_MAJOR')
        for kind in ('functions','constraints','triggers','columns','indexes'):
            rows99(value[kind],kind,True)
        views[key]=value
    before,after=views['before98_ref'],views['after99_ref']
    need99(before['server_version_num']==after['server_version_num'],'SAME99_CI_SERVER')
    history99(before['history_wire'],after['history_wire'])
    specs=migration99_functions(source_sql)
    selected_before,selected_after=selected99(before),selected99(after)
    need99(len(selected_before['functions'])==1 and selected_before['functions'][0]['name']=='guard_capacity_dispatch_job'
           and len(selected_after['functions'])==12
           and {r['name'] for r in selected_after['functions']}==set(FUNCTIONS99),'EXACT99_SOURCE_FUNCTIONS_NO_OVERLOAD')
    pg_function99(selected_before['functions'][0],specs['guard_capacity_dispatch_job']['prior'])
    for row in selected_after['functions']:
        pg_function99(row,specs[row['name']])
    oldfn={(r['name'],r['arguments']):r for r in before['functions']}
    newfn={(r['name'],r['arguments']):r for r in after['functions']}
    expected=copy.deepcopy(oldfn)
    for row in selected_after['functions']:
        expected[(row['name'],row['arguments'])]=row
    need99(expected.keys()==newfn.keys() and all(same99(expected[k],newfn[k]) for k in expected),'ALL99_OTHER_PUBLIC_FUNCTIONS_UNCHANGED')
    catalog99_expected(before,after)
    need99(same99(prior98catalog8['catalog91']['shared_dispatch_guard'],
                 [{'name':'guard_capacity_dispatch_job','definition':selected_before['functions'][0]['definition']}]),
           'NATIVE98_GUARD_EQUALS_CI_AND_SOURCE_DOWN')
    oldchecks=[{k:r[k] for k in ('name','validated','definition')} for r in before['constraints']
               if r['table']=='capacity_dispatch_jobs' and r['name'] in OLD_CHECKS99]
    need99(len(oldchecks)==2 and same99(prior98catalog8['catalog91']['dispatch_constraints'],oldchecks)
           and same99(prior98catalog8['schema98'],retained98(before)),'WHOLE98_DUPLICATED_GUARD_CHECKS_TRIGGERS_MATCH_CI')
    lookup=next(r for r in selected_after['indexes'] if r['name']==LOOKUP99)
    need99(same99(artifact['lookup_index'],lookup),'ACTUAL99_COMPLETE_LOOKUP_INDEX_ARTIFACT')
    return {'before':selected_before,'after':selected_after,'before98':retained98(before),
            'after98':retained98(after),'source_functions':specs,
            'server_version_num':before['server_version_num'],'source_commit':expected_source}


def structural99(value,defs,before=False):
    closed99(value,'server_version_num table columns indexes','CLOSED99_FRESH_STRUCTURE4')
    need99(type(value['server_version_num']) is int and value['server_version_num']//10000 in (16,17),'FRESH99_SUPPORTED_PG')
    if before:
        need99(value['table'] is None and value['columns']==[] and value['indexes']==[],'PRE99_STRUCTURE_ABSENT')
        return value
    need99(same99(value['table'],{'name':TABLE99,'kind':'r','persistence':'p','replica_identity':'d',
                                'row_security':False,'force_row_security':False}),'FRESH99_ORDINARY_HEAP')
    expected=[{**{k:r[k] for k in ('name','number','type','not_null')},
               'identity':'','generated':'','default':None} for r in defs['after']['columns']]
    need99(same99(value['columns'],expected)
           and same99(value['indexes'],defs['after']['indexes']),'FRESH99_NO_DEFAULTS_AND_COMPLETE_CI_INDEXES')
    return value


def catalog99_delta(prior98catalog8,beforeFull,afterFull,source_functions,defs):
    closed99(prior98catalog8,OLD8,'CLOSED99_IMMUTABLE_PRIOR98')
    need99(same99(projection98_99(beforeFull),prior98catalog8)
           and same99(source_functions,defs['source_functions']),'NATIVE99_WHOLE_BEFORE_AND_SOURCE')
    supplement99(beforeFull['schema99']);supplement99(afterFull['schema99'])
    need99(same99(beforeFull['schema99'],defs['before']) and same99(afterFull['schema99'],defs['after']),
           'WHOLE99_NATIVE_CATALOG_EQUALS_AUTHENTICATED_CI')
    structural99(beforeFull['structural99'],defs,True);structural99(afterFull['structural99'],defs)
    need99(beforeFull['structural99']['server_version_num']==afterFull['structural99']['server_version_num'],
           'SAME99_NATIVE_SERVER')
    expected=copy.deepcopy(prior98catalog8)
    guard=next(r for r in defs['after']['functions'] if r['name']=='guard_capacity_dispatch_job')
    expected['catalog91']['shared_dispatch_guard']=[{'name':guard['name'],'definition':guard['definition']}]
    expected['catalog91']['dispatch_constraints']=[
        {k:r[k] for k in ('name','validated','definition')} for r in defs['after98']['constraints']
        if r['table']=='capacity_dispatch_jobs' and r['name'] in NEW_CHECKS99]
    expected['schema98']=defs['after98']
    need99(len(expected['catalog91']['dispatch_constraints'])==2
           and same99(projection98_99(afterFull),expected)
           and same99(beforeFull['structural98'],afterFull['structural98']),
           'ONLY99_AUTHENTICATED_OLD8_OVERLAPS_ALL_OTHER_BYTES_ARRAYS_EXACT')
    history99(beforeFull['legacy']['complete_history_wire'],afterFull['legacy']['complete_history_wire'])
    result={**expected,'schema99':afterFull['schema99']}
    need99(same99(result,catalog99_projection(afterFull)),'WHOLE99_NINE_KEY_PROJECTION')
    return result


def root99_overlay(rawRoot99,rawRoot98,pins,read_ref):
    need99(digest99(ROOT98_SHA) and sha99(rawRoot98)==ROOT98_SHA,'IMMUTABLE99_ROOT98_WHOLE_ORIGINAL')
    previous,value=loads99(rawRoot98),loads99(rawRoot99)
    closed99(value,'schema reviewed_by_root schema_before schema_after current_core_source current_ops_source business_source amd64_D migration99_sha256 complete_history_sha256 prior98_history_sha256 catalog99_sha256 index92_definition_sha256 catalog90_91_sha256 job_uid pod_uid exit_code single_job_create provider_guest_core_mutations old_records_and_sdk_preserved original_refs','ROOT99_CLOSED21')
    need99(previous['schema']=='root_goose98_installed_provision_timeout_acceptance_v1'
           and previous['reviewed_by_root'] is True and type(previous['schema_after']) is int and previous['schema_after']==98
           and value['schema']=='root_goose99_preaction_failed_plan_acceptance_v1' and value['reviewed_by_root'] is True
           and type(value['schema_before']) is int and value['schema_before']==98
           and type(value['schema_after']) is int and value['schema_after']==99,'ROOT99_SEPARATE_HISTORICAL98')
    need99(value['current_core_source']==CURRENT_CORE9
           and value['current_ops_source']==pins['current_ops_source'] and source99(value['current_ops_source'])
           and value['business_source']==pins['business_source'] and source99(value['business_source'])
           and value['amd64_D']==pins['amd64_D'] and digest99(value['amd64_D']),'ROOT99_HONEST_CORE9_NEW_COMPANION')
    need99(value['migration99_sha256']==M99
           and value['prior98_history_sha256']==previous['complete_history_sha256']==pins['prior98_history_sha256']
           and value['index92_definition_sha256']==previous['index92_definition_sha256']==pins['index92_definition_sha256']
           and all(digest99(value[k]) and value[k]==pins[k] for k in (
               'complete_history_sha256','catalog99_sha256','catalog90_91_sha256')),'ROOT99_WHOLE_HISTORY_AND_CATALOG')
    uuid=lambda v:type(v) is str and re.fullmatch('[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',v) is not None and v!='00000000-0000-0000-0000-000000000000'
    need99(uuid(value['job_uid']) and uuid(value['pod_uid']) and type(value['exit_code']) is int and value['exit_code']==0
           and value['single_job_create'] is True and type(value['provider_guest_core_mutations']) is int
           and value['provider_guest_core_mutations']==0 and value['old_records_and_sdk_preserved'] is True,
           'ROOT99_ONE_JOB_ZERO_PROVIDER_GUEST_CORE_MUTATIONS')
    closed99(value['original_refs'],'migration_result before_catalog after_catalog source_ci qualified_image','ROOT99_FIVE_RAW_ORIGINAL_ROLES')
    for ref in value['original_refs'].values():
        original99(ref,read_ref)
    need99(len({r['sha256'] for r in value['original_refs'].values()})==5,'ROOT99_DISTINCT_WHOLE_ORIGINALS')
    return value

FULL_CATALOG99_SQL = "SELECT jsonb_build_object('server_version_num',current_setting('server_version_num')::int,'history_wire',(SELECT json_agg(row_to_json(g) ORDER BY id)::text FROM public.goose_db_version g),'functions',(SELECT coalesce(jsonb_agg(jsonb_build_object('name',p.proname,'arguments',pg_get_function_identity_arguments(p.oid),'definition',pg_get_functiondef(p.oid)) ORDER BY p.proname,pg_get_function_identity_arguments(p.oid)),'[]'::jsonb) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public' AND p.prokind='f'),'constraints',(SELECT coalesce(jsonb_agg(jsonb_build_object('table',r.relname,'name',c.conname,'kind',c.contype,'validated',c.convalidated,'definition',pg_get_constraintdef(c.oid,false)) ORDER BY r.relname,c.conname),'[]'::jsonb) FROM pg_constraint c JOIN pg_class r ON r.oid=c.conrelid JOIN pg_namespace n ON n.oid=r.relnamespace WHERE n.nspname='public'),'triggers',(SELECT coalesce(jsonb_agg(jsonb_build_object('table',r.relname,'name',g.tgname,'enabled',g.tgenabled,'definition',pg_get_triggerdef(g.oid,false)) ORDER BY r.relname,g.tgname),'[]'::jsonb) FROM pg_trigger g JOIN pg_class r ON r.oid=g.tgrelid JOIN pg_namespace n ON n.oid=r.relnamespace WHERE n.nspname='public' AND NOT g.tgisinternal),'columns',(SELECT coalesce(jsonb_agg(jsonb_build_object('table',r.relname,'name',a.attname,'number',a.attnum,'type',format_type(a.atttypid,a.atttypmod),'not_null',a.attnotnull,'has_default',a.atthasdef) ORDER BY r.relname,a.attnum),'[]'::jsonb) FROM pg_attribute a JOIN pg_class r ON r.oid=a.attrelid JOIN pg_namespace n ON n.oid=r.relnamespace WHERE n.nspname='public' AND r.relkind IN('r','p') AND a.attnum>0 AND NOT a.attisdropped),'indexes',(SELECT coalesce(jsonb_agg(jsonb_build_object('table',r.relname,'name',c.relname,'definition',pg_get_indexdef(x.indexrelid),'predicate',pg_get_expr(x.indpred,x.indrelid),'expressions',pg_get_expr(x.indexprs,x.indrelid),'valid',x.indisvalid,'ready',x.indisready,'live',x.indislive,'primary',x.indisprimary,'unique',x.indisunique,'keys',x.indkey::text,'key_count',x.indnkeyatts,'method',am.amname) ORDER BY r.relname,c.relname),'[]'::jsonb) FROM pg_index x JOIN pg_class r ON r.oid=x.indrelid JOIN pg_class c ON c.oid=x.indexrelid JOIN pg_namespace n ON n.oid=r.relnamespace JOIN pg_am am ON am.oid=c.relam WHERE n.nspname='public'))"
STRUCTURE99_SQL = "SELECT jsonb_build_object(\n'server_version_num',current_setting('server_version_num')::int,\n'table',(SELECT jsonb_build_object('name',c.relname,'kind',c.relkind,'persistence',c.relpersistence,'replica_identity',c.relreplident,'row_security',c.relrowsecurity,'force_row_security',c.relforcerowsecurity) FROM pg_class c WHERE c.oid=to_regclass('public.capacity_dispatch_preaction_plan_dispositions')),\n'columns',(SELECT coalesce(jsonb_agg(jsonb_build_object('name',a.attname,'number',a.attnum,'type',format_type(a.atttypid,a.atttypmod),'not_null',a.attnotnull,'identity',a.attidentity,'generated',a.attgenerated,'default',pg_get_expr(d.adbin,d.adrelid)) ORDER BY a.attnum),'[]'::jsonb) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid=to_regclass('public.capacity_dispatch_preaction_plan_dispositions') AND a.attnum>0 AND NOT a.attisdropped),\n'indexes',(SELECT coalesce(jsonb_agg(x ORDER BY x->>'table',x->>'name'),'[]'::jsonb) FROM jsonb_array_elements((SELECT v->'indexes' FROM complete99))x WHERE x->>'table'='capacity_dispatch_preaction_plan_dispositions' OR x->>'name'='capacity_dispatch_failed_workflow_returned_idx'))"


def catalog99_select(legacy,base_select=None):
    need99(callable(base_select),'AUTHENTICATED98_SELECTOR_REQUIRED')
    sql=base_select(legacy)
    old="c.conname IN('capacity_dispatch_jobs_state_v8_check','capacity_dispatch_jobs_lifecycle_v8_check','capacity_dispatch_jobs_state_v9_check','capacity_dispatch_jobs_lifecycle_v9_check','capacity_dispatch_jobs_state_v10_check','capacity_dispatch_jobs_lifecycle_v10_check')"
    need99(type(sql) is str and sql.count(old)==1,'ONE99_AUTHENTICATED_OLD_DISPATCH_SELECTOR')
    replacement=old[:-1]+",'capacity_dispatch_jobs_state_v11_check','capacity_dispatch_jobs_lifecycle_v11_check')"
    sql=sql.replace(old,replacement,1)
    return ('WITH old98(v) AS ('+sql+'), complete99(v) AS ('+FULL_CATALOG99_SQL
            +'), supplement99(v) AS (SELECT jsonb_build_object('
            + "'functions',(SELECT coalesce(jsonb_agg(x ORDER BY x->>'name',x->>'arguments'),'[]'::jsonb) FROM jsonb_array_elements(v->'functions')x WHERE x->>'name'=ANY(ARRAY["
            + ','.join("'"+name+"'" for name in FUNCTIONS99)+"])),"
            + "'constraints',(SELECT coalesce(jsonb_agg(x ORDER BY x->>'table',x->>'name'),'[]'::jsonb) FROM jsonb_array_elements(v->'constraints')x WHERE x->>'table'='"+TABLE99+"'),"
            + "'triggers',(SELECT coalesce(jsonb_agg(x ORDER BY x->>'table',x->>'name'),'[]'::jsonb) FROM jsonb_array_elements(v->'triggers')x WHERE (x->>'table',x->>'name') IN("
            + ','.join("('"+table+"','"+name+"')" for table,name in TRIGGERS99)+")),"
            + "'columns',(SELECT coalesce(jsonb_agg(x ORDER BY (x->>'number')::int),'[]'::jsonb) FROM jsonb_array_elements(v->'columns')x WHERE x->>'table'='"+TABLE99+"'),"
            + "'indexes',(SELECT coalesce(jsonb_agg(x ORDER BY x->>'table',x->>'name'),'[]'::jsonb) FROM jsonb_array_elements(v->'indexes')x WHERE x->>'table'='"+TABLE99+"' OR x->>'name'='"+LOOKUP99+"')) FROM complete99),"
            + 'structure99(v) AS ('+STRUCTURE99_SQL+') SELECT (SELECT v FROM old98)'
            + " || jsonb_build_object('schema99',(SELECT v FROM supplement99),'structural99',(SELECT v FROM structure99),"
            + "'ledger98',(SELECT jsonb_build_object('rows',count(*),'sha256',encode(digest(COALESCE(jsonb_agg(to_jsonb(x) ORDER BY id),'[]'::jsonb)::text,'sha256'),'hex')) FROM public.capacity_dispatch_installed_provision_timeout_dispositions x))")

def preaction_stamp99(value):
    stamp = preaction_utc99(value).astimezone(datetime.timezone.utc)
    delta = stamp - datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)
    fraction = re.search(r'\.(\d{1,9})(?=Z|[+-])', value)
    tail = int((fraction.group(1) + '000000000')[:9][-3:]) if fraction else 0
    return ((delta.days * 86400 + delta.seconds) * 1000000 + delta.microseconds) * 1000 + tail


PREACTION99_CASE_SCHEMA = 'root_preaction_failed_plan_case_v1'
PREACTION99_TARGET = {
 'job_id':'3f7c5c0c-d93e-4962-b4a6-47318db4139a',
 'run_id':'de899202-54f7-4679-b00e-82b33d743aa1',
 'root_anchor_id':'283120bd-bc9b-406a-ab3d-e4969652a659',
 'current_runtime_source':CURRENT_CORE9,'current_generation':44,'current_fencing_token':85,'member_count':8}
SCAN_BASE99 = 'schema clock_skew_margin_seconds grants_created_or_updated_since_start open_undisposed_grants preregistrations_since_start create_witnesses_since_start enrollments_since_start installations_since_start qualification_probe_challenges_since_start qualification_native_source_returns_since_start source_recovery_cleanup_challenges_since_start source_recovery_cleanup_effect_permits_since_start partial_nativeoff_reconciliations_since_start partial_nativeoff_reads_since_start prejournal_refusal_recoveries_since_start presend_retirement_recoveries_since_start retirement_intents_since_start retirement_contexts_since_start retirement_original_returns_since_start retirement_delete_bindings_since_start retirement_native_readbacks_since_start caller_possible_sends_since_start caller_returns_since_start runtime_snapshot_challenges_since_start runtime_snapshot_returns_since_start authority_reads_since_start authority_returns_since_start authority_transport_returns_since_start native_poweroff_reads_since_start canary_challenges_since_start canary_nonces_since_start canary_possible_sends_since_start canary_returns_since_start intents_updated_since_start notify_window_markers_for_job intent_events_since_start native_commands_since_start native_lifetimes_updated_since_start native_lifetime_archives_since_start native_pod_checkpoints_since_start executor_activity_updated_since_start resource_slots_updated_since_start provider_read_performed provider_quiescence_proved base_schema pure_assessment_intent_updates observation_refresh_slot_updates'
SCAN99_COUNTERS = 'other_busy_dispatches other_busy_runs authority_issues_since_start disposal_rows_since_start retirement_forwards_since_start retirement_forward_reads_since_start undisposed_grants'
RECORDS99 = 'job run intent policy members proofs current_grants unresolved_grants current_canaries current_retirements authority_slots other_jobs other_runs anchor anchor_valid scan'


def pg_bytea99(value):
    need99(type(value) is str and re.fullmatch(r'\\x(?:[0-9a-f]{2})+',value) is not None,'CANONICAL99_PG_BYTEA')
    raw=bytes.fromhex(value[2:])
    need99(len(raw)<=CAP,'BOUNDED99_SAVED_WIRE')
    return raw


def preaction_scan99(value):
    closed99(value,'schema base current_intent_matches_anchor current_members_match_anchor '+SCAN99_COUNTERS,'CLOSED99_SCAN11')
    need99(value['schema']=='preaction_failed_plan_effect_scan_v1'
           and value['current_intent_matches_anchor'] is True and value['current_members_match_anchor'] is True
           and all(type(value[k]) is int and value[k]==0 for k in SCAN99_COUNTERS.split()),'NO99_COMMITTED_PLAN_AUTHORITY_OR_FOREIGN_BUSY')
    base=closed99(value['base'],SCAN_BASE99,'COMPLETE99_INHERITED_SCAN47')
    specials={'schema','base_schema','clock_skew_margin_seconds','provider_read_performed','provider_quiescence_proved',
              'resource_slots_updated_since_start','observation_refresh_slot_updates'}
    need99(base['schema']=='finalization_lost_dispatch_effect_scan_v1'
           and base['base_schema']=='abandoned_started_dispatch_effect_scan_v2'
           and type(base['clock_skew_margin_seconds']) is int and base['clock_skew_margin_seconds']==30
           and base['provider_read_performed'] is False and base['provider_quiescence_proved'] is False
           and all(type(base[k]) is int and base[k]==0 for k in set(base)-specials)
           and type(base['resource_slots_updated_since_start']) is int and base['resource_slots_updated_since_start']>=0
           and type(base['observation_refresh_slot_updates']) is int
           and base['resource_slots_updated_since_start']==base['observation_refresh_slot_updates'],
           'EXACT99_SOURCE_TOLERABLE_SCAN_NOT_PROVIDER_QUIESCENCE')
    return value


def preaction99_lanes(value,case,provider):
    keys='jobs_busy runs_busy forward_unreturned_reads live_unreturned_canaries intent_count intent_busy pending_authority forward_markers'.split()
    providers=closed99(case.get('provider_lanes'),'aws hetzner known_hz_preservation','CLOSED99_PROVIDER_LANES3')
    for name in ('aws','hetzner'):
        closed99(providers[name],' '.join(keys),'CLOSED99_PROVIDER_COUNTERS8')
    context=closed99(providers['known_hz_preservation'],
        'helper_source_ref fixed_current_sql_ref known_baseline_ref known_root_ref policy_state_full_ref',
        'CLOSED99_KNOWN_HZ_CONTEXT5')
    for ref in context.values():
        closed99(ref,'path sha256','CLOSED99_KNOWN_HZ_REF2')
        need99(type(ref['path']) is str and PurePosixPath(ref['path']).is_absolute()
               and '..' not in PurePosixPath(ref['path']).parts and digest99(ref['sha256']),
               'ABSOLUTE99_KNOWN_HZ_WHOLE_REF')
    lanes={k:value[k] for k in keys}
    need99(case.get('schema')==PREACTION99_CASE_SCHEMA and provider in ('aws','hetzner')
           and all(type(v) is int for v in lanes.values()) and same99(lanes,case['provider_lanes'][provider])
           and lanes['jobs_busy']==(1 if provider=='aws' else 0) and lanes['intent_count']==1
           and lanes['intent_busy'] in (0,1) and all(lanes[k]==0 for k in (
               'runs_busy','forward_unreturned_reads','live_unreturned_canaries','pending_authority','forward_markers')),
           'EXACT99_RAW_E70_OWN_UNKNOWN_NOT_FALSE_QUIET')
    return lanes


def validate_preaction99(value,case):
    closed99(case,'schema job_id run_id root_anchor_id policy_id policy_checksum current_runtime_source current_generation current_fencing_token current_lease_owner current_executor_id member_count expected_records_sha256 provider_lanes','CLOSED99_FAILED_PLAN_CASE14')
    need99(case['schema']==PREACTION99_CASE_SCHEMA and all(case[k]==v for k,v in PREACTION99_TARGET.items())
           and all(type(case[k]) is int for k in ('current_generation','current_fencing_token','member_count'))
           and digest99(case['expected_records_sha256']),'EXACT99_G44_FAILED_PLAN_NOT_PROVISION_TIMEOUT')
    closed99(value,'schema observed_at_core records_wire','CLOSED99_PREACTION_SNAPSHOT3')
    need99(value['schema']=='unknown_preaction_failed_plan_snapshot_v1' and type(value['records_wire']) is str
           and 0<len(value['records_wire'].encode())<=CAP
           and sha99(value['records_wire'].encode())==case['expected_records_sha256'],'WHOLE99_PREACTION_RECORDS_SHA')
    r=closed99(loads99(value['records_wire']),RECORDS99,'COMPLETE99_PREACTION_ROLES16')
    j,w,i,p,a=(r[k] for k in ('job','run','intent','policy','anchor'))
    need99(all(type(x) is dict for x in (j,w,i,p,a)) and r['anchor_valid'] is True
           and all(type(r[k]) is list for k in ('members','proofs','current_grants','unresolved_grants',
               'current_canaries','current_retirements','authority_slots','other_jobs','other_runs')),'TYPED99_RAW_ROLES_AND_M98_VALID')
    closed99(a,'id job_id run_id original_record original_wire original_dispatch_wire original_run_wire original_intent_wire members_wire recorded_at','WHOLE99_ANCHOR_TABLE10')
    ar=closed99(a['original_record'],'schema id job_id run_id policy_id policy_checksum generation fencing_token lease_owner executor_id preregistration_id create_grant_id original_dispatch_sha256 original_run_sha256 original_intent_sha256 members_sha256 original_deadline original_intent_lease_expires_at original_returned_at recorded_at members','IMMUTABLE99_M98_RECORD21')
    need99(ar['schema']=='unknown_installed_provision_timeout_disposition_v1'
           and a['id']==ar['id']==case['root_anchor_id'] and a['job_id']==ar['job_id'] and a['run_id']==ar['run_id']
           and same99(loads99(pg_bytea99(a['original_wire'])),ar)
           and all(sha99(pg_bytea99(a[field]))==ar[pin] for field,pin in (
               ('original_dispatch_wire','original_dispatch_sha256'),('original_run_wire','original_run_sha256'),
               ('original_intent_wire','original_intent_sha256'),('members_wire','members_sha256')))
           and same99(loads99(pg_bytea99(a['members_wire'])),ar['members'])
           and same99(i,loads99(pg_bytea99(a['original_intent_wire']))),'ALL99_M98_FIVE_WIRES_RETAINED_CURRENT_INTENT_EXACT')
    ns=preaction_stamp99
    env=loads99(j['envelope']);oldenv=loads99(loads99(pg_bytea99(a['original_dispatch_wire']))['envelope'])
    authority=lambda e:{k:v for k,v in e.items() if k not in ('job_id','run_id','source_tick','metadata','metadata_sha256')}
    metadata=lambda e:{k:v for k,v in e['metadata'].items() if k not in ('scheduled_for','capacity_dispatch_job_id')}
    need99(same99(authority(env),authority(oldenv)) and same99(metadata(env),metadata(oldenv))
           and j['id']==case['job_id'] and j['run_id']==w['id']==case['run_id']
           and j['state']=='unknown' and j['return_status']==w['status']=='failed' and j['finalization_ack_at'] is None
           and j['protocol']==env['protocol']=='capacity_dispatch_prestart_v1'
           and all(v is None for k,v in j.items() if k.endswith('_disposition_id'))
           and sha99(j['envelope'].encode())==j['envelope_sha256']
           and env['job_id']==j['id'] and env['run_id']==w['id']
           and same99(env['inputs'],w['inputs']) and same99(env['metadata'],w['metadata'])
           and env['metadata']['triggered_by']=='workflow_scheduler'
           and env['metadata']['capacity_dispatch_job_id']==j['id']
           and ns(j['started_at'])==ns(w['started_at'])<ns(j['lease_expires_at'])
           and ns(j['returned_at'])==ns(w['finished_at'])>=ns(j['started_at'])
           and ns(a['recorded_at'])<=ns(j['started_at'])
           and ns(value['observed_at_core'])>=max(ns(j['returned_at']),ns(j['lease_expires_at'])),
           'AUTHENTIC99_UNKNOWN_NO_ACK_NEW_PLAN_SAME_ANCHOR_AUTHORITY_EXPIRED')
    # Finish final-clock and markFinalizationUnknown can preserve different errors.
    # Authenticate each in the whole job/run records; never equate human messages.
    need99(all(j[k] is None or type(j[k]) is str for k in ('return_error','finalization_error'))
           and any(type(j[k]) is str and j[k] for k in ('return_error','finalization_error'))
           and type(w['error']) is str and w['error'],'ORIGINAL99_INDEPENDENT_FAILED_PRODUCER_ERRORS')
    scope=('dakasa-production','production','notify','original_notify_aws_vm_members')
    need99(tuple(j[k] for k in ('realm','environment','domain','dimension'))==scope
           and tuple(i[k] for k in ('namespace','environment','domain','dimension'))==scope
           and i['policy_id']==p['id']==ar['policy_id']==case['policy_id']==env['policy']['id']
           and i['policy_checksum']==p['checksum']==ar['policy_checksum']==case['policy_checksum']==env['policy']['checksum']
           and i['generation']==ar['generation']==case['current_generation']
           and i['fencing_token']==ar['fencing_token']==case['current_fencing_token']
           and i['lease_owner']==ar['lease_owner']==case['current_lease_owner']
           and i['lease_executor_id']==ar['executor_id']==case['current_executor_id']
           and i['phase']=='preparing' and i['recovery_only'] is False and not i.get('floor_degraded',False)
           and ns(value['observed_at_core'])>=ns(i['lease_expires_at'])
           and not any(k in i for k in ('installed_guest_reconcile','retirement_forward','original_notify_window',
               'failed_installed_disposal','failed_serving_disposal','failed_expansion_terminal_reconcile',
               'failed_unwitnessed_expansion_cleanup_id'))
           and p['kind']=='capacity_policy' and p['active'] is True and p['namespace']==scope[0]
           and p['spec']['execution_enabled'] is True,'UNCHANGED99_G44_PREPARING_EXPIRED_ANCHOR_POLICY')
    preaction_scan99(r['scan'])
    need99(all(r[k]==[] for k in ('unresolved_grants','current_canaries','current_retirements',
               'authority_slots','other_jobs','other_runs')) and len(r['current_grants'])==1
           and r['current_grants'][0]['id']==ar['create_grant_id']
           and r['current_grants'][0]['state']=='confirmed','NO99_UNRESOLVED_ACTION_OR_EXTRA_CURRENT_GRANT')
    need99(len(r['members'])==len(r['proofs'])==len(ar['members'])==case['member_count']
           and [m['slot'] for m in ar['members']]==list(range(1,9)),'WHOLE99_EIGHT_INSTALLED_MEMBERS')
    for ordinal,(member,proof,am) in enumerate(zip(r['members'],r['proofs'],ar['members']),1):
        closed99(am,'slot preregistration_id create_grant_id tuple request_sha256 preregistration_sha256 witness_sha256 enrollment_sha256 installation_sha256 receipt_sha256','M98_MEMBER99_CLOSED10')
        closed99(proof,'slot_record grant preregistration witness enrollment installation','CLOSED99_CURRENT_MEMBER_PROOF')
        tup=closed99(am['tuple'],'provider integration_instance_id instance_checksum integration_type_id type_checksum scope_checksum profile_checksum profile slot resource_id resource_created_at','SAME99_PHYSICAL_TUPLE11')
        g,pre,wi,en,ins=(proof[k] for k in ('grant','preregistration','witness','enrollment','installation'))
        need99(type(member['slot']) is int and member['slot']==am['slot']==tup['slot']==ordinal
               and proof['slot_record']==member and member['slot_record']['tombstone'] is False
               and 'authority_kind' not in member['slot_record'] and tup['provider']=='aws'
               and member['resource_id']==member['slot_record']['resource_id']==tup['resource_id']
               and member['slot_record']['resource_created_at']==tup['resource_created_at']
               and member['slot_record']['desired_spec_sha256']==am['request_sha256']
               and member['integration_instance_id']==tup['integration_instance_id']
               and member['scope_checksum']==tup['scope_checksum'] and member['profile_name']==tup['profile']
               and pre['id']==wi['preregistration_id']==en['preregistration_id']==ins['preregistration_id']==am['preregistration_id']
               and pre['create_grant_id']==g['id']==am['create_grant_id'] and g['state']=='confirmed'
               and 'authority_kind' not in g['grant_record']
               and all(sha99(pg_bytea99(row[field]))==am[pin] for row,field,pin in (
                   (pre,'original_wire','preregistration_sha256'),(wi,'original_wire','witness_sha256'),
                   (en,'receipt_wire','receipt_sha256'),(ins,'original_wire','installation_sha256')))
               and wi['witness_sha256']==am['witness_sha256'] and en['enrollment_sha256']==am['enrollment_sha256']
               and ins['confirmation_sha256']==am['installation_sha256']
               and loads99(pg_bytea99(wi['original_wire']))['tuple']==tup
               and en['enrollment_record']['statement']['tuple']==tup,'AUTHENTIC99_EIGHT_IMMUTABLE_CREATE_SDK_INSTALLATION_JOINS')
    need99(ar['members'][0]['tuple']['resource_id']=='i-070b5767a35c7f0d5','PROTECTED99_S1_NEVER_DELETE')
    result=w['result'];start=ns(result['started_at']);finish=ns(result['finished_at']);rowfinish=ns(w['finished_at'])
    need99(result['status']=='failed' and result['workflow']=={'kind':'workflow',**{k:env['workflow'][k] for k in ('id','namespace','name','version')}}
           and result['metadata']=={**env['metadata'],'failed_step':'plan-original-guest'}
           and type(result['steps']) is list and len(result['steps'])==7
           and ns(w['started_at'])<=start<ns(j['lease_expires_at']) and start<=finish<=rowfinish,
           'AUTHENTIC99_RESPONSE_METADATA_AND_DISTINCT_NS_CLOCKS')
    ids=('plan-original-guest','provision-original-notify','retire-original-guest','refresh-original-membership','complete-original-provision','finish-original-retirement','complete-original-retirement')
    ops=('capacity.plan_original_guest','capacity.provision_original_guest','capacity.retire_original_guest','capacity.complete_original_guest','capacity.complete_original_guest','capacity.finish_original_guest_retirement','capacity.complete_original_guest')
    previous=start
    for index,(step,identity,operation) in enumerate(zip(result['steps'],ids,ops)):
        begin,end=ns(step['started_at']),ns(step['finished_at'])
        need99(step['id']==identity and step['kind']=='yggdrasil'
               and step['operation']==step['capability']==operation
               and not any(k in step for k in ('integration_instance','integration_type'))
               and previous<=begin<=end<=rowfinish,'EXACT99_SEVEN_ORDERED_STEPS')
        previous=end
        if index==0:
            closed99(step['metadata'],'original_guest_reconcile_refusal_stage','FAILED99_PLAN_METADATA')
            stage=step['metadata']['original_guest_reconcile_refusal_stage']
            need99(step['status']=='failed' and type(step['attempts']) is int and step['attempts']==1
                   and type(stage) is str and 1<=len(stage.encode())<=128 and stage.strip()==stage
                   and '\n' not in stage and '\r' not in stage and end==finish,'FAILED99_PLAN_NO_ERROR_CATEGORY_WHITELIST')
        else:
            need99(step['status']=='skipped' and type(step.get('attempts',0)) is int and step.get('attempts',0)==0
                   and step.get('metadata',{})=={} and begin>=finish
                   and step['error']=='workflow aborted after step "plan-original-guest" failed','SIX99_AUTHENTIC_ABORTS_NO_ACTIONS')
    return r

PREACTION99_SQL = "WITH job AS MATERIALIZED (\n SELECT * FROM public.capacity_dispatch_jobs\n WHERE id='3f7c5c0c-d93e-4962-b4a6-47318db4139a'::uuid\n AND realm='dakasa-production' AND environment='production' AND domain='notify'\n AND dimension='original_notify_aws_vm_members'\n), run AS MATERIALIZED (\n SELECT w.* FROM public.workflow_runs w JOIN job j ON j.run_id=w.id\n), intent AS MATERIALIZED (\n SELECT i.* FROM public.capacity_intents i JOIN job j ON\n (i.namespace,i.environment,i.domain,i.dimension)=(j.realm,j.environment,j.domain,j.dimension)\n), policy AS MATERIALIZED (\n SELECT p.* FROM public.manifests p JOIN job j ON p.id::text=j.envelope::jsonb#>>'{policy,id}'\n), members AS MATERIALIZED (\n SELECT s.* FROM public.capacity_resource_slots s JOIN job j ON\n (s.namespace,s.environment,s.domain,s.dimension)=(j.realm,j.environment,j.domain,j.dimension)\n WHERE s.resource_id<>'' AND s.slot_record->'tombstone'='false'::jsonb\n), proofs AS MATERIALIZED (\n SELECT s.slot,jsonb_build_object('slot_record',to_jsonb(s),\n 'grant',to_jsonb(g),'preregistration',to_jsonb(p),'witness',to_jsonb(w),\n 'enrollment',to_jsonb(e),'installation',to_jsonb(i)) AS value\n FROM members s JOIN public.capacity_mutation_grants g ON\n (g.namespace,g.environment,g.domain,g.dimension,g.integration_instance_id,g.scope_checksum,g.profile_name,g.slot)=\n (s.namespace,s.environment,s.domain,s.dimension,s.integration_instance_id,s.scope_checksum,s.profile_name,s.slot)\n JOIN public.capacity_vm_provisioning_preregistrations p ON p.create_grant_id=g.id\n JOIN public.capacity_guest_original_create_witnesses w ON w.preregistration_id=p.id\n JOIN public.capacity_vm_original_enrollments e ON e.preregistration_id=p.id\n JOIN public.capacity_guest_original_installations i ON i.preregistration_id=p.id\n WHERE w.original_record#>>'{tuple,resource_id}'=s.resource_id\n AND w.original_record#>>'{tuple,resource_created_at}'=s.slot_record->>'resource_created_at'\n), anchor AS MATERIALIZED(SELECT * FROM public.capacity_dispatch_installed_provision_timeout_dispositions WHERE id='283120bd-bc9b-406a-ab3d-e4969652a659'::uuid),\nscan(v) AS MATERIALIZED(WITH j AS MATERIALIZED(SELECT * FROM public.capacity_dispatch_jobs WHERE id='3f7c5c0c-d93e-4962-b4a6-47318db4139a'::uuid),\n a AS MATERIALIZED(SELECT * FROM public.capacity_dispatch_installed_provision_timeout_dispositions WHERE id='283120bd-bc9b-406a-ab3d-e4969652a659'::uuid),\n win AS(SELECT started_at-interval '30 seconds' AS t FROM j),\n it AS(SELECT intent FROM public.capacity_intents i,j WHERE i.namespace=j.realm AND i.environment=j.environment AND i.domain=j.domain AND i.dimension=j.dimension),\n sl AS(SELECT s.* FROM public.capacity_resource_slots s,j WHERE s.namespace=j.realm AND s.environment=j.environment AND s.domain=j.domain AND s.dimension=j.dimension),\n g AS(SELECT g.* FROM public.capacity_mutation_grants g,j WHERE g.namespace=j.realm AND g.environment=j.environment AND g.domain=j.domain AND g.dimension=j.dimension),\n mem AS(SELECT x FROM a,jsonb_array_elements(a.original_record->'members')x),\n busy_runs AS(\n  SELECT w.id FROM public.workflow_runs w,j WHERE w.workflow_id=(j.envelope::jsonb#>>'{workflow,id}')::uuid AND w.id<>j.run_id\n   AND (coalesce(w.status,'') NOT IN('succeeded','failed','cancelled') OR w.finished_at IS NULL)\n  UNION\n  SELECT w.id FROM public.workflow_runs w,j WHERE w.workflow_id IS NULL\n   AND w.workflow_namespace=j.envelope::jsonb#>>'{workflow,namespace}' AND w.workflow_name=j.envelope::jsonb#>>'{workflow,name}' AND w.id<>j.run_id\n   AND (coalesce(w.status,'') NOT IN('succeeded','failed','cancelled') OR w.finished_at IS NULL))\nSELECT jsonb_build_object('schema','preaction_failed_plan_effect_scan_v1',\n 'base',(SELECT public.finalization_lost_dispatch_effect_scan(j.realm,j.environment,j.domain,j.dimension,j.id,j.started_at,j.lease_expires_at)FROM j),\n 'current_intent_matches_anchor',coalesce((SELECT it.intent=convert_from(a.original_intent_wire,'UTF8')::jsonb FROM it,a),false),\n 'current_members_match_anchor',coalesce((SELECT\n  (SELECT count(*)FROM sl WHERE resource_id<>'' AND slot_record->'tombstone'='false'::jsonb)=jsonb_array_length(a.original_record->'members')\n  AND NOT EXISTS(SELECT 1 FROM sl WHERE sl.slot_record ? 'authority_kind' OR sl.resource_id<>'' AND sl.slot_record->'tombstone'='false'::jsonb AND NOT EXISTS(\n   SELECT 1 FROM mem WHERE sl.integration_instance_id::text=x#>>'{tuple,integration_instance_id}' AND sl.scope_checksum=x#>>'{tuple,scope_checksum}'\n   AND sl.profile_name=x#>>'{tuple,profile}' AND sl.slot=(x->>'slot')::integer AND sl.resource_id=x#>>'{tuple,resource_id}'\n   AND sl.slot_record->>'resource_id'=sl.resource_id AND sl.slot_record->>'resource_created_at'=x#>>'{tuple,resource_created_at}'\n   AND sl.slot_record->>'desired_spec_sha256'=x->>'request_sha256'\n   AND EXISTS(SELECT 1 FROM g WHERE g.id::text=x->>'create_grant_id' AND g.state='confirmed' AND NOT(g.grant_record ? 'authority_kind')\n    AND g.original_disposition_id IS NULL AND g.failed_original_disposition_id IS NULL AND g.native_denied_disposition_id IS NULL AND g.enrolled_failed_disposition_id IS NULL)))\n  FROM a),false),\n 'other_busy_dispatches',(SELECT count(*)FROM public.capacity_dispatch_jobs x,j WHERE x.realm=j.realm AND x.environment=j.environment AND x.domain=j.domain AND x.dimension=j.dimension AND x.id<>j.id\n  AND(x.state IN('queued','started','unknown')OR x.state='returned'AND x.finalization_ack_at IS NULL)),\n 'other_busy_runs',(SELECT count(*)FROM busy_runs),\n 'authority_issues_since_start',(SELECT count(*)FROM public.capacity_guest_authority_issues x JOIN public.manifests p ON p.id=x.policy_id CROSS JOIN j,win\n  WHERE(x.issue_id=j.run_id OR p.namespace=j.realm AND p.kind='capacity_policy'AND p.spec->>'environment'=j.environment AND p.spec->>'domain'=j.domain AND p.spec->>'dimension'=j.dimension)\n   AND x.recorded_at>=win.t),\n 'disposal_rows_since_start',(SELECT count(*)FROM public.capacity_guest_failed_installed_disposals x,j,win WHERE x.namespace=j.realm AND x.environment=j.environment AND x.domain=j.domain AND x.dimension=j.dimension AND x.recorded_at>=win.t)\n  +(SELECT count(*)FROM public.capacity_guest_failed_serving_disposals x,j,win WHERE x.namespace=j.realm AND x.environment=j.environment AND x.domain=j.domain AND x.dimension=j.dimension AND x.recorded_at>=win.t),\n 'retirement_forwards_since_start',(SELECT count(*)FROM public.capacity_guest_retirement_forwards x,j,win WHERE x.namespace=j.realm AND x.environment=j.environment AND x.domain=j.domain AND x.dimension=j.dimension AND x.recorded_at>=win.t),\n 'retirement_forward_reads_since_start',(SELECT count(*)FROM public.capacity_guest_retirement_forward_reads x JOIN public.capacity_vm_retirement_intents r ON r.id=x.retirement_request_id JOIN public.capacity_vm_provisioning_preregistrations p ON p.id=r.preregistration_id JOIN g ON g.id=p.create_grant_id CROSS JOIN win WHERE x.recorded_at>=win.t),\n 'undisposed_grants',(SELECT count(*)FROM g WHERE g.state IN('issued','redeemed','settled','compensating')AND NOT(g.grant_record?'authority_kind')\n  AND g.original_disposition_id IS NULL AND g.failed_original_disposition_id IS NULL AND g.native_denied_disposition_id IS NULL AND g.enrolled_failed_disposition_id IS NULL))),\nsnapshot(v) AS MATERIALIZED (\n SELECT json_build_object(\n 'anchor',(SELECT row_to_json(a) FROM anchor a),\n 'anchor_valid',(SELECT public.installed_provision_timeout_valid(a.original_record,a.original_dispatch_wire,a.original_run_wire,a.original_intent_wire,a.members_wire) FROM anchor a),\n 'scan',(SELECT v FROM scan),\n 'job',(SELECT row_to_json(j) FROM job j),'run',(SELECT row_to_json(w) FROM run w),\n 'intent',(SELECT i.intent FROM intent i),'policy',(SELECT row_to_json(p) FROM policy p),\n 'members',(SELECT COALESCE(json_agg(row_to_json(s) ORDER BY s.slot),'[]'::json) FROM members s),\n 'proofs',(SELECT COALESCE(json_agg(value ORDER BY slot),'[]'::json) FROM proofs),\n 'current_grants',(SELECT COALESCE(json_agg(row_to_json(g) ORDER BY g.id),'[]'::json)\n FROM public.capacity_mutation_grants g,job j,intent i\n WHERE(g.namespace,g.environment,g.domain,g.dimension)=(j.realm,j.environment,j.domain,j.dimension)\n AND g.generation=(i.intent->>'generation')::bigint AND NOT(g.grant_record ? 'authority_kind')),\n 'unresolved_grants',(SELECT COALESCE(json_agg(g.id ORDER BY g.id),'[]'::json)\n FROM public.capacity_mutation_grants g,job j WHERE\n (g.namespace,g.environment,g.domain,g.dimension)=(j.realm,j.environment,j.domain,j.dimension)\n AND NOT(g.grant_record ? 'authority_kind') AND g.state IN('issued','redeemed','settled','compensating')\n AND g.original_disposition_id IS NULL AND g.failed_original_disposition_id IS NULL\n AND g.native_denied_disposition_id IS NULL AND g.enrolled_failed_disposition_id IS NULL),\n 'current_canaries',(SELECT COALESCE(json_agg(c.id ORDER BY c.id),'[]'::json)\n FROM public.capacity_guest_notify_canary_challenges c,intent i\n WHERE c.policy_id::text=i.intent->>'policy_id' AND c.generation=(i.intent->>'generation')::bigint\n AND c.fence=(i.intent->>'fencing_token')::bigint AND c.lease_owner::text=i.intent->>'lease_owner'\n AND c.executor_id::text=i.intent->>'lease_executor_id'),\n 'current_retirements',(SELECT COALESCE(json_agg(r.id ORDER BY r.id),'[]'::json)\n FROM public.capacity_vm_retirement_intents r WHERE r.preregistration_id IN\n (SELECT (value#>>'{preregistration,id}')::uuid FROM proofs)),\n 'authority_slots',(SELECT COALESCE(json_agg(row_to_json(s) ORDER BY s.slot),'[]'::json)\n FROM public.capacity_resource_slots s,job j WHERE\n (s.namespace,s.environment,s.domain,s.dimension)=(j.realm,j.environment,j.domain,j.dimension)\n AND s.slot_record ? 'authority_kind'),\n 'other_jobs',(SELECT COALESCE(json_agg(x.id ORDER BY x.id),'[]'::json)\n FROM public.capacity_dispatch_jobs x,job j WHERE\n (x.realm,x.environment,x.domain,x.dimension)=(j.realm,j.environment,j.domain,j.dimension)\n AND x.id<>j.id AND x.state IN('queued','started')),\n 'other_runs',(SELECT COALESCE(json_agg(w.id ORDER BY w.id),'[]'::json)\n FROM public.workflow_runs w JOIN public.capacity_dispatch_jobs x ON x.run_id=w.id,job j\n WHERE(x.realm,x.environment,x.domain,x.dimension)=(j.realm,j.environment,j.domain,j.dimension)\n AND w.id<>j.run_id AND w.status IN('pending','running'))\n )\n)\nSELECT jsonb_build_object('schema','unknown_preaction_failed_plan_snapshot_v1',\n 'observed_at_core',clock_timestamp(),'records_wire',(SELECT v::text FROM snapshot))"

def preaction_utc99(value):
    need99(type(value) is str and re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})', value), 'ACTUAL_ZONED_TIMESTAMP')
    # Python before 3.11 accepts only 3/6 fractional digits; retain the raw wire
    # and parse its accepted 1..9 digits at datetime's microsecond precision.
    normalized = re.sub(r'\.(\d{1,9})(?=Z|[+-])', lambda match: '.' + (match.group(1) + '000000')[:6], value)
    return datetime.datetime.fromisoformat(normalized.replace('Z', '+00:00'))
