"""CI-only declared schema99 operands; this file grants no CI/Native acceptance."""
import ast
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest import mock


def canonical(value):
    return (json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def load99(name,relative):
    path=Path(__file__).resolve().parent.parent/relative
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


H=load99('declared_catalog99','rollout/catalog99_helpers.py')
G=load99('declared_goose99','rollout/goose99_native_once.py')


def fixture99():
    # Reuse existing declared full schema98 operands; no Native catalog is fabricated.
    from test_catalog98 import fixture98
    previous=fixture98()
    ci_before=copy.deepcopy(previous['ci_after'])
    ci_before['columns']=[{**r,'has_default':False} for r in ci_before['columns']]
    ci_before['indexes']=[]
    ci_after=copy.deepcopy(ci_before)
    specs=H.migration99_functions(M99_SQL)
    def function(name,spec):
        attrs='' if spec['volatility']=='VOLATILE' else spec['volatility']
        if spec['utc']:
            attrs+=(' ' if attrs else '')+'SET "TimeZone" TO \'UTC\''
        definition=('CREATE OR REPLACE FUNCTION public.'+name+'('+spec['arguments']+')\n RETURNS '
                    +spec['result']+'\n LANGUAGE '+spec['language']+'\n '+attrs+'\n AS $function$'
                    +spec['body']+'$function$\n')
        return {'name':name,'arguments':spec['arguments'],'definition':definition}
    ci_after['functions']=[r for r in ci_after['functions'] if r['name']!='guard_capacity_dispatch_job']
    ci_after['functions']+=[function(n,specs[n]) for n in H.FUNCTIONS99]
    ci_after['functions'].sort(key=lambda r:(r['name'],r['arguments']))
    ci_after['constraints']=[r for r in ci_after['constraints'] if r['name'] not in H.OLD_CHECKS99]
    for old,new in zip(H.OLD_CHECKS99,H.NEW_CHECKS99):
        row=copy.deepcopy(next(r for r in ci_before['constraints'] if r['name']==old))
        row['name']=new;row['definition']=row['definition'].replace('installed_timeout_disposed','preaction_plan_disposed')
        ci_after['constraints'].append(row)
    table=H.TABLE99
    for ordinal,(name,type_) in enumerate(H.COLUMNS99,1):
        ci_after['columns'].append({'table':table,'name':name,'number':ordinal,'type':type_,
                                   'not_null':True,'has_default':False})
    ci_after['columns'].sort(key=lambda r:(r['table'],r['number']))
    for number,key in enumerate(('id','job_id','run_id','successor_job_id','successor_run_id'),1):
        name='declared99_identity_'+str(number);kind='p' if number==1 else 'u'
        ci_after['constraints'].append({'table':table,'name':name,'kind':kind,'validated':True,
                                       'definition':('PRIMARY KEY' if kind=='p' else 'UNIQUE')+' ('+key+')'})
        ci_after['indexes'].append({'table':table,'name':name,'definition':'CREATE UNIQUE INDEX '+name+' ON public.'+table+' USING btree ('+key+')',
            'predicate':None,'expressions':None,'valid':True,'ready':True,'live':True,'primary':number==1,
            'unique':True,'keys':str(number),'key_count':1,'method':'btree'})
    for number,key in enumerate(('job_id','run_id','successor_job_id','successor_run_id'),1):
        ci_after['constraints'].append({'table':table,'name':'declared99_fk_'+str(number),'kind':'f','validated':True,
            'definition':'FOREIGN KEY ('+key+') REFERENCES public.'+('workflow_runs' if 'run' in key else 'capacity_dispatch_jobs')+'(id)'
                         +(' DEFERRABLE INITIALLY DEFERRED' if number>2 else '')})
    for number in range(9):
        ci_after['constraints'].append({'table':table,'name':'declared99_check_'+str(number),'kind':'c',
                                       'validated':True,'definition':'CHECK (true)'})
    # PostgreSQL records a CONSTRAINT TRIGGER as its own kind-t constraint.
    # Both original PG16/17 catalogs retain it separately from the four FKs.
    ci_after['constraints'].append({'table':table,'name':'preaction_failed_plan_complete_links',
        'kind':'t','validated':True,'definition':'TRIGGER DEFERRABLE INITIALLY DEFERRED'})
    function_for={'preaction_failed_plan_insert':'guard_preaction_failed_plan_insert',
                  'preaction_failed_plan_immutable':'immutable_preaction_failed_plan',
                  'preaction_failed_plan_complete_links':'require_preaction_failed_plan_links',
                  'preaction_failed_plan_job_insert':'guard_preaction_failed_plan_job_insert',
                  'preaction_failed_plan_workflow_immutable':'guard_preaction_failed_plan_workflow'}
    for relation,name in H.TRIGGERS99:
        ci_after['triggers'].append({'table':relation,'name':name,'enabled':'O',
            'definition':'CREATE TRIGGER '+name+' BEFORE INSERT ON public.'+relation+' FOR EACH ROW EXECUTE FUNCTION public.'+function_for[name]+'()'})
    partial={'table':'capacity_dispatch_jobs','name':H.LOOKUP99,
             'definition':"CREATE INDEX capacity_dispatch_failed_workflow_returned_idx ON public.capacity_dispatch_jobs USING btree (((envelope::jsonb #>> '{workflow,id}'::text[])), returned_at) WHERE ((state = 'returned'::text) AND (return_status = 'failed'::text) AND (returned_at IS NOT NULL) AND (finalization_ack_at IS NOT NULL))",
             'predicate':"((state = 'returned'::text) AND (return_status = 'failed'::text) AND (returned_at IS NOT NULL) AND (finalization_ack_at IS NOT NULL))",
             'expressions':"(envelope::jsonb #>> '{workflow,id}'::text[])",'valid':True,'ready':True,'live':True,
             'primary':False,'unique':False,'keys':'0 14','key_count':2,'method':'btree'}
    ci_after['indexes'].append(partial)
    for kind in ('constraints','triggers','indexes'):
        ci_after[kind].sort(key=lambda r:(r['table'],r['name']))
    history=json.loads(ci_before['history_wire'])
    ci_after['history_wire']=canonical(history+[{'id':history[-1]['id']+1,'version_id':99,'is_applied':True,
                                               'tstamp':'2026-11-12T00:00:00+00:00'}]).decode()
    before=copy.deepcopy(previous['after']);prior={**copy.deepcopy(previous['after']['legacy'])}
    prior=H.projection98_99(before)
    before['schema99']=H.selected99(ci_before)
    before['structural99']={'server_version_num':160013,'table':None,'columns':[],'indexes':[]}
    before['ledger98']={'rows':1,'sha256':'c'*64}
    after=copy.deepcopy(before)
    after['legacy']['complete_history_wire']=ci_after['history_wire']
    after['schema98']=H.retained98(ci_after)
    after['legacy']['catalog91']['shared_dispatch_guard']=[{
        'name':'guard_capacity_dispatch_job','definition':next(r for r in ci_after['functions'] if r['name']=='guard_capacity_dispatch_job')['definition']}]
    after['legacy']['catalog91']['dispatch_constraints']=[
        {k:r[k] for k in ('name','validated','definition')} for r in ci_after['constraints']
        if r['table']=='capacity_dispatch_jobs' and r['name'] in H.NEW_CHECKS99]
    after['schema99']=H.selected99(ci_after)
    after['structural99']={'server_version_num':160013,'table':{'name':table,'kind':'r','persistence':'p',
        'replica_identity':'d','row_security':False,'force_row_security':False},
        'columns':[{**{k:r[k] for k in ('name','number','type','not_null')},'identity':'','generated':'','default':None}
                   for r in ci_after['columns'] if r['table']==table],
        'indexes':copy.deepcopy(after['schema99']['indexes'])}
    f={'prior':prior,'before':before,'after':after,'ci_before':ci_before,'ci_after':ci_after,'source':'a'*40}
    reseal99(f)
    return f


def reseal99(f):
    blobs={}
    def retain(name,value):
        raw=canonical(value);path='/declared-ci99/'+name;blobs[path]=raw
        return {'path':path,'sha256':digest(raw)}
    old=retain('before98.original.json',f['ci_before']);new=retain('after99.original.json',f['ci_after'])
    artifact={'schema':'preaction_failed_plan_schema99_pg_catalog_v1','source_commit':f['source'],'postgres_major':16,
              'fixture_only':True,'native_authority':False,'before98_ref':{**old,'bytes':len(blobs[old['path']])},
              'after99_ref':{**new,'bytes':len(blobs[new['path']])},'migration99_sha256':digest(M99_SQL.encode()),
              'history_sole99_append':True,'old_public_functions_changed':['guard_capacity_dispatch_job'],
              'new_table_columns':13,'new_table_unique_indexes':5,
              'lookup_index':next(r for r in f['ci_after']['indexes'] if r['name']==H.LOOKUP99),
              'all_constraints_validated':True}
    f['artifact']=artifact;f['carrier']={'artifact_ref':retain('artifact.original.json',artifact),
        'before98_ref':old,'after99_ref':new};f['blobs']=blobs


def declared_preaction99():
    from test_restore98_same_epoch_lineage import declared_restoration
    f=declared_restoration();r=copy.deepcopy(f['originals']);a=copy.deepcopy(f['saved']['disposition'])
    ar=a['original_record'];ar['id']=H.PREACTION99_TARGET['root_anchor_id'];a['id']=ar['id']
    a['original_wire']='\\x'+canonical(ar).hex()
    r.update(anchor=a,anchor_valid=True)
    j,w=r['job'],r['run'];j.update(id=H.PREACTION99_TARGET['job_id'],run_id=H.PREACTION99_TARGET['run_id'],
        state='unknown',return_status='failed',return_error='original return failed',finalization_error='original ACK failed',
        finalization_ack_at=None,created_at='2026-11-11T20:09:03Z',started_at='2026-11-11T20:09:03.981151Z',
        returned_at='2026-11-11T20:09:11.041588Z',lease_expires_at='2026-11-11T20:14:03.963630Z')
    env=json.loads(j['envelope']);env.update(job_id=j['id'],run_id=j['run_id'],source_tick=j['created_at'])
    env['metadata'].update(capacity_dispatch_job_id=j['id'],scheduled_for=j['created_at'])
    j['envelope']=canonical(env).decode();j['envelope_sha256']=digest(j['envelope'].encode())
    w.update(id=j['run_id'],status='failed',error='workflow finalization error',started_at=j['started_at'],
             finished_at=j['returned_at'],metadata=copy.deepcopy(env['metadata']),inputs=copy.deepcopy(env['inputs']))
    ids=('plan-original-guest','provision-original-notify','retire-original-guest','refresh-original-membership',
         'complete-original-provision','finish-original-retirement','complete-original-retirement')
    ops=('capacity.plan_original_guest','capacity.provision_original_guest','capacity.retire_original_guest',
         'capacity.complete_original_guest','capacity.complete_original_guest','capacity.finish_original_guest_retirement',
         'capacity.complete_original_guest')
    steps=[]
    for n,(identity,operation) in enumerate(zip(ids,ops)):
        stamp='2026-11-11T20:09:11.00%04dZ'%n
        steps.append({'id':identity,'kind':'yggdrasil','operation':operation,'capability':operation,
            'status':'failed' if n==0 else 'skipped','attempts':1 if n==0 else 0,
            'metadata':{'original_guest_reconcile_refusal_stage':'installed_resume_claim'} if n==0 else {},
            'started_at':'2026-11-11T20:09:03.992904837Z' if n==0 else stamp,
            'finished_at':'2026-11-11T20:09:11.000000Z' if n==0 else stamp,
            'error':'original Guest held' if n==0 else 'workflow aborted after step "plan-original-guest" failed'})
    w['result']={'status':'failed','workflow':{'kind':'workflow',**{k:env['workflow'][k] for k in ('id','namespace','name','version')}},
                 'metadata':{**env['metadata'],'failed_step':'plan-original-guest'},'steps':steps,
                 'started_at':'2026-11-11T20:09:03.992904837Z','finished_at':steps[0]['finished_at']}
    base={k:0 for k in H.SCAN_BASE99.split()}
    base.update(schema='finalization_lost_dispatch_effect_scan_v1',base_schema='abandoned_started_dispatch_effect_scan_v2',
                clock_skew_margin_seconds=30,provider_read_performed=False,provider_quiescence_proved=False)
    r['scan']={**{k:0 for k in H.SCAN99_COUNTERS.split()},'schema':'preaction_failed_plan_effect_scan_v1',
               'base':base,'current_intent_matches_anchor':True,'current_members_match_anchor':True}
    case={'schema':H.PREACTION99_CASE_SCHEMA,**H.PREACTION99_TARGET,'policy_id':r['intent']['policy_id'],
          'policy_checksum':r['intent']['policy_checksum'],'current_lease_owner':r['intent']['lease_owner'],
          'current_executor_id':r['intent']['lease_executor_id'],'expected_records_sha256':None,
          'provider_lanes':{provider:{'jobs_busy':1 if provider=='aws' else 0,'runs_busy':0,'forward_unreturned_reads':0,
              'live_unreturned_canaries':0,'intent_count':1,'intent_busy':1 if provider=='aws' else 0,
              'pending_authority':0,'forward_markers':0} for provider in ('aws','hetzner')}}
    # Declared Source operands only; no actual historical/Root/full-state custody is claimed.
    case['provider_lanes']['known_hz_preservation']={name:{'path':'/declared-hz99/'+name,
        'sha256':digest(('declared-hz99:'+name).encode())} for name in (
            'helper_source_ref','fixed_current_sql_ref','known_baseline_ref','known_root_ref','policy_state_full_ref')}
    value={'schema':'unknown_preaction_failed_plan_snapshot_v1','observed_at_core':'2026-11-11T21:00:00Z','records_wire':''}
    seal_preaction99(value,case,r)
    return value,case,r


def seal_preaction99(value,case,records):
    value['records_wire']=canonical(records).decode()
    case['expected_records_sha256']=digest(value['records_wire'].encode())


class Catalog99Tests(unittest.TestCase):
    def definitions(self,f):
        return H.constraint99_definitions(f['prior'],f['carrier'],lambda ref:f['blobs'][ref['path']],f['source'],M99_SQL)

    def test_source_carrier_and_all_authorized_old8_overlaps(self):
        f=fixture99();defs=self.definitions(f)
        specs=H.migration99_functions(M99_SQL)
        self.assertEqual(set(specs),set(H.FUNCTIONS99))
        result=H.catalog99_delta(f['prior'],f['before'],f['after'],specs,defs)
        self.assertEqual(set(result),set(H.OLD8.split())|{'schema99'})
        self.assertEqual(result['schema94'],f['prior']['schema94'])
        for role in ('schema98','catalog91','structural98'):
            bad=copy.deepcopy(f['after'])
            if role=='schema98':
                bad[role]['functions']=copy.deepcopy(f['before'][role]['functions'])
            elif role=='catalog91':
                bad['legacy'][role]['shared_dispatch_guard']=copy.deepcopy(f['prior'][role]['shared_dispatch_guard'])
            else:bad[role]['columns'][0]['not_null']=False
            with self.subTest(role=role),self.assertRaises(RuntimeError):
                H.catalog99_delta(f['prior'],f['before'],bad,specs,defs)
        for fault in ('missing','renamed','not_deferred'):
            bad=copy.deepcopy(f)
            row=next(r for r in bad['ci_after']['constraints'] if r['kind']=='t')
            if fault=='missing':bad['ci_after']['constraints'].remove(row)
            elif fault=='renamed':row['name']='foreign_constraint_trigger'
            else:row['definition']='TRIGGER'
            bad['ci_after']['constraints'].sort(key=lambda r:(r['table'],r['name']))
            reseal99(bad)
            with self.subTest(constraint_trigger=fault),self.assertRaises(RuntimeError):self.definitions(bad)
        for removed in ('preaction_failed_plan_job_insert','preaction_failed_plan_workflow_immutable'):
            bad=copy.deepcopy(f['after']);bad['schema98']['triggers']=[r for r in bad['schema98']['triggers'] if r['name']!=removed]
            with self.subTest(missing_overlap=removed),self.assertRaises(RuntimeError):
                H.catalog99_delta(f['prior'],f['before'],bad,specs,defs)

    def test_whole_ci_originals_source_and_unrelated_delta_fail_closed(self):
        f=fixture99();self.definitions(f)
        for kind in ('functions','constraints','triggers','columns','indexes'):
            bad=copy.deepcopy(f);row=copy.deepcopy(bad['ci_after'][kind][0])
            if kind=='columns':row['type']='text'
            elif kind=='indexes':row['ready']=False
            else:row['definition']+=' unrelated'
            bad['ci_after'][kind][0]=row;reseal99(bad)
            with self.subTest(kind=kind),self.assertRaises(RuntimeError):self.definitions(bad)
        with self.assertRaises(RuntimeError):
            H.constraint99_definitions(f['prior'],f['carrier'],lambda ref:f['blobs'][ref['path']]+b' ',f['source'],M99_SQL)
        with self.assertRaises(RuntimeError):
            H.constraint99_definitions(f['prior'],f['carrier'],lambda ref:f['blobs'][ref['path']],'b'*40,M99_SQL)
        with self.assertRaises(RuntimeError):H.migration99_functions(M99_SQL+'\n')
        selector="c.conname IN('capacity_dispatch_jobs_state_v8_check','capacity_dispatch_jobs_lifecycle_v8_check','capacity_dispatch_jobs_state_v9_check','capacity_dispatch_jobs_lifecycle_v9_check','capacity_dispatch_jobs_state_v10_check','capacity_dispatch_jobs_lifecycle_v10_check')"
        sql=H.catalog99_select('declared',base_select=lambda _: 'SELECT '+selector)
        self.assertIn('capacity_dispatch_jobs_state_v11_check',sql);self.assertIn("'ledger98'",sql)
        with self.assertRaises(RuntimeError):H.catalog99_select('declared',base_select=lambda _:'SELECT true')


        # Exercise the real selector on a non-C default collation. This minimum
        # catalog is a disposable sorting fixture, never migration qualification.
        import os
        import subprocess
        import uuid
        container=os.environ.get('GUARDIAN_CI_POSTGRES_CONTAINER','')
        self.assertEqual(os.environ.get('GITHUB_ACTIONS'),'true')
        self.assertRegex(container,r'^[a-f0-9]{64}$')
        self.assertIn(os.environ.get('DOCKER_HOST'),(None,'','unix:///var/run/docker.sock'))
        image=subprocess.run(['docker','inspect','--format','{{.Config.Image}}',container],
                             capture_output=True,timeout=8)
        self.assertEqual(image.returncode,0,image.stderr.decode(errors='replace'))
        self.assertEqual(image.stdout.strip(),b'postgres:16')
        evidence=Path(os.environ['GUARDIAN_CI_EVIDENCE'])/'catalog99-c-order-pg16'
        evidence.mkdir(parents=True,exist_ok=False)
        database='catalog99_c_order_'+uuid.uuid4().hex
        originals=[]
        def psql(db,statement):
            prefix=evidence/('%02d'%(len(originals)+1))
            raw=statement.encode()
            argv=['docker','exec','-i',container,'psql','-X','-q','-v','ON_ERROR_STOP=1',
                  '-A','-t','-U','guardian_ci','-d',db]
            prefix.with_suffix('.SQL').write_bytes(raw)
            result=subprocess.run(argv,input=raw,capture_output=True,timeout=8)
            prefix.with_suffix('.stdout').write_bytes(result.stdout)
            prefix.with_suffix('.stderr').write_bytes(result.stderr)
            prefix.with_suffix('.exit').write_text(str(result.returncode)+'\n')
            originals.append({'SQL':{'name':prefix.with_suffix('.SQL').name,'bytes':len(raw),'sha256':digest(raw)},
                              'stdout':{'name':prefix.with_suffix('.stdout').name,'bytes':len(result.stdout),'sha256':digest(result.stdout)},
                              'stderr':{'name':prefix.with_suffix('.stderr').name,'bytes':len(result.stderr),'sha256':digest(result.stderr)},
                              'exit':result.returncode})
            self.assertEqual(result.returncode,0,result.stderr.decode(errors='replace'))
            self.assertLessEqual(len(result.stdout),16*1024*1024)
            return result.stdout.decode()
        limits="SET statement_timeout='3s'; SET lock_timeout='500ms';\n"
        psql('yggdrasil',limits+'CREATE DATABASE '+database+" TEMPLATE template0 LOCALE_PROVIDER icu ICU_LOCALE 'en-US-u-ka-shifted-ks-level3';")
        try:
            setup="""CREATE EXTENSION pgcrypto;
CREATE TABLE public.goose_db_version(id bigint PRIMARY KEY,version_id bigint,is_applied boolean);
CREATE TABLE public.capacity_dispatch_installed_provision_timeout_dispositions(id uuid PRIMARY KEY);
CREATE TABLE public.capacity_dispatch_preaction_plan_dispositions(
 id uuid PRIMARY KEY,job_id uuid NOT NULL UNIQUE,run_id uuid NOT NULL UNIQUE,
 successor_job_id uuid NOT NULL UNIQUE,successor_run_id uuid NOT NULL UNIQUE);
"""
            psql(database,limits+setup)
            locale=json.loads(psql(database,limits+"""SELECT jsonb_build_object(
 'server_version_num',current_setting('server_version_num')::int,
 'database',current_database(),'provider',d.datlocprovider::text,'icu_locale',d.daticulocale)
 FROM pg_database d WHERE d.datname=current_database();"""))
            self.assertEqual(locale['server_version_num']//10000,16)
            self.assertEqual(locale['database'],database)
            self.assertEqual(locale['provider'],'i');self.assertEqual(locale['icu_locale'],'en-US-u-ka-shifted-ks-level3')
            # Only the inherited-selector token is stubbed. All new complete99,
            # supplement99 and structure99 queries execute exactly as shipped.
            base_select=lambda _: "SELECT jsonb_build_object('declared_selector',"+selector+") FROM (VALUES ('fixture')) c(conname)"
            fixed=H.catalog99_select('declared-minimum-catalog',base_select=base_select)
            self.assertEqual(fixed.count(' COLLATE "C"'),19)
            uncollated=fixed.replace(' COLLATE "C"','')
            self.assertNotIn('COLLATE',uncollated)
            old=json.loads(psql(database,limits+uncollated+';'))
            actual=json.loads(psql(database,limits+fixed+';'))
            names=[row['name'] for row in actual['schema99']['indexes']]
            self.assertEqual(len(names),5)
            self.assertEqual(sum(name.startswith(H.TABLE99+'_') for name in names),3)
            self.assertEqual(len(actual['schema99']['constraints']),5)
            # PostgreSQL-generated truncated successor names reproduce the
            # production failure without inventing a locale-sorted JSON array.
            for kind in ('constraints','indexes'):
                ordering=lambda row:(row['table'],row['name'])
                self.assertNotEqual(old['schema99'][kind],sorted(old['schema99'][kind],key=ordering))
                with self.assertRaisesRegex(RuntimeError,'DECLARED99_QUERY_ORDER_'+kind):
                    H.rows99(old['schema99'][kind],kind)
            for kind in ('functions','constraints','triggers','columns','indexes'):
                H.rows99(actual['schema99'][kind],kind)
                self.assertEqual(sorted(canonical(row) for row in actual['schema99'][kind]),
                                 sorted(canonical(row) for row in old['schema99'][kind]))
            self.assertEqual(actual['schema99']['columns'],old['schema99']['columns'])
            H.rows99(actual['structural99']['indexes'],'indexes')
            self.assertEqual(sorted(canonical(row) for row in actual['structural99']['indexes']),
                             sorted(canonical(row) for row in old['structural99']['indexes']))
            self.assertEqual({k:v for k,v in actual['structural99'].items() if k!='indexes'},
                             {k:v for k,v in old['structural99'].items() if k!='indexes'})
            self.assertEqual({k:v for k,v in actual.items() if k not in ('schema99','structural99')},
                             {k:v for k,v in old.items() if k not in ('schema99','structural99')})
            source=os.environ['SOURCE_COMMIT'];self.assertRegex(source,r'^[a-f0-9]{40}$')
            facts={'schema':'catalog99_real_PG16_nonC_default_sort_regression_v1','source_commit':source,
                   'locale':locale,'fixed_SQL_sha256':digest(fixed.encode()),
                   'uncollated_control_SQL_sha256':digest(uncollated.encode()),
                   'explicit_C_text_operands':19,'generated_index_names':names,
                   'uncollated_actual_constraints_and_indexes_refused':True,
                   'fixed_actual_all_five_arrays_pass_unchanged_rows99':True,
                   'whole_member_rows_and_all_other_fields_identical':True,
                   'scope':'disposable minimum catalog sorting fixture only; no application migration',
                   'Native_Job_or_production_qualification':False,'originals':originals}
        finally:
            psql('yggdrasil',limits+'DROP DATABASE '+database+';')
        (evidence/'RESULT.PUBLIC.json').write_text(json.dumps(facts,indent=2,sort_keys=True)+'\n')

    def test_structure_history_and_distinct_root99_roles(self):
        f=fixture99();defs=self.definitions(f);H.structural99(f['before']['structural99'],defs,True)
        H.structural99(f['after']['structural99'],defs)
        for fault in ('default','identity','index','predicate','server','heap'):
            bad=copy.deepcopy(f['after']['structural99'])
            if fault=='default':bad['columns'][0]['default']='gen_random_uuid()'
            elif fault=='identity':bad['columns'][0]['identity']='a'
            elif fault=='index':bad['indexes'][0]['valid']=False
            elif fault=='predicate':bad['indexes'][0]['predicate']='true'
            elif fault=='server':bad['server_version_num']=True
            else:bad['table']['kind']='p'
            with self.subTest(fault=fault),self.assertRaises(RuntimeError):H.structural99(bad,defs)
        H.history99(f['ci_before']['history_wire'],f['ci_after']['history_wire'])
        bad=json.loads(f['ci_after']['history_wire']);bad[0]['tstamp']='rewritten'
        with self.assertRaises(RuntimeError):H.history99(f['ci_before']['history_wire'],canonical(bad).decode())
        previous=json.loads(ROOT98_ORIGINAL)
        blobs={}
        refs={}
        for key in ('migration_result','before_catalog','after_catalog','source_ci','qualified_image'):
            raw=canonical({'declared_role':key});path='/declared-root99/'+key;blobs[path]=raw
            refs[key]={'path':path,'sha256':digest(raw)}
        pins={'current_ops_source':'c'*40,'business_source':'d'*40,'amd64_D':'e'*64,
              'prior98_history_sha256':previous['complete_history_sha256'],
              'index92_definition_sha256':previous['index92_definition_sha256'],
              'complete_history_sha256':'1'*64,'catalog99_sha256':'2'*64,'catalog90_91_sha256':'3'*64}
        receipt={'schema':'root_goose99_preaction_failed_plan_acceptance_v1','reviewed_by_root':True,
                 'schema_before':98,'schema_after':99,'current_core_source':H.CURRENT_CORE9,
                 'migration99_sha256':H.M99,**pins,'job_uid':'00000000-0000-4000-8000-000000000001',
                 'pod_uid':'00000000-0000-4000-8000-000000000002','exit_code':0,'single_job_create':True,
                 'provider_guest_core_mutations':0,'old_records_and_sdk_preserved':True,'original_refs':refs}
        self.assertEqual(H.root99_overlay(canonical(receipt),ROOT98_ORIGINAL,pins,lambda ref:blobs[ref['path']]),receipt)
        for key,value in (('reviewed_by_root',False),('schema_before',97),('current_core_source','0'*40),('provider_guest_core_mutations',True)):
            bad=copy.deepcopy(receipt);bad[key]=value
            with self.subTest(key=key),self.assertRaises(RuntimeError):
                H.root99_overlay(canonical(bad),ROOT98_ORIGINAL,pins,lambda ref:blobs[ref['path']])

    def test_actual_failed_plan_anchor_and_raw_e70_owned_unknown(self):
        value,case,r=declared_preaction99();self.assertEqual(H.validate_preaction99(value,case),r)
        # Independent authentic error domains are deliberately unequal in the positive.
        self.assertNotEqual(r['job']['return_error'],r['run']['error'])
        for provider in ('aws','hetzner'):
            self.assertEqual(H.preaction99_lanes(case['provider_lanes'][provider],case,provider),case['provider_lanes'][provider])
        for fault in ('ack','plan_success','sdk','anchor_wire','extra_busy','missing_abort','response_clock','foreign_fence','false_int'):
            bad=copy.deepcopy(r);v=copy.deepcopy(value);c=copy.deepcopy(case)
            if fault=='ack':bad['job']['finalization_ack_at']=bad['job']['returned_at']
            elif fault=='plan_success':bad['run']['result']['steps'][0]['status']='succeeded'
            elif fault=='sdk':bad['proofs'][0]['grant']['state']='settled'
            elif fault=='anchor_wire':bad['anchor']['original_run_wire']='\\x7b7d'
            elif fault=='extra_busy':bad['scan']['other_busy_dispatches']=1
            elif fault=='missing_abort':bad['run']['result']['steps'].pop()
            elif fault=='response_clock':bad['run']['result']['started_at']=bad['job']['lease_expires_at']
            elif fault=='foreign_fence':bad['intent']['fencing_token']+=1
            else:bad['scan']['other_busy_runs']=False
            seal_preaction99(v,c,bad)
            with self.subTest(fault=fault),self.assertRaises(RuntimeError):H.validate_preaction99(v,c)
        # Existing M98 witness semantics stay byteexact; this is a declared
        # selector operand, not a fabricated PG catalog/deparse original.
        rollout=Path(__file__).resolve().parent.parent/'rollout'
        old_source=(rollout/'restore98_recovered_g44.py').read_text()
        old_tree=ast.parse(old_source)
        old_bridge=next(n for n in old_tree.body if isinstance(n,ast.Assign)
                        and any(isinstance(x,ast.Name) and x.id=='G44_TERMINAL_UNION' for x in n.targets))
        self.assertEqual(H.G44_TERMINAL_UNION,ast.literal_eval(old_bridge.value))
        old_function=next(n for n in old_tree.body if isinstance(n,ast.FunctionDef) and n.name=='e70_sql')
        new_source=(rollout/'catalog99_helpers.py').read_text()
        new_function=next(n for n in ast.parse(new_source).body
                          if isinstance(n,ast.FunctionDef) and n.name=='e70_sql')
        self.assertEqual(ast.get_source_segment(new_source,new_function),
                         ast.get_source_segment(old_source,old_function).replace('need(','need99('))
        selector="c.conname IN('capacity_dispatch_jobs_state_v8_check','capacity_dispatch_jobs_lifecycle_v8_check','capacity_dispatch_jobs_state_v9_check','capacity_dispatch_jobs_lifecycle_v9_check')"
        legacy=("WITH dispatch_terminal_witnesses AS MATERIALIZED (\n SELECT NULL::uuid AS job_id WHERE false"
                "\n),\npolicies AS MATERIALIZED(SELECT 1 AS version)\n"
                "SELECT count(*) FROM pg_constraint c WHERE "+selector)
        typed_sql=H.e70_sql(legacy)
        expanded=selector[:-1]+",'capacity_dispatch_jobs_state_v10_check','capacity_dispatch_jobs_lifecycle_v10_check')"
        self.assertEqual(typed_sql.replace(H.G44_TERMINAL_UNION,'',1).replace(expanded,selector,1),legacy)
        paired_sql=H.aws_preaction99_query(legacy)
        self.assertIn('raw_e70(value) AS MATERIALIZED (\n'+legacy+'\n)',paired_sql)
        self.assertIn('m98_typed_e70(value) AS MATERIALIZED (\n'+typed_sql+'\n)',paired_sql)
        for invalid_factory in (legacy.replace(selector,'false'),legacy.replace('\n),\npolicies AS MATERIALIZED(','\n),\nwrong_boundary AS MATERIALIZED(')):
            with self.assertRaises(RuntimeError):H.aws_preaction99_query(invalid_factory)
        projected={**case['provider_lanes']['aws'],'policy_catalog_wire':'declared whole policy',
                   'owned_slots':[{'slot':1,'resource_id':'declared'}]}
        raw=copy.deepcopy(projected);raw['jobs_busy']=2
        responses={'raw_e70':raw,'m98_typed_e70':projected}
        untouched=canonical(responses)
        self.assertIs(H.aws_preaction99_projection(responses),projected)
        self.assertEqual(canonical(responses),untouched)
        self.assertEqual(raw['jobs_busy'],2)
        self.assertEqual(H.preaction99_lanes(projected,case,'aws'),case['provider_lanes']['aws'])
        # A nonM98 extra failure remains busy after the single authenticated
        # ancestor projection, so the unchanged jobs1 guard must still refuse.
        extra=copy.deepcopy(responses)
        extra['raw_e70']['jobs_busy']=3;extra['m98_typed_e70']['jobs_busy']=2
        extra_case=copy.deepcopy(case);extra_case['provider_lanes']['aws']['jobs_busy']=2
        with self.assertRaises(RuntimeError):
            H.preaction99_lanes(H.aws_preaction99_projection(extra),extra_case,'aws')
        for fault in ('extra_wrapper','missing_raw','raw_not_dict','typed_not_dict','extra_field',
                      'missing_lane','raw_bool','typed_bool','unproved_ancestor','two_removed','other_lane'):
            bad=copy.deepcopy(responses)
            if fault=='extra_wrapper':bad['ignored']=raw
            elif fault=='missing_raw':bad.pop('raw_e70')
            elif fault=='raw_not_dict':bad['raw_e70']=[]
            elif fault=='typed_not_dict':bad['m98_typed_e70']=[]
            elif fault=='extra_field':bad['raw_e70']['ignored']=0
            elif fault=='missing_lane':
                for row in bad.values():row.pop('runs_busy')
            elif fault=='raw_bool':bad['raw_e70']['runs_busy']=False
            elif fault=='typed_bool':bad['m98_typed_e70']['intent_count']=True
            elif fault=='unproved_ancestor':bad['m98_typed_e70']['jobs_busy']=2
            elif fault=='two_removed':bad['raw_e70']['jobs_busy']=3
            else:bad['raw_e70']['pending_authority']=1
            with self.subTest(e70_projection_fault=fault),self.assertRaises(RuntimeError):
                H.aws_preaction99_projection(bad)
        bad=copy.deepcopy(case);bad['provider_lanes']['aws']['jobs_busy']=0
        with self.assertRaises(RuntimeError):H.preaction99_lanes(bad['provider_lanes']['aws'],bad,'aws')
        for fault in ('missing_context','extra_provider','extra_counter','missing_ref','extra_ref',
                      'missing_ref_field','extra_ref_field','relative_path','parent_path','zero_digest','bool_digest'):
            bad=copy.deepcopy(case);providers=bad['provider_lanes'];context=providers['known_hz_preservation']
            if fault=='missing_context':providers.pop('known_hz_preservation')
            elif fault=='extra_provider':providers['unowned']={}
            elif fault=='extra_counter':providers['aws']['ignored']=0
            elif fault=='missing_ref':context.pop('known_root_ref')
            elif fault=='extra_ref':context['ignored']={}
            elif fault=='missing_ref_field':context['known_root_ref'].pop('sha256')
            elif fault=='extra_ref_field':context['known_root_ref']['ignored']=True
            elif fault=='relative_path':context['known_root_ref']['path']='relative/original'
            elif fault=='parent_path':context['known_root_ref']['path']='/owned/../unowned'
            elif fault=='zero_digest':context['known_root_ref']['sha256']='0'*64
            else:context['known_root_ref']['sha256']=False
            with self.subTest(context_fault=fault),self.assertRaises(RuntimeError):
                H.preaction99_lanes(providers['aws'],bad,'aws')
        self.assertNotIn('public.capacity_dispatch_preaction_plan_dispositions',H.PREACTION99_SQL)
        self.assertNotIn('public.preaction_failed_plan_effect_scan(',H.PREACTION99_SQL)

    def test_goose99_generation282_single_job_and_inert_entrypoint(self):
        # Exercise the real whole14 Core preimage guard before any Job/claim path.
        dep_uid,pod_uid,rs_uid=uid99(810),uid99(811),uid99(812)
        rs_name='yggdrasil-declared-core9';pod_name=rs_name+'-declared'
        rs_uri='/apis/apps/v1/namespaces/dakasa/replicasets/'+rs_name
        config_digest='c'*64;started='2026-11-11T01:20:26Z'
        image=G.PREFIX+G.CURRENT_CORE_D
        dep={'metadata':{'uid':dep_uid,'generation':282,'annotations':{'dakasa.io/core-source-commit':G.CURRENT_CORE_R}},
             'spec':{'replicas':1,'template':{'spec':{'containers':[{'name':'core','image':image}]}}},
             'status':{'observedGeneration':282,'readyReplicas':1,'updatedReplicas':1,'availableReplicas':1,'unavailableReplicas':0}}
        rs={'metadata':{'uid':rs_uid,'name':rs_name,'ownerReferences':[{'uid':dep_uid,'controller':True}]},
            'spec':{'replicas':1,'template':copy.deepcopy(dep['spec']['template'])}}
        pod={'metadata':{'uid':pod_uid,'name':pod_name,'ownerReferences':[{'uid':rs_uid,'controller':True}]},
             'spec':{'nodeName':'declared-brain','containers':[{'name':'core','image':image}]},
             'status':{'phase':'Running','containerStatuses':[{'name':'core','ready':True,'restartCount':0,
                       'containerID':'containerd://declared-core9','state':{'running':{'startedAt':started}},
                       'imageID':image,'image':'sha256:'+config_digest}]}}
        expected={'deployment_uid':dep_uid,'generation':282,
                  'deployment_spec_sha256':G.sha(G.wire(dep['spec'])),
                  'deployment_metadata_sha256':G.sha(G.wire(G.stable_metadata(dep))),
                  'replicaset_name':rs_name,'replicaset_uid':rs_uid,
                  'replicaset_spec_sha256':G.sha(G.wire(rs['spec'])),
                  'replicaset_metadata_sha256':G.sha(G.wire(G.stable_metadata(rs))),
                  'pod_name':pod_name,'pod_uid':pod_uid,'container_id':'containerd://declared-core9',
                  'container_started_at':started,'node_name':'declared-brain',
                  'pod_spec_sha256':G.sha(G.wire(pod['spec']))}
        objects={G.DEP_URI:dep,rs_uri:rs,G.CORE_PODS_URI:{'kind':'PodList','metadata':{},'items':[pod]}}
        with mock.patch.multiple(G,CURRENT_CORE_GENERATION=282,CURRENT_CORE_UID=dep_uid,
                                 CURRENT_CORE_POD_UID=pod_uid,CURRENT_RS_UID=rs_uid,
                                 RS_URI=rs_uri,CURRENT_CORE_CONFIG=config_digest):
            api=mock.Mock();api.get.side_effect=lambda uri:copy.deepcopy(objects[uri])
            actual=G.core(api,expected)
            self.assertEqual(actual,expected);self.assertIsNot(actual,expected)
            self.assertEqual(api.get.call_args_list,[mock.call(G.DEP_URI),mock.call(rs_uri),mock.call(G.CORE_PODS_URI)])
            api.request.assert_not_called()
            stale=copy.deepcopy(expected);stale['generation']=281
            api.get.reset_mock()
            with self.assertRaises(G.Hold):G.core(api,stale)
            api.get.assert_not_called();api.request.assert_not_called()
            with mock.patch.object(G,'CURRENT_CORE_GENERATION',281):
                with self.assertRaises(G.Hold):G.core(api,stale)
            for fault in ('deployment_uid','deployment_spec','deployment_metadata','replicaset_uid','pod_spec','api_generation'):
                with self.subTest(core_preimage_fault=fault):
                    bad=copy.deepcopy(objects)
                    if fault=='deployment_uid':bad[G.DEP_URI]['metadata']['uid']=uid99(813)
                    elif fault=='deployment_spec':bad[G.DEP_URI]['spec']['replicas']=2
                    elif fault=='deployment_metadata':bad[G.DEP_URI]['metadata']['annotations']['foreign']='changed'
                    elif fault=='replicaset_uid':bad[rs_uri]['metadata']['uid']=uid99(814)
                    elif fault=='pod_spec':bad[G.CORE_PODS_URI]['items'][0]['spec']['nodeName']='foreign'
                    else:bad[G.DEP_URI]['status']['observedGeneration']=281
                    api.get.side_effect=lambda uri,bad=bad:copy.deepcopy(bad[uri])
                    with self.assertRaises(G.Hold):G.core(api,expected)
                    api.request.assert_not_called()
        uid=uid99(800);new_digest='d'*64
        with mock.patch.multiple(G,JOB_UUID=uid99(801),COMPANION_IMAGE_D=new_digest):
            job=G.job_manifest();self.assertEqual(job['metadata']['name'],'core-goose99-'+uid99(801).replace('-',''))
            self.assertEqual((job['spec']['backoffLimit'],job['spec']['activeDeadlineSeconds']),(0,240))
            self.assertEqual(job['spec']['template']['spec']['containers'][0]['command'],['/bin/sh','-ceu','/app/goose up'])
            with tempfile.TemporaryDirectory()as folder,mock.patch.object(G,'CLAIM',Path(folder)/'NEW99-CLAIM'),mock.patch.object(G.time,'monotonic',return_value=100),mock.patch.object(G,'JOB_MANIFEST_SHA256',G.sha(G.wire(job))):
                api=mock.Mock();api.get.return_value=None
                api.request.return_value=(201,G.wire({'metadata':{'name':G.job_name(),'namespace':'dakasa','uid':uid}}),{'framing_valid':True})
                backend=types.SimpleNamespace(once=mock.Mock())
                self.assertEqual(G.create_once(api,backend,Path(folder),job,'a'*64,'b'*64,600,100),uid)
                self.assertEqual(api.request.call_args.args[:2],('POST',G.JOB_URI))
                self.assertEqual(api.request.call_count,1)
                self.assertEqual(json.loads(backend.once.call_args_list[0].args[1])['schema'],'goose99_companion_job_possible_v1')

        with mock.patch.object(G,'private_read') as io:
            with self.assertRaises(G.Hold):G.require_bound()
            io.assert_not_called()
        self.assertEqual(G.DB_REFS['DB_PASSWORD'],{'secretKeyRef':{'name':'yggdrasil-secrets','key':'DB_PASSWORD'}})
        self.assertEqual(G.ROOT.name,'goose99-preaction-failed-plan')
        self.assertNotIn('goose98',str(G.CLAIM))


def uid99(number):
    return '00000000-0000-4000-8000-%012d'%number

M99_SQL = '-- +goose Up\n-- ADR-0112: preserve a recorded failed PLAN with no committed authority.\n-- This distinct terminal is neither ACK/success nor provider quiescence/replay.\n-- The applied M87/M91/M98 meanings and every old dispatch guard remain intact.\n-- Regular transactional index: existing Goose lock/build limits remain in force.\nCREATE INDEX IF NOT EXISTS capacity_dispatch_failed_workflow_returned_idx\n ON public.capacity_dispatch_jobs USING btree ((envelope::jsonb #>> \'{workflow,id}\'::text[]),returned_at)\n WHERE state=\'returned\' AND return_status=\'failed\' AND returned_at IS NOT NULL AND finalization_ack_at IS NOT NULL;\n\n\n-- Exact UTC nanoseconds from the authenticated ISO wire, never a clock read.\n-- PostgreSQL\'s timestamptz fraction is microsecond-quantized; retain all nine\n-- raw response/step digits before comparing their causal order.\n-- +goose StatementBegin\nCREATE OR REPLACE FUNCTION public.preaction_failed_plan_timestamp_ns(value text)\nRETURNS numeric LANGUAGE plpgsql IMMUTABLE SET timezone=\'UTC\' AS $$\nDECLARE parts text[]; whole timestamptz; answer numeric;\nBEGIN\n parts=regexp_match(value,\'^([0-9]{4}-[0-9]{2}-[0-9]{2}T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9])(?:[.]([0-9]{1,9}))?(Z|[+-][0-2][0-9]:[0-5][0-9])$\');\n IF parts IS NULL THEN RETURN NULL;END IF;\n whole=(parts[1]||parts[3])::timestamptz;\n IF NOT isfinite(whole)THEN RETURN NULL;END IF;\n answer=extract(epoch FROM whole)*1000000000+substring(coalesce(parts[2],\'\')||\'000000000\' FROM 1 FOR 9)::numeric;\n IF answer=-62135596800000000000 THEN RETURN NULL;END IF;\n RETURN answer;\nEXCEPTION WHEN OTHERS THEN RETURN NULL;\nEND;$$;\n-- +goose StatementEnd\n\n-- +goose StatementBegin\nCREATE OR REPLACE FUNCTION public.preaction_failed_plan_graph_valid(spec jsonb,realm text,policy_name text,binding_name text)\nRETURNS boolean LANGUAGE plpgsql IMMUTABLE AS $$\nDECLARE ref jsonb; common jsonb; use_plan jsonb; want jsonb; step jsonb; n integer;\n ids text[]:=ARRAY[\'plan-original-guest\',\'provision-original-notify\',\'complete-original-provision\',\'retire-original-guest\',\'finish-original-retirement\',\'complete-original-retirement\',\'refresh-original-membership\'];\n ops text[]:=ARRAY[\'capacity.plan_original_guest\',\'capacity.provision_original_guest\',\'capacity.complete_original_guest\',\'capacity.retire_original_guest\',\'capacity.finish_original_guest_retirement\',\'capacity.complete_original_guest\',\'capacity.complete_original_guest\'];\n timeouts integer[]:=ARRAY[90,600,90,180,90,90,90];\nBEGIN\n IF (jsonb_typeof(spec)=\'object\' AND spec->>\'dispatch_mode\'=\'async\' AND jsonb_typeof(spec->\'authorization\')=\'object\'\n AND spec#>>\'{trigger,mode}\'=\'schedule\' AND spec#>\'{trigger,enabled}\'=\'true\'::jsonb AND jsonb_typeof(spec#>\'{trigger,schedule}\')=\'object\'\n AND spec#>\'{input_schema,required}\'=\'["policy"]\'::jsonb AND spec#>\'{input_schema,additionalProperties}\'=\'false\'::jsonb\n AND (SELECT count(*)FROM jsonb_object_keys(spec#>\'{input_schema,properties}\'))=1 AND spec#>>\'{input_schema,properties,policy,type}\'=\'object\'\n AND coalesce(spec->\'defaults\',\'{}\'::jsonb)=\'{}\'::jsonb AND jsonb_typeof(spec->\'steps\')=\'array\' AND jsonb_array_length(spec->\'steps\')=7) IS NOT TRUE THEN RETURN false; END IF;\n ref=jsonb_build_object(\'namespace\',realm,\'name\',policy_name);\n common=jsonb_build_object(\'policy\',ref,\'binding_name\',binding_name,\'slot\',\'{{ steps.plan-original-guest.metadata.slot }}\',\n  \'generation\',\'{{ steps.plan-original-guest.metadata.generation }}\',\'fencing_token\',\'{{ steps.plan-original-guest.metadata.fencing_token }}\',\'lease_owner\',\'{{ steps.plan-original-guest.metadata.lease_owner }}\');\n want=\'[]\'::jsonb;\n FOR n IN 1..7 LOOP\n  step=jsonb_build_object(\'id\',ids[n],\'use\',jsonb_build_object(\'kind\',\'yggdrasil\',\'operation\',ops[n]),\n   \'timeout_seconds\',timeouts[n],\'retry\',jsonb_build_object(\'max_attempts\',1));\n  IF n=1 THEN step=step||jsonb_build_object(\'with\',jsonb_build_object(\'policy\',ref));\n  ELSIF n=7 THEN step=step||jsonb_build_object(\'with\',jsonb_build_object(\'policy\',ref,\'mode\',\'refresh\'),\n   \'condition\',\'{{ steps.plan-original-guest.metadata.mode }} == refresh\',\'depends_on\',jsonb_build_array(\'plan-original-guest\'));\n  ELSE\n   use_plan=common;\n   IF n IN(3,6) THEN use_plan=use_plan||jsonb_build_object(\'mode\',CASE n WHEN 3 THEN \'provision\' ELSE \'retire\' END); END IF;\n   IF n IN(4,5) THEN use_plan=use_plan||jsonb_build_object(\'preregistration_id\',\'{{ steps.plan-original-guest.metadata.preregistration_id }}\'); END IF;\n   IF n IN(5,6) THEN use_plan=use_plan||jsonb_build_object(\'request_id\',\'{{ steps.retire-original-guest.metadata.request_id }}\'); END IF;\n   step=step||jsonb_build_object(\'with\',use_plan,\'condition\',CASE WHEN n IN(2,3) THEN \'{{ steps.plan-original-guest.metadata.mode }} == provision\' ELSE \'{{ steps.plan-original-guest.metadata.mode }} == retire\' END,\n    \'depends_on\',jsonb_build_array(CASE n WHEN 3 THEN \'provision-original-notify\' WHEN 5 THEN \'retire-original-guest\' WHEN 6 THEN \'finish-original-retirement\' ELSE \'plan-original-guest\' END));\n  END IF;\n  want=want||jsonb_build_array(step);\n END LOOP;\n RETURN spec->\'steps\'=want;\nEXCEPTION WHEN OTHERS THEN RETURN false;\nEND; $$;\n-- +goose StatementEnd\n\n-- Same enumerated M83/M84 ledgers and fixed thirty-second skew window.\n-- No provider call, quiescence assertion or current caller flag is evidence.\n-- +goose StatementBegin\nCREATE OR REPLACE FUNCTION public.preaction_failed_plan_effect_scan(job uuid,anchor uuid)\nRETURNS jsonb LANGUAGE sql STABLE SET timezone=\'UTC\' AS $$\nWITH j AS MATERIALIZED(SELECT * FROM public.capacity_dispatch_jobs WHERE id=job),\n a AS MATERIALIZED(SELECT * FROM public.capacity_dispatch_installed_provision_timeout_dispositions WHERE id=anchor),\n win AS(SELECT started_at-interval \'30 seconds\' AS t FROM j),\n it AS(SELECT intent FROM public.capacity_intents i,j WHERE i.namespace=j.realm AND i.environment=j.environment AND i.domain=j.domain AND i.dimension=j.dimension),\n sl AS(SELECT s.* FROM public.capacity_resource_slots s,j WHERE s.namespace=j.realm AND s.environment=j.environment AND s.domain=j.domain AND s.dimension=j.dimension),\n g AS(SELECT g.* FROM public.capacity_mutation_grants g,j WHERE g.namespace=j.realm AND g.environment=j.environment AND g.domain=j.domain AND g.dimension=j.dimension),\n mem AS(SELECT x FROM a,jsonb_array_elements(a.original_record->\'members\')x),\n busy_runs AS(\n  SELECT w.id FROM public.workflow_runs w,j WHERE w.workflow_id=(j.envelope::jsonb#>>\'{workflow,id}\')::uuid AND w.id<>j.run_id\n   AND (coalesce(w.status,\'\') NOT IN(\'succeeded\',\'failed\',\'cancelled\') OR w.finished_at IS NULL)\n  UNION\n  SELECT w.id FROM public.workflow_runs w,j WHERE w.workflow_id IS NULL\n   AND w.workflow_namespace=j.envelope::jsonb#>>\'{workflow,namespace}\' AND w.workflow_name=j.envelope::jsonb#>>\'{workflow,name}\' AND w.id<>j.run_id\n   AND (coalesce(w.status,\'\') NOT IN(\'succeeded\',\'failed\',\'cancelled\') OR w.finished_at IS NULL))\nSELECT jsonb_build_object(\'schema\',\'preaction_failed_plan_effect_scan_v1\',\n \'base\',(SELECT public.finalization_lost_dispatch_effect_scan(j.realm,j.environment,j.domain,j.dimension,j.id,j.started_at,j.lease_expires_at)FROM j),\n \'current_intent_matches_anchor\',coalesce((SELECT it.intent=convert_from(a.original_intent_wire,\'UTF8\')::jsonb FROM it,a),false),\n \'current_members_match_anchor\',coalesce((SELECT\n  (SELECT count(*)FROM sl WHERE resource_id<>\'\' AND slot_record->\'tombstone\'=\'false\'::jsonb)=jsonb_array_length(a.original_record->\'members\')\n  AND NOT EXISTS(SELECT 1 FROM sl WHERE sl.slot_record ? \'authority_kind\' OR sl.resource_id<>\'\' AND sl.slot_record->\'tombstone\'=\'false\'::jsonb AND NOT EXISTS(\n   SELECT 1 FROM mem WHERE sl.integration_instance_id::text=x#>>\'{tuple,integration_instance_id}\' AND sl.scope_checksum=x#>>\'{tuple,scope_checksum}\'\n   AND sl.profile_name=x#>>\'{tuple,profile}\' AND sl.slot=(x->>\'slot\')::integer AND sl.resource_id=x#>>\'{tuple,resource_id}\'\n   AND sl.slot_record->>\'resource_id\'=sl.resource_id AND sl.slot_record->>\'resource_created_at\'=x#>>\'{tuple,resource_created_at}\'\n   AND sl.slot_record->>\'desired_spec_sha256\'=x->>\'request_sha256\'\n   AND EXISTS(SELECT 1 FROM g WHERE g.id::text=x->>\'create_grant_id\' AND g.state=\'confirmed\' AND NOT(g.grant_record ? \'authority_kind\')\n    AND g.original_disposition_id IS NULL AND g.failed_original_disposition_id IS NULL AND g.native_denied_disposition_id IS NULL AND g.enrolled_failed_disposition_id IS NULL)))\n  FROM a),false),\n \'other_busy_dispatches\',(SELECT count(*)FROM public.capacity_dispatch_jobs x,j WHERE x.realm=j.realm AND x.environment=j.environment AND x.domain=j.domain AND x.dimension=j.dimension AND x.id<>j.id\n  AND(x.state IN(\'queued\',\'started\',\'unknown\')OR x.state=\'returned\'AND x.finalization_ack_at IS NULL)),\n \'other_busy_runs\',(SELECT count(*)FROM busy_runs),\n \'authority_issues_since_start\',(SELECT count(*)FROM public.capacity_guest_authority_issues x JOIN public.manifests p ON p.id=x.policy_id CROSS JOIN j,win\n  WHERE(x.issue_id=j.run_id OR p.namespace=j.realm AND p.kind=\'capacity_policy\'AND p.spec->>\'environment\'=j.environment AND p.spec->>\'domain\'=j.domain AND p.spec->>\'dimension\'=j.dimension)\n   AND x.recorded_at>=win.t),\n \'disposal_rows_since_start\',(SELECT count(*)FROM public.capacity_guest_failed_installed_disposals x,j,win WHERE x.namespace=j.realm AND x.environment=j.environment AND x.domain=j.domain AND x.dimension=j.dimension AND x.recorded_at>=win.t)\n  +(SELECT count(*)FROM public.capacity_guest_failed_serving_disposals x,j,win WHERE x.namespace=j.realm AND x.environment=j.environment AND x.domain=j.domain AND x.dimension=j.dimension AND x.recorded_at>=win.t),\n \'retirement_forwards_since_start\',(SELECT count(*)FROM public.capacity_guest_retirement_forwards x,j,win WHERE x.namespace=j.realm AND x.environment=j.environment AND x.domain=j.domain AND x.dimension=j.dimension AND x.recorded_at>=win.t),\n \'retirement_forward_reads_since_start\',(SELECT count(*)FROM public.capacity_guest_retirement_forward_reads x JOIN public.capacity_vm_retirement_intents r ON r.id=x.retirement_request_id JOIN public.capacity_vm_provisioning_preregistrations p ON p.id=r.preregistration_id JOIN g ON g.id=p.create_grant_id CROSS JOIN win WHERE x.recorded_at>=win.t),\n \'undisposed_grants\',(SELECT count(*)FROM g WHERE g.state IN(\'issued\',\'redeemed\',\'settled\',\'compensating\')AND NOT(g.grant_record?\'authority_kind\')\n  AND g.original_disposition_id IS NULL AND g.failed_original_disposition_id IS NULL AND g.native_denied_disposition_id IS NULL AND g.enrolled_failed_disposition_id IS NULL))\n$$;\n-- +goose StatementEnd\n\n-- +goose StatementBegin\nCREATE OR REPLACE FUNCTION public.preaction_failed_plan_effect_scan_tolerable(scan jsonb)\nRETURNS boolean LANGUAGE sql IMMUTABLE AS $$\nSELECT coalesce(jsonb_typeof(scan)=\'object\' AND(SELECT count(*)FROM jsonb_object_keys(scan))=11\n AND scan ?& ARRAY[\'schema\',\'base\',\'current_intent_matches_anchor\',\'current_members_match_anchor\',\'other_busy_dispatches\',\'other_busy_runs\',\'authority_issues_since_start\',\'disposal_rows_since_start\',\'retirement_forwards_since_start\',\'retirement_forward_reads_since_start\',\'undisposed_grants\']\n AND scan->>\'schema\'=\'preaction_failed_plan_effect_scan_v1\'\n AND scan->\'current_intent_matches_anchor\'=\'true\'::jsonb AND scan->\'current_members_match_anchor\'=\'true\'::jsonb\n AND NOT EXISTS(SELECT 1 FROM jsonb_each(scan) x WHERE x.key NOT IN(\'schema\',\'base\',\'current_intent_matches_anchor\',\'current_members_match_anchor\')AND (jsonb_typeof(x.value)IS DISTINCT FROM \'number\' OR x.value::text<>\'0\'))\n AND jsonb_typeof(scan->\'base\')=\'object\' AND(SELECT count(*)FROM jsonb_object_keys(scan->\'base\'))=47\n AND(scan->\'base\') ?& ARRAY[\'schema\',\'clock_skew_margin_seconds\',\'grants_created_or_updated_since_start\',\'open_undisposed_grants\',\'preregistrations_since_start\',\'create_witnesses_since_start\',\'enrollments_since_start\',\'installations_since_start\',\'qualification_probe_challenges_since_start\',\'qualification_native_source_returns_since_start\',\'source_recovery_cleanup_challenges_since_start\',\'source_recovery_cleanup_effect_permits_since_start\',\'partial_nativeoff_reconciliations_since_start\',\'partial_nativeoff_reads_since_start\',\'prejournal_refusal_recoveries_since_start\',\'presend_retirement_recoveries_since_start\',\'retirement_intents_since_start\',\'retirement_contexts_since_start\',\'retirement_original_returns_since_start\',\'retirement_delete_bindings_since_start\',\'retirement_native_readbacks_since_start\',\'caller_possible_sends_since_start\',\'caller_returns_since_start\',\'runtime_snapshot_challenges_since_start\',\'runtime_snapshot_returns_since_start\',\'authority_reads_since_start\',\'authority_returns_since_start\',\'authority_transport_returns_since_start\',\'native_poweroff_reads_since_start\',\'canary_challenges_since_start\',\'canary_nonces_since_start\',\'canary_possible_sends_since_start\',\'canary_returns_since_start\',\'intents_updated_since_start\',\'notify_window_markers_for_job\',\'intent_events_since_start\',\'native_commands_since_start\',\'native_lifetimes_updated_since_start\',\'native_lifetime_archives_since_start\',\'native_pod_checkpoints_since_start\',\'executor_activity_updated_since_start\',\'resource_slots_updated_since_start\',\'provider_read_performed\',\'provider_quiescence_proved\',\'base_schema\',\'pure_assessment_intent_updates\',\'observation_refresh_slot_updates\']\n AND scan#>>\'{base,schema}\'=\'finalization_lost_dispatch_effect_scan_v1\'\n AND scan#>>\'{base,base_schema}\'=\'abandoned_started_dispatch_effect_scan_v2\'\n AND scan#>\'{base,clock_skew_margin_seconds}\'=\'30\'::jsonb\n AND scan#>\'{base,provider_read_performed}\'=\'false\'::jsonb AND scan#>\'{base,provider_quiescence_proved}\'=\'false\'::jsonb\n AND scan#>\'{base,intents_updated_since_start}\'=\'0\'::jsonb AND scan#>\'{base,pure_assessment_intent_updates}\'=\'0\'::jsonb\n AND jsonb_typeof(scan#>\'{base,resource_slots_updated_since_start}\')=\'number\'\n AND scan#>>\'{base,resource_slots_updated_since_start}\'~\'^[0-9]+$\'\n AND scan#>>\'{base,observation_refresh_slot_updates}\'~\'^[0-9]+$\'\n AND scan#>\'{base,resource_slots_updated_since_start}\'=scan#>\'{base,observation_refresh_slot_updates}\'\n AND NOT EXISTS(SELECT 1 FROM jsonb_each(scan->\'base\')x\n  WHERE x.key NOT IN(\'schema\',\'base_schema\',\'clock_skew_margin_seconds\',\'provider_read_performed\',\'provider_quiescence_proved\',\n   \'intents_updated_since_start\',\'pure_assessment_intent_updates\',\'resource_slots_updated_since_start\',\'observation_refresh_slot_updates\')AND (jsonb_typeof(x.value)IS DISTINCT FROM \'number\' OR x.value::text<>\'0\')),false)\n$$;\n-- +goose StatementEnd\n\n-- Error fields are separately authenticated whole originals, never cross-equal:\n-- Finish final_clock may replace only return_error; markFinalizationUnknown\n-- replaces workflow.error plus finalization_error while retaining return_error.\n-- Neither message identity nor a human error category is authority.\n-- Validate only immutable historical custody here. Current eligibility is\n-- rederived separately by INSERT under the actual scope/row locks.\n-- +goose StatementBegin\nCREATE OR REPLACE FUNCTION public.preaction_failed_plan_valid(r jsonb,d bytea,w bytea,i bytea,m bytea,e bytea)\nRETURNS boolean LANGUAGE plpgsql STABLE SET timezone=\'UTC\' AS $$\nDECLARE dj jsonb; rw jsonb; intent jsonb; members jsonb; evidence jsonb; env jsonb; result jsonb; step jsonb; ord integer;\n j public.capacity_dispatch_jobs; run public.workflow_runs; a public.capacity_dispatch_installed_provision_timeout_dispositions;\n policy public.manifests; wf public.manifests;\n previous_step_finished numeric; response_start_ns numeric; response_finish_ns numeric; row_finish_ns numeric;\n ids text[]:=ARRAY[\'plan-original-guest\',\'provision-original-notify\',\'retire-original-guest\',\'refresh-original-membership\',\'complete-original-provision\',\'finish-original-retirement\',\'complete-original-retirement\'];\n ops text[]:=ARRAY[\'capacity.plan_original_guest\',\'capacity.provision_original_guest\',\'capacity.retire_original_guest\',\'capacity.complete_original_guest\',\'capacity.complete_original_guest\',\'capacity.finish_original_guest_retirement\',\'capacity.complete_original_guest\'];\nBEGIN\n IF r IS NULL OR d IS NULL OR w IS NULL OR i IS NULL OR m IS NULL OR e IS NULL\n OR octet_length(d)NOT BETWEEN 1 AND 1048576 OR octet_length(w)NOT BETWEEN 1 AND 8388608\n OR octet_length(i)NOT BETWEEN 1 AND 1048576 OR octet_length(m)NOT BETWEEN 1 AND 1048576 OR octet_length(e)NOT BETWEEN 1 AND 8388608 THEN RETURN false; END IF;\n IF(jsonb_typeof(r)=\'object\'AND(SELECT count(*)FROM jsonb_object_keys(r))=19\n AND r ?& ARRAY[\'schema\',\'id\',\'job_id\',\'run_id\',\'successor_job_id\',\'successor_run_id\',\'root_anchor_id\',\'policy_id\',\'policy_checksum\',\'generation\',\'fencing_token\',\'original_dispatch_sha256\',\'original_run_sha256\',\'original_intent_sha256\',\'members_sha256\',\'evidence_sha256\',\'original_deadline\',\'original_returned_at\',\'recorded_at\']\n AND r->>\'schema\'=\'unknown_preaction_failed_plan_disposition_v1\'\n AND jsonb_typeof(r->\'generation\')=\'number\'AND r->>\'generation\'~\'^[1-9][0-9]*$\'AND(r->>\'generation\')::bigint<=9007199254740991\n AND jsonb_typeof(r->\'fencing_token\')=\'number\'AND r->>\'fencing_token\'~\'^[1-9][0-9]*$\'AND(r->>\'fencing_token\')::bigint<=9007199254740991)IS NOT TRUE THEN RETURN false; END IF;\n IF EXISTS(SELECT 1 FROM unnest(ARRAY[\'id\',\'job_id\',\'run_id\',\'successor_job_id\',\'successor_run_id\',\'root_anchor_id\',\'policy_id\'])k\n  WHERE jsonb_typeof(r->k)IS DISTINCT FROM \'string\'OR r->>k!~\'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$\'OR r->>k=\'00000000-0000-0000-0000-000000000000\')\n OR EXISTS(SELECT 1 FROM unnest(ARRAY[\'policy_checksum\',\'original_dispatch_sha256\',\'original_run_sha256\',\'original_intent_sha256\',\'members_sha256\',\'evidence_sha256\'])k\n  WHERE jsonb_typeof(r->k)IS DISTINCT FROM \'string\'OR r->>k!~\'^[0-9a-f]{64}$\')\n OR EXISTS(SELECT 1 FROM unnest(ARRAY[\'original_deadline\',\'original_returned_at\',\'recorded_at\'])k\n  WHERE jsonb_typeof(r->k)IS DISTINCT FROM \'string\'OR NOT isfinite((r->>k)::timestamptz))\n THEN RETURN false; END IF;\n dj=convert_from(d,\'UTF8\')::jsonb; rw=convert_from(w,\'UTF8\')::jsonb; intent=convert_from(i,\'UTF8\')::jsonb;\n members=convert_from(m,\'UTF8\')::jsonb; evidence=convert_from(e,\'UTF8\')::jsonb;env=(dj->>\'envelope\')::jsonb;result=rw->\'result\';\n IF(encode(sha256(d),\'hex\')=r->>\'original_dispatch_sha256\'AND encode(sha256(w),\'hex\')=r->>\'original_run_sha256\'\n AND encode(sha256(i),\'hex\')=r->>\'original_intent_sha256\'AND encode(sha256(m),\'hex\')=r->>\'members_sha256\'\n AND encode(sha256(e),\'hex\')=r->>\'evidence_sha256\'AND public.preaction_failed_plan_effect_scan_tolerable(evidence)\n AND jsonb_typeof(dj)=\'object\'AND jsonb_typeof(rw)=\'object\'AND jsonb_typeof(intent)=\'object\'\n AND jsonb_typeof(members)=\'array\'AND jsonb_array_length(members)BETWEEN 2 AND 8\n AND r->>\'job_id\'<>r->>\'successor_job_id\'AND r->>\'run_id\'<>r->>\'successor_run_id\')IS NOT TRUE THEN RETURN false; END IF;\n SELECT * INTO j FROM public.capacity_dispatch_jobs WHERE id=(r->>\'job_id\')::uuid;\n IF NOT FOUND THEN RETURN false; END IF;\n SELECT * INTO run FROM public.workflow_runs WHERE id=(r->>\'run_id\')::uuid;\n IF NOT FOUND THEN RETURN false; END IF;\n SELECT * INTO a FROM public.capacity_dispatch_installed_provision_timeout_dispositions WHERE id=(r->>\'root_anchor_id\')::uuid;\n IF NOT FOUND THEN RETURN false; END IF;\n IF(public.installed_provision_timeout_valid(a.original_record,a.original_dispatch_wire,a.original_run_wire,a.original_intent_wire,a.members_wire)\n AND convert_from(a.original_wire,\'UTF8\')::jsonb=a.original_record\n AND a.original_record->>\'policy_id\'=r->>\'policy_id\'AND a.original_record->>\'policy_checksum\'=r->>\'policy_checksum\'\n AND a.original_record->\'generation\'=r->\'generation\'AND a.original_record->\'fencing_token\'=r->\'fencing_token\'\n AND intent=convert_from(a.original_intent_wire,\'UTF8\')::jsonb AND m=a.members_wire\n AND a.recorded_at<=(dj->>\'started_at\')::timestamptz\n AND ((convert_from(a.original_dispatch_wire,\'UTF8\')::jsonb->>\'envelope\')::jsonb-ARRAY[\'job_id\',\'run_id\',\'source_tick\',\'metadata\',\'metadata_sha256\'])\n  =(env-ARRAY[\'job_id\',\'run_id\',\'source_tick\',\'metadata\',\'metadata_sha256\'])\n AND (((convert_from(a.original_dispatch_wire,\'UTF8\')::jsonb->>\'envelope\')::jsonb->\'metadata\')-ARRAY[\'scheduled_for\',\'capacity_dispatch_job_id\'])\n  =((env->\'metadata\')-ARRAY[\'scheduled_for\',\'capacity_dispatch_job_id\'])\n AND dj->>\'id\'=r->>\'job_id\'AND dj->>\'run_id\'=r->>\'run_id\'AND dj->>\'state\'=\'unknown\'\n AND dj->\'finalization_ack_at\'=\'null\'::jsonb AND dj->>\'return_status\'=\'failed\'\n AND jsonb_typeof(dj->\'return_error\')IN(\'string\',\'null\') AND jsonb_typeof(dj->\'finalization_error\')IN(\'string\',\'null\')\n AND(coalesce(length(dj->>\'return_error\'),0)>0 OR coalesce(length(dj->>\'finalization_error\'),0)>0)\n AND(dj->>\'started_at\')::timestamptz<(dj->>\'lease_expires_at\')::timestamptz\n AND(dj->>\'returned_at\')::timestamptz>=(dj->>\'started_at\')::timestamptz\n AND(dj->>\'lease_expires_at\')::timestamptz=(r->>\'original_deadline\')::timestamptz\n AND(dj->>\'returned_at\')::timestamptz=(r->>\'original_returned_at\')::timestamptz\n AND(r->>\'recorded_at\')::timestamptz>=(r->>\'original_deadline\')::timestamptz\n AND(r->>\'recorded_at\')::timestamptz>=(r->>\'original_returned_at\')::timestamptz\n AND j.run_id=run.id AND j.finalization_ack_at IS NULL AND j.state IN(\'unknown\',\'preaction_plan_disposed\')\n AND(to_jsonb(j)-ARRAY[\'state\',\'updated_at\'])=(dj-ARRAY[\'state\',\'updated_at\'])\n AND(j.state=\'preaction_plan_disposed\'OR to_jsonb(j)=dj)\n AND to_jsonb(run)=rw AND rw->>\'status\'=\'failed\'AND jsonb_typeof(rw->\'error\')=\'string\'AND length(rw->>\'error\')>0\n AND(rw->>\'started_at\')::timestamptz=(dj->>\'started_at\')::timestamptz\n AND(rw->>\'finished_at\')::timestamptz=(r->>\'original_returned_at\')::timestamptz\n AND rw#>>\'{metadata,triggered_by}\'=\'workflow_scheduler\'AND rw#>>\'{metadata,capacity_dispatch_job_id}\'=j.id::text\n AND rw->\'metadata\'=env->\'metadata\'AND rw->\'inputs\'=env->\'inputs\'\n AND rw->>\'workflow_namespace\'=env#>>\'{workflow,namespace}\'AND rw->>\'workflow_name\'=env#>>\'{workflow,name}\'\n AND rw->\'workflow_version\'=env#>\'{workflow,version}\'\n AND(rw->\'workflow_id\'=\'null\'::jsonb OR rw->>\'workflow_id\'=env#>>\'{workflow,id}\')\n AND(env->>\'protocol\')=\'capacity_dispatch_prestart_v1\'AND env->>\'protocol\'=dj->>\'protocol\'\n AND env->>\'job_id\'=j.id::text AND env->>\'run_id\'=run.id::text\n AND encode(sha256(convert_to(dj->>\'envelope\',\'UTF8\')),\'hex\')=dj->>\'envelope_sha256\'\n AND env#>>\'{policy,id}\'=r->>\'policy_id\'AND env#>>\'{policy,checksum}\'=r->>\'policy_checksum\'\n AND env#>>\'{metadata,triggered_by}\'=\'workflow_scheduler\'AND env#>>\'{metadata,capacity_dispatch_job_id}\'=j.id::text\n AND intent->>\'namespace\'=j.realm AND intent->>\'environment\'=j.environment AND intent->>\'domain\'=j.domain AND intent->>\'dimension\'=j.dimension\n AND intent->\'generation\'=r->\'generation\'AND intent->\'fencing_token\'=r->\'fencing_token\'\n AND intent->>\'policy_id\'=r->>\'policy_id\'AND intent->>\'policy_checksum\'=r->>\'policy_checksum\')IS NOT TRUE THEN RETURN false; END IF;\n SELECT * INTO policy FROM public.manifests WHERE id=(r->>\'policy_id\')::uuid AND kind=\'capacity_policy\';\n IF NOT FOUND THEN RETURN false; END IF;\n SELECT * INTO wf FROM public.manifests WHERE id=(env#>>\'{workflow,id}\')::uuid AND kind=\'workflow\';\n IF NOT FOUND THEN RETURN false; END IF;\n IF(policy.namespace=j.realm AND policy.checksum=r->>\'policy_checksum\'\n AND wf.namespace=env#>>\'{workflow,namespace}\'AND wf.name=env#>>\'{workflow,name}\'AND to_jsonb(wf.version)=env#>\'{workflow,version}\'AND wf.checksum=env#>>\'{workflow,checksum}\'\n AND public.preaction_failed_plan_graph_valid(wf.spec,policy.namespace,policy.name,policy.spec#>>\'{mutation_bindings,0,name}\')\n AND jsonb_typeof(result)=\'object\'AND result->>\'status\'=\'failed\'AND jsonb_typeof(result->\'steps\')=\'array\'AND jsonb_array_length(result->\'steps\')=7\n AND result->\'metadata\'=((env->\'metadata\')||jsonb_build_object(\'failed_step\',\'plan-original-guest\'))\n AND result->\'workflow\'=jsonb_build_object(\'kind\',\'workflow\',\'id\',wf.id,\'namespace\',wf.namespace,\'name\',wf.name,\'version\',wf.version))IS NOT TRUE THEN RETURN false; END IF;\n response_start_ns=public.preaction_failed_plan_timestamp_ns(result->>\'started_at\');\n response_finish_ns=public.preaction_failed_plan_timestamp_ns(result->>\'finished_at\');\n row_finish_ns=public.preaction_failed_plan_timestamp_ns(rw->>\'finished_at\');\n IF(response_start_ns>=public.preaction_failed_plan_timestamp_ns(rw->>\'started_at\')\n AND response_start_ns<public.preaction_failed_plan_timestamp_ns(dj->>\'lease_expires_at\')\n AND response_finish_ns>=response_start_ns AND response_finish_ns<=row_finish_ns)IS NOT TRUE THEN RETURN false;END IF;\n previous_step_finished=response_start_ns;\n FOR step,ord IN SELECT value,n::integer FROM jsonb_array_elements(result->\'steps\')WITH ORDINALITY x(value,n) LOOP\n  IF(step->>\'id\'=ids[ord]AND step->>\'kind\'=\'yggdrasil\'AND step->>\'operation\'=ops[ord]AND step->>\'capability\'=ops[ord]\n  AND NOT step ?| ARRAY[\'integration_instance\',\'integration_type\']\n  AND public.preaction_failed_plan_timestamp_ns(step->>\'started_at\')>=previous_step_finished\n  AND public.preaction_failed_plan_timestamp_ns(step->>\'finished_at\')>=public.preaction_failed_plan_timestamp_ns(step->>\'started_at\')\n  AND public.preaction_failed_plan_timestamp_ns(step->>\'finished_at\')<=row_finish_ns)IS NOT TRUE THEN RETURN false; END IF;\n  previous_step_finished=public.preaction_failed_plan_timestamp_ns(step->>\'finished_at\');\n  IF ord=1 THEN\n   IF(step->>\'status\'=\'failed\'AND step->\'attempts\'=\'1\'::jsonb\n   AND public.preaction_failed_plan_timestamp_ns(step->>\'finished_at\')=response_finish_ns\n   AND jsonb_typeof(step->\'metadata\')=\'object\'AND(SELECT count(*)FROM jsonb_object_keys(step->\'metadata\'))=1\n   AND jsonb_typeof(step#>\'{metadata,original_guest_reconcile_refusal_stage}\')=\'string\'\n   AND octet_length(step#>>\'{metadata,original_guest_reconcile_refusal_stage}\')BETWEEN 1 AND 128\n   AND strpos(step#>>\'{metadata,original_guest_reconcile_refusal_stage}\',chr(13))=0 AND strpos(step#>>\'{metadata,original_guest_reconcile_refusal_stage}\',chr(10))=0\n   AND btrim(step#>>\'{metadata,original_guest_reconcile_refusal_stage}\',chr(32)||chr(9)||chr(13)||chr(10)||chr(11)||chr(12))=step#>>\'{metadata,original_guest_reconcile_refusal_stage}\')IS NOT TRUE THEN RETURN false; END IF;\n  ELSE\n   IF(step->>\'status\'=\'skipped\'AND coalesce(step->\'attempts\',\'0\'::jsonb)=\'0\'::jsonb\n   AND coalesce(step->\'metadata\',\'{}\'::jsonb)=\'{}\'::jsonb\n   AND step->>\'error\'=\'workflow aborted after step "plan-original-guest" failed\'\n   AND public.preaction_failed_plan_timestamp_ns(step->>\'started_at\')>=response_finish_ns)IS NOT TRUE THEN RETURN false; END IF;\n  END IF;\n END LOOP;\n RETURN true;\nEXCEPTION WHEN OTHERS THEN RETURN false;\nEND; $$;\n-- +goose StatementEnd\n\nCREATE TABLE IF NOT EXISTS public.capacity_dispatch_preaction_plan_dispositions (\n id uuid PRIMARY KEY,\n job_id uuid NOT NULL UNIQUE REFERENCES public.capacity_dispatch_jobs(id),\n run_id uuid NOT NULL UNIQUE REFERENCES public.workflow_runs(id),\n successor_job_id uuid NOT NULL UNIQUE REFERENCES public.capacity_dispatch_jobs(id) DEFERRABLE INITIALLY DEFERRED,\n successor_run_id uuid NOT NULL UNIQUE REFERENCES public.workflow_runs(id) DEFERRABLE INITIALLY DEFERRED,\n original_record jsonb NOT NULL,\n original_wire bytea NOT NULL CHECK(octet_length(original_wire)BETWEEN 1 AND 1048576),\n original_dispatch_wire bytea NOT NULL CHECK(octet_length(original_dispatch_wire)BETWEEN 1 AND 1048576),\n original_run_wire bytea NOT NULL CHECK(octet_length(original_run_wire)BETWEEN 1 AND 8388608),\n original_intent_wire bytea NOT NULL CHECK(octet_length(original_intent_wire)BETWEEN 1 AND 1048576),\n members_wire bytea NOT NULL CHECK(octet_length(members_wire)BETWEEN 1 AND 1048576),\n evidence_wire bytea NOT NULL CHECK(octet_length(evidence_wire)BETWEEN 1 AND 8388608),\n recorded_at timestamptz NOT NULL,\n CHECK(original_record=convert_from(original_wire,\'UTF8\')::jsonb),\n CHECK(id::text=original_record->>\'id\'AND job_id::text=original_record->>\'job_id\'AND run_id::text=original_record->>\'run_id\'\n  AND successor_job_id::text=original_record->>\'successor_job_id\'AND successor_run_id::text=original_record->>\'successor_run_id\'),\n CHECK(recorded_at=(original_record->>\'recorded_at\')::timestamptz)\n);\n\n-- +goose StatementBegin\nCREATE OR REPLACE FUNCTION public.guard_preaction_failed_plan_insert()RETURNS trigger LANGUAGE plpgsql SET timezone=\'UTC\'AS $$\nDECLARE j public.capacity_dispatch_jobs; a public.capacity_dispatch_installed_provision_timeout_dispositions; env jsonb; it jsonb; actual jsonb; policy public.manifests;\nBEGIN\n SELECT * INTO STRICT j FROM public.capacity_dispatch_jobs WHERE id=NEW.job_id;\n IF EXISTS(SELECT 1 FROM unnest(ARRAY[j.realm,j.environment,j.domain,j.dimension])v WHERE v IS NULL OR v!~\'^[ -~]+$\'OR v~\'[<>&]\')THEN RAISE EXCEPTION \'preaction plan requires exact shared scope encoding\';END IF;\n PERFORM pg_advisory_xact_lock(hashtextextended(array_to_json(ARRAY[j.realm,j.environment,j.domain,j.dimension])::text,0));\n SELECT * INTO STRICT j FROM public.capacity_dispatch_jobs WHERE id=NEW.job_id FOR UPDATE;\n env=j.envelope::jsonb;\n PERFORM id FROM public.manifests WHERE id IN((env#>>\'{policy,id}\')::uuid,(env#>>\'{workflow,id}\')::uuid,(env#>>\'{rbac,id}\')::uuid,(env#>>\'{authorization_policy,id}\')::uuid)ORDER BY id FOR SHARE;\n SELECT * INTO STRICT policy FROM public.manifests WHERE id=(env#>>\'{policy,id}\')::uuid;\n SELECT intent INTO STRICT it FROM public.capacity_intents WHERE namespace=j.realm AND environment=j.environment AND domain=j.domain AND dimension=j.dimension FOR UPDATE;\n PERFORM id FROM public.workflow_runs WHERE id=NEW.run_id FOR SHARE;\n PERFORM slot FROM public.capacity_resource_slots WHERE namespace=j.realm AND environment=j.environment AND domain=j.domain AND dimension=j.dimension ORDER BY integration_instance_id,scope_checksum,profile_name,slot FOR SHARE;\n PERFORM id FROM public.capacity_mutation_grants WHERE namespace=j.realm AND environment=j.environment AND domain=j.domain AND dimension=j.dimension ORDER BY id FOR SHARE;\n SELECT * INTO STRICT a FROM public.capacity_dispatch_installed_provision_timeout_dispositions WHERE id=(NEW.original_record->>\'root_anchor_id\')::uuid;\n IF j.state<>\'unknown\'OR j.run_id<>NEW.run_id OR j.finalization_ack_at IS NOT NULL\n OR to_jsonb(j)IS DISTINCT FROM convert_from(NEW.original_dispatch_wire,\'UTF8\')::jsonb\n OR it IS DISTINCT FROM convert_from(NEW.original_intent_wire,\'UTF8\')::jsonb\n OR it IS DISTINCT FROM convert_from(a.original_intent_wire,\'UTF8\')::jsonb\n OR NOT policy.active OR policy.checksum<>NEW.original_record->>\'policy_checksum\'\n OR NOT EXISTS(SELECT 1 FROM public.manifests x WHERE x.id=(env#>>\'{workflow,id}\')::uuid AND x.active AND x.checksum=env#>>\'{workflow,checksum}\')\n OR NOT EXISTS(SELECT 1 FROM public.manifests x WHERE x.id=(env#>>\'{rbac,id}\')::uuid AND x.active AND x.checksum=env#>>\'{rbac,checksum}\')\n OR env?\'authorization_policy\'AND NOT EXISTS(SELECT 1 FROM public.manifests x WHERE x.id=(env#>>\'{authorization_policy,id}\')::uuid AND x.active AND x.checksum=env#>>\'{authorization_policy,checksum}\')\n OR NEW.recorded_at<transaction_timestamp()OR NEW.recorded_at>clock_timestamp()\n OR j.lease_expires_at>NEW.recorded_at OR j.returned_at>NEW.recorded_at\n OR public.preaction_failed_plan_valid(NEW.original_record,NEW.original_dispatch_wire,NEW.original_run_wire,NEW.original_intent_wire,NEW.members_wire,NEW.evidence_wire)IS DISTINCT FROM true\n THEN RAISE EXCEPTION \'preaction plan requires exact closed expired original and immutable anchor\';END IF;\n actual=public.preaction_failed_plan_effect_scan(j.id,a.id);\n IF actual IS DISTINCT FROM convert_from(NEW.evidence_wire,\'UTF8\')::jsonb\n OR public.preaction_failed_plan_effect_scan_tolerable(actual)IS DISTINCT FROM true\n THEN RAISE EXCEPTION \'preaction plan requires independently rederived complete no-claim evidence\';END IF;\n RETURN NEW;\nEND;$$;\n-- +goose StatementEnd\n\n-- +goose StatementBegin\nCREATE OR REPLACE FUNCTION public.check_preaction_failed_plan_transition(old_row public.capacity_dispatch_jobs,new_row public.capacity_dispatch_jobs)\nRETURNS public.capacity_dispatch_jobs LANGUAGE plpgsql AS $$\nDECLARE receipt public.capacity_dispatch_preaction_plan_dispositions;\nBEGIN\n IF old_row.state=\'preaction_plan_disposed\'THEN\n  IF new_row IS DISTINCT FROM old_row THEN RAISE EXCEPTION \'preaction plan terminal is immutable\';END IF;RETURN new_row;\n END IF;\n IF old_row.state<>\'unknown\'OR new_row.state<>\'preaction_plan_disposed\'OR old_row.finalization_ack_at IS NOT NULL\n OR(to_jsonb(new_row)-ARRAY[\'state\',\'updated_at\'])IS DISTINCT FROM(to_jsonb(old_row)-ARRAY[\'state\',\'updated_at\'])\n THEN RAISE EXCEPTION \'preaction plan terminal preserves every original dispatch field\';END IF;\n SELECT * INTO STRICT receipt FROM public.capacity_dispatch_preaction_plan_dispositions WHERE job_id=old_row.id AND run_id=old_row.run_id;\n IF convert_from(receipt.original_dispatch_wire,\'UTF8\')::jsonb IS DISTINCT FROM to_jsonb(old_row)\n OR new_row.updated_at IS DISTINCT FROM receipt.recorded_at\n THEN RAISE EXCEPTION \'preaction plan terminal needs same transaction receipt\';END IF;\n RETURN new_row;\nEND;$$;\n-- +goose StatementEnd\n\n-- +goose StatementBegin\nCREATE OR REPLACE FUNCTION public.guard_preaction_failed_plan_job_insert()RETURNS trigger LANGUAGE plpgsql AS $$\nBEGIN\n IF NEW.state=\'preaction_plan_disposed\'THEN RAISE EXCEPTION \'preaction plan terminal needs retained original job\';END IF;\n RETURN NEW;\nEND;$$;\n-- +goose StatementEnd\n\n-- +goose StatementBegin\nCREATE OR REPLACE FUNCTION public.immutable_preaction_failed_plan()RETURNS trigger LANGUAGE plpgsql AS $$\nBEGIN RAISE EXCEPTION \'preaction plan receipt is immutable\';END;$$;\n-- +goose StatementEnd\n\n-- +goose StatementBegin\nCREATE OR REPLACE FUNCTION public.guard_preaction_failed_plan_workflow()RETURNS trigger LANGUAGE plpgsql AS $$\nBEGIN\n IF EXISTS(SELECT 1 FROM public.capacity_dispatch_preaction_plan_dispositions WHERE run_id=OLD.id)AND(TG_OP=\'DELETE\'OR NEW IS DISTINCT FROM OLD)\n THEN RAISE EXCEPTION \'preaction plan original workflow remains immutable\';END IF;\n IF TG_OP=\'DELETE\'THEN RETURN OLD;END IF;RETURN NEW;\nEND;$$;\n-- +goose StatementEnd\n\n-- Explicit successor IDs are linked only at the SAME transaction\'s commit.\n-- Saved eligibility is historical; do not rerun current-effect checks here,\n-- since that successor is now legitimately pending and later may advance.\n-- +goose StatementBegin\nCREATE OR REPLACE FUNCTION public.require_preaction_failed_plan_links()RETURNS trigger LANGUAGE plpgsql AS $$\nDECLARE j public.capacity_dispatch_jobs; s public.capacity_dispatch_jobs; w public.workflow_runs; original jsonb; env jsonb; next_env jsonb;\nBEGIN\n SELECT * INTO STRICT j FROM public.capacity_dispatch_jobs WHERE id=NEW.job_id;\n SELECT * INTO STRICT s FROM public.capacity_dispatch_jobs WHERE id=NEW.successor_job_id;\n SELECT * INTO STRICT w FROM public.workflow_runs WHERE id=NEW.successor_run_id;\n original=convert_from(NEW.original_dispatch_wire,\'UTF8\')::jsonb;env=j.envelope::jsonb;next_env=s.envelope::jsonb;\n IF j.state<>\'preaction_plan_disposed\'OR j.run_id<>NEW.run_id OR j.finalization_ack_at IS NOT NULL OR j.updated_at IS DISTINCT FROM NEW.recorded_at\n OR(to_jsonb(j)-ARRAY[\'state\',\'updated_at\'])IS DISTINCT FROM(original-ARRAY[\'state\',\'updated_at\'])\n OR public.preaction_failed_plan_valid(NEW.original_record,NEW.original_dispatch_wire,NEW.original_run_wire,NEW.original_intent_wire,NEW.members_wire,NEW.evidence_wire)IS DISTINCT FROM true\n OR s.run_id<>NEW.successor_run_id OR s.id=j.id OR s.run_id=j.run_id OR s.source_tick=j.source_tick\n OR s.state<>\'queued\'OR s.started_at IS NOT NULL OR s.returned_at IS NOT NULL OR s.finalization_ack_at IS NOT NULL\n OR s.lease_owner IS NOT NULL OR s.lease_expires_at IS NOT NULL OR s.fencing_token<>0\n OR s.realm<>j.realm OR s.environment<>j.environment OR s.domain<>j.domain OR s.dimension<>j.dimension\n OR w.status<>\'pending\'OR w.started_at IS NOT NULL OR w.finished_at IS NOT NULL\n OR(next_env-ARRAY[\'job_id\',\'run_id\',\'source_tick\',\'metadata\',\'metadata_sha256\'])IS DISTINCT FROM(env-ARRAY[\'job_id\',\'run_id\',\'source_tick\',\'metadata\',\'metadata_sha256\'])\n OR((next_env->\'metadata\')-ARRAY[\'scheduled_for\',\'capacity_dispatch_job_id\'])IS DISTINCT FROM((env->\'metadata\')-ARRAY[\'scheduled_for\',\'capacity_dispatch_job_id\'])\n OR next_env->>\'job_id\'<>s.id::text OR next_env->>\'run_id\'<>s.run_id::text OR next_env->>\'source_tick\'<>s.source_tick\n OR next_env#>>\'{metadata,capacity_dispatch_job_id}\'<>s.id::text OR next_env#>>\'{metadata,scheduled_for}\'<>s.source_tick\n OR w.metadata IS DISTINCT FROM next_env->\'metadata\'OR w.inputs IS DISTINCT FROM next_env->\'inputs\'\n OR w.workflow_namespace IS DISTINCT FROM next_env#>>\'{workflow,namespace}\'OR w.workflow_name IS DISTINCT FROM next_env#>>\'{workflow,name}\'\n OR w.workflow_version IS DISTINCT FROM(next_env#>>\'{workflow,version}\')::integer\n OR encode(sha256(convert_to(s.envelope,\'UTF8\')),\'hex\')<>s.envelope_sha256\n OR NOT EXISTS(SELECT 1 FROM public.capacity_dispatch_wakes x WHERE x.job_id=s.id AND x.realm=s.realm AND x.environment=s.environment AND x.domain=s.domain AND x.dimension=s.dimension AND x.source_tick=s.source_tick)\n THEN RAISE EXCEPTION \'preaction plan needs one exact distinct queued successor and unchanged originals in same commit\';END IF;\n RETURN NULL;\nEND;$$;\n-- +goose StatementEnd\nALTER TABLE public.capacity_dispatch_jobs DROP CONSTRAINT IF EXISTS capacity_dispatch_jobs_state_v10_check;\nALTER TABLE public.capacity_dispatch_jobs DROP CONSTRAINT IF EXISTS capacity_dispatch_jobs_lifecycle_v10_check;\nALTER TABLE public.capacity_dispatch_jobs ADD CONSTRAINT capacity_dispatch_jobs_state_v11_check\n CHECK(state IN(\'queued\',\'started\',\'unknown\',\'returned\',\'prestart_rejected\',\'failed_disposed\',\'native_denied_disposed\',\'enrolled_failed_disposed\',\'abandoned_disposed\',\'finalization_lost_disposed\',\'unknown_maintenance_disposed\',\'http_maintenance_disposed\',\'installed_timeout_disposed\',\'preaction_plan_disposed\'));\nALTER TABLE public.capacity_dispatch_jobs ADD CONSTRAINT capacity_dispatch_jobs_lifecycle_v11_check CHECK(\n (state IN(\'queued\',\'prestart_rejected\') AND started_at IS NULL AND returned_at IS NULL)\n OR(state=\'started\' AND started_at IS NOT NULL AND returned_at IS NULL)\n OR(state=\'unknown\' AND started_at IS NOT NULL)\n OR(state IN(\'returned\',\'failed_disposed\',\'native_denied_disposed\',\'enrolled_failed_disposed\',\'unknown_maintenance_disposed\',\'http_maintenance_disposed\',\'installed_timeout_disposed\',\'preaction_plan_disposed\') AND started_at IS NOT NULL AND returned_at IS NOT NULL)\n OR(state IN(\'abandoned_disposed\',\'finalization_lost_disposed\') AND started_at IS NOT NULL AND returned_at IS NULL));\n\n-- +goose StatementBegin\nCREATE OR REPLACE FUNCTION public.guard_capacity_dispatch_job() RETURNS trigger\n    LANGUAGE plpgsql AS $$\nBEGIN\n    IF OLD.state=\'preaction_plan_disposed\' OR NEW.state=\'preaction_plan_disposed\' THEN\n        RETURN public.check_preaction_failed_plan_transition(OLD,NEW);\n    END IF;\n    IF OLD.state=\'installed_timeout_disposed\' OR NEW.state=\'installed_timeout_disposed\' THEN\n        RETURN public.check_installed_provision_timeout_transition(OLD,NEW);\n    END IF;\n    IF OLD.state=\'http_maintenance_disposed\' OR NEW.state=\'http_maintenance_disposed\' THEN\n        RETURN public.check_http_maintenance_dispatch_transition(OLD,NEW);\n    END IF;\n    IF OLD.state=\'unknown_maintenance_disposed\' OR NEW.state=\'unknown_maintenance_disposed\'\n       OR OLD.unknown_maintenance_disposition_id IS NOT NULL OR NEW.unknown_maintenance_disposition_id IS NOT NULL THEN\n        RETURN public.check_unknown_maintenance_dispatch_transition(OLD,NEW);\n    END IF;\n    IF OLD.state=\'finalization_lost_disposed\' OR NEW.state=\'finalization_lost_disposed\'\n       OR OLD.finalization_lost_disposition_id IS NOT NULL OR NEW.finalization_lost_disposition_id IS NOT NULL THEN\n        RETURN public.check_finalization_lost_dispatch_transition(OLD,NEW);\n    END IF;\n    IF OLD.state=\'abandoned_disposed\' OR NEW.state=\'abandoned_disposed\'\n       OR OLD.abandoned_disposition_id IS NOT NULL OR NEW.abandoned_disposition_id IS NOT NULL THEN\n        RETURN public.check_abandoned_dispatch_transition(OLD,NEW);\n    END IF;\n    IF OLD.state=\'enrolled_failed_disposed\' OR NEW.state=\'enrolled_failed_disposed\'\n       OR OLD.enrolled_failed_disposition_id IS NOT NULL OR NEW.enrolled_failed_disposition_id IS NOT NULL THEN\n        RETURN public.check_enrolled_failed_original_dispatch_transition(OLD,NEW);\n    END IF;\n    IF OLD.state=\'native_denied_disposed\' OR NEW.state=\'native_denied_disposed\'\n       OR OLD.native_denied_disposition_id IS NOT NULL OR NEW.native_denied_disposition_id IS NOT NULL THEN\n        RETURN public.check_native_denied_dispatch_transition(OLD,NEW);\n    END IF;\n    IF OLD.state=\'failed_disposed\' OR NEW.state=\'failed_disposed\'\n       OR OLD.failed_original_disposition_id IS NOT NULL OR NEW.failed_original_disposition_id IS NOT NULL THEN\n        RETURN public.check_failed_original_dispatch_transition(OLD,NEW);\n    END IF;\n    IF (NEW.id, NEW.run_id, NEW.protocol, NEW.realm, NEW.environment, NEW.domain,\n        NEW.dimension, NEW.source_tick, NEW.envelope, NEW.envelope_sha256, NEW.created_at)\n       IS DISTINCT FROM\n       (OLD.id, OLD.run_id, OLD.protocol, OLD.realm, OLD.environment, OLD.domain,\n        OLD.dimension, OLD.source_tick, OLD.envelope, OLD.envelope_sha256, OLD.created_at) THEN\n        RAISE EXCEPTION \'capacity dispatch immutable identity\';\n    END IF;\n    IF OLD.started_at IS NOT NULL AND\n       (NEW.started_at, NEW.lease_owner, NEW.fencing_token, NEW.lease_expires_at)\n       IS DISTINCT FROM\n       (OLD.started_at, OLD.lease_owner, OLD.fencing_token, OLD.lease_expires_at) THEN\n        RAISE EXCEPTION \'capacity dispatch immutable start ownership\';\n    END IF;\n    IF OLD.started_at IS NULL AND NEW.started_at IS NOT NULL AND\n       (OLD.protocol <> \'capacity_dispatch_prestart_v1\' OR OLD.state <> \'queued\'\n        OR NEW.state <> \'started\' OR NEW.lease_owner IS NULL\n        OR NEW.lease_expires_at IS NULL OR clock_timestamp() >= NEW.lease_expires_at\n        OR NEW.started_at >= NEW.lease_expires_at) THEN\n        RAISE EXCEPTION \'capacity dispatch start requires live original deadline\';\n    END IF;\n    IF OLD.started_at IS NULL AND\n       (NEW.lease_owner, NEW.fencing_token, NEW.lease_expires_at) IS DISTINCT FROM\n       (OLD.lease_owner, OLD.fencing_token, OLD.lease_expires_at) AND\n       (OLD.protocol <> \'capacity_dispatch_prestart_v1\' OR OLD.state <> \'queued\'\n        OR NEW.state <> \'queued\' OR NEW.started_at IS NOT NULL\n        OR NEW.fencing_token <> OLD.fencing_token + 1 OR NEW.lease_owner IS NULL\n        OR NEW.lease_expires_at IS NULL OR NEW.lease_expires_at <= clock_timestamp()\n        OR OLD.lease_expires_at > clock_timestamp()) THEN\n        RAISE EXCEPTION \'capacity dispatch claim requires expired prestart fence\';\n    END IF;\n    IF NEW.pending_wake_count < OLD.pending_wake_count OR\n       NEW.pending_wake_count > OLD.pending_wake_count + 1 THEN\n        RAISE EXCEPTION \'capacity dispatch bounded wake increment\';\n    END IF;\n    IF OLD.returned_at IS NOT NULL AND NEW.returned_at IS DISTINCT FROM OLD.returned_at THEN\n        RAISE EXCEPTION \'capacity dispatch immutable actual return\';\n    END IF;\n    IF OLD.returned_at IS NOT NULL AND\n       (NEW.return_status, NEW.return_error) IS DISTINCT FROM\n       (OLD.return_status, OLD.return_error) THEN\n        RAISE EXCEPTION \'capacity dispatch immutable actual return cause\';\n    END IF;\n    IF OLD.finalization_ack_at IS NOT NULL AND\n       (NEW.finalization_ack_at,NEW.state) IS DISTINCT FROM\n       (OLD.finalization_ack_at,OLD.state) THEN\n        RAISE EXCEPTION \'capacity dispatch immutable observed acknowledgment\';\n    END IF;\n    IF OLD.finalization_ack_at IS NULL AND NEW.finalization_ack_at IS NOT NULL AND\n       (OLD.state <> \'returned\' OR OLD.returned_at IS NULL OR NEW.state <> \'returned\'\n        OR clock_timestamp() >= OLD.lease_expires_at) THEN\n        RAISE EXCEPTION \'capacity dispatch acknowledgment requires live original owner\';\n    END IF;\n    -- A truthful original return is retained when the commit acknowledgment\n    -- crosses the original context/deadline. Downgrade only; never replay.\n    IF (OLD.state = \'returned\' AND NEW.state NOT IN (\'returned\', \'unknown\')) OR\n       (OLD.state = \'unknown\' AND NEW.state <> \'unknown\') OR\n       (OLD.state = \'started\' AND NEW.state = \'queued\') THEN\n        RAISE EXCEPTION \'capacity dispatch cannot replay\';\n    END IF;\n    RETURN NEW;\nEND;\n$$;\n-- +goose StatementEnd\n\n-- +goose StatementBegin\nDO $idempotent$ BEGIN\n IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid=\'public.capacity_dispatch_preaction_plan_dispositions\'::regclass AND tgname=\'preaction_failed_plan_insert\')THEN\n  CREATE TRIGGER preaction_failed_plan_insert BEFORE INSERT ON public.capacity_dispatch_preaction_plan_dispositions FOR EACH ROW EXECUTE FUNCTION public.guard_preaction_failed_plan_insert();\n END IF;\n IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid=\'public.capacity_dispatch_preaction_plan_dispositions\'::regclass AND tgname=\'preaction_failed_plan_immutable\')THEN\n  CREATE TRIGGER preaction_failed_plan_immutable BEFORE UPDATE OR DELETE ON public.capacity_dispatch_preaction_plan_dispositions FOR EACH ROW EXECUTE FUNCTION public.immutable_preaction_failed_plan();\n END IF;\n IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid=\'public.capacity_dispatch_preaction_plan_dispositions\'::regclass AND tgname=\'preaction_failed_plan_complete_links\')THEN\n  CREATE CONSTRAINT TRIGGER preaction_failed_plan_complete_links AFTER INSERT ON public.capacity_dispatch_preaction_plan_dispositions DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.require_preaction_failed_plan_links();\n END IF;\n IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid=\'public.capacity_dispatch_jobs\'::regclass AND tgname=\'preaction_failed_plan_job_insert\')THEN\n  CREATE TRIGGER preaction_failed_plan_job_insert BEFORE INSERT ON public.capacity_dispatch_jobs FOR EACH ROW EXECUTE FUNCTION public.guard_preaction_failed_plan_job_insert();\n END IF;\n IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid=\'public.workflow_runs\'::regclass AND tgname=\'preaction_failed_plan_workflow_immutable\')THEN\n  CREATE TRIGGER preaction_failed_plan_workflow_immutable BEFORE UPDATE OR DELETE ON public.workflow_runs FOR EACH ROW EXECUTE FUNCTION public.guard_preaction_failed_plan_workflow();\n END IF;\nEND;$idempotent$;\n-- +goose StatementEnd\n\n-- +goose Down\n-- Never delete a retained historical proof or reinterpret a terminal to roll back.\n-- +goose StatementBegin\nDO $refuse$ BEGIN\n IF EXISTS(SELECT 1 FROM public.capacity_dispatch_preaction_plan_dispositions)\n OR EXISTS(SELECT 1 FROM public.capacity_dispatch_jobs WHERE state=\'preaction_plan_disposed\')\n THEN RAISE EXCEPTION \'retained preaction plan evidence prevents rollback\';END IF;\nEND;$refuse$;\n-- +goose StatementEnd\nDROP TRIGGER IF EXISTS preaction_failed_plan_workflow_immutable ON public.workflow_runs;\nDROP TRIGGER IF EXISTS preaction_failed_plan_job_insert ON public.capacity_dispatch_jobs;\nDROP TRIGGER IF EXISTS preaction_failed_plan_complete_links ON public.capacity_dispatch_preaction_plan_dispositions;\nDROP TRIGGER IF EXISTS preaction_failed_plan_immutable ON public.capacity_dispatch_preaction_plan_dispositions;\nDROP TRIGGER IF EXISTS preaction_failed_plan_insert ON public.capacity_dispatch_preaction_plan_dispositions;\n-- +goose StatementBegin\nCREATE OR REPLACE FUNCTION public.guard_capacity_dispatch_job() RETURNS trigger\n    LANGUAGE plpgsql AS $$\nBEGIN\n    IF OLD.state=\'installed_timeout_disposed\' OR NEW.state=\'installed_timeout_disposed\' THEN\n        RETURN public.check_installed_provision_timeout_transition(OLD,NEW);\n    END IF;\n    IF OLD.state=\'http_maintenance_disposed\' OR NEW.state=\'http_maintenance_disposed\' THEN\n        RETURN public.check_http_maintenance_dispatch_transition(OLD,NEW);\n    END IF;\n    IF OLD.state=\'unknown_maintenance_disposed\' OR NEW.state=\'unknown_maintenance_disposed\'\n       OR OLD.unknown_maintenance_disposition_id IS NOT NULL OR NEW.unknown_maintenance_disposition_id IS NOT NULL THEN\n        RETURN public.check_unknown_maintenance_dispatch_transition(OLD,NEW);\n    END IF;\n    IF OLD.state=\'finalization_lost_disposed\' OR NEW.state=\'finalization_lost_disposed\'\n       OR OLD.finalization_lost_disposition_id IS NOT NULL OR NEW.finalization_lost_disposition_id IS NOT NULL THEN\n        RETURN public.check_finalization_lost_dispatch_transition(OLD,NEW);\n    END IF;\n    IF OLD.state=\'abandoned_disposed\' OR NEW.state=\'abandoned_disposed\'\n       OR OLD.abandoned_disposition_id IS NOT NULL OR NEW.abandoned_disposition_id IS NOT NULL THEN\n        RETURN public.check_abandoned_dispatch_transition(OLD,NEW);\n    END IF;\n    IF OLD.state=\'enrolled_failed_disposed\' OR NEW.state=\'enrolled_failed_disposed\'\n       OR OLD.enrolled_failed_disposition_id IS NOT NULL OR NEW.enrolled_failed_disposition_id IS NOT NULL THEN\n        RETURN public.check_enrolled_failed_original_dispatch_transition(OLD,NEW);\n    END IF;\n    IF OLD.state=\'native_denied_disposed\' OR NEW.state=\'native_denied_disposed\'\n       OR OLD.native_denied_disposition_id IS NOT NULL OR NEW.native_denied_disposition_id IS NOT NULL THEN\n        RETURN public.check_native_denied_dispatch_transition(OLD,NEW);\n    END IF;\n    IF OLD.state=\'failed_disposed\' OR NEW.state=\'failed_disposed\'\n       OR OLD.failed_original_disposition_id IS NOT NULL OR NEW.failed_original_disposition_id IS NOT NULL THEN\n        RETURN public.check_failed_original_dispatch_transition(OLD,NEW);\n    END IF;\n    IF (NEW.id, NEW.run_id, NEW.protocol, NEW.realm, NEW.environment, NEW.domain,\n        NEW.dimension, NEW.source_tick, NEW.envelope, NEW.envelope_sha256, NEW.created_at)\n       IS DISTINCT FROM\n       (OLD.id, OLD.run_id, OLD.protocol, OLD.realm, OLD.environment, OLD.domain,\n        OLD.dimension, OLD.source_tick, OLD.envelope, OLD.envelope_sha256, OLD.created_at) THEN\n        RAISE EXCEPTION \'capacity dispatch immutable identity\';\n    END IF;\n    IF OLD.started_at IS NOT NULL AND\n       (NEW.started_at, NEW.lease_owner, NEW.fencing_token, NEW.lease_expires_at)\n       IS DISTINCT FROM\n       (OLD.started_at, OLD.lease_owner, OLD.fencing_token, OLD.lease_expires_at) THEN\n        RAISE EXCEPTION \'capacity dispatch immutable start ownership\';\n    END IF;\n    IF OLD.started_at IS NULL AND NEW.started_at IS NOT NULL AND\n       (OLD.protocol <> \'capacity_dispatch_prestart_v1\' OR OLD.state <> \'queued\'\n        OR NEW.state <> \'started\' OR NEW.lease_owner IS NULL\n        OR NEW.lease_expires_at IS NULL OR clock_timestamp() >= NEW.lease_expires_at\n        OR NEW.started_at >= NEW.lease_expires_at) THEN\n        RAISE EXCEPTION \'capacity dispatch start requires live original deadline\';\n    END IF;\n    IF OLD.started_at IS NULL AND\n       (NEW.lease_owner, NEW.fencing_token, NEW.lease_expires_at) IS DISTINCT FROM\n       (OLD.lease_owner, OLD.fencing_token, OLD.lease_expires_at) AND\n       (OLD.protocol <> \'capacity_dispatch_prestart_v1\' OR OLD.state <> \'queued\'\n        OR NEW.state <> \'queued\' OR NEW.started_at IS NOT NULL\n        OR NEW.fencing_token <> OLD.fencing_token + 1 OR NEW.lease_owner IS NULL\n        OR NEW.lease_expires_at IS NULL OR NEW.lease_expires_at <= clock_timestamp()\n        OR OLD.lease_expires_at > clock_timestamp()) THEN\n        RAISE EXCEPTION \'capacity dispatch claim requires expired prestart fence\';\n    END IF;\n    IF NEW.pending_wake_count < OLD.pending_wake_count OR\n       NEW.pending_wake_count > OLD.pending_wake_count + 1 THEN\n        RAISE EXCEPTION \'capacity dispatch bounded wake increment\';\n    END IF;\n    IF OLD.returned_at IS NOT NULL AND NEW.returned_at IS DISTINCT FROM OLD.returned_at THEN\n        RAISE EXCEPTION \'capacity dispatch immutable actual return\';\n    END IF;\n    IF OLD.returned_at IS NOT NULL AND\n       (NEW.return_status, NEW.return_error) IS DISTINCT FROM\n       (OLD.return_status, OLD.return_error) THEN\n        RAISE EXCEPTION \'capacity dispatch immutable actual return cause\';\n    END IF;\n    IF OLD.finalization_ack_at IS NOT NULL AND\n       (NEW.finalization_ack_at,NEW.state) IS DISTINCT FROM\n       (OLD.finalization_ack_at,OLD.state) THEN\n        RAISE EXCEPTION \'capacity dispatch immutable observed acknowledgment\';\n    END IF;\n    IF OLD.finalization_ack_at IS NULL AND NEW.finalization_ack_at IS NOT NULL AND\n       (OLD.state <> \'returned\' OR OLD.returned_at IS NULL OR NEW.state <> \'returned\'\n        OR clock_timestamp() >= OLD.lease_expires_at) THEN\n        RAISE EXCEPTION \'capacity dispatch acknowledgment requires live original owner\';\n    END IF;\n    -- A truthful original return is retained when the commit acknowledgment\n    -- crosses the original context/deadline. Downgrade only; never replay.\n    IF (OLD.state = \'returned\' AND NEW.state NOT IN (\'returned\', \'unknown\')) OR\n       (OLD.state = \'unknown\' AND NEW.state <> \'unknown\') OR\n       (OLD.state = \'started\' AND NEW.state = \'queued\') THEN\n        RAISE EXCEPTION \'capacity dispatch cannot replay\';\n    END IF;\n    RETURN NEW;\nEND;\n$$;\n-- +goose StatementEnd\nALTER TABLE public.capacity_dispatch_jobs DROP CONSTRAINT IF EXISTS capacity_dispatch_jobs_state_v11_check;\nALTER TABLE public.capacity_dispatch_jobs DROP CONSTRAINT IF EXISTS capacity_dispatch_jobs_lifecycle_v11_check;\nALTER TABLE public.capacity_dispatch_jobs ADD CONSTRAINT capacity_dispatch_jobs_state_v10_check\n CHECK(state IN(\'queued\',\'started\',\'unknown\',\'returned\',\'prestart_rejected\',\'failed_disposed\',\'native_denied_disposed\',\'enrolled_failed_disposed\',\'abandoned_disposed\',\'finalization_lost_disposed\',\'unknown_maintenance_disposed\',\'http_maintenance_disposed\',\'installed_timeout_disposed\'));\nALTER TABLE public.capacity_dispatch_jobs ADD CONSTRAINT capacity_dispatch_jobs_lifecycle_v10_check CHECK(\n (state IN(\'queued\',\'prestart_rejected\') AND started_at IS NULL AND returned_at IS NULL)\n OR(state=\'started\' AND started_at IS NOT NULL AND returned_at IS NULL)\n OR(state=\'unknown\' AND started_at IS NOT NULL)\n OR(state IN(\'returned\',\'failed_disposed\',\'native_denied_disposed\',\'enrolled_failed_disposed\',\'unknown_maintenance_disposed\',\'http_maintenance_disposed\',\'installed_timeout_disposed\') AND started_at IS NOT NULL AND returned_at IS NOT NULL)\n OR(state IN(\'abandoned_disposed\',\'finalization_lost_disposed\') AND started_at IS NOT NULL AND returned_at IS NULL));\nDROP FUNCTION IF EXISTS public.require_preaction_failed_plan_links();\nDROP FUNCTION IF EXISTS public.guard_preaction_failed_plan_workflow();\nDROP FUNCTION IF EXISTS public.immutable_preaction_failed_plan();\nDROP FUNCTION IF EXISTS public.guard_preaction_failed_plan_job_insert();\nDROP FUNCTION IF EXISTS public.check_preaction_failed_plan_transition(public.capacity_dispatch_jobs,public.capacity_dispatch_jobs);\nDROP FUNCTION IF EXISTS public.guard_preaction_failed_plan_insert();\nDROP TABLE IF EXISTS public.capacity_dispatch_preaction_plan_dispositions;\nDROP FUNCTION IF EXISTS public.preaction_failed_plan_valid(jsonb,bytea,bytea,bytea,bytea,bytea);\nDROP FUNCTION IF EXISTS public.preaction_failed_plan_effect_scan(uuid,uuid);\nDROP FUNCTION IF EXISTS public.preaction_failed_plan_effect_scan_tolerable(jsonb);\nDROP FUNCTION IF EXISTS public.preaction_failed_plan_graph_valid(jsonb,text,text,text);\nDROP FUNCTION IF EXISTS public.preaction_failed_plan_timestamp_ns(text);\nDROP INDEX IF EXISTS public.capacity_dispatch_failed_workflow_returned_idx;\n'
ROOT98_ORIGINAL = b'{"amd64_D":"ed5ee3a2a5e90e54acc3cc2492fcc302a85e1b7adb6f545c605c5bfe2a730b42","business_source":"9f0266de7a2982352b7ff8fd627e73ceba12c896","catalog90_91_sha256":"5d389dc43e18a761eba20071ea19cc2b1c623fb2ec7e901dd34dc40c02b76397","catalog98_sha256":"83862b62bf2a0ec2390c4fd6e3df81f6aaf767489237d49f46b625b890bce227","complete_history_sha256":"165671580add8166ce3fbdbc7fc340e6f0c9e0f8b5952d1fdac6754fc2f4599e","current_core_source":"0764e6b267d3d6ddbfb4d7a4b9fb4024018bf89f","current_ops_source":"bb18f0b0bbf2bafb7d337a8dba0797d9237140b9","exit_code":0,"index92_definition_sha256":"e1297a08ac809f6b9c1cf09a4ffc17df17821d01e9bd787434ff52c6d6324426","job_uid":"499ccb27-b18f-422c-b474-8ad542ba93ed","migration98_sha256":"b1ef412772f6d50fbd6a3becfd68965748951e94010d5e845f1a9af5563fdde6","old_records_and_sdk_preserved":true,"original_refs":{"after_catalog":{"path":"/var/lib/dakasa-core-rollout/goose98-installed-provision-timeout/migration98-63f08ef5-14a6-472d-835c-d4cb172734af/AFTER-CATALOG.stdout","sha256":"15c2c5231a44f4298e865f2d78e3fdf388f1dcf6cfa4da8805c6aacec478fa40"},"before_catalog":{"path":"/var/lib/dakasa-core-rollout/goose98-installed-provision-timeout/migration98-63f08ef5-14a6-472d-835c-d4cb172734af/BEFORE-CATALOG.stdout","sha256":"b144b8c0d807ae5a6dca3c2a72dc5c4491b02794a0d17fef580e0775d20206ef"},"migration_result":{"path":"/var/lib/dakasa-core-rollout/goose98-installed-provision-timeout/root98-reconciled-result-19be7c14-e7d5-481e-92e5-c5c4fd0eff15/RECONCILED-MIGRATION-RESULT.PUBLIC.json","sha256":"96da557ef837dca69befbaabcb6b1f6b60c83eaa532442faf07a11db9a1688c5"},"qualified_image":{"path":"/var/lib/dakasa-core-rollout/core9-schema98-static-9f-data-7a77cca5-f01a-4b3a-965a-14b2f70d966c/ROOT-IMAGE-REGISTRY.NATIVE-ABI.json","sha256":"b8ead8de2214d4f456eec0a7e8428ef879d8e912d0e164faa4f8d043b09d6985"},"source_ci":{"path":"/var/lib/dakasa-core-rollout/core9-schema98-static-9f-data-7a77cca5-f01a-4b3a-965a-14b2f70d966c/SOURCE-CI-ACCEPTANCE.original.json","sha256":"8a32b4a10a7e29c0dea080afd86fe93ca72f3a6d50acce82caab0ebea07adc62"}},"pod_uid":"3e30c5dd-d19f-4e0d-b236-18d2b2649777","prior97_history_sha256":"10597e2743d72500162cdcff084ea4bbf701a7e057a8cb27b44df0221b69bca4","provider_guest_core_mutations":0,"reviewed_by_root":true,"schema":"root_goose98_installed_provision_timeout_acceptance_v1","schema_after":98,"schema_before":97,"single_job_create":true}\n'

if __name__=="__main__":unittest.main()
