"""Declared Goose96 CI operands; no Native migration or acceptance authority."""
import ast
import copy
import importlib.util
import json
import os
import re
import subprocess
import uuid
from pathlib import Path
import tempfile
import types
import unittest
from unittest import mock
import test_goose95_native_once as historical
from test_g15pair_core_cas import pre_read_operand, reseal_pre_read

ROOT=Path(__file__).resolve().parents[3]
SOURCE=ROOT/'ops/network-guardian/rollout/goose96_native_once.py'
MIGRATION=ROOT/'db/migrations/00096_guest_retirement_pre_read_continuation.sql'
spec=importlib.util.spec_from_file_location('goose96_under_test',SOURCE)
G=importlib.util.module_from_spec(spec);spec.loader.exec_module(G)


def catalog95_operand():
    """Real immutable Source bodies, declared PostgreSQL-shaped rows only."""
    import re
    history=[{'id':i+1,'version_id':n,'is_applied':True}for i,n in enumerate([0]+[n for n in range(1,96)if n!=40])]
    sql=MIGRATION.read_text();down=sql.split('-- +goose Down',1)[1]
    body=re.search(r"CREATE OR REPLACE FUNCTION public\.retirement_forward_continuation_valid\(r jsonb, retirement uuid\) RETURNS boolean\nLANGUAGE plpgsql STABLE SET timezone='UTC' AS \$\$(.*?)\$\$;",down,re.S).group(1)
    definition='DECLARED exact original function header\n'+body+'\nDECLARED end'
    function={'name':'retirement_forward_continuation_valid','arguments':'r jsonb, retirement uuid',
        'result':'boolean','language':'plpgsql','volatility':'s','config':['TimeZone=UTC'],
        'body':body,'definition':definition}
    check={'table':'capacity_guest_retirement_forwards','name':'retirement_forward_continuation93',
        'validated':True,'definition':"CHECK ((original_record #>> '{continuation,schema}'::text[]) = 'original_settled_absence_continuation_v1'::text)"}
    rows94=historical.G.source_functions(historical.MIGRATION.read_text())
    rows95=historical.G95.source_functions(historical.MIGRATION95.read_text())
    rows94.update(rows95)
    schema94={'tables':[{'name':'public.capacity_intents'}],
        'columns':[{'table':'public.capacity_intents','name':'intent','type':'jsonb'}],
        'constraints':[{'table':'public.capacity_intents','name':'capacity_intents_pkey','validated':True,'definition':'DECLARED PK'}],
        'indexes':[{'table':'public.capacity_intents','name':'public.capacity_intents_pkey','valid':True,'ready':True,'live':True,'definition':'DECLARED index'}],
        'triggers':[{'table':'public.capacity_intents','name':'DECLARED immutable94 trigger','definition':'DECLARED trigger'}],
        'functions':[{'name':name,'qualified_name':'public.'+name,**row,'definition':'DECLARED header\n'+row['body']+'\nDECLARED end'}for name,row in sorted(rows94.items())]}
    return {'legacy':{'database':'yggdrasil','readonly':'on','latest_versions':[r['version_id']for r in history],
        'rows90':1,'rows91':1,'other_migrators_ddl':0,'other_cic':0,'ddl_locks':0,
        'complete_history_wire':json.dumps(history),'catalog90':{'constraints':[check],'tables':[{'name':'DECLARED original'}]},'catalog91':{'guard':'DECLARED immutable91'}},
        'supplement':{'columns90_91':[{'name':'DECLARED original column'}],'functions93':[function],
            'index92_valid':True,'index92_definition':'DECLARED index92','old_records':{'all_old_rows':'DECLARED byte hash'}},
        'schema94':schema94,'old_grants':{'rows':2,'sha256':'a'*64},'ledgers94':[{'name':'DECLARED retained94','rows':140,'sha256':'b'*64}]}



def declared_constraint96_artifact(prior):
    """Declared CI operand only; real PG16 artifact is produced by the shipped-M96 case."""
    before=prior['legacy']['catalog90']['constraints'][0]['definition']
    after=before.replace("= 'original_settled_absence_continuation_v1'::text",
        "= ANY (ARRAY['original_settled_absence_continuation_v1'::text, 'original_settled_absence_pre_read_continuation_v1'::text])",1)
    return {'schema':'declared_M96_PG16_exact_Source_CHECK_deparse_v1','migration93_sha256':G.M93,
        'migration96_sha256':G.M96,'before_definition':before,
        'after':{'server_version':'16.0 DECLARED','server_version_num':160000,'database':'goose96_deparse_'+'0'*32,
            'definition':after,'validated':True,'old_constraint_rows':0},
        'scope':'disposable minimum table CHECK only','Native_or_Job_qualification':False}


class Goose96OnceTests(unittest.TestCase):
    def test_forced_unbound_refuses_before_io(self):
        for flag in (False,True):
            with mock.patch.multiple(G,SOURCE_BOUND=flag,COMPANION_SOURCE_Q=None,COMPANION_IMAGE_D=None),mock.patch.object(G,'private_read') as read,mock.patch.object(G,'reference') as ref:
                with self.assertRaises(G.Hold):G.main()
                read.assert_not_called();ref.assert_not_called()

    def test_goose96_job_scope_and_distinct_claim(self):
        with mock.patch.multiple(G,JOB_UUID='a78740e4-6263-43dc-a0b2-56eb29368119',COMPANION_IMAGE_D='1'*64):
            job=G.job_manifest();p=job['spec']['template']['spec'];c=p['containers'][0]
            self.assertEqual(job['metadata']['name'],'core-goose96-a78740e4626343dca0b256eb29368119')
            self.assertEqual(job['metadata']['labels']['app'],'yggdrasil-goose96-companion')
            self.assertEqual((job['spec']['backoffLimit'],job['spec']['activeDeadlineSeconds'],job['spec']['parallelism']),(0,240,1))
            self.assertEqual(c['command'],['/bin/sh','-ceu','/app/goose up'])
            self.assertEqual(p['restartPolicy'],'Never');self.assertFalse(p['automountServiceAccountToken'])
            self.assertEqual(c['image'],G.PREFIX+'1'*64);self.assertNotIn('volumeMounts',c)
            self.assertNotEqual(G.ROOT,historical.G95.ROOT);self.assertNotEqual(G.CLAIM,historical.G95.CLAIM)
            self.assertNotIn('goose95',str(G.CLAIM));self.assertNotEqual(job['metadata']['labels']['app'],'yggdrasil')

    def test_shipped_m96_guard_and_96_only_job_logs(self):
        raw=MIGRATION.read_bytes();self.assertEqual(G.M96,G.sha(raw))
        functions=G.source_functions(raw.decode())
        self.assertEqual(set(functions),{'retirement_forward_continuation_valid'})
        row=functions['retirement_forward_continuation_valid']
        self.assertEqual({k:row[k]for k in ('arguments','result','language','volatility','config')},
            {'arguments':'r jsonb, retirement uuid','result':'boolean','language':'plpgsql','volatility':'s','config':['TimeZone=UTC']})
        self.assertIn('original_settled_absence_pre_read_continuation_v1',row['body'])
        self.assertIn('retained pre-read continuation proof requires schema96',raw.decode().split('-- +goose Down',1)[1])
        for bad in (raw.decode().replace('CREATE OR REPLACE FUNCTION','CREATE FUNCTION',1),
                raw.decode().replace('retirement_forward_continuation_valid(r jsonb, retirement uuid)','foreign_valid(r jsonb, retirement uuid)',1)):
            with mock.patch.object(G,'M96',G.sha(bad.encode())),self.assertRaises(G.Hold):G.source_functions(bad)
        tree=ast.parse(SOURCE.read_text())
        posts=[n for n in ast.walk(tree)if isinstance(n,ast.Call)and isinstance(n.func,ast.Attribute)and n.func.attr=='request'and n.args and isinstance(n.args[0],ast.Constant)and n.args[0].value=='POST']
        self.assertEqual(len(posts),1)
        # Real96 emits only96 because applied95 is skipped. Exercise the full
        # owned-Job/pod/log observer with declared completed metadata; no Nativecall.
        uid='11111111-1111-4111-8111-111111111111';poduid='22222222-2222-4222-8222-222222222222'
        log96=b'2026-11-05T00:00:00Z OK 00096_guest_retirement_pre_read_continuation.sql\ngoose: successfully migrated database to version: 96\n'
        log95=b'2026-11-05T00:00:00Z OK 00095_failed_expansion_read_failure_continuation.sql\ngoose: successfully migrated database to version: 95\n'
        with mock.patch.multiple(G,JOB_UUID='a78740e4-6263-43dc-a0b2-56eb29368119',COMPANION_IMAGE_D='1'*64),mock.patch.object(G.time,'monotonic',return_value=100):
            job=G.job_manifest();name=G.job_name()
            current={'metadata':{'uid':uid,'name':name,'namespace':'dakasa'},'status':{'conditions':[{'type':'Complete','status':'True'}],'succeeded':1}}
            pod={'metadata':{'name':'declared-goose96-pod','uid':poduid,'ownerReferences':[{'kind':'Job','controller':True,'uid':uid,'name':name}]},
                 'status':{'phase':'Succeeded','containerStatuses':[{'name':'migrator','restartCount':0,'imageID':'registry@sha256:'+'1'*64,'state':{'terminated':{'exitCode':0}}}]}}
            for logs,accepted in ((log96,True),(log95,False)):
                api=mock.Mock();api.get.side_effect=[copy.deepcopy(current),{'items':[copy.deepcopy(pod)]}]
                api.request.return_value=(200,logs,{'framing_valid':True})
                with mock.patch.object(G,'job_shape') as shape:
                    if accepted:self.assertEqual(G.observe_owned_job(api,job,types.SimpleNamespace(),uid,1000),(uid,poduid,G.sha(logs)))
                    else:
                        with self.assertRaises(G.Hold) as held:G.observe_owned_job(api,job,types.SimpleNamespace(),uid,1000)
                        self.assertEqual(str(held.exception),'ORIGINAL_GOOSE96_LOG_COMPLETE_EXIT0')
                    self.assertEqual(shape.call_count,2)
                api.request.assert_called_once_with('GET','/api/v1/namespaces/dakasa/pods/declared-goose96-pod/log?container=migrator&timestamps=true')

        # The existing Owned PG16 service supplies the real deparser result.
        # This disposable minimal database exercises only exact Source CHECK DDL,
        # never the companion Job or an application/production migration.
        container=os.environ['GUARDIAN_CI_POSTGRES_CONTAINER']
        evidence=Path(os.environ['GUARDIAN_CI_EVIDENCE'])/'m96-pg16-check-deparse'
        evidence.mkdir(parents=True,exist_ok=False)
        database='goose96_deparse_'+uuid.uuid4().hex
        command_number=[0]
        def psql(db,sql):
            command_number[0]+=1;prefix=evidence/('%02d'%command_number[0])
            argv=['docker','exec','-i',container,'psql','-X','-q','-v','ON_ERROR_STOP=1',
                  '-A','-t','-U','guardian_ci','-d',db]
            result=subprocess.run(argv,input=sql.encode(),capture_output=True,timeout=30)
            prefix.with_suffix('.SQL').write_text(sql)
            prefix.with_suffix('.stdout').write_bytes(result.stdout)
            prefix.with_suffix('.stderr').write_bytes(result.stderr)
            prefix.with_suffix('.exit').write_text(str(result.returncode)+'\n')
            self.assertEqual(result.returncode,0,result.stderr.decode(errors='replace'))
            return result.stdout.decode()
        source93=ROOT/'db/migrations/00093_guest_retirement_settled_absence_continuation.sql'
        oldraw=source93.read_bytes();self.assertEqual(G.sha(oldraw),G.M93)
        oldcheck=re.findall(r"ALTER TABLE public\.capacity_guest_retirement_forwards ADD CONSTRAINT retirement_forward_continuation93 CHECK\(.*?;",oldraw.decode().split('-- +goose Down',1)[0],re.S)
        self.assertEqual(len(oldcheck),1)
        first_do=raw.decode().split('-- +goose StatementBegin',1)[1].split('-- +goose StatementEnd',1)[0]
        self.assertTrue(first_do.strip().startswith('DO $$ BEGIN'))
        psql('yggdrasil','CREATE DATABASE '+database+';')
        try:
            sql='CREATE TABLE public.capacity_guest_retirement_forwards(original_record jsonb NOT NULL);\n'+oldcheck[0]
            psql(database,sql)
            before=psql(database,"SELECT pg_get_constraintdef(oid,false) FROM pg_constraint WHERE conrelid='public.capacity_guest_retirement_forwards'::regclass AND conname='retirement_forward_continuation93';")
            before=before.strip();self.assertTrue(before)
            psql(database,first_do)
            select="""SELECT json_build_object('server_version',current_setting('server_version'),
                'server_version_num',current_setting('server_version_num')::int,'database',current_database(),
                'definition',pg_get_constraintdef(oid,false),'validated',convalidated,
                'old_constraint_rows',(SELECT count(*) FROM pg_constraint
                    WHERE conrelid='public.capacity_guest_retirement_forwards'::regclass
                    AND conname='retirement_forward_continuation93'))
                FROM pg_constraint WHERE conrelid='public.capacity_guest_retirement_forwards'::regclass
                AND conname='retirement_forward_continuation96';"""
            actual=json.loads(psql(database,select))
            self.assertEqual(actual['server_version_num']//10000,16)
            self.assertEqual(actual['database'],database);self.assertTrue(actual['validated'])
            self.assertEqual(actual['old_constraint_rows'],0)
            facts={'schema':'declared_M96_PG16_exact_Source_CHECK_deparse_v1',
                'migration93_sha256':G.sha(oldraw),'migration96_sha256':G.sha(raw),
                'before_definition':before,'after':actual,'scope':'disposable minimum table CHECK only',
                'Native_or_Job_qualification':False}
            (evidence/'RESULT.PUBLIC.json').write_text(json.dumps(facts,indent=2)+'\n')
            prior=catalog95_operand();prior['legacy']['catalog90']['constraints'][0]['definition']=before
            self.assertEqual(G.constraint96_definition(G.catalog94_projection(prior),facts),actual['definition'])
        finally:
            psql('yggdrasil','DROP DATABASE '+database+';')

    def test_known_preread_failed_ack_zero_own_and_same_paid_sdk(self):
        value,case=pre_read_operand();saved=copy.deepcopy(value);savedcase=copy.deepcopy(case)
        self.assertTrue(G.validate_pre_read96(value,case));self.assertEqual(value,saved);self.assertEqual(case,savedcase)
        self.assertEqual(value['records']['own_read_count'],0)
        self.assertEqual(len(value['records']['destroy_grants']),1)
        self.assertEqual(value['records']['destroy_grants'][0]['grant_record']['settlement']['original_provider_destroy_return']['response_status'],200)
        faults=('own_count','own_prepared_inventory','own_returned_malformed','unreturned','missing_ACK','unknown_job','live_lease',
            'missing_SDK','SDK_status','SDK_source','SDK_attempt','SDK_action','SDK_request','SDK_resource','SDK_birth','SDK_clock',
            'uncertain_settlement','future_retyped_schema','wrong_pending_status','retimed_read','wrong_wire','failed_step_status','foreign_case')
        for fault in faults:
            bad=copy.deepcopy(saved);c=copy.deepcopy(savedcase);r=bad['records'];t=G.PRE_READ_TARGET
            forwards=r['forward_rows'];parents=[x for x in forwards if x['id']==t['failed_admission_id']]
            grant=r['destroy_grants'][0];job=next(x for x in r['owning_dispatch_jobs']if x['run_id']==t['failed_run_id'])
            if fault=='own_count':r['own_read_count']=1
            elif fault in ('own_prepared_inventory','own_returned_malformed'):
                row=copy.deepcopy(r['all_read_rows'][0 if fault=='own_prepared_inventory'else 1])
                row.update(id='30000000-0000-4000-8000-000000000001',admission_id=t['failed_admission_id'],kind='inventory')
                if fault=='own_prepared_inventory':row['original_record'].update(admission_id=t['failed_admission_id'],read_id=row['id'])
                else:
                    row['original_record']['read'].update(admission_id=t['failed_admission_id'],read_id=row['id'])
                    row['original_record'].update(status='DECLARED_UNSUPPORTED',call_failed=True,original_context_failed=True)
                # Deliberately keep own_count zero: complete raw rows must catch
                # the case even when a success-only aggregate would conceal it.
                r['all_read_rows'].append(row)
            elif fault=='unreturned':r['unreturned_prepared']=[copy.deepcopy(r['all_read_rows'][0])]
            elif fault=='missing_ACK':job['finalization_ack_at']=None
            elif fault=='unknown_job':job['state']='unknown'
            elif fault=='live_lease':
                r['current_intent']['intent']['lease_expires_at']='2026-11-10T16:02:00Z'
                r['current_intent_pgtext']=json.dumps(r['current_intent']['intent'],sort_keys=True,separators=(',',':'))
            elif fault.startswith('SDK_')or fault in ('missing_SDK','uncertain_settlement'):
                settlement=grant['grant_record']['settlement'];sdk=settlement['original_provider_destroy_return']
                if fault=='missing_SDK':settlement.pop('original_provider_destroy_return')
                elif fault=='uncertain_settlement':settlement['outcome']='uncertain'
                else:
                    key={'SDK_status':'response_status','SDK_source':'adapter_source_commit','SDK_attempt':'attempt_id',
                        'SDK_action':'action_id','SDK_request':'request_sha256','SDK_resource':'resource_id',
                        'SDK_birth':'resource_created_at','SDK_clock':'returned_at'}[fault]
                    sdk[key]=202 if fault=='SDK_status'else sdk['context_deadline']if fault=='SDK_clock'else 'foreign'
                grant['grant_pgtext']=json.dumps(grant['grant_record'],sort_keys=True,separators=(',',':'))
                for row in parents:row['original_record']['continuation']['destroy_grant_sha256']=G.sha(grant['grant_pgtext'].encode())
            elif fault=='future_retyped_schema':
                for row in parents:row['original_record']['continuation']['schema']='original_settled_absence_pre_read_continuation_v1'
            elif fault in ('wrong_pending_status','retimed_read'):
                returned=next(x for x in r['all_read_rows']if x['stage']=='returned')
                if fault=='wrong_pending_status':returned['original_record']['status']='failed'
                else:
                    returned['original_record']['read']['original_deadline_core']='2026-11-10T16:00:10Z'
                    next(x for x in r['all_read_rows']if x['stage']=='prepared')['original_record']['original_deadline_core']='2026-11-10T16:00:10Z'
                reseal_pre_read(bad,c)
                for row in parents:row['original_record']['continuation']['pending_read_sha256']=returned['record_sha256']
            elif fault=='wrong_wire':forwards[0]['record_sha256']='f'*64
            elif fault=='failed_step_status':
                run=next(x for x in r['workflow_runs']if x['id']==t['failed_run_id'])
                next(x for x in run['result']['steps']if x['id']=='finish-original-retirement')['status']='succeeded'
                run['run_wire']=json.dumps({k:v for k,v in run.items()if k!='run_wire'},sort_keys=True,separators=(',',':'))
            else:c['root_admission_id']='foreign'
            job['dispatch_wire']=json.dumps({k:v for k,v in job.items()if k!='dispatch_wire'},sort_keys=True,separators=(',',':'))
            if fault!='wrong_wire':reseal_pre_read(bad,c)
            else:
                # Preserve deliberately invalid raw SHA while rejoining outer PG wire.
                raw=json.dumps(r,sort_keys=True,separators=(',',':'));bad['records_wire']=raw
                bad['records_sha256']=c['expected_records_sha256']=G.sha(raw.encode())
            with self.subTest(pre_read_fault=fault),self.assertRaises(G.Hold)as held:G.validate_pre_read96(bad,c)
            if fault in ('own_prepared_inventory','own_returned_malformed'):
                self.assertEqual(str(held.exception),'NO_PREPARED_OR_RETURNED_OF_ANY_KIND_FOR_FAILED_OWNER')
        self.assertEqual(value,saved);self.assertEqual(case,savedcase)

    def test_immutable_root95_receipt_and_original_five_roles_preserved(self):
        self.assertEqual(G.BASELINE95_ACCEPTANCE_SHA256,'b80ec307962a67b8a28722c8fbf88add02c25de08847253fbae7838de1c0153d')
        # Explicit declared local custody boundary isolates the historical receipt
        # ABI. No real Root receipt or future image/CI acceptance is generated.
        rawrefs={}
        def ref(name,value):
            raw=value if isinstance(value,bytes)else G.wire(value)
            r={'path':'/declared/'+name,'sha256':G.sha(raw)};rawrefs[r['path']]=raw;return r
        def reference(r,*_):
            raw=rawrefs[r['path']]
            if G.sha(raw)!=r['sha256']:raise G.Hold('declared full-byte custody mismatch')
            return raw
        source='c'*40;image='d'*64
        ci=ref('ci',{'schema':'DECLARED separately tested SourceCI boundary'})
        roster={'schema':'qualified_companion_SQL_SHA_size_roster_v1','source':source,
                'files':{str(n)+'.sql':{'version':n,'sha256':'a'*64,'bytes':1}for n in range(1,97)if n!=40}}
        for version,name,pin in ((93,'00093_guest_retirement_settled_absence_continuation.sql',G.M93),
                (94,'00094_failed_unwitnessed_expansion_cleanups.sql',G.M94),
                (95,'00095_failed_expansion_read_failure_continuation.sql',G.M95),
                (96,'00096_guest_retirement_pre_read_continuation.sql',G.M96)):
            roster['files'].pop(str(version)+'.sql');roster['files'][name]={'version':version,'sha256':pin,'bytes':1}
        rr=ref('roster',roster)
        full=ref('full-image',{'schema':'root_actual_compiler_GHCR_image_acceptance_v1','source':source,'amd64_D':image,
            'CI_acceptance_sha256':ci['sha256'],'all17manualrelease_steps_success':True,'Source_SQL_roster_sha256':rr['sha256'],
            'platforms':{p:{'all4_ELF_headers_metadata_CGO0_clean_actualSource':True,'later_relevant_whiteout_or_file_mutations':[]}for p in ('amd64','arm64')}})
        proof=ref('registry',{'schema':'root_core_R_qualified_image_registry_acceptance_v1','source':source,
            'amd64_manifest_digest':'sha256:'+image,'image':G.PREFIX+image,'original_HTTP200_exact_body_complete':True,
            'qualified_for_existing_image_only_production_CAS':True,'Source_CI_manual_release_all_layers_ELF_and_SQL_acceptance':full})
        baseline={'schema':'root_goose95_failed_expansion_read_continuation_acceptance_v1','reviewed_by_root':True,
            'schema_before':94,'schema_after':95,'current_core_source':'7cd5cea0834bcee901c282bc81b9486d5c16513b',
            'current_ops_source':'85be49ecdc4c5610f57dc1331a5781f37721d6d2','business_source':G.CURRENT_CORE_R,
            'amd64_D':G.CURRENT_CORE_D,'migration95_sha256':G.M95,
            **{k:'e'*64 for k in ('complete_history_sha256','prior94_history_sha256','catalog95_sha256','index92_definition_sha256','catalog90_91_sha256')},
            'job_uid':'11111111-1111-4111-8111-111111111111','pod_uid':'22222222-2222-4222-8222-222222222222',
            'exit_code':0,'single_job_create':True,'provider_guest_core_mutations':0,'old_records_and_sdk_preserved':True,
            'original_refs':{role:ref('original-'+role,b'DECLARED whole immutable original bytes')for role in ('migration_result','before_catalog','after_catalog','source_ci','qualified_image')}}
        self.assertEqual(len(baseline),21);self.assertEqual(len(baseline['original_refs']),5)
        b=ref('root95',baseline)
        cfg={'source_ci_acceptance':ci,'companion_image_proof':proof,'companion_sql_roster':rr,
             'migration96_sql':{'source_ref':{'path':str(MIGRATION),'sha256':G.M96},
                'constraint96_deparse_ref':ref('declared-constraint96',declared_constraint96_artifact(catalog95_operand()))},
             'baseline95_acceptance':b}
        with mock.patch.multiple(G,SOURCE_CI_GATE_SHA256=ci['sha256'],COMPANION_SOURCE_Q=source,
                COMPANION_IMAGE_D=image,COMPANION_IMAGE_PROOF_SHA256=proof['sha256'],BASELINE95_ACCEPTANCE_SHA256=b['sha256']), \
                mock.patch.object(G,'reference',side_effect=reference),mock.patch.object(G,'source_ci_valid'):
            saved=copy.deepcopy(baseline);self.assertEqual(G.qualification(cfg),saved);self.assertEqual(baseline,saved)
            for fault in ('retyped96','retimed_before','retimed_after','retimed_current_core','retimed_business','wrong95migration',
                    'new_provider_authority','missing_original_role','extra_original_role','new_root_field'):
                bad=copy.deepcopy(saved)
                if fault=='retyped96':bad['schema']='root_goose96_pre_read_continuation_acceptance_v1'
                elif fault=='retimed_before':bad['schema_before']=95
                elif fault=='retimed_after':bad['schema_after']=96
                elif fault=='retimed_current_core':bad['current_core_source']=G.CURRENT_CORE_R
                elif fault=='retimed_business':bad['business_source']=source
                elif fault=='wrong95migration':bad['migration95_sha256']='f'*64
                elif fault=='new_provider_authority':bad['provider_guest_core_mutations']=1
                elif fault=='missing_original_role':bad['original_refs'].pop('before_catalog')
                elif fault=='extra_original_role':bad['original_refs']['extra']=next(iter(bad['original_refs'].values()))
                else:bad['invented_acceptance']=True
                br=ref('bad-root95',bad);badcfg={**cfg,'baseline95_acceptance':br}
                with self.subTest(root95_fault=fault),mock.patch.object(G,'BASELINE95_ACCEPTANCE_SHA256',br['sha256']),self.assertRaises(G.Hold):G.qualification(badcfg)

    def test_prior95_catalog_and_sole96_function_and_constraint_delta(self):
        old=catalog95_operand();functions=G.source_functions(MIGRATION.read_text())
        facts=declared_constraint96_artifact(old)
        accepted={'complete_history_sha256':G.sha(old['legacy']['complete_history_wire'].encode()),
            'catalog95_sha256':G.sha(G.wire(G.catalog94_projection(old))),
            'index92_definition_sha256':G.sha(old['supplement']['index92_definition'].encode())}
        G.check_catalog(old,accepted,functions,migration=facts)
        after=copy.deepcopy(old);history=G.loads(after['legacy']['complete_history_wire'])
        history.append({'id':len(history)+1,'version_id':96,'is_applied':True})
        after['legacy']['latest_versions'].append(96);after['legacy']['complete_history_wire']=json.dumps(history)
        fn=after['supplement']['functions93'][0];newbody=functions['retirement_forward_continuation_valid']['body']
        fn['definition']=fn['definition'].replace(fn['body'],newbody,1);fn['body']=newbody
        check=after['legacy']['catalog90']['constraints'][0]
        expected_check=check['definition'].replace("= 'original_settled_absence_continuation_v1'::text","= ANY (ARRAY['original_settled_absence_continuation_v1'::text, 'original_settled_absence_pre_read_continuation_v1'::text])",1)
        check.update(name='retirement_forward_continuation96',definition=expected_check)
        G.check_catalog(after,accepted,functions,old=old,migration=facts)
        self.assertEqual(after['schema94'],old['schema94'])
        self.assertEqual(after['old_grants'],old['old_grants']);self.assertEqual(after['ledgers94'],old['ledgers94'])
        for fault in ('old_history','missing96','duplicate96','false96','function_body','function_header','function_config',
                'function_definition','extra_function','check_definition','check_name','check_not_validated',
                'extra_constraint','old_table','old_column','old_trigger','old_index','old94_function','old_SDK','ledger'):
            bad=copy.deepcopy(after)
            if fault in ('old_history','missing96','duplicate96','false96'):
                h=G.loads(bad['legacy']['complete_history_wire'])
                if fault=='old_history':h[-2]['is_applied']=False
                elif fault=='missing96':h.pop()
                elif fault=='duplicate96':h.append(copy.deepcopy(h[-1]))
                else:h[-1]['is_applied']=False
                bad['legacy']['complete_history_wire']=json.dumps(h)
            elif fault=='function_body':bad['supplement']['functions93'][0]['body']+=' '
            elif fault=='function_header':bad['supplement']['functions93'][0]['arguments']='foreign jsonb'
            elif fault=='function_config':bad['supplement']['functions93'][0]['config']=['TimeZone=foreign']
            elif fault=='function_definition':bad['supplement']['functions93'][0]['definition']='foreign'
            elif fault=='extra_function':bad['supplement']['functions93'].append(copy.deepcopy(bad['supplement']['functions93'][0]))
            elif fault=='check_definition':bad['legacy']['catalog90']['constraints'][0]['definition']+=' OR true'
            elif fault=='check_name':bad['legacy']['catalog90']['constraints'][0]['name']='foreign'
            elif fault=='check_not_validated':bad['legacy']['catalog90']['constraints'][0]['validated']=False
            elif fault=='extra_constraint':bad['legacy']['catalog90']['constraints'].append({'name':'foreign'})
            elif fault=='old_table':bad['legacy']['catalog90']['tables'][0]['name']='foreign'
            elif fault=='old_column':bad['supplement']['columns90_91'][0]['name']='foreign'
            elif fault=='old_trigger':bad['schema94']['triggers'][0]['definition']='foreign'
            elif fault=='old_index':bad['schema94']['indexes'][0]['definition']='foreign'
            elif fault=='old94_function':bad['schema94']['functions'][0]['body']+=' '
            elif fault=='old_SDK':bad['old_grants']['sha256']='f'*64
            else:bad['ledgers94'][0]['rows']+=1
            with self.subTest(catalog96_fault=fault),self.assertRaises(G.Hold):G.check_catalog(bad,accepted,functions,old=old,migration=facts)

        for fault in ('source93','source96','PG17','unvalidated','old_check_retained','before','same_after','extra_field'):
            bad=copy.deepcopy(facts)
            if fault=='source93':bad['migration93_sha256']='f'*64
            elif fault=='source96':bad['migration96_sha256']='f'*64
            elif fault=='PG17':bad['after']['server_version_num']=170000
            elif fault=='unvalidated':bad['after']['validated']=False
            elif fault=='old_check_retained':bad['after']['old_constraint_rows']=1
            elif fault=='before':bad['before_definition']='foreign'
            elif fault=='same_after':bad['after']['definition']=bad['before_definition']
            else:bad['invented_authority']=True
            with self.subTest(deparse_fault=fault),self.assertRaises(G.Hold):
                G.constraint96_definition(G.catalog94_projection(old),bad)

    def test_goose96_lost_ack_current15_and_method_guards(self):
        for phase in ('lost_ack','stale_after_markers'):
            with tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);run=root/'run';run.mkdir();clock=[100.0]
                def once(path,raw):
                    with Path(path).open('xb') as stream:stream.write(raw)
                    if phase=='stale_after_markers':clock[0]+=8
                api=mock.Mock();api.get.return_value=None;api.request.side_effect=TimeoutError('declared lost ACK')
                with mock.patch.multiple(G,CLAIM=root/'GOOSE96-POSSIBLE-CREATE.json',JOB_UUID='a78740e4-6263-43dc-a0b2-56eb29368119',COMPANION_IMAGE_D='1'*64),mock.patch.object(G.time,'monotonic',side_effect=lambda:clock[0]):
                    job=G.job_manifest()
                    with mock.patch.object(G,'JOB_MANIFEST_SHA256',G.sha(G.wire(job))):
                        with self.assertRaises((TimeoutError,G.Hold)):G.create_once(api,types.SimpleNamespace(once=once),run,job,'2'*64,'3'*64,1000,100)
                        self.assertTrue(G.CLAIM.exists())
                        with self.assertRaises(G.Hold):G.create_once(api,types.SimpleNamespace(once=once),run,job,'2'*64,'3'*64,1000,100)
                    self.assertEqual(api.request.call_count,1 if phase=='lost_ack' else 0)
        inner=mock.Mock();C=types.SimpleNamespace(once=lambda *_:None)
        with mock.patch.object(G,'JOB_UUID','a78740e4-6263-43dc-a0b2-56eb29368119'):
            api=G.CapturedAPI(inner,C,Path('/declared'),True)
            for method,uri,body in [('PATCH',G.DEP_URI,b'{}'),('DELETE',G.JOB_URI+'/old',None),('POST',G.DEP_URI,b'{}')]:
                with self.assertRaises(G.Hold):api.request(method,uri,body)
        inner.request.assert_not_called()


if __name__=='__main__':unittest.main()
