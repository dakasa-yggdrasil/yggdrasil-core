"""Declared Goose97 CI operands; no Native migration or acceptance authority."""
import ast
import base64
import copy
import importlib.util
import json
import re
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock
import test_goose96_native_once as historical
from test_g15pair_core_cas import (normal_finish_operand, seal_normal_finish_fixture, normal_finish_encoded,
    NORMAL_FINISH_PG_DEADLINE_CASES, reseal_normal_finish_caller)

ROOT=Path(__file__).resolve().parents[3]
SOURCE=ROOT/'ops/network-guardian/rollout/goose97_native_once.py'
MIGRATION=ROOT/'db/migrations/00097_guest_retirement_normal_finish_recovery.sql'
spec=importlib.util.spec_from_file_location('goose97_under_test',SOURCE)
G=importlib.util.module_from_spec(spec);spec.loader.exec_module(G)


def catalog96_operand():
    """Historical Source remains unchanged; all rows are declared CI operands."""
    value=historical.catalog95_operand()
    history=G.loads(value['legacy']['complete_history_wire'])
    history.append({'id':len(history)+1,'version_id':96,'is_applied':True})
    value['legacy']['complete_history_wire']=json.dumps(history)
    value['legacy']['latest_versions'].append(96)
    fn=value['supplement']['functions93'][0]
    body=historical.G.source_functions(historical.MIGRATION.read_text())['retirement_forward_continuation_valid']['body']
    fn['definition']=fn['definition'].replace(fn['body'],body,1);fn['body']=body
    check=value['legacy']['catalog90']['constraints'][0]
    check.update(name='retirement_forward_continuation96',
        definition=historical.declared_constraint96_artifact(historical.catalog95_operand())['after']['definition'])
    value['legacy']['catalog90']['constraints'].append({'table':'capacity_guest_retirement_forwards',
        'name':'retirement_forward_mode93','validated':True,
        'definition':"CHECK ((original_record ->> 'mode'::text) = ANY (ARRAY['live'::text, 'historical'::text, 'settled_absence_continuation'::text]))"})
    down=MIGRATION.read_text().split('-- +goose Down',1)[1]
    guard=re.findall(r"CREATE OR REPLACE FUNCTION public\.guard_retirement_forward\(\) RETURNS trigger LANGUAGE plpgsql AS \$\$(.*?)\$\$;",down,re.S)
    assert len(guard)==1
    for name,body,args,result,config,volatility in (
        ('guard_retirement_forward',guard[0],'','trigger',None,'v'),
        ('retirement_forward_continuation_quiet','DECLARED immutable quiet body','r jsonb, retirement uuid','boolean',['TimeZone=UTC'],'s'),
        ('guard_retirement_forward_read','DECLARED immutable read guard','','trigger',None,'v'),
        ('guard_retirement_forward_delete_binding','DECLARED immutable binding guard','','trigger',None,'v')):
        value['supplement']['functions93'].append({'name':name,'arguments':args,'result':result,
            'language':'plpgsql','volatility':volatility,'config':config,'body':body,
            'definition':'DECLARED prior PostgreSQL header\n'+body+'\nDECLARED end'})
    value['supplement']['functions93'].sort(key=lambda row:row['name'])
    prior_guard=next(row for row in value['supplement']['functions93']if row['name']=='guard_retirement_forward')
    value['legacy']['catalog90']['functions']=[{'name':name,'definition':prior_guard['definition']if name=='guard_retirement_forward'else'DECLARED retained legacy '+name}
        for name in ('guard_retirement_forward','guard_retirement_forward_delete_binding','guard_retirement_forward_read','guard_retirement_forward_terminal')]
    value['legacy']['catalog90']['constraints'].sort(key=lambda row:(row['table'],row['name']))
    return value


def catalog97_operand(before):
    """Explicit same-hash custody copies of declared PG16 originals; no native authority."""
    functions=G.migration97_functions(MIGRATION.read_text())
    after=copy.deepcopy(before)
    history=G.loads(after['legacy']['complete_history_wire'])
    history.append({'id':len(history)+1,'version_id':97,'is_applied':True})
    after['legacy']['complete_history_wire']=json.dumps(history);after['legacy']['latest_versions'].append(97)
    old=next(row for row in after['supplement']['functions93'] if row['name']=='guard_retirement_forward')
    for name,fields in functions.items():
        row={'name':name,**fields,'definition':'DECLARED current PostgreSQL header\n'+fields['body']+'\nDECLARED end'}
        if name=='guard_retirement_forward':old.update(row)
        else:after['supplement']['functions93'].append(row)
    after['supplement']['functions93'].sort(key=lambda row:row['name'])
    next(row for row in after['legacy']['catalog90']['functions']if row['name']=='guard_retirement_forward')['definition']=old['definition']
    mode=next(row for row in after['legacy']['catalog90']['constraints']if row['name']=='retirement_forward_mode93')
    normal=copy.deepcopy(mode)
    mode.update(name='retirement_forward_mode97',definition="CHECK ((original_record ->> 'mode'::text) = ANY (ARRAY['live'::text, 'historical'::text, 'settled_absence_continuation'::text, 'normal_finish_recovery'::text]))")
    normal.update(name='retirement_forward_normal_finish97',definition="CHECK ((original_record ->> 'mode'::text) <> 'normal_finish_recovery'::text OR (original_record #>> '{normal_finish_recovery,schema}'::text[]) = 'original_normal_finish_recovery_v1'::text)")
    after['legacy']['catalog90']['constraints'].append(normal)
    after['legacy']['catalog90']['constraints'].sort(key=lambda row:(row['table'],row['name']))
    refs={}
    def ref(path,raw):
        r={'path':path,'sha256':G.sha(raw)};refs[path]=raw;return r
    def view(value):
        return {'server_version_num':160000,
            'functions':{row['name']:row['definition']for row in value['supplement']['functions93']
                if row['name']in('guard_retirement_forward','retirement_forward_continuation_valid','retirement_forward_continuation_quiet','retirement_forward_normal_finish_recovery_valid')},
            'constraints':[{k:row[k]for k in('name','validated','definition')}for row in value['legacy']['catalog90']['constraints']]}
    before_raw,after_raw=G.wire(view(before)),G.wire(view(after))
    br=ref('/declared/copied-before96.json',before_raw);ar=ref('/declared/copied-after97.json',after_raw)
    artifact={'schema':'normal_finish_recovery_schema97_pg_catalog_v1','source_commit':'c'*40,
        'postgres_major':16,'fixture_only':True,'native_authority':False,
        'before96_ref':{'path':'/canonical/CI/before96.json','sha256':br['sha256'],'bytes':len(before_raw)},
        'after97_ref':{'path':'/canonical/CI/after97.json','sha256':ar['sha256'],'bytes':len(after_raw)},
        'migration97_sha256':G.M97,'old_continuation_functions_unchanged':True,
        'old_continuation_constraints_unchanged':True,'old_mode93_absent':True,
        'new_mode97_and_normal_finish97_validated':True}
    carrier={'artifact_ref':ref('/declared/artifact12.json',G.wire(artifact)),'before96_ref':br,'after97_ref':ar}
    def read_ref(r,*_):
        raw=refs[r['path']]
        if G.sha(raw)!=r['sha256']:raise G.Hold('DECLARED_CUSTODY_SHA')
        return raw
    return after,functions,carrier,refs,read_ref


class Goose97OnceTests(unittest.TestCase):
    def test_forced_unbound_refuses_before_io(self):
        for flag in (False,True):
            with mock.patch.multiple(G,SOURCE_BOUND=flag,COMPANION_SOURCE_Q=None,COMPANION_IMAGE_D=None),mock.patch.object(G,'private_read') as read,mock.patch.object(G,'reference') as ref:
                with self.assertRaises(G.Hold):G.main()
                read.assert_not_called();ref.assert_not_called()
        # The actual complete S8 representation exceeds the generic4MiB cap.
        # Exercise real private-file I/O in the existing root-owned CI child.
        program=r"""
import hashlib,json,sys,tempfile,types
from pathlib import Path
source=Path(sys.argv[1]);raw=source.read_bytes()
assert hashlib.sha256(raw).hexdigest()==sys.argv[2]
g=types.ModuleType('goose97_complete_baseline_CI');g.__file__=str(source)
exec(compile(raw,str(source),'exec'),g.__dict__)
with tempfile.TemporaryDirectory(prefix='goose97-baseline-')as name:
    p=Path(name)/'complete.json';body=json.dumps({'declared':'x'*(5<<20)}).encode()
    p.write_bytes(body);p.chmod(0o600);ref={'path':str(p),'sha256':g.sha(body)}
    assert g.normal_finish_baseline(ref)=={'declared':'x'*(5<<20)}
    try:g.reference(ref)
    except g.Hold:pass
    else:raise AssertionError('generic4MiB reference accepted oversized file')
    try:g.normal_finish_baseline(dict(ref,sha256='f'*64))
    except g.Hold:pass
    else:raise AssertionError('baseline accepted wrong complete SHA')
    p.write_bytes(b'x'*((8<<20)+1))
    try:g.normal_finish_baseline({'path':str(p),'sha256':g.sha(p.read_bytes())})
    except g.Hold:pass
    else:raise AssertionError('baseline accepted more than existing8MiB transport bound')
"""
        result=subprocess.run(['sudo','-n',sys.executable,'-I','-B','-c',program,str(SOURCE),G.sha(SOURCE.read_bytes())],capture_output=True,text=True,timeout=8)
        self.assertEqual(result.returncode,0,result.stderr)

    def test_goose97_job_scope_and_distinct_claim(self):
        with mock.patch.multiple(G,JOB_UUID='a78740e4-6263-43dc-a0b2-56eb29368119',COMPANION_IMAGE_D='1'*64):
            job=G.job_manifest();p=job['spec']['template']['spec'];c=p['containers'][0]
            self.assertEqual(job['metadata']['name'],'core-goose97-a78740e4626343dca0b256eb29368119')
            self.assertEqual(job['metadata']['labels']['app'],'yggdrasil-schema97-companion')
            self.assertEqual((job['spec']['backoffLimit'],job['spec']['activeDeadlineSeconds'],job['spec']['parallelism']),(0,240,1))
            self.assertEqual(c['command'],['/bin/sh','-ceu','/app/goose up'])
            self.assertEqual(p['restartPolicy'],'Never');self.assertFalse(p['automountServiceAccountToken'])
            self.assertEqual(c['image'],G.PREFIX+'1'*64);self.assertNotIn('volumeMounts',c)
            self.assertNotEqual(G.ROOT,historical.G.ROOT);self.assertNotEqual(G.CLAIM,historical.G.CLAIM)
            self.assertNotIn('goose96',str(G.CLAIM));self.assertNotEqual(job['metadata']['labels']['app'],'yggdrasil')

    def test_shipped_m97_two_functions_and_97_only_job_logs(self):
        raw=MIGRATION.read_bytes();self.assertEqual(G.M97,G.sha(raw))
        functions=G.migration97_functions(raw.decode())
        self.assertEqual(set(functions),{'guard_retirement_forward','retirement_forward_normal_finish_recovery_valid'})
        self.assertIn('normal_finish_recovery',functions['retirement_forward_normal_finish_recovery_valid']['body'])
        self.assertIn('finalized_intent_sha256',functions['retirement_forward_normal_finish_recovery_valid']['body'])
        self.assertIn('retained normal-finish recovery proof requires schema97',raw.decode().split('-- +goose Down',1)[1])
        for text in ('retirement_forward_continuation_quiet','retirement_forward_continuation_valid'):
            self.assertNotIn('CREATE OR REPLACE FUNCTION public.'+text+'(',raw.decode().split('-- +goose Down',1)[0])
        for bad in (raw.decode().replace('CREATE OR REPLACE FUNCTION','CREATE FUNCTION',1),
                    raw.decode().replace('retirement_forward_normal_finish_recovery_valid(r jsonb, retirement uuid)','foreign_valid(r jsonb, retirement uuid)',1)):
            with mock.patch.object(G,'M97',G.sha(bad.encode())),self.assertRaises(G.Hold):G.migration97_functions(bad)
        tree=ast.parse(SOURCE.read_text())
        posts=[n for n in ast.walk(tree)if isinstance(n,ast.Call)and isinstance(n.func,ast.Attribute)and n.func.attr=='request'and n.args and isinstance(n.args[0],ast.Constant)and n.args[0].value=='POST']
        self.assertEqual(len(posts),1)
        # Real97 emits only97 because applied96 is skipped. Exercise the full
        # owned-Job/pod/log observer with declared completed metadata; no Nativecall.
        uid='11111111-1111-4111-8111-111111111111';poduid='22222222-2222-4222-8222-222222222222'
        log97=b'2026-11-05T00:00:00Z OK 00097_guest_retirement_normal_finish_recovery.sql\ngoose: successfully migrated database to version: 97\n'
        log96=b'2026-11-05T00:00:00Z OK 00096_guest_retirement_pre_read_continuation.sql\ngoose: successfully migrated database to version: 96\n'
        with mock.patch.multiple(G,JOB_UUID='a78740e4-6263-43dc-a0b2-56eb29368119',COMPANION_IMAGE_D='1'*64),mock.patch.object(G.time,'monotonic',return_value=100):
            job=G.job_manifest();name=G.job_name()
            current={'metadata':{'uid':uid,'name':name,'namespace':'dakasa'},'status':{'conditions':[{'type':'Complete','status':'True'}],'succeeded':1}}
            pod={'metadata':{'name':'declared-goose97-pod','uid':poduid,'ownerReferences':[{'kind':'Job','controller':True,'uid':uid,'name':name}]},
                 'status':{'phase':'Succeeded','containerStatuses':[{'name':'migrator','restartCount':0,'imageID':'registry@sha256:'+'1'*64,'state':{'terminated':{'exitCode':0}}}]}}
            for logs,accepted in ((log97,True),(log96,False)):
                api=mock.Mock();api.get.side_effect=[copy.deepcopy(current),{'items':[copy.deepcopy(pod)]}]
                api.request.return_value=(200,logs,{'framing_valid':True})
                with mock.patch.object(G,'job_shape') as shape:
                    if accepted:self.assertEqual(G.observe_owned_job(api,job,types.SimpleNamespace(),uid,1000),(uid,poduid,G.sha(logs)))
                    else:
                        with self.assertRaises(G.Hold) as held:G.observe_owned_job(api,job,types.SimpleNamespace(),uid,1000)
                        self.assertEqual(str(held.exception),'ORIGINAL_GOOSE97_LOG_COMPLETE_EXIT0')
                    self.assertEqual(shape.call_count,2)
                api.request.assert_called_once_with('GET','/api/v1/namespaces/dakasa/pods/declared-goose97-pod/log?container=migrator&timestamps=true')


    def test_goose97_lost_ack_current15_and_method_guards(self):
        for phase in ('lost_ack','stale_after_markers'):
            with tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);run=root/'run';run.mkdir();clock=[100.0]
                def once(path,raw):
                    with Path(path).open('xb') as stream:stream.write(raw)
                    if phase=='stale_after_markers':clock[0]+=8
                api=mock.Mock();api.get.return_value=None;api.request.side_effect=TimeoutError('declared lost ACK')
                with mock.patch.multiple(G,CLAIM=root/'GOOSE97-POSSIBLE-CREATE.json',JOB_UUID='a78740e4-6263-43dc-a0b2-56eb29368119',COMPANION_IMAGE_D='1'*64),mock.patch.object(G.time,'monotonic',side_effect=lambda:clock[0]):
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


    def test_immutable_root96_receipt_and_original_five_roles_preserved(self):
        self.assertEqual(G.BASELINE96_ACCEPTANCE_SHA256,'c44e5ef3554ee494001815358434119c31832977db90a44eb925097df137c9d6')
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
                'files':{str(n)+'.sql':{'version':n,'sha256':'a'*64,'bytes':1}for n in range(1,98)if n!=40}}
        for version,name,pin in ((93,'00093_guest_retirement_settled_absence_continuation.sql',G.M93),
                (94,'00094_failed_unwitnessed_expansion_cleanups.sql',G.M94),
                (95,'00095_failed_expansion_read_failure_continuation.sql',G.M95),
                (96,'00096_guest_retirement_pre_read_continuation.sql',G.M96),
                (97,'00097_guest_retirement_normal_finish_recovery.sql',G.M97)):
            roster['files'].pop(str(version)+'.sql');roster['files'][name]={'version':version,'sha256':pin,'bytes':1}
        rr=ref('roster',roster)
        full=ref('full-image',{'schema':'root_actual_compiler_GHCR_image_acceptance_v1','source':source,'amd64_D':image,
            'CI_acceptance_sha256':ci['sha256'],'all17manualrelease_steps_success':True,'Source_SQL_roster_sha256':rr['sha256'],
            'platforms':{p:{'all4_ELF_headers_metadata_CGO0_clean_actualSource':True,'later_relevant_whiteout_or_file_mutations':[]}for p in ('amd64','arm64')}})
        proof=ref('registry',{'schema':'root_core_R_qualified_image_registry_acceptance_v1','source':source,
            'amd64_manifest_digest':'sha256:'+image,'image':G.PREFIX+image,'original_HTTP200_exact_body_complete':True,
            'qualified_for_existing_image_only_production_CAS':True,'Source_CI_manual_release_all_layers_ELF_and_SQL_acceptance':full})
        baseline={'schema':'root_goose96_guest_retirement_pre_read_continuation_acceptance_v1','reviewed_by_root':True,
            'schema_before':95,'schema_after':96,'current_core_source':'33a846d31a5b123b2c1141192671bc830bf6d9c8',
            'current_ops_source':'33873025539cfb5691154fb8ded4fc4fd94eaf94','business_source':'045176d16947555ccbc33a8b51635b08d2d9270e',
            'amd64_D':'85be238c7f5b15760f7eb903646cc48f6b4b86a6995d0a4727a1ba0d86d06876','migration96_sha256':G.M96,
            **{k:'e'*64 for k in ('complete_history_sha256','prior95_history_sha256','catalog96_sha256','index92_definition_sha256','catalog90_91_sha256')},
            'job_uid':'11111111-1111-4111-8111-111111111111','pod_uid':'22222222-2222-4222-8222-222222222222',
            'exit_code':0,'single_job_create':True,'provider_guest_core_mutations':0,'old_records_and_sdk_preserved':True,
            'original_refs':{role:ref('original-'+role,b'DECLARED whole immutable original bytes')for role in ('migration_result','before_catalog','after_catalog','source_ci','qualified_image')}}
        self.assertEqual(len(baseline),21);self.assertEqual(len(baseline['original_refs']),5)
        b=ref('root96',baseline)
        _,_,carrier,_,_=catalog97_operand(catalog96_operand())
        cfg={'source_ci_acceptance':ci,'companion_image_proof':proof,'companion_sql_roster':rr,
             'migration97_sql':{'source_ref':{'path':str(MIGRATION),'sha256':G.M97},
                 'constraint97_deparse_ref':carrier},'baseline96_acceptance':b}
        with mock.patch.multiple(G,SOURCE_CI_GATE_SHA256=ci['sha256'],COMPANION_SOURCE_Q=source,
                COMPANION_IMAGE_D=image,COMPANION_IMAGE_PROOF_SHA256=proof['sha256'],BASELINE96_ACCEPTANCE_SHA256=b['sha256']), \
                mock.patch.object(G,'reference',side_effect=reference),mock.patch.object(G,'source_ci_valid'):
            saved=copy.deepcopy(baseline);self.assertEqual(G.qualification(cfg),saved);self.assertEqual(baseline,saved)
            for fault in ('retyped97','retimed_before','retimed_after','retimed_current_core','retimed_business','wrong96migration',
                    'new_provider_authority','missing_original_role','extra_original_role','new_root_field'):
                bad=copy.deepcopy(saved)
                if fault=='retyped97':bad['schema']='root_goose97_normal_finish_recovery_acceptance_v1'
                elif fault=='retimed_before':bad['schema_before']=96
                elif fault=='retimed_after':bad['schema_after']=97
                elif fault=='retimed_current_core':bad['current_core_source']=G.CURRENT_CORE_R
                elif fault=='retimed_business':bad['business_source']=source
                elif fault=='wrong96migration':bad['migration96_sha256']='f'*64
                elif fault=='new_provider_authority':bad['provider_guest_core_mutations']=1
                elif fault=='missing_original_role':bad['original_refs'].pop('before_catalog')
                elif fault=='extra_original_role':bad['original_refs']['extra']=next(iter(bad['original_refs'].values()))
                else:bad['invented_acceptance']=True
                br=ref('bad-root96',bad);badcfg={**cfg,'baseline96_acceptance':br}
                with self.subTest(root96_fault=fault),mock.patch.object(G,'BASELINE96_ACCEPTANCE_SHA256',br['sha256']),self.assertRaises(G.Hold):G.qualification(badcfg)


    def test_prior96_catalog_and_sole97_two_function_two_check_delta(self):
        before=catalog96_operand()
        after,functions,carrier,refs,read_ref=catalog97_operand(before)
        accepted={'complete_history_sha256':G.sha(before['legacy']['complete_history_wire'].encode()),
            'catalog96_sha256':G.sha(G.wire(G.catalog94_projection(before))),
            'index92_definition_sha256':G.sha(before['supplement']['index92_definition'].encode())}
        self.assertEqual(len(G.loads(refs[carrier['artifact_ref']['path']])),12)
        self.assertEqual(set(carrier),{'artifact_ref','before96_ref','after97_ref'})
        with mock.patch.object(G,'COMPANION_SOURCE_Q','c'*40),mock.patch.object(G,'reference',side_effect=read_ref):
            G.check_catalog(before,accepted,functions,migration=carrier)
            G.check_catalog(after,accepted,functions,old=before,migration=carrier)
            self.assertEqual(len(before['legacy']['catalog90']['functions']),4)
            self.assertEqual(before['legacy']['catalog90']['functions'][1:],after['legacy']['catalog90']['functions'][1:])
            definitions=G.constraint97_definitions(G.catalog94_projection(before),carrier,read_ref,'c'*40)
            for fault in ('missing_legacy_guard','duplicate_legacy_guard','conflicting_legacy_guard','extra_legacy_guard_field'):
                prior=G.catalog94_projection(copy.deepcopy(before));rows=prior['catalog90']['functions']
                if fault=='missing_legacy_guard':rows.pop(0)
                elif fault=='duplicate_legacy_guard':rows.append(copy.deepcopy(rows[0]))
                elif fault=='conflicting_legacy_guard':rows[0]['definition']+=' foreign'
                else:rows[0]['invented_authority']=True
                with self.subTest(prior97_duplicate_projection=fault),self.assertRaises(G.Hold):
                    G.catalog97_delta(prior,G.catalog94_projection(after),functions,definitions)
            for fault in ('old_history','missing97','duplicate97','false97','function_body','function_header',
                    'function_definition','extra_function','old_quiet_function','check_definition','check_name',
                    'check_not_validated','extra_constraint','old_table','old_column','old_trigger',
                    'old_index','old94_function','old_SDK','ledger','legacy_guard_definition',
                    'missing_legacy_guard','duplicate_legacy_guard','extra_legacy_guard_field','other_legacy_function'):
                bad=copy.deepcopy(after)
                f=next(row for row in bad['supplement']['functions93']if row['name']=='retirement_forward_normal_finish_recovery_valid')
                check=next(row for row in bad['legacy']['catalog90']['constraints']if row['name']=='retirement_forward_normal_finish97')
                if fault in ('old_history','missing97','duplicate97','false97'):
                    h=G.loads(bad['legacy']['complete_history_wire'])
                    if fault=='old_history':h[-2]['is_applied']=False
                    elif fault=='missing97':h.pop()
                    elif fault=='duplicate97':h.append(copy.deepcopy(h[-1]))
                    else:h[-1]['is_applied']=False
                    bad['legacy']['complete_history_wire']=json.dumps(h)
                elif fault=='function_body':f['body']+=' '
                elif fault=='function_header':f['arguments']='foreign jsonb'
                elif fault=='function_definition':f['definition']='foreign'
                elif fault=='extra_function':bad['supplement']['functions93'].append(copy.deepcopy(f))
                elif fault=='old_quiet_function':
                    next(row for row in bad['supplement']['functions93']if row['name']=='retirement_forward_continuation_quiet')['body']+=' '
                elif fault=='check_definition':check['definition']+=' OR true'
                elif fault=='check_name':check['name']='foreign'
                elif fault=='check_not_validated':check['validated']=False
                elif fault=='extra_constraint':bad['legacy']['catalog90']['constraints'].append(dict(copy.deepcopy(check),name='foreign'))
                elif fault=='old_table':bad['legacy']['catalog90']['tables'][0]['name']='foreign'
                elif fault=='old_column':bad['supplement']['columns90_91'][0]['name']='foreign'
                elif fault=='old_trigger':bad['schema94']['triggers'][0]['definition']='foreign'
                elif fault=='old_index':bad['schema94']['indexes'][0]['definition']='foreign'
                elif fault=='old94_function':bad['schema94']['functions'][0]['body']+=' '
                elif fault=='old_SDK':bad['old_grants']['sha256']='f'*64
                elif fault=='legacy_guard_definition':bad['legacy']['catalog90']['functions'][0]['definition']+=' foreign'
                elif fault=='missing_legacy_guard':bad['legacy']['catalog90']['functions'].pop(0)
                elif fault=='duplicate_legacy_guard':bad['legacy']['catalog90']['functions'].append(copy.deepcopy(bad['legacy']['catalog90']['functions'][0]))
                elif fault=='extra_legacy_guard_field':bad['legacy']['catalog90']['functions'][0]['invented_authority']=True
                elif fault=='other_legacy_function':bad['legacy']['catalog90']['functions'][1]['definition']+=' foreign'
                else:bad['ledgers94'][0]['rows']+=1
                with self.subTest(catalog97_fault=fault),self.assertRaises(G.Hold):
                    G.check_catalog(bad,accepted,functions,old=before,migration=carrier)
        for fault in ('extra_artifact_field','wrong_source','wrong_migration','PG15','not_fixture','native_authority',
                      'before_bytes','before_SHA','after_unvalidated','old_check_retained','old_function_changed'):
            badrefs=copy.deepcopy(refs)
            artifact=G.loads(badrefs[carrier['artifact_ref']['path']])
            if fault=='extra_artifact_field':artifact['invented_authority']=True
            elif fault=='wrong_source':artifact['source_commit']='d'*40
            elif fault=='wrong_migration':artifact['migration97_sha256']='f'*64
            elif fault=='PG15':artifact['postgres_major']=15
            elif fault=='not_fixture':artifact['fixture_only']=False
            elif fault=='native_authority':artifact['native_authority']=True
            elif fault=='before_bytes':artifact['before96_ref']['bytes']+=1
            elif fault=='before_SHA':artifact['before96_ref']['sha256']='f'*64
            else:
                view=G.loads(badrefs[carrier['after97_ref']['path']])
                if fault=='after_unvalidated':view['constraints'][0]['validated']=False
                elif fault=='old_check_retained':
                    view['constraints'].append(copy.deepcopy(next(row for row in G.loads(refs[carrier['before96_ref']['path']])['constraints']if row['name']=='retirement_forward_mode93')))
                else:view['functions']['retirement_forward_continuation_valid']+=' '
                raw=G.wire(view);badrefs[carrier['after97_ref']['path']]=raw
                artifact['after97_ref'].update(sha256=G.sha(raw),bytes=len(raw))
            raw=G.wire(artifact);badrefs[carrier['artifact_ref']['path']]=raw
            badcarrier=copy.deepcopy(carrier)
            for role in badcarrier:badcarrier[role]['sha256']=G.sha(badrefs[badcarrier[role]['path']])
            def read_bad(ref,*_):
                raw=badrefs[ref['path']]
                if G.sha(raw)!=ref['sha256']:raise G.Hold('DECLARED_BAD_REF_SHA')
                return raw
            with self.subTest(PG97_original_fault=fault),self.assertRaises(G.Hold):
                G.constraint97_definitions(G.catalog94_projection(before),badcarrier,read_bad,'c'*40)
        # The artifact is data from actual PG CI, never a guessed extra schema field.
        fn=next(n for n in ast.parse(SOURCE.read_text()).body if isinstance(n,ast.FunctionDef)and n.name=='main')
        calls=[n for n in ast.walk(fn)if isinstance(n,ast.Call)and isinstance(n.func,ast.Name)and n.func.id=='check_catalog']
        self.assertEqual(len(calls),3)
        self.assertTrue(all(any(k.arg=='migration'and isinstance(k.value,ast.Name)and k.value.id=='deparse'for k in n.keywords)for n in calls))


    def test_normal_finish_original_success_failed_off_and_same_paid_create(self):
        value,case=normal_finish_operand();saved=copy.deepcopy(value);saved_case=copy.deepcopy(case)
        self.assertTrue(G.validate_normal_finish97(value,case))
        def source_spans(path):
            raw=path.read_text()
            return {n.name:ast.get_source_segment(raw,n)for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef)}
        own,shared=source_spans(SOURCE),source_spans(ROOT/'ops/network-guardian/rollout/core_image_cas_once_g15.py')
        for name in ('normal_finish_stamp_ns','normal_finish_pg_deadline_equal','validate_normal_finish97'):
            self.assertEqual(own[name],shared[name],name)
        # Real retained949ns wire rounds up in PG; wire order is never rounded.
        for wire_deadline,pg_deadline in NORMAL_FINISH_PG_DEADLINE_CASES+(
                ('2026-11-10T23:05:37.871732949-03:00','2026-11-11T02:05:37.871733+00:00'),
                ('2026-12-31T23:59:59.999999500Z','2027-01-01T00:00:00Z')):
            with self.subTest(normal_deadline_precision=(wire_deadline,pg_deadline)):
                self.assertTrue(G.normal_finish_pg_deadline_equal(wire_deadline,pg_deadline))
        exact,exactcase=normal_finish_operand(wire_deadline='2026-11-11T02:05:37.871732949Z',
            pg_deadline='2026-11-11T02:05:37.871733+00:00')
        self.assertTrue(G.validate_normal_finish97(exact,exactcase))
        offset,offsetcase=normal_finish_operand(wire_deadline='2026-11-10T23:05:37.871732949-03:00',
            pg_deadline='2026-11-11T02:05:37.871733+00:00')
        self.assertTrue(G.validate_normal_finish97(offset,offsetcase))
        self.assertEqual(G.normal_finish_stamp_ns('2026-11-11T02:05:37.871732950Z')-
            G.normal_finish_stamp_ns('2026-11-11T02:05:37.871732949Z'),1)
        for precision_fault in ('wrong_PG_microsecond','neighbor_PG_microsecond','PG_submicrosecond',
                'wire_deadline_shift','one_ns_late','exact_wire_deadline','one_ns_order_inversion'):
            bad,bcase=copy.deepcopy(exact),copy.deepcopy(exactcase);r=bad['records']
            caller=r['caller_returns'][0]['original_record'];request=r['retirement_requests'][0]
            if precision_fault=='wrong_PG_microsecond':request['original_deadline']='2026-11-11T02:05:37.871732+00:00'
            elif precision_fault=='neighbor_PG_microsecond':request['original_deadline']='2026-11-11T02:05:37.871734+00:00'
            elif precision_fault=='PG_submicrosecond':request['original_deadline']='2026-11-11T02:05:37.871733001Z'
            elif precision_fault=='wire_deadline_shift':caller['original_deadline']='2026-11-11T02:05:37.871732950Z'
            elif precision_fault=='one_ns_late':caller['driver_returned_at']='2026-11-11T02:05:37.871732950Z'
            elif precision_fault=='exact_wire_deadline':caller['driver_returned_at']=caller['original_deadline']
            else:
                caller['read_returned_at']='2026-11-11T02:05:08.200000500Z'
                caller['close_returned_at']='2026-11-11T02:05:08.200000499Z'
            reseal_normal_finish_caller(bad,bcase)
            with self.subTest(normal_deadline_precision_fault=precision_fault),self.assertRaises(G.Hold):
                G.validate_normal_finish97(bad,bcase)
        self.assertEqual(value,saved);self.assertEqual(case,saved_case)
        records=value['records']
        self.assertEqual(len(records),18);self.assertEqual(len(records['original_returns']),5)
        self.assertEqual(records['forward_rows'],[]);self.assertEqual(records['destroy_grants'],[])
        self.assertNotEqual(records['retirement_requests'][0]['intent_sha256'],
            records['native_poweroff_reads'][0]['original_record']['intent_sha256'])
        for fault in ('case_schema','case_source','case_generation','case_fence','case_owner','old_case',
                'body_wire','caller_status','caller_late','caller_context','missing_fourth','false_poweroff',
                'missing_read_return','extra_read','failed_off_retyped','invented_plan','context_failure',
                'preflight_as_final','missing_ACK','run_running','wrong_retire','lease_live','forward_marker',
                'new_DELETE','SDK_source','SDK_status','SDK_resource','SDK_clock','bytea_alias'):
            bad,bcase=copy.deepcopy(value),copy.deepcopy(case);r=bad['records']
            request=r['retirement_requests'][0];caller=r['caller_returns'][0]['original_record']
            prepared,returned=r['native_poweroff_reads'];d,v=prepared['original_record'],returned['original_record']
            grant=r['create_grants'][0]['grant_record'];sdk=grant['settlement']['original_provider_create_return']
            if fault=='case_schema':bcase['schema']='terminal_s8_and_current_live_failed_owner_v1'
            elif fault=='case_source':bcase['current_runtime_source']='f'*40
            elif fault=='case_generation':bcase['current_generation']=34
            elif fault=='case_fence':bcase['current_fencing_token']=70
            elif fault=='case_owner':bcase['current_lease_owner']='10000000-0000-4000-8000-000000000099'
            elif fault=='old_case':bcase['old_S8_authority']=True
            elif fault=='body_wire':bad['records_wire']+=' '
            elif fault=='caller_status':caller['status']=500
            elif fault=='caller_late':caller['driver_returned_at']=caller['original_deadline']
            elif fault=='caller_context':caller['original_context_failed']=True
            elif fault=='missing_fourth':r['original_returns'].pop()
            elif fault=='false_poweroff':r['original_returns'][-1]['original_return_record']['record']['powered_off_observed']=True
            elif fault=='missing_read_return':r['native_poweroff_reads'].pop()
            elif fault=='extra_read':r['native_poweroff_reads'].append(copy.deepcopy(returned))
            elif fault=='failed_off_retyped':v['call_failed']=False
            elif fault=='invented_plan':v['plan']={'server':{'status':'stopped'}}
            elif fault=='context_failure':v['original_context_failed']=True
            elif fault=='preflight_as_final':
                d['intent_sha256']=request['intent_sha256'];v['challenge']=copy.deepcopy(d)
                returned['original_native_join_wire']='\\x'+normal_finish_encoded(d).hex()
            elif fault=='missing_ACK':r['owning_dispatch_jobs'][0]['finalization_ack_at']=None
            elif fault=='run_running':r['workflow_runs'][0]['status']='running'
            elif fault=='wrong_retire':
                next(row for row in r['workflow_runs'][0]['result']['steps']if row['id']=='retire-original-guest')['status']='failed'
            elif fault=='lease_live':r['current_intent']['intent']['lease_expires_at']='2030-01-01T00:00:00Z'
            elif fault=='forward_marker':r['current_intent']['intent']['retirement_forward']={'id':'declared'}
            elif fault=='new_DELETE':r['delete_bindings'].append({'declared':'forbidden new write'})
            elif fault=='SDK_source':sdk['adapter_source_commit']='f'*40
            elif fault=='SDK_status':sdk['response_status']=True
            elif fault=='SDK_resource':sdk['resource_id']='i-foreign'
            elif fault=='SDK_clock':sdk['returned_at']=sdk['context_deadline']
            elif fault=='bytea_alias':request['original_wire']=base64.b64encode(bytes.fromhex(request['wire_hex'])).decode()
            if fault not in ('body_wire','bytea_alias'):seal_normal_finish_fixture(bad,bcase)
            else:
                # Keep the outer PG record custody honest while corrupting the
                # inner native bytea representation or exact whole snapshot SHA.
                if fault=='bytea_alias':
                    bad['records_wire']=normal_finish_encoded(r).decode()
                    bad['records_sha256']=bcase['expected_records_sha256']=G.sha(bad['records_wire'].encode())
            with self.subTest(normal_finish_fault=fault),self.assertRaises(G.Hold):
                G.validate_normal_finish97(bad,bcase)
        e70={'queries':{'original_notify_aws_vm_members':'DECLARED AWS E70','original_notify_hetzner_vm_members':'DECLARED HZ E70'}}
        provider_snapshots={name:{**copy.deepcopy(case['provider_lanes'][name]),
            'intent_identity':{'declared':name},'owned_slots':[{'declared':'full '+name+' roster'}],
            'active_policies':[{'declared':'full '+name+' policy'}],
            'policy_catalog_wire':'DECLARED exact '+name+' policy catalog wire'}for name in ('aws','hetzner')}
        replies=[copy.deepcopy(provider_snapshots[name])for name in ('aws','hetzner')]+[copy.deepcopy(value)]
        V=types.SimpleNamespace(query=mock.Mock(side_effect=replies))
        self.assertEqual(G.database(V,object(),Path('/declared'),e70,value,case,'BEFORE'),provider_snapshots)
        self.assertEqual(V.query.call_count,3)
        self.assertEqual(V.query.call_args.args[-1],G.NORMAL_FINISH_SQL)
        replies[0]['jobs_busy']=1
        V=types.SimpleNamespace(query=mock.Mock(side_effect=replies))
        with self.assertRaises(G.Hold):G.database(V,object(),Path('/declared'),e70,value,case,'PRESEND')
        self.assertEqual(V.query.call_count,1)

if __name__=="__main__":unittest.main()
