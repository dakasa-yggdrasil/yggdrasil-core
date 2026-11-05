"""Declared G13 CAS data only; never OCI, Root approval or native evidence. No target functions are executed during Source preparation."""
import ast
import base64
import contextlib
import copy
import json
from pathlib import Path
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / 'rollout/core_image_cas_once_g13.py'
cas = types.ModuleType('declared_g13_core_cas_CI')
cas.__file__ = str(PATH)
exec(compile(PATH.read_bytes(), str(PATH), 'exec'), cas.__dict__)


@contextlib.contextmanager
def binding():
    """Declared operands only; no validator or filesystem function is bypassed."""
    with patch.multiple(cas, SOURCE_BOUND=True, CORE_R='c'*40, NEW_DIGEST='d'*64,
        SOURCE_PIN='a'*64, TOOL_PINS={n:'a'*64 for n in ('pair_change_contract.py','derive_g13pair_controller_config.py','derive_standing_config.py','g13cut.py')},
        CONFIG_REF={'path':'/declared/config','sha256':'a'*64},
        SQL_DATA_REF={'path':'/declared/E70','sha256':cas.POLICY92_SQL_SHA},
        OLD_CONTAINER_ID='containerd://'+'b'*64, OLD_IMAGE_CONFIG_DIGEST='sha256:'+'e'*64,
        M94_MIGRATION_SHA=cas.M94_FINAL_SQL_SHA256, M94_NEW_TRIGGERS=('declared94',),
        CHANGE_CAUSE='Declared CI new source; no release or Root approval.'):
        yield


def core_operand():
    image = '153828470928.dkr.ecr.us-east-1.amazonaws.com/ghcr/dakasa-yggdrasil/yggdrasil-core@sha256:'+cas.OLD_DIGEST
    c = types.SimpleNamespace(OLD_DIGEST=cas.OLD_DIGEST,OLD_CORE_SOURCE=cas.OLD_SOURCE,
        NEW_DIGEST='d'*64,IMAGE_PREFIX=image.rsplit(':',1)[0]+':')
    d = {'apiVersion':'apps/v1','kind':'Deployment','metadata':{'namespace':'dakasa','name':'yggdrasil','uid':cas.UID,'generation':276,'resourceVersion':'1','annotations':{'dakasa.io/core-source-commit':cas.OLD_SOURCE,'retain':'declared'}},
        'spec':{'replicas':1,'template':{'spec':{'containers':[{'name':'core','image':image,'env':[{'name':'DECLARED','value':'unchanged'}],'resources':{'limits':{'cpu':'1'}}}]}}},
        'status':{'observedGeneration':276,'readyReplicas':1,'updatedReplicas':1,'availableReplicas':1}}
    ps = {'items':[{'metadata':{'uid':cas.OLD_POD,'name':'declared-r3'},'spec':{'containers':[{'name':'core','image':image}]},'status':{'phase':'Running','podIP':'192.0.2.1','containerStatuses':[{'name':'core','ready':True,'restartCount':0,'state':{'running':{'startedAt':'2026-11-04T16:00:00Z'}},'imageID':image,'containerID':'containerd://'+'b'*64}]}}]}
    return d, ps, c





def a3_operand():
    """Declared storage originals; no actual Root approval or provider evidence."""
    lease, finished, observed = '2026-11-05T00:25:12.260723Z','2026-11-05T00:20:14.370000Z','2026-11-05T01:00:00Z'
    ids = {k:'11111111-1111-4111-8111-111111111111' for k in ('workflow_id','lease_owner','executor_id')}
    p = {**ids,'preregistration_id':cas.A3_PRE,'original_create_grant_id':cas.A3_GRANT,'original_create_request_sha256':'5'*64,'slot':2,
         'policy_id':cas.A3_POLICY,'policy_checksum':'6'*64,'generation':22,'fence':43,'binding_name':'declared',
         'original_deadline':'2026-11-05T00:25:09Z','reserved_at':'2026-11-05T00:20:10Z'}
    wire = cas.canonical(p)
    grant = {'grant_id':cas.A3_GRANT,'state':'settled','capability':'ensure_ec2_instance','slot':2,'request_sha256':'5'*64,
             'binding_name':'declared','integration_instance_id':'declared-instance','scope_checksum':'7'*64,'profile_name':'declared','expires_at':'2026-11-05T00:25:09Z'}
    sdk = {'schema':'aws_original_run_instances_return_v1','provider':'aws','adapter_source_commit':cas.A3_CREATOR,
           'grant_id':cas.A3_GRANT,'attempt_id':cas.A3_ATTEMPT,'request_sha256':'5'*64,'action_id':cas.A3_ACTION,
           'resource_id':cas.A3_RESOURCE,'resource_created_at':cas.A3_BIRTH,'next_action_ids':[],
           'called_at':'2026-11-05T00:20:12Z','returned_at':'2026-11-05T00:20:14.251Z','context_deadline':'2026-11-05T00:25:09Z',
           'response_status':200,'response_bytes':17,'response_body_sha256':'8'*64}
    settlement = {'grant_id':cas.A3_GRANT,'attempt_id':cas.A3_ATTEMPT,'request_sha256':'5'*64,'outcome':'accepted','transport_completed':True,
                  'resource_id':cas.A3_RESOURCE,'resource_created_at':cas.A3_BIRTH,'action_id':cas.A3_ACTION,'original_provider_create_return':sdk,'observed_at':'2026-11-05T00:20:14.252Z'}
    gr = {'id':cas.A3_GRANT,'state':'settled','namespace':'dakasa-production','environment':'production','domain':'notify','dimension':'original_notify_aws_vm_members',
          'grant_record':{**ids,'grant':grant,'settlement':settlement,'binding':{'name':'declared','ensure_capability':'ensure_ec2_instance','original_provider_source_commit':cas.A3_CREATOR,'integration_instance_id':'declared-instance','scope_checksum':'7'*64,'profile_name':'declared'},
                          'policy_id':cas.A3_POLICY,'policy_checksum':'6'*64,'generation':22,'fencing_token':43,'attempt_id':cas.A3_ATTEMPT},
          **{k:None for k in ('original_disposition_id','failed_original_disposition_id','native_denied_disposition_id','enrolled_failed_disposition_id','failed_unwitnessed_expansion_cleanup_id')}}
    intent = {'generation':22,'fencing_token':43,'phase':'preparing','lease_owner':ids['lease_owner'],'lease_executor_id':ids['executor_id'],'lease_expires_at':lease,
              'baseline_snapshot':{'units':1},'assessment':{'snapshot':{'units':1}},'decision':{'units':2},'policy_id':cas.A3_POLICY,'policy_checksum':'6'*64}
    w = {'id':cas.A3_RUN,'status':'failed','finished_at':finished,'result':{'steps':[{'status':'failed','metadata':{'original_guest_refusal_predicate':'original-guest-step-25'}}]}}
    enrollment = {'preregistration_id':'22222222-2222-4222-8222-222222222222','enrollment_record':{'statement':{'tuple':{'resource_id':cas.S1_RESOURCE,'resource_created_at':cas.S1_BIRTH}}}}
    survivor = {'slot':1,'resource_id':cas.S1_RESOURCE,'slot_record':{'resource_created_at':cas.S1_BIRTH,'resource_id':cas.S1_RESOURCE,'tombstone':False},
                'integration_instance_id':'declared-instance','scope_checksum':'7'*64,'profile_name':'declared',
                'enrollments':[{'enrollment':enrollment,'witness':{'preregistration_id':enrollment['preregistration_id']},'installation':{'preregistration_id':enrollment['preregistration_id']}}]}
    value = {'observed_at_pg':observed,'intent_pgtext':cas.canonical(intent).decode(),'run_pgtext':cas.canonical(w).decode(),'grant_pgtext':cas.canonical(gr).decode(),
             # Dispatch authority is independent of capacity's fence/owner.
             'dispatch':[{'id':cas.A3_JOB,'run_id':cas.A3_RUN,'state':'returned','return_status':'failed','fencing_token':1,'lease_owner':'different-dispatch-owner',
                          'envelope':{'workflow':{'id':ids['workflow_id']}},'returned_at':finished,'finalization_ack_at':'2026-11-05T00:20:14.389Z','lease_expires_at':lease}],
             'preregistration':{'id':cas.A3_PRE,'create_grant_id':cas.A3_GRANT,'original_wire':'\\x'+wire.hex(),'preregistration_record':p,'original_deadline':p['original_deadline']},
             'active_policy':{'id':cas.A3_POLICY,'kind':'capacity_policy','active':True,'checksum':'6'*64},'survivors':[survivor],
             **{k:[] for k in ('target_witnesses','target_enrollments','target_installations','target_retirements','factory_bindings','compensations','cleanup_admissions')}}
    case = {**ids,'lease_expires_at':lease,'policy_checksum':'6'*64,'intent_sha256':cas.sha(value['intent_pgtext'].encode()),
            'run_sha256':cas.sha(value['run_pgtext'].encode()),'grant_sha256':cas.sha(value['grant_pgtext'].encode()),'preregistration_sha256':cas.sha(wire)}
    return value, {'case':case}, types.SimpleNamespace(loads=json.loads)


def source94_rows():
    """Actual checked-in migration text only; never executes SQL or provider code."""
    import re
    raw = (ROOT.parents[1]/'db/migrations/00094_failed_unwitnessed_expansion_cleanups.sql').read_bytes()
    if cas.sha(raw) != cas.M94_FINAL_SQL_SHA256:
        raise AssertionError('exact final migration94 Source bytes required')
    rows = []
    for name,args,result,stable,body in re.findall(r'CREATE FUNCTION public\.([a-z_]+)\(([^)]*)\) RETURNS (trigger|boolean) LANGUAGE plpgsql( STABLE)? AS \$\$(.*?)\$\$;',raw.decode().split('-- +goose Down')[0],re.S):
        rows.append({'name':name,'qualified_name':'public.'+name,'arguments':', '.join(a.strip() for a in args.split(',')) if args else '',
                     'result':result,'language':'plpgsql','volatility':'s' if stable else 'v','config':None,'body':body,'definition':'DECLARED pg_get_functiondef; literal Source body checked separately'})
    return rows


class G13CoreCASTests(unittest.TestCase):
    def test_forced_unbound_refuses_before_all_input_auth_or_native_io(self):
        with patch.object(cas,'SOURCE_BOUND',False), patch.object(cas,'read') as read, patch.object(cas,'load_tools') as tools, patch.object(cas,'API') as api:
            for call in (cas.main,lambda:cas.maintenance_inputs(object()),lambda:cas.database_a3(None,None,None,None,'BEFORE'),lambda:cas.g13_acceptance(None,None,None,None,None),lambda:cas.patch_once(None,None,None,None,None,0)):
                with self.subTest(call=repr(call)), self.assertRaises(cas.Hold): call()
            read.assert_not_called(); tools.assert_not_called(); api.assert_not_called()
        with patch.multiple(cas,SOURCE_BOUND=True,CORE_R=None,NEW_DIGEST=None,M94_MIGRATION_SHA=None),patch.object(cas,'read') as read:
            with self.assertRaises(cas.Hold):cas.require_bound()
            read.assert_not_called()

    def test_r3_preimage_and_full_cas_mutation_footprint(self):
        with binding():
            d, ps, C = core_operand(); cas.core_before(d,ps,C)
            for axis in ('source','pod','container','image','generation'):
                wrong, pods = copy.deepcopy(d),copy.deepcopy(ps)
                if axis=='source': wrong['metadata']['annotations']['dakasa.io/core-source-commit']='f'*40
                elif axis=='pod': pods['items'][0]['metadata']['uid']='22222222-2222-4222-8222-222222222222'
                elif axis=='container': pods['items'][0]['status']['containerStatuses'][0]['containerID']='containerd://'+'f'*64
                elif axis=='image': wrong['spec']['template']['spec']['containers'][0]['image']+='wrong'
                else: wrong['metadata']['generation']+=1
                with self.subTest(axis=axis),self.assertRaises(cas.Hold):cas.core_before(wrong,pods,C)
            ops=cas.build_patch(d,C)
            self.assertEqual([r['path'] for r in ops if r['op']=='test'],['/metadata/uid','/metadata/resourceVersion','/metadata/generation','/metadata/annotations','/spec'])
            self.assertEqual([r['path'] for r in ops if r['op']!='test'],['/spec/template/spec/containers/0/image','/metadata/annotations/dakasa.io~1core-source-commit','/metadata/annotations/kubernetes.io~1change-cause'])
            after=copy.deepcopy(d);after['spec']['template']['spec']['containers'][0]['image']=C.IMAGE_PREFIX+C.NEW_DIGEST
            after['metadata']['annotations'].update({'dakasa.io/core-source-commit':cas.CORE_R,'kubernetes.io/change-cause':cas.CHANGE_CAUSE});after['metadata'].update(generation=277,resourceVersion='2')
            cas.result_shape(d,after,C)
            for field in ('env','resources'):
                wrong=copy.deepcopy(after);wrong['spec']['template']['spec']['containers'][0][field]={}
                with self.subTest(field=field),self.assertRaises(cas.Hold):cas.result_shape(d,wrong,C)

    def test_known_a3_create_refuses_uncertain_ack_authority_or_epoch(self):
        value,c,C=a3_operand();self.assertTrue(cas.validate_a3(value,c,C))
        for fault in ('missing_ack','unknown','wrong_finish','wrong_predicate','unexpired_lease','foreign_capacity_owner','sdk_not_200','foreign_sdk_source','foreign_vm','sdk_next_action','sdk_before_reservation','sdk_after_grant_expiry','disposed_parent','wrong_prereg_wire','witness','enrollment','installation','retirement','cleanup_admission','extra_survivor','missing_survivor_enrollment','inactive_policy'):
            v=copy.deepcopy(value);config=copy.deepcopy(c)
            if fault=='missing_ack':v['dispatch'][0]['finalization_ack_at']=None
            elif fault=='unknown':v['dispatch'][0]['state']='unknown'
            elif fault=='wrong_finish':v['dispatch'][0]['returned_at']='2026-11-05T00:20:15Z'
            elif fault=='wrong_predicate':
                r=json.loads(v['run_pgtext']);r['result']['steps'][0]['metadata']['original_guest_refusal_predicate']='original-guest-step-17';v['run_pgtext']=cas.canonical(r).decode();config['case']['run_sha256']=cas.sha(v['run_pgtext'].encode())
            elif fault in ('unexpired_lease','foreign_capacity_owner'):
                i=json.loads(v['intent_pgtext'])
                if fault=='unexpired_lease':i['lease_expires_at']=config['case']['lease_expires_at']='2026-11-05T02:00:00Z'
                else:i['lease_owner']='22222222-2222-4222-8222-222222222222'
                v['intent_pgtext']=cas.canonical(i).decode();config['case']['intent_sha256']=cas.sha(v['intent_pgtext'].encode())
            elif fault in ('sdk_not_200','foreign_sdk_source','foreign_vm','sdk_next_action','sdk_before_reservation','sdk_after_grant_expiry','disposed_parent'):
                g=json.loads(v['grant_pgtext']);sdk=g['grant_record']['settlement']['original_provider_create_return']
                if fault=='sdk_not_200':sdk['response_status']=202
                elif fault=='foreign_sdk_source':sdk['adapter_source_commit']='f'*40
                elif fault=='foreign_vm':sdk['resource_id']='i-foreign'
                elif fault=='sdk_next_action':sdk['next_action_ids']=['declared-unexpected-action']
                elif fault=='sdk_before_reservation':sdk['called_at']='2026-11-05T00:20:09Z'
                elif fault=='sdk_after_grant_expiry':sdk['context_deadline']='2026-11-05T00:25:10Z'
                else:g['failed_unwitnessed_expansion_cleanup_id']='22222222-2222-4222-8222-222222222222'
                v['grant_pgtext']=cas.canonical(g).decode();config['case']['grant_sha256']=cas.sha(v['grant_pgtext'].encode())
            elif fault=='wrong_prereg_wire':v['preregistration']['original_wire']='\\x00'
            elif fault in ('witness','enrollment','installation','retirement','cleanup_admission'):
                key={'witness':'target_witnesses','enrollment':'target_enrollments','installation':'target_installations','retirement':'target_retirements','cleanup_admission':'cleanup_admissions'}[fault];v[key]=[{'declared':'present'}]
            elif fault=='extra_survivor':v['survivors'].append(copy.deepcopy(v['survivors'][0]))
            elif fault=='missing_survivor_enrollment':v['survivors'][0]['enrollments']=[]
            else:v['active_policy']['active']=False
            with self.subTest(fault=fault),self.assertRaises(cas.Hold):cas.validate_a3(v,config,C)
        # No synthetic grant or new seven-CAS/admission fields enter the image case.
        self.assertNotIn('Pending',cas.A3_SQL);self.assertNotIn('fd24881a',PATH.read_text())

    def test_once_markers_precede_only_actual_patch_and_prevent_replay(self):
        events=[];files={}
        def once(path,raw):
            if path in files:raise FileExistsError(str(path))
            files[path]=raw;events.append(('durable',path.name))
        C=types.SimpleNamespace(NEW_DIGEST='d'*64,wire=cas.canonical,once=once,loads=json.loads)
        class API:
            def request(self,method,uri,body=None):events.append((method,uri));return 200,b'{}',{}
        with binding(),patch.object(cas.time,'monotonic',return_value=100):
            cas.patch_once(API(),C,Path('/declared/run'),b'[]',{},99)
            self.assertEqual(events[:3],[('durable',cas.global_marker(C).name),('durable','POSSIBLE-SEND.json'),('PATCH',cas.DEP_URI+'?fieldManager=core-image-cas-once')])
            with self.assertRaises(FileExistsError):cas.patch_once(API(),C,Path('/declared/run2'),b'[]',{},99)
            self.assertEqual(sum(e[0]=='PATCH' for e in events),1)

    def test_lost_ack_is_get_only_and_expired_current15_never_sends(self):
        for expired in (False,True):
            events=[];files={}
            def once(path,raw):
                if path in files:raise FileExistsError(str(path))
                files[path]=raw;events.append(('durable',path.name))
            C=types.SimpleNamespace(NEW_DIGEST='d'*64,wire=cas.canonical,once=once,loads=json.loads)
            class API:
                def request(self,method,uri,body=None):
                    events.append((method,uri))
                    if method=='PATCH':raise TimeoutError('declared lost acknowledgement')
                    return 200,b'{}',{}
            with binding(),patch.object(cas.time,'monotonic',return_value=100):
                with self.assertRaises(cas.Hold):cas.patch_once(API(),C,Path('/declared/run'),b'[]',{},0 if expired else 99)
                self.assertEqual([e[0] for e in events if e[0] in ('GET','PATCH')],[] if expired else ['PATCH','GET'])
                with self.assertRaises(FileExistsError):cas.patch_once(API(),C,Path('/declared/run2'),b'[]',{},99)
                self.assertEqual(sum(e[0]=='PATCH' for e in events),0 if expired else 1)

    def test_common_custody_and_schema94_preserve_prior93_whole_history(self):
        old=(ROOT/'rollout/core_image_cas_once_g12.py').read_text();new=PATH.read_text()
        def spans(raw):return {n.name:ast.get_source_segment(raw,n) for n in ast.parse(raw).body if isinstance(n,(ast.FunctionDef,ast.ClassDef))}
        a,b=spans(old),spans(new)
        for name in ('API','operation_lock','read','api_read','result_shape','query','workflow_busy_logical_index92_sql','catalog_sql','catalog_projection','catalog_select','patch_once','utc'):
            self.assertEqual(a[name],b[name],name)
        self.assertIn("statement_timeout='3s'",b['query']);self.assertIn("lock_timeout='500ms'",b['query']);self.assertIn('timeout=8',b['query'])
        history=[{'id':i+1,'version_id':n,'is_applied':True} for i,n in enumerate([0]+[n for n in range(1,95) if n!=40])]
        facts={'database':'yggdrasil','readonly':'on','history_max_version':94,'latest_versions':[r['version_id'] for r in history],
               'rows90':1,'rows91':1,'rows92':1,'complete_history_wire':json.dumps(history),'catalog90':{},'catalog91':{},'other_migrators_ddl':0,'other_cic':0,'ddl_locks':0}
        cat={'tables':[{'name':n} for n in ('public.capacity_failed_unwitnessed_expansion_cleanups','public.capacity_failed_unwitnessed_expansion_cleanup_events','public.capacity_mutation_grants','public.capacity_intents')],
             'columns':[{'table':'public.capacity_intents','name':'intent','type':'jsonb'}],
             'constraints':[{'table':'public.capacity_intents','name':'capacity_intents_pkey','validated':True,'definition':'DECLARED original PK'}],
             'indexes':[{'table':'public.capacity_intents','name':'public.capacity_intents_pkey','valid':True,'ready':True,'live':True,'definition':'DECLARED original index'}],
             'triggers':[{'name':'declared94','table':'public.capacity_mutation_grants'}, {'table':'public.capacity_intents','name':cas.M94_INTENT_TRIGGER,'enabled':'O',
                         'function':'public.guard_failed_unwitnessed_expansion_cleanup_intent()','definition':cas.M94_INTENT_TRIGGER_DEFINITION}],
             'functions':source94_rows()}
        current={'legacy':copy.deepcopy(facts),'supplement':{'columns90_91':[],'functions93':[],'index92_valid':True,'index92_definition':'declared'},'schema94':cat}
        projection=cas.catalog94_projection(current)
        refs={}
        def ref(name,raw):
            path='/declared/'+name;refs[path]=raw;return {'path':path,'sha256':cas.sha(raw)}
        prior=ref('prior93',json.dumps(history[:-1]).encode());catalog=ref('catalog94',cas.canonical(projection))
        pins={'complete_history_sha256':cas.sha(facts['complete_history_wire'].encode()),'index92_definition_sha256':cas.sha(b'declared'),
              'catalog90_91_sha256':cas.sha(cas.canonical({'catalog90':{},'catalog91':{}})),'schema94_catalog_sha256':cas.sha(cas.canonical(projection))}
        with binding():
            receipt={'schema':'root_goose94_failed_unwitnessed_expansion_cleanup_acceptance_v1','reviewed_by_root':True,'schema_before':93,'schema_after':94,
                     'current_core_source':cas.OLD_SOURCE,'current_ops_source':'3e617cc176026cd70ee885ede753fbc6f6dd17a6','business_source':cas.CORE_R,'amd64_D':cas.NEW_DIGEST,
                     'migration94_sha256':cas.M94_MIGRATION_SHA,'complete_history_sha256':pins['complete_history_sha256'],'prior93_history_sha256':prior['sha256'],
                     'catalog94_sha256':pins['schema94_catalog_sha256'],'index92_definition_sha256':pins['index92_definition_sha256'],'catalog90_91_sha256':pins['catalog90_91_sha256'],
                     'job_uid':'11111111-1111-4111-8111-111111111111','pod_uid':'22222222-2222-4222-8222-222222222222','exit_code':0,'single_job_create':True,
                     'provider_guest_core_mutations':0,'old_records_and_sdk_preserved':True,
                     'original_refs':{n:ref(n,b'declared original') for n in ('migration_result','before_catalog','after_catalog','source_ci','qualified_image')}}
            rootref=ref('root94',cas.canonical(receipt));config={'schema_pins':pins,'prior93_history_ref':prior,'schema94_catalog_ref':catalog,'acceptance_refs':{'Root_Goose94_acceptance':rootref}}
            legacy={'schema_facts':facts,'index89_valid':True,'index92_valid':True,'index92_definition':'declared'}
            with patch.object(cas,'input_ref',side_effect=lambda C,r:refs[r['path']]):
                cas.schema94_facts(config,legacy,current,types.SimpleNamespace(loads=json.loads))
                for fault in ('old_history','catalog','root_mutation','extra_root_field'):
                    oldrefs=copy.deepcopy(refs)
                    if fault=='old_history':refs[prior['path']]=json.dumps([{**r,'id':999} if r['version_id']==93 else r for r in history[:-1]]).encode()
                    elif fault=='catalog':refs[catalog['path']]=cas.canonical({**projection,'schema94':{**cat,'indexes':[]}})
                    else:
                        bad=copy.deepcopy(receipt);bad['provider_guest_core_mutations']=1 if fault=='root_mutation' else 0
                        if fault=='extra_root_field':bad['invented_authority']=True
                        refs[rootref['path']]=cas.canonical(bad)
                    with self.subTest(fault=fault),self.assertRaises(cas.Hold):cas.schema94_facts(config,legacy,current,types.SimpleNamespace(loads=json.loads))
                    refs.clear();refs.update(oldrefs)
        # Full post94 catalog equality preserves every old intent column,
        # constraint and index, rather than checking only the new trigger.
        with binding(),patch.object(cas,'input_ref',side_effect=lambda C,r:refs[r['path']]):
            for axis in ('columns','constraints','indexes','tables','missing_intent_trigger','intent_trigger_body','function_body','function_result'):
                bad = copy.deepcopy(current)
                if axis in ('columns','constraints','indexes'):
                    bad['schema94'][axis] = []
                elif axis == 'tables':
                    bad['schema94']['tables'] = [r for r in bad['schema94']['tables'] if r['name'] != 'public.capacity_intents']
                elif axis == 'missing_intent_trigger':
                    bad['schema94']['triggers'] = [r for r in bad['schema94']['triggers'] if r['name'] != cas.M94_INTENT_TRIGGER]
                elif axis == 'intent_trigger_body':
                    bad['schema94']['triggers'][-1]['definition'] += ' DECLARED changed timing'
                elif axis == 'function_body':
                    bad['schema94']['functions'][0]['body'] += '\n-- DECLARED changed body'
                else:
                    bad['schema94']['functions'][0]['result'] = 'boolean'
                with self.subTest(final_catalog_axis=axis),self.assertRaises(cas.Hold):
                    cas.schema94_facts(config,legacy,bad,types.SimpleNamespace(loads=json.loads))
            # Even a newly pinned full catalog cannot transfer qualification
            # to a different Source function body or intent trigger semantics.
            for axis in ('function_body','intent_trigger'):
                bad = copy.deepcopy(current); cfg = copy.deepcopy(config); proof = copy.deepcopy(receipt); oldrefs = copy.deepcopy(refs)
                if axis == 'function_body': bad['schema94']['functions'][0]['body'] += '\n-- DECLARED foreign Source'
                else: bad['schema94']['triggers'][-1]['definition'] += ' DECLARED foreign timing'
                projected = cas.catalog94_projection(bad); raw = cas.canonical(projected)
                refs[catalog['path']] = raw; cfg['schema_pins']['schema94_catalog_sha256'] = cas.sha(raw)
                proof['catalog94_sha256'] = cas.sha(raw); refs[rootref['path']] = cas.canonical(proof)
                with self.subTest(resealed_wrong_Source=axis),self.assertRaises(cas.Hold):
                    cas.schema94_facts(cfg,legacy,bad,types.SimpleNamespace(loads=json.loads))
                refs.clear();refs.update(oldrefs)
        legacy=(ROOT/'tests/fixtures/g13-cas-legacy-catalog.sql').read_bytes();self.assertEqual(cas.sha(legacy),cas.LEGACY_CATALOG_SHA)
        sql=cas.catalog94_select(legacy.decode());self.assertTrue(sql.startswith('WITH old93(v) AS (WITH legacy AS (SELECT '));self.assertNotIn('COMMIT;',sql)


if __name__=='__main__':unittest.main()
