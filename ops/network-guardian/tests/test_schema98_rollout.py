"""Declared schema98 operator operands; CI only, no Native qualification."""
import ast
import copy
import hashlib
import importlib.util
import json
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
ROLLOUT = ROOT/'ops/network-guardian/rollout'


def load98(name, path):
    spec = importlib.util.spec_from_file_location(name,path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


C = load98('declared_core9_cas98',ROLLOUT/'core_image_cas_once_g15_schema98.py')
G = load98('declared_goose98',ROLLOUT/'goose98_native_once.py')
P = load98('declared_post98',ROLLOUT/'post_core_inventory_schema98_readonly.py')


def data98(value):
    return json.dumps(value,sort_keys=True,separators=(',',':')).encode()


def digest98(raw):
    return hashlib.sha256(raw).hexdigest()


def uuid98(number):
    return '00000000-0000-4000-8000-%012d'%number


def installed_operand98():
    """All signatures/records here are declared data, never Native receipts."""
    case = {**C.INSTALLED_TIMEOUT_TARGET,'schema':C.INSTALLED_TIMEOUT_CASE_SCHEMA,
            'expected_records_sha256':None,'provider_lanes':{}}
    scope = dict(namespace='dakasa-production',environment='production',domain='notify',dimension='original_notify_aws_vm_members')
    binding = dict(name='declared-original',integration_instance_id=uuid98(10),integration_checksum='1'*64,
                   integration_type_id=uuid98(11),integration_type_checksum='2'*64,scope_checksum='3'*64,
                   profile_name='declared-profile',ensure_capability='ensure_vm')
    retirement = {'mode':'original_guest_notify_reconcile_v1','members':[{'slot':n}for n in range(1,9)]}
    workflow = dict(id=uuid98(12),namespace=scope['namespace'],name='declared-original',version=1,checksum='4'*64)
    metadata = {'triggered_by':'workflow_scheduler','capacity_dispatch_job_id':case['job_id']}
    env = dict(protocol='capacity_dispatch_prestart_v1',job_id=case['job_id'],run_id=case['run_id'],
               policy={'id':case['policy_id'],'namespace':scope['namespace'],'name':'declared-policy','version':18,'checksum':case['policy_checksum']},workflow=workflow,metadata=metadata,inputs={})
    envelope = data98(env).decode()
    start='2026-11-11T10:04:07.964761Z';deadline='2026-11-11T10:09:07.964761Z';returned='2026-11-11T10:09:07.965763Z'
    job = dict(id=case['job_id'],run_id=case['run_id'],realm=scope['namespace'],environment=scope['environment'],
               domain=scope['domain'],dimension=scope['dimension'],protocol=env['protocol'],state='unknown',
               return_status='failed',return_error='capacity dispatch original deadline exceeded',
               finalization_error='capacity dispatch original deadline exceeded',finalization_ack_at=None,
               started_at=start,lease_expires_at=deadline,returned_at=returned,envelope=envelope,
               envelope_sha256=digest98(envelope.encode()),pending_wake_count=32,failed_original_disposition_id=None)
    intent = {**scope,'policy_id':case['policy_id'],'policy_checksum':case['policy_checksum'],
              'generation':44,'fencing_token':85,'lease_owner':case['current_lease_owner'],
              'lease_executor_id':case['current_executor_id'],'lease_expires_at':'2026-11-11T10:09:15Z',
              'phase':'preparing','recovery_only':False,'decision':{'action':'expand','units':8},
              'baseline_snapshot':{'units':7},'assessment':{'snapshot':{'units':7}}}
    policy = dict(id=case['policy_id'],checksum=case['policy_checksum'],namespace=scope['namespace'],
                  kind='capacity_policy',active=True,spec={'execution_enabled':True,'ceiling':8,
                  'mutation_bindings':[binding],'guest_retirement_binding':retirement,'guest_notify_reconcile_binding':{'mode':'original_guest_notify_reconcile_v1'}})
    members=[];proofs=[];selected=None
    for slot in range(1,9):
        current=slot==8;pre_id='096c3054-fe8d-4a8d-afc8-fdff2bc9f241'if current else uuid98(100+slot)
        grant_id='8062bc1c-888f-46cf-ace7-11c7027aed1f'if current else uuid98(200+slot)
        generation=44 if current else 20+slot;fence=85 if current else 30+slot
        owner=case['current_lease_owner']if current else uuid98(300+slot)
        executor=case['current_executor_id']if current else uuid98(400+slot)
        resource='i-070b5767a35c7f0d5'if slot==1 else 'i-declared%08d'%slot
        birth='2026-11-03T01:17:18Z'if slot==1 else '2026-11-11T10:04:16Z'
        reserved='2026-11-11T10:04:16Z'if current else '2026-11-11T06:00:00Z'
        expiry=deadline if current else '2026-11-11T06:05:00Z'
        created_return='2026-11-11T10:08:35Z'if current else '2026-11-11T06:00:02Z'
        installed_at='2026-11-11T10:08:35.013390Z'if current else '2026-11-11T06:00:24Z'
        request_sha=('%064x'%slot)
        tup=dict(provider='aws',integration_instance_id=binding['integration_instance_id'],instance_checksum=binding['integration_checksum'],
                 integration_type_id=binding['integration_type_id'],type_checksum=binding['integration_type_checksum'],
                 scope_checksum=binding['scope_checksum'],profile_checksum='5'*64,profile=binding['profile_name'],slot=slot,
                 resource_id=resource,resource_created_at=birth)
        pr=dict(schema='original_guest_provisioning_preregistration_v1',preregistration_id=pre_id,original_create_grant_id=grant_id,
                original_create_request_sha256=request_sha,slot=slot,generation=generation,fence=fence,lease_owner=owner,
                executor_id=executor,policy_id=case['policy_id'],policy_checksum=case['policy_checksum'],workflow_id=workflow['id'],
                reserved_at=reserved,original_deadline=expiry,core_source_commit='e'*40)
        wr=dict(schema='original_guest_create_witness_v1',preregistration_id=pre_id,original_create_grant_id=grant_id,
                original_create_request_sha256=request_sha,original_create_attempt_id=uuid98(500+slot),tuple=tup,
                original_create_returned_at=created_return)
        clock_sha='%064x'%(600+slot)
        issued='2026-11-11T10:08:34Z'if current else '2026-11-11T06:00:23Z'
        read_returned='2026-11-11T10:08:34.5Z'if current else '2026-11-11T06:00:23.5Z'
        er={'statement':{'tuple':tup,'issued_at':issued,'original_provisioning_clock_sha256':clock_sha},'signature':'DECLARED_NOT_A_NATIVE_SIGNATURE'}
        receipt={'preregistration_id':pre_id,'enrollment':er}
        receipt_wire=data98(receipt);enrollment_sha=digest98(data98(er))
        ins=dict(schema='guest_original_installation_v2',preregistration_id=pre_id,original_receipt_sha256=digest98(receipt_wire),
                 enrollment_sha256=enrollment_sha,installed_at=installed_at,admitted_at=installed_at,
                 production_clock=dict(schema='original_guest_installation_clock_v2',original_provisioning_clock_sha256=clock_sha,
                    original_receipt_read_started_monotonic_ns=100,original_receipt_read_returned_monotonic_ns=200,
                    original_receipt_read_returned_at=read_returned,installed_monotonic_ns=300,admitted_monotonic_ns=400,
                    original_confirmation_prepared_monotonic_ns=500))
        slot_record=dict(resource_id=resource,resource_created_at=birth,tombstone=False,desired_spec_sha256=request_sha)
        member={**scope,'slot':slot,'integration_instance_id':binding['integration_instance_id'],'scope_checksum':binding['scope_checksum'],
                'profile_name':binding['profile_name'],'resource_id':resource,'slot_record':slot_record}
        grant_record=dict(binding=binding,grant=dict(grant_id=grant_id,state='confirmed',capability='ensure_vm',request_sha256=request_sha),
                          generation=generation,fencing_token=fence,lease_owner=owner,executor_id=executor,policy_id=case['policy_id'],
                          policy_checksum=case['policy_checksum'],workflow_id=workflow['id'],attempt_id=wr['original_create_attempt_id'],
                          settlement=dict(outcome='accepted',transport_completed=True,resource_id=resource,resource_created_at=birth))
        grant={**scope,'id':grant_id,'state':'confirmed','generation':generation,'grant_record':grant_record}
        pre=dict(id=pre_id,create_grant_id=grant_id,created_at=reserved,original_deadline=expiry,
                 original_wire='\\x'+data98(pr).hex(),preregistration_record=pr,binding_wire='\\x'+data98(retirement).hex())
        witness=dict(preregistration_id=pre_id,original_wire='\\x'+data98(wr).hex(),original_record=wr,witness_sha256=digest98(data98(wr)))
        enrollment=dict(preregistration_id=pre_id,receipt_wire='\\x'+receipt_wire.hex(),enrollment_record=er,enrollment_sha256=enrollment_sha)
        installation=dict(preregistration_id=pre_id,original_wire='\\x'+data98(ins).hex(),confirmation_sha256=digest98(data98(ins)),recorded_at=installed_at)
        members.append(member);proofs.append(dict(slot_record=member,grant=grant,preregistration=pre,witness=witness,enrollment=enrollment,installation=installation))
        if current:selected=pr
    ids=('plan-original-guest','provision-original-notify','retire-original-guest','refresh-original-membership','complete-original-provision','finish-original-retirement','complete-original-retirement')
    ops=('capacity.plan_original_guest','capacity.provision_original_guest','capacity.retire_original_guest','capacity.complete_original_guest','capacity.complete_original_guest','capacity.finish_original_guest_retirement','capacity.complete_original_guest')
    statuses=('succeeded','succeeded','skipped','skipped','failed','skipped','skipped')
    steps=[]
    for identity,operation,status in zip(ids,ops,statuses):
        steps.append(dict(id=identity,kind='yggdrasil',operation=operation,capability=operation,status=status,attempts=0 if status=='skipped'else 1,
                          started_at='2026-11-11T10:08:35.646Z',finished_at='2026-11-11T10:08:35.647Z',metadata={}))
    steps[2]['metadata']={'condition':'{{ steps.plan-original-guest.metadata.mode }} == retire','skip_reason':'condition'}
    steps[3]['metadata']={'condition':'{{ steps.plan-original-guest.metadata.mode }} == refresh','skip_reason':'condition'}
    steps[0].update(started_at='2026-11-11T10:04:15Z',finished_at='2026-11-11T10:04:15.1Z',metadata={'mode':'provision','slot':8,'generation':44,'fencing_token':85,'lease_owner':case['current_lease_owner']})
    steps[1].update(started_at='2026-11-11T10:04:15.1Z',finished_at='2026-11-11T10:08:35.646Z',metadata={'preregistration':selected})
    steps[4].update(started_at='2026-11-11T10:08:35.646Z',finished_at=returned,metadata={'original_guest_reconcile_refusal_stage':'source_assessment'},error='original Guest reconciliation held')
    result=dict(status='failed',workflow={'kind':'workflow',**{k:workflow[k]for k in ('id','namespace','name','version')}},steps=steps)
    run=dict(id=case['run_id'],status='failed',error=job['return_error'],started_at=start,finished_at=returned,metadata=metadata,inputs={},result=result)
    records=dict(job=job,run=run,intent=intent,policy=policy,members=members,proofs=proofs,current_grants=[proofs[-1]['grant']],
                 unresolved_grants=[],current_canaries=[],current_retirements=[],authority_slots=[],other_jobs=[],other_runs=[])
    lanes=dict(jobs_busy=1,runs_busy=0,forward_unreturned_reads=0,live_unreturned_canaries=0,intent_count=1,intent_busy=1,pending_authority=0,forward_markers=0)
    case['provider_lanes']={'aws':lanes,'hetzner':{**lanes,'jobs_busy':0,'intent_busy':0}}
    value={'schema':'unknown_installed_provision_timeout_snapshot_v1','observed_at_core':'2026-11-11T10:20:00Z','records_wire':''}
    reseal_installed98(value,case,records)
    return value,case,records


def reseal_installed98(value,case,records):
    value['records_wire']=data98(records).decode()
    case['expected_records_sha256']=digest98(value['records_wire'].encode())


class Schema98RolloutTests(unittest.TestCase):
    def test_unbound_schema98_operators_refuse_before_io(self):
        for module,read_name in ((C,'read'),(G,'private_read'),(P,'read_private')):
            with self.subTest(module=module.__name__),mock.patch.object(module,'SOURCE_BOUND',False),mock.patch.object(module,read_name)as read:
                with self.assertRaises(module.Hold):module.main()
                read.assert_not_called()

    def test_original_G44_unknown_installed_roster_and_historical_axes(self):
        value,case,records=installed_operand98()
        for module in (C,G):
            with self.subTest(module=module.__name__):
                self.assertEqual(module.validate_installed_timeout98(value,case),records)
                self.assertEqual(module.HISTORICAL_CORE8_SOURCE,'0764e6b267d3d6ddbfb4d7a4b9fb4024018bf89f')
                self.assertEqual(module.HISTORICAL_M9_OPS_SOURCE,'b6a1d90e0c6e61b01c12c8fb7504afeec9de4f94')
        # Real PG nearest-us representation does not change raw step ordering.
        pr=records['proofs'][-1]['preregistration'];original=records['run']['result']['steps'][1]['metadata']['preregistration']
        original['reserved_at']='2026-11-11T10:04:16.000000949Z'
        pr['preregistration_record']=original;pr['original_wire']='\\x'+data98(original).hex();pr['created_at']='2026-11-11T10:04:16.000001Z'
        reseal_installed98(value,case,records)
        self.assertEqual(C.validate_installed_timeout98(value,case),records)
        # E70 counts this exact immutable AWS UNKNOWN job; retain raw1, never quiet0.
        for module in (C,G):
            for provider in ('aws','hetzner'):
                self.assertEqual(module.installed_timeout_lanes98(case['provider_lanes'][provider],case,provider),case['provider_lanes'][provider])
            for provider,busy in (('aws',0),('aws',2),('hetzner',1)):
                altered=copy.deepcopy(case);altered['provider_lanes'][provider]['jobs_busy']=busy
                with self.subTest(module=module.__name__,provider=provider,busy=busy),self.assertRaises(module.Hold):
                    module.installed_timeout_lanes98(altered['provider_lanes'][provider],altered,provider)
            with self.assertRaises(module.Hold):
                module.installed_timeout_lanes98(case['provider_lanes']['aws'],case,'foreign')
            altered=copy.deepcopy(case);altered['provider_lanes']['aws']['jobs_busy']=0
            with self.assertRaises(module.Hold):
                module.installed_timeout_lanes98(case['provider_lanes']['aws'],altered,'aws')
            altered=copy.deepcopy(case);altered['job_id']=uuid98(904)
            with self.assertRaises(module.Hold):
                module.installed_timeout_lanes98(case['provider_lanes']['aws'],altered,'aws')

    def test_G44_preimage_rejects_resealed_wrong_history_and_effects(self):
        def change_record(label,r):
            if label=='false_ACK':r['job']['finalization_ack_at']=r['job']['returned_at']
            elif label=='returned':r['job']['state']='returned'
            elif label=='late_original_live':r['intent']['lease_expires_at']='2026-11-11T10:21:00Z'
            elif label=='missing_member':r['members'].pop()
            elif label=='missing_installation':r['proofs'][-1]['installation']['original_wire']='\\x7b7d'
            elif label=='hidden_DELETE':r['current_grants'].append(copy.deepcopy(r['current_grants'][0]))
            elif label=='unresolved':r['unresolved_grants'].append(uuid98(900))
            elif label=='notify':r['current_canaries'].append(uuid98(901))
            elif label=='retirement':r['current_retirements'].append(uuid98(902))
            elif label=='foreign_authority':r['authority_slots'].append({'declared':True})
            elif label=='other_job':r['other_jobs'].append(uuid98(903))
            elif label=='new_epoch':r['intent']['fencing_token']+=1
            elif label=='wrong_floor':r['intent']['baseline_snapshot']['units']=0
            elif label=='wrong_stage':r['run']['result']['steps'][4]['metadata']['original_guest_reconcile_refusal_stage']='notify'
            elif label=='wrong_operation':r['run']['result']['steps'][2]['operation']='capacity.provision_original_guest'
            elif label=='wrong_capability':r['run']['result']['steps'][2]['capability']='capacity.provision_original_guest'
            elif label=='wrong_kind':r['run']['result']['steps'][2]['kind']='http'
            elif label.startswith('skip_'):
                _,ordinal,fault=label.split('_');step=r['run']['result']['steps'][int(ordinal)]
                if fault=='condition':step['metadata']['condition']='{{ steps.plan-original-guest.metadata.mode }} == provision'
                elif fault=='reason':step['metadata']['skip_reason']='other'
                elif fault=='extra':step['metadata']['extra']=True
                elif fault=='empty':step['metadata']={}
            elif label=='bool_attempt':r['run']['result']['steps'][0]['attempts']=True
            elif label=='reordered':r['run']['result']['steps'][2:4]=reversed(r['run']['result']['steps'][2:4])
            elif label=='late_provision':r['run']['result']['steps'][1]['finished_at']=r['proofs'][-1]['preregistration']['preregistration_record']['original_deadline']
            elif label=='inverted_wire':r['run']['result']['steps'][0]['finished_at']='2026-11-11T10:04:15.100000001Z'
            elif label=='wrong_S1':r['members'][0]['resource_id']='i-declared-wrong'
            elif label=='unconfirmed':r['proofs'][0]['grant']['state']='settled'
            elif label=='foreign_tuple':r['proofs'][0]['witness']['original_record']['tuple']['resource_id']='i-wrong'
            elif label.startswith('clock_')or label=='installation_v1':
                row=r['proofs'][-1]['installation'];installed=json.loads(bytes.fromhex(row['original_wire'][2:]))
                if label=='installation_v1':installed['schema']='guest_original_installation_v1'
                elif label=='clock_schema':installed['production_clock']['schema']='original_guest_provisioning_clock_v2'
                elif label=='clock_digest':installed['production_clock']['original_provisioning_clock_sha256']='f'*64
                elif label=='clock_order':installed['production_clock']['installed_monotonic_ns']=1
                elif label=='clock_type':installed['production_clock']['original_receipt_read_started_monotonic_ns']=True
                raw=data98(installed);row['original_wire']='\\x'+raw.hex();row['confirmation_sha256']=digest98(raw)
        for label in ('false_ACK','returned','late_original_live','missing_member','missing_installation','hidden_DELETE','unresolved',
                      'notify','retirement','foreign_authority','other_job','new_epoch','wrong_floor','wrong_stage','wrong_operation',
                      'wrong_capability','wrong_kind','bool_attempt','reordered','late_provision','inverted_wire','wrong_S1','unconfirmed','foreign_tuple',
                      'installation_v1','clock_schema','clock_digest','clock_order','clock_type',
                      'skip_2_condition','skip_3_condition','skip_2_reason','skip_3_reason',
                      'skip_2_extra','skip_3_extra','skip_2_empty','skip_3_empty','skip_5_extra','skip_6_extra'):
            value,case,records=installed_operand98();change_record(label,records);reseal_installed98(value,case,records)
            for module in (C,G):
                with self.subTest(label=label,module=module.__name__),self.assertRaises((module.Hold,KeyError,TypeError,ValueError)):
                    module.validate_installed_timeout98(value,case)
        value,case,records=installed_operand98();case['current_runtime_source']=C.ROOT97_CURRENT_CORE_SOURCE
        with self.assertRaises(C.Hold):C.validate_installed_timeout98(value,case)

    def test_goose98_single_Job_and_CAS_single_PATCH_preserve_once(self):
        # Exercise the real whole14 Core preimage guard before any Job/claim path.
        dep_uid,pod_uid,rs_uid=uuid98(810),uuid98(811),uuid98(812)
        rs_name='yggdrasil-declared-core8';pod_name=rs_name+'-declared'
        rs_uri='/apis/apps/v1/namespaces/dakasa/replicasets/'+rs_name
        config_digest='c'*64;started='2026-11-11T01:20:26Z'
        image=G.PREFIX+G.CURRENT_CORE_D
        dep={'metadata':{'uid':dep_uid,'generation':281,'annotations':{'dakasa.io/core-source-commit':G.CURRENT_CORE_R}},
             'spec':{'replicas':1,'template':{'spec':{'containers':[{'name':'core','image':image}]}}},
             'status':{'observedGeneration':281,'readyReplicas':1,'updatedReplicas':1,'availableReplicas':1,'unavailableReplicas':0}}
        rs={'metadata':{'uid':rs_uid,'name':rs_name,'ownerReferences':[{'uid':dep_uid,'controller':True}]},
            'spec':{'replicas':1,'template':copy.deepcopy(dep['spec']['template'])}}
        pod={'metadata':{'uid':pod_uid,'name':pod_name,'ownerReferences':[{'uid':rs_uid,'controller':True}]},
             'spec':{'nodeName':'declared-brain','containers':[{'name':'core','image':image}]},
             'status':{'phase':'Running','containerStatuses':[{'name':'core','ready':True,'restartCount':0,
                       'containerID':'containerd://declared-core8','state':{'running':{'startedAt':started}},
                       'imageID':image,'image':'sha256:'+config_digest}]}}
        expected={'deployment_uid':dep_uid,'generation':281,
                  'deployment_spec_sha256':G.sha(G.wire(dep['spec'])),
                  'deployment_metadata_sha256':G.sha(G.wire(G.stable_metadata(dep))),
                  'replicaset_name':rs_name,'replicaset_uid':rs_uid,
                  'replicaset_spec_sha256':G.sha(G.wire(rs['spec'])),
                  'replicaset_metadata_sha256':G.sha(G.wire(G.stable_metadata(rs))),
                  'pod_name':pod_name,'pod_uid':pod_uid,'container_id':'containerd://declared-core8',
                  'container_started_at':started,'node_name':'declared-brain',
                  'pod_spec_sha256':G.sha(G.wire(pod['spec']))}
        objects={G.DEP_URI:dep,rs_uri:rs,G.CORE_PODS_URI:{'kind':'PodList','metadata':{},'items':[pod]}}
        with mock.patch.multiple(G,CURRENT_CORE_GENERATION=281,CURRENT_CORE_UID=dep_uid,
                                 CURRENT_CORE_POD_UID=pod_uid,CURRENT_RS_UID=rs_uid,
                                 RS_URI=rs_uri,CURRENT_CORE_CONFIG=config_digest):
            api=mock.Mock();api.get.side_effect=lambda uri:copy.deepcopy(objects[uri])
            actual=G.core(api,expected)
            self.assertEqual(actual,expected);self.assertIsNot(actual,expected)
            self.assertEqual(api.get.call_args_list,[mock.call(G.DEP_URI),mock.call(rs_uri),mock.call(G.CORE_PODS_URI)])
            api.request.assert_not_called()
            stale=copy.deepcopy(expected);stale['generation']=280
            api.get.reset_mock()
            with self.assertRaises(G.Hold):G.core(api,stale)
            api.get.assert_not_called();api.request.assert_not_called()
            with mock.patch.object(G,'CURRENT_CORE_GENERATION',280):
                with self.assertRaises(G.Hold):G.core(api,stale)
            for fault in ('deployment_uid','deployment_spec','deployment_metadata','replicaset_uid','pod_spec','api_generation'):
                with self.subTest(core_preimage_fault=fault):
                    bad=copy.deepcopy(objects)
                    if fault=='deployment_uid':bad[G.DEP_URI]['metadata']['uid']=uuid98(813)
                    elif fault=='deployment_spec':bad[G.DEP_URI]['spec']['replicas']=2
                    elif fault=='deployment_metadata':bad[G.DEP_URI]['metadata']['annotations']['foreign']='changed'
                    elif fault=='replicaset_uid':bad[rs_uri]['metadata']['uid']=uuid98(814)
                    elif fault=='pod_spec':bad[G.CORE_PODS_URI]['items'][0]['spec']['nodeName']='foreign'
                    else:bad[G.DEP_URI]['status']['observedGeneration']=280
                    api.get.side_effect=lambda uri,bad=bad:copy.deepcopy(bad[uri])
                    with self.assertRaises(G.Hold):G.core(api,expected)
                    api.request.assert_not_called()
        uid=uuid98(800);new_digest='d'*64
        with mock.patch.multiple(G,JOB_UUID=uuid98(801),COMPANION_IMAGE_D=new_digest):
            job=G.job_manifest();self.assertEqual(job['metadata']['name'],'core-goose98-'+uuid98(801).replace('-',''))
            self.assertEqual((job['spec']['backoffLimit'],job['spec']['activeDeadlineSeconds']),(0,240))
            self.assertEqual(job['spec']['template']['spec']['containers'][0]['command'],['/bin/sh','-ceu','/app/goose up'])
            with tempfile.TemporaryDirectory()as folder,mock.patch.object(G,'CLAIM',Path(folder)/'NEW98-CLAIM'),mock.patch.object(G.time,'monotonic',return_value=100),mock.patch.object(G,'JOB_MANIFEST_SHA256',G.sha(G.wire(job))):
                api=mock.Mock();api.get.return_value=None
                api.request.return_value=(201,G.wire({'metadata':{'name':G.job_name(),'namespace':'dakasa','uid':uid}}),{'framing_valid':True})
                backend=types.SimpleNamespace(once=mock.Mock())
                self.assertEqual(G.create_once(api,backend,Path(folder),job,'a'*64,'b'*64,600,100),uid)
                self.assertEqual(api.request.call_args.args[:2],('POST',G.JOB_URI))
                self.assertEqual(api.request.call_count,1)
                self.assertEqual(json.loads(backend.once.call_args_list[0].args[1])['schema'],'goose98_companion_job_possible_v1')
        from test_catalog98 import declared_catalog98, M98_SQL
        fixture=declared_catalog98()
        H=load98('declared_before98_guard',ROLLOUT/'catalog98_helpers.py')
        before98=fixture['before']
        before98['legacy'].update(database='yggdrasil',readonly='on',latest_versions=[0]+[n for n in range(1,98)if n!=40],
                                  rows90=1,rows91=1,other_migrators_ddl=0,other_cic=0,ddl_locks=0)
        accepted={'index92_definition_sha256':G.sha(before98['supplement']['index92_definition'].encode()),
                  'complete_history_sha256':G.sha(before98['legacy']['complete_history_wire'].encode()),
                  'catalog97_sha256':G.sha(G.wire(H.projection97_98(before98)))}
        with mock.patch.multiple(G,COMPANION_SOURCE_Q=fixture['source'],CATALOG98_MODULE_CACHE=H),mock.patch.object(G,'reference',side_effect=lambda ref,*_:fixture['blobs'][ref['path']]),mock.patch.object(G,'create_once')as create:
            G.check_catalog98(before98,accepted,H.migration98_functions(M98_SQL),migration=fixture['carrier'],source_sql=M98_SQL)
            drift=copy.deepcopy(before98)
            drift['schema98']['columns'][0]['not_null']=not drift['schema98']['columns'][0]['not_null']
            with self.assertRaises(G.Hold):
                G.check_catalog98(drift,accepted,H.migration98_functions(M98_SQL),migration=fixture['carrier'],source_sql=M98_SQL)
            create.assert_not_called()
        before={'metadata':{'resourceVersion':'17','annotations':{'declared':'value'}},'spec':{'template':{'spec':{'containers':[{'image':'old'}]}}}}
        backend=types.SimpleNamespace(IMAGE_PREFIX='registry@sha256:',NEW_DIGEST=new_digest,once=mock.Mock(),wire=data98,loads=json.loads)
        with mock.patch.multiple(C,CORE_R='f'*40,GENERATION=281),mock.patch.object(C,'require_bound'),mock.patch.object(C.time,'monotonic',return_value=100):
            patch=C.build_patch(before,backend)
            self.assertEqual(len(patch),8);self.assertEqual(sum(row['op']=='test'for row in patch),5)
            self.assertEqual(patch[5]['value'],'registry@sha256:'+new_digest)
            api=mock.Mock();api.request.return_value=(200,b'{}',{})
            self.assertEqual(C.patch_once(api,backend,Path('/declared'),data98(patch),{},100),{})
            self.assertEqual(api.request.call_count,1);self.assertEqual(api.request.call_args.args[0],'PATCH')
            self.assertIn('CORE-IMAGE-R8-0764-D9B6-TO-',str(backend.once.call_args_list[0].args[0]))

    def test_post98_reads_catalog_only_with_distinct_saved_context(self):
        from test_catalog98 import legacy_c9_bytes
        H=load98('declared_pure98_for_post',ROLLOUT/'catalog98_helpers.py')
        H.catalog97_select=C.catalog97_select
        legacy=legacy_c9_bytes();legacyref={'path':'/declared/C9.sql','sha256':digest98(legacy)}
        refs={name:{'path':'/declared/'+name,'sha256':'a'*64}for name in ('94','95','96','97','98')}
        keys=('prior93_history_ref','prior94_history_ref','prior95_history_ref','prior96_history_ref','prior97_history_ref',
              'schema94_catalog_ref','schema95_catalog_ref','schema96_catalog_ref','schema97_catalog_ref','schema98_catalog_ref')
        cfg={key:{'path':'/declared/'+key,'sha256':'b'*64}for key in keys};cfg['legacy_catalog_sql_ref']=legacyref
        saved={'schema':C.INSTALLED_TIMEOUT_SCHEMA,**cfg,'acceptance_refs':{'Root_Goose'+name+'_acceptance':ref for name,ref in refs.items()}}
        catalog={'legacy':{'complete_history_wire':'[]'},'supplement':{'index92_valid':True,'index92_definition':'declared'}}
        V=types.SimpleNamespace(INSTALLED_TIMEOUT_SCHEMA=C.INSTALLED_TIMEOUT_SCHEMA,
             maintenance_inputs=mock.Mock(return_value=(saved,b'{}',{})),catalog98_select=H.catalog98_select,
             query=mock.Mock(return_value={'catalog':catalog,'rows92':1,'history_max_version':98,'index89_valid':True}),
             schema98_facts=mock.Mock(),catalog98_projection=mock.Mock(return_value={'declared':'projection'}))
        backend=types.SimpleNamespace(sha=digest98,wire=data98,once=mock.Mock())
        def read(_backend,ref):
            return legacy if ref==legacyref else b'[]'
        with mock.patch.multiple(P,ROOT94_REF=refs['94'],ROOT95_REF=refs['95'],ROOT96_REF=refs['96'],ROOT97_REF=refs['97'],ROOT98_REF=refs['98']),mock.patch.object(P,'ref',side_effect=read):
            observed=P.schema98(V,backend,None,Path('/declared'),cfg)
        self.assertEqual(observed['schema_version'],98)
        sql=V.query.call_args.args[-1]
        self.assertNotIn(P.BUSINESS_LEDGER_PROJECTION,sql)
        self.assertNotIn('capacity_resource_slots',sql)
        self.assertNotIn(C.INSTALLED_TIMEOUT_TARGET['job_id'],sql)
        self.assertIn('capacity_dispatch_installed_provision_timeout_dispositions',sql)
        V.schema98_facts.assert_called_once()
        self.assertFalse(observed['business_ledger_rows_queried'])


if __name__ == '__main__':
    unittest.main()
