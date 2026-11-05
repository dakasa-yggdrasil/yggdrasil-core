"""CI-only Goose95 contracts with immutable declared94 ancestry; no Native qualification."""
import ast
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[3]
SOURCE=ROOT/'ops/network-guardian/rollout/goose94_native_once.py'
MIGRATION=ROOT/'db/migrations/00094_failed_unwitnessed_expansion_cleanups.sql'
spec=importlib.util.spec_from_file_location('goose94_under_test',SOURCE)
G=importlib.util.module_from_spec(spec);spec.loader.exec_module(G)

SOURCE95=ROOT/'ops/network-guardian/rollout/goose95_native_once.py'
MIGRATION95=ROOT/'db/migrations/00095_failed_expansion_read_failure_continuation.sql'
spec95=importlib.util.spec_from_file_location('goose95_under_test',SOURCE95)
G95=importlib.util.module_from_spec(spec95);spec95.loader.exec_module(G95)



def declared_cleanup95():
    """CI-only authentic-shaped declared rows; no Native or human authority."""
    expiry='2026-11-05T08:00:10Z'; observed='2026-11-05T08:01:00Z'
    epoch={'generation':23,'fencing_token':44,'lease_owner':'11111111-1111-4111-8111-111111111111',
           'executor_id':'22222222-2222-4222-8222-222222222222','lease_expires_at':expiry}
    sdk={'schema':'aws_original_run_instances_return_v1','response_status':200,'adapter_source_commit':G95.A3_CREATOR,
         'grant_id':G95.A3_GRANT,'resource_id':G95.A3_RESOURCE,'resource_created_at':G95.A3_BIRTH}
    sdktext=json.dumps(sdk,separators=(',',':'))
    ad={'schema':'failed_unwitnessed_expansion_cleanup_v1','id':G95.CLEANUP_ID,'grant_id':G95.A3_GRANT,
        'child_grant_id':G95.CHILD_ID,'job_id':G95.A3_JOB,'run_id':G95.A3_RUN,'preregistration_id':G95.A3_PRE,
        'resource_id':G95.A3_RESOURCE,'resource_created_at':G95.A3_BIRTH,'slot':2,'survivor_count':1,
        'original_SDK_return_sha256':G95.sha(sdktext.encode())}
    admission={'id':G95.CLEANUP_ID,'grant_id':G95.A3_GRANT,'child_grant_id':G95.CHILD_ID,'original_record':ad}
    grant={'grant_id':G95.CHILD_ID,'state':'settled','compensation_of':'','request_sha256':'e'*64,
           'expected_resource_id':G95.A3_RESOURCE,'expected_resource_created_at':G95.A3_BIRTH,'expires_at':expiry}
    settlement={'outcome':'accepted','transport_completed':True,'action_id':'declared-paid-action',
                'auxiliary_inventory_complete':True,'auxiliary_resources':[{'kind':'aws_ebs_volume','id':'declared-volume'},{'kind':'aws_network_interface','id':'declared-eni'}],
                'grant_id':G95.CHILD_ID,'attempt_id':'55555555-5555-4555-8555-555555555555','request_sha256':'e'*64,
                'resource_id':G95.A3_RESOURCE,'resource_created_at':G95.A3_BIRTH}
    destroy={'schema':'aws_original_terminate_instances_return_v1','provider':'aws','adapter_source_commit':G95.A3_CREATOR,
             'response_status':200,'grant_id':G95.CHILD_ID,'attempt_id':settlement['attempt_id'],'action_id':settlement['action_id'],
             'request_sha256':'e'*64,'resource_id':G95.A3_RESOURCE,'resource_created_at':G95.A3_BIRTH,
             'called_at':'2026-11-05T07:59:50Z','returned_at':'2026-11-05T07:59:51Z','context_deadline':'2026-11-05T08:00:00Z','next_action_ids':[]}
    settlement['original_provider_destroy_return']=destroy
    receipt={'grant':grant,'resource_id':G95.A3_RESOURCE,'resource_created_at':G95.A3_BIRTH,
             **{k:v for k,v in settlement.items()if k!='original_provider_destroy_return'}}
    child={'id':G95.CHILD_ID,'state':'settled',G95.CHILD_COLUMN:G95.CLEANUP_ID,'grant_record':{'grant':grant,'settlement':settlement,'attempt_id':settlement['attempt_id']}}
    parent={'id':G95.A3_GRANT,'state':'settled',G95.CHILD_COLUMN:None,'grant_record':{'grant':{'state':'settled'},'settlement':{'original_provider_create_return':sdk}}}
    def event(seq,stage,evidence,at):
        record={'schema':'failed_unwitnessed_expansion_cleanup_event_v1',**epoch,'sequence':seq,'stage':stage,
                'run_id':G95.CLEANUP_RUN,'cleanup_id':G95.CLEANUP_ID,'child_grant_id':G95.CHILD_ID,'recorded_at':at,'evidence':evidence}
        return {'cleanup_id':G95.CLEANUP_ID,'child_grant_id':G95.CHILD_ID,'run_id':G95.CLEANUP_RUN,
                'sequence':seq,'stage':stage,'recorded_at':at,'original_record':record}
    read={'schema':'failed_unwitnessed_expansion_native_read_v1','kind':'absence','read_id':'33333333-3333-4333-8333-333333333333',
          'cleanup_id':G95.CLEANUP_ID,'child_grant_id':G95.CHILD_ID,'claim_sequence':1,
          'issued_at_core':'2026-11-05T08:00:00Z','original_deadline_core':'2026-11-05T08:00:05Z'}
    admission['admission_sha256']=G95.sha(G95.wire(ad));read['admission_sha256']=admission['admission_sha256']
    rawread=G95.wire(read);rawreceipt=G95.wire(receipt)
    observation={'server_absent':True,'server_absence_complete':True,'auxiliary_inventory_complete':True,
                 'hold_reasons':['aws_network_interface_still_present'],
                 'auxiliary_resources':[{'kind':'aws_ebs_volume','absent':True},{'kind':'aws_network_interface','absent':False}]}
    observer={'schema':'original_settled_retirement_absence_read_return_v1','observer_source_commit':'d8cbbf48873d24439216f98c30afe2669a525b54',
              'original_adapter_source_commit':G95.A3_CREATOR,'read_id':read['read_id'],'read_sha256':G95.sha(rawread),
              'original_receipt_sha256':G95.sha(rawreceipt),'observation':observation}
    good={'schema':'failed_unwitnessed_expansion_native_return_v1','status':'observed','pending':True,'complete':False,
          'call_failed':False,'original_context_failed':False,'read':read,'receipt':receipt,'observation':observation,
          'read_wire':G95.base64.b64encode(rawread).decode(),'receipt_wire':G95.base64.b64encode(rawreceipt).decode(),
          'original_observer_return':G95.base64.b64encode(G95.wire(observer)).decode(),'observer_source_commit':observer['observer_source_commit']}
    newread={**read,'read_id':'44444444-4444-4444-8444-444444444444','issued_at_core':'2026-11-05T08:00:04Z','original_deadline_core':'2026-11-05T08:00:09Z'}
    failed={'schema':'failed_unwitnessed_expansion_native_return_v1','status':'','pending':False,'complete':False,
            'call_failed':True,'original_context_failed':True,'read':newread,'receipt':receipt,
            'read_wire':G95.base64.b64encode(G95.wire(newread)).decode(),'receipt_wire':good['receipt_wire'],
            'started_at_core':'2026-11-05T08:00:04Z','returned_at_core':'2026-11-05T08:00:09Z'}
    events=[event(1,'claimed',{},'2026-11-05T07:59:40Z'),event(133,'pending_absence',good,'2026-11-05T08:00:03Z'),
            event(134,'absence_prepared',newread,'2026-11-05T08:00:04Z'),event(135,'absence_returned',failed,'2026-11-05T08:00:09Z')]
    for row,pin in [(admission,'admission_sha256')]+[(e,'event_sha256') for e in events]:
        raw=G95.wire(row['original_record']);row['wire_hex']=raw.hex();row[pin]=G95.sha(raw)
    v={'observed_at_pg':observed,'admissions':[admission],'events':events,'intent':{},'parent':parent,'parent_sdk_pgtext':sdktext,
       'child':child,'workflow_run':{'id':G95.CLEANUP_RUN,'status':'failed','finished_at':'2026-11-05T08:00:09Z'},
       'dispatch':[{'run_id':G95.CLEANUP_RUN,'state':'returned','return_status':'failed','returned_at':'2026-11-05T08:00:09Z','finalization_ack_at':'2026-11-05T08:00:09Z'}]}
    c={'cleanup_id':G95.CLEANUP_ID,'child_grant_id':G95.CHILD_ID,'owning_run_id':G95.CLEANUP_RUN,'latest_sequence':135,
       'lease_expires_at':expiry,'provider_lanes':None}
    return v,c


def declared_a3():
    before='2026-11-05T00:21:00Z'; after='2026-11-05T01:00:00Z'
    k={'workflow_id':'11111111-1111-4111-8111-111111111111','lease_owner':'22222222-2222-4222-8222-222222222222',
       'executor_id':'33333333-3333-4333-8333-333333333333','lease_expires_at':before,'policy_checksum':'a'*64}
    i={'generation':22,'fencing_token':43,'phase':'preparing','lease_owner':k['lease_owner'],'lease_executor_id':k['executor_id'],
       'lease_expires_at':before,'baseline_snapshot':{'units':1},'assessment':{'snapshot':{'units':1}},'decision':{'units':2},
       'policy_id':G.A3_POLICY,'policy_checksum':k['policy_checksum']}
    run={'id':G.A3_RUN,'status':'failed','finished_at':before,'result':{'steps':[{'status':'failed','metadata':{'original_guest_refusal_predicate':'original-guest-step-25'}}]}}
    grant={'state':'settled','grant_id':G.A3_GRANT,'capability':'ensure_ec2_instance','slot':2,'request_sha256':'b'*64,
           'integration_instance_id':'declared-instance','scope_checksum':'c'*64,'profile_name':'declared-profile','binding_name':'declared-binding','expires_at':before}
    sdk={'schema':'aws_original_run_instances_return_v1','provider':'aws','adapter_source_commit':G.A3_CREATOR,
         'grant_id':G.A3_GRANT,'attempt_id':G.A3_ATTEMPT,'request_sha256':grant['request_sha256'],'resource_id':G.A3_RESOURCE,
         'resource_created_at':G.A3_BIRTH,'action_id':G.A3_ACTION,'next_action_ids':[], 'called_at':'2026-11-05T00:20:13Z',
         'returned_at':'2026-11-05T00:20:15Z','context_deadline':before,'response_status':200,'response_body_sha256':'d'*64,'response_bytes':100}
    record={'grant':grant,'settlement':{'grant_id':G.A3_GRANT,'attempt_id':G.A3_ATTEMPT,'outcome':'accepted','transport_completed':True,
            'request_sha256':grant['request_sha256'],'action_id':G.A3_ACTION,'resource_id':G.A3_RESOURCE,'resource_created_at':G.A3_BIRTH,'original_provider_create_return':sdk,'observed_at':sdk['returned_at']},
            'binding':{'ensure_capability':'ensure_ec2_instance','original_provider_source_commit':G.A3_CREATOR,'name':'declared-binding',**{x:grant[x] for x in ('integration_instance_id','scope_checksum','profile_name')}},
            'policy_id':G.A3_POLICY,'policy_checksum':k['policy_checksum'],'workflow_id':k['workflow_id'],'generation':22,'fencing_token':43,
            'lease_owner':k['lease_owner'],'executor_id':k['executor_id'],'attempt_id':G.A3_ATTEMPT}
    g={'id':G.A3_GRANT,'state':'settled','namespace':'dakasa-production','environment':'production','domain':'notify',
       'dimension':'original_notify_aws_vm_members','grant_record':record,
       **{x:None for x in ('original_disposition_id','failed_original_disposition_id','native_denied_disposition_id','enrolled_failed_disposition_id')}}
    pre={'preregistration_id':G.A3_PRE,'original_create_grant_id':G.A3_GRANT,'original_create_request_sha256':grant['request_sha256'],
         'slot':2,'policy_id':G.A3_POLICY,'policy_checksum':k['policy_checksum'],'workflow_id':k['workflow_id'],'generation':22,'fence':43,
         'lease_owner':k['lease_owner'],'executor_id':k['executor_id'],'binding_name':'declared-s2','original_deadline':before,'reserved_at':'2026-11-05T00:20:13Z'}
    raw=G.wire(pre)
    grb={'mutation_binding_name':grant['binding_name'],'members':[{'slot':1,'name':'declared-s1'},{'slot':2,'name':'declared-s2'}]}
    enrollment={'preregistration_id':'declared-s1','enrollment_record':{'statement':{'tuple':{'resource_id':G.S1_RESOURCE,'resource_created_at':G.S1_BIRTH}}}}
    survivor={'slot':1,'resource_id':G.S1_RESOURCE,'slot_record':{'resource_created_at':G.S1_BIRTH,'resource_id':G.S1_RESOURCE,'tombstone':False},
              **{x:grant[x] for x in ('integration_instance_id','scope_checksum','profile_name')},
              'enrollments':[{'enrollment':enrollment,'witness':{'preregistration_id':'declared-s1'},'installation':{'preregistration_id':'declared-s1'}}]}
    v={'observed_at_pg':after,'intent_pgtext':G.wire(i).decode(),'run_pgtext':G.wire(run).decode(),'grant_pgtext':G.wire(g).decode(),
       'dispatch':[{'id':G.A3_JOB,'run_id':G.A3_RUN,'state':'returned','return_status':'failed','returned_at':before,
                    'finalization_ack_at':before,'lease_expires_at':before,'envelope':{'workflow':{'id':k['workflow_id']}}}],
       'preregistration':{'id':G.A3_PRE,'create_grant_id':G.A3_GRANT,'original_wire':'\\x'+raw.hex(),'binding_wire':'\\x'+G.wire(grb).hex(),'preregistration_record':pre,'original_deadline':before},
       'active_policy':{'id':G.A3_POLICY,'kind':'capacity_policy','active':True,'checksum':k['policy_checksum']},'survivors':[survivor],
       **{x:[] for x in ('target_witnesses','target_enrollments','target_installations','target_retirements','factory_bindings','compensations','cleanup_admissions')}}
    for field,pin in (('intent_pgtext','intent_sha256'),('run_pgtext','run_sha256'),('grant_pgtext','grant_sha256')):k[pin]=G.sha(v[field].encode())
    k['preregistration_sha256']=G.sha(raw)
    return v,{'case':k}


class Goose95OnceTests(unittest.TestCase):
    def test_forced_unbound_refuses_before_io(self):
        for flag in (False,True):
            with mock.patch.multiple(G,SOURCE_BOUND=flag,M94=None,COMPANION_SOURCE_Q=None,COMPANION_IMAGE_D=None),mock.patch.object(G,'private_read') as read,mock.patch.object(G,'reference') as ref:
                with self.assertRaises(G.Hold):G.main()
                read.assert_not_called();ref.assert_not_called()

        for flag in (False,True):
            with mock.patch.multiple(G95,SOURCE_BOUND=flag,COMPANION_SOURCE_Q=None,COMPANION_IMAGE_D=None),mock.patch.object(G95,'private_read') as read:
                with self.assertRaises(G95.Hold):G95.main()
                read.assert_not_called()

    def test_goose95_job_scope_and_distinct_claim(self):
        with mock.patch.multiple(G,JOB_UUID='a78740e4-6263-43dc-a0b2-56eb29368119',COMPANION_IMAGE_D='1'*64):
            job=G.job_manifest();p=job['spec']['template']['spec'];c=p['containers'][0]
            self.assertEqual(job['metadata']['name'],'core-goose94-a78740e4626343dca0b256eb29368119')
            self.assertEqual((job['spec']['backoffLimit'],job['spec']['activeDeadlineSeconds'],job['spec']['parallelism']),(0,240,1))
            self.assertEqual(c['command'],['/bin/sh','-ceu','/app/goose up'])
            self.assertEqual(p['restartPolicy'],'Never');self.assertFalse(p['automountServiceAccountToken'])
            self.assertEqual(c['image'],G.PREFIX+'1'*64);self.assertNotIn('volumeMounts',c)
            self.assertEqual(str(G.ROOT),'/var/lib/dakasa-core-rollout/goose94-failed-unwitnessed-expansion')
            self.assertNotIn('goose93',str(G.CLAIM));self.assertNotEqual(job['metadata']['labels']['app'],'yggdrasil')

        with mock.patch.multiple(G95,JOB_UUID='a78740e4-6263-43dc-a0b2-56eb29368119',COMPANION_IMAGE_D='1'*64):
            job95=G95.job_manifest()
            self.assertEqual(job95['metadata']['name'],'core-goose95-a78740e4626343dca0b256eb29368119')
            self.assertEqual(job95['metadata']['labels']['app'],'yggdrasil-goose95-companion')
            self.assertNotEqual(G95.ROOT,G.ROOT);self.assertNotEqual(G95.CLAIM,G.CLAIM)

    def test_shipped_m95_single_guard_and_95_only_job_logs(self):
        raw=MIGRATION.read_bytes()
        self.assertEqual(G.M94,G.sha(raw))  # Frozen Source identity only; main remains unbound.
        rows=G.source_functions(raw.decode());self.assertEqual(set(rows),set(G.M94_FUNCTIONS))
        self.assertEqual(len(rows),6)  # Method ID retained; final approved Source has six functions.
        for name,row in rows.items():
            self.assertTrue(row['body']);self.assertEqual(row['result'],'boolean' if name=='failed_expansion_absence_read_valid' else 'trigger')
        self.assertEqual(rows['failed_expansion_absence_read_valid']['volatility'],'s')
        for bad in (raw.decode().replace('CREATE FUNCTION','CREATE OR REPLACE FUNCTION',1),raw.decode().replace('guard_failed_unwitnessed_expansion_cleanup()','foreign_cleanup()',1)):
            with self.assertRaises(G.Hold):G.source_functions(bad)
        tree=ast.parse(SOURCE.read_text())
        posts=[n for n in ast.walk(tree) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and n.func.attr=='request' and n.args and isinstance(n.args[0],ast.Constant) and n.args[0].value=='POST']
        self.assertEqual(len(posts),1)

        rows95=G95.source_functions(MIGRATION95.read_text())
        self.assertEqual(set(rows95),{'guard_failed_unwitnessed_expansion_cleanup_event'})
        for bad in (MIGRATION95.read_text().replace('CREATE OR REPLACE FUNCTION','CREATE FUNCTION',1),
                    MIGRATION95.read_text().replace('guard_failed_unwitnessed_expansion_cleanup_event()','foreign_guard()',1)):
            with mock.patch.object(G95,'M95',G95.sha(bad.encode())),self.assertRaises(G95.Hold):G95.source_functions(bad)

        # Real95 emits only95 because applied94 is skipped. Exercise the full
        # owned-Job/pod/log observer with declared completed metadata; no Nativecall.
        uid='11111111-1111-4111-8111-111111111111';poduid='22222222-2222-4222-8222-222222222222'
        log95=b'2026-11-05T00:00:00Z OK 00095_failed_expansion_read_failure_continuation.sql\ngoose: successfully migrated database to version: 95\n'
        log94=b'2026-11-05T00:00:00Z OK 00094_failed_unwitnessed_expansion_cleanups.sql\ngoose: successfully migrated database to version: 94\n'
        with mock.patch.multiple(G95,JOB_UUID='a78740e4-6263-43dc-a0b2-56eb29368119',COMPANION_IMAGE_D='1'*64),mock.patch.object(G95.time,'monotonic',return_value=100):
            job=G95.job_manifest();name=G95.job_name()
            current={'metadata':{'uid':uid,'name':name,'namespace':'dakasa'},'status':{'conditions':[{'type':'Complete','status':'True'}],'succeeded':1}}
            pod={'metadata':{'name':'declared-goose95-pod','uid':poduid,'ownerReferences':[{'kind':'Job','controller':True,'uid':uid,'name':name}]},
                 'status':{'phase':'Succeeded','containerStatuses':[{'name':'migrator','restartCount':0,'imageID':'registry@sha256:'+'1'*64,'state':{'terminated':{'exitCode':0}}}]}}
            for logs,accepted in ((log95,True),(log94,False)):
                api=mock.Mock();api.get.side_effect=[copy.deepcopy(current),{'items':[copy.deepcopy(pod)]}]
                api.request.return_value=(200,logs,{'framing_valid':True})
                with mock.patch.object(G95,'job_shape') as shape:
                    if accepted:self.assertEqual(G95.observe_owned_job(api,job,types.SimpleNamespace(),uid,1000),(uid,poduid,G95.sha(logs)))
                    else:
                        with self.assertRaises(G95.Hold) as held:G95.observe_owned_job(api,job,types.SimpleNamespace(),uid,1000)
                        self.assertEqual(str(held.exception),'ORIGINAL_GOOSE95_LOG_COMPLETE_EXIT0')
                    self.assertEqual(shape.call_count,2)
                api.request.assert_called_once_with('GET','/api/v1/namespaces/dakasa/pods/declared-goose95-pod/log?container=migrator&timestamps=true')

    def test_known_cleanup_paid_sdk_raw_timeout_and_closed_ack(self):
        v,c=declared_a3();C=types.SimpleNamespace(loads=G.loads)
        self.assertNotEqual(v['preregistration']['preregistration_record']['binding_name'],G.loads(v['grant_pgtext'])['grant_record']['binding']['name'])
        self.assertTrue(G.validate_a3(v,c,C))
        for fault in ('missing_ack','unknown_job','witness','enrollment','installation','retirement','wrong_source','uncertain','sdk_not200','unexpired','second_survivor','wrong_wire','metadata_steps_only','sdk_next_action','settlement_next_action','destroy_receipt','sdk_before_reservation','sdk_after_grant_expiry','wrong_binding','missing_member','duplicate_member','foreign_member','wrong_mutation_join','wrong_prereg_binding'):
            bad=copy.deepcopy(v);case=copy.deepcopy(c)
            if fault in ('missing_member','duplicate_member','foreign_member','wrong_mutation_join','wrong_prereg_binding'):
                pre=bad['preregistration'];stored=G.loads(bytes.fromhex(pre['binding_wire'][2:]))
                if fault=='missing_member':stored['members']=[m for m in stored['members']if m['slot']!=2]
                elif fault=='duplicate_member':stored['members'].append(copy.deepcopy(stored['members'][1]))
                elif fault=='foreign_member':stored['members'][1]['name']='declared-foreign-member'
                elif fault=='wrong_mutation_join':stored['mutation_binding_name']='declared-foreign-profile'
                else:pre['preregistration_record']['binding_name']='declared-foreign-member'
                pre['binding_wire']='\\x' + G.wire(stored).hex()
                resealed=G.wire(pre['preregistration_record']);pre['original_wire']='\\x'+resealed.hex()
                case['case']['preregistration_sha256']=G.sha(resealed)
            elif fault=='missing_ack':bad['dispatch'][0]['finalization_ack_at']=None
            elif fault=='unknown_job':bad['dispatch'][0]['state']='unknown'
            elif fault in ('witness','enrollment','installation','retirement'):bad['target_'+{'witness':'witnesses','enrollment':'enrollments','installation':'installations','retirement':'retirements'}[fault]]=[{}]
            elif fault=='unexpired':bad['observed_at_pg']='2026-11-05T00:20:59Z'
            elif fault=='second_survivor':bad['survivors'].append(copy.deepcopy(bad['survivors'][0]))
            elif fault=='wrong_wire':bad['preregistration']['original_wire']+='20'
            elif fault=='metadata_steps_only':
                r=G.loads(bad['run_pgtext']);r['result']['metadata']={'steps':r['result'].pop('steps')};bad['run_pgtext']=G.wire(r).decode();case['case']['run_sha256']=G.sha(bad['run_pgtext'].encode())
            else:
                g=G.loads(bad['grant_pgtext']);settlement=g['grant_record']['settlement']
                if fault=='wrong_source':settlement['original_provider_create_return']['adapter_source_commit']='f'*40
                elif fault=='uncertain':settlement['outcome']='uncertain'
                elif fault=='sdk_not200':settlement['original_provider_create_return']['response_status']=202
                elif fault=='sdk_next_action':settlement['original_provider_create_return']['next_action_ids']=['unexpected']
                elif fault=='settlement_next_action':settlement['next_action_ids']=['unexpected']
                elif fault=='destroy_receipt':settlement['original_provider_destroy_return']={'unexpected':True}
                elif fault=='sdk_before_reservation':settlement['original_provider_create_return']['called_at']='2026-11-05T00:20:12Z'
                elif fault=='sdk_after_grant_expiry':settlement['original_provider_create_return']['context_deadline']='2026-11-05T00:21:01Z'
                else:g['grant_record']['binding']['scope_checksum']='f'*64
                bad['grant_pgtext']=G.wire(g).decode();case['case']['grant_sha256']=G.sha(bad['grant_pgtext'].encode())
            with self.subTest(fault=fault),self.assertRaises(G.Hold) as held:G.validate_a3(bad,case,C)
            if fault in ('missing_member','duplicate_member','foreign_member','wrong_mutation_join','wrong_prereg_binding'):
                self.assertEqual(str(held.exception),'ORIGINAL_GRB_PROFILE_MUTATION_JOIN'if fault=='wrong_mutation_join'else'ORIGINAL_GRB_UNIQUE_SLOT_MEMBER')

        declared,case95=declared_cleanup95();self.assertTrue(G95.validate_cleanup95(declared,case95))
        for fault in ('missing_ACK','live_lease','foreign_child','raw_as_success','failed_observer','foreign_receipt','wrong_H7_hash','wrong_SDK_status','read_before_deadline','missing_destroy_SDK','destroy_schema','destroy_source','destroy_status','destroy_grant','destroy_attempt','destroy_action','destroy_request','destroy_resource','destroy_birth','destroy_clock'):
            bad=copy.deepcopy(declared)
            if fault.startswith('destroy_') or fault=='missing_destroy_SDK':
                settlement=bad['child']['grant_record']['settlement'];destroy=settlement['original_provider_destroy_return']
                if fault=='missing_destroy_SDK':settlement.pop('original_provider_destroy_return')
                elif fault=='destroy_schema':destroy['schema']='foreign'
                elif fault=='destroy_source':destroy['adapter_source_commit']='f'*40
                elif fault=='destroy_status':destroy['response_status']=202
                elif fault=='destroy_grant':destroy['grant_id']='foreign'
                elif fault=='destroy_attempt':destroy['attempt_id']='foreign'
                elif fault=='destroy_action':destroy['action_id']='foreign'
                elif fault=='destroy_request':destroy['request_sha256']='f'*64
                elif fault=='destroy_resource':destroy['resource_id']='foreign'
                elif fault=='destroy_birth':destroy['resource_created_at']='2026-11-05T00:20:15Z'
                else:destroy['returned_at']=destroy['context_deadline']
            elif fault=='missing_ACK':bad['dispatch'][0]['finalization_ack_at']=None
            elif fault=='live_lease':bad['observed_at_pg']='2026-11-05T08:00:09Z'
            elif fault=='foreign_child':bad['child'][G95.CHILD_COLUMN]='foreign'
            elif fault=='raw_as_success':bad['events'][-1]['original_record']['evidence']['complete']=True
            elif fault=='failed_observer':bad['events'][-1]['original_record']['evidence']['observer_source_commit']='forbidden'
            elif fault=='foreign_receipt':
                good=bad['events'][1]['original_record']['evidence'];good['receipt']=copy.deepcopy(good['receipt'])
                good['receipt']['grant']['grant_id']='foreign'
                wire=G95.wire(good['receipt']);good['receipt_wire']=G95.base64.b64encode(wire).decode()
                observer=G95.loads(G95.base64.b64decode(good['original_observer_return']));observer['original_receipt_sha256']=G95.sha(wire)
                good['original_observer_return']=G95.base64.b64encode(G95.wire(observer)).decode()
                failed=bad['events'][-1]['original_record']['evidence'];failed['receipt']=copy.deepcopy(good['receipt']);failed['receipt_wire']=good['receipt_wire']
            elif fault=='wrong_H7_hash':bad['events'][1]['original_record']['evidence']['read_wire']=G95.base64.b64encode(b'{}').decode()
            elif fault=='wrong_SDK_status':
                sdk=G95.loads(bad['parent_sdk_pgtext']);sdk['response_status']=202;bad['parent_sdk_pgtext']=json.dumps(sdk,separators=(',',':'))
                bad['parent']['grant_record']['settlement']['original_provider_create_return']=sdk
                bad['admissions'][0]['original_record']['original_SDK_return_sha256']=G95.sha(bad['parent_sdk_pgtext'].encode())
            else:bad['events'][-1]['original_record']['evidence']['returned_at_core']='2026-11-05T08:00:08Z'
            for row,pin in [(bad['admissions'][0],'admission_sha256')]+[(e,'event_sha256')for e in bad['events']]:
                raw=G95.wire(row['original_record']);row['wire_hex']=raw.hex();row[pin]=G95.sha(raw)
            with self.subTest(case95_fault=fault),self.assertRaises(G95.Hold):G95.validate_cleanup95(bad,case95)

    def test_historical_m94_sdk_and_child_binding_preserved(self):
        old,c=declared_a3();new=copy.deepcopy(old);g=G.loads(new['grant_pgtext']);g[G.CHILD_COLUMN]=None;new['grant_pgtext']=G.wire(g).decode()
        new['observed_at_pg']='2026-11-05T01:01:00Z'
        G.validate_a3(new,c,types.SimpleNamespace(loads=G.loads),after=True);G.a3_preserved(new,old,after=True)
        for fault in ('nonnull_child','old_column','sdk_bytes','old_run'):
            bad=copy.deepcopy(new);g=G.loads(bad['grant_pgtext'])
            if fault=='nonnull_child':g[G.CHILD_COLUMN]='declared-child'
            elif fault=='old_column':g['state']='confirmed'
            elif fault=='sdk_bytes':g['grant_record']['settlement']['original_provider_create_return']['response_bytes']+=1
            else:bad['run_pgtext']+=' '
            bad['grant_pgtext']=G.wire(g).decode()
            with self.subTest(fault=fault),self.assertRaises(G.Hold):G.a3_preserved(bad,old,after=True)
        nochild=copy.deepcopy(old)
        with self.assertRaises(G.Hold):G.a3_preserved(nochild,old,after=True)
        # Same JSON value but changed raw record whitespace cannot masquerade as preserved original bytes.
        changed=copy.deepcopy(new);changed['grant_pgtext']=changed['grant_pgtext'].replace('"grant_record":{','"grant_record": { ')
        with self.assertRaises(G.Hold):G.a3_preserved(changed,old,after=True)

    def test_prior94_catalog_and_sole95_event_guard_delta(self):
        legacy="BEGIN READ ONLY; SET LOCAL statement_timeout='8000ms'; SET LOCAL lock_timeout='1000ms';\nSELECT jsonb_build_object('rows90',1);\nCOMMIT;"
        V=types.SimpleNamespace(workflow_busy_logical_index92_sql=lambda:'FALSE')
        with mock.patch.object(G,'LEGACY_CATALOG_SHA',G.sha(legacy.encode())):sql=G.catalog94_sql(legacy,V)
        self.assertIn("to_regclass('public.capacity_failed_unwitnessed_expansion_cleanups')",sql)
        self.assertIn("statement_timeout='8000ms'",sql);self.assertIn("lock_timeout='1000ms'",sql)
        for key in ('catalog90','catalog91','functions93','old_records','old_grants','ledgers94'):self.assertIn(key,sql if key not in ('catalog90','catalog91') else SOURCE.read_text())
        history=[{'id':n+1,'version_id':v,'is_applied':True} for n,v in enumerate([0]+[x for x in range(1,94)if x!=40])]
        old={'legacy':{'database':'yggdrasil','readonly':'on','latest_versions':[r['version_id'] for r in history],'rows90':1,'rows91':1,'other_migrators_ddl':0,'other_cic':0,'ddl_locks':0,'complete_history_wire':json.dumps(history),'catalog90':{},'catalog91':{}},
             'supplement':{'columns90_91':[],'functions93':[],'index92_valid':True,'index92_definition':'declared-index','old_records':{'declared':'sha'}},
             'schema94':{'tables':[{'name':'public.capacity_mutation_grants'},{'name':'public.capacity_intents'}],'columns':[],'constraints':[],'indexes':[],'triggers':[],'functions':[]},'ledgers94':[],'old_grants':{'rows':1,'sha256':'a'*64,'new_nonnull':0}}
        accepted={'complete_history_sha256':G.sha(old['legacy']['complete_history_wire'].encode()),'schema93_catalog_sha256':G.sha(G.wire(G.catalog_projection(old))),'index92_definition_sha256':G.sha(b'declared-index')}
        G.check_catalog(old,accepted,{})
        for fault in ('history','old_catalog','index','preexisting94'):
            bad=copy.deepcopy(old)
            if fault=='history':bad['legacy']['complete_history_wire']+=' '
            elif fault=='old_catalog':bad['legacy']['catalog90']['foreign']=True
            elif fault=='index':bad['supplement']['index92_valid']=False
            else:bad['schema94']['functions']=[{'name':'foreign'}]
            with self.subTest(fault=fault),self.assertRaises(G.Hold):G.check_catalog(bad,accepted,{})
        # Exercise the actual post-DDL comparator, including the child-only index delta.
        source=MIGRATION.read_text();funcs=G.source_functions(source)
        grant_table={'name':'public.capacity_mutation_grants'}
        old['schema94']['tables']=[grant_table,{'name':'public.capacity_intents','kind':'r','persistence':'p'}]
        old['schema94']['columns']=[{'table':'public.capacity_intents','name':'intent','type':'jsonb','not_null':True,'default':None}]
        old['schema94']['triggers']=[{'name':'declared_old_intent_trigger','table':'public.capacity_intents','function':'declared_old_intent_guard()','enabled':'O','definition':'declared original trigger'}]
        old['schema94']['indexes']=[{'table':'public.capacity_mutation_grants','name':'public.capacity_mutation_grants_open_slot_idx','valid':True,'ready':True,'live':True,'unique':True,'definition':'CREATE UNIQUE INDEX declared WHERE (state IS NOT NULL)'}]
        state_names=G.re.findall(r'ALTER TABLE\s+public\.capacity_mutation_grants\s+ADD CONSTRAINT\s+([a-z0-9_]+)\s+CHECK\s*\(',source.split('-- +goose Down')[0])
        self.assertEqual(len(state_names),1)
        # PostgreSQL deparse of the unchanged M58 eight-state Source predicate.
        states=('issued','redeemed','settled','confirmed','rejected','expired','compensating','compensated')
        old_predicate="CHECK ((state = ANY (ARRAY["+", ".join("'"+x+"'::text" for x in states)+"])))"
        old_state={'table':'public.capacity_mutation_grants','name':state_names[0],'type':'c','validated':True,'deferrable':False,'deferred':False,'definition':old_predicate}
        old_intent_constraint={'table':'public.capacity_intents','name':'capacity_intents_pkey','type':'p','validated':True,'definition':'PRIMARY KEY (namespace, environment, domain, dimension)'}
        old['schema94']['constraints']=[old_state,old_intent_constraint]
        old['schema94']['indexes'].append({'table':'public.capacity_intents','name':'public.capacity_intents_pkey','valid':True,'ready':True,'live':True,'unique':True,'definition':'declared original intent index'})
        after=copy.deepcopy(old);after['legacy']['latest_versions'].append(94)
        after['legacy']['complete_history_wire']=json.dumps(history+[{'id':len(history)+1,'version_id':94,'is_applied':True}])
        after['schema94']['tables'] += [{'name':name} for name in sorted(G.NEW_TABLES)]
        after['schema94']['columns'].append({'table':'public.capacity_mutation_grants','name':G.CHILD_COLUMN,'number':20,'type':'uuid','not_null':False,'default':None,'identity':'','generated':''})
        names=G.re.findall(r'ALTER TABLE\s+public\.capacity_mutation_grants\s+ADD CONSTRAINT\s+([a-z0-9_]+)\s+FOREIGN KEY',source.split('-- +goose Down')[0])
        self.assertEqual(len(names),1)
        after['schema94']['constraints']=[old_intent_constraint,{'table':'public.capacity_mutation_grants','name':names[0],'type':'f','validated':True,'definition':'FOREIGN KEY (failed_unwitnessed_expansion_cleanup_id, id) REFERENCES capacity_failed_unwitnessed_expansion_cleanups(id, child_grant_id)'}]
        state=copy.deepcopy(old_state);state['definition']=old_predicate.replace("])))",", 'cleanup_closed'::text])))")
        after['schema94']['constraints'].insert(0,state)
        after['schema94']['indexes'][0]['definition']+=' AND (failed_unwitnessed_expansion_cleanup_id IS NULL)'
        triggers=G.re.findall(r'CREATE TRIGGER ([a-z0-9_]+) .*? ON public\.([a-z0-9_]+).*? EXECUTE FUNCTION public\.([a-z0-9_]+)\(\);',source.split('-- +goose Down')[0])
        after['schema94']['triggers'] += [{'name':name,'table':'public.'+table,'function':function+'()','enabled':'O'}for name,table,function in triggers]
        after['schema94']['functions']=[{'name':name,'qualified_name':'public.'+name,**row,'definition':'declared full definition'}for name,row in funcs.items()]
        intent_guard=next(r for r in after['schema94']['triggers'] if r['function']=='guard_failed_unwitnessed_expansion_cleanup_intent()')
        intent_guard['definition']='CREATE TRIGGER '+intent_guard['name']+' BEFORE UPDATE ON public.capacity_intents FOR EACH ROW EXECUTE FUNCTION guard_failed_unwitnessed_expansion_cleanup_intent()'
        after['ledgers94']=[{'name':name,'rows':0}for name in sorted(G.NEW_TABLES)]
        G.check_catalog(after,accepted,funcs,old=old,migration=source)
        # PostgreSQL may qualify a visible function. Only this exact public.
        # visibility token varies; table, timing, row and identity remain exact.
        qualified=copy.deepcopy(after)
        for row in qualified['schema94']['triggers']:
            if row['name'] != 'declared_old_intent_trigger':row['function']='public.'+row['function']
            if row.get('definition','').startswith('CREATE TRIGGER ') and row['name'] != 'declared_old_intent_trigger':
                row['definition']=row['definition'].replace('EXECUTE FUNCTION ','EXECUTE FUNCTION public.',1)
        G.check_catalog(qualified,accepted,funcs,old=old,migration=source)
        for fault in ('old_sdk','old_catalog','old_history','nonnull_child','ledger_not_empty','function_body','old_index','extra_trigger','extra_state_OR','extra_state','invalid_fk','trigger_function','function_qualified_name','unqualified_table','intent_properties','intent_columns','intent_constraints','intent_indexes','intent_old_trigger','intent_guard_function','intent_guard_timing','extra_intent_trigger'):
            bad=copy.deepcopy(after)
            if fault=='old_sdk':bad['old_grants']['sha256']='b'*64
            elif fault=='old_catalog':bad['legacy']['catalog91']['foreign']=True
            elif fault=='old_history':
                h=G.loads(bad['legacy']['complete_history_wire']);h[0]['is_applied']=False;bad['legacy']['complete_history_wire']=json.dumps(h)
            elif fault=='nonnull_child':bad['old_grants']['new_nonnull']=1
            elif fault=='ledger_not_empty':bad['ledgers94'][0]['rows']=1
            elif fault=='function_body':bad['schema94']['functions'][0]['body']+=' '
            elif fault=='old_index':bad['schema94']['indexes'][0]['definition']='foreign'
            elif fault=='extra_state_OR':bad['schema94']['constraints'][0]['definition']+=' OR true'
            elif fault=='extra_state':bad['schema94']['constraints'][0]['definition']=bad['schema94']['constraints'][0]['definition'].replace(", 'cleanup_closed'::text",", 'cleanup_closed'::text, 'invented'::text")
            elif fault=='invalid_fk':next(r for r in bad['schema94']['constraints'] if r['type']=='f')['definition']='FOREIGN KEY (failed_unwitnessed_expansion_cleanup_id, id) REFERENCES capacity_failed_unwitnessed_expansion_cleanups(id, grant_id)'
            elif fault=='trigger_function':bad['schema94']['triggers'][0]['function']='foreign()'
            elif fault=='function_qualified_name':bad['schema94']['functions'][0]['qualified_name']='foreign.'+bad['schema94']['functions'][0]['name']
            elif fault=='unqualified_table':bad['schema94']['tables'][0]['name']='capacity_mutation_grants'
            elif fault=='intent_properties':next(r for r in bad['schema94']['tables'] if r['name']=='public.capacity_intents')['kind']='v'
            elif fault=='intent_columns':next(r for r in bad['schema94']['columns'] if r['table']=='public.capacity_intents')['type']='text'
            elif fault=='intent_constraints':next(r for r in bad['schema94']['constraints'] if r['table']=='public.capacity_intents')['definition']='foreign'
            elif fault=='intent_indexes':next(r for r in bad['schema94']['indexes'] if r['table']=='public.capacity_intents')['definition']='foreign'
            elif fault=='intent_old_trigger':next(r for r in bad['schema94']['triggers'] if r['name']=='declared_old_intent_trigger')['function']='foreign()'
            elif fault=='intent_guard_function':next(r for r in bad['schema94']['triggers'] if r['function']=='guard_failed_unwitnessed_expansion_cleanup_intent()')['function']='foreign()'
            elif fault=='intent_guard_timing':next(r for r in bad['schema94']['triggers'] if r['function']=='guard_failed_unwitnessed_expansion_cleanup_intent()')['definition']='CREATE TRIGGER foreign AFTER UPDATE ON public.capacity_intents FOR EACH ROW EXECUTE FUNCTION guard_failed_unwitnessed_expansion_cleanup_intent()'
            elif fault=='extra_intent_trigger':bad['schema94']['triggers'].append({'name':'extra_intent','table':'public.capacity_intents','function':'foreign()','enabled':'O'})
            else:bad['schema94']['triggers'].append({'name':'foreign','table':sorted(G.NEW_TABLES)[0],'function':'foreign()','enabled':'O'})
            with self.subTest(after_fault=fault),self.assertRaises(G.Hold):G.check_catalog(bad,accepted,funcs,old=old,migration=source)

        old95=copy.deepcopy(after)
        for row in old95['schema94']['functions']:
            row['definition']='declared unchanged function header\n'+row['body']+'\ndeclared unchanged tail'
        accepted95={'complete_history_sha256':G95.sha(old95['legacy']['complete_history_wire'].encode()),
                    'catalog94_sha256':G95.sha(G95.wire(G95.catalog94_projection(old95))),
                    'index92_definition_sha256':G95.sha(b'declared-index')}
        funcs95=G95.source_functions(MIGRATION95.read_text());G95.check_catalog(old95,accepted95,funcs95)
        after95=copy.deepcopy(old95);h=G95.loads(after95['legacy']['complete_history_wire']);h.append({'id':len(h)+1,'version_id':95,'is_applied':True})
        after95['legacy']['complete_history_wire']=json.dumps(h);after95['legacy']['latest_versions'].append(95)
        row=next(x for x in after95['schema94']['functions']if x['name']==G95.M95_FUNCTION)
        body95=funcs95[G95.M95_FUNCTION]['body'];row['definition']=row['definition'].replace(row['body'],body95,1);row['body']=body95
        G95.check_catalog(after95,accepted95,funcs95,old=old95,migration=MIGRATION95.read_text())
        for fault in ('prior94_history','other_function','changed_definition_header','constraint','old_ledger','old_SDK','extra_function'):
            bad=copy.deepcopy(after95)
            if fault=='prior94_history':
                h=G95.loads(bad['legacy']['complete_history_wire']);h[-2]['is_applied']=False;bad['legacy']['complete_history_wire']=json.dumps(h)
            elif fault=='other_function':next(x for x in bad['schema94']['functions']if x['name']!=G95.M95_FUNCTION)['body']+=' '
            elif fault=='changed_definition_header':next(x for x in bad['schema94']['functions']if x['name']==G95.M95_FUNCTION)['definition']='foreign '+row['definition']
            elif fault=='constraint':bad['schema94']['constraints'][0]['definition']+=' OR true'
            elif fault=='old_ledger':bad['ledgers94'][0]['rows']+=1
            elif fault=='old_SDK':bad['old_grants']['sha256']='foreign'
            else:bad['schema94']['functions'].append(copy.deepcopy(row))
            with self.subTest(catalog95_fault=fault),self.assertRaises(G95.Hold):G95.check_catalog(bad,accepted95,funcs95,old=old95)

    def test_goose95_lost_ack_current15_and_method_guards(self):
        for phase in ('lost_ack','stale_after_markers'):
            with tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);run=root/'run';run.mkdir();clock=[100.0]
                def once(path,raw):
                    with Path(path).open('xb') as stream:stream.write(raw)
                    if phase=='stale_after_markers':clock[0]+=8
                api=mock.Mock();api.get.return_value=None;api.request.side_effect=TimeoutError('declared lost ACK')
                with mock.patch.multiple(G95,CLAIM=root/'GOOSE95-POSSIBLE-CREATE.json',JOB_UUID='a78740e4-6263-43dc-a0b2-56eb29368119',COMPANION_IMAGE_D='1'*64),mock.patch.object(G95.time,'monotonic',side_effect=lambda:clock[0]):
                    job=G95.job_manifest()
                    with mock.patch.object(G95,'JOB_MANIFEST_SHA256',G95.sha(G95.wire(job))):
                        with self.assertRaises((TimeoutError,G95.Hold)):G95.create_once(api,types.SimpleNamespace(once=once),run,job,'2'*64,'3'*64,1000,100)
                        self.assertTrue(G95.CLAIM.exists())
                        with self.assertRaises(G95.Hold):G95.create_once(api,types.SimpleNamespace(once=once),run,job,'2'*64,'3'*64,1000,100)
                    self.assertEqual(api.request.call_count,1 if phase=='lost_ack' else 0)
        inner=mock.Mock();C=types.SimpleNamespace(once=lambda *_:None)
        with mock.patch.object(G95,'JOB_UUID','a78740e4-6263-43dc-a0b2-56eb29368119'):
            api=G95.CapturedAPI(inner,C,Path('/declared'),True)
            for method,uri,body in [('PATCH',G95.DEP_URI,b'{}'),('DELETE',G95.JOB_URI+'/old',None),('POST',G95.DEP_URI,b'{}')]:
                with self.assertRaises(G95.Hold):api.request(method,uri,body)
        inner.request.assert_not_called()


if __name__=='__main__':unittest.main()
