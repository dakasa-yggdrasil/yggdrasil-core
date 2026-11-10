"""Declared G15/Core6 CAS operands; Source CI only, no production authority."""
import ast
import base64
import contextlib
import copy
import json
from pathlib import Path
import types
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
PATH=ROOT/'rollout/core_image_cas_once_g15.py'
cas=types.ModuleType('declared_g15_core_cas_CI');cas.__file__=str(PATH)
exec(compile(PATH.read_bytes(),str(PATH),'exec'),cas.__dict__)

def pre_read_operand():
    """Declared synthetic storage/wires; never Root/Native authority or production evidence."""
    t=cas.PRE_READ_TARGET
    def encoded(x):return json.dumps(x,separators=(',',':'),sort_keys=True)
    def sealed(x,**columns):
        raw=encoded(x).encode();return dict(columns,original_record=x,wire_hex=raw.hex(),record_sha256=cas.sha(raw))
    policy='10000000-0000-4000-8000-000000000001';owner='10000000-0000-4000-8000-000000000002';executor='10000000-0000-4000-8000-000000000003';ancestor='10000000-0000-4000-8000-000000000004'
    oldjobid='10000000-0000-4000-8000-000000000005';jobid='10000000-0000-4000-8000-000000000006';workflow='10000000-0000-4000-8000-000000000007';attempt='10000000-0000-4000-8000-000000000008';action='10000000-0000-4000-8000-000000000009'
    tuple95={'provider':'aws','slot':8,'resource_id':t['resource_id'],'resource_created_at':'2026-11-10T15:57:16Z','profile_name':'declared','scope_checksum':'a'*64,'integration_instance_id':'10000000-0000-4000-8000-000000000010'}
    original={'Request':{'intent':{'tuple':tuple95,'workflow_id':workflow}}}
    base={'id':t['root_admission_id'],'stage':'admitted','recorded_at':'2026-11-10T16:00:00Z','mode':'live','root_admission_id':t['root_admission_id'],'retirement_request_id':t['retirement_request_id'],'preregistration_id':t['preregistration_id'],'prefix_sha256':'b'*64,'original_caller_sha256':'c'*64,'evidence':{'declared':True},'original':original,'generation':31,'fence':54,'lease_owner':owner,'executor_id':executor,'run_id':ancestor,'destroy_grant_id':t['destroy_grant_id']}
    anchor=sealed(copy.deepcopy(base),id=t['root_admission_id'],stage='admitted',admission_id=t['root_admission_id'])
    off=sealed(dict(base,stage='off_qualified',recorded_at='2026-11-10T16:00:01Z'),id=t['root_admission_id'],stage='off_qualified',admission_id=t['root_admission_id'])
    eligibility={'schema':'original_guest_partial_poweroff_delete_eligibility_v1','admission_id':anchor['id'],'admission_sha256':anchor['record_sha256']};eligibilitywire=encoded(eligibility).encode()
    binding={'intent_id':t['retirement_request_id'],'destroy_grant_id':t['destroy_grant_id'],'original_eligibility_record':eligibility,'wire_hex':eligibilitywire.hex(),'eligibility_sha256':cas.sha(eligibilitywire)}
    grant={'grant_id':t['destroy_grant_id'],'state':'settled','expected_resource_id':t['resource_id'],'expected_resource_created_at':tuple95['resource_created_at'],'request_sha256':'d'*64,'expires_at':'2026-11-10T16:05:00Z','compensation_of':''}
    aux=[{'kind':'aws_ebs_volume','id':'declared-volume'},{'kind':'aws_network_interface','id':'declared-interface'}]
    sdk={'schema':'aws_original_terminate_instances_return_v1','provider':'aws','adapter_source_commit':'c34e330d8b266bb88e29ae7cf7b01df6f9fd96ce','response_status':200,'grant_id':t['destroy_grant_id'],'attempt_id':attempt,'action_id':action,'request_sha256':'d'*64,'resource_id':t['resource_id'],'resource_created_at':tuple95['resource_created_at'],'next_action_ids':[],'called_at':'2026-11-10T16:00:02Z','returned_at':'2026-11-10T16:00:03Z','context_deadline':'2026-11-10T16:04:00Z'}
    settlement={'outcome':'accepted','transport_completed':True,'action_id':action,'request_sha256':'d'*64,'resource_id':t['resource_id'],'resource_created_at':tuple95['resource_created_at'],'auxiliary_resources':aux,'auxiliary_inventory_complete':True,'original_provider_destroy_return':sdk}
    record={'grant':grant,'settlement':settlement,'attempt_id':attempt,'generation':31,'fencing_token':54,'lease_owner':owner,'executor_id':executor}
    storedgrant={'id':t['destroy_grant_id'],'state':'settled','generation':31,'grant_record':record,'grant_pgtext':encoded(record),**{k:None for k in ('original_disposition_id','failed_original_disposition_id','native_denied_disposition_id','enrolled_failed_disposition_id','failed_unwitnessed_expansion_cleanup_id')}}
    receipt={'grant':grant,'attempt_id':attempt,**{k:settlement[k]for k in ('outcome','transport_completed','action_id','resource_id','resource_created_at','auxiliary_resources','auxiliary_inventory_complete')}}
    read={'read_id':t['pending_read_id'],'admission_id':anchor['id'],'admission_sha256':anchor['record_sha256'],'destroy_grant_id':t['destroy_grant_id'],'retirement_request_id':t['retirement_request_id'],'prefix_sha256':'b'*64,'original_caller_sha256':'c'*64,'tuple':tuple95,'issued_at_core':'2026-11-10T16:00:04Z','original_deadline_core':'2026-11-10T16:00:09Z','adapter_source_commit':'c34e330d8b266bb88e29ae7cf7b01df6f9fd96ce'}
    prepared=sealed(read,id=t['pending_read_id'],admission_id=anchor['id'],stage='prepared',kind='absence',recorded_at='2026-11-10T16:00:04Z')
    observation={'destroy_grant_id':t['destroy_grant_id'],'destroy_grant_state':'settled','id':t['resource_id'],'created_at':tuple95['resource_created_at'],'original_outcome':'accepted','original_transport_completed':True,'auxiliary_inventory_complete':True,'billable_resources_absent':False,'retirement_complete':False,'aws_retirement_lifecycle':{'schema':'aws_original_terminate_and_native_absence_v1','request_id':action,'ec2_state':'shutting-down'},'server_absent':False,'server_absence_complete':False,'server_status':'shutting-down','next_actions':[],'auxiliary_resources':[dict(x,absent=False)for x in aux],'hold_reasons':['instance_not_terminated','aws_ebs_volume_still_present','aws_network_interface_still_present']}
    observer={'schema':'original_settled_retirement_absence_read_return_v1','observer_source_commit':'d8cbbf48873d24439216f98c30afe2669a525b54','original_adapter_source_commit':'c34e330d8b266bb88e29ae7cf7b01df6f9fd96ce','read_id':read['read_id'],'read_sha256':prepared['record_sha256'],'original_receipt_sha256':cas.sha(encoded(receipt).encode()),'observation':observation}
    returned={'read':read,'status':'observed','call_failed':False,'original_context_failed':False,'started_at_core':'2026-11-10T16:00:04Z','original_returned_at_core':'2026-11-10T16:00:05Z','original_destroy_receipt':receipt,'original_observer_return':base64.b64encode(encoded(observer).encode()).decode(),'observer_source_commit':observer['observer_source_commit'],'observation':observation}
    pending=sealed(returned,id=t['pending_read_id'],admission_id=anchor['id'],stage='returned',kind='absence',recorded_at='2026-11-10T16:00:05Z')
    oldrun={'id':ancestor,'status':'failed','finished_at':'2026-11-10T16:00:10Z'};oldrun['run_wire']=encoded(oldrun)
    oldjob={'id':oldjobid,'run_id':ancestor,'state':'returned','return_status':'failed','returned_at':'2026-11-10T16:00:10Z','finalization_ack_at':'2026-11-10T16:00:11Z'};oldjob['dispatch_wire']=encoded(oldjob)
    proof={'schema':'original_settled_absence_continuation_v1','requesting_run_id':t['failed_run_id'],'failed_run_id':ancestor,'failed_run_sha256':cas.sha(oldrun['run_wire'].encode()),'dispatch_id':oldjobid,'dispatch_sha256':cas.sha(oldjob['dispatch_wire'].encode()),'destroy_grant_sha256':cas.sha(storedgrant['grant_pgtext'].encode()),'delete_eligibility_sha256':binding['eligibility_sha256'],'pending_read_id':t['pending_read_id'],'pending_read_sha256':pending['record_sha256']}
    request=dict(base,id=t['failed_admission_id'],stage='requested',mode='settled_absence_continuation',recorded_at='2026-11-10T16:00:12Z',parent_admission_id=off['id'],parent_admission_sha256=off['record_sha256'],run_id='',continuation=proof,failed_run=base64.b64encode(oldrun['run_wire'].encode()).decode())
    requested=sealed(request,id=t['failed_admission_id'],stage='requested',admission_id=t['failed_admission_id'])
    admitted=sealed(dict(request,stage='admitted',recorded_at='2026-11-10T16:00:13Z',fence=55,run_id=t['failed_run_id']),id=t['failed_admission_id'],stage='admitted',admission_id=t['failed_admission_id'])
    steps=[{'id':'plan-original-guest','status':'succeeded','metadata':{'generation':31,'fencing_token':55,'lease_owner':owner}},{'id':'retire-original-guest','status':'succeeded','metadata':{'retirement_forward_id':t['failed_admission_id'],'request_id':t['retirement_request_id']}},{'id':'finish-original-retirement','status':'failed'}]+[{'id':x,'status':'skipped'}for x in ('provision-original-notify','complete-original-provision','refresh-original-membership','complete-original-retirement')]
    run={'id':t['failed_run_id'],'status':'failed','finished_at':'2026-11-10T16:00:20Z','metadata':{'capacity_dispatch_job_id':jobid,'triggered_by':'workflow_scheduler'},'result':{'status':'failed','steps':steps}};run['run_wire']=encoded(run)
    job={'id':jobid,'run_id':run['id'],'state':'returned','return_status':'failed','returned_at':run['finished_at'],'finalization_ack_at':'2026-11-10T16:00:21Z','envelope':encoded({'workflow':{'id':workflow}})};job['dispatch_wire']=encoded(job)
    intent={'policy_id':policy,'policy_checksum':'e'*64,'generation':31,'fencing_token':55,'phase':'drained','lease_owner':owner,'lease_executor_id':executor,'lease_expires_at':'2026-11-10T16:00:43Z','retirement_forward':{'id':t['failed_admission_id'],'stage':'admitted','mode':'settled_absence_continuation'}}
    r={'selected_runtime_source':cas.OLD_SOURCE,'target':{'parent_forward_id':t['root_admission_id'],'retirement_request_id':t['retirement_request_id'],'preregistration_id':t['preregistration_id'],'resource_id':t['resource_id']},'current_intent':{'intent':intent},'current_intent_pgtext':encoded(intent),'active_policies':[{'id':policy,'checksum':'e'*64}],'forward_rows':[anchor,off,requested,admitted],'retirement_contexts':[],'delete_bindings':[binding],'destroy_grants':[storedgrant],'read_counts':[],'own_read_count':0,'all_read_rows':[prepared,pending],'unreturned_prepared':[],'latest_reads_all_outcomes':[prepared,pending],'workflow_runs':[oldrun,run],'workflow_run_steps':[],'owning_dispatch_jobs':[oldjob,job]}
    value={'observed_at_pg':'2026-11-10T16:01:00Z','records':r,'records_wire':encoded(r),'records_sha256':cas.sha(encoded(r).encode())}
    case={k:t[k]for k in ('retirement_request_id','failed_admission_id','root_admission_id','destroy_grant_id')};case.update(expected_records_sha256=value['records_sha256'],provider_lanes={'aws':dict(intent_count=1,intent_busy=1,pending_authority=1,jobs_busy=0,runs_busy=0,forward_markers=1,forward_unreturned_reads=0,live_unreturned_canaries=0),'hetzner':dict(intent_count=1,intent_busy=0,pending_authority=0,jobs_busy=0,runs_busy=0,forward_markers=0,forward_unreturned_reads=0,live_unreturned_canaries=0)})
    return value,case


def reseal_pre_read(value,case):
    """Declared fixture mutation helper; tests rejoin raw frames, never bypass validators."""
    for row in value['records']['forward_rows']+value['records']['all_read_rows']:
        row['wire_hex']=json.dumps(row['original_record'],separators=(',',':'),sort_keys=True).encode().hex();row['record_sha256']=cas.sha(bytes.fromhex(row['wire_hex']))
    raw=json.dumps(value['records'],separators=(',',':'),sort_keys=True);value['records_wire']=raw;value['records_sha256']=case['expected_records_sha256']=cas.sha(raw.encode())

DECLARED_CHECK96='CHECK (declared_old_proof OR declared_pre_read_proof)'

@contextlib.contextmanager
def binding():
    with patch.multiple(cas,SOURCE_BOUND=True,CORE_R='c'*40,NEW_DIGEST='d'*64,SOURCE_PIN='a'*64,G15_OPS_P='e'*40,
        TOOL_PINS={n:'a'*64 for n in ('pair_change_contract.py','derive_g15pair_controller_config.py','derive_standing_config.py','g15cut.py')},
        CONFIG_REF={'path':'/declared/config','sha256':'a'*64},SQL_DATA_REF={'path':'/declared/E70','sha256':cas.POLICY92_SQL_SHA},
        UID='10000000-0000-4000-8000-000000000011',OLD_POD='10000000-0000-4000-8000-000000000012',GENERATION=278,
        OLD_CONTAINER_ID='containerd://'+'b'*64,OLD_IMAGE_CONFIG_DIGEST='sha256:'+'e'*64):yield


def core_operand():
    prefix='153828470928.dkr.ecr.us-east-1.amazonaws.com/ghcr/dakasa-yggdrasil/yggdrasil-core@sha256:';image=prefix+cas.OLD_DIGEST
    C=types.SimpleNamespace(OLD_DIGEST=cas.OLD_DIGEST,OLD_CORE_SOURCE=cas.OLD_SOURCE,NEW_DIGEST=cas.NEW_DIGEST,IMAGE_PREFIX=prefix)
    d={'apiVersion':'apps/v1','kind':'Deployment','metadata':{'namespace':'dakasa','name':'yggdrasil','uid':cas.UID,'generation':278,'resourceVersion':'1','annotations':{'dakasa.io/core-source-commit':cas.OLD_SOURCE,'retain':'declared'}},'spec':{'replicas':1,'template':{'spec':{'containers':[{'name':'core','image':image,'env':[{'name':'DECLARED','value':'unchanged'}],'resources':{'limits':{'cpu':'1'}}}]}}},'status':{'observedGeneration':278,'readyReplicas':1,'updatedReplicas':1,'availableReplicas':1}}
    p={'items':[{'metadata':{'uid':cas.OLD_POD,'name':'declared-core5'},'spec':{'containers':[{'name':'core','image':image}]},'status':{'phase':'Running','podIP':'192.0.2.1','containerStatuses':[{'name':'core','ready':True,'restartCount':0,'state':{'running':{'startedAt':'2026-11-10T15:00:00Z'}},'imageID':image,'containerID':cas.OLD_CONTAINER_ID}]}}]}
    return d,p,C


def acceptance_operand():
    events=[];ctrl={'boot_id':'10000000-0000-4000-8000-000000000001','pid':2,'start_ticks':3,'InvocationID':'1'*32,'ExecMainStartTimestampMonotonic':'4'};guard=dict(ctrl,pid=5,start_ticks=6,InvocationID='2'*32,ExecMainStartTimestampMonotonic='7')
    protected=cas.required_protected_refs();standing=b'DECLARED standing';ledger=Path('/declared/ledger');full=copy.deepcopy(ctrl);fullpath=ledger/'declared-key-QUALIFIED.PUBLIC.json';ownpath=ledger/(guard['boot_id']+'-GUARDIAN-'+guard['InvocationID']+'-FIRST-CURRENT15-RETURN.PUBLIC.json')
    measurement={'qualified_15_seconds':True,'all_requested_rows_accounted_for':True};kernel={'all_four_backends_and_reverse_sources_positive':True}
    own={'schema':'Root_owning_finite512_current15_readonly_observation_v1','source_sha256':cas.SOURCE_PIN,'standing_config_sha256':cas.sha(standing),'identity':full,'measurement':measurement,'kernel':kernel}
    result={'source_commit':cas.G15_OPS_P,'source_R':cas.CORE_R,'amd64_D':cas.NEW_DIGEST,'new_guardian_source_sha256':cas.SOURCE_PIN,'controller_config_sha256':'f'*64,'independent_current15':True,'all_inherited_budget_and_original_refs_unchanged':True,'Core_Cold_Hub_or_provider_mutation':False,'conservative_per_role_gap_seconds':{'controller':0,'guardian':0},'standing_sha256':cas.sha(standing),'controller':ctrl,'guardian':guard,'actual_new_full120_ref':{'path':str(fullpath),'sha256':cas.sha(b'DECLARED full120')},'own_daemon_first_current15_ref':{'path':str(ownpath),'sha256':cas.sha(cas.canonical(own))}}
    returned={'schema':'g15_pair_swap_return_v1','status':'CONFIG_SWAP_OK','result':result,'automatic_replay':False,'Guest_or_Core_business_authority':False}
    manifest={'source_commit':cas.G15_OPS_P,'protected_refs':[{'path':p,'sha256':h}for p,h in protected.items()]}
    class Owner:
        sha=cas.SOURCE_PIN;raw_config=standing
        def __init__(self,pin):events.append(('owner',pin))
        def identity(self):return full
        def original_qualification_measurement(self,identity):events.append(('full120',identity));return {'declared':True}
        def key(self,identity):return 'declared-key'
        def current15_readonly(self):events.append(('fresh15',None));return {'identity':full,'measurement':measurement,'kernel':kernel},b'DECLARED prefix',b'DECLARED closing',[{}]
    class Backend:
        def __init__(self,*args):pass
        def files(self,successor):events.append(('files',successor))
        def protected(self):return protected
    data={Path('/declared/standing'):standing,fullpath:b'DECLARED full120',ownpath:cas.canonical(own)}
    def identity(x):cas.need(set(x)=={'boot_id','pid','start_ticks','InvocationID','ExecMainStartTimestampMonotonic'}and type(x['pid'])is int and x['pid']>1,'DECLARED_CLOSED_PHYSICAL_IDENTITY')
    C=types.SimpleNamespace(NEW_DIGEST=cas.NEW_DIGEST,HEAD_CONFIG_SHA='f'*64,NEW_STANDING=Path('/declared/standing'),CTRL='ctrl',GUARD='guard',NEW_CONFIG=Path('/declared/config'),NEW_SOURCE=Path('/declared/source'),LEDGER=ledger,sha=cas.sha,wire=cas.canonical,loads=json.loads,once=lambda p,r:events.append(('once',p.name)),read=lambda p,*args:data[p],identity=identity,load_guardian=lambda *args:types.SimpleNamespace(Owner=Owner))
    def physical(unit,argv):events.append(('physical',unit,argv));return ctrl if unit=='ctrl'else guard
    def guardian_argv(source,pin):
        events.append(('guardian_argv',source,pin))
        return ['/usr/bin/python3','-B',str(source/'network_guardian.py'),'--watch','--source-sha256',pin]
    cut=types.SimpleNamespace(C=C,Backend=Backend,physical_identity=physical,controller_argv=lambda *args:['declared-controller'],guardian_argv=guardian_argv)
    return cut,Path('/declared/package'),manifest,returned,Path('/declared/run'),events


class G15CoreCASTests(unittest.TestCase):
    def test_forced_unbound_and_runtime_config_ref_before_io(self):
        for call in (cas.main,lambda:cas.maintenance_inputs(None),lambda:cas.database_pre_read96(None,None,None,None,'BEFORE'),lambda:cas.g15_acceptance(None,None,None,None,None),lambda:cas.accepted_guardian(None,None),lambda:cas.patch_once(None,None,None,None,None,0)):
            with self.subTest(call=repr(call)),patch.object(cas,'read')as read,patch.object(cas,'API')as api,patch.object(cas,'load_tools')as tools:
                with self.assertRaises(cas.Hold):call()
                read.assert_not_called();api.assert_not_called();tools.assert_not_called()
        with binding(),patch.object(cas,'CONFIG_REF',None),patch.object(cas,'read')as read:
            cas.require_source_bound()
            with self.assertRaises(cas.Hold):cas.require_bound()
            read.assert_not_called()
        for path,pin in [('relative','a'*64),('/declared/../file','a'*64),('//declared/file','a'*64),('/declared/file','0'*64)]:
            with self.subTest(path=path),self.assertRaises(cas.Hold):cas.validated_config_ref(path,pin)
        self.assertEqual(cas.validated_config_ref('/declared/file','a'*64),{'path':'/declared/file','sha256':'a'*64})
        cas.closed_g15_return_path(cas.ROOT/'swap-once-declared'/'RETURN.json',cas.ROOT)
        for p in (cas.ROOT/'guardian-source-repair-declared'/'RETURN.json',cas.ROOT/'swap-once-declared'/'HOLD.json',Path('/declared/RETURN.json')):
            with self.assertRaises(cas.Hold):cas.closed_g15_return_path(p,cas.ROOT)
        tree=ast.parse(PATH.read_text());main=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='main');calls=[n for n in ast.walk(main)if isinstance(n,ast.Call)]
        lexical=min(n.lineno for n in calls if isinstance(n.func,ast.Name)and n.func.id=='closed_g15_return_path')
        reads=[n.lineno for n in calls if isinstance(n.func,ast.Attribute)and n.func.attr in ('read','private_dir')and n.args and ((isinstance(n.args[0],ast.Name)and n.args[0].id=='returned_path')or(isinstance(n.args[0],ast.Attribute)and isinstance(n.args[0].value,ast.Name)and n.args[0].value.id=='returned_path'))]
        self.assertLess(lexical,min(reads));self.assertEqual(sum(isinstance(n,ast.If)and ast.unparse(n.test)=="__name__ == '__main__'"for n in tree.body),1)

    def test_current_core5_and_full_eight_operation_cas(self):
        with binding():
            d,p,C=core_operand();cas.core_before(d,p,C)
            for axis in ('source','uid','pod','container','image','generation','restart'):
                a,b=copy.deepcopy(d),copy.deepcopy(p)
                if axis=='source':a['metadata']['annotations']['dakasa.io/core-source-commit']='f'*40
                elif axis=='uid':a['metadata']['uid']='10000000-0000-4000-8000-000000000099'
                elif axis=='pod':b['items'][0]['metadata']['uid']='10000000-0000-4000-8000-000000000099'
                elif axis=='container':b['items'][0]['status']['containerStatuses'][0]['containerID']='containerd://'+'f'*64
                elif axis=='image':a['spec']['template']['spec']['containers'][0]['image']+='foreign'
                elif axis=='generation':a['metadata']['generation']+=1
                else:b['items'][0]['status']['containerStatuses'][0]['restartCount']=1
                with self.subTest(axis=axis),self.assertRaises(cas.Hold):cas.core_before(a,b,C)
            ops=cas.build_patch(d,C);self.assertEqual(len(ops),8)
            self.assertEqual([r['path']for r in ops if r['op']=='test'],['/metadata/uid','/metadata/resourceVersion','/metadata/generation','/metadata/annotations','/spec'])
            self.assertEqual([r['path']for r in ops if r['op']!='test'],['/spec/template/spec/containers/0/image','/metadata/annotations/dakasa.io~1core-source-commit','/metadata/annotations/kubernetes.io~1change-cause'])
            after=copy.deepcopy(d);after['spec']['template']['spec']['containers'][0]['image']=C.IMAGE_PREFIX+C.NEW_DIGEST;after['metadata']['annotations'].update({'dakasa.io/core-source-commit':cas.CORE_R,'kubernetes.io/change-cause':cas.CHANGE_CAUSE});after['metadata'].update(generation=279,resourceVersion='2');cas.result_shape(d,after,C)
            bad=copy.deepcopy(after);bad['spec']['template']['spec']['containers'][0]['env']=[]
            with self.assertRaises(cas.Hold):cas.result_shape(d,bad,C)

    def test_known_s8_zero_any_own_read_and_full_pending_sdk_lineage(self):
        value,case=pre_read_operand();self.assertTrue(cas.validate_pre_read96(value,case))
        for fault in ('own_prepared','own_returned','missing_ack','unknown_run','foreign_owner','live_lease','deadline','sdk_status','sdk_action','latest_failure','foreign_pending','raw_hash'):
            v,c=copy.deepcopy(value),copy.deepcopy(case);r=v['records']
            if fault.startswith('own_'):r['own_read_count']=1;r['all_read_rows'].append(dict(r['all_read_rows'][0],admission_id=cas.PRE_READ_TARGET['failed_admission_id'],stage='prepared'if fault=='own_prepared'else'returned'))
            elif fault=='missing_ack':r['owning_dispatch_jobs'][-1]['finalization_ack_at']=None
            elif fault=='unknown_run':r['workflow_runs'][-1]['status']='running'
            elif fault=='foreign_owner':r['current_intent']['intent']['lease_owner']='foreign';r['current_intent_pgtext']=json.dumps(r['current_intent']['intent'])
            elif fault=='live_lease':r['current_intent']['intent']['lease_expires_at']='2026-11-10T17:00:00Z';r['current_intent_pgtext']=json.dumps(r['current_intent']['intent'])
            elif fault=='deadline':r['all_read_rows'][-1]['original_record']['original_returned_at_core']='2026-11-10T16:00:09Z'
            elif fault=='sdk_status':r['destroy_grants'][0]['grant_record']['settlement']['original_provider_destroy_return']['response_status']=True
            elif fault=='sdk_action':r['destroy_grants'][0]['grant_record']['settlement']['original_provider_destroy_return']['action_id']='foreign'
            elif fault=='latest_failure':r['all_read_rows'].append(dict(r['all_read_rows'][-1],id='10000000-0000-4000-8000-000000000088',recorded_at='2026-11-10T16:00:30Z'))
            elif fault=='foreign_pending':r['all_read_rows'][-1]['admission_id']=cas.PRE_READ_TARGET['failed_admission_id']
            else:r['forward_rows'][-1]['original_record']['prefix_sha256']='f'*64
            if fault in ('sdk_status','sdk_action'):
                g=r['destroy_grants'][0];g['grant_pgtext']=json.dumps(g['grant_record'],separators=(',',':'),sort_keys=True)
                for row in r['forward_rows']:
                    if row['id']==cas.PRE_READ_TARGET['failed_admission_id']:row['original_record']['continuation']['destroy_grant_sha256']=cas.sha(g['grant_pgtext'].encode())
            reseal_pre_read(v,c)
            if fault=='deadline':
                pending=next(x for x in r['all_read_rows']if x['stage']=='returned')
                for row in r['forward_rows']:
                    if row['id']==cas.PRE_READ_TARGET['failed_admission_id']:row['original_record']['continuation']['pending_read_sha256']=pending['record_sha256']
                reseal_pre_read(v,c)
            with self.subTest(fault=fault),self.assertRaises((cas.Hold,KeyError,TypeError)):cas.validate_pre_read96(v,c)
        # Whole Source guards are semantic: changing self-consistent snapshots
        # cannot make any current owner's raw row disappear through filtering.
        self.assertIn("'all_read_rows'",cas.PRE_READ_SQL);self.assertIn("WHERE admission_id='756a0af2",cas.PRE_READ_SQL);self.assertNotIn("kind='absence'",cas.PRE_READ_SQL)

    def test_normal_g15_full120_own15_fresh15_and_once_markers(self):
        with binding():
            cut,folder,manifest,returned,run,events=acceptance_operand();accepted=cas.g15_acceptance(cut,folder,manifest,returned,run)
            self.assertEqual(accepted[2:4],(returned['result']['controller'],returned['result']['guardian']));self.assertTrue(any(x[0]=='full120'for x in events));self.assertTrue(any(x[0]=='fresh15'for x in events))
            self.assertIn(('guardian_argv',cut.C.NEW_SOURCE,cas.SOURCE_PIN),events)
            self.assertIn(('physical',cut.C.GUARD,['/usr/bin/python3','-B',str(cut.C.NEW_SOURCE/'network_guardian.py'),'--watch','--source-sha256',cas.SOURCE_PIN]),events)
            for fault in ('old_schema','hold','extra','gap','protected','guardian'):
                m,b=copy.deepcopy(manifest),copy.deepcopy(returned)
                if fault=='old_schema':b['schema']='g14_guardian_source_forward_repair_return_v1'
                elif fault=='hold':b['status']='HOLD'
                elif fault=='extra':b['repair']={}
                elif fault=='gap':b['result']['conservative_per_role_gap_seconds']['guardian']=1
                elif fault=='protected':m['protected_refs'].pop()
                else:b['result']['guardian']['pid']+=1
                with self.subTest(fault=fault),self.assertRaises(cas.Hold):cas.g15_acceptance(cut,folder,m,b,run)
        events=[];files={}
        def once(path,raw):
            if path in files:raise FileExistsError(str(path))
            files[path]=raw;events.append(('durable',path.name))
        C=types.SimpleNamespace(NEW_DIGEST='d'*64,wire=cas.canonical,once=once,loads=json.loads)
        class API:
            def request(self,method,uri,body=None):events.append((method,uri));return 200,b'{}',{}
        with binding(),patch.object(cas.time,'monotonic',return_value=100):
            cas.patch_once(API(),C,Path('/declared/run'),b'[]',{},99)
            self.assertEqual([x[0]for x in events],['durable','durable','PATCH'])
            with self.assertRaises(FileExistsError):cas.patch_once(API(),C,Path('/declared/run2'),b'[]',{},99)
            self.assertEqual(sum(x[0]=='PATCH'for x in events),1)

    def test_lost_ack_get_only_and_expired_current15_no_send(self):
        for expired in (False,True):
            events=[];files={}
            def once(path,raw):
                if path in files:raise FileExistsError(str(path))
                files[path]=raw;events.append(('durable',path.name))
            C=types.SimpleNamespace(NEW_DIGEST='d'*64,wire=cas.canonical,once=once,loads=json.loads)
            class API:
                def request(self,method,uri,body=None):
                    events.append((method,uri))
                    if method=='PATCH':raise TimeoutError('declared lost ACK')
                    return 200,b'{}',{}
            with binding(),patch.object(cas.time,'monotonic',return_value=100):
                with self.assertRaises(cas.Hold):cas.patch_once(API(),C,Path('/declared/run'),b'[]',{},0 if expired else 99)
                self.assertEqual([x[0]for x in events if x[0]in ('PATCH','GET')],[]if expired else['PATCH','GET'])
                with self.assertRaises(FileExistsError):cas.patch_once(API(),C,Path('/declared/run2'),b'[]',{},99)

    def test_exact96_function_constraint_delta_and_prior95_custody(self):
        sql=(ROOT.parents[1]/'db/migrations/00096_guest_retirement_pre_read_continuation.sql').read_text();self.assertEqual(cas.sha(sql.encode()),cas.M96)
        body=cas.re.search(r"STABLE SET timezone='UTC' AS \$\$(.*?)\$\$;",sql.split('-- +goose Down')[0],cas.re.S).group(1)
        row={'name':'retirement_forward_continuation_valid','arguments':'r jsonb, retirement uuid','result':'boolean','language':'plpgsql','volatility':'s','config':['TimeZone=UTC'],'body':'DECLARED prior95 body','definition':'DECLARED HEADER DECLARED prior95 body DECLARED TAIL'}
        prior={'catalog90':{'constraints':[{'table':'capacity_guest_retirement_forwards','name':'retirement_forward_continuation93','validated':True,'definition':'CHECK (declared_old_proof)'}]},'catalog91':{},'columns90_91':[],'functions93':[row],'index92_definition':'declared exact index','index92_valid':True,'schema94':{k:[]for k in ('tables','columns','constraints','indexes','triggers','functions')}}
        after=copy.deepcopy(prior);after['functions93'][0].update(body=body,definition='DECLARED HEADER '+body+' DECLARED TAIL');after['catalog90']['constraints'][0].update(name='retirement_forward_continuation96',definition=DECLARED_CHECK96)
        self.assertEqual(cas.catalog96_delta(prior,after,body,DECLARED_CHECK96),after)
        for axis in ('columns','index','other_function','function_body','function_header','constraint','unvalidated'):
            bad=copy.deepcopy(after)
            if axis=='columns':bad['columns90_91']=[{'foreign':True}]
            elif axis=='index':bad['index92_definition']='foreign'
            elif axis=='other_function':bad['functions93'].append(copy.deepcopy(row))
            elif axis=='function_body':bad['functions93'][0]['body']+='-- foreign'
            elif axis=='function_header':bad['functions93'][0]['volatility']='v'
            elif axis=='constraint':bad['catalog90']['constraints'][0]['definition']='CHECK (true)'
            else:bad['catalog90']['constraints'][0]['validated']=False
            with self.subTest(axis=axis),self.assertRaises(cas.Hold):cas.catalog96_delta(prior,bad,body,DECLARED_CHECK96)
        artifact={'schema':'declared_M96_PG16_exact_Source_CHECK_deparse_v1','migration93_sha256':'cc2b2843d14d4183ea68d25dbb9b9b58d1a353044e6ebf46ece6b93778e937e9','migration96_sha256':cas.M96,'before_definition':'CHECK (declared_old_proof)','after':{'server_version':'16.declared','server_version_num':160000,'database':'goose96_deparse_'+'a'*32,'definition':DECLARED_CHECK96,'validated':True,'old_constraint_rows':0},'scope':'disposable minimum table CHECK only','Native_or_Job_qualification':False}
        self.assertEqual(cas.constraint96_definition(prior,artifact),DECLARED_CHECK96)
        for field in ('migration96_sha256','before_definition','Native_or_Job_qualification','server_version_num','definition','validated','old_constraint_rows'):
            bad=copy.deepcopy(artifact)
            if field=='migration96_sha256':bad[field]='f'*64
            elif field=='before_definition':bad[field]='CHECK (foreign)'
            elif field=='Native_or_Job_qualification':bad[field]=True
            else:bad['after'][field]={'server_version_num':170000,'definition':'foreign','validated':False,'old_constraint_rows':1}[field]
            with self.subTest(artifact=field),self.assertRaises(cas.Hold):cas.constraint96_definition(prior,bad)
        old=(ROOT/'rollout/core_image_cas_once_g14.py').read_text();new=PATH.read_text()
        def spans(s):return {n.name:ast.get_source_segment(s,n)for n in ast.parse(s).body if isinstance(n,(ast.FunctionDef,ast.ClassDef))}
        a,b=spans(old),spans(new)
        for name in ('API','operation_lock','read','api_read','result_shape','query','workflow_busy_logical_index92_sql','catalog_sql','catalog_projection','catalog_select','catalog94_projection','catalog94_select','patch_once','validated_config_ref','require_bound','utc'):self.assertEqual(a[name],b[name],name)
        self.assertIn("statement_timeout='3s'",b['query']);self.assertIn("lock_timeout='500ms'",b['query']);self.assertIn('timeout=8',b['query'])
        self.assertIn("'b80ec307962a67b8a28722c8fbf88add02c25de08847253fbae7838de1c0153d'",b['root96_overlay']);self.assertNotIn('Root_Goose95_acceptance',b['root96_overlay'])
