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
    t={'root_admission_id': 'b8f529ca-43eb-4351-9ac3-a8774f90f562', 'failed_admission_id': '756a0af2-3ce3-4992-8fe2-116bb8da12cd', 'retirement_request_id': '87f9530e-0868-4538-98e7-96f241462c49', 'preregistration_id': '9cdb3d59-3085-4ecb-b384-49f47b2b03b4', 'destroy_grant_id': 'c46345dc-a21f-4d7d-834b-e8e8f38b7643', 'failed_run_id': 'ef121889-8828-4a8b-b821-873a13c15032', 'pending_read_id': '41de89ba-bec2-479a-87f6-cf5e4a602213', 'resource_id': 'i-03d9ec5b7702b6ee6'}
    def encoded(x):return json.dumps(x,separators=(',',':'),sort_keys=True)
    def sealed(x,**columns):
        if 'recorded_at'in x:columns.setdefault('recorded_at',x['recorded_at'])
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
    r={'selected_runtime_source':'33a846d31a5b123b2c1141192671bc830bf6d9c8','target':{'parent_forward_id':t['root_admission_id'],'retirement_request_id':t['retirement_request_id'],'preregistration_id':t['preregistration_id'],'resource_id':t['resource_id']},'current_intent':{'intent':intent},'current_intent_pgtext':encoded(intent),'active_policies':[{'id':policy,'checksum':'e'*64}],'forward_rows':[anchor,off,requested,admitted],'retirement_contexts':[],'delete_bindings':[binding],'destroy_grants':[storedgrant],'read_counts':[],'own_read_count':0,'all_read_rows':[prepared,pending],'unreturned_prepared':[],'latest_reads_all_outcomes':[prepared,pending],'workflow_runs':[oldrun,run],'workflow_run_steps':[],'owning_dispatch_jobs':[oldjob,job]}
    value={'observed_at_pg':'2026-11-10T16:01:00Z','records':r,'records_wire':encoded(r),'records_sha256':cas.sha(encoded(r).encode())}
    case={k:t[k]for k in ('retirement_request_id','failed_admission_id','root_admission_id','destroy_grant_id')};case.update(expected_records_sha256=value['records_sha256'],provider_lanes={'aws':dict(intent_count=1,intent_busy=1,pending_authority=1,jobs_busy=0,runs_busy=0,forward_markers=1,forward_unreturned_reads=0,live_unreturned_canaries=0),'hetzner':dict(intent_count=1,intent_busy=0,pending_authority=0,jobs_busy=0,runs_busy=0,forward_markers=0,forward_unreturned_reads=0,live_unreturned_canaries=0)})
    return value,case


def reseal_pre_read(value,case):
    """Declared fixture mutation helper; tests rejoin raw frames, never bypass validators."""
    for row in value['records']['forward_rows']+value['records']['all_read_rows']:
        row['wire_hex']=json.dumps(row['original_record'],separators=(',',':'),sort_keys=True).encode().hex();row['record_sha256']=cas.sha(bytes.fromhex(row['wire_hex']))
    raw=json.dumps(value['records'],separators=(',',':'),sort_keys=True);value['records_wire']=raw;value['records_sha256']=case['expected_records_sha256']=cas.sha(raw.encode())


def current_pre_read_operand():
    """Declared current57 shape; old Go96/f55 fixture remains historical above.

    These synthetic JSON/wires exercise the retained classic anchor followed
    by two typed96 zero-read failures. Reused opaque IDs are labels only;
    neither this fixture nor its hashes are Native/Root acceptance evidence.
    """
    value,case=pre_read_operand();r=value['records']
    encoded=lambda x:json.dumps(x,separators=(',',':'),sort_keys=True)
    previous=copy.deepcopy(r['forward_rows'][-1]);previous_run=copy.deepcopy(r['workflow_runs'][-1]);previous_job=copy.deepcopy(r['owning_dispatch_jobs'][-1])
    for fence,admission,runid,jobid,owner,executor in (
        (56,'c49f4092-bb5d-43e7-9560-9b32e1fd1e0c','89e2b9ba-6963-4183-bb27-bbf51db31c09','a0e2e863-0b5a-4aaa-8c2e-6faa9e91d122','10000000-0000-4000-8000-000000000020','10000000-0000-4000-8000-000000000021'),
        (57,'78b8df5a-eb37-4a18-8029-15ee02d93bd1','21b8f725-d82c-40aa-8401-a4fbdca98d28','9c65b8f7-988a-41e1-8b76-5c34e0071645','10000000-0000-4000-8000-000000000022','10000000-0000-4000-8000-000000000023'),
    ):
        minute=fence-55
        at=lambda second:f'2026-11-10T16:{minute:02d}:{second:02d}Z'
        old=previous['original_record']
        proof=copy.deepcopy(old['continuation'])
        proof.update(schema='original_settled_absence_pre_read_continuation_v1',requesting_run_id=runid,failed_run_id=previous_run['id'],failed_run_sha256=cas.sha(previous_run['run_wire'].encode()),dispatch_id=previous_job['id'],dispatch_sha256=cas.sha(previous_job['dispatch_wire'].encode()))
        requested=copy.deepcopy(old)
        requested.update(id=admission,stage='requested',recorded_at=at(12),parent_admission_id=previous['id'],parent_admission_sha256=previous['record_sha256'],fence=fence-1,run_id='',continuation=proof,failed_run=base64.b64encode(previous_run['run_wire'].encode()).decode())
        admitted=copy.deepcopy(requested)
        admitted.update(stage='admitted',recorded_at=at(13),fence=fence,run_id=runid,lease_owner=owner,executor_id=executor)
        frames=[]
        for original in (requested,admitted):
            raw=encoded(original).encode()
            frames.append(dict(id=admission,stage=original['stage'],admission_id=admission,recorded_at=original['recorded_at'],original_record=original,wire_hex=raw.hex(),record_sha256=cas.sha(raw)))
        r['forward_rows'].extend(frames)
        run=copy.deepcopy(previous_run)
        run.update(id=runid,finished_at=at(20))
        run['metadata']['capacity_dispatch_job_id']=jobid
        steps={s['id']:s for s in run['result']['steps']}
        steps['plan-original-guest']['metadata'].update(generation=31,fencing_token=fence,lease_owner=owner)
        steps['retire-original-guest']['metadata'].update(retirement_forward_id=admission,request_id=case['retirement_request_id'])
        steps['finish-original-retirement']['metadata']={'original_guest_refusal_predicate':'original-guest-step-17'}
        run['run_wire']=encoded({k:v for k,v in run.items()if k!='run_wire'})
        job=copy.deepcopy(previous_job)
        job.update(id=jobid,run_id=runid,returned_at=run['finished_at'],finalization_ack_at=at(21))
        job['dispatch_wire']=encoded({k:v for k,v in job.items()if k!='dispatch_wire'})
        r['workflow_runs'].append(run);r['owning_dispatch_jobs'].append(job)
        previous,previous_run,previous_job=frames[-1],run,job
    p=previous['original_record']
    current=r['current_intent']['intent']
    current.update(generation=31,fencing_token=57,lease_owner=p['lease_owner'],lease_executor_id=p['executor_id'],lease_expires_at='2026-11-10T16:02:43Z')
    current['retirement_forward'].update(id=p['id'],stage='admitted',mode='settled_absence_continuation')
    r['current_intent_pgtext']=encoded(current)
    r['selected_runtime_source']='045176d16947555ccbc33a8b51635b08d2d9270e'
    r['read_counts']=[dict(kind='absence',stage=stage,rows=1,first_at=row['recorded_at'],last_at=row['recorded_at'])for stage,row in zip(('prepared','returned'),r['all_read_rows'])]
    value['observed_at_pg']='2026-11-10T16:06:00Z'
    case.update(failed_admission_id=p['id'],current_runtime_source=r['selected_runtime_source'],current_generation=31,current_fencing_token=57,current_failed_run_id=previous_run['id'],current_lease_owner=p['lease_owner'])
    reseal_pre_read(value,case)
    return value,case


def reseal_current_pre_read(value,case,update_expected=True):
    """Reseal declared raw joins so semantic faults cannot hide behind bad SHA.

    Keeping update_expected False instead tests the immutable Root snapshot
    binding itself, as BEFORE/PRESEND must do for any retained-original change.
    """
    r=value['records'];encoded=lambda x:json.dumps(x,separators=(',',':'),sort_keys=True)
    runs={w['id']:w for w in r['workflow_runs']};jobs={j['id']:j for j in r['owning_dispatch_jobs']}
    for w in runs.values():w['run_wire']=encoded({k:v for k,v in w.items()if k!='run_wire'})
    for j in jobs.values():j['dispatch_wire']=encoded({k:v for k,v in j.items()if k!='dispatch_wire'})
    grant=r['destroy_grants'][0];grant['grant_pgtext']=encoded(grant['grant_record'])
    for row in r['all_read_rows']:
        raw=encoded(row['original_record']).encode();row['wire_hex']=raw.hex();row['record_sha256']=cas.sha(raw)
    pending=next(x for x in r['all_read_rows']if x['id']=='41de89ba-bec2-479a-87f6-cf5e4a602213'and x['stage']=='returned')
    last={}
    for row in r['forward_rows']:
        original=row['original_record'];proof=original.get('continuation')
        if proof:
            proof.update(destroy_grant_sha256=cas.sha(grant['grant_pgtext'].encode()),delete_eligibility_sha256=r['delete_bindings'][0]['eligibility_sha256'],pending_read_sha256=pending['record_sha256'],failed_run_sha256=cas.sha(runs[proof['failed_run_id']]['run_wire'].encode()),dispatch_sha256=cas.sha(jobs[proof['dispatch_id']]['dispatch_wire'].encode()))
            original['failed_run']=base64.b64encode(runs[proof['failed_run_id']]['run_wire'].encode()).decode()
        parent=original.get('parent_admission_id')
        if parent in last:original['parent_admission_sha256']=last[parent]['record_sha256']
        raw=encoded(original).encode();row['wire_hex']=raw.hex();row['record_sha256']=cas.sha(raw);last[row['id']]=row
    r['current_intent_pgtext']=encoded(r['current_intent']['intent'])
    raw=encoded(r);value['records_wire']=raw;value['records_sha256']=cas.sha(raw.encode())
    if update_expected:case['expected_records_sha256']=value['records_sha256']



def seal_image_fixture(value, case=None):
    encoded=lambda x:json.dumps(x,sort_keys=True,separators=(',',':'))
    r=value['records']
    for row in r['forward_rows']+r['all_read_rows']:
        raw=encoded(row['original_record']).encode();row['wire_hex']=raw.hex();row['record_sha256']=cas.sha(raw)
    for g in r.get('create_grants',[])+r['destroy_grants']:g['grant_pgtext']=encoded(g['grant_record'])
    for w in r['workflow_runs']:w['run_wire']=encoded({k:v for k,v in w.items()if k!='run_wire'})
    for j in r['owning_dispatch_jobs']:j['dispatch_wire']=encoded({k:v for k,v in j.items()if k!='dispatch_wire'})
    r['current_intent_pgtext']=encoded(r['current_intent']['intent'])
    raw=encoded(r);value['records_wire']=raw;value['records_sha256']=cas.sha(raw.encode())
    if case is not None:case['expected_records_sha256']=value['records_sha256']

def live_image_operand():
    """Declared real-shaped LIVE and terminal classes; no original production bytes."""
    value,oldcase=pre_read_operand();r=value['records'];t=cas.LIVE_TARGET
    encoded=lambda x:json.dumps(x,sort_keys=True,separators=(',',':'))
    tuple_={'provider':'aws','integration_instance_id':'10000000-0000-4000-8000-000000000010','instance_checksum':'1'*64,'integration_type_id':'20000000-0000-4000-8000-000000000010','type_checksum':'2'*64,'scope_checksum':'a'*64,'profile_checksum':'3'*64,'profile':'declared','slot':t['slot'],'resource_id':t['resource_id'],'resource_created_at':t['resource_created_at']}
    original_intent={'generation':34,'fencing_token':70,'phase':'draining'}
    a=copy.deepcopy(r['forward_rows'][0]['original_record'])
    a.update(schema='original_guest_partial_poweroff_forward_v1',id=t['admission_id'],root_admission_id=t['admission_id'],stage='admitted',mode='live',issuer='source:ordinary-retirement',actual_core_source=cas.OLD_SOURCE,preregistration_id=t['preregistration_id'],retirement_request_id=t['retirement_request_id'],generation=34,fence=70,lease_owner=t['lease_owner'],executor_id=t['executor_id'],run_id=t['run_id'],recorded_at='2026-11-10T16:00:00Z',original_generation=34,original_fence=70,original_intent_wire=base64.b64encode(encoded(original_intent).encode()).decode(),original_intent_sha256=cas.sha(encoded(original_intent).encode()))
    a.pop('destroy_grant_id',None);a['original']['Request']['intent']['tuple']=tuple_
    create_id='20000000-0000-4000-8000-000000000001'
    a['original']['Preregistration']={'original_create_grant_id':create_id,'original_create_request_sha256':'d'*64}
    def frame(record):
        raw=encoded(record).encode();return dict(id=record['id'],stage=record['stage'],admission_id=record['id'],recorded_at=record['recorded_at'],original_record=record,wire_hex=raw.hex(),record_sha256=cas.sha(raw))
    admitted=frame(a)
    binding={'name':'declared','integration_instance_id':tuple_['integration_instance_id'],'scope_checksum':tuple_['scope_checksum'],'profile_name':tuple_['profile'],'original_provider_source_commit':cas.A3_CREATOR,'ensure_capability':'ensure_ec2_instance','destroy_capability':'terminate_ec2_instance'}
    paid=copy.deepcopy(r['destroy_grants'][0]);record=paid['grant_record'];g=record['grant'];settle=record['settlement'];sdk=settle['original_provider_destroy_return']
    paid['id']=g['grant_id']=sdk['grant_id']=t['destroy_grant_id'];paid['generation']=record['generation']=34;record.update(fencing_token=70,lease_owner=t['lease_owner'],executor_id=t['executor_id'],binding=binding)
    g.update(binding_name='declared',capability='terminate_ec2_instance',integration_instance_id=tuple_['integration_instance_id'],scope_checksum=tuple_['scope_checksum'],profile_name=tuple_['profile'],slot=5,expected_resource_id=tuple_['resource_id'],expected_resource_created_at=tuple_['resource_created_at'])
    settle.update(resource_id=tuple_['resource_id'],resource_created_at=tuple_['resource_created_at']);sdk.update(resource_id=tuple_['resource_id'],resource_created_at=tuple_['resource_created_at'],response_body_sha256='9'*64,response_bytes=512)
    create=copy.deepcopy(paid);create['id']=create_id;cr=create['grant_record'];cr['grant'].update(grant_id=create_id,state='confirmed',capability='ensure_ec2_instance');create['state']='confirmed'
    cs=cr['settlement'];cs['original_provider_create_return']=cs.pop('original_provider_destroy_return');cs['original_provider_create_return'].update(schema='aws_original_run_instances_return_v1',grant_id=create_id)
    receipt={'grant':g,'attempt_id':record['attempt_id'],**{k:settle[k]for k in ('outcome','transport_completed','action_id','resource_id','resource_created_at','auxiliary_resources','auxiliary_inventory_complete')}}
    rows=[]
    def pair(ident,kind,second,failed=False):
        read={'schema':'original_core_guest_retirement_forward_read_v1','read_id':ident,'admission_id':a['id'],'admission_sha256':admitted['record_sha256'],'retirement_request_id':a['retirement_request_id'],'kind':kind,'prefix_sha256':a['prefix_sha256'],'original_caller_sha256':a['original_caller_sha256'],'adapter_source_commit':cas.A3_CREATOR,'tuple':tuple_,'destroy_grant_id':''if kind=='off'else t['destroy_grant_id'],'issued_at_core':f'2026-11-10T16:00:{second:02d}Z','original_deadline_core':f'2026-11-10T16:00:{second+5:02d}Z'}
        reply={'schema':'original_core_guest_retirement_forward_read_return_v1','read':read,'status':''if failed else'observed','call_failed':failed,'original_context_failed':failed,'started_at_core':read['issued_at_core'],'original_returned_at_core':f'2026-11-10T16:00:{second+1:02d}Z'}
        if kind=='off':reply['plan']={'server':{'id':tuple_['resource_id'],'created_at':tuple_['resource_created_at'],'status':'stopped'}}
        else:reply['original_destroy_receipt']=receipt
        for stage,body,at in (('prepared',read,read['issued_at_core']),('returned',reply,reply['original_returned_at_core'])):
            raw=encoded(body).encode();rows.append(dict(id=ident,stage=stage,admission_id=a['id'],kind=kind,recorded_at=at,original_record=body,wire_hex=raw.hex(),record_sha256=cas.sha(raw)))
    pair('c274c871-8861-4124-8d6c-85e0ba6896ff','off',4)
    off=copy.deepcopy(a);off.update(stage='off_qualified',recorded_at=rows[1]['recorded_at'],admission_sha256=admitted['record_sha256'],native_off_read_id=rows[1]['id'],native_off_sha256=rows[1]['record_sha256'])
    q=frame(off)
    pair('20000000-0000-4000-8000-000000000020','absence',8)
    pair('7dd59209-0c2c-4d13-8198-878fcec0aa74','absence',12,True)
    eligibility={'schema':'original_guest_partial_poweroff_delete_eligibility_v1','admission_id':a['id'],'admission_sha256':admitted['record_sha256'],'native_off_read_id':off['native_off_read_id'],'native_off_sha256':off['native_off_sha256']}
    ew=encoded(eligibility).encode();delete={'intent_id':a['retirement_request_id'],'destroy_grant_id':t['destroy_grant_id'],'original_eligibility_record':eligibility,'wire_hex':ew.hex(),'eligibility_sha256':cas.sha(ew)}
    run=copy.deepcopy(r['workflow_runs'][-1]);run.update(id=t['run_id'],finished_at='2026-11-10T16:00:20Z');run['metadata']['capacity_dispatch_job_id']=t['dispatch_id']
    st={x['id']:x for x in run['result']['steps']};st['plan-original-guest']['metadata'].update(generation=34,fencing_token=70,lease_owner=t['lease_owner']);st['retire-original-guest']['metadata'].update(retirement_forward_id=a['id'],request_id=a['retirement_request_id'])
    job=copy.deepcopy(r['owning_dispatch_jobs'][-1]);job.update(id=t['dispatch_id'],run_id=run['id'],returned_at=run['finished_at'],finalization_ack_at='2026-11-10T16:00:21Z')
    intent={'policy_id':r['active_policies'][0]['id'],'policy_checksum':r['active_policies'][0]['checksum'],'generation':34,'fencing_token':70,'phase':'drained','lease_owner':a['lease_owner'],'lease_executor_id':a['executor_id'],'lease_expires_at':'2026-11-10T16:00:43Z','retirement_forward':cas.forward_marker_data(off)}
    r.update(selected_runtime_source=cas.OLD_SOURCE,target={'parent_forward_id':a['id'],'retirement_request_id':a['retirement_request_id'],'preregistration_id':a['preregistration_id'],'resource_id':tuple_['resource_id']},current_intent={'intent':intent},forward_rows=[admitted,q],create_grants=[create],delete_bindings=[delete],destroy_grants=[paid],all_read_rows=rows,own_read_count=len(rows),unreturned_prepared=[],latest_reads_all_outcomes=rows[-6:],workflow_runs=[run],owning_dispatch_jobs=[job])
    value['observed_at_pg']='2026-11-10T16:01:00Z'
    case={'schema':cas.LIVE_CASE_SCHEMA,'retirement_request_id':a['retirement_request_id'],'admission_id':a['id'],'preregistration_id':a['preregistration_id'],'current_runtime_source':cas.OLD_SOURCE,'current_generation':34,'current_fencing_token':70,'current_lease_owner':a['lease_owner'],'current_executor_id':a['executor_id'],'current_failed_run_id':a['run_id'],'expected_records_sha256':'0'*64,'provider_lanes':oldcase['provider_lanes'],'historical_s8_ref':cas.S8_TERMINAL_REF}
    seal_image_fixture(value,case)
    # PG column timestamps use +00:00; original Go wire retains Z.
    for row in r['forward_rows']+r['all_read_rows']:row['recorded_at']=row['recorded_at'].replace('Z','+00:00')
    seal_image_fixture(value,case)
    return value,case

def terminal_image_operand():
    value,case=current_pre_read_operand();r=value['records'];a=r['forward_rows'][-1]['original_record']
    # A synthetic terminal of the historical31 epoch, independently of LIVE34.
    a.update(schema='original_guest_partial_poweroff_forward_v1',actual_core_source=cas.OLD_SOURCE,original_intent_sha256='e'*64,original_generation=31,original_fence=54,preregistration_id=cas.PRE_READ_TARGET['preregistration_id'])
    tuple_=a['original']['Request']['intent']['tuple'];tuple_['profile']=tuple_.pop('profile_name');tuple_.update(slot=8,instance_checksum='1'*64,integration_type_id='20000000-0000-4000-8000-000000000010',type_checksum='2'*64,profile_checksum='3'*64)
    # Preserve actual admitted bytes and append an independent own absence pair.
    seal_image_fixture(value);admitted=r['forward_rows'][-1]
    own=copy.deepcopy(r['all_read_rows'][0]);read=own['original_record'];ident='f3c6eee8-02e0-4f06-bf76-4b7377d7cf21'
    read.update(read_id=ident,kind='absence',admission_id=a['id'],admission_sha256=admitted['record_sha256'],tuple=tuple_,issued_at_core='2026-11-10T16:03:00Z',original_deadline_core='2026-11-10T16:03:05Z')
    own.update(id=ident,admission_id=a['id'],recorded_at=read['issued_at_core'])
    returned=copy.deepcopy(r['all_read_rows'][1]);reply=returned['original_record'];reply.update(read=read,started_at_core='2026-11-10T16:03:00Z',original_returned_at_core='2026-11-10T16:03:01Z')
    obs=reply['observation'];obs.update(server_absent=True,server_absence_complete=True,server_status='',billable_resources_absent=True,retirement_complete=True,hold_reasons=[])
    for aux in obs['auxiliary_resources']:aux['absent']=True
    returned.update(id=ident,admission_id=a['id'],recorded_at=reply['original_returned_at_core'])
    r['all_read_rows'].extend((own,returned));seal_image_fixture(value)
    terminal=copy.deepcopy(a);terminal.update(stage='terminal',recorded_at='2026-11-10T16:03:02Z',admission_sha256=admitted['record_sha256'],native_absence_sha256=returned['record_sha256'])
    ti={'generation':a['generation'],'fencing_token':a['fence'],'phase':'promoted','lease_expires_at':None,'retirement_forward':cas.forward_marker_data(terminal)}
    raw=cas.canonical(ti);terminal.update(terminal_intent_wire=base64.b64encode(raw).decode(),terminal_intent_sha256=cas.sha(raw))
    encoded=lambda x:json.dumps(x,sort_keys=True,separators=(',',':'));raw=encoded(terminal).encode()
    tr=dict(id=a['id'],stage='terminal',admission_id=a['id'],recorded_at=terminal['recorded_at'],original_record=terminal,wire_hex=raw.hex(),record_sha256=cas.sha(raw));r['forward_rows'].append(tr)
    g=r['destroy_grants'][0];g['state']=g['grant_record']['grant']['state']='confirmed';g['grant_record']['proof']={'resource_absent':True,'auxiliary_absent':[{'kind':'aws_ebs_volume'},{'kind':'aws_network_interface'}]}
    gr=g['grant_record'];gr['binding']={'name':'declared','integration_instance_id':tuple_['integration_instance_id'],'scope_checksum':tuple_['scope_checksum'],'profile_name':tuple_['profile'],'ensure_capability':'ensure_ec2_instance','destroy_capability':'terminate_ec2_instance','original_provider_source_commit':cas.A3_CREATOR}
    gr['grant'].update(binding_name='declared',capability='terminate_ec2_instance',integration_instance_id=tuple_['integration_instance_id'],scope_checksum=tuple_['scope_checksum'],profile_name=tuple_['profile'],slot=8)
    gr['settlement']['original_provider_destroy_return'].update(response_body_sha256='9'*64,response_bytes=512)
    run=r['workflow_runs'][-1];run['status']=run['result']['status']='succeeded';run['finished_at']='2026-11-10T16:03:03Z'
    steps={x['id']:x for x in run['result']['steps']};steps['finish-original-retirement']['status']=steps['complete-original-retirement']['status']='succeeded'
    job=r['owning_dispatch_jobs'][-1];job.update(return_status='succeeded',returned_at=run['finished_at'],finalization_ack_at='2026-11-10T16:03:04Z')
    # Current intent belongs elsewhere; it is never terminal31's authority.
    r['current_intent']['intent'].update(generation=34,fencing_token=70)
    seal_image_fixture(value)
    target={'admission_id':a['id'],'record_sha256':tr['record_sha256'],'native_absence_sha256':returned['record_sha256'],'terminal_intent_sha256':terminal['terminal_intent_sha256'],'run_id':a['run_id'],'read_id':ident,'generation':a['generation'],'fence':a['fence']}
    return value,target

DECLARED_CHECK96='CHECK (declared_old_proof OR declared_pre_read_proof)'
DECLARED_INVENTORY_MANIFEST={'schemaVersion':2,'mediaType':'application/vnd.oci.image.manifest.v1+json','config':{'mediaType':'application/vnd.oci.image.config.v1+json','size':12,'digest':'sha256:'+'4'*64},'layers':[{'mediaType':'application/vnd.oci.image.layer.v1.tar+gzip','size':12,'digest':'sha256:'+'5'*64}]}

@contextlib.contextmanager
def binding():
    with patch.multiple(cas,SOURCE_BOUND=True,CORE_R='c'*40,NEW_DIGEST='d'*64,SOURCE_PIN='a'*64,G15_OPS_P='e'*40,INVENTORY_SOURCE='1'*40,INVENTORY_DIGEST=cas.sha(cas.canonical(DECLARED_INVENTORY_MANIFEST)),INVENTORY_CONFIG_DIGEST='4'*64,
        TOOL_PINS={n:'a'*64 for n in ('pair_change_contract.py','derive_g15pair_controller_config.py','derive_standing_config.py','g15cut.py')},
        CONFIG_REF={'path':'/declared/config','sha256':'a'*64},SQL_DATA_REF={'path':'/declared/E70','sha256':cas.POLICY92_SQL_SHA},
        UID='10000000-0000-4000-8000-000000000011',OLD_POD='10000000-0000-4000-8000-000000000012',GENERATION=279,
        OLD_CONTAINER_ID='containerd://'+'b'*64,OLD_IMAGE_CONFIG_DIGEST='sha256:'+'e'*64):yield


def core_operand():
    prefix='153828470928.dkr.ecr.us-east-1.amazonaws.com/ghcr/dakasa-yggdrasil/yggdrasil-core@sha256:';image=prefix+cas.OLD_DIGEST
    C=types.SimpleNamespace(OLD_DIGEST=cas.OLD_DIGEST,OLD_CORE_SOURCE=cas.OLD_SOURCE,NEW_DIGEST=cas.NEW_DIGEST,IMAGE_PREFIX=prefix)
    d={'apiVersion':'apps/v1','kind':'Deployment','metadata':{'namespace':'dakasa','name':'yggdrasil','uid':cas.UID,'generation':cas.GENERATION,'resourceVersion':'1','annotations':{'dakasa.io/core-source-commit':cas.OLD_SOURCE,'retain':'declared'}},'spec':{'replicas':1,'template':{'spec':{'containers':[{'name':'core','image':image,'env':[{'name':'DECLARED','value':'unchanged'}],'resources':{'limits':{'cpu':'1'}}}]}}},'status':{'observedGeneration':cas.GENERATION,'readyReplicas':1,'updatedReplicas':1,'availableReplicas':1}}
    p={'items':[{'metadata':{'uid':cas.OLD_POD,'name':'declared-core6'},'spec':{'containers':[{'name':'core','image':image}]},'status':{'phase':'Running','podIP':'192.0.2.1','containerStatuses':[{'name':'core','ready':True,'restartCount':0,'state':{'running':{'startedAt':'2026-11-10T15:00:00Z'}},'imageID':image,'containerID':cas.OLD_CONTAINER_ID}]}}]}
    return d,p,C


def inventory_description_wire(description=None):
    """Actual SDK HTTP framing, not the decoded inner RPC reply."""
    inner=cas.canonical({'ok':True,'data':cas.expected_inventory_description()if description is None else description})
    return cas.canonical({'content_type':'application/json','body':base64.b64encode(inner).decode('ascii')})


def reader_operand(manifest=None):
    """Declared semantic Root/Kube operands; real input_ref hashes all bytes.

    Tests scope the immutable known Root9/M7 pins to these synthetic originals
    after separately asserting production constants. No receipt is published.
    """
    bodies={};events=[]
    def ref(name,value):
        raw=value if type(value)is bytes else cas.canonical(value)
        p='/declared/reader/'+name;bodies[Path(p)]=raw
        return {'path':p,'sha256':cas.sha(raw)}
    app=cas.INVENTORY_APP;labels={'app':app};image=cas.INVENTORY_IMAGE_PREFIX+cas.INVENTORY_DIGEST
    uid=lambda n:'20000000-0000-4000-8000-'+str(n).zfill(12)
    dep={'apiVersion':'apps/v1','kind':'Deployment','metadata':{'namespace':'dakasa','name':app,'uid':uid(1),'generation':1},'spec':{'replicas':1,'selector':{'matchLabels':labels},'template':{'metadata':{'labels':labels},'spec':{'containers':[{'name':app,'image':image}]}}},'status':{'observedGeneration':1,'readyReplicas':1,'updatedReplicas':1,'availableReplicas':1}}
    svc={'apiVersion':'v1','kind':'Service','metadata':{'namespace':'dakasa','name':app,'uid':uid(2)},'spec':{'type':'ClusterIP','clusterIP':'10.43.1.2','selector':labels,'ports':[{'protocol':'TCP','port':8081,'targetPort':8081}]}}
    pod={'metadata':{'namespace':'dakasa','name':app+'-abc123-unit','uid':uid(3),'labels':labels,'ownerReferences':[{'controller':True,'kind':'ReplicaSet','name':app+'-abc123','uid':uid(4)}]},'spec':{'containers':[{'name':app,'image':image}]},'status':{'phase':'Running','conditions':[{'type':'Ready','status':'True'}],'containerStatuses':[{'name':app,'ready':True,'restartCount':0,'containerID':'containerd://'+'3'*64,'imageID':image,'state':{'running':{'startedAt':'2026-11-10T20:00:00Z'}}}]}}
    receipt={'schema':'root_aws_original_inventory_readonly_operational_acceptance_v1','reviewed_by_root':True,'status':'QUALIFIED_IMAGE_AND_DEPLOYMENT_VERIFIED','source':cas.INVENTORY_SOURCE,'amd64_D':cas.INVENTORY_DIGEST,'namespace':'dakasa','deployment_uid':uid(1),'service_uid':uid(2),'pod_uid':uid(3),'container_id':'containerd://'+'3'*64,'provider':'aws-original-inventory-readonly','version':'1.0.0','operation':'observe_original_profile_inventory','original_profile_source_commit':cas.A3_CREATOR,'original_refs':{'qualified_image':ref('image',DECLARED_INVENTORY_MANIFEST if manifest is None else manifest),'source_ci':ref('ci',b'DECLARED complete Source-CI boundary'),'deployment':ref('deployment',dep),'service':ref('service',svc),'pod':ref('pod',pod),'describe':ref('describe',inventory_description_wire()),'health':ref('health',b'readonly observer up')}}
    pair=ref('M7-return',b'DECLARED original normal M7 return')
    core={'schema':'root_core_retirement_observer_operational_acceptance_v1','reviewed_by_root':True,'status':'QUALIFIED_IMAGE_AND_DEPLOYMENT_VERIFIED','source':cas.OLD_SOURCE,'amd64_D':cas.OLD_DIGEST,'process_replacement_ref':ref('Core6-process',b'DECLARED Core6 replacement original'),'native_observation_ref':ref('Core6-observe',b'DECLARED Core6 observation original'),'controller_pair_ref':pair,'qualified_image_and_deployment_verified':True}
    refs={role:ref(role,b'DECLARED independent historical/release original')for role in ('qualified_business_release','business_Source_CI','Root_Goose94_acceptance','Root_Goose95_acceptance','Root_Goose96_acceptance','Root_separate_rollout_review')}
    refs.update(current_Core6_operational_acceptance=ref('Core6-root9',core),inventory_readonly_operational_acceptance=ref('reader-root15',receipt))
    def read(path,*_):events.append(('read',str(path)));return bodies[Path(path)]
    def once(path,raw):events.append(('once',path.name));bodies[Path(path)]=raw
    C=types.SimpleNamespace(read=read,wire=cas.canonical,once=once,digest=cas.digest_value,loads=cas.loads)
    return C,{'acceptance_refs':refs},receipt,dep,svc,{'items':[pod]},bodies,events,core


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
        for call in (cas.main,lambda:cas.maintenance_inputs(None),lambda:cas.database_pre_read96(None,None,None,None,'BEFORE'),lambda:cas.deployment_ready_inputs(None,None),lambda:cas.inventory_reader(None,None,None,'BEFORE',None),lambda:cas.g15_acceptance(None,None,None,None,None),lambda:cas.accepted_guardian(None,None),lambda:cas.patch_once(None,None,None,None,None,0)):
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
        # Historical method ID stays in the existing283 census; operands are
        # the distinct current Core6/gen279 and future Core7 target.
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
            after=copy.deepcopy(d);after['spec']['template']['spec']['containers'][0]['image']=C.IMAGE_PREFIX+C.NEW_DIGEST;after['metadata']['annotations'].update({'dakasa.io/core-source-commit':cas.CORE_R,'kubernetes.io/change-cause':cas.CHANGE_CAUSE});after['metadata'].update(generation=cas.GENERATION+1,resourceVersion='2');cas.result_shape(d,after,C)
            bad=copy.deepcopy(after);bad['spec']['template']['spec']['containers'][0]['env']=[]
            with self.assertRaises(cas.Hold):cas.result_shape(d,bad,C)
        self.assertEqual(cas.ROOT_CORE6_SHA,'20529efa40348fa53bc625ff665a1399733530e319ce1a007c9a2804e8bfc157')
        self.assertEqual(cas.M7_RETURN_SHA,'e04f0d09bd55295664b7b7d2b62a8df4421d7b92089e360765ae4cddceb70c7c')
        with binding():
            C,c,receipt,dep,svc,pods,bodies,events,core=reader_operand()
            def ref(name,value):
                raw=value if type(value)is bytes else cas.canonical(value);p=Path('/declared/reader/'+name);bodies[p]=raw
                return {'path':str(p),'sha256':cas.sha(raw)}
            # Only immutable historical-ID/hash boundary constants are scoped
            # to declared originals; all validators/input_ref hashes are real.
            with patch.multiple(cas,ROOT_CORE6_SHA=c['acceptance_refs']['current_Core6_operational_acceptance']['sha256'],M7_RETURN_SHA=core['controller_pair_ref']['sha256']):
                self.assertEqual(cas.deployment_ready_inputs(C,c),receipt)
                self.assertEqual(set(c['acceptance_refs']),set('qualified_business_release business_Source_CI Root_Goose94_acceptance Root_Goose95_acceptance Root_Goose96_acceptance Root_separate_rollout_review current_Core6_operational_acceptance inventory_readonly_operational_acceptance'.split()))
                for fault in ('h7_source','normal_provider','wrong_operation','not_reviewed','missing_role','extra_role','wrong_original_hash'):
                    r,b=copy.deepcopy(receipt),copy.deepcopy(c)
                    if fault=='h7_source':r['source']='d8cbbf48873d24439216f98c30afe2669a525b54'
                    elif fault=='normal_provider':r['provider']='aws'
                    elif fault=='wrong_operation':r['operation']='observe_fleet_inventory'
                    elif fault=='not_reviewed':r['reviewed_by_root']=False
                    elif fault=='missing_role':r['original_refs'].pop('describe')
                    elif fault=='extra_role':r['original_refs']['callback']=r['original_refs']['health']
                    else:r['original_refs']['health']['sha256']='f'*64
                    b['acceptance_refs']['inventory_readonly_operational_acceptance']=ref('bad-reader-'+fault,r)
                    with self.subTest(reader=fault),self.assertRaises(cas.Hold):cas.deployment_ready_inputs(C,b)
                for fault in ('target_source','target_image','root96_alias','wrong_m7'):
                    old=copy.deepcopy(core);b=copy.deepcopy(c)
                    if fault=='target_source':old['source']=cas.CORE_R
                    elif fault=='target_image':old['amd64_D']=cas.NEW_DIGEST
                    elif fault=='root96_alias':old['schema']='root_goose96_guest_retirement_pre_read_continuation_acceptance_v1'
                    else:old['controller_pair_ref']['sha256']='f'*64
                    oldref=ref('bad-core6-'+fault,old);b['acceptance_refs']['current_Core6_operational_acceptance']=oldref
                    with self.subTest(old_core=fault),patch.object(cas,'ROOT_CORE6_SHA',oldref['sha256']),self.assertRaises(cas.Hold):cas.deployment_ready_inputs(C,b)
            for fault in ('config_identity','no_layers','boolean_config_size','wrong_media_type'):
                manifest=copy.deepcopy(DECLARED_INVENTORY_MANIFEST)
                if fault=='config_identity':manifest['config']['digest']='sha256:'+'f'*64
                elif fault=='no_layers':manifest['layers']=[]
                elif fault=='boolean_config_size':manifest['config']['size']=True
                else:manifest['mediaType']='application/json'
                with patch.object(cas,'INVENTORY_DIGEST',cas.sha(cas.canonical(manifest))):
                    other,config,*tail=reader_operand(manifest);oldcore=tail[-1]
                    with self.subTest(reader_manifest=fault),patch.multiple(cas,ROOT_CORE6_SHA=config['acceptance_refs']['current_Core6_operational_acceptance']['sha256'],M7_RETURN_SHA=oldcore['controller_pair_ref']['sha256']),self.assertRaises(cas.Hold):cas.deployment_ready_inputs(other,config)
            self.assertEqual(cas.inventory_objects(receipt,dep,svc,pods),'10.43.1.2')
            config=copy.deepcopy(pods);config['items'][0]['status']['containerStatuses'][0]['imageID']='containerd://sha256:'+cas.INVENTORY_CONFIG_DIGEST
            self.assertEqual(cas.inventory_objects(receipt,dep,svc,config),'10.43.1.2')
            for fault in ('foreign_pod','foreign_image_id','normal_binary','foreign_service','extra_pod','unready','wrong_owner'):
                d,s,p=copy.deepcopy(dep),copy.deepcopy(svc),copy.deepcopy(pods)
                if fault=='foreign_pod':p['items'][0]['metadata']['uid']='20000000-0000-4000-8000-000000000099'
                elif fault=='foreign_image_id':p['items'][0]['status']['containerStatuses'][0]['imageID']='sha256:'+'f'*64
                elif fault=='normal_binary':d['spec']['template']['spec']['containers'][0]['command']=['/app/integration-aws']
                elif fault=='foreign_service':s['spec']['selector']={'app':'integration-aws'}
                elif fault=='extra_pod':p['items'].append(copy.deepcopy(p['items'][0]))
                elif fault=='unready':p['items'][0]['status']['containerStatuses'][0]['ready']=False
                else:p['items'][0]['metadata']['ownerReferences'][0]['kind']='Deployment'
                with self.subTest(reader_objects=fault),self.assertRaises(cas.Hold):cas.inventory_objects(receipt,d,s,p)
            descriptions=[]
            for fault in ('h7','normal','mutations','boolean_zero','amqp','unknown'):
                d=cas.expected_inventory_description()
                if fault=='h7':d['source_commit']='d8cbbf48873d24439216f98c30afe2669a525b54'
                elif fault=='normal':d['provider']='aws'
                elif fault=='mutations':d['native_mutations']=1
                elif fault=='boolean_zero':d['native_mutations']=False
                elif fault=='amqp':d['amqp_registered']=True
                else:d['foreign_authority']=True
                descriptions.append((fault,d))
            for fault,d in descriptions:
                with self.subTest(reader_describe=fault),self.assertRaises(cas.Hold):cas.inventory_description(inventory_description_wire(d))
            valid=inventory_description_wire();outer=json.loads(valid);inner=base64.b64decode(outer['body'],validate=True)
            malformed={}
            for fault in ('unknown_outer','duplicate_outer','trailing_outer','missing_body','missing_content_type','wrong_content_type','bad_base64','unknown_inner','duplicate_inner','trailing_inner','missing_ok','false_ok','missing_normal_flag','bare_inner'):
                o=copy.deepcopy(outer);body=inner
                if fault=='unknown_outer':o['foreign_authority']=True
                elif fault=='duplicate_outer':malformed[fault]=valid.replace(b'"body":',b'"body":"unused","body":',1);continue
                elif fault=='trailing_outer':malformed[fault]=valid+b' {}';continue
                elif fault=='missing_body':del o['body']
                elif fault=='missing_content_type':del o['content_type']
                elif fault=='wrong_content_type':o['content_type']='text/plain'
                elif fault=='bad_base64':o['body']='!'
                elif fault=='unknown_inner':obj=json.loads(body);obj['foreign_authority']=True;body=cas.canonical(obj)
                elif fault=='duplicate_inner':body=body.replace(b'"ok":true',b'"ok":true,"ok":true',1)
                elif fault=='trailing_inner':body+=b' {}'
                elif fault=='missing_ok':obj=json.loads(body);del obj['ok'];body=cas.canonical(obj)
                elif fault=='false_ok':obj=json.loads(body);obj['ok']=False;body=cas.canonical(obj)
                elif fault=='missing_normal_flag':obj=json.loads(body);del obj['data']['normal_adapter_operations'];body=cas.canonical(obj)
                elif fault=='bare_inner':malformed[fault]=inner;continue
                if fault in ('unknown_inner','duplicate_inner','trailing_inner','missing_ok','false_ok','missing_normal_flag'):o['body']=base64.b64encode(body).decode('ascii')
                malformed[fault]=cas.canonical(o)
            self.assertEqual(cas.inventory_description(valid),cas.expected_inventory_description())
            for fault,wire in malformed.items():
                with self.subTest(reader_layer=fault),self.assertRaises(cas.Hold):cas.inventory_description(wire)
            calls=[]
            class API:
                def request(self,method,uri,body=None):
                    calls.append((method,uri));self_values={cas.INVENTORY_DEP_URI:dep,cas.INVENTORY_SVC_URI:svc,cas.INVENTORY_PODS_URI:pods}
                    if method!='GET' or uri not in self_values:raise AssertionError('not a read-only Kube metadata GET')
                    return 200,cas.canonical(self_values[uri]),{}
            class Connection:
                sock=None
                def __init__(self,address,port,timeout):
                    if (address,port,timeout)!=('10.43.1.2',8081,2):raise AssertionError('unbound reader origin/deadline')
                def request(self,method,uri,body,headers):
                    calls.append((method,uri));self.uri=uri
                    if (method,uri)==('GET','/healthz'):
                        if body is not None:raise AssertionError('health GET body')
                    elif (method,uri)==('POST','/rpc/describe'):
                        if json.loads(body)!={'provider':'aws-original-inventory-readonly','expected_version':'1.0.0','expected_source_commit':cas.INVENTORY_SOURCE}:raise AssertionError('wrong closed Describe')
                    else:raise AssertionError('SDK execute, mutation, or unreviewed path attempted')
                def getresponse(self):return types.SimpleNamespace(status=200,read=lambda cap:b'readonly observer up'if self.uri=='/healthz'else inventory_description_wire())
                def close(self):calls.append(('close',self.uri))
            with patch.object(cas.http.client,'HTTPConnection',Connection),patch.object(cas.time,'monotonic',return_value=100):
                identity=cas.inventory_reader(API(),C,Path('/declared/run'),'PRESEND',receipt)
            self.assertEqual(identity['container_id'],receipt['container_id'])
            self.assertEqual([x for x in calls if x[0]in ('GET','POST','PATCH')],[('GET',cas.INVENTORY_DEP_URI),('GET',cas.INVENTORY_SVC_URI),('GET',cas.INVENTORY_PODS_URI),('GET','/healthz'),('POST','/rpc/describe')])
            self.assertEqual(sum(x[0]=='close'for x in calls),2)

    def test_known_s8_zero_any_own_read_and_full_pending_sdk_lineage(self):
        value,case=current_pre_read_operand()
        self.assertEqual(set(case),set('retirement_request_id failed_admission_id root_admission_id destroy_grant_id expected_records_sha256 provider_lanes current_runtime_source current_generation current_fencing_token current_failed_run_id current_lease_owner'.split()))
        self.assertEqual(len(value['records']['forward_rows']),8)
        self.assertEqual(case['current_fencing_token'],57)
        self.assertLess(cas.utc(value['records']['destroy_grants'][0]['grant_record']['grant']['expires_at']),cas.utc(value['observed_at_pg']))
        self.assertTrue(cas.validate_pre_read96(value,case))
        # Original Go96 inputs remain historical rather than inheriting the
        # current CAS globals. They cannot become the current Core6 case.
        historical,historical_case=pre_read_operand()
        self.assertEqual(historical['records']['selected_runtime_source'],'33a846d31a5b123b2c1141192671bc830bf6d9c8')
        with self.assertRaises(cas.Hold):cas.validate_pre_read96(historical,historical_case)
        faults=('own_prepared','own_returned_error','own_returned_malformed','hidden_own_prepared','ancestor_own_read','missing_ack','running','unknown_job','foreign_owner','live_lease','generation_reset','counter_reset','sdk_status','sdk_action','sdk_next_action','new_delete','foreign_roster','latest_raw_failure','foreign_pending','classic_alias','missing_classic','parent_ack_clock','deadline','old_runtime_alias','raw_hash')
        for fault in faults:
            v,c=copy.deepcopy(value),copy.deepcopy(case);r=v['records']
            current=next(x for x in r['forward_rows']if x['id']==c['failed_admission_id']and x['stage']=='admitted')
            ownrun=next(x for x in r['workflow_runs']if x['id']==c['current_failed_run_id'])
            ownjob=next(x for x in r['owning_dispatch_jobs']if x['run_id']==ownrun['id'])
            if fault in ('own_prepared','own_returned_error','own_returned_malformed','hidden_own_prepared','ancestor_own_read'):
                prepared=copy.deepcopy(r['all_read_rows'][0]);readid='10000000-0000-4000-8000-000000000080'
                admission=current['original_record']['parent_admission_id']if fault=='ancestor_own_read'else current['id']
                prepared.update(id=readid,admission_id=admission,kind='inventory',recorded_at='2026-11-10T16:02:14Z')
                prepared['original_record'].update(read_id=readid,admission_id=admission,admission_sha256=current['record_sha256'],issued_at_core='2026-11-10T16:02:14Z',original_deadline_core='2026-11-10T16:02:19Z')
                r['all_read_rows'].append(prepared)
                if fault in ('own_returned_error','own_returned_malformed'):
                    raw=copy.deepcopy(r['all_read_rows'][1]);raw.update(id=readid,admission_id=admission,kind='inventory',recorded_at='2026-11-10T16:02:19Z')
                    raw['original_record']={'read':prepared['original_record'],'status':''if fault=='own_returned_error'else'unsupported-status','call_failed':fault=='own_returned_error','original_context_failed':fault=='own_returned_error','started_at_core':'2026-11-10T16:02:14Z','original_returned_at_core':'2026-11-10T16:02:19Z'}
                    r['all_read_rows'].append(raw);r['own_read_count']=2
                elif fault=='own_prepared':r['own_read_count']=1;r['unreturned_prepared']=[prepared]
                # Hidden count/open summaries cannot hide any retained row of
                # this owner or of an inherited zero-read typed predecessor.
            elif fault=='missing_ack':ownjob['finalization_ack_at']=None
            elif fault=='running':ownrun['status']='running';ownrun['finished_at']=None;ownjob.update(state='running',return_status=None,returned_at=None,finalization_ack_at=None)
            elif fault=='unknown_job':ownjob.update(state='unknown',return_status='unknown',finalization_ack_at=None)
            elif fault=='foreign_owner':r['current_intent']['intent']['lease_owner']='10000000-0000-4000-8000-000000000099'
            elif fault=='live_lease':r['current_intent']['intent']['lease_expires_at']='2026-11-10T16:07:00Z'
            elif fault=='generation_reset':r['current_intent']['intent']['generation']=30
            elif fault=='counter_reset':r['current_intent']['intent']['fencing_token']=55
            elif fault=='sdk_status':r['destroy_grants'][0]['grant_record']['settlement']['original_provider_destroy_return']['response_status']=True
            elif fault=='sdk_action':r['destroy_grants'][0]['grant_record']['settlement']['original_provider_destroy_return']['action_id']='10000000-0000-4000-8000-000000000099'
            elif fault=='sdk_next_action':r['destroy_grants'][0]['grant_record']['settlement']['original_provider_destroy_return']['next_action_ids']=['10000000-0000-4000-8000-000000000099']
            elif fault=='new_delete':extra=copy.deepcopy(r['destroy_grants'][0]);extra['id']='10000000-0000-4000-8000-000000000099';r['destroy_grants'].append(extra)
            elif fault=='foreign_roster':r['active_policies'].append({'id':'10000000-0000-4000-8000-000000000099','checksum':'f'*64})
            elif fault=='latest_raw_failure':
                ident='10000000-0000-4000-8000-000000000088'
                prep=copy.deepcopy(r['all_read_rows'][0]);prep.update(id=ident,recorded_at='2026-11-10T16:00:06Z');prep['original_record'].update(read_id=ident,issued_at_core='2026-11-10T16:00:06Z',original_deadline_core='2026-11-10T16:00:11Z')
                raw=copy.deepcopy(r['all_read_rows'][-1]);raw.update(id=ident,recorded_at='2026-11-10T16:00:07Z');raw['original_record']={'read':prep['original_record'],'status':'','call_failed':True,'original_context_failed':True,'started_at_core':'2026-11-10T16:00:06Z','original_returned_at_core':'2026-11-10T16:00:07Z'}
                r['all_read_rows'].extend((prep,raw));r['latest_reads_all_outcomes']=r['all_read_rows'][:]
            elif fault in ('foreign_pending','classic_alias'):
                for row in r['forward_rows']:
                    if row['id']==current['id']:row['original_record']['continuation']['pending_read_id'if fault=='foreign_pending'else'schema']='10000000-0000-4000-8000-000000000099'if fault=='foreign_pending'else'original_settled_absence_continuation_v1'
            elif fault=='missing_classic':r['forward_rows']=[x for x in r['forward_rows']if not(x['id']=='756a0af2-3ce3-4992-8fe2-116bb8da12cd'and x['stage']=='requested')]
            elif fault=='parent_ack_clock':
                q=next(x for x in r['forward_rows']if x['id']==current['id']and x['stage']=='requested');q['recorded_at']=q['original_record']['recorded_at']='2026-11-10T16:01:14Z'
            elif fault=='deadline':r['all_read_rows'][1]['recorded_at']=r['all_read_rows'][1]['original_record']['original_returned_at_core']='2026-11-10T16:00:09Z'
            elif fault=='old_runtime_alias':r['selected_runtime_source']='33a846d31a5b123b2c1141192671bc830bf6d9c8'
            reseal_current_pre_read(v,c)
            if fault=='raw_hash':
                r['forward_rows'][-1]['record_sha256']='f'*64
                raw=json.dumps(r,separators=(',',':'),sort_keys=True);v['records_wire']=raw;v['records_sha256']=c['expected_records_sha256']=cas.sha(raw.encode())
            with self.subTest(fault=fault),self.assertRaises(cas.Hold):cas.validate_pre_read96(v,c)
        # BEFORE/PRESEND are bound to the same complete reviewed snapshot;
        # self-consistent wire rehashing cannot replace any old SDK/original.
        changed,pinned=copy.deepcopy(value),copy.deepcopy(case)
        changed['records']['destroy_grants'][0]['grant_record']['settlement']['original_provider_destroy_return']['called_at']='2026-11-10T16:00:02.1Z'
        reseal_current_pre_read(changed,pinned,update_expected=False)
        with self.assertRaises(cas.Hold):cas.validate_pre_read96(changed,pinned)
        # Exercise the real database admission composition with declared query
        # returns. Catalog validation has its separate real cases below; no
        # query or provider operation is sent by these in-memory boundaries.
        with binding():
            full={}
            for provider in ('aws','hetzner'):
                full[provider]={**copy.deepcopy(case['provider_lanes'][provider]),'intent_identity':{'declared':provider},'owned_slots':[{'slot':1,'retained':True}],'active_policies':[{'declared':provider}],'policy_catalog_wire':'DECLARED unchanged '+provider}
            saved=cas.canonical(value);legacy=b'DECLARED existing catalog SQL'
            refs={'/declared/preimage':saved,'/declared/catalog':legacy}
            C=types.SimpleNamespace(read=lambda path,*args:refs[str(path)],digest=cas.digest_value)
            config={'pre_read_case':copy.deepcopy(case),'policy_state':{provider:{k:copy.deepcopy(full[provider][k])for k in ('intent_identity','owned_slots','active_policies','policy_catalog_wire')}for provider in full},'pre_read_preimage_ref':{'path':'/declared/preimage','sha256':cas.sha(saved)},'legacy_catalog_sql_ref':{'path':'/declared/catalog','sha256':cas.sha(legacy)}}
            sql={'queries':{'original_notify_aws_vm_members':'DECLARED AWS','original_notify_hetzner_vm_members':'DECLARED HZ'}}
            for fault in ('none','foreign_roster','new_busy_lane','changed_original_presend'):
                aws=copy.deepcopy(full['aws']);observed=copy.deepcopy(value);cfg=copy.deepcopy(config);calls=[]
                if fault=='foreign_roster':aws['owned_slots'].append({'slot':8,'foreign':True})
                elif fault=='new_busy_lane':aws['jobs_busy']=1
                elif fault=='changed_original_presend':observed['records']['current_intent']['updated_at']='2026-11-10T16:02:58Z';reseal_current_pre_read(observed,cfg['pre_read_case'])
                def query(cut,run,label,text):
                    calls.append(text)
                    if text==sql['queries']['original_notify_aws_vm_members']:return aws
                    if text==sql['queries']['original_notify_hetzner_vm_members']:return full['hetzner']
                    if text==cas.PRE_READ_SQL:return observed
                    if text=='DECLARED catalog SELECT':return {'declared':'catalog returned'}
                    raise AssertionError('new query/mutation outside reviewed four stages')
                with self.subTest(database_admission=fault),patch.object(cas,'query',side_effect=query),patch.object(cas,'catalog94_select',return_value='DECLARED catalog SELECT'),patch.object(cas,'schema96_facts')as schema:
                    invoke=lambda:cas.database_pre_read96(types.SimpleNamespace(C=C),Path('/declared/run'),cfg,sql,'PRESEND')
                    if fault=='none':
                        self.assertEqual(invoke(),case['provider_lanes']);schema.assert_called_once()
                        self.assertEqual(len(calls),5)
                    else:
                        with self.assertRaises(cas.Hold):invoke()
                        schema.assert_not_called()
        self.assertIn("'all_read_rows'",cas.PRE_READ_SQL)
        self.assertNotIn("WHERE admission_id='756a0af2",cas.PRE_READ_SQL)
        self.assertNotIn("kind='absence'",cas.PRE_READ_SQL)


        # Separate ordinary LIVE34 scenario. The terminal31 snapshot is
        # historical custody, never the current owner or read-zero authority.
        live,livecase=live_image_operand()
        terminal,target=terminal_image_operand()
        terminal_raw=cas.canonical(terminal)
        history_ref={'path':cas.S8_TERMINAL_REF['path'],'sha256':cas.sha(terminal_raw)}
        livecase['historical_s8_ref']=history_ref
        current_raw=cas.canonical(live)
        C=types.SimpleNamespace(digest=cas.digest_value,read=lambda path,*args:{history_ref['path']:terminal_raw,'/declared/current-live':current_raw}[str(path)])
        config={'schema':cas.LIVE_SCHEMA,'pre_read_case':livecase,'pre_read_preimage_ref':{'path':'/declared/current-live','sha256':cas.sha(current_raw)}}
        with patch.object(cas,'S8_TERMINAL_REF',history_ref),patch.object(cas,'S8_TERMINAL_TARGET',target):
            self.assertTrue(cas.validate_current_live(live,livecase))
            self.assertTrue(cas.validate_terminal_s8(terminal))
            self.assertTrue(cas.validate_maintenance_scenario(config,C))
            self.assertEqual(live['records']['own_read_count'],6)
            self.assertTrue(live['records']['all_read_rows'][-1]['original_record']['call_failed'])
            self.assertEqual(live['records']['all_read_rows'][-1]['original_record']['status'],'')
            self.assertNotEqual(livecase['current_generation'],target['generation'])
            for fault in ('old_epoch','unknown_mode','foreign_marker','off_copy','missing_ack','unknown_job','live_lease','open_read','missing_pair','unknown_return','sdk_status','sdk_next','unknown_destroy','foreign_binding','sdk_target','foreign_policy','zero_own_count','cross_root','return_after_ack','wire_hash'):
                v,c=copy.deepcopy(live),copy.deepcopy(livecase);r=v['records']
                if fault=='old_epoch':r['current_intent']['intent']['generation']=31
                elif fault=='unknown_mode':r['forward_rows'][0]['original_record']['mode']='settled_absence_continuation'
                elif fault=='foreign_marker':r['current_intent']['intent']['retirement_forward']['id']=target['admission_id']
                elif fault=='off_copy':r['forward_rows'][1]['original_record']['evidence']={'foreign':True}
                elif fault=='missing_ack':r['owning_dispatch_jobs'][0]['finalization_ack_at']=None
                elif fault=='unknown_job':r['owning_dispatch_jobs'][0]['state']='unknown'
                elif fault=='live_lease':r['current_intent']['intent']['lease_expires_at']='2026-11-10T16:02:00Z'
                elif fault=='open_read':r['unreturned_prepared']=[r['all_read_rows'][-2]]
                elif fault=='missing_pair':r['all_read_rows'].pop();r['own_read_count']-=1
                elif fault=='unknown_return':r['all_read_rows'][-1]['original_record']['status']='unsupported'
                elif fault=='sdk_status':r['destroy_grants'][0]['grant_record']['settlement']['original_provider_destroy_return']['response_status']=True
                elif fault=='sdk_next':r['destroy_grants'][0]['grant_record']['settlement']['original_provider_destroy_return']['next_action_ids']=['foreign']
                elif fault=='unknown_destroy':r['destroy_grants'][0]['state']=r['destroy_grants'][0]['grant_record']['grant']['state']='redeemed'
                elif fault=='foreign_binding':r['delete_bindings'][0]['intent_id']=cas.PRE_READ_TARGET['retirement_request_id']
                elif fault=='sdk_target':r['create_grants'][0]['grant_record']['settlement']['original_provider_create_return']['resource_id']='i-fffffffffffffffff'
                elif fault=='foreign_policy':r['active_policies'].append({'id':'foreign','checksum':'f'*64})
                elif fault=='zero_own_count':r['own_read_count']=0
                elif fault=='cross_root':c['retirement_request_id']=cas.PRE_READ_TARGET['retirement_request_id']
                elif fault=='return_after_ack':r['all_read_rows'][-1]['recorded_at']='2026-11-10T16:00:22Z'
                seal_image_fixture(v,c)
                if fault=='wire_hash':r['all_read_rows'][-1]['record_sha256']='f'*64;raw=json.dumps(r,sort_keys=True,separators=(',',':'));v['records_wire']=raw;v['records_sha256']=c['expected_records_sha256']=cas.sha(raw.encode())
                with self.subTest(current_live=fault),self.assertRaises(cas.Hold):cas.validate_current_live(v,c)
            for fault in ('paid_not_confirmed','sdk_unknown','proof_absence_false','missing_terminal_ack','pending_absence','foreign_terminal_ref'):
                v=copy.deepcopy(terminal);r=v['records']
                if fault=='paid_not_confirmed':r['destroy_grants'][0]['state']=r['destroy_grants'][0]['grant_record']['grant']['state']='settled'
                elif fault=='sdk_unknown':r['destroy_grants'][0]['grant_record']['settlement']['original_provider_destroy_return']['response_status']=500
                elif fault=='proof_absence_false':r['destroy_grants'][0]['grant_record']['proof']['resource_absent']=False
                elif fault=='missing_terminal_ack':r['owning_dispatch_jobs'][-1]['state']='unknown'
                elif fault=='pending_absence':r['all_read_rows'][-1]['original_record']['observation']['retirement_complete']=False
                else:
                    bad=copy.deepcopy(livecase);bad['historical_s8_ref']={'path':'/declared/foreign-S8','sha256':history_ref['sha256']}
                    with self.assertRaises(cas.Hold):cas.validate_current_live(live,bad)
                    continue
                seal_image_fixture(v)
                with self.subTest(historical_terminal=fault),self.assertRaises(cas.Hold):cas.validate_terminal_s8(v)
        # Metadata remains one exact8-op image CAS. Standalone Source need not
        # equal the independently-qualified network package, or reroll it.
        module=ast.parse(PATH.read_bytes())
        guard=[n for n in module.body if isinstance(n,ast.If)and isinstance(n.test,ast.Compare)and isinstance(n.test.left,ast.Name)and n.test.left.id=='__name__']
        self.assertEqual(len(guard),1);self.assertIs(module.body[-1],guard[0])
        self.assertEqual(cas.CAP,16<<20)
        self.assertIn("'create_grants'",cas.CURRENT_LIVE_SQL)
        self.assertIn("'all_read_rows'",cas.CURRENT_LIVE_SQL)
        self.assertNotIn("kind='absence'",cas.CURRENT_LIVE_SQL)
        with binding():
            self.assertEqual(cas.global_marker(types.SimpleNamespace(NEW_DIGEST='d'*64)).name,'CORE-IMAGE-R6-045-D85BE-TO-'+cas.CORE_R+'-'+'d'*64+'-POSSIBLE.json')

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
            self.assertIn('CORE-IMAGE-R6-045-D85BE-TO-',str(cas.global_marker(C)))
            self.assertNotIn('R5-33A-D35195',str(cas.global_marker(C)))
            cas.patch_once(API(),C,Path('/declared/run'),b'[]',{},99)
            self.assertEqual([x[0]for x in events],['durable','durable','PATCH','durable','durable'])
            self.assertEqual([x[1]for x in events[3:]],['PATCH-ACTUAL-RETURN.json','PATCH-ACTUAL-RETURN.HTTP.json'])
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
        # The sole embedded historical public Root95 original is byte-exact,
        # not a synthesized authority or a current Core7 acceptance. New Root96
        # operands below are declared semantic CI data and never published.
        prior95_raw=base64.b64decode('eyJhbWQ2NF9EIjoiMzUxOTVlNGRkZmYyYTY5ZjJhZTdmY2E4ZjI0YjQzMTc3YzYxYzQ5ZjEyMTE3YTRmZTQ5MjVhNDNlOWNkNmZkZSIsImJ1c2luZXNzX3NvdXJjZSI6IjMzYTg0NmQzMWE1YjEyM2IyYzExNDExOTI2NzFiYzgzMGJmNmQ5YzgiLCJjYXRhbG9nOTBfOTFfc2hhMjU2IjoiNmMwZTc2MDhkOTMxNGM3MGQ3NWVmNDA4NzJlODVlYWUyNGRlODNlYTBkZTg4MWVlOTAyMTVmOWE5ZDlhMGUxNiIsImNhdGFsb2c5NV9zaGEyNTYiOiJlOTE0ZTM3OThlZWU5YzAzMzBmMGNjNTk0NWNjMTExMzRhOTQ3Yjc2OTk5Zjg3MjBhNTZmMDY1NWI2MDE4NDc1IiwiY29tcGxldGVfaGlzdG9yeV9zaGEyNTYiOiJiNmM2ZTg3OTc4YzVhZGY5ZDYxMGZlNWJmMjRkOTVjZmY2OTdkM2I3ZjQyMzlkOGYzNjZiOTk0MjMzYTcxMTM5IiwiY3VycmVudF9jb3JlX3NvdXJjZSI6IjdjZDVjZWEwODM0YmNlZTkwMWMyODJiYzgxYjk0ODZkNWMxNjUxM2IiLCJjdXJyZW50X29wc19zb3VyY2UiOiI4NWJlNDllY2RjNGM1NjEwZjU3ZGMxMzMxYTU3ODFmMzc3MjFkNmQyIiwiZXhpdF9jb2RlIjowLCJpbmRleDkyX2RlZmluaXRpb25fc2hhMjU2IjoiZTEyOTdhMDhhYzgwOWY2YjljMWNmMDlhNGZmYzE3ZGYxNzgyMWQwMWU5YmQ3ODc0MzRmZjUyYzZkNjMyNDQyNiIsImpvYl91aWQiOiJiYWE1MGFkYy02NTBmLTQyY2UtOTY2ZS1jZjEzYzQzOTZlMGMiLCJtaWdyYXRpb245NV9zaGEyNTYiOiI1MGYyZjFmNzEyYTkxYWJmM2NjZDE3ZDBmYjIwNDBkMzBiNGJkMmM2NDU1MjY4OTAyZTE0NTJlOTIyYTk0ODA4Iiwib2xkX3JlY29yZHNfYW5kX3Nka19wcmVzZXJ2ZWQiOnRydWUsIm9yaWdpbmFsX3JlZnMiOnsiYWZ0ZXJfY2F0YWxvZyI6eyJwYXRoIjoiL3Zhci9saWIvZGFrYXNhLWNvcmUtcm9sbG91dC9nb29zZTk1LWZhaWxlZC1leHBhbnNpb24tcmVhZC1jb250aW51YXRpb24vbWlncmF0aW9uOTUtNDFkZGRiYzUtNzJhMi00MDBlLWE5ZDAtNDhiY2Q0NzVjYTcwL0FGVEVSLUNBVEFMT0cuc3Rkb3V0Iiwic2hhMjU2IjoiZmY2NDQ1Zjg0M2E2N2I5NjkzNWQ3ZTkzNGIxMDkxZmQ4MDdhYzI0NGRmODdlM2U2ZmU0YWUzY2FkYTg2ZjFjMCJ9LCJiZWZvcmVfY2F0YWxvZyI6eyJwYXRoIjoiL3Zhci9saWIvZGFrYXNhLWNvcmUtcm9sbG91dC9nb29zZTk1LWZhaWxlZC1leHBhbnNpb24tcmVhZC1jb250aW51YXRpb24vbWlncmF0aW9uOTUtNDFkZGRiYzUtNzJhMi00MDBlLWE5ZDAtNDhiY2Q0NzVjYTcwL0JFRk9SRS1DQVRBTE9HLnN0ZG91dCIsInNoYTI1NiI6IjY0Y2E5ZTBhZDcwZmIwNzQxOGMzMjVlZmQ1ZDQ0YWNhNWMxMzliMjJmNzZlMjU0NWNhNjIwMzZjNTJmMDczYmYifSwibWlncmF0aW9uX3Jlc3VsdCI6eyJwYXRoIjoiL3Zhci9saWIvZGFrYXNhLWNvcmUtcm9sbG91dC9nb29zZTk1LWZhaWxlZC1leHBhbnNpb24tcmVhZC1jb250aW51YXRpb24vbWlncmF0aW9uOTUtNDFkZGRiYzUtNzJhMi00MDBlLWE5ZDAtNDhiY2Q0NzVjYTcwL1JFVFVSTi5QVUJMSUMuanNvbiIsInNoYTI1NiI6ImUxNDc0NDZhNzA2MjQzNmU2MjJkNTNlMDRkOGQ0Y2I2ZTYyMGUxMTM0NDZmZmMyMTA0NjE5MzNjNTJiMDI5ZTMifSwicXVhbGlmaWVkX2ltYWdlIjp7InBhdGgiOiIvdmFyL2xpYi9kYWthc2EtY29yZS1yb2xsb3V0L2cxNHBhaXIvZ29vc2U5NS1yNS1pbnB1dHMtYjY4NDcxN2UtYzJkMC00N2RiLWE1ZDYtYTVmZWEzMjRhNDJkL1JFR0lTVFJZLUlNQUdFLkVYSVNUSU5HLUFCSS5ST09ULmpzb24iLCJzaGEyNTYiOiI2ZDVhZGU1ZTA1M2UyNGI3ZTEwODM4MTdiNWE3NTA2NmY2N2MyZWMzODJmMjdiNjM5MjIzZjgyMmZlN2VjZDc3In0sInNvdXJjZV9jaSI6eyJwYXRoIjoiL3Zhci9saWIvZGFrYXNhLWNvcmUtcm9sbG91dC9nMTRwYWlyL2dvb3NlOTUtcjUtaW5wdXRzLWI2ODQ3MTdlLWMyZDAtNDdkYi1hNWQ2LWE1ZmVhMzI0YTQyZC9SNS1TT1VSQ0UtQ0ktQUNDRVBUQU5DRS5QVUJMSUMuanNvbiIsInNoYTI1NiI6IjVkMzE2YzRlNmQ1ODhkODJiNDM2ZDBlNmM2ZDdkMDEyNDkwYmE0NmUzYzY5YmYxZDA2YzM3NjVhMDE2N2EyZmMifX0sInBvZF91aWQiOiJmNDM5ODk4NC0zM2VhLTQwYWYtODBjMi1kYjBiMGFkODY3NDAiLCJwcmlvcjk0X2hpc3Rvcnlfc2hhMjU2IjoiMWE2ODdmYmFhNjc2NzllYTc3YmViZjNjZTI0YTY5MGFlY2RkYTUyZDY5ZjM3YWYxYzU3YWIwMmRkYTc0MWI3MiIsInByb3ZpZGVyX2d1ZXN0X2NvcmVfbXV0YXRpb25zIjowLCJyZXZpZXdlZF9ieV9yb290Ijp0cnVlLCJzY2hlbWEiOiJyb290X2dvb3NlOTVfZmFpbGVkX2V4cGFuc2lvbl9yZWFkX2NvbnRpbnVhdGlvbl9hY2NlcHRhbmNlX3YxIiwic2NoZW1hX2FmdGVyIjo5NSwic2NoZW1hX2JlZm9yZSI6OTQsInNpbmdsZV9qb2JfY3JlYXRlIjp0cnVlfQo=',validate=True)
        self.assertEqual(cas.sha(prior95_raw),'b80ec307962a67b8a28722c8fbf88add02c25de08847253fbae7838de1c0153d')
        prior95=json.loads(prior95_raw);originals={}
        def read_ref(ref):
            raw=originals[ref['path']]
            self.assertEqual(cas.sha(raw),ref['sha256']);return raw
        def original(role):
            raw=cas.canonical({'declared_complete_original':role});path='/declared/Root96/'+role;originals[path]=raw
            return {'path':path,'sha256':cas.sha(raw)}
        pins={'current_ops_source':cas.ROOT96_HISTORICAL_OPS_SOURCE,'business_source':cas.ROOT96_HISTORICAL_BUSINESS_SOURCE,'amd64_D':cas.ROOT96_HISTORICAL_AMD64_D,'complete_history_sha256':'a'*64,'prior95_history_sha256':prior95['complete_history_sha256'],'catalog96_sha256':'b'*64,'index92_definition_sha256':prior95['index92_definition_sha256'],'catalog90_91_sha256':'c'*64}
        root96={'schema':'root_goose96_guest_retirement_pre_read_continuation_acceptance_v1','reviewed_by_root':True,'schema_before':95,'schema_after':96,'current_core_source':prior95['business_source'],'current_ops_source':pins['current_ops_source'],'business_source':pins['business_source'],'amd64_D':pins['amd64_D'],'migration96_sha256':cas.M96,'complete_history_sha256':pins['complete_history_sha256'],'prior95_history_sha256':pins['prior95_history_sha256'],'catalog96_sha256':pins['catalog96_sha256'],'index92_definition_sha256':pins['index92_definition_sha256'],'catalog90_91_sha256':pins['catalog90_91_sha256'],'job_uid':'30000000-0000-4000-8000-000000000001','pod_uid':'30000000-0000-4000-8000-000000000002','exit_code':0,'single_job_create':True,'provider_guest_core_mutations':0,'old_records_and_sdk_preserved':True,'original_refs':{role:original(role)for role in ('migration_result','before_catalog','after_catalog','source_ci','qualified_image')}}
        self.assertEqual(cas.ROOT96_SHA,'c44e5ef3554ee494001815358434119c31832977db90a44eb925097df137c9d6')
        self.assertEqual((pins['business_source'],pins['amd64_D'],pins['current_ops_source']),('045176d16947555ccbc33a8b51635b08d2d9270e','85be238c7f5b15760f7eb903646cc48f6b4b86a6995d0a4727a1ba0d86d06876','33873025539cfb5691154fb8ded4fc4fd94eaf94'))
        self.assertEqual(cas.root96_overlay(cas.canonical(root96),prior95_raw,pins,read_ref),root96)
        for fault in ('target_source','target_digest','new_ops_alias','wrong_schema','provider_effect','missing_original','extra_original','not_reviewed'):
            bad=copy.deepcopy(root96)
            if fault=='target_source':bad['business_source']='f'*40
            elif fault=='target_digest':bad['amd64_D']='f'*64
            elif fault=='new_ops_alias':bad['current_ops_source']='f'*40
            elif fault=='wrong_schema':bad['schema']='root_core_retirement_observer_operational_acceptance_v1'
            elif fault=='provider_effect':bad['provider_guest_core_mutations']=1
            elif fault=='missing_original':bad['original_refs'].pop('before_catalog')
            elif fault=='extra_original':bad['original_refs']['current_core7']=next(iter(bad['original_refs'].values()))
            else:bad['reviewed_by_root']=False
            with self.subTest(historical96=fault),self.assertRaises(cas.Hold):cas.root96_overlay(cas.canonical(bad),prior95_raw,pins,read_ref)
        source=ast.parse(PATH.read_text());schemafn=next(n for n in source.body if isinstance(n,ast.FunctionDef)and n.name=='schema96_facts')
        historical_pin_names={n.id for n in ast.walk(schemafn)if isinstance(n,ast.Name)and n.id.startswith('ROOT96_HISTORICAL_')}
        self.assertEqual(historical_pin_names,{'ROOT96_HISTORICAL_OPS_SOURCE','ROOT96_HISTORICAL_BUSINESS_SOURCE','ROOT96_HISTORICAL_AMD64_D'})
        old=(ROOT/'rollout/core_image_cas_once_g14.py').read_text();new=PATH.read_text()
        def spans(s):return {n.name:ast.get_source_segment(s,n)for n in ast.parse(s).body if isinstance(n,(ast.FunctionDef,ast.ClassDef))}
        a,b=spans(old),spans(new)
        for name in ('API','operation_lock','read','api_read','result_shape','query','workflow_busy_logical_index92_sql','catalog_sql','catalog_projection','catalog_select','catalog94_projection','catalog94_select','patch_once','validated_config_ref','require_bound','utc'):self.assertEqual(a[name],b[name],name)
        self.assertIn("statement_timeout='3s'",b['query']);self.assertIn("lock_timeout='500ms'",b['query']);self.assertIn('timeout=8',b['query'])
        self.assertIn("'b80ec307962a67b8a28722c8fbf88add02c25de08847253fbae7838de1c0153d'",b['root96_overlay']);self.assertNotIn('Root_Goose95_acceptance',b['root96_overlay'])
