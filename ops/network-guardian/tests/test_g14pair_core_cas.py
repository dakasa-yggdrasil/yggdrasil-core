"""Declared G14 CAS data only; never OCI, Root approval or native evidence. No target functions are executed during Source preparation."""
import ast
import base64
import contextlib
import copy
import datetime as declared_datetime
import json
from pathlib import Path
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / 'rollout/core_image_cas_once_g14.py'
cas = types.ModuleType('declared_g14_core_cas_CI')
cas.__file__ = str(PATH)
exec(compile(PATH.read_bytes(), str(PATH), 'exec'), cas.__dict__)


@contextlib.contextmanager
def binding():
    """Declared operands only; no validator or filesystem function is bypassed."""
    with patch.multiple(cas, SOURCE_BOUND=True, CORE_R='c'*40, NEW_DIGEST='d'*64,
        SOURCE_PIN='a'*64, G14_OPS_P='e'*40, TOOL_PINS={n:'a'*64 for n in ('pair_change_contract.py','derive_g14pair_controller_config.py','derive_standing_config.py','g14cut.py')},
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
    d = {'apiVersion':'apps/v1','kind':'Deployment','metadata':{'namespace':'dakasa','name':'yggdrasil','uid':cas.UID,'generation':277,'resourceVersion':'1','annotations':{'dakasa.io/core-source-commit':cas.OLD_SOURCE,'retain':'declared'}},
        'spec':{'replicas':1,'template':{'spec':{'containers':[{'name':'core','image':image,'env':[{'name':'DECLARED','value':'unchanged'}],'resources':{'limits':{'cpu':'1'}}}]}}},
        'status':{'observedGeneration':277,'readyReplicas':1,'updatedReplicas':1,'availableReplicas':1}}
    ps = {'items':[{'metadata':{'uid':cas.OLD_POD,'name':'declared-r4'},'spec':{'containers':[{'name':'core','image':image}]},'status':{'phase':'Running','podIP':'192.0.2.1','containerStatuses':[{'name':'core','ready':True,'restartCount':0,'state':{'running':{'startedAt':'2026-11-04T16:00:00Z'}},'imageID':image,'containerID':'containerd://'+'b'*64}]}}]}
    return d, ps, c





def a3_operand():
    """Declared storage originals; no actual Root approval or provider evidence."""
    lease, finished, observed = '2026-11-05T00:25:12.260723Z','2026-11-05T00:20:14.370000Z','2026-11-05T09:00:00Z'
    ids = {k:'11111111-1111-4111-8111-111111111111' for k in ('workflow_id','lease_owner','executor_id')}
    p = {**ids,'preregistration_id':cas.A3_PRE,'original_create_grant_id':cas.A3_GRANT,'original_create_request_sha256':'5'*64,'slot':2,
         'policy_id':cas.A3_POLICY,'policy_checksum':'6'*64,'generation':22,'fence':43,'binding_name':'declared-s2',
         'original_deadline':'2026-11-05T00:25:09Z','reserved_at':'2026-11-05T00:20:10Z'}
    wire = cas.canonical(p)
    grb={'mutation_binding_name':'declared','members':[{'slot':1,'name':'declared-s1'},{'slot':2,'name':'declared-s2'}]}
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
    intent = {'generation':22,'fencing_token':44,'phase':'preparing','lease_owner':'1ae59626-0bbf-443c-ab8a-077281339abe','lease_executor_id':'24304589-a1fb-4abb-bf5a-85923cab995e','lease_expires_at':'2026-11-05T08:21:09.746607Z',
              'failed_unwitnessed_expansion_cleanup_id':cas.CLEANUP_ID,
              'baseline_snapshot':{'units':1},'assessment':{'snapshot':{'units':1}},'decision':{'units':2,'reason':'failed_unwitnessed_expansion_cleanup'},'policy_id':cas.A3_POLICY,'policy_checksum':'6'*64}
    w = {'id':cas.A3_RUN,'status':'failed','finished_at':finished,'result':{'steps':[{'status':'failed','metadata':{'original_guest_refusal_predicate':'original-guest-step-25'}}]}}
    enrollment = {'preregistration_id':'22222222-2222-4222-8222-222222222222','enrollment_record':{'statement':{'tuple':{'resource_id':cas.S1_RESOURCE,'resource_created_at':cas.S1_BIRTH}}}}
    survivor = {'slot':1,'resource_id':cas.S1_RESOURCE,'slot_record':{'resource_created_at':cas.S1_BIRTH,'resource_id':cas.S1_RESOURCE,'tombstone':False},
                'integration_instance_id':'declared-instance','scope_checksum':'7'*64,'profile_name':'declared',
                'enrollments':[{'enrollment':enrollment,'witness':{'preregistration_id':enrollment['preregistration_id']},'installation':{'preregistration_id':enrollment['preregistration_id']}}]}
    value = {'observed_at_pg':observed,'intent_pgtext':cas.canonical(intent).decode(),'run_pgtext':cas.canonical(w).decode(),'grant_pgtext':cas.canonical(gr).decode(),
             # Dispatch authority is independent of capacity's fence/owner.
             'dispatch':[{'id':cas.A3_JOB,'run_id':cas.A3_RUN,'state':'returned','return_status':'failed','fencing_token':1,'lease_owner':'different-dispatch-owner',
                          'envelope':{'workflow':{'id':ids['workflow_id']}},'returned_at':finished,'finalization_ack_at':'2026-11-05T00:20:14.389Z','lease_expires_at':lease}],
             'preregistration':{'id':cas.A3_PRE,'create_grant_id':cas.A3_GRANT,'original_wire':'\\x'+wire.hex(),'binding_wire':'\\x'+cas.canonical(grb).hex(),'preregistration_record':p,'original_deadline':p['original_deadline']},
             'active_policy':{'id':cas.A3_POLICY,'kind':'capacity_policy','active':True,'checksum':'6'*64},'survivors':[survivor],
             **{k:[] for k in ('target_witnesses','target_enrollments','target_installations','target_retirements','factory_bindings','compensations')},
             'cleanup_admissions':[{'id':cas.CLEANUP_ID,'grant_id':cas.A3_GRANT,'child_grant_id':cas.CHILD_ID}]}
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
                     'result':result,'language':'plpgsql','volatility':'s' if stable else 'v','config':None,'body':body,'definition':'DECLARED pg_get_functiondef with literal body:'+body})
    return rows


def cleanup_operand(value):
    """Declared selected storage frames only; never actual provider/Root proof."""
    parent=cas.loads(value['grant_pgtext']); sdktext=cas.canonical(parent['grant_record']['settlement']['original_provider_create_return']).decode()
    owner={'generation':22,'fencing_token':44,'lease_owner':'1ae59626-0bbf-443c-ab8a-077281339abe','executor_id':'24304589-a1fb-4abb-bf5a-85923cab995e','lease_expires_at':'2026-11-05T08:21:09.746607Z'}
    aux=[{'kind':'aws_ebs_volume','id':'vol-0123456789abcdef0','requires_absence':True},{'kind':'aws_network_interface','id':'eni-0123456789abcdef0','requires_absence':True}]
    grant={'grant_id':cas.CHILD_ID,'state':'settled','compensation_of':'','request_sha256':'9'*64,'expected_resource_id':cas.A3_RESOURCE,'expected_resource_created_at':cas.A3_BIRTH,'expires_at':'2026-11-05T08:17:15.211Z'}
    destroy={'schema':'aws_original_terminate_instances_return_v1','provider':'aws','adapter_source_commit':cas.A3_CREATOR,'grant_id':cas.CHILD_ID,'attempt_id':'44444444-4444-4444-8444-444444444444','request_sha256':grant['request_sha256'],'resource_id':cas.A3_RESOURCE,'resource_created_at':cas.A3_BIRTH,'action_id':'55555555-5555-4555-8555-555555555555','called_at':'2026-11-05T08:16:16.100Z','returned_at':'2026-11-05T08:16:16.200Z','context_deadline':'2026-11-05T08:17:15.211Z','response_status':200,'response_body_sha256':'b'*64,'response_bytes':19,'next_action_ids':[]}
    settled={'grant_id':cas.CHILD_ID,'attempt_id':destroy['attempt_id'],'request_sha256':grant['request_sha256'],'observed_at':destroy['returned_at'],'next_action_ids':[],'outcome':'accepted','transport_completed':True,'resource_id':cas.A3_RESOURCE,'resource_created_at':cas.A3_BIRTH,'action_id':destroy['action_id'],'auxiliary_resources':aux,'auxiliary_inventory_complete':True,'original_provider_destroy_return':destroy}
    child={'id':cas.CHILD_ID,'state':'settled',cas.CHILD_COLUMN:cas.CLEANUP_ID,'grant_record':{'grant':grant,'attempt_id':destroy['attempt_id'],'created_at':'2026-11-05T08:16:15.211Z','settlement':settled}}
    receipt={'grant':copy.deepcopy(grant),'attempt_id':destroy['attempt_id'],**{k:copy.deepcopy(settled[k]) for k in ('outcome','transport_completed','resource_id','resource_created_at','action_id','auxiliary_resources','auxiliary_inventory_complete')}}
    admission={'id':cas.CLEANUP_ID,'grant_id':cas.A3_GRANT,'child_grant_id':cas.CHILD_ID,'job_id':cas.A3_JOB,'run_id':cas.A3_RUN,'preregistration_id':cas.A3_PRE,'resource_id':cas.A3_RESOURCE,'resource_created_at':cas.A3_BIRTH,'slot':2,'survivor_count':1,'original_SDK_return_sha256':cas.sha(sdktext.encode())}
    aw=cas.canonical(admission); a={'id':cas.CLEANUP_ID,'grant_id':cas.A3_GRANT,'child_grant_id':cas.CHILD_ID,'original_record':admission,'admission_sha256':cas.sha(aw),'wire_hex':aw.hex()}
    prior={'schema':'failed_unwitnessed_expansion_native_read_v1','kind':'absence','read_id':'66666666-6666-4666-8666-666666666666','cleanup_id':cas.CLEANUP_ID,'child_grant_id':cas.CHILD_ID,'admission_sha256':a['admission_sha256'],'claim_sequence':2,'issued_at_core':'2026-11-05T08:17:12.736Z','original_deadline_core':'2026-11-05T08:17:14.290Z'}
    read={**prior,'read_id':'77777777-7777-4777-8777-777777777777','issued_at_core':'2026-11-05T08:17:14.197Z','original_deadline_core':'2026-11-05T08:17:14.290Z'}
    observation={'server_absent':True,'server_absence_complete':True,'auxiliary_inventory_complete':True,'hold_reasons':['aws_network_interface_still_present'],'auxiliary_resources':[{'kind':r['kind'],'id':r['id'],'absent':r['kind']=='aws_ebs_volume'} for r in aux]}
    encoded=lambda raw:base64.b64encode(raw).decode()
    pw=cas.canonical(receipt);rw=cas.canonical(prior)
    h={'schema':'original_settled_retirement_absence_read_return_v1','observer_source_commit':'d8cbbf48873d24439216f98c30afe2669a525b54','original_adapter_source_commit':cas.A3_CREATOR,'read_id':prior['read_id'],'read_sha256':cas.sha(rw),'original_receipt_sha256':cas.sha(pw),'observation':observation}
    good={'schema':'failed_unwitnessed_expansion_native_return_v1','status':'observed','call_failed':False,'original_context_failed':False,'pending':True,'complete':False,'read':prior,'read_wire':encoded(rw),'receipt':copy.deepcopy(receipt),'receipt_wire':encoded(pw),'observation':observation,'observer_source_commit':h['observer_source_commit'],'original_observer_return':encoded(cas.canonical(h))}
    failed={'schema':good['schema'],'status':'','call_failed':True,'original_context_failed':True,'pending':False,'complete':False,'read':read,'read_wire':encoded(cas.canonical(read)),'receipt':copy.deepcopy(receipt),'receipt_wire':encoded(pw),'started_at_core':'2026-11-05T08:17:14.198Z','returned_at_core':'2026-11-05T08:17:14.291Z'}
    events=[]
    for seq,stage,evidence,at in [(2,'claimed',None,'2026-11-05T08:16:09.746Z'),(133,'pending_absence',good,'2026-11-05T08:17:13.069Z'),(134,'absence_prepared',read,'2026-11-05T08:17:14.091Z'),(135,'absence_returned',failed,'2026-11-05T08:17:14.301Z')]:
        record={**owner,'cleanup_id':cas.CLEANUP_ID,'child_grant_id':cas.CHILD_ID,'run_id':cas.CLEANUP_RUN,'sequence':seq,'stage':stage,'recorded_at':at}
        if evidence is not None:record['evidence']=copy.deepcopy(evidence)
        wire=cas.canonical(record);events.append({'sequence':seq,'stage':stage,'run_id':cas.CLEANUP_RUN,'child_grant_id':cas.CHILD_ID,'cleanup_id':cas.CLEANUP_ID,'recorded_at':at,'original_record':record,'wire_hex':wire.hex(),'event_sha256':cas.sha(wire)})
    v={'observed_at_pg':'2026-11-05T09:00:00Z','admissions':[a],'events':events,'intent':cas.loads(value['intent_pgtext']),'parent':parent,'parent_sdk_pgtext':sdktext,'child':child,'workflow_run':{'id':cas.CLEANUP_RUN,'status':'failed','finished_at':'2026-11-05T08:17:14.321Z'},'dispatch':[{'run_id':cas.CLEANUP_RUN,'state':'returned','return_status':'failed','returned_at':'2026-11-05T08:17:14.321Z','finalization_ack_at':'2026-11-05T08:17:14.341Z'}]}
    case={'cleanup_id':cas.CLEANUP_ID,'child_grant_id':cas.CHILD_ID,'owning_run_id':cas.CLEANUP_RUN,'latest_sequence':135,'lease_expires_at':owner['lease_expires_at'],'provider_lanes':{p:{'jobs_busy':0,'runs_busy':0,'forward_unreturned_reads':0,'live_unreturned_canaries':0,'intent_count':1,'intent_busy':1 if p=='aws' else 0,'pending_authority':2 if p=='aws' else 0,'forward_markers':0} for p in ('aws','hetzner')}}
    return v,case


def reseal_cleanup_rows(value):
    """Reseal DECLARED local vectors to test semantic joins past wire hashing."""
    for row,pin in [(value['admissions'][0],'admission_sha256')]+[(e,'event_sha256') for e in value['events']]:
        wire=cas.canonical(row['original_record']);row['wire_hex']=wire.hex();row[pin]=cas.sha(wire)


def schema95_operand():
    """Actual SQL Source bodies; every PG/Root row below is declared CI data."""
    import re
    history=[{'id':i+1,'version_id':n,'is_applied':True} for i,n in enumerate([0]+[n for n in range(1,96) if n!=40])]
    facts={'database':'yggdrasil','readonly':'on','history_max_version':95,'latest_versions':[r['version_id'] for r in history],'rows90':1,'rows91':1,'rows92':1,'complete_history_wire':json.dumps(history),'catalog90':{},'catalog91':{},'other_migrators_ddl':0,'other_cic':0,'ddl_locks':0}
    catalog={'tables':[{'name':n} for n in ('public.capacity_failed_unwitnessed_expansion_cleanups','public.capacity_failed_unwitnessed_expansion_cleanup_events','public.capacity_mutation_grants','public.capacity_intents')],'columns':[{'table':'public.capacity_intents','name':'intent','type':'jsonb'}],'constraints':[{'table':'public.capacity_intents','name':'capacity_intents_pkey','validated':True,'definition':'DECLARED unchangedPK'}],'indexes':[{'table':'public.capacity_intents','name':'public.capacity_intents_pkey','valid':True,'ready':True,'live':True,'definition':'DECLARED unchangedIndex'}],'triggers':[{'table':'public.capacity_intents','name':cas.M94_INTENT_TRIGGER,'enabled':'O','function':'public.guard_failed_unwitnessed_expansion_cleanup_intent()','definition':cas.M94_INTENT_TRIGGER_DEFINITION}],'functions':source94_rows()}
    prior={'legacy':copy.deepcopy(facts),'supplement':{'columns90_91':[],'functions93':[],'index92_valid':True,'index92_definition':'declared'},'schema94':catalog}
    current=copy.deepcopy(prior)
    raw=(ROOT.parents[1]/'db/migrations/00095_failed_expansion_read_failure_continuation.sql').read_bytes()
    if cas.sha(raw)!=cas.M95_MIGRATION_SHA:raise AssertionError('exact Source95 migration required')
    match=re.search(r'CREATE OR REPLACE FUNCTION public\.guard_failed_unwitnessed_expansion_cleanup_event\(\) RETURNS trigger LANGUAGE plpgsql AS \$\$(.*?)\$\$;',raw.decode().split('-- +goose Down')[0],re.S)
    if match is None:raise AssertionError('exact95eventguard Source')
    for row in current['schema94']['functions']:
        if row['name']=='guard_failed_unwitnessed_expansion_cleanup_event':
            row['definition']=row['definition'].replace(row['body'],match.group(1),1);row['body']=match.group(1)
    old_projection=cas.catalog94_projection(prior);projection=cas.catalog94_projection(current)
    refs={}
    def ref(name,raw,expected=None):
        path='/declared/'+name;refs[path]=raw;return {'path':path,'sha256':expected or cas.sha(raw)}
    prior93=ref('prior93',json.dumps(history[:-2]).encode());prior94=ref('prior94',json.dumps(history[:-1]).encode())
    catalog94=ref('catalog94',cas.canonical(old_projection));catalog95=ref('catalog95',cas.canonical(projection))
    pins={'complete_history_sha256':cas.sha(facts['complete_history_wire'].encode()),'index92_definition_sha256':cas.sha(b'declared'),'catalog90_91_sha256':cas.sha(cas.canonical({'catalog90':{},'catalog91':{}})),'schema94_catalog_sha256':catalog94['sha256'],'schema95_catalog_sha256':catalog95['sha256']}
    common={'reviewed_by_root':True,'schema_before':94,'schema_after':95,'current_core_source':cas.OLD_SOURCE,'current_ops_source':cas.G14_OPS_P,'business_source':cas.CORE_R,'amd64_D':cas.NEW_DIGEST,'complete_history_sha256':pins['complete_history_sha256'],'index92_definition_sha256':pins['index92_definition_sha256'],'catalog90_91_sha256':pins['catalog90_91_sha256'],'job_uid':'11111111-1111-4111-8111-111111111111','pod_uid':'22222222-2222-4222-8222-222222222222','exit_code':0,'single_job_create':True,'provider_guest_core_mutations':0,'old_records_and_sdk_preserved':True,'original_refs':{n:ref(n,b'DECLARED original; not operational evidence') for n in ('migration_result','before_catalog','after_catalog','source_ci','qualified_image')}}
    root94={**copy.deepcopy(common),'schema':'root_goose94_failed_unwitnessed_expansion_cleanup_acceptance_v1','schema_before':93,'schema_after':94,'business_source':cas.OLD_SOURCE,'amd64_D':cas.OLD_DIGEST,'migration94_sha256':cas.M94_MIGRATION_SHA,'complete_history_sha256':prior94['sha256'],'prior93_history_sha256':prior93['sha256'],'catalog94_sha256':pins['schema94_catalog_sha256']}
    root95={**copy.deepcopy(common),'schema':'root_goose95_failed_expansion_read_continuation_acceptance_v1','migration95_sha256':cas.M95_MIGRATION_SHA,'prior94_history_sha256':prior94['sha256'],'catalog95_sha256':pins['schema95_catalog_sha256']}
    # Interface-isolated schema fixture: retain the real immutable REF pin,
    # while the input_ref stub returns explicitly DECLARED schema data.
    r94=ref('root94',cas.canonical(root94),'3ad88f1ada8cc96db0d6c6b0c3844a4de070e18f458cd6b053ab3a468b90c5e4');r95=ref('root95',cas.canonical(root95))
    config={'schema_pins':pins,'prior93_history_ref':prior93,'prior94_history_ref':prior94,'schema94_catalog_ref':catalog94,'schema95_catalog_ref':catalog95,'acceptance_refs':{'Root_Goose94_acceptance':r94,'Root_Goose95_acceptance':r95}}
    legacy={'schema_facts':facts,'index89_valid':True,'index92_valid':True,'index92_definition':'declared'}
    return config,legacy,current,refs,ref,root94,root95


def repair_acceptance_operand():
    """Trusted-helper interface isolation; no actual repair or Root evidence."""
    events=[]
    ctrl={'boot_id':'11111111-1111-4111-8111-111111111111','pid':2,'start_ticks':3,'InvocationID':'1'*32,'ExecMainStartTimestampMonotonic':'4'}
    guard={**ctrl,'pid':5,'start_ticks':6,'InvocationID':'2'*32,'ExecMainStartTimestampMonotonic':'7'}
    protected=cas.required_protected_refs()
    folder=Path('/declared/package');run=Path('/declared/run');standing=b'DECLARED standing'
    ledger=Path('/declared/ledger');full=copy.deepcopy(ctrl)
    full_path=ledger/'declared-key-QUALIFIED.PUBLIC.json'
    own_path=ledger/(guard['boot_id']+'-GUARDIAN-'+guard['InvocationID']+'-FIRST-CURRENT15-RETURN.PUBLIC.json')
    measurement={'qualified_15_seconds':True,'all_requested_rows_accounted_for':True}
    kernel={'all_four_backends_and_reverse_sources_positive':True}
    own={'schema':'Root_owning_finite512_current15_readonly_observation_v1','source_sha256':cas.SOURCE_PIN,'standing_config_sha256':cas.sha(standing),'identity':full,'measurement':measurement,'kernel':kernel}
    originals={n:{'path':'/declared/'+n,'sha256':'a'*64} for n in ('claim','hold','before','standing','failed_guardian_descriptor','controller_commit')}
    originals['native_commands']={}
    repair={'schema':'g14_guardian_source_forward_repair_evidence_v1','failed_swap_manifest_sha256':'b'*64,'failed_swap_originals':originals,'failed_guardian_restart_count':3,'repair_claim_ref':{'path':'/declared/repair-claim','sha256':'a'*64},'repair_helper_ref':{'path':'/declared/g14_guardian_source_repair_once.py','sha256':'c'*64}}
    result={'source_commit':'e'*40,'source_R':cas.CORE_R,'amd64_D':cas.NEW_DIGEST,'new_guardian_source_sha256':cas.SOURCE_PIN,'controller_config_sha256':'f'*64,'independent_current15':True,'all_inherited_budget_and_original_refs_unchanged':True,'Core_Cold_Hub_or_provider_mutation':False,'conservative_per_role_gap_seconds':{'controller':0,'guardian':0},'standing_sha256':cas.sha(standing),'controller':ctrl,'guardian':guard,'actual_new_full120_ref':{'path':str(full_path),'sha256':cas.sha(b'DECLARED full120')},'own_daemon_first_current15_ref':{'path':str(own_path),'sha256':cas.sha(cas.canonical(own))},'guardian_restart_baseline':3,'repair':repair}
    returned={'schema':'g14_guardian_source_forward_repair_return_v1','status':'GUARDIAN_SOURCE_REPAIR_OK','result':result,'automatic_replay':False,'Guest_or_Core_business_authority':False}
    manifest={'source_commit':'e'*40,'protected_refs':[{'path':p,'sha256':h} for p,h in protected.items()]}
    class Owner:
        sha=cas.SOURCE_PIN;raw_config=standing
        def __init__(self,pin):events.append(('owner',pin))
        def identity(self):return full
        def original_qualification_measurement(self,identity):events.append(('full120',identity));return {'declared':True}
        def key(self,identity):return 'declared-key'
        def current15_readonly(self):
            events.append(('fresh15',None))
            return {'identity':full,'measurement':measurement,'kernel':kernel},b'DECLARED prefix',b'DECLARED closing',[{}]
    class Backend:
        def __init__(self,*args):pass
        def files(self,successor):events.append(('files',successor))
        def protected(self):return protected
    data={Path('/declared/standing'):standing,full_path:b'DECLARED full120',own_path:cas.canonical(own)}
    def identity(value):
        # Exact public physical-identity contract, with declared operands only.
        cas.need(type(value) is dict and set(value)=={'boot_id','pid','start_ticks','InvocationID','ExecMainStartTimestampMonotonic'},'CLOSED_NATIVE_IDENTITY')
        cas.need(cas.re.fullmatch('[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}',str(value['boot_id']))
                 and type(value['pid']) is int and value['pid']>1 and type(value['start_ticks']) is int and value['start_ticks']>0
                 and cas.re.fullmatch('[a-f0-9]{32}',str(value['InvocationID'])) and cas.re.fullmatch('[1-9][0-9]*',str(value['ExecMainStartTimestampMonotonic'])),'EXACT_PHYSICAL_NATIVE_IDENTITY')
    C=types.SimpleNamespace(NEW_DIGEST=cas.NEW_DIGEST,HEAD_CONFIG_SHA='f'*64,NEW_STANDING=Path('/declared/standing'),CTRL='ctrl',GUARD='guard',NEW_CONFIG=Path('/declared/config'),NEW_SOURCE=Path('/declared/source'),LEDGER=ledger,sha=cas.sha,wire=cas.canonical,loads=json.loads,once=lambda p,r:events.append(('once',p.name)),read=lambda p,*args:data[p],identity=identity,load_guardian=lambda *args:types.SimpleNamespace(Owner=Owner))
    def physical(unit,argv):
        events.append(('physical',unit))
        if unit!='ctrl':raise AssertionError('repair must not use legacy Guardian observer')
        return ctrl
    cut=types.SimpleNamespace(C=C,Backend=Backend,physical_identity=physical,controller_argv=lambda p:['declared-controller'],guardian_argv=lambda *args:['declared-guardian'])
    def validate(cut,folder,manifest,returned,run):events.append(('repair-validator',run));return returned['result']['repair']
    def observe(cut,pin,expected,baseline):
        events.append(('repair-observer',baseline));cas.need(baseline in (0,3),'DECLARED_BASELINE');return expected
    helper=types.SimpleNamespace(validate_repair_return=validate,observe_guardian=observe)
    return cut,folder,manifest,returned,run,helper,events


class G14CoreCASTests(unittest.TestCase):
    def test_forced_unbound_refuses_before_all_input_auth_or_native_io(self):
        # The scoped return path is a lexical check before private-directory,
        # file or Source-helper access. No filesystem authority comes from it.
        state=cas.ROOT
        for leaf in ('swap-once-declared','guardian-source-repair-11111111-1111-4111-8111-111111111111'):
            cas.closed_g14_return_path(state/leaf/'RETURN.json',state)
        for path in (Path('/declared/RETURN.json'),state/'foreign'/'RETURN.json',
                     state/'swap-once-declared'/'HOLD.json',
                     state/'guardian-source-repair-11111111111141118111111111111111'/'RETURN.json',
                     state/'guardian-source-repair-11111111-1111-4111-8111-11111111111g'/'RETURN.json',
                     state/'guardian-source-repair-11111111-1111-4111-8111-111111111111-extra'/'RETURN.json'):
            with self.subTest(return_path=str(path)),patch.object(cas,'read') as read,patch.object(cas,'load_repair_helper') as helper:
                with self.assertRaises(cas.Hold):cas.closed_g14_return_path(path,state)
                read.assert_not_called();helper.assert_not_called()
        with self.assertRaises(cas.Hold):cas.closed_g14_return_path(state/'swap-once-declared'/'RETURN.json',Path('/declared/foreign-state'))
        main=next(n for n in ast.parse(PATH.read_text()).body if isinstance(n,ast.FunctionDef) and n.name=='main')
        calls=[n for n in ast.walk(main) if isinstance(n,ast.Call)]
        order={name:min(n.lineno for n in calls if isinstance(n.func,ast.Name) and n.func.id==name)
               for name in ('closed_g14_return_path','load_repair_helper')}
        return_reads=[n.lineno for n in calls if isinstance(n.func,ast.Attribute) and n.func.attr=='read'
                      and n.args and isinstance(n.args[0],ast.Name) and n.args[0].id=='returned_path']
        return_dirs=[n.lineno for n in calls if isinstance(n.func,ast.Attribute) and n.func.attr=='private_dir'
                     and n.args and isinstance(n.args[0],ast.Attribute) and isinstance(n.args[0].value,ast.Name)
                     and n.args[0].value.id=='returned_path']
        self.assertLess(order['closed_g14_return_path'],min(return_reads+return_dirs+[order['load_repair_helper']]))
        with patch.object(cas,'SOURCE_BOUND',False), patch.object(cas,'read') as read, patch.object(cas,'load_tools') as tools, patch.object(cas,'API') as api:
            for call in (cas.main,lambda:cas.maintenance_inputs(object()),lambda:cas.database_a3(None,None,None,None,'BEFORE'),lambda:cas.g14_acceptance(None,None,None,None,None),lambda:cas.patch_once(None,None,None,None,None,0)):
                with self.subTest(call=repr(call)), self.assertRaises(cas.Hold): call()
            read.assert_not_called(); tools.assert_not_called(); api.assert_not_called()
        with patch.object(cas,'SOURCE_BOUND',False),patch.object(cas,'read') as read:
            cut=types.SimpleNamespace(physical_identity=lambda *args: self.fail('unbound native observer'))
            for call in (lambda:cas.accepted_guardian(cut,{}),lambda:cas.load_repair_helper({})):
                with self.assertRaises(cas.Hold):call()
            read.assert_not_called()
        with patch.multiple(cas,SOURCE_BOUND=True,CORE_R=None,NEW_DIGEST=None,M94_MIGRATION_SHA=None),patch.object(cas,'read') as read:
            with self.assertRaises(cas.Hold):cas.require_bound()
            read.assert_not_called()
        # The qualified Source may leave only the Root's late data ref unbound.
        # Every direct maintenance entrypoint still needs the complete guard.
        with binding(), patch.object(cas,'CONFIG_REF',None), patch.object(cas,'read') as read, patch.object(cas,'API') as api:
            cas.require_source_bound()
            for call in (cas.require_bound, lambda:cas.load_tools(Path('/declared/package')),
                         lambda:cas.maintenance_inputs(object()),lambda:cas.database_a3(None,None,None,None,'BEFORE'),
                         lambda:cas.g14_acceptance(None,None,None,None,None),lambda:cas.patch_once(None,None,None,None,None,0)):
                with self.subTest(late_ref_call=repr(call)),self.assertRaises(cas.Hold):call()
            read.assert_not_called();api.assert_not_called()
        argv=['declared-cas','--package','/declared/package','--expected-ops-source','c'*40,
              '--expected-manifest-sha256','a'*64,'--g14-swap-return','/declared/RETURN.json',
              '--expected-g14-swap-return-sha256','a'*64,'--evidence-dir','/declared/evidence',
              '--execute-core-image-cas-once']
        for suffix in ([],['--config-ref-path','/declared/config'],['--expected-config-sha256','a'*64]):
            with binding(),patch.object(cas,'CONFIG_REF',None),patch.object(cas.sys,'argv',argv+suffix),patch.object(cas,'load_tools') as tools,patch.object(cas,'read') as read,patch.object(cas,'API') as api:
                with self.subTest(missing_runtime_arg=suffix),self.assertRaises(SystemExit) as failure:cas.main()
                self.assertEqual(failure.exception.code,2);self.assertIsNone(cas.CONFIG_REF)
                tools.assert_not_called();read.assert_not_called();api.assert_not_called()
        for path,pin in (('relative/config','a'*64),('/declared/../config','a'*64),('/declared/./config','a'*64),('//declared/config','a'*64),('/','a'*64),('/declared/config',''),('/declared/config','A'*64),('/declared/config','0'*64)):
            with binding(),patch.object(cas,'CONFIG_REF',None),patch.object(cas.sys,'argv',argv+['--config-ref-path',path,'--expected-config-sha256',pin]),patch.object(cas,'load_tools') as tools,patch.object(cas,'read') as read,patch.object(cas,'API') as api:
                with self.subTest(runtime_path=path,runtime_sha=pin),self.assertRaises(cas.Hold):cas.main()
                self.assertIsNone(cas.CONFIG_REF);tools.assert_not_called();read.assert_not_called();api.assert_not_called()
        with binding(),patch.object(cas,'CONFIG_REF',None),patch.object(cas.sys,'argv',argv+['--config-ref-path','/declared/config','--expected-config-sha256','a'*64]),patch.object(cas.sys,'platform','linux'),patch.object(cas.os,'geteuid',return_value=0),patch.object(cas,'load_tools',side_effect=RuntimeError('DECLARED_FIRST_IO_BOUNDARY')) as tools,patch.object(cas,'read') as read,patch.object(cas,'API') as api:
            with self.assertRaisesRegex(RuntimeError,'DECLARED_FIRST_IO_BOUNDARY'):cas.main()
            self.assertEqual(cas.CONFIG_REF,{'path':'/declared/config','sha256':'a'*64})
            cas.require_bound();tools.assert_called_once_with(Path('/declared/package'));read.assert_not_called();api.assert_not_called()

    def test_r4_preimage_and_full_cas_mutation_footprint(self):
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
            after['metadata']['annotations'].update({'dakasa.io/core-source-commit':cas.CORE_R,'kubernetes.io/change-cause':cas.CHANGE_CAUSE});after['metadata'].update(generation=278,resourceVersion='2')
            cas.result_shape(d,after,C)
            for field in ('env','resources'):
                wrong=copy.deepcopy(after);wrong['spec']['template']['spec']['containers'][0][field]={}
                with self.subTest(field=field),self.assertRaises(cas.Hold):cas.result_shape(d,wrong,C)

    def test_known_c117_deadline_failed_read_refuses_uncertain_ack_authority_or_epoch(self):
        value,c,C=a3_operand()
        self.assertNotEqual(value['preregistration']['preregistration_record']['binding_name'],cas.loads(value['grant_pgtext'])['grant_record']['binding']['name'])
        self.assertTrue(cas.validate_a3(value,c,C))
        for fault in ('missing_ack','unknown','wrong_finish','wrong_predicate','unexpired_lease','foreign_capacity_owner','sdk_not_200','foreign_sdk_source','foreign_vm','sdk_next_action','sdk_before_reservation','sdk_after_grant_expiry','disposed_parent','wrong_prereg_wire','witness','enrollment','installation','retirement','cleanup_admission','extra_survivor','missing_survivor_enrollment','inactive_policy','missing_member','duplicate_member','foreign_member','wrong_mutation_join','wrong_prereg_binding'):
            v=copy.deepcopy(value);config=copy.deepcopy(c)
            if fault in ('missing_member','duplicate_member','foreign_member','wrong_mutation_join','wrong_prereg_binding'):
                pre=v['preregistration'];stored=cas.loads(bytes.fromhex(pre['binding_wire'][2:]))
                if fault=='missing_member':stored['members']=[m for m in stored['members']if m['slot']!=2]
                elif fault=='duplicate_member':stored['members'].append(copy.deepcopy(stored['members'][1]))
                elif fault=='foreign_member':stored['members'][1]['name']='declared-foreign-member'
                elif fault=='wrong_mutation_join':stored['mutation_binding_name']='declared-foreign-profile'
                else:pre['preregistration_record']['binding_name']='declared-foreign-member'
                pre['binding_wire']='\\x' + cas.canonical(stored).hex()
                resealed=cas.canonical(pre['preregistration_record']);pre['original_wire']='\\x'+resealed.hex()
                config['case']['preregistration_sha256']=cas.sha(resealed)
            elif fault=='missing_ack':v['dispatch'][0]['finalization_ack_at']=None
            elif fault=='unknown':v['dispatch'][0]['state']='unknown'
            elif fault=='wrong_finish':v['dispatch'][0]['returned_at']='2026-11-05T00:20:15Z'
            elif fault=='wrong_predicate':
                r=json.loads(v['run_pgtext']);r['result']['steps'][0]['metadata']['original_guest_refusal_predicate']='original-guest-step-17';v['run_pgtext']=cas.canonical(r).decode();config['case']['run_sha256']=cas.sha(v['run_pgtext'].encode())
            elif fault in ('unexpired_lease','foreign_capacity_owner'):
                i=json.loads(v['intent_pgtext'])
                if fault=='unexpired_lease':i['lease_expires_at']=config['case']['lease_expires_at']='2026-11-05T10:00:00Z'
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
                key={'witness':'target_witnesses','enrollment':'target_enrollments','installation':'target_installations','retirement':'target_retirements','cleanup_admission':'cleanup_admissions'}[fault];v[key]=[{'id':'22222222-2222-4222-8222-222222222222','grant_id':cas.A3_GRANT,'child_grant_id':cas.CHILD_ID}] if fault=='cleanup_admission' else [{'declared':'present'}]
            elif fault=='extra_survivor':v['survivors'].append(copy.deepcopy(v['survivors'][0]))
            elif fault=='missing_survivor_enrollment':v['survivors'][0]['enrollments']=[]
            else:v['active_policy']['active']=False
            with self.subTest(fault=fault),self.assertRaises(cas.Hold) as held:cas.validate_a3(v,config,C)
            if fault in ('missing_member','duplicate_member','foreign_member','wrong_mutation_join','wrong_prereg_binding'):
                self.assertEqual(str(held.exception),'ORIGINAL_GRB_PROFILE_MUTATION_JOIN'if fault=='wrong_mutation_join'else'ORIGINAL_GRB_UNIQUE_SLOT_MEMBER')
        cleanup,cleanup_case=cleanup_operand(value)
        self.assertTrue(cas.validate_cleanup95(cleanup,cleanup_case))
        for fault in ('missing_ack','unknown_dispatch','wrong_finish','live_owner','foreign_old_owner','failed_call_false','failed_context_false','raw_before_deadline','read_pair_mismatch','wrong_pending_hold','child_not_settled','unknown_child_aux','foreign_child','sdk_missing','sdk_schema','sdk_source','sdk_status','sdk_bool_status','sdk_grant','sdk_attempt','sdk_action','sdk_request','sdk_target','sdk_birth','sdk_next_action','sdk_deadline'):
            v=copy.deepcopy(cleanup);case=copy.deepcopy(cleanup_case)
            q,p,r=v['events'][-3:];failed=r['original_record']['evidence'];child=v['child'];settlement=child['grant_record']['settlement'];sdk=settlement['original_provider_destroy_return']
            if fault=='missing_ack':v['dispatch'][0]['finalization_ack_at']=None
            elif fault=='unknown_dispatch':v['dispatch'][0]['state']='unknown'
            elif fault=='wrong_finish':v['workflow_run']['finished_at']='2026-11-05T08:17:14.322Z'
            elif fault=='live_owner':
                case['lease_expires_at']='2026-11-05T10:00:00Z'
                for event in v['events']:event['original_record']['lease_expires_at']=case['lease_expires_at']
            elif fault=='foreign_old_owner':r['original_record']['lease_owner']='88888888-8888-4888-8888-888888888888'
            elif fault=='failed_call_false':failed['call_failed']=False
            elif fault=='failed_context_false':failed['original_context_failed']=False
            elif fault=='raw_before_deadline':failed['returned_at_core']='2026-11-05T08:17:14.289Z'
            elif fault=='read_pair_mismatch':
                failed['read']['read_id']='88888888-8888-4888-8888-888888888888'
                failed['read_wire']=base64.b64encode(cas.canonical(failed['read'])).decode()
            elif fault=='wrong_pending_hold':
                good=q['original_record']['evidence'];good['observation']['hold_reasons']=[]
                h=cas.loads(base64.b64decode(good['original_observer_return']));h['observation']=good['observation']
                good['original_observer_return']=base64.b64encode(cas.canonical(h)).decode()
            elif fault=='child_not_settled':child['state']='issued'
            elif fault=='unknown_child_aux':settlement['auxiliary_inventory_complete']=False
            elif fault=='foreign_child':child['id']='88888888-8888-4888-8888-888888888888'
            elif fault=='sdk_missing':settlement.pop('original_provider_destroy_return')
            elif fault=='sdk_schema':sdk['schema']='DECLARED unsupported return'
            elif fault=='sdk_source':sdk['adapter_source_commit']='f'*40
            elif fault=='sdk_status':sdk['response_status']=202
            elif fault=='sdk_bool_status':sdk['response_status']=True
            elif fault=='sdk_grant':sdk['grant_id']=cas.A3_GRANT
            elif fault=='sdk_attempt':sdk['attempt_id']='88888888-8888-4888-8888-888888888888'
            elif fault=='sdk_action':sdk['action_id']='DECLARED foreign action'
            elif fault=='sdk_request':sdk['request_sha256']='f'*64
            elif fault=='sdk_target':sdk['resource_id']='i-00000000000000000'
            elif fault=='sdk_birth':sdk['resource_created_at']='2026-11-05T00:20:15Z'
            elif fault=='sdk_next_action':sdk['next_action_ids']=['DECLARED unknown action']
            else:sdk['returned_at']=sdk['context_deadline']
            reseal_cleanup_rows(v)
            with self.subTest(cleanup95_fault=fault),self.assertRaises(cas.Hold):cas.validate_cleanup95(v,case)
        # No synthetic grant or new seven-CAS/admission fields enter the image case.
        self.assertNotIn('Pending',cas.A3_SQL);self.assertNotIn('fd24881a',PATH.read_text())

    def test_once_markers_precede_only_actual_patch_and_prevent_replay(self):
        # Exercise the full common acceptance after the trusted repair helper,
        # including full120, own15 and an independent fresh15; no Root facts.
        with binding():
            cut,folder,manifest,returned,run,helper,events=repair_acceptance_operand()
            with patch.object(cas,'load_repair_helper',return_value=helper):
                accepted=cas.g14_acceptance(cut,folder,manifest,returned,run)
                self.assertEqual(len(accepted),5)
                self.assertEqual(accepted[2:4],(returned['result']['controller'],returned['result']['guardian']))
                self.assertEqual(cas.accepted_guardian(cut,returned),accepted[3])
            self.assertIn(('repair-validator',run),events)
            self.assertEqual(events.count(('repair-observer',3)),2)
            self.assertTrue(any(e[0]=='full120' for e in events));self.assertTrue(any(e[0]=='fresh15' for e in events))
            self.assertNotIn(('physical','guard'),events)
            # The old failed swap/HOLD cannot masquerade as a success receipt.
            wrong=copy.deepcopy(returned);wrong.update(schema='g14_pair_swap_return_v1',status='HOLD')
            with self.assertRaises(cas.Hold):cas.g14_acceptance(cut,folder,manifest,wrong,run)
        # Real loader boundary: lexical/ref/global SHA refusals occur before IO;
        # only exact Source bytes may become the trusted helper interface.
        helper_raw=b"def validate_repair_return(*args): return {'declared': True}\ndef observe_guardian(*args): return args[2]\n"
        with binding():
            cut,folder,manifest,returned,run,helper,events=repair_acceptance_operand()
            pin=cas.sha(helper_raw);returned['result']['repair']['repair_helper_ref']['sha256']=pin
            with patch.object(cas,'REPAIR_HELPER_SHA256',pin),patch.object(cas,'read',return_value=helper_raw) as read:
                module=cas.load_repair_helper(returned)
                self.assertTrue(callable(module.validate_repair_return));self.assertTrue(callable(module.observe_guardian))
                read.assert_called_once_with(Path('/declared/g14_guardian_source_repair_once.py'),131072,0o600)
            for fault in ('unbound_helper','foreign_helper_ref','wrong_filename','relative_helper','baseline_bool','baseline_two','old_hold'):
                bad=copy.deepcopy(returned);global_pin=pin
                if fault=='unbound_helper':global_pin=None
                elif fault=='foreign_helper_ref':bad['result']['repair']['repair_helper_ref']['sha256']='f'*64
                elif fault=='wrong_filename':bad['result']['repair']['repair_helper_ref']['path']='/declared/foreign.py'
                elif fault=='relative_helper':bad['result']['repair']['repair_helper_ref']['path']='relative.py'
                elif fault=='baseline_bool':bad['result']['guardian_restart_baseline']=False
                elif fault=='baseline_two':bad['result']['guardian_restart_baseline']=2
                else:bad['status']='HOLD'
                with self.subTest(repair_fault=fault),patch.object(cas,'REPAIR_HELPER_SHA256',global_pin),patch.object(cas,'read') as read:
                    with self.assertRaises(cas.Hold):cas.load_repair_helper(bad)
                    read.assert_not_called()
            with patch.object(cas,'REPAIR_HELPER_SHA256',pin),patch.object(cas,'read',return_value=b'DECLARED wrong helper bytes'):
                with self.assertRaises(cas.Hold):cas.load_repair_helper(returned)
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

    def test_common_custody_and_schema95_preserve_prior94_whole_history(self):
        old=(ROOT/'rollout/core_image_cas_once_g13.py').read_text();new=PATH.read_text()
        def spans(raw):return {n.name:ast.get_source_segment(raw,n) for n in ast.parse(raw).body if isinstance(n,(ast.FunctionDef,ast.ClassDef))}
        a,b=spans(old),spans(new)
        for name in ('API','operation_lock','read','api_read','result_shape','query','workflow_busy_logical_index92_sql','catalog_sql','catalog_projection','catalog_select','catalog94_projection','catalog94_select','patch_once','validated_config_ref','require_bound','utc'):
            self.assertEqual(a[name],b[name],name)
        self.assertIn("statement_timeout='3s'",b['query']);self.assertIn("lock_timeout='500ms'",b['query']);self.assertIn('timeout=8',b['query'])
        # Keep real input_ref hashing separately tested; schema-level Root data
        # below uses the declared backend interface, not actual Root authority.
        raw=b'DECLARED immutable source bytes';ref={'path':'/declared/original','sha256':cas.sha(raw)}
        C=types.SimpleNamespace(digest=cas.digest_value,read=lambda *args:raw)
        self.assertEqual(cas.input_ref(C,ref),raw)
        with self.assertRaises(cas.Hold):cas.input_ref(C,{**ref,'sha256':'0'*64})
        with self.assertRaises(cas.Hold):cas.input_ref(C,{**ref,'sha256':cas.sha(b'DECLARED different body')})
        with binding():
            config,legacy,current,refs,ref,root94,root95=schema95_operand()
            C=types.SimpleNamespace(loads=json.loads)
            with patch.object(cas,'input_ref',side_effect=lambda C,r:refs[r['path']]):
                cas.schema95_facts(config,legacy,current,C)
                for fault in ('prior94_history','root95_not_reviewed','root95_extra_field','root95_old_ops','root95_wrong_source','root95_wrong_digest','root95_missing_original','root95_mutation','wrong95_hash'):
                    cfg=copy.deepcopy(config);saved=copy.deepcopy(refs);proof=copy.deepcopy(root95)
                    if fault=='prior94_history':refs[cfg['prior94_history_ref']['path']]=b'[]'
                    elif fault=='wrong95_hash':cfg['schema_pins']['schema95_catalog_sha256']='f'*64
                    else:
                        if fault=='root95_not_reviewed':proof['reviewed_by_root']=False
                        elif fault=='root95_extra_field':proof['invented_authority']=True
                        elif fault=='root95_old_ops':proof['current_ops_source']='a'*40
                        elif fault=='root95_wrong_source':proof['business_source']='a'*40
                        elif fault=='root95_wrong_digest':proof['amd64_D']='a'*64
                        elif fault=='root95_missing_original':proof['original_refs'].pop('migration_result')
                        else:proof['provider_guest_core_mutations']=1
                        refs[cfg['acceptance_refs']['Root_Goose95_acceptance']['path']]=cas.canonical(proof)
                    with self.subTest(root95_fault=fault),self.assertRaises(cas.Hold):cas.schema95_facts(cfg,legacy,current,C)
                    refs.clear();refs.update(saved)
                for axis in ('columns','constraints','indexes','tables','triggers','old_function','event_body','function_result','definition_outside_body'):
                    bad=copy.deepcopy(current);cfg=copy.deepcopy(config);saved=copy.deepcopy(refs);proof=copy.deepcopy(root95)
                    if axis in ('columns','constraints','indexes','tables','triggers'):bad['schema94'][axis]=[]
                    else:
                        name='guard_failed_unwitnessed_expansion_cleanup_event' if axis in ('event_body','definition_outside_body') else 'guard_failed_unwitnessed_expansion_cleanup'
                        row=next(r for r in bad['schema94']['functions'] if r['name']==name)
                        if axis in ('old_function','event_body'):row['body']+='\n-- DECLARED unqualified Source mutation'
                        elif axis=='function_result':row['result']='boolean'
                        else:row['definition']+=' DECLARED changed function attribute'
                    # Even resealing the expected current snapshot and Root95
                    # cannot qualify an unrelated DDL/Source change over94.
                    projected=cas.catalog94_projection(bad);body=cas.canonical(projected)
                    refs[cfg['schema95_catalog_ref']['path']]=body;cfg['schema_pins']['schema95_catalog_sha256']=cas.sha(body)
                    proof['catalog95_sha256']=cas.sha(body);refs[cfg['acceptance_refs']['Root_Goose95_acceptance']['path']]=cas.canonical(proof)
                    with self.subTest(resealed_schema95_axis=axis),self.assertRaises(cas.Hold):cas.schema95_facts(cfg,legacy,bad,C)
                    refs.clear();refs.update(saved)
            legacy_sql=(ROOT/'tests/fixtures/g13-cas-legacy-catalog.sql').read_bytes()
            self.assertEqual(cas.sha(legacy_sql),cas.LEGACY_CATALOG_SHA)
            sql=cas.catalog94_select(legacy_sql.decode());self.assertTrue(sql.startswith('WITH old93(v) AS (WITH legacy AS (SELECT '));self.assertNotIn('COMMIT;',sql)
            # The complete data-only maintenance preflight executes its actual
            # closed config/A3/cleanup predicates with a declared ref backend.
            value,original,C0=a3_operand();cleanup,cleanup_case=cleanup_operand(value)
            d,ps,Core=core_operand();Core.loads=json.loads;Core.SOURCE_R=cas.CORE_R
            Core.OLD_CORE_UID=cas.UID;Core.OLD_CORE_GENERATION=cas.GENERATION;Core.OLD_CORE_POD_UID=cas.OLD_POD
            config.update(schema='g14_failed_cleanup_deadline_continuation_image_maintenance_v1',source_R=cas.CORE_R,amd64_D=cas.NEW_DIGEST,
                core_preimage={'deployment_uid':cas.UID,'generation':cas.GENERATION,'pod_uid':cas.OLD_POD,'container_id':cas.OLD_CONTAINER_ID,'image_config_digest':cas.OLD_IMAGE_CONFIG_DIGEST,'spec_sha256':'1'*64,'annotations_sha256':'2'*64},
                case=original['case'],policy_state={cloud:{k:[] for k in ('intent_identity','owned_slots','active_policies','policy_catalog_wire')} for cloud in ('aws','hetzner')},
                current_preimage_ref=ref('current-a3',cas.canonical(value)),cleanup_preimage_ref=ref('current-cleanup',cas.canonical(cleanup)),cleanup_case=cleanup_case,
                legacy_catalog_sql_ref=ref('catalog-select',legacy_sql))
            for role in ('qualified_business_release','business_Source_CI','Root_separate_rollout_review'):config['acceptance_refs'][role]=ref(role,b'DECLARED independent data')
            refs[cas.SQL_DATA_REF['path']]=cas.canonical({'schema':'fixed_policy_publication_schema92_SQL_data_v1','queries':{'original_notify_aws_vm_members':'DECLARED readonly AWS SELECT','original_notify_hetzner_vm_members':'DECLARED readonly HZ SELECT'}})
            refs[cas.CONFIG_REF['path']]=cas.canonical(config)
            with patch.object(cas,'input_ref',side_effect=lambda C,r:refs[r['path']]):
                actual,original_wire,sql=cas.maintenance_inputs(Core)
                self.assertEqual(actual,config);self.assertEqual(original_wire,refs[cas.CONFIG_REF['path']]);self.assertEqual(set(sql['queries']),{'original_notify_aws_vm_members','original_notify_hetzner_vm_members'})
                # Execute the actual complete BEFORE/PRESEND data predicates,
                # with explicit declared SQL-return and wall-clock interfaces.
                # Neither the mock clock nor returned rows are Root/live facts.
                class FixtureDatetime(declared_datetime.datetime):
                    @classmethod
                    def now(cls,tz=None):return cls(2026,11,5,9,0,0,tzinfo=declared_datetime.timezone.utc)
                clock=types.SimpleNamespace(datetime=FixtureDatetime,timezone=declared_datetime.timezone,timedelta=declared_datetime.timedelta)
                lanes={cloud:{**copy.deepcopy(legacy),**cleanup_case['provider_lanes'][cloud],**config['policy_state'][cloud]} for cloud in ('aws','hetzner')}
                def declared_query(cut,run,label,sql):
                    if label.endswith('-SCHEMA95'):return copy.deepcopy(current)
                    if label.endswith('-aws'):return copy.deepcopy(lanes['aws'])
                    if label.endswith('-hetzner'):return copy.deepcopy(lanes['hetzner'])
                    if label.endswith('-A3'):return copy.deepcopy(value)
                    if label.endswith('-C117-OWNED-READ-FAILURE'):return copy.deepcopy(cleanup)
                    raise AssertionError('unexpected declared read '+label)
                with patch.object(cas,'datetime',clock),patch.object(cas,'query',side_effect=declared_query) as query:
                    for phase in ('BEFORE','PRESEND'):cas.database_a3(types.SimpleNamespace(C=Core),Path('/declared/run'),config,sql,phase)
                    self.assertEqual(query.call_count,10)
                    with self.assertRaises(cas.Hold):cas.database_a3(types.SimpleNamespace(C=Core),Path('/declared/run'),config,sql,'AFTER')
                    self.assertEqual(query.call_count,10)
                def changed_query(cut,run,label,sql):
                    row=declared_query(cut,run,label,sql)
                    if label.endswith('-C117-OWNED-READ-FAILURE'):row['workflow_run']['error']='DECLARED changed whole immutable return'
                    return row
                with patch.object(cas,'datetime',clock),patch.object(cas,'query',side_effect=changed_query):
                    with self.assertRaises(cas.Hold):cas.database_a3(types.SimpleNamespace(C=Core),Path('/declared/run'),config,sql,'BEFORE')



if __name__=='__main__':unittest.main()
