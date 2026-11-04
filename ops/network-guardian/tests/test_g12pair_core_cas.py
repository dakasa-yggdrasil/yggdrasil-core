"""Declared G12 CAS data only; never OCI, Root approval or native evidence."""
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
PATH = ROOT / 'rollout/core_image_cas_once_g12.py'
cas = types.ModuleType('declared_g12_core_cas_CI')
cas.__file__ = str(PATH)
exec(compile(PATH.read_bytes(), str(PATH), 'exec'), cas.__dict__)


@contextlib.contextmanager
def binding():
    """Declared operands only; no validator or filesystem function is bypassed."""
    with patch.multiple(cas, SOURCE_BOUND=True, CORE_R='c'*40, NEW_DIGEST='d'*64,
        SOURCE_PIN='a'*64, TOOL_PINS={n:'a'*64 for n in ('pair_change_contract.py','derive_g12pair_controller_config.py','derive_standing_config.py','g12cut.py')},
        CONFIG_REF={'path':'/declared/config','sha256':'a'*64},
        SQL_DATA_REF={'path':'/declared/E70','sha256':cas.POLICY92_SQL_SHA},
        OLD_CONTAINER_ID='containerd://'+'b'*64, OLD_IMAGE_CONFIG_DIGEST='sha256:'+'e'*64,
        CHANGE_CAUSE='Declared CI new source; no release or Root approval.'):
        yield


def core_operand():
    image = '153828470928.dkr.ecr.us-east-1.amazonaws.com/ghcr/dakasa-yggdrasil/yggdrasil-core@sha256:'+cas.OLD_DIGEST
    c = types.SimpleNamespace(OLD_DIGEST=cas.OLD_DIGEST,OLD_CORE_SOURCE=cas.OLD_SOURCE,
        NEW_DIGEST='d'*64,IMAGE_PREFIX=image.rsplit(':',1)[0]+':')
    d = {'apiVersion':'apps/v1','kind':'Deployment','metadata':{'namespace':'dakasa','name':'yggdrasil','uid':cas.UID,'generation':275,'resourceVersion':'1','annotations':{'dakasa.io/core-source-commit':cas.OLD_SOURCE,'retain':'declared'}},
        'spec':{'replicas':1,'template':{'spec':{'containers':[{'name':'core','image':image,'env':[{'name':'DECLARED','value':'unchanged'}],'resources':{'limits':{'cpu':'1'}}}]}}},
        'status':{'observedGeneration':275,'readyReplicas':1,'updatedReplicas':1,'availableReplicas':1}}
    ps = {'items':[{'metadata':{'uid':cas.OLD_POD,'name':'declared-r2'},'spec':{'containers':[{'name':'core','image':image}]},'status':{'phase':'Running','podIP':'192.0.2.1','containerStatuses':[{'name':'core','ready':True,'restartCount':0,'state':{'running':{'startedAt':'2026-11-04T16:00:00Z'}},'imageID':image,'containerID':'containerd://'+'b'*64}]}}]}
    return d, ps, c


def seal(record, **extra):
    raw = cas.canonical(record).rstrip(b'\n')
    return {**extra,'original_wire':'\\x'+raw.hex(),'record_sha256':cas.sha(raw),'original_record':record}


def s2_operand():
    """Minimal declared rows reach the actual typed S2 guard, never SQL/native."""
    lease, issued, returned, finished = '2026-11-04T17:58:00Z','2026-11-04T17:59:00Z','2026-11-04T17:59:01Z','2026-11-04T17:59:02Z'
    ids = {k:'11111111-1111-4111-8111-111111111111' for k in ('run_id','dispatch_id','workflow_id','lease_owner','executor_id','action_id','pending_read_id')}
    e = {'nonce_sha256':'1'*64,'journal_sha256':['2'*64]*3,'authority_sha256':['3'*64]*4,'caller_sha256':'4'*64}
    request = {'intent':{'request_id':cas.RETIREMENT,'tuple':{'provider':'aws','resource_id':'i-declared-original','resource_created_at':'2026-11-04T16:00:00Z','integration_instance_id':'declared-aws','scope_checksum':'9'*64,'profile':'declared'}}}
    a = {'retirement_request_id':cas.RETIREMENT,'id':cas.FORWARD,'stage':'admitted','root_admission_id':cas.FORWARD,'mode':'live','generation':15,'fence':33,'lease_owner':ids['lease_owner'],'executor_id':ids['executor_id'],'run_id':ids['run_id'],'original':{'Request':request},'evidence':e,'prefix_sha256':'8'*64,'original_caller_sha256':e['caller_sha256']}
    ar = seal(a,id=cas.FORWARD,stage='admitted',retirement_request_id=cas.RETIREMENT,recorded_at=issued)
    off = {**a,'stage':'off_qualified','admission_sha256':ar['record_sha256']}
    of = seal(off,id=cas.FORWARD,stage='off_qualified',recorded_at=issued)
    grant = {'grant_id':cas.DESTROY,'state':'settled','request_sha256':'5'*64,'expected_resource_id':'i-declared-original','expected_resource_created_at':'2026-11-04T16:00:00Z','integration_instance_id':'declared-aws','scope_checksum':'9'*64,'profile_name':'declared'}
    sdk = {'schema':'aws_original_terminate_instances_return_v1','provider':'aws','grant_id':cas.DESTROY,'attempt_id':ids['action_id'],'request_sha256':'5'*64,'action_id':ids['action_id'],'response_status':200,'response_body_sha256':cas.sha(b'declared SDK body'),'response_bytes':17,'resource_id':grant['expected_resource_id'],'resource_created_at':grant['expected_resource_created_at'],'adapter_source_commit':'a'*40,'called_at':'2026-11-04T17:58:50Z','returned_at':'2026-11-04T17:58:51Z','context_deadline':'2026-11-04T17:59:50Z','next_action_ids':[]}
    aux = [{'kind':'aws_ebs_volume','id':'vol-declared'},{'kind':'aws_network_interface','id':'eni-declared'}]
    settlement = {'grant_id':cas.DESTROY,'outcome':'accepted','transport_completed':True,'auxiliary_inventory_complete':True,'action_id':ids['action_id'],'original_provider_destroy_return':sdk,'resource_id':grant['expected_resource_id'],'resource_created_at':grant['expected_resource_created_at'],'auxiliary_resources':aux,'next_action_ids':[]}
    gr = {'id':cas.DESTROY,'state':'settled','namespace':'dakasa-production','dimension':'original_notify_aws_vm_members','grant_record':{'grant':grant,'attempt_id':ids['action_id'],'fencing_token':33,'lease_owner':ids['lease_owner'],'executor_id':ids['executor_id'],'settlement':settlement,'binding':{'original_provider_source_commit':'a'*40}},**{k:None for k in ('original_disposition_id','failed_original_disposition_id','native_denied_disposition_id','enrolled_failed_disposition_id')}}
    eligibility = {'schema':'original_guest_partial_poweroff_delete_eligibility_v1','admission_id':cas.FORWARD,'admission_sha256':ar['record_sha256']}; bw = cas.canonical(eligibility)
    b = {'destroy_grant_id':cas.DESTROY,'intent_id':cas.RETIREMENT,'original_wire':'\\x'+bw.hex(),'original_eligibility_record':eligibility,'eligibility_sha256':cas.sha(bw)}
    challenge = {'schema':'original_core_guest_retirement_forward_read_v1','kind':'absence','admission_id':cas.FORWARD,'retirement_request_id':cas.RETIREMENT,'tuple':request['intent']['tuple'],'prefix_sha256':'8'*64,'original_caller_sha256':e['caller_sha256'],'read_id':ids['pending_read_id'],'destroy_grant_id':cas.DESTROY,'admission_sha256':ar['record_sha256'],'issued_at_core':issued,'original_deadline_core':'2026-11-04T17:59:05Z','adapter_source_commit':'a'*40,'mutation_binding_sha256':'6'*64}
    prep = seal(challenge,id=ids['pending_read_id'],stage='prepared',kind='absence',admission_id=cas.FORWARD,retirement_request_id=cas.RETIREMENT,recorded_at=issued)
    receipt = {'grant':grant,'attempt_id':ids['action_id'],'outcome':'accepted','transport_completed':True,'action_id':ids['action_id'],'resource_id':grant['expected_resource_id'],'resource_created_at':grant['expected_resource_created_at'],'auxiliary_resources':aux,'auxiliary_inventory_complete':True}
    o = {'id':receipt['resource_id'],'created_at':receipt['resource_created_at'],'destroy_grant_id':cas.DESTROY,'destroy_grant_state':'settled','original_outcome':'accepted','original_transport_completed':True,'auxiliary_inventory_complete':True,'next_actions':[],'server_absent':True,'server_absence_complete':True,'billable_resources_absent':False,'retirement_complete':False,'hold_reasons':['aws_network_interface_still_present'],'aws_retirement_lifecycle':{'schema':'aws_original_terminate_and_native_absence_v1','request_id':ids['action_id'],'ec2_state':'terminated','observed_at':returned},'auxiliary_resources':[{'kind':x['kind'],'id':x['id'],'absent':n==0,'observed_at':returned} for n,x in enumerate(aux)]}
    o.update(observation_started_at=issued,server_observed_at=returned,observed_at=returned,delete_action={'known':False,'observed':False},writer_quiescence_evidence=False,provider_fencing_evidence=False,invoice_reconciled=False)
    observer = {'schema':'original_settled_retirement_absence_read_return_v1','observer_source_commit':'b'*40,'original_adapter_source_commit':'a'*40,'read_id':ids['pending_read_id'],'read_sha256':prep['record_sha256'],'original_receipt_sha256':cas.sha(cas.canonical(receipt).rstrip(b'\n')),'observation':o}
    rr = {'schema':'original_core_guest_retirement_forward_read_return_v1','read':challenge,'status':'observed','call_failed':False,'original_context_failed':False,'started_at_core':issued,'original_returned_at_core':returned,'observation':o,'original_destroy_receipt':receipt,'observer_source_commit':'b'*40,'original_observer_return':base64.b64encode(cas.canonical(observer)).decode()}
    ret = seal(rr,id=ids['pending_read_id'],stage='returned',kind='absence',admission_id=cas.FORWARD,retirement_request_id=cas.RETIREMENT,recorded_at=returned)
    intent = {'generation':15,'fencing_token':33,'phase':'drained','lease_owner':ids['lease_owner'],'lease_executor_id':ids['executor_id'],'lease_expires_at':lease,'retirement_forward':{'id':cas.FORWARD,'retirement_request_id':cas.RETIREMENT,'stage':'off_qualified'}}
    w = {'id':ids['run_id'],'status':'failed','finished_at':finished}
    v = {'observed_at_pg':'2026-11-04T18:00:00Z','intent_pgtext':cas.canonical(intent).decode(),'run_pgtext':cas.canonical(w).decode(),'dispatch':[{'id':ids['dispatch_id'],'run_id':ids['run_id'],'state':'returned','return_status':'failed','envelope':{'workflow':{'id':ids['workflow_id']}},'returned_at':finished,'finalization_ack_at':'2026-11-04T17:59:03Z'}],'forwards':[ar,of],'grant':gr,'bindings':[b],'original_intent':{'id':cas.RETIREMENT},'original_returns':[{'sequence':1,'kind':'production_clock_nonce_v2','return_sha256':'1'*64,'original_return_record':{'final_request':request}}]+[{'sequence':n+2,'return_sha256':'2'*64} for n in range(3)],'original_callers':[{'return_sha256':'4'*64}],'original_authorities':[{'return':{'authority_sha256':'3'*64}} for _ in range(4)],'original_context':{'declared':'not native'},'original_attempts':[],'authority_transports':[],'reads':[prep,ret]}
    k = {**ids,'lease_expires_at':lease,'journal_rows':3,'read_rows':2,'intent_sha256':cas.sha(v['intent_pgtext'].encode()),'run_sha256':cas.sha(v['run_pgtext'].encode()),'pending_read_sha256':ret['record_sha256'],'observer_source':'b'*40,'receipt_sha256':observer['original_receipt_sha256']}
    return v, {'case':k}, types.SimpleNamespace(loads=json.loads)


class G12CoreCASTests(unittest.TestCase):
    def test_forced_unbound_refuses_before_all_input_auth_or_native_io(self):
        with patch.object(cas,'SOURCE_BOUND',False), patch.object(cas,'read') as read, patch.object(cas,'load_tools') as tools, patch.object(cas,'API') as api:
            for call in (cas.main,lambda:cas.maintenance_inputs(object()),lambda:cas.database_s2(None,None,None,None,'BEFORE'),lambda:cas.g12_acceptance(None,None,None,None,None),lambda:cas.patch_once(None,None,None,None,None,0)):
                with self.subTest(call=repr(call)), self.assertRaises(cas.Hold): call()
            read.assert_not_called(); tools.assert_not_called(); api.assert_not_called()

    def test_r2_preimage_and_full_cas_mutation_footprint(self):
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
            after['metadata']['annotations'].update({'dakasa.io/core-source-commit':cas.CORE_R,'kubernetes.io/change-cause':cas.CHANGE_CAUSE});after['metadata'].update(generation=276,resourceVersion='2')
            cas.result_shape(d,after,C)
            for field in ('env','resources'):
                wrong=copy.deepcopy(after);wrong['spec']['template']['spec']['containers'][0][field]={}
                with self.subTest(field=field),self.assertRaises(cas.Hold):cas.result_shape(d,wrong,C)

    def test_known_s2_pending_refuses_missing_ack_unknown_or_grant_drift(self):
        value,c,C=s2_operand();self.assertTrue(cas.validate_s2(value,c,C))
        for fault in ('missing_ack','unknown','foreign_grant','uncertain','sdk_not_200','lease_owner','extra_binding','original_wire'):
            v=copy.deepcopy(value);config=copy.deepcopy(c)
            if fault=='missing_ack':v['dispatch'][0]['finalization_ack_at']=None
            elif fault=='unknown':v['dispatch'][0]['state']='unknown'
            elif fault=='foreign_grant':v['grant']['id']='22222222-2222-4222-8222-222222222222'
            elif fault=='uncertain':v['grant']['grant_record']['settlement']['outcome']='uncertain'
            elif fault=='sdk_not_200':v['grant']['grant_record']['settlement']['original_provider_destroy_return']['response_status']=202
            elif fault=='lease_owner':
                i=json.loads(v['intent_pgtext']);i['lease_owner']='22222222-2222-4222-8222-222222222222';v['intent_pgtext']=cas.canonical(i).decode();config['case']['intent_sha256']=cas.sha(v['intent_pgtext'].encode())
            elif fault=='extra_binding':v['bindings'].append(v['bindings'][0])
            else:v['forwards'][0]['original_wire']+='00'
            with self.subTest(fault=fault),self.assertRaises(cas.Hold):cas.validate_s2(v,config,C)
        v=copy.deepcopy(value);config=copy.deepcopy(c)
        rr=v['reads'][1]['original_record'];rr['observation']['auxiliary_resources'][1]['absent']=True
        observer=json.loads(base64.b64decode(rr['original_observer_return']))
        observer['observation']=rr['observation'];rr['original_observer_return']=base64.b64encode(cas.canonical(observer)).decode()
        row=v['reads'][1];extra={k:z for k,z in row.items() if k not in ('original_record','original_wire','record_sha256')}
        v['reads'][1]=seal(rr,**extra);config['case']['pending_read_sha256']=v['reads'][1]['record_sha256']
        with self.assertRaises(cas.Hold):cas.validate_s2(v,config,C)

        # A matching configured hash cannot authenticate different actual receipt bytes.
        v=copy.deepcopy(value);config=copy.deepcopy(c);rr=v['reads'][1]['original_record']
        observer=json.loads(base64.b64decode(rr['original_observer_return']))
        observer['original_receipt_sha256']='f'*64;config['case']['receipt_sha256']='f'*64
        rr['original_observer_return']=base64.b64encode(cas.canonical(observer)).decode()
        row=v['reads'][1];extra={k:z for k,z in row.items() if k not in ('original_record','original_wire','record_sha256')}
        v['reads'][1]=seal(rr,**extra);config['case']['pending_read_sha256']=v['reads'][1]['record_sha256']
        with self.assertRaises(cas.Hold):cas.validate_s2(v,config,C)
        # Raw subtree extraction retains original Go field order and escape bytes.
        raw=b'{"read":{"b":2,"a":"\\u003c"},"original_destroy_receipt":{"z":1,"a":2}}'
        self.assertEqual(cas.raw_json_member(raw,'read'),b'{"b":2,"a":"\\u003c"}')
        self.assertEqual(cas.raw_json_member(raw,'original_destroy_receipt'),b'{"z":1,"a":2}')
        with self.assertRaises(cas.Hold):cas.raw_json_member(b'{"read":1,"read":2}','read')

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

    def test_common_api_mutex_filesystem_and_bounded_sql_are_literal(self):
        old=(ROOT/'rollout/core_image_cas_once_g11.py').read_text();new=PATH.read_text()
        def spans(raw):return {n.name:ast.get_source_segment(raw,n) for n in ast.parse(raw).body if isinstance(n,(ast.FunctionDef,ast.ClassDef))}
        a,b=spans(old),spans(new)
        for name in ('API','operation_lock','read','api_read','result_shape','query','workflow_busy_logical_index92_sql'):
            self.assertEqual(a[name],b[name],name)
        self.assertIn("statement_timeout='3s'",b['query']);self.assertIn("lock_timeout='500ms'",b['query']);self.assertIn('timeout=8',b['query'])
        self.assertNotIn('37a2bbc2',new);self.assertNotIn('fencing_token\'] == 31',new)
        legacy=(ROOT/'tests/fixtures/g12-cas-legacy-catalog.sql').read_bytes()
        self.assertEqual(cas.sha(legacy),cas.LEGACY_CATALOG_SHA)
        select=cas.catalog_select(legacy.decode())
        self.assertTrue(select.startswith('WITH legacy AS (SELECT '))
        self.assertNotIn('COMMIT;',select)
        value={'legacy':{'catalog90':{},'catalog91':{},'complete_history_wire':'declared','other_ddl':0},'supplement':{'columns90_91':[],'functions93':[],'index92_valid':True,'index92_definition':'declared','old_records':{'rows':0}}}
        projected=cas.catalog_projection(value)
        value['legacy']['complete_history_wire']='changed';value['supplement']['old_records']['rows']=99
        self.assertEqual(cas.catalog_projection(value),projected)

        # Head93 keeps the E70 ABI unchanged; its prior*_wire fields include93.
        # True preservation is checked against the separate whole prior92 receipt.
        history=[{'id':i+1,'version_id':n,'is_applied':True} for i,n in enumerate([0]+[n for n in range(1,94) if n!=40])]
        constraints=[{'name':n,'validated':True} for n in ('retirement_forward_mode93','retirement_forward_continuation93')]
        facts={'database':'yggdrasil','readonly':'on','history_max_version':93,'latest_versions':[r['version_id'] for r in history],
            'rows90':1,'rows91':1,'rows92':1,'complete_history_wire':json.dumps(history),'prior_history_wire':'ABI includes93','prior91_history_wire':'ABI includes93',
            'catalog90':{'constraints':constraints},'catalog91':{},'other_migrators_ddl':0,'other_cic':0,'ddl_locks':0}
        current={'legacy':copy.deepcopy(facts),'supplement':{'columns90_91':[],'index92_valid':True,'index92_definition':'declared',
            'functions93':[{'name':n,'definition':'declared','body':'declared'} for n in ('guard_retirement_forward','guard_retirement_forward_read','guard_retirement_forward_delete_binding','retirement_forward_continuation_quiet','retirement_forward_continuation_valid')]}}
        projected=cas.catalog_projection(current)
        pins={'complete_history_sha256':cas.sha(facts['complete_history_wire'].encode()),'index92_definition_sha256':cas.sha(b'declared'),
            'catalog90_91_sha256':cas.sha(cas.canonical({'catalog90':facts['catalog90'],'catalog91':facts['catalog91']})),
            'schema93_catalog_sha256':cas.sha(cas.canonical(projected))}
        config={'schema_pins':pins,'prior92_history_ref':'prior92','schema93_catalog_ref':'catalog93'}
        refs={'prior92':json.dumps(history[:-1]).encode(),'catalog93':cas.canonical(projected)}
        legacy={'schema_facts':facts,'index89_valid':True,'index92_valid':True,'index92_definition':'declared'}
        with patch.object(cas,'input_ref',side_effect=lambda C,ref:refs[ref]):
            cas.schema93_facts(config,legacy,current,types.SimpleNamespace(loads=json.loads))
            refs['prior92']=json.dumps([{**r,'id':999} if r['version_id']==89 else r for r in history[:-1]]).encode()
            with self.assertRaises(cas.Hold):cas.schema93_facts(config,legacy,current,types.SimpleNamespace(loads=json.loads))

        for name,pin in {'catalog_sql':'bd641768dd8de4ce87444e4d3be4ca52f559c86e8992d926cd2963a85733e1f4','catalog_projection':'33a327ef28be83e114b8df23c5af313ebc84e7a6e54b081b70f3dd979915718f'}.items():
            self.assertEqual(cas.sha((b[name]+'\n').encode()),pin,name)


if __name__=='__main__':unittest.main()
