"""CI-only declared HTTP/custody fixtures; no credentials, API or Native calls."""
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
SOURCE=ROOT/'ops/network-guardian/rollout/admit_failed_unwitnessed_expansion_cleanup_once.py'
spec=importlib.util.spec_from_file_location('m94_cleanup_client',SOURCE)
C=importlib.util.module_from_spec(spec)
spec.loader.exec_module(C)  # CI only: module defines inert stdlib functions.


def declared_summary():
    return {'schema':'failed_unwitnessed_expansion_cleanup_v1','id':'fe39518f-21b1-41f8-a58b-b452bd73cf86',
            'grant_id':C.GRANT,'child_grant_id':'3906379f-a4cb-4f71-9e7b-33cb81d03be7','job_id':C.JOB,'run_id':C.RUN,
            'preregistration_id':C.PRE,'stage':'requested','event_count':1,'slot':2,'resource_id':C.RESOURCE,
            'resource_created_at':C.BIRTH,'original_auxiliary_inventory_complete':False,'original_SDK_return_sha256':'a'*64,
            'original_guest_success':False,'clean_cycle_credit':False,'serving_or_business_or_savings_authority':False}


def declared_problem():
    msg='failed_unwitnessed_expansion_cleanup_not_found'
    return {'status':404,'type':C.ORIGIN+'/errors/integration.not_found','title':'Not Found',
            'code':'integration.not_found','detail':msg,'error':msg}


class M94CleanupClientTests(unittest.TestCase):
    def test_inert_guard_stops_before_files_token_or_http(self):
        with mock.patch.object(C,'SOURCE_BOUND',False),mock.patch.object(C,'read')as read,mock.patch.object(C,'Client')as client:
            with self.assertRaises(C.Hold):C.main()
        read.assert_not_called();client.assert_not_called()

    def test_exact_two_uuid_body_and_closed_transport_routes(self):
        self.assertEqual(C.loads(C.request_body()),{'grant_id':C.GRANT,'job_id':C.JOB})
        client=C.Client.__new__(C.Client);client.body_sha256=C.sha(C.request_body());client.armed=None;client.writes=0;client.csrf='TEST_ONLY'
        with mock.patch.object(C.http.client,'HTTPSConnection')as network:
            for method,uri,body in [('DELETE',C.POST_URI,b'{}'),('POST',C.POST_URI,b'{}'),('GET',C.POST_URI,None),('POST','/api/v1/workflows/run',C.request_body())]:
                with self.assertRaises(C.Hold):client.call(method,uri,body)
        network.assert_not_called();self.assertEqual(client.writes,0)
        tree=ast.parse(SOURCE.read_text());posts=[n for n in ast.walk(tree)if isinstance(n,ast.Call)and isinstance(n.func,ast.Attribute)and n.func.attr=='call'and n.args and isinstance(n.args[0],ast.Constant)and n.args[0].value=='POST']
        self.assertEqual(len(posts),1)

    def test_closed_summary_rejects_changed_scope_or_false_credit(self):
        good=declared_summary();self.assertEqual(C.summary(good),good)
        for name in ('grant','job','child','unknown','aux','Guest','cycle','serving','bool_count','stage'):
            bad=copy.deepcopy(good)
            if name=='grant':bad['grant_id']=bad['child_grant_id']
            elif name=='job':bad['job_id']=bad['id']
            elif name=='child':bad['child_grant_id']=C.GRANT
            elif name=='unknown':bad['caller_proof']=True
            elif name=='aux':bad['original_auxiliary_inventory_complete']=True
            elif name=='Guest':bad['original_guest_success']=True
            elif name=='cycle':bad['clean_cycle_credit']=True
            elif name=='serving':bad['serving_or_business_or_savings_authority']=True
            elif name=='bool_count':bad['event_count']=True
            else:bad['stage']='caller_approved'
            with self.subTest(name=name),self.assertRaises(C.Hold):C.summary(bad)

    def test_async_progress_preserves_ack_identity_not_whole_summary(self):
        ack=declared_summary();later=copy.deepcopy(ack);later.update(stage='claimed',event_count=2)
        self.assertEqual(C.same_admission(ack,later),later)
        for field,value in [('event_count',0),('id',ack['child_grant_id']),('original_SDK_return_sha256','b'*64)]:
            bad=copy.deepcopy(later);bad[field]=value
            with self.subTest(field=field),self.assertRaises(C.Hold):C.same_admission(ack,bad)
        bad=copy.deepcopy(ack);bad['stage']='terminal'
        with self.assertRaises(C.Hold):C.same_admission(ack,bad)

    def test_unknown_post_consumes_real_exclusive_claim_no_replay(self):
        with tempfile.TemporaryDirectory()as tmp:
            prep=Path(tmp);prep.chmod(0o700);state=prep/'STATE';a=types.SimpleNamespace(mode='admit-once',execute_cleanup_admission_once=True,token_config=prep/'UNUSED-TOKEN')
            first=prep/'first';first.mkdir(mode=0o700)
            api=mock.Mock();api.receipt.return_value=(None,{'file':'HTTP-001.json','sha256':'a'*64});api.call.side_effect=TimeoutError('DECLARED lost ACK; no real connection')
            with mock.patch.object(C,'PREP',prep),mock.patch.object(C,'STATE',state),mock.patch.object(C,'inputs',return_value=({'Root94':b'{}'},b'{}')),mock.patch.object(C,'Client',return_value=api):
                with self.assertRaises(TimeoutError):C.run(a,first,'a'*64)
                self.assertTrue((state/C.CLAIM_NAME).is_file());claim=(state/C.CLAIM_NAME).read_bytes()
                second=prep/'second';second.mkdir(mode=0o700)
                with self.assertRaises(C.Hold):C.run(a,second,'a'*64)
                self.assertEqual((state/C.CLAIM_NAME).read_bytes(),claim)
            self.assertEqual(api.call.call_count,1);self.assertEqual(api.call.call_args.args[:2],('POST',C.POST_URI))

    def test_observer_after_claim_is_get_only_and_not_original_ack(self):
        with tempfile.TemporaryDirectory()as tmp:
            prep=Path(tmp);prep.chmod(0o700);state=prep/'STATE';state.mkdir(mode=0o700);C.put(state,C.CLAIM_NAME,b'{"DECLARED":true}\n')
            evidence=prep/'read';evidence.mkdir(mode=0o700);a=types.SimpleNamespace(mode='reconcile',execute_cleanup_admission_once=False,token_config=prep/'UNUSED-TOKEN')
            api=mock.Mock();api.receipt.return_value=(declared_summary(),{'file':'HTTP-001.json','sha256':'a'*64})
            with mock.patch.object(C,'PREP',prep),mock.patch.object(C,'STATE',state),mock.patch.object(C,'inputs',return_value=({'Root94':b'{}'},b'{}')),mock.patch.object(C,'Client',return_value=api):C.run(a,evidence,'a'*64)
            api.call.assert_not_called();api.receipt.assert_called_once()
            value=C.loads((evidence/'OBSERVATION.json').read_bytes());self.assertEqual(value['writes'],0);self.assertTrue(value['observed_receipt_is_not_original_POST_201_ACK']);self.assertTrue(value['global_possible_exists'])

    def test_only_current_exact_problem404_means_no_admission(self):
        client=C.Client.__new__(C.Client);ref={'file':'HTTP-001.json','sha256':'a'*64}
        with mock.patch.object(client,'call',return_value=(404,C.wire(declared_problem()),ref)):
            self.assertIsNone(client.receipt()[0])
        for fault in ('detail','code','status'):
            value=declared_problem();value[fault]='other'
            with self.subTest(fault=fault),mock.patch.object(client,'call',return_value=(404,C.wire(value),ref)),self.assertRaises(C.Hold):client.receipt()
        with mock.patch.object(client,'call',return_value=(503,C.wire(declared_problem()),ref)),self.assertRaises(C.Hold):client.receipt()

    def test_partial_http_custody_is_retained_before_framing_hold(self):
        with tempfile.TemporaryDirectory()as tmp:
            folder=Path(tmp);folder.chmod(0o700)
            client=C.Client.__new__(C.Client);client.token='DECLARED_TEST_TOKEN';client.csrf='DECLARED_TEST_CSRF';client.jar=C.http.cookiejar.CookieJar();client.folder=folder;client.body_sha256=C.sha(C.request_body());client.seq=0;client.writes=0;client.armed=('POST',C.POST_URI,client.body_sha256)
            response=mock.Mock();response.status=201;response.headers=mock.Mock();response.headers.get_all.side_effect=lambda name,default=[]:['999']if name=='Content-Length'else[];response.read.return_value=b'{}';response.getheader.side_effect=lambda name,default=None:default
            conn=mock.Mock();conn.getresponse.return_value=response
            with mock.patch.object(C.http.client,'HTTPSConnection',return_value=conn),mock.patch.object(C.signal,'getitimer',return_value=(120.0,0.0)),mock.patch.object(C.signal,'setitimer'),mock.patch.object(client.jar,'extract_cookies'):
                with self.assertRaises(C.Hold):client.call('POST',C.POST_URI,C.request_body())
            value=C.loads((folder/'HTTP-001.json').read_bytes());self.assertFalse(value['framing_valid']);self.assertEqual(value['error_class'],'InvalidOrIncompleteHTTPFraming');self.assertEqual(value['body_base64'],'e30=');self.assertEqual(client.writes,1);conn.request.assert_called_once();conn.close.assert_called_once()
