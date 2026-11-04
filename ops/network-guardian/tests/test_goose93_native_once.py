"""CI-only focused Source tests. Declared data is never Native qualification."""
import ast
import base64
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
SOURCE = ROOT/'ops/network-guardian/rollout/goose93_native_once.py'
MIGRATION = ROOT/'db/migrations/00093_guest_retirement_settled_absence_continuation.sql'
spec = importlib.util.spec_from_file_location('inert_goose93_under_test', SOURCE)
G = importlib.util.module_from_spec(spec)
spec.loader.exec_module(G)


class Goose93OnceTests(unittest.TestCase):
    def test_inert_before_any_input_or_credential_io(self):
        future=('COMPANION_SOURCE_Q','COMPANION_IMAGE_D','SOURCE_CI_GATE_SHA256','COMPANION_IMAGE_PROOF_SHA256','JOB_UUID','CONFIG_SHA256','JOB_MANIFEST_SHA256','EXPECTED_CHECKS','EXPECTED_EXTRA_CHECKS')
        # This vector must remain inert even when the reviewed P4 Source is bound.
        # Actual preparation bindings are recorded separately in static evidence.
        for source_bound in (False,True):
            with self.subTest(source_bound=source_bound), mock.patch.multiple(G,SOURCE_BOUND=source_bound,**{name:None for name in future}), \
                    mock.patch.object(G,'private_read',side_effect=AssertionError('IO forbidden')) as read, \
                    mock.patch.object(G,'reference',side_effect=AssertionError('IO forbidden')) as reference:
                with self.assertRaises(G.Hold):G.main()
                read.assert_not_called();reference.assert_not_called()

        # Declared CI data proves job/check cardinalities are different; it
        # does not qualify the actual still-pending compiler Source cohort.
        ci={'schema':'root_core_retirement_observer_exact_source_CI_acceptance_v1','reviewed_by_root':True,'source':'a'*40,'workflow_count':1,'job_count':1,
            'runs':[{'id':1,'name':'declared','event':'pull_request'}],'jobs':[{'id':10,'name':'declared-job'}],
            'check_runs':[{'id':10,'name':'declared-job','status':'completed','conclusion':'success'},
                          {'id':20,'name':'CodeQL','status':'completed','conclusion':'success'}]}
        checks=frozenset((r['id'],r['name'],r['status'],r['conclusion']) for r in ci['check_runs'])
        with mock.patch.multiple(G,COMPANION_SOURCE_Q='a'*40,EXPECTED_RUNS=1,EXPECTED_JOBS=1,REQUIRED_CI=frozenset({('declared','pull_request')}),EXPECTED_CHECKS=checks,EXPECTED_EXTRA_CHECKS=frozenset({(20,'CodeQL','completed','success')})):
            G.source_ci_valid(ci)
            for fault in ('extra_identity','extra_outcome','extra_status','extra_missing','foreign_job','job_name','duplicate_check'):
                bad=copy.deepcopy(ci)
                if fault=='extra_identity':bad['check_runs'][1]['id']=21
                elif fault=='extra_outcome':bad['check_runs'][1]['conclusion']='skipped'
                elif fault=='extra_status':bad['check_runs'][1]['status']='in_progress'
                elif fault=='extra_missing':bad['check_runs'].pop()
                elif fault=='foreign_job':bad['jobs'][0]['id']=11
                elif fault=='job_name':bad['jobs'][0]['name']='foreign'
                else:bad['check_runs'].append(copy.deepcopy(bad['check_runs'][1]))
                with self.assertRaises(G.Hold):G.source_ci_valid(bad)

    def test_exact_one_job_image_only_and_no_restart_or_overlay(self):
        with mock.patch.object(G,'JOB_UUID','a78740e4-6263-43dc-a0b2-56eb29368119'), mock.patch.object(G,'COMPANION_IMAGE_D','1'*64):
            job = G.job_manifest()
            self.assertEqual(job['spec']['backoffLimit'],0)
            self.assertEqual(job['spec']['parallelism'],1)
            pod = job['spec']['template']['spec']; container = pod['containers'][0]
            self.assertEqual(pod['restartPolicy'],'Never')
            self.assertFalse(pod['automountServiceAccountToken'])
            self.assertEqual(container['image'], G.PREFIX+'1'*64)
            self.assertEqual(container['command'],['/bin/sh','-ceu','/app/goose up'])
            self.assertNotIn('volumes',pod)
            self.assertNotIn('volumeMounts',container)
            self.assertNotEqual(job['metadata']['labels']['app'],'yggdrasil')

    def test_actual_m93_source_definitions_not_normalized(self):
        sql = MIGRATION.read_bytes()
        self.assertEqual(G.sha(sql),G.M93)
        rows = G.source_functions(sql.decode())
        self.assertEqual(set(rows),G.REPLACED|G.ADDED)
        self.assertEqual(rows['retirement_forward_continuation_valid']['config'],['timezone=UTC'])
        self.assertEqual(rows['retirement_forward_continuation_quiet']['volatility'],'s')
        self.assertIn("known.state='settled'",rows['retirement_forward_continuation_valid']['body'])
        for name in ('original_disposition_id','failed_original_disposition_id','native_denied_disposition_id','enrolled_failed_disposition_id'):
            self.assertIn('known.'+name+' IS NULL',rows['retirement_forward_continuation_valid']['body'])
        self.assertEqual(sum(1 for n in ast.walk(ast.parse(SOURCE.read_text())) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and n.func.attr=='request' and n.args and isinstance(n.args[0],ast.Constant) and n.args[0].value=='POST'),1)
        rows = declared_pending_rows()
        self.assertTrue(G.pending_absence_valid(*rows,G.AWS_OBSERVER_SOURCE))
        exact = b'{"other":1,"receipt":{"z":"\\u003c&","a":2}}'
        self.assertEqual(G.raw_json_member(exact,'receipt'),b'{"z":"\\u003c&","a":2}')
        for fault in ('wrong_observer','arbitrary_hold','missing_prepared','wrong_receipt_hash','wrong_sdk_request','expired_core_context'):
            prepared, returned, admitted, grant = declared_pending_rows()
            record = returned['original_record']
            if fault=='wrong_observer': record['observer_source_commit']='f'*40
            elif fault=='arbitrary_hold':
                record['observation']['hold_reasons']=['forged_pending']
                observer=G.loads(base64.b64decode(record['original_observer_return']))
                observer['observation']=record['observation']
                record['original_observer_return']=base64.b64encode(declared_json(observer)).decode()
            elif fault=='missing_prepared': prepared=None
            elif fault=='wrong_receipt_hash':
                observer=G.loads(base64.b64decode(record['original_observer_return']))
                observer['original_receipt_sha256']='f'*64
                record['original_observer_return']=base64.b64encode(declared_json(observer)).decode()
            elif fault=='wrong_sdk_request':grant['grant_record']['settlement']['original_provider_destroy_return']['request_sha256']='f'*64
            else:record['original_returned_at_core']=record['read']['original_deadline_core']
            raw=declared_json(record); returned['original_wire']='\\x'+raw.hex();returned['record_sha256']=G.sha(raw)
            self.assertFalse(G.pending_absence_valid(prepared,returned,admitted,grant,G.AWS_OBSERVER_SOURCE),fault)


    def test_catalog_query_keeps_full_reviewed_query_and_native_budgets(self):
        legacy = "BEGIN READ ONLY; SET LOCAL statement_timeout='8000ms'; SET LOCAL lock_timeout='1000ms';\nSELECT jsonb_build_object('rows90',1);\nCOMMIT;"  # DECLARED composition fixture, no SQL execution
        fake = types.SimpleNamespace(workflow_busy_logical_index92_sql=lambda:'FALSE /* declared scalar only */')
        with mock.patch.object(G,'LEGACY_CATALOG_SHA',G.sha(legacy.encode())):
            sql = G.catalog_sql(legacy,fake)
        self.assertIn("statement_timeout='8000ms'",sql)
        self.assertIn("lock_timeout='1000ms'",sql)
        self.assertIn('columns90_91',sql)
        self.assertIn('old_records',sql)
        self.assertIn('pg_get_functiondef',sql)
        for table in ('capacity_guest_retirement_forwards','capacity_guest_retirement_forward_reads','capacity_dispatch_http_maintenance_dispositions'):
            self.assertIn(table,sql)
        self.assertTrue(sql.endswith('COMMIT;'))
        with mock.patch.object(G,'LEGACY_CATALOG_SHA',G.sha(legacy.encode())):
            with self.assertRaises(G.Hold):
                G.catalog_sql(legacy.replace('rows90','forged_rows'),fake)

    def test_job_uncertainty_consumes_durable_marker_and_never_sends_again(self):
        # Only custody/HTTP boundary is declared here. Real file O_EXCL prevents
        # the second administrative send even when its first response is lost.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); claim = root/'GOOSE93-POSSIBLE-CREATE.json'; evidence = root/'migration93'; evidence.mkdir()
            def once(path, raw):
                with Path(path).open('xb') as stream: stream.write(raw)
            api = mock.Mock(); api.get.return_value = None; api.request.side_effect = TimeoutError('declared lost ACK')
            with mock.patch.object(G,'CLAIM',claim), mock.patch.object(G,'JOB_UUID','a78740e4-6263-43dc-a0b2-56eb29368119'), mock.patch.object(G,'COMPANION_IMAGE_D','1'*64):
                job = G.job_manifest()
                with mock.patch.object(G,'JOB_MANIFEST_SHA256',G.sha(G.wire(job))):
                    with self.assertRaises(TimeoutError):
                        G.create_once(api,types.SimpleNamespace(once=once),evidence,job,'2'*64,'3'*64,G.time.monotonic()+500,G.time.monotonic())
                    self.assertTrue(claim.exists())
                    with self.assertRaises(G.Hold):
                        G.create_once(api,types.SimpleNamespace(once=once),evidence,job,'2'*64,'3'*64,G.time.monotonic()+500,G.time.monotonic())
                    self.assertEqual(api.request.call_count,1)
                    self.assertEqual(api.request.call_args.args[0],'POST')
                    marker = json.loads(claim.read_bytes())
                    self.assertFalse(marker['automatic_retry'])
                    self.assertTrue(marker['effects_may_have_happened_after_marker'])
        for phase in ('absent_GET','durable_markers'):
            with tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp); evidence=root/'migration93';evidence.mkdir();clock=[100.0]
                def delayed_once(path,raw):
                    with Path(path).open('xb') as stream:stream.write(raw)
                    if phase=='durable_markers':clock[0]+=8
                def delayed_get(*args,**kwargs):
                    if phase=='absent_GET':clock[0]+=16
                    return None
                api=mock.Mock();api.get.side_effect=delayed_get
                with mock.patch.object(G,'CLAIM',root/'POSSIBLE.json'),mock.patch.object(G,'JOB_UUID','a78740e4-6263-43dc-a0b2-56eb29368119'),mock.patch.object(G,'COMPANION_IMAGE_D','1'*64),mock.patch.object(G.time,'monotonic',side_effect=lambda:clock[0]):
                    job=G.job_manifest()
                    with mock.patch.object(G,'JOB_MANIFEST_SHA256',G.sha(G.wire(job))):
                        with self.assertRaises(G.Hold):G.create_once(api,types.SimpleNamespace(once=delayed_once),evidence,job,'2'*64,'3'*64,1000.0,100.0)
                    self.assertTrue(G.CLAIM.exists())
                    api.request.assert_not_called()


    def test_closed_http_scope_forbids_core_patch_delete_and_other_job(self):
        inner = mock.Mock(); inner.request.side_effect = AssertionError('transport must not be reached')
        c = types.SimpleNamespace(once=lambda *_:None)
        with mock.patch.object(G,'JOB_UUID','a78740e4-6263-43dc-a0b2-56eb29368119'):
            api = G.CapturedAPI(inner,c,Path('/declared'),True)
            for method, uri, body in [('PATCH',G.DEP_URI,b'{}'),('DELETE',G.JOB_URI+'/old',None),('POST',G.DEP_URI,b'{}'),('GET','/api/v1/secrets',None)]:
                with self.assertRaises(G.Hold): api.request(method,uri,body)
        inner.request.assert_not_called()

    def test_exact_approved_catalog_delta_rejects_old_record_or_body_change(self):
        # A declared catalogue fixture exercises only comparison logic; actual
        # M93 creation/eligibility is independently covered by repository PG CI.
        funcs = G.source_functions(MIGRATION.read_text())
        history = [{'id':i+1,'version_id':v,'is_applied':True} for i,v in enumerate([0]+[n for n in range(1,93)if n!=40])]
        old90={'tables':[],'indexes':[],'triggers':[], 'functions':[{'name':n,'definition':'old-'+n}for n in sorted(G.REPLACED)], 'constraints':[{'table':'capacity_guest_retirement_forwards','name':'old_mode','definition':'mode actual_core_source','validated':True}]}
        old91={'full':'declared unchanged'}
        old={'legacy':{'database':'yggdrasil','readonly':'on','latest_versions':[r['version_id']for r in history],'rows90':1,'rows91':1,'other_migrators_ddl':0,'other_cic':0,'ddl_locks':0,'complete_history_wire':json.dumps(history),'catalog90':old90,'catalog91':old91},
             'supplement':{'columns90_91':[],'old_records':{'declared':'hash'},'index92_valid':True,'index92_definition':'declared-index','functions93':[{'name':n}for n in sorted(G.REPLACED)]}}
        accepted={'complete_history_sha256':G.sha(old['legacy']['complete_history_wire'].encode()),'schema90_91_catalog_sha256':G.sha(G.wire({'catalog90':old90,'catalog91':old91})),'index92_definition_sha256':G.sha(b'declared-index')}
        G.check_catalog(old,accepted,funcs)
        after=copy.deepcopy(old); after['legacy']['latest_versions'].append(93)
        after['legacy']['complete_history_wire']=json.dumps(history+[{'id':len(history)+1,'version_id':93,'is_applied':True}])
        after['legacy']['catalog90']['constraints']=[{'table':'capacity_guest_retirement_forwards','name':n,'definition':'declared Root review pending','validated':True}for n in sorted(G.CHECKS93)]
        after['supplement']['functions93']=[{'name':n,**v,'definition':'declared'}for n,v in sorted(funcs.items())]
        G.check_catalog(after,accepted,funcs,old)
        for fault in ('records','body','columns','index','wrong_check_relation','unknown_constraint'):
            bad=copy.deepcopy(after)
            if fault=='records':bad['supplement']['old_records']={}
            elif fault=='body':bad['supplement']['functions93'][0]['body']+=' '
            elif fault=='columns':bad['supplement']['columns90_91'].append({'changed':True})
            elif fault=='index':bad['supplement']['index92_valid']=False
            elif fault=='wrong_check_relation':bad['legacy']['catalog90']['constraints'][0]['table']='capacity_guest_retirement_forward_reads'
            else:bad['legacy']['catalog90']['constraints'].append({'name':'foreign','definition':'foreign','validated':True})
            with self.assertRaises(G.Hold):G.check_catalog(bad,accepted,funcs,old)


def declared_json(value):
    # Deliberate Go-shaped fixture order. Never a Root input or Native receipt.
    return json.dumps(value,separators=(',',':'),ensure_ascii=True).encode()


def declared_pending_rows():
    at='2026-11-04T16:42:40Z';done='2026-11-04T16:42:40.3Z'
    tuple_={'provider':'aws','integration_instance_id':'declared-instance','scope_checksum':'a'*64,'profile':'declared','resource_id':'i-00000000000000001','resource_created_at':'2026-11-04T10:00:00Z'}
    native={'grant_id':G.S2_GRANT,'binding_name':'declared','integration_instance_id':tuple_['integration_instance_id'],'scope_checksum':tuple_['scope_checksum'],'profile_name':tuple_['profile'],'slot':2,'capability':'destroy_ec2_instance','request_sha256':'b'*64,'expected_resource_id':tuple_['resource_id'],'expected_resource_created_at':tuple_['resource_created_at'],'state':'settled'}
    aux=[{'kind':'aws_ebs_volume','id':'vol-00000000000000001','requires_absence':True},{'kind':'aws_network_interface','id':'eni-00000000000000001','requires_absence':True}]
    sdk={'schema':'aws_original_terminate_instances_return_v1','provider':'aws','adapter_source_commit':'c'*40,'grant_id':G.S2_GRANT,'attempt_id':'declared-attempt','request_sha256':native['request_sha256'],'resource_id':tuple_['resource_id'],'resource_created_at':tuple_['resource_created_at'],'action_id':'declared-action','next_action_ids':[],'called_at':'2026-11-04T16:41:43Z','returned_at':'2026-11-04T16:41:43.2Z','context_deadline':'2026-11-04T16:42:12Z','response_status':200,'response_body_sha256':'e'*64,'response_bytes':100}
    settlement={'outcome':'accepted','transport_completed':True,'resource_id':tuple_['resource_id'],'resource_created_at':tuple_['resource_created_at'],'action_id':'declared-action','next_action_ids':[],'auxiliary_resources':aux,'auxiliary_inventory_complete':True,'original_provider_destroy_return':sdk}
    grant={'id':G.S2_GRANT,'state':'settled','grant_record':{'grant':native,'binding':{'original_provider_source_commit':'c'*40},'attempt_id':'declared-attempt','settlement':settlement},**{k:None for k in ('original_disposition_id','failed_original_disposition_id','native_denied_disposition_id','enrolled_failed_disposition_id')}}
    receipt={'grant':native,'attempt_id':'declared-attempt','outcome':'accepted','transport_completed':True,'resource_id':tuple_['resource_id'],'resource_created_at':tuple_['resource_created_at'],'action_id':'declared-action','auxiliary_resources':aux,'auxiliary_inventory_complete':True}
    def row(record,**meta):
        raw=declared_json(record)
        return {'original_record':json.loads(raw),'original_wire':'\\x'+raw.hex(),'record_sha256':G.sha(raw),'recorded_at':at,**meta}
    admitted=row({'stage':'admitted','retirement_request_id':G.S2_INTENT,'prefix_sha256':'d'*64,'original_caller_sha256':'e'*64,'original':{'Request':{'intent':{'tuple':tuple_}}}},id=G.S2_FORWARD,stage='admitted')
    read={'schema':'original_core_guest_retirement_forward_read_v1','read_id':'declared-read','admission_id':G.S2_FORWARD,'retirement_request_id':G.S2_INTENT,'kind':'absence','admission_sha256':admitted['record_sha256'],'prefix_sha256':'d'*64,'original_caller_sha256':'e'*64,'mutation_binding_sha256':'f'*64,'adapter_source_commit':'c'*40,'tuple':tuple_,'destroy_grant_id':G.S2_GRANT,'issued_at_core':at,'original_deadline_core':'2026-11-04T16:42:45Z'}
    prepared=row(read,id='declared-read',stage='prepared',kind='absence',admission_id=G.S2_FORWARD,retirement_request_id=G.S2_INTENT)
    observation={'aws_retirement_lifecycle':{'schema':'aws_original_terminate_and_native_absence_v1','request_id':'declared-action','ec2_state':'terminated','observed_at':'2026-11-04T16:42:40.2Z'},'id':tuple_['resource_id'],'created_at':tuple_['resource_created_at'],'destroy_grant_id':G.S2_GRANT,'destroy_grant_state':'settled','original_outcome':'accepted','original_transport_completed':True,'server_absent':True,'server_absence_complete':True,'server_observed_at':'2026-11-04T16:42:40.1Z','delete_action':{'known':False,'observed':False},'next_actions':[],'auxiliary_resources':[{'kind':v['kind'],'id':v['id'],'absent':n==0,'observed_at':'2026-11-04T16:42:40.2Z'}for n,v in enumerate(aux)],'auxiliary_inventory_complete':True,'billable_resources_absent':False,'retirement_complete':False,'hold_reasons':['aws_network_interface_still_present'],'invoice_reconciled':False,'writer_quiescence_evidence':False,'provider_fencing_evidence':False,'observation_started_at':at,'observed_at':'2026-11-04T16:42:40.2Z'}
    observer={'schema':'original_settled_retirement_absence_read_return_v1','observer_source_commit':G.AWS_OBSERVER_SOURCE,'original_adapter_source_commit':'c'*40,'read_id':'declared-read','read_sha256':prepared['record_sha256'],'original_receipt_sha256':G.sha(declared_json(receipt)),'observation':observation}
    returned=row({'schema':'original_core_guest_retirement_forward_read_return_v1','read':read,'status':'observed','observation':observation,'original_destroy_receipt':receipt,'started_at_core':at,'original_returned_at_core':done,'call_failed':False,'original_context_failed':False,'observer_source_commit':G.AWS_OBSERVER_SOURCE,'original_observer_return':base64.b64encode(declared_json(observer)).decode()},id='declared-read',stage='returned',kind='absence',admission_id=G.S2_FORWARD,retirement_request_id=G.S2_INTENT)
    returned['recorded_at']='2026-11-04T16:42:40.4Z'
    return prepared,returned,admitted,grant


if __name__ == '__main__':
    unittest.main()
