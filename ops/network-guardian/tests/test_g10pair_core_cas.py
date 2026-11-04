"""G10 image maintenance: declared current rows, never retirement authority."""
import ast
import copy
import json
from pathlib import Path
import subprocess
import tempfile
import types
import unittest
from unittest.mock import patch

import test_g10pair_source as source
import test_g9pair_core_cas as historical

CAS_PATH=source.ROOT/'rollout/core_image_cas_once_g10.py'
cas=source.load(CAS_PATH)


def known_operand():
    request={'declared':'same historical original request'}
    evidence={'caller_sha256':'1'*64,'nonce_sha256':'2'*64,'journal_sha256':['3'*64,'4'*64,'5'*64],
              'authority_sha256':['6'*64,'7'*64,'8'*64,'9'*64]}
    i={'generation':14,'fencing_token':30,'phase':'drained','lease_owner':'ee16e55c-3efa-4667-bfd1-b1deb2313432',
       'lease_executor_id':'7f039d97-8374-4f53-919f-4640e718ffb8','lease_expires_at':cas.LEASE,
       'retirement_forward':{'id':cas.CHILD,'stage':'admitted','retirement_request_id':'376a7e86-905d-44dd-8583-c8fed2ecac1a',
       'preregistration_id':'20e58827-cfe9-403e-8e34-765547326927'}}
    w={'id':cas.FAILED,'status':'failed','finished_at':'2026-11-04T04:43:15.100000Z'}
    rows=[]
    for identifier,stage in ((cas.PARENT,'requested'),(cas.PARENT,'admitted'),(cas.PARENT,'off_qualified'),(cas.CHILD,'requested'),(cas.CHILD,'admitted')):
        x={'id':identifier,'stage':stage,'root_admission_id':cas.PARENT,'original':{'Request':request},
           'evidence':copy.deepcopy(evidence),'original_caller_sha256':evidence['caller_sha256']}
        if identifier==cas.CHILD:
            x.update(parent_admission_id=cas.PARENT,parent_admission_sha256=rows[2]['record_sha256'])
        if identifier==cas.CHILD and stage=='admitted':
            x.update(generation=14,fence=30,lease_owner=i['lease_owner'],executor_id=i['lease_executor_id'],
                     run_id=cas.FAILED,destroy_grant_id=cas.DESTROY)
        raw=cas.canonical(x)
        rows.append({'id':identifier,'stage':stage,'record_sha256':cas.sha(raw),'original_record':x,
                     'original_wire':'\\x'+raw.hex(),'preregistration_id':i['retirement_forward']['preregistration_id']})
    eligibility={'schema':'original_guest_partial_poweroff_delete_eligibility_v1','admission_id':cas.PARENT,
                 'admission_sha256':rows[1]['record_sha256']}
    grant={'id':cas.DESTROY,'state':'settled','namespace':'dakasa-production','environment':'production','domain':'notify',
           'dimension':'original_notify_aws_vm_members','original_disposition_id':None,'failed_original_disposition_id':None,
           'native_denied_disposition_id':None,'enrolled_failed_disposition_id':None,
           'grant_record':{'settlement':{'grant_id':cas.DESTROY,'outcome':'accepted','transport_completed':True,'auxiliary_inventory_complete':True}}}
    v={'observed_at_pg':'2026-11-04T05:00:00Z','intent_pgtext':cas.canonical(i).decode(),
       'failed_run_pgtext':cas.canonical(w).decode(),
       'dispatch':[{'id':'4d861caf-b785-4726-952a-4a93da13169c','run_id':cas.FAILED,'state':'returned','return_status':'failed',
                    'returned_at':w['finished_at'],'finalization_ack_at':'2026-11-04T04:43:15.113019Z',
                    'envelope':{'workflow':{'id':'9bb4a35b-6eb4-4983-9133-73bd96cfea94'}}}],
       'forwards':rows,'destroy':grant,
       'delete_bindings':[{'destroy_grant_id':cas.DESTROY,'intent_id':i['retirement_forward']['retirement_request_id'],
                          'original_eligibility_record':eligibility,'original_wire':'\\x'+cas.canonical(eligibility).hex()}],
       'original_intent':{'id':i['retirement_forward']['retirement_request_id']},
       'original_returns':[{'sequence':1,'kind':'production_clock_nonce_v2','return_sha256':evidence['nonce_sha256'],
                            'original_return_record':{'final_request':request}}]+
                           [{'sequence':n,'return_sha256':pin}for n,pin in enumerate(evidence['journal_sha256'],2)],
       'original_callers':[{'return_sha256':evidence['caller_sha256']}],
       'original_authorities':[{'read':{'ordinal':n},'return':{'authority_sha256':pin}}for n,pin in enumerate(evidence['authority_sha256'])]}
    return v,{'current_intent_sha256':cas.sha(v['intent_pgtext'].encode()),'failed_run_sha256':cas.sha(v['failed_run_pgtext'].encode())}


def change_intent(v,c,fn):
    i=json.loads(v['intent_pgtext']);fn(i);v['intent_pgtext']=cas.canonical(i).decode();c['current_intent_sha256']=cas.sha(v['intent_pgtext'].encode())


class G10CASTests(unittest.TestCase):
    def test_inert_before_any_source_input_api_or_private_write(self):
        with patch.object(cas,'PROPOSAL_BOUND',False),patch.object(cas,'read')as read, \
                patch.object(cas,'load_tools')as tools,patch.object(cas,'API')as api:
            with self.assertRaises(cas.Hold):cas.main()
            read.assert_not_called();tools.assert_not_called();api.assert_not_called()

    def test_known_child_is_maintenance_only_and_preserves_original_bytes(self):
        v,c=known_operand();raw=cas.canonical(v)
        self.assertTrue(cas.validate_known_child(v,c,json.loads))
        self.assertEqual(cas.canonical(v),raw)
        for digits,microseconds in enumerate((100000,120000,123000,123400,123450,123456,123456,123456,123456),1):
            fraction='123456789'[:digits]
            expected=cas.datetime.datetime(2026,11,4,19,18,53,microseconds,tzinfo=cas.datetime.timezone.utc)
            for zone in ('Z','+00:00'):
                stamp='2026-11-04T19:18:53.'+fraction+zone
                with self.subTest(fraction_digits=digits,zone=zone):
                    self.assertEqual(cas.utc(stamp),expected)
                    declared,config=known_operand();declared['observed_at_pg']=stamp
                    original=cas.canonical(declared)
                    self.assertTrue(cas.validate_known_child(declared,config,json.loads))
                    self.assertEqual(cas.canonical(declared),original)
        # The real PostgreSQL CI return had five digits; parse a copy only.
        stamp='2026-11-04T19:18:53.36165+00:00'
        self.assertEqual(cas.utc(stamp),cas.datetime.datetime(2026,11,4,19,18,53,361650,tzinfo=cas.datetime.timezone.utc))
        self.assertEqual(stamp,'2026-11-04T19:18:53.36165+00:00')

    def test_foreign_child_parent_epoch_lease_and_grant_are_refused(self):
        mutations=(lambda i:i.update(fencing_token=29),lambda i:i.update(generation=15),
                   lambda i:i.update(lease_owner=cas.PARENT),lambda i:i.update(lease_executor_id=cas.PARENT),
                   lambda i:i['retirement_forward'].update(id=cas.PARENT),lambda i:i['retirement_forward'].update(stage='terminal'))
        for mutate in mutations:
            v,c=known_operand();change_intent(v,c,mutate)
            with self.subTest(mutation=repr(mutate)),self.assertRaises(cas.Hold):cas.validate_known_child(v,c,json.loads)
        for key,value in (('state','confirmed'),('id',cas.PARENT),('dimension','other')):
            v,c=known_operand();v['destroy'][key]=value
            with self.subTest(grant=key),self.assertRaises(cas.Hold):cas.validate_known_child(v,c,json.loads)
        v,c=known_operand();v['observed_at_pg']=cas.LEASE
        with self.assertRaises(cas.Hold):cas.validate_known_child(v,c,json.loads)

    def test_failed_ack_full_frame_and_original_authorities_cannot_be_replaced(self):
        changes=(lambda v:v['dispatch'][0].update(finalization_ack_at=None),
                 lambda v:v['dispatch'][0].update(return_status='succeeded'),
                 lambda v:v['dispatch'][0].update(run_id=cas.PARENT),
                 lambda v:v['forwards'].append(copy.deepcopy(v['forwards'][0])),
                 lambda v:v['forwards'][-1]['original_record'].update(parent_admission_id=cas.CHILD),
                 lambda v:v['forwards'][0].update(original_wire='\\x7b7d'),
                 lambda v:v['original_returns'][0].update(return_sha256='f'*64),
                 lambda v:v['original_authorities'].pop(),
                 lambda v:v['original_callers'].append(copy.deepcopy(v['original_callers'][0])),
                 lambda v:v['delete_bindings'][0]['original_eligibility_record'].update(admission_id=cas.CHILD),
                 lambda v:v['destroy']['grant_record']['settlement'].update(auxiliary_inventory_complete=False))
        for n,mutate in enumerate(changes):
            v,c=known_operand();mutate(v)
            with self.subTest(vector=n),self.assertRaises(cas.Hold):cas.validate_known_child(v,c,json.loads)

    def test_new_busy_rows_roster_drift_and_extra_authority_never_inherit_exception(self):
        v,c=known_operand();c.update(schema_pins={},current_preimage_ref={},policy_state={})
        quiet={'intent_count':1,'jobs_busy':0,'runs_busy':0,'forward_unreturned_reads':0,'live_unreturned_canaries':0,
               'intent_busy':1,'pending_authority':1,'forward_markers':1,'intent_identity':{'declared':'aws'},
               'owned_slots':[1,2,3],'active_policies':[{'declared':'policy'}],'policy_catalog_wire':'declared'}
        hz={**quiet,'intent_busy':0,'pending_authority':0,'forward_markers':0,'intent_identity':{'declared':'hz'}}
        for provider,value in (('aws',quiet),('hetzner',hz)):
            c['policy_state'][provider]={k:value[k]for k in ('intent_identity','owned_slots','active_policies','policy_catalog_wire')}
        sql={'queries':{'original_notify_aws_vm_members':'SELECT 1','original_notify_hetzner_vm_members':'SELECT 2'}}
        fake=types.SimpleNamespace(C=types.SimpleNamespace(loads=json.loads))
        def run(values):
            with patch.object(cas,'input_ref',return_value=cas.canonical(v)),patch.object(cas,'schema_facts'),patch.object(cas,'query',side_effect=values):
                cas.database_known_child(fake,Path('/CI-only'),c,sql,'BEFORE')
        run([quiet,hz,v])
        for field in ('jobs_busy','runs_busy','forward_unreturned_reads','live_unreturned_canaries','pending_authority','forward_markers'):
            bad=copy.deepcopy(quiet);bad[field]+=1
            with self.subTest(field=field),self.assertRaises(cas.Hold):run([bad,hz,v])
        bad=copy.deepcopy(hz);bad['policy_catalog_wire']='changed'
        with self.assertRaises(cas.Hold):run([quiet,bad,v])

    def test_full_patch_shape_and_sql_original_helpers_remain_exact(self):
        for name in ('retained_dispatch_terminal_ctes','workflow_busy_logical_index92_sql'):
            self.assertEqual(source.source_span(CAS_PATH,None,name),source.source_span(historical.CAS_PATH,None,name))
        before={'apiVersion':'apps/v1','kind':'Deployment','metadata':{'uid':cas.UID,'generation':273,
                'annotations':{'dakasa.io/core-source-commit':cas.OLD_SOURCE,'unrecognized':'preserve'},'labels':{'unknown':'preserve'}},
                'spec':{'template':{'spec':{'containers':[{'name':'core','image':'old','env':[{'name':'declared','value':'data'}]}]}},
                        'unknown':{'preserve':[1,2]}}}
        with patch.multiple(cas,GENERATION=273,CORE_R='c'*40,CHANGE_CAUSE='declared CI cause'):
            C=types.SimpleNamespace(IMAGE_PREFIX='declared@sha256:',NEW_DIGEST='d'*64)
            after=copy.deepcopy(before);after['spec']['template']['spec']['containers'][0]['image']=C.IMAGE_PREFIX+C.NEW_DIGEST
            after['metadata']['generation']=274;after['metadata']['annotations'].update({'dakasa.io/core-source-commit':cas.CORE_R,'kubernetes.io/change-cause':cas.CHANGE_CAUSE})
            cas.result_shape(before,after,C)
            for key in ('unknown','template'):
                wrong=copy.deepcopy(after);wrong['spec'].pop(key)
                with self.subTest(key=key),self.assertRaises(cas.Hold):cas.result_shape(before,wrong,C)

    def test_sql_timeout_and_partial_originals_keep_real_custody(self):
        def wire(v):return cas.canonical(v)
        fake=types.SimpleNamespace(KUBE=['declared-kube'],C=types.SimpleNamespace(wire=wire,loads=json.loads))
        for result in (subprocess.TimeoutExpired(['declared'],8,output=b'partial',stderr=b'failed'),
                       subprocess.CompletedProcess(['declared'],1,b'bad',b'error')):
            with tempfile.TemporaryDirectory()as d:
                saved={};fake.C.once=lambda p,b:saved.setdefault(Path(p).name,b)
                with patch.object(cas.subprocess,'run',side_effect=result if isinstance(result,Exception)else None,
                                  return_value=result if not isinstance(result,Exception)else None)as invoke:
                    with self.assertRaises(cas.Hold):cas.query(fake,Path(d),'capture','SELECT 1')
                self.assertEqual(invoke.call_count,1)
                self.assertEqual(invoke.call_args.kwargs['timeout'],8)
                self.assertIn("statement_timeout='3s'",saved['capture.sql'].decode())
                self.assertIn("lock_timeout='500ms'",saved['capture.sql'].decode())
                self.assertTrue(saved['capture.sql'].decode().endswith('ROLLBACK;\n'))
                self.assertIn('capture.stdout',saved);self.assertIn('capture.stderr',saved)
                receipt=json.loads(saved['capture.RETURN.json']);self.assertEqual(receipt['timed_out'],isinstance(result,Exception))


class G10KnownChildPostgresTests(unittest.TestCase):
    """Execute the new complete SELECT on declared columns in the existing PG16 service."""
    setUpClass=classmethod(historical.old.G8CASPostgresTests.setUpClass.__func__)
    pg=historical.old.G8CASPostgresTests.pg

    def test_full_known_child_select_rollback_and_extra_descendant_refusal(self):
        self.pg('DROP SCHEMA public CASCADE; CREATE SCHEMA public;')
        v,c=known_operand();intent=json.loads(v['intent_pgtext']);w=json.loads(v['failed_run_pgtext'])
        request=intent['retirement_forward']['retirement_request_id']
        tables={
            'capacity_intents':[{'namespace':'dakasa-production','environment':'production','domain':'notify',
                                 'dimension':'original_notify_aws_vm_members','intent':intent}],
            'workflow_runs':[w], 'capacity_dispatch_jobs':v['dispatch'],
            'capacity_guest_retirement_forwards':v['forwards'], 'capacity_mutation_grants':[v['destroy']],
            'capacity_vm_retirement_delete_bindings':v['delete_bindings'], 'capacity_vm_retirement_intents':[v['original_intent']],
            'capacity_vm_retirement_original_returns':[{**r,'intent_id':request,'kind':r.get('kind','declared journal'),
                                                       'original_return_record':r.get('original_return_record',{})}for r in v['original_returns']],
            'capacity_guest_original_caller_returns':[{**r,'intent_id':request}for r in v['original_callers']],
            'capacity_guest_original_authority_reads':[{'id':str(n),'intent_id':request,'phase':'before_start'if n<2 else'after_start','ordinal':n}for n in range(4)],
            'capacity_guest_original_authority_returns':[{'read_id':str(n),'authority_sha256':r['return']['authority_sha256']}for n,r in enumerate(v['original_authorities'])]}
        for table,rows in tables.items():
            keys=sorted({k for row in rows for k in row})
            column_types={k:('bytea'if k=='original_wire' else 'jsonb'if any(type(row.get(k))in(dict,list)for row in rows)
                            else 'integer'if any(type(row.get(k))is int for row in rows)else 'text')for k in keys}
            definition=','.join('"'+k+'" '+column_types[k]for k in keys)
            raw=json.dumps(rows).replace("'","''")
            self.pg('CREATE TABLE '+table+'('+definition+'); INSERT INTO '+table+' SELECT * FROM jsonb_populate_recordset(NULL::'+table+",'"+raw+"'::jsonb);")
        def snapshot():
            fields=["'"+name+"',(SELECT jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text) FROM "+name+' t)'for name in sorted(tables)]
            return self.pg('SELECT jsonb_build_object('+','.join(fields)+');').stdout
        before=snapshot()
        wrapped="BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY; SET LOCAL statement_timeout='3s'; SET LOCAL lock_timeout='500ms'; SET LOCAL timezone='UTC';\n"+cas.KNOWN_CHILD_SQL+';\nROLLBACK;'
        actual=json.loads(self.pg(wrapped).stdout)
        c['current_intent_sha256']=cas.sha(actual['intent_pgtext'].encode())
        c['failed_run_sha256']=cas.sha(actual['failed_run_pgtext'].encode())
        self.assertTrue(cas.validate_known_child(actual,c,json.loads))
        self.assertEqual(snapshot(),before)
        self.pg("INSERT INTO capacity_guest_retirement_forwards SELECT '11111111-1111-4111-8111-111111111111', original_record, original_wire, preregistration_id, record_sha256, stage FROM capacity_guest_retirement_forwards WHERE id='"+cas.CHILD+"' AND stage='requested';")
        altered=snapshot();actual=json.loads(self.pg(wrapped).stdout)
        with self.assertRaises(cas.Hold):cas.validate_known_child(actual,c,json.loads)
        self.assertEqual(snapshot(),altered)
