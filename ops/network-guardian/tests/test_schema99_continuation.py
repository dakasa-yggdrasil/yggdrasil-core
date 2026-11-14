"""CI-only declared99 continuation operands; no Native or cycle authority."""
import ast
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import types
import unittest
from unittest import mock

from test_catalog99 import declared_preaction99
from test_restore98_same_epoch_lineage import declared_restoration, policy_for
import hz_preservation_operands as HZ

ROLLOUT=Path(__file__).resolve().parent.parent/'rollout'

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m);return m

C=load('declared_core10_cas99',ROLLOUT/'core_image_cas_once_g15_schema99.py')
P=load('declared_core10_post99',ROLLOUT/'post_core_inventory_schema99_readonly.py')
R=load('declared_core10_restore99',ROLLOUT/'restore99_preaction_continuation.py')
W=load('declared_core10_watch99',ROLLOUT/'watch_preaction_readiness_continuation_readonly.py')
O=load('declared_old_restore98',ROLLOUT/'restore98_recovered_g44.py')
H=load('declared_catalog99_for_continuation',ROLLOUT/'catalog99_helpers.py')

def wire(value):return (json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()
def sha(value):return hashlib.sha256(value).hexdigest()
def pg(value):return '\\x'+value.hex()
def uid(number):return '00000000-0000-4000-8000-%012d'%number

def fixture():
    """Declared pure validation data; actual natural PG cases are separate."""
    preimage,case,before=declared_preaction99();legacy=declared_restoration()
    saved=copy.deepcopy(legacy['saved']);saved['disposition']=copy.deepcopy(before['anchor'])
    anchor=saved['disposition'];record=anchor['original_record']
    ready=saved['readiness_job'];ready.update(created_at='2026-11-11T21:00:00Z',
        started_at='2026-11-11T21:00:01Z',returned_at='2026-11-11T21:00:03Z',
        updated_at='2026-11-11T21:00:03Z',finalization_ack_at='2026-11-11T21:00:03Z',
        lease_expires_at='2026-11-11T21:05:00Z')
    env=copy.deepcopy(json.loads(before['job']['envelope']));env.update(job_id=ready['id'],
        run_id=ready['run_id'],source_tick=ready['created_at'])
    env['metadata'].update(capacity_dispatch_job_id=ready['id'],scheduled_for=ready['created_at'])
    ready['envelope']=wire(env).decode();ready['envelope_sha256']=sha(ready['envelope'].encode())
    saved['readiness_run'].update(started_at=ready['started_at'],finished_at=ready['returned_at'])
    current=json.loads(saved['current_intent_wire']);current['installed_guest_reconcile'].update(
        installed_provision_timeout_disposition_id=anchor['id'],new_run_id=ready['run_id'])
    current['updated_at']=ready['returned_at'];saved['current_intent_wire']=wire(current).decode()
    saved['observed_at']='2026-11-11T21:00:04Z'
    j,w=copy.deepcopy(before['job']),copy.deepcopy(before['run'])
    j['updated_at']=j['returned_at'];j.setdefault('pending_wake_count',32)
    original_domains=[wire(j),wire(w),bytes.fromhex(anchor['original_intent_wire'][2:]),
        bytes.fromhex(anchor['members_wire'][2:]),wire(before['scan'])]
    receipt={'schema':'unknown_preaction_failed_plan_disposition_v1','id':uid(990),
        'job_id':j['id'],'run_id':w['id'],'successor_job_id':ready['id'],'successor_run_id':ready['run_id'],
        'root_anchor_id':anchor['id'],'policy_id':case['policy_id'],'policy_checksum':case['policy_checksum'],
        'generation':44,'fencing_token':85,'original_deadline':j['lease_expires_at'],
        'original_returned_at':j['returned_at'],'recorded_at':'2026-11-11T21:00:00Z'}
    for key,raw in zip(('original_dispatch_sha256','original_run_sha256','original_intent_sha256',
                        'members_sha256','evidence_sha256'),original_domains):receipt[key]=sha(raw)
    row={k:receipt[k]for k in('id','job_id','run_id','successor_job_id','successor_run_id','recorded_at')}
    row.update(original_record=receipt,original_wire=pg(wire(receipt)))
    for key,raw in zip(('original_dispatch_wire','original_run_wire','original_intent_wire',
                        'members_wire','evidence_wire'),original_domains):row[key]=pg(raw)
    terminal=copy.deepcopy(j);terminal.update(state='preaction_plan_disposed',updated_at=receipt['recorded_at'])
    item={'row':row,'predicate_valid':True,'job':terminal,'run':w,'successor_job':copy.deepcopy(ready),
          'successor_run':copy.deepcopy(saved['readiness_run'])}
    value={'schema':'recovered_preaction_plan_continuation_v1','observed_at':saved['observed_at'],
        'installed_recovery':saved,'preaction_dispositions':[item]}
    raw=wire(value);component=R.member_wire99(raw,'installed_recovery')
    outer_ref={'path':'/declared99/whole.original.json','sha256':sha(raw)}
    component_ref={'path':'/declared99/component.original.json','sha256':sha(component)}
    blobs={outer_ref['path']:raw,component_ref['path']:component}
    # The original preimage may have legitimate bounded coalesced wakes before
    # classification. Keep every other original field exact in both domains.
    before['job']=copy.deepcopy(j);preimage['records_wire']=wire(before).decode()
    case['expected_records_sha256']=sha(preimage['records_wire'].encode())
    proof=R.promotion99(value,case,preimage,O,H,outer_ref,component_ref)
    expected={'schema':'root_saved_preaction_continuation_originals_v1',
        'whole_continuation_original_ref':outer_ref,'installed_timeout_recovery':proof['installed_timeout_recovery']}
    bundle={'context':{'preaction_case':case},'preaction_preimage':preimage,'old':O,'helper':H}
    fresh=copy.deepcopy(value);v=fresh['installed_recovery']
    v['same_epoch_lineage']={'schema':'same_G44_ordinary_refresh_lineage_v1',
        'anchor_job_id':ready['id'],'anchor_run_id':ready['run_id'],'anchor_created_at':ready['created_at'],
        'jobs_wire':wire([terminal]).decode(),'job_count':1,'job_ids':[terminal['id']],
        'runs_wire':wire([w]).decode(),'run_count':1,'run_ids':[w['id']],
        'vm_grant_changes_wire':wire([]).decode(),'vm_grant_change_count':0}
    def read(ref):
        data=blobs[ref['path']]
        if sha(data)!=ref['sha256']:raise AssertionError('declared whole reference mismatch')
        return data
    return dict(value=value,case=case,preimage=preimage,bundle=bundle,expected=expected,
                read=read,blobs=blobs,fresh=fresh,component_ref=component_ref,outer_ref=outer_ref)


class Schema99ContinuationTests(unittest.TestCase):
    def test_current_core9_preimage_and_inert_operators(self):
        HZ.exercise_same_and_allowed_refresh_preserves_whole_originals(self)
        self.assertFalse(C.SOURCE_BOUND);self.assertFalse(P.SOURCE_BOUND);self.assertFalse(W.SOURCE_BOUND)
        self.assertIsNone(C.ROOT99_SHA);self.assertIsNone(P.ROOT99_REF)
        self.assertIsNone(P.CORE_R);self.assertIsNone(W.SOURCE_R);self.assertIsNone(W.CONFIG_REF)
        # The caller must join the frozen cfg hashes to its own actual full
        # body before considering observational changes against the known root.
        before=HZ.fixture();full=before['hetzner']['hz_current_full']
        fields=('intent_identity','owned_slots','active_policies','policy_catalog_wire')
        projection={k:copy.deepcopy(before['hetzner'][k])for k in fields}
        context={'helper_source_ref':{'path':'/declared99/HZ-helper.py','sha256':'f'*64}}
        config={'preaction_case':{'provider_lanes':{'known_hz_preservation':context}},
                'policy_state':{'hetzner':projection}}
        inputs={'known_baseline':copy.deepcopy(full),'policy_state_full':copy.deepcopy(full),
                'fixed_current_sql':HZ.G.HZ_CURRENT_SQL}
        with mock.patch.object(C,'pure99_module',return_value=HZ.G),mock.patch.object(HZ.G,'inputs',return_value=inputs):
            self.assertEqual(C.known_hz99_inputs(config,object())[1],inputs)
            bad=copy.deepcopy(config);bad['policy_state']['hetzner']['intent_identity'][0]['intent_sha256']='f'*64
            with self.assertRaises(HZ.G.Hold):C.known_hz99_inputs(bad,object())
        for m,call in((C,C.require_source_bound),(P,P.require_bound),(W,W.main)):
            with mock.patch.object(m,'read' if hasattr(m,'read')else'read_private',side_effect=AssertionError('IO forbidden')):
                with self.assertRaises((C.Hold,P.Hold,W.Hold)):call()
        # Retain all historical function/class source spans, not just their names.
        for current,previous in((C,'core_image_cas_once_g15_schema98.py'),(P,'post_core_inventory_schema98_readonly.py')):
            old=(ROLLOUT/previous).read_text();new=Path(current.__file__).read_text()
            oldlines=old.splitlines();newlines=new.splitlines()
            nodes={n.name:n for n in ast.parse(new).body if isinstance(n,(ast.FunctionDef,ast.ClassDef))}
            for n in ast.parse(old).body:
                if isinstance(n,(ast.FunctionDef,ast.ClassDef)):
                    other=nodes[n.name]
                    self.assertEqual(oldlines[n.lineno-1:n.end_lineno],newlines[other.lineno-1:other.end_lineno],n.name)
        ctl=types.SimpleNamespace(OLD_DIGEST=C.CURRENT_CORE9_DIGEST,OLD_CORE_SOURCE=C.CURRENT_CORE9_SOURCE,
            IMAGE_PREFIX='registry/core@sha256:')
        image=ctl.IMAGE_PREFIX+ctl.OLD_DIGEST
        d={'apiVersion':'apps/v1','kind':'Deployment','metadata':{'namespace':'dakasa','name':'yggdrasil',
            'uid':uid(1),'generation':282,'resourceVersion':'42','annotations':{'dakasa.io/core-source-commit':ctl.OLD_CORE_SOURCE}},
            'status':{'observedGeneration':282,'readyReplicas':1,'updatedReplicas':1,'availableReplicas':1},
            'spec':{'replicas':1,'template':{'spec':{'containers':[{'name':'core','image':image}]}}}}
        pod={'metadata':{'uid':uid(2),'name':'declared-core9'},'spec':{'containers':[{'name':'core','image':image}]},
            'status':{'phase':'Running','podIP':'127.0.0.1','containerStatuses':[{'name':'core','ready':True,
                'restartCount':0,'state':{'running':{'startedAt':'2026-11-11T20:08:49Z'}},
                'imageID':image,'containerID':'containerd://'+'a'*64}]}}
        with mock.patch.multiple(C,UID=uid(1),GENERATION=282,OLD_POD=uid(2),OLD_CONTAINER_ID='containerd://'+'a'*64):
            self.assertEqual(C.core_before99(d,{'items':[pod]},ctl)['generation'],282)
            for change in('old-generation','old-source','foreign-CID'):
                a,b=copy.deepcopy(d),copy.deepcopy(pod)
                if change=='old-generation':a['metadata']['generation']=281
                elif change=='old-source':a['metadata']['annotations']['dakasa.io/core-source-commit']='0'*40
                else:b['status']['containerStatuses'][0]['containerID']='containerd://'+'b'*64
                with self.assertRaises(C.Hold):C.core_before99(a,{'items':[b]},ctl)

    def test_lexical_component_and_finite_observer(self):
        HZ.exercise_authority_epoch_policy_and_physical_mutations_refuse(self)
        raw=b'{ "installed_recovery" : { "x" : "\\u00e9", "v": [1,  2] }, "other":true }\n'
        self.assertEqual(R.member_wire99(raw,'installed_recovery'),b'{ "x" : "\\u00e9", "v": [1,  2] }')
        for bad in(b'{"installed_recovery":1,"installed_recovery":2}',b'{"x":1}'):
            with self.assertRaises((R.Hold,KeyError)):R.member_wire99(bad,'installed_recovery')
        self.assertEqual((W.MAX_WATCH_SECONDS,W.MAX_SAMPLES,W.QUERY_PROCESS_BOUND_SECONDS),(600,600,8))
        text=Path(W.__file__).read_text();self.assertIn('old_watch_custody99',text)
        self.assertIn("out.mkdir(mode=0o700,exist_ok=False)",text)
        self.assertNotIn('gh api',text);self.assertNotIn("request('POST'",text)
        sql=R.continuation_sql99(O)
        self.assertIn('public.preaction_failed_plan_valid(',sql)
        self.assertIn('successor_job_id',sql);self.assertIn('successor_run_id',sql)
        self.assertNotIn('UPDATE public.',sql);self.assertNotIn('DELETE FROM',sql)
        old="c.conname IN('capacity_dispatch_jobs_state_v8_check','capacity_dispatch_jobs_lifecycle_v8_check','capacity_dispatch_jobs_state_v9_check','capacity_dispatch_jobs_lifecycle_v9_check','capacity_dispatch_jobs_state_v10_check','capacity_dispatch_jobs_lifecycle_v10_check')"
        catalog_sql=H.catalog99_select('',base_select=lambda _:old)
        self.assertEqual(catalog_sql.count(P.BUSINESS_LEDGER98_PROJECTION99),1)
        stable=catalog_sql.replace(P.BUSINESS_LEDGER98_PROJECTION99,'',1)
        self.assertNotIn("'ledger98'",stable)

    def test_six_wire_chain_and_explicit_successor(self):
        HZ.exercise_immutable_origin_arrays_and_inactive_slot_refuse(self)
        f=fixture();chain=R.chain99(f['value']['preaction_dispositions'],f['case'],f['value']['installed_recovery'],f['preimage'],H)
        self.assertEqual(chain['receipt_count'],1)
        self.assertEqual(chain['first_failed_plan_job_id'],f['case']['job_id'])
        for field in('original_wire','original_dispatch_wire','original_run_wire','original_intent_wire','members_wire','evidence_wire'):
            value=copy.deepcopy(f['value']);value['preaction_dispositions'][0]['row'][field]+='ff'
            with self.assertRaises((R.Hold,ValueError,KeyError)):
                R.chain99(value['preaction_dispositions'],f['case'],value['installed_recovery'],f['preimage'],H)
        for kind in('ACK','successor','missing','extra','predicate'):
            value=copy.deepcopy(f['value']);items=value['preaction_dispositions']
            if kind=='ACK':items[0]['job']['finalization_ack_at']='2026-11-11T21:00:00Z'
            elif kind=='successor':items[0]['successor_job']['id']=uid(999)
            elif kind=='missing':items.clear()
            elif kind=='extra':items.append(copy.deepcopy(items[0]))
            else:items[0]['predicate_valid']=False
            with self.assertRaises((R.Hold,ValueError,KeyError)):
                R.chain99(items,f['case'],value['installed_recovery'],f['preimage'],H)

    def test_saved_lineage_accounts_only_authenticated_typed_ancestors(self):
        HZ.exercise_e70_raw_hash_join_and_other_projection_changes_refuse(self)
        f=fixture();result=R.recovered_current99(f['fresh'],f['expected'],policy_for(f['fresh']['installed_recovery']),f['bundle'],f['read'])
        self.assertEqual(result['authenticated_typed_ancestor_count'],1)
        self.assertEqual(result['intervening_readonly_jobs'],0)
        self.assertEqual(result['unfiltered_lineage_job_count'],1)
        for kind in('unproved-job','typed-row-change','grant','bad-component'):
            a=fixture();v=a['fresh'];line=v['installed_recovery']['same_epoch_lineage']
            if kind=='unproved-job':
                j=copy.deepcopy(v['preaction_dispositions'][0]['job']);j['id']=uid(992);j['run_id']=uid(993)
                w=copy.deepcopy(v['preaction_dispositions'][0]['run']);w['id']=j['run_id']
                line.update(jobs_wire=wire([j]).decode(),job_ids=[j['id']],runs_wire=wire([w]).decode(),run_ids=[w['id']])
            elif kind=='typed-row-change':
                j=json.loads(line['jobs_wire']);j[0]['return_error']='rewritten';line['jobs_wire']=wire(j).decode()
            elif kind=='grant':line.update(vm_grant_changes_wire=wire([{'id':uid(994)}]).decode(),vm_grant_change_count=1)
            else:a['blobs'][a['component_ref']['path']]=wire({'different':True})
            with self.assertRaises((R.Hold,O.Hold,AssertionError,ValueError,KeyError)):
                R.recovered_current99(v,a['expected'],policy_for(v['installed_recovery']),a['bundle'],a['read'])

    def test_readiness_requires_real_ack_marker_and_typed_chain(self):
        HZ.exercise_nanosecond_rollback_unknown_and_truncated_originals_refuse(self)
        f=fixture();observed=W.phase99(f['value'],O,f['case'])
        self.assertTrue(W.complete99(f['value'],observed))
        for kind in('no-ACK','no-marker','no-chain','future-generation'):
            a=fixture();value=a['value'];v=value['installed_recovery']
            if kind=='no-ACK':
                v['readiness_job']['finalization_ack_at']=None
                self.assertFalse(W.complete99(value,W.phase99(value,O,a['case'])));continue
            elif kind=='no-marker':
                intent=json.loads(v['current_intent_wire']);intent.pop('installed_guest_reconcile');v['current_intent_wire']=wire(intent).decode()
            elif kind=='no-chain':value['preaction_dispositions']=[]
            else:
                intent=json.loads(v['current_intent_wire']);intent['generation']=45;v['current_intent_wire']=wire(intent).decode()
                with self.assertRaises(W.Hold):W.phase99(value,O,a['case'])
                continue
            with self.assertRaises((R.Hold,O.Hold,ValueError,KeyError)):
                R.promotion99(value,a['case'],a['preimage'],O,H,a['outer_ref'],a['component_ref'])

if __name__=='__main__':unittest.main()
