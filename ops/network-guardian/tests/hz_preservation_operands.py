"""CI-only declared ordinary-HZ preservation operands; no Native acceptance."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
from unittest import mock

P=Path(__file__).resolve().parent.parent/'rollout/hz_ordinary_preservation.py'
spec=importlib.util.spec_from_file_location('declared_goose99_HZ',P)
G=importlib.util.module_from_spec(spec);spec.loader.exec_module(G)


def wire(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)


def sha(value):
    return hashlib.sha256(value.encode()).hexdigest()


def fixture():
    now='2026-11-11T22:20:00.123456789Z'
    scope={'namespace':'dakasa-production','environment':'production','domain':'notify',
        'dimension':'original_notify_hetzner_vm_members'}
    intent={**scope,'generation':10,'fencing_token':24,'phase':'promoted',
        'policy_id':'11f93535-0e01-4cb0-8f3b-a8fb7c14c93d',
        'policy_checksum':'721cf2f748f28bfea44503f148618b1f0b9ba3146c23699ec7cd4d11c167354f',
        'assessment':{'units':1},'decision':{'mode':'refresh'},'updated_at':now,'recovery_only':False,
        'lease_owner':'declared-same-owner','executor_id':'declared-same-executor',
        'lease_expires_at':'2026-11-11T22:21:00Z'}
    row={**scope,'intent':intent,'updated_at':now}
    record={'resource_id':'174243510','resource_created_at':'2026-11-03T01:40:09Z',
        'desired_spec_sha256':'0f90e29d6a426866194811b413eb0738fe40b66fedd39d82482e2ca4ddcdc7cc',
        'declared_immutable_guard':1,'tombstone':False,'observed_at':now,'receipt_ref':'original-guest-reconcile:declared',
        'original_create_grant_id':'declared-CREATE','preregistration_id':'declared-pre',
        'witness_id':'declared-witness','enrollment_id':'declared-enrollment','installation_id':'declared-install'}
    slot={**scope,'integration_instance_id':'declared-integration','scope_checksum':'1'*64,
        'profile_name':'notify-hetzner-elastic','slot':1,'resource_id':'174243510',
        'slot_record':record,'revision':4,'updated_at':now}
    inactive_record={**record,'resource_id':'','tombstone':True,'observed_at':'2026-11-02T01:00:00Z',
        'resource_created_at':'2026-10-25T07:40:48Z','receipt_ref':'failed-installed-native-absence:declared'}
    inactive={**slot,'resource_id':'','slot_record':inactive_record,'revision':2,'updated_at':'2026-11-02T01:00:00Z'}
    def saved_slot(s):
        text=wire(s['slot_record'])
        return {'row_wire':wire(s),'slot_record_text':text,'slot_record_sha256':sha(text)}
    text=wire(intent)
    full={'schema':'Root_HZ_current_full_records_and_immutable_S1_origins_v1',
        'observed_at':now,'window_lo':'2026-11-11T18:00:24Z','window_hi':'2026-11-11T18:16:24Z',
        'expected':{'generation':10,'fence':24,'phase':'promoted','policy_id':intent['policy_id'],
            'policy_checksum':intent['policy_checksum'],'resource_id':'174243510'},
        'intent':[{'row_wire':wire(row),'intent_text':text,'intent_sha256':sha(text)}],
        'slots':[saved_slot(inactive),saved_slot(slot)],
        'grants_all_states':[{'row_wire':wire({'id':'declared-sdk-'+str(n),'state':'confirmed',
            'grant_record':{'immutable':n}}),'grant_record_text':wire({'immutable':n})}for n in range(10)],
        'preregistrations':[{'row_wire':wire({'id':'declared-pre','wire':'unaltered'}),'original_wire_sha256':'2'*64,'binding_wire_sha256':'3'*64}],
        'witnesses':[{'row_wire':wire({'id':'declared-witness','wire':'unaltered'}),'original_wire_sha256':'4'*64}],
        'enrollments':[{'row_wire':wire({'id':'declared-enrollment','wire':'unaltered'}),'registration_wire_sha256':'5'*64,'receipt_wire_sha256':'6'*64}],
        'installations':[{'row_wire':wire({'id':'declared-install','wire':'unaltered'}),'original_wire_sha256':'7'*64}]}
    hz={k:0 for k in ('jobs_busy','runs_busy','forward_unreturned_reads','live_unreturned_canaries',
        'intent_busy','pending_authority','forward_markers')}
    hz.update(intent_count=1,intent_identity=[{**scope,'generation':10,'fencing_token':24,'phase':'promoted',
        'policy_id':intent['policy_id'],'policy_checksum':intent['policy_checksum'],'intent_sha256':sha(text)}],
        owned_slots=[{'slot':1,'resource_id':'174243510','slot_record_sha256':sha(wire(record))}],
        active_policies=[{'id':intent['policy_id'],'checksum':intent['policy_checksum'],'version':1}],
        policy_catalog_wire=wire([{'id':intent['policy_id'],'checksum':intent['policy_checksum']}]),hz_current_full=full)
    return {'aws':{'whole_original':'declared unchanged AWS/SDK snapshot'},'hetzner':hz}


def change_intent(snapshot,change):
    hz=snapshot['hetzner'];saved=hz['hz_current_full']['intent'][0];row=json.loads(saved['row_wire'])
    change(row['intent']);row['updated_at']=row['intent']['updated_at']
    saved.update(row_wire=wire(row),intent_text=wire(row['intent']),intent_sha256=sha(wire(row['intent'])))
    hz['intent_identity'][0]['intent_sha256']=saved['intent_sha256']


def change_slot(snapshot,index,change):
    hz=snapshot['hetzner'];saved=hz['hz_current_full']['slots'][index];row=json.loads(saved['row_wire'])
    change(row);saved.update(row_wire=wire(row),slot_record_text=wire(row['slot_record']),slot_record_sha256=sha(wire(row['slot_record'])))
    if index==1:hz['owned_slots'][0]['slot_record_sha256']=saved['slot_record_sha256']


def refreshed(before):
    out=copy.deepcopy(before);now='2026-11-11T22:20:01.123456790Z'
    change_intent(out,lambda i:i.update(assessment={'units':1,'fresh':True},decision={'mode':'refresh','fresh':True},updated_at=now))
    def update(s):
        s['slot_record'].update(observed_at=now,receipt_ref='original-guest-reconcile:declared-next')
        s.update(revision=s['revision']+1,updated_at=now)
    change_slot(out,1,update);out['hetzner']['hz_current_full']['observed_at']=now
    return out


def exercise_same_and_allowed_refresh_preserves_whole_originals(self):
    before=fixture();after=refreshed(before);originals=(wire(before),wire(after))
    self.assertTrue(G.same_database(before,copy.deepcopy(before)))
    self.assertTrue(G.same_database(before,after))
    self.assertNotEqual(before['hetzner']['intent_identity'][0]['intent_sha256'],after['hetzner']['intent_identity'][0]['intent_sha256'])
    self.assertNotEqual(before['hetzner']['owned_slots'][0]['slot_record_sha256'],after['hetzner']['owned_slots'][0]['slot_record_sha256'])
    self.assertEqual((wire(before),wire(after)),originals)
    self.assertEqual(G.stamp_ns('2026-11-11T22:20:00.123456790Z')-G.stamp_ns('2026-11-11T22:20:00.123456789Z'),1)
    query=G.query("SELECT jsonb_build_object('declared',true);")
    self.assertIn(G.HZ_CURRENT_SQL.strip(),query)
    self.assertIn('ordinary AS MATERIALIZED',query)
    self.assertIn('current_full AS MATERIALIZED',query)
    self.assertNotIn('BEGIN',query)
    self.assertEqual(hashlib.sha256(G.HZ_CURRENT_SQL.encode()).hexdigest(),'3de7311f0ab1fe56e6eb1e5f4c0c18d7dff1d73dab463c750ca504f97eec54ff')
    # Closed known-original inputs use declared fixture pins only inside CI;
    # this test never claims the production Root review or its acceptance.
    blobs={'/declared/known.json':wire(before['hetzner']['hz_current_full']).encode(),
        '/declared/policy.json':wire(after['hetzner']['hz_current_full']).encode(),
        '/declared/root.json':b'{"schema":"declared-CI-only-root","reviewed_by_root":false}',
        '/declared/current.sql':G.HZ_CURRENT_SQL.encode()}
    ref=lambda path:{'path':path,'sha256':hashlib.sha256(blobs[path]).hexdigest()}
    context={'helper_source_ref':{'path':'/declared/helper.py','sha256':'c'*64},
        'fixed_current_sql_ref':ref('/declared/current.sql'),'known_baseline_ref':ref('/declared/known.json'),
        'known_root_ref':ref('/declared/root.json'),'policy_state_full_ref':ref('/declared/policy.json')}
    with mock.patch.multiple(G,KNOWN_BASELINE_SHA=context['known_baseline_ref']['sha256'],
                             KNOWN_ROOT_SHA=context['known_root_ref']['sha256']):
        read=lambda r:blobs[r['path']]
        loaded=G.inputs(context,read)
        self.assertEqual(set(loaded),{'known_baseline','policy_state_full','fixed_current_sql'})
        self.assertEqual(loaded['known_baseline'],before['hetzner']['hz_current_full'])
        self.assertEqual(loaded['policy_state_full'],after['hetzner']['hz_current_full'])
        self.assertEqual(loaded['fixed_current_sql'],G.HZ_CURRENT_SQL)
        for changed in blobs:
            def altered(r):return blobs[r['path']]+(b' ' if r['path']==changed else b'')
            with self.subTest(whole_ref=changed),self.assertRaises(G.Hold):G.inputs(context,altered)
        bad=copy.deepcopy(context);bad['foreign_ref']=context['known_root_ref']
        with self.assertRaises(G.Hold):G.inputs(bad,read)
        bad=copy.deepcopy(context);bad['known_baseline_ref']['sha256']='f'*64
        with self.assertRaises(G.Hold):G.inputs(bad,read)


def exercise_authority_epoch_policy_and_physical_mutations_refuse(self):
    before=fixture()
    for key,value in [('generation',11),('fencing_token',25),('phase','preparing'),
            ('policy_id','foreign-policy'),('policy_checksum','f'*64),('lease_owner','foreign-owner'),
            ('executor_id','foreign-executor'),('lease_expires_at','2026-11-11T23:00:00Z'),('recovery_only',0)]:
        bad=refreshed(before);change_intent(bad,lambda i:i.update({key:value}))
        with self.subTest(intent_axis=key),self.assertRaises(G.Hold):G.same_database(before,bad)
    for key,value in [('resource_created_at','2026-11-03T01:40:10Z'),('desired_spec_sha256','f'*64),
            ('resource_id','foreign-resource'),('tombstone',True),('original_create_grant_id','foreign-grant'),
            ('preregistration_id','foreign-pre'),('witness_id','foreign-witness'),
            ('enrollment_id','foreign-enrollment'),('installation_id','foreign-install'),('declared_immutable_guard',True)]:
        bad=refreshed(before);change_slot(bad,1,lambda s:s['slot_record'].update({key:value}))
        with self.subTest(slot_axis=key),self.assertRaises(G.Hold):G.same_database(before,bad)


def exercise_immutable_origin_arrays_and_inactive_slot_refuse(self):
    before=fixture()
    for key in ('grants_all_states','preregistrations','witnesses','enrollments','installations'):
        bad=refreshed(before);bad['hetzner']['hz_current_full'][key][0]['row_wire']+=' '
        with self.subTest(original_array=key),self.assertRaises(G.Hold):G.same_database(before,bad)
    bad=refreshed(before);change_slot(bad,0,lambda s:s['slot_record'].update(observed_at='2026-11-11T22:20:00Z'))
    with self.assertRaises(G.Hold):G.same_database(before,bad)
    for key in ('slots','grants_all_states'):
        bad=refreshed(before);bad['hetzner']['hz_current_full'][key].append(copy.deepcopy(bad['hetzner']['hz_current_full'][key][0]))
        with self.subTest(extra_original=key),self.assertRaises(G.Hold):G.same_database(before,bad)


def exercise_e70_raw_hash_join_and_other_projection_changes_refuse(self):
    before=fixture()
    for role,field in (('intent_identity','intent_sha256'),('owned_slots','slot_record_sha256')):
        bad=refreshed(before);bad['hetzner'][role][0][field]='f'*64
        with self.subTest(unjoined_hash=field),self.assertRaises(G.Hold):G.same_database(before,bad)
        bad=refreshed(before);bad['hetzner'][role][0]['foreign_identity']='changed'
        with self.subTest(other_identity=role),self.assertRaises(G.Hold):G.same_database(before,bad)
    for role in ('aws','active_policies','policy_catalog_wire','jobs_busy','intent_count'):
        bad=refreshed(before)
        if role=='aws':bad['aws']['whole_original']='changed'
        elif role=='active_policies':bad['hetzner'][role][0]['checksum']='f'*64
        elif role=='policy_catalog_wire':bad['hetzner'][role]+=' '
        else:bad['hetzner'][role]+=1
        with self.subTest(projection=role),self.assertRaises(G.Hold):G.same_database(before,bad)


def exercise_nanosecond_rollback_unknown_and_truncated_originals_refuse(self):
    before=fixture()
    bad=copy.deepcopy(before);change_intent(bad,lambda i:i.update(updated_at='2026-11-11T22:20:00.123456788Z'))
    with self.assertRaises(G.Hold):G.same_database(before,bad)
    bad=copy.deepcopy(before);change_slot(bad,1,lambda s:s['slot_record'].update(observed_at='2026-11-11T22:20:00.123456788Z'))
    with self.assertRaises(G.Hold):G.same_database(before,bad)
    bad=refreshed(before);change_slot(bad,1,lambda s:s.update(revision=3))
    with self.assertRaises(G.Hold):G.same_database(before,bad)
    bad=refreshed(before);bad['hetzner']['hz_current_full']['foreign_field']=True
    with self.assertRaises(G.Hold):G.same_database(before,bad)
    bad=refreshed(before);bad['hetzner']['hz_current_full']['installations']=[]
    with self.assertRaises(G.Hold):G.same_database(before,bad)
    bad=refreshed(before);bad['hetzner']['hz_current_full']['observed_at']='2026-11-11T22:19:59.999999999Z'
    with self.assertRaises(G.Hold):G.same_database(before,bad)
    bad=refreshed(before);bad['hetzner']['hz_current_full']['intent'][0]['intent_text']+=' '
    with self.assertRaises(G.Hold):G.same_database(before,bad)


