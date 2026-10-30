import hashlib,json,tempfile,types,unittest
from pathlib import Path
from unittest.mock import patch
import brain_inspector as b
class InspectorTests(unittest.TestCase):
 def setUp(self):
  self.t=tempfile.TemporaryDirectory();self.old=b'old';self.e={'old_config_sha256':hashlib.sha256(self.old).hexdigest(),'new_config_sha256':'f'*64,'boot_id':'boot'}
  self.i=object.__new__(b.BrainInspector);self.i.seq=0;self.i.out=Path(self.t.name);self.i.old=Path(self.t.name)/'old';self.i.lease={};self.i.ssm_evidence={};self.i.native=None;self.i.expected=self.e
  self.i.g=types.SimpleNamespace(read=lambda path,*args:self.old,NEW_CONFIG='config',UNIT='controller',GUARDIAN='guardian',RUNTIME=Path('/runtime'))
  self.i.static=lambda:('handles',{});self.i.properties=lambda unit:{'ActiveState':'inactive','SubState':'dead','MainPID':'0'};self.i.cgroup_empty=lambda _:True;self.i.prior_controller_terminated=lambda:True
 def tearDown(self):self.t.cleanup()
 def test_check_once_requires_readonly_four_backend_contract(self):
  response={'schema':'root_R11_static_empty_and_current_readonly_check_v1','applied':False,'backends':['broker','core','rds','redis'],'prometheus_sources':1,'held_native_read_classes':{}}
  self.i.call=lambda *args,**kwargs:json.dumps(response).encode()
  self.assertTrue(self.i.check_once(self.old,self.e))
  for key,value in [('applied',True),('backends',['core']),('prometheus_sources',0)]:
   altered={**response,key:value};self.i.call=lambda *args,**kwargs:json.dumps(altered).encode()
   with self.assertRaises(b.Held):self.i.check_once(self.old,self.e)
 def test_snapshot_never_claims_unproven_previous_recovery_closed(self):
  self.i.check_once=lambda *_:True
  with patch.object(b.scope_collector,'collect',return_value={'result':{'owner_and_cgroup_empty':True}}),patch.object(Path,'read_text',return_value='boot'):
   v=self.i.snapshot()
  self.assertFalse(v['previous_recovery_start_terminal'])
 def test_prior_process_identity_checked_from_original_pid(self):
  self.i.expected['prior_controller']={'pid':123,'start_ticks':777};stat='123 (x) S '+('0 '*18)+'777 0'
  with patch.object(b.scope_collector,'fs_read',return_value={'status':'ok','errno':None,'content':stat,'fd_closed':True}):self.assertFalse(b.BrainInspector.prior_controller_terminated(self.i))
  with patch.object(b.scope_collector,'fs_read',return_value={'status':'absent','errno':2,'content':None,'fd_closed':True}):self.assertTrue(b.BrainInspector.prior_controller_terminated(self.i))
  with patch.object(b.scope_collector,'fs_read',return_value={'status':'error','errno':13,'content':None,'fd_closed':True}):
   with self.assertRaises(b.Held):b.BrainInspector.prior_controller_terminated(self.i)
 def test_guardian_history_unproven_keeps_recovery_held(self):
  basic={k:True for k in ('owner_terminal','controller_identity_verified','core_healthy','nft_structure_exact','hub_and_cold_unchanged','unit_hashes_exact','runtime_hashes_exact','boot_identity_exact','guardian_cgroup_empty')};basic.update(config_sha256=self.e['old_config_sha256'],guardian_state='inactive');self.i.snapshot=lambda:basic
  self.i.expected.update(post_recovery_controller={'pid':123,'invocation_id':'id','start_ticks':777},prior_guardian={'pid':456,'start_ticks':333});self.i.properties=lambda _: {'ActiveState':'active','SubState':'running','MainPID':'123','InvocationID':'id'}
  self.i.call=lambda *_:b'nft';self.i.coverage=types.SimpleNamespace(kernel_text=lambda _:{'all_four_backends_and_reverse_sources_positive':True});stat='123 (x) S '+('0 '*18)+'777 0'
  def read(path):
   return {'status':'ok','errno':None,'content':stat,'fd_closed':True} if path=='/proc/123/stat' else {'status':'absent','errno':2,'content':None,'fd_closed':True}
  with patch.object(b.scope_collector,'fs_read',side_effect=read):v=self.i.snapshot_guardian()
  self.assertFalse(v['previous_guardian_start_terminal']);self.assertTrue(v['prior_guardian_identity_absent'])
 def test_wrong_old_config_rejected(self):
  with self.assertRaises(b.Held):self.i.check_once(b'other',self.e)
 def test_existing_controller_requires_stable_identity_old_config_and_backends(self):
  basic={'owner_terminal':True,'controller_state':'running','controller_identity_verified':True,'config_sha256':self.e['old_config_sha256'],'guardian_state':'inactive','guardian_cgroup_empty':True};self.i.snapshot=lambda:basic
  self.i.structure=lambda:'handles';self.i.call=lambda *_:b'nft';self.i.coverage=types.SimpleNamespace(kernel_text=lambda _:{'all_four_backends_and_reverse_sources_positive':True})
  props={'ActiveState':'active','SubState':'running','MainPID':'123','InvocationID':'a'*32};self.i.properties=lambda _:props
  stat='123 (x) S '+('0 '*18)+'777 0';read={'status':'ok','errno':None,'content':stat,'fd_closed':True}
  with patch.object(b.scope_collector,'fs_read',return_value=read):
   result=self.i.observe_existing_controller();self.assertEqual(result['controller_identity']['start_ticks'],777);self.assertTrue(result['start_attribution_not_inferred'])
   self.i.coverage=types.SimpleNamespace(kernel_text=lambda _:{'all_four_backends_and_reverse_sources_positive':False})
   with self.assertRaises(b.Held):self.i.observe_existing_controller()
   basic['config_sha256']=self.e['new_config_sha256']
   with self.assertRaises(b.Held):self.i.observe_existing_controller()
if __name__=='__main__':unittest.main(verbosity=2)
