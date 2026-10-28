import contextlib,hashlib,json,unittest
import guardian_restart as g
class Fake:
 def __init__(self):self.g=False;self.m=False;self.sent=0;self.id={'pid':9,'invocation':'abc'};self.overrides={}
 @contextlib.contextmanager
 def maintenance_lock(self):self.m=True;yield;self.m=False
 @contextlib.contextmanager
 def guardian_lock(self):self.g=True;yield;self.g=False
 def snapshot(self):
  return {**{k:True for k in ('owner_terminal','previous_guardian_start_terminal','controller_identity_verified','controller_config_is_reviewed_old','core_healthy','same_47_handles','all_four_backends_positive','hub_and_cold_unchanged','unit_hashes_exact','runtime_hashes_exact','boot_identity_exact','guardian_cgroup_empty','prior_guardian_identity_absent','no_pending_jobs')},'controller_identity':self.id,'guardian_state':'inactive','maintenance_lock_owned':self.m,'guardian_lock_owned':self.g,**self.overrides}
 def claim_once(self,identity):
  self.raw=json.dumps({'schema':'guardian_recovery_possible_start_intent_v1','run_id':'a'*20,'controller_identity':identity}).encode();return {'schema':'guardian_recovery_possible_start_marker_v1','run_id':'a'*20,'path':'/marker','sha256':hashlib.sha256(self.raw).hexdigest(),**{k:True for k in ('exclusive_create','file_fsync','directory_fsync','readback_verified')}}
 def readback_marker(self,_):return self.raw
 def start_once(self,_):self.sent+=1;return {'exit_code':0,'captured_output_truncated':False,**{k:True for k in ('native_started','wait_zero','stdout_EOF','stderr_EOF','all_local_FDs_closed','local_child_joined')}}
 def observe_guardian(self):return {'distinct_guardian_lifetime':True,'same_controller_identity':self.id}
class Tests(unittest.TestCase):
 def test_new_guardian_not_conflated_with_qualification(self):
  b=Fake();v=g.restart(b,b.id);self.assertEqual(b.sent,1);self.assertFalse(v['own_current15_qualified']);self.assertTrue(v['further_guardian_observation_required'])
 def test_unsafe_states_hold_before_start(self):
  for key,value in (('previous_guardian_start_terminal',False),('prior_guardian_identity_absent',False),('no_pending_jobs',False),('all_four_backends_positive',False),('guardian_state','active')):
   b=Fake();b.overrides[key]=value
   with self.assertRaises(g.Held):g.restart(b,b.id)
   self.assertEqual(b.sent,0)
 def test_marker_readback_mismatch_holds(self):
  b=Fake();b.readback_marker=lambda _:b'tampered'
  with self.assertRaises(g.Held):g.restart(b,b.id)
  self.assertEqual(b.sent,0)
if __name__=='__main__':unittest.main(verbosity=2)
