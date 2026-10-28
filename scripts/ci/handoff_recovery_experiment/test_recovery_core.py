import copy,importlib.util,json,os,tempfile,unittest
from pathlib import Path
spec=importlib.util.spec_from_file_location('recovery_core',Path(__file__).parent/'recovery_core.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class RecoveryStateTests(unittest.TestCase):
 def setUp(self):
  self.expected={'old_config_sha256':m.digest(b'old config'),'new_config_sha256':m.digest(b'new config')}
  self.s={'owner_terminal':True,'maintenance_lock_owned':True,'controller_lock_owned':True,'unit_hashes_exact':True,'runtime_hashes_exact':True,'boot_identity_exact':True,'hub_and_cold_unchanged':True,'core_healthy':True,'config_is_regular_single_link':True,'nft_structure_exact':True,'config_sha256':self.expected['new_config_sha256'],'guardian_state':'inactive','guardian_cgroup_empty':True,'controller_state':'inactive','controller_pid_absent':True,'controller_cgroup_empty':True,'controller_start_job_pending':False,'check_once_old_config_success':True}
 def test_stopped_with_new_config_restores_then_starts(self):
  d=m.decide(self.s,self.expected);self.assertTrue(d['restore_old_config']);self.assertTrue(d['start_requested'])
 def test_stopped_with_old_config_starts_without_replace(self):
  self.s['config_sha256']=self.expected['old_config_sha256'];d=m.decide(self.s,self.expected);self.assertFalse(d['restore_old_config']);self.assertTrue(d['start_requested'])
 def test_running_process_does_not_restart_or_replace(self):
  self.s.update(controller_state='running',controller_identity_verified=True);d=m.decide(self.s,self.expected);self.assertFalse(d['start_requested']);self.assertFalse(d['restore_old_config'])
 def test_running_process_with_unknown_identity_rejected(self):
  self.s['controller_state']='running'
  with self.assertRaises(m.Held):m.decide(self.s,self.expected)
 def test_pending_or_activating_never_replays_start(self):
  for s in ({'controller_state':'activating'}, {'controller_start_job_pending':True}):
   snap={**self.s,**s};self.assertEqual(m.decide(snap,self.expected)['action'],'observe_pending_start')
 def test_nonclosed_or_incomplete_evidence_refused(self):
  for key in ('owner_terminal','maintenance_lock_owned','controller_lock_owned','unit_hashes_exact','runtime_hashes_exact','boot_identity_exact','hub_and_cold_unchanged','core_healthy','config_is_regular_single_link','nft_structure_exact','controller_pid_absent','controller_cgroup_empty','guardian_cgroup_empty','check_once_old_config_success'):
   s={**self.s,key:False}
   with self.subTest(key=key),self.assertRaises(m.Held):m.decide(s,self.expected)
 def test_unknown_job_or_unauthorized_config_refused(self):
  for key,value in [('controller_start_job_pending',None),('config_sha256','f'*64),('guardian_state','activating')]:
   with self.subTest(key=key),self.assertRaises(m.Held):m.decide({**self.s,key:value},self.expected)
 def test_running_guardian_must_not_race_corrective_start(self):
  with self.assertRaises(m.Held):m.decide({**self.s,'guardian_state':'active'},self.expected)
class FileCASTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.p=Path(self.tmp.name)/'config';self.p.write_bytes(b'new config');self.p.chmod(0o600);self.uid=os.getuid()
 def tearDown(self):self.tmp.cleanup()
 def test_exact_old_restored_atomically(self):
  r=m.restore_old_config(self.p,b'old config',m.digest(b'new config'),m.digest(b'old config'),self.uid);self.assertEqual(self.p.read_bytes(),b'old config');self.assertTrue(r['changed']);self.assertEqual(list(self.p.parent.iterdir()),[self.p])
 def test_incorrect_expected_hash_has_no_effect(self):
  with self.assertRaises(m.Held):m.restore_old_config(self.p,b'old config','0'*64,m.digest(b'old config'),self.uid)
  self.assertEqual(self.p.read_bytes(),b'new config')
 def test_old_bytes_must_match_attested_hash(self):
  with self.assertRaises(m.Held):m.restore_old_config(self.p,b'wrong',m.digest(b'new config'),m.digest(b'old config'),self.uid)
 def test_nonprivate_config_rejected(self):
  self.p.chmod(0o644)
  with self.assertRaises(m.Held):m.restore_old_config(self.p,b'old config',m.digest(b'new config'),m.digest(b'old config'),self.uid)
 def test_symlink_rejected(self):
  self.p.unlink();self.p.symlink_to('/dev/null')
  with self.assertRaises(OSError):m.restore_old_config(self.p,b'old config',m.digest(b'new config'),m.digest(b'old config'),self.uid)
 def test_noop_does_not_rewrite_config(self):
  self.p.write_bytes(b'old config');ino=self.p.stat().st_ino;r=m.restore_old_config(self.p,b'old config',m.digest(b'old config'),m.digest(b'old config'),self.uid);self.assertFalse(r['changed']);self.assertEqual(self.p.stat().st_ino,ino)
class OrchestrationTests(unittest.TestCase):
 def setUp(self):
  import contextlib
  self.base=RecoveryStateTests();self.base.setUp();self.expected=self.base.expected;self.snap={**self.base.s,'previous_recovery_start_terminal':True}
  outer=self
  class Fake:
   def __init__(self):self.state=copy.deepcopy(outer.snap);self.state['controller_lock_owned']=False;self.calls=[];self.restore_race=False;self.unresolved=False;self.unlock_race=False;self.marker_raw=json.dumps({'schema':'handoff_recovery_possible_start_intent_v1','run_id':'1'*20,'old_config_sha256':outer.expected['old_config_sha256'],'new_config_sha256':outer.expected['new_config_sha256']},sort_keys=True).encode();self.marker={'schema':'handoff_recovery_possible_start_marker_v1','run_id':'1'*20,'path':'/test/marker','sha256':m.digest(self.marker_raw),'exclusive_create':True,'file_fsync':True,'directory_fsync':True,'readback_verified':True}
   def maintenance_lock(self):return contextlib.nullcontext()
   @contextlib.contextmanager
   def controller_lock(self):
    self.state['controller_lock_owned']=True
    try:yield
    finally:self.state['controller_lock_owned']=False
   def snapshot(self):
    self.calls.append('snapshot')
    if self.unlock_race and 'marker' in self.calls and not self.state['controller_lock_owned']:self.state['controller_start_job_pending']=True
    return copy.deepcopy(self.state)
   def verify_reviewed_old_config(self,old,expected):self.calls.append('check')
   def restore(self,old,cur,expected):
    self.calls.append('restore');self.state['config_sha256']=expected
    if self.restore_race:self.state['controller_start_job_pending']=True
    return {'changed':True,'after_sha256':expected}
   def claim_start_once(self,expected):self.calls.append('marker');return self.marker
   def readback_marker(self,marker):self.calls.append('marker-read');return self.marker_raw
   def start_once(self):
    self.calls.append('start')
    if self.state['controller_lock_owned']:raise AssertionError('controller lock held across START')
    if self.unresolved:raise TimeoutError('original send outcome unknown')
    return {'exit_code':0,'captured_output_truncated':False,'native_started':True,'wait_zero':True,'stdout_EOF':True,'stderr_EOF':True,'all_local_FDs_closed':True,'local_child_joined':True}
   def observe_started(self):self.calls.append('observe');return {'new_controller_identity_verified':True,'same_47_native_handles':True,'all_four_backends_positive':True}
  self.backend=Fake()
 def test_distinct_start_after_restore_has_durable_marker(self):
  r=m.recover_with_backend(self.backend,self.expected,b'old config');self.assertEqual(self.backend.calls,['snapshot','snapshot','check','restore','snapshot','marker','marker-read','snapshot','start','observe']);self.assertTrue(r['start_attempted']);self.assertTrue(r['guardian_requalification_needed']);self.assertFalse(r['no_gap_inferred'])
 def test_pending_start_remains_read_only(self):
  self.backend.state['controller_start_job_pending']=True;r=m.recover_with_backend(self.backend,self.expected,b'old config');self.assertEqual(self.backend.calls,['snapshot']);self.assertFalse(r['start_attempted'])
 def test_race_after_restore_refuses_start(self):
  self.backend.restore_race=True
  with self.assertRaises(m.Held):m.recover_with_backend(self.backend,self.expected,b'old config')
  self.assertNotIn('start',self.backend.calls);self.assertNotIn('marker',self.backend.calls)
 def test_race_after_controller_unlock_refuses_start(self):
  self.backend.unlock_race=True
  with self.assertRaises(m.Held):m.recover_with_backend(self.backend,self.expected,b'old config')
  self.assertIn('marker',self.backend.calls);self.assertNotIn('start',self.backend.calls)
 def test_unknown_start_exception_does_not_replay(self):
  self.backend.unresolved=True
  with self.assertRaises(TimeoutError):m.recover_with_backend(self.backend,self.expected,b'old config')
  self.assertEqual(self.backend.calls.count('start'),1);self.assertIn('marker',self.backend.calls)
 def test_marker_requires_structured_durable_custody(self):
  for bad in (None,False,{},'',{**self.backend.marker,'readback_verified':False},{**self.backend.marker,'run_id':'bad'},{**self.backend.marker,'sha256':'bad'}):
   self.backend.marker=bad;self.backend.calls=[];self.backend.state['config_sha256']=self.expected['new_config_sha256']
   with self.subTest(marker=bad),self.assertRaises(m.Held):m.recover_with_backend(self.backend,self.expected,b'old config')
   self.assertNotIn('start',self.backend.calls)
 def test_marker_content_or_readback_mismatch_refused(self):
  self.backend.marker_raw=b'wrong bytes'
  with self.assertRaises(m.Held):m.recover_with_backend(self.backend,self.expected,b'old config')
  self.assertNotIn('start',self.backend.calls)
 def test_running_guardian_still_requires_qualification(self):
  self.backend.state.update(controller_state='running',controller_identity_verified=True,guardian_state='active')
  r=m.recover_with_backend(self.backend,self.expected,b'old config');self.assertTrue(r['guardian_requalification_needed'])
 def test_unresolved_previous_start_refuses_new_one(self):
  self.backend.state['previous_recovery_start_terminal']=False
  with self.assertRaises(m.Held):m.recover_with_backend(self.backend,self.expected,b'old config')
  self.assertNotIn('marker',self.backend.calls);self.assertNotIn('start',self.backend.calls)

class CrossProcessLockTests(unittest.TestCase):
 def test_distinct_child_takes_controller_lock_before_maintenance_is_released(self):
  import contextlib,fcntl,subprocess,sys
  case=RecoveryStateTests();case.setUp();state={**case.s,'previous_recovery_start_terminal':True,'controller_lock_owned':False};expected=case.expected
  with tempfile.TemporaryDirectory() as td:
   controller=Path(td)/'controller.lock';maintenance=Path(td)/'maintenance.lock';controller.touch();maintenance.touch()
   @contextlib.contextmanager
   def lock(path):
    with path.open('r+') as f:
     fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB)
     try:yield
     finally:fcntl.flock(f,fcntl.LOCK_UN)
   class Backend:
    def maintenance_lock(self):return lock(maintenance)
    @contextlib.contextmanager
    def controller_lock(self):
     with lock(controller):
      state['controller_lock_owned']=True
      try:yield
      finally:state['controller_lock_owned']=False
    def snapshot(self):return copy.deepcopy(state)
    def verify_reviewed_old_config(self,old,e):pass
    def restore(self,old,current,want):state['config_sha256']=want;return {'changed':True,'after_sha256':want}
    def claim_start_once(self,e):
     self.raw=json.dumps({'schema':'handoff_recovery_possible_start_intent_v1','run_id':'1'*20,'old_config_sha256':e['old_config_sha256'],'new_config_sha256':e['new_config_sha256']},sort_keys=True).encode()
     return {'schema':'handoff_recovery_possible_start_marker_v1','run_id':'1'*20,'path':'/test/marker','sha256':m.digest(self.raw),'exclusive_create':True,'file_fsync':True,'directory_fsync':True,'readback_verified':True}
    def readback_marker(self,marker):return self.raw
    def start_once(self):
     code="import fcntl,sys; f=open(sys.argv[1],'r+'); fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB); print('controller-lock-acquired')"
     child=subprocess.run([sys.executable,'-c',code,str(controller)],capture_output=True,timeout=5)
     if child.returncode!=0 or child.stdout.strip()!=b'controller-lock-acquired':raise AssertionError('child could not acquire controller lock')
     with maintenance.open('r+') as observer:
      with self.assertRaises(BlockingIOError):fcntl.flock(observer,fcntl.LOCK_EX|fcntl.LOCK_NB)
     return {'exit_code':0,'captured_output_truncated':False,'native_started':True,'wait_zero':True,'stdout_EOF':True,'stderr_EOF':True,'all_local_FDs_closed':True,'local_child_joined':True}
    def observe_started(self):return {'new_controller_identity_verified':True,'same_47_native_handles':True}
   Backend.assertRaises=self.assertRaises
   result=m.recover_with_backend(Backend(),expected,b'old config');self.assertTrue(result['start_attempted'])

if __name__=='__main__':unittest.main(verbosity=2)
