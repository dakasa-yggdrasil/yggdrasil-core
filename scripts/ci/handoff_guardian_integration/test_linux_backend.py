import errno,hashlib,os,tempfile,unittest
from unittest.mock import patch
from pathlib import Path
import recovery_core as core
from linux_backend import LinuxBackend
sha=lambda b:hashlib.sha256(b).hexdigest()
class Inspector:
 def __init__(self,p):self.path=p;self.running=False
 def check_once(self,old,expected):return sha(old)==expected['old_config_sha256']
 def snapshot(self):
  return {'owner_terminal':True,'unit_hashes_exact':True,'runtime_hashes_exact':True,'boot_identity_exact':True,'hub_and_cold_unchanged':True,'core_healthy':True,'config_is_regular_single_link':True,'nft_structure_exact':True,'config_sha256':sha(self.path.read_bytes()),'guardian_state':'inactive','controller_state':'running' if self.running else 'inactive','controller_pid_absent':not self.running,'controller_cgroup_empty':not self.running,'controller_start_job_pending':False,'guardian_cgroup_empty':True,'check_once_old_config_success':True,'previous_recovery_start_terminal':True,'controller_identity_verified':self.running}
 def observe_started(self):return {'new_controller_identity_verified':self.running,'same_47_native_handles':True}
 def observe_existing_controller(self):return {'existing_controller_identity_verified':self.running,'start_attribution_not_inferred':True,'same_47_native_handles':True,'all_four_observed_positive':True}
class LinuxBackendTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();d=Path(self.temp.name);os.chmod(d,0o700);self.maintenance=d/'m';self.lock=d/'c';self.config=d/'config'
  for p,b in ((self.maintenance,b''),(self.lock,b''),(self.config,b'new')):p.write_bytes(b);os.chmod(p,0o600)
  self.i=Inspector(self.config);self.calls=[]
  def native(argv,**kw):
   self.calls.append(argv);self.i.running=True;return b'',{'native_started':True,'exit_code':0,'wait_zero':True,'stdout_EOF':True,'stderr_EOF':True,'all_local_FDs_closed':True,'local_child_joined':True,'captured_output_truncated':False}
  self.backend=LinuxBackend(maintenance_path=self.maintenance,controller_path=self.lock,config_path=self.config,marker_directory=d,run_id='a'*20,inspector=self.i,native=native,expected_uid=os.getuid());self.expected={'old_config_sha256':sha(b'old'),'new_config_sha256':sha(b'new')}
 def tearDown(self):self.temp.cleanup()
 def test_actual_files_locks_restore_and_one_start(self):
  result=core.recover_with_backend(self.backend,self.expected,b'old');self.assertEqual(self.config.read_bytes(),b'old');self.assertTrue(result['restore_performed']);self.assertEqual(len(self.calls),1);self.assertTrue(result['guardian_requalification_needed']);self.assertFalse(result['no_gap_inferred']);self.assertTrue(self.backend.readback_marker(result['possible_start_marker']))
 def test_duplicate_possible_marker_never_sends(self):
  (Path(self.temp.name)/'ROOT-ONE-RECOVERY-POSSIBLE-START.PUBLIC.json').write_text('existing')
  with self.assertRaises(core.Held):core.recover_with_backend(self.backend,self.expected,b'old')
  self.assertEqual(self.calls,[]);self.assertEqual(self.config.read_bytes(),b'new')
 def test_running_old_controller_is_observed_without_new_start(self):
  self.config.write_bytes(b'old');self.i.running=True
  result=core.recover_with_backend(self.backend,self.expected,b'old');self.assertEqual(result['action'],'observe_running_controller');self.assertFalse(result['start_attempted']);self.assertTrue(result['observation']['start_attribution_not_inferred']);self.assertEqual(self.calls,[])
 def test_running_new_controller_is_not_attributed_or_adopted(self):
  self.i.running=True
  result=core.recover_with_backend(self.backend,self.expected,b'old');self.assertEqual(result['action'],'observe_running_controller');self.assertNotIn('observation',result);self.assertEqual(self.calls,[])
 def test_lock_is_real_and_nonreentrant(self):
  with self.backend.maintenance_lock():
   with self.assertRaises(core.Held):
    with self.backend.maintenance_lock():pass
   self.assertTrue(self.backend.snapshot()['maintenance_lock_owned'])
 def test_direct_start_without_marker_is_rejected(self):
  with self.backend.maintenance_lock():
   with self.assertRaises(core.Held):self.backend.start_once()
  self.assertEqual(self.calls,[])
 def test_tampered_marker_is_rejected_before_start(self):
  with self.backend.maintenance_lock():
   with self.backend.controller_lock():self.backend.claim_start_once(self.expected)
   path=Path(self.temp.name)/'ROOT-ONE-RECOVERY-POSSIBLE-START.PUBLIC.json';path.write_bytes(b'tampered')
   with self.assertRaises(core.Held):self.backend.start_once()
  self.assertEqual(self.calls,[])
 def test_start_is_one_shot_even_when_called_directly(self):
  with self.backend.maintenance_lock():
   with self.backend.controller_lock():self.backend.claim_start_once(self.expected)
   self.backend.start_once()
   with self.assertRaises(core.Held):self.backend.start_once()
  self.assertEqual(len(self.calls),1)
 def test_uncertain_start_never_retried(self):
  def uncertain(*args,**kwargs):self.calls.append(args[0]);raise TimeoutError('unknown outcome')
  self.backend.native=uncertain
  with self.backend.maintenance_lock():
   with self.backend.controller_lock():self.backend.claim_start_once(self.expected)
   with self.assertRaises(TimeoutError):self.backend.start_once()
   with self.assertRaises(core.Held):self.backend.start_once()
  self.assertEqual(len(self.calls),1)
 def test_unprotected_lock_parent_rejected(self):
  os.chmod(self.temp.name,0o777)
  with self.assertRaises(core.Held):
   with self.backend.maintenance_lock():pass
 def test_marker_stat_permission_or_io_errors_hold_before_cas(self):
  original=os.stat
  for code in (errno.EACCES,errno.EIO):
   def checked(path,*args,**kwargs):
    if path=='ROOT-ONE-RECOVERY-POSSIBLE-START.PUBLIC.json':raise OSError(code,'injected marker error')
    return original(path,*args,**kwargs)
   with patch('linux_backend.os.stat',side_effect=checked):
    with self.assertRaises(OSError):core.recover_with_backend(self.backend,self.expected,b'old')
   self.assertEqual(self.config.read_bytes(),b'new');self.assertEqual(self.calls,[])
 def test_check_once_failure_never_starts(self):
  self.i.check_once=lambda *_:False
  with self.assertRaises(core.Held):core.recover_with_backend(self.backend,self.expected,b'old')
  self.assertEqual(self.calls,[])
if __name__=='__main__':unittest.main(verbosity=2)
