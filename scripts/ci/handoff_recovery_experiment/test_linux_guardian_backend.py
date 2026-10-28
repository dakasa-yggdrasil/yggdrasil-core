import os,tempfile,unittest
from pathlib import Path
import guardian_restart as core
from linux_guardian_backend import LinuxGuardianBackend
from test_guardian_restart import Fake
class Inspector(Fake):
 def snapshot_guardian(self):
  v=self.snapshot();v.pop('guardian_lock_owned');v.pop('maintenance_lock_owned');return v
class Tests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();d=Path(self.tmp.name);os.chmod(d,0o700);m=d/'m';g=d/'g'
  for p in (m,g):p.write_bytes(b'');os.chmod(p,0o600)
  self.inspector=Inspector();self.calls=[]
  def native(argv,**kwargs):
   self.calls.append(argv);return b'',{'exit_code':0,'captured_output_truncated':False,**{k:True for k in ('native_started','wait_zero','stdout_EOF','stderr_EOF','all_local_FDs_closed','local_child_joined')}}
  self.b=LinuxGuardianBackend(maintenance_path=m,guardian_path=g,marker_directory=d,run_id='a'*20,inspector=self.inspector,native=native,expected_uid=os.getuid())
 def tearDown(self):self.tmp.cleanup()
 def test_actual_locks_and_marker_then_one_explicit_start(self):
  v=core.restart(self.b,self.inspector.id);self.assertEqual(len(self.calls),1);self.assertEqual(self.calls[0],['/usr/bin/systemctl','start','dakasa-capacity-network-guardian.service']);self.assertFalse(v['own_current15_qualified'])
 def test_old_marker_blocks_before_start(self):
  (Path(self.tmp.name)/'ROOT-ONE-GUARDIAN-START.PUBLIC.json').write_text('old')
  with self.assertRaises(core.Held):core.restart(self.b,self.inspector.id)
  self.assertEqual(self.calls,[])
 def test_unknown_send_never_repeated(self):
  def unknown(argv,**kwargs):self.calls.append(argv);raise TimeoutError('unknown')
  self.b.native=unknown
  with self.b.maintenance_lock():
   with self.b.guardian_lock():marker=self.b.claim_once(self.inspector.id)
   with self.assertRaises(TimeoutError):self.b.start_once(marker)
   with self.assertRaises(core.Held):self.b.start_once(marker)
  self.assertEqual(len(self.calls),1)
if __name__=='__main__':unittest.main(verbosity=2)
