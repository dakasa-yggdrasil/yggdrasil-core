import os,tempfile,unittest
from pathlib import Path
import bound_recovery_driver as d
import recovery_core
class Inspector:
 def __init__(self,path):self.last_binding={'schema':'bound_handoff_recovery_marker_namespace_v1','marker_directory':str(path),'marker_absence_or_recovery_authorized':False}
 def snapshot(self):return {'previous_recovery_start_terminal':False}
class Tests(unittest.TestCase):
 def setUp(self):
  self.t=tempfile.TemporaryDirectory();self.p=Path(self.t.name);os.chmod(self.p,0o700);self.m=self.p/'m';self.c=self.p/'c';self.config=self.p/'config'
  for p in (self.m,self.c,self.config):p.write_bytes(b'');os.chmod(p,0o600)
  self.i=Inspector(self.p);self.b=d.BoundLinuxBackend(maintenance_path=self.m,controller_path=self.c,config_path=self.config,marker_directory=self.p,run_id='a'*20,inspector=self.i,native=None,expected_uid=os.getuid())
 def tearDown(self):self.t.cleanup()
 def test_only_under_maintenance_can_derive_first_possible_start(self):
  with self.assertRaises(recovery_core.Held):self.b.snapshot()
  with self.b.maintenance_lock():self.assertTrue(self.b.snapshot()['previous_recovery_start_terminal'])
 def test_marker_namespace_mismatch_holds(self):
  self.i.last_binding['marker_directory']='/other'
  with self.b.maintenance_lock():
   with self.assertRaises(d.Held):self.b.snapshot()
 def test_existing_marker_cannot_be_bypassed(self):
  (self.p/'ROOT-ONE-RECOVERY-POSSIBLE-START.PUBLIC.json').write_text('old')
  with self.b.maintenance_lock():
   with self.assertRaises(recovery_core.Held):self.b.snapshot()
 def test_inspector_cannot_self_assert_history(self):
  self.i.snapshot=lambda:{'previous_recovery_start_terminal':True}
  with self.b.maintenance_lock():
   with self.assertRaises(d.Held):self.b.snapshot()
if __name__=='__main__':unittest.main(verbosity=2)
