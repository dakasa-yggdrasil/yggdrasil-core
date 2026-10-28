import json,os,tempfile,types,unittest
from unittest.mock import patch
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
class PrepareTests(unittest.TestCase):
 def setUp(self):
  import hashlib
  self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name);self.run='a'*20;self.folder=self.root/('Core263-pair-handoff-'+self.run);self.folder.mkdir();self.old=self.root/'old';self.old.write_bytes(b'old');self.lease=self.root/'lease';self.lease.write_text(json.dumps({'schema':'handoff_isolated_owner_lease_v1','run_id':self.run}));self.base=self.folder/'RECOVERY-BASELINE.PUBLIC.json';self.base.write_text(json.dumps({'schema':'Root_Core263_preSTOP_recovery_baseline_v1','run_id':self.run,'old_config_sha256':hashlib.sha256(b'old').hexdigest()}));self.g=types.SimpleNamespace(NEW_CONFIG=self.old,read=lambda p,*_:Path(p).read_bytes(),loads=json.loads)
 def tearDown(self):self.tmp.cleanup()
 def args(self):
  ref=lambda p:{'path':str(p),'sha256':'1'*64}
  return {'guardian':self.g,'base':None,'bridge':None,'coverage':None,'native':None,'lease_ref':ref(self.lease),'scope_ref':ref(self.root/'scope'),'baseline_ref':ref(self.base),'handoff_marker_ref':ref(self.root/'marker'),'ssm_evidence':{},'expected_source_sha256':'2'*64,'expected_admission_sha256':'3'*64,'diagnostic_root':self.root}
 def test_prepares_only_from_recorded_baseline_and_matching_old_bytes(self):
  instance=types.SimpleNamespace(configure_binding=lambda **kwargs:None)
  with patch.object(d,'BRAIN_ROOT',self.root),patch.object(d,'BoundBrainInspector',return_value=instance) as ctor:
   self.assertIs(d.prepare_inspector(**self.args()),instance);self.assertEqual(ctor.call_args.kwargs['expected']['run_id'],self.run)
   self.old.write_bytes(b'different')
   with self.assertRaises(d.Held):d.prepare_inspector(**self.args())
class ExecuteTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name);self.run='b'*20;self.handoff='a'*20;(self.root/('Core263-pair-handoff-'+self.handoff)).mkdir(mode=0o700)
  self.inspector=types.SimpleNamespace(lease={'run_id':self.handoff},g=types.SimpleNamespace(read=lambda *_:b'old'),old='/tmp/old',expected={'old_config_sha256':'1'*64,'new_config_sha256':'2'*64})
 def tearDown(self):self.tmp.cleanup()
 def test_durable_return_contains_only_real_result(self):
  result={'action':'observe_running_controller','start_attempted':False,'guardian_requalification_needed':True};backend=types.SimpleNamespace()
  with patch.object(d,'BRAIN_ROOT',self.root),patch.object(d,'build_controller',return_value=backend),patch('sys.platform','linux'),patch('os.geteuid',return_value=0),patch.object(recovery_core,'recover_with_backend',return_value=result):ref=d.execute_controller_recovery(inspector=self.inspector,native=None,run_id=self.run)
  value=json.loads(Path(ref['path']).read_bytes());self.assertEqual(value['result'],result);self.assertTrue(value['guardian_requalification_not_inferred'])
 def test_uncertain_error_records_hold_not_success(self):
  backend=types.SimpleNamespace()
  with patch.object(d,'BRAIN_ROOT',self.root),patch.object(d,'build_controller',return_value=backend),patch('sys.platform','linux'),patch('os.geteuid',return_value=0),patch.object(recovery_core,'recover_with_backend',side_effect=TimeoutError('unknown')):
   with self.assertRaises(TimeoutError):d.execute_controller_recovery(inspector=self.inspector,native=None,run_id=self.run)
  out=self.root/('Core263-pair-handoff-'+self.handoff)/('controller-recovery-'+self.run);self.assertTrue((out/'HOLD.PUBLIC.json').exists());self.assertFalse((out/'RETURN.PUBLIC.json').exists())
if __name__=='__main__':unittest.main(verbosity=2)
