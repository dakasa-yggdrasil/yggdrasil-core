import hashlib,json,tempfile,types,unittest
from pathlib import Path
from unittest.mock import patch
import brain_inspector as b
class InspectorTests(unittest.TestCase):
 def setUp(self):
  self.t=tempfile.TemporaryDirectory();self.old=b'old';self.e={'old_config_sha256':hashlib.sha256(self.old).hexdigest(),'new_config_sha256':'f'*64,'boot_id':'boot'}
  self.i=object.__new__(b.BrainInspector);self.i.seq=0;self.i.out=Path(self.t.name);self.i.old=Path(self.t.name)/'old';self.i.lease={};self.i.ssm_evidence={};self.i.native=None;self.i.expected=self.e
  self.i.g=types.SimpleNamespace(read=lambda path,*args:self.old,NEW_CONFIG='config',UNIT='controller',GUARDIAN='guardian',RUNTIME=Path('/runtime'))
  self.i.static=lambda:('handles',{});self.i.properties=lambda unit:{'ActiveState':'inactive','SubState':'dead','MainPID':'0'};self.i.cgroup_empty=lambda _:True
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
 def test_wrong_old_config_rejected(self):
  with self.assertRaises(b.Held):self.i.check_once(b'other',self.e)
if __name__=='__main__':unittest.main(verbosity=2)
