"""Synthetic chain; no real controller, systemd, SSM, network or Guardian."""
import hashlib,json,tempfile,types,unittest
from pathlib import Path
from unittest.mock import patch
import bound_recovery_driver as d
import guardian_restart,recovery_core

class Tests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name);self.h='a'*20;self.r='b'*20
  self.out=self.root/('Core263-pair-handoff-'+self.h)/('controller-recovery-'+self.r);self.out.mkdir(parents=True)
  self.identity={'pid':123,'invocation_id':'c'*32,'start_ticks':456}
  self.inspector=types.SimpleNamespace(lease={'run_id':self.h},expected={})
 def tearDown(self):self.tmp.cleanup()
 def controller(self,obs=None,action='distinct_start_closed',start_attempted=True):
  obs=obs or {'new_controller_identity_verified':True,'same_47_native_handles':True,'all_four_observed_positive':True,'controller_identity':self.identity}
  v={'schema':'bound_handoff_controller_recovery_original_return_v1','handoff_run_id':self.h,'recovery_run_id':self.r,'result':{'action':action,'start_attempted':start_attempted,'observation':obs}}
  p=self.out/'RETURN.PUBLIC.json';raw=json.dumps(v).encode();p.write_bytes(raw);return {'path':str(p),'sha256':hashlib.sha256(raw).hexdigest()}
 def run_chain(self,ref):
  backend=types.SimpleNamespace();started=[]
  def guardian(b,identity):started.append(identity);return {'guardian_start_attempted':True,'own_current15_qualified':False}
  with patch.object(d,'COMBINED_RECOVERY_ENABLED',True),patch.object(d,'BRAIN_ROOT',self.root),patch.object(d,'execute_controller_recovery',return_value=ref),patch.object(recovery_core,'read_regular',side_effect=lambda p,uid:(p.read_bytes(),None)),patch.object(d,'build_guardian',return_value=backend),patch.object(guardian_restart,'restart',side_effect=guardian):
   value=d.execute_controller_then_guardian(inspector=self.inspector,native=None,run_id=self.r)
  return value,started
 def test_closed_controller_is_bound_to_guardian(self):
  value,started=self.run_chain(self.controller());self.assertEqual(started,[self.identity]);self.assertEqual(self.inspector.expected['post_recovery_controller'],self.identity)
  receipt=json.loads(Path(value['path']).read_bytes());self.assertTrue(receipt['own_current15_not_inferred'])
 def test_tampered_receipt_fails_before_guardian(self):
  ref=self.controller();Path(ref['path']).write_text('{}')
  with self.assertRaisesRegex(d.Held,'EXACT_CLOSED_CONTROLLER_RETURN'):self.run_chain(ref)
 def test_unobserved_controller_does_not_start_guardian(self):
  ref=self.controller(action='observe_running_controller')
  with self.assertRaisesRegex(d.Held,'INDEPENDENT_EXISTING_CONTROLLER_OBSERVATION'):self.run_chain(ref)
 def test_observed_existing_controller_is_not_attributed_to_recovery(self):
  obs={'existing_controller_identity_verified':True,'start_attribution_not_inferred':True,'same_47_native_handles':True,'all_four_observed_positive':True,'controller_identity':self.identity}
  value,started=self.run_chain(self.controller(obs=obs,action='observe_running_controller',start_attempted=False));self.assertEqual(started,[self.identity]);self.assertTrue(Path(value['path']).exists())
 def test_observation_missing_backends_fails(self):
  obs={'existing_controller_identity_verified':True,'start_attribution_not_inferred':True,'same_47_native_handles':True,'all_four_observed_positive':False,'controller_identity':self.identity}
  with self.assertRaisesRegex(d.Held,'SAME_OBSERVED_CONTROLLER_AND_BACKENDS'):self.run_chain(self.controller(obs=obs,action='observe_running_controller',start_attempted=False))
 def test_guarded_by_default(self):
  with self.assertRaisesRegex(d.Held,'DRAFT_NOT_RELEASED'):d.execute_controller_then_guardian(inspector=self.inspector,native=None,run_id=self.r)

if __name__=='__main__':unittest.main(verbosity=2)
