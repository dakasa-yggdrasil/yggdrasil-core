import hashlib,json,unittest
import scope_binding as b
class Tests(unittest.TestCase):
 def setUp(self):
  self.run='a'*20;self.source='b'*64;self.adm='c'*64;unit='dakasa-network-handoff-'+self.run+'.service';self.lease={'schema':'handoff_isolated_owner_lease_v1','run_id':self.run,'source_sha256':self.source,'unit':unit,'cgroup':'/system.slice/'+unit,'pid':1_000,'start_ticks':1,'boot_id':'12345678-1234-1234-1234-123456789abc'};self.scope={'schema':'Root_Core263_original_pair_handoff_scope_v1','source_sha256':self.source,'admission_sha256':self.adm,'old_controller_config_sha256':'d'*64,'new_controller_config_sha256':'e'*64};self.ssm={'schema':'verified_ssm_terminal_transport_only_v1','command_id':'cmd','instance_id':'iid','request_sha256':'f'*64,'terminal_does_not_prove_remote_process_or_job_absent':True};self.ts={'schema':'handoff_owner_scope_terminal_check_v1','run_id':self.run,'unit':unit,'owner_lease_sha256':hashlib.sha256((json.dumps(self.lease,sort_keys=True,separators=(',',':'))+'\n').encode()).hexdigest(),'boot_id':self.lease['boot_id'],'same_boot':True,'owner_and_cgroup_empty':True,'no_pending_systemd_jobs':True,'terminal_ssm_distinct':True,'ssm_original':{k:self.ssm[k]for k in ('command_id','instance_id','request_sha256')}}
 def call(self,**kw):
  l=(json.dumps(self.lease,sort_keys=True,separators=(',',':'))+'\n').encode();s=json.dumps(self.scope).encode();folder='/opt/dakasa/capacity-network/Core263-pair-handoff-'+self.run
  lr={'path':folder+'/OWNER-LEASE.PUBLIC.json','sha256':hashlib.sha256(l).hexdigest()};sr={'path':folder+'/HANDOFF-SCOPE.PUBLIC.json','sha256':hashlib.sha256(s).hexdigest()}
  baseline={'schema':'Root_Core263_preSTOP_recovery_baseline_v1','run_id':self.run,'source_sha256':self.source,'boot_id':self.lease['boot_id'],'old_config_sha256':self.scope['old_controller_config_sha256'],'new_config_sha256':self.scope['new_controller_config_sha256'],'current_core_or_handoff_completion_not_inferred':True};br=json.dumps(baseline).encode();bref={'path':folder+'/RECOVERY-BASELINE.PUBLIC.json','sha256':hashlib.sha256(br).hexdigest()}
  marker={'source_sha256':self.source,'run_id':self.run,'recovery_baseline_ref':bref,'isolated_owner_lease_ref':lr,'unknown_or_failed_original_replay_permitted':False};mr=json.dumps(marker).encode();mref={'path':'/opt/dakasa/capacity-network/ROOT-ONE-CORE263-TWO-PAIR-HANDOFF','sha256':hashlib.sha256(mr).hexdigest()}
  args={'lease_bytes':l,'scope_bytes':s,'lease_original_ref':lr,'scope_original_ref':sr,'baseline_bytes':br,'baseline_original_ref':bref,'handoff_marker_bytes':mr,'handoff_marker_original_ref':mref,'terminal_scope':self.ts,'ssm_original':self.ssm,'expected_source_sha256':self.source,'expected_admission_sha256':self.adm};args.update(kw);return b.bind(**args)
 def test_marker_namespace_is_only_handoff_folder(self):
  result=self.call();self.assertTrue(result['marker_directory'].endswith(self.run));self.assertFalse(result['marker_absence_or_recovery_authorized'])
 def test_mismatch_cannot_rebind_another_owner_or_caller(self):
  for args in ({'expected_source_sha256':'0'*64},{'expected_admission_sha256':'0'*64},{'ssm_original':{**self.ssm,'command_id':'other'}}):
   with self.assertRaises(b.Held):self.call(**args)
 def test_original_files_and_terminal_status_required(self):
  with self.assertRaises(b.Held):self.call(lease_original_ref={'path':'/tmp/fake','sha256':'0'*64})
  with self.assertRaises(b.Held):self.call(terminal_scope={**self.ts,'owner_and_cgroup_empty':False})
if __name__=='__main__':unittest.main(verbosity=2)
