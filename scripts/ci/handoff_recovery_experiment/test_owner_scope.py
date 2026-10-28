import base64,hashlib,unittest
import owner_scope as s
class ScopeTest(unittest.TestCase):
 def setUp(self):
  self.r='a'*20;self.boot='7d6b3ec1-139d-4089-bac1-4621cbff83d0';self.stat='123 (x ) has spaces) '+('S '+'0 '*18+'777 0')
  self.l=s.make_lease(run_id=self.r,source_sha256='b'*64,boot_id=self.boot,pid=123,proc_stat=self.stat,cgroup='/system.slice/'+s.unit_for(self.r));self.p={'Id':s.unit_for(self.r),'ActiveState':'inactive','MainPID':'0','ControlGroup':'','KillMode':'control-group','Delegate':'no','Restart':'no'};self.ssm={'schema':'verified_ssm_terminal_transport_only_v1','terminal_does_not_prove_remote_process_or_job_absent':True}
 def call(self,**kw):
  t={'exit_code':0,'captured_output_truncated':False,**{k:True for k in ('native_started','wait_zero','stdout_EOF','stderr_EOF','all_local_FDs_closed','local_child_joined')}}
  absent=lambda path:{'path':path,'fd_closed':True,'status':'absent','errno':2,'content':None}
  diag=lambda raw:{'schema':'private_original_baker_SSH_diagnostic_v1','original_local_transport':t,'stdout_base64':base64.b64encode(raw.encode()).decode(),'stdout_sha256':hashlib.sha256(raw.encode()).hexdigest(),'stdout_bytes':len(raw.encode())}
  unit_out=''.join(k+'='+v+'\n' for k,v in self.p.items());v={'lease':self.l,'boot_read':{'path':'/proc/sys/kernel/random/boot_id','fd_closed':True,'status':'ok','errno':None,'content':self.boot},'unit_read':{'argv':['/usr/bin/systemctl','show',s.unit_for(self.r),'--property=Id,ActiveState,MainPID,ControlGroup,KillMode,Delegate,Restart'],'stdout':unit_out,'stdout_sha256':hashlib.sha256(unit_out.encode()).hexdigest(),'transport':t,'original_diagnostic':diag(unit_out)},'cgroup_read':absent('/sys/fs/cgroup'+self.l['cgroup']+'/cgroup.events'),'pid_read':absent('/proc/123/stat'),'jobs_read':{'argv':['/usr/bin/systemctl','list-jobs','--no-pager','--no-legend'],'stdout':'','stdout_sha256':hashlib.sha256(b'').hexdigest(),'transport':t,'original_diagnostic':diag('')},'ssm_terminal':{**self.ssm,'command_id':'cmd','instance_id':'instance','request_sha256':'digest'},'expected_ssm':{'command_id':'cmd','instance_id':'instance','request_sha256':'digest'}};v.update(kw);return s.validate_terminal(**v)
 def test_dead_scope_is_distinct_from_ssm(self):self.assertTrue(self.call()['owner_and_cgroup_empty'])
 def test_live_pid_live_child_and_jobs_are_rejected(self):
  t={'exit_code':0,'captured_output_truncated':False,**{k:True for k in ('native_started','wait_zero','stdout_EOF','stderr_EOF','all_local_FDs_closed','local_child_joined')}}
  raw=b'11 x start';diag={'schema':'private_original_baker_SSH_diagnostic_v1','original_local_transport':t,'stdout_base64':base64.b64encode(raw).decode(),'stdout_sha256':hashlib.sha256(raw).hexdigest(),'stdout_bytes':len(raw)}
  for kw in ({'pid_read':{'path':'/proc/123/stat','fd_closed':True,'status':'ok','errno':None,'content':self.stat}},{'cgroup_read':{'path':'/sys/fs/cgroup'+self.l['cgroup']+'/cgroup.events','fd_closed':True,'status':'ok','errno':None,'content':'populated 1\nfrozen 0\n'}},{'jobs_read':{'argv':['/usr/bin/systemctl','list-jobs','--no-pager','--no-legend'],'stdout':'11 x start','stdout_sha256':hashlib.sha256(b'11 x start').hexdigest(),'transport':t,'original_diagnostic':diag}}):
   with self.assertRaises(s.Held):self.call(**kw)
 def test_unattempted_or_permission_denied_read_rejected(self):
  for status,errno in [('unknown',None),('error',13)]:
   with self.assertRaises(s.Held):self.call(pid_read={'path':'/proc/123/stat','fd_closed':True,'status':status,'errno':errno,'content':None})
 def test_scope_or_boot_mismatch_rejected(self):
  with self.assertRaises(s.Held):self.call(boot_read={'path':'/proc/sys/kernel/random/boot_id','fd_closed':True,'status':'ok','errno':None,'content':'00000000-0000-0000-0000-000000000000'})
  with self.assertRaises(s.Held):s.make_lease(run_id=self.r,source_sha256='b'*64,boot_id=self.boot,pid=123,proc_stat=self.stat,cgroup='/system.slice/ssm-agent.service')
if __name__=='__main__':unittest.main(verbosity=2)
