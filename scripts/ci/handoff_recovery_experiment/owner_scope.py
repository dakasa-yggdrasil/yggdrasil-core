"""Helpers for a future isolated, cgroup-owned handoff owner.

The current R5 operator does not create this lease and is NOT qualified by it.
An SSM caller must launch a unique systemd service with KillMode=control-group,
Delegate=no, no restart, no --collect before inspection and no service replays; that launch and
its original terminal SSM custody are a separate prerequisite.
"""
import hashlib,json,os,re,stat
from pathlib import Path
class Held(Exception):pass
def need(v,g):
 if not v:raise Held(g)
def start_ticks(raw):
 # comm can contain spaces and parentheses: split only after the final ')'.
 i=raw.rfind(')');need(i>=0,'VALID_PROC_STAT');v=raw[i+1:].strip().split();need(len(v)>19 and v[19].isdigit(),'VALID_PROC_START_TICKS');return int(v[19])
def unit_for(run_id):
 need(type(run_id)is str and re.fullmatch('[a-f0-9]{20}',run_id) is not None,'EXACT_RUN_ID');return 'dakasa-network-handoff-'+run_id+'.service'
def make_lease(*,run_id,source_sha256,boot_id,pid,proc_stat,cgroup):
 unit=unit_for(run_id);need(re.fullmatch('[a-f0-9]{64}',source_sha256) is not None and re.fullmatch('[a-f0-9-]{36}',boot_id) is not None and type(pid)is int and pid>1,'EXACT_SOURCE_BOOT_PID')
 need(cgroup=='/system.slice/'+unit,'ISOLATED_OWNER_SERVICE_CGROUP_REQUIRED')
 return {'schema':'handoff_isolated_owner_lease_v1','run_id':run_id,'source_sha256':source_sha256,'boot_id':boot_id,'pid':pid,'start_ticks':start_ticks(proc_stat),'unit':unit,'cgroup':cgroup}
def fs_result(v,expected_path):
 need(type(v)is dict and v.get('path')==expected_path and v.get('fd_closed') is True,'EXACT_CLOSED_FILESYSTEM_READ')
 if v.get('status')=='absent':need(v.get('errno')==2 and v.get('content') is None,'ONLY_EXPLICIT_ENOENT');return None
 need(v.get('status')=='ok' and v.get('errno') is None and type(v.get('content'))is str,'ONLY_SUCCESSFUL_FILESYSTEM_READ');return v['content']
def native_stdout(v,expected_argv):
 need(type(v)is dict and v.get('argv')==expected_argv and type(v.get('stdout'))is str and type(v.get('transport'))is dict,'TYPED_EXACT_NATIVE_READ');t=v['transport'];need(t.get('exit_code')==0 and t.get('captured_output_truncated') is False and all(t.get(k)is True for k in ('native_started','wait_zero','stdout_EOF','stderr_EOF','all_local_FDs_closed','local_child_joined')),'CLOSED_ZERO_NATIVE_READ');need(v.get('stdout_sha256')==hashlib.sha256(v['stdout'].encode()).hexdigest(),'EXACT_NATIVE_STDOUT');return v['stdout']
def validate_terminal(*,lease,boot_read,unit_read,cgroup_read,pid_read,jobs_read,ssm_terminal,expected_ssm):
 unit=unit_for(lease['run_id']);current_boot=fs_result(boot_read,'/proc/sys/kernel/random/boot_id');need(type(current_boot)is str and lease['schema']=='handoff_isolated_owner_lease_v1' and lease['unit']==unit and lease['cgroup']=='/system.slice/'+unit and lease['boot_id']==current_boot.strip(),'SAME_ISOLATED_SCOPE_AND_BOOT')
 need(ssm_terminal.get('schema')=='verified_ssm_terminal_transport_only_v1' and ssm_terminal.get('terminal_does_not_prove_remote_process_or_job_absent') is True and type(expected_ssm)is dict and set(expected_ssm)=={'command_id','instance_id','request_sha256'} and all(ssm_terminal.get(k)==v for k,v in expected_ssm.items()),'EXACT_ORIGINAL_TERMINAL_SSM_REQUIRED')
 raw=native_stdout(unit_read,['/usr/bin/systemctl','show',unit,'--property=Id,ActiveState,MainPID,ControlGroup,KillMode,Delegate,Restart']);rows=[line.split('=',1) for line in raw.splitlines()];need(all(len(row)==2 for row in rows) and len({row[0] for row in rows})==len(rows),'UNIQUE_UNIT_PROPERTIES');unit_properties=dict(rows)
 need(unit_properties.get('Id')==unit and unit_properties.get('ActiveState') in ('inactive','failed') and unit_properties.get('MainPID')=='0' and unit_properties.get('ControlGroup') in ('',lease['cgroup']) and unit_properties.get('KillMode')=='control-group' and unit_properties.get('Delegate')=='no' and unit_properties.get('Restart')=='no','OWNER_SERVICE_TERMINAL_AND_ISOLATED')
 all_systemd_jobs=native_stdout(jobs_read,['/usr/bin/systemctl','list-jobs','--no-pager','--no-legend']);need(not all_systemd_jobs.strip(),'NO_PENDING_SYSTEMD_JOBS')
 cgroup_events=fs_result(cgroup_read,'/sys/fs/cgroup'+lease['cgroup']+'/cgroup.events');current_pid_stat=fs_result(pid_read,'/proc/'+str(lease['pid'])+'/stat')
 if cgroup_events is not None:
  rows=dict(line.split() for line in cgroup_events.splitlines());need(rows.get('populated')=='0','OWNER_CGROUP_AND_DESCENDANTS_EMPTY')
 if current_pid_stat is not None:need(start_ticks(current_pid_stat)!=lease['start_ticks'],'OWNER_PROCESS_TERMINATED_OR_PID_REUSED')
 return {'schema':'handoff_owner_scope_terminal_check_v1','unit':unit,'run_id':lease['run_id'],'same_boot':True,'owner_and_cgroup_empty':True,'no_pending_systemd_jobs':True,'terminal_ssm_distinct':True,'guarantee_depends_on_exclusive_one_shot_launch_and_locked_revalidation':True}
