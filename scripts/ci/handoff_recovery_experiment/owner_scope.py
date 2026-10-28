"""Helpers for a future isolated, cgroup-owned handoff owner.

The current R5 operator does not create this lease and is NOT qualified by it.
An SSM caller must launch a unique systemd service with KillMode=control-group,
Delegate=no, no restart, no --collect before inspection and no service replays; that launch and
its original terminal SSM custody are a separate prerequisite.
"""
import hashlib,json,os,re,stat
import ssm_terminal_custody
from pathlib import Path
class Held(Exception):pass
def need(v,g):
 if not v:raise Held(g)
def start_ticks(raw):
 # comm can contain spaces and parentheses: split only after the final ')'.
 i=raw.rfind(')');need(i>=0,'VALID_PROC_STAT');v=raw[i+1:].strip().split();need(len(v)>19 and v[19].isdigit(),'VALID_PROC_START_TICKS');return int(v[19])
def unit_for(run_id,kind='handoff'):
 need(type(run_id)is str and re.fullmatch('[a-f0-9]{20}',run_id) is not None and kind in ('handoff','controller_recovery'),'EXACT_RUN_ID_AND_OWNER_KIND');return ('dakasa-network-handoff-' if kind=='handoff' else 'dakasa-controller-recovery-')+run_id+'.service'
def make_lease(*,run_id,source_sha256,boot_id,pid,proc_stat,cgroup,kind='handoff'):
 unit=unit_for(run_id,kind);need(re.fullmatch('[a-f0-9]{64}',source_sha256) is not None and re.fullmatch('[a-f0-9-]{36}',boot_id) is not None and type(pid)is int and pid>1,'EXACT_SOURCE_BOOT_PID')
 need(cgroup=='/system.slice/'+unit,'ISOLATED_OWNER_SERVICE_CGROUP_REQUIRED')
 return {'schema':('handoff_isolated_owner_lease_v1' if kind=='handoff' else 'controller_recovery_isolated_owner_lease_v1'),'run_id':run_id,'source_sha256':source_sha256,'boot_id':boot_id,'pid':pid,'start_ticks':start_ticks(proc_stat),'unit':unit,'cgroup':cgroup}
def fs_result(v,expected_path):
 need(type(v)is dict and v.get('path')==expected_path and v.get('fd_closed') is True,'EXACT_CLOSED_FILESYSTEM_READ')
 if v.get('status')=='absent':need(v.get('errno')==2 and v.get('content') is None,'ONLY_EXPLICIT_ENOENT');return None
 need(v.get('status')=='ok' and v.get('errno') is None and type(v.get('content'))is str,'ONLY_SUCCESSFUL_FILESYSTEM_READ');return v['content']
def native_stdout(v,expected_argv):
 need(type(v)is dict and v.get('argv')==expected_argv and type(v.get('stdout'))is str and type(v.get('transport'))is dict,'TYPED_EXACT_NATIVE_READ');t=v['transport'];need(t.get('exit_code')==0 and t.get('captured_output_truncated') is False and all(t.get(k)is True for k in ('native_started','wait_zero','stdout_EOF','stderr_EOF','all_local_FDs_closed','local_child_joined')),'CLOSED_ZERO_NATIVE_READ');need(v.get('stdout_sha256')==hashlib.sha256(v['stdout'].encode()).hexdigest(),'EXACT_NATIVE_STDOUT');diagnostic=v.get('original_diagnostic');need(ssm_terminal_custody.stdout(diagnostic)==v['stdout'].encode(),'EXACT_ORIGINAL_DIAGNOSTIC_STDOUT');dt=diagnostic['original_local_transport'];need(all(t.get(k)==dt.get(k) for k in ('pid','exit_code','native_started','wait_zero','stdout_EOF','stderr_EOF','all_local_FDs_closed','local_child_joined','captured_output_truncated')),'SAME_NATIVE_CALL_AND_DIAGNOSTIC');return v['stdout']
def validate_terminal(*,lease,boot_read,unit_read,cgroup_read,pid_read,jobs_read,ssm_terminal,expected_ssm,kind='handoff'):
 unit=unit_for(lease['run_id'],kind);current_boot=fs_result(boot_read,'/proc/sys/kernel/random/boot_id');need(type(current_boot)is str and lease['schema']==('handoff_isolated_owner_lease_v1' if kind=='handoff' else 'controller_recovery_isolated_owner_lease_v1') and lease['unit']==unit and lease['cgroup']=='/system.slice/'+unit and lease['boot_id']==current_boot.strip(),'SAME_ISOLATED_SCOPE_AND_BOOT')
 need(ssm_terminal.get('schema')=='verified_ssm_terminal_transport_only_v1' and ssm_terminal.get('terminal_does_not_prove_remote_process_or_job_absent') is True and type(expected_ssm)is dict and set(expected_ssm)=={'command_id','instance_id','request_sha256'} and all(ssm_terminal.get(k)==v for k,v in expected_ssm.items()),'EXACT_ORIGINAL_TERMINAL_SSM_REQUIRED')
 raw=native_stdout(unit_read,['/usr/bin/systemctl','show',unit,'--property=Id,ActiveState,MainPID,ControlGroup,KillMode,Delegate,Restart']);rows=[line.split('=',1) for line in raw.splitlines()];need(all(len(row)==2 for row in rows) and len({row[0] for row in rows})==len(rows),'UNIQUE_UNIT_PROPERTIES');unit_properties=dict(rows)
 need(unit_properties.get('Id')==unit and unit_properties.get('ActiveState') in ('inactive','failed') and unit_properties.get('MainPID')=='0' and unit_properties.get('ControlGroup') in ('',lease['cgroup']) and unit_properties.get('KillMode')=='control-group' and unit_properties.get('Delegate')=='no' and unit_properties.get('Restart')=='no','OWNER_SERVICE_TERMINAL_AND_ISOLATED')
 all_systemd_jobs=native_stdout(jobs_read,['/usr/bin/systemctl','list-jobs','--no-pager','--no-legend']);need(not all_systemd_jobs.strip(),'NO_PENDING_SYSTEMD_JOBS')
 cgroup_events=fs_result(cgroup_read,'/sys/fs/cgroup'+lease['cgroup']+'/cgroup.events');current_pid_stat=fs_result(pid_read,'/proc/'+str(lease['pid'])+'/stat')
 if cgroup_events is not None:
  rows=dict(line.split() for line in cgroup_events.splitlines());need(rows.get('populated')=='0','OWNER_CGROUP_AND_DESCENDANTS_EMPTY')
 if current_pid_stat is not None:need(start_ticks(current_pid_stat)!=lease['start_ticks'],'OWNER_PROCESS_TERMINATED_OR_PID_REUSED')
 return {'schema':('handoff_owner_scope_terminal_check_v1' if kind=='handoff' else 'controller_recovery_owner_scope_terminal_check_v1'),'unit':unit,'run_id':lease['run_id'],'owner_lease_sha256':hashlib.sha256((json.dumps(lease,sort_keys=True,separators=(',',':'))+'\n').encode()).hexdigest(),'boot_id':lease['boot_id'],'same_boot':True,'owner_and_cgroup_empty':True,'no_pending_systemd_jobs':True,'terminal_ssm_distinct':True,'ssm_original':dict(expected_ssm),'guarantee_depends_on_exclusive_one_shot_launch_and_locked_revalidation':True}

def persist_self_lease(*,run_id,source_path,source_sha256,output_directory,kind='handoff'):
 """Write one durable self identity; callable only inside its isolated service.

 Does not launch the service or prove its later termination. All parent-path
 ownership and immutability are additional installer/admission obligations.
 """
 import sys
 need(sys.platform=='linux' and os.geteuid()==0,'LINUX_ROOT_REQUIRED')
 src=Path(source_path);out=Path(output_directory);need(src.is_absolute() and out.is_absolute(),'ABSOLUTE_SOURCE_AND_OUTPUT')
 fd=os.open(src,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  st=os.fstat(fd);need(stat.S_ISREG(st.st_mode) and st.st_uid==0 and st.st_nlink==1 and not stat.S_IMODE(st.st_mode)&0o022,'SAFE_OWNER_SOURCE');raw=b''
  while True:
   part=os.read(fd,65536)
   if not part:break
   raw+=part;need(len(raw)<=1<<20,'BOUNDED_OWNER_SOURCE')
 finally:os.close(fd)
 need(hashlib.sha256(raw).hexdigest()==source_sha256,'EXACT_OWNER_SOURCE_SHA')
 pid=os.getpid();boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip();proc=Path('/proc/'+str(pid)+'/stat').read_text();groups=Path('/proc/'+str(pid)+'/cgroup').read_text().splitlines();unified=[r[3:] for r in groups if r.startswith('0::')];need(len(unified)==1,'ONLY_UNIFIED_CGROUP_V2')
 lease=make_lease(run_id=run_id,source_sha256=source_sha256,boot_id=boot,pid=pid,proc_stat=proc,cgroup=unified[0],kind=kind);body=(json.dumps(lease,sort_keys=True,separators=(',',':'))+'\n').encode()
 d=os.open(out,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  ds=os.fstat(d);need(ds.st_uid==0 and not stat.S_IMODE(ds.st_mode)&0o077,'PRIVATE_OWNER_DIRECTORY');name='OWNER-LEASE.PUBLIC.json';f=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=d)
  with os.fdopen(f,'wb') as file:file.write(body);file.flush();os.fsync(file.fileno())
  os.fsync(d);f=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=d)
  with os.fdopen(f,'rb') as file:need(file.read(len(body)+1)==body,'OWNER_LEASE_READBACK')
 finally:os.close(d)
 return {'path':str(out/name),'sha256':hashlib.sha256(body).hexdigest()}
