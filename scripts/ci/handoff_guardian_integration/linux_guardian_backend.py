"""Linux Guardian restart primitives. No production entry point or inspector.

Guardian's reviewed unit has After= ordering without Requires=. Existing
Restart=on-failure remains effective; a single explicit start is not a claim
that systemd made no automatic restarts. All prior starts and live observations
must be verified independently by the source-pinned inspector.
"""
import contextlib,hashlib,json,os,time
from pathlib import Path
import linux_backend as locks
import guardian_restart as core
GUARDIAN='dakasa-capacity-network-guardian.service';START=['/usr/bin/systemctl','start',GUARDIAN]
class LinuxGuardianBackend:
 def __init__(self,*,maintenance_path,guardian_path,marker_directory,run_id,inspector,native,expected_uid=0):
  self.maintenance_path=Path(maintenance_path);self.guardian_path=Path(guardian_path);self.marker_directory=Path(marker_directory);self.run_id=run_id;self.inspector=inspector;self.native=native;self.expected_uid=expected_uid;self.holding_maintenance=False;self.holding_guardian=False;self.marker=None;self.start_called=False
  core.need(all(p.is_absolute() for p in (self.maintenance_path,self.guardian_path,self.marker_directory)) and len(run_id)==20 and all(c in '0123456789abcdef' for c in run_id),'EXACT_ABSOLUTE_SCOPE_AND_RUN')
 @contextlib.contextmanager
 def maintenance_lock(self):
  core.need(not self.holding_maintenance and not self.holding_guardian,'NONREENTRANT_MAINTENANCE');fd=locks.LinuxBackend._open_lock(self,self.maintenance_path);self.holding_maintenance=True
  try:yield
  finally:self.holding_maintenance=False;os.close(fd)
 @contextlib.contextmanager
 def guardian_lock(self):
  core.need(self.holding_maintenance and not self.holding_guardian,'GUARDIAN_LOCK_ORDER');fd=locks.LinuxBackend._open_lock(self,self.guardian_path);self.holding_guardian=True
  try:yield
  finally:self.holding_guardian=False;os.close(fd)
 def snapshot(self):
  core.need(self.holding_maintenance,'MAINTENANCE_REQUIRED')
  if self.marker is None:
   core.need(locks.marker_absent(self.marker_directory,'ROOT-ONE-GUARDIAN-START.PUBLIC.json',self.expected_uid),'PRIOR_POSSIBLE_GUARDIAN_START_REQUIRES_RECONCILIATION');state='absent'
  else:
   core.need(hashlib.sha256(self.readback_marker(self.marker)).hexdigest()==self.marker['sha256'],'SAME_CURRENT_PROCESS_GUARDIAN_MARKER');state='claimed_by_this_process'
  v=self.inspector.snapshot_guardian()
  core.need(type(v)is dict and not ({'maintenance_lock_owned','guardian_lock_owned','same_handoff_guardian_marker_state'}&set(v)),'INSPECTOR_DOES_NOT_ASSERT_LOCKS_OR_LOCAL_MARKER');return {**v,'maintenance_lock_owned':self.holding_maintenance,'guardian_lock_owned':self.holding_guardian,'same_handoff_guardian_marker_state':state}
 def claim_once(self,identity):
  core.need(self.holding_maintenance and self.holding_guardian and self.marker is None,'GUARDIAN_MARKER_LOCKS');d=os.open(self.marker_directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
  try:
   st=os.fstat(d);core.need(st.st_uid==self.expected_uid and not (st.st_mode&0o077),'PRIVATE_MARKER_DIRECTORY');name='ROOT-ONE-GUARDIAN-START.PUBLIC.json';data=(json.dumps({'schema':'guardian_recovery_possible_start_intent_v1','run_id':self.run_id,'controller_identity':identity},sort_keys=True,separators=(',',':'))+'\n').encode()
   fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=d)
   with os.fdopen(fd,'wb')as f:f.write(data);f.flush();os.fsync(f.fileno())
   os.fsync(d);marker={'schema':'guardian_recovery_possible_start_marker_v1','run_id':self.run_id,'path':str(self.marker_directory/name),'sha256':hashlib.sha256(data).hexdigest(),'exclusive_create':True,'file_fsync':True,'directory_fsync':True,'readback_verified':False};core.need(self.readback_marker(marker)==data,'GUARDIAN_MARKER_READBACK');marker['readback_verified']=True;self.marker=dict(marker);return marker
  finally:os.close(d)
 def readback_marker(self,marker):
  p=Path(marker['path']);core.need(p==self.marker_directory/'ROOT-ONE-GUARDIAN-START.PUBLIC.json','EXACT_GUARDIAN_MARKER_PATH');raw,_=locks.core.read_regular(p,self.expected_uid);return raw
 def start_once(self,marker):
  core.need(self.holding_maintenance and not self.holding_guardian and not self.start_called and self.marker==marker,'GUARDIAN_ONE_SHOT_AND_LOCK_STATE');core.need(hashlib.sha256(self.readback_marker(marker)).hexdigest()==marker['sha256'],'SAME_GUARDIAN_INTENT_IMMEDIATELY_BEFORE_START');self.start_called=True
  started=time.monotonic();_,facts=self.native(START,deadline=started+20,stdin=b'',env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C'},cap=1<<20,diagnostic_path=getattr(self,'start_diagnostic',None));return {**facts,'argv':list(START),'started_monotonic':started,'finished_monotonic':time.monotonic()}
 def observe_guardian(self):return self.inspector.observe_guardian()
