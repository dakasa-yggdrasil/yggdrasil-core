"""Guardian recovery orchestration. No production backend or entry point.

A backend must derive all observations from real closed native calls, bind the
previous owner and Guardian lifetimes, and persist/re-read an exclusive marker.
Live Guardian requalification remains a separate, observed obligation.
"""
import hashlib,json,re
class Held(Exception):pass
def need(v,g):
 if not v:raise Held(g)
def stable(s,identity):
 for k in ('maintenance_lock_owned','owner_terminal','controller_identity_verified','controller_config_is_reviewed_old','core_healthy','same_47_handles','all_four_backends_positive','hub_and_cold_unchanged','unit_hashes_exact','runtime_hashes_exact','boot_identity_exact'):
  need(s.get(k) is True,'REQUIRED_'+k.upper())
 need(s.get('controller_identity')==identity,'SAME_NEW_CONTROLLER_LIFETIME')
 need(s.get('guardian_state')=='inactive'and s.get('guardian_cgroup_empty') is True and s.get('prior_guardian_identity_absent') is True and s.get('no_pending_jobs') is True,'STOPPED_GUARDIAN_NO_JOBS_OR_PRIOR_PROCESS')
def restart(backend,controller_identity):
 with backend.maintenance_lock():
  first=backend.snapshot();stable(first,controller_identity)
  need(first.get('same_handoff_guardian_marker_state')=='absent','NO_SAME_HANDOFF_GUARDIAN_START_ATTEMPT')
  with backend.guardian_lock():
   current=backend.snapshot();stable(current,controller_identity);need(current.get('guardian_lock_owned') is True,'GUARDIAN_MUTEX_HELD')
   need(current.get('same_handoff_guardian_marker_state')=='absent','NO_SAME_HANDOFF_GUARDIAN_START_ATTEMPT')
   marker=backend.claim_once(controller_identity)
   need(type(marker)is dict and set(marker)=={'schema','run_id','path','sha256','exclusive_create','file_fsync','directory_fsync','readback_verified'} and marker.get('schema')=='guardian_recovery_possible_start_marker_v1' and re.fullmatch('[0-9a-f]{20}',str(marker.get('run_id'))) is not None and type(marker.get('path')) is str and marker['path'].startswith('/') and re.fullmatch('[0-9a-f]{64}',str(marker.get('sha256'))) is not None and all(marker.get(k)is True for k in ('exclusive_create','file_fsync','directory_fsync','readback_verified')),'DURABLE_GUARDIAN_START_INTENT')
   raw=backend.readback_marker(marker);need(type(raw)is bytes and hashlib.sha256(raw).hexdigest()==marker['sha256'],'GUARDIAN_MARKER_BYTES');v=json.loads(raw);need(v=={'schema':'guardian_recovery_possible_start_intent_v1','run_id':marker['run_id'],'controller_identity':controller_identity},'GUARDIAN_MARKER_SAME_CONTROLLER_IDENTITY')
  after=backend.snapshot();stable(after,controller_identity);need(after.get('guardian_lock_owned') is False and after.get('maintenance_lock_owned') is True,'MAINTENANCE_HELD_GUARDIAN_MUTEX_RELEASED')
  need(after.get('same_handoff_guardian_marker_state')=='claimed_by_this_process','SAME_OWN_GUARDIAN_START_ATTEMPT')
  f=backend.start_once(marker);need(type(f)is dict and type(f.get('exit_code'))is int and f['exit_code']==0 and f.get('captured_output_truncated') is False and all(f.get(k)is True for k in ('native_started','wait_zero','stdout_EOF','stderr_EOF','all_local_FDs_closed','local_child_joined')),'GUARDIAN_START_OUTCOME_CLOSED_ZERO')
  obs=backend.observe_guardian();need(type(obs)is dict and obs.get('distinct_guardian_lifetime') is True and obs.get('same_controller_identity')==controller_identity,'ACTUAL_RUNNING_GUARDIAN_IDENTITY')
  return {'guardian_start_attempted':True,'possible_start_marker':marker,'start_custody':f,'guardian_observation':obs,'own_current15_qualified':False,'original120_not_reclassified':True,'further_guardian_observation_required':True}
