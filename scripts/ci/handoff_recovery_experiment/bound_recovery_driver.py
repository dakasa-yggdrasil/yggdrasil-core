"""Recovery integration draft. No entry point; not approved for production.

The containing source-reviewed SSM executor must verify every supplied original
request/diagnostic and install source-pinned modules before constructing these
classes. Scope binding is rederived while the maintenance lock is held. This
is not protection against privileged operators that ignore the shared protocol.
"""
from pathlib import Path
import brain_inspector,linux_backend,linux_guardian_backend,scope_binding,ssm_terminal_custody
BRAIN_ROOT=Path('/opt/dakasa/capacity-network')
class Held(Exception):pass
def need(v,g):
 if not v:raise Held(g)
class BoundBrainInspector(brain_inspector.BrainInspector):
 def configure_binding(self,*,lease_ref,scope_ref,baseline_ref,handoff_marker_ref,expected_source_sha256,expected_admission_sha256):
  self.binding_inputs={'lease_original_ref':lease_ref,'scope_original_ref':scope_ref,'baseline_original_ref':baseline_ref,'handoff_marker_original_ref':handoff_marker_ref,'expected_source_sha256':expected_source_sha256,'expected_admission_sha256':expected_admission_sha256};self.last_binding=None
 def snapshot(self):
  need(hasattr(self,'binding_inputs'),'REVIEWED_HANDOFF_BINDING_REQUIRED');v=super().snapshot();kw=self.binding_inputs;lease=self.g.read(kw['lease_original_ref']['path'],4096,0o600);scope=self.g.read(kw['scope_original_ref']['path'],32768,0o600);ssm=ssm_terminal_custody.qualify(**self.ssm_evidence)
  baseline=self.g.read(kw['baseline_original_ref']['path'],32768,0o600);marker=self.g.read(kw['handoff_marker_original_ref']['path'],32768,0o600);bound=scope_binding.bind(lease_bytes=lease,scope_bytes=scope,baseline_bytes=baseline,handoff_marker_bytes=marker,terminal_scope=self.last_scope_result,ssm_original=ssm,**kw)
  need(bound['old_config_sha256']==self.expected['old_config_sha256'] and bound['new_config_sha256']==self.expected['new_config_sha256'],'SAME_REVIEWED_CONFIG_PAIR_IN_SCOPE');baseline=bound['recovery_baseline'];need(all(self.expected.get(k)==baseline.get(k) for k in ('boot_id','guardian_source_sha256','guardian_authority_sha256','handles_sha256','prior_controller','prior_guardian','prior_unit_properties','core')),'EXACT_PRESTOP_CONTROLLER_GUARDIAN_NETWORK_AND_CORE_BASELINE');self.last_binding=bound;return v
class BoundLinuxBackend(linux_backend.LinuxBackend):
 def snapshot(self):
  v=super().snapshot();bound=self.inspector.last_binding;need(type(bound)is dict and bound.get('schema')=='bound_handoff_recovery_marker_namespace_v1' and bound.get('marker_directory')==str(self.marker_directory) and bound.get('marker_absence_or_recovery_authorized') is False,'EXACT_ORIGINAL_HANDOFF_MARKER_NAMESPACE')
  # super().snapshot() runs with the shared mutex and refuses any pre-existing
  # possible-start marker unless it is this same process's own exact marker.
  # One marked recovery per authenticated future handoff is thus enforced.
  need(v.get('previous_recovery_start_terminal') is False,'ONLY_UNQUALIFIED_INSPECTOR_STATUS_MAY_BE_DERIVED_BY_BOUND_BACKEND');v['previous_recovery_start_terminal']=True;return v
class BoundGuardianBackend(linux_guardian_backend.LinuxGuardianBackend):
 def snapshot(self):
  v=super().snapshot();bound=self.inspector.last_binding;need(type(bound)is dict and bound.get('schema')=='bound_handoff_recovery_marker_namespace_v1' and bound.get('marker_directory')==str(self.marker_directory) and bound.get('marker_absence_or_recovery_authorized') is False,'EXACT_ORIGINAL_HANDOFF_GUARDIAN_MARKER_NAMESPACE')
  need(v.get('previous_guardian_start_terminal') is False,'ONLY_UNQUALIFIED_GUARDIAN_STATUS_MAY_BE_DERIVED_BY_BOUND_BACKEND');v['previous_guardian_start_terminal']=True;return v

def build_controller(*,inspector,native,marker_directory,run_id):
 """Force the actual reviewed Brain paths; caller must bind scope first."""
 return BoundLinuxBackend(maintenance_path='/run/dakasa-capacity-network/guardian-maintenance.lock',controller_path='/run/dakasa-capacity-network/controller.lock',config_path='/etc/dakasa/capacity-network/controller.r42-cold-unknown184014.production.json',marker_directory=marker_directory,run_id=run_id,inspector=inspector,native=native,expected_uid=0)

def build_guardian(*,inspector,native,marker_directory,run_id):
 return BoundGuardianBackend(maintenance_path='/run/dakasa-capacity-network/guardian-maintenance.lock',guardian_path='/var/lib/dakasa-capacity-network-recovery/guardian.lock',marker_directory=marker_directory,run_id=run_id,inspector=inspector,native=native,expected_uid=0)

def execute_controller_recovery(*,inspector,native,run_id):
 """Called only by a separately source-pinned SSM owner; no autonomous retry.

 A durable marker survives an unknown result. A missing completion receipt is
 never interpreted as a failed START. Guardian start/requalification is separate.
 """
 import json,os,re,sys
 import recovery_core
 need(sys.platform=='linux' and os.geteuid()==0 and re.fullmatch('[a-f0-9]{20}',str(run_id)),'EXACT_LINUX_ROOT_RECOVERY_RUN')
 handoff=inspector.lease['run_id'];need(re.fullmatch('[a-f0-9]{20}',str(handoff)),'EXACT_AUTHENTIC_HANDOFF_RUN');folder=BRAIN_ROOT/('Core263-pair-handoff-'+handoff);out=folder/('controller-recovery-'+run_id);out.mkdir(mode=0o700)
 backend=build_controller(inspector=inspector,native=native,marker_directory=folder,run_id=run_id);backend.start_diagnostic=out/'START-NATIVE-ORIGINAL-IO.PRIVATE.json';old=inspector.g.read(inspector.old,32768,0o600);expected={k:inspector.expected[k]for k in ('old_config_sha256','new_config_sha256')}
 def record(name,value):
  raw=(json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode();fd=os.open(out/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
  with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
  d=os.open(out,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
  try:os.fsync(d)
  finally:os.close(d)
  return {'path':str(out/name),'sha256':__import__('hashlib').sha256(raw).hexdigest()}
 try:
  result=recovery_core.recover_with_backend(backend,expected,old);ref=record('RETURN.PUBLIC.json',{'schema':'bound_handoff_controller_recovery_original_return_v1','handoff_run_id':handoff,'recovery_run_id':run_id,'result':result,'guardian_requalification_not_inferred':True,'unobserved_no_gap_not_inferred':True});return ref
 except BaseException as e:
  # The marker and original runtime evidence, not this generic error, determine
  # whether a START might have occurred. Never call the same operation again.
  try:record('HOLD.PUBLIC.json',{'schema':'bound_handoff_controller_recovery_hold_v1','handoff_run_id':handoff,'recovery_run_id':run_id,'error_class':type(e).__name__,'automatic_replay_permitted':False})
  except BaseException:pass
  raise

def prepare_inspector(*,guardian,base,bridge,coverage,native,lease_ref,scope_ref,baseline_ref,handoff_marker_ref,ssm_evidence,expected_source_sha256,expected_admission_sha256,diagnostic_root):
 """Derive expected state from the recorded pre-STOP baseline, not caller guesses.

 Reads here do not authorize a start. The inspector revalidates the whole join
 under maintenance lock before the backend permits any restoration/start.
 """
 lease=guardian.loads(guardian.read(lease_ref['path'],4096,0o600));baseline=guardian.loads(guardian.read(baseline_ref['path'],32768,0o600));need(lease.get('schema')=='handoff_isolated_owner_lease_v1' and baseline.get('schema')=='Root_Core263_preSTOP_recovery_baseline_v1' and lease.get('run_id')==baseline.get('run_id'),'EXACT_ORIGINAL_RECOVERY_BASELINE_AND_LEASE')
 run=lease['run_id'];need(__import__('re').fullmatch('[a-f0-9]{20}',str(run)),'EXACT_HANDOFF_RUN');folder=BRAIN_ROOT/('Core263-pair-handoff-'+run);need(baseline_ref['path']==str(folder/'RECOVERY-BASELINE.PUBLIC.json'),'ONLY_HANDOFF_BASELINE_PATH')
 old=folder/'OLD-CONTROLLER-CONFIG.PUBLIC.json'
 if not old.exists():old=guardian.NEW_CONFIG
 need(__import__('hashlib').sha256(guardian.read(old,32768,0o600)).hexdigest()==baseline['old_config_sha256'],'ACTUAL_EXACT_OLD_CONFIG_BYTES')
 inspector=BoundBrainInspector(guardian=guardian,base=base,bridge=bridge,coverage=coverage,native=native,expected=baseline,lease=lease,ssm_evidence=ssm_evidence,old_config_path=old,diagnostic_root=diagnostic_root)
 inspector.configure_binding(lease_ref=lease_ref,scope_ref=scope_ref,baseline_ref=baseline_ref,handoff_marker_ref=handoff_marker_ref,expected_source_sha256=expected_source_sha256,expected_admission_sha256=expected_admission_sha256)
 return inspector
