"""Recovery integration draft. No entry point; not approved for production.

The containing source-reviewed SSM executor must verify every supplied original
request/diagnostic and install source-pinned modules before constructing these
classes. Scope binding is rederived while the maintenance lock is held. This
is not protection against privileged operators that ignore the shared protocol.
"""
from pathlib import Path
import brain_inspector,linux_backend,linux_guardian_backend,scope_binding,ssm_terminal_custody
class Held(Exception):pass
def need(v,g):
 if not v:raise Held(g)
class BoundBrainInspector(brain_inspector.BrainInspector):
 def configure_binding(self,*,lease_ref,scope_ref,expected_source_sha256,expected_admission_sha256):
  self.binding_inputs={'lease_original_ref':lease_ref,'scope_original_ref':scope_ref,'expected_source_sha256':expected_source_sha256,'expected_admission_sha256':expected_admission_sha256};self.last_binding=None
 def snapshot(self):
  need(hasattr(self,'binding_inputs'),'REVIEWED_HANDOFF_BINDING_REQUIRED');v=super().snapshot();kw=self.binding_inputs;lease=self.g.read(kw['lease_original_ref']['path'],4096,0o600);scope=self.g.read(kw['scope_original_ref']['path'],32768,0o600);ssm=ssm_terminal_custody.qualify(**self.ssm_evidence)
  bound=scope_binding.bind(lease_bytes=lease,scope_bytes=scope,terminal_scope=self.last_scope_result,ssm_original=ssm,**kw)
  need(bound['old_config_sha256']==self.expected['old_config_sha256'] and bound['new_config_sha256']==self.expected['new_config_sha256'],'SAME_REVIEWED_CONFIG_PAIR_IN_SCOPE');self.last_binding=bound;return v
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
