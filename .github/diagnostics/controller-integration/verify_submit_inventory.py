"""CI-only closed inventory of active and isolated legacy submit call sites."""
import ast
from pathlib import Path

root=Path(__file__).resolve().parent
active={'runtime/ci_guardian_registry.py':1,'runtime/ci_guardian50_session.py':2,
        'runtime/guarded_generation.py':1,'runtime/controller.py':2,'verify_controller_guardian.py':1}
legacy={**active,'verify_controller_guardian.py':5}
def inventory(directory):
    found={}
    for file in directory.rglob('*.py'):
        tree=ast.parse(file.read_text(),filename=str(file))
        count=sum(isinstance(node,ast.Call) and isinstance(node.func,ast.Attribute)
                  and node.func.attr=='submit' for node in ast.walk(tree))
        if count:found[str(file.relative_to(directory))]=count
    return found
for name,directory,expected in [('active',root,active),
    ('isolated-legacy',root.parent/'controller-integration-baseline',legacy)]:
    found=inventory(directory)
    if found!=expected:raise RuntimeError('UNREVIEWED_'+name+'_SUBMIT_CALLS: '+repr(found))
source=(root/'runtime'/'guarded_generation.py').read_text()
if source.count('drain_v3.authorize_positive')!=2 or source.count('drain_v3.authorize_emergency')!=2:
    raise RuntimeError('CENTRAL_EMITTER_PRECHECK_AND_PRESEND_GATE_REQUIRED')
native=(root/'runtime'/'native_io.py').read_text()
if ("role in ('initial_static_apply','hot_dynamic_apply')" not in native
        or 'CI_DRAIN_COORDINATION.admission_or_other_writer()' not in native):
    raise RuntimeError('COMMON_NATIVE_WRITE_GATE_REQUIRED')
tree=ast.parse(source)
netlink_sends=sum(isinstance(node,ast.Call) and isinstance(node.func,ast.Attribute)
    and node.func.attr=='send' and isinstance(node.func.value,ast.Attribute)
    and node.func.value.attr=='nl' for node in ast.walk(tree))
if netlink_sends!=2:
    raise RuntimeError('UNREVIEWED_COMMON_NETLINK_SENDS')
direct_native={}
for file in (root/'runtime').glob('*.py'):
    tree=ast.parse(file.read_text(),filename=str(file))
    for node in ast.walk(tree):
        if (isinstance(node,ast.Call) and isinstance(node.func,ast.Attribute)
                and node.func.attr in ('native','_command')
                and isinstance(node.func.value,ast.Name)):
            key=(file.name,node.func.value.id,node.func.attr)
            direct_native[key]=direct_native.get(key,0)+1
if direct_native!={('native_io.py','process','native'):1,
                    ('eks_https.py','original_process','native'):1}:
    raise RuntimeError('UNREVIEWED_DIRECT_NATIVE_CALLS: '+repr(direct_native))
raw_internal_calls={}
for file in (root/'runtime').glob('*.py'):
    tree=ast.parse(file.read_text(),filename=str(file))
    for node in ast.walk(tree):
        if isinstance(node,ast.ImportFrom) and node.module=='native_io' and any(x.name=='_command' for x in node.names):
            raise RuntimeError('DIRECT_NATIVE_COMMAND_IMPORT_FORBIDDEN')
        if isinstance(node,ast.Call) and isinstance(node.func,ast.Name) and node.func.id=='_command':
            raw_internal_calls[file.name]=raw_internal_calls.get(file.name,0)+1
if raw_internal_calls!={'native_io.py':2}:
    raise RuntimeError('UNREVIEWED_INTERNAL_COMMAND_CALLS: '+repr(raw_internal_calls))
print('PASS closed active and separately isolated legacy inventories; not production coverage')
