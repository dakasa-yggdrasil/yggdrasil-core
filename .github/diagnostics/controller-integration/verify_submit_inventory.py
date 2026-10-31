"""CI-only closed inventory of GenerationEmitter submit call sites."""
import ast
from pathlib import Path

root=Path(__file__).resolve().parent
expected={'runtime/ci_guardian_registry.py':1,'runtime/ci_guardian50_session.py':2,
          'runtime/guarded_generation.py':1,'runtime/controller.py':2,
          'verify_controller_guardian.py':5}
found={}
for file in root.rglob('*.py'):
    tree=ast.parse(file.read_text(),filename=str(file))
    count=sum(isinstance(node,ast.Call) and isinstance(node.func,ast.Attribute)
              and node.func.attr=='submit' for node in ast.walk(tree))
    if count:found[str(file.relative_to(root))]=count
if found!=expected:raise RuntimeError('UNREVIEWED_SUBMIT_CALLS: '+repr(found))
source=(root/'runtime'/'guarded_generation.py').read_text()
if source.count('drain_v3.authorize_positive')!=2 or source.count('drain_v3.authorize_emergency')!=2:
    raise RuntimeError('CENTRAL_EMITTER_PRECHECK_AND_PRESEND_GATE_REQUIRED')
print('PASS closed CI submit inventory and central initial/pre-send gates; not production coverage')
