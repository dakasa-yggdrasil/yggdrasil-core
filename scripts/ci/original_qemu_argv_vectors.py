"""Extract both real source argv expressions without starting either workload.

Usage: python3 original_qemu_argv_vectors.py --core-root CORE --guest-root GUEST
Writes only two synthetic-path vectors for TestExactOriginalCommand.
"""
import argparse
import ast
import json
from pathlib import Path
import posixpath
import re


def evaluate(expression, values):
    tree = ast.parse(expression, mode='eval')
    allowed = (ast.Expression, ast.List, ast.Constant, ast.BinOp, ast.Add,
               ast.Name, ast.Load, ast.Call, ast.Subscript, ast.Mult)
    if any(not isinstance(n, allowed) for n in ast.walk(tree)):
        raise ValueError('unexpected argv expression')
    for n in ast.walk(tree):
        if isinstance(n, ast.Call) and (not isinstance(n.func, ast.Name)
                                       or n.func.id not in ('str', 'join')):
            raise ValueError('unexpected argv call')
    return eval(compile(tree, '<original-argv>', 'eval'),
                {'__builtins__': {}, 'str': str, 'join': posixpath.join}, values)


def vectors(core, guest):
    code = (core/'internal/capacitynativeqemu/realm_linux.go').read_text()
    function = code.split('func (r *Realm) verifyFixedCommand(', 1)[1].split('\nfunc ', 1)[0]
    if 'exactOriginalCommand(raw, expected, native.CommandLineSHA256)' not in function:
        raise ValueError('original verifier must consume the complete exact argv')
    matches = re.findall(r'expected := \[\]string\{([^\n]+)\}', function)
    if len(matches) != 1:
        raise ValueError('one original expected vector required')
    expected = '[' + matches[0] + ']'
    expected = expected.replace('r.Request.Slots[slot-1].ResourceID', 'resource_id')
    expected = expected.replace('r.publicSerial(slot)', 'serial')
    expected = expected.replace('filepath.Join', 'join').replace('actorPort(slot)', 'port')
    tree = ast.parse((guest/'.github/fixtures/native-provisioning/run.py').read_text())
    expressions = [n.value for n in ast.walk(tree) if isinstance(n, ast.Assign)
                   and isinstance(n.value, ast.List) and n.value.elts
                   and isinstance(n.value.elts[0], ast.Constant)
                   and n.value.elts[0].value == 'qemu-system-x86_64']
    if len(expressions) != 1:
        raise ValueError('one actual Guest QEMU argv required')
    result = []
    for slot in (1, 2):
        directory = '/source/slot-' + str(slot)
        identity = '00000000-0000-4000-8000-00000000000' + str(slot)
        serial = '/public/slot-' + str(slot) + '-original-qemu-serial.log'
        values = dict(slot=slot, dir=directory, resource_id=identity, serial=serial,
                      resource_ids={slot: identity}, port=str(18447+slot*1000),
                      disk=directory+'/original.qcow2', seed=directory+'/seed.img',
                      iso=directory+'/source.iso', qmp_path=directory+'/original-qmp.sock')
        result.append({'Expected': evaluate(expected, values),
                       'Actual': evaluate(ast.unparse(expressions[0]), values)})
    return result


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--core-root', type=Path, required=True)
    p.add_argument('--guest-root', type=Path, required=True)
    args = p.parse_args()
    print(json.dumps(vectors(args.core_root, args.guest_root)))
