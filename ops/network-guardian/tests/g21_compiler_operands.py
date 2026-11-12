"""Declared CI-only operands for the existing maintenance ID; no host claim."""
import ast
import copy
import json
from pathlib import Path
import tempfile
import types
from unittest.mock import patch


def exercise_g21_compiler_binding(test, root):
    source = root / 'rollout/assemble_g21_pair_package.py'
    raw_compiler = source.read_bytes()
    module = types.ModuleType('declared_g21_compiler_CI')
    module.__file__ = str(source)
    exec(compile(raw_compiler, str(source), 'exec'), module.__dict__)
    test.assertIs(module.SOURCE_BOUND, False)
    test.assertIsNone(module.INPUTS_REF)
    test.assertIsNone(module.BINDINGS_REF)
    with patch.object(module, 'read_ref', side_effect=AssertionError('INERT file I/O')), \
         patch.object(module.subprocess, 'run', side_effect=AssertionError('INERT Git I/O')):
        with test.assertRaisesRegex(module.Hold, 'INERT_NO_FILE_OR_GIT_IO_BEFORE_ROOT_BINDING'):
            module.main()
    main = next(n for n in ast.parse(raw_compiler).body if isinstance(n, ast.FunctionDef) and n.name == 'main')
    keys = next(n.value for n in ast.walk(main) if isinstance(n, ast.Assign) and
                any(isinstance(t, ast.Name) and t.id == 'keys' for t in n.targets))
    test.assertEqual(ast.literal_eval(keys), {'schema', 'source_worktree', 'out', 'ci_attestation_ref',
        'root_controller_review_ref', 'root_standing_review_ref', 'controller_unit_ref',
        'predecessor_manifest_ref', 'actual_M14_swap_return_ref', 'continuity_peer_ipv4',
        'expected_controller_identity', 'expected_guardian_identity'})
    test.assertEqual(module.OLD_MANIFEST_SHA, '2984c52bc1eac995f6a4eee2ee7c218a9ee5bd16abe483be2e70d3c5f18f74ae')
    package_root = root / 'g15pair'
    package = json.loads((package_root / 'PACKAGE.json').read_bytes())
    raw = {name: (package_root / name).read_bytes() for name in package['files']}
    raw['PACKAGE.json'] = (package_root / 'PACKAGE.json').read_bytes()
    module.EXPECTED_HEAD = 'b' * 40
    module.EXPECTED_R = 'c' * 40
    module.EXPECTED_D = 'd' * 64
    module.CONTROLLER_UNIT_SHA = 'f' * 64
    values = {'PROPOSAL_BOUND': True, 'HEAD_CORE_SOURCE': module.EXPECTED_R,
        'SOURCE_R': module.EXPECTED_R, 'HEAD_NEW_CORE_DIGEST': 'sha256:' + module.EXPECTED_D,
        'NEW_DIGEST': module.EXPECTED_D, 'G23_CONTROLLER_CONFIG_SHA': 'e' * 64,
        'G23_CONFIG_SHA': 'e' * 64, 'OLD_CORE_POD_UID': '11111111-1111-4111-8111-111111111111',
        'OLD_CORE_CONTAINER_ID': 'containerd://' + 'a' * 64}
    bound = {}
    for name, allowed in module.PYTHON_BINDINGS.items():
        data = raw[name]
        for key in allowed:
            old = (key + '=' + ('False' if key == 'PROPOSAL_BOUND' else 'None')).encode()
            # The standing Source deliberately retains its original spaced assignment.
            if old not in data:
                old = (key + ' = ' + ('False' if key == 'PROPOSAL_BOUND' else 'None')).encode()
            test.assertEqual(data.count(old), 1, (name, key))
            old_value = b'False' if key == 'PROPOSAL_BOUND' else b'None'
            data = data.replace(old, old[:-len(old_value)] + repr(values[key]).encode(), 1)
        bound[name] = data
        actual = module.literal_inverse(raw[name], data, allowed)
        test.assertEqual(actual, {key: values[key] for key in allowed})
    guardian = 'source/network_guardian.py'
    old_pin, new_pin = module.sha(raw[guardian]), module.sha(bound[guardian])
    for name in module.BOUND_UNITS:
        test.assertEqual(raw[name].count(('--source-sha256 ' + old_pin).encode()), 1)
        bound[name] = raw[name].replace(old_pin.encode(), new_pin.encode(), 1)
    bound_package = copy.deepcopy(package)
    bound_package.update(base_Core_source=module.EXPECTED_R,
        amd64_Core_manifest_digest='sha256:' + module.EXPECTED_D,
        controller_config_sha256='e' * 64, controller_unit_sha256=module.CONTROLLER_UNIT_SHA,
        source_bound=True, proposal_bound=True, source_unit_hash_arguments_bound=True,
        inert_unit_source_sha_argument=new_pin, bound_Guardian_bytes=len(bound[guardian]),
        fixed_width_latebind_Guardian_bytes=len(bound[guardian]))
    bound_package['files'] = {name: module.sha(bound.get(name, data)) for name, data in raw.items() if name != 'PACKAGE.json'}
    bound['PACKAGE.json'] = module.wire(bound_package)
    with tempfile.TemporaryDirectory(prefix='declared-g21-overlay-') as folder:
        folder = Path(folder)
        def write(name, data):
            path = folder / name
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open('xb') as stream:
                stream.write(data)
            path.chmod(0o600)
            return {'path': str(path), 'sha256': module.sha(data)}
        binding = {'schema': 'g23_root_literal_source_bindings_v1',
            'source_commit': module.EXPECTED_HEAD, 'reviewed_by_root': True,
            'bound_source_refs': {name: write(name, data) for name, data in bound.items()}}
        module.BINDINGS_REF = {'path': str(folder / 'DECLARED-BINDING.json'), 'sha256': '1' * 64}
        calls = []
        def git_blob(name):
            test.assertTrue(name.startswith(module.PREFIX))
            calls.append(name)
            return raw[name.removeprefix(module.PREFIX)]
        overlay, proof = module.bound_source_overlay(git_blob, binding)
        test.assertEqual(overlay, bound)
        test.assertEqual(len(overlay), 7)
        test.assertIs(proof['bound_bytes_are_CI_git_blobs'], False)
        test.assertIs(proof['future_native_standing_or_swap_qualified'], False)
        test.assertTrue(proof['whole_byte_inverse_only_allowlisted_literals'])
        test.assertEqual(proof['raw_git_files'], {name: module.sha(raw[name]) for name in bound})
        test.assertEqual(proof['root_bound_files'], {name: module.sha(data) for name, data in bound.items()})
        test.assertEqual(set(calls), {module.PREFIX + name for name in raw})
        mutations = {
            'unknown_literal': (guardian, bound[guardian] + b'\nUNREVIEWED_HEADER=1\n'),
            'function_edit': (guardian, bound[guardian].replace(b'def sha(raw):', b'def sha(raw, unreviewed=False):', 1)),
            'PACKAGE_false_to_zero': ('PACKAGE.json', module.wire({**bound_package,
                'actual_G18_predecessor': {**bound_package['actual_G18_predecessor'], 'Core_candidate_eligible': 0}})),
        }
        for fault, (name, data) in mutations.items():
            test.assertNotEqual(data, bound[name], fault)
            candidate = copy.deepcopy(binding)
            candidate['bound_source_refs'][name] = write('fault-' + fault + '.data', data)
            with test.subTest(compiler_fault=fault), test.assertRaises(module.Hold):
                module.bound_source_overlay(git_blob, candidate)
        foreign = copy.deepcopy(binding)
        foreign['bound_source_refs'][guardian] = dict(binding['bound_source_refs']['tools/pair_change_contract.py'])
        with test.assertRaises(module.Hold):
            module.bound_source_overlay(git_blob, foreign)
        unknown = copy.deepcopy(binding)
        unknown['bound_source_refs']['unreviewed.py'] = dict(binding['bound_source_refs'][guardian])
        with test.assertRaises(module.Hold):
            module.bound_source_overlay(git_blob, unknown)
