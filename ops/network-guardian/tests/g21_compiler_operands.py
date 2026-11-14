"""Declared CI-only operands for the existing maintenance ID; no host claim."""
import ast
import copy
import json
from pathlib import Path
import tempfile
import types
from unittest.mock import patch


def exercise_g21_compiler_binding(test, root):
    source = root / 'rollout/assemble_g25_pair_package.py'
    raw_compiler = source.read_bytes()
    module = types.ModuleType('declared_g25_compiler_CI')
    module.__file__ = str(source)
    exec(compile(raw_compiler, str(source), 'exec'), module.__dict__)
    test.assertIs(module.SOURCE_BOUND, False)
    test.assertIsNone(module.INPUTS_REF)
    test.assertIsNone(module.BINDINGS_REF)
    for name in ('EXPECTED_HEAD', 'EXPECTED_R', 'EXPECTED_D', 'CONTROLLER_REVIEW_SHA',
                 'CONTROLLER_UNIT_SHA', 'PREP_ROOT'):
        test.assertIsNone(getattr(module, name))
    test.assertEqual(module.CAP, 16 << 20)
    with patch.object(module, 'read_ref', side_effect=AssertionError('INERT file I/O')), \
         patch.object(module.subprocess, 'run', side_effect=AssertionError('INERT Git I/O')):
        with test.assertRaisesRegex(module.Hold, 'INERT_NO_FILE_OR_GIT_IO_BEFORE_ROOT_BINDING'):
            module.main()
    main = next(n for n in ast.parse(raw_compiler).body if isinstance(n, ast.FunctionDef) and n.name == 'main')
    keys = next(n.value for n in ast.walk(main) if isinstance(n, ast.Assign) and
                any(isinstance(t, ast.Name) and t.id == 'keys' for t in n.targets))
    test.assertEqual(ast.literal_eval(keys), {'schema', 'source_worktree', 'out', 'ci_attestation_ref',
        'root_controller_review_ref', 'root_standing_review_ref', 'controller_unit_ref',
        'predecessor_manifest_ref', 'actual_M16_swap_return_ref', 'continuity_peer_ipv4',
        'expected_controller_identity', 'expected_guardian_identity'})
    test.assertEqual(module.OLD_MANIFEST_SHA, 'b78df9192cb32b97abaa6acd3268f54eb57a8cce95be848ca78342449d4cd16a')
    test.assertEqual(module.PYTHON_BINDINGS, {
        'source/network_guardian.py': {'PROPOSAL_BOUND', 'HEAD_CORE_SOURCE',
            'HEAD_NEW_CORE_DIGEST', 'G25_CONTROLLER_CONFIG_SHA'},
        'tools/pair_change_contract.py': {'PROPOSAL_BOUND', 'SOURCE_R', 'NEW_DIGEST',
            'G25_CONFIG_SHA', 'OLD_CORE_POD_UID', 'OLD_CORE_CONTAINER_ID'},
        'tools/derive_g15pair_controller_config.py': {'PROPOSAL_BOUND',
            'HEAD_NEW_CORE_DIGEST', 'G25_CONFIG_SHA'},
        'tools/derive_standing_config.py': {'PROPOSAL_BOUND'},
        'tools/g15cut.py': {'PROPOSAL_BOUND'},
    })
    test.assertEqual(module.BOUND_UNITS, {
        'units/dakasa-capacity-network-cold-transport.service',
        'units/dakasa-capacity-network-guardian.service'})
    manifest = next(n.value for n in ast.walk(main) if isinstance(n, ast.Assign) and
                    any(isinstance(t, ast.Name) and t.id == 'manifest' for t in n.targets))
    test.assertEqual({ast.literal_eval(key) for key in manifest.keys}, {
        'schema', 'source_commit', 'source_R', 'amd64_D', 'runtime_package_sha256',
        'files', 'tools', 'controller_unit_sha256', 'root_controller_review_sha256',
        'root_standing_review_sha256', 'expected_controller_identity',
        'expected_guardian_identity', 'protected_refs', 'ci_attestation',
        'continuity_peer_ipv4'})
    payload = next(n.value for n in ast.walk(main) if isinstance(n, ast.Assign) and
                   any(isinstance(t, ast.Name) and t.id == 'payload' for t in n.targets))
    fixed_payload = {ast.literal_eval(key) for key in payload.keys if key is not None}
    test.assertEqual(fixed_payload, {'PACKAGE.json', 'MANIFEST.json', 'controller.service',
        'ROOT-CONTROLLER-REVIEW.txt', 'ROOT-STANDING-REVIEW.txt'})
    test.assertEqual(payload.keys.count(None), 2)
    package_root = root / 'g15pair'
    package = json.loads((package_root / 'PACKAGE.json').read_bytes())
    raw = {name: (package_root / name).read_bytes() for name in package['files']}
    raw['PACKAGE.json'] = (package_root / 'PACKAGE.json').read_bytes()
    contract_tree = ast.parse(raw['tools/pair_change_contract.py'])
    modules = module.literal(contract_tree, 'MODULES')
    tools = module.literal(contract_tree, 'TOOLS')
    helpers = module.literal(contract_tree, 'HELPERS')
    test.assertEqual((len(modules), len(tools)), (8, 4))
    test.assertEqual((len(set(modules)), len(set(tools))), (8, 4))
    test.assertEqual(len(helpers), 7)
    test.assertEqual(len(module.literal(contract_tree, 'REQUIRED_CI')), 18)
    runtime_names = {'source/' + name for name in modules} | module.BOUND_UNITS
    source_names = runtime_names | {'tools/' + name for name in tools} | {'README.md'}
    test.assertEqual(set(package['files']), source_names)
    test.assertEqual((len(source_names), len(runtime_names), len(tools),
                      len(fixed_payload) + len(runtime_names) + len(tools)),
                     (15, 10, 4, 19))
    module.EXPECTED_HEAD = 'b' * 40
    module.EXPECTED_R = 'c' * 40
    module.EXPECTED_D = 'd' * 64
    module.CONTROLLER_UNIT_SHA = 'f' * 64
    values = {'PROPOSAL_BOUND': True, 'HEAD_CORE_SOURCE': module.EXPECTED_R,
        'SOURCE_R': module.EXPECTED_R, 'HEAD_NEW_CORE_DIGEST': 'sha256:' + module.EXPECTED_D,
        'NEW_DIGEST': module.EXPECTED_D, 'G25_CONTROLLER_CONFIG_SHA': 'e' * 64,
        'G25_CONFIG_SHA': 'e' * 64, 'OLD_CORE_POD_UID': '11111111-1111-4111-8111-111111111111',
        'OLD_CORE_CONTAINER_ID': 'containerd://' + 'a' * 64}
    bound = {}
    for name, allowed in module.PYTHON_BINDINGS.items():
        data = raw[name]
        tree = ast.parse(data)
        lines = data.splitlines(keepends=True)
        offsets = [0]
        for line in lines:
            offsets.append(offsets[-1] + len(line))
        edits = []
        for key in allowed:
            nodes = [node for node in tree.body if isinstance(node, ast.Assign) and
                     any(isinstance(target, ast.Name) and target.id == key
                         for target in node.targets)]
            test.assertEqual(len(nodes), 1, (name, key))
            node = nodes[0]
            test.assertEqual(len(node.targets), 1)
            test.assertIsInstance(node.targets[0], ast.Name)
            test.assertIsInstance(node.value, ast.Constant)
            test.assertEqual(node.lineno, node.end_lineno)
            test.assertEqual(node.value.lineno, node.value.end_lineno)
            if key == 'PROPOSAL_BOUND':
                test.assertIs(node.value.value, False)
            else:
                test.assertIsNone(node.value.value)
            lo = offsets[node.value.lineno - 1] + node.value.col_offset
            hi = offsets[node.value.end_lineno - 1] + node.value.end_col_offset
            edits.append((lo, hi, repr(values[key]).encode()))
        for lo, hi, value in sorted(edits, reverse=True):
            data = data[:lo] + value + data[hi:]
        ast.parse(data)
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
    with tempfile.TemporaryDirectory(prefix='declared-g25-overlay-') as folder:
        folder = Path(folder)
        def write(name, data):
            path = folder / name
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open('xb') as stream:
                stream.write(data)
            path.chmod(0o600)
            return {'path': str(path), 'sha256': module.sha(data)}
        binding = {'schema': 'g25_root_literal_source_bindings_v1',
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
        test.assertEqual(len(overlay), 8)
        test.assertEqual(set(overlay), set(module.PYTHON_BINDINGS) |
                         module.BOUND_UNITS | {'PACKAGE.json'})
        test.assertEqual(module.literal_inverse(raw['tools/g15cut.py'],
            overlay['tools/g15cut.py'], {'PROPOSAL_BOUND'}), {'PROPOSAL_BOUND': True})
        missing_engine = copy.deepcopy(binding)
        del missing_engine['bound_source_refs']['tools/g15cut.py']
        with test.assertRaises(module.Hold):
            module.bound_source_overlay(git_blob, missing_engine)
        test.assertIs(proof['bound_bytes_are_CI_git_blobs'], False)
        test.assertIs(proof['future_native_standing_or_swap_qualified'], False)
        test.assertTrue(proof['whole_byte_inverse_only_allowlisted_literals'])
        test.assertEqual(proof['raw_git_files'], {name: module.sha(raw[name]) for name in bound})
        test.assertEqual(proof['root_bound_files'], {name: module.sha(data) for name, data in bound.items()})
        test.assertEqual(set(calls), {module.PREFIX + name for name in raw})
        mutations = {
            'unknown_literal': (guardian, bound[guardian] + b'\nUNREVIEWED_HEADER=1\n'),
            'function_edit': (guardian, bound[guardian].replace(b'def sha(raw):', b'def sha(raw, unreviewed=False):', 1)),
            'engine_function_edit': ('tools/g15cut.py',
                bound['tools/g15cut.py'].replace(b'def sibling(name):',
                    b'def sibling(name, unreviewed=False):', 1)),
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
