"""Derive G9 standing bytes from the installed four authority axes and exact package.

Only a new private staging file is written. No service/unit/ledger/key is changed.
Definitions on import are inert; the successor Guardian is loaded only by main.
"""
import argparse
import copy
import os
from pathlib import Path
import sys
import types


def _contract():
    # Definitions from exact source bytes; no .pyc is consulted.
    path = Path(__file__).with_name('pair_change_contract.py')
    raw = path.read_bytes()
    value = types.ModuleType('g9_pair_contract_for_derivation')
    value.__file__ = str(path)
    exec(compile(raw, str(path), 'exec'), value.__dict__)
    return value


C = _contract()


def build(G, m, old, controller_raw, hub_raw, review, units):
    C.require_bound()
    """Use the real Source builder and preserve every inherited authority fact."""
    C.need(old['guardian_source_sha256'] == C.ACTUAL_PREDECESSOR_SOURCE_SHA and old['new_controller_config_sha256'] == C.G8_CONFIG_SHA
           and old['g6_predecessor_guardian_source_sha256'] == C.G6_SOURCE_SHA
           and old['g6_predecessor_standing_config_sha256'] == C.G6_STANDING_SHA, 'ACTUAL_G8_WITH_CANONICAL_G6_AND_BOOT_V2_ANCESTRY')
    C.need(C.sha(controller_raw) == C.HEAD_CONFIG_SHA, 'EXACT_ROOT_G9_CONTROLLER')
    value = G.standing_config(m['files']['source/network_guardian.py'], units[C.CTRL], units[C.HUB], units[C.COLD], units[C.GUARD],
                              controller_raw, hub_raw, review, R43_proofs=copy.deepcopy(old['R43_proofs']),
                              Core262_context_ref=copy.deepcopy(old['Core262_context_ref']), proof_index_ref=copy.deepcopy(old['proof_index_ref']),
                              context_sources=copy.deepcopy(old['context_sources']), hub_source_sha=old['hub_source_sha256'],
                              r13_predecessor_standing_sha=old['r13_predecessor_standing_config_sha256'])
    added = set(value) - set(old)
    changed = {k for k in old if value[k] != old[k]}
    C.need(added == {'g8_predecessor_guardian_source_sha256', 'g8_predecessor_standing_config_sha256'} and
           changed == {'schema', 'guardian_source_sha256', 'controller_unit_sha256', 'cold_unit_sha256', 'guardian_unit_sha256', 'new_controller_config_sha256', 'Root_review'}, 'CLOSED_G9_STANDING_SUCCESSOR_DELTA')
    C.need(all(value[k] == v for k, v in C.ANCESTORS.items()), 'FOUR_DISTINCT_HISTORICAL_AUTHORITIES')
    G.validate(value)
    return value


def expected_inputs(G, m, value, units):
    return {'source_sha256': m['files']['source/network_guardian.py'], 'unit_sha256': units,
            'controller_prefix_sha256': {g: pin for g, _, _, pin in G.PAIR_CHAIN[:-1]},
            'ancestry_input_sha256': {
                'predecessor_standing_config_sha256': value['predecessor_standing_config_sha256'],
                'r13_predecessor_standing_config_sha256': value['r13_predecessor_standing_config_sha256'],
                'r42_controller_config_sha256': C.sha(G.read(G.OLD_CONFIG, 32768, 0o600)),
                'r13_base_controller_config_sha256': G.BASE_CONFIG_SHA,
                'hub_source_sha256': value['hub_source_sha256'], 'hub_boot_config_sha256': value['hub_boot_config_sha256'],
                'hub_unit_sha256': value['hub_unit_sha256']}}


def derive(folder, m, units_dir, output):
    C.require_bound()
    C.need(os.geteuid() == 0 and sys.platform == 'linux', 'ROOT_LINUX_DERIVATION_ONLY')
    source_pin = m['files']['source/network_guardian.py']
    C.need({p.name for p in C.NEW_SOURCE.iterdir()} == set(C.MODULES), 'EXACT_INSTALLED_G9_SOURCE8')
    for name in C.MODULES:
        C.need(C.sha(C.read(C.NEW_SOURCE / name)) == m['files']['source/' + name], 'EXACT_INSTALLED_SUCCESSOR_SOURCE')
    C.need({p.name for p in C.OLD_SOURCE.iterdir()} == set(C.MODULES), 'EXACT_INSTALLED_G8_SOURCE8')
    for name in C.MODULES:
        pin = C.ACTUAL_PREDECESSOR_SOURCE_SHA if name == 'network_guardian.py' else C.HELPERS[name]
        C.need(C.sha(C.read(C.OLD_SOURCE / name)) == pin, 'EXACT_ACTUAL_G8_PREDECESSOR_SOURCE')
    G = C.load_guardian(C.NEW_SOURCE, source_pin)
    C.need(G.HERE == C.NEW_SOURCE and G.CONFIG == C.NEW_STANDING and G.NEW_CONFIG == C.NEW_CONFIG and G.G9_CONTROLLER_CONFIG_SHA == C.HEAD_CONFIG_SHA, 'EXACT_G9_SOURCE_PATHS_AND_HEAD')
    old_raw = C.read(C.OLD_STANDING, 32768, 0o600)
    C.need(C.sha(old_raw) == C.ACTUAL_PREDECESSOR_STANDING_SHA, 'EXACT_ACTUAL_PREDECESSOR_STANDING')
    old = G.loads(old_raw)
    C.need(old['schema'] == 'Root_standing_R13_g8pair_successor_Core262_R43_network_boot_terminal_recovery_v1', 'EXACT_G8_STANDING_SCHEMA')
    for path, pin in [(C.OLD_CONFIG, C.G8_CONFIG_SHA), (C.NEW_CONFIG, C.HEAD_CONFIG_SHA), (C.DROPIN, C.DROPIN_SHA)]:
        C.need(C.sha(C.read(path, 32768)) == pin, 'UNCHANGED_HISTORICAL_AND_EXACT_NEW_CONFIG')
    C.need({p.name for p in G.RUNTIME.iterdir()} == set(G.RUNTIME_HASHES) and all(C.sha(C.read(G.RUNTIME / n)) == h for n, h in G.RUNTIME_HASHES.items()), 'UNCHANGED_RUNTIME14')
    old_controller = G.read(G.OLD_CONFIG, 32768, 0o600)
    chain = G.read_pair_chain()
    controller_raw = G.pair_chain_controller_config_pure(old_controller, chain)
    C.need(C.sha(controller_raw) == C.HEAD_CONFIG_SHA and controller_raw == C.read(C.NEW_CONFIG, 32768, 0o600), 'SOURCE_ACCEPTS_EXACT_ROOT_CONTROLLER_CONFIG')
    units_dir = Path(units_dir)
    C.need(units_dir == C.UNIT_DIR or not str(units_dir).startswith(('/etc/', '/run/', '/proc/', '/sys/')), 'LIVE_OR_PRIVATE_STAGED_UNITS_ONLY')
    if units_dir != C.UNIT_DIR:
        C.private_dir(units_dir)
    unit_pins = {C.CTRL: m['controller_unit_sha256'], C.COLD: m['files']['units/' + C.COLD], C.GUARD: m['files']['units/' + C.GUARD], C.HUB: C.OLD_UNIT_SHAS[C.HUB]}
    for name, pin in unit_pins.items():
        path = (C.UNIT_DIR if name == C.HUB else units_dir) / name
        C.need(C.sha(C.read(path, 32768)) == pin, 'EXACT_REVIEWED_STAGED_OR_LIVE_UNIT')
    hub_raw = G.read(G.HUB13_CONFIG, 32768, 0o600)
    C.need(C.sha(hub_raw) == old['hub_boot_config_sha256'] and C.sha(G.read(G.HUB13_SOURCE)) == old['hub_source_sha256'], 'UNCHANGED_HUB_SOURCE_AND_SEAL')
    review = C.read(folder / 'ROOT-STANDING-REVIEW.txt', 8192, 0o600).decode().removesuffix('\n')
    reviews = [old['Root_review']]
    for path in [G.G6_PREDECESSOR_CONFIG, G.G6_BOOT_V2_PREDECESSOR_CONFIG, G.G7_PREDECESSOR_CONFIG, G.R13_PREDECESSOR_CONFIG, *[v[2] for v in G.PAIR_STANDING_CHAIN]]:
        reviews.append(G.loads(G.read(path, 32768, 0o600))['Root_review'])
    C.need(120 <= len(review) <= 4096 and review not in reviews, 'NEW_ROOT_STANDING_REVIEW')
    value = build(G, m, old, controller_raw, hub_raw, review, unit_pins)
    G.r13_predecessor_standing(value)
    C.need(G.g6_predecessor_standing(value) == (C.G6_SOURCE_SHA, C.G6_STANDING_SHA) and G.g6_boot_v2_predecessor_standing(value) == (C.F315_SOURCE_SHA, C.F315_STANDING_SHA)
           and G.g7_predecessor_standing(value) == (C.G7_SOURCE_SHA, C.G7_STANDING_SHA)
           and G.g8_predecessor_standing(value) == (C.ACTUAL_PREDECESSOR_SOURCE_SHA, C.ACTUAL_PREDECESSOR_STANDING_SHA), 'FOUR_HISTORICAL_AUTHORITIES_AUTHENTICATED')
    C.need(G.pair_predecessor_standings(value) == [(link[1], link[4]) for link in G.PAIR_STANDING_CHAIN], 'UNCHANGED_PAIR_PREFIX_AUTHORITIES')
    G.Owner.hub_seal(types.SimpleNamespace(config=value))
    raw = G.wire(value)
    C.need(len(raw) <= 32768 and G.loads(raw) == value, 'BOUNDED_CANONICAL_STANDING')
    output = Path(output).absolute()
    C.need(not str(output).startswith(('/etc/', '/run/', '/proc/', '/sys/')) and not output.exists() and not output.is_symlink(), 'NEW_PRIVATE_STAGING_OUTPUT_ONLY')
    C.once(output, raw)
    expected = expected_inputs(G, m, value, unit_pins)
    inputs = {'successor_guardian_source_sha256': source_pin, 'head_generation': 'g9pair', 'head_core_digest': 'sha256:' + C.NEW_DIGEST,
              'head_controller_config_sha256': C.HEAD_CONFIG_SHA, 'historical_g6_controller_config_sha256': C.G6_CONFIG_SHA,
              'pair_predecessor_standing_config_sha256': dict(C.PREFIX_STANDINGS), **C.ANCESTORS,
              'pair_chain_controller_config_sha256': {**expected['controller_prefix_sha256'], 'g9pair': C.HEAD_CONFIG_SHA},
              **unit_pins, **expected['ancestry_input_sha256']}
    result = {'schema': C.DERIVATION_SCHEMA, 'hub_profile': 'r13', 'units_source': 'live' if units_dir == C.UNIT_DIR else 'staged',
              'standing_config_sha256': C.sha(raw), 'standing_config_written': True, 'input_sha256': inputs,
              'review_text_printed': False, 'private_files_read': False}
    C.validate_standing_output(result, expected, result['units_source'])
    return result, expected


def main():
    C.require_bound()
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--package', required=True, type=Path)
    p.add_argument('--expected-manifest-sha256', required=True)
    p.add_argument('--out', required=True, type=Path)
    p.add_argument('--units-dir', type=Path, default=C.UNIT_DIR)
    a = p.parse_args()
    folder, m = C.package(a.package, a.expected_manifest_sha256)
    C.need(Path(__file__).absolute() == folder / 'tools' / 'derive_standing_config.py'
           and C.sha(C.read(__file__)) == m['tools']['derive_standing_config.py'], 'DERIVER_FROM_EXACT_REVIEWED_OPERATIONAL_PACKAGE')
    result, _ = derive(folder, m, a.units_dir, a.out)
    print(C.wire(result).decode(), end='', flush=True)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(C.wire({'schema': 'r13_g9pair_standing_derivation_HOLD_v1', 'guard': str(error)[:180], 'automatic_replay': False}).decode(), end='', flush=True)
        raise SystemExit(30) from None
