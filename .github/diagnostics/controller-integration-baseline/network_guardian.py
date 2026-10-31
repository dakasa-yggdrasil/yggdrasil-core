"""Root-standing Core262/R43 cold transport and terminal controller recovery.

No action on import. No STOP, configuration write, cloud request or hot-batch
replay exists. New lifetimes use fresh Source47 initializers and local clocks.
"""

# LAB-only execution on dedicated disposable host.
import argparse
import ast
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time
import types

ROOT = Path('/opt/dakasa/capacity-network')
HERE = ROOT / 'network-boot-recovery-Core263-pair-successor-v1'
SELF = HERE / 'network_guardian.py'
CONFIG = Path('/etc/dakasa/capacity-network/network-recovery.Core263.pair-successor.production.json')
LEDGER = Path('/var/lib/dakasa-capacity-network-recovery')
RUN = Path('/run/dakasa-capacity-network')
UNIT = 'dakasa-capacity-network.service'
HUB = 'dakasa-capacity-network-hub.service'
COLD = 'dakasa-capacity-network-cold-transport.service'
GUARDIAN = 'dakasa-capacity-network-guardian.service'
RUNTIME = ROOT / 'source-r42-cold-unknown184014-v1'
NEW_CONFIG = Path('/etc/dakasa/capacity-network/controller.r42-cold-unknown184014.production.json')
HUB_SOURCE = ROOT / 'network-boot-recovery-r42-source-v1/hub_boot_once.py'
HUB_CONFIG = Path('/etc/dakasa/capacity-network/hub-boot.r42.production.json')
BASE_PATH = ROOT / 'mss1240-transport-source-v1/mss_transport.py'
BASE_SHA = 'e7597e7c07eb39ccef8e57647dc7fd5db17a636d5136c8bd4fd1c258e76edd1d'
HUB_SHA = '778c23c9619dbdb53e8664aef9efce979cc4d507c5fc9ae6ff5fb5d0b3904cd9'
COVERAGE_SHA = '77e0f3c2f12cd632044ed4520c020909868326395ed9bc685d53ec1126009ab7'
JOURNAL_SHA = 'd2615b51416aa44ddfeb41faae384fc4cfdfd6d86a3c8cc2518b981ad626ba06'
INITIAL_BOOT = '9930f6b8-f1e4-4542-a81b-9000e0efa4ed'
PROOF_CACHE_SHA = '9c9f95e0fb295b010dfd594bc6249fe3d62a14677cf9a3875f2fa18daf9e1745'
REVIEWED_CANDIDATE_QUALIFIER_REF = None  # Pin only after final CI and image evidence.
REVIEWED_HANDOFF_QUALIFIER_REF = None  # Pin only after current-controller contract review.
TAKEOVER_SOURCE_SHA = 'fc0fc99d7a64a9defd7412a540cb11b596fd499b960e67f08e0c89c88e971f64'
PAIR_AUTHORITY_SHA = '968585e9a101f4b13645a57bbf48abdb2a27f980afb7da0b8d9474a317e7452f'
CURRENT_TAIL_SHA = 'c7b40b8fe555666bb920e00a210fb94ef8909f4d33a3e705e661dd1a2ec242f7'
CURRENT_READER_SHA = '0ee8f3a22e261d45ed421cb835b457092edc086bcbd920f7a6b160060452875e'
INITIAL_COLD_SHA = '1cb3555b1e066efd22955cecb6994457d98f75bc8cbbcb0d4fbd8a0dc27dd287'
RUNTIME_HASHES = {'brain_https.py': '061fc069ca5e4b9fb0a018a576513f24505d892b3382e184bc50bfd30df5f745', 'controller.py': '73ae9aba272903adfbcad4718f9e8a7113098152f47c404e77a5f412c9f0abcb', 'dns_native.py': '6883e6996a3fae04842450b18d3eb1f070e05d33afde694a3678285550b653fb', 'eks_https.py': 'e25ed2a1ca7ce8236ebe9e18e5fa0c8298046c682b71fbd6b71e7224d103f57b', 'install_owned_once.py': 'afd234db5ca0e0a4f37fae31d8456cc3541be865595ea60fb83f823a5bb4b5e3', 'kube_native.py': '55eff9dbb5106b18c3ec7f2b204ab38382bc43a9fb25b0c7a8e135f87fd5a7e7', 'native_io.py': '5e61ea686a2b3647528fe34ea5b11240390c8b192164959bc0c3087620174244', 'native_structure.py': '1ef7d08271cc4520a423d8c3cd7e7a4a87ce85206074553c9abf11dbd13ecbee', 'nft_owner.py': '4c22928d953459812b7e6f51b6564398fc0f50fa8adebf63a587e2cd01d08526', 'observations.py': 'bc59af9e9bb60f7ace06021c4cb866b201d3bde1a757ba4587234736de138d33', 'original_process.py': '3dd813c9a74a62779b0db9fdc54179a1daab3fb9aa106dfeed4a886abf7e3e87', 'transition_adoption.py': 'dc4ea8f2981ff0a04e48f16e36ad0a5dde15a4d6aaf1ee0e17d7462afa87894a', 'whole_witness.py': '1df133f092a0018c67c3716d58482bdc4e6657b2ac5aa8a33d77fcbbbcb75973'}
CORE_CONTEXT_SHA = '5f4d0f3a23485a0f1c09d275e811c89b14ccde220b89758efa45ba84e8fb34af'
STAGE_HELPERS = (('R42', 'R42_stage_reconstruction.py', '36e3fc994ab45717ceebc498d14edb05e5f23ea372480e73125e0fb7529577b6'), ('R41', 'R41_stage_reconstruction.py', '5869ce56507326acaa4993d2b4f632437e73551618554499e71892d8c0a5479e'), ('R40', 'R40_stage_reconstruction.py', '03fba3e2e226e24e1efc74604c6dfa74b786b8ed38f273c7d77fe13c09b7661e'), ('R39', 'R39_success_stage_reconstruction.py', '593c3ea3bf881bce0082efce079af5c0b78695d3227f95cbfbc29c59ab9ada94'), ('R38', 'R38_success_stage_reconstruction.py', 'e984f33248574665163a29d8b9f39eb5ea6146762e7230c95209b3e328250c40'))

MACHINE_SHA = '87f663031776097c12feb5358b3a39186657bec73ae5ee71c87b786dca9dbc01'
WG_CONFIG_SHA = '4fe9d22e15e663a6171b119993547252fa8887e1ea141c9a705cce4f732c594a'
PROPS = 'LoadState,MainPID,ExecMainPID,ActiveState,SubState,NRestarts,InvocationID,ExecMainStartTimestampMonotonic,ControlGroup,Result,ExecMainCode,ExecMainStatus,FragmentPath,Restart,DropInPaths'
FIELDS = {'schema', 'guardian_source_sha256', 'controller_unit_sha256', 'hub_unit_sha256',
          'cold_unit_sha256', 'guardian_unit_sha256', 'new_controller_config_sha256',
          'hub_boot_config_sha256', 'Root_review', 'R43_proofs', 'Core262_context_ref', 'proof_index_ref', 'context_sources', 'pair_successor_ref', 'unit_dropin_run_id', 'cold_dropin_sha256', 'guardian_dropin_sha256'}


def require(ok, guard):
    if not ok:
        raise RuntimeError(guard)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def wire(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


def loads(raw):
    def unique(rows):
        result = {}
        for key, value in rows:
            require(key not in result, 'NO_DUPLICATE_ROOT_JSON')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique,
                      parse_constant=lambda _: require(False, 'NO_NONFINITE_ROOT_JSON'))


def read(path, cap=131072, mode=None):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        a = os.fstat(fd)
        require(stat.S_ISREG(a.st_mode) and a.st_uid == 0 and not stat.S_IMODE(a.st_mode) & 0o022,
                'ROOT_OWNED_OPERAND')
        require(mode is None or stat.S_IMODE(a.st_mode) == mode, 'EXACT_ROOT_MODE')
        data, size = [], 0
        while True:
            chunk = os.read(fd, min(65536, cap + 1 - size))
            if not chunk:
                break
            data.append(chunk)
            size += len(chunk)
            require(size <= cap, 'BOUNDED_FULL_FILE')
        b = os.fstat(fd)
        require((a.st_dev, a.st_ino, a.st_size, a.st_mtime_ns, a.st_ctime_ns)
                == (b.st_dev, b.st_ino, b.st_size, b.st_mtime_ns, b.st_ctime_ns), 'STABLE_FULL_EOF')
        return b''.join(data)
    finally:
        os.close(fd)


def directory(path):
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not path.is_symlink()
            and stat.S_IMODE(info.st_mode) == 0o700, 'ROOT_PRIVATE_DIRECTORY')


def once(path, raw):
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def module(path, expected, original_source_path=None):
    raw = read(path)
    require(sha(raw) == expected, 'EXACT_REVIEWED_SOURCE')
    value = types.ModuleType('boot_recovery_' + path.stem)
    value.__file__ = str(path) if original_source_path is None else str(original_source_path)
    exec(compile(raw, value.__file__, 'exec'), value.__dict__)
    return value


def future_controller_config(actual_raw, actual_anchor):
    """No second controller/config transition: preserve the ACTUAL R42 bytes."""
    require(sha(actual_raw) == actual_anchor['controller_config_sha256'], 'EXACT_ACTUAL_R42_CONFIG')
    value=loads(actual_raw)
    require(value['source_files_sha256']==RUNTIME_HASHES and value['core_container_images']==actual_anchor['approved_core_pairs'], 'SAME_R42_THIRTEEN_SOURCES_AND_EXACT_IMAGE_PAIR')
    return actual_raw


def future_hub_config(old_raw, runtime_roster, root_review):
    """Pure successor of Root's original stable key/route Hub seal."""
    value = loads(old_raw)
    require(value['schema'] == 'root_fixed_original_hub_boot_owner_v1'
            and value['execute'] is True and value['source_sha256'] == '61acf63a013637c41af8814028c5fb90550f5baa9ea482efe014a9e6fd504fba'
            and value['host_machine_id_sha256'] == MACHINE_SHA
            and value['hub_wg_config_sha256'] == WG_CONFIG_SHA
            and value['initial_boot_id'] == INITIAL_BOOT and value['initial_ifindex'] == 2825,
            'ORIGINAL_ROOT_STABLE_HUB_INSTALLATION')
    del value['r5_source_files_sha256']
    value.update(schema='lab_first_hub_boot_seal_v1',
                 source_sha256=HUB_SHA, runtime_source_files_sha256=runtime_roster,
                 root_review_attestation=root_review)
    require(type(root_review) is str and 120 <= len(root_review) <= 4096, 'EXPLICIT_ROOT_HUB_REVIEW')
    return wire(value)


def exact_ref(value):
    require(type(value)is dict and set(value)=={'path','sha256'}and type(value['path'])is str and value['path'].startswith('/')and re.fullmatch('[a-f0-9]{64}',str(value['sha256'])),'EXACT_PUBLIC_ORIGINAL_OR_COPY_REF')

def standing_config(*, pins, unit_dropin_run_id):
    # Source-only LAB constructor. Inputs still need live provenance checks.
    names={'guardian_source_sha256','controller_unit_sha256','hub_unit_sha256','cold_unit_sha256','guardian_unit_sha256','new_controller_config_sha256','hub_boot_config_sha256','cold_dropin_sha256','guardian_dropin_sha256'}
    require(type(pins)is dict and set(pins)==names,'EXACT_LAB_GUARDIAN_PINS_REQUIRED')
    value={**pins,'schema':'disposable_lab_guardian_config_v1','lab_only':True,'production_authority':False,'unit_dropin_run_id':unit_dropin_run_id}
    validate(value)
    return value

def validate(value):
    # LAB-only local seal: no R43/handoff claims or production authority.
    pins={'guardian_source_sha256','controller_unit_sha256','hub_unit_sha256','cold_unit_sha256','guardian_unit_sha256','new_controller_config_sha256','hub_boot_config_sha256','cold_dropin_sha256','guardian_dropin_sha256'}
    require(type(value)is dict and set(value)==pins|{'schema','lab_only','production_authority','unit_dropin_run_id'} and value['schema']=='disposable_lab_guardian_config_v1' and value['lab_only'] is True and value['production_authority'] is False and all(type(value[k])is str and re.fullmatch('[a-f0-9]{64}',value[k]) for k in pins) and type(value['unit_dropin_run_id'])is str and re.fullmatch('[a-f0-9]{20}',value['unit_dropin_run_id']),'CLOSED_LAB_GUARDIAN_CONFIG_NO_HISTORY')


def prior_boot_start_callers_quiescent(records, boot_id, unit, source_sha, config_sha):
    """Pure same-Boot/unit prior-CLI closure gate; status zero is not required."""
    require(type(records) is list and unit in (COLD, HUB, UNIT), 'EXACT_BOOT_PRIOR_CALLER_SCOPE')
    matched = 0
    for record in records:
        possible = record['possible_start']
        if possible.get('boot_id') != boot_id or possible.get('unit') != unit:
            continue
        matched += 1
        caller = record['original_caller']
        require(possible['schema'] == 'Root_boot_pre_effect_one_original_unit_START_possible_v1'
                and possible['source_sha256'] == source_sha
                and possible['standing_config_sha256'] == config_sha,
                'SAME_BOOT_UNIT_SOURCE_AND_CONFIG_PRIOR_START')
        require(type(caller) is dict
                and caller['schema'] == 'Root_boot_original_unit_START_caller_v1'
                and caller['boot_id'] == boot_id and caller['source_sha256'] == source_sha
                and caller['possible_START_ref'] == record['possible_start_ref'],
                'DURABLE_PRIOR_ORIGINAL_BOOT_START_CALLER_JOIN')
        original = caller['original_native_call']
        facts = original['original_transport']
        require(original['argv'] == ['/usr/bin/systemctl', 'start', unit]
                and facts.get('local_child_joined') is True
                and facts.get('all_local_FDs_closed') is True,
                'ALL_PRIOR_SAME_UNIT_START_CLIENTS_JOINED_AND_FDS_CLOSED')
    require(matched < 3, 'AT_MOST_THREE_DISTINCT_PRE_EFFECT_BOOT_ATTEMPTS_PER_UNIT')
    return matched


class Owner:
    def __init__(self, source_sha):
        self.invocation_started = time.monotonic()
        self.current_read_capture = None
        require(os.geteuid() == 0 and Path(__file__) == SELF and sha(read(SELF)) == source_sha,
                'EXACT_ROOT_INSTALLED_GUARDIAN_SOURCE')
        self.sha = source_sha
        self.raw_config = read(CONFIG, 32768, 0o600)
        self.config = loads(self.raw_config)
        validate(self.config)
        require(self.config['guardian_source_sha256'] == source_sha, 'STANDING_SAME_SOURCE')
        self.B = module(BASE_PATH, BASE_SHA)
        self.C = module(ROOT / 'r33-compat-bridge-r2/bridge_contract.py', self.B.BRIDGE_SHA)
        self.n = module(ROOT / 'r33-compat-bridge-r2/frozen_native.py', self.B.NATIVE_SHA)
        self.coverage = module(HERE / 'coverage.py', COVERAGE_SHA)
        self.journal_contract = module(HERE / 'journal_contract.py', JOURNAL_SHA)
        self.hub = module(HUB_SOURCE, HUB_SHA)
        self.boot = self.C.instance()
        require(re.fullmatch('[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}', self.boot), 'ACTUAL_BOOT')
        directory(LEDGER)
        self.calls = []
        self.insert_remaining = set()
        self.start_admitted = False
        self.journal_identity = None
        self.recovering_identity = None
        self.anchor = self.actual_R42_anchor()
        self.initial_identity = self.anchor['identity']
        self.deadline = time.monotonic() + 60
        self.static()

    def actual_R42_anchor(self):
        # Historical Source mathematics runs once. Every consumed original and
        # source file is re-read/hash checked before any cached typed use.
        helper=module(HERE/'proof_cache.py',PROOF_CACHE_SHA)
        g=types.SimpleNamespace(require=require,read=read,loads=loads,sha=sha,wire=wire,exact_ref=exact_ref,HERE=HERE,pair_authority=module(HERE/'guardian_pair_authority.py',PAIR_AUTHORITY_SHA),pair_authority_sha=PAIR_AUTHORITY_SHA,reviewed_candidate_qualifier_ref=REVIEWED_CANDIDATE_QUALIFIER_REF,reviewed_handoff_qualifier_ref=REVIEWED_HANDOFF_QUALIFIER_REF)
        return helper.qualify(self,g)

    def effective_successor_units(self):
        # These bracketed reads establish observed consistency only; they do
        # not claim another root actor could not change and restore state.
        helper=module(HERE/'takeover_units_DRAFT.py',TAKEOVER_SOURCE_SHA)
        run=self.config['unit_dropin_run_id']
        for kind,unit,key in (('cold',COLD,'cold_dropin_sha256'),('guardian',GUARDIAN,'guardian_dropin_sha256')):
            path=Path('/etc/systemd/system')/(unit+'.d')/('90-dakasa-pair-'+run+'.conf')
            expected=helper.make_dropin(kind,str(SELF),self.sha)
            require(sha(expected)==self.config[key],'EXACT_REVIEWED_SUCCESSOR_DROPIN_HASH')
            first=read(path,32768,0o644)
            argv=['/usr/bin/systemctl','show',unit,'--property=LoadState,FragmentPath,DropInPaths,ExecStart']
            before=self.call('effective-'+kind+'-first',argv,cap=65536,seconds=6)
            after=self.call('effective-'+kind+'-second',argv,cap=65536,seconds=6)
            last=read(path,32768,0o644)
            require(first==last==expected and before==after,'SAME_EXACT_DROPIN_AND_EFFECTIVE_UNIT_DURING_BRACKET')
            helper.validate_effective_unit(kind,run,expected,before)

    def static(self):
        require(read(CONFIG, 32768, 0o600) == self.raw_config, 'UNCHANGED_STANDING_ROOT_AUTHORITY')
        self.effective_successor_units()
        for unit, key in ((UNIT, 'controller_unit_sha256'), (HUB, 'hub_unit_sha256'),
                          (COLD, 'cold_unit_sha256'), (GUARDIAN, 'guardian_unit_sha256')):
            require(sha(read('/etc/systemd/system/' + unit, 32768)) == self.config[key],
                    'EXACT_REVIEWED_FUTURE_SERVICE_UNITS')
        require(sha(read('/etc/systemd/system.control/' + UNIT + '.d/50-CPUQuota.conf', 4096)) == self.C.DROPIN_SHA,
                'UNCHANGED_CPU100_DROPIN')
        roster = dict(RUNTIME_HASHES)
        require({p.name for p in RUNTIME.iterdir()}==set(roster)and all(sha(read(RUNTIME/name))==pin for name,pin in roster.items()),'EXACT_ACTUAL_R42_THIRTEEN_RUNTIME_SOURCES')
        actual=self.actual_R42_anchor()
        require(actual==self.anchor,'SAME_IMMUTABLE_R42_ORIGINAL_ANCHOR')
        expected=self._qualified_historical_cache['successor_controller_raw']
        require(read(NEW_CONFIG,32768,0o600)==expected and sha(expected)==self.config['new_controller_config_sha256'],
                'EXACT_QUALIFIED_SUCCESSOR_PAIR_CONTROLLER_CONFIG')
        hubraw = read(HUB_CONFIG, 32768, 0o600)
        require(sha(hubraw) == self.config['hub_boot_config_sha256'], 'EXACT_FUTURE_HUB_SEAL')
        seal = loads(hubraw)
        require(seal['schema'] == 'lab_first_hub_boot_seal_v1'
                and seal['execute'] is True and seal['source_sha256'] == HUB_SHA
                and seal['runtime_source_files_sha256'] == roster
                and seal['host_machine_id_sha256'] == MACHINE_SHA
                and seal['hub_wg_config_sha256'] == WG_CONFIG_SHA
                and sha(read('/etc/machine-id', 4096)) == MACHINE_SHA,
                'STABLE_SAME_HUB_MACHINE_KEY_CONFIG_AND_SOURCE47')
        self.hub.validate_public_peers(seal['peer_public_keys'], seal['hub_public_key'])
        require(sha(read(self.hub.CONF, 65536, 0o600)) == WG_CONFIG_SHA, 'UNCHANGED_PRIVATE_WG_CONFIGURATION')
        for path in ('/usr/sbin/iptables', '/usr/sbin/iptables-save'):
            executable = self.C.executable(path)
            require(executable['sha256'] == self.C.FRONTEND_SHA
                    and executable['resolved_path'] == '/usr/sbin/xtables-nft-multi', 'SAME_EXISTING_NFT_FRONTEND')
        return seal

    def call(self, role, argv, codes=(0,), cap=8 << 20, seconds=6):
        mss_checks = [['/usr/sbin/iptables', '-w', '2', '-t', 'mangle', '-C', 'POSTROUTING', *v]
                      for v in self.B.rules().values()]
        bridge_checks = [['/usr/sbin/iptables', '-w', '2', '-C', 'FORWARD', *v]
                         for v in self.C.functional_rules(self.B.BRIDGE_OPERATION).values()]
        pure = argv in mss_checks + bridge_checks or argv in (
            ['/usr/sbin/iptables-save', '-c', '-t', 'mangle'], ['/usr/sbin/iptables-save', '-c', '-t', 'filter'],
            ['/usr/sbin/nft', '-a', '-j', 'list', 'ruleset'],
            ['/usr/sbin/nft', '-a', 'list', 'table', 'inet', 'dakasa_capacity_network'],
            ['/usr/sbin/ip', '-d', '-j', 'link', 'show', 'dev', 'wg-capacity'],
            ['/usr/sbin/ip', '-j', '-4', 'address', 'show', 'dev', 'wg-capacity'],
            ['/usr/sbin/ip', '-j', '-4', 'route', 'show', 'table', 'all']) or (
                len(argv) == 4 and argv[:2] == ['/usr/bin/systemctl', 'show']
                and argv[2] in (UNIT, HUB, COLD, GUARDIAN) and argv[3].startswith('--property=')) or (
                len(argv) == 4 and argv[:3] == [str(self.hub.WG_BINARY), 'show', 'wg-capacity']
                and argv[3] in ('allowed-ips', 'public-key', 'listen-port'))
        journal = False
        if self.journal_identity is not None:
            base = self.journal_argv(self.journal_identity)
            journal = argv == base or (argv[:len(base)] == base and len(argv) == len(base) + 1
                and (argv[-1].startswith('--after-cursor=') or argv[-1] in ('--lines=1', '--lines=512')))
        insert = tuple(argv) in self.insert_remaining
        start = self.start_admitted in (UNIT, HUB, COLD) and argv == ['/usr/bin/systemctl', 'start', self.start_admitted]
        require(pure or journal or insert or start, 'ONLY_READS_EXACT_EIGHT_COLD_INSERTS_OR_ONE_TERMINAL_START')
        if insert:
            self.insert_remaining.remove(tuple(argv))  # consumed before actual send
        if start:
            self.start_admitted = False
        raw, facts = self.n.native(argv, deadline=min(self.deadline - 1, time.monotonic() + seconds),
                                   env=self.B.SAFE, cap=cap, diagnostic_path=None)
        self.calls.append({'role': role, 'argv': argv, 'original_transport': facts,
                           'stdout_sha256': sha(raw), 'stdout_bytes': len(raw)})
        require(type(facts['exit_code']) is int and facts['exit_code'] in codes
                and facts['wait_zero'] is (facts['exit_code'] == 0)
                and facts['captured_output_truncated'] is False
                and all(facts[k] for k in ('native_started', 'stdout_EOF', 'stderr_EOF',
                                           'all_local_FDs_closed', 'local_child_joined')),
                'SAME_ORIGINAL_NATIVE_EXPECTED_STATUS_EOF_CLOSE_JOIN')
        if self.current_read_capture is not None:
            require(len(self.current_read_capture)<128 and sum(row['bytes']for row in self.current_read_capture)+len(raw)<=32<<20,'BOUNDED_COMPLETE_ORIGINAL_CURRENT_READ_CAPTURE')
            self.current_read_capture.append({'role':role,'argv':list(argv),'original_call_index':len(self.calls)-1,'sha256':sha(raw),'bytes':len(raw),'body':raw})
        return raw

    def properties(self, unit=UNIT):
        raw = self.call('identity-' + unit, ['/usr/bin/systemctl', 'show', unit, '--property=' + PROPS])
        pairs = [row.split('=', 1) for row in raw.decode('ascii').splitlines()]
        require(all(len(row) == 2 for row in pairs) and len(pairs) == len(PROPS.split(',')), 'FULL_UNIT_PROPERTIES')
        value = dict(pairs)
        require(set(value) == set(PROPS.split(',')) and value['LoadState'] == 'loaded'
                and value['FragmentPath'] == '/etc/systemd/system/' + unit and value['NRestarts'] == '0'
                and value['Restart'] == 'no', 'EXACT_LOADED_NO_IMPLICIT_RESTART_UNIT')
        expected_dropin = ('/etc/systemd/system.control/' + UNIT + '.d/50-CPUQuota.conf' if unit == UNIT else '/etc/systemd/system/' + unit + '.d/90-dakasa-pair-' + self.config['unit_dropin_run_id'] + '.conf' if unit in (COLD, GUARDIAN) else '')
        require(value['DropInPaths'] == expected_dropin, 'ONLY_UNCHANGED_CONTROLLER_CPU_DROPIN')
        return value

    def identity(self):
        props = self.properties()
        require(props['ActiveState'] == 'active' and props['SubState'] == 'running'
                and props['Result'] == 'success' and props['ExecMainStatus'] == '0'
                and props['ControlGroup'] == '/system.slice/' + UNIT
                and props['MainPID'].isdigit() and int(props['MainPID']) > 1
                and re.fullmatch('[a-f0-9]{32}', props['InvocationID']), 'ACTUAL_CONTROLLER_RUNNING_R0')
        pid = int(props['MainPID'])
        proc = read('/proc/' + str(pid) + '/stat', 4096)
        ticks = proc[proc.rfind(b')') + 1:].split()[19]
        require(ticks.isdigit(), 'ACTUAL_PROCESS_START_TICKS')
        command = read('/proc/' + str(pid) + '/cmdline', 4096)
        initial=False  # LAB starts without any admitted historical lifetime.
        future=b'\0'.join(x.encode()for x in ['/usr/bin/python3','-B',str(RUNTIME/'controller.py'),'--config',str(NEW_CONFIG),'--run'])+b'\0'
        require(command==future,'EXACT_ACTUAL_R42_RUNTIME_COMMAND_FOR_INITIAL_OR_FRESH_LIFETIME')
        require(os.sched_getscheduler(pid) == os.SCHED_OTHER and os.sched_getparam(pid).sched_priority == 0,
                'NORMAL_SCHEDULER_NO_RT')
        require(read('/proc/' + str(pid) + '/stat', 4096)[proc.rfind(b')') + 1:].split()[19] == ticks,
                'SAME_UNREUSED_CONTROLLER_PID')
        return {'boot_id': self.boot, 'pid': pid, 'start_ticks': int(ticks),
                'InvocationID': props['InvocationID'],
                'ExecMainStartTimestampMonotonic': props['ExecMainStartTimestampMonotonic'],
                'cmdline_sha256': sha(command), 'initial_R42_admitted_lifetime': initial}

    def key(self, identity):
        return sha(wire(identity))

    def wg(self):
        return self.wg_snapshot(self.static())

    def wg_snapshot(self, seal):
        require(sha(read(self.hub.WG_BINARY, 8 << 20)) == self.hub.WG_SHA, 'SAME_ORIGINAL_WG_BINARY')
        values = loads(self.call('public-WG-link', ['/usr/sbin/ip', '-d', '-j', 'link', 'show', 'dev', 'wg-capacity']))
        require(len(values) == 1, 'ONE_ACTUAL_WG_INTERFACE')
        link = values[0]
        require(type(link['ifindex']) is int and link.get('ifalias') == self.hub.ALIAS
                and link['mtu'] == 1280 and 'UP' in link['flags']
                and link.get('linkinfo', {}).get('info_kind') == 'wireguard', 'EXACT_NATIVE_HUB_INTERFACE')
        addresses = loads(self.call('public-WG-addresses', ['/usr/sbin/ip', '-j', '-4', 'address', 'show', 'dev', 'wg-capacity']))
        require(len(addresses) == 1 and addresses[0]['ifindex'] == link['ifindex']
                and len(addresses[0]['addr_info']) == 3
                and {v['local'] for v in addresses[0]['addr_info']} == set(self.hub.VIPS)
                and all(v['family'] == 'inet' and v['prefixlen'] == 32 and v['scope'] == 'global'
                        for v in addresses[0]['addr_info']), 'EXACT_THREE_FIXED_VIPS')
        allowed = self.call('public-WG-peer-bindings', [str(self.hub.WG_BINARY), 'show', 'wg-capacity', 'allowed-ips']).decode().splitlines()
        require(len(allowed) == 16 and {v.split()[1].removesuffix('/32'): v.split()[0] for v in allowed}
                == seal['peer_public_keys'], 'EXACT_SIXTEEN_STANDING_PUBLIC_PEERS')
        require(self.call('public-WG-key', [str(self.hub.WG_BINARY), 'show', 'wg-capacity', 'public-key']).decode().strip()
                == seal['hub_public_key']
                and self.call('public-WG-listen', [str(self.hub.WG_BINARY), 'show', 'wg-capacity', 'listen-port']).strip()
                == b'51820', 'SAME_ORIGINAL_HUB_PUBLIC_IDENTITY')
        self.hub.route_shape(loads(self.call('full-routes-RAM', ['/usr/sbin/ip', '-j', '-4', 'route', 'show', 'table', 'all'])), True)
        return {'ifindex': link['ifindex'], 'hub_public_key': seal['hub_public_key'],
                'peer_public_keys': seal['peer_public_keys'], 'mtu': 1280, 'VIP_count': 3, 'route_count': 16}

    def kernel(self, measurement=None, allow_absent=False, *, guarded=None):
        if guarded is not None:
            require(measurement is None and not allow_absent, 'GUARDED_OBSERVATION_IS_NOT_LEGACY_MEASUREMENT')
            return self.kernel_guarded(guarded)
        raw = self.call('full-native-ruleset', ['/usr/sbin/nft', '-a', '-j', 'list', 'ruleset'])
        owned, all_rows = self.C._objects(raw)
        if owned:
            require(sha(self.C._structure(owned, keep_handles=False)) == self.C.AST47, 'ACTUAL_SOURCE_COMPILED47')
        else:
            require(allow_absent and measurement is None, 'ACTUAL_SOURCE47_REQUIRED')
        source = read(RUNTIME / 'nft_owner.py')
        require(sha(source) == RUNTIME_HASHES['nft_owner.py'], 'UNCHANGED_RUNTIME_MARK_PREFLIGHT_SOURCE')
        node = next(x for x in ast.parse(source).body if isinstance(x, ast.FunctionDef) and x.name == 'ruleset_mark_preflight')
        namespace = {'TABLE': 'dakasa_capacity_network', 'require': require, 'json': json}
        exec(compile(ast.Module(body=[node], type_ignores=[]), 'actual_runtime_mark_guard', 'exec'), namespace)
        namespace['ruleset_mark_preflight'](all_rows)
        if allow_absent:
            return {'owned47_handle_structure_sha256': None if not owned else sha(self.C._structure(owned, keep_handles=True)),
                    'unchanged_runtime_global_mark_preflight': True}
        handles, ordinals = {}, {}
        for row in owned:
            kind = next(iter(row))
            item = row[kind]
            if kind == 'rule':
                ordinal = ordinals.get(item['chain'], 0)
                ordinals[item['chain']] = ordinal + 1
                key = (kind, item['chain'], str(ordinal))
            else:
                key = (kind, item['name'])
            require(key not in handles, 'ONE_CURRENT_NATIVE_OBJECT')
            handles[key] = item['handle']
        if measurement is not None:
            require(measurement['compiled_native_ast_sha256'] == self.C.AST47
                    and [{'key': list(k), 'handle': v} for k, v in sorted(handles.items())]
                    == measurement['initial_original_structure_handles'], 'SAME_HONEST_ORIGINAL_INITIALIZER47_HANDLES_BY_EXPLICIT_KIND')
            kind=measurement['initial_structure_proof_kind']
            require((kind=='original_native_apply_echo'and measurement['initial_original_echo_handles']==measurement['initial_original_structure_handles']and measurement['initial_original_read_handles']is None)or(kind=='original_owned_read_adoption'and measurement['initial_original_echo_handles']is None and measurement['initial_original_read_handles']==measurement['initial_original_structure_handles']),'NO_READ_ADOPTION_ECHO_ALIAS')
        text = self.call('native-dynamic-expiries', ['/usr/sbin/nft', '-a', 'list', 'table', 'inet', 'dakasa_capacity_network'])
        observed = time.monotonic()
        return self.coverage.kernel_text(text), observed

    def kernel_guarded(self, context):
        """CI/LAB 50-object observation, not wired into watch or effect leases.

        The verified receipt retains original ACK/FD provenance; its generation
        must stay stable across all full-structure, mark, tuple and source reads.
        A genid change remains HOLD and never rewrites the historical receipt.
        """
        import base64, socket
        require(type(context) is dict and set(context)=={'verified','verifier','sources','nl','transition','live','probe','probe_sha256'},
                'EXACT_GUARDED_KERNEL_CONTEXT')
        verified=context['verified'];verifier=context['verifier'];nl=context['nl'];transition=context['transition']
        require(type(verified) is verifier._VerifiedGeneration and verified.capability is verifier._VERIFIED_CAPABILITY
                and verified.guardian_pid==os.getpid() and verified.sender_pidfd is not None
                and verified.anchor['netns']==os.readlink('/proc/self/ns/net'),
                'SAME_LIVE_GUARDIAN_VERIFIED_GUARDED_GENERATION')
        pin=transition.OriginalPin(base64.b64decode(verified.anchor['initial'],validate=True))
        source=read(RUNTIME/'nft_owner.py')
        require(sha(source)==RUNTIME_HASHES['nft_owner.py'],'UNCHANGED_RUNTIME_MARK_PREFLIGHT_SOURCE')
        node=next(x for x in ast.parse(source).body if isinstance(x,ast.FunctionDef) and x.name=='ruleset_mark_preflight')
        namespace={'TABLE':'dakasa_capacity_network','require':require,'json':json}
        exec(compile(ast.Module(body=[node],type_ignores=[]),'actual_runtime_mark_guard','exec'),namespace)
        net=socket.socket(socket.AF_NETLINK,socket.SOCK_RAW,12);net.bind((0,0));net.settimeout(5)
        try:
            first=nl.genid(net)
            require(first==verified.result['after'],'GUARDED_RECEIPT_GENERATION_CHANGED')
            def full_shape():
                raw=self.call('full-native-ruleset-guarded',['/usr/sbin/nft','-a','-j','list','ruleset'])
                _owned,all_rows=self.C._objects(raw)
                transition.verify_guarded(pin,raw,observed_chain_handle=verified.result['chain'],
                                           observed_rule_handles=tuple(verified.result['handles']))
                namespace['ruleset_mark_preflight'](all_rows)
            full_shape()
            envelope=context['live'].observe(verified,verifier=verifier,sources=context['sources'],nl=nl,
                        coverage=self.coverage,probe_path=context['probe'],probe_sha256=context['probe_sha256'])
            kernel=self.coverage.kernel_text(self.call('native-dynamic-expiries-guarded',
                                ['/usr/sbin/nft','-a','list','table','inet','dakasa_capacity_network']))
            full_shape()
            require(nl.genid(net)==first==envelope['observation']['genid'],
                    'SAME_GUARDED_GENERATION_AROUND_FULL_OWNER_KERNEL')
            require(envelope.get('grant_authority') is False and envelope.get('cross_process_effect_lease') is False,
                    'NO_GUARDED_EFFECT_AUTHORITY_FROM_KERNEL_OBSERVATION')
            return {'scope':'guarded50_non_authorizing_ci_lab','kernel':kernel,'live':envelope},time.monotonic()
        finally:net.close()

    def transport(self):
        raw = self.call('full-filter', ['/usr/sbin/iptables-save', '-c', '-t', 'filter'])
        rules = self.C.functional_rules(self.B.BRIDGE_OPERATION)
        rows = self.C.bridge_lines(raw, rules)
        require(len(rows) == 4, 'FOUR_EXISTING_FUNCTIONAL_BRIDGE_RULES')
        for role, rule in rules.items():
            self.call('bridge-present-' + role, ['/usr/sbin/iptables', '-w', '2', '-C', 'FORWARD', *rule])
        mang = self.B.mangle(self.call('full-mangle', ['/usr/sbin/iptables-save', '-c', '-t', 'mangle']))
        require(len(mang['owned_rules']) == 4, 'FOUR_EXISTING_FUNCTIONAL_MSS_RULES')
        for role, rule in self.B.rules().items():
            self.call('mss-present-' + role, ['/usr/sbin/iptables', '-w', '2', '-t', 'mangle', '-C', 'POSTROUTING', *rule])
        return {'bridge_operation': self.B.BRIDGE_OPERATION, 'MSS_operation': self.B.OPERATION,
                'full_filter_without_only_counters_sha256': self.C.full_filter(raw)['complete_structure_without_only_counters_sha256'],
                'other_mangle_structure_sha256': mang['other_structure_sha256'],
                'four_bridge_and_four_MSS_original_checks_zero': True}

    def cold_guard(self):
        require(self.boot == INITIAL_BOOT, 'COLD_RESTORE_ONLY_LATER_BOOT')
        require(not Path('/sys/class/net/wg-capacity').exists(), 'COLD_RESTORE_BEFORE_ANY_WG_INTERFACE')
        own = self.properties(COLD)
        require(own['MainPID'] == own['ExecMainPID'] == str(os.getpid())
                and own['ActiveState'] == 'activating' and own['SubState'] == 'start'
                and own['InvocationID'] == os.environ.get('INVOCATION_ID')
                and own['ControlGroup'] == '/system.slice/' + COLD
                and read('/proc/self/cgroup', 4096) == ('0::/system.slice/' + COLD + '\n').encode(),
                'OWN_COLD_ONESHOT_NATIVE_IDENTITY')
        for unit in (UNIT, HUB):
            props = self.properties(unit)
            require(props['MainPID'] == props['ExecMainPID'] == props['ExecMainStartTimestampMonotonic'] == '0'
                    and props['ActiveState'] == 'inactive' and props['SubState'] == 'dead'
                    and props['InvocationID'] == '', 'BOTH_SERVICES_NEVER_STARTED_THIS_BOOT')
            path = Path('/sys/fs/cgroup/system.slice') / unit / 'cgroup.procs'
            require(not path.exists() or read(path, 4096).strip() == b'', 'NO_SERVICE_CHILD_OR_OLD_LIFETIME')
            raw = self.call('cold-required-order-' + unit, ['/usr/bin/systemctl', 'show', unit, '--property=Requires,After'])
            values = dict(row.split('=', 1) for row in raw.decode().splitlines())
            require(COLD in values['Requires'].split() and COLD in values['After'].split(), 'EFFECTIVE_REQUIRED_ORDERED_COLD_DEPENDENCY')
        self.static()

    def current_original47(self,identity):
        # Handle identity is lifetime-specific. A reboot creates new kernel
        # objects; the historical R43 handles cannot be silently reused.
        require(self.original_qualification_exists(identity),'OWN_CURRENT_LIFETIME120_REQUIRED_FOR_CURRENT47')
        value=loads(read(LEDGER/(self.key(identity)+'-QUALIFIED.PUBLIC.json'),16<<20,0o600))
        require(value['identity']==identity and value['source_sha256']==self.sha and value['standing_config_sha256']==sha(self.raw_config),'SAME_OWN_CURRENT_LIFETIME_FOR_CURRENT47')
        return value['measurement']

    def current15_context(self):
        reader=module(HERE/'current15_bounded_reader.py',CURRENT_READER_SHA)
        tail=module(HERE/'current15_bounded_tail_contract.py',CURRENT_TAIL_SHA)
        return types.SimpleNamespace(require=require,loads=loads,sha=sha,wire=wire,read=read,once=once,LEDGER=LEDGER,INITIAL_BOOT=INITIAL_BOOT,COLD=COLD,HUB=HUB,reader=reader,tail=tail)

    def current15_readonly(self):
        g=self.current15_context()
        return g.reader.observe(self,g)

    def initial_boot_read_adoption(self):
        with self.maintenance():
            helper=module(HERE/'initial_boot_Cold_read_adoption.py',INITIAL_COLD_SHA)
            value,self.initial_cold_read_return_ref=helper.read_adopt(self,self.current15_context(),self.invocation_started)
            return value

    def cold_restore(self):
        require(self.boot == INITIAL_BOOT, 'SAME_ACTUAL_LAB_FIRST_COLD_BOOT')
        self.deadline = time.monotonic() + 60
        self.cold_guard()
        kernel_before = self.kernel(allow_absent=True)
        b = self.C.functional_rules(self.B.BRIDGE_OPERATION)
        m = self.B.rules()
        filter_before = self.call('cold-filter-before', ['/usr/sbin/iptables-save', '-c', '-t', 'filter'])
        require(b'Root-R33-WG-ens5-compat-' not in filter_before,'NO_HISTORICAL_FOREIGN_BRIDGE_MARKERS_ON_LAB')
        require(not self.C.bridge_lines(filter_before, b), 'NO_COLD_BRIDGE_PARTIAL_OR_FOREIGN_OWNERSHIP')
        filter_sha = self.C.full_filter(filter_before)['complete_structure_without_only_counters_sha256']
        mangle_raw=self.call('cold-mangle-before', ['/usr/sbin/iptables-save', '-c', '-t', 'mangle'])
        require(b'Root-WG-MSS1240-' not in mangle_raw,'NO_HISTORICAL_FOREIGN_MSS_MARKERS_ON_LAB')
        mang_before=self.B.mangle(mangle_raw)
        require(not mang_before['owned_rules'], 'NO_COLD_MSS_PARTIAL_OR_FOREIGN_OWNERSHIP')
        inserts = []
        for role, rule in b.items():
            self.call('cold-bridge-absent-' + role, ['/usr/sbin/iptables', '-w', '2', '-C', 'FORWARD', *rule], (1,))
        for role, rule in m.items():
            self.call('cold-mss-absent-' + role, ['/usr/sbin/iptables', '-w', '2', '-t', 'mangle', '-C', 'POSTROUTING', *rule], (1,))
        for role in reversed(list(b)):
            inserts.append(['/usr/sbin/iptables', '-w', '2', '-I', 'FORWARD', '1', *b[role]])
        for role in reversed(list(m)):
            inserts.append(['/usr/sbin/iptables', '-w', '2', '-t', 'mangle', '-I', 'POSTROUTING', '1', *m[role]])
        self.cold_guard()
        marker = LEDGER / (self.boot + '-COLD-POSSIBLE-SEND.PUBLIC.json')
        once(marker, wire({'schema': 'lab_first_cold_eight_possible_send_v1',
            'boot_id': self.boot, 'source_sha256': self.sha, 'standing_config_sha256': sha(self.raw_config),
            'exact_eight_commands': inserts, 'unknown_or_partial_retry_authorized': False}))
        self.cold_guard()
        self.insert_remaining = {tuple(argv) for argv in inserts}
        try:
            for i, argv in enumerate(inserts):
                self.call('cold-one-insert-' + str(i + 1), argv)
        finally:
            self.insert_remaining.clear()
        result = self.transport()
        after = self.call('cold-filter-after', ['/usr/sbin/iptables-save', '-c', '-t', 'filter'])
        other_filter_after = self.C.without_bridge(after, b)
        # K3s remains active and may legitimately publish unrelated chains.
        # Exact closed native -I argv scopes OUR writes to the eight rules.
        # Preserve full before/after hashes honestly, without attributing a
        # concurrent foreign-table change to this owner or failing a boot.
        other_snapshots = {'filter_before_sha256': filter_sha,
            'filter_after_without_our_four_sha256': other_filter_after,
            'mangle_before_without_our_four_sha256': mang_before['other_structure_sha256'],
            'mangle_after_without_our_four_sha256': result['other_mangle_structure_sha256'],
            'other_ordered_filter_equal_observed': filter_sha == other_filter_after,
            'other_ordered_mangle_equal_observed': mang_before['other_structure_sha256'] == result['other_mangle_structure_sha256'],
            'foreign_concurrent_changes_not_attributed_or_authorized_by_this_owner': True}
        require(self.kernel(allow_absent=True) == kernel_before, 'INET47_AND_GLOBAL_MARK_OWNER_PRESERVED_ACROSS_COLD_INSERTS')
        self.cold_guard()
        require(time.monotonic() < self.deadline - 1, 'ORIGINAL_COLD_OWNER_BUDGET')
        value = {'schema': 'lab_first_cold_eight_return_v1', 'boot_id': self.boot, 'cold_invocation_id': os.environ.get('INVOCATION_ID'), 'cold_exec_pid': os.getpid(),
                 'source_sha256': self.sha, 'standing_config_sha256': sha(self.raw_config),
                 'original_native_calls': self.calls, 'transport': result, 'insert_count': 8,
                 'complete_other_structure_observations': other_snapshots,
                 'old_original_install_results_reclassified': False,
                 'WG_routes_marks_inet47_or_service_mutations': 0,
                 'controller_lifetime_or_Guest_business_qualified': False}
        once(LEDGER / (self.boot + '-COLD-ORIGINAL-RETURN.PUBLIC.json'), wire(value))
        return value

    def journal_argv(self, identity):
        return ['/usr/bin/journalctl', '-o', 'json', '--all', '--no-pager',
            '--output-fields=_PID,_SYSTEMD_INVOCATION_ID,MESSAGE,__MONOTONIC_TIMESTAMP,__CURSOR,_BOOT_ID',
            '_PID=' + str(identity['pid']), '_SYSTEMD_INVOCATION_ID=' + identity['InvocationID'],
            '_BOOT_ID=' + self.boot.replace('-', '')]

    def full_journal(self, identity):
        self.journal_identity = identity
        argv = self.journal_argv(identity)
        raw = self.call('new-lifetime-full-journal', argv, cap=64 << 20, seconds=15)
        now = time.monotonic()
        seen, previous = set(), 0
        for line in raw.splitlines():
            cursor, stamp = self.journal_contract.journal_row(loads(line), identity['pid'],
                identity['InvocationID'], self.boot.replace('-', ''))
            require(cursor not in seen and previous <= stamp and stamp / 1000000 <= now,
                    'ALL_ORIGINAL_JOURNAL_ROWS_SAME_BOOT_LIFETIME_FORWARD_CLOCK')
            seen.add(cursor)
            previous = stamp
        measured = self.coverage.journal(raw, identity['pid'], identity['InvocationID'], now, minimum_original_batches=1)
        anchor = self.journal_contract.journal_anchor(raw, identity['pid'], identity['InvocationID'],
                                                     self.boot.replace('-', ''), now)
        return raw, measured, anchor, argv

    def qualify_new_lifetime(self, identity, original_deadline=None, START_ref=None):
        self.calls = []
        self.deadline = min(time.monotonic() + 210, original_deadline) if original_deadline is not None else time.monotonic() + 210
        original_work_deadline = self.deadline
        wg = self.wg()
        self.transport()
        # This is a new lifetime's explicit epoch, never a reset of R35/R36.
        # Start only after actual full dynamic collections are positive.
        warm_end = time.monotonic() + 30
        while True:
            require(self.identity() == identity, 'SAME_NEW_CONTROLLER_DURING_INITIAL_WARMUP')
            kernel, observed = self.kernel()
            if kernel['all_four_backends_and_reverse_sources_positive']:
                # Sets may still belong to the preceding controller. Require
                # journal coverage from this exact lifetime before the epoch.
                self.journal_identity = identity
                raw = self.call('warmup-own-lifetime-journal', self.journal_argv(identity), cap=64 << 20, seconds=15)
                measured = self.coverage.journal(raw, identity['pid'], identity['InvocationID'], time.monotonic(), minimum_original_batches=0)
                window = measured['current_continuous_window']
                if (window is not None and window['start'] <= observed <= window['observed_until']
                        and time.monotonic() < window['guaranteed_until'] and self.identity() == identity):
                    break
            require(time.monotonic() + 3 < warm_end, 'NEW_LIFETIME_BOUNDED_COLD_WARMUP')
            time.sleep(2)
        first_read = time.monotonic()
        first_transport = self.transport()
        first_sample = {'started': first_read, 'finished': time.monotonic(), 'transport': first_transport}
        epoch = time.monotonic()
        require(window['start'] <= epoch < window['guaranteed_until'], 'OWN_WARMUP_COVERAGE_STILL_LIVE_AT_EPOCH')
        end = epoch + 120
        require(end + 35 < original_work_deadline, 'NEW_FULL120_AND_FINAL_READS_FIT_ORIGINAL_OPERATION_BUDGET')
        key = self.key(identity)
        once(LEDGER / (key + '-FIXED120-START.PUBLIC.json'), wire({
            'schema': 'Root_new_network_lifetime_original_fixed120_start_v1',
            'source_sha256': self.sha, 'identity': identity, 'start': epoch, 'end': end,
            'original_work_deadline': original_work_deadline, 'old_R35_R36_epoch_reused_or_reset': False}))
        samples = [first_sample]
        while True:
            started = time.monotonic()
            require(self.identity() == identity, 'SAME_NEW_PHYSICAL_CONTROLLER_ACROSS120')
            transport = self.transport()
            samples.append({'started': started, 'finished': time.monotonic(), 'transport': transport})
            if time.monotonic() >= end:
                break
            time.sleep(min(5, max(0, end - time.monotonic())))
        require(samples[0]['started'] <= samples[0]['finished'] <= epoch
                and epoch - samples[0]['finished'] < 1 and samples[-1]['finished'] >= end
                and all(row['finished'] - row['started'] < 20 for row in samples)
                and all(0 <= b['started'] - a['finished'] <= 5.5 for a, b in zip(samples, samples[1:])),
                'ACTUAL_PERIODIC_FUNCTIONAL_EIGHT_RULE_READS_SPAN_NEW120')
        raw, measured, anchor, argv = self.full_journal(identity)
        require(self.identity() == identity and self.wg() == wg, 'SAME_CONTROLLER_WG_PUBLIC_SHAPE_AFTER120')
        kernel, observed = self.kernel(measured)
        suffix = self.call('new-lifetime-one-closing-cursor', argv + ['--after-cursor=' + anchor['cursor']],
                           cap=64 << 20, seconds=8)
        measured, closing = self.journal_contract.closing_journal(measured, suffix,
            identity['pid'], identity['InvocationID'], self.boot.replace('-', ''), anchor,
            time.monotonic(), self.coverage)
        finished = time.monotonic()
        current = measured['current_continuous_window']
        require(end <= finished < original_work_deadline and current is not None
                and current['start'] <= epoch and current['observed_until'] >= end
                and current['observed_seconds'] >= 120 and measured['qualified_15_seconds'] is True
                and current['start'] <= observed <= current['observed_until'] <= finished < current['guaranteed_until']
                and kernel['all_four_backends_and_reverse_sources_positive'], 'NEW_ORIGINAL120_NO_GAP_AND_STRICT_CURRENT15')
        journal_path = LEDGER / (key + '-ORIGINAL-PREFIX.JSONL')
        suffix_path = LEDGER / (key + '-ORIGINAL-CLOSING.JSONL')
        once(journal_path, raw)
        once(suffix_path, suffix)
        value = {'schema': 'Root_new_network_lifetime_original120_current15_return_v1',
            'source_sha256': self.sha, 'standing_config_sha256': sha(self.raw_config),
            'identity': identity, 'start': epoch, 'end': end, 'finished': finished,
            'original_work_deadline': original_work_deadline, 'measurement': measured,
            'kernel': kernel, 'kernel_observed': observed, 'closing_cursor': closing,
            'periodic_transport_samples': samples, 'WG_public_shape': wg,
            'original_native_calls': self.calls,
            'original_START_caller_ref': START_ref,
            'original_prefix_ref': {'path': str(journal_path), 'sha256': sha(raw)},
            'original_suffix_ref': {'path': str(suffix_path), 'sha256': sha(suffix)},
            'network_original120_and_current15': True,
            'original_R35_R36_or_unknown_native_success_reclassified': False,
            'Guest_TLS_Core_capacity_business_or_savings_authority': False}
        once(LEDGER / (key + '-QUALIFIED.PUBLIC.json'), wire(value))
        return value

    def original_qualification_exists(self, identity):
        # A validated handoff is its own source/START lineage, not a Guardian
        # qualification. The proof cache has rederived the complete handoff.
        path = LEDGER / (self.key(identity) + '-QUALIFIED.PUBLIC.json')
        if not path.exists():
            return False
        value = loads(read(path, 16 << 20, 0o600))
        require(value['schema'] == 'Root_new_network_lifetime_original120_current15_return_v1'
                and value['source_sha256'] == self.sha and value['identity'] == identity
                and value['standing_config_sha256'] == sha(self.raw_config), 'SAME_OWNED_NEW_LIFETIME_ORIGINAL_RETURN')
        # Recompute the complete historical proof, not a cached JSON flag.
        a, b = value['original_prefix_ref'], value['original_suffix_ref']
        require(Path(a['path']) == LEDGER / (self.key(identity) + '-ORIGINAL-PREFIX.JSONL')
                and Path(b['path']) == LEDGER / (self.key(identity) + '-ORIGINAL-CLOSING.JSONL'), 'FIXED_OWNED_JOURNAL_PROOFS')
        prefix, suffix = read(a['path'], 64 << 20, 0o600), read(b['path'], 64 << 20, 0o600)
        require(sha(prefix) == a['sha256'] and sha(suffix) == b['sha256'], 'FULL_ORIGINAL_JOURNAL_BYTES')
        measured = self.coverage.journal(prefix, identity['pid'], identity['InvocationID'],
                                         value['finished'], minimum_original_batches=1)
        anchor = self.journal_contract.journal_anchor(prefix, identity['pid'], identity['InvocationID'],
            self.boot.replace('-', ''), value['finished'])
        measured, _ = self.journal_contract.closing_journal(measured, suffix, identity['pid'],
            identity['InvocationID'], self.boot.replace('-', ''), anchor, value['finished'], self.coverage)
        current = measured['current_continuous_window']
        require(current is not None and current['start'] <= value['start']
                and value['end'] - value['start'] == 120 and current['observed_until'] >= value['end']
                and measured['qualified_15_seconds'] is True and value['finished'] < current['guaranteed_until'],
                'RECOMPUTED_ORIGINAL_LIFETIME120_NEVER_CURRENT_HEALTH_ALIAS')
        return True

    @contextlib.contextmanager
    def maintenance(self):
        directory(RUN)
        path = RUN / 'guardian-maintenance.lock'
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            info = os.fstat(fd)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
                    and stat.S_IMODE(info.st_mode) == 0o600, 'SAME_ROOT_SHARED_MAINTENANCE_MUTEX')
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            yield
            require((info.st_dev, info.st_ino) == (path.lstat().st_dev, path.lstat().st_ino), 'UNCHANGED_MAINTENANCE_LOCK')
        finally:
            os.close(fd)

    def failed(self, expected):
        props = self.properties()
        require(props['MainPID'] == '0' and props['ActiveState'] == 'failed'
                and props['SubState'] == 'failed' and props['Result'] != 'success'
                and props['ExecMainPID'] == str(expected['pid'])
                and props['InvocationID'] == expected['InvocationID']
                and props['ExecMainStartTimestampMonotonic'] == expected['ExecMainStartTimestampMonotonic'],
                'EXACT_OBSERVED_TERMINAL_PREDECESSOR')
        require(not Path('/proc/' + str(expected['pid'])).exists(), 'TERMINAL_PHYSICAL_PID_ABSENT')
        cgroup = Path('/sys/fs/cgroup/system.slice') / UNIT / 'cgroup.procs'
        require(not cgroup.exists() or read(cgroup, 65536).strip() == b'', 'ALL_CONTROLLER_NATIVE_CHILDREN_JOINED_OR_ABSENT')
        return props

    def terminal_after_own_START(self, predecessor):
        """A real new unit execution may fail before an OS PID sample is possible.

        Its original possible-START and exact unit are known; the original
        caller may have returned nonzero or unknown. No missing OS start tick,
        command observation or original success is invented. This record
        only permits a later quiescent recovery, never lifetime qualification.
        """
        props = self.properties()
        require(props['ActiveState'] == 'failed' and props['SubState'] == 'failed'
                and props['MainPID'] == '0' and props['ExecMainPID'].isdigit()
                and int(props['ExecMainPID']) > 1 and int(props['ExecMainPID']) != predecessor['pid']
                and re.fullmatch('[a-f0-9]{32}', props['InvocationID'])
                and props['InvocationID'] != predecessor['InvocationID']
                and props['ExecMainStartTimestampMonotonic'].isdigit(), 'ACTUAL_NEW_FAILED_UNIT_EXECUTION_AFTER_OWN_START')
        value = {'boot_id': self.boot, 'pid': int(props['ExecMainPID']), 'start_ticks': None,
                 'InvocationID': props['InvocationID'],
                 'ExecMainStartTimestampMonotonic': props['ExecMainStartTimestampMonotonic'],
                 'cmdline_sha256': None, 'initial_R42_admitted_lifetime': False,
                 'OS_process_never_sampled_before_terminal_exit': True}
        self.failed(value)
        return value

    def boot_terminal_predecessor(self):
        # systemd can finish the first failed simple-service job before this
        # watcher runs. Authenticate the same boot's actual cold/Hub successful
        # jobs rather than assuming that an old Boot/PID or a flag is admission.
        require(self.boot == INITIAL_BOOT, 'BOOT_TERMINAL_DISCOVERY_ONLY_NEW_BOOT')
        for unit in (COLD, HUB):
            props = self.properties(unit)
            require(props['ActiveState'] == 'active' and props['SubState'] == 'exited'
                    and props['MainPID'] == '0' and props['Result'] == 'success'
                    and props['ExecMainStatus'] == '0' and props['ExecMainPID'].isdigit()
                    and int(props['ExecMainPID']) > 1 and re.fullmatch('[a-f0-9]{32}', props['InvocationID']),
                    'ORIGINAL_COLD_AND_HUB_SYSTEMD_EXECUTIONS_BOTH_ZERO_THIS_BOOT')
        cold = loads(read(LEDGER / (self.boot + '-COLD-ORIGINAL-RETURN.PUBLIC.json'), 1 << 20, 0o600))
        require(cold['schema'] == 'lab_first_cold_eight_return_v1'
                and cold['source_sha256'] == self.sha and cold['boot_id'] == self.boot
                and cold['standing_config_sha256'] == sha(self.raw_config), 'OWN_ACTUAL_SAME_BOOT_COLD_RETURN')
        hub = loads(read(RUN / ('hub-boot-' + self.boot + '-RETURN.json'), 32768, 0o600))
        require(hub['schema'] == 'lab_first_hub_boot_return_v1'
                and hub['boot_id'] == self.boot and hub['seal_sha256'] == self.config['hub_boot_config_sha256']
                and hub['mode'] == 'LAB_FIRST_BOOT_CREATE', 'OWN_ACTUAL_SAME_BOOT_HUB_RETURN')
        self.wg()
        self.transport()
        self.kernel()
        value = self.terminal_after_own_START({'pid': 0, 'InvocationID': ''})
        value['initial_systemd_boot_job_failed_before_watcher_OS_sample'] = True
        return value

    def never_started(self, unit):
        props = self.properties(unit)
        require(props['MainPID'] == props['ExecMainPID'] == props['ExecMainStartTimestampMonotonic'] == '0'
                and props['ActiveState'] in ('inactive', 'failed'), 'NO_FIRST_BOOT_SERVICE_EXECUTION_YET')
        return props

    def joined_unit(self, unit, props):
        require(props['MainPID'] == '0' and props['ActiveState'] in ('inactive', 'failed')
                and props['SubState'] in ('dead', 'failed'), 'QUIESCENT_BOOT_PREDECESSOR_UNIT')
        if props['ExecMainPID'] != '0':
            require(props['ExecMainPID'].isdigit() and not Path('/proc/' + props['ExecMainPID']).exists(),
                    'PREVIOUS_BOOT_OWNER_PHYSICAL_PID_ABSENT')
        group = Path('/sys/fs/cgroup/system.slice') / unit / 'cgroup.procs'
        require(not group.exists() or read(group, 65536).strip() == b'', 'ALL_PREVIOUS_BOOT_OWNER_NATIVE_CHILDREN_ABSENT')

    def successful_boot_unit(self, unit):
        props = self.properties(unit)
        return (props['ActiveState'] == 'active' and props['SubState'] == 'exited'
                and props['MainPID'] == '0' and props['Result'] == 'success'
                and props['ExecMainStatus'] == '0')

    def boot_start_service_once(self, unit, predecessor):
        # Each real failed/never-run predecessor permits at most one START.
        # The worker's own pre-intent checks still run inside the started job.
        require(unit in (COLD, HUB, UNIT), 'ONLY_EXACT_FIXED_BOOT_START_UNITS')
        key = sha(wire({'boot': self.boot, 'unit': unit, 'predecessor': predecessor}))
        prefix = self.boot + '-BOOT-' + unit + '-'
        attempts = list(LEDGER.glob(prefix + '*-POSSIBLE-START.PUBLIC.json'))
        require(len(attempts) < 3, 'AT_MOST_THREE_DISTINCT_PRE_EFFECT_BOOT_ATTEMPTS_PER_UNIT')
        marker = LEDGER / (prefix + key + '-POSSIBLE-START.PUBLIC.json')
        if marker.exists():
            return False  # No fresh execution was observed; never repeat this send.
        prior = []
        for path in attempts:
            raw = read(path, 32768, 0o600)
            caller_path = path.with_name(path.name.replace('-POSSIBLE-START.PUBLIC.json',
                                                          '-ORIGINAL-CALLER.PUBLIC.json'))
            # No caller (including a crash after the marker) is unknown, never
            # permission for another START. Native nonzero itself is allowed.
            caller = loads(read(caller_path, 32768, 0o600))
            prior.append({'possible_start': loads(raw),
                          'possible_start_ref': {'path': str(path), 'sha256': sha(raw)},
                          'original_caller': caller})
        require(prior_boot_start_callers_quiescent(prior, self.boot, unit, self.sha,
                    sha(self.raw_config)) == len(attempts), 'ALL_FIXED_PATH_PRIOR_BOOT_CALLERS_AUTHENTICATED')
        once(marker, wire({'schema': 'Root_boot_pre_effect_one_original_unit_START_possible_v1',
            'source_sha256': self.sha, 'standing_config_sha256': sha(self.raw_config),
            'boot_id': self.boot, 'unit': unit, 'predecessor': predecessor,
            'started_monotonic': time.monotonic(), 'same_possible_START_retry': False}))
        self.start_admitted = unit
        error = None
        argv = ['/usr/bin/systemctl', 'start', unit]
        try:
            self.call('one-boot-START-' + unit, argv, seconds=70 if unit != UNIT else 12)
        except Exception as caught:
            error = caught
        call = next((row for row in reversed(self.calls) if row['role'] == 'one-boot-START-' + unit), None)
        if call is None:
            call = {'role': 'one-boot-START-' + unit, 'argv': argv,
                    'original_transport': dict(getattr(self.n.native, 'last_custody', {}) or {}),
                    'stdout_sha256': None, 'stdout_bytes': None,
                    'original_native_exception_before_stdout_return': True}
        once(LEDGER / (prefix + key + '-ORIGINAL-CALLER.PUBLIC.json'), wire({
            'schema': 'Root_boot_original_unit_START_caller_v1', 'boot_id': self.boot,
            'source_sha256': self.sha, 'possible_START_ref': {'path': str(marker), 'sha256': sha(read(marker, 32768, 0o600))},
            'original_native_call': call, 'expected_zero': error is None,
            'exception_class': None if error is None else type(error).__name__}))
        return error is None

    def bootstrap_never_started(self):
        """Complete the local boot jobs, never retry an existing kernel intent.

        Hub imports current controller helpers but performs no Core/API/DNS
        read: Source47 initialization is empty. A local pre-intent failure can
        therefore be retried as a distinct real unit execution after quiescence.
        """
        require(self.boot == INITIAL_BOOT, 'AUTONOMOUS_BOOT_ONLY_LATER_BOOT')
        self.deadline = time.monotonic() + 90
        self.never_started(UNIT)
        RUN.mkdir(mode=0o700, exist_ok=True)
        directory(RUN)
        with self.maintenance():
            self.static()
            self.never_started(UNIT)
            if not self.successful_boot_unit(COLD):
                require(not Path('/sys/class/net/wg-capacity').exists(), 'NO_INTERFACE_BEFORE_COLD_BOOT_RETRY')
                self.never_started(HUB)
                props = self.properties(COLD)
                self.joined_unit(COLD, props)
                marker = LEDGER / (self.boot + '-COLD-POSSIBLE-SEND.PUBLIC.json')
                returned = LEDGER / (self.boot + '-COLD-ORIGINAL-RETURN.PUBLIC.json')
                require(not marker.exists() and not returned.exists(), 'NO_COLD_KERNEL_INTENT_OR_RETURN_RETRY')
                self.boot_start_service_once(COLD, props)
                return False
            if not self.successful_boot_unit(HUB):
                require(not Path('/sys/class/net/wg-capacity').exists(), 'NO_INTERFACE_BEFORE_HUB_BOOT_RETRY')
                props = self.properties(HUB)
                self.joined_unit(HUB, props)
                require(not (RUN / ('hub-boot-' + self.boot + '-INTENT.json')).exists()
                        and not (RUN / ('hub-boot-' + self.boot + '-RETURN.json')).exists(),
                        'NO_HUB_KERNEL_INTENT_OR_RETURN_RETRY')
                self.hub.route_shape(loads(self.call('boot-full-routes-RAM',
                    ['/usr/sbin/ip', '-j', '-4', 'route', 'show', 'table', 'all'])), False)
                self.boot_start_service_once(HUB, props)
                return False
            # A failed Requires/After startup job does not necessarily start
            # the controller when Hub later succeeds. Send its first START
            # exactly once after real local readiness, with no old PID clock.
            self.wg()
            self.transport()
            self.kernel()
            cold_props=self.properties(COLD);hub_props=self.properties(HUB)
            cold=loads(read(LEDGER / (self.boot + '-COLD-ORIGINAL-RETURN.PUBLIC.json'), 1 << 20, 0o600));hub=loads(read(RUN / ('hub-boot-' + self.boot + '-RETURN.json'), 32768, 0o600))
            require(cold.get('schema')=='lab_first_cold_eight_return_v1' and cold.get('boot_id')==self.boot and cold.get('source_sha256')==self.sha and cold.get('standing_config_sha256')==sha(self.raw_config) and cold.get('insert_count')==8 and str(cold.get('cold_exec_pid'))==cold_props['ExecMainPID'] and cold.get('cold_invocation_id')==cold_props['InvocationID'],'SAME_LAB_COLD_RETURN_AND_UNIT')
            require(hub.get('schema')=='lab_first_hub_boot_return_v1' and hub.get('boot_id')==self.boot and hub.get('seal_sha256')==self.config['hub_boot_config_sha256'] and hub.get('mode')=='LAB_FIRST_BOOT_CREATE' and str(hub.get('hub_exec_pid'))==hub_props['ExecMainPID'] and hub.get('hub_invocation_id')==hub_props['InvocationID'],'SAME_LAB_HUB_RETURN_AND_UNIT')
            require(self.successful_boot_unit(COLD) and self.successful_boot_unit(HUB),'SAME_LAB_BOOT_UNITS_STILL_SUCCESSFUL')
            props = self.never_started(UNIT)
            self.joined_unit(UNIT, props)
            require(self.properties(COLD)==cold_props and self.properties(HUB)==hub_props,'SAME_LAB_COLD_HUB_UNIT_IDENTITIES_BEFORE_CONTROLLER_START')
            self.boot_start_service_once(UNIT, props)
            return True

    def recover_terminal(self, expected):
        self.calls = []
        self.deadline = time.monotonic() + 240
        self.recovering_identity = None
        with self.maintenance():
            self.static()
            before = self.failed(expected)
            self.wg()
            self.transport()
            self.kernel()  # A fresh read of the actual owned47, no old apply adoption.
            lock = os.open(RUN / 'controller.lock', os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                require(self.failed(expected) == before, 'SAME_TERMINAL_PREDECESSOR_UNDER_CONTROLLER_LOCK')
                key = self.key(expected)
                existing = list(LEDGER.glob(self.boot + '-RECOVERY-*-POSSIBLE-START.PUBLIC.json'))
                require(len(existing) < 3, 'THREE_DISTINCT_TERMINAL_RECOVERIES_MAXIMUM_PER_BOOT')
                for path in existing:
                    previous = loads(read(path, 32768, 0o600))
                    require(previous['source_sha256'] == self.sha and previous['boot_id'] == self.boot
                            and 0 <= previous['started_monotonic'] <= time.monotonic(), 'SAME_BOOT_ORIGINAL_RECOVERY_CLOCK')
                    if time.monotonic() - previous['started_monotonic'] < 300:
                        return expected, None  # Wait without renewing the previous operation or sending.
                marker = LEDGER / (self.boot + '-RECOVERY-' + key + '-POSSIBLE-START.PUBLIC.json')
                once(marker, wire({'schema': 'Root_terminal_predecessor_one_new_START_possible_v1',
                    'boot_id': self.boot, 'predecessor': expected, 'source_sha256': self.sha,
                    'standing_config_sha256': sha(self.raw_config), 'started_monotonic': time.monotonic(),
                    'old_unknown_hot_batch_replayed_or_qualified': False}))
            finally:
                os.close(lock)  # Release before START; the new controller owns this flock.
            require(self.failed(expected) == before, 'SAME_TERMINAL_PREDECESSOR_IMMEDIATELY_BEFORE_START')
            self.start_admitted = UNIT
            start_error = None
            start_argv = ['/usr/bin/systemctl', 'start', UNIT]
            try:
                self.call('one-terminal-controller-START', start_argv, seconds=12)
            except Exception as error:
                start_error = error
            original_call = next((row for row in reversed(self.calls)
                if row['role'] == 'one-terminal-controller-START'), None)
            if original_call is None:
                original_call = {'role': 'one-terminal-controller-START', 'argv': start_argv,
                    'original_transport': dict(getattr(self.n.native, 'last_custody', {}) or {}),
                    'stdout_sha256': None, 'stdout_bytes': None,
                    'original_native_exception_before_stdout_return': True}
            start_raw = wire({'schema': 'Root_terminal_recovery_original_controller_START_caller_v1',
                'source_sha256': self.sha, 'predecessor': expected,
                'possible_START_ref': {'path': str(marker), 'sha256': sha(read(marker, 32768, 0o600))},
                'original_native_call': original_call,
                'original_START_returned_expected_zero': start_error is None,
                'original_exception_class': None if start_error is None else type(start_error).__name__})
            start_path = LEDGER / (key + '-ORIGINAL-START-CALLER.PUBLIC.json')
            once(start_path, start_raw)
            if start_error is not None:
                # A failed local START is never repeated. A genuinely distinct
                # failed unit invocation is a new predecessor, observed only
                # after that original caller has joined or been closed.
                facts = original_call['original_transport']
                if facts.get('local_child_joined') is True and facts.get('all_local_FDs_closed') is True:
                    try:
                        self.recovering_identity = self.terminal_after_own_START(expected)
                    except Exception:
                        pass
                raise start_error
            try:
                current = self.identity()
            except Exception:
                self.recovering_identity = self.terminal_after_own_START(expected)
                raise RuntimeError('NEW_UNIT_FAILED_BEFORE_RUNNING_OS_IDENTITY_COULD_BE_SAMPLED') from None
            require(current['InvocationID'] != expected['InvocationID'] and current['pid'] != expected['pid']
                    and current['initial_R42_admitted_lifetime'] is False, 'DISTINCT_FRESH_REVIEWED_CONTROLLER_LIFETIME')
            self.recovering_identity = current
            result = self.qualify_new_lifetime(current, self.deadline,
                {'path': str(start_path), 'sha256': sha(start_raw)})
            return current, result

    def watch_initial_identity(self):
        return None  # No LAB history is admitted.

    def watch(self, *, guarded=None, stop=None, publish=None, duration=None):
        if guarded is not None:
            # Separate non-authorizing experimental mode. The existing
            # production watch/recovery path below is not changed or invoked.
            require(os.environ.get('CI_GUARDED_FIXTURE')=='1' and stop is not None and callable(publish)
                    and type(duration) in (int,float) and 0<duration<=20,
                    'BOUNDED_PRIVATE_GUARDED_WATCH_ONLY')
            deadline=time.monotonic()+duration
            while not stop.is_set() and time.monotonic()<deadline:
                try:
                    value,observed=self.kernel(guarded=guarded)
                    publish({'event':'SAMPLE','observed':observed,'generation':value['live']['observation']['genid'],
                             'production_authority':False})
                except Exception as error:
                    publish({'event':'HOLD','error_class':type(error).__name__,'guard':str(error)[:160],
                             'production_authority':False})
                    return
                stop.wait(min(.25,max(0,deadline-time.monotonic())))
            publish({'event':'FINISHED','production_authority':False})
            return
        # A second Guardian cannot race this permanent owner after a service restart.
        fd = os.open(LEDGER / 'guardian.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            known = self.watch_initial_identity()
            while True:
                self.calls = []
                # Renew exactly once at the start of a new watch iteration;
                # static's native reads share this fixed iteration deadline.
                self.deadline = time.monotonic() + 60
                self.static()
                props = self.properties()
                if (known is None and self.boot == INITIAL_BOOT and props['MainPID'] == '0'
                        and props['ExecMainPID'] == '0' and props['ExecMainStartTimestampMonotonic'] == '0'
                        and props['ActiveState'] in ('inactive', 'failed')):
                    try:
                        self.bootstrap_never_started()
                    except BlockingIOError:
                        pass
                    except Exception as error:
                        print(wire({'schema': 'Root_network_guardian_local_boot_HOLD_v1',
                            'source_sha256': self.sha, 'boot_id': self.boot,
                            'guard': str(error)[:180], 'error_class': type(error).__name__,
                            'kernel_intent_or_unknown_native_replayed': False}).decode(), end='', flush=True)
                    time.sleep(10)
                    continue
                if props['ActiveState'] == 'failed' and known is None and self.boot == INITIAL_BOOT:
                    known = self.boot_terminal_predecessor()
                if props['ActiveState'] == 'active' and props['SubState'] == 'running':
                    current = self.identity()
                    if current != known:
                        known = current
                        measured = self.original_qualification_exists(current)
                        started = (LEDGER / (self.key(current) + '-FIXED120-START.PUBLIC.json')).exists()
                        if not current['initial_R42_admitted_lifetime'] and not measured and not started:
                            try:
                                self.qualify_new_lifetime(current)
                            except Exception as error:
                                # Preserve this first window. The running daemon
                                # can recover its own DNS data; never restart a
                                # live controller to manufacture a clean epoch.
                                once(LEDGER / (self.key(current) + '-QUALIFICATION-HOLD.PUBLIC.json'), wire({
                                    'schema': 'Root_new_lifetime_original_window_HOLD_v1',
                                    'source_sha256': self.sha, 'identity': current,
                                    'error_class': type(error).__name__, 'guard': str(error)[:180],
                                    'original_native_calls': self.calls, 'epoch_replayed': False}))
                                continue
                    try:
                        observed,prefix,suffix,reads=self.current15_readonly()
                        require(observed['identity']==current,'SAME_CURRENT_WATCHER_LIFETIME')
                        invocation=os.environ.get('INVOCATION_ID','')
                        require(re.fullmatch('[a-f0-9]{32}',invocation),'OWN_CURRENT_GUARDIAN_INVOCATION')
                        key=self.boot+'-GUARDIAN-'+invocation+'-FIRST-CURRENT15'
                        path=LEDGER/(key+'-RETURN.PUBLIC.json')
                        if not path.exists():
                            g=self.current15_context();first_ref=g.reader.persist(self,g,observed,prefix,suffix,reads,key)
                        else:first_ref={'path':str(path),'sha256':sha(read(path,1<<20,0o600))}
                        value={'schema':'Root_network_guardian_current_operational_descriptor_v1','source_sha256':self.sha,'identity':current,'read_finished_monotonic':observed['finished_monotonic'],'kernel_observed':observed['kernel_observed'],'all_four_backends_currently_positive':observed['kernel']['all_four_backends_and_reverse_sources_positive'],'transport':observed['transport'],'current15':observed['measurement'],'first_own_current15_original_ref':first_ref,'first_ref_is_historical_after_first_sample':True,'mutations_this_sample':0,'historical120_is_not_current15_or_Guest_business_authority':True,'unobserved_lifetime_continuity_claimed':False}
                        print(wire(value).decode(),end='',flush=True)
                    except Exception as error:
                        print(wire({'schema':'Root_network_guardian_current15_HOLD_v1','source_sha256':self.sha,'identity':current,'error_class':type(error).__name__,'guard':str(error)[:180],'mutations_this_sample':0,'current15_or_business_authority':False}).decode(),end='',flush=True)
                elif props['ActiveState'] == 'failed' and known is not None:
                    try:
                        known, result = self.recover_terminal(known)
                        if result is not None:
                            print(wire({'schema': 'Root_guardian_new_lifetime_return_ref_v1',
                                'identity': known, 'return_ref': {'path': str(LEDGER / (self.key(known) + '-QUALIFIED.PUBLIC.json')),
                                'sha256': sha(wire(result))}}).decode(), end='', flush=True)
                    except BlockingIOError:
                        pass  # An actual planned maintenance owner currently holds the shared mutex.
                    except Exception as error:
                        if self.recovering_identity is not None:
                            known = self.recovering_identity
                        print(wire({'schema': 'Root_network_guardian_terminal_recovery_HOLD_v1',
                            'source_sha256': self.sha, 'predecessor_or_new_identity': known,
                            'guard': str(error)[:180], 'error_class': type(error).__name__,
                            'old_unknown_native_success_inferred': False, 'same_possible_START_replayed': False}).decode(), end='', flush=True)
                elif props['ActiveState'] == 'inactive':
                    # Never interfere with an intentional stop/maintenance transaction.
                    known = None
                else:
                    require(props['ActiveState'] in ('activating', 'deactivating'), 'UNADMITTED_CHANGED_OR_UNKNOWN_SERVICE_STATE')
                time.sleep(5)
        finally:
            os.close(fd)


def main():
    p = argparse.ArgumentParser()
    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument('--cold-restore', action='store_true')
    mode.add_argument('--watch', action='store_true')
    mode.add_argument('--read-once', action='store_true')
    p.add_argument('--source-sha256', required=True)
    args = p.parse_args()
    # Only this disposable LAB boot may execute this derived copy.
    import urllib.request
    require(os.geteuid() == 0 and Path('/proc/sys/kernel/random/boot_id').read_text().strip() == '9930f6b8-f1e4-4542-a81b-9000e0efa4ed', 'EXACT_DISPOSABLE_LAB_BOOT')
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    request = urllib.request.Request('http://169.254.169.254/latest/api/token', method='PUT', headers={'X-aws-ec2-metadata-token-ttl-seconds':'60'})
    token = opener.open(request, timeout=3).read().decode()
    request = urllib.request.Request('http://169.254.169.254/latest/dynamic/instance-identity/document', headers={'X-aws-ec2-metadata-token':token})
    identity = json.loads(opener.open(request, timeout=3).read())
    require(identity.get('instanceId') == 'i-0aab3e2de66e1150a' and identity.get('accountId') == '153828470928' and identity.get('region') == 'us-east-1', 'EXACT_DISPOSABLE_LAB_INSTANCE')
    owner = Owner(args.source_sha256)
    if args.cold_restore:
        value = owner.cold_restore()
        print(wire({'schema': value['schema'], 'boot_id': value['boot_id'], 'insert_count': 8,
                'original_return_ref': {'path': str(LEDGER / (owner.boot + '-COLD-ORIGINAL-RETURN.PUBLIC.json')),
                                        'sha256': sha(wire(value))}}).decode(), end='', flush=True)
    elif args.read_once:
        identity = owner.identity()
        wg = owner.wg()
        transport = owner.transport()
        kernel, observed = owner.kernel()
        require(owner.identity() == identity, 'SAME_ACTUAL_LIFETIME_DURING_READONLY')
        print(wire({'schema': 'Root_network_recovery_readonly_prepared_current_return_v1',
            'identity': identity, 'WG': wg, 'transport': transport, 'kernel': kernel,
            'kernel_observed': observed, 'original_native_calls': owner.calls, 'mutations': 0,
            'new_runtime_or_new_boot_executed_or_qualified': False}).decode(), end='', flush=True)
    else:
        owner.watch()


if __name__ == '__main__':
    main()
