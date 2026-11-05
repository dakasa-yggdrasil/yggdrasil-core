"""One forward Guardian-source repair; the C14 controller is never submitted.

The consumed six-command swap and its failed Guardian remain immutable. Only
the two future unit files and a new standing authority are installed, followed
by one daemon-reload and one ordinary Guardian start. Unknown ACK is HOLD.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import sys
import time
import types

SOURCE_BOUND = False
OPS_SOURCE = None
PACKAGE_SHA256 = None
TOOL_PINS = None
GUARDIAN_SOURCE_SHA256 = None
CONFIG_SHA256 = None
FAILED_MANIFEST_SHA256 = '79669ded4147520ce140ce5b69bed08867feecc80e26f1c1c5546fae74075360'
FAILED_SOURCE_SHA256 = '2d4454c6eb62f14a7d9ce151ce7eeb9260679af1215ef04697c2f35329a7b430'
FAILED_STANDING_SHA256 = '43fd7478bb3205a99ab42b9132190e8e9074f04dad98239ce359eac8250ac26e'
CONTROLLER_CONFIG_SHA256 = '90fb39778f79963af7a515401df0e66d969de997d7762aed6f2c50284a733804'
FAILED_SOURCE = Path('/opt/dakasa/capacity-network/network-boot-recovery-r13-g14pair-source-v1')
FAILED_UNITS = {'dakasa-capacity-network.service': '996834aef6c6b11ee4a9df9f3e6fd19c3524fe32eae60b12f655ab281c828674',
                'dakasa-capacity-network-cold-transport.service': 'a577ad69f6c511218d1360341d3cd634d678e1a91c2961757891a536d7c7bdc4',
                'dakasa-capacity-network-guardian.service': '5171ad2f03f07ee90db5505d54cdac070b6c0d25bb75a935faf87a56573e2204'}
FAILED_RESTARTS = 3
REPAIR_SCHEMA = 'g14_guardian_source_forward_repair_return_v1'
EVIDENCE_SCHEMA = 'g14_guardian_source_forward_repair_evidence_v1'
REPAIR_SEQUENCE = (('RELOAD-FUTURE-UNITS', ['/usr/bin/systemctl', 'daemon-reload']),
                   ('START-NEW-GUARDIAN', ['/usr/bin/systemctl', 'start', 'dakasa-capacity-network-guardian.service']))


def need(value, guard):
    if not value:
        raise RuntimeError(guard)


def digest(value):
    return type(value) is str and re.fullmatch('[a-f0-9]{64}', value) is not None and value != '0' * 64


def require_bound():
    need(SOURCE_BOUND is True and type(OPS_SOURCE) is str and re.fullmatch('[a-f0-9]{40}', OPS_SOURCE)
         and all(digest(x) for x in (PACKAGE_SHA256, GUARDIAN_SOURCE_SHA256, CONFIG_SHA256))
         and type(TOOL_PINS) is dict and set(TOOL_PINS) == {'pair_change_contract.py', 'derive_g14pair_controller_config.py', 'derive_standing_config.py', 'g14cut.py'}
         and all(digest(x) for x in TOOL_PINS.values()), 'INERT_G14_GUARDIAN_REPAIR_BEFORE_IO')


def closed(value, fields, guard):
    need(type(value) is dict and set(value) == set(fields.split()), guard)


def reference(C, value, cap=16 << 20):
    closed(value, 'path sha256', 'CLOSED_REPAIR_ORIGINAL_REF')
    need(type(value['path']) is str and Path(value['path']).is_absolute() and digest(value['sha256']), 'PINNED_REPAIR_ORIGINAL_REF')
    raw = C.read(value['path'], cap, 0o600)
    need(C.sha(raw) == value['sha256'], 'UNCHANGED_REPAIR_ORIGINAL_BYTES')
    return raw


def original_swap(cut, refs):
    """Authenticate the completed effect prefix, never turn its HOLD into success."""
    C = cut.C
    closed(refs, 'claim hold before standing failed_guardian_descriptor controller_commit native_commands', 'CLOSED_FAILED_SWAP_ORIGINALS')
    values = {key: C.loads(reference(C, refs[key])) for key in refs if key != 'native_commands'}
    claim, hold, before = values['claim'], values['hold'], values['before']
    original_run = Path(claim['run'])
    need(refs['claim']['path'] == str(C.STATE / ('SWAP-' + FAILED_MANIFEST_SHA256 + '-POSSIBLE.json'))
         and refs['hold']['path'] == str(original_run / 'HOLD.json')
         and refs['before']['path'] == str(original_run / 'BEFORE.json')
         and refs['controller_commit']['path'] == str(original_run / 'NEW-CONTROLLER-FIRST-COMPLETE-COMMIT.json'),
         'EXACT_ORIGINAL_CONSUMED_SWAP_PATHS')
    need(claim['schema'] == 'g14_once_only_swap_claim_v1' and claim['manifest_sha256'] == FAILED_MANIFEST_SHA256
         and claim['automatic_replay'] is False and claim['old_controller'] == before['controller']
         and claim['old_guardian'] == before['guardian'], 'SAME_CONSUMED_G14_SWAP_CLAIM_AND_ORIGINAL_BEFORE')
    need(hold['schema'] == 'g14_pair_swap_HOLD_v1' and hold['automatic_replay'] is False, 'ORIGINAL_FAILED_SWAP_HOLD_PRESERVED')
    need(refs['standing']['sha256'] == FAILED_STANDING_SHA256
         and values['standing']['guardian_source_sha256'] == FAILED_SOURCE_SHA256
         and values['standing']['new_controller_config_sha256'] == CONTROLLER_CONFIG_SHA256,
         'EXACT_FAILED_V1_STANDING_NOT_REPLACED')
    C.identity(before['controller']); C.identity(before['guardian'])
    committed = values['controller_commit']
    C.identity(committed['identity'])
    need(committed['identity']['boot_id'] == before['controller']['boot_id']
         and committed['identity']['pid'] != before['controller']['pid']
         and committed['identity']['InvocationID'] != before['controller']['InvocationID']
         and all(x == 0 for x in committed['conservative_per_role_gap_seconds'].values()), 'ORIGINAL_C14_CONTROLLER_ADOPTION_PREFIX')
    commands = refs['native_commands']
    need(type(commands) is dict and set(commands) == {n for n, _ in cut.NATIVE_SEQUENCE}, 'ALL_SIX_ORIGINAL_COMMANDS_REQUIRED')
    for name, argv in cut.NATIVE_SEQUENCE:
        pair = commands[name]
        closed(pair, 'possible_ref return_ref', 'ORIGINAL_NATIVE_COMMAND_PAIR')
        need(pair['possible_ref']['path'] == str(original_run / (name + '-POSSIBLE-SEND.json'))
             and pair['return_ref']['path'] == str(original_run / (name + '-NATIVE-RETURN.json')), 'SAME_ORIGINAL_SWAP_COMMAND_LEAF')
        possible, returned = (C.loads(reference(C, pair[key])) for key in ('possible_ref', 'return_ref'))
        need(possible['schema'] == 'g14_native_possible_send_v1' and possible['name'] == name
             and possible['argv'] == argv and possible['retry'] is False
             and returned['schema'] == 'g14_native_return_v1' and returned['name'] == name
             and type(returned['exit_code']) is int and returned['exit_code'] == 0 and returned['retry'] is False,
             'ALL_SIX_ORIGINAL_NATIVE_ACKS_ZERO_NO_NEW_SEND')
    failed = values['failed_guardian_descriptor']
    need(failed['LoadState'] == 'loaded' and failed['ActiveState'] == 'failed'
         and failed['SubState'] == 'failed' and failed['MainPID'] == '0'
         and failed['Result'] in ('start-limit-hit', 'exit-code') and failed['NRestarts'] == str(FAILED_RESTARTS)
         and failed['Restart'] == 'on-failure' and failed['DropInPaths'] == ''
         and failed['FragmentPath'] == str(C.UNIT_DIR / C.GUARD), 'ACTUAL_FAILED_V1_THREE_RESTARTS_NO_LIVE_GUARDIAN')
    return values


def observe_guardian(cut, source_sha256, expected_identity, restart_baseline):
    """Only the new qualified incarnation may retain the old unit counter."""
    require_bound()
    C = cut.C
    need(source_sha256 == GUARDIAN_SOURCE_SHA256 and type(restart_baseline) is int
         and restart_baseline in (0, FAILED_RESTARTS), 'EXACT_REPAIR_INCARNATION_BASELINE')
    p = cut.properties(C.GUARD)
    need(p['ActiveState'] == 'active' and p['SubState'] == 'running' and p['Result'] == 'success'
         and p['NRestarts'] == str(restart_baseline) and p['MainPID'] == p['ExecMainPID']
         and p['MainPID'].isdigit() and int(p['MainPID']) > 1, 'SAME_REPAIR_INCARNATION_WITHOUT_AUTO_RESTART')
    pid = int(p['MainPID']); raw = cut.proc_bytes('/proc/%d/stat' % pid)
    ticks = int(raw[raw.rfind(b')') + 1:].split()[19])
    argv = cut.guardian_argv(C.NEW_SOURCE, source_sha256)
    need(cut.proc_bytes('/proc/%d/cmdline' % pid) == b'\0'.join(v.encode() for v in argv) + b'\0', 'EXACT_NEW_REPAIR_GUARDIAN_COMMAND')
    value = {'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(), 'pid': pid, 'start_ticks': ticks,
             'InvocationID': p['InvocationID'], 'ExecMainStartTimestampMonotonic': p['ExecMainStartTimestampMonotonic']}
    C.identity(value)
    need(value == expected_identity and p['FragmentPath'] == str(C.UNIT_DIR / C.GUARD)
         and p['DropInPaths'] == '' and p['Restart'] == 'on-failure', 'EXACT_REPAIR_GUARDIAN_PHYSICAL_IDENTITY')
    return value


def first_guardian(cut, source_sha256, old_guardian, failed, sent_at):
    """One initial exec window starts before START, shorter than RestartSec15."""
    require_bound()
    C = cut.C; deadline = sent_at + 2; seen = None
    while time.monotonic() < deadline:
        p = cut.properties(C.GUARD, seconds=max(.001, min(.5, deadline-time.monotonic())))
        need(p['NRestarts'] in ('0', str(FAILED_RESTARTS)) and p['ActiveState'] in ('active', 'activating')
             and p['SubState'] in ('start', 'start-post', 'running') and p['Result'] == 'success', 'ONLY_INITIAL_REPAIR_EXEC_HANDOFF')
        if p['MainPID'] != '0':
            need(p['MainPID'].isdigit() and int(p['MainPID']) > 1 and p['ExecMainPID'] == p['MainPID'], 'ONE_REPAIR_START_PROCESS')
            pid = int(p['MainPID']); raw = cut.proc_bytes('/proc/%d/stat' % pid)
            value = {'boot_id': old_guardian['boot_id'], 'pid': pid,
                     'start_ticks': int(raw[raw.rfind(b')')+1:].split()[19]), 'InvocationID': p['InvocationID'],
                     'ExecMainStartTimestampMonotonic': p['ExecMainStartTimestampMonotonic']}
            C.identity(value)
            need(value['pid'] != old_guardian['pid'] and value['InvocationID'] not in (old_guardian['InvocationID'], failed['InvocationID']), 'DISTINCT_REPAIR_GUARDIAN_INVOCATION')
            if seen is None: seen = (value, int(p['NRestarts']))
            need(seen == (value, int(p['NRestarts'])), 'ONE_EXEC_HANDOFF_NO_RESTART')
            if p['ActiveState'] == 'active' and p['SubState'] == 'running':
                observe_guardian(cut, source_sha256, value, seen[1])
                need(time.monotonic() <= deadline, 'REPAIR_INITIAL_EXEC_WITHIN_TWO_SECONDS')
                return value, seen[1]
        time.sleep(min(.02, max(0, deadline-time.monotonic())))
    raise RuntimeError('REPAIR_INITIAL_EXEC_CEILING_NO_SECOND_START')


def validate_repair_return(cut, folder, manifest, returned, run):
    require_bound()
    C = cut.C
    closed(returned, 'schema status result automatic_replay Guest_or_Core_business_authority', 'CLOSED_REPAIR_RETURN')
    need(returned['schema'] == REPAIR_SCHEMA and returned['status'] == 'GUARDIAN_SOURCE_REPAIR_OK'
         and returned['automatic_replay'] is False and returned['Guest_or_Core_business_authority'] is False, 'EXACT_GUARDIAN_FORWARD_REPAIR_NOT_SWAP_SUCCESS')
    result = returned['result']; repair = result['repair']
    closed(repair, 'schema failed_swap_manifest_sha256 failed_swap_originals failed_guardian_restart_count repair_claim_ref repair_helper_ref', 'CLOSED_REPAIR_EVIDENCE')
    need(repair['schema'] == EVIDENCE_SCHEMA and repair['failed_swap_manifest_sha256'] == FAILED_MANIFEST_SHA256
         and repair['failed_guardian_restart_count'] == FAILED_RESTARTS, 'EXACT_SINGLE_FAILED_SWAP_REPAIR_CASE')
    originals = original_swap(cut, repair['failed_swap_originals'])
    need(result['controller'] == originals['controller_commit']['identity']
         and result['source_commit'] == manifest['source_commit'] == OPS_SOURCE
         and result['new_guardian_source_sha256'] == GUARDIAN_SOURCE_SHA256
         and result['controller_config_sha256'] == CONTROLLER_CONFIG_SHA256,
         'SAME_ORIGINAL_C14_CONTROLLER_NO_NEW_LIFETIME_OR_PAIR')
    claim = C.loads(reference(C, repair['repair_claim_ref']))
    closed(claim, 'schema failed_swap_manifest_sha256 failed_swap_originals controller new_manifest_sha256 script_sha256 config_sha256 run automatic_replay', 'CLOSED_CONSUMED_REPAIR_CLAIM')
    need(repair['repair_claim_ref']['path'] == str(C.STATE / ('GUARDIAN-SOURCE-REPAIR-FROM-' + FAILED_MANIFEST_SHA256 + '-POSSIBLE.json'))
         and claim['schema'] == 'g14_guardian_source_repair_possible_v1' and claim['failed_swap_manifest_sha256'] == FAILED_MANIFEST_SHA256
         and claim['failed_swap_originals'] == repair['failed_swap_originals'] and claim['controller'] == result['controller']
         and claim['automatic_replay'] is False and claim['new_manifest_sha256'] == PACKAGE_SHA256
         and claim['script_sha256'] == repair['repair_helper_ref']['sha256'] and claim['config_sha256'] == CONFIG_SHA256
         and Path(claim['run']).parent == C.STATE and re.fullmatch('guardian-source-repair-[a-f0-9-]{36}',Path(claim['run']).name),
         'SAME_CONSUMED_SEMANTIC_REPAIR_ONCE')
    need(repair['repair_helper_ref']['path'] == str(Path(__file__).absolute())
         and C.sha(reference(C, repair['repair_helper_ref'])) == repair['repair_helper_ref']['sha256'], 'EXACT_PINNED_REPAIR_HELPER')
    observe_guardian(cut, GUARDIAN_SOURCE_SHA256, result['guardian'], result['guardian_restart_baseline'])
    return repair


def repair_backend_type(cut):
    C = cut.C
    class RepairBackend(cut.Backend):
        def preconditions(self):
            need(time.monotonic()-self.started < 90, 'EXISTING_PRE_SEND_NINETY_SECONDS')
            self.originals = original_swap(cut, self.cfg['failed_swap_originals'])
            need(self.cfg['current_controller'] == self.originals['controller_commit']['identity']
                 and self.new_controller == self.m['expected_controller_identity'] == self.cfg['current_controller']
                 and self.old_guardian == self.originals['before']['guardian'], 'ROOT_EXACT_CURRENT_CONTROLLER_AND_ORIGINAL_G13_GUARDIAN')
            need(cut.physical_identity(C.CTRL, cut.controller_argv(C.NEW_CONFIG)) == self.new_controller, 'LIVE_UNCHANGED_C14_CONTROLLER')
            for name, pin in FAILED_UNITS.items():
                need(C.sha(C.read(C.UNIT_DIR/name,32768)) == pin, 'EXACT_FAILED_SWAP_INSTALLED_UNITS')
            need(C.sha(C.read(C.UNIT_DIR/C.HUB,32768)) == C.OLD_UNIT_SHAS[C.HUB]
                 and C.sha(C.read(C.DROPIN,4096)) == C.DROPIN_SHA, 'UNCHANGED_HUB_UNIT_AND_CPU_OVERRIDE')
            need(C.sha(C.read(FAILED_SOURCE/'network_guardian.py',1<<20)) == FAILED_SOURCE_SHA256, 'FAILED_V1_SOURCE_BYTES_PRESERVED')
            self.failed = self.originals['failed_guardian_descriptor']; self.failed_state()
            self.oneshots = {}
            for name in (C.COLD,C.HUB):
                p = cut.properties(name)
                need(p['ActiveState']=='active' and p['SubState']=='exited' and p['Result']=='success','ORIGINAL_COLD_HUB_COMPLETED')
                self.oneshots[name] = {k:p[k] for k in (*cut.IDENTITY_PROPS,'NRestarts','ActiveState','SubState','Result')}
            self.core_before = cut.core_overlap(); self.controller_inputs(); self.protected_before = self.protected()
            G = C.load_guardian(C.NEW_SOURCE,GUARDIAN_SOURCE_SHA256)
            need(len(C.read(C.NEW_SOURCE/'network_guardian.py',1<<20)) <= 131072,'ACTUAL_GUARDIAN_FITS_UNCHANGED_SELF_READ_CAP')
            full = {**self.new_controller,'cmdline_sha256':C.sha(b'\0'.join(v.encode()for v in cut.controller_argv(C.NEW_CONFIG))+b'\0'),'initial_R42_admitted_lifetime':False}
            key=C.sha(C.wire(full))
            need(not (C.LEDGER/(key+'-FIXED120-START.PUBLIC.json')).exists() and not (C.LEDGER/(key+'-QUALIFICATION-HOLD.PUBLIC.json')).exists()
                 and not (C.LEDGER/(key+'-QUALIFIED.PUBLIC.json')).exists(),'NO_PRIOR_CURRENT_CONTROLLER_WINDOW_REARM')
            self.journal=cut.Journal(self.run);self.probe=cut.Continuity(self.run,self.core_before,self.m['continuity_peer_ipv4'])
            until=time.monotonic()+30
            while time.monotonic()<until:
                need(cut.physical_identity(C.CTRL,cut.controller_argv(C.NEW_CONFIG))==self.new_controller,'SAME_CONTROLLER_SELECTING_EXISTING_TTL')
                commits=[(row,cut.complete_commit(rec))for row,rec in self.journal.joined(self.new_controller)]
                commits=[(r,v)for r,v in commits if v]
                if commits:
                    row,v=commits[-1]
                    if v['render_started']+v['minimum_all_ttl_ms']/1000-time.monotonic()>=3.5:
                        self.first_commit=v;self.record_once('FRESH-UNCHANGED-CONTROLLER-COMMIT.json',{'original':row,'measured':v});return
                time.sleep(.05)
            raise RuntimeError('NO_FRESH_CURRENT_CONTROLLER_COMPLETE_COMMIT')

        def failed_state(self, loaded_new=False):
            p=cut.properties(C.GUARD)
            for name in ('LoadState','ActiveState','SubState','Result','MainPID','ExecMainPID','NRestarts','InvocationID','ExecMainStartTimestampMonotonic','FragmentPath','DropInPaths','Restart'):
                need(p[name]==self.failed[name],'FAILED_V1_DESCRIPTOR_UNCHANGED_BEFORE_ONE_START')
            expected=cut.guardian_argv(C.NEW_SOURCE,GUARDIAN_SOURCE_SHA256)if loaded_new else cut.guardian_argv(FAILED_SOURCE,FAILED_SOURCE_SHA256)
            need(all(v in p['ExecStart']for v in expected),'EXACT_FAILED_OR_NEW_LOADED_GUARDIAN_DEFINITION')
            cg=Path('/sys/fs/cgroup/system.slice')/C.GUARD/'cgroup.procs'
            need(not cg.exists()or not cut.proc_bytes(cg,65536).strip(),'FAILED_GUARDIAN_CGROUP_EMPTY_NO_INVENTED_DEAD_PID')
            need(cut.physical_identity(C.CTRL,cut.controller_argv(C.NEW_CONFIG))==self.new_controller,'SAME_C14_CONTROLLER_BEFORE_REPAIR_EFFECT')

        def claim_once(self):
            self.repair_claim=C.STATE/('GUARDIAN-SOURCE-REPAIR-FROM-'+FAILED_MANIFEST_SHA256+'-POSSIBLE.json')
            C.once(self.repair_claim,C.wire({'schema':'g14_guardian_source_repair_possible_v1','failed_swap_manifest_sha256':FAILED_MANIFEST_SHA256,
                'failed_swap_originals':self.cfg['failed_swap_originals'],'controller':self.new_controller,'new_manifest_sha256':self.pin,
                'script_sha256':C.sha(C.read(__file__,1<<20,0o600)),'config_sha256':CONFIG_SHA256,'run':str(self.run),'automatic_replay':False}))

        def install_future_units(self):
            self.failed_state()
            for unit in(C.COLD,C.GUARD):
                self.failed_state();self.cas(unit,FAILED_UNITS[unit],C.read(self.folder/'units'/unit,32768))

        def validate_static_owner(self):
            self.failed_state(loaded_new=True)
            G=C.load_guardian(C.NEW_SOURCE,GUARDIAN_SOURCE_SHA256)
            owner=G.Owner(GUARDIAN_SOURCE_SHA256)
            full={**self.new_controller,'cmdline_sha256':C.sha(b'\0'.join(v.encode()for v in cut.controller_argv(C.NEW_CONFIG))+b'\0'),'initial_R42_admitted_lifetime':False}
            need(owner.identity()==full and C.sha(owner.raw_config)==self.standing_pin
                 and self.protected()==self.protected_before,'ACTUAL_PINNED_OWNER_SELF_STANDING_ANCESTRY_AND_SAME_CONTROLLER')
            key=owner.key(full)
            need(not(C.LEDGER/(key+'-FIXED120-START.PUBLIC.json')).exists()
                 and not(C.LEDGER/(key+'-QUALIFICATION-HOLD.PUBLIC.json')).exists()
                 and not(C.LEDGER/(key+'-QUALIFIED.PUBLIC.json')).exists(),'STATIC_CONSTRUCTOR_CREATED_NO_RUNTIME_QUALIFICATION')
            self.failed_state(loaded_new=True)
            self.record_once('STATIC-OWNER-VALIDATION.json',{'source_sha256':GUARDIAN_SOURCE_SHA256,
                'standing_sha256':self.standing_pin,'controller':self.new_controller,'constructor_completed':True,
                'watch_or_qualification_or_recovery_invoked':False,'runtime_health_or_full120_or_current15_credit':False})

        def wait_new_guardian(self):
            self.new_guardian,self.restart_baseline=first_guardian(cut,GUARDIAN_SOURCE_SHA256,self.old_guardian,self.failed,self.start_sent_at)
            deadline=time.monotonic()+240
            full={**self.new_controller,'cmdline_sha256':C.sha(b'\0'.join(v.encode()for v in cut.controller_argv(C.NEW_CONFIG))+b'\0'),'initial_R42_admitted_lifetime':False}
            key=C.sha(C.wire(full))
            while time.monotonic()<deadline:
                need(cut.physical_identity(C.CTRL,cut.controller_argv(C.NEW_CONFIG))==self.new_controller,'SAME_EXISTING_CONTROLLER_ACROSS_FRESH120')
                observe_guardian(cut,GUARDIAN_SOURCE_SHA256,self.new_guardian,self.restart_baseline)
                need(not(C.LEDGER/(key+'-QUALIFICATION-HOLD.PUBLIC.json')).exists(),'ORIGINAL_QUALIFICATION_HOLD_NEVER_REARMED')
                pub=C.LEDGER/(self.new_guardian['boot_id']+'-GUARDIAN-'+self.new_guardian['InvocationID']+'-FIRST-CURRENT15-RETURN.PUBLIC.json')
                if pub.exists():
                    raw=C.read(pub,16<<20,0o600);v=C.loads(raw)
                    need(v['schema']=='Root_owning_finite512_current15_readonly_observation_v1'and v['source_sha256']==GUARDIAN_SOURCE_SHA256
                         and v['standing_config_sha256']==self.standing_pin and v['identity']==full and v['measurement']['qualified_15_seconds']is True
                         and v['measurement']['all_requested_rows_accounted_for']is True and v['kernel']['all_four_backends_and_reverse_sources_positive']is True,'OWN_REPAIR_GUARDIAN_CURRENT15')
                    self.publication_ref={'path':str(pub),'sha256':C.sha(raw)};G=C.load_guardian(C.NEW_SOURCE,GUARDIAN_SOURCE_SHA256);owner=G.Owner(GUARDIAN_SOURCE_SHA256)
                    need(owner.identity()==full and owner.original_qualification_measurement(full)is not None,'RECOMPUTED_NATURAL_EXISTING_CONTROLLER_FULL120')
                    obs,prefix,suffix,reads=owner.current15_readonly()
                    need(obs['identity']==full and obs['measurement']['qualified_15_seconds']is True and obs['measurement']['all_requested_rows_accounted_for']is True
                         and obs['kernel']['all_four_backends_and_reverse_sources_positive']is True,'FRESH_INDEPENDENT_REPAIR_CURRENT15')
                    observe_guardian(cut,GUARDIAN_SOURCE_SHA256,self.new_guardian,self.restart_baseline)
                    C.once(self.run/'INDEPENDENT-CURRENT15-PREFIX.JSONL',prefix);C.once(self.run/'INDEPENDENT-CURRENT15-CLOSING.JSONL',suffix)
                    self.record_once('INDEPENDENT-CURRENT15.json',{'observation':obs,'native_read_count':len(reads),'own_daemon_first_ref':self.publication_ref,'actual_existing_controller_full120_recomputed':True})
                    p=C.LEDGER/(key+'-QUALIFIED.PUBLIC.json');self.full120_ref={'path':str(p),'sha256':C.sha(C.read(p,16<<20,0o600))};return
                time.sleep(1)
            raise RuntimeError('EXISTING_FULL120_AND_NEW_OWN15_CEILING_NO_SECOND_START')

        def final_closure(self):
            self.files(successor=True)
            need(cut.physical_identity(C.CTRL,cut.controller_argv(C.NEW_CONFIG))==self.new_controller,'SAME_C14_CONTROLLER_THROUGH_REPAIR_CLOSURE')
            observe_guardian(cut,GUARDIAN_SOURCE_SHA256,self.new_guardian,self.restart_baseline)
            need(C.sha(C.read(C.NEW_STANDING,32768,0o600))==self.standing_pin
                 and C.sha(C.read(self.publication_ref['path'],16<<20,0o600))==self.publication_ref['sha256']
                 and C.sha(C.read(self.full120_ref['path'],16<<20,0o600))==self.full120_ref['sha256'],'UNCHANGED_NEW_ORIGINAL_FULL120_OWN15_STANDING')
            for name in(C.COLD,C.HUB):
                p=cut.properties(name);need({k:p[k]for k in self.oneshots[name]}==self.oneshots[name],'COLD_HUB_ORIGINAL_LIFETIMES_UNCHANGED')
            need(self.protected()==self.protected_before and cut.core_overlap()==self.core_before,'SAME43_BUDGET1_AND_CORE4')
            for path,dev,ino in self.locks:
                s=path.lstat();need((s.st_dev,s.st_ino)==(dev,ino),'SAME_OPERATION_MUTEX_INODES')
            commits=[cut.complete_commit(rec)for _,rec in self.journal.joined(self.new_controller)];commits=[v for v in commits if v and v['native_apply_returned']>=self.first_commit['native_apply_returned']]
            need(len(commits)>=2 and commits[0]==self.first_commit,'ORIGINAL_CURRENT_CONTROLLER_COMMITS_COVER_REPAIR')
            self.gaps={k:0 for k in self.first_commit['ttl_ms']}
            for a,b in zip(commits,commits[1:]):
                need(set(a['ttl_ms'])==set(b['ttl_ms'])and b['commit_sequence']>a['commit_sequence'],'SAME_ALL_ROLE_KNOWN_CONTROLLER_COMMIT_CHAIN')
                for k,ttl in a['ttl_ms'].items():self.gaps[k]=max(self.gaps[k],max(0,b['native_apply_returned']-a['render_started']-ttl/1000))
            need(all(v==0 for v in self.gaps.values()),'NO_CONSERVATIVE_ROLE_GAP_DURING_REPAIR_INTERVAL')
            self.probe.close();continuity=self.probe.summary()
            helper={'path':str(Path(__file__).absolute()),'sha256':C.sha(C.read(__file__,1<<20,0o600))}
            return {'source_commit':self.m['source_commit'],'source_R':C.SOURCE_R,'amd64_D':C.NEW_DIGEST,'new_guardian_source_sha256':GUARDIAN_SOURCE_SHA256,
                'standing_sha256':self.standing_pin,'controller_config_sha256':C.HEAD_CONFIG_SHA,'controller':self.new_controller,'guardian':self.new_guardian,
                'actual_new_full120_ref':self.full120_ref,'own_daemon_first_current15_ref':self.publication_ref,'independent_current15':True,
                'all_inherited_budget_and_original_refs_unchanged':True,'continuity':continuity,'conservative_per_role_gap_seconds':self.gaps,
                'Core_Cold_Hub_or_provider_mutation':False,'guardian_restart_baseline':self.restart_baseline,
                'repair':{'schema':EVIDENCE_SCHEMA,'failed_swap_manifest_sha256':FAILED_MANIFEST_SHA256,'failed_swap_originals':self.cfg['failed_swap_originals'],
                    'failed_guardian_restart_count':FAILED_RESTARTS,'repair_claim_ref':{'path':str(self.repair_claim),'sha256':C.sha(C.read(self.repair_claim,1<<20,0o600))},'repair_helper_ref':helper}}
    return RepairBackend


def repair_once(cut, backend):
    require_bound()
    try:
        backend.preconditions();backend.claim_once();backend.install_future_units();backend.install_standing_once();backend.failed_state()
        cut.send_once(backend,*REPAIR_SEQUENCE[0],seconds=30);backend.failed_state(loaded_new=True);backend.validate_static_owner()
        backend.start_sent_at=time.monotonic();cut.send_once(backend,*REPAIR_SEQUENCE[1],seconds=30)
        backend.wait_new_guardian();result=backend.final_closure()
        backend.record_once('RETURN.json',{'schema':REPAIR_SCHEMA,'status':'GUARDIAN_SOURCE_REPAIR_OK','result':result,'automatic_replay':False,'Guest_or_Core_business_authority':False})
        return result
    except Exception as error:
        backend.record_once('HOLD.json',{'schema':'g14_guardian_source_forward_repair_HOLD_v1','guard':str(error)[:180],
            'error_class':type(error).__name__,'automatic_replay':False,'no_unit_Core_or_provider_cleanup':True})
        raise


def main():
    require_bound()
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--package',required=True,type=Path);p.add_argument('--config',required=True,type=Path)
    p.add_argument('--expected-script-sha256',required=True);p.add_argument('--evidence-dir',required=True,type=Path);p.add_argument('--execute-once',required=True,action='store_true');a=p.parse_args()
    need(os.geteuid()==0 and sys.platform=='linux'and not sys.flags.optimize,'ROOT_LINUX_UNOPTIMIZED_ONLY')
    raw=Path(__file__).read_bytes();need(digest(a.expected_script_sha256)and hashlib.sha256(raw).hexdigest()==a.expected_script_sha256,'ROOT_REVIEWED_REPAIR_SOURCE_BYTES')
    for name,pin in TOOL_PINS.items():need(hashlib.sha256((a.package/'tools'/name).read_bytes()).hexdigest()==pin,'EXACT_REVIEWED_G14_TOOL_BYTES')
    path=a.package/'tools/g14cut.py';cut=types.ModuleType('qualified_g14_cut_for_guardian_repair');cut.__file__=str(path);exec(compile(path.read_bytes(),str(path),'exec'),cut.__dict__);C=cut.C
    folder,m=C.package(a.package,PACKAGE_SHA256)
    need(m['source_commit']==OPS_SOURCE and m['files']['source/network_guardian.py']==GUARDIAN_SOURCE_SHA256
         and m['controller_unit_sha256']==FAILED_UNITS[C.CTRL]and C.HEAD_CONFIG_SHA==CONTROLLER_CONFIG_SHA256,'QUALIFIED_NEW_SOURCE_SAME_C14_CONTROLLER_PACKAGE')
    cfgraw=C.read(a.config,4<<20,0o600);need(C.sha(cfgraw)==CONFIG_SHA256,'EXACT_ROOT_REPAIR_CONFIG');cfg=C.loads(cfgraw)
    closed(cfg,'schema current_controller failed_swap_originals','CLOSED_GUARDIAN_FORWARD_REPAIR_CONFIG');need(cfg['schema']=='root_g14_guardian_source_forward_repair_config_v1','EXACT_REPAIR_CONFIG_SCHEMA')
    run=a.evidence_dir.absolute();need(run.parent==C.STATE and re.fullmatch('guardian-source-repair-[a-f0-9-]{36}',run.name),'NEW_REPAIR_EVIDENCE_LEAF')
    C.private_dir(run,create=True);backend=None
    def stop(number,frame):raise RuntimeError('SIGNAL_HOLD_NO_AUTOMATIC_REPLAY')
    for sig in(signal.SIGALRM,signal.SIGTERM,signal.SIGINT,signal.SIGHUP):signal.signal(sig,stop)
    signal.setitimer(signal.ITIMER_REAL,420)
    try:
        with cut.custody()as locks:
            # Same Source standing builder, first using private staged unit bytes.
            units=run/'units';C.private_dir(units,create=True);C.once(units/C.CTRL,C.read(folder/'controller.service',32768))
            for name in(C.COLD,C.GUARD):C.once(units/name,C.read(folder/'units'/name,32768))
            deriv=cut.sibling('derive_standing_config');standing=run/'STAGED-STANDING.json';out,expected=deriv.derive(folder,m,units,standing)
            pin=C.validate_standing_output(out,expected,'staged');staged={'standing_sha256':pin,'staged_standing_path':str(standing)}
            backend=repair_backend_type(cut)(folder,m,PACKAGE_SHA256,run,staged,locks,{})
            backend.cfg=cfg;backend.new_controller=cfg['current_controller'];repair_once(cut,backend)
    finally:
        if backend is not None:backend.close()
        signal.setitimer(signal.ITIMER_REAL,0)


if __name__=='__main__':
    main()
