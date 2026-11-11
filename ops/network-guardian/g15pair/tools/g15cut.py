"""G15-only one-shot operational CLI: stage, qualify, preconditions, swap-once.

No import-time/native action. Every consequential native submission has a
previous durable possible-send and one actual return; uncertainty is HOLD.
There is no rollback, reset, resume, legacy mode or automatic second submission.
"""
import argparse
import collections
import contextlib
import errno
import fcntl
import types
import ipaddress
import json
import math
import os
from pathlib import Path
import selectors
import signal
import stat
import subprocess
import sys
import threading
import time


PROPOSAL_BOUND = True

def sibling(name):
    if PROPOSAL_BOUND is not True:
        raise RuntimeError('G15_UNBOUND_BEFORE_SOURCE_IO')
    # Compile the actual .py bytes, never an unauthenticated cached .pyc.
    path = Path(__file__).with_name(name + '.py')
    raw = path.read_bytes()
    module = types.ModuleType('g15_operational_' + name)
    module.__file__ = str(path)
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


C = sibling('pair_change_contract')
Hold = C.Hold
CTRL, GUARD, COLD, HUB = C.CTRL, C.GUARD, C.COLD, C.HUB
NATIVE_SEQUENCE = (
    ('STOP-OLD-GUARDIAN', ['/usr/bin/systemctl', 'stop', GUARD]),
    ('RELOAD-CONTROLLER-DEFINITION', ['/usr/bin/systemctl', 'daemon-reload']),
    ('STOP-OLD-CONTROLLER', ['/usr/bin/systemctl', 'stop', CTRL]),
    ('START-NEW-CONTROLLER', ['/usr/bin/systemctl', 'start', CTRL]),
    ('RELOAD-FUTURE-UNITS', ['/usr/bin/systemctl', 'daemon-reload']),
    ('START-NEW-GUARDIAN', ['/usr/bin/systemctl', 'start', GUARD]),
)
PROPERTIES = 'LoadState,ActiveState,SubState,Result,MainPID,ExecMainPID,NRestarts,InvocationID,ExecMainStartTimestampMonotonic,ControlGroup,FragmentPath,DropInPaths,Restart,ExecStart'
KUBE = ['/usr/local/bin/k3s', 'kubectl', '--kubeconfig=/etc/rancher/k3s/k3s.yaml', '--request-timeout=8s']
IDENTITY_PROPS = ('MainPID', 'ExecMainPID', 'InvocationID', 'ExecMainStartTimestampMonotonic')
OPERATION_LOCK = Path('/var/lib/dakasa-capacity-network-r13-cutover/operation.lock')


def send_once(backend, name, argv, seconds=20):
    C.require_bound()
    """This is the effect boundary used by the actual CLI and remote CI tests."""
    allowed = dict(NATIVE_SEQUENCE)
    C.need(name in allowed and argv == allowed[name], 'CLOSED_G15_NATIVE_SUBMISSION')
    backend.record_once(name + '-POSSIBLE-SEND.json', {'schema': 'g15_native_possible_send_v1', 'name': name, 'argv': argv,
                        'retry': False, 'native_return_is_not_qualification': True})
    try:
        result = backend.native(argv, seconds)
    except Exception as error:
        backend.record_once(name + '-NATIVE-RETURN.json', {'schema': 'g15_native_return_uncertain_v1', 'name': name,
                            'error_class': type(error).__name__, 'acknowledgement_uncertain': True, 'retry': False})
        raise Hold('NATIVE_ACK_UNCERTAIN_' + name) from error
    backend.record_once(name + '-NATIVE-RETURN.json', {'schema': 'g15_native_return_v1', 'name': name, 'exit_code': result.returncode,
                        'stdout_sha256': C.sha(result.stdout), 'stdout_bytes': len(result.stdout),
                        'stderr_sha256': C.sha(result.stderr), 'stderr_bytes': len(result.stderr), 'retry': False})
    C.need(result.returncode == 0, 'ORIGINAL_NATIVE_NONZERO_' + name)
    return result


def swap_once(backend):
    C.require_bound()
    """One fixed forward attempt. Failure never invokes another mutating method."""
    try:
        backend.preconditions()
        backend.claim_once()
        backend.quiescent_guardian()
        send_once(backend, *NATIVE_SEQUENCE[0])
        backend.assert_old_guardian_absent()
        backend.cas_controller_once()
        send_once(backend, *NATIVE_SEQUENCE[1], seconds=30)
        backend.verify_controller_definition()
        backend.fresh_window()
        send_once(backend, *NATIVE_SEQUENCE[2])
        backend.assert_old_controller_absent()
        backend.controller_inputs()
        send_once(backend, *NATIVE_SEQUENCE[3])
        backend.wait_new_controller()
        backend.cas_future_units_once()
        backend.install_standing_once()
        send_once(backend, *NATIVE_SEQUENCE[4], seconds=30)
        send_once(backend, *NATIVE_SEQUENCE[5], seconds=30)
        backend.wait_new_guardian()
        result = backend.final_closure()
        backend.record_once('RETURN.json', {'schema': 'g15_pair_swap_return_v1', 'status': 'CONFIG_SWAP_OK', 'result': result,
                            'automatic_replay': False, 'Guest_or_Core_business_authority': False})
        return result
    except Exception as error:
        # Recording a HOLD cannot authorize any follow-up native action.
        backend.record_once('HOLD.json', {'schema': 'g15_pair_swap_HOLD_v1', 'guard': str(error)[:180],
                            'error_class': type(error).__name__, 'automatic_replay': False,
                            'actual_process_unit_and_receipt_reconciliation_required': True})
        raise


def native(argv, seconds=20, cap=32 << 20):
    p = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         cwd='/', start_new_session=True,
                         env={'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8'})
    chunks = {'stdout': [], 'stderr': []}; sizes = {'stdout': 0, 'stderr': 0}
    deadline = time.monotonic() + seconds
    try:
        with selectors.DefaultSelector() as selector:
            for name in ('stdout', 'stderr'):
                pipe = getattr(p, name); os.set_blocking(pipe.fileno(), False)
                selector.register(pipe, selectors.EVENT_READ, name)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(argv, seconds, b''.join(chunks['stdout']), b''.join(chunks['stderr']))
                for key, _ in selector.select(min(.1, remaining)):
                    name = key.data
                    data = os.read(key.fileobj.fileno(), 65536)
                    if not data:
                        selector.unregister(key.fileobj); key.fileobj.close()
                        continue
                    sizes[name] += len(data)
                    C.need(sizes[name] <= (cap if name == 'stdout' else 262144), 'BOUNDED_NATIVE_RETURN')
                    chunks[name].append(data)
        code = p.wait(timeout=max(.001, deadline - time.monotonic()))
    except BaseException:
        # Only this local client group is killed. PID1-owned units are separate.
        try:
            os.killpg(p.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        p.wait(timeout=5)
        raise
    finally:
        for name in ('stdout', 'stderr'):
            getattr(p, name).close()
    return subprocess.CompletedProcess(argv, code, b''.join(chunks['stdout']), b''.join(chunks['stderr']))


def properties(unit, seconds=8):
    C.need(unit in C.UNITS, 'CLOSED_OWNED_UNIT')
    r = native(['/usr/bin/systemctl', 'show', unit, '--property=' + PROPERTIES], seconds)
    C.need(r.returncode == 0, 'SYSTEMD_READ_ZERO')
    return dict(line.split('=', 1) for line in r.stdout.decode().splitlines())


def proc_bytes(path, cap=4096):
    # procfs reports size0/nlink0; the PID/startticks/command are checked together.
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        raw = os.read(fd, cap + 1)
        C.need(len(raw) <= cap, 'BOUNDED_PROC_READ')
        return raw
    finally:
        os.close(fd)


def physical_identity(unit, argv):
    p = properties(unit)
    C.need(p['ActiveState'] == 'active' and p['SubState'] == 'running' and p['Result'] == 'success' and p['NRestarts'] == '0'
           and p['MainPID'] == p['ExecMainPID'] and p['MainPID'].isdigit() and int(p['MainPID']) > 1, 'ACTIVE_ZERO_RESTART_PHYSICAL_UNIT')
    pid = int(p['MainPID'])
    raw = proc_bytes('/proc/%d/stat' % pid)
    ticks = int(raw[raw.rfind(b')') + 1:].split()[19])
    C.need(proc_bytes('/proc/%d/cmdline' % pid) == b'\0'.join(v.encode() for v in argv) + b'\0', 'EXACT_PHYSICAL_PROCESS_COMMAND')
    value = {'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(), 'pid': pid, 'start_ticks': ticks,
             'InvocationID': p['InvocationID'], 'ExecMainStartTimestampMonotonic': p['ExecMainStartTimestampMonotonic']}
    C.identity(value)
    C.need(p['FragmentPath'] == str(C.UNIT_DIR / unit) and p['DropInPaths'] == (str(C.DROPIN) if unit == CTRL else '')
           and p['Restart'] == ('no' if unit == CTRL else 'on-failure'), 'EXACT_FRAGMENT_AND_KNOWN_DROPIN')
    return value


def controller_argv(config):
    return ['/usr/bin/python3', '-B', str(C.RUNTIME / 'controller.py'), '--config', str(config), '--run']


def guardian_argv(source, pin):
    return ['/usr/bin/python3', '-B', str(source / 'network_guardian.py'), '--watch', '--source-sha256', pin]


def wait_exec_identity(unit, argv, deadline, old):
    """Observe one Type=simple fork→exec handoff for at most2s; never START."""
    until = min(deadline, time.monotonic() + 2)
    seen = None
    expected_cmd = b'\0'.join(value.encode() for value in argv) + b'\0'
    while time.monotonic() < until:
        remaining = until - time.monotonic()
        p = properties(unit, seconds=max(.001, min(.5, remaining)))
        C.need(p['LoadState'] == 'loaded' and p['FragmentPath'] == str(C.UNIT_DIR / unit)
               and p['DropInPaths'] == (str(C.DROPIN) if unit == CTRL else '')
               and p['Restart'] == ('no' if unit == CTRL else 'on-failure') and p['NRestarts'] == '0', 'EXACT_UNCHANGED_STARTUP_UNIT_SHAPE')
        C.need(p['ActiveState'] in ('active', 'activating') and p['SubState'] in ('start', 'start-post', 'running')
               and p['Result'] == 'success', 'ONLY_INITIAL_EXEC_HANDOFF_NOT_FAILED_INACTIVE_OR_RESTART')
        if p['MainPID'] == '0':
            C.need(seen is None and p['ActiveState'] == 'activating' and p['ExecMainPID'] in ('0', str(old['pid'])), 'NO_OBSERVED_NEW_PROCESS_MAY_DISAPPEAR')
        else:
            C.need(p['MainPID'].isdigit() and int(p['MainPID']) > 1 and p['ExecMainPID'] == p['MainPID'], 'ONE_OBSERVED_STARTUP_PROCESS')
            pid = int(p['MainPID'])
            raw = proc_bytes('/proc/%d/stat' % pid)
            ticks = int(raw[raw.rfind(b')') + 1:].split()[19])
            value = {'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(), 'pid': pid, 'start_ticks': ticks,
                     'InvocationID': p['InvocationID'], 'ExecMainStartTimestampMonotonic': p['ExecMainStartTimestampMonotonic']}
            C.identity(value)
            C.need(value['boot_id'] == old['boot_id'] and value['pid'] != old['pid'] and value['InvocationID'] != old['InvocationID'], 'ACTUAL_NEW_STARTUP_LIFETIME_SAME_BOOT')
            if seen is None:
                seen = value
            C.need(value == seen, 'SAME_NEW_PID_INVOCATION_AND_STARTTICKS_DURING_EXEC_HANDOFF')
            if proc_bytes('/proc/%d/cmdline' % pid) == expected_cmd and p['ActiveState'] == 'active' and p['SubState'] == 'running':
                return value
        time.sleep(min(.02, max(0, until - time.monotonic())))
    raise Hold('BOUNDED_INITIAL_EXEC_HANDOFF_EXHAUSTED_NO_SECOND_START')


def assert_absent(unit, old):
    p = properties(unit)
    C.need(p['ActiveState'] == 'inactive' and p['MainPID'] == '0' and p['ExecMainPID'] in ('0', str(old['pid'])) and not Path('/proc/%d' % old['pid']).exists(), 'EXACT_OLD_PROCESS_ABSENT_AFTER_ACK')
    cgroup = Path('/sys/fs/cgroup/system.slice') / unit / 'cgroup.procs'
    C.need(not cgroup.exists() or not proc_bytes(cgroup, 65536).strip(), 'STOPPED_CGROUP_EMPTY')


@contextlib.contextmanager
def custody():
    """Hold both existing locks nonblocking; no lock file is created or replaced."""
    fds, facts = [], []
    try:
        for path in (OPERATION_LOCK, C.MAINTENANCE):
            fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
            fds.append(fd)
            s = os.fstat(fd)
            C.need(stat.S_ISREG(s.st_mode) and s.st_uid == 0 and s.st_nlink == 1 and stat.S_IMODE(s.st_mode) == 0o600, 'EXACT_EXISTING_OPERATION_MUTEX')
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            facts.append((path, s.st_dev, s.st_ino))
        yield facts
        for path, dev, ino in facts:
            s = path.lstat()
            C.need((s.st_dev, s.st_ino) == (dev, ino), 'SAME_OPERATION_MUTEX_INODES_THROUGH_CLOSURE')
    finally:
        for fd in reversed(fds):
            os.close(fd)


class Journal:
    """Bounded original journal stream, exact native unit/boot/PID/Invocation joins."""
    def __init__(self, run):
        self.run, self.rows, self.error = run, [], None
        self.lock = threading.Lock()
        self.fd = os.open(run / 'CONTROLLER-ORIGINAL.JSONL', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        self.p = subprocess.Popen(['/usr/bin/journalctl', '-u', CTRL, '-o', 'json', '--all', '-f', '-n', '0', '--no-pager'],
                                  stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, cwd='/')
        self.thread = threading.Thread(target=self.collect, daemon=True)
        self.closed = False
        self.thread.start()

    def collect(self):
        size = 0
        try:
            while True:
                raw = self.p.stdout.readline(262145)
                if not raw:
                    return
                size += len(raw)
                C.need(len(raw) <= 262144 and size <= 64 << 20, 'BOUNDED_ORIGINAL_CONTROLLER_JOURNAL')
                row = C.loads(raw)
                with self.lock:
                    view = memoryview(raw)
                    while view:
                        n = os.write(self.fd, view)
                        C.need(n > 0, 'FULL_ORIGINAL_JOURNAL_WRITE')
                        view = view[n:]
                    self.rows.append(row)
        except Exception as error:
            self.error = error

    def joined(self, identity):
        C.need(self.error is None and self.p.poll() is None, 'ORIGINAL_JOURNAL_STREAM_LIVE')
        with self.lock:
            rows = list(self.rows)
        out = []
        for row in rows:
            if str(row.get('_PID')) == str(identity['pid']) and row.get('_SYSTEMD_INVOCATION_ID') == identity['InvocationID'] and row.get('_BOOT_ID') == identity['boot_id'].replace('-', ''):
                try:
                    out.append((row, C.loads(row['MESSAGE'])))
                except (ValueError, TypeError):
                    raise Hold('MALFORMED_EXACT_CONTROLLER_JOURNAL') from None
        return out

    def close(self):
        if self.closed:
            return
        self.closed = True
        if self.p.poll() is None:
            self.p.terminate()
        self.p.wait(timeout=8)
        self.thread.join(timeout=8)
        C.need(not self.thread.is_alive(), 'READONLY_JOURNAL_CLIENT_JOINED')
        os.fsync(self.fd); os.close(self.fd)


def complete_commit(rec):
    try:
        C.need(type(rec) is dict and rec.get('schema') == 'capacity_owned_nft_native_batch_v3' and rec.get('phase') == 'only_dynamic_elements' and rec.get('applied') is True, 'HOT_KNOWN_COMMIT')
        f = rec['original_native_command_facts']
        C.need(f['schema'] == 'capacity_netlink_hot_batch_v1' and f['committed'] is True and f['late'] is False, 'KNOWN_ON_TIME_NETLINK_COMMIT')
        ttl = {'backend:' + k: int(v['kernel_timeout_ms']) for k, v in rec['backend_freshness'].items()}
        ttl.update({'core_ready4:' + str(v['address']): int(v['kernel_timeout_ms']) for v in rec['core_source_freshness']})
        ttl.update({'prometheus_ready4:' + str(v['address']): int(v['kernel_timeout_ms']) for v in rec['prometheus_source_freshness']})
        C.need(all(ttl.get('backend:' + k, 0) > 0 for k in ('core', 'broker', 'rds', 'redis')) and len(rec['core_source_freshness']) >= 1 and len(rec['prometheus_source_freshness']) == 1
               and all(v > 0 for v in ttl.values()) and rec['backends_admitted'] == 4 and rec['prometheus_sources_admitted'] == 1 and rec['held_native_read_classes'] == {}, 'COMPLETE_FOUR_BACKENDS_AND_REVERSE_SOURCES')
        render, returned = float(rec['render_started']), float(rec['native_apply_returned'])
        C.need(all(math.isfinite(v) for v in (render, returned)) and 0 < render <= returned, 'FINITE_KNOWN_COMMIT_TIMES')
        return {'render_started': render, 'native_apply_returned': returned, 'ttl_ms': ttl, 'minimum_all_ttl_ms': min(ttl.values()), 'commit_sequence': rec['commit_sequence']}
    except (Hold, KeyError, TypeError, ValueError, OverflowError):
        return None


def core_overlap():
    C.require_bound()
    """Inspect only selected public fields; never persist Pod/Deployment env."""
    dep = native(KUBE + ['-n', 'dakasa', 'get', 'deployment', 'yggdrasil', '-o', 'json'], 12)
    pods = native(KUBE + ['-n', 'dakasa', 'get', 'pods', '-l', 'app=yggdrasil', '-o', 'json'], 12)
    C.need(dep.returncode == pods.returncode == 0, 'CORE_READONLY_CENSUS_ZERO')
    d, ps = C.loads(dep.stdout), C.loads(pods.stdout)['items']
    C.need(C.OLD_DIGEST == '85be238c7f5b15760f7eb903646cc48f6b4b86a6995d0a4727a1ba0d86d06876', 'EXACT_CURRENT_R6_OVERLAP_DIGEST')
    image = C.IMAGE_PREFIX + C.OLD_DIGEST
    C.need(d['metadata']['uid'] == C.OLD_CORE_UID and d['metadata'].get('annotations', {}).get('dakasa.io/core-source-commit') == C.OLD_CORE_SOURCE
           and d['metadata']['generation'] == C.OLD_CORE_GENERATION and not d['metadata'].get('deletionTimestamp')
           and d['spec'].get('replicas', 1) == 1 and d['status']['observedGeneration'] == d['metadata']['generation']
           and all(d['status'].get(k) == 1 for k in ('readyReplicas', 'availableReplicas', 'updatedReplicas'))
           and [(x['name'], x['image']) for x in d['spec']['template']['spec']['containers']] == [('core', image)], 'EXACT_READY_OVERLAP_CORE_TEMPLATE')
    C.need(len(ps) == 1, 'ONE_CORE_POD_NO_OLD_OR_EXTRA_POD')
    p = ps[0]
    C.need(p['metadata']['uid'] == C.OLD_CORE_POD_UID and p['metadata'].get('deletionTimestamp') is None and p['status']['phase'] == 'Running' and [(x['name'], x['image']) for x in p['spec']['containers']] == [('core', image)]
           and len(p['status']['containerStatuses']) == 1, 'ONE_CURRENT_OVERLAP_CORE_CONTAINER')
    s = p['status']['containerStatuses'][0]
    C.need(s['name'] == 'core' and s['ready'] is True and s['restartCount'] == 0 and s.get('state', {}).get('running') and s['imageID'].rsplit(':', 1)[-1] == C.OLD_DIGEST, 'EXACT_OVERLAP_AMD64_IMAGEID_ZERO_RESTART')
    return {'deployment_uid': d['metadata']['uid'], 'generation': d['metadata']['generation'], 'pod_uid': p['metadata']['uid'],
            'pod_name': p['metadata']['name'], 'pod_ip': p['status']['podIP'], 'image': image, 'imageID': s['imageID'], 'containerID': s['containerID']}


class Continuity:
    """Payload-free NEW TCP probes from the actual singleton Core netns."""
    CODE = "import errno,json,socket,sys,time;s=socket.socket();s.settimeout(1.0);t=time.monotonic();c=s.connect_ex((sys.argv[1],9447));s.close();print(json.dumps({'started':t,'finished':time.monotonic(),'errno':c,'path_ok':c in (0,errno.ECONNREFUSED)}))"

    def __init__(self, run, core, selected_peer):
        self.run, self.rows, self.error, self.stop = run, [], None, threading.Event()
        r = native(['/usr/local/bin/k3s', 'crictl', 'ps', '-o', 'json', '--name', '^core$', '--state', 'Running'], 10)
        C.need(r.returncode == 0, 'CORE_NATIVE_CONTAINER_READ_ZERO')
        matches = [v for v in C.loads(r.stdout)['containers'] if v.get('labels', {}).get('io.kubernetes.pod.uid') == core['pod_uid'] and v.get('labels', {}).get('io.kubernetes.container.name') == 'core']
        C.need(len(matches) == 1 and core['containerID'].split('://')[-1] == matches[0]['id'], 'EXACT_CORE_CONTAINER_FOR_CONTINUITY')
        r = native(['/usr/local/bin/k3s', 'crictl', 'inspect', '-o', 'json', matches[0]['id']], 10)
        C.need(r.returncode == 0, 'CORE_CONTAINER_PROCESS_READ_ZERO')
        value = C.loads(r.stdout); self.pid = int(value['info']['pid']); del value
        raw = proc_bytes('/proc/%d/stat' % self.pid)
        self.start_ticks = int(raw[raw.rfind(b')') + 1:].split()[19])
        r = native(['/usr/sbin/nft', '-j', 'list', 'set', 'inet', 'dakasa_capacity_network', 'peers4'], 8)
        C.need(r.returncode == 0, 'PUBLIC_PEERS_SET_READ_ZERO')
        peers = []
        for v in C.loads(r.stdout)['nftables']:
            for x in v.get('set', {}).get('elem', []):
                if isinstance(x, dict):
                    x = x.get('elem', x).get('val')
                peers.append(str(ipaddress.IPv4Address(x)))
        C.need(1 <= len(peers) <= 16, 'BOUNDED_REGISTERED_PEERS4')
        C.need(selected_peer in peers, 'ROOT_SELECTED_ACTUAL_HETZNER_PEER_IN_OWNED_PEERS4')
        self.peer = selected_peer
        C.need(self.attempt(self.peer)['path_ok'], 'LIVE_CORE_TO_EXACT_REVIEWED_HETZNER_PEER_9447_PATH')
        self.fd = os.open(run / 'CONTINUITY-ORIGINAL.JSONL', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        self.thread = threading.Thread(target=self.loop, daemon=True)
        self.closed = False
        self.thread.start()
        try:
            time.sleep(5)
            C.need(len(self.rows) >= 5 and all(v['path_ok'] for v in self.rows), 'POSITIVE_REAL_PATH_BASELINE')
        except BaseException:
            self.close()
            raise

    def attempt(self, peer):
        raw = proc_bytes('/proc/%d/stat' % self.pid)
        C.need(int(raw[raw.rfind(b')') + 1:].split()[19]) == self.start_ticks, 'SAME_CORE_NETNS_PROCESS')
        r = native(['/usr/bin/nsenter', '--target', str(self.pid), '--net', '--', '/usr/bin/python3', '-I', '-B', '-c', self.CODE, peer], 3)
        C.need(r.returncode == 0, 'CONTINUITY_READ_CLIENT_ZERO')
        row = C.loads(r.stdout)
        C.need(set(row) == {'started', 'finished', 'errno', 'path_ok'} and type(row['path_ok']) is bool, 'CLOSED_ORIGINAL_PATH_PROBE')
        return row

    def loop(self):
        try:
            while not self.stop.is_set():
                start = time.monotonic()
                row = self.attempt(self.peer)
                self.rows.append(row)
                os.write(self.fd, C.wire(row))
                if len(self.rows) >= 2400:
                    raise Hold('BOUNDED_CONTINUITY_WINDOW')
                self.stop.wait(max(0, .25 - (time.monotonic() - start)))
        except Exception as error:
            self.error = error

    def close(self):
        if self.closed:
            return
        self.closed = True
        self.stop.set(); self.thread.join(timeout=5)
        C.need(not self.thread.is_alive(), 'READONLY_PATH_PROBE_JOINED')
        os.fsync(self.fd); os.close(self.fd)

    def summary(self):
        C.need(self.error is None and self.rows and all(v['path_ok'] for v in self.rows), 'ACTUAL_CONTINUITY_PROBES_ALL_POSITIVE')
        return {'attempts': len(self.rows), 'path_ok': len(self.rows), 'failure': 0, 'peer': self.peer, 'port': 9447,
                'first_monotonic': self.rows[0]['started'], 'last_monotonic': self.rows[-1]['finished']}


class Backend:
    """Actual pinned Brain implementation, shared orchestration with CI seam."""
    def __init__(self, folder, manifest, manifest_sha, run, staged, lock_facts, qualification):
        self.folder, self.m, self.pin, self.run, self.staged, self.locks = folder, manifest, manifest_sha, run, staged, lock_facts
        self.qualification = qualification
        self.old_controller = manifest['expected_controller_identity']
        self.old_guardian = manifest['expected_guardian_identity']
        self.journal = None
        self.probe = None
        self.new_controller = None
        self.new_guardian = None
        self.started = time.monotonic()

    def record_once(self, name, value):
        C.need('/' not in name and name.endswith('.json'), 'FIXED_OPERATIONAL_RECEIPT_NAME')
        C.once(self.run / name, C.wire(value))

    def native(self, argv, seconds):
        return native(argv, seconds)

    def protected(self):
        out = {}
        for value in self.m['protected_refs']:
            actual = C.sha(C.read(value['path'], 64 << 20, 0o600))
            C.need(actual == value['sha256'], 'UNCHANGED_ACTUAL_ORIGINAL_PROTECTED_REF')
            out[value['path']] = actual
        markers = sorted(C.LEDGER.glob(self.old_controller['boot_id'] + '-RECOVERY-*-POSSIBLE-START.PUBLIC.json'))
        C.need(len(markers) == 1, 'ACTUAL_ONE_OF_THREE_INHERITED_NETWORK_RECOVERY_BUDGET')
        for path in markers:
            out[str(path)] = C.sha(C.read(path, 32768, 0o600))
        return out

    def controller_inputs(self):
        raw = C.read(C.NEW_CONFIG, 32768, 0o600)
        C.need(C.sha(raw) == C.HEAD_CONFIG_SHA, 'FRESH_EXACT_G15_CONTROLLER_CONFIG_BEFORE_EFFECT')
        G = C.load_guardian(C.NEW_SOURCE, self.m['files']['source/network_guardian.py'])
        pins = G.RUNTIME_HASHES
        C.need(type(pins) is dict and len(pins) == 14 and C.loads(raw)['source_files_sha256'] == pins
               and {p.name for p in C.RUNTIME.iterdir()} == set(pins)
               and all(C.sha(C.read(C.RUNTIME / name)) == pin for name, pin in pins.items()), 'FRESH_EXACT_IMMUTABLE_RUNTIME14_BEFORE_EFFECT')

    def files(self, successor=False):
        self.controller_inputs()
        expected = dict(C.OLD_UNIT_SHAS)
        if successor:
            expected.update({CTRL: self.m['controller_unit_sha256'], COLD: self.m['files']['units/' + COLD], GUARD: self.m['files']['units/' + GUARD]})
        for name, pin in expected.items():
            C.need(C.sha(C.read(C.UNIT_DIR / name, 32768)) == pin, 'EXACT_CURRENT_OWNED_UNIT_BYTES')
            props = properties(name)
            C.need(props['FragmentPath'] == str(C.UNIT_DIR / name) and props['DropInPaths'] == (str(C.DROPIN) if name == CTRL else ''), 'EXACT_OWNED_FRAGMENTS_AND_DROPIN_ROSTER')
        C.need(C.sha(C.read(C.DROPIN, 4096)) == C.DROPIN_SHA and C.sha(C.read(C.OLD_CONFIG, 32768, 0o600)) == C.ACTUAL_PREDECESSOR_CONFIG_SHA
               and C.sha(C.read(C.OLD_STANDING, 32768, 0o600)) == C.ACTUAL_PREDECESSOR_STANDING_SHA, 'UNCHANGED_ACTUAL_G12_CONFIG_AND_CPU_OVERRIDE')
        for directory, pin in [(C.OLD_SOURCE, C.ACTUAL_PREDECESSOR_SOURCE_SHA), (C.NEW_SOURCE, self.m['files']['source/network_guardian.py'])]:
            C.need({p.name for p in directory.iterdir()} == set(C.MODULES), 'EXACT_SOURCE8_DIRECTORY')
            for name in C.MODULES:
                expected_pin = pin if name == 'network_guardian.py' else C.HELPERS[name]
                C.need(C.sha(C.read(directory / name)) == expected_pin, 'UNCHANGED_SOURCE8_BYTES')

    def preconditions(self):
        C.need(time.monotonic() - self.started < 90, 'BOUNDED_PRE_SEND_OPERATION')
        self.files()
        C.need(physical_identity(CTRL, controller_argv(C.OLD_CONFIG)) == self.old_controller and
               physical_identity(GUARD, guardian_argv(C.OLD_SOURCE, C.ACTUAL_PREDECESSOR_SOURCE_SHA)) == self.old_guardian, 'SAME_ROOT_REVIEWED_ACTUAL_LIFETIMES')
        self.oneshots = {}
        for name in (COLD, HUB):
            p = properties(name)
            C.need(p['ActiveState'] == 'active' and p['SubState'] == 'exited' and p['Result'] == 'success', 'ORIGINAL_COLD_AND_HUB_COMPLETED_LIFETIMES')
            self.oneshots[name] = {k: p[k] for k in (*IDENTITY_PROPS, 'NRestarts', 'ActiveState', 'SubState', 'Result')}
        self.core_before = core_overlap()
        C.need(self.qualification['core_overlap'] == self.core_before and self.qualification['boot_id'] == self.old_controller['boot_id']
               and 0 <= time.monotonic() - self.qualification['observed_monotonic'] <= 600, 'FRESH_EXACT_NO_APPLY_QUALIFICATION_SAME_CORE_AND_BOOT')
        self.protected_before = self.protected()
        G = C.load_guardian(C.OLD_SOURCE, C.ACTUAL_PREDECESSOR_SOURCE_SHA)
        self.old_owner = G.Owner(C.ACTUAL_PREDECESSOR_SOURCE_SHA)
        current = self.old_owner.identity()
        C.need(current['pid'] == self.old_controller['pid'] and current['InvocationID'] == self.old_controller['InvocationID'] and self.old_owner.original_qualification_exists(current), 'ACTUAL_AUTHENTICATED_PREDECESSOR_FULL120')
        observation, prefix, suffix, reads = self.old_owner.current15_readonly()
        C.need(observation['measurement']['qualified_15_seconds'] is True and observation['kernel']['all_four_backends_and_reverse_sources_positive'] is True, 'PREDECESSOR_FRESH_CURRENT15_ALL_FOUR')
        C.once(self.run / 'PREDECESSOR-CURRENT15-PREFIX.JSONL', prefix)
        C.once(self.run / 'PREDECESSOR-CURRENT15-CLOSING.JSONL', suffix)
        self.record_once('BEFORE.json', {'controller': self.old_controller, 'guardian': self.old_guardian, 'core': self.core_before,
                         'protected_refs': self.protected_before, 'predecessor_current15': observation, 'native_read_count': len(reads)})
        self.journal = Journal(self.run)
        self.probe = Continuity(self.run, self.core_before, self.m['continuity_peer_ipv4'])

    def claim_once(self):
        # Global per-package claim survives a different evidence directory/process.
        C.once(C.STATE / ('SWAP-' + self.pin + '-POSSIBLE.json'), C.wire({'schema': 'g15_once_only_swap_claim_v1', 'manifest_sha256': self.pin,
               'old_controller': self.old_controller, 'old_guardian': self.old_guardian, 'run': str(self.run), 'automatic_replay': False}))

    def quiescent_guardian(self):
        deadline = time.monotonic() + 25
        while time.monotonic() < deadline:
            C.need(physical_identity(GUARD, guardian_argv(C.OLD_SOURCE, C.ACTUAL_PREDECESSOR_SOURCE_SHA)) == self.old_guardian, 'SAME_GUARDIAN_BEFORE_ONCE_STOP')
            r = native(['/usr/bin/journalctl', '-u', GUARD, '-o', 'json', '--all', '-n', '24', '--no-pager'], 4)
            C.need(r.returncode == 0, 'GUARDIAN_DESCRIPTOR_ORIGINAL_READ_ZERO')
            now = time.monotonic()
            for raw in reversed(r.stdout.splitlines()):
                row = C.loads(raw)
                if str(row.get('_PID')) != str(self.old_guardian['pid']) or row.get('_SYSTEMD_INVOCATION_ID') != self.old_guardian['InvocationID'] or row.get('_BOOT_ID') != self.old_guardian['boot_id'].replace('-', ''):
                    continue
                rec = C.loads(row['MESSAGE'])
                if rec.get('schema') == 'Root_network_guardian_current_operational_descriptor_v1' and 0 <= now - int(row['__MONOTONIC_TIMESTAMP']) / 1e6 < 3:
                    C.need(rec['source_sha256'] == C.ACTUAL_PREDECESSOR_SOURCE_SHA and rec['identity']['pid'] == self.old_controller['pid'] and rec['identity']['InvocationID'] == self.old_controller['InvocationID']
                           and rec['all_four_backends_currently_positive'] is True and rec['current15']['qualified_15_seconds'] is True and rec['mutations_this_sample'] == 0, 'EXACT_FRESH_GUARDIAN_QUIESCENT_DESCRIPTOR')
                    self.record_once('QUIESCENT-DESCRIPTOR.json', row)
                    self.controller_inputs()
                    return
            time.sleep(.15)
        raise Hold('NO_FRESH_QUIESCENT_GUARDIAN_DESCRIPTOR')

    def assert_old_guardian_absent(self):
        assert_absent(GUARD, self.old_guardian)

    def cas(self, unit, pin, new):
        C.need(unit in (CTRL, COLD, GUARD), 'CLOSED_CAS_UNIT')
        target = C.UNIT_DIR / unit
        old = C.read(target, 32768)
        C.need(C.sha(old) == pin, 'EXACT_FRESH_UNIT_CAS_PREIMAGE')
        C.once(self.run / (unit + '.ORIGINAL'), old)
        self.record_once(unit + '-POSSIBLE-REPLACE.json', {'old_sha256': pin, 'new_sha256': C.sha(new), 'automatic_rollback': False})
        temporary = target.with_name(unit + '.g15pair-once')
        C.once(temporary, new, 0o644)
        C.need(C.read(target, 32768) == old, 'UNIT_UNCHANGED_IMMEDIATELY_BEFORE_REPLACE')
        os.replace(temporary, target); C.sync_dir(target.parent)
        C.need(C.read(target, 32768) == new, 'EXACT_UNIT_CAS_READBACK')

    def cas_controller_once(self):
        C.need(physical_identity(CTRL, controller_argv(C.OLD_CONFIG)) == self.old_controller, 'OLD_CONTROLLER_STILL_RUNNING_BEFORE_UNIT_CAS')
        self.cas(CTRL, C.OLD_UNIT_SHAS[CTRL], C.read(self.folder / 'controller.service', 32768))

    def verify_controller_definition(self):
        C.need(physical_identity(CTRL, controller_argv(C.OLD_CONFIG)) == self.old_controller, 'SAME_RUNNING_OLD_CONTROLLER_AFTER_RELOAD')
        p = properties(CTRL)
        C.need(str(C.NEW_CONFIG) in p['ExecStart'] and str(C.OLD_CONFIG) not in p['ExecStart'] and p['Restart'] == 'no', 'EXACT_NEW_LOADED_CONTROLLER_DEFINITION')

    def fresh_window(self):
        deadline, last = time.monotonic() + 90, None
        while time.monotonic() < deadline:
            C.need(physical_identity(CTRL, controller_argv(C.OLD_CONFIG)) == self.old_controller, 'SAME_CONTROLLER_SELECTING_FRESH_COMPLETE_TTL')
            for row, rec in self.journal.joined(self.old_controller):
                info = complete_commit(rec)
                if info:
                    residual = info['render_started'] + info['minimum_all_ttl_ms'] / 1000 - time.monotonic()
                    if residual >= 3.5:
                        info['residual_at_selection_seconds'] = residual
                        self.fresh = info
                        self.record_once('FRESH-SOURCE-COMMIT.json', {'original': row, 'measured': info})
                        self.controller_inputs()
                        C.need(info['render_started'] + info['minimum_all_ttl_ms'] / 1000 - time.monotonic() >= 3.5, 'FRESH_ALL_ROLE_TTL_AFTER_CONFIG_AND_RUNTIME_RECHECK')
                        return
                    last = info
            time.sleep(.05)
        self.record_once('NO-FRESH-WINDOW.json', {'last_complete_commit': last, 'controller_unit_may_already_be_G15': True, 'automatic_restore': False})
        raise Hold('NO_FRESH_COMPLETE_ALL_ROLE_TTL_NO_AUTOMATIC_RESTORE')

    def assert_old_controller_absent(self):
        assert_absent(CTRL, self.old_controller)

    def wait_new_controller(self):
        deadline = time.monotonic() + 30
        adoption, probe = False, False
        self.new_controller = wait_exec_identity(CTRL, controller_argv(C.NEW_CONFIG), deadline, self.old_controller)
        while time.monotonic() < deadline:
            current = physical_identity(CTRL, controller_argv(C.NEW_CONFIG))
            C.need(current['InvocationID'] != self.old_controller['InvocationID'] and current['pid'] != self.old_controller['pid'], 'ACTUAL_NEW_CONTROLLER_PHYSICAL_LIFETIME')
            if self.new_controller is None:
                self.new_controller = current
            C.need(current == self.new_controller, 'SAME_NEW_CONTROLLER_THROUGH_INITIAL_COMMIT')
            for row, rec in self.journal.joined(current):
                C.need(rec.get('status') != 'HOLD' and not str(rec.get('schema', '')).endswith('_HOLD_v1'), 'NEW_CONTROLLER_HOLD_NO_REPLAY')
                C.need(not (rec.get('schema') == 'capacity_owned_nft_native_batch_v3' and rec.get('phase') == 'initial_static_no_dynamic'), 'NO_TABLE_RECREATION')
                if rec.get('schema') == 'capacity_owned_nft_original_read_adoption_v1':
                    C.need(rec.get('native_mutations') == 0 and rec.get('applied') is False, 'READ_ADOPTION_NO_MUTATIONS')
                    adoption = True
                if rec.get('schema') == 'capacity_netlink_startup_probe_v1':
                    C.need(rec.get('probe_batch_changed_state') is False, 'NO_APPLY_STARTUP_PROBE')
                    probe = True
                commit = complete_commit(rec)
                if adoption and probe and commit:
                    gaps = {k: max(0, commit['native_apply_returned'] - self.fresh['render_started'] - ttl / 1000) for k, ttl in self.fresh['ttl_ms'].items()}
                    self.record_once('NEW-CONTROLLER-FIRST-COMPLETE-COMMIT.json', {'identity': current, 'original': row, 'known_commit': commit, 'conservative_per_role_gap_seconds': gaps})
                    self.gaps = gaps
                    return
            time.sleep(.05)
        raise Hold('NEW_CONTROLLER_READINESS_CEILING_NO_ROLLBACK')

    def cas_future_units_once(self):
        for unit in (COLD, GUARD):
            self.cas(unit, C.OLD_UNIT_SHAS[unit], C.read(self.folder / 'units' / unit, 32768))

    def install_standing_once(self):
        D = sibling('derive_standing_config')
        out = self.run / 'LIVE-STANDING.json'
        std, expected = D.derive(self.folder, self.m, C.UNIT_DIR, out)
        pin = C.validate_standing_output(std, expected, 'live')
        C.need(pin == self.staged['standing_sha256'] and C.read(out, 32768) == C.read(Path(self.staged['staged_standing_path']), 32768), 'BYTE_IDENTICAL_STAGED_AND_LIVE_DERIVATION')
        self.record_once('STANDING-POSSIBLE-INSTALL.json', {'sha256': pin, 'path': str(C.NEW_STANDING), 'automatic_rollback': False})
        C.once(C.NEW_STANDING, C.read(out, 32768), 0o600)
        self.standing_pin = pin

    def wait_new_guardian(self):
        deadline = time.monotonic() + 240
        source_pin = self.m['files']['source/network_guardian.py']
        cmd = guardian_argv(C.NEW_SOURCE, source_pin)
        controller_full = {**self.new_controller, 'cmdline_sha256': C.sha(b'\0'.join(x.encode() for x in controller_argv(C.NEW_CONFIG)) + b'\0'), 'initial_R42_admitted_lifetime': False}
        key = C.sha(C.wire(controller_full))
        self.new_guardian = wait_exec_identity(GUARD, cmd, deadline, self.old_guardian)
        while time.monotonic() < deadline:
            C.need(physical_identity(CTRL, controller_argv(C.NEW_CONFIG)) == self.new_controller, 'SAME_NEW_CONTROLLER_WAITING_OWN120_AND_OWN15')
            C.need(not (C.LEDGER / (key + '-QUALIFICATION-HOLD.PUBLIC.json')).exists(), 'ORIGINAL_FIRST_QUALIFICATION_HOLD_NO_REPLAY')
            current = physical_identity(GUARD, cmd)
            C.need(current['pid'] != self.old_guardian['pid'] and current['InvocationID'] != self.old_guardian['InvocationID'], 'NEW_GUARDIAN_PHYSICAL_LIFETIME')
            if self.new_guardian is None:
                self.new_guardian = current
            C.need(current == self.new_guardian, 'SAME_NEW_GUARDIAN_NO_IMPLICIT_RESTART')
            pub = C.LEDGER / (current['boot_id'] + '-GUARDIAN-' + current['InvocationID'] + '-FIRST-CURRENT15-RETURN.PUBLIC.json')
            if pub.exists():
                raw = C.read(pub, 16 << 20, 0o600)
                value = C.loads(raw)
                C.need(value['schema'] == 'Root_owning_finite512_current15_readonly_observation_v1' and value['source_sha256'] == source_pin
                       and value['standing_config_sha256'] == self.standing_pin and value['identity'] == controller_full
                       and value['measurement']['qualified_15_seconds'] is True and value['measurement']['all_requested_rows_accounted_for'] is True
                       and value['kernel']['all_four_backends_and_reverse_sources_positive'] is True, 'ACTUAL_OWN_NEW_DAEMON_CURRENT15_WITH_EXACT_NEW_CONTROLLER')
                self.publication_ref = {'path': str(pub), 'sha256': C.sha(raw)}
                # No assessor runs before the owning daemon's own original return.
                G = C.load_guardian(C.NEW_SOURCE, source_pin)
                owner = G.Owner(source_pin)
                observed_identity = owner.identity()
                C.need(observed_identity == controller_full, 'SAME_NEW_SOURCE_AUTHENTICATED_CONTROLLER')
                measurement = owner.original_qualification_measurement(observed_identity)
                C.need(measurement is not None, 'AUTHENTICATED_ACTUAL_NEW_CONTROLLER_FULL120_RECOMPUTED')
                observation, prefix, suffix, reads = owner.current15_readonly()
                C.need(observation['identity'] == controller_full and observation['measurement']['qualified_15_seconds'] is True
                       and observation['measurement']['all_requested_rows_accounted_for'] is True
                       and observation['kernel']['all_four_backends_and_reverse_sources_positive'] is True, 'INDEPENDENT_NEW_LIFETIME_CURRENT15_ALL_FOUR')
                C.once(self.run / 'INDEPENDENT-CURRENT15-PREFIX.JSONL', prefix)
                C.once(self.run / 'INDEPENDENT-CURRENT15-CLOSING.JSONL', suffix)
                self.record_once('INDEPENDENT-CURRENT15.json', {'observation': observation, 'native_read_count': len(reads), 'own_daemon_first_ref': self.publication_ref,
                                 'actual_new_full120_recomputed': True, 'historical_120_is_not_current_health': True})
                self.qualified_identity = controller_full
                self.full120_ref = {'path': str(C.LEDGER / (key + '-QUALIFIED.PUBLIC.json')),
                                    'sha256': C.sha(C.read(C.LEDGER / (key + '-QUALIFIED.PUBLIC.json'), 16 << 20, 0o600))}
                return
            time.sleep(1)
        raise Hold('NEW_OWN120_AND_DAEMON_CURRENT15_CEILING_NO_REPLAY')

    def final_closure(self):
        self.files(successor=True)
        C.need(physical_identity(CTRL, controller_argv(C.NEW_CONFIG)) == self.new_controller and
               physical_identity(GUARD, guardian_argv(C.NEW_SOURCE, self.m['files']['source/network_guardian.py'])) == self.new_guardian, 'SAME_NEW_PHYSICAL_LIFETIMES_THROUGH_INDEPENDENT_CLOSURE')
        C.need(C.sha(C.read(C.NEW_STANDING, 32768, 0o600)) == self.standing_pin and C.sha(C.read(self.publication_ref['path'], 16 << 20, 0o600)) == self.publication_ref['sha256']
               and C.sha(C.read(self.full120_ref['path'], 16 << 20, 0o600)) == self.full120_ref['sha256'], 'IMMUTABLE_NEW_STANDING_OWN15_AND_ACTUAL_FULL120_REFS')
        for name in (COLD, HUB):
            p = properties(name)
            C.need({k: p[k] for k in self.oneshots[name]} == self.oneshots[name], 'COLD_HUB_SAME_ORIGINAL_COMPLETED_LIFETIMES_NO_EXECUTION')
        C.need(self.protected() == self.protected_before and core_overlap() == self.core_before, 'INHERITED_BUDGET_ORIGINAL_PROOFS_AND_CORE_UNCHANGED')
        for path, dev, ino in self.locks:
            s = path.lstat(); C.need((s.st_dev, s.st_ino) == (dev, ino), 'SAME_EXISTING_MUTEX_INODES')
        self.probe.close()
        continuity = self.probe.summary()
        C.need(all(v == 0 for v in self.gaps.values()), 'NO_CONSERVATIVE_ALL_ROLE_TTL_LAPSE')
        return {'source_commit': self.m['source_commit'], 'source_R': C.SOURCE_R, 'amd64_D': C.NEW_DIGEST,
                'new_guardian_source_sha256': self.m['files']['source/network_guardian.py'], 'standing_sha256': self.standing_pin,
                'controller_config_sha256': C.HEAD_CONFIG_SHA, 'controller': self.new_controller, 'guardian': self.new_guardian,
                'actual_new_full120_ref': self.full120_ref, 'own_daemon_first_current15_ref': self.publication_ref,
                'independent_current15': True, 'all_inherited_budget_and_original_refs_unchanged': True,
                'continuity': continuity, 'conservative_per_role_gap_seconds': self.gaps, 'Core_Cold_Hub_or_provider_mutation': False}

    def close(self):
        # Only local read-only observer clients are joined; no unit action here.
        if self.probe is not None:
            self.probe.close()
        if self.journal is not None:
            self.journal.close()


def unit_from_predecessor(raw):
    C.need(C.sha(raw) == C.OLD_UNIT_SHAS[CTRL], 'EXACT_CONTROLLER_UNIT_PREIMAGE')
    old = ('ExecStart=' + ' '.join(controller_argv(C.OLD_CONFIG))).encode()
    new = ('ExecStart=' + ' '.join(controller_argv(C.NEW_CONFIG))).encode()
    lines = raw.split(b'\n')
    C.need([v for v in lines if v.startswith(b'ExecStart')] == [old], 'ONE_EXACT_CONTROLLER_EXECSTART')
    return b'\n'.join(new if v == old else v for v in lines)


def load_staged(path, pin, manifest_pin):
    raw = C.read(path, 65536, 0o600)
    C.need(C.sha(raw) == pin, 'EXACT_ROOT_REVIEWED_NATIVE_STAGE_RECEIPT')
    staged = C.loads(raw)
    C.need(type(staged) is dict and set(staged) == {'schema', 'manifest_sha256', 'controller_config_sha256', 'standing_sha256', 'staged_standing_path', 'derivation_output', 'expected_derivation', 'source_target', 'source_roster', 'units', 'live_standing_installed'}
           and staged['schema'] == C.STAGED_SCHEMA and staged['manifest_sha256'] == manifest_pin and staged['controller_config_sha256'] == C.HEAD_CONFIG_SHA
           and staged['source_target'] == str(C.NEW_SOURCE) and staged['live_standing_installed'] is False, 'CLOSED_G15_STAGE_RECEIPT')
    C.need(C.validate_standing_output(staged['derivation_output'], staged['expected_derivation'], 'staged') == staged['standing_sha256']
           and C.sha(C.read(staged['staged_standing_path'], 32768, 0o600)) == staged['standing_sha256'], 'EXACT_STAGED_STANDING_AND_DUAL_ABI')
    return staged


def stage(folder, m, pin, run):
    C.require_bound()
    """Inert installation only. This command itself is a production write gate."""
    C.need(physical_identity(CTRL, controller_argv(C.OLD_CONFIG)) == m['expected_controller_identity'] and
           physical_identity(GUARD, guardian_argv(C.OLD_SOURCE, C.ACTUAL_PREDECESSOR_SOURCE_SHA)) == m['expected_guardian_identity'], 'SAME_FRESH_ROOT_REVIEWED_PRE_STAGE_LIFETIMES')
    C.need(all(C.sha(C.read(C.UNIT_DIR / n, 32768)) == h for n, h in C.OLD_UNIT_SHAS.items())
           and C.sha(C.read(C.DROPIN, 4096)) == C.DROPIN_SHA and C.sha(C.read(C.OLD_STANDING, 32768, 0o600)) == C.ACTUAL_PREDECESSOR_STANDING_SHA, 'EXACT_ACTUAL_G12_PRE_STAGE_POSTURE')
    C.need(unit_from_predecessor(C.read(C.UNIT_DIR / CTRL, 32768)) == C.read(folder / 'controller.service', 32768), 'CONTROLLER_UNIT_ONLY_CONFIG_PATH_CHANGED')
    controller = sibling('derive_g15pair_controller_config')
    raw = controller.derive(controller.read_private(controller.R42_CONFIG),
                            [controller.read_private(path) for _, _, path, _ in controller.PAIR_CHAIN[:-1]],
                            C.read(folder / 'ROOT-CONTROLLER-REVIEW.txt', 8192, 0o600).decode().removesuffix('\n'))
    C.need(C.sha(raw) == C.HEAD_CONFIG_SHA, 'EXACT_ROOT_REVIEWED_CONFIG_TWIN')
    C.once(C.STATE / ('STAGE-' + pin + '-POSSIBLE.json'), C.wire({'manifest_sha256': pin, 'run': str(run), 'inert_sources_and_config_only': True, 'automatic_replay': False}))
    if C.NEW_CONFIG.exists():
        C.need(C.read(C.NEW_CONFIG, 32768, 0o600) == raw, 'EXISTING_NEW_CONFIG_BYTE_IDENTICAL')
    else:
        C.once(C.NEW_CONFIG, raw)
    C.private_dir(C.NEW_SOURCE, create=True)
    for name in C.MODULES:
        C.once(C.NEW_SOURCE / name, C.read(folder / 'source' / name))
    cross = controller.guardian_cross_check(controller.read_private(controller.R42_CONFIG),
                                            [controller.read_private(path) for _, _, path, _ in controller.PAIR_CHAIN[:-1]], raw,
                                            m['files']['source/network_guardian.py'])
    C.need(cross == 'accepted_by_pinned_g15pair_guardian', 'ACTUAL_PINNED_SUCCESSOR_ACCEPTS_G15_CONFIG')
    units = run / 'units'; C.private_dir(units, create=True)
    C.once(units / CTRL, C.read(folder / 'controller.service', 32768))
    for name in (COLD, GUARD):
        C.once(units / name, C.read(folder / 'units' / name, 32768))
    D = sibling('derive_standing_config')
    std, expected = D.derive(folder, m, units, run / 'STAGED-STANDING.json')
    result = {'schema': C.STAGED_SCHEMA, 'manifest_sha256': pin, 'controller_config_sha256': C.HEAD_CONFIG_SHA,
              'standing_sha256': std['standing_config_sha256'], 'staged_standing_path': str(run / 'STAGED-STANDING.json'),
              'derivation_output': std, 'expected_derivation': expected, 'source_target': str(C.NEW_SOURCE),
              'source_roster': {n: m['files']['source/' + n] for n in C.MODULES},
              'units': {CTRL: m['controller_unit_sha256'], COLD: m['files']['units/' + COLD], GUARD: m['files']['units/' + GUARD]},
              'live_standing_installed': False}
    C.once(run / 'STAGED.json', C.wire(result))
    return result


def qualify(folder, m, pin, staged, run):
    C.require_bound()
    """Actual existing runtime check-once: reads/probe only, never apply."""
    C.need(C.sha(C.read(C.NEW_CONFIG, 32768, 0o600)) == C.HEAD_CONFIG_SHA, 'EXACT_STAGED_G15_CONTROLLER')
    source = C.load_guardian(C.NEW_SOURCE, m['files']['source/network_guardian.py'])
    C.need({p.name for p in C.RUNTIME.iterdir()} == set(source.RUNTIME_HASHES) and
           all(C.sha(C.read(C.RUNTIME / n)) == h for n, h in source.RUNTIME_HASHES.items()), 'EXACT_EXISTING_RUNTIME14')
    census = core_overlap()
    r = native(['/usr/bin/python3', '-B', str(C.RUNTIME / 'controller.py'), '--config', str(C.NEW_CONFIG), '--check-once'], 120)
    C.once(run / 'CHECK-ONCE-ORIGINAL.JSONL', r.stdout)
    rows = [C.loads(line) for line in r.stdout.splitlines() if line.strip()]
    adoption = [x for x in rows if x.get('schema') == 'capacity_owned_nft_original_read_adoption_v1']
    probe = [x for x in rows if x.get('schema') == 'capacity_netlink_startup_probe_v1']
    final = [x for x in rows if x.get('schema') == 'root_R11_static_empty_and_current_readonly_check_v1']
    C.need(r.returncode == 0 and len(adoption) == len(probe) == len(final) == 1 and adoption[0].get('native_mutations') == 0 and adoption[0].get('applied') is False
           and probe[0].get('probe_batch_changed_state') is False and final[0].get('backends') == ['broker', 'core', 'rds', 'redis'] and final[0].get('prometheus_sources') == 1
           and final[0].get('held_native_read_classes') == {} and not any(x.get('status') == 'HOLD' for x in rows), 'ACTUAL_RUNTIME_NO_APPLY_QUALIFICATION')
    result = {'schema': 'g15_no_apply_qualification_v1', 'manifest_sha256': pin, 'controller_config_sha256': C.HEAD_CONFIG_SHA,
              'observed_monotonic': time.monotonic(), 'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
              'original_check_once_ref': {'path': str(run / 'CHECK-ONCE-ORIGINAL.JSONL'), 'sha256': C.sha(r.stdout)},
              'core_overlap': census, 'standing_sha256': staged['standing_sha256'], 'native_apply': False,
              'actual_new_controller120_or_live_acceptance': False}
    C.once(run / 'QUALIFIED.json', C.wire(result))
    return result


def main():
    C.require_bound()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('stage', 'qualify', 'preconditions', 'swap-once'))
    parser.add_argument('--package', required=True, type=Path)
    parser.add_argument('--expected-manifest-sha256', required=True)
    parser.add_argument('--evidence-dir', required=True, type=Path)
    parser.add_argument('--stage-receipt', type=Path)
    parser.add_argument('--expected-stage-receipt-sha256')
    parser.add_argument('--qualification-receipt', type=Path)
    parser.add_argument('--expected-qualification-receipt-sha256')
    parser.add_argument('--execute-once', action='store_true')
    a = parser.parse_args()
    C.need(os.geteuid() == 0 and sys.platform == 'linux', 'ROOT_ON_PINNED_BRAIN_ONLY')
    folder, m = C.package(a.package, a.expected_manifest_sha256)
    C.need(Path(__file__).absolute() == folder / 'tools' / 'g15cut.py' and C.sha(C.read(__file__)) == m['tools']['g15cut.py'], 'EXECUTED_TOOL_FROM_EXACT_REVIEWED_PACKAGE')
    run = a.evidence_dir.absolute()
    C.need(run.parent == C.STATE and run.name.startswith(a.mode + '-') and len(run.name) < 160, 'CLOSED_NEW_OPERATION_EVIDENCE_DIRECTORY')
    if a.mode == 'stage' and a.execute_once and not C.STATE.exists():
        C.shared_parent(C.STATE.parent)
        C.private_dir(C.STATE, create=True)
    C.private_dir(C.STATE)
    C.private_dir(run, create=True)
    def interrupted(signum, _frame):
        raise Hold('OPERATOR_SIGNAL_' + str(signum) + '_RECONCILE_NO_REPLAY')
    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(signum, interrupted)
    backend = None
    try:
        with custody() as locks:
            if a.mode == 'stage':
                C.need(a.execute_once and a.stage_receipt is None and a.expected_stage_receipt_sha256 is None and a.qualification_receipt is None and a.expected_qualification_receipt_sha256 is None, 'EXPLICIT_INERT_STAGE_WRITE_AUTHORIZATION')
                result = stage(folder, m, a.expected_manifest_sha256, run)
            else:
                C.need(a.stage_receipt is not None and C.digest(a.expected_stage_receipt_sha256), 'EXACT_NATIVE_STAGE_REFERENCE_REQUIRED')
                staged = load_staged(a.stage_receipt, a.expected_stage_receipt_sha256, a.expected_manifest_sha256)
                C.need(staged['source_roster'] == {n: m['files']['source/' + n] for n in C.MODULES} and staged['units'] == {CTRL: m['controller_unit_sha256'], COLD: m['files']['units/' + COLD], GUARD: m['files']['units/' + GUARD]}, 'STAGED_RUNTIME_AND_UNIT_ROSTERS_MATCH_PACKAGE')
                if a.mode == 'qualify':
                    C.need(not a.execute_once and a.qualification_receipt is None and a.expected_qualification_receipt_sha256 is None, 'QUALIFY_IS_READ_ONLY_WITH_NO_CALLER_RESULT')
                    result = qualify(folder, m, a.expected_manifest_sha256, staged, run)
                else:
                    C.need(a.qualification_receipt is not None and C.digest(a.expected_qualification_receipt_sha256), 'EXACT_NATIVE_NO_APPLY_QUALIFICATION_REFERENCE_REQUIRED')
                    raw = C.read(a.qualification_receipt, 65536, 0o600)
                    C.need(C.sha(raw) == a.expected_qualification_receipt_sha256, 'ROOT_REVIEWED_NO_APPLY_QUALIFICATION_SHA')
                    qualification = C.loads(raw)
                    C.need(type(qualification) is dict and set(qualification) == {'schema', 'manifest_sha256', 'controller_config_sha256', 'core_overlap', 'standing_sha256', 'native_apply', 'actual_new_controller120_or_live_acceptance', 'observed_monotonic', 'boot_id', 'original_check_once_ref'}
                           and qualification['schema'] == 'g15_no_apply_qualification_v1' and qualification['manifest_sha256'] == a.expected_manifest_sha256
                           and qualification['controller_config_sha256'] == C.HEAD_CONFIG_SHA and qualification['standing_sha256'] == staged['standing_sha256']
                           and qualification['native_apply'] is False and qualification['actual_new_controller120_or_live_acceptance'] is False, 'CLOSED_ACTUAL_NO_APPLY_QUALIFICATION')
                    ref = qualification['original_check_once_ref']
                    C.need(type(ref) is dict and set(ref) == {'path', 'sha256'} and Path(ref['path']).parent == a.qualification_receipt.parent
                           and C.sha(C.read(ref['path'], 32 << 20, 0o600)) == ref['sha256'], 'ORIGINAL_CHECK_ONCE_RECEIPT_STILL_PINNED')
                    backend = Backend(folder, m, a.expected_manifest_sha256, run, staged, locks, qualification)
                    if a.mode == 'preconditions':
                        C.need(not a.execute_once, 'PRECONDITIONS_NEVER_SUBMIT_NATIVE_EFFECT')
                        backend.preconditions()
                        result = {'status': 'PRECONDITIONS_OK', 'manifest_sha256': a.expected_manifest_sha256, 'native_effects': 0, 'actual_new_controller120_or_live_acceptance': False}
                        backend.record_once('RETURN.json', result)
                    else:
                        C.need(a.execute_once, 'EXPLICIT_ONE_SHOT_SWAP_REQUIRED')
                        result = swap_once(backend)
            print(C.wire(result).decode(), end='', flush=True)
    finally:
        if backend is not None:
            backend.close()


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(C.wire({'schema': 'g15_operational_HOLD_v1', 'guard': str(error)[:180], 'error_class': type(error).__name__,
                      'automatic_replay': False, 'no_automatic_unit_or_Core_cleanup': True,
                      'fresh_native_reconciliation_before_any_next_operation': True}).decode(), end='', flush=True)
        raise SystemExit(30) from None
