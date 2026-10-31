"""LAB-only local systemd peer identity, not an authorization or effect fence.

Assumes no other privileged actor can replace source files, unit properties,
processes or sockets during the transaction. Callers own and close the pidfd.
"""
import hashlib
import os
import re
import select
import stat
import subprocess
from pathlib import Path


def _need(value, reason):
    if not value:
        raise RuntimeError(reason)


def _properties(unit):
    _need(re.fullmatch(r'[a-zA-Z0-9_.@:-]+\.service', unit) is not None, 'EXACT_SERVICE_UNIT_REQUIRED')
    p = subprocess.run(['/usr/bin/systemctl', 'show', unit, '--property=MainPID,InvocationID,ActiveState,ControlGroup', '--no-pager'],
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=3, check=True)
    rows = p.stdout.decode('ascii').splitlines()
    pairs = [row.split('=', 1) for row in rows]
    _need(len(pairs) == 4 and len({a for a, _ in pairs}) == 4, 'EXACT_SYSTEMD_PROPERTIES')
    return dict(pairs)


def _startticks(pid):
    data = Path('/proc/%d/stat' % pid).read_bytes()
    after = data.rsplit(b') ', 1)
    _need(len(after) == 2, 'PROC_STAT_FORMAT')
    fields = after[1].split()
    return int(fields[19])


def _secure_source(path, expected_sha256):
    _need(path.is_absolute() and '..' not in path.parts, 'ABSOLUTE_NONTRAVERSING_SOURCE_REQUIRED')
    for parent in reversed(path.parents):
        st = os.lstat(parent)
        _need(stat.S_ISDIR(st.st_mode) and st.st_uid == 0 and
              ((st.st_mode & 0o022) == 0 or (st.st_mode & stat.S_ISVTX)),
              'ROOT_CONTROLLED_SOURCE_ANCESTORS_REQUIRED')
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        a = os.fstat(fd)
        _need(stat.S_ISREG(a.st_mode) and a.st_uid == 0 and not a.st_mode & 0o022 and a.st_size <= 4*1024*1024,
              'ROOT_CONTROLLED_REGULAR_SOURCE_REQUIRED')
        data = bytearray()
        while True:
            part = os.read(fd, 65536)
            if not part: break
            data.extend(part)
            _need(len(data) <= 4*1024*1024, 'BOUNDED_SOURCE_REQUIRED')
        b = os.fstat(fd); c = os.lstat(path)
        key = lambda st:(st.st_dev, st.st_ino, st.st_uid, st.st_mode, st.st_size, st.st_mtime_ns, st.st_ctime_ns)
        _need(key(a) == key(b) == key(c) and hashlib.sha256(data).hexdigest() == expected_sha256,
              'EXACT_STABLE_SOURCE_INODE_AND_BYTES_REQUIRED')
    finally:
        os.close(fd)


def _current_ids(pid, uid, gid):
    lines = Path('/proc/%d/status' % pid).read_text().splitlines()
    values = {k:v for k,v in (line.split(':',1) for line in lines if ':' in line) if k in ('Uid','Gid')}
    _need(set(values) == {'Uid','Gid'} and [int(x) for x in values['Uid'].split()] == [uid]*4
          and [int(x) for x in values['Gid'].split()] == [gid]*4, 'SAME_PROCESS_UID_GID_REQUIRED')

def authenticate(channel, *, unit, expected_invocation, expected_argv, source_sha256, expected_uid=0):
    """Bind an already-connected Unix peer to observed unit, process and bytes."""
    import socket
    import struct
    _need(type(channel) is socket.socket, 'ORIGINAL_CONNECTED_SOCKET_REQUIRED')
    pid, uid, gid = struct.unpack('3i', channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    source_index = (3 if type(expected_argv) is list and expected_argv[:3] == ['/usr/bin/python3', '-I', '-B']
                    else 2 if type(expected_argv) is list and expected_argv[:2] == ['/usr/bin/python3', '-B'] else -1)
    _need(uid == expected_uid and pid > 1 and source_index > 0 and len(expected_argv) > source_index,
          'EXPECTED_UID_AND_EXACT_ARGV_REQUIRED')
    _need(re.fullmatch(r'[0-9a-f]{32}', expected_invocation) is not None
          and re.fullmatch(r'[0-9a-f]{64}', source_sha256) is not None, 'EXPECTED_PIN_FORMAT')
    first = _properties(unit)
    _need(first['ActiveState'] == 'active' and int(first['MainPID']) == pid
          and first['InvocationID'] == expected_invocation and first['ControlGroup'].startswith('/system.slice/'),
          'SYSTEMD_MAINPID_INVOCATION_AND_CGROUP_REQUIRED')
    ticks = _startticks(pid)
    fd = os.pidfd_open(pid, 0)
    try:
        poll = select.poll();poll.register(fd, select.POLLIN)
        _need(not poll.poll(0) and _startticks(pid) == ticks, 'SAME_LIVE_PROCESS_AFTER_PIDFD')
        raw_argv = Path('/proc/%d/cmdline' % pid).read_bytes()
        _need(raw_argv.endswith(b'\0') and raw_argv[:-1].split(b'\0') == [x.encode() for x in expected_argv],
              'EXACT_PROCESS_ARGV_REQUIRED')
        executable = os.stat('/proc/%d/exe' % pid)
        expected_executable = os.stat(expected_argv[0])
        _need((executable.st_dev, executable.st_ino) == (expected_executable.st_dev, expected_executable.st_ino),
              'EXACT_INTERPRETER_INODE_REQUIRED')
        _current_ids(pid, uid, gid)
        source = Path(expected_argv[source_index])
        _secure_source(source, source_sha256)
        cgroups = Path('/proc/%d/cgroup' % pid).read_text().splitlines()
        _need(cgroups == ['0::' + first['ControlGroup']], 'EXACT_PROCESS_CGROUP_REQUIRED')
        _current_ids(pid, uid, gid)
        second = _properties(unit)
        _need(second == first and not poll.poll(0) and _startticks(pid) == ticks,
              'SAME_ACTIVE_UNIT_AND_PROCESS_AFTER_READ')
        return {'pid': pid, 'start_ticks': ticks, 'pidfd': fd, 'invocation_id': expected_invocation,
                'control_group': first['ControlGroup'], 'unit': unit}
    except BaseException:
        os.close(fd)
        raise
