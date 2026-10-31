"""Experimental single-host fenced admission/publication coordination.

LAB ONLY. Requires all writers to share this state and lock; it does not solve
TTL expiry, independent writers, process failover or node failure. Never use
as production authorization. Retired addresses are deliberately never GC'd.
"""
import contextlib
import fcntl
import ipaddress
import json
import os
import pathlib
import re
import stat
import tempfile

class FenceError(RuntimeError):
    pass

class Coordinator:
    def __init__(self, directory):
        self.directory = pathlib.Path(directory)
        self.lock_path = self.directory / 'drain.lock'
        self.state_path = self.directory / 'drain-fences.json'
        self._directory_identity = None
        self._lock_identity = None

    def _private_directory(self):
        info=os.lstat(self.directory)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid!=0
                or stat.S_IMODE(info.st_mode)!=0o700):
            raise FenceError('ROOT_PRIVATE_COORDINATION_DIRECTORY_REQUIRED')
        identity=(info.st_dev,info.st_ino)
        if self._directory_identity is not None and identity!=self._directory_identity:
            raise FenceError('COORDINATION_DIRECTORY_REPLACED')
        self._directory_identity=identity

    def _checked_lock(self, fd):
        actual=os.fstat(fd);named=os.lstat(self.lock_path)
        if (not stat.S_ISREG(actual.st_mode) or actual.st_uid!=0
                or stat.S_IMODE(actual.st_mode)!=0o600 or actual.st_nlink!=1
                or (actual.st_dev,actual.st_ino)!=(named.st_dev,named.st_ino)):
            raise FenceError('ROOT_PRIVATE_STABLE_LOCK_REQUIRED')
        identity=(actual.st_dev,actual.st_ino)
        if self._lock_identity is not None and identity!=self._lock_identity:
            raise FenceError('COORDINATION_LOCK_REPLACED')
        self._lock_identity=identity

    def revalidate_lock(self):
        self._private_directory()
        named=os.lstat(self.lock_path)
        if self._lock_identity is None or (named.st_dev,named.st_ino)!=self._lock_identity:
            raise FenceError('COORDINATION_LOCK_REPLACED')

    def _read_state(self):
        fd=os.open(self.state_path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            before=os.fstat(fd)
            if (not stat.S_ISREG(before.st_mode) or before.st_uid!=0
                    or stat.S_IMODE(before.st_mode)!=0o600 or before.st_nlink!=1
                    or before.st_size>1048576):
                raise FenceError('ROOT_PRIVATE_FENCE_STATE_REQUIRED')
            raw=bytearray()
            while len(raw)<=1048576:
                part=os.read(fd,min(65536,1048577-len(raw)))
                if not part:break
                raw.extend(part)
            after=os.fstat(fd);named=os.lstat(self.state_path)
            stamp=lambda st:(st.st_dev,st.st_ino,st.st_uid,st.st_mode,st.st_nlink,st.st_size,st.st_mtime_ns,st.st_ctime_ns)
            if len(raw)>1048576 or stamp(before)!=stamp(after) or stamp(after)!=stamp(named):
                raise FenceError('FENCE_STATE_CHANGED_DURING_READ')
            return json.loads(raw)
        finally:os.close(fd)

    def initialize_for_test(self):
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=False)
        self.lock_path.touch(mode=0o600, exist_ok=False)
        self._write({'version': 2, 'retired': {}, 'anchor': None})

    def _write(self, state):
        self._private_directory()
        fd, name = tempfile.mkstemp(prefix='.fences-', dir=self.directory)
        try:
            with os.fdopen(fd, 'w') as file:
                json.dump(state, file, sort_keys=True, separators=(',', ':'))
                file.flush()
                os.fsync(file.fileno())
            os.replace(name, self.state_path)
            directory_fd = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            if os.path.exists(name):
                os.unlink(name)

    @contextlib.contextmanager
    def locked(self, *, nonblocking=False):
        fd=None
        try:
            self._private_directory()
            fd = os.open(self.lock_path, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
            self._checked_lock(fd)
        except BaseException as exc:
            if fd is not None:os.close(fd)
            if isinstance(exc,OSError):raise FenceError('COORDINATOR_UNAVAILABLE') from exc
            raise
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | (fcntl.LOCK_NB if nonblocking else 0))
            except BlockingIOError as exc:
                raise FenceError('COORDINATOR_BUSY') from exc
            self._checked_lock(fd)
            try:
                state = self._read_state()
                if set(state) != {'version', 'retired', 'anchor'} or state['version'] != 2 or type(state['retired']) is not dict:
                    raise FenceError('INVALID_FENCE_STATE')
                for uid, address in state['retired'].items():
                    if not re.fullmatch(r'[a-f0-9-]{36}', uid) or str(ipaddress.IPv4Address(address)) != address:
                        raise FenceError('INVALID_FENCE_ROW')
                anchor = state['anchor']
                if anchor is not None and (type(anchor) is not dict or set(anchor) != {'uid', 'address'}
                        or not re.fullmatch(r'[a-f0-9-]{36}', anchor['uid'])
                        or str(ipaddress.IPv4Address(anchor['address'])) != anchor['address']):
                    raise FenceError('INVALID_FENCE_ANCHOR')
            except (OSError, ValueError, TypeError, KeyError) as exc:
                raise FenceError('FENCE_STATE_UNAVAILABLE') from exc
            # Exceptions from the protected writer must retain their original
            # type: a native send may already have happened and is not NoSend.
            yield state
        finally:
            os.close(fd)

    def retire(self, state, uid, address, *, anchor_uid=None, anchor_address=None):
        if not re.fullmatch(r'[a-f0-9-]{36}', uid) or str(ipaddress.IPv4Address(address)) != address:
            raise FenceError('INVALID_RETIRED_IDENTITY')
        retired = dict(state['retired'])
        if uid in retired and retired[uid] != address:
            raise FenceError('UID_ADDRESS_DRIFT')
        retired[uid] = address
        if (anchor_uid is None) != (anchor_address is None):
            raise FenceError('INCOMPLETE_FENCE_ANCHOR')
        anchor = None
        if anchor_uid is not None:
            if not re.fullmatch(r'[a-f0-9-]{36}', anchor_uid) or str(ipaddress.IPv4Address(anchor_address)) != anchor_address:
                raise FenceError('INVALID_FENCE_ANCHOR')
            if anchor_uid in retired or anchor_address in retired.values():
                raise FenceError('RETIRED_ANCHOR')
            anchor = {'uid': anchor_uid, 'address': anchor_address}
        updated = {'version': 2, 'retired': retired, 'anchor': anchor}
        self._write(updated)
        state.update(updated)

    @staticmethod
    def require_allowed(state, uid, address):
        if uid in state['retired'] or address in state['retired'].values():
            raise FenceError('RETIRED_BACKEND')
