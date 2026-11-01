"""Bounded CI-only sender quiescence custody. Grants no cancellation authority.

All socket-capable writers must cooperate with the same stable writer inode;
this cannot exclude an unparticipating CAP_NET_ADMIN writer. The caller must
retain the marker and separately authenticate/reconcile Guardian state.
"""
import fcntl,os,socket,stat
import drain_marker_v3_DRAFT as marker
import guarded_nl as nl
import recovery_terminality_DRAFT as terminal

class Held(RuntimeError):pass

def require(value,reason):
    if not value:raise Held(reason)

class ExclusiveObservation:
    def __init__(self,anchor,netlink,expected_genid,*,independent_guard=None):
        require(type(anchor) is terminal.MarkerAnchor and type(netlink) is socket.socket
                and type(expected_genid) is int,'EXACT_CUSTODIAN_INPUTS_REQUIRED')
        self.anchor=anchor;self.netlink=netlink;self.expected_genid=expected_genid
        self.fd=None;self.pid=os.getpid();self.independent_guard=independent_guard
    def __enter__(self):
        coord=self.anchor.coordinator
        observed=marker._durable_marker_identity(coord)
        require(observed[:3]==self.anchor.key,'ORIGINAL_MARKER_REQUIRED')
        recorded=observed[3].get('writer_lock_identity')
        require(type(recorded) is list and len(recorded)==2 and all(type(x) is int for x in recorded),
                'MARKER_WRITER_INODE_REQUIRED')
        guard=self.independent_guard
        if guard is not None:
            require(type(guard) is IndependentWriterGuard and guard.live.marker is self.anchor
                    and guard.pid==os.getpid() and guard.fd is not None,'SAME_INDEPENDENT_GUARD_REQUIRED')
            # The sender and every descendant must be terminal before the
            # Guardian closes the transferred sender OFD or upgrades its own.
            terminal.prove_terminal_for_marker(self.anchor)
            os.close(guard.sender_fd);guard.sender_fd=None
            fd=guard.fd
        else:fd=os.open(coord.writer_lock,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            self.fd=fd;self.writer_identity=tuple(recorded);self._same_inode()
            # flock conversion is not guaranteed atomic. Failure is HOLD;
            # success is followed by terminality/inode/genid revalidation.
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            if guard is not None:guard.fd=None
            self.verify()
            return self
        except BaseException:
            if guard is None:os.close(fd)
            self.fd=None;raise
    def _same_inode(self):
        opened=os.fstat(self.fd);named=os.lstat(self.anchor.coordinator.writer_lock)
        require(stat.S_ISREG(opened.st_mode) and opened.st_uid==0 and opened.st_nlink==1
                and stat.S_IMODE(opened.st_mode)==0o600 and
                (opened.st_dev,opened.st_ino)==(named.st_dev,named.st_ino)==self.writer_identity,
                'SAME_ROOT_PRIVATE_WRITER_INODE_REQUIRED')
    def _exclusive_held(self):
        fd=os.open(self.anchor.coordinator.writer_lock,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            opened=os.fstat(fd)
            require((opened.st_dev,opened.st_ino)==self.writer_identity,'SAME_PROBE_INODE_REQUIRED')
            try:fcntl.flock(fd,fcntl.LOCK_SH|fcntl.LOCK_NB)
            except BlockingIOError:return
            raise Held('EXCLUSIVE_WRITER_FENCE_LOST')
        finally:os.close(fd)
    def verify(self):
        require(self.fd is not None and self.pid==os.getpid(),'SAME_LIVE_EXCLUSIVE_CUSTODIAN_REQUIRED')
        self._same_inode();self._exclusive_held()
        terminal.prove_terminal_for_marker(self.anchor)
        require(nl.genid(self.netlink)==self.expected_genid,'EXCLUSIVE_OBSERVATION_GENID_CHANGED')
        self._same_inode();self._exclusive_held()
        terminal.prove_terminal_for_marker(self.anchor)
        require(nl.genid(self.netlink)==self.expected_genid,'EXCLUSIVE_OBSERVATION_GENID_CHANGED')
        return {'terminal_sender':True,'writer_inode':self.writer_identity,'genid':self.expected_genid,
                'marker':self.anchor.key,'cancel_authority':False,'production_authority':False}
    def __exit__(self,*_):
        if self.fd is not None:os.close(self.fd);self.fd=None

class LiveSenderCustody:
    """Authenticate a live systemd sender and receive its real frozen BPF FDs.

    The object is observation-only: it cannot tell a Guardian registry to
    release a permit and cannot clear any marker. The sender retains its FDs.
    """
    def __init__(self,channel,*,unit,invocation,argv,source_sha256,coord,netlink):
        import array,ctypes,json,struct
        require(type(channel) is socket.socket and type(coord) is marker.CoordinatorV3
                and type(netlink) is socket.socket,'ORIGINAL_CONNECTED_CUSTODY_INPUTS_REQUIRED')
        require(os.geteuid()==0 and os.environ.get('CI_GUARDED_FIXTURE')=='1'
                and os.environ.get('CI_HOST_NETNS') and os.readlink('/proc/self/ns/net')!=os.environ['CI_HOST_NETNS'],
                'ONLY_PRIVATE_CI_CUSTODY_REQUIRED')
        self.channel=channel;self.netlink=netlink;self.coord=coord;self.pid=os.getpid();self.fds=[];self.anchor=None;self.receipt_fd=None
        try:
            before=nl.genid(netlink)
            self.anchor=terminal.capture_authenticated(channel,unit=unit,invocation=invocation,argv=argv,source_sha256=source_sha256)
            payload,anc,flags,_=channel.recvmsg(65536,socket.CMSG_SPACE(4*array.array('i').itemsize))
            require(payload.endswith(b'\n') and not flags&(socket.MSG_CTRUNC|socket.MSG_TRUNC) and len(anc)==1,
                    'EXACT_BOUNDED_SENDER_DESCRIPTOR_MESSAGE')
            level,kind,data=anc[0];received=array.array('i');received.frombytes(data[:len(data)-len(data)%received.itemsize]);self.fds=list(received)
            require(level==socket.SOL_SOCKET and kind==socket.SCM_RIGHTS and len(self.fds)==4,
                    'EXACT_FOUR_TRANSFERRED_BPF_DESCRIPTORS')
            document=json.loads(payload);require(type(document) is dict and set(document)=={'records'}
                and type(document['records']) is list and len(document['records'])==2,'EXACT_SENDER_RECORDS_REQUIRED')
            self.records=document['records'];sender_pid=self.anchor.verified['pid'];ids=[]
            for record,pf,mf in zip(self.records,self.fds[::2],self.fds[1::2]):
                require(type(record) is dict and all(type(record.get(k)) is int and record[k]>0 for k in ('program_fd','map_fd','program_id','map_id')),
                        'TYPED_SENDER_BPF_RECORD_REQUIRED')
                require(int(nl.fdinfo(sender_pid,record['program_fd'])['prog_id'])==int(nl.fdinfo(os.getpid(),pf)['prog_id'])==record['program_id']
                        and int(nl.fdinfo(sender_pid,record['map_fd'])['map_id'])==int(nl.fdinfo(os.getpid(),mf)['map_id'])==record['map_id']
                        and nl.fdinfo(sender_pid,record['map_fd'])['frozen'].strip()=='1'
                        and nl.fdinfo(os.getpid(),mf)['frozen'].strip()=='1','SENDER_AND_CUSTODIAN_FDS_MUST_MATCH')
                info=nl.ProgInfo();maps=(ctypes.c_uint32*8)();info.nr_map_ids=8;info.map_ids=ctypes.addressof(maps)
                nl.info(pf,info)
                require(info.id==record['program_id'] and info.nr_map_ids==1 and maps[0]==record['map_id'],
                        'PROGRAM_MUST_REFERENCE_EXACT_TRANSFERRED_MAP')
                ids.append((record['program_id'],record['map_id']))
            require(len({x[0] for x in ids})==len({x[1] for x in ids})==2,'DISTINCT_SENDER_PROGRAMS_AND_MAPS_REQUIRED')
            self.marker=terminal.capture_marker(self.anchor,coord)
            require(len(argv)==4 and argv[:2]==['/usr/bin/python3','-B'], 'EXACT_SENDER_ARGUMENTS_REQUIRED')
            self.receipts=__import__('pathlib').Path(argv[3])/'sender-receipts'
            require(os.path.realpath(self.receipts)==str(self.receipts),'EXACT_NON_SYMLINK_RECEIPT_DIRECTORY_REQUIRED')
            self.receipt_fd=os.open(self.receipts,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
            info=os.fstat(self.receipt_fd);named=os.lstat(self.receipts)
            require(stat.S_ISDIR(info.st_mode) and info.st_uid==0 and stat.S_IMODE(info.st_mode)==0o700
                    and (info.st_dev,info.st_ino)==(named.st_dev,named.st_ino),'ROOT_PRIVATE_STABLE_RECEIPT_DIRECTORY_REQUIRED')
            self.receipt_inode=(info.st_dev,info.st_ino)
            require(nl.genid(netlink)==before,'KERNEL_CHANGED_DURING_LIVE_CUSTODY')
            self.genid=before
        except BaseException:
            self.close();raise
    def inspect_no_recorded_send(self, fence):
        # This is evidence only. It does not prove that uninstrumented writers
        # are impossible, that Guardian registries agree, or that a permit may
        # be canceled. No marker is unlinked by this method.
        require(type(fence) is ExclusiveObservation and fence.anchor is self.marker
                and fence.netlink is self.netlink and self.receipt_fd is not None
                and self.pid==os.getpid(),'SAME_SENDER_AND_EXCLUSIVE_FENCE_REQUIRED')
        fence.verify()
        opened=os.fstat(self.receipt_fd);named=os.lstat(self.receipts)
        require(stat.S_ISDIR(named.st_mode) and (opened.st_dev,opened.st_ino)==
                (named.st_dev,named.st_ino)==self.receipt_inode,'ORIGINAL_RECEIPT_DIRECTORY_CHANGED')
        require(os.listdir(self.receipt_fd)==[],'SENDER_RECEIPT_DIRECTORY_NOT_EMPTY')
        fence.verify()
        named=os.lstat(self.receipts)
        require((named.st_dev,named.st_ino)==self.receipt_inode and os.listdir(self.receipt_fd)==[],
                'ORIGINAL_RECEIPT_DIRECTORY_CHANGED')
        return {'empty_original_receipts_observed':True,'cancel_authority':False,'production_authority':False}
    def close(self):
        if self.receipt_fd is not None:os.close(self.receipt_fd);self.receipt_fd=None
        for fd in self.fds:os.close(fd)
        self.fds=[]
        if self.anchor is not None:self.anchor.close();self.anchor=None


class IndependentWriterGuard:
    """Guardian-owned SH on a separate open-file-description, CI only.

    A sender may unlock/convert its SCM-transferred OFD; that cannot remove
    this separately opened SH. This is not cancellation or recovery authority.
    """
    def __init__(self,live):
        import array,json
        require(type(live) is LiveSenderCustody and live.pid==os.getpid() and live.anchor is not None,
                'LIVE_AUTHENTICATED_SENDER_CUSTODY_REQUIRED')
        require(not terminal._pidfd_terminal(live.anchor.verified['pidfd']),'ORIGINAL_SENDER_MUST_BE_LIVE')
        self.live=live;self.pid=os.getpid();self.fd=None;self.sender_fd=None;unclaimed=[]
        try:
            live.channel.sendall(b'L')
            raw,anc,flags,_=live.channel.recvmsg(4096,socket.CMSG_SPACE(array.array('i').itemsize))
            for level,kind,data in anc:
                if level==socket.SOL_SOCKET and kind==socket.SCM_RIGHTS:
                    received=array.array('i');received.frombytes(data[:len(data)-len(data)%received.itemsize])
                    unclaimed.extend(received)
            require(raw.endswith(b'\n') and not flags&(socket.MSG_CTRUNC|socket.MSG_TRUNC) and len(anc)==1
                    and anc[0][:2]==(socket.SOL_SOCKET,socket.SCM_RIGHTS) and len(unclaimed)==1,
                    'EXACT_ONE_WRITER_FD_REQUIRED')
            self.sender_fd=unclaimed.pop();msg=json.loads(raw)
            require(type(msg) is dict and set(msg)=={'schema','writer_fd'} and msg['schema']=='ci_writer_lease_transfer_v1'
                    and type(msg['writer_fd']) is int and msg['writer_fd']>=0,'EXACT_WRITER_FD_MESSAGE_REQUIRED')
            info=marker._durable_marker_identity(live.coord);expected=tuple(info[3]['writer_lock_identity'])
            source=os.stat('/proc/%d/fd/%d'%(live.anchor.verified['pid'],msg['writer_fd']))
            sent=os.fstat(self.sender_fd);named=os.lstat(live.coord.writer_lock)
            require((source.st_dev,source.st_ino)==(sent.st_dev,sent.st_ino)==
                    (named.st_dev,named.st_ino)==expected,'SAME_SENDER_WRITER_INODE_REQUIRED')
            self.fd=os.open(live.coord.writer_lock,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
            opened=os.fstat(self.fd)
            require((opened.st_dev,opened.st_ino)==expected,'SAME_INDEPENDENT_GUARD_INODE_REQUIRED')
            fcntl.flock(self.fd,fcntl.LOCK_SH|fcntl.LOCK_NB)
            require(not terminal._pidfd_terminal(live.anchor.verified['pidfd'])
                    and marker._marker_identity(live.coord)[:3]==live.marker.key,'SAME_LIVE_SENDER_MARKER_REQUIRED')
        except BaseException:
            for fd in unclaimed:os.close(fd)
            if self.fd is not None:os.close(self.fd);self.fd=None
            if self.sender_fd is not None:os.close(self.sender_fd);self.sender_fd=None
            raise
    def close_after_terminal(self):
        terminal.prove_terminal_for_marker(self.live.marker)
        if self.sender_fd is not None:os.close(self.sender_fd);self.sender_fd=None
        if self.fd is not None:os.close(self.fd);self.fd=None
