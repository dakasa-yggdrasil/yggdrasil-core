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
    def __init__(self,anchor,netlink,expected_genid):
        require(type(anchor) is terminal.MarkerAnchor and type(netlink) is socket.socket
                and type(expected_genid) is int,'EXACT_CUSTODIAN_INPUTS_REQUIRED')
        self.anchor=anchor;self.netlink=netlink;self.expected_genid=expected_genid
        self.fd=None;self.pid=os.getpid()
    def __enter__(self):
        coord=self.anchor.coordinator
        observed=marker._durable_marker_identity(coord)
        require(observed[:3]==self.anchor.key,'ORIGINAL_MARKER_REQUIRED')
        recorded=observed[3].get('writer_lock_identity')
        require(type(recorded) is list and len(recorded)==2 and all(type(x) is int for x in recorded),
                'MARKER_WRITER_INODE_REQUIRED')
        fd=os.open(coord.writer_lock,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            self.fd=fd;self.writer_identity=tuple(recorded);self._same_inode()
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            self.verify()
            return self
        except BaseException:
            os.close(fd);self.fd=None;raise
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
        self.channel=channel;self.netlink=netlink;self.coord=coord;self.pid=os.getpid();self.fds=[];self.anchor=None
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
            require(nl.genid(netlink)==before,'KERNEL_CHANGED_DURING_LIVE_CUSTODY')
            self.genid=before
        except BaseException:
            self.close();raise
    def close(self):
        for fd in self.fds:os.close(fd)
        self.fds=[]
        if self.anchor is not None:self.anchor.close();self.anchor=None
