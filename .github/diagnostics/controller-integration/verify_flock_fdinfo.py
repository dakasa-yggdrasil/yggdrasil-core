"""Real-kernel adversarial flock attribution diagnostic; no send authority."""
import fcntl,json,os,select,socket,tempfile,time
from pathlib import Path

def ticks(pid):
 raw=Path('/proc/%d/stat'%pid).read_bytes();return int(raw[raw.rfind(b')')+1:].split()[19])
def exchange(sock,cmd):
 sock.sendall((cmd+'\n').encode());raw=bytearray()
 while not raw.endswith(b'\n'):
  part=sock.recv(1)
  if not part:raise RuntimeError('CHILD_CLOSED')
  raw.extend(part)
 return json.loads(raw)
def exclusive(fd):
 test=os.open('/proc/self/fd/'+str(fd),os.O_RDONLY|os.O_CLOEXEC)
 try:
  try:fcntl.flock(test,fcntl.LOCK_EX|fcntl.LOCK_NB);return True
  except BlockingIOError:return False
 finally:os.close(test)

def observe(pid,pidfd,fd,expected):
 poll=select.poll();poll.register(pidfd,select.POLLIN|select.POLLHUP|select.POLLERR)
 assert not poll.poll(0);start=ticks(pid)
 path=Path('/proc/%d/fd/%d'%(pid,fd));first=path.stat();data=Path('/proc/%d/fdinfo/%d'%(pid,fd)).read_text().splitlines();last=path.stat()
 assert (first.st_dev,first.st_ino)==(last.st_dev,last.st_ino)==expected and ticks(pid)==start and not poll.poll(0)
 lines=[x for x in data if x.startswith('lock:')]
 if not lines:return False
 assert len(lines)==1
 parts=lines[0].split();assert len(parts)==9 and parts[2:5]==['FLOCK','ADVISORY','READ'] and parts[7:]==['0','EOF']
 major,minor,inode=parts[6].split(':')
 assert (int(major,16),int(minor,16),int(inode))==(os.major(expected[0]),os.minor(expected[0]),expected[1])
 return True

parentfd,path=tempfile.mkstemp(prefix='ci-flock-fdinfo-',dir='/run');os.fchmod(parentfd,0o600)
fcntl.flock(parentfd,fcntl.LOCK_SH|fcntl.LOCK_NB);info=os.fstat(parentfd);expected=(info.st_dev,info.st_ino)
a,b=socket.socketpair();pid=os.fork()
if pid==0:
 a.close();os.close(parentfd)  # do not inherit the other observer's SH OFD
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW);reader=b.makefile('rb',buffering=0)
 try:
  while True:
   op=reader.readline().decode().strip()
   if op=='SH':fcntl.flock(fd,fcntl.LOCK_SH|fcntl.LOCK_NB)
   elif op=='UN':fcntl.flock(fd,fcntl.LOCK_UN)
   elif op=='REOPEN':
    target=fd;os.close(fd);fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    if fd!=target:os.dup2(fd,target);os.close(fd);fd=target
   elif op=='EXIT':break
   b.sendall((json.dumps({'pid':os.getpid(),'fd':fd})+'\n').encode())
 finally:os.close(fd);b.close();os._exit(0)
b.close();pidfd=os.pidfd_open(pid)
try:
 p=exchange(a,'PING');assert p['pid']==pid;fd=p['fd']
 assert not exclusive(parentfd) and not observe(pid,pidfd,fd,expected)
 print('PASS other observer holds SH while sender unlocked: sender fdinfo has no lock',flush=True)
 exchange(a,'SH');assert observe(pid,pidfd,fd,expected) and not exclusive(parentfd)
 print('PASS sender-specific FD shows FLOCK READ after acquisition',flush=True)
 exchange(a,'UN');assert not observe(pid,pidfd,fd,expected) and not exclusive(parentfd)
 r=exchange(a,'REOPEN');assert r['fd']==fd and not observe(pid,pidfd,fd,expected)
 print('PASS release and reused FD do not inherit another observer\'s SH evidence',flush=True)
 exchange(a,'SH');assert observe(pid,pidfd,fd,expected)
 print('BOUNDARY fdinfo is an instantaneous observation, not an atomic fence against later unlock or SCM transfer',flush=True)
finally:
 try:a.sendall(b'EXIT\n')
 except OSError:pass
 a.close();os.waitpid(pid,0);os.close(pidfd);os.close(parentfd);os.unlink(path)
