"""Independent systemd holder peer, CI only. No external effect is issued."""
import json,os,socket,sys,time
from pathlib import Path
sockpath,go,acquired,revoked=sys.argv[1:]
deadline=time.monotonic()+20
while not Path(go).exists():
    if time.monotonic()>=deadline:raise RuntimeError('HOLDER_GO_TIMEOUT')
    time.sleep(.01)
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.settimeout(10);s.connect(sockpath)
s.sendall((json.dumps({'id':1,'op':'acquire','until_ns':time.monotonic_ns()+2_500_000_000})+'\n').encode())
def read():
    b=bytearray()
    while not b.endswith(b'\n'):
        c=s.recv(1)
        if not c:raise EOFError('HOLDER_GUARDIAN_CLOSED')
        b.extend(c)
    return json.loads(b)
answer=read()
if not answer.get('ok') or answer.get('production_authority') is not False:raise RuntimeError('REAL_HOLDER_LEASE_REFUSED')
Path(acquired).write_text(json.dumps({'genid':answer['genid'],'until':answer['expires_monotonic_ns']}))
event=read()
if event.get('event')!='REVOKED':raise RuntimeError('EXPECTED_HOLDER_REVOCATION')
Path(revoked).write_text('REVOKED')
s.close()
