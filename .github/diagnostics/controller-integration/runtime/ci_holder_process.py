"""Independent systemd holder peer, CI only. No external effect is issued."""
import json,os,select,socket,sys,time
from pathlib import Path
sockpath,go,acquired,revoked=sys.argv[1:]
deadline=time.monotonic()+20
while not Path(go).exists():
    if time.monotonic()>=deadline:raise RuntimeError('HOLDER_GO_TIMEOUT')
    time.sleep(.01)
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.settimeout(10);s.connect(sockpath)
def send(value, until_ns=None):
    if until_ns is not None:
        remaining=until_ns-time.monotonic_ns()
        if remaining<=0:raise RuntimeError('HOLDER_PREVIOUS_LEASE_EXPIRED')
        s.settimeout(min(10,remaining/1_000_000_000))
    try:s.sendall((json.dumps(value)+'\n').encode())
    except OSError as exc:
        # A partial write or lost reply is uncertain, never evidence that the
        # recipient or any external operation stopped at the deadline.
        raise RuntimeError('HOLDER_RENEW_SEND_UNKNOWN') from exc
    finally:s.settimeout(10)
    if until_ns is not None and time.monotonic_ns()>=until_ns:
        raise RuntimeError('HOLDER_RENEW_SEND_UNKNOWN')
def read(until_ns=None):
    b=bytearray()
    while not b.endswith(b'\n'):
        if until_ns is not None:
            remaining=until_ns-time.monotonic_ns()
            if remaining<=0:raise RuntimeError('HOLDER_PREVIOUS_LEASE_EXPIRED')
            poll=select.poll();poll.register(s,select.POLLIN|select.POLLHUP|select.POLLERR)
            if not poll.poll(max(1,min(500,(remaining+999999)//1000000))):continue
        c=s.recv(1)
        if not c:raise EOFError('HOLDER_GUARDIAN_CLOSED')
        b.extend(c)
        if len(b)>4096:raise RuntimeError('BOUNDED_HOLDER_REPLY_REQUIRED')
    return json.loads(b)
def revoked_event(row):
    if row.get('event')=='REVOKED':
        Path(revoked).write_text('REVOKED');s.close();sys.exit(42)

send({'id':1,'op':'acquire','until_ns':time.monotonic_ns()+2_500_000_000})
answer=read()
if not answer.get('ok') or answer.get('production_authority') is not False:raise RuntimeError('REAL_HOLDER_LEASE_REFUSED')
old_until=answer['expires_monotonic_ns'];token=answer['token'];ident=1
Path(acquired).write_text(json.dumps({'genid':answer['genid'],'until':old_until,'renewals':0,'started_ns':time.monotonic_ns()}))
if os.environ.get('CI_HOLDER_RENEW_TEST')!='1':
    event=read();revoked_event(event);raise RuntimeError('EXPECTED_HOLDER_REVOCATION')
started=time.monotonic_ns();renewals=0;busy_count=0;genids=[answer['genid']]
while True:
    now=time.monotonic_ns()
    if now>=old_until:raise RuntimeError('HOLDER_PREVIOUS_LEASE_EXPIRED')
    if now<old_until-1_100_000_000:
        poll=select.poll();poll.register(s,select.POLLIN|select.POLLHUP|select.POLLERR)
        if poll.poll(max(1,min(100,(old_until-1_100_000_000-now+999999)//1000000))):
            revoked_event(read(old_until));raise RuntimeError('UNEXPECTED_HOLDER_EVENT')
        continue
    ident+=1;send({'id':ident,'op':'renew','token':token,'until_ns':time.monotonic_ns()+2_500_000_000},old_until)
    reply=read(old_until);revoked_event(reply)
    if reply.get('id')!=ident:raise RuntimeError('EXACT_RENEW_REPLY_ID_REQUIRED')
    if reply.get('reason')=='BUSY':busy_count+=1;time.sleep(.025);continue
    now=time.monotonic_ns();new_until=reply.get('expires_monotonic_ns')
    if (not reply.get('ok') or reply.get('production_authority') is not False
            or reply.get('external_effect_authorized') is not False or reply.get('token')!=token
            or type(new_until) is not int or now>=old_until or new_until<=old_until):
        raise RuntimeError('EXACT_NONOVERLAPPING_RENEWAL_REQUIRED')
    old_until=new_until;renewals+=1;genids.append(reply['genid'])
    Path(acquired).write_text(json.dumps({'genid':reply['genid'],'until':old_until,
                    'renewals':renewals,'busy_count':busy_count,'genids':genids,
                    'started_ns':started,'last_ack_ns':now}))
