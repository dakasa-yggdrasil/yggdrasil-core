"""LAB-only holder IPC; no message provides external effect authority.

Peer identity is established separately from systemd and SO_PEERCRED before
construction. The only callback that may issue a lease uses the Guardian's
same-process Reader, generation certificate and coverage chain. This protocol
is observational; effect-boundary admission must be independently fenced.
"""
import json
import socket
import threading
import select
import time
import guarded_effect_lease_two_peers_DRAFT as effect_lease


class HolderSession:
    def __init__(self, channel, authority, acquire, validate_status, *, renew=None, status=None, release=None, on_lost=None):
        if type(channel) is not socket.socket or channel is not authority.channel or not callable(acquire) or not callable(validate_status):
            raise RuntimeError('ORIGINAL_AUTHENTICATED_HOLDER_CHANNEL_REQUIRED')
        self.channel, self.authority, self.acquire, self.validate_status = channel, authority, acquire, validate_status
        self.renew,self.status,self.release,self.on_lost=renew,status,release,on_lost
        self.lock = threading.Lock()
        self.stopped = threading.Event()
        self.last_id = 0
        self.monitor = None

    def _send(self, value):
        encoded = (json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()
        with self.lock:
            self.channel.sendall(encoded)

    def revoke_and_notify(self):
        if self.on_lost is not None:self.on_lost()
        else:self.authority.revoke()
        try:self._send({'event':'REVOKED'})
        except (BrokenPipeError,ConnectionResetError,OSError):pass

    def serve(self):
        def monitor():
            while not self.stopped.wait(.05):
                with self.authority.lock:lease=self.authority.lease
                if lease is None:continue
                try:self.authority._source_live(lease)
                except Exception:
                    with self.authority.lock:same=self.authority.lease is lease and not lease['revoked']
                    if not same:continue
                    self.revoke_and_notify();self.stopped.set()
                    try:self.channel.shutdown(socket.SHUT_RD)
                    except OSError:pass
                    return
        worker=threading.Thread(target=monitor);self.monitor=worker;worker.start()
        stream = self.channel.makefile('rb',buffering=0)
        try:
            while not self.stopped.is_set():
                raw=stream.readline(4097)
                if not raw:break
                if len(raw)>4096 or not raw.endswith(b'\n'):raise RuntimeError('BOUNDED_SINGLE_REQUEST_REQUIRED')
                def pairs(items):
                    out={}
                    for key,value in items:
                        if key in out:raise RuntimeError('DUPLICATE_JSON_KEY')
                        out[key]=value
                    return out
                req=json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _: (_ for _ in ()).throw(RuntimeError('FINITE_JSON_REQUIRED')))
                if type(req) is not dict or type(req.get('id')) is not int or req['id']<=self.last_id:
                    raise RuntimeError('MONOTONIC_REQUEST_ID_REQUIRED')
                ident=req['id'];self.last_id=ident;op=req.get('op')
                try:
                    if op=='acquire' and set(req)=={'id','op','until_ns'} and type(req['until_ns']) is int:
                        issued=self.acquire(req['until_ns'])
                        value={key:issued[key] for key in ('token','expires_monotonic_ns','genid','external_effect_authorized','production_authority')}
                    elif op=='status' and set(req)=={'id','op','token'} and type(req['token']) is str:
                        if self.status is not None:value=self.status(req['token'])
                        else:
                            self.authority.status(req['token']);self.validate_status()
                            value=self.authority.status(req['token'])
                    elif (op=='renew' and set(req)=={'id','op','token','until_ns'}
                          and type(req['token']) is str and type(req['until_ns']) is int and self.renew is not None):
                        value=self.renew(req['token'],req['until_ns'])
                    elif op=='release' and set(req)=={'id','op','token'} and type(req['token']) is str:
                        value=(self.release(req['token']) if self.release is not None else self.authority.release(req['token']))
                    else:raise RuntimeError('EXACT_OPERATION_FIELDS_REQUIRED')
                    if value.get('external_effect_authorized') is not False:
                        raise RuntimeError('NO_EXTERNAL_AUTHORITY')
                    self._send({'id':ident,'ok':True,**value})
                except effect_lease.BusyBeforeRenew:
                    self._send({'id':ident,'ok':False,'reason':'BUSY'})
                except Exception:
                    self.revoke_and_notify()
                    self._send({'id':ident,'ok':False,'reason':'HOLD'})
        finally:
            if self.on_lost is not None:self.on_lost()
            else:self.authority.revoke()
            self.stopped.set()
            worker.join(3)
            if worker.is_alive():raise RuntimeError('HOLDER_MONITOR_NOT_STOPPED')
            stream.close()


def require_terminal(worker, label, timeout=5):
    if worker is not None:
        worker.join(timeout)
        if worker.is_alive():raise RuntimeError(label+'_NOT_TERMINAL')


def close_after_workers(worker, session, authority, timeout=5):
    """Do not close peer, preparer or sender FDs while either reader lives."""
    require_terminal(worker,'HOLDER_WORKER',timeout)
    monitor=None if session is None else session.monitor
    require_terminal(monitor,'HOLDER_MONITOR',timeout)
    if authority is not None:authority.close()
