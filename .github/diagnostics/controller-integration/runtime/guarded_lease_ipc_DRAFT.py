"""LAB-only holder IPC; no message provides external effect authority.

Peer identity is established separately from systemd and SO_PEERCRED before
construction. The only callback that may issue a lease uses the Guardian's
same-process Reader, generation certificate and coverage chain. This protocol
is observational; effect-boundary admission must be independently fenced.
"""
import json
import socket
import threading


class HolderSession:
    def __init__(self, channel, authority, acquire, validate_status):
        if type(channel) is not socket.socket or channel is not authority.channel or not callable(acquire) or not callable(validate_status):
            raise RuntimeError('ORIGINAL_AUTHENTICATED_HOLDER_CHANNEL_REQUIRED')
        self.channel, self.authority, self.acquire, self.validate_status = channel, authority, acquire, validate_status
        self.lock = threading.Lock()
        self.stopped = threading.Event()
        self.last_id = 0

    def _send(self, value):
        encoded = (json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()
        with self.lock:
            self.channel.sendall(encoded)

    def revoke_and_notify(self):
        self.authority.revoke()
        try:self._send({'event':'REVOKED'})
        except (BrokenPipeError,ConnectionResetError,OSError):pass

    def serve(self):
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
                        self.authority.status(req['token'])
                        self.validate_status()
                        value=self.authority.status(req['token'])
                    elif op=='release' and set(req)=={'id','op','token'} and type(req['token']) is str:
                        value=self.authority.release(req['token'])
                    else:raise RuntimeError('EXACT_OPERATION_FIELDS_REQUIRED')
                    if value.get('external_effect_authorized') is not False:
                        raise RuntimeError('NO_EXTERNAL_AUTHORITY')
                    self._send({'id':ident,'ok':True,**value})
                except Exception:
                    self.revoke_and_notify()
                    self._send({'id':ident,'ok':False,'reason':'HOLD'})
        finally:
            self.authority.revoke()
            self.stopped.set()
            stream.close()
