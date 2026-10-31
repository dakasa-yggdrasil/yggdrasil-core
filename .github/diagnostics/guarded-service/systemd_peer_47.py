"""Service-shaped peer for disposable Guardian precommit integration test."""
import json,os,socket,sys
from pathlib import Path
raw=Path('/proc/self/stat').read_bytes().rsplit(b') ',1)[1].split()
ticks=int(raw[19])
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.connect(sys.argv[1]);s.settimeout(10)
request={'schema':'lab_precommit47_request_v1','nonce':'a'*64,'sender_pid':os.getpid(),
         'sender_start_ticks':ticks,'origin_digest':'b'*64,'origin_raw_sha256':'c'*64}
s.sendall((json.dumps(request,sort_keys=True,separators=(',',':'))+'\n').encode())
data=bytearray()
while not data.endswith(b'\n'):
    part=s.recv(1)
    if not part:raise RuntimeError('guardian reply missing')
    data.extend(part)
reply=json.loads(data);assert reply['origin_digest']=='b'*64 and reply['production_authority'] is False
s.close()
