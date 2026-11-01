"""Test-only original courier/Engine against a Go httptest server on loopback.

Identity checks, native absence and eligibility are fixtures. Never contacts a
provider or production; the fixed-name connector is forced to 127.0.0.1.
"""
import datetime, hashlib, http.client, importlib.util, json, os, socket, ssl
import sys, time, types, urllib.request
from pathlib import Path

def module(name, sha):
 path=Path(__file__).resolve().parent/name
 if hashlib.sha256(path.read_bytes()).hexdigest()!=sha:raise RuntimeError('EXACT_DRAFT_SOURCE_REQUIRED')
 spec=importlib.util.spec_from_file_location('lab_'+path.stem,path)
 m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m

core=module('operate_once.py','7d33e2d78c8e22aa48dd67a917f1f728b4657da0ae87246adf68931154e7a2e3')
h=module('wire_http_DRAFT.py','635c164b674c9c75f018e259ade94b3ed122883d7f7d8ef93a3199106c84e8a8')
action,root_arg,port_arg,cert,grant,job=sys.argv[1:]
root=Path(root_arg).resolve(strict=True);port=int(port_arg)
if action not in ('uncertain','replay','get') or not 1<=port<=65535:raise RuntimeError('LAB_INPUT_REQUIRED')
marker=root/'marker';wire=root/'wire';wire.mkdir(exist_ok=True)
for name in ('intent.json','receipt.json'):
 p=wire/name
 if not p.exists():p.write_text(name)
class Wire:
 path=str(wire);receipt={'request_id':'lab-synthetic-request'};cutoff=time.monotonic()+15;continuous_cutoff=time.monotonic_ns()+15_000_000_000
 def check(self):pass
class Native:
 @staticmethod
 def once(path,value):
  with open(path,'x') as f:json.dump(value,f)
class Operator:
 SERVER=h.SERVER
 def configure(self,**kw):pass
 def request(self,path,method,body=None,**kw):
  if kw['tries']!=1 or kw['allow_replay'] is not False:raise RuntimeError('RETRY_REFUSED')
  req=urllib.request.Request(self.SERVER+path,method=method,data=json.dumps(body).encode() if body is not None else None)
  req.add_header('Authorization','Bearer lab-synthetic-token')
  return json.loads(self._ygg_open(req,kw['timeout']).read())
def summary(value,*_):
 if not isinstance(value,dict) or value.get('grant_id')!=grant or value.get('job_id')!=job or value.get('dispatch_state')!='failed_disposed' or value.get('original_finalization_ack_present') is not False or value.get('original_unknown_ACK_preserved') is not True or value.get('provider_mutations')!=0:raise RuntimeError('EXACT_LAB_SUMMARY_REQUIRED')
c=types.SimpleNamespace(ROUTE='/api/v1/ops/capacity/failed-original-dispositions',NEW_CORE_SOURCE='lab-fixture',fresh=lambda v:None,utc=lambda s:datetime.datetime.fromisoformat(s.replace('Z','+00:00')),loads=json.loads,summary=summary)
out=root/action;out.mkdir();e=object.__new__(core.Engine);e.c=c;e.t={'grant':grant,'job':job};e.a=types.SimpleNamespace(execute_reviewed_sha256='a'*64,contract_sha256='b'*64,Core_context_ref=('lab','fixture'));e.out=out;e.n=Native;e.wire=Wire();e.hard=time.monotonic()+30;e.continuous=lambda:(time.monotonic_ns(),time.monotonic_ns());e.current_core=lambda *a:None;e.prior_cleanup=lambda:None;e.fresh_absence=lambda:None
def snapshot(label):
 (out/(label+'-ELIGIBILITY.PUBLIC.json')).write_text('{}');e.snapshot_cutoff=time.monotonic_ns()+15_000_000_000
 return {'observed_at':datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00','Z')},{}
e.snapshot=snapshot;core.MARKER=marker;op=Operator();core.load=lambda path,pin:h if path==core.HTTP else op
ctx=ssl.create_default_context(cafile=cert);orig=http.client.HTTPSConnection
def loopback(host,port_arg,**kw):
 if (host,port_arg)!=('yggdrasil.dakasa.me',443):raise RuntimeError('FIXED_NAME_REQUIRED')
 conn=orig(host,port_arg,**kw)
 conn._create_connection=lambda _address,timeout=None,source_address=None:socket.create_connection(('127.0.0.1',port),timeout,source_address)
 return conn
h.ssl.create_default_context=lambda:ctx;h.http=types.SimpleNamespace(client=types.SimpleNamespace(HTTPSConnection=loopback))
if action=='get':
 result=e.ledger(False)
 if not result['GET_never_replays_POST']:raise RuntimeError('GET_ONLY_REQUIRED')
 print('LAB_GET_RECONCILED')
else:
 try:e.ledger(True)
 except RuntimeError as ex:
  expected='UNCERTAIN_OR_REFUSED_REQUEST_GET_ONLY_NO_REPLAY' if action=='uncertain' else 'ONE_POSSIBLE_POST_NEVER_REPLAY'
  if str(ex)!=expected:raise
  if not marker.is_dir():raise RuntimeError('MARKER_REQUIRED')
  print('LAB_'+action.upper()+'_HOLD')
 else:raise RuntimeError('HOLD_REQUIRED')
