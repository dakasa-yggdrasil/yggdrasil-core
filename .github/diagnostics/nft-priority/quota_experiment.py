"""Disposable comparison: CPUQuota=100%, same nft transport, nice 0 vs -5.

Target scope has two synthetic CPU peers, sharing a two-CPU affinity with four
external competitors. Alternating blocks compare latency and outsider throughput.
No production authorization, kernel deadline proof, or causal claim follows.
"""
import collections,json,os,pathlib,signal,subprocess,sys,time
import nft_owner as nft
import original_process as transport
N=30
FIXTURE=b'''add table inet dakasa_capacity_network
add set inet dakasa_capacity_network core_ready4 { type ipv4_addr; flags timeout; size 8; }
add set inet dakasa_capacity_network prometheus_ready4 { type ipv4_addr; flags timeout; size 1; }
add set inet dakasa_capacity_network backend_forward4 { type ipv4_addr . inet_service . ipv4_addr . inet_service; flags timeout; size 8; }
add map inet dakasa_capacity_network backend_dnat4 { type ipv4_addr . inet_service : ipv4_addr . inet_service; flags timeout; size 8; }
'''
HOG='''import json,signal,time\nstart=time.monotonic();n=0;stop=False\ndef done(*_):\n global stop;stop=True\nsignal.signal(signal.SIGTERM,done)\nwhile not stop:n+=1\nprint(json.dumps({"iterations":n,"elapsed":time.monotonic()-start}),flush=True)'''

def start_hogs(n):return [subprocess.Popen([sys.executable,'-u','-c',HOG],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True) for _ in range(n)]
def end_hogs(ps):
 for p in ps:p.terminate()
 rows=[]
 for p in ps:
  try:out,_=p.communicate(timeout=4);rows.append(json.loads(out))
  except Exception:p.kill();p.communicate();rows.append({'error':'no_counter'})
 return rows

def cpu_stats():
 row=pathlib.Path('/proc/self/cgroup').read_text().strip().splitlines()[0];path=row.split(':',2)[2]
 p=pathlib.Path('/sys/fs/cgroup')/path.lstrip('/')
 data={}
 for name in ('cpu.stat','cpu.max'):
  data[name]=(p/name).read_text()
 return data

def worker(nice):
 peers=start_hogs(2);start=cpu_stats();before=os.getpriority(os.PRIO_PROCESS,0)
 try:
  assert start['cpu.max'].strip()=='100000 100000', 'EXPECTED_ONE_CPU_QUOTA'
  os.setpriority(os.PRIO_PROCESS,0,nice);actual=os.getpriority(os.PRIO_PROCESS,0)
  childnice=int(subprocess.check_output([sys.executable,'-c','import os;print(os.getpriority(os.PRIO_PROCESS,0))'],text=True,timeout=10))
  policy=os.sched_getscheduler(0);rt=os.sched_getparam(0).sched_priority
  rows=[]
  for i in range(N):
   began=time.monotonic();backend=[nft.Backend(k,a,nft.PORTS[k],began,began+20.,'test-only') for k,a in [('core','10.42.1.1'),('broker','10.43.1.2'),('rds','10.43.1.3'),('redis','10.43.1.4')]]
   prom=nft.PrometheusSource('10.42.1.2',began,began+20.,'test-only');payload=nft.render_refresh(backend,now=began,prometheus_sources=[prom]).encode()+('# qtrial '+str(i)+'\n').encode();t=time.monotonic()
   if t-began>=.05:rows.append({'outcome':'presend_discard','elapsed':t-began});continue
   try:
    _,f=transport.native(['/usr/sbin/nft','-f','-'],stdin=payload,deadline=t+.2)
    ok=all(f.get(k) is True for k in ('wait_zero','stdout_EOF','stderr_EOF','local_child_joined'))
    rows.append({'outcome':'success' if ok else 'closed_failure','elapsed':time.monotonic()-t})
   except Exception as e:rows.append({'outcome':'unknown_or_timeout','elapsed':time.monotonic()-t,'guard':str(e)[:100]})
  os.setpriority(os.PRIO_PROCESS,0,before);restored=os.getpriority(os.PRIO_PROCESS,0)
  result={'status':'complete','nice':nice,'actual':actual,'child_nice':childnice,'scheduler':policy,'realtime_priority':rt,'restored_nice':restored,'stats_before':start,'stats_after':cpu_stats(),'samples':rows}
 finally:end_hogs(peers)
 print(json.dumps(result),flush=True);return 0

def pct(xs,p):
 xs=sorted(xs);return xs[min(len(xs)-1,int((len(xs)-1)*p))] if xs else None

def main():
 if len(sys.argv)==3 and sys.argv[1]=='worker':return worker(int(sys.argv[2]))
 assert os.geteuid()==0
 cpus=sorted(os.sched_getaffinity(0));assert len(cpus)>=2;os.sched_setaffinity(0,set(cpus[-2:]))
 subprocess.run(['/usr/sbin/nft','-f','-'],input=FIXTURE,check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=15)
 runs=[]
 try:
  for i,nice in enumerate((0,-5,-5,0)):
   outsiders=start_hogs(4)
   try:
    args=['/usr/bin/systemd-run','--quiet','--scope','--unit=nft-priority-ci-'+str(i),'-p','CPUQuota=100%','-p','CPUQuotaPeriodSec=100ms',sys.executable,'-B',__file__,'worker',str(nice)]
    p=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=150,text=True)
   finally:competitors=end_hogs(outsiders)
   if p.returncode:runs.append({'status':'worker_failed','nice':nice,'returncode':p.returncode,'stderr_tail':p.stderr[-700:],'competitors':competitors});break
   row=json.loads(p.stdout);row['competitors']=competitors;runs.append(row)
 finally:subprocess.run(['/usr/sbin/nft','delete','table','inet','dakasa_capacity_network'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=10)
 summary={}
 for nice in (0,-5):
  blocks=[x for x in runs if x.get('status')=='complete' and x.get('nice')==nice];rows=[s for b in blocks for s in b['samples']];ds=[x['elapsed'] for x in rows if x['outcome']!='presend_discard'];rates=[c['iterations']/c['elapsed'] for b in blocks for c in b['competitors'] if c.get('elapsed',0)>0]
  summary[str(nice)]={'n':len(rows),'counts':dict(collections.Counter(x['outcome'] for x in rows)),'p50_s':pct(ds,.5),'p95_s':pct(ds,.95),'p99_s':pct(ds,.99),'max_s':max(ds,default=None),'external_iterations_per_second_sum':sum(rates)/len(blocks) if blocks else None,'rollback_verified':all(b['actual']==nice and b['child_nice']==nice and b['restored_nice']==0 and b['scheduler']==0 and b['realtime_priority']==0 for b in blocks) if blocks else False}
 data={'schema':'nft_nice_quota_diagnostic_v1','affinity':cpus[-2:],'scope_cpu_quota':'100%/100ms','target_synthetic_cpu_peers':2,'external_cpu_competitors':4,'order':[0,-5,-5,0],'runs':runs,'summary':summary,'synthetic_pressure_not_production':True,'absolute_deadline_kernel_effect_proven':False,'production_effect':False}
 pathlib.Path(os.environ['PROBE_OUTPUT']).write_text(json.dumps(data,sort_keys=True)+'\n');print(json.dumps({'summary':summary,'complete':len(runs)==4 and all(x.get('status')=='complete' for x in runs),'production_effect':False}),flush=True)
 return 0 if len(runs)==4 and all(x.get('status')=='complete' for x in runs) else 2
if __name__=='__main__':raise SystemExit(main())
