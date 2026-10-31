"""Disposable Linux netns experiment: original nft render/transport under CPU load.

Four alternating trials share one pinned core with eight fixed CPU competitors.
Every invocation renders a new synthetic observation. This is not production
and it does not prove a solution to late kernel effects or endpoint availability.
"""
import collections, json, os, pathlib, signal, statistics, subprocess, sys, time
import nft_owner as nft
import original_process as transport

N=40
HOGS=8
FIXTURE=b'''add table inet dakasa_capacity_network
add set inet dakasa_capacity_network core_ready4 { type ipv4_addr; flags timeout; size 8; }
add set inet dakasa_capacity_network prometheus_ready4 { type ipv4_addr; flags timeout; size 1; }
add set inet dakasa_capacity_network backend_forward4 { type ipv4_addr . inet_service . ipv4_addr . inet_service; flags timeout; size 8; }
add map inet dakasa_capacity_network backend_dnat4 { type ipv4_addr . inet_service : ipv4_addr . inet_service; flags timeout; size 8; }
'''

def child(level):
    os.setpriority(os.PRIO_PROCESS,0,level)
    actual=os.getpriority(os.PRIO_PROCESS,0)
    if actual != level:
        print(json.dumps({'status':'PRIORITY_UNAVAILABLE','requested':level,'actual':actual}),flush=True);return 2
    rows=[]
    for i in range(N):
        start=time.monotonic()
        backends=[nft.Backend(k,a,nft.PORTS[k],start,start+20.,'test-only') for k,a in [('core','10.42.1.1'),('broker','10.43.1.2'),('rds','10.43.1.3'),('redis','10.43.1.4')]]
        prom=nft.PrometheusSource('10.42.1.2',start,start+20.,'test-only')
        payload=nft.render_refresh(backends,now=start,prometheus_sources=[prom]).encode()+('# trial '+str(i)+'\n').encode()
        before=time.monotonic()
        if before-start>=.05:
            rows.append({'elapsed':before-start,'outcome':'presend_discard'});continue
        capture={}
        try:
            out,facts=transport.native(['/usr/sbin/nft','-f','-'],stdin=payload,deadline=before+.2,capture=capture)
            ok=facts.get('wait_zero') and facts.get('stdout_EOF') and facts.get('stderr_EOF') and facts.get('local_child_joined')
            rows.append({'elapsed':time.monotonic()-before,'outcome':'success' if ok else 'closed_failure'})
        except Exception as e:
            rows.append({'elapsed':time.monotonic()-before,'outcome':'unknown_or_timeout','reason':type(e).__name__,'guard':str(e)[:100]})
    print(json.dumps({'status':'complete','nice':actual,'samples':rows}),flush=True);return 0

def pct(xs,p):
    xs=sorted(xs)
    return xs[min(len(xs)-1,int((len(xs)-1)*p))] if xs else None

def main():
    if len(sys.argv)==3 and sys.argv[1]=='worker':return child(int(sys.argv[2]))
    assert os.geteuid()==0
    cpus=sorted(os.sched_getaffinity(0));cpu=cpus[-1];os.sched_setaffinity(0,{cpu})
    subprocess.run(['/usr/sbin/nft','-f','-'],input=FIXTURE,check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=15)
    hogs=[subprocess.Popen([sys.executable,'-c','while True: pass'],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL) for _ in range(HOGS)]
    outputs=[]
    try:
        for level in (0,-10,-10,0):
            p=subprocess.run([sys.executable,'-B',__file__,'worker',str(level)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=100,text=True)
            if p.returncode:
                outputs.append({'status':'worker_failed','nice':level,'returncode':p.returncode,'stderr_tail':p.stderr[-400:]});break
            outputs.append(json.loads(p.stdout))
    finally:
        for p in hogs:p.terminate()
        for p in hogs:
            try:p.wait(timeout=3)
            except subprocess.TimeoutExpired:p.kill();p.wait(timeout=3)
        subprocess.run(['/usr/sbin/nft','delete','table','inet','dakasa_capacity_network'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=10)
    summary={}
    for level in (0,-10):
        batches=[x for x in outputs if x.get('nice')==level and x.get('status')=='complete']
        rows=[r for x in batches for r in x['samples']];dur=[r['elapsed'] for r in rows if r['outcome']!='presend_discard'];counts=collections.Counter(r['outcome'] for r in rows)
        summary[str(level)]={'n':len(rows),'counts':dict(counts),'native_seconds_p50':pct(dur,.50),'native_seconds_p95':pct(dur,.95),'native_seconds_p99':pct(dur,.99),'native_seconds_max':max(dur,default=None)}
    result={'schema':'nft_priority_diagnostic_v1','cpu':cpu,'hog_processes':HOGS,'samples_per_batch':N,'batch_order':[0,-10,-10,0],'batches':outputs,'summary':summary,'temporary_netns_only':True,'production_effect':False,'clinical_causality_proven':False,'absolute_kernel_deadline_proven':False}
    pathlib.Path(os.environ['PROBE_OUTPUT']).write_text(json.dumps(result,sort_keys=True)+'\n')
    print(json.dumps({'summary':summary,'all_four_batches_completed':len(outputs)==4 and all(x.get('status')=='complete' for x in outputs),'production_effect':False,'absolute_kernel_deadline_proven':False}),flush=True)
    return 0 if len(outputs)==4 and all(x.get('status')=='complete' for x in outputs) else 2
if __name__=='__main__':raise SystemExit(main())
