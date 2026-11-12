import os,json,time,statistics,platform,sys,tracemalloc,random
from pathlib import Path
from datetime import UTC,datetime
import networkx as nx, psutil
from app.domain.graph_engine import build_networkx_graph,find_attack_paths,verify_reachability
from app.domain.models import *
from app.domain.remediation_sim import RemediationTransform,simulate_remediation
C="c51c1044a88fce763d559c9ea9976f9bd2bba91e"; NOW=datetime(2026,11,12,tzinfo=UTC); OUT=Path("benchmark-results"); OUT.mkdir(exist_ok=True); P=psutil.Process()
def N(i,start=False,target=False): return GraphNode(NodeKind.ASSET,f"n{i}",f"N{i}",criticality="critical" if target else "medium",is_external_entry=start,is_crown_jewel=target,metadata={"initial_capabilities":["session_token"]} if start else {})
def E(i,a,b,m=None): return GraphEdge(f"e{i}",NodeKind.ASSET,f"n{a}",NodeKind.ASSET,f"n{b}",RelationType.CONNECTS_TO,FactKind.OBSERVED_FACT,.9,NOW,edge_metadata=m or {})
def fixture(kind,n,seed):
 r=random.Random(seed); ns=[N(i,i==0,i==n-1) for i in range(n)]; es=[]; k=0
 for i in range(n):
  if kind=="chain":
   if i<n-1:
    m={"adds_capabilities":[f"c{i%9}"]} if i%5==0 else ({"removes_capabilities":[f"c{(i-2)%9}"]} if i%5==2 else {})
    es.append(E(k,i,i+1,m)); k+=1
  elif kind=="cycle":
   es.append(E(k,i,(i+1)%n,{"adds_capabilities":[f"c{i%9}"]} if i%2==0 else {})); k+=1
   for off in (7,31,67,131,251):
    m={"adds_capabilities":[f"c{r.randrange(9)}"]} if r.random()<.4 else {}
    if r.random()<.3:m["removes_capabilities"]=[f"c{r.randrange(9)}"]
    es.append(E(k,i,(i+off)%n,m)); k+=1
  else:
   for off in (1,2,5,11,23):
    if i+off<n: es.append(E(k,i,i+off,{"adds_capabilities":[f"d{i%11}"]} if off in (1,5) else {})); k+=1
 return ns,es
def CSTR(ns,h): return PathSearchConstraints([ns[0].key],[ns[-1].key],algorithm=AlgorithmType.DIJKSTRA,max_hops=h,max_candidates=300,top_k=10,timeout_seconds=30,allow_unknown_preconditions=False)
def run(name,ns,es,rep):
 c=CSTR(ns,max(6,len(ns)-1) if name=="chain100" else 8); rss=P.memory_info().rss; tracemalloc.start()
 t=time.perf_counter();g,bs=build_networkx_graph(ns,es,as_of=NOW);b=(time.perf_counter()-t)*1000
 t=time.perf_counter();p=find_attack_paths(g,c);s=(time.perf_counter()-t)*1000
 t=time.perf_counter();v=verify_reachability(g,c);q=(time.perf_counter()-t)*1000
 _,peak=tracemalloc.get_traced_memory();tracemalloc.stop()
 return dict(case=name,repeat=rep,execution_class="DIRECT_SENTINELGRAPH_DOMAIN",commit=C,nodes=g.number_of_nodes(),edges=g.number_of_edges(),build_ms=b,search_ms=s,verify_ms=q,total_ms=b+s+q,rss_delta_bytes=P.memory_info().rss-rss,python_peak_bytes=peak,paths=len(p.paths),candidates=p.candidates_evaluated,search_complete=p.candidate_search_complete,truncated=p.is_truncated,status=v.status,verify_complete=v.complete,possible=v.reachable_unbounded,confirmed=v.confirmed_reachable_unbounded)
def pct(a,q): 
 a=sorted(a); x=(len(a)-1)*q; i=int(x); return round(a[i]+(a[min(i+1,len(a)-1)]-a[i])*(x-i),4)
def baseline():
 ns=[N(i,i==0,i==4) for i in range(5)]
 es=[E(0,0,1,{"adds_capabilities":["session_token"]}),E(1,1,2,{"requires_capabilities":["session_token"]}),E(2,2,3,{"removes_capabilities":["session_token"]}),E(3,3,4,{"requires_capabilities":["session_token"]})]
 g,_=build_networkx_graph(ns,es,as_of=NOW); c=CSTR(ns,4)
 try: bfs=bool(nx.shortest_path(nx.DiGraph(g),ns[0].key,ns[-1].key))
 except nx.NetworkXNoPath:bfs=False
 v=verify_reachability(g,c)
 # 2-route diamond, exact hitting set over complete simple path enumeration
 dn=[N(i,i==0,i==5) for i in range(6)]; de=[E(10,0,1),E(11,1,5),E(12,0,2),E(13,2,5),E(14,0,3),E(15,3,4),E(16,4,5)]
 dg,_=build_networkx_graph(dn,de,as_of=NOW); paths=[]; stack=[(dn[0].key,[dn[0].key],[])]
 while stack:
  u,np,ep=stack.pop()
  if u==dn[-1].key and ep:paths.append(ep);continue
  for _,z,eid in dg.out_edges(u,keys=True):
   if z not in np:stack.append((z,np+[z],ep+[str(eid)]))
 best=None
 for mask in range(1<<len(de)):
  chosen={de[i].edge_id for i in range(len(de)) if mask>>i&1}
  if all(chosen.intersection(x) for x in paths) and (best is None or len(chosen)<len(best)):best=chosen
 tx=[RemediationTransform(RemediationTransformType.REMOVE_RELATIONSHIP,relationship_id=x) for x in sorted(best or [])]
 sim=simulate_remediation(nodes=dn,edges=de,constraints=CSTR(dn,5),transforms=tx)
 return dict(static_bfs_reachable=bfs,sentinelgraph_status=v.status,verification_complete=v.complete,confirmed_reachable=v.confirmed_reachable_unbounded,static_bfs_false_positive=bool(bfs and v.complete and not v.confirmed_reachable_unbounded),indeterminate_not_counted=not v.complete,hitting_set_path_count=len(paths),hitting_set_selected=sorted(best or []),hitting_set_cardinality=len(best or []),hitting_set_runtime_scope="exact exhaustive subset search on complete 3-path fixture",remediation_residual_status=sim.modelled.reachability_status,residual_verification_complete=sim.modelled.reachability_verification_complete,indeterminate_safety_trigger=sim.modelled.reachability_status=="INDETERMINATE")
def main():
 profile=sys.argv[1] if len(sys.argv)>1 else "section8"; reps=int(sys.argv[2]) if len(sys.argv)>2 else 5; seed=20261112
 m=dict(commit=C,profile=profile,repeats=reps,python=sys.version,platform=platform.platform(),networkx=nx.__version__,generated_at_utc=datetime.now(UTC).isoformat())
 if profile in ("section8","all"):
  specs=[("chain100","chain",100),("cyclic1000","cycle",1000),("layered2500","dag",2500),("layered5000","dag",5000)]; rows=[]
  with open(OUT/"topology_raw.jsonl","w") as f:
   for name,k,n in specs:
    ns,es=fixture(k,n,seed)
    for j in range(reps):
     x=run(name,ns,es,j+1); rows.append(x);f.write(json.dumps(x)+"\\n");f.flush()
  sm=[]
  for name,k,n in specs:
   a=[x for x in rows if x["case"]==name]; sm.append(dict(case=name,nodes=n,edges=a[0]["edges"],runs=len(a),**{f"{z}_{p}":pct([x[z+"_ms" if z!="total" else "total_ms"] for x in a],q) for z in ("build","search","verify","total") for p,q in (("p50",.5),("p95",.95))},peak_python_bytes=max(x["python_peak_bytes"] for x in a),max_rss_delta_bytes=max(x["rss_delta_bytes"] for x in a),statuses={s:sum(x["status"]==s for x in a) for s in set(x["status"] for x in a)},complete_runs=sum(x["verify_complete"] for x in a)))
  m["topology_summary"]=sm
 if profile in ("baseline","all"):
  b=[baseline() for _ in range(reps)]; (OUT/"baseline_raw.json").write_text(json.dumps(b,indent=2));m["baseline_runs"]=b
 (OUT/"manifest.json").write_text(json.dumps(m,indent=2));print(json.dumps(m,indent=2))
if __name__=="__main__":main()
