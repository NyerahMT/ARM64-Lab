"""Automatic AOT work planner for byte-verified original instruction maps.

The caller supplies a verified decoder map and, optionally, observed execution
counts. Compile all supported instructions, even when adjacent instructions
are unsupported. A gap never becomes an invented instruction or API result.
Generated source/objects remain in a private build directory.
"""
from collections import Counter,defaultdict
import hashlib,json
from pathlib import Path
import mxb_demo_block_batch as blocks

MAX_NODES=32768
MAX_SHARD_NODES=2048

def plan(ins,observed=None,exclude=(),max_nodes=MAX_NODES):
    if not 1<=max_nodes<=MAX_NODES:raise ValueError("node budget")
    observed={} if observed is None else observed
    if any(not isinstance(p,int) or p<0 or not isinstance(n,int) or n<1 for p,n in observed.items()):
        raise ValueError("invalid execution counts")
    if len(ins)>1000000 or len(observed)>1000000:raise ValueError("inventory budget")
    gaps=defaultdict(lambda:{"addresses":0,"executions":0,"sample_pcs":[]})
    supported=set();deferred=set();excluded=set(exclude)
    def gap(pc,op,reason):
        key=(op,reason);g=gaps[key];g["addresses"]+=1;g["executions"]+=observed.get(pc,0)
        if len(g["sample_pcs"])<8:g["sample_pcs"].append(hex(pc))
    # Hot code first; stable tie breaking. A deferred supported address is
    # not an unsupported instruction and is not counted as translated.
    for pc in sorted(set(ins)|set(observed),key=lambda p:(-observed.get(p,0),p)):
        if pc not in ins:
            gap(pc,"unknown","unverified_instruction");continue
        row=ins[pc];op=row[1]
        if op in excluded:
            gap(pc,op,"reference_domain_excluded");continue
        try:blocks.emit(row,pc)
        except ValueError as exc:
            gap(pc,op,str(exc).split(":")[0]);continue
        if len(supported)<max_nodes:supported.add(pc)
        else:deferred.add(pc)
    report={"decoded_pcs":len(ins),"observed_pcs":len(observed),
        "observed_executions":sum(observed.values()),"selected_pcs":len(supported),
        "deferred_supported_pcs":len(deferred),
        "selected_observed_pcs":len(supported&observed.keys()),
        "selected_observed_executions":sum(observed.get(p,0) for p in supported),
        "gaps":[{"mnemonic":op,"reason":why,**g} for (op,why),g in sorted(gaps.items(),key=lambda x:(-x[1]["executions"],-x[1]["addresses"],x[0]))],
        "compiled":False,"arm64_executed":False,"continuous_startup":False}
    return supported,deferred,report

def generate_shards(ins,selected,shard_nodes=MAX_SHARD_NODES):
    """Nonoverlapping shards. Each shard exports uniquely named step/run.
    A common dispatcher can resume at any selected original PC.
    """
    if not 1<=shard_nodes<=MAX_SHARD_NODES or not 0<len(selected)<=MAX_NODES:
        raise ValueError("shard budget")
    groups=[];current=[]
    # Never split an original 4 KiB page between two dispatchers unless
    # absolutely necessary (page size bounds original instruction count).
    for pc in sorted(selected):
        if current and len(current)>=shard_nodes and pc>>12!=current[-1]>>12:
            groups.append(current);current=[]
        current.append(pc)
    if current:groups.append(current)
    shards=[];page_owner={}
    for i,group in enumerate(groups):
        if len(group)>MAX_NODES:raise ValueError("oversized shard")
        src,accepted,rejected=blocks.generate(ins,set(group))
        if accepted!=set(group) or rejected:raise ValueError("planner/generator disagreement")
        src=("#define mxb_block_step mxb_auto_step_"+str(i)+"\n"
             "#define mxb_block_run mxb_auto_run_"+str(i)+"\n"+src)
        for pc in group:
            prior=page_owner.setdefault(pc>>12,i)
            if prior!=i:raise ValueError("page ownership overlap")
        shards.append(src)
    dispatch=[blocks.PREAMBLE]
    dispatch.extend(f"extern int mxb_auto_step_{i}(mxb_cfg*);\n" for i in range(len(shards)))
    dispatch.append("int mxb_auto_step(mxb_cfg*s){if(!s)return -1;switch(s->rip>>12){\n")
    dispatch.extend(f"case UINT64_C({page}):return mxb_auto_step_{i}(s);\n" for page,i in sorted(page_owner.items()))
    dispatch.append("default:return 2;}}\nint mxb_auto_run(mxb_cfg*s,uint64_t stop,unsigned budget){if(!s)return -1;while(budget--){if(s->rip==stop)return 1;int r=mxb_auto_step(s);if(r!=1)return r;}return s->rip==stop?1:0;}\n")
    return shards,"".join(dispatch)

def write_build(ins,selected,destination,report,shard_nodes=MAX_SHARD_NODES):
    """Write a fresh, private build. Never reuse generated code for another
    executable/translator revision; caller owns compilation and validation.
    """
    root=Path(destination);root.mkdir(mode=0o700,parents=True,exist_ok=False)
    shards,dispatch=generate_shards(ins,selected,shard_nodes)
    paths=[]
    for i,source in enumerate([*shards,dispatch]):
        path=root/(f"shard-{i:04d}.c" if i<len(shards) else "dispatch.c")
        path.write_text(source,encoding="utf-8");paths.append(path)
    report=dict(report,shards=len(shards),source_sha256={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in paths})
    (root/"plan.json").write_text(json.dumps(report,indent=2)+"\n",encoding="utf-8")
    return paths,report

def regressions():
    # These are ordinary synthetic instructions, never original game bytes.
    ins={0x1000:(b"\x90","nop",""),0x1001:(b"\xc3","ret",""),
         0x2000:(b"\x0f\xa2","cpuid",""),0x3000:(b"\x90","nop","")}
    chosen,deferred,r=plan(ins,{0x1000:2,0x1001:3,0x2000:20,0x3000:8,0x4000:50},max_nodes=2)
    assert chosen=={0x1001,0x3000} and deferred=={0x1000}
    assert r["selected_observed_executions"]==11 and r["observed_executions"]==83
    assert r["gaps"][0]["reason"]=="unverified_instruction"
    assert r["gaps"][1]["mnemonic"]=="cpuid"
    chosen,_,r=plan(ins,exclude={"ret"})
    assert 0x1001 not in chosen and r["selected_pcs"]==2
    src,dispatch=generate_shards(ins,chosen,1)
    assert len(src)==2 and "mxb_auto_step_0" in src[0] and "mxb_auto_step_1" in src[1]
    assert "case UINT64_C(1):" in dispatch and "case UINT64_C(3):" in dispatch
    for fn in (lambda:plan(ins,{1:0}),lambda:plan(ins,max_nodes=0),lambda:generate_shards(ins,set()),lambda:generate_shards(ins,{0x2000})):
        try:fn()
        except ValueError:pass
        else:raise AssertionError("invalid plan accepted")
    return 11

if __name__=="__main__":
    print("AUTO_TRANSLATOR_REGRESSIONS",regressions())
