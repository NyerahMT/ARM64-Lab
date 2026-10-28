#!/usr/bin/env python3
"""Original x64 boot-path call dependency closure, for native ARM64 sequencing.

Seed ONLY with executed original startup .pdata functions. Traverse *real*
direct CALL targets in complete, hash-pinned original x64 unwind intervals.
Normalize mid-interval targets to owner only with explicit evidence. Classify
original PE calls, imported Windows/CRT and external Steamworks, unresolved
indirect CALLs, and call-cycle SCCs. Generate bounded leaf-first work packages
without mistaking the analysis for native ARM64 execution, fabricated game
logic or Steamworks authorization.

No original instruction bytes, original assets or generated machine code are
placed in diagnostic metadata.
"""
from __future__ import annotations
from bisect import bisect_right
from collections import Counter, deque
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_GRP_CALL
from capstone.x86 import X86_OP_IMM, X86_OP_MEM

MAX_ROOTS=128
MAX_FUNCTIONS=512
MAX_DEPTH=7
MAX_INTERVAL_BYTES=32768
MAX_TOTAL_BYTES=3*1024*1024
MAX_EDGES=8192
MAX_IMPORTS=4096
MAX_BATCH=32

def _index(unwind):
    if not isinstance(unwind,dict) or not 1<=len(unwind)<=600000:
        raise ValueError("Invalid original PE unwind index")
    spans=sorted(unwind.items())
    starts=[v[0] for v in spans]
    ends=[v[1] for v in spans]
    for i,(start,end) in enumerate(spans):
        if (not isinstance(start,int) or not isinstance(end,int) or
            start<0 or start>=end or end>1<<32 or
            i and ends[i-1]>start):
            raise ValueError("Untrusted original unwind overlap or boundary")
    return starts,ends

def _owner(va,starts,ends):
    i=bisect_right(starts,va)-1
    return starts[i] if i>=0 and va<ends[i] else None

def _scc(graph):
    """Deterministic Tarjan SCCs; each SCC must translate/link as one group."""
    counter=[0]
    ids={}
    low={}
    stack=[]
    visiting=set()
    groups=[]
    def visit(node):
        ids[node]=low[node]=counter[0]
        counter[0]+=1
        stack.append(node);visiting.add(node)
        for nxt in sorted(graph.get(node,())):
            if nxt not in ids:
                visit(nxt);low[node]=min(low[node],low[nxt])
            elif nxt in visiting:
                low[node]=min(low[node],ids[nxt])
        if low[node]==ids[node]:
            group=[]
            while True:
                nxt=stack.pop()
                visiting.remove(nxt)
                group.append(nxt)
                if nxt==node:break
            groups.append(tuple(sorted(group)))
    for node in sorted(graph):
        if node not in ids:visit(node)
    return sorted(groups,key=lambda group:(len(group),group))

def analyze_native_boot_closure(pe,unwind,priorities,imports,*,base,
                                max_depth=MAX_DEPTH,max_functions=MAX_FUNCTIONS):
    if not 0<=max_depth<=MAX_DEPTH or not 1<=max_functions<=MAX_FUNCTIONS:
        raise ValueError("Unbounded original startup dependency walk")
    roots=priorities.get("prioritized_original_functions")
    if not isinstance(roots,list) or not 1<=len(roots)<=MAX_ROOTS:
        raise ValueError("Missing bounded actually executed x64 startup roots")
    if not isinstance(imports,list) or len(imports)>MAX_IMPORTS:
        raise ValueError("Invalid original PE import list")
    starts,ends=_index(unwind)
    if not isinstance(base,int) or not 0<=base<1<<64:
        raise ValueError("Invalid original PE image base")
    iat={}
    for slot,library,symbol in imports:
        if not 0<=slot<1<<32 or slot in iat:
            raise ValueError("Duplicate/bad original IAT slot")
        iat[slot]=(library,symbol)
    queue=deque()
    seen_roots=set()
    for row in roots:
        va=int(row["original_function_entry_rva"],16)
        if va not in seen_roots:
            if _owner(va,starts,ends)!=va:
                raise ValueError("Startup seed was not an exact original unwind entry")
            queue.append((va,0));seen_roots.add(va)
    graph={}
    detail={}
    total_bytes=0
    total_edges=0
    omitted=set()
    truncated=False
    unknown_targets=Counter()
    visited=set()
    decoder=Cs(CS_ARCH_X86,CS_MODE_64)
    decoder.detail=True
    while queue:
        va,depth=queue.popleft()
        if va in visited:continue
        if len(visited)>=max_functions:
            truncated=True;omitted.add(va)
            continue
        if _owner(va,starts,ends)!=va:
            raise ValueError("Original dependency queued without unwind start")
        end=ends[bisect_right(starts,va)-1]
        length=end-va
        if length>MAX_INTERVAL_BYTES or length<=0 or total_bytes+length>MAX_TOTAL_BYTES:
            detail[va]={"status":"original_unwind_window_out_of_budget",
                        "depth":depth,"native_verified":False}
            visited.add(va)
            truncated=True
            continue
        try:
            body=bytes(pe.read_rva(va,length))
        except (ValueError,OverflowError):
            detail[va]={"status":"unreadable_original_unwind_body",
                        "depth":depth,"native_verified":False}
            visited.add(va)
            continue
        instructions=list(decoder.disasm(body,base+va))
        if not instructions or sum(x.size for x in instructions)!=length:
            detail[va]={"status":"nonlinear_or_partial_original_decode",
                        "depth":depth,"native_verified":False}
            visited.add(va)
            continue
        total_bytes+=length
        visited.add(va)
        downstream=set()
        imports_used=set()
        indirect=0
        embedded_entry_calls=0
        original_direct=0
        for inst in instructions:
            if not inst.group(CS_GRP_CALL):continue
            total_edges+=1
            if total_edges>MAX_EDGES:raise ValueError("Unbounded original call graph")
            op=inst.operands[0] if inst.operands else None
            if op is not None and op.type==X86_OP_IMM:
                destination=op.imm-base
                owner=_owner(destination,starts,ends)
                if owner is None:
                    unknown_targets["direct_CALL_outside_unwind"]+=1
                    continue
                original_direct+=1
                if destination!=owner:
                    embedded_entry_calls+=1
                downstream.add(owner)
                if owner not in visited and depth<max_depth:
                    queue.append((owner,depth+1))
                elif owner not in visited:
                    omitted.add(owner);truncated=True
            elif (op is not None and op.type==X86_OP_MEM and
                  inst.reg_name(op.mem.base)=="rip" and not op.mem.index):
                slot=inst.address+inst.size+op.mem.disp-base
                pair=iat.get(slot)
                if pair:
                    lib,name=pair
                    cls=("Steamworks_external" if lib.lower() in
                         ("steam_api64.dll","steam_api.dll") else "Windows_CRT_external")
                    imports_used.add((cls,lib.lower(),name))
                else:indirect+=1
            else:indirect+=1
        graph[va]=downstream
        detail[va]={
            "status":"original_linear_call_edges_classified_not_native_proof",
            "depth":depth,
            "direct_original_CALL_count":original_direct,
            "direct_original_callee_entries":[hex(x) for x in sorted(downstream)],
            "mid_function_direct_call_targets":embedded_entry_calls,
            "named_imports":[{"class":cls,"library":lib,"symbol":name}
                             for cls,lib,name in sorted(imports_used)],
            "unknown_or_indirect_CALL_count":indirect,
            "native_verified":False,
        }
    actual=set(graph)
    # Leaf-first dependency ordering: a batch becomes independently addressable
    # only after its known original callees; cycles are grouped, never ignored.
    internal={v:{c for c in children if c in actual} for v,children in graph.items()}
    groups=_scc(internal)
    group_index={v:i for i,group in enumerate(groups) for v in group}
    deps={i:{group_index[n] for v in group for n in internal[v]
             if group_index[n]!=i} for i,group in enumerate(groups)}
    remaining=set(range(len(groups)))
    ordered=[]
    while remaining:
        ready=sorted([i for i in remaining if not (deps[i]&remaining)],
                     key=lambda i:(min(detail[v]["depth"] for v in groups[i]),
                                   groups[i]))
        if not ready:raise RuntimeError("SCC condensation graph must be acyclic")
        for i in ready:
            ordered.append(i);remaining.remove(i)
    batches=[]
    for gi in ordered:
        members=groups[gi]
        named={tuple((e["class"],e["library"],e["symbol"])) for n in members
               for e in detail[n]["named_imports"]}
        blockers={
            "needs_original_native_translation":len(members),
            "Steamworks_external":sum(v[0]=="Steamworks_external" for v in named),
            "Windows_CRT_external":sum(v[0]=="Windows_CRT_external" for v in named),
            "unknown_indirect_CALL":sum(detail[n]["unknown_or_indirect_CALL_count"] for n in members),
            "out_of_walk_direct_callees":len(set().union(*(graph[n] for n in members))-actual),
        }
        batches.append({
            "original_function_entry_rvas":[hex(v) for v in members],
            "original_function_count":len(members),
            "original_call_cycle":len(members)>1 or any(v in graph[v] for v in members),
            "known_imports":[{"class":a,"library":b,"symbol":c} for a,b,c in sorted(named)],
            "blockers":blockers,
            "fully_translated_to_native_arm64":False,
            "executable_on_iphone":False,
        })
    # Leaf-first *analysis* is not native readiness: only name groups that
    # have no original child/call/import obligations as immediate translation
    # candidates, and keep all external dependencies explicit.
    foundational=[]
    for i,b in enumerate(batches):
        roots=[int(x,16) for x in b["original_function_entry_rvas"]]
        blockers=b["blockers"]
        if (not b["original_call_cycle"] and
            not any(graph.get(v) for v in roots) and
            not blockers["Steamworks_external"] and
            not blockers["Windows_CRT_external"] and
            not blockers["unknown_indirect_CALL"] and
            not blockers["out_of_walk_direct_callees"]):
            foundational.append(i)
    all_imports={tuple((x["class"],x["library"],x["symbol"]))
                 for v in detail.values() for x in v.get("named_imports",[])}
    return {
        "schema":1,
        "source":"actual SHA-pinned original x64 startup unwind PCs and direct-CALL code metadata",
        "observed_x64_seed_functions":len(seen_roots),
        "reachable_original_functions_inspected":len(visited),
        "complete_linear_callsite_windows":len(actual),
        "direct_original_CALL_edges":sum(len(v) for v in graph.values()),
        "named_original_import_dependencies":len(all_imports),
        "steamworks_external_dependencies":sum(v[0]=="Steamworks_external" for v in all_imports),
        "unresolved_indirect_CALL_sites":sum(v["unknown_or_indirect_CALL_count"]
                                            for v in detail.values() if "unknown_or_indirect_CALL_count" in v),
        "direct_target_outside_unwind":dict(unknown_targets),
        "unvisited_required_original_callees":[hex(x) for x in sorted(omitted)],
        "closure_truncated":truncated,
        "original_call_cycle_components":sum(b["original_call_cycle"] for b in batches),
        "foundational_no_call_no_import_translation_batch_indices":foundational,
        "foundational_translation_batch_count":len(foundational),
        "all_original_direct_calls_closed_to_known_unwind_entries":(
            not truncated and not unknown_targets and
            len(graph)==len(visited) and
            all(not b["blockers"]["out_of_walk_direct_callees"] for b in batches)),
        "complete_boot_runtime_or_auth_closure":False,
        "topological_native_translation_batches":batches,
        "per_original_function":{hex(k):v for k,v in sorted(detail.items())},
        "actual_original_arm64_functions_native_verified_by_this_pass":0,
        "steam_authorization_bypassed":False,
        "original_steam_runtime_executed":False,
        "iphone_game_launched":False,
        "proprietary_source_or_binaries_exported":False,
    }
