#!/usr/bin/env python3
"""Map the entire SHA-verified MX Bikes PE64 executable, metadata only.

Discovers every executable section and every .pdata unwind interval; then
performs bounded Capstone decoding, identifies direct-call graph edges, classifies
indirect/control-flow blockers and ranks short candidates near game main.
No original instructions, machine code, game strings or lifted IR are exported.

Important: unwind coverage != every game function; linear disassembly != proven
control flow; candidate != validated native ARM64 translation or game boot.
"""
from __future__ import annotations
from bisect import bisect_right
from collections import Counter,deque
from pathlib import Path
import argparse
import hashlib
import json
import struct
import sys
import time

from capstone import Cs,CS_ARCH_X86,CS_MODE_64,CS_GRP_CALL,CS_GRP_JUMP,CS_GRP_RET
from capstone.x86 import X86_OP_IMM,X86_OP_MEM

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"arm64-lab"))
from tools.pe_probe import PE

INPUT_SHA="4ae7de3854b4d0a18271679fb57a1f2fdf0b21804417b85dd82055078ea123b6"
MAIN_RVA=0x136710
FIRST_CALLEE=0x136120
ENTRY_RVA=0x2ab31c
CRT_RVA=0x2ab02c
MAX_INTERVAL=32768
MAX_GLOBAL_BYTES=48*1024*1024
MAX_CALL_EDGES=1600000
MAX_UNWIND_RECORDS=600000
TOP_CANDIDATES=512
PER_FUNCTION_CALLS_CAP=1024

def walk_unwind(pe):
    directory,length=pe.directory(3)
    if not directory or not length or length%12 or length//12>MAX_UNWIND_RECORDS:
        raise RuntimeError("Invalid or excessive PE unwind directory")
    rows=list(struct.iter_unpack("<III",pe.read_rva(directory,length)))
    unique={}
    duplicate=0
    invalid=0
    for begin,end,meta in rows:
        if not begin or not meta or end<=begin:
            invalid+=1
            continue
        if begin in unique:
            duplicate+=1
            if unique[begin]!=end:
                raise RuntimeError("Conflicting PE unwind start-to-end intervals")
            continue
        unique[begin]=end
    return unique,len(rows),duplicate,invalid

def map_executable(original,max_interval=MAX_INTERVAL):
    start=time.monotonic()
    pe=PE(original)
    digest=hashlib.sha256(pe.b).hexdigest()
    if digest!=INPUT_SHA:
        raise RuntimeError("Input game executable revision differs from pinned SHA256")
    sections=[(n,rva,rva+max(vsz,sz),sz) for n,vsz,rva,sz,ptr,flags in pe.sections
              if flags&0x20000000]
    if not sections:
        raise RuntimeError("No executable sections in original PE")
    records,total_records,duplicate,invalid=walk_unwind(pe)
    starts=sorted(records)
    ends=[records[begin] for begin in starts]
    def executable_window(begin,end):
        return any(lo<=begin<end<=hi for _,lo,hi,_ in sections)
    def owner(address):
        index=bisect_right(starts,address)-1
        if index<0 or address>=ends[index]:
            return None
        return starts[index]
    decoder=Cs(CS_ARCH_X86,CS_MODE_64)
    decoder.detail=True
    counts=Counter()
    mnemonics=Counter()
    call_targets=Counter()
    direct_by_source={}
    rows=[]
    instruction_count=0
    processed_bytes=0
    total_exec_raw=sum(raw for _,_,_,raw in sections)
    total_exec_virtual=sum(hi-lo for _,lo,hi,_ in sections)
    for begin in starts:
        end=records[begin]
        length=end-begin
        item={
            "rva":hex(begin),"end_rva":hex(end),"bytes":length,
            "status":None,"instructions":0,"direct_calls":0,
            "direct_call_targets":0,"internal_branches":0,
            "escaping_branches":0,"indirect_calls":0,
            "indirect_jumps":0,"import_thunk_calls":0,
            "ret_count":0,"first_control":None,
            "batch_candidate":False,
        }
        if not executable_window(begin,end):
            item["status"]="outside_executable_section"
        elif length>max_interval:
            item["status"]="oversized_interval"
        elif processed_bytes+length>MAX_GLOBAL_BYTES:
            item["status"]="global_decode_budget"
        else:
            try:
                code=pe.read_rva(begin,length)
            except (ValueError,struct.error):
                item["status"]="unmapped_or_truncated"
            else:
                ins=list(decoder.disasm(code,begin))
                if not ins or sum(i.size for i in ins)!=length:
                    item["status"]="incomplete_linear_decode"
                else:
                    item["status"]="decoded_linear"
                    item["instructions"]=len(ins)
                    processed_bytes+=length
                    instruction_count+=len(ins)
                    outgoing=set()
                    for inst in ins:
                        mnemonics[inst.mnemonic]+=1
                        iscall=inst.group(CS_GRP_CALL)
                        isjump=inst.group(CS_GRP_JUMP)
                        isret=inst.group(CS_GRP_RET)
                        if isret:
                            item["ret_count"]+=1
                        if not (iscall or isjump or isret):
                            continue
                        if item["first_control"] is None:
                            item["first_control"]=inst.mnemonic
                        op=inst.operands[0] if inst.operands else None
                        if iscall:
                            if op is not None and op.type==X86_OP_IMM:
                                target=int(op.imm)
                                call_targets[target]+=1
                                outgoing.add(target)
                                item["direct_calls"]+=1
                            elif op is not None and op.type==X86_OP_MEM:
                                item["import_thunk_calls"]+=1
                            else:
                                item["indirect_calls"]+=1
                        if isjump:
                            if op is not None and op.type==X86_OP_IMM:
                                target=int(op.imm)
                                if begin<=target<end:
                                    item["internal_branches"]+=1
                                else:
                                    item["escaping_branches"]+=1
                            else:
                                item["indirect_jumps"]+=1
                    item["direct_call_targets"]=len(outgoing)
                    item["batch_candidate"]=(
                        length<=2048 and len(ins)<=400 and
                        item["indirect_jumps"]==0
                    )
                    if outgoing:
                        direct_by_source[begin]=sorted(outgoing)[:PER_FUNCTION_CALLS_CAP]
        counts[item["status"]]+=1
        rows.append(item)

    decoded_by_begin={int(x["rva"],16):x for x in rows if x["status"]=="decoded_linear"}
    graph={}
    all_function_edges=0
    unknown_direct_targets=Counter()
    for begin,targets in direct_by_source.items():
        matched=[]
        for target in targets:
            tgt=owner(target)
            if tgt in decoded_by_begin:
                matched.append(tgt)
                all_function_edges+=1
            elif executable_window(target,target+1):
                unknown_direct_targets[target]+=1
        if matched:
            graph[begin]=sorted(set(matched))
    roots=[r for r in (MAIN_RVA,FIRST_CALLEE,ENTRY_RVA,CRT_RVA)
           if owner(r) is not None]
    depths={}
    q=deque()
    for root in roots:
        begin=owner(root)
        if begin not in depths:
            depths[begin]=0
            q.append(begin)
    while q:
        src=q.popleft()
        if depths[src]>=12:
            continue
        for next_begin in graph.get(src,()):
            if next_begin not in depths:
                depths[next_begin]=depths[src]+1
                q.append(next_begin)
    for item in rows:
        begin=int(item["rva"],16)
        if begin in depths:
            item["depth_from_known_roots"]=depths[begin]
        if item["status"]=="decoded_linear":
            item["direct_references"]=call_targets[begin]
            item["discovered_in_call_graph"]=begin in depths

    # Direct CALLs can target legitimate x64 leaf routines WITHOUT .pdata.
    # Do not manufacture function boundaries. Identify only their first
    # contiguous, bounded block and report as unconfirmed code entrypoints.
    unwindless_targets=[
        (target,count) for target,count in unknown_direct_targets.items()
        if owner(target) is None
    ]
    unwindless_targets.sort(key=lambda x:(x[0]!=FIRST_CALLEE,-x[1],x[0]))
    unwindless_entries=[]
    for target,refcount in unwindless_targets[:4000]:
        entry={"rva":hex(target),"direct_call_references":refcount,
               "unwind_protected":False,"static_first_block_verified":False,
               "first_control":None,"first_block_instructions":0}
        section=next(((lo,hi) for _,lo,hi,raw in sections
                      if lo<=target<hi and target<lo+raw),None)
        if section:
            end=min(target+256,section[0]+next(
                raw for _,lo,hi,raw in sections if lo==section[0]))
            try:
                blob=pe.read_rva(target,end-target)
                ins_count=0
                for ins in decoder.disasm(blob,target):
                    ins_count+=1
                    if ins_count>48:
                        break
                    if ins.group(CS_GRP_CALL) or ins.group(CS_GRP_JUMP) or ins.group(CS_GRP_RET):
                        entry["first_control"]=ins.mnemonic
                        entry["first_control_rva"]=hex(ins.address)
                        entry["first_block_instructions"]=ins_count
                        entry["static_first_block_verified"]=True
                        break
            except ValueError:
                pass
        unwindless_entries.append(entry)
    candidates=[x for x in rows if x["batch_candidate"]]
    candidates.sort(key=lambda x:(
        x.get("depth_from_known_roots",99),
        x["indirect_calls"]+x["import_thunk_calls"],
        x["bytes"],-x.get("direct_references",0),
        int(x["rva"],16)))
    selected=[]
    # Start with the original main/callee and then closest bounded call graph.
    # This selection does NOT imply semantic completeness or success in Remill.
    seen=set()
    for row in candidates:
        if len(selected)>=TOP_CANDIDATES:
            break
        rva=row["rva"]
        if rva in seen:
            continue
        seen.add(rva)
        selected.append({
            "rva":rva,"end_rva":row["end_rva"],
            "bytes":row["bytes"],"instructions":row["instructions"],
            "root_distance":row.get("depth_from_known_roots"),
            "imports":row["import_thunk_calls"],
            "indirect_calls":row["indirect_calls"],
            "indirect_jumps":row["indirect_jumps"],
            "status":"syntactic_candidate_not_translated"
        })
    # .pdata intervals can overlap/chunk and do not count byte-for-byte twice.
    union=[]
    for row in rows:
        a=int(row["rva"],16)
        b=int(row["end_rva"],16)
        if not executable_window(a,b):
            continue
        if union and a<=union[-1][1]:
            union[-1][1]=max(union[-1][1],b)
        else:
            union.append([a,b])
    unwind_covered=sum(b-a for a,b in union)
    return {
      "schema":1,
      "original_file_verified":True,
      "input_sha256":digest,
      "mapping_kind":"static PE unwind intervals + linear decode + bounded direct-call graph",
      "sections":[{"name":n,"start_rva":hex(lo),"end_rva":hex(hi),
                   "raw_bytes":raw} for n,lo,hi,raw in sections],
      "statistics":{
        "exec_section_count":len(sections),
        "executable_raw_bytes":total_exec_raw,
        "executable_virtual_bytes":total_exec_virtual,
        "pdata_records":total_records,
        "unique_unwind_intervals":len(starts),
        "duplicate_unwind_records":duplicate,
        "invalid_unwind_records":invalid,
        "unwind_covered_executable_bytes":unwind_covered,
        "unwind_exec_coverage_ratio":round(unwind_covered/total_exec_virtual,4) if total_exec_virtual else 0,
        "fully_linear_decoded_intervals":counts["decoded_linear"],
        "fully_linear_decoded_bytes":processed_bytes,
        "original_x64_instructions_statically_decoded":instruction_count,
        "direct_call_targets_found":len(call_targets),
        "direct_call_graph_sources":len(direct_by_source),
        "original_direct_call_edges_to_decoded_intervals":all_function_edges,
        "unknown_direct_executable_targets":len(unknown_direct_targets),
        "direct_call_targets_without_unwind_records":len(unwindless_targets),
        "unwindless_first_blocks_with_control_found":sum(
            bool(x["static_first_block_verified"]) for x in unwindless_entries),
        "root_reachable_decoded_intervals":len(depths),
        "eligible_syntactic_batch_candidates":len(candidates),
        "selected_first_batch_candidates":len(selected),
        "classification_counts":dict(counts),
        "elapsed_seconds":round(time.monotonic()-start,2)
      },
      "roots":[{"requested_rva":hex(r),"unwind_start":hex(owner(r))} for r in roots],
      "top_mnemonics":mnemonics.most_common(35),
      "priority_batch":selected,
      "direct_call_graph":{
          hex(src):[hex(dest) for dest in targets]
          for src,targets in sorted(direct_by_source.items())
      },
      "unmapped_direct_target_examples":[hex(r) for r,_ in unknown_direct_targets.most_common(50)],
      "unwindless_direct_call_candidates":unwindless_entries,
      "interval_map":rows,
      "limitations":[
        "The entire executable's headers, executable sections and unwind records were inventoried.",
        "Unwind intervals are not all game functions; non-unwind leaf functions and jump tables can be missed.",
        "Linear disassembly and basic call edges cannot prove branch or functional completeness.",
        "Candidate status measures structural suitability only; no automatic native compilation is claimed.",
        "No executable input, original code bytes, decompiled source, derived IR or native objects were exported."
      ]
    }

def run(executable,out,max_interval=MAX_INTERVAL):
    mapdata=map_executable(executable,max_interval=max_interval)
    out.mkdir(parents=True,exist_ok=True)
    (out/"whole-game-map.json").write_text(json.dumps(mapdata,separators=(",",":"))+"\n")
    (out/"lift-candidates.json").write_text(json.dumps(
        {"input_sha256":mapdata["input_sha256"],
         "candidates":mapdata["priority_batch"],
         "does_not_prove_arm64_execution":True},indent=2)+"\n")
    stats=mapdata["statistics"]
    lines=[
      "# MX Bikes entire executable — static translation map","",
      f"- SHA-verified original executable: **YES**",
      f"- Executable sections inventoried: **{stats['exec_section_count']}**",
      f"- Executable raw bytes: **{stats['executable_raw_bytes']:,}**",
      f"- PE unwind entries inspected: **{stats['pdata_records']:,}**",
      f"- Unique unwind intervals: **{stats['unique_unwind_intervals']:,}**",
      f"- Completely linearly decoded intervals: **{stats['fully_linear_decoded_intervals']:,}**",
      f"- Original x64 instructions statically decoded: **{stats['original_x64_instructions_statically_decoded']:,}**",
      f"- Direct-call edges into decoded intervals: **{stats['original_direct_call_edges_to_decoded_intervals']:,}**",
      f"- Intervals reached in bounded call graph from main/callee/CRT: **{stats['root_reachable_decoded_intervals']:,}**",
      f"- Structurally eligible batch-lifting candidates: **{stats['eligible_syntactic_batch_candidates']:,}**",
      f"- Selected first batch: **{stats['selected_first_batch_candidates']:,}**",
      f"- Direct-call targets without unwind records: **{stats['direct_call_targets_without_unwind_records']:,}**",
      f"- Such targets with decodable first control block: **{stats['unwindless_first_blocks_with_control_found']:,}**",
      f"- Mapping time: **{stats['elapsed_seconds']} seconds**",
      "",
      "## Classification",
    ]
    for k,v in sorted(stats["classification_counts"].items()):
        lines.append(f"- {k.replace('_',' ')}: {v:,}")
    lines += ["","## Highest-priority discovered function intervals"]
    for x in mapdata["priority_batch"][:24]:
        lines.append(f"- {x['rva']} — {x['bytes']} bytes, {x['instructions']} instructions, root distance {x['root_distance']}")
    lines += ["","## Unwindless code call targets (candidate entries only)"]
    for leaf in mapdata["unwindless_direct_call_candidates"][:15]:
        lines.append(f"- {leaf['rva']}, referenced by {leaf['direct_call_references']} direct calls, "
                     f"first control {leaf['first_control']}, "
                     f"bounded first block verified: {leaf['static_first_block_verified']}")
    lines += ["","**This inventories the original game image. It does not execute each game path, " +
        "prove all functions were found, validate lifted code, boot the engine or render a frame.**",""]
    summary="\n".join(lines)
    (out/"whole-game-map.md").write_text(summary)
    print(summary)
    return mapdata

if __name__=="__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("executable",type=Path)
    parser.add_argument("report_directory",type=Path)
    parser.add_argument("--max-interval",type=int,default=MAX_INTERVAL)
    args=parser.parse_args()
    run(args.executable,args.report_directory,args.max_interval)
