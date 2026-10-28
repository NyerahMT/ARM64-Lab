#!/usr/bin/env python3
"""Construct a deterministic original-VA native-link plan from the full PE map.

Never equate static decode / successful LLVM object compilation with a verified
callable ARM64 function. Only explicit, differential-verified native symbols
may enter the dispatch registry. Every other call is an actionable unresolved
edge. No executable, instructions or derived machine code are emitted.
"""
import argparse
from collections import Counter,deque
import json
from pathlib import Path
import re

ROOT_MAIN=0x136710
ROOT_CALLEE=0x136120
MAX_DEPTH=9
MAX_VERIFIED=131072
SYMBOL=re.compile(r"^[_a-zA-Z][_a-zA-Z0-9]{0,126}$")

def build(mapping,verified=None):
    stats=mapping["statistics"]
    graph={int(k,16):[int(x,16) for x in values]
           for k,values in mapping.get("direct_call_graph",{}).items()}
    if not graph:
        raise RuntimeError("Whole-game map is missing explicit original direct-call graph")
    indexed={int(x["rva"],16):x for x in mapping["interval_map"]}
    unwindless={int(x["rva"],16):x
                for x in mapping["unwindless_direct_call_candidates"]}
    verified=verified or []
    registrations={}
    for item in verified:
        addr=int(item["original_rva"],16)
        symbol=item["native_symbol"]
        if (addr in registrations or not SYMBOL.fullmatch(symbol) or
            item.get("full_function_behavior_verified") is not True or
            item.get("win64_guest_call_abi_verified") is not True or
            not item.get("differential_test_run_url")):
            raise RuntimeError("Native linker registration lacks complete audited evidence")
        registrations[addr]=symbol
    if len(registrations)>MAX_VERIFIED:
        raise RuntimeError("Native registered function limit exceeded")
    root_addresses=[ROOT_MAIN]
    discovered={ROOT_MAIN:0}
    parents={}
    queue=deque(root_addresses)
    while queue:
        src=queue.popleft()
        distance=discovered[src]
        if distance>=MAX_DEPTH:
            continue
        for target in graph.get(src,[]):
            if target not in discovered:
                discovered[target]=distance+1
                parents[target]=src
                queue.append(target)
    edges=[(src,tgt) for src in discovered
           for tgt in graph.get(src,[]) if src!=tgt]
    def classify(rva):
        if rva in registrations:
            return "verified_callable_native"
        if rva==ROOT_MAIN:
            return "original_main_first_block_native_only"
        if rva in indexed:
            status=indexed[rva]["status"]
            return ("decoded_original_unwind_interval_no_verified_native"
                    if status=="decoded_linear" else
                    "original_unwind_interval_needs_recovery")
        if rva in unwindless:
            return ("unwindless_first_block_only_no_verified_native"
                    if unwindless[rva]["static_first_block_verified"] else
                    "unwindless_unrecovered_target")
        return "direct_target_not_in_function_inventory"
    statuses=Counter(classify(tgt) for _,tgt in edges)
    all_calls=sum(len(v) for v in graph.values())
    prioritized=[]
    seen=set()
    for source,target in sorted(edges,key=lambda e:(
          discovered[e[0]],e[0]!=ROOT_MAIN,e[0],e[1])):
        if target in seen:
            continue
        seen.add(target)
        prioritized.append({
            "source_rva":hex(source),"target_rva":hex(target),
            "source_depth":discovered[source],"native_status":classify(target),
            "ready_for_native_dispatch":target in registrations,
            "evidence":"Original x64 disassembly direct CALL; no implicit translation"
        })
    known_first=next((e for e in prioritized
                      if int(e["target_rva"],16)==ROOT_CALLEE),None)
    if not known_first:
        raise RuntimeError("Verified original main-to-0x136120 edge missing")
    manifest={
      "schema":1,
      "source":"SHA-verified original MX Bikes whole executable static PE map",
      "source_original_sha256":mapping["input_sha256"],
      "static_unwind_intervals":stats["unique_unwind_intervals"],
      "static_decode_success_count":stats["fully_linear_decoded_intervals"],
      "total_original_direct_call_sites_in_mapped_intervals":all_calls,
      "main_call_graph_root":hex(ROOT_MAIN),
      "main_root_first_known_target":hex(ROOT_CALLEE),
      "main_root_target_status":known_first["native_status"],
      "main_direct_reachable_addresses_within_depth":len(discovered),
      "main_direct_call_edges_within_depth":len(edges),
      "verified_native_function_registrations":len(registrations),
      "unresolved_main_direct_edges":sum(target not in registrations for _,target in edges),
      "unresolved_categories":dict(statuses),
      "native_dispatch_table":[
          {"original_rva":hex(rva),"native_symbol":symbol}
          for rva,symbol in sorted(registrations.items())
      ],
      "prioritized_unresolved_edges":[
          x for x in prioritized if not x["ready_for_native_dispatch"]
      ][:250],
      "limitations":[
          "Only static direct CALL edges are mapped; indirect calls and jump tables are unresolved.",
          "A full function body, x64 versus ARM64 behavioral differential and guest ABI must pass before registry activation.",
          "48 successfully compiled Remill objects are NOT automatically callable.",
          "At present game main has a tested first basic block, not a full native game-main function.",
          "No whole game native linking, graphics initialization or iPhone build is asserted."
      ],
    }
    return manifest

def run(map_path,out_path,verified_file=None):
    data=json.loads(map_path.read_text())
    verified=json.loads(verified_file.read_text()) if verified_file else []
    result=build(data,verified)
    out_path.mkdir(parents=True,exist_ok=True)
    (out_path/"original-va-native-link-plan.json").write_text(
        json.dumps(result,indent=2)+"\n")
    lines=[
      "# MX Bikes original-VA native link plan",
      "",
      "- SHA-pinned original binary function map loaded: **YES**",
      "- Original direct call sites inventoried: **"+str(result["total_original_direct_call_sites_in_mapped_intervals"])+"**",
      "- Main-root reachable source/target addresses: **"+str(result["main_direct_reachable_addresses_within_depth"])+"**",
      "- Bounded direct-call edges from original main: **"+str(result["main_direct_call_edges_within_depth"])+"**",
      "- Verified callable native function registrations: **"+str(result["verified_native_function_registrations"])+"**",
      "- Currently unresolved original main edges: **"+str(result["unresolved_main_direct_edges"])+"**",
      "- Immediate main-to-callee connection: **"+result["main_root_first_known_target"]+"**",
      "- First callee linker status: **"+result["main_root_target_status"].replace("_"," ")+"**",
      "",
      "## First unresolved main-root call edges",
    ]
    for x in result["prioritized_unresolved_edges"][:12]:
        lines.append("- "+x["source_rva"]+" -> "+x["target_rva"]+": "+
                     x["native_status"].replace("_"," "))
    lines+=["",
            "**Automatic linking is available once a function passes a full-body guest ABI differential. "
            "Compiled-but-unverified ARM64 objects remain unresolved, rather than being falsely registered.**",
            ""]
    summary="\n".join(lines)
    (out_path/"original-va-native-link-plan.md").write_text(summary)
    print(summary)
    return result

if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("whole_game_map",type=Path)
    p.add_argument("report_dir",type=Path)
    p.add_argument("--verified-symbols",type=Path)
    args=p.parse_args()
    run(args.whole_game_map,args.report_dir,args.verified_symbols)
