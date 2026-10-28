#!/usr/bin/env python3
"""Launch-first MX Bikes dependency ledger from verified same-run CI metadata.

This is a read-only evidence gate, not an executable generator. A native function
may have passed a full x64/host/AArch64 differential while its compiled object
is still ephemeral. Never count such proof as linked native code, a boot, an
authorized imported service, graphics or an iOS app.
"""
from __future__ import annotations

import argparse
from collections import Counter, deque
import json
from pathlib import Path

# Deliberately dependency-free: this validator runs without Capstone/Unicorn
# or the commercial game asset. The full-game workflow cross-checks the same
# SHA against mxbikes_whole_game_map before generating its reports.
SHA="4ae7de3854b4d0a18271679fb57a1f2fdf0b21804417b85dd82055078ea123b6"
MAIN_RVA=0x136710
FIRST_CALLEE=0x136120
ENTRY_RVA=0x2ab31c
CRT_RVA=0x2ab02c

EXPECTED_SOURCE="SHA-verified original MX Bikes whole executable static PE map"
EXPECTED_IMPORT="SHA-pinned PE import table plus static original x64 instructions"
MAX_CALL_EDGES=1600000
MAX_VERIFIED=131072


def address(raw):
    if not isinstance(raw,str) or not raw.startswith("0x"):
        raise ValueError("Original address must be hexadecimal")
    value=int(raw,16)
    if not 0<=value<1<<32:
        raise ValueError("Original address outside RVA range")
    return value


def summarize(mapping,link_plan,import_scan,service_matrix,launch_probe,coverage):
    """Build one reproducible, conservative report of actual launch blockers."""
    if not all(isinstance(x,dict) for x in (
        mapping,link_plan,import_scan,service_matrix,launch_probe,coverage)):
        raise ValueError("Launch ledger sources must be JSON objects")
    if (mapping.get("input_sha256")!=SHA or mapping.get("original_file_verified") is not True or
        link_plan.get("source_original_sha256")!=SHA or
        link_plan.get("source")!=EXPECTED_SOURCE or
        import_scan.get("original_sha256")!=SHA or
        import_scan.get("input_kind")!=EXPECTED_IMPORT or
        service_matrix.get("original_sha256")!=SHA or
        coverage.get("original_sha256")!=SHA):
        raise ValueError("Launch ledger input binary provenance mismatch")

    dispatch=link_plan.get("native_dispatch_table")
    if not isinstance(dispatch,list) or len(dispatch)>MAX_VERIFIED:
        raise ValueError("Missing or oversized native evidence registry")
    verified=set()
    for item in dispatch:
        a=address(item["original_rva"])
        if a in verified or not item.get("native_symbol"):
            raise ValueError("Duplicate/missing native evidence registration")
        verified.add(a)
    if link_plan.get("verified_native_function_registrations")!=len(verified):
        raise ValueError("Native evidence count disagrees with registry")
    graph_data=mapping.get("direct_call_graph")
    if not isinstance(graph_data,dict) or len(graph_data)>MAX_CALL_EDGES:
        raise ValueError("Unbounded or missing original direct-call graph")
    graph={}
    for raw_source,targets in graph_data.items():
        if not isinstance(targets,list) or len(targets)>1024:
            raise ValueError("Original direct-call adjacency exceeds budget")
        src=address(raw_source)
        if src in graph:
            raise ValueError("Duplicate original source")
        graph[src]={address(target) for target in targets}
    direct_main=sorted(graph.get(MAIN_RVA,set()))
    if FIRST_CALLEE not in direct_main:
        raise ValueError("Original first game-main CALL edge missing")

    bounded=link_plan.get("main_direct_call_edges_within_depth")
    unresolved=link_plan.get("unresolved_main_direct_edges")
    if (not isinstance(bounded,int) or not isinstance(unresolved,int) or
        not 1<=bounded<=MAX_CALL_EDGES or not 0<=unresolved<=bounded):
        raise ValueError("Native linker dependency counts are invalid")
    main_verified=sum(x in verified for x in direct_main)
    # Independently repeat the native linker depth-9 graph walk. A fabricated
    # or stale resolved-edge count must not become evidence of launch progress.
    discovered={MAIN_RVA:0}
    todo=deque([MAIN_RVA])
    while todo:
        node=todo.popleft()
        if discovered[node]>=9:
            continue
        for target in sorted(graph.get(node,())):
            if target not in discovered:
                discovered[target]=discovered[node]+1
                todo.append(target)
    graph_edges={(src,dst) for src in discovered
                 for dst in graph.get(src,()) if src!=dst}
    computed_unresolved=sum(dst not in verified for _,dst in graph_edges)
    if (bounded!=len(graph_edges) or unresolved!=computed_unresolved or
        bounded<len(direct_main) or main_verified>bounded-unresolved):
        raise ValueError("Native dependency closure counters inconsistent")
    known_unresolved=link_plan.get("prioritized_unresolved_edges",[])
    if not isinstance(known_unresolved,list) or len(known_unresolved)>250:
        raise ValueError("Unbounded original dependency list")
    priority_edges=[]
    for edge in known_unresolved:
        src=address(edge["source_rva"])
        dst=address(edge["target_rva"])
        if ((src,dst) not in graph_edges or dst in verified or
            edge.get("ready_for_native_dispatch") is not False):
            raise ValueError("Unresolved edge missing from authentic original CALL graph")
        priority_edges.append({
            "source_rva":hex(src),"target_rva":hex(dst),
            "reason":edge["native_status"],
            "min_static_depth":edge.get("source_depth")
        })
    priority_edges.sort(key=lambda e:(e["target_rva"]!=hex(FIRST_CALLEE),
                                      e["min_static_depth"] if isinstance(e["min_static_depth"],int) else 99,
                                      e["source_rva"],e["target_rva"]))
    coverage_stats=coverage.get("combined",{})
    if coverage_stats.get("verified_native_leaves_from_same_run")!=len(verified):
        raise ValueError("Startup graph and full native proof inventory disagree")
    static_nodes=coverage_stats.get("potentially_reachable_static_nodes")
    reachable=coverage_stats.get("verified_leaves_potentially_reachable")
    if not all(isinstance(x,int) and x>=0 for x in (static_nodes,reachable)):
        raise ValueError("Incomplete original root reachability summary")

    services=service_matrix.get("services",[])
    if not isinstance(services,list) or len(services)>4096:
        raise ValueError("Unbounded imported-service inventory")
    by_service={}
    classes=Counter()
    for service in services:
        key=(service["dll"].lower(),service["symbol"].lower())
        if key in by_service:
            raise ValueError("Ambiguous imported service identity")
        by_service[key]=service
        classes[service["status"]]+=1
    scanned_imports=import_scan.get("direct_iat_callsites",[])
    if not isinstance(scanned_imports,list) or len(scanned_imports)>4096:
        raise ValueError("Unbounded direct-import inventory")
    all_missing=sorted(f"{dll}::{name}" for (dll,name),s in by_service.items()
                       if s["status"]=="missing")
    x64=launch_probe.get("original_x64_startup_probe",{})
    preliminary=launch_probe.get("native_arm64_startup_readiness",{})
    if not isinstance(x64,dict) or not isinstance(preliminary,dict):
        raise ValueError("Missing x64 startup probe")
    reached=x64.get("original_process_milestones_reached",{})
    stop=x64.get("first_stopping_boundary",{})
    if not isinstance(stop,dict) or not isinstance(reached,dict):
        raise ValueError("Malformed original x64 execution evidence")
    stopping_import=stop.get("import")
    if stopping_import is not None and not isinstance(stopping_import,str):
        raise ValueError("Invalid original imported-service name")
    stop_service=None
    if stopping_import and "::" in stopping_import:
        dll,symbol=stopping_import.split("::",1)
        evidence=by_service.get((dll.lower(),symbol.lower()))
        if evidence:
            stop_service={"family":evidence["family"],"status":evidence["status"]}
    first_static_status="verified_original_full_function" if FIRST_CALLEE in verified else (
        "unverified_original_function")

    gates={
        "original_x64_crt_tail_observed_in_emulator":reached.get("crt_tail") is True,
        "original_x64_game_main_observed_in_emulator":reached.get("game_main") is True,
        "native_pe_entry_full_function_verified":ENTRY_RVA in verified,
        "native_crt_start_full_function_verified":CRT_RVA in verified,
        "native_game_main_full_function_verified":MAIN_RVA in verified,
        "native_first_main_callee_full_function_verified":FIRST_CALLEE in verified,
        "all_bounded_main_direct_CALL_edges_verified":unresolved==0,
        "persistent_arm64_function_objects_linked":False,
        "original_native_arm64_entry_executed":False,
        "native_graphics_or_menu_launched":False,
        "iphone_ipa_built_and_launched":False,
    }
    # x64 Unicorn's synthetic guest CRT probes are not the ARM64 native build.
    first_blockers=[
        {"track":"native_execution","kind":"complete_first_main_callee",
         "rva":hex(FIRST_CALLEE),"state":first_static_status},
        {"track":"original_x64_reference","kind":"first_dynamic_safe_stop",
         "reason":stop.get("type","unknown"),
         "unresolved_import":stopping_import,"service":stop_service},
        {"track":"native_execution","kind":"unresolved_main_call_closure",
         "bounded_edges":bounded,"unresolved_edges":unresolved},
        {"track":"runtime_services","kind":"missing_external_service_families",
         "missing_services":all_missing},
        {"track":"native_integration","kind":"persistent_native_binary",
         "state":"not_built_or_linked"},
    ]
    return {
        "schema":1,"original_sha256":SHA,
        "report_kind":"launch_first_metadata_evidence_not_game_boot",
        "native_functions_full_return_differential_verified":len(verified),
        "native_functions_linked_into_persistent_executable":0,
        "native_startup_root_verification":{
            "entry":hex(ENTRY_RVA),"crt":hex(CRT_RVA),
            "main":hex(MAIN_RVA),"first_main_callee":hex(FIRST_CALLEE),
        },
        "main_call_closure":{
            "direct_callee_entries":[hex(x) for x in direct_main],
            "direct_callees_verified":main_verified,
            "direct_callees_total":len(direct_main),
            "bounded_static_direct_call_edges":bounded,
            "bounded_static_direct_call_edges_unresolved":unresolved,
            "bounded_static_direct_call_edges_verified":bounded-unresolved,
            "first_unresolved_edges":priority_edges[:32],
            "closed_and_linked":False,
        },
        "startup_root_static_reachability":{
            "nodes_examined":static_nodes,
            "fully_verified_functions_in_roots":reachable,
            "complete_original_native_root_chain_verified":False,
        },
        "original_x64_reference_frontier":{
            "crt_tail_reached":gates["original_x64_crt_tail_observed_in_emulator"],
            "game_main_reached":gates["original_x64_game_main_observed_in_emulator"],
            "original_instructions_executed":x64.get("original_instructions_reached"),
            "safe_stop_reason":stop.get("type"),
            "first_unresolved_import":stopping_import,
            "service_status":stop_service,
            "initial_probe_native_evidence_count":preliminary.get(
                "native_verified_original_complete_functions"),
            "note":"Synthetic Windows x64 import/CRT model, never native ARM64 execution."
        },
        "runtime_services":{
            "status_counts":dict(sorted(classes.items())),
            "missing_service_names":all_missing,
            "direct_import_callsite_count":len(scanned_imports),
            "native_runtime_adapter_complete":False,
        },
        "first_order_blockers":first_blockers,
        "launch_gates":gates,
        "launch_milestones_passed":0,
        "launch_milestones_total":3,
        "overall_port_completion_percent_available":False,
        "recommended_engineering_order":[
            "Prove complete original 0x136120 function and main CALL/RET closure with exact Win64 ABI, including all reachable branch successors.",
            "Implement legitimate read-only guest filesystem and MSVCR90 fopen service dependency using owned local assets; differential-test service semantics.",
            "Keep reproducible private native code artifacts with a real ARM64 linker/runtime, then test executable entry before window/menu or iOS IPA."
        ],
        "source_code_or_original_executable_exported":False,
        "original_steamworks_authorization_bypassed":False,
    }


def run(mapping_path,link_path,import_path,service_path,probe_path,coverage_path,out):
    values=[json.loads(Path(p).read_text()) for p in (
        mapping_path,link_path,import_path,service_path,probe_path,coverage_path)]
    report=summarize(*values)
    out=Path(out)
    out.mkdir(parents=True,exist_ok=True)
    (out/"launch-first-blocker-ledger.json").write_text(json.dumps(report,indent=2)+"\n")
    calls=report["main_call_closure"]
    sample=report["original_x64_reference_frontier"]
    lines=[
        "# MX Bikes launch-first blocker ledger","",
        "- Complete original functions with x64/host/ARM64 proofs: **"+
        str(report["native_functions_full_return_differential_verified"])+"**",
        "- Native functions linked in an executable: **0**",
        "- Game-main direct callees verified: **"+
        str(calls["direct_callees_verified"])+"/"+str(calls["direct_callees_total"])+"**",
        "- Bounded native main call edges unresolved: **"+
        str(calls["bounded_static_direct_call_edges_unresolved"])+"/"+
        str(calls["bounded_static_direct_call_edges"])+"**",
        "- Original x64 emulator reached game main: **"+
        str(sample["game_main_reached"])+"**",
        "- Original x64 safe stop: **"+str(sample["safe_stop_reason"])+"**",
        "- Original x64 unresolved import: **"+str(sample["first_unresolved_import"])+"**",
        "- Native first game-main callee 0x136120 proven: **"+
        str(report["launch_gates"]["native_first_main_callee_full_function_verified"])+"**",
        "- Actual native executable, graphics/menu, iOS launch: **NO**","",
        "## Priority engineering gates","",
    ]
    lines.extend(f"{i}. {task}" for i,task in enumerate(
        report["recommended_engineering_order"],1))
    lines+=["","This report is evidence about startup blockers, not a percentage of the game translated.",
            "Passing tests on ephemeral ARM64 functions does not create a linkable native application.",""]
    (out/"launch-first-blocker-ledger.md").write_text("\n".join(lines))
    print("\n".join(lines))
    return report


if __name__=="__main__":
    p=argparse.ArgumentParser()
    for arg in ("whole_game_map","native_link_plan","import_scan","service_matrix",
                "original_first_launch_probe","startup_chain_coverage","metadata_out"):
        p.add_argument(arg,type=Path)
    a=p.parse_args()
    run(a.whole_game_map,a.native_link_plan,a.import_scan,a.service_matrix,
        a.original_first_launch_probe,a.startup_chain_coverage,a.metadata_out)
