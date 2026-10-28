#!/usr/bin/env python3
"""Actual ARM64 differential test of startup-reachable original no-CALL leaves.

Consumes independent SHA-pinned original x64 startup CALL-closure metadata,
selects ONLY proven no-CALL/no-import candidates, decodes exact reachable CFG,
executes four original x64 full returns, compiles guest C to host and AArch64,
then executes native AArch64 ELF against identical guest-state fixtures.
No C/ELF/original machine bytes leave the private CI runner. A syntactically
valid call graph, or just compiling a function, never registers a native proof.
Does not call Steamworks, implement a game boot, or produce an iPhone IPA.
"""
from __future__ import annotations
from collections import Counter
import argparse
import json
import os
from pathlib import Path

from mxbikes_cfg_full_native_wave import (
    recover_cfg,x64_reference,compile_batch,CASES)
from mxbikes_whole_game_map import INPUT_SHA

MAX_FOUNDATIONAL=16

def eligible_original_entries(closure,limit=MAX_FOUNDATIONAL):
    if not 1<=limit<=MAX_FOUNDATIONAL:
        raise ValueError("Unbounded startup native proof wave")
    if closure.get("schema")!=1 or closure.get("steam_authorization_bypassed") is not False:
        raise ValueError("Unknown/fabricated startup call closure")
    batches=closure.get("topological_native_translation_batches",[])
    selected=closure.get("foundational_no_call_no_import_translation_batch_indices",[])
    if not isinstance(batches,list) or not isinstance(selected,list):
        raise ValueError("Untrusted original x64 startup dependency graph")
    original=closure.get("per_original_function",{})
    results=[]
    seen=set()
    for index in selected:
        if not isinstance(index,int) or not 0<=index<len(batches):
            raise ValueError("Invalid foundational original function batch")
        b=batches[index]
        if b["original_call_cycle"] or len(b["original_function_entry_rvas"])!=1:
            raise ValueError("Unsafe caller/cycle presented as leaf")
        blockers=b["blockers"]
        if any(blockers[key] for key in ("Steamworks_external","Windows_CRT_external",
            "unknown_indirect_CALL","out_of_walk_direct_callees")):
            raise ValueError("Startup external import falsely presented as leaf")
        rva=int(b["original_function_entry_rvas"][0],16)
        if rva in seen:raise ValueError("Duplicate original startup function entry")
        seen.add(rva)
        info=original.get(hex(rva))
        if not info or info.get("status")!="original_linear_call_edges_classified_not_native_proof":
            continue
        if info.get("direct_original_CALL_count") or info.get("named_imports") or info.get("unknown_or_indirect_CALL_count"):
            raise ValueError("Original leaf contradicts direct x64 CALL evidence")
        results.append(rva)
    return results[:limit],max(0,len(results)-limit)

def run_real_original_leaf_wave(pe,unwind,closure,output_dir,*,limit=MAX_FOUNDATIONAL):
    roots,not_checked=eligible_original_entries(closure,limit=limit)
    if len(unwind)>600000:
        raise ValueError("Unbounded original unwind index")
    starts=set(unwind)
    rejection=Counter()
    tested=0
    proven=[]
    for rva in roots:
        plan,reason=recover_cfg(pe,rva,starts,require_branch=False)
        if plan is None:
            rejection[reason]+=1
            continue
        expected=[]
        for k in range(CASES):
            try:ref,reason=x64_reference(pe,plan,k)
            except Exception as exc:
                ref=None;reason="original_x64_fixture_exception_"+type(exc).__name__
            if reason:
                rejection[reason]+=1
                break
            expected.append(ref)
        if len(expected)!=CASES:
            continue
        tested+=1
        try:
            compile_batch([plan],{rva:expected})
        except Exception as exc:
            rejection["host_or_native_differential_failure_"+type(exc).__name__]+=1
            continue
        # Fully completed original function and *executed* native code under
        # controlled guest input; not full runtime compatibility or game boot.
        proven.append(hex(rva))
    output_dir=Path(output_dir)
    output_dir.mkdir(parents=True,exist_ok=True)
    run_id=os.environ.get("GITHUB_RUN_ID")
    if proven and not (run_id and run_id.isdecimal()):
        raise RuntimeError("Native proof lacks a real private GitHub CI execution")
    report={
        "schema":1,
        "sha_pinned_original_executable":INPUT_SHA,
        "original_startup_foundational_candidates_selected":len(roots),
        "foundational_candidates_skipped_by_budget":not_checked,
        "original_full_return_reference_candidates":tested,
        "new_complete_original_functions_x64_host_arm64_proven":len(proven),
        "original_x64_to_arm64_differential_fixtures":len(proven)*CASES,
        "new_verified_original_function_rvas":proven,
        "proof_run_url":("https://github.com/NyerahMT/ReflexBuildInput/actions/runs/"+run_id
                         if proven else None),
        "fail_closed_rejections":dict(sorted(rejection.items())),
        "game_booted_on_native_arm64":False,
        "iphone_ipa_created":False,
        "steam_authorization_implemented":False,
        "proprietary_native_code_exported":False,
    }
    (output_dir/"startup-real-native-leaf-wave.json").write_text(json.dumps(report,indent=2)+"\n")
    lines=["# Executed native ARM64 proofs of original startup leaf candidates","",
        "- Original no-call startup leaf candidates checked: **"+str(len(roots))+"**",
        "- Original complete x64 return candidates: **"+str(tested)+"**",
        "- Full original functions executed x64/host/native ARM64: **"+str(len(proven))+"**",
        "- Native differential original fixtures: **"+str(len(proven)*CASES)+"**",
        "- New privately verified original function RVAs: **"+", ".join(proven)+"**",
        "- Real ARM64 game startup / graphics / iOS IPA: **NO**","",
        "## Rejected proof families","| Reason | Candidates |","| --- | ---: |"]
    lines.extend("| "+a+" | "+str(b)+" |" for a,b in rejection.most_common())
    lines.extend(["","Completeness is proven for controlled guest fixtures only; no game runtime is declared.",""])
    (output_dir/"startup-real-native-leaf-wave.md").write_text("\n".join(lines))
    print("\n".join(lines))
    return report

if __name__=="__main__":
    from tools.pe_probe import PE
    from mxbikes_whole_game_map import walk_unwind
    import hashlib
    p=argparse.ArgumentParser()
    p.add_argument("original_exe",type=Path)
    p.add_argument("closure_metadata",type=Path)
    p.add_argument("output_dir",type=Path)
    args=p.parse_args()
    pe=PE(args.original_exe)
    if hashlib.sha256(pe.b).hexdigest()!=INPUT_SHA:
        raise RuntimeError("Untrusted original binary")
    closure=json.loads(args.closure_metadata.read_text())
    run_real_original_leaf_wave(pe,walk_unwind(pe)[0],closure,args.output_dir)
