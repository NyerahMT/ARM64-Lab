#!/usr/bin/env python3
"""Native ARM64 full-return differential of original CALL targets lacking .pdata.

Original entrypoints come ONLY from SHA-pinned direct x64 CALL evidence and
must have a bounded first-control decode. Discover complete reachable CFGs,
execute every instruction in original Unicorn x64, compare guest stack, heap,
registers, flags with compiled host C and executed AArch64 ELF. Any unresolved
CALL, imported thunk, cross-function control flow or unsupported semantic is
rejected. Proprietary game bytes and generated native ELF stay ephemeral in CI.

A complete control-flow proof under synthetic guest fixtures is not equivalent
to iOS game boot, and ephemeral verification is not a persistent linker object.
"""
from __future__ import annotations

import argparse
from bisect import bisect_right
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import mxbikes_cfg_full_native_wave as cfg
from mxbikes_whole_game_map import INPUT_SHA, FIRST_CALLEE

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"arm64-lab"))
from tools.pe_probe import PE

MAX_UNWINDLESS=4000
MAX_NATIVE_CANDIDATES=192
MAX_SELECT=768
MAX_BATCH=8

def select_targets(mapping,verified,limit=MAX_SELECT):
    """Select all strict direct-CALL entrypoints without .pdata ownership."""
    if not 1<=limit<=MAX_SELECT:
        raise ValueError("Unbounded original direct-CALL entry selection")
    if (mapping.get("input_sha256")!=INPUT_SHA or
        mapping.get("original_file_verified") is not True):
        raise ValueError("Incorrect original executable provenance")
    records=mapping.get("interval_map")
    roots=mapping.get("unwindless_direct_call_candidates")
    if (not isinstance(records,list) or not 1<=len(records)<=9000 or
        not isinstance(roots,list) or len(roots)>MAX_UNWINDLESS):
        raise ValueError("Invalid bounded unwind/call evidence")
    protected=sorted((int(v["rva"],16),int(v["end_rva"],16)) for v in records)
    starts=[v[0] for v in protected]
    seen=set()
    proven={int(x["original_rva"],16) for x in verified
            if x.get("full_function_behavior_verified") is True and
               x.get("win64_guest_call_abi_verified") is True}
    candidates=[]
    rejection=Counter()
    for row in roots:
        try:
            rva=int(row["rva"],16)
            count=row["direct_call_references"]
        except (ValueError,TypeError,KeyError):
            rejection["invalid_original_entry_metadata"]+=1
            continue
        if rva in seen:
            raise ValueError("Duplicate direct-CALL target in original map")
        seen.add(rva)
        pos=bisect_right(starts,rva)-1
        if pos>=0 and rva<protected[pos][1]:
            rejection["original_unwind_owns_target"]+=1
            continue
        if (row.get("unwind_protected") is not False or
            row.get("static_first_block_verified") is not True or
            not isinstance(count,int) or count<=0 or not 0<rva<1<<32):
            rejection["no_verified_original_direct_call_first_block"]+=1
            continue
        if rva in proven:
            rejection["already_native_verified"]+=1
            continue
        candidates.append((rva,count))
    candidates.sort(key=lambda x:(x[0]!=FIRST_CALLEE,-x[1],x[0]))
    skipped=max(0,len(candidates)-limit)
    return [r for r,_ in candidates[:limit]],rejection,skipped,seen

def run_original(pe,mapping,prior,out,*,limit=MAX_SELECT):
    selections,reasons,deferred,all_direct_starts=select_targets(mapping,prior,limit)
    protected={int(v["rva"],16) for v in mapping["interval_map"]}
    # Never allow a recovered block to enter any other identified x64 entry.
    roots=protected|all_direct_starts
    complete=[]
    original_cases={}
    x64_rejected=Counter()
    for rva in selections:
        plan,reason=cfg.recover_cfg(pe,rva,roots,require_branch=False)
        if plan is None:
            reasons[reason]+=1
            continue
        expected=[]
        for case in range(cfg.CASES):
            reference,reason=cfg.x64_reference(pe,plan,case)
            if reason:
                x64_rejected[reason]+=1
                break
            expected.append(reference)
        if len(expected)!=cfg.CASES:
            continue
        complete.append(plan)
        original_cases[rva]=expected
    if len(complete)>MAX_NATIVE_CANDIDATES:
        deferred+=len(complete)-MAX_NATIVE_CANDIDATES
    native_queue=complete[:MAX_NATIVE_CANDIDATES]
    native_good=[]
    native_bad=Counter()
    def attempt(group):
        if not group:
            return
        try:
            cfg.compile_batch(group,original_cases)
        except (RuntimeError,ValueError,subprocess.SubprocessError) as exc:
            if len(group)>1:
                mid=len(group)//2
                attempt(group[:mid])
                attempt(group[mid:])
            else:
                native_bad[str(exc).split(":",1)[0]]+=1
        else:
            native_good.extend(group)
    for start in range(0,len(native_queue),MAX_BATCH):
        attempt(native_queue[start:start+MAX_BATCH])
    if len(native_good)>len(native_queue):
        raise RuntimeError("Original native proof accounting impossible")
    run_id=os.environ.get("GITHUB_RUN_ID","")
    if native_good and not run_id.isdecimal():
        raise RuntimeError("Native verification without trusted CI run")
    additions=[{
        "original_rva":hex(p["rva"]),
        "native_symbol":f"mx_unwindless_native_{p['rva']:08x}",
        "full_function_behavior_verified":True,
        "win64_guest_call_abi_verified":True,
        "code_presence":"ephemeral_ci_elf_only",
        "native_binary_persisted":False,
        "original_direct_CALL_entry_without_pdata":True,
        "differential_test_run_url":
            "https://github.com/NyerahMT/ReflexBuildInput/actions/runs/"+run_id,
        "proof_scope":"Complete bounded original reachable CFG x64/host/AArch64 four-case return and guest memory/flags differential; unwindless direct-call entry only"
    } for p in native_good]
    existing={int(v["original_rva"],16):v for v in prior}
    for entry in additions:
        key=int(entry["original_rva"],16)
        if key in existing:
            raise RuntimeError("Duplicate native verified original address")
        existing[key]=entry
    out=Path(out)
    out.mkdir(parents=True,exist_ok=True)
    (out/"verified-batch-registrations.json").write_text(
        json.dumps(list(existing.values()),indent=2)+"\n")
    report={
        "schema":1,"input_sha256":INPUT_SHA,
        "unwindless_direct_call_targets_considered":len(selections),
        "selection_or_execution_deferred":deferred,
        "complete_reachable_original_cfg_reference_candidates":len(complete),
        "original_candidates_native_tested":len(native_queue),
        "new_original_unwindless_arm64_functions_verified":len(native_good),
        "new_full_return_differential_cases":len(native_good)*cfg.CASES,
        "total_verified_native_function_metadata":len(existing),
        "new_verified_original_rvas":[hex(x["rva"]) for x in native_good],
        "static_or_decode_rejections":dict(reasons.most_common()),
        "original_x64_reference_rejections":dict(x64_rejected.most_common()),
        "native_reference_rejections":dict(native_bad.most_common()),
        "game_engine_started":False,"iphone_ipa_built":False,
        "native_executable_persisted":False,
        "original_code_or_game_assets_exported":False
    }
    (out/"unwindless-original-native-wave.json").write_text(
        json.dumps(report,indent=2)+"\n")
    lines=["# Original unwound-free direct CALL targets — native ARM64 full-return batch","",
           "- Original unprotected direct-CALL entries checked: **"+str(len(selections))+"**",
           "- Original complete x64-return candidates: **"+str(len(complete))+"**",
           "- Native differential candidates attempted: **"+str(len(native_queue))+"**",
           "- New original complete functions x64/host/AArch64 verified: **"+str(len(native_good))+"**",
           "- Matching original full-return fixtures: **"+str(len(native_good)*cfg.CASES)+"**",
           "- Unchecked candidates: **"+str(deferred)+"**",
           "- Total verified native metadata entries: **"+str(len(existing))+"**",
           "- Game engine, rendered menu, iOS IPA: **NO**","",
           "## Fail-closed blocker families"]
    lines.extend("- "+k+": "+str(v) for k,v in reasons.most_common(15))
    lines.extend("- Original x64 "+k+": "+str(v) for k,v in x64_rejected.most_common(10))
    lines.extend("- Native "+k+": "+str(v) for k,v in native_bad.most_common(10))
    lines.append("Every new verified entry requires complete original x64 and executed ARM64 state differentials. Original and generated code stay private.")
    (out/"unwindless-original-native-wave.md").write_text("\n".join(lines)+"\n")
    print("\n".join(lines))
    return report

if __name__=="__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("sha_verified_original_exe",type=Path)
    parser.add_argument("same_run_original_map",type=Path)
    parser.add_argument("native_verified_manifest",type=Path)
    parser.add_argument("report_directory",type=Path)
    args=parser.parse_args()
    pe=PE(args.sha_verified_original_exe)
    if hashlib.sha256(pe.b).hexdigest()!=INPUT_SHA:
        raise RuntimeError("Original executable SHA-256 mismatch")
    mapping=json.loads(args.same_run_original_map.read_text())
    prior=json.loads(args.native_verified_manifest.read_text())
    if not isinstance(prior,list):
        raise ValueError("Invalid native verification manifest")
    run_original(pe,mapping,prior,args.report_directory)
