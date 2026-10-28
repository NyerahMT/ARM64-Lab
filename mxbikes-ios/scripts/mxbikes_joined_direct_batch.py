#!/usr/bin/env python3
"""Batch-verify complete original Win64 caller->callee pairs on native ARM64.

Only a fully decoded, flag-preserving, bounded Win64 stack-adjust/CALL/undo/
RET body with a SAME-RUN verified, flag-preserving native leaf is eligible.
Other 3,540+ caller-containing intervals stay unresolved until their entire
bodies, service effects and guest ABI are verified. No game code is exported.
"""
from __future__ import annotations
import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_GRP_CALL

from mxbikes_verified_leaf_autolink import (
    BASE, FIXTURES, ROOT, EXE_SHA, discover as discover_leafs,
    x64_reference, generate_source, execute_arm64_elf
)
from mxbikes_native_link_plan import build as build_link_plan

ROOT_TEMPLATES = (
    (bytes.fromhex("488d6424d8"), bytes.fromhex("488d642428"), None),
    (b"\x53",b"\x5b","rbx"), # push/pop rbx
    (b"\x56",b"\x5e","rsi"), # push/pop rsi
    (b"\x57",b"\x5f","rdi"), # push/pop rdi
)
PRESERVES_FLAGS = {
    "ret", "nop_ret", "mov_eax_imm_ret", "mov_eax_ecx_ret",
    "mov_eax_edx_ret", "mov_rax_rcx_ret", "mov_eax_r8d_ret",
    "mov_eax_r9d_ret", "mov_rax_r8_ret", "mov_rax_r9_ret",
    "mov_rax_rdx_ret",
}
MAX_JOINED = 24


def safe_callee(candidate):
    return (candidate.get("kind") in PRESERVES_FLAGS or
            candidate.get("kind","").startswith("lea_")) and not candidate.get("cfg_plan")


def find_joinable(pe, mapping, leaf_candidates, verified, *, limit=MAX_JOINED):
    if mapping.get("input_sha256") != EXE_SHA or mapping.get("original_file_verified") is not True:
        raise ValueError("Native caller graph has wrong original executable revision")
    if not 0 <= limit <= MAX_JOINED:
        raise ValueError("Unbounded original caller batch")
    if limit==0:
        return [],Counter()
    audited={int(x["original_rva"],16) for x in verified if (
        x.get("full_function_behavior_verified") is True and
        x.get("win64_guest_call_abi_verified") is True and
        x.get("code_presence")=="ephemeral_ci_elf_only" and
        str(x.get("differential_test_run_url","")).startswith(
            "https://github.com/NyerahMT/ReflexBuildInput/actions/runs/"))}
    children={item["rva"]:item for item in leaf_candidates
              if item["rva"] in audited and safe_callee(item)}
    targets={int(a,16):{int(b,16) for b in children_}
             for a,children_ in mapping.get("direct_call_graph",{}).items()}
    decoder=Cs(CS_ARCH_X86,CS_MODE_64)
    decoder.detail=True
    selected=[]
    seen=set()
    counts=Counter()
    for row in mapping.get("interval_map",[]):
        if row.get("status")!="decoded_linear" or row.get("bytes") not in (8,16):
            continue
        rva=int(row["rva"],16)
        if rva in seen:
            continue
        seen.add(rva)
        if not targets.get(rva):
            continue
        length=row["bytes"]
        code=pe.read_rva(rva,length)
        for before,after,saved_register in ROOT_TEMPLATES:
            if length!=len(before)+len(after)+6:
                continue
            if not (code.startswith(before) and
                    code[len(before):len(before)+1]==b"\xe8" and
                    code[len(before)+5:-1]==after and
                    code[-1:]==b"\xc3"):
                continue
            return_rva=rva+len(before)+5
            delta=int.from_bytes(code[len(before)+1:len(before)+5],
                                 "little",signed=True)
            target=return_rva+delta
            child=children.get(target)
            if not child or target not in targets[rva]:
                counts["unsupported_or_unverified_original_child"]+=1
                continue
            dis=list(decoder.disasm(code,rva))
            expected_ops=(["push","call","pop","ret"] if saved_register
                          else ["lea","call","lea","ret"])
            if (len(dis)!=4 or sum(x.size for x in dis)!=length
                or [x.mnemonic for x in dis]!=expected_ops
                or dis[1].operands[0].imm!=target):
                counts["independent_decode_rejected"]+=1
                continue
            selected.append({
                "rva":rva,"body":code,"kind":"joined_flag_preserving_caller",
                "child_rva":target, "prefix_bytes":len(before),
                "saved_register":saved_register,
                "joined_children":[child], "wave_batch_id":None,
                "boundary_evidence":"complete_pdata_interval_and_verified_direct_callee",
            })
            counts["eligible_complete_flag_preserving_caller"]+=1
            break
        if len(selected)>=limit:
            break
    return selected,counts


def run(original, map_path, verified_path, output, *, wave_path=None):
    from tools.pe_probe import PE
    pe=PE(original)
    if hashlib.sha256(pe.b).hexdigest()!=EXE_SHA:
        raise RuntimeError("Owned original game executable SHA changed")
    mapping=json.loads(map_path.read_text())
    verified=json.loads(verified_path.read_text())
    if not isinstance(verified,list):
        raise ValueError("Verified native-leaf registry must be a list")
    waves=json.loads(wave_path.read_text()) if wave_path else None
    _,leaves,_,_=discover_leafs(original,mapping,waves)
    parents,counts=find_joinable(pe,mapping,leaves,verified)
    out_verified=[]
    if parents:
        used_child_rvas={p["child_rva"] for p in parents}
        children=[c for c in leaves if c["rva"] in used_child_rvas]
        candidates=parents+children
        references={}
        for item in candidates:
            references[item["rva"]]=[x64_reference(item,i) for i in range(FIXTURES)]
            if item["kind"]=="joined_flag_preserving_caller":
                # A full original nested call/return must visit both exact
                # instruction bodies. Missing paths remain unverified.
                covered=set().union(*(set(t) for t in item["_joined_traces"]))
                md=Cs(CS_ARCH_X86,CS_MODE_64)
                intended={ins.address for region in [item,*item["joined_children"]]
                          for ins in md.disasm(region["body"],region["rva"])}
                if covered!=intended:
                    raise RuntimeError("Original nested caller or callee not fully visited")
        src=generate_source(candidates,references)
        with tempfile.TemporaryDirectory(prefix="mxb-joined-private-") as td:
            root=Path(td)
            code=root/"joined-original-private.c"
            code.write_text(src)
            flags=["-O2","-std=c11","-Wall","-Wextra","-Werror",
                   "-I",str(ROOT/"arm64-lab"/"runtime")]
            host=root/"host"
            proc=subprocess.run(["cc",*flags,"-DHOST",str(code),"-o",str(host)],
                                capture_output=True,text=True)
            if proc.returncode:
                raise RuntimeError("Joined host compile failed: "+proc.stderr[-2500:])
            proc=subprocess.run([str(host)],capture_output=True,text=True)
            if proc.returncode:
                raise RuntimeError("Joined original-x64 / host differential failed: "+proc.stderr[-2000:])
            arm=root/"joined-aarch64.elf"
            proc=subprocess.run([
                "clang","--target=aarch64-unknown-linux-gnu","-fuse-ld=lld",
                "-nostdlib","-static","-ffreestanding",
                "-fno-stack-protector","-fno-builtin",*flags,
                "-Wl,-e,smoke","-Wl,-z,max-page-size=4096",
                "-Wl,--build-id=none",str(code),"-o",str(arm),
            ],capture_output=True,text=True)
            if proc.returncode:
                raise RuntimeError("Joined ARM64 compile failed: "+proc.stderr[-2500:])
            result=execute_arm64_elf(arm,instruction_budget=2500000,
                                     timeout_us=16000000)
            if result["arm64_smoke_exit"]!=0:
                raise RuntimeError("Joined original/native ARM64 differential mismatch")
        run_id=os.environ.get("GITHUB_RUN_ID")
        if not run_id or not run_id.isdecimal():
            raise RuntimeError("Cannot register original joined functions without audited Actions run")
        evidence="https://github.com/NyerahMT/ReflexBuildInput/actions/runs/"+run_id
        out_verified=[{
            "original_rva":hex(p["rva"]),
            "native_symbol":f"mx_verified_{p['rva']:08x}",
            "full_function_behavior_verified":True,
            "win64_guest_call_abi_verified":True,
            "differential_test_run_url":evidence,
            "proof_scope":"Original x64 LEA/CALL/LEA/RET plus separately verified child; "
                          "12 nested host and executed ARM64 full-state fixtures",
            "code_presence":"ephemeral_ci_elf_only",
        } for p in parents]
    combined={int(v["original_rva"],16):v for v in verified}
    for v in out_verified:
        addr=int(v["original_rva"],16)
        if addr in combined:
            raise RuntimeError("Duplicate original native symbol on joined branch")
        combined[addr]=v
    # No joined-caller registration without actual passed ARM64 execution.
    native_plan=build_link_plan(mapping,list(combined.values()))
    output.mkdir(parents=True,exist_ok=True)
    (output/"verified-batch-registrations.json").write_text(
        json.dumps(list(combined.values()),indent=2)+"\n")
    data={
        "schema":1,"original_sha256":EXE_SHA,
        "original_called_function_candidates_checked":len(mapping.get("interval_map",[])),
        "original_joined_eligible_candidates":counts["eligible_complete_flag_preserving_caller"],
        "joinable_original_x64_callers_native_verified":len(out_verified),
        "original_x64_to_host_to_executed_arm64_nested_cases":len(out_verified)*FIXTURES,
        "verified_native_leaves_reused":len(verified),
        "merged_verified_native_functions":len(combined),
        "unsupported_nested_callers_promoted":False,
        "complete_game_main":False,
        "full_engine_boot_verified":False,
        "note":"Original full bodies required; no actual joined candidates means zero added native functions.",
    }
    (output/"joined-call-batch.json").write_text(json.dumps(data,indent=2)+"\n")
    (output/"joined-call-native-link-plan.json").write_text(
        json.dumps(native_plan,indent=2)+"\n")
    report="\n".join([
        "# MX Bikes verified native caller→callee batches","",
        "- Original complete flag-preserving joined callers discovered: **"+
            str(data["original_joined_eligible_candidates"])+"**",
        "- Nested caller functions x64/host/ARM64 verified: **"+
            str(data["joinable_original_x64_callers_native_verified"])+"**",
        "- Original nested differential fixtures executed: **"+
            str(data["original_x64_to_host_to_executed_arm64_nested_cases"])+"**",
        "- Total merged verified native functions: **"+
            str(data["merged_verified_native_functions"])+"**","",
        "**No unverified caller or missing callee is promoted to native dispatch.**",
        "**Not game boot, graphics or an iOS binary.**",""
    ])
    (output/"joined-call-batch.md").write_text(report)
    print(report)
    return data


if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("owned_original",type=Path)
    p.add_argument("same_run_original_map",type=Path)
    p.add_argument("verified_leaf_manifest",type=Path)
    p.add_argument("output",type=Path)
    p.add_argument("--waves",type=Path)
    args=p.parse_args()
    run(args.owned_original,args.same_run_original_map,
        args.verified_leaf_manifest,args.output,wave_path=args.waves)
