#!/usr/bin/env python3
"""Classify original MX Bikes native-translation blockers by reusable *families*.

Private SHA-verified executable bytes never leave the CI runner. This writes
only aggregate instruction/maturity metadata; it does not translate, compile,
or register any original function.
"""
from __future__ import annotations
import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import sys

from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_GRP_CALL, CS_GRP_JUMP, CS_GRP_RET
from capstone.x86 import X86_OP_MEM

from mxbikes_acyclic_leaf_cfg import decode as decode_cfg
from mxbikes_verified_leaf_autolink import classify as classify_closed
from mxbikes_whole_game_map import INPUT_SHA

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"arm64-lab"))
from tools.pe_probe import PE

MAX_BYTES = 512
MAX_INSTRUCTIONS = 96
MAX_INTERVALS = 10000

FAMILIES = (
    "already_supported_shape",
    "nested_direct_calls",
    "import_or_indirect_calls",
    "guest_memory",
    "stack_state",
    "vector_or_floating_point",
    "indirect_control",
    "no_complete_return",
    "branch_and_flags",
    "register_arithmetic",
)


def classify_instructions(insns, body, rva):
    if classify_closed(body) or decode_cfg(body, rva):
        return "already_supported_shape"
    if any(ins.group(CS_GRP_CALL) and ins.op_str.startswith(("qword ptr", "rax", "rcx", "rdx"))
           for ins in insns):
        return "import_or_indirect_calls"
    if any(ins.group(CS_GRP_CALL) for ins in insns):
        return "nested_direct_calls"
    if any(ins.group(CS_GRP_JUMP) and ins.op_str.startswith(("rax","rcx","rdx","qword ptr"))
           for ins in insns):
        return "indirect_control"
    if any(any(x in (ins.op_str or "").lower() for x in ("xmm","ymm","zmm","st("))
           for ins in insns):
        return "vector_or_floating_point"
    mem=[]
    for ins in insns:
        # LEA is address arithmetic, not a memory read/write.
        if ins.mnemonic == "lea":
            continue
        for operand in ins.operands:
            if operand.type == X86_OP_MEM:
                base=ins.reg_name(operand.mem.base) if operand.mem.base else ""
                mem.append(base)
    if any(m not in ("rsp","rbp","esp","ebp") for m in mem):
        return "guest_memory"
    if mem or any(ins.mnemonic in ("push","pop","leave","enter") for ins in insns):
        return "stack_state"
    if not any(ins.group(CS_GRP_RET) for ins in insns):
        return "no_complete_return"
    if any(ins.group(CS_GRP_JUMP) for ins in insns):
        return "branch_and_flags"
    return "register_arithmetic"


def analyze(pe, mapping):
    if (not isinstance(mapping,dict) or mapping.get("input_sha256")!=INPUT_SHA
        or mapping.get("original_file_verified") is not True):
        raise ValueError("Blocker inventory must use the pinned original-game map")
    rows=mapping.get("interval_map")
    if not isinstance(rows,list) or len(rows)>600000:
        raise ValueError("Invalid bounded original interval map")
    direct=Counter(int(target,16) for targets in mapping.get("direct_call_graph",{}).values()
                   for target in targets)
    decoder=Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail=True
    counts=Counter()
    referees=Counter()
    mnemonic_by_family=defaultdict(Counter)
    properties=defaultdict(Counter)
    inspected=0
    for row in rows:
        if row.get("status")!="decoded_linear":
            continue
        length=row.get("bytes",0)
        if not isinstance(length,int) or not 1<=length<=MAX_BYTES:
            continue
        if not 1<=row.get("instructions",0)<=MAX_INSTRUCTIONS:
            continue
        if inspected>=MAX_INTERVALS:
            raise RuntimeError("Native family inventory overrun")
        rva=int(row["rva"],16)
        body=pe.read_rva(rva,length)
        insns=list(decoder.disasm(body,rva))
        if not insns or sum(ins.size for ins in insns)!=length:
            raise RuntimeError("Private original interval decoding disagrees with pinned map")
        family=classify_instructions(insns,body,rva)
        if family not in FAMILIES:
            raise RuntimeError("Unknown blocker family")
        counts[family]+=1
        referees[family]+=direct[rva]
        properties[family]["original_instructions"]+=len(insns)
        properties[family]["direct_called_intervals"]+=bool(direct[rva])
        properties[family]["startup_reachable_intervals"]+=row.get("depth_from_known_roots") is not None
        for ins in insns:
            mnemonic_by_family[family][ins.mnemonic]+=1
        inspected+=1
    categories=[]
    for family in FAMILIES:
        count=counts[family]
        categories.append({
            "family":family, "unwind_intervals":count,
            "original_direct_call_references":referees[family],
            "direct_called_intervals":properties[family]["direct_called_intervals"],
            "startup_root_reachable_intervals":properties[family]["startup_reachable_intervals"],
            "total_original_x64_instructions":properties[family]["original_instructions"],
            "common_mnemonics":[{"mnemonic":n,"count":v}
                                for n,v in mnemonic_by_family[family].most_common(8)],
            "fully_native_verified_by_inventory":False,
        })
    ranked=sorted((r for r in categories if r["family"]!="already_supported_shape"),
                  key=lambda x:(-x["startup_root_reachable_intervals"],
                                -x["original_direct_call_references"],
                                -x["direct_called_intervals"],
                                x["family"]))
    return {
        "schema":1,
        "original_sha256":INPUT_SHA,
        "kind":"private_original_family_aggregate_not_native_execution",
        "small_decoded_intervals_scanned":inspected,
        "families":categories,
        "prioritized_batch_families":[x["family"] for x in ranked],
        "known_structural_shapes_are_not_native_proofs":True,
        "original_guest_memory_or_stack_runtime_supplied":False,
        "private_original_code_exported":False,
        "notes":"Aggregate structural opportunities only; labels omit copied original instructions and do not prove execution.",
    }


def run(executable, mapping_file, output):
    pe=PE(executable)
    if hashlib.sha256(pe.b).hexdigest()!=INPUT_SHA:
        raise RuntimeError("Original game executable SHA changed")
    mapping=json.loads(mapping_file.read_text())
    data=analyze(pe,mapping)
    output.mkdir(parents=True,exist_ok=True)
    (output/"native-family-inventory.json").write_text(json.dumps(data,indent=2)+"\n")
    lines=["# MX Bikes — grouped original x64 native translation opportunities","",
           "- Structurally inspected small intervals: **"+str(data["small_decoded_intervals_scanned"])+"**",
           "- Existing structural forms are **not** automatically native-verified","",
           "| Blocking family | Original intervals | Direct-called intervals | Call references | Startup reachable |",
           "| --- | ---: | ---: | ---: | ---: |"]
    for row in data["families"]:
        lines.append("| "+row["family"]+" | "+str(row["unwind_intervals"])+" | "+
                     str(row["direct_called_intervals"])+" | "+
                     str(row["original_direct_call_references"])+" | "+
                     str(row["startup_root_reachable_intervals"])+" |")
    lines.extend(["","## Prioritized development families",""])
    for key in data["prioritized_batch_families"][:8]:
        row=next(x for x in data["families"] if x["family"]==key)
        lines.append("- "+key+": "+", ".join(x["mnemonic"] for x in row["common_mnemonics"][:6]))
    lines.extend(["","**Static, metadata-only diagnostics; this report cannot increase ARM64 completion counts.**",""])
    report="\n".join(lines)
    (output/"native-family-inventory.md").write_text(report)
    print(report)
    return data


if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("owned_sha_verified_original",type=Path)
    p.add_argument("same_run_whole_executable_map",type=Path)
    p.add_argument("metadata_output",type=Path)
    args=p.parse_args()
    run(args.owned_sha_verified_original,args.same_run_whole_executable_map,args.metadata_output)
