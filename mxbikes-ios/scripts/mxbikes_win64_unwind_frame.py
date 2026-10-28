#!/usr/bin/env python3
"""Validate real Win64 PE unwind frame metadata against executed x64 prologues.

A parser+Unicorn check proves only a function's *entry prologue*, not its
later CALL-site RSP/RBP relationship or a complete translated function.
Original executable bytes are used only in the private SHA-pinned CI runner.
No original instructions are exported.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import struct
import sys

from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_GRP_CALL, CS_GRP_JUMP, CS_GRP_RET
from unicorn import Uc, UcError, UC_ARCH_X86, UC_MODE_64
from unicorn.x86_const import UC_X86_REG_RSP, UC_X86_REG_RBP, UC_X86_REG_RIP

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"arm64-lab"))
from tools.pe_probe import PE
from mxbikes_whole_game_map import INPUT_SHA

BASE=0x140000000
STACK_BASE=0x710000000
ENTRY_SP=STACK_BASE+0x10000
MAX_PARENT_PROLOGUES=512
MAX_PROLOGUE_BYTES=255
MAX_UNWIND_CODES=96
MAX_FRAME_ALLOC=65536

# AMD64 PE unwind operation encodings; only stack-impacting, non-volatile
# register saves and the frame-pointer setup are eligible for our verifier.
SAVE_SLOT_COUNTS={0:1,1:None,2:1,3:1,4:2,5:3,8:2,9:3}


def pdata_index(pe):
    rva,size=pe.directory(3)
    if not rva or size<=0 or size%12 or size//12>600000:
        raise ValueError("Invalid original PE32+ unwind-function directory")
    entries={}
    for begin,end,metadata in struct.iter_unpack("<III",pe.read_rva(rva,size)):
        if not begin or end<=begin or not metadata:
            continue
        if begin in entries and entries[begin]!=(end,metadata):
            raise ValueError("Conflicting PE unwind function entries")
        entries[begin]=(end,metadata)
    return entries


def decode_unwind(pe, metadata):
    try:
        hdr=pe.read_rva(metadata,4)
    except (ValueError,struct.error):
        return {"eligible":False,"reason":"xdata_header_unmapped"}
    version=hdr[0]&7
    flags=hdr[0]>>3
    prolog=hdr[1]
    count=hdr[2]
    frame_reg=hdr[3]&15
    frame_off=hdr[3]>>4
    if version not in (1,2) or count>MAX_UNWIND_CODES or not prolog:
        return {"eligible":False,"reason":"unsupported_header"}
    if flags&4:
        return {"eligible":False,"reason":"chained_unwind_info"}
    if frame_reg not in (0,5):
        return {"eligible":False,"reason":"other_frame_register"}
    if frame_reg==0 and frame_off:
        return {"eligible":False,"reason":"frameless_record_has_frame_offset"}
    try:
        codes=pe.read_rva(metadata+4,count*2)
    except (ValueError,struct.error):
        return {"eligible":False,"reason":"xdata_unwind_codes_unmapped"}
    stack_impact=0
    pushes=0
    setfp=0
    i=0
    while i<count:
        code_offset=codes[2*i]
        opcode=codes[2*i+1]&15
        info=codes[2*i+1]>>4
        if code_offset>prolog:
            return {"eligible":False,"reason":"unwind_offset_exceeds_prologue"}
        if opcode not in SAVE_SLOT_COUNTS:
            return {"eligible":False,"reason":"unsupported_unwind_opcode"}
        slots=SAVE_SLOT_COUNTS[opcode]
        if opcode==1:
            slots=2 if info==0 else 3 if info==1 else 0
        if not slots or i+slots>count:
            return {"eligible":False,"reason":"truncated_unwind_operand"}
        if opcode==0:
            pushes+=1
            stack_impact+=8
        elif opcode==1:
            if info==0:
                size=int.from_bytes(codes[2*i+2:2*i+4],"little")*8
            else:
                size=int.from_bytes(codes[2*i+2:2*i+6],"little")
            stack_impact+=size
        elif opcode==2:
            stack_impact+=8*info+8
        elif opcode==3:
            setfp+=1
            if info:
                return {"eligible":False,"reason":"invalid_frame_register_opcode"}
        i+=slots
        if stack_impact>MAX_FRAME_ALLOC:
            return {"eligible":False,"reason":"frame_exceeds_bounded_stack"}
    if frame_reg==5 and setfp!=1:
        return {"eligible":False,"reason":"missing_or_repeated_frame_pointer_setup"}
    if frame_reg==0 and setfp:
        return {"eligible":False,"reason":"frameless_record_declares_setfp"}
    if stack_impact>MAX_FRAME_ALLOC or (frame_reg==5 and frame_off*16>stack_impact+512):
        return {"eligible":False,"reason":"implausible_unwind_frame"}
    return {
        "eligible":True, "version":version, "flags":flags,
        "prologue_bytes":prolog,
        "has_declared_rbp_frame":frame_reg==5,
        "frame_offset_bytes":frame_off*16 if frame_reg==5 else None,
        "stack_decrement_bytes":stack_impact, "nonvolatile_pushes":pushes,
        "frame_rbp_offset_from_entry_rsp":frame_off*16-stack_impact if frame_reg==5 else None,
    }


def validate_prologue(pe,begin,end,unwind):
    """Execute the exact original prologue until its PE-recorded boundary."""
    if not unwind.get("eligible"):
        return "unwind_not_supported"
    size=unwind["prologue_bytes"]
    if not 1<=size<=MAX_PROLOGUE_BYTES or begin+size>end:
        return "prologue_not_within_pdata_function"
    code=pe.read_rva(begin,size)
    decoder=Cs(CS_ARCH_X86,CS_MODE_64)
    decoder.detail=True
    instructions=list(decoder.disasm(code,BASE+begin))
    if (not instructions or sum(x.size for x in instructions)!=size or
        any(x.group(CS_GRP_CALL) or x.group(CS_GRP_JUMP) or x.group(CS_GRP_RET)
            for x in instructions)):
        return "control_flow_or_partial_prologue_decode"
    uc=Uc(UC_ARCH_X86,UC_MODE_64)
    page=begin&~4095
    last=(begin+size-1)&~4095
    for at in range(page,last+1,4096):
        uc.mem_map(BASE+at,4096)
    uc.mem_map(STACK_BASE,131072)
    uc.mem_write(BASE+begin,code)
    uc.reg_write(UC_X86_REG_RSP,ENTRY_SP)
    uc.reg_write(UC_X86_REG_RBP,STACK_BASE+0x18000)
    uc.reg_write(UC_X86_REG_RIP,BASE+begin)
    try:
        uc.emu_start(BASE+begin,BASE+begin+size,timeout=1000000,count=128)
    except (UcError,ValueError):
        return "original_x64_prologue_emulation_failed"
    if uc.reg_read(UC_X86_REG_RIP)!=BASE+begin+size:
        return "prologue_did_not_reach_end"
    if uc.reg_read(UC_X86_REG_RSP)!=ENTRY_SP-unwind["stack_decrement_bytes"]:
        return "unwind_stack_allocation_disagrees_with_x64"
    if unwind["has_declared_rbp_frame"]:
        if uc.reg_read(UC_X86_REG_RBP)!=uc.reg_read(UC_X86_REG_RSP)+unwind["frame_offset_bytes"]:
            return "unwind_rbp_disagrees_with_x64"
        return "original_x64_rbp_prologue_matches_unwind"
    return "original_x64_frameless_prologue_matches_unwind"


def analyze(pe,mapping,verified):
    if (mapping.get("input_sha256")!=INPUT_SHA or
        mapping.get("original_file_verified") is not True):
        raise ValueError("Prologue validation requires SHA-pinned original map")
    if not isinstance(verified,list):
        raise ValueError("Verified native evidence must be a list")
    targets={int(x["original_rva"],16) for x in verified
             if x.get("full_function_behavior_verified") is True and
                x.get("win64_guest_call_abi_verified") is True and
                x.get("code_presence")=="ephemeral_ci_elf_only"}
    call_edges=mapping.get("direct_call_graph",{})
    parent_rvas={int(parent,16) for parent,children in call_edges.items()
                 if any(int(child,16) in targets for child in children)}
    if len(parent_rvas)>MAX_PARENT_PROLOGUES:
        raise RuntimeError("Caller prologue analysis cap exceeded")
    pdata=pdata_index(pe)
    status=Counter()
    frame_sizes=Counter()
    metadata_summary=Counter()
    for begin in sorted(parent_rvas):
        matched=pdata.get(begin)
        if not matched:
            status["no_matching_pdata_function"]+=1
            continue
        end,metadata=matched
        info=decode_unwind(pe,metadata)
        if not info.get("eligible"):
            status[info["reason"]]+=1
            continue
        frame_sizes["frame_alloc_0_to_255" if info["stack_decrement_bytes"]<256 else
                    "frame_alloc_256_to_1023" if info["stack_decrement_bytes"]<1024 else
                    "frame_alloc_1024_plus"]+=1
        metadata_summary["parsed_rbp_frames" if info["has_declared_rbp_frame"]
                         else "parsed_frameless_frames"]+=1
        verdict=validate_prologue(pe,begin,end,info)
        status[verdict]+=1
    return {
        "schema":1,
        "original_sha256":INPUT_SHA,
        "kind":"original_x64_prologue_unwind_consistency_only",
        "caller_function_intervals_with_verified_native_leaf_edges":len(parent_rvas),
        "rbp_prologues_metadata_parsed":metadata_summary["parsed_rbp_frames"],
        "frameless_prologues_metadata_parsed":metadata_summary["parsed_frameless_frames"],
        "original_x64_rbp_prologues_matching_win64_unwind":status["original_x64_rbp_prologue_matches_unwind"],
        "original_x64_frameless_prologues_matching_win64_unwind":status["original_x64_frameless_prologue_matches_unwind"],
        "original_x64_prologues_matching_win64_unwind":status["original_x64_rbp_prologue_matches_unwind"]+status["original_x64_frameless_prologue_matches_unwind"],
        "unwind_validation_outcomes":dict(sorted(status.items())),
        "frame_allocation_buckets":dict(sorted(frame_sizes.items())),
        "actual_original_callsite_rsp_rbp_traced":False,
        "complete_caller_functions_native_verified":0,
        "original_executable_bytes_exported":False,
        "full_engine_boot_verified":False,
        "limitation":"The original prologue result is not proof of RSP/RBP at a later internal CALL; full caller execution remains unresolved.",
    }


def run(original,mapping_path,verified_path,output):
    pe=PE(original)
    if hashlib.sha256(pe.b).hexdigest()!=INPUT_SHA:
        raise RuntimeError("Original MX Bikes executable SHA mismatch")
    result=analyze(pe,json.loads(mapping_path.read_text()),
                   json.loads(verified_path.read_text()))
    output.mkdir(parents=True,exist_ok=True)
    (output/"original-win64-prologue-audit.json").write_text(json.dumps(result,indent=2)+"\n")
    lines=["# MX Bikes original Win64 frame/unwind prologue audit","",
           "- Caller functions with verified native leaf edges: **"+str(result["caller_function_intervals_with_verified_native_leaf_edges"])+"**",
           "- Original metadata with parsable RBP frames: **"+str(result["rbp_prologues_metadata_parsed"])+"**",
           "- Original metadata with parsable frameless stacks: **"+str(result["frameless_prologues_metadata_parsed"])+"**",
           "- Original x64 frameless prologues agreeing with unwind: **"+str(result["original_x64_frameless_prologues_matching_win64_unwind"])+"**",
           "- Original x64 prologues dynamically agreeing with PE unwind: **"+
             str(result["original_x64_prologues_matching_win64_unwind"])+"**","",
           "| Verification outcome | Original function count |",
           "| --- | ---: |"]
    lines.extend("| "+key+" | "+str(count)+" |"
                 for key,count in result["unwind_validation_outcomes"].items())
    lines.extend(["","**This verifies original entry prologues only, NOT RBP or RSP at an internal CALL site.**",
                  "**No full caller function or engine startup is claimed.**",""])
    markdown="\n".join(lines)
    (output/"original-win64-prologue-audit.md").write_text(markdown)
    print(markdown)
    return result


if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("owned_sha_pinned_original",type=Path)
    p.add_argument("same_run_whole_executable_map",type=Path)
    p.add_argument("verified_native_manifest",type=Path)
    p.add_argument("output",type=Path)
    args=p.parse_args()
    run(args.owned_sha_pinned_original,args.same_run_whole_executable_map,
        args.verified_native_manifest,args.output)
