#!/usr/bin/env python3
"""Explore first original MX Bikes internal function after GetModuleFileNameA.

The entry edge is original RVA 0x136764 -> 0x15b790. Inspect the native
callee first basic block from original PE and verify its first control is
reached by executing original main + original callee + modeled filename API.
This is private x64 analysis; no native helper execution claimed.
"""
from pathlib import Path
import hashlib,json,sys,struct
from capstone import Cs,CS_ARCH_X86,CS_MODE_64,CS_GRP_CALL,CS_GRP_JUMP,CS_GRP_RET
from capstone.x86 import X86_OP_IMM
from mxbikes_post_filename_probe import discover,original_probe
from mxbikes_main_filename_native import (
 BASE,EXE_SHA,AFTER_IMPORT,inspect_original,verify_next_import
)
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"arm64-lab"))
from tools.pe_probe import PE
TARGET=0x15b790
EXPECTED_CALL=0x136764
MAX_INS=38

def helper_first_frontier(pe):
    md=Cs(CS_ARCH_X86,CS_MODE_64);md.detail=True
    code=pe.read_rva(TARGET,256)
    prefix=[]
    control=None
    for ins in md.disasm(code,TARGET):
        if ins.group(CS_GRP_CALL) or ins.group(CS_GRP_JUMP) or ins.group(CS_GRP_RET):
            control=ins;break
        prefix.append(ins)
        if len(prefix)>MAX_INS:
            raise RuntimeError("Original helper prefix exceeds bound")
    if control is None:
        raise RuntimeError("No bounded first original helper control")
    pdata,size=pe.directory(3)
    candidates=[]
    if pdata and size and size%12==0:
        candidates=[{"start_rva":hex(lo),"end_rva":hex(hi)}
                    for lo,hi,_ in struct.iter_unpack("<III",pe.read_rva(pdata,size))
                    if lo<=TARGET<hi]
    return {
        "helper_rva":hex(TARGET),
        "prefix_instructions_before_control":len(prefix),
        "prefix_bytes":control.address-TARGET,
        "next_control_rva":hex(control.address),
        "next_control_mnemonic":control.mnemonic,
        "next_control_operands":control.op_str,
        "first_control_after_prefix":control.address,
        "unwind_intervals":candidates,
        "original_prefix_forms":[{"rva":hex(ins.address),"mnemonic":ins.mnemonic,
                                  "operands":ins.op_str} for ins in prefix]
    },control

def run(executable,out):
    pe=PE(executable)
    if hashlib.sha256(pe.b).hexdigest()!=EXE_SHA:
        raise RuntimeError("Original game SHA mismatch")
    layout,_,_=inspect_original(pe)
    module_import_slot=verify_next_import(pe)
    main_frontier,main_control=discover(pe)
    md=Cs(CS_ARCH_X86,CS_MODE_64);md.detail=True
    call=list(md.disasm(pe.read_rva(EXPECTED_CALL,5),EXPECTED_CALL))
    if (main_control.address!=EXPECTED_CALL or
        len(call)!=1 or not call[0].group(CS_GRP_CALL) or
        call[0].operands[0].type!=X86_OP_IMM or
        int(call[0].operands[0].imm)!=TARGET):
        raise RuntimeError("Expected original game helper callsite changed")
    helper,frontier=helper_first_frontier(pe)
    executions=[original_probe(pe,layout,module_import_slot,frontier,k)
                for k in (0,5,9)]
    for x in executions:
        if x["pc_rva"]!=helper["next_control_rva"]:
            raise RuntimeError("Original helper first control not executed")
    helper.pop("first_control_after_prefix")
    result={
      "original_sha_verified":True,
      "game_main_callsite_rva":hex(EXPECTED_CALL),
      "direct_original_call_target_rva":hex(TARGET),
      "caller_post_filename_prefix_instructions":main_frontier["original_precontrol_instructions"],
      **helper,
      "original_x64_main_through_helper_execution_cases":executions,
      "native_arm64_helper_executed":False,
      "game_engine_initialized":False
    }
    out.mkdir(parents=True,exist_ok=True)
    (out/"after-filename-helper-first-frontier.json").write_text(json.dumps(result,indent=2)+"\n")
    lines=[
      "# MX Bikes — first internal helper after filename import","",
      "- Original game main CALL: **"+hex(EXPECTED_CALL)+" → "+hex(TARGET)+"**",
      "- First helper original x64 instructions before control: **"+str(result["prefix_instructions_before_control"])+"**",
      "- First helper control: **"+result["next_control_rva"]+" "+result["next_control_mnemonic"]+" "+result["next_control_operands"]+"**",
      "- Verified authentic original x64 end-to-end scenarios: **"+str(len(executions))+"**",
      "","## Original first helper block"
    ]
    lines.extend("- "+r["rva"]+": "+r["mnemonic"]+" "+r["operands"]
                 for r in result["original_prefix_forms"])
    lines+=["",
      "**This only confirms original x64 path and first control target. No new ARM64 helper body or game startup is asserted.**",""]
    summary="\n".join(lines)
    (out/"after-filename-helper-first-frontier.md").write_text(summary)
    print(summary)
    return result

if __name__=="__main__":
    if len(sys.argv)!=3:
        raise SystemExit("usage: next_helper.py original-game.exe metadata-dir")
    run(Path(sys.argv[1]),Path(sys.argv[2]))
