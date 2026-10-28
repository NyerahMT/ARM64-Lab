#!/usr/bin/env python3
"""Map actual next outer initializer callee after cookie-checked child RETURN.

Uses the authentic SHA-pinned Win64 x64 path to the parent 0x133F03 CALL,
then executes original CALL 0x130580 and the real target first basic block.
Always stop at the target's next transfer, never execute unresolved services.
The bounded grouped dependency map is static; the original control reached
is separately dynamically verified. No AArch64 implementation is claimed.
"""
import hashlib,json,sys
from pathlib import Path
from unicorn.x86_const import (
 UC_X86_REG_RIP,UC_X86_REG_RSP,UC_X86_REG_RAX,UC_X86_REG_RBX,
 UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_RSI,UC_X86_REG_RDI
)
import mxbikes_init_nested_wave as scan
import mxbikes_init_child_return_native as native
import mxbikes_init_child_return_probe as early
import mxbikes_main_joined_callee_native as joined
import mxbikes_main_boot_next_call_native as boot
from mxbikes_whole_game_map import INPUT_SHA

BASE=joined.BASE
CHILD=0x130580
CALL=early.NEXT_CALL

def x64_nested_successor(pe,value,first_control,count):
    uc=joined.new_cpu(pe)
    caller=joined.ENTRY_SP-0x288
    uc.mem_write(BASE+boot.GLOBAL_RVA,value.to_bytes(4,"little"))
    for reg,v in (
      (UC_X86_REG_RIP,BASE+boot.CALLSITE),(UC_X86_REG_RSP,caller),
      (UC_X86_REG_RAX,1),(UC_X86_REG_RBX,0x12345678),
      (UC_X86_REG_RCX,value),(UC_X86_REG_RDX,BASE+boot.CONSTANT_RVA),
      (UC_X86_REG_RSI,0x111122223333),(UC_X86_REG_RDI,0x444455556666)):
        uc.reg_write(reg,v)
    uc.emu_start(BASE+boot.CALLSITE,BASE+native.prior.parent.CALL,
                 timeout=3000000,count=35)
    uc.emu_start(BASE+native.prior.parent.CALL,0,
                 timeout=3000000,count=10)
    if uc.reg_read(UC_X86_REG_RIP)!=BASE+native.prior.TAKEN:
        raise ValueError("Original x64 initializer expected early-return branch")
    uc.emu_start(BASE+native.prior.TAKEN,0,
                 timeout=3000000,count=3)
    uc.emu_start(BASE+early.CHECK_CALL,0,
                 timeout=3000000,count=12)
    if uc.reg_read(UC_X86_REG_RIP)!=BASE+CALL:
        raise ValueError("Actual checker CALL/RET did not resume parent initializer")
    uc.emu_start(BASE+CALL,0,timeout=3000000,count=1+count)
    result={
      "original_input_dword":value,
      "first_control_rva":hex(first_control),
      "reached_first_original_control":
          uc.reg_read(UC_X86_REG_RIP)==BASE+first_control,
      "actual_next_guest_rva":hex(uc.reg_read(UC_X86_REG_RIP)-BASE),
      "actual_rsp":hex(uc.reg_read(UC_X86_REG_RSP)),
      "original_dword":value,
      "original_nested_returned":True,
      "native_arm64_next_function_executed":False
    }
    if not result["reached_first_original_control"]:
        raise ValueError("Original x64 next callee control not reached")
    return result

def run(executable,out):
    from tools.pe_probe import PE
    pe=PE(executable)
    if hashlib.sha256(pe.b).hexdigest()!=INPUT_SHA:
        raise ValueError("Original owned game binary SHA mismatch")
    native.verify(pe)
    call=scan.decode_call(pe,CALL)
    if call["callee_rva"]!=hex(CHILD):
        raise ValueError("Original next initializer CALL target moved")
    blocks,budget=scan.bounded_wave(pe,CHILD)
    first=blocks[0]
    if first.get("status")!="static_first_transfer_found":
        raise ValueError("Original next initializer callee lacked bounded control")
    ctrl=int(first["control_rva"],16)
    samples=[x64_nested_successor(pe,v,ctrl,first["precontrol_instruction_count"])
             for v in (0,1,0x80000000)]
    report={
       "original_sha256":INPUT_SHA,
       "original_outer_call_rva":hex(CALL),
       "original_direct_child_rva":hex(CHILD),
       "original_child_first_control_rva":hex(ctrl),
       "original_child_precontrol_original_instructions":
           first["precontrol_instruction_count"],
       "original_x64_dynamic_first_control_cases":len(samples),
       "original_x64_dynamic_samples":samples,
       "original_static_bounded_wave":blocks,
       "static_budget":budget,
       "native_aarch64_new_callee_translated":False,
       "actual_game_engine_renderer_or_loading_screen":False
    }
    out.mkdir(parents=True,exist_ok=True)
    (out/"next-outer-init-callee-wave.json").write_text(json.dumps(report,indent=2)+"\n")
    lines=["# MX Bikes — original next parent CALL after genuine child RET","",
       "- Original direct CALL: **"+hex(CALL)+" → "+hex(CHILD)+"**",
       "- Next original basic-block instruction count: **"+
          str(first["precontrol_instruction_count"])+"**",
       "- Next real control: **"+first["control_rva"]+" "+
          first["control_kind"]+" "+first["control_operands"]+"**",
       "- Original x64 dynamic next-control samples: **"+
          str(sum(x["reached_first_original_control"] for x in samples))+
          "/"+str(len(samples))+"**",
       "- Bounded static dependency nodes: **"+str(len(blocks))+"**",
       "","## Authenticated original x64 first basic block"]
    lines.extend("- "+x["rva"]+" "+x["mnemonic"]+" "+x["operands"]
                 for x in first["precontrol_instruction_forms"])
    lines.extend(["","Native ARM64 new callee not yet implemented; engine, graphics and IPA not running.",""])
    (out/"next-outer-init-callee-wave.md").write_text("\n".join(lines))
    print("\n".join(lines))
    return report

if __name__=="__main__":
    if len(sys.argv)!=3:
        raise SystemExit("usage: next_outer_init_wave.py original.exe report-dir")
    run(Path(sys.argv[1]),Path(sys.argv[2]))
