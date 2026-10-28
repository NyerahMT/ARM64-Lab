#!/usr/bin/env python3
"""Original x64-only next completed nested return-path reconnaissance.

Inspect signed-JLE taken branch 0x133C9A, its real 0x133CA7 cookie checker
CALL -> 0x2AAE60, its authentic RET into initializer 0x133EFB, and
next initializer CALL 0x133F03. The private SHA-pinned original PE is
executed only as a guest with no guessed return/Steam services.
Only RVA register/stack and control-flow metadata are exported.
"""
import hashlib,json,sys
from pathlib import Path
from capstone import Cs,CS_ARCH_X86,CS_MODE_64,CS_GRP_CALL
from capstone.x86 import X86_OP_IMM
from unicorn import UC_HOOK_CODE, UcError
from unicorn.x86_const import (
 UC_X86_REG_RIP,UC_X86_REG_RSP,UC_X86_REG_RAX,UC_X86_REG_RBX,
 UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_RSI,UC_X86_REG_RDI,
 UC_X86_REG_EFLAGS
)
import mxbikes_init_child_successors_native as parent
import mxbikes_init_nested_wave as wave
import mxbikes_main_boot_next_call_native as boot
import mxbikes_main_joined_callee_native as joined
from mxbikes_whole_game_map import INPUT_SHA

BASE=joined.BASE
CHECK_CALL=parent.TAKEN_CONTROL
CHECK_TARGET=0x2aae60
CHECK_RETURN=0x133cac
AFTER_CHILD_RET=0x133efb
NEXT_CALL=0x133f03
BOUND=120

def inspect(pe):
    parent.validate_original(pe)
    call=wave.decode_call(pe,CHECK_CALL,following=CHECK_RETURN)
    next_call=wave.decode_call(pe,NEXT_CALL)
    if call["callee_rva"]!=hex(CHECK_TARGET) or next_call["callee_rva"]!=hex(0x130580):
        raise ValueError("Original nested cookie checker or next outer call moved")
    targets=(CHECK_TARGET,CHECK_RETURN,AFTER_CHILD_RET)
    return {
       "authentic_cookie_call":call,
       "next_original_outer_call":next_call,
       "original_x64_return_dependencies":[{
           **wave.scan_first_block(pe,rva),
           "original_unwind_owner":wave.unwind_owner(pe,rva)
       } for rva in targets]
    }

def original_x64_return(pe,dword,*,rbx=0x12345678,rsi=0x111122223333,rdi=0x444455556666):
    uc=joined.new_cpu(pe)
    stack=joined.ENTRY_SP-0x288
    uc.mem_write(BASE+boot.GLOBAL_RVA,int(dword).to_bytes(4,"little"))
    for reg,value in (
      (UC_X86_REG_RIP,BASE+boot.CALLSITE),(UC_X86_REG_RSP,stack),
      (UC_X86_REG_RAX,1),(UC_X86_REG_RBX,rbx),
      (UC_X86_REG_RCX,dword),(UC_X86_REG_RDX,BASE+boot.CONSTANT_RVA),
      (UC_X86_REG_RSI,rsi),(UC_X86_REG_RDI,rdi)):
        uc.reg_write(reg,value)
    uc.emu_start(BASE+boot.CALLSITE,BASE+parent.parent.CALL,
                 timeout=3000000,count=35)
    if uc.reg_read(UC_X86_REG_RIP)!=BASE+parent.parent.CALL:
        raise ValueError("Original outer first block failed")
    uc.emu_start(BASE+parent.parent.CALL,0,
                 timeout=3000000,count=10)
    if uc.reg_read(UC_X86_REG_RIP)!=BASE+parent.TAKEN:
        raise ValueError("Original child was expected to take JLE")
    uc.emu_start(BASE+parent.TAKEN,0,timeout=3000000,count=3)
    if uc.reg_read(UC_X86_REG_RIP)!=BASE+CHECK_CALL:
        raise ValueError("Authentic early branch did not reach real CALL")
    seen=[]
    def hook(u,pc,size,context):
        seen.append(pc)
        if pc==BASE+NEXT_CALL:u.emu_stop()
    uc.hook_add(UC_HOOK_CODE,hook)
    status="unknown"
    try:
        uc.emu_start(BASE+CHECK_CALL,0,timeout=3000000,count=BOUND)
        status="reached_next_outer_call" if seen and seen[-1]==BASE+NEXT_CALL else "bounded_original_x64"
    except UcError as exc:
        status="original_x64_guest_fault_"+type(exc).__name__
    flags=uc.reg_read(UC_X86_REG_EFLAGS)
    sp=uc.reg_read(UC_X86_REG_RSP)
    path=[hex(x-BASE) if BASE<=x<BASE+0x800000 else "external" for x in seen]
    return {
      "original_input_dword":dword,"status":status,
      "observed_guest_instructions":len(path),
      "original_x64_trace_rvas":path[:BOUND],
      "authentic_cookie_checker_called":hex(CHECK_TARGET) in path,
      "authentic_cookie_checker_returned":hex(CHECK_RETURN) in path,
      "authentic_child_return_reached":hex(AFTER_CHILD_RET) in path,
      "authentic_next_outer_call_reached":hex(NEXT_CALL) in path,
      "original_guest_rip":hex(uc.reg_read(UC_X86_REG_RIP)-BASE),
      "original_guest_rsp":hex(sp),
      "original_guest_rax":hex(uc.reg_read(UC_X86_REG_RAX)),
      "original_guest_rcx":hex(uc.reg_read(UC_X86_REG_RCX)),
      "original_guest_rdx":hex(uc.reg_read(UC_X86_REG_RDX)),
      "original_guest_rbx":hex(uc.reg_read(UC_X86_REG_RBX)),
      "original_zf":int(bool(flags&64)),
      "original_cf":int(bool(flags&1)),
      "original_sf":int(bool(flags&128)),
      "outer_return_slot":hex(int.from_bytes(uc.mem_read(stack-8,8),"little")),
      "child_return_slot":hex(int.from_bytes(uc.mem_read(stack-0x2a0-8,8),"little"))
    }

def run(executable,out):
    from tools.pe_probe import PE
    pe=PE(executable)
    if hashlib.sha256(pe.b).hexdigest()!=INPUT_SHA:
        raise ValueError("Original PE SHA mismatch")
    report=inspect(pe)
    report["original_x64_return_samples"]=[original_x64_return(pe,value)
                                              for value in (0,1,0x80000000)]
    report["actual_native_aarch64_child_function_fully_returned"]=False
    report["game_engine_or_renderer_started"]=False
    out.mkdir(parents=True,exist_ok=True)
    (out/"nested-child-return-original-x64.json").write_text(json.dumps(report,indent=2)+"\n")
    lines=["# MX Bikes — original early child full CALL/RET boundary","",
      "- SHA-pinned original checker CALL: **"+hex(CHECK_CALL)+
      " → "+hex(CHECK_TARGET)+"**",
      "- Original checker return address: **"+hex(CHECK_RETURN)+"**",
      "- Next original parent CALL: **"+hex(NEXT_CALL)+"**",""]
    for row in report["original_x64_return_dependencies"]:
        lines.extend(["## "+row["entry_rva"],
         "- Original instructions to first control: **"+str(row.get("precontrol_instruction_count"))+"**",
         "- Original control: **"+row.get("control_rva","unresolved")+
            " "+row.get("control_kind","unknown")+" "+row.get("control_operands","")+"**"])
        lines.extend("- "+x["rva"]+" "+x["mnemonic"]+" "+x["operands"]
                     for x in row.get("precontrol_instruction_forms",[]))
    for s in report["original_x64_return_samples"]:
        lines.extend(["",
          "- Original x64 DWORD "+hex(s["original_input_dword"])+": **"+
             s["status"]+"**, checker called/returned "+
             str(s["authentic_cookie_checker_called"])+"/"+
             str(s["authentic_cookie_checker_returned"])+
             ", child returned "+str(s["authentic_child_return_reached"])+
             ", next parent call "+str(s["authentic_next_outer_call_reached"]),
          "- Actual original guest PC trace: "+", ".join(s["original_x64_trace_rvas"])])
    lines.extend(["","No fake security-cookie result, no full native child RET, no engine/graphics.",""])
    (out/"nested-child-return-original-x64.md").write_text("\n".join(lines))
    print("\n".join(lines))
    return report

if __name__=="__main__":
    if len(sys.argv)!=3:
        raise SystemExit("usage: nested_return_probe.py original-owned-exe metadata-dir")
    run(Path(sys.argv[1]),Path(sys.argv[2]))
