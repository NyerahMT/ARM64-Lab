#!/usr/bin/env python3
"""Verify original nested dependency 0x1305A9 -> 0x2AAEBC in game startup.

Recover actual Win64 basic-block forms, unwind ownership, direct descendants,
and run the original x64 guest from preceding CALL+child/cookie return through
the new nested CALL to its earliest control, without fabricated returns.
Export metadata only and fail closed on unknown OS services.
"""
import hashlib,json,sys
from pathlib import Path
from unicorn import UC_HOOK_CODE, UcError
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
from capstone.x86 import X86_OP_MEM
from mxbikes_first_callee_emu import import_slots
from unicorn.x86_const import (
 UC_X86_REG_RIP,UC_X86_REG_RSP,UC_X86_REG_RAX,UC_X86_REG_RBX,
 UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_RSI,UC_X86_REG_RDI,
 UC_X86_REG_R12,UC_X86_REG_EFLAGS
)
import mxbikes_init_nested_wave as scan
import mxbikes_main_joined_callee_native as joined
import mxbikes_main_boot_next_call_native as initial
import mxbikes_init_child_successors_native as child
import mxbikes_init_child_return_native as returned
import mxbikes_next_outer_init_native as parent
from mxbikes_whole_game_map import INPUT_SHA

BASE=joined.BASE
CALL=parent.BOUNDARY
TARGET=parent.NESTED
CAP=80

def original_sample(pe,value,first):
    uc=joined.new_cpu(pe)
    outer=joined.ENTRY_SP-0x288
    uc.mem_write(BASE+initial.GLOBAL_RVA,value.to_bytes(4,"little"))
    for reg,v in (
      (UC_X86_REG_RIP,BASE+initial.CALLSITE),
      (UC_X86_REG_RSP,outer),(UC_X86_REG_RAX,1),
      (UC_X86_REG_RBX,0x123456789ABC),
      (UC_X86_REG_RSI,0x111122223333),
      (UC_X86_REG_RDI,0x444455556666),
      (UC_X86_REG_RCX,value),
      (UC_X86_REG_RDX,BASE+initial.CONSTANT_RVA)):
        uc.reg_write(reg,v)
    uc.emu_start(BASE+initial.CALLSITE,BASE+child.parent.CALL,
                 timeout=3000000,count=35)
    if uc.reg_read(UC_X86_REG_RIP)!=BASE+child.parent.CALL:
        raise ValueError("Original parent prefix drifted")
    uc.emu_start(BASE+child.parent.CALL,0,
                 timeout=3000000,count=10)
    if uc.reg_read(UC_X86_REG_RIP)!=BASE+child.TAKEN:
        raise ValueError("Original signed condition should return from nested child")
    uc.emu_start(BASE+child.TAKEN,0,timeout=3000000,count=3)
    uc.emu_start(BASE+returned.x64.CHECK_CALL,0,timeout=3000000,count=12)
    if uc.reg_read(UC_X86_REG_RIP)!=BASE+parent.CALL:
        raise ValueError("Original security-checked child did not return")
    uc.emu_start(BASE+parent.CALL,0,timeout=3000000,count=8)
    if uc.reg_read(UC_X86_REG_RIP)!=BASE+CALL:
        raise ValueError("Original next initializer callee did not reach nested CALL")
    seen=[]
    control=BASE+int(first["control_rva"],16)
    def hook(u,pc,size,ctx):
        seen.append(pc)
        if pc==control:u.emu_stop()
    uc.hook_add(UC_HOOK_CODE,hook)
    try:
        uc.emu_start(BASE+CALL,0,timeout=3000000,count=CAP)
        status="first_control_reached" if seen and seen[-1]==control else "bounded_no_first_control"
    except UcError as exc:
        status="original_x64_fault_"+type(exc).__name__
    flags=uc.reg_read(UC_X86_REG_EFLAGS)
    return {
      "original_dword":value,
      "status":status,
      "nested_called":BASE+TARGET in seen,
      "first_control_hit":control in seen,
      "original_instructions_executed":len(seen),
      "trace_first_rvas":[hex(pc-BASE) if BASE<=pc<BASE+0x800000 else "outside"
                          for pc in seen[:20]],
      "final_guest_rip":hex(uc.reg_read(UC_X86_REG_RIP)),
      "final_guest_rsp":hex(uc.reg_read(UC_X86_REG_RSP)),
      "final_rax":hex(uc.reg_read(UC_X86_REG_RAX)),
      "final_rcx":hex(uc.reg_read(UC_X86_REG_RCX)),
      "final_rdx":hex(uc.reg_read(UC_X86_REG_RDX)),
      "original_flags_zf_sf_cf":[int(bool(flags&64)),
                                  int(bool(flags&128)),
                                  int(bool(flags&1))],
      "native_aarch64_child_executed":False
    }

def run(executable,out):
    from tools.pe_probe import PE
    pe=PE(executable)
    if hashlib.sha256(pe.b).hexdigest()!=INPUT_SHA:
        raise ValueError("Owned game source SHA mismatch")
    parent.verify_original(pe)
    direct=scan.decode_call(pe,CALL)
    if direct["callee_rva"]!=hex(TARGET):
        raise ValueError("Original direct CALL not to expected game helper")
    rows,budget=scan.bounded_wave(pe,TARGET)
    first=rows[0]
    md=Cs(CS_ARCH_X86,CS_MODE_64);md.detail=True
    instructions=list(md.disasm(pe.read_rva(TARGET,8),TARGET,count=1))
    if len(instructions)!=1:
        raise ValueError("Could not verify real thunk opcode")
    ins=instructions[0]
    if (ins.mnemonic!="jmp" or len(ins.operands)!=1 or
        ins.operands[0].type!=X86_OP_MEM or
        ins.reg_name(ins.operands[0].mem.base)!="rip" or
        ins.operands[0].mem.index):
        raise ValueError("Original nested target is not a RIP-relative Win64 import thunk")
    import_slot_rva=ins.address+ins.size+ins.operands[0].mem.disp
    imported=[{"dll":str(dll),"symbol":str(name)}
              for slot,dll,name in import_slots(pe) if int(slot)==import_slot_rva]
    if len(imported)!=1:
        raise ValueError("Imported service pointer lacks one original Win64 IAT name")
    if (imported[0]["dll"].lower(),imported[0]["symbol"].lower())!=("msvcr90.dll","fopen"):
        raise ValueError("Original Win64 startup dependency is not authentic CRT fopen")
    def bounded_original_cstring(rva):
        raw=pe.read_rva(rva,96)
        terminator=raw.find(b"\x00")
        if terminator<1 or terminator>=80 or not all(32<=x<127 for x in raw[:terminator]):
            raise ValueError("Original fopen argument not a bounded printable C string")
        return raw[:terminator].decode("ascii")
    args={
        "filename_guest_rva":hex(0x342e40),
        "mode_guest_rva":hex(0x3422f0),
        "filename":bounded_original_cstring(0x342e40),
        "mode":bounded_original_cstring(0x3422f0),
    }
    successor=scan.scan_first_block(pe,0x1305ae)
    if first["status"]!="static_first_transfer_found":
        raise ValueError("Original x64 nested helper lacks resolvable first control")
    samples=[original_sample(pe,dword,first) for dword in (0,1,0x80000000)]
    report={
        "original_sha256":INPUT_SHA,
        "authentic_nested_call":direct,
        "original_helper_unwind":scan.unwind_owner(pe,TARGET),
        "original_first_block":first,
        "authenticated_original_iat_rva":hex(import_slot_rva),
        "authenticated_original_import":imported[0],
        "authenticated_original_fopen_arguments":args,
        "original_after_fopen_first_block":successor,
        "other_static_descendants":rows[1:],
        "bounded_wave":budget,
        "original_x64_dynamic_samples":samples,
        "native_arm64_nested_dependency_implemented":False,
        "first_loading_screen_observed":False,
    }
    out.mkdir(parents=True,exist_ok=True)
    (out/"next-nested-dependency-wave.json").write_text(json.dumps(report,indent=2)+"\n")
    lines=["# MX Bikes — next authentic nested startup dependency","",
       "- Authentic original CALL: **"+hex(CALL)+" → "+hex(TARGET)+"**",
       "- Original IAT slot: **"+hex(import_slot_rva)+"**",
       "- Original import: **"+imported[0]["dll"]+"!"+imported[0]["symbol"]+"**",
       "- Original fopen filename: **"+args["filename"]+"**",
       "- Original fopen mode: **"+args["mode"]+"**",
       "- After fopen next original control: **"+str(successor.get("control_rva"))+
         " "+str(successor.get("control_kind"))+"**",
       "- Original helper first basic block: **"+
          str(first["precontrol_instruction_count"])+" instructions**",
       "- First original control: **"+first["control_rva"]+
          " "+first["control_kind"]+" "+first["control_operands"]+"**",
       "- Original x64 cases reaching control: **"+
          str(sum(q["first_control_hit"] for q in samples))+"/"+str(len(samples))+"**",
       "- Static descendant nodes: **"+str(len(rows)-1)+"**",
       "","## Original guest instruction forms"]
    lines.extend("- "+r["rva"]+" "+r["mnemonic"]+" "+r["operands"]
                 for r in first.get("precontrol_instruction_forms",[]))
    for row in rows[1:]:
        lines.extend(["","## Direct descendant "+row["entry_rva"],
            "- Precontrol instructions: "+str(row.get("precontrol_instruction_count",0)),
            "- Next control: "+str(row.get("control_rva"))+" "+str(row.get("control_kind"))])
    for s in samples:
        lines.extend(["","- x64 DWORD "+hex(s["original_dword"])+": "+
                      s["status"]+"; first PCs "+", ".join(s["trace_first_rvas"])])
    lines.extend(["","## Post-fopen original first block"])
    lines.extend("- "+item["rva"]+" "+item["mnemonic"]+" "+item["operands"]
                 for item in successor.get("precontrol_instruction_forms",[]))
    lines.extend(["","This is bounded original-x64 reconnaissance, not a native game engine/IPA.",""])
    (out/"next-nested-dependency-wave.md").write_text("\n".join(lines))
    print("\n".join(lines))
    return report

if __name__=="__main__":
    if len(sys.argv)!=3:raise SystemExit("usage: nested_dependency.py owned.exe report-dir")
    run(Path(sys.argv[1]),Path(sys.argv[2]))
