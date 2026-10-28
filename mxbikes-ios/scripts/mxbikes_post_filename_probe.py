#!/usr/bin/env python3
"""Locate the original main's next control after KERNEL32!GetModuleFileNameA.

SHA-pinned owned PE, decode from RVA 0x13675c to first CALL/branch/RET;
execute the original main through callee and the modeled Windows import to
that control instruction. All original bytes stay private. The API response
is an explicit controlled fixture, never a claim to execute real KERNEL32.
"""
from pathlib import Path
import hashlib,json,struct,sys
from capstone import Cs,CS_ARCH_X86,CS_MODE_64,CS_GRP_CALL,CS_GRP_JUMP,CS_GRP_RET
from capstone.x86 import X86_OP_MEM
from unicorn import UC_HOOK_CODE
from unicorn.x86_const import (
    UC_X86_REG_RIP,UC_X86_REG_RSP,UC_X86_REG_RAX,
    UC_X86_REG_RBX,UC_X86_REG_RCX,UC_X86_REG_RDX,
    UC_X86_REG_R8,UC_X86_REG_R9,UC_X86_REG_RDI,
    UC_X86_REG_RSI,UC_X86_REG_R11,UC_X86_REG_R10,
    UC_X86_REG_EFLAGS
)
from mxbikes_main_filename_native import (
 BASE,MAIN,AFTER_IMPORT,CALL_IMPORT,HOST_STUB,PATH,PATH_LEN,
 WINDOW,verify_next_import,
 inspect_original,new_cpu,ENTRY_SP,TEST_INPUT,
 SEED_RBX,SEED_RDI,SEED_RSI,SEED_R11,EXE_SHA
)
from mxbikes_first_callee_emu import import_slots

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"arm64-lab"))
from tools.pe_probe import PE

def discover(pe):
    md=Cs(CS_ARCH_X86,CS_MODE_64)
    md.detail=True
    decoded=[]
    control=None
    for ins in md.disasm(pe.read_rva(AFTER_IMPORT,256),AFTER_IMPORT):
        if ins.group(CS_GRP_CALL) or ins.group(CS_GRP_JUMP) or ins.group(CS_GRP_RET):
            control=ins
            break
        decoded.append(ins)
        if len(decoded)>32:
            raise RuntimeError("Too many original post-import instructions")
    if not control:
        raise RuntimeError("No original post-import transfer within 256 bytes")
    details={"start_rva":hex(AFTER_IMPORT),
             "stop_control_rva":hex(control.address),
             "stop_mnemonic":control.mnemonic,
             "stop_operands":control.op_str,
             "original_precontrol_instructions":len(decoded),
             "original_precontrol_bytes":control.address-AFTER_IMPORT,
             "instruction_forms":[{"rva":hex(i.address),
                  "mnemonic":i.mnemonic,"operands":i.op_str} for i in decoded]}
    if(control.group(CS_GRP_CALL) and len(control.operands)==1 and
       control.operands[0].type==X86_OP_MEM and
       control.reg_name(control.operands[0].mem.base)=="rip" and
       not control.operands[0].mem.index):
        slot=(control.address+control.size+
              control.operands[0].mem.disp)
        known={int(rva):{"dll":dll,"name":name}
               for rva,dll,name in import_slots(pe)}
        details["next_import_iat_slot_rva"]=hex(slot)
        details["next_import"]=known.get(slot)
    return details,control

def original_probe(pe,layout,slot,stop,case):
    cpu=new_cpu(pe)
    cpu.mem_map(HOST_STUB,4096)
    cpu.mem_write(HOST_STUB,b"\xc3")
    cpu.mem_write(BASE+slot,struct.pack("<Q",HOST_STUB))
    cpu.mem_write(TEST_INPUT,b"\x00")
    cpu.mem_write(ENTRY_SP,struct.pack("<Q",BASE+0x777777))
    seeds={
      UC_X86_REG_RIP:BASE+MAIN,UC_X86_REG_RSP:ENTRY_SP,
      UC_X86_REG_RAX:0x888876543210+case,
      UC_X86_REG_RBX:SEED_RBX,UC_X86_REG_RCX:BASE,
      UC_X86_REG_RDX:0,UC_X86_REG_R8:TEST_INPUT,UC_X86_REG_R9:10,
      UC_X86_REG_RDI:SEED_RDI,UC_X86_REG_RSI:SEED_RSI,
      UC_X86_REG_R11:SEED_R11,UC_X86_REG_R10:0x78123456789,
      UC_X86_REG_EFLAGS:0x202|[0,1,0x40,0x80,0xc1,0x41,0x200,0x81][case%8]
    }
    for reg,value in seeds.items():cpu.reg_write(reg,value)
    responses=[]
    trace=[]
    def hook(u,pc,size,ctx):
        trace.append(pc)
        if pc==HOST_STUB:
            if(u.reg_read(UC_X86_REG_RCX)!=0 or
               u.reg_read(UC_X86_REG_R8)!=WINDOW or
               u.reg_read(UC_X86_REG_RDX)!=ENTRY_SP-0x288+0x140):
                raise RuntimeError("Original KERNEL32 call changed arguments")
            u.mem_write(u.reg_read(UC_X86_REG_RDX),PATH+b"\x00")
            u.reg_write(UC_X86_REG_RAX,PATH_LEN)
            responses.append(pc)
        if len(trace)>80:
            raise RuntimeError("Original instructions exceeded hard bound")
    cpu.hook_add(UC_HOOK_CODE,hook)
    cpu.emu_start(BASE+MAIN,BASE+stop.address,timeout=4000000,count=80)
    pc=cpu.reg_read(UC_X86_REG_RIP)
    if (pc!=BASE+stop.address or len(responses)!=1 or
        BASE+AFTER_IMPORT not in trace):
        raise RuntimeError("Did not execute authentic main through module filename to next frontier")
    regvalues={name:hex(cpu.reg_read(reg)) for name,reg in {
        "rax":UC_X86_REG_RAX,"rdx":UC_X86_REG_RDX,
        "rcx":UC_X86_REG_RCX,"r8":UC_X86_REG_R8,
        "r9":UC_X86_REG_R9,"r10":UC_X86_REG_R10,
        "rsp":UC_X86_REG_RSP,"rip":UC_X86_REG_RIP
    }.items()}
    ef=cpu.reg_read(UC_X86_REG_EFLAGS)
    regvalues["flags"]={"zf":bool(ef&64),"cf":bool(ef&1),
                        "sf":bool(ef&128),"of":bool(ef&0x800)}
    # Authentic original Win64 helper call stack and saved argument.
    import struct as _struct
    saved_arg=_struct.unpack("<Q",bytes(cpu.mem_read(ENTRY_SP-0x288,8)))[0]
    return_slot=_struct.unpack("<Q",bytes(cpu.mem_read(ENTRY_SP-0x288-8,8)))[0]
    return {"case":case,"pc_rva":hex(pc-BASE),
            "original_helper_shadow_arg":hex(saved_arg),
            "original_helper_guest_return":hex(return_slot),
            "original_executed_instruction_count":len(trace),
            "precontrol_instructions_executed":len([pc for pc in trace if BASE+AFTER_IMPORT<=pc<BASE+stop.address]),
            "modeled_import_responses":len(responses),
            "registers":regvalues}

def run(executable,out):
    pe=PE(executable)
    if hashlib.sha256(pe.b).hexdigest()!=EXE_SHA:
        raise RuntimeError("Original game SHA mismatch")
    layout,_,_=inspect_original(pe)
    slot=verify_next_import(pe)
    meta,stop=discover(pe)
    meta["actual_original_x64_execution"]=[
        original_probe(pe,layout,slot,stop,k) for k in (0,5,9)]
    if not all(x["precontrol_instructions_executed"]==
               meta["original_precontrol_instructions"]
               for x in meta["actual_original_x64_execution"]):
        raise RuntimeError("Original step count differs from static scan")
    meta["native_arm64_post_import_instructions_executed"]=0
    meta["full_game_engine_booted"]=False
    meta["fixture_executable_path_is_synthetic"]=True
    out.mkdir(parents=True,exist_ok=True)
    (out/"post-filename-control.json").write_text(json.dumps(meta,indent=2)+"\n")
    lines=["# Original MX Bikes next main frontier after GetModuleFileNameA","",
           "- Start RVA: **"+meta["start_rva"]+"**",
           "- Original x64 instructions before next control: **"+
             str(meta["original_precontrol_instructions"])+"**",
           "- Next control: **"+meta["stop_control_rva"]+
             " "+meta["stop_mnemonic"]+" "+meta["stop_operands"]+"**",
           "- Next import: **"+str(meta.get("next_import"))+"**",
           "- Executed from original game main through modeled Windows import: **"+
             str(len(meta["actual_original_x64_execution"]))+" validated cases**","",
           "## Original precontrol disassembly"]
    for item in meta["instruction_forms"]:
        lines.append("- "+item["rva"]+": "+item["mnemonic"]+" "+item["operands"])
    lines+=["",
        "**This is original x64 reconnaissance. No new native ARM64 instructions "
        "or additional original Windows imports are executed here.**",""]
    summary="\n".join(lines)
    (out/"post-filename-control.md").write_text(summary)
    print(summary)
    return meta

if __name__=="__main__":
    if len(sys.argv)!=3:
        raise SystemExit("usage: post_filename.py original-pe report-dir")
    run(Path(sys.argv[1]),Path(sys.argv[2]))
