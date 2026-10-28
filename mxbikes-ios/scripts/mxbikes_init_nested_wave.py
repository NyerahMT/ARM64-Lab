#!/usr/bin/env python3
"""Private, bounded next-dependency wave for the verified native initializer.

Discover authentic original x64 direct callees after 0x133EF6, preserve
Win64 instruction identity, unwind ownership, and execute the original x64
child only to its first transfer without faking a Windows/Steam return.
Metadata only: no original bytes, guest memory, native objects or assets.
"""
import hashlib,json,struct,sys
from pathlib import Path
from capstone import Cs,CS_ARCH_X86,CS_MODE_64,CS_GRP_CALL,CS_GRP_JUMP,CS_GRP_RET
from capstone.x86 import X86_OP_IMM,X86_OP_MEM
from unicorn import UC_HOOK_CODE, UcError
from unicorn.x86_const import (
    UC_X86_REG_RIP,UC_X86_REG_RSP,UC_X86_REG_RAX,UC_X86_REG_RSI,
    UC_X86_REG_RCX,UC_X86_REG_RDX,
)
import mxbikes_main_boot_init_callee_native as previous
import mxbikes_main_boot_next_call_native as initial
import mxbikes_main_joined_callee_native as joined
from mxbikes_whole_game_map import INPUT_SHA

BASE=joined.BASE
NESTED=0x133ef6
POST_NESTED=0x133efb
NEXT_CALL=0x133f03
MAX_WAVE=12
MAX_PRECONTROL=48
MAX_INS_BUDGET=160
MAX_BYTES=320

def decode_call(pe,rva,*,following=None):
    md=Cs(CS_ARCH_X86,CS_MODE_64);md.detail=True
    rows=list(md.disasm(pe.read_rva(rva,8),rva,count=1))
    if not rows or rows[0].address!=rva or not rows[0].group(CS_GRP_CALL):
        raise ValueError("Expected original CALL instruction not present")
    ins=rows[0]
    if following is not None and rva+ins.size!=following:
        raise ValueError("Original CALL continuation moved")
    if len(ins.operands)!=1 or ins.operands[0].type!=X86_OP_IMM:
        return {"call_rva":hex(rva),"kind":"unresolved_indirect_call",
                "continuation_rva":hex(rva+ins.size),"callee_rva":None}
    target=ins.operands[0].imm
    if not 0x1000<=target<0x800000:
        raise ValueError("Original direct CALL target outside plausible PE image")
    return {"call_rva":hex(rva),"kind":"direct_original_game_call",
            "continuation_rva":hex(rva+ins.size),"callee_rva":hex(target)}

def scan_first_block(pe,rva,*,cap=MAX_PRECONTROL):
    if not 0x1000<=rva<0x800000 or cap<1 or cap>MAX_PRECONTROL:
        raise ValueError("Invalid original dependency block")
    md=Cs(CS_ARCH_X86,CS_MODE_64);md.detail=True
    forms=[]
    control=None
    for ins in md.disasm(pe.read_rva(rva,MAX_BYTES),rva):
        if (ins.group(CS_GRP_CALL) or ins.group(CS_GRP_JUMP) or
            ins.group(CS_GRP_RET)):
            control=ins;break
        if ins.mnemonic in ("syscall","sysenter","ud2","hlt","int3"):
            break
        forms.append({"rva":hex(ins.address),"mnemonic":ins.mnemonic,
                      "operands":ins.op_str})
        if len(forms)>cap:break
    if control is None:
        return {"entry_rva":hex(rva),"status":"unresolved_bounded_decode",
                "precontrol_instruction_count":len(forms),
                "native_arm64_executed":False}
    row={"entry_rva":hex(rva),"status":"static_first_transfer_found",
         "precontrol_instruction_count":len(forms),
         "precontrol_instruction_forms":forms,
         "control_rva":hex(control.address),"control_kind":control.mnemonic,
         "control_operands":control.op_str,
         "continuation_rva":hex(control.address+control.size),
         "native_arm64_executed":False}
    if (len(control.operands)==1 and
        control.operands[0].type==X86_OP_IMM):
        row["direct_destination_rva"]=hex(control.operands[0].imm)
    elif (len(control.operands)==1 and
          control.operands[0].type==X86_OP_MEM):
        op=control.operands[0]
        if control.reg_name(op.mem.base)=="rip" and not op.mem.index:
            row["indirect_pointer_rva"]=hex(control.address+control.size+op.mem.disp)
    return row

def unwind_owner(pe,rva):
    start,size=pe.directory(3)
    if not start or not size or size%12:
        return {"status":"no_valid_unwind_table"}
    matches=[]
    for lo,hi,meta in struct.iter_unpack("<III",pe.read_rva(start,size)):
        if lo<=rva<hi:
            matches.append((lo,hi))
            if len(matches)>1:break
    if len(matches)!=1:
        return {"status":"missing_or_ambiguous_unwind_owner",
                "matching_intervals":len(matches)}
    lo,hi=matches[0]
    return {"status":"unique_unwind_interval",
            "begin_rva":hex(lo),"end_rva":hex(hi),
            "exact_entry":lo==rva}

def bounded_wave(pe,root):
    queue=[root];seen=set();rows=[]
    while queue and len(rows)<MAX_WAVE:
        rva=queue.pop(0)
        if rva in seen:continue
        seen.add(rva)
        row=scan_first_block(pe,rva)
        row["unwind"]=unwind_owner(pe,rva)
        rows.append(row)
        target=row.get("direct_destination_rva")
        if row.get("control_kind")=="call" and target:
            destination=int(target,16)
            if 0x1000<=destination<0x800000 and destination not in seen:
                queue.append(destination)
    return rows,{"pending_unexplored":len(queue),
                 "wave_limit":MAX_WAVE,
                 "all_static_targets_exhausted":not queue}

def x64_to_first_transfer(pe,child,*,parser_dword,rsi_seed):
    if child.get("status")!="static_first_transfer_found":
        return {"status":"skipped_unresolved_first_transfer"}
    uc=joined.new_cpu(pe)
    original_rsp=joined.ENTRY_SP-0x288
    uc.mem_write(BASE+initial.GLOBAL_RVA,int(parser_dword).to_bytes(4,"little"))
    for register,value in (
        (UC_X86_REG_RIP,BASE+initial.CALLSITE),
        (UC_X86_REG_RSP,original_rsp),
        (UC_X86_REG_RAX,1),
        (UC_X86_REG_RSI,rsi_seed),
        (UC_X86_REG_RCX,parser_dword),
        (UC_X86_REG_RDX,BASE+initial.CONSTANT_RVA)):
        uc.reg_write(register,value)
    # Execute ONLY the independently validated x64 outer prefix.
    uc.emu_start(BASE+initial.CALLSITE,BASE+NESTED,
                 timeout=3000000,count=35)
    if uc.reg_read(UC_X86_REG_RIP)!=BASE+NESTED:
        raise ValueError("Original outer initializer no longer reaches first CALL")
    reached=[]
    expected=BASE+int(child["control_rva"],16)
    def stop(u,pc,size,ctx):
        reached.append(pc)
        if pc==expected:u.emu_stop()
    uc.hook_add(UC_HOOK_CODE,stop)
    result={"parser_dword":int(parser_dword),
            "observed_original_x64_instruction_count":0,
            "reached_original_child_control":False,
            "first_control_rva":child["control_rva"],
            "modeled_external_services":False,
            "native_arm64_child_executed":False}
    try:
        uc.emu_start(BASE+NESTED,0,timeout=3000000,
                     count=MAX_INS_BUDGET)
        result["status"]="stopped_at_child_transfer" if reached and reached[-1]==expected else "bounded_without_reaching_control"
    except UcError as exc:
        result["status"]="original_guest_emulation_fault"
        result["fault_class"]=type(exc).__name__
    result["observed_original_x64_instruction_count"]=len(reached)
    result["reached_original_child_control"]=bool(reached and reached[-1]==expected)
    if reached:
        result["last_observed_original_rva"]=hex(reached[-1]-BASE) if BASE<=reached[-1]<BASE+0x800000 else None
    return result

def run(executable,out):
    from tools.pe_probe import PE
    pe=PE(executable)
    if hashlib.sha256(pe.b).hexdigest()!=INPUT_SHA:
        raise ValueError("Private original executable SHA changed")
    previous.verify_original(pe)
    first=decode_call(pe,NESTED,following=POST_NESTED)
    second=decode_call(pe,NEXT_CALL)
    if first["callee_rva"] is None:
        raise ValueError("Next original game CALL is not statically direct")
    entry=int(first["callee_rva"],16)
    wave,budget=bounded_wave(pe,entry)
    # These are illustrative original x64 fixtures, not full game launch.
    samples=[x64_to_first_transfer(pe,wave[0],
                 parser_dword=value,rsi_seed=0x1234567890+value)
             for value in (0,1,2,0x80)]
    result={
       "original_sha256":INPUT_SHA,
       "first_nested_direct_call":first,
       "next_original_parent_call":second,
       "child_first_control":wave[0],
       "bounded_dependency_wave":wave,
       "bounded_wave_budget":budget,
       "original_x64_child_precontrol_cases":samples,
       "verified_native_child_bodies":0,
       "engine_booted":False,
       "graphics_initialized":False,
       "loading_screen_rendered":False}
    out.mkdir(parents=True,exist_ok=True)
    (out/"initializer-nested-wave.json").write_text(json.dumps(result,indent=2)+"\n")
    lines=["# MX Bikes — original first game initializer nested-call wave","",
       "- Verified outer native ARM64 frontier: **"+hex(NESTED)+"**",
       "- Direct x64 CALL target: **"+first["callee_rva"]+"**",
       "- First child control: **"+wave[0].get("control_rva","unresolved")+" "+
          wave[0].get("control_kind","unknown")+"**",
       "- First child precontrol instructions: **"+
          str(wave[0].get("precontrol_instruction_count",0))+"**",
       "- Original x64 controls reached: **"+
          str(sum(s["reached_original_child_control"] for s in samples))+
          "/"+str(len(samples))+"**",
       "- Nested direct dependency nodes mapped (static): **"+str(len(wave))+"**",
       "- Actual nested original ARM64 function bodies: **0**","",
       "## Target function first block"]
    lines.extend("- "+i["rva"]+": "+i["mnemonic"]+" "+i["operands"]
                 for i in wave[0].get("precontrol_instruction_forms",[]))
    lines.extend(["",
       "Unresolved calls remain fail-closed. No Steam, engine, rendering or iOS game launch.",""])
    (out/"initializer-nested-wave.md").write_text("\n".join(lines))
    print("\n".join(lines))
    return result

if __name__=="__main__":
    if len(sys.argv)!=3:
        raise SystemExit("usage: mxbikes_init_nested_wave.py owned-original.exe metadata-dir")
    run(Path(sys.argv[1]),Path(sys.argv[2]))
