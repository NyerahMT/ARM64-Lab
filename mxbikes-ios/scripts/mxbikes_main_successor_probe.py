#!/usr/bin/env python3
"""Bounded original MX Bikes game main/CALL/callee successor probe.

Executes authentic original x64 (SHA verified), starting in game main,
through first native-proven callee JE and each selected successor path,
stopping BEFORE the next transfer instruction. Reports bounded code shapes.
No full callee, engine or native next-block execution is claimed.
"""
import hashlib,json,struct,sys
from pathlib import Path
from capstone import Cs,CS_ARCH_X86,CS_MODE_64,CS_GRP_CALL,CS_GRP_JUMP,CS_GRP_RET
from capstone.x86 import X86_OP_MEM
from unicorn import UcError,UC_HOOK_CODE,UC_HOOK_MEM_INVALID
from unicorn.x86_const import (
 UC_X86_REG_RAX,UC_X86_REG_RBX,UC_X86_REG_RCX,UC_X86_REG_RDX,
 UC_X86_REG_R8,UC_X86_REG_R9,UC_X86_REG_RDI,UC_X86_REG_RSI,
 UC_X86_REG_R11,UC_X86_REG_R10,UC_X86_REG_RIP,UC_X86_REG_RSP,
 UC_X86_REG_EFLAGS
)
from mxbikes_first_callee_emu import import_slots
from mxbikes_main_joined_callee_native import (
 new_cpu, inspect_original,BASE,MAIN,CALLEE,AFTER_CALL,
 CODE_DATA,STACK,ENTRY_SP,TEST_INPUT,
 SEED_RBX,SEED_RDI,SEED_RSI,SEED_R11
)
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"arm64-lab"))
from tools.pe_probe import PE
SHA="4ae7de3854b4d0a18271679fb57a1f2fdf0b21804417b85dd82055078ea123b6"
MAX_SUCCESSOR_BYTES=256
MAX_SUCCESSOR_INSTRUCTIONS=32

def decode_successor(pe,start):
    md=Cs(CS_ARCH_X86,CS_MODE_64);md.detail=True
    forms=[]
    stop=None
    for ins in md.disasm(pe.read_rva(start,MAX_SUCCESSOR_BYTES),start):
        if ins.group(CS_GRP_JUMP) or ins.group(CS_GRP_CALL) or ins.group(CS_GRP_RET):
            stop=ins;break
        if ins.mnemonic in ("syscall","sysenter","int3","ud2","hlt"):
            raise RuntimeError("Invalid or unsupported original x64 successor opcode")
        if len(forms)>=MAX_SUCCESSOR_INSTRUCTIONS:
            raise RuntimeError("Original successor exceeds bounded decode budget")
        forms.append(ins)
    if stop is None:
        raise RuntimeError("No next x64 control flow within successor prefix budget")
    return {
       "entry_rva":hex(start),
       "prefix_instruction_count":len(forms),
       "prefix_bytes":stop.address-start,
       "first_control_rva":hex(stop.address),
       "first_control_kind":stop.mnemonic,
       "first_control_operands":stop.op_str,
       "prefix_instruction_forms":[
           {"rva":hex(ins.address),"mnemonic":ins.mnemonic,
            "operands":ins.op_str} for ins in forms
       ],
       "prefix_address_set":set(BASE+x.address for x in forms),
       "first_control_pc":BASE+stop.address
    }

def execute_frontier(pe,layout,entry,first_control,first_control_pc,byte):
    uc=new_cpu(pe)
    uc.mem_write(TEST_INPUT,bytes([byte]))
    uc.mem_write(ENTRY_SP,struct.pack("<Q",BASE+0x777777))
    seeds={
      UC_X86_REG_RIP:BASE+MAIN,UC_X86_REG_RSP:ENTRY_SP,
      UC_X86_REG_RAX:0x888876543210,
      UC_X86_REG_RBX:SEED_RBX,UC_X86_REG_RCX:BASE,
      UC_X86_REG_RDX:0,UC_X86_REG_R8:TEST_INPUT,UC_X86_REG_R9:10,
      UC_X86_REG_RDI:SEED_RDI,UC_X86_REG_RSI:SEED_RSI,
      UC_X86_REG_R11:SEED_R11,UC_X86_REG_R10:0x78123456789,
      UC_X86_REG_EFLAGS:0x202
    }
    for reg,value in seeds.items():uc.reg_write(reg,value)
    trace=[];faults=[]
    def on_code(m,address,size,context):
        trace.append(address)
        if address==first_control_pc:
            m.emu_stop()
        if len(trace)>85:
            faults.append("instruction_budget_exceeded")
            m.emu_stop()
    def on_fault(m,access,address,size,value,context):
        faults.append("unmapped_guest_access at "+hex(address))
        return False
    uc.hook_add(UC_HOOK_CODE,on_code)
    uc.hook_add(UC_HOOK_MEM_INVALID,on_fault)
    try:
        uc.emu_start(BASE+MAIN,0,timeout=3000000,count=85)
    except UcError as exc:
        faults.append(str(exc))
    arrived=uc.reg_read(UC_X86_REG_RIP)==first_control_pc and not faults
    if trace and trace[-1]==first_control_pc and arrived:
        allowed=set(first_control["prefix_address_set"])
        in_successor=[a for a in trace if a in allowed]
        arrived=bool(len(in_successor)==first_control["prefix_instruction_count"] or
                     not first_control["prefix_instruction_count"])
    return {
       "input_first_byte":byte,
       "start_main_rva":hex(MAIN),
       "main_to_callee_branch_executed":BASE+CALLEE in trace,
       "successor_entry_seen":BASE+entry in trace,
       "next_control_reached":arrived,
       "original_executed_insns_including_control_stop":len(trace),
       "final_pc_rva":hex(uc.reg_read(UC_X86_REG_RIP)-BASE),
       "faults":faults[:3],
       "final_guest_rsp":hex(uc.reg_read(UC_X86_REG_RSP))
    }

def run(executable,reports):
    pe=PE(executable)
    if hashlib.sha256(pe.b).hexdigest()!=SHA:
        raise RuntimeError("Original executable SHA mismatch")
    layout,_,_=inspect_original(pe)
    cases=[
        ("empty_command",layout["taken_va"]-BASE,0),
        ("nonempty_command",layout["fallthrough_va"]-BASE,ord("M")),
        ("after_empty_callee_return",AFTER_CALL,0)
    ]
    iat_symbols={rva:{"dll":dll,"name":name}
                 for rva,dll,name in import_slots(pe)}
    md=Cs(CS_ARCH_X86,CS_MODE_64);md.detail=True
    mapped=[]
    for label,start,input_byte in cases:
        block=decode_successor(pe,start)
        result=execute_frontier(pe,layout,start,block,block["first_control_pc"],input_byte)
        if not result["next_control_reached"] or not result["successor_entry_seen"]:
            raise RuntimeError("Original x64 successor execution not proven: "+
                               label+": "+repr(result))
        block.pop("prefix_address_set")
        block.pop("first_control_pc")
        control_rva=int(block["first_control_rva"],16)
        stop=list(md.disasm(pe.read_rva(control_rva,8),control_rva))[0]
        if (stop.mnemonic=="call" and len(stop.operands)==1 and
            stop.operands[0].type==X86_OP_MEM and
            stop.reg_name(stop.operands[0].mem.base)=="rip" and
            not stop.operands[0].mem.index):
            slot=stop.address+stop.size+stop.operands[0].mem.disp
            block["import_iat_slot_rva"]=hex(slot)
            block["import_identity"]=iat_symbols.get(slot)
        mapped.append({"path":label,**block,"original_execution":result,
                       "native_arm64_successor_executed":False})
    stats={
        "original_executable_sha_verified":True,
        "base_callee_rva":hex(CALLEE),
        "original_two_je_successors_executed_up_to_next_control":2,
        "post_empty_callee_return_main_prefix_executed":1,
        "successors":mapped,
        "full_game_callee_executed":False,
        "native_successors_translated":0,
        "engine_booted":False,
        "limitations":"x64 successor straight-line prefix only; stops BEFORE next original control transfer."
    }
    reports.mkdir(parents=True,exist_ok=True)
    (reports/"game-callee-successors.json").write_text(json.dumps(stats,indent=2)+"\n")
    lines=["# MX Bikes real game-callee branch successors and return-to-main frontier",""]
    for item in mapped:
        lines.extend([
            "## "+item["path"],
            "- RVA: **"+item["entry_rva"]+"**",
            "- Original x64 successor instructions before next control: **"+str(item["prefix_instruction_count"])+"**",
            "- Next control: **"+item["first_control_rva"]+" "+item["first_control_kind"]+" "+item["first_control_operands"]+"**",
            "- Executed from real main through original CALL and JE: **YES**",
            "- Windows import: **"+str(item.get("import_identity") or "not at this boundary")+"**",
            "",
            "### Original successor prefix"
        ])
        lines.extend("- "+x["rva"]+": "+x["mnemonic"]+" "+x["operands"]
                     for x in item["prefix_instruction_forms"])
        lines.append("")
    lines.extend(["**Original x64 successor and post-return prefixes only; none of these new instructions are translated to native ARM64 yet.**",""])
    summary="\n".join(lines)
    (reports/"game-callee-successors.md").write_text(summary)
    print(summary)
    return stats

if __name__=="__main__":
    if len(sys.argv)!=3:
        raise SystemExit("usage: successor.py original-game.exe outdir")
    run(Path(sys.argv[1]),Path(sys.argv[2]))
