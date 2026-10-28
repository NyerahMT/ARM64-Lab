#!/usr/bin/env python3
"""Inspect original MX Bikes nested startup callee at RVA 0x2ab41a.

Disassembles original SHA-verified PE in private CI, and attempts authentic
x64 execution from game main via controlled GetModuleFileNameA to first
control in this nested callee. Reports separately static and executed status.
No original game code bytes or lifted output leave the private runner.
"""
from pathlib import Path
import hashlib,json,struct,sys
from capstone import Cs,CS_ARCH_X86,CS_MODE_64,CS_GRP_CALL,CS_GRP_JUMP,CS_GRP_RET
from capstone.x86 import X86_OP_IMM,X86_OP_MEM
from mxbikes_first_callee_emu import import_slots
from mxbikes_main_filename_native import (
 BASE,MAIN,EXE_SHA,AFTER_IMPORT,inspect_original,verify_next_import
)
from mxbikes_post_filename_probe import original_probe
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"arm64-lab"))
from tools.pe_probe import PE

TARGET=0x2ab41a
CALLER=0x15b7a5
LIMIT=192

def inspect(pe):
    md=Cs(CS_ARCH_X86,CS_MODE_64);md.detail=True
    caller=list(md.disasm(pe.read_rva(CALLER,5),CALLER))
    if(len(caller)!=1 or not caller[0].group(CS_GRP_CALL) or
       caller[0].operands[0].type!=X86_OP_IMM or
       caller[0].operands[0].imm!=TARGET):
        raise RuntimeError("Original nested callee CALL identity changed")
    instructions=[]
    control=None
    for ins in md.disasm(pe.read_rva(TARGET,LIMIT),TARGET):
        if(ins.group(CS_GRP_CALL) or ins.group(CS_GRP_JUMP) or
           ins.group(CS_GRP_RET)):
            control=ins;break
        instructions.append(ins)
        if len(instructions)>32:
            raise RuntimeError("Original nested callee first block unbounded")
    if control is None:raise RuntimeError("No transfer in nested first block")
    pdata,size=pe.directory(3)
    metadata=[]
    if pdata and size%12==0:
        metadata=[{"begin_rva":hex(begin),"end_rva":hex(end)}
                  for begin,end,_ in struct.iter_unpack("<III",pe.read_rva(pdata,size))
                  if begin<=TARGET<end]
    iat=None
    if(len(control.operands)==1 and
       control.operands[0].type==X86_OP_MEM and
       control.reg_name(control.operands[0].mem.base)=="rip" and
       not control.operands[0].mem.index):
        slot=control.address+control.size+control.operands[0].mem.disp
        names={int(rv):{"dll":str(dll),"name":str(name)} for rv,dll,name in import_slots(pe)}
        iat={"slot_rva":hex(slot),"resolved_import":names.get(slot)}
    return control,{
        "indirect_import_lookup":iat,
        "nested_original_entry_rva":hex(TARGET),
        "caller_original_call_rva":hex(CALLER),
        "prefix_original_instructions":len(instructions),
        "first_original_control_rva":hex(control.address),
        "first_control_mnemonic":control.mnemonic,
        "first_control_operands":control.op_str,
        "unwind_entry_intervals":metadata,
        "instruction_forms":[{"rva":hex(i.address),"mnemonic":i.mnemonic,"operands":i.op_str}
                             for i in instructions]
    }

def run(executable,out):
    pe=PE(executable)
    if hashlib.sha256(pe.b).hexdigest()!=EXE_SHA:
        raise RuntimeError("Original game file SHA mismatch")
    layout,_,_=inspect_original(pe)
    slot=verify_next_import(pe)
    stop,info=inspect(pe)
    samples=[]
    for case in (0,5,9):
        try:
            result=original_probe(pe,layout,slot,stop,case)
            if result["pc_rva"]!=info["first_original_control_rva"]:
                raise RuntimeError("Original x64 control frontier moved")
            samples.append({"case":case,"reached":True,
                            "original_executed_instructions":result["original_executed_instruction_count"],
                            "final_rva":result["pc_rva"]})
        except Exception as exc:
            samples.append({"case":case,"reached":False,
                            "failure_class":type(exc).__name__,
                            "diagnostic":str(exc)[:160]})
    info["original_x64_dynamic_cases"]=samples
    info["original_first_control_reached_in_x64"]=sum(int(s["reached"]) for s in samples)
    info["native_arm64_callee_executed"]=False
    info["game_engine_initialized"]=False
    out.mkdir(parents=True,exist_ok=True)
    (out/"nested-game-callee-probe.json").write_text(json.dumps(info,indent=2)+"\n")
    lines=[
      "# MX Bikes nested startup callee 0x2ab41a","",
      "- Caller original RVA: **"+hex(CALLER)+"**",
      "- Original nested entry RVA: **"+hex(TARGET)+"**",
      "- Precontrol instruction count: **"+str(info["prefix_original_instructions"])+"**",
      "- Next original transfer: **"+info["first_original_control_rva"]+
        " "+info["first_control_mnemonic"]+" "+info["first_control_operands"]+"**",
      "- Original x64 executions reaching that transfer: **"+
        str(info["original_first_control_reached_in_x64"])+"/3**","",
      "- Original import lookup: **"+str(info.get("indirect_import_lookup"))+"**",
      "## Original first basic block"
    ]
    lines.extend("- "+row["rva"]+": "+row["mnemonic"]+" "+row["operands"]
                 for row in info["instruction_forms"])
    lines+=["","**Static discovery and original x64 dynamic checks only. No native implementation of this new callee is claimed.**",""]
    summary="\n".join(lines)
    (out/"nested-game-callee-probe.md").write_text(summary)
    print(summary)
    return info

if __name__=="__main__":
    if len(sys.argv)!=3:raise SystemExit("usage: nested_probe.py original.exe reports")
    run(Path(sys.argv[1]),Path(sys.argv[2]))
