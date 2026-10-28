#!/usr/bin/env python3
"""Inspect original MX Bikes PE at first jump successor after native strcpy join.

The earlier native differential reaches RVA 0x15b7cf. This tool only
disassembles a bounded original x64 block from that address, classifies the
first transfer, and reports metadata without exporting copyrighted bytes.
"""
from pathlib import Path
import hashlib,json,sys
from capstone import Cs,CS_ARCH_X86,CS_MODE_64,CS_GRP_CALL,CS_GRP_JUMP,CS_GRP_RET
from capstone.x86 import X86_OP_IMM,X86_OP_MEM
from mxbikes_joined_strcpy_native import EXE_SHA,BASE
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"arm64-lab"))
from tools.pe_probe import PE
START=0x15b7cf
MAX_INS=48
SCAN_BYTES=256

def run(exe,dest):
    pe=PE(exe)
    if hashlib.sha256(pe.b).hexdigest()!=EXE_SHA:
        raise RuntimeError("Original game executable revision mismatch")
    decoder=Cs(CS_ARCH_X86,CS_MODE_64);decoder.detail=True
    former=list(decoder.disasm(pe.read_rva(0x15b7bf,2),0x15b7bf))
    if (len(former)!=1 or former[0].mnemonic!="jmp" or
        former[0].op_str!="0x15b7cf"):
        raise RuntimeError("Verified original strcpy return JMP changed")
    forms=[]
    control=None
    for ins in decoder.disasm(pe.read_rva(START,SCAN_BYTES),START):
        if(ins.group(CS_GRP_JUMP) or ins.group(CS_GRP_CALL) or ins.group(CS_GRP_RET)):
            control=ins;break
        forms.append({"rva":hex(ins.address),"mnemonic":ins.mnemonic,
                      "operands":ins.op_str})
        if len(forms)>=MAX_INS:
            raise RuntimeError("Bounded original successor scan exceeded limit")
    if control is None:raise RuntimeError("No next original x64 control within budget")
    d={
      "original_sha_verified":True,"target_rva":hex(START),
      "source_jump_rva":"0x15b7bf",
      "original_instruction_prefix_count":len(forms),
      "first_control_rva":hex(control.address),
      "first_control_mnemonic":control.mnemonic,
      "first_control_operands":control.op_str,
      "instruction_forms":forms,
      "original_branch_target":None,
      "original_import_slot":None,
      "native_successor_executed":False,
      "original_successor_executed":False,
      "engine_initialized":False
    }
    if control.operands and control.operands[0].type==X86_OP_IMM:
        d["original_branch_target"]=hex(int(control.operands[0].imm))
    if (control.operands and control.operands[0].type==X86_OP_MEM and
        control.reg_name(control.operands[0].mem.base)=="rip" and
        not control.operands[0].mem.index):
        d["original_import_slot"]=hex(control.address+control.size+
                                      control.operands[0].mem.disp)
    dest.mkdir(parents=True,exist_ok=True)
    (dest/"post-strcpy-jump-successor.json").write_text(json.dumps(d,indent=2)+"\n")
    lines=[
      "# Original MX Bikes filename helper successor","",
      "- Original jump target: **"+hex(START)+"**",
      "- Instructions before next transfer: **"+str(len(forms))+"**",
      "- Next transfer: **"+hex(control.address)+" "+
         control.mnemonic+" "+control.op_str+"**",
      "- Next transfer's direct target: **"+str(d["original_branch_target"])+"**",
      "","## Original successor instructions"
    ]
    lines+=["- "+f["rva"]+": "+f["mnemonic"]+" "+f["operands"] for f in forms]
    lines+=["","**Static map only. No claim the successor runs natively yet.**",""]
    text="\n".join(lines)
    (dest/"post-strcpy-jump-successor.md").write_text(text)
    print(text)
    return d

if __name__=="__main__":
    if len(sys.argv)!=3:raise SystemExit("usage: script.py original-mxbikes.exe report-dir")
    run(Path(sys.argv[1]),Path(sys.argv[2]))
