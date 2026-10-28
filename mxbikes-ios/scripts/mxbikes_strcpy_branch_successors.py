#!/usr/bin/env python3
"""Bounded static original x64 successor discovery after verified MOVSX/TEST/JE.

Owned PE must match its SHA. No bytecode, machine code or copyrighted
binary data leaves the private job. Successor blocks are discovered,
not claimed to execute natively or dynamically.
"""
from pathlib import Path
import hashlib,json,sys
from capstone import Cs,CS_ARCH_X86,CS_MODE_64,CS_GRP_CALL,CS_GRP_JUMP,CS_GRP_RET
from capstone.x86 import X86_OP_IMM,X86_OP_MEM
from mxbikes_joined_strcpy_native import EXE_SHA
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"arm64-lab"))
from tools.pe_probe import PE
SOURCES={"normal_nonzero_fallthrough":0x15b7db,"zero_byte_taken":0x15b801}
MAX_BYTES=224
MAX_INS=36

def inspect(pe,decoder,addr):
    decoded=[];end=None
    for inst in decoder.disasm(pe.read_rva(addr,MAX_BYTES),addr):
        if (inst.group(CS_GRP_CALL) or inst.group(CS_GRP_RET) or
            inst.group(CS_GRP_JUMP)):
            end=inst;break
        decoded.append(inst)
        if len(decoded)>=MAX_INS:
            raise RuntimeError(f"Original successor at {addr:#x} exceeds instruction bound")
    if not end:raise RuntimeError(f"No control found after {addr:#x}")
    out={"entry_rva":hex(addr),"straightline_instructions":len(decoded),
         "first_control_rva":hex(end.address),
         "first_control_mnemonic":end.mnemonic,
         "first_control_operands":end.op_str,
         "forms":[{"rva":hex(inst.address),"mnemonic":inst.mnemonic,
                   "operands":inst.op_str} for inst in decoded]}
    if end.operands:
        op=end.operands[0]
        if op.type==X86_OP_IMM:
            out["direct_destination_rva"]=hex(int(op.imm))
        elif op.type==X86_OP_MEM and end.reg_name(op.mem.base)=="rip":
            out["indirect_pointer_rva"]=hex(end.address+end.size+op.mem.disp)
    return out

def run(original,out):
    pe=PE(original)
    if hashlib.sha256(pe.b).hexdigest()!=EXE_SHA:
        raise RuntimeError("Original owned game SHA mismatch")
    md=Cs(CS_ARCH_X86,CS_MODE_64);md.detail=True
    branch=list(md.disasm(pe.read_rva(0x15b7d9,2),0x15b7d9))
    if len(branch)!=1 or branch[0].mnemonic!="je" or branch[0].op_str!="0x15b801":
        raise RuntimeError("Original branch identities changed")
    results={name:inspect(pe,md,addr) for name,addr in SOURCES.items()}
    data={"original_sha_verified":True,"successors":results,
          "native_successors_executed":0,
          "dynamic_original_successors_executed":0,
          "limitations":"Static bounded decode only. No original path traversal or native AArch64 successor in this step."}
    out.mkdir(parents=True,exist_ok=True)
    (out/"strcpy-jcc-successors.json").write_text(json.dumps(data,indent=2)+"\n")
    lines=["# MX Bikes two original filename JE successors",""]
    for title,block in results.items():
        lines+=["## "+title.replace("_"," ").title(),
                "- Entry: **"+block["entry_rva"]+"**",
                "- Original straight-line instructions before control: **"+
                  str(block["straightline_instructions"])+"**",
                "- Next control: **"+block["first_control_rva"]+" "+
                   block["first_control_mnemonic"]+" "+block["first_control_operands"]+"**",""]
        lines+=["- "+f["rva"]+" "+f["mnemonic"]+" "+f["operands"]
                for f in block["forms"]]
        lines.append("")
    lines+=["**Discovery only; no native code execution in these successor blocks.**",""]
    summary="\n".join(lines)
    (out/"strcpy-jcc-successors.md").write_text(summary)
    print(summary)
    return data

if __name__=="__main__":
    if len(sys.argv)!=3:raise SystemExit("usage: successors.py original-exe output-dir")
    run(Path(sys.argv[1]),Path(sys.argv[2]))
