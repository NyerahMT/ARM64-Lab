#!/usr/bin/env python3
"""Private-only original CRT instruction form and first CFG frontier.

For engineer review in PRIVATE GitHub Actions logs; no machine-code bytes,
derived C, IR or AArch64 objects are committed or uploaded.
"""
from pathlib import Path
import hashlib, sys
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
from capstone.x86 import X86_OP_IMM,X86_OP_REG,X86_OP_MEM
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"arm64-lab"))
from tools.pe_probe import PE

SHA="4ae7de3854b4d0a18271679fb57a1f2fdf0b21804417b85dd82055078ea123b6"
START=0x2ab02c
SIZE=518

def run(path):
    pe=PE(path)
    if hashlib.sha256(pe.b).hexdigest()!=SHA:
        raise RuntimeError("Unexpected original private game executable")
    md=Cs(CS_ARCH_X86,CS_MODE_64)
    md.detail=True
    ins=list(md.disasm(pe.read_rva(START,SIZE),START))
    if len(ins)!=126 or sum(i.size for i in ins)!=SIZE:
        raise RuntimeError("Pinned next original CRT region changed")
    direct={i.address for i in ins}
    for idx,i in enumerate(ins):
        if idx>=126:break
        op_types=[]
        for op in i.operands:
            typ={X86_OP_IMM:"imm",X86_OP_REG:"reg",X86_OP_MEM:"mem"}.get(op.type,"other")
            if op.type==X86_OP_MEM:
                typ+=f"/{i.reg_name(op.mem.segment) or '-'}:{i.reg_name(op.mem.base) or '-'}+{op.mem.disp:#x}"
            op_types.append(typ)
        next_pc=i.address+i.size
        edge=""
        if i.mnemonic.startswith("j") and i.operands and i.operands[0].type==X86_OP_IMM:
            dest=int(i.operands[0].imm)
            edge=f" target={dest:#x} {'IN' if dest in direct else 'OUT'}"
        print(f"{idx:03d} {i.address:#010x} {i.mnemonic:14s} {i.op_str:57s} [{','.join(op_types)}]{edge}")
    print(f"Verified {len(ins)} original x64 instructions; original code not translated or run")

if __name__=="__main__":
    if len(sys.argv)!=2:raise SystemExit("usage: script.py /private/original.exe")
    run(Path(sys.argv[1]))
