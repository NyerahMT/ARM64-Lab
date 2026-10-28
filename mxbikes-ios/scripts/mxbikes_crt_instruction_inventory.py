#!/usr/bin/env python3
"""Private instruction-form inventory for first CRT initializer.

Prints original disassembly only inside private GitHub Actions logs.
It never uploads code bytes, IR, objects or source-derived artifacts.
"""
import hashlib
import sys
from pathlib import Path
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"arm64-lab"))
from tools.pe_probe import PE

SOURCE_SHA="4ae7de3854b4d0a18271679fb57a1f2fdf0b21804417b85dd82055078ea123b6"

def run(executable):
    pe=PE(executable)
    if hashlib.sha256(pe.b).hexdigest()!=SOURCE_SHA:
        raise ValueError("Unexpected original input")
    rva,size=0x2ab954,179
    md=Cs(CS_ARCH_X86,CS_MODE_64);md.detail=True
    inst=list(md.disasm(pe.read_rva(rva,size),rva))
    if len(inst)!=39 or sum(i.size for i in inst)!=size:
        raise RuntimeError("Original startup initializer changed")
    for i in inst:
        op_types=["reg" if op.type==1 else "imm" if op.type==2 else "mem" if op.type==3 else "other" for op in i.operands]
        print(f"{i.address:#010x} {i.mnemonic:<8} {i.op_str:<50} [{','.join(op_types)}]")
    print(f"Decoded {len(inst)} original x64 instructions in {size} bytes; no ARM64 executed")

if __name__=="__main__":
    if len(sys.argv)!=2:raise SystemExit("usage: script.py /private/mxbikes.exe")
    run(sys.argv[1])
