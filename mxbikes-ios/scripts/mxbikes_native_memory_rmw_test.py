#!/usr/bin/env python3
"""Synthetic memory arithmetic differential; never reads original game data."""
import struct
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64
from unicorn.x86_const import UC_X86_REG_EFLAGS
from mxbikes_native_cfg_lift import MEMORY_RUNTIME, EXTRA, RUNTIME_SOURCES, decode_cfg, compile_native, u

BASE=0x10000000
DATA=0x10002000
ARITH_FLAGS=0x8d5

def run():
    parts=[MEMORY_RUNTIME,EXTRA]
    cases=[]
    # Test each operation independently so later arithmetic cannot hide INC/DEC flags.
    for width in (32,64):
        size=width//8
        for name,modrm,opcode,imm in (("inc",5,0xff,None),("dec",13,0xff,None),
                                     ("add",5,0x83,1),("sub",45,0x83,0xff)):
            tag=f"{name}{width}"
            prefix=bytes([0x48]) if width==64 else b""
            length=len(prefix)+6+(imm is not None)
            raw=prefix+bytes([opcode,modrm])+struct.pack("<i",DATA-(BASE+length))
            if imm is not None:raw+=bytes([imm])
            stop=BASE+len(raw)
            body,pages,nodes=decode_cfg([(BASE,raw)],BASE,stop)
            if pages!=[DATA] or nodes!={BASE}:raise ValueError("Bad fixture decode")
            parts.append(body.replace("lifted_begin",tag+"_begin").replace("lifted_resume",tag+"_resume"))
            for initial in (0,1,(1<<width)-1,(1<<(width-1))-1,1<<(width-1)):
                for carry in (0,1):
                    flags=0x202|carry
                    uc=Uc(UC_ARCH_X86,UC_MODE_64)
                    uc.mem_map(BASE,4096);uc.mem_write(BASE,raw)
                    uc.mem_map(DATA,4096);uc.mem_write(DATA,initial.to_bytes(size,"little"))
                    uc.reg_write(UC_X86_REG_EFLAGS,flags);uc.emu_start(BASE,stop,count=1)
                    expected=int.from_bytes(uc.mem_read(DATA,size),"little")
                    ef=uc.reg_read(UC_X86_REG_EFLAGS)&ARITH_FLAGS
                    cases.append(f"""{{State s={{0}};uint64_t value={u(initial)};s.flags={u(flags)};
                    if(!mxb_guest_map(&s.memory,{u(DATA)},(uint8_t*)&value,{size},3))return 1;
                    Cursor c={tag}_begin();
                    if({tag}_resume(&s,&c,1)!=0||c.steps!=1||c.pc!={u(stop)}||
                       value!={u(expected)}||(s.flags&{u(ARITH_FLAGS)})!={u(ef)})return 2;
                    }}""")
            # Read-only destination must fail before altering guest data or flags.
            cases.append(f"""{{State s={{0}};uint64_t value=7;s.flags=0x203;
            if(!mxb_guest_map(&s.memory,{u(DATA)},(uint8_t*)&value,{size},1))return 3;
            Cursor c={tag}_begin();
            if({tag}_resume(&s,&c,1)!=MXB_NATIVE_MEMORY_FAULT||!s.fault||value!=7||s.flags!=0x203)return 4;
            }}""")
    parts.extend(["int smoke(void){",*cases,"return 0;}","#ifdef HOST\nint main(void){return smoke();}\n#endif"])
    compile_native("\n".join(parts),RUNTIME_SOURCES)
    print(f"PASS: {len(cases)} synthetic memory arithmetic and permission cases on host and AArch64")

if __name__=="__main__":run()
