#!/usr/bin/env python3
"""SHA-pinned, immutable RIP-relative original PE data reads for ARM64 CFGs."""
from capstone.x86 import X86_OP_MEM,X86_OP_IMM
import mxbikes_cfg_extended_regs as xreg

MAX_STATIC_REFERENCES=12

def static_operand(ins,part):
    if part.type!=X86_OP_MEM or part.size not in (4,8):return None
    m=part.mem
    if ins.reg_name(m.base)!="rip" or m.index or m.segment:return None
    absolute=ins.address+ins.size+m.disp
    if not 0<=absolute<=0xffffffffffffffff:return None
    return absolute,part.size

def references(ins):
    if len(ins.operands)!=2 or ins.mnemonic not in ("mov","cmp"):return []
    a,b=ins.operands
    item=static_operand(ins,b if ins.mnemonic=="mov" else a)
    if ins.mnemonic=="mov" and a.type==X86_OP_MEM:return []
    return [item] if item else []

def emit(ins):
    if len(ins.operands)!=2 or ins.mnemonic not in ("mov","cmp"):return None
    a,b=ins.operands
    if ins.mnemonic=="mov":
        site=static_operand(ins,b)
        dst=xreg.native_reg(ins,a)
        if not site or not dst or dst[1]!=site[1]:return None
        addr,width=site
        cast="(uint32_t)" if width==4 else ""
        return ("{uint64_t v=0U;"
                f"if(!mx_cfg_transfer(&mem,UINT64_C({addr}),&v,{width}U,0))return 11;"
                f"s.{dst[0]}={cast}v;}}")
    site=static_operand(ins,a)
    if not site:return None
    addr,width=site
    src=xreg.native_reg(ins,b)
    if src and src[1]==width:
        rhs=f"(s.{src[0]}&UINT64_C({(1<<(width*8))-1}))"
    elif b.type==X86_OP_IMM:
        rhs=f"UINT64_C({b.imm&((1<<(width*8))-1)})"
    else:return None
    mask=(1<<(width*8))-1
    sign=1<<(width*8-1)
    return ("{uint64_t a=0U;"
            f"if(!mx_cfg_transfer(&mem,UINT64_C({addr}),&a,{width}U,0))return 11;"
            f"a&=UINT64_C({mask});uint64_t b={rhs};"
            f"uint64_t v=(a-b)&UINT64_C({mask});"
            f"s.cf=(a<b);s.zf=(v==0U);s.sf=(v>>{width*8-1}U)&1U;"
            f"s.of=(((a^b)&(a^v)&UINT64_C({sign}))!=0U);"
            "uint64_t p=v&UINT64_C(255);"
            "p^=p>>4U;p^=p>>2U;p^=p>>1U;"
            "s.pf=(p&1U)==0U;}")
