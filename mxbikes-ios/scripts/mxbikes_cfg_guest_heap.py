#!/usr/bin/env python3
"""Fail-closed x64 guest-heap MOV/CMP/MOVSXD translator for bounded native CFGs.

Supported operands: ordinary 32/64-bit integer MOV and 32-bit memory CMP IMM,
and MOVSXD reg64,[GPR+disp]. No indexed/segment/RIP/stack access, no virtual
memory host-pointer casts, no ignored side effects. The caller maps a known
synthetic guest heap range in both Unicorn x64 and compiled ARM64 and compares
EVERY heap byte after a complete original x64 return.
"""
from capstone.x86 import X86_OP_IMM,X86_OP_MEM,X86_OP_REG
import mxbikes_cfg_extended_regs as xreg
import mxbikes_native_prefix_wave as prefix

GP=(prefix.C_REGS|xreg.EXT)-{"rsp","rbp","rip"}
MAX_DISP=1024

def guest_access(ins,op):
    if op.type!=X86_OP_MEM or op.size not in (4,8):return None
    m=op.mem
    if m.index or m.segment or abs(m.disp)>MAX_DISP:
        return None
    base=ins.reg_name(m.base)
    if base not in GP:return None
    return base,m.disp,op.size

def memory_bases(ins):
    out=set()
    for arg in ins.operands:
        data=guest_access(ins,arg)
        if data is not None:out.add(data[0])
    return out

def transfer_code(mem,write,value,*,width=None):
    base,displacement,nbytes=mem
    if width is not None and nbytes!=width:return None
    address=f"s.{base}+UINT64_C({displacement&prefix.MASK})"
    return (
        f"if(!mx_cfg_transfer(&mem,{address},&{value},{nbytes}U,{1 if write else 0}))return 11;"
    )

def emit(ins):
    if len(ins.operands)!=2 or ins.mnemonic not in ("mov","movsxd","cmp"):
        return None
    dst,src=ins.operands
    left=guest_access(ins,dst)
    right=guest_access(ins,src)
    r_dst=xreg.native_reg(ins,dst)
    r_src=xreg.native_reg(ins,src)
    if ins.mnemonic=="mov":
        if right and r_dst and right[2]==r_dst[1]:
            read=transfer_code(right,False,"v")
            cast="(uint32_t)" if r_dst[1]==4 else ""
            return f"{{uint64_t v=0U;{read}s.{r_dst[0]}={cast}v;}}"
        if left and r_src and left[2]==r_src[1]:
            write=transfer_code(left,True,"v")
            return f"{{uint64_t v=s.{r_src[0]};{write}}}"
        if left and src.type==X86_OP_IMM:
            n=left[2]
            mask=(1<<(n*8))-1
            write=transfer_code(left,True,"v")
            return f"{{uint64_t v=UINT64_C({src.imm&mask});{write}}}"
    if ins.mnemonic=="movsxd" and right and right[2]==4 and r_dst and r_dst[1]==8:
        read=transfer_code(right,False,"v")
        return (f"{{uint64_t v=0U;{read}"
                f"s.{r_dst[0]}=(uint64_t)(int64_t)(int32_t)(uint32_t)v;}}")
    if ins.mnemonic=="cmp" and left and left[2] in (4,8) and (
        r_src and r_src[1]==left[2] or src.type==X86_OP_IMM
    ):
        n=left[2]
        mask=(1<<(n*8))-1
        sign=1<<(n*8-1)
        b=(f"(s.{r_src[0]}&UINT64_C({mask}))" if r_src else
           f"UINT64_C({src.imm&mask})")
        read=transfer_code(left,False,"a")
        return (
            f"{{uint64_t a=0U;{read}"
            f"a&=UINT64_C({mask});uint64_t b={b};"
            f"uint64_t v=(a-b)&UINT64_C({mask});"
            f"s.cf=(a<b);s.zf=(v==0U);"
            f"s.sf=(v>>{n*8-1}U)&1U;"
            f"s.of=(((a^b)&(a^v)&UINT64_C({sign}))!=0U);"
            "uint64_t p=v&UINT64_C(255);"
            "p^=p>>4U;p^=p>>2U;p^=p>>1U;"
            "s.pf=(p&1U)==0U;}"
        )
    return None
