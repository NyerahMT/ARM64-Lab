#!/usr/bin/env python3
"""Fail-closed x64 guest-heap MOV/CMP/MOVSXD translator for bounded native CFGs.

Supported operands: integer MOV, both memory CMP operand orders, MOVZX,
and MOVSXD with bounded base-register addressing. No indexed/segment/RIP/stack access, no virtual
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
    if op.type!=X86_OP_MEM or op.size not in (1,2,4,8):return None
    m=op.mem
    if m.index or m.segment or 0x67 in ins.prefix or abs(m.disp)>MAX_DISP:
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
    if len(ins.operands)!=2 or ins.mnemonic not in ("mov","movsxd","movzx","cmp"):
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
    if ins.mnemonic=="movzx" and right and right[2] in (1,2) and r_dst and r_dst[1] in (4,8) and r_dst[0] not in ("rsp","rbp"):
        read=transfer_code(right,False,"v")
        return f"{{uint64_t v=0U;{read}s.{r_dst[0]}=v;}}"
    if ins.mnemonic=="cmp":
        # Accept both operand orders, exact width, and masked immediates.
        # Neither CMP nor memory reads change the compared operands.
        if left and (r_src and r_src[1]==left[2] or src.type==X86_OP_IMM):
            n=left[2]
            mask=(1<<(n*8))-1
            rhs=(f"(s.{r_src[0]}&UINT64_C({mask}))" if r_src else
                 f"UINT64_C({src.imm&mask})")
            setup=f"uint64_t a=0U;{transfer_code(left,False,'a')}uint64_t b={rhs};"
        elif right and r_dst and r_dst[1]==right[2]:
            n=right[2]
            mask=(1<<(n*8))-1
            setup=f"uint64_t a=s.{r_dst[0]}&UINT64_C({mask});uint64_t b=0U;{transfer_code(right,False,'b')}"
        else:
            return None
        sign=1<<(n*8-1)
        return (
            "{"+setup+
            f"a&=UINT64_C({mask});b&=UINT64_C({mask});"
            f"uint64_t v=(a-b)&UINT64_C({mask});"
            f"s.cf=(a<b);s.zf=(v==0U);"
            f"s.sf=(v>>{n*8-1}U)&1U;"
            f"s.of=(((a^b)&(a^v)&UINT64_C({sign}))!=0U);"
            "uint64_t p=v&UINT64_C(255);"
            "p^=p>>4U;p^=p>>2U;p^=p>>1U;"
            "s.pf=(p&1U)==0U;}"
        )
    return None
