#!/usr/bin/env python3
"""Fail-closed full-CFG x64 guest stack MOV operands with expanded bounded fixture.

A syntactically supported displacement is never sufficient: recover_cfg must
also prove its effective address falls entirely inside the fully compared
guest stack window for all reachable control-flow paths.
"""
from capstone.x86 import X86_OP_MEM
import mxbikes_cfg_extended_regs as regs
import mxbikes_native_prefix_wave as prefix

MAX_DISP=16384

def stack_address(ins,op):
    if op.type!=X86_OP_MEM or op.size not in (4,8):return None
    mem=op.mem
    if mem.index or mem.segment or abs(mem.disp)>MAX_DISP:return None
    base=ins.reg_name(mem.base)
    if base not in ("rsp","rbp"):return None
    return base,mem.disp,op.size

def emit(ins):
    if ins.mnemonic!="mov" or len(ins.operands)!=2:return None
    dst,src=ins.operands
    r_dst=regs.native_reg(ins,dst)
    r_src=regs.native_reg(ins,src)
    read=stack_address(ins,src)
    write=stack_address(ins,dst)
    if read and r_dst and read[2]==r_dst[1]:
        base,disp,n=read
        cast="(uint32_t)" if n==4 else ""
        return ("{uint64_t v=0U;"
                f"if(!mx_cfg_transfer(&mem,s.{base}+UINT64_C({disp&prefix.MASK}),"
                f"&v,{n}U,0))return 11;"
                f"s.{r_dst[0]}={cast}v;}}")
    if write and r_src and write[2]==r_src[1]:
        base,disp,n=write
        return (f"{{uint64_t v=s.{r_src[0]};"
                f"if(!mx_cfg_transfer(&mem,s.{base}+UINT64_C({disp&prefix.MASK}),"
                f"&v,{n}U,1))return 11;}}")
    return None
