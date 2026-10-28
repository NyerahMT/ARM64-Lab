#!/usr/bin/env python3
"""Native x64 R12..R15 Win64 preserved GPR + stack-frame translation.

Extends existing original x64 subset for saved registers (R12-R15), 32-bit
register forms, MOV/LEA/PUSH/POP, MOVSXD and architectural multi-byte NOP.
Original guest stack reads/writes require cfg memory guards; nonstack / SIMD
memory access and untracked widths are explicitly not translated.
"""
from capstone.x86 import X86_OP_REG, X86_OP_MEM, X86_OP_IMM
import mxbikes_native_prefix_wave as prefix

EXT={"r12","r13","r14","r15"}
EXT32={n+"d":n for n in EXT}
MORE=EXT|set(EXT32)
GP={*prefix.C_REGS,*EXT}
MASK=prefix.MASK

def native_reg(ins,op):
    if op.type!=X86_OP_REG:return None
    n=ins.reg_name(op.reg)
    if n in EXT:return n,8
    if n in EXT32:return EXT32[n],4
    return prefix.reg(ins,op)

def emit(ins):
    operands=ins.operands
    name=ins.mnemonic
    if name=="nop": # Includes multibyte NOP [reg] alignment, never reads memory.
        return "(void)0;"
    if name in ("push","pop") and len(operands)==1:
        r=native_reg(ins,operands[0])
        if r and r[0] in EXT and r[1]==8:
            if name=="push":
                return (f"if(s.rsp<8U)return 10;s.rsp-=8U;"
                        f"{{uint64_t v=s.{r[0]};"
                        "if(!mx_cfg_transfer(&mem,s.rsp,&v,8U,1))return 11;}")
            return (f"{{uint64_t v=0U;"
                    "if(!mx_cfg_transfer(&mem,s.rsp,&v,8U,0))return 11;"
                    f"s.{r[0]}=v;s.rsp+=8U;}}")
    if name in ("mov","movsxd","lea") and len(operands)==2:
        a,b=operands
        dst=native_reg(ins,a)
        src=native_reg(ins,b)
        # Flag-preserving x64 sign extension of r/m32 to r64.
        if name=="movsxd" and dst and src and dst[1]==8 and src[1]==4:
            return (f"s.{dst[0]}=(uint64_t)(int64_t)(int32_t)"
                    f"(uint32_t)s.{src[0]};")
        if name=="mov" and (dst and dst[0] in EXT or src and src[0] in EXT):
            if dst and src and dst[1]==src[1]:
                cast="(uint32_t)" if dst[1]==4 else ""
                return f"s.{dst[0]}={cast}s.{src[0]};"
            if dst and b.type==X86_OP_IMM:
                val=b.imm&((1<<(dst[1]*8))-1)
                return f"s.{dst[0]}=UINT64_C({val});"
            read=prefix.guest_stack_mem(ins,b)
            write=prefix.guest_stack_mem(ins,a)
            if dst and read and dst[1]==read["size"]:
                return (
                    f"{{uint64_t val=0U;if(!mx_cfg_transfer(&mem,"
                    f"s.{read['base']}+UINT64_C({read['disp']&MASK}),"
                    f"&val,{read['size']}U,0))return 11;"
                    f"s.{dst[0]}={'(uint32_t)' if dst[1]==4 else ''}val;}}"
                )
            if write and src and src[1]==write["size"]:
                return (
                    f"{{uint64_t val=s.{src[0]};"
                    "if(!mx_cfg_transfer(&mem,"
                    f"s.{write['base']}+UINT64_C({write['disp']&MASK}),"
                    f"&val,{write['size']}U,1))return 11;}}"
                )
        if name=="lea" and dst and dst[1]==8 and (
            dst[0] in EXT or b.type==X86_OP_MEM and
            ins.reg_name(b.mem.base) in EXT
        ) and b.type==X86_OP_MEM:
            mem=b.mem
            if not mem.index and not mem.segment:
                source=ins.reg_name(mem.base)
                if source in GP|{"rsp","rbp","rip"}:
                    expr=(f"UINT64_C({ins.address+ins.size})" if source=="rip"
                          else f"s.{source}")
                    return f"s.{dst[0]}={expr}+UINT64_C({mem.disp&MASK});"
    if name in ("xor","test") and len(operands)==2:
        dst=native_reg(ins,operands[0])
        src=native_reg(ins,operands[1])
        if (dst and src and dst[1]==src[1] and
            (dst[0] in EXT or src[0] in EXT)):
            width=dst[1]*8
            mask=0xffffffff if width==32 else MASK
            if name=="xor":
                expr=f"(s.{dst[0]}^s.{src[0]})&UINT64_C({mask})"
            else:
                expr=f"(s.{dst[0]}&s.{src[0]})&UINT64_C({mask})"
            assign=(f"s.{dst[0]}=v;" if name=="xor" else "")
            return (
                f"{{uint64_t v={expr};{assign}"
                f"s.cf=0U;s.of=0U;s.zf=(v==0U);"
                f"s.sf=(v>>{width-1}U)&1U;"
                "uint64_t p=v&UINT64_C(255);"
                "p^=p>>4U;p^=p>>2U;p^=p>>1U;"
                "s.pf=(p&1U)==0U;}"
            )
    return None
