#!/usr/bin/env python3
"""Full CF/ZF/SF/OF/PF x64 register arithmetic / TEST flags for native CFG.

Supports only 32/64-bit GPR forms, immediate operands and Win64 stack pointer
arithmetic. All unsupported instructions fail closed. Uses unsigned arithmetic
throughout; signed overflow and even low-byte parity match x86.
"""
from capstone.x86 import X86_OP_REG,X86_OP_IMM
import mxbikes_native_prefix_wave as prefix
import mxbikes_cfg_extended_regs as extended

KINDS={"add","sub","cmp","and","or","xor","inc","dec","test"}
FIELDS={"cf","zf","sf","of","pf"}

def expr_reg(ins,op):
    if op.type!=X86_OP_REG:return None
    info=extended.native_reg(ins,op)
    if info:return info
    return None

def parity_snippet():
    # Popcount on low byte by xor-fold, then parity bit: even parity = ~bit.
    return ("uint64_t parity=val&UINT64_C(255);"
            "parity^=parity>>4U;parity^=parity>>2U;parity^=parity>>1U;"
            "s.pf=(parity&1U)==0U;")

def translate(ins):
    name=ins.mnemonic
    ops=ins.operands
    if name not in KINDS or len(ops) not in (1,2):return None
    dst=expr_reg(ins,ops[0])
    if not dst:return None
    field,width=dst
    if width not in (4,8):return None
    mask=(1<<(8*width))-1
    top=8*width-1
    sign=1<<top
    maskc=f"UINT64_C({mask})"
    if name in ("inc","dec"):
        if len(ops)!=1 or field=="rsp":return None
        expression="a+UINT64_C(1)" if name=="inc" else "a-UINT64_C(1)"
        # INC and DEC preserve incoming x86 carry flag
        of=f"(a==UINT64_C({sign-1}))" if name=="inc" else f"(a==UINT64_C({sign}))"
        return ("{uint64_t a=s."+field+"&"+maskc+";"
                "uint64_t val=("+expression+")&"+maskc+";"
                f"s.{field}=val;s.zf=(val==0U);s.sf=(val>>{top}U)&1U;"
                f"s.of={of};"+parity_snippet()+"}")
    if len(ops)!=2:return None
    arg=ops[1]
    if arg.type==X86_OP_REG:
        src=expr_reg(ins,arg)
        if not src or src[1]!=width:return None
        rhs=f"(s.{src[0]}&{maskc})"
    elif arg.type==X86_OP_IMM and name not in ("test",):
        rhs=f"UINT64_C({arg.imm&mask})"
    elif arg.type==X86_OP_IMM and name=="test":
        rhs=f"UINT64_C({arg.imm&mask})"
    else:
        return None
    if name in ("add","sub") and field=="rsp" and arg.type!=X86_OP_IMM:
        return None
    if field=="rsp" and name not in ("add","sub"):
        return None
    if name in ("add","sub") and field=="rsp":
        if not 0<=arg.imm<=65536:return None
    a=f"(s.{field}&{maskc})"
    expr={
        "add":"a+b","sub":"a-b","cmp":"a-b","and":"a&b",
        "or":"a|b","xor":"a^b","test":"a&b"
    }[name]
    cf=("(val<a)" if name=="add" else "(a<b)" if name in ("sub","cmp") else "0U")
    of=(f"(((~(a^b))&(a^val)&UINT64_C({sign}))!=0U)" if name=="add"
         else f"((((a^b)&(a^val))&UINT64_C({sign}))!=0U)" if name in ("sub","cmp")
         else "0U")
    write="" if name in ("test","cmp") else f"s.{field}=val;"
    return ("{uint64_t a="+a+";uint64_t b="+rhs+";"
            "uint64_t val=("+expr+")&"+maskc+";"
            +write+f"s.cf={cf};s.zf=(val==0U);s.sf=(val>>{top}U)&1U;"
            f"s.of={of};"+parity_snippet()+"}")

def predicates():
    return {
        "je":"s.zf","jz":"s.zf","jne":"!s.zf","jnz":"!s.zf",
        "jb":"s.cf","jc":"s.cf","jnae":"s.cf",
        "jae":"!s.cf","jnb":"!s.cf","jnc":"!s.cf",
        "jbe":"(s.cf||s.zf)","jna":"(s.cf||s.zf)",
        "ja":"(!s.cf&&!s.zf)","jnbe":"(!s.cf&&!s.zf)",
        "js":"s.sf","jns":"!s.sf",
        "jl":"(s.sf!=s.of)","jnge":"(s.sf!=s.of)",
        "jge":"(s.sf==s.of)","jnl":"(s.sf==s.of)",
        "jle":"(s.zf||(s.sf!=s.of))","jng":"(s.zf||(s.sf!=s.of))",
        "jg":"(!s.zf&&(s.sf==s.of))","jnle":"(!s.zf&&(s.sf==s.of))",
        "jp":"s.pf","jpe":"s.pf","jnp":"!s.pf","jpo":"!s.pf",
    }
