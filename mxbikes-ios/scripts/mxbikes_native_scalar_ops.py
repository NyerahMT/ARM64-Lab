#!/usr/bin/env python3
"""Exact subset of scalar x86-64 register arithmetic for generated C/AArch64.

Implements the destination and x86 CF/ZF/SF effects of 32/64-bit register-only
ADD/SUB/CMP/AND/OR/XOR/INC/DEC for bounded complete original function
translation. No implicit import, guest-pointer, parity/overflow-sensitive
branch or unsupported x64 semantics is claimed. Unknown shapes return None.
"""
from __future__ import annotations
from capstone.x86 import X86_OP_REG, X86_OP_IMM
import mxbikes_native_prefix_wave as base

BINARY={"add","sub","cmp","and","or","xor"}
UNARY={"inc","dec"}

def translate(ins):
    operands=ins.operands
    op=ins.mnemonic
    if op not in BINARY|UNARY:
        return None
    if not operands or operands[0].type!=X86_OP_REG:
        return None
    dst=base.reg(ins,operands[0])
    if dst is None or dst[0]=="rsp" or dst[1] not in (4,8):
        return None
    field,bits=dst
    mask=0xffffffff if bits==4 else 0xffffffffffffffff
    mask_c=f"UINT64_C({mask})"
    sign=31 if bits==4 else 63
    if op in UNARY:
        if len(operands)!=1:
            return None
        delta=1
        expr="a+delta" if op=="inc" else "a-delta"
        # INC/DEC explicitly preserve original CF, unlike ADD/SUB.
        return (
            f"{{uint64_t a=s.{field}&{mask_c};uint64_t delta={delta}U;"
            f"uint64_t val=({expr})&{mask_c};"
            f"s.{field}=val;s.zf=(val==0U);s.sf=(val>>{sign}U)&1U;}}"
        )
    if len(operands)!=2:
        return None
    operand=operands[1]
    if operand.type==X86_OP_REG:
        src=base.reg(ins,operand)
        if not src or src[1]!=bits or src[0]=="rsp":
            return None
        rhs=f"(s.{src[0]}&{mask_c})"
    elif operand.type==X86_OP_IMM:
        rhs=f"UINT64_C({operand.imm&mask})"
    else:
        return None
    a=f"(s.{field}&{mask_c})"
    if op=="add":
        expression="a+b"
        cf="(val<a)"
    elif op in ("sub","cmp"):
        expression="a-b"
        cf="(a<b)"
    elif op=="and":
        expression="a&b"
        cf="0U"
    elif op=="or":
        expression="a|b"
        cf="0U"
    else:
        expression="a^b"
        cf="0U"
    store="" if op=="cmp" else f"s.{field}=val;"
    return (
        f"{{uint64_t a={a};uint64_t b={rhs};"
        f"uint64_t val=({expression})&{mask_c};"
        f"{store}s.cf={cf};s.zf=(val==0U);"
        f"s.sf=(val>>{sign}U)&1U;}}"
    )
