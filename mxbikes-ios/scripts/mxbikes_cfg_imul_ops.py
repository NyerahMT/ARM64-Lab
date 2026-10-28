#!/usr/bin/env python3
"""Signed x64 IMUL reg-reg and reg-reg-imm semantics for bounded ARM64 CFGs.

Only explicit GPR 32/64-bit destinations and register/known immediate sources
are admitted. Truncation and defined CF/OF overflow behavior are exact; x86
SF/ZF/PF are architecturally undefined for IMUL; preserve observed
Unicorn reference behavior for PF/SF/ZF in bounded fixtures.
Differential verification compares every observed fixture value
and rejects nonmatching originals rather than promoting guessed semantics.
"""
from capstone.x86 import X86_OP_IMM
import mxbikes_cfg_extended_regs as regs

def emit(ins):
    if ins.mnemonic!="imul" or len(ins.operands) not in (2,3):
        return None
    ops=ins.operands
    dst=regs.native_reg(ins,ops[0])
    if not dst or dst[0] in ("rsp","rbp") or dst[1] not in (4,8):
        return None
    mask=(1<<(8*dst[1]))-1
    sign_left="(int64_t)" if dst[1]==8 else "(int32_t)(uint32_t)"
    sign_out="(__int128)(int64_t)" if dst[1]==8 else "(__int128)(int32_t)(uint32_t)"
    if len(ops)==3:
        src=regs.native_reg(ins,ops[1])
        if not src or src[1]!=dst[1] or ops[2].type!=X86_OP_IMM:
            return None
        b=f"UINT64_C({ops[2].imm&mask})"
        a=f"s.{src[0]}"
    else:
        src=regs.native_reg(ins,ops[1])
        if not src or src[1]!=dst[1]:
            return None
        a=f"s.{dst[0]}"
        b=f"s.{src[0]}"
    return (
        "{"
        f"int64_t a={sign_left}({a});"
        f"int64_t b={sign_left}({b});"
        "__int128 product=(__int128)a*(__int128)b;"
        f"uint64_t lo=(uint64_t)product&UINT64_C({mask});"
        f"s.{dst[0]}=lo;"
        f"s.cf=s.of=(product!={sign_out}lo);"
        # Keep deterministic Unicorn fixture behavior for undefined IMUL
        # status bits; all flags are still cross-compared against original x64.
        f"s.zf=(lo==0U);s.sf=(lo>>{8*dst[1]-1}U)&1U;"
        "uint64_t parity=lo&UINT64_C(255);"
        "parity^=parity>>4U;parity^=parity>>2U;parity^=parity>>1U;"
        "s.pf=(parity&1U)==0U;"
        "}"
    )
