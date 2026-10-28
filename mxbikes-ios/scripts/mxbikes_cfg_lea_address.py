#!/usr/bin/env python3
"""Exact Win64 LEA pure-address arithmetic for native AArch64 CFGs.

LEA does not read guest memory. 32-bit destination writes zero-extend and
64-bit destination writes wrap modulo 2**64. Refuse stack/frame-pointer writes
(the static stack analyzer must observe those separately), address-size
overrides, non-canonical operands and untracked base/index registers.
"""
from capstone.x86 import X86_OP_MEM
import mxbikes_cfg_extended_regs as regs
import mxbikes_native_prefix_wave as prefix

VALID_BASE=regs.GP | {"rsp","rbp","rip"}
MASK=prefix.MASK

def emit(ins):
    if ins.mnemonic!="lea" or len(ins.operands)!=2:return None
    dst,src=ins.operands
    if src.type!=X86_OP_MEM or src.mem.segment:return None
    reg=regs.native_reg(ins,dst)
    if not reg or reg[0] in ("rsp","rbp"):return None
    # Instruction address-size override changes offset arithmetic semantics.
    if hasattr(ins,"prefix") and 0x67 in ins.prefix:return None
    m=src.mem
    if m.index:return None
    base=ins.reg_name(m.base)
    if base not in VALID_BASE:return None
    if m.disp < -(1<<31) or m.disp >= 1<<31:return None
    base_c=(f"UINT64_C({ins.address+ins.size})" if base=="rip"
            else f"s.{base}")
    value=f"({base_c}+UINT64_C({m.disp&MASK}))"
    if reg[1]==4:value=f"(uint32_t){value}"
    elif reg[1]!=8:return None
    return f"s.{reg[0]}={value};"
