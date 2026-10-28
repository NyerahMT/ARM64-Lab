#!/usr/bin/env python3
"""Flag-preserving x64 CMOVcc register-register instruction family.

Only known 32/64-bit GPR pairs and verified x86 flag predicates; no
speculative memory-source reads. Reject frame/stack pointer destinations
whose mutations cannot be statically tracked by CFG stack dataflow.
"""
import mxbikes_cfg_flag_ops as flags
import mxbikes_cfg_extended_regs as regs

def emit(ins):
    if not ins.mnemonic.startswith("cmov") or len(ins.operands)!=2:return None
    suffix=ins.mnemonic[4:]
    predicate=flags.predicates().get("j"+suffix)
    if predicate is None:return None
    dst=regs.native_reg(ins,ins.operands[0])
    src=regs.native_reg(ins,ins.operands[1])
    if not dst or not src or dst[1]!=src[1]:return None
    if dst[0] in ("rsp","rbp"):return None
    if dst[1]==4:
        # Win64 writes to r32 clear bits 63..32 even when CMOV condition fails.
        # The original low 32 bits remain unchanged in the false case.
        return (f"if({predicate})s.{dst[0]}=(uint32_t)s.{src[0]};"
                f"else s.{dst[0]}=(uint32_t)s.{dst[0]};")
    return f"if({predicate})s.{dst[0]}=s.{src[0]};"
