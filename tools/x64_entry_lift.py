#!/usr/bin/env python3
"""Restricted Win64 entry-wrapper control-effect lift into portable C.

This does NOT lift or execute either original callee. It models original
stack adjustments, the call/return pairing through a synthetic callee, and
the final tail transfer. The input executable and generated C stay private.
"""
from __future__ import annotations

from .entry_wrapper import decode_entry_wrapper


def lift_entry_to_c(blob: bytes, entry_rva: int) -> str:
    meta = decode_entry_wrapper(blob, entry_rva)
    call_rva = int(meta["direct_call_rva"], 16)
    tail_rva = int(meta["tail_jmp_rva"], 16)
    adjustment = meta["stack_adjustment_bytes"]
    return (
        "/* Models Win64 entry wrapper control effects, not callee bodies. */\n"
        "typedef unsigned long long guest_u64;\n"
        "typedef struct {\n"
        "    guest_u64 guest_rsp;\n"
        "    guest_u64 callee_entry_rsp;\n"
        "    guest_u64 call_target_rva;\n"
        "    guest_u64 tail_target_rva;\n"
        "    guest_u64 call_count;\n"
        "    guest_u64 tail_count;\n"
        "} guest_entry_state;\n"
        "void lifted_entry(guest_entry_state *s) {\n"
        f"    s->guest_rsp -= {adjustment}ULL;\n"
        "    /* A Win64 CALL pushes an 8-byte return address. */\n"
        "    s->guest_rsp -= 8ULL;\n"
        "    s->callee_entry_rsp = s->guest_rsp;\n"
        f"    s->call_target_rva = 0x{call_rva:x}ULL;\n"
        "    s->call_count += 1ULL;\n"
        "    /* Injected synthetic callee RET pops that return address. */\n"
        "    s->guest_rsp += 8ULL;\n"
        f"    s->guest_rsp += {adjustment}ULL;\n"
        f"    s->tail_target_rva = 0x{tail_rva:x}ULL;\n"
        "    s->tail_count += 1ULL;\n"
        "}\n"
    )
