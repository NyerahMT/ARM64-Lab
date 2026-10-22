"""Strict whole-function x64 scalar return leaves to native guest-state C.

Permitted original instructions:
 - xor eax,eax ; ret       (31 c0 c3 or 33 c0 c3)
 - mov eax,imm32 ; ret     (b8 xx xx xx xx c3)
Exactly one full callable function must already be identified independently.
Never interpret these byte patterns as evidence of a valid function boundary.
"""
from __future__ import annotations
import re


class UnsupportedGuestLeaf(ValueError):
    pass


def lift_guest_leaf_to_c(code: bytes, entry_va: int,
                         function_name: str = "native_guest_leaf") -> str:
    if (not isinstance(code, bytes) or not isinstance(entry_va, int)
            or isinstance(entry_va, bool) or not 0 < entry_va <= (1 << 64) - 1
            or not isinstance(function_name, str)
            or re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]{0,63}", function_name) is None):
        raise UnsupportedGuestLeaf("Invalid source, entry address or C identifier")
    xor = code in (bytes.fromhex("31c0c3"), bytes.fromhex("33c0c3"))
    mov = len(code) == 6 and code[0] == 0xb8 and code[-1] == 0xc3
    if not (xor or mov):
        raise UnsupportedGuestLeaf("Not a supported complete x64 scalar return leaf")
    value = 0 if xor else int.from_bytes(code[1:5], "little")
    # 32-bit EAX writes zero-extend into RAX. XOR updates integer condition
    # flags; MOV leaves flags intact. Other EFLAGS are not modeled by this
    # minimal guest state. RET reads an existing guest return address.
    flags = " s->zf=1U; s->sf=0U; s->cf=0U;\n" if xor else ""
    return (
        '#include <stdint.h>\n#include "mx_crt_cluster_guest.h"\n'
        f'int {function_name}(mx_crt_cluster_state *s,mx_cfg_memory *m) {{\n'
        f' if(!s||!m||s->fault||s->rip!=UINT64_C({entry_va})||'
        's->rsp>UINT64_MAX-8U||s->instructions>190U)'
        'return MX_CRT_CLUSTER_INVALID;\n'
        ' uint64_t ret=0;\n'
        ' if(!mx_cfg_transfer(m,s->rsp,&ret,8U,0)||!ret)'
        'return MX_CRT_CLUSTER_MEMORY_FAULT;\n'
        f' s->rax=UINT64_C({value});\n'
        + flags +
        ' s->instructions+=2U; s->rsp+=8U; s->rip=ret;\n'
        ' return MX_CRT_CLUSTER_RETURNED;\n}\n'
    )
