"""Lift the complete, 17-instruction, *empty* Win64 CRT callback-table helper.

This intentionally narrow translator rejects any initializer range that is
nonempty. It does not pretend to dispatch unknown indirect callbacks or
implement a general Windows CRT; such tables require separately validated
targets and an indirect-call scheduler.
"""
from __future__ import annotations

import re

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG


class UnsupportedEmptyCRTTable(ValueError):
    pass


# All the original instructions must match, not just a prefix or some opcodes.
EXPECTED = (
    ("mov", "qword ptr [rsp + 8], rbx"),
    ("push", "rdi"),
    ("sub", "rsp, 0x20"),
    ("lea", None),
    ("lea", None),
    ("jmp", None),
    ("mov", "rax, qword ptr [rbx]"),
    ("test", "rax, rax"),
    ("je", None),
    ("call", "rax"),
    ("add", "rbx, 8"),
    ("cmp", "rbx, rdi"),
    ("jb", None),
    ("mov", "rbx, qword ptr [rsp + 0x30]"),
    ("add", "rsp, 0x20"),
    ("pop", "rdi"),
    ("ret", ""),
)


def lift_empty_crt_table(
    code: bytes, start_rva: int, image_base: int = 0x140000000,
    function_name: str = "native_empty_crt_table",
) -> tuple[str, dict]:
    if (not isinstance(code, bytes) or not 48 <= len(code) <= 96 or
        not isinstance(start_rva, int) or isinstance(start_rva, bool) or
        not 0 <= start_rva < (1 << 32) or
        not isinstance(image_base, int) or isinstance(image_base, bool) or
        not 0 < image_base < (1 << 64) - (1 << 32) or
        not isinstance(function_name, str) or
        not re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]{0,63}", function_name)):
        raise UnsupportedEmptyCRTTable("Unsafe or incomplete original CRT helper")
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    ins = list(md.disasm(code, start_rva))
    if len(ins) != len(EXPECTED) or sum(i.size for i in ins) != len(code):
        raise UnsupportedEmptyCRTTable("Require one complete 17-instruction function")
    for i, (mnemonic, operand_text) in zip(ins, EXPECTED):
        if i.mnemonic != mnemonic or (
            operand_text is not None and i.op_str != operand_text
        ):
            raise UnsupportedEmptyCRTTable("Unrecognized original CRT instruction")
    # These branch targets must be exact instruction boundaries.
    for index, target_index in ((5, 11), (8, 10), (12, 6)):
        operands = ins[index].operands
        if (len(operands) != 1 or operands[0].type != X86_OP_IMM or
            operands[0].imm != ins[target_index].address):
            raise UnsupportedEmptyCRTTable("Unknown indirect or off-CFG branch")
    first, last = [], []
    for index, destination in ((3, first), (4, last)):
        i = ins[index]
        ops = i.operands
        if (len(ops) != 2 or ops[0].type != X86_OP_REG or
            i.reg_name(ops[0].reg) != ("rbx" if index == 3 else "rdi") or
            ops[1].type != X86_OP_MEM or
            i.reg_name(ops[1].mem.base) != "rip" or
            ops[1].mem.index != 0):
            raise UnsupportedEmptyCRTTable("Unsupported callback-table LEA")
        destination.append(image_base + i.address + i.size + ops[1].mem.disp)
    if not (first[0] == last[0] and 0 < first[0] < (1 << 64) and
            not first[0] & 7):
        raise UnsupportedEmptyCRTTable(
            "Nonempty/unaligned callback table cannot be silently skipped")
    entry = image_base + start_rva
    # This is a *verified* zero-trip loop: the indirect CALL RAX is
    # unreachable. Preserve x64 caller-home-slot writes, PUSH/POP and RET,
    # RAX, and the final CMP flags; do not invent a callback result.
    source = (
        '#include <stdint.h>\n#include "mx_crt_cluster_guest.h"\n'
        f'int {function_name}(mx_crt_cluster_state*s,mx_cfg_memory*m){{\n'
        f' if(!s||!m||s->fault||s->rip!=UINT64_C({entry})||'
        's->rsp<40U||s->rsp>UINT64_MAX-8U||'
        's->instructions>244U)return MX_CRT_CLUSTER_INVALID;\n'
        ' uint64_t old_rbx=s->rbx,old_rdi=s->rdi,ret=0,restored_rbx=0,'
        'restored_rdi=0;\n'
        ' /* Original: mov [rsp+8],rbx; push rdi; sub rsp,0x20. */\n'
        ' if(!mx_cfg_transfer(m,s->rsp+8U,&old_rbx,8U,1)||'
        '!mx_cfg_transfer(m,s->rsp-8U,&old_rdi,8U,1))'
        'return MX_CRT_CLUSTER_MEMORY_FAULT;\n'
        ' uint64_t inner_sp=s->rsp-40U;\n'
        ' if(!mx_cfg_transfer(m,inner_sp+48U,&restored_rbx,8U,0)||'
        '!mx_cfg_transfer(m,inner_sp+32U,&restored_rdi,8U,0)||'
        '!mx_cfg_transfer(m,s->rsp,&ret,8U,0)||!ret)'
        'return MX_CRT_CLUSTER_MEMORY_FAULT;\n'
        ' /* Identical RIP-relative LEAs, so the initial CMP is equal. */\n'
        ' s->rbx=restored_rbx;s->rdi=restored_rdi;\n'
        ' s->zf=1U;s->sf=0U;s->cf=0U;\n'
        ' s->instructions+=12U;s->rsp+=8U;s->rip=ret;\n'
        ' return MX_CRT_CLUSTER_RETURNED;\n}\n'
    )
    return source, {
        "decoded_instructions": len(ins),
        "translated_instruction_path_length": 12,
        "original_callback_range_is_empty": True,
        "guest_callback_table_va": hex(first[0]),
        "indirect_calls_executed": 0,
        "full_unwind_interval_verified": False,
        "real_engine_startup_verified": False,
    }
