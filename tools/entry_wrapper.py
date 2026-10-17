#!/usr/bin/env python3
"""Fail-closed MX Bikes-style Win64 entry wrapper analyzer and x64 test harness.

Executes only original entry-wrapper instructions, NOT the original startup
callees. The called function is replaced by an injected synthetic RET; the
tail-jump destination is a stop marker. This is a control-flow/stack test,
not an engine initialization or native ARM64 execution proof.
"""
from __future__ import annotations

import struct

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_IMM
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE
from unicorn.x86_const import UC_X86_REG_RSP, UC_X86_REG_RIP

IMAGE_BASE = 0x140000000
STACK_BASE = 0x50000000
STACK_SIZE = 0x10000


def decode_entry_wrapper(blob: bytes, rva: int):
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    instructions = list(md.disasm(blob, rva))
    if len(instructions) != 4 or sum(i.size for i in instructions) != len(blob):
        raise ValueError("Expected exactly four completely decoded entry instructions")
    sub, call, add, jump = instructions
    if not (
        sub.mnemonic == "sub" and sub.op_str == "rsp, 0x28"
        and call.mnemonic == "call"
        and add.mnemonic == "add" and add.op_str == "rsp, 0x28"
        and jump.mnemonic == "jmp"
    ):
        raise ValueError("Unsupported Win64 entry wrapper shape")
    if not (call.operands and call.operands[0].type == X86_OP_IMM
            and jump.operands and jump.operands[0].type == X86_OP_IMM):
        raise ValueError("Only direct relative startup transfers supported")
    target_call = int(call.operands[0].imm)
    target_jump = int(jump.operands[0].imm)
    if target_call == target_jump:
        raise ValueError("Call and tail jump must have distinct destinations")
    return {
        "entry_rva": hex(rva),
        "entry_length": len(blob),
        "real_instruction_count": len(instructions),
        "direct_call_rva": hex(target_call),
        "tail_jmp_rva": hex(target_jump),
        "win64_shadow_space_bytes": 32,
        "stack_adjustment_bytes": 40,
    }


def emulate_stubbed_wrapper(blob: bytes, rva: int):
    metadata = decode_entry_wrapper(blob, rva)
    call_rva = int(metadata["direct_call_rva"], 16)
    jump_rva = int(metadata["tail_jmp_rva"], 16)
    start_va = IMAGE_BASE + rva
    call_va = IMAGE_BASE + call_rva
    jump_va = IMAGE_BASE + jump_rva
    addresses = [start_va, start_va + len(blob) - 1, call_va, jump_va]
    page_min = min(addresses) & ~0xfff
    page_max = (max(addresses) + 0x1000) & ~0xfff
    if page_max - page_min > 0x10000:
        raise ValueError("Startup targets too distant for this bounded local harness")

    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    uc.mem_map(page_min, page_max - page_min)
    uc.mem_map(STACK_BASE, STACK_SIZE)
    uc.mem_write(start_va, blob)
    # Only these two synthetic bytes stand in for real callee behavior:
    uc.mem_write(call_va, b"\xc3")  # synthetic ret at first callee entry
    uc.mem_write(jump_va, b"\x90")  # synthetic sentinel at tail target
    initial_rsp = STACK_BASE + STACK_SIZE - 0x108
    if initial_rsp % 16 != 8:
        raise AssertionError("Win64 guest entry stack should be 8 mod 16")
    uc.mem_write(initial_rsp, struct.pack("<Q", 0xDEADBEE0))
    uc.reg_write(UC_X86_REG_RSP, initial_rsp)
    uc.reg_write(UC_X86_REG_RIP, start_va)
    visit = []
    def trace(emu, address, size, user_data):
        visit.append(hex(address - IMAGE_BASE) if address >= IMAGE_BASE else "guest_other")
    uc.hook_add(UC_HOOK_CODE, trace)
    # Executes genuine entry instructions and ONE injected ret, halts at tail target.
    uc.emu_start(start_va, jump_va, timeout=1_000_000, count=12)
    final_rsp = uc.reg_read(UC_X86_REG_RSP)
    final_rip = uc.reg_read(UC_X86_REG_RIP)
    returned = final_rsp == initial_rsp
    reached_tail = final_rip == jump_va
    saw_callee_stub = hex(call_rva) in visit
    saw_tail_transfer = hex(rva + len(blob) - 5) in visit
    # The entry opcode at last 5 bytes is a direct 5-byte JMP for this shape.
    expected_rvas = [hex(rva), hex(rva+4), hex(call_rva),
                     hex(rva+9), hex(rva+13)]
    if not (returned and reached_tail and saw_callee_stub and saw_tail_transfer
            and visit == expected_rvas):
        raise AssertionError(f"Entry wrapper diverged; trace={visit}, rip={hex(final_rip)}, rsp={hex(final_rsp)}")
    return {
        **metadata,
        "original_entry_instructions_executed": 4,
        "synthetic_callee_return_executed": 1,
        "x64_stack_balanced": returned,
        "x64_call_target_reached": saw_callee_stub,
        "x64_tail_transfer_reached": reached_tail,
        "trace_rvas": visit,
        "limits": [
            "Only original 18-byte entry wrapper was executed.",
            "The actual function called at the first target was NOT executed (synthetic RET).",
            "The actual function reached by the tail JMP was NOT executed (synthetic stop marker).",
            "This is x64 CPU emulation, not ARM64 recompilation or iOS boot.",
        ],
    }


def synthetic_wrapper(rva=0x300, callee=0x500, tail=0x700):
    # Purpose-built synthetic code, not code copied from any game.
    return (b"\x48\x83\xec\x28"
            + b"\xe8" + struct.pack("<i", callee - (rva + 9))
            + b"\x48\x83\xc4\x28"
            + b"\xe9" + struct.pack("<i", tail - (rva + 18)))
