#!/usr/bin/env python3
"""Fail-closed tiny AOT x86-64 Windows import-call -> C/ARM64 translation.

Supported: sub/add rsp,imm; mov ecx/edx/r8d/r9d,imm32; RIP-relative
call [IAT]; ret, or final RIP-relative jmp [IAT]. No arbitrary memory,
indirect dispatch or original game startup is supported by this module.
"""
from __future__ import annotations
import json
import re
import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_REG, X86_OP_IMM, X86_OP_MEM


class UnsupportedWin64Code(ValueError):
    pass


def _import_ref(instruction, operand, iat):
    if operand.type != X86_OP_MEM or instruction.reg_name(operand.mem.base) != "rip":
        raise UnsupportedWin64Code("Only direct RIP-relative IAT imports allowed")
    if operand.mem.index != 0 or operand.mem.scale not in (0, 1):
        raise UnsupportedWin64Code("Indexed memory is not an import address")
    iat_rva = instruction.address + instruction.size + operand.mem.disp
    if iat_rva not in iat:
        raise UnsupportedWin64Code(f"Unrecognized IAT slot {iat_rva:#x}")
    dll, name = iat[iat_rva]
    if not all(isinstance(v, str) and re.fullmatch(r"[A-Za-z0-9_.@?#$]+", v) for v in (dll, name)):
        raise UnsupportedWin64Code("Unsupported DLL or symbol name")
    return dll, name, iat_rva


def lift_import_sequence(code: bytes, start_rva: int, iat: dict[int, tuple[str, str]]):
    """Translate a structurally verified, restricted x64 code span.

    The generated C uses the tested native Win64 import registry and returns:
      1 if all supported imports execute, 0 for unsupported, -1 for bad input
      or a recognized runtime failure. This is a limited AOT *semantics model*,
      not a complete translator, nor general support for guest memory.
    """
    if not isinstance(code, bytes) or not (1 <= len(code) <= 256):
        raise UnsupportedWin64Code("Supported function length is 1..256 bytes")
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail = True
    insns = list(decoder.disasm(code, start_rva))
    if not insns or sum(ins.size for ins in insns) != len(code):
        raise UnsupportedWin64Code("Incomplete x64 disassembly")
    src = [
        '#include <stdint.h>\n#include "mx_import_registry.h"\n',
        "int lifted_import_sequence(const mx_import_runtime *rt, mx_win64_call *state) {\n",
        "    if (!rt || !state) return -1;\n",
    ]
    stack_depth = 0
    calls = []
    terminated = False
    for n, ins in enumerate(insns):
        mnemonic = ins.mnemonic.lower()
        ops = ins.operands
        if mnemonic in ("sub", "add") and len(ops) == 2 and ops[0].type == X86_OP_REG and ins.reg_name(ops[0].reg) == "rsp" and ops[1].type == X86_OP_IMM:
            amount = int(ops[1].imm)
            if not (amount > 0 and amount <= 256 and amount % 8 == 0):
                raise UnsupportedWin64Code("Invalid guest stack adjustment")
            stack_depth += amount if mnemonic == "sub" else -amount
            if not 0 <= stack_depth <= 256:
                raise UnsupportedWin64Code("Guest stack underflow/overflow")
            src.append(f"    state->rsp {'-=' if mnemonic=='sub' else '+='} {amount}ULL;\n")
            continue
        if mnemonic == "mov" and len(ops) == 2 and ops[0].type == X86_OP_REG and ops[1].type == X86_OP_IMM:
            reg = ins.reg_name(ops[0].reg)
            field = {"ecx":"rcx", "edx":"rdx", "r8d":"r8", "r9d":"r9"}.get(reg)
            if field is None:
                raise UnsupportedWin64Code(f"Register {reg} not supported")
            value = int(ops[1].imm) & 0xffffffff
            # mov to a 32-bit GPR zero-extends the 64-bit register.
            src.append(f"    state->{field} = 0x{value:x}ULL;\n")
            continue
        if mnemonic in ("call", "jmp") and len(ops) == 1:
            dll, name, address = _import_ref(ins, ops[0], iat)
            if mnemonic == "call" and (stack_depth < 32 or stack_depth % 16 != 8):
                raise UnsupportedWin64Code("Win64 call needs >=32 shadow bytes and 16-byte aligned caller stack")
            if mnemonic == "jmp" and (n != len(insns)-1 or stack_depth != 0):
                raise UnsupportedWin64Code("Import tail jump must terminate with unmodified entry stack")
            # Names come through strict validation, not arbitrary code injection.
            src.append(f"    {{ int outcome = mx_dispatch_supported_win64_import(rt, {json.dumps(dll)}, {json.dumps(name)}, state);\n")
            src.append("      if (outcome != 1) return outcome; }\n")
            calls.append({"kind":mnemonic,"iat_rva":hex(address),"dll":dll,"symbol":name})
            if mnemonic == "jmp":
                src.append("    return 1;\n")
                terminated = True
            continue
        if mnemonic == "ret" and len(ops) == 0 and n == len(insns)-1:
            if stack_depth:
                raise UnsupportedWin64Code("Unbalanced guest stack on RET")
            src.append("    return 1;\n")
            terminated = True
            continue
        raise UnsupportedWin64Code(f"Unsupported instruction {ins.address:#x}: {ins.mnemonic} {ins.op_str}")
    if not terminated or not calls:
        raise UnsupportedWin64Code("A translated function must terminate and call a known import")
    src.append("}\n")
    return "".join(src), {"instructions":len(insns), "imports":calls, "bytes":len(code),
                            "scope":"Restricted Windows x64 import sequence; not a game boot."}


def synthetic_import_sequence(rva=0x1000, sleep_slot=0x1300, tick_slot=0x1308):
    """Purpose-built reference x64 bytes. NOT code from the commercial game."""
    prelude = b"\x48\x83\xec\x28\xb9\x19\x00\x00\x00"
    first = rva + len(prelude)
    call_sleep = b"\xff\x15" + struct.pack("<i", sleep_slot-(first+6))
    second = first + len(call_sleep)
    call_tick = b"\xff\x15" + struct.pack("<i", tick_slot-(second+6))
    return prelude + call_sleep + call_tick + b"\x48\x83\xc4\x28\xc3"
