#!/usr/bin/env python3
"""Small, fail-closed x86-64 SSE scalar-to-C lifter for straight-line math.

Supports only a deliberately tiny subset of register/memory SSE instructions,
restricted pointer addressing and balanced RSP adjustments. Generated C models
scalar lane outputs; it is NOT a whole-program x86-64 recompilator.

Use with original code in a private working directory. Do not commit derived
game source, binary objects or original game files to a public repository.
"""
from __future__ import annotations

import argparse
import pathlib

from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_GRP_RET
from capstone.x86 import X86_OP_REG, X86_OP_IMM, X86_OP_MEM

from .pe_probe import PE

PAMBLE = """#include <stdint.h>
#include <string.h>
static float _as_float(uint32_t bits) {
    float x; memcpy(&x, &bits, sizeof(x)); return x;
}
static uint32_t _as_bits(float x) {
    uint32_t bits; memcpy(&bits, &x, sizeof(bits)); return bits;
}
void lifted(float *dst, const float *a, const float *b) {
    uint32_t save_xmm[4] = {0};
"""


class UnsupportedInstruction(ValueError):
    pass


def _reg(instruction, operand):
    if operand.type != X86_OP_REG:
        raise UnsupportedInstruction(f"Expected register at {instruction.address:#x}")
    return instruction.reg_name(operand.reg)


def _xmm(instruction, operand):
    name = _reg(instruction, operand)
    if not name.startswith("xmm") or not name[3:].isdigit() or int(name[3:]) > 15:
        raise UnsupportedInstruction(f"Not an XMM register at {instruction.address:#x}: {name}")
    return name


def _ptr(instruction, operand):
    if operand.type != X86_OP_MEM:
        raise UnsupportedInstruction(f"Expected pointer at {instruction.address:#x}")
    mem = operand.mem
    if mem.index:
        raise UnsupportedInstruction("Indexed x64 addresses are not supported")
    base = instruction.reg_name(mem.base)
    if base not in ("rcx", "rdx", "r8"):
        raise UnsupportedInstruction(f"Pointer base {base} is not supported")
    if mem.disp < 0 or mem.disp % 4 or mem.disp > 4096:
        raise UnsupportedInstruction("Unexpected pointer displacement")
    mapping = {"rcx": "dst", "rdx": "a", "r8": "b"}
    return f"{mapping[base]}[{mem.disp//4}]"


def _stack(instruction, operand):
    if operand.type != X86_OP_MEM or operand.mem.disp != 0 or operand.mem.index:
        raise UnsupportedInstruction("Only movaps [rsp] is supported")
    if instruction.reg_name(operand.mem.base) != "rsp":
        raise UnsupportedInstruction("Only movaps [rsp] is supported")


def _float_expr(instruction, operand):
    if operand.type == X86_OP_REG:
        return f"_as_float({_xmm(instruction, operand)}[0])"
    if operand.type == X86_OP_MEM:
        return _ptr(instruction, operand)
    raise UnsupportedInstruction(f"Unsupported floating point source at {instruction.address:#x}")


def lift(code: bytes, start_rva: int):
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail = True
    instructions = list(decoder.disasm(code, start_rva))
    if not instructions or sum(i.size for i in instructions) != len(code):
        raise UnsupportedInstruction("Incomplete or ambiguous disassembly")
    xmm_names = set()
    for inst in instructions:
        for operand in inst.operands:
            if operand.type == X86_OP_REG:
                name = inst.reg_name(operand.reg)
                if name.startswith("xmm"):
                    xmm_names.add(name)
    body = [PAMBLE]
    for name in sorted(xmm_names, key=lambda x:int(x[3:])):
        body.append(f"    uint32_t {name}[4] = {{0}};\n")
    stack_depth = 0
    saw_ret = False
    for ix, inst in enumerate(instructions):
        op = inst.operands
        mn = inst.mnemonic
        if mn in ("sub", "add") and len(op) == 2 and op[0].type == X86_OP_REG and _reg(inst, op[0]) == "rsp" and op[1].type == X86_OP_IMM:
            delta = int(op[1].imm)
            if delta < 0 or delta > 256 or delta % 8:
                raise UnsupportedInstruction("Unsupported stack adjustment")
            stack_depth += delta if mn == "sub" else -delta
            if stack_depth < 0 or stack_depth > 256:
                raise UnsupportedInstruction("Unbalanced stack pointer")
            continue
        if mn == "movss" and len(op) == 2:
            if op[0].type == X86_OP_REG:
                dest = _xmm(inst,op[0])
                if op[1].type == X86_OP_MEM:
                    value = _ptr(inst, op[1])
                    body.append(f"    {dest}[0] = _as_bits({value});\n")
                    body.append(f"    {dest}[1] = {dest}[2] = {dest}[3] = 0;\n")
                elif op[1].type == X86_OP_REG:
                    body.append(f"    {dest}[0] = {_xmm(inst, op[1])}[0];\n")
                else:
                    raise UnsupportedInstruction("Unknown MOVSS source")
            elif op[0].type == X86_OP_MEM:
                dest = _ptr(inst,op[0])
                src = _xmm(inst,op[1])
                body.append(f"    {dest} = _as_float({src}[0]);\n")
            else:
                raise UnsupportedInstruction("Unknown MOVSS destination")
            continue
        if mn == "movaps" and len(op) == 2:
            if op[0].type == X86_OP_REG:
                dest = _xmm(inst,op[0])
                if op[1].type == X86_OP_REG:
                    src = _xmm(inst,op[1])
                else:
                    _stack(inst,op[1])
                    if stack_depth < 16:
                        raise UnsupportedInstruction("movaps reads outside allocated stack")
                    src = "save_xmm"
                body.append(f"    memcpy({dest}, {src}, 16);\n")
            elif op[0].type == X86_OP_MEM:
                _stack(inst,op[0])
                if stack_depth < 16:
                    raise UnsupportedInstruction("movaps writes outside allocated stack")
                src = _xmm(inst,op[1])
                body.append(f"    memcpy(save_xmm, {src}, 16);\n")
            else:
                raise UnsupportedInstruction("Unknown MOVAPS destination")
            continue
        if mn in ("mulss", "subss", "addss") and len(op) == 2:
            dest = _xmm(inst,op[0])
            src = _float_expr(inst,op[1])
            symbol = {"mulss": "*", "subss": "-", "addss": "+"}[mn]
            body.append(f"    {dest}[0] = _as_bits(_as_float({dest}[0]) {symbol} {src});\n")
            continue
        if mn == "ret" and inst.group(CS_GRP_RET) and ix == len(instructions)-1:
            if stack_depth:
                raise UnsupportedInstruction("Stack depth nonzero at RET")
            saw_ret = True
            continue
        raise UnsupportedInstruction(f"Unsupported opcode at {inst.address:#x}: {mn}")
    if not saw_ret:
        raise UnsupportedInstruction("Function does not end with a supported RET")
    body.append("}\n")
    return "".join(body), len(instructions)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("exe", type=pathlib.Path)
    p.add_argument("--rva", type=lambda v: int(v,0), required=True)
    p.add_argument("--length", type=int, required=True)
    p.add_argument("--output", type=pathlib.Path, required=True)
    a = p.parse_args()
    if not (0 < a.length <= 512):
        p.error("Function length must be in 1..512 bytes")
    code = PE(a.exe).read_rva(a.rva, a.length)
    generated, count = lift(code, a.rva)
    a.output.parent.mkdir(parents=True, exist_ok=True)
    a.output.write_text(generated, encoding="utf8")
    print(f"Lifted {count} supported x64 instructions from {a.rva:#x} to temporary C (no execution proof).")


if __name__ == "__main__":
    main()
