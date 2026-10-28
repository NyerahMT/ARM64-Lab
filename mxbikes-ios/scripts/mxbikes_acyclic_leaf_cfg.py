#!/usr/bin/env python3
"""Conservative entire-body translator for small, forward-only x64 leaf CFGs.

Accepts only exact opcode forms listed below, contiguous decodes, forward
intra-body jumps, and complete RET exits.  Does not treat linear disassembly
or a successful native compile as behavioral verification.  Every generated
candidate must still pass original-Unicorn vs host vs executed-AArch64 tests.
"""
from __future__ import annotations

MAX_BYTES = 96
MAX_INSTRUCTIONS = 32
REGS = ("rax", "rcx", "rdx")


def decode(code: bytes, origin: int):
    if not isinstance(code, bytes) or not 3 <= len(code) <= MAX_BYTES:
        return None
    ops = []
    i = 0
    while i < len(code):
        start = i
        opcode = code[i]
        row = {"offset": i}
        if opcode == 0x90:
            row["op"] = "nop"
            i += 1
        elif opcode == 0xC3:
            row["op"] = "ret"
            i += 1
        elif opcode in (0xB8, 0xB9, 0xBA) and i + 5 <= len(code):
            row.update(op="mov_imm", reg=REGS[opcode - 0xB8], bits=32,
                       value=int.from_bytes(code[i+1:i+5], "little"))
            i += 5
        elif opcode in (0x31, 0x85, 0x8B) and i + 2 <= len(code):
            modrm = code[i+1]
            if opcode == 0x31 and modrm in (0xC0, 0xC9, 0xD2):
                row.update(op="zero", reg=REGS[(modrm - 0xC0)//9], bits=32)
            elif opcode == 0x85 and modrm in (0xC0, 0xC9, 0xD2):
                row.update(op="test", reg=REGS[(modrm - 0xC0)//9], bits=32)
            elif opcode == 0x8B and modrm in (0xC1, 0xC2):
                row.update(op="mov_reg", reg="rax",
                           src="rcx" if modrm == 0xC1 else "rdx", bits=32)
            else:
                return None
            i += 2
        elif opcode == 0x48 and i + 3 <= len(code) and code[i+1] in (0x31, 0x85):
            modrm = code[i+2]
            if modrm not in (0xC0, 0xC9, 0xD2):
                return None
            row.update(op="zero" if code[i+1] == 0x31 else "test",
                       reg=REGS[(modrm - 0xC0)//9], bits=64)
            i += 3
        elif opcode == 0x48 and i + 10 <= len(code) and code[i+1] in (0xB8, 0xB9, 0xBA):
            row.update(op="mov_imm", reg=REGS[code[i+1] - 0xB8], bits=64,
                       value=int.from_bytes(code[i+2:i+10], "little"))
            i += 10
        elif opcode in (0x74, 0x75, 0xEB) and i + 2 <= len(code):
            displacement = int.from_bytes(code[i+1:i+2], "little", signed=True)
            row.update(op={0x74:"jz", 0x75:"jnz", 0xEB:"jmp"}[opcode],
                       target=i+2+displacement)
            i += 2
        elif opcode == 0xE9 and i + 5 <= len(code):
            displacement = int.from_bytes(code[i+1:i+5], "little", signed=True)
            row.update(op="jmp", target=i+5+displacement)
            i += 5
        elif opcode == 0x0F and i + 6 <= len(code) and code[i+1] in (0x84, 0x85):
            displacement = int.from_bytes(code[i+2:i+6], "little", signed=True)
            row.update(op="jz" if code[i+1] == 0x84 else "jnz",
                       target=i+6+displacement)
            i += 6
        else:
            return None
        row["next"] = i
        row["rva"] = origin + start
        ops.append(row)
        if len(ops) > MAX_INSTRUCTIONS:
            return None

    starts = {r["offset"] for r in ops}
    by_offset = {r["offset"]: r for r in ops}
    if 0 not in starts or ops[-1]["op"] != "ret":
        return None
    for row in ops:
        kind = row["op"]
        if kind in ("jz", "jnz", "jmp"):
            if row["target"] <= row["offset"] or row["target"] not in starts:
                return None
        if kind not in ("ret", "jmp") and row["next"] not in starts:
            return None

    seen = set()
    stack = [0]
    while stack:
        pc = stack.pop()
        if pc in seen:
            continue
        seen.add(pc)
        row = by_offset[pc]
        if row["op"] != "ret":
            if row["op"] in ("jz", "jnz", "jmp"):
                stack.append(row["target"])
            if row["op"] != "jmp":
                stack.append(row["next"])
    # Require entire interval to be reachable. Reject padding, hidden code, or
    # trailing bytes that only a linear decoder would misleadingly accept.
    if seen != starts or not any(row["op"] == "ret" for row in ops):
        return None
    if not any(row["op"] in ("jmp", "jz", "jnz") for row in ops):
        return None
    return {"kind": "bounded_forward_cfg", "rva": origin,
            "instructions": len(ops), "branches": sum(r["op"] in ("jz", "jnz") for r in ops),
            "returns": sum(r["op"] == "ret" for r in ops), "ops": ops}


def emit_native(plan):
    if not isinstance(plan, dict) or plan.get("kind") != "bounded_forward_cfg":
        raise ValueError("No verified structural plan to translate")
    lines = ["uint64_t return_va=0U;",
             "if(!mx_cfg_transfer(m,s->rsp,&return_va,8U,0))return MX_NATIVE_LINK_STACK;",
             "uint32_t guest_pc=0U;",
             "for(uint32_t budget=0U;budget<33U;budget++){",
             "switch(guest_pc){"]
    for row in plan["ops"]:
        kind = row["op"]
        lines.append(f'case {row["offset"]}U:')
        if kind == "ret":
            lines.append("s->rsp+=8U;s->rip=return_va;return MX_NATIVE_LINK_OK;")
            continue
        if kind == "mov_imm":
            cast = "(uint32_t)" if row["bits"] == 32 else ""
            lines.append(f's->{row["reg"]}={cast}UINT64_C({row["value"]});')
        elif kind == "mov_reg":
            lines.append(f's->{row["reg"]}=(uint32_t)s->{row["src"]};')
        elif kind == "zero":
            lines.append(f's->{row["reg"]}=UINT64_C(0);s->cf=0U;s->zf=1U;s->sf=0U;')
        elif kind == "test":
            mask = "UINT64_C(0xffffffff)" if row["bits"] == 32 else "UINT64_MAX"
            bit = 31 if row["bits"] == 32 else 63
            lines.append(f'{{uint64_t tested=s->{row["reg"]}&{mask};'
                         f's->cf=0U;s->zf=(tested==0U);s->sf=(tested>>{bit}U)&1U;}}')
        if kind in ("jz", "jnz"):
            predicate = "s->zf" if kind == "jz" else "!s->zf"
            lines.append(f'guest_pc=({predicate})?{row["target"]}U:{row["next"]}U;break;')
        elif kind == "jmp":
            lines.append(f'guest_pc={row["target"]}U;break;')
        else:
            lines.append(f'guest_pc={row["next"]}U;break;')
    lines.extend(["default:return MX_NATIVE_LINK_INVALID;", "}", "}",
                  "return MX_NATIVE_LINK_INVALID;"])
    return "\n".join(lines)
