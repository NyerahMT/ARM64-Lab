"""Fail-closed inspection of the original PE entry wrapper and unwind ranges.

This is metadata inspection, not native execution or function translation.
No commercial bytes are emitted.
"""
from __future__ import annotations
import argparse
import json
import struct
from collections import Counter
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_GRP_CALL, CS_GRP_JUMP
from capstone.x86_const import X86_OP_MEM, X86_OP_IMM, X86_REG_RIP
from .pe_probe import PE


def unwind_range(pe, target):
    rva, size = pe.directory(3)
    if not rva or size % 12:
        raise ValueError("Missing or invalid unwind directory")
    raw = pe.read_rva(rva, size)
    matches = []
    for off in range(0, len(raw), 12):
        begin, end, unwind = struct.unpack_from("<III", raw, off)
        if begin <= target < end and begin < end:
            matches.append({"begin": hex(begin), "end": hex(end),
                            "size": end - begin, "unwind_rva": hex(unwind)})
    return matches



def profile_first_callee(pe, callee_rva):
    """Statically decode the complete unwind interval containing the first callee.

    Fail closed unless the call target coincides with exactly one unwind
    interval start. This is NOT evidence of executable ARM64 translation.
    """
    candidates = [
        item for item in unwind_range(pe, callee_rva)
        if int(item["begin"], 16) == callee_rva
    ]
    if len(candidates) != 1:
        raise ValueError("First callee does not have a unique unwind interval start")
    region = candidates[0]
    length = region["size"]
    if not 0 < length <= 65536:
        raise ValueError("First callee unwind interval exceeds bounds")
    data = pe.read_rva(callee_rva, length)
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    decoded = list(md.disasm(data, callee_rva))
    if not decoded or sum(ins.size for ins in decoded) != length:
        raise ValueError("Callee unwind interval cannot be decoded completely")
    counter = Counter(ins.mnemonic for ins in decoded)
    direct_calls = []
    indirect_calls = 0
    conditional_branches = 0
    indirect_branches = 0
    rip_memory_references = 0
    lock_prefixed = 0
    for ins in decoded:
        if ins.prefix and 0xf0 in ins.prefix:
            lock_prefixed += 1
        if any(op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP
               for op in ins.operands):
            rip_memory_references += 1
        if ins.group(CS_GRP_CALL):
            if ins.operands and ins.operands[0].type == X86_OP_IMM:
                direct_calls.append(hex(ins.operands[0].imm))
            else:
                indirect_calls += 1
        if ins.group(CS_GRP_JUMP):
            if ins.operands and ins.operands[0].type != X86_OP_IMM:
                indirect_branches += 1
            if ins.mnemonic.startswith("j") and ins.mnemonic != "jmp":
                conditional_branches += 1
    return {
        "callee_rva": hex(callee_rva),
        "unwind_interval_size": length,
        "decoded_instruction_count": len(decoded),
        "fully_decoded": True,
        "mnemonic_counts": dict(sorted(counter.items())),
        "direct_call_targets": direct_calls,
        "indirect_call_count": indirect_calls,
        "conditional_branch_count": conditional_branches,
        "indirect_branch_count": indirect_branches,
        "rip_relative_memory_instruction_count": rip_memory_references,
        "lock_prefixed_instruction_count": lock_prefixed,
        "native_arm64_executed": False,
        "limitations": [
            "Unwind interval can differ from an entire callable function.",
            "Static disassembly does not prove instruction execution or CFG reachability.",
            "No original instructions are emitted; no ARM64 translation is performed.",
        ],
    }


def inspect_entry(pe):
    entry = pe.u32(pe.opt + 16)
    code = pe.read_rva(entry, 18)
    # Verify the exact four-instruction wrapper before interpreting offsets.
    if not (code[:4] == bytes.fromhex("4883ec28") and
            code[4] == 0xe8 and code[9:13] == bytes.fromhex("4883c428") and
            code[13] == 0xe9):
        raise ValueError("Entry is not the supported 18-byte CALL/JMP wrapper")
    call_disp = struct.unpack_from("<i", code, 5)[0]
    jump_disp = struct.unpack_from("<i", code, 14)[0]
    callee = entry + 9 + call_disp
    tail = entry + 18 + jump_disp
    if callee == tail or callee == entry or tail == entry:
        raise ValueError("Degenerate startup call or tail targets")
    if not (0 <= callee < 2**32 and 0 <= tail < 2**32):
        raise ValueError("Relative branch destination outside RVA range")
    # Ensure both destinations are backed by bytes; no guessing from metadata.
    pe.read_rva(callee, 1)
    pe.read_rva(tail, 1)
    return {
        "entry_rva": hex(entry),
        "first_call_rva": hex(callee),
        "tail_jump_rva": hex(tail),
        "entry_unwind": unwind_range(pe, entry),
        "first_call_unwind": unwind_range(pe, callee),
        "tail_jump_unwind": unwind_range(pe, tail),
        "first_callee_instruction_profile": profile_first_callee(pe, callee),
        "native_arm64_executed": False,
        "note": "Static PE inspection only; unwind intervals are not verified full functions."
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("exe", help="Private local original PE input")
    args = parser.parse_args()
    try:
        print(json.dumps(inspect_entry(PE(args.exe)), indent=2))
    except (OSError, ValueError, struct.error) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()
