"""Fail-closed inspection of the original PE entry wrapper and unwind ranges.

This is metadata inspection, not native execution or function translation.
No commercial bytes are emitted.
"""
from __future__ import annotations
import argparse
import json
import struct
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
