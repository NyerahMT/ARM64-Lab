#!/usr/bin/env python3
"""Private read-only MX Bikes executable-entry reconnaissance.

Disassembles the actual 4-instruction PE entry wrapper. No original instruction
bytes are uploaded, no callees are executed, and no engine boot is claimed.
"""
import hashlib
import json
import pathlib
import sys

from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_GRP_CALL, CS_GRP_JUMP, CS_GRP_RET
from capstone.x86 import X86_OP_IMM

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "arm64-lab"))
from tools.pe_probe import PE
from tools.entry_wrapper import emulate_stubbed_wrapper

KNOWN_SHA256 = "4ae7de3854b4d0a18271679fb57a1f2fdf0b21804417b85dd82055078ea123b6"

def inspect(path):
    pe = PE(path)
    meta = pe.inventory()
    if meta["sha256"] != KNOWN_SHA256:
        raise ValueError("Unexpected binary revision")
    entry = int(meta["entry_rva"], 16)
    code = pe.read_rva(entry, 64)
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    instructions = list(md.disasm(code, entry))[:4]
    if len(instructions) != 4:
        raise RuntimeError("Failed to decode four entry instructions")
    records = []
    for instr in instructions:
        targets = []
        if (instr.group(CS_GRP_CALL) or instr.group(CS_GRP_JUMP)) and instr.operands and instr.operands[0].type == X86_OP_IMM:
            targets.append(hex(instr.operands[0].imm))
        records.append({
            "rva": hex(instr.address),
            "mnemonic": instr.mnemonic,
            "operands": instr.op_str,
            "length": instr.size,
            "direct_targets": targets,
            "is_call": bool(instr.group(CS_GRP_CALL)),
            "is_jump": bool(instr.group(CS_GRP_JUMP)),
            "is_return": bool(instr.group(CS_GRP_RET)),
        })
    verified_wrapper = b"".join(i.bytes for i in instructions)
    controlled = emulate_stubbed_wrapper(verified_wrapper, entry)
    return {
        "controlled_x64_execution": controlled,
        "input_sha256": meta["sha256"],
        "entry_rva": meta["entry_rva"],
        "wrapper_size_bytes": sum(i.size for i in instructions),
        "wrapper_sha256": hashlib.sha256(b"".join(i.bytes for i in instructions)).hexdigest(),
        "instructions": records,
        "scope": "Original four entry instructions executed under x64 CPU emulation; actual callees replaced by synthetic stops.",
    }

if __name__=="__main__":
    if len(sys.argv) != 3:
        raise SystemExit("Usage: python entry_recon.py game.exe report-dir")
    dest = pathlib.Path(sys.argv[2])
    dest.mkdir(parents=True, exist_ok=True)
    result = inspect(sys.argv[1])
    (dest / "entry-recon.json").write_text(json.dumps(result, indent=2)+"\n")
    lines = ["# Original MX Bikes entry-wrapper reconnaissance","",
             f"- Entry RVA: {result['entry_rva']}",
             f"- Wrapper length: {result['wrapper_size_bytes']} bytes",
             f"- SHA256 of wrapper bytes: {result['wrapper_sha256']}", "",
             "## Disassembly metadata (no machine-code bytes)",""]
    for inst in result["instructions"]:
        lines.append(f"- {inst['rva']}: {inst['mnemonic']} {inst['operands']}"
                     + (f" ; targets {', '.join(inst['direct_targets'])}" if inst["direct_targets"] else ""))
    trace = result["controlled_x64_execution"]
    lines += ["", "## Controlled original-entry execution", "",
              f"- Original entry instructions executed under x64 emulation: {trace['original_entry_instructions_executed']}",
              f"- Synthetic callee RET instructions executed: {trace['synthetic_callee_return_executed']}",
              f"- Original stack pointer restored: {trace['x64_stack_balanced']}",
              f"- Tail-jump destination reached: {trace['x64_tail_transfer_reached']}",
              f"- Original callee executed: NO (synthetic RET stub)",
              f"- Original tail destination executed: NO (stop marker)",
              "", "This is isolated original-entry instruction execution under x64 emulation; it is NOT a boot or ARM64 execution.", ""]
    summary = "\n".join(lines)
    (dest / "entry-recon.md").write_text(summary)
    print(summary)
