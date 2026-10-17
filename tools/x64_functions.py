#!/usr/bin/env python3
"""PE32+ Windows x64 unwind-function discovery, read-only and metadata-only.

An unwind record names a protected address interval, not a guaranteed complete
source-level function. Linear decoding does not verify reachable control flow.
"""
from __future__ import annotations

import argparse
import collections
import json
import pathlib
import struct

from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_GRP_JUMP, CS_GRP_CALL, CS_GRP_RET
from capstone.x86 import X86_OP_IMM

from .pe_probe import PE


def analyze(executable: pathlib.Path, max_bytes: int = 8192):
    pe = PE(executable)
    info = pe.inventory()
    directory_rva, directory_size = pe.directory(3)
    if not directory_rva or not directory_size:
        raise ValueError("No PE x64 exception directory")
    if directory_size % 12:
        raise ValueError("Malformed Windows unwind record array")
    data = pe.read_rva(directory_rva, directory_size)
    sections = [s for s in pe.sections if s[5] & 0x20000000]
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail = True
    totals = collections.Counter()
    instruction_counts = collections.Counter()
    categories = collections.Counter()
    candidate_list = []
    direct_call_targets = collections.Counter()
    rejected = collections.Counter()
    sizes = []
    unique_intervals = set()
    for offset in range(0, len(data), 12):
        begin, end, unwind = struct.unpack_from("<III", data, offset)
        totals["unwind_records"] += 1
        if end <= begin or begin == 0 or not unwind:
            rejected["invalid_ranges"] += 1
            continue
        if (begin, end) in unique_intervals:
            rejected["duplicate_interval"] += 1
            continue
        unique_intervals.add((begin, end))
        size = end - begin
        sizes.append(size)
        totals["unique_unwind_intervals"] += 1
        if not any(begin >= rva and end <= rva + max(vsize, raw_size) for _name, vsize, rva, raw_size, _ptr, _flags in sections):
            rejected["outside_executable_sections"] += 1
            continue
        if size > max_bytes:
            rejected["above_decode_cap"] += 1
            continue
        try:
            blob = pe.read_rva(begin, size)
        except ValueError:
            rejected["unmapped_interval"] += 1
            continue
        instructions = list(decoder.disasm(blob, begin))
        if not instructions or sum(i.size for i in instructions) != size:
            rejected["partial_or_undecodable"] += 1
            continue
        totals["fully_decoded_intervals"] += 1
        branch_targets = []
        has_call = False
        has_indirect_branch = False
        return_count = 0
        for inst in instructions:
            instruction_counts[inst.mnemonic] += 1
            if inst.group(CS_GRP_RET):
                return_count += 1
            if inst.group(CS_GRP_CALL):
                has_call = True
                if inst.operands and inst.operands[0].type == X86_OP_IMM:
                    direct_call_targets[inst.operands[0].imm] += 1
            if inst.group(CS_GRP_JUMP):
                if inst.operands and inst.operands[0].type == X86_OP_IMM:
                    branch_targets.append(inst.operands[0].imm)
                else:
                    has_indirect_branch = True
        if instructions[-1].group(CS_GRP_RET):
            categories["terminal_return"] += 1
        if has_call:
            categories["has_call"] += 1
        if has_indirect_branch:
            categories["indirect_jump"] += 1
        out_of_range = sum(not begin <= target < end for target in branch_targets)
        if out_of_range:
            categories["external_direct_jump"] += 1
        # Metadata-backed, completely decoded, no calls/branches, ends in ret:
        # a strong *translation test target*, not proof of a callable function.
        pure = (
            instructions[-1].group(CS_GRP_RET)
            and not has_call
            and not branch_targets
            and not has_indirect_branch
            and return_count == 1
        )
        if pure:
            categories["straight_line_return"] += 1
        if pure and size <= 128 and len(instructions) <= 32:
            categories["short_straight_line"] += 1
        if size <= 128 and len(instructions) <= 32:
            candidate_list.append({
                "begin_rva": hex(begin),
                "end_rva": hex(end),
                "bytes": size,
                "instructions": len(instructions),
                "ends_with_ret": bool(instructions[-1].group(CS_GRP_RET)),
                "straight_line": bool(pure),
                "has_call": has_call,
                "jump_outside_interval": bool(out_of_range),
                "mnemonics": [i.mnemonic for i in instructions][:32],
            })
    for entry in candidate_list:
        entry["direct_call_references"] = direct_call_targets[ int(entry["begin_rva"], 16) ]
    categories["interval_starts_directly_called"] = sum(direct_call_targets[begin] > 0 for begin, end in unique_intervals)
    categories["short_intervals_directly_called"] = sum(item["direct_call_references"] > 0 for item in candidate_list)
    categories["short_straight_line_directly_called"] = sum(
        item["straight_line"] and item["direct_call_references"] > 0 for item in candidate_list
    )
    candidate_list.sort(key=lambda c: (
        not bool(c["direct_call_references"]),
        not c["straight_line"],
        c["bytes"],
        c["begin_rva"],
    ))
    return {
        "input_sha256": info["sha256"],
        "image_base": info["image_base"],
        "entry_rva": info["entry_rva"],
        "exception_record_count": totals["unwind_records"],
        "unique_unwind_intervals": totals["unique_unwind_intervals"],
        "fully_decoded_intervals": totals["fully_decoded_intervals"],
        "interval_size_min": min(sizes) if sizes else None,
        "interval_size_median": sorted(sizes)[len(sizes)//2] if sizes else None,
        "interval_size_max": max(sizes) if sizes else None,
        "categories": dict(categories),
        "rejections": dict(rejected),
        "top_instruction_mnemonics": instruction_counts.most_common(35),
        "direct_call_target_count": len(direct_call_targets),
        "short_candidate_count": len(candidate_list),
        "short_candidate_examples": candidate_list[:75],
        "scope": [
            "Unwind intervals can denote fragments or chained exception records rather than whole functions.",
            "Linear disassembly is not full control-flow validation and does not prove execution.",
            "An interval is only a candidate for semantics-preserving recompilation.",
            "Only metadata is emitted, not original bytes, generated code, or executable archives.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("executable", type=pathlib.Path)
    parser.add_argument("--output-dir", type=pathlib.Path, required=True)
    parser.add_argument("--max-bytes", type=int, default=8192)
    args = parser.parse_args()
    report = analyze(args.executable, max_bytes=args.max_bytes)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "unwind-functions.json").write_text(json.dumps(report, indent=2) + "\n")
    lines = [
        "# MX Bikes native x64 function reconnaissance", "",
        f"- Executable SHA-256: {report['input_sha256']}",
        f"- Unwind records: {report['exception_record_count']}",
        f"- Unique unwind intervals: {report['unique_unwind_intervals']}",
        f"- Fully decoded intervals (bounded): {report['fully_decoded_intervals']}",
        f"- Short decoded intervals (<=128 bytes, <=32 instructions): {report['short_candidate_count']}",
        f"- Median protected interval size: {report['interval_size_median']} bytes",
        f"- Recorded starts referenced by direct calls: {report['categories']['interval_starts_directly_called']}",
        f"- Short straight-line intervals referenced by direct calls: {report['categories']['short_straight_line_directly_called']}",
        "", "## Static structural categories", ""
    ]
    lines += [f"- {key.replace('_',' ')}: {value}" for key,value in sorted(report["categories"].items())]
    lines += ["", "## Representative short intervals", ""]
    for cand in report["short_candidate_examples"][:20]:
        lines.append(f"- {cand['begin_rva']}: {cand['bytes']} bytes, {cand['instructions']} instructions, "
                     f"straight-line={cand['straight_line']}, call references={cand['direct_call_references']}, instruction classes={','.join(cand['mnemonics'])}")
    lines += ["", "## Caveat", "",
              "These intervals are sourced from actual PE unwind records, unlike raw byte-pattern matches. "
              "Direct call references strengthen the case for genuine entrypoints but do not establish a complete function. "
              "They are not proven independent callable functions or completed ARM64 translations.",
              ""]
    summary = "\n".join(lines)
    (args.output_dir / "unwind-functions.md").write_text(summary)
    print(summary)


if __name__ == "__main__":
    main()
