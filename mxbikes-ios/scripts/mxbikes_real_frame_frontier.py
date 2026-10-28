#!/usr/bin/env python3
"""Metadata-only original MX Bikes engine/graphics dependency reachability.

All original instruction bytes stay on user's own machine. This tool builds a
CONSERVATIVE, STATIC direct-CALL graph from genuinely decoded PE .pdata function
intervals, joining RIP-relative IAT calls to imported graphics/Steam/Win32 names.
A candidate static path is NOT observed execution, authorization, valid
control-flow reachability, or an engine frame.
"""
from __future__ import annotations

import argparse
from bisect import bisect_right
from collections import Counter, deque
import hashlib
import json
from pathlib import Path
import struct
import sys

from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_GRP_CALL
from capstone.x86 import X86_OP_IMM, X86_OP_MEM

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))
from tools.pe_probe import PE

EXE_SHA = "4ae7de3854b4d0a18271679fb57a1f2fdf0b21804417b85dd82055078ea123b6"
STEAM_MAIN_RVA = 0x136710
STEAM_BOOTSTRAP_RVA = 0x1306ed
MAX_PDATA = 8 * 1024 * 1024
MAX_UNWINDS = 600000
MAX_FUNCTION_BYTES = 32768
MAX_TOTAL_DECODED = 48 * 1024 * 1024
MAX_IMPORTS = 4096
MAX_REACHABLE = 100000
MAX_DEPTH = 16
MAX_EXAMPLES = 20
GRAPHICS_LIBS = {"opengl32.dll", "glu32.dll", "d3d9.dll", "d3d11.dll", "dxgi.dll"}
STEAM_LIBS = {"steam_api64.dll", "steam_api.dll"}


def _unwind_regions(pe):
    rva, length = pe.directory(3)
    if not rva or not length or length % 12 or length > MAX_PDATA or length // 12 > MAX_UNWINDS:
        raise ValueError("unavailable_or_oversized_original_unwind_index")
    decoded = struct.iter_unpack("<III", pe.read_rva(rva, length))
    regions = {}
    for first, end, unwind_info in decoded:
        if not first or not unwind_info or end <= first:
            continue
        if first in regions and regions[first] != end:
            raise ValueError("contradictory_original_unwind_interval")
        regions[first] = end
    starts = sorted(regions)
    ends = [regions[start] for start in starts]
    if not starts or any(starts[i+1] < ends[i] for i in range(len(starts)-1)):
        raise ValueError("overlapping_or_missing_unwind_intervals")
    return starts, ends


def static_index(pe, imported, *, main_rva=STEAM_MAIN_RVA,
                 max_total=MAX_TOTAL_DECODED, max_depth=MAX_DEPTH):
    """Index fully decoded original unwind spans, then rank possible call paths.

    Only *exact* entry-to-entry near CALLs build graph edges. Skips undecodable
    and oversized spans; never treats linear disassembly as a solved CFG.
    """
    if not 0 <= main_rva < (1 << 32) or not 0 < max_total <= MAX_TOTAL_DECODED:
        raise ValueError("invalid_main_or_decode_budget")
    if not 0 <= max_depth <= MAX_DEPTH:
        raise ValueError("invalid_max_depth")
    if not isinstance(imported, (list, tuple)) or len(imported) > MAX_IMPORTS:
        raise ValueError("invalid_original_import_table")
    imports = {}
    for slot, library, symbol in imported:
        if (not isinstance(slot, int) or slot in imports or not 0 <= slot < (1 << 32)
                or not isinstance(library, str) or not library
                or not isinstance(symbol, str) or not symbol):
            raise ValueError("invalid_or_duplicate_original_IAT")
        imports[slot] = (library, symbol)

    starts, ends = _unwind_regions(pe)
    index_by_entry = {rva: i for i, rva in enumerate(starts)}
    index_set = set(starts)
    base = 0x140000000
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail = True
    results = {}
    stats = Counter()
    total_bytes = 0
    section_windows = [(rva, rva + raw) for _, _, rva, raw, _, flags
                       in pe.sections if flags & 0x20000000 and raw]
    if not section_windows:
        raise ValueError("no_executable_original_sections")

    for first, end in zip(starts, ends):
        length = end - first
        if length > MAX_FUNCTION_BYTES:
            stats["skipped_oversized"] += 1
            continue
        if not any(lo <= first < end <= hi for lo, hi in section_windows):
            stats["skipped_non_executable"] += 1
            continue
        if total_bytes + length > max_total:
            stats["skipped_budget"] += 1
            continue
        try:
            raw = pe.read_rva(first, length)
            instructions = list(decoder.disasm(raw, base + first))
        except (ValueError, OverflowError):
            stats["skipped_unreadable"] += 1
            continue
        if not instructions or sum(row.size for row in instructions) != length:
            stats["skipped_incomplete_decode"] += 1
            continue
        total_bytes += length
        local_targets = set()
        calls = []
        for row in instructions:
            if row.mnemonic not in ("call", "jmp") or len(row.operands) != 1:
                continue
            operand = row.operands[0]
            if operand.type == X86_OP_IMM and row.group(CS_GRP_CALL):
                target = int(operand.imm) - base
                # No speculative interior-of-function edges.
                if target in index_set:
                    local_targets.add(target)
                else:
                    stats["unknown_direct_targets"] += 1
            elif operand.type == X86_OP_MEM:
                mem = operand.mem
                if row.reg_name(mem.base) != "rip" or mem.index:
                    continue
                slot = row.address + row.size + mem.disp - base
                if slot not in imports:
                    continue
                library, symbol = imports[slot]
                calls.append({
                    "site_rva": hex(row.address - base),
                    "kind": row.mnemonic,
                    "iat_rva": hex(slot),
                    "dll": library,
                    "symbol": symbol,
                    "class": ("steam" if library.lower() in STEAM_LIBS
                              else "graphics" if library.lower() in GRAPHICS_LIBS
                              else "other"),
                })
        results[first] = {"target_entries": sorted(local_targets),
                          "imports": calls, "instructions": len(instructions)}
        stats["complete_linear_decodes"] += 1
        stats["direct_call_edges"] += len(local_targets)
        stats["matched_import_calls_and_jumps"] += len(calls)

    i = bisect_right(starts, main_rva) - 1
    if i < 0 or main_rva >= ends[i] or starts[i] not in results:
        raise ValueError("original_main_function_not_decoded")
    root = starts[i]
    parents = {root: None}
    distance = {root: 0}
    queue = deque([root])
    while queue:
        node = queue.popleft()
        if distance[node] >= max_depth:
            continue
        for next_node in results[node]["target_entries"]:
            if next_node not in results or next_node in parents:
                continue
            if len(parents) >= MAX_REACHABLE:
                raise ValueError("static_graph_reachability_budget")
            distance[next_node] = distance[node] + 1
            parents[next_node] = node
            queue.append(next_node)
    def path_to(target):
        path = []
        while target is not None:
            path.append(hex(target))
            target = parents[target]
        return list(reversed(path))

    ranked = []
    all_by_class = Counter()
    for owner, row in results.items():
        for call in row["imports"]:
            all_by_class[call["class"]] += 1
            if owner not in parents:
                continue
            ranked.append({**call, "containing_unwind_rva": hex(owner),
                           "direct_call_depth_from_main": distance[owner],
                           "static_call_chain": path_to(owner),
                           "executed": False, "conditional_branches_proven": False})
    ranked.sort(key=lambda x: (x["direct_call_depth_from_main"],
                               x["containing_unwind_rva"], x["site_rva"]))
    classification = {}
    for category in ("graphics", "steam", "other"):
        subset = [row for row in ranked if row["class"] == category]
        classification[category] = {
            "candidate_import_calls_from_main_graph": len(subset),
            "shortest_direct_call_depth": subset[0]["direct_call_depth_from_main"] if subset else None,
            "examples": subset[:MAX_EXAMPLES]
        }
    return {
        "original_executable_provenance": "SHA-pinned original PE locally decoded; no original bytes exported",
        "original_game_main_rva": hex(main_rva),
        "main_unwind_entry_rva": hex(root),
        "unwind_region_count": len(starts),
        "function_linear_decodes_completed": stats["complete_linear_decodes"],
        "total_function_bytes_decoded": total_bytes,
        "function_decoding_skips": dict(sorted((k, v) for k, v in stats.items() if k.startswith("skipped_"))),
        "candidate_direct_call_edges": stats["direct_call_edges"],
        "static_main_direct_call_graph_nodes": len(parents),
        "candidate_imports_across_all_decoded_functions": dict(all_by_class),
        "candidate_imports_on_direct_call_graph": classification,
        "original_game_code_executed_by_this_scan": False,
        "steam_client_initialized": False,
        "graphics_calls_observed_from_real_execution": 0,
        "actual_game_frames_rendered": 0,
        "warnings": [
            "Linear original x64 unwind disassembly is a candidate, not recovered control-flow truth.",
            "Direct-call edges do not prove conditional branches, reachable instructions or completed callees.",
            "External or indirect CALLs and virtual dispatch can hide engine paths.",
            "No Steam licensing, original engine frames or graphics calls were executed."
        ]
    }


def audit_owned_exe(exe: Path, out: Path, *, runtime_report=None):
    exe = Path(exe).expanduser().resolve()
    out = Path(out).expanduser().resolve()
    if out == REPO or REPO in out.parents:
        raise ValueError("output_must_be_outside_public_repository")
    if not exe.is_file() or exe.stat().st_size > 750 * 1024 * 1024:
        raise ValueError("owned_original_executable_missing_or_oversized")
    if hashlib.sha256(exe.read_bytes()).hexdigest() != EXE_SHA:
        raise ValueError("original_game_SHA256_drift")
    from mxbikes_first_callee_emu import import_slots
    pe = PE(exe)
    result = static_index(pe, import_slots(pe))
    result["original_executable_sha256"] = EXE_SHA
    if runtime_report:
        # The accelerated guest trace currently provides only a subset of
        # dynamic PCs; do not claim complete dynamic code coverage from it.
        dynamic = json.loads(Path(runtime_report).read_text())
        if not dynamic.get("original_pe_sha_verified"):
            raise ValueError("unverified_original_dynamic_runtime_report")
        result["last_authenticated_guest_run"] = {
            "reported_original_blocks": dynamic.get("original_guest_basic_block_executions"),
            "reported_GL_import_events": dynamic.get("actual_original_gl_import_events"),
            "real_guest_stop": dynamic.get("stop"),
            "is_exhaustive_runtime_coverage": False
        }
    out.mkdir(parents=True, exist_ok=True)
    (out / "original-graphics-static-paths.json").write_text(
        json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--owned-exe", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--runtime-report", type=Path)
    args = parser.parse_args(argv)
    try:
        obj = audit_owned_exe(args.owned_exe, args.out, runtime_report=args.runtime_report)
    except (OSError, ValueError) as exc:
        parser.exit(2, "Original-game static scan rejected: " + str(exc) + "\n")
    categories = obj["candidate_imports_on_direct_call_graph"]
    print(json.dumps({
        "full_unwind_function_decodes": obj["function_linear_decodes_completed"],
        "static_functions_linked_to_main": obj["static_main_direct_call_graph_nodes"],
        "graphics_static_candidates": categories["graphics"]["candidate_import_calls_from_main_graph"],
        "steam_static_candidates": categories["steam"]["candidate_import_calls_from_main_graph"],
        "original_engine_code_executed": False,
        "actual_game_frames_rendered": 0,
    }, indent=2))


if __name__ == "__main__":
    main()
