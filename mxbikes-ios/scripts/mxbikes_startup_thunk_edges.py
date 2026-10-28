#!/usr/bin/env python3
"""Resolve original MX Bikes startup imported-call and thunk dependencies.

This is a *static* and bounded supplement to the existing direct-call graph,
not a dynamic execution trace. An indirect CALL or a JMP through an IAT slot
does not prove that the imported service executes on the selected path.

Original code stays on the private CI runner. Persisted JSON contains only
source/target RVAs, validated import symbol identifiers, and blocker counts.
"""
from __future__ import annotations

import argparse
from bisect import bisect_right
from collections import Counter, deque
import hashlib
import json
from pathlib import Path
import sys

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_IMM, X86_OP_MEM

from mxbikes_startup_chain_coverage import SHA, ROOTS, parsed_rva
from mxbikes_first_callee_emu import import_slots

MAX_INTERVAL_BYTES = 32768
MAX_ROOT_NODES = 256
MAX_UNWINDLESS_THUNKS = 4096
MAX_IMPORT_SLOTS = 32768
MAX_DIRECT_EDGES = 60000
MAX_THUNK_HOPS = 4


def graph_context(mapping, depth=12):
    if mapping.get("input_sha256") != SHA or mapping.get("original_file_verified") is not True:
        raise ValueError("Unknown pinned original executable map")
    rows = mapping["interval_map"]
    starts = [parsed_rva(x["rva"]) for x in rows]
    ends = [parsed_rva(x["end_rva"]) for x in rows]
    if starts != sorted(starts) or len(starts) != len(set(starts)):
        raise ValueError("Unsorted or duplicate unwind intervals")
    index = {parsed_rva(x["rva"]): x for x in rows}
    edges = {
        parsed_rva(source): [parsed_rva(value) for value in dests]
        for source, dests in mapping["direct_call_graph"].items()
    }
    if sum(map(len, edges.values())) > MAX_DIRECT_EDGES:
        raise ValueError("Direct-call audit budget exceeded")
    def owner(address):
        i = bisect_right(starts, address) - 1
        return starts[i] if i >= 0 and address < ends[i] else None
    root_owner = {key: owner(rva) or rva for key, rva in ROOTS.items()}
    visited = {}
    todo = deque((r, 0) for r in root_owner.values())
    while todo:
        src, level = todo.popleft()
        if src in visited:
            continue
        visited[src] = level
        if len(visited) > MAX_ROOT_NODES:
            raise ValueError("Excessive reachable original code targets")
        if level >= depth:
            continue
        for target in edges.get(src, ()):
            dest = owner(target) or target
            if dest not in visited:
                todo.append((dest, level + 1))
    return visited, index, edges, owner


def resolve_import_dependencies(pe, mapping, imports, depth=12):
    """Import slot format: iterable[(iat_slot_rva,dll,symbol)]."""
    visited, indexed, edges, owner = graph_context(mapping, depth=depth)
    slots = {}
    for slot, dll, symbol in imports:
        if (not isinstance(slot, int) or slot < 0 or slot >= (1 << 32)
            or not isinstance(dll, str) or not isinstance(symbol, str)
            or not dll or not symbol or len(dll) > 120 or len(symbol) > 160
            or slot in slots):
            raise ValueError("Malformed or duplicate import IAT slot")
        slots[slot] = (dll.lower(), symbol)
        if len(slots) > MAX_IMPORT_SLOTS:
            raise ValueError("IAT slot budget exceeded")

    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail = True

    def one(rva):
        blob = pe.read_rva(rva, 15)
        seq = list(decoder.disasm(blob, rva, count=1))
        return seq[0] if seq and seq[0].address == rva else None

    def mem_slot(ins):
        if (ins is None or len(ins.operands) != 1 or
            ins.operands[0].type != X86_OP_MEM):
            return None
        op = ins.operands[0]
        if ins.reg_name(op.mem.base) != "rip" or op.mem.index:
            return None
        return ins.address + ins.size + op.mem.disp

    named_imports = []
    unresolved_import_sites = []
    examined = 0
    thunk_candidates = {
        target for src in visited for target in edges.get(src, ())
        if owner(target) is None
    }
    if len(thunk_candidates) > MAX_UNWINDLESS_THUNKS:
        raise ValueError("Excessive non-unwind startup targets")

    for node, level in sorted(visited.items(), key=lambda pair: (pair[1], pair[0])):
        row = indexed.get(node)
        if row is None or row["status"] != "decoded_linear":
            continue
        length = parsed_rva(row["end_rva"]) - node
        if length < 1 or length > MAX_INTERVAL_BYTES:
            continue
        insns = list(decoder.disasm(pe.read_rva(node, length), node))
        if not insns or sum(x.size for x in insns) != length:
            raise ValueError("Previously decoded interval has drifted")
        examined += 1
        for ins in insns:
            if ins.mnemonic != "call":
                continue
            slot = mem_slot(ins)
            if slot is None:
                continue
            record = {
                "source_rva": hex(node),
                "callsite_rva": hex(ins.address),
                "iat_slot_rva": hex(slot),
                "static_root_depth": level,
                "kind": "indirect_memory_call",
                "dynamically_executed": False,
                "native_runtime_service_implemented": False,
            }
            if slot in slots:
                dll, symbol = slots[slot]
                record.update({"kind": "direct_iat_call",
                               "import_dll": dll,
                               "import_symbol": symbol})
                named_imports.append(record)
            else:
                unresolved_import_sites.append(record)

    thunks = []
    for target in sorted(thunk_candidates):
        cur = target
        seen = set()
        result = {
            "called_target_rva": hex(target),
            "kind": "unresolved_unwindless_target",
            "static_root_depth": min(
                visited[src] + 1 for src in visited
                if target in edges.get(src, ())
            ),
            "dynamically_executed": False,
            "verified_native_function": False,
        }
        for hop in range(MAX_THUNK_HOPS):
            if cur in seen:
                result["kind"] = "thunk_cycle"
                break
            seen.add(cur)
            try:
                ins = one(cur)
            except (ValueError, OverflowError):
                break
            if ins is None or ins.mnemonic != "jmp":
                break
            slot = mem_slot(ins)
            if slot is not None:
                result["iat_slot_rva"] = hex(slot)
                if slot in slots:
                    dll, symbol = slots[slot]
                    result.update({
                        "kind": "import_thunk",
                        "import_dll": dll,
                        "import_symbol": symbol,
                        "thunk_hops": hop + 1,
                    })
                else:
                    result["kind"] = "unknown_memory_jump"
                break
            if (len(ins.operands) == 1 and
                ins.operands[0].type == X86_OP_IMM):
                dest = int(ins.operands[0].imm)
                if dest < 0 or dest >= (1 << 32):
                    break
                if owner(dest) is not None:
                    result.update({
                        "kind": "direct_code_tail_jump",
                        "target_function_rva": hex(owner(dest)),
                        "thunk_hops": hop + 1,
                    })
                    break
                cur = dest
                continue
            break
        thunks.append(result)

    counts = Counter(x["kind"] for x in thunks)
    import_summary = Counter(
        (x["import_dll"], x["import_symbol"])
        for x in (thunks + named_imports) if "import_dll" in x
    )
    return {
        "schema": 1,
        "original_sha256": SHA,
        "input_kind": "SHA-pinned PE import table plus static original x64 instructions",
        "root_depth_limit": depth,
        "bounded_reachable_static_nodes": len(visited),
        "decoded_root_intervals_examined": examined,
        "direct_call_targets_without_unwind_examined": len(thunks),
        "identified_import_thunks": counts["import_thunk"],
        "identified_direct_iat_callsites": len(named_imports),
        "unresolved_indirect_memory_callsites": len(unresolved_import_sites),
        "thunk_categories": dict(counts),
        "unique_named_import_dependencies": len(import_summary),
        "import_dependencies": [
            {"dll": dll, "symbol": symbol, "statically_referenced": count,
             "real_service_implemented": False}
            for (dll, symbol), count in sorted(import_summary.items())
        ],
        "original_import_thunks": thunks,
        "direct_iat_callsites": named_imports,
        "unknown_memory_callsites": unresolved_import_sites[:100],
        "limitations": [
            "Import thunks are external service dependencies, never native-translated functions.",
            "Static scans can include unreachable code and omit callback/indirect code paths.",
            "An original IAT symbol name does not imply Windows runtime availability.",
            "A bounded first opcode does not prove an entire unwindless function was decoded.",
            "No original instructions, executable bytes, native output, or proprietary game assets are exported.",
        ],
    }


def render(result):
    lines = [
        "# Original MX Bikes startup import-thunk and indirect-call blockers", "",
        f"- Bounded original direct-call root nodes: **{result['bounded_reachable_static_nodes']}**",
        f"- Root unwind-described intervals statically decoded: **{result['decoded_root_intervals_examined']}**",
        f"- Called targets without unwind records examined: **{result['direct_call_targets_without_unwind_examined']}**",
        f"- Recognized imported-function thunks: **{result['identified_import_thunks']}**",
        f"- Recognized direct IAT callsites in root intervals: **{result['identified_direct_iat_callsites']}**",
        f"- Unresolved indirect memory callsites: **{result['unresolved_indirect_memory_callsites']}**",
        f"- Distinct named external dependencies: **{result['unique_named_import_dependencies']}**",
        "", "## Statically named external-service blockers", ""
    ]
    for entry in result["import_dependencies"][:50]:
        lines.append(
            f"- {entry['dll']}::{entry['symbol']} — {entry['statically_referenced']} source references"
        )
    lines += [
        "", "**This recovers original static imports and thunk identities, NOT "
        "additional fully translated native functions or dynamic startup execution.**", ""
    ]
    return "\n".join(lines)


def run(executable, mapping_path, output):
    from tools.pe_probe import PE
    pe = PE(executable)
    if hashlib.sha256(pe.b).hexdigest() != SHA:
        raise ValueError("Original executable SHA has changed")
    mapping = json.loads(mapping_path.read_text())
    report = resolve_import_dependencies(pe, mapping, import_slots(pe))
    output.mkdir(parents=True, exist_ok=True)
    (output / "startup-import-thunk-edges.json").write_text(
        json.dumps(report, indent=2) + "\n")
    text = render(report)
    (output / "startup-import-thunk-edges.md").write_text(text)
    print(text)
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("sha_verified_original_exe", type=Path)
    parser.add_argument("same_run_whole_game_map", type=Path)
    parser.add_argument("metadata_output", type=Path)
    args = parser.parse_args()
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "arm64-lab"))
    run(args.sha_verified_original_exe, args.same_run_whole_game_map,
        args.metadata_output)
