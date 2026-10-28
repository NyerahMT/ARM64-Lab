#!/usr/bin/env python3
"""Audit direct-call startup reachability against SAME-RUN verified ARM64 leaves.

Input is existing original-game metadata ONLY: whole-game-map.json and the
autolinker verification manifest. Neither decompiled code, bytes, LLVM IR,
unverified native objects, nor fabricated executable functions are emitted.

STATIC DIRECT-CALL POTENTIAL REACHABILITY IS NOT DYNAMIC EXECUTION. Unwind
records are not a definitive count of functions; indirect calls, callbacks,
jump-table edges, external services and leafs without unwind records escape
this analysis. The verified manifest counts ONLY its explicitly evidenced
fully-returning, differential-tested leafs, not every verified block in
other startup CI gates.
"""
from __future__ import annotations
import argparse
from bisect import bisect_right
from collections import Counter, defaultdict, deque
import json
from pathlib import Path
import re

ROOTS = {
    "game_main": 0x136710,
    "crt_startup": 0x2ab02c,
    "pe_entry": 0x2ab31c,
}
MAX_DEPTH = 12
MAX_NODES = 250000
SHA = "4ae7de3854b4d0a18271679fb57a1f2fdf0b21804417b85dd82055078ea123b6"
EVIDENCE = re.compile(
    r"^https://github\.com/NyerahMT/ReflexBuildInput/actions/runs/[0-9]+$"
)
SYMBOL = re.compile(r"^mx_verified_[0-9a-f]{8}$")
UNWINDLESS_SYMBOL = re.compile(r"^mx_unwindless_native_[0-9a-f]{8}$")


def parsed_rva(value: str) -> int:
    if not isinstance(value, str) or not re.fullmatch(r"0x[0-9a-fA-F]{1,16}", value):
        raise ValueError("Invalid original RVA notation")
    return int(value, 16)


def verify_manifest(manifest, mapping=None):
    if not isinstance(manifest, list) or len(manifest) > 131072:
        raise ValueError("Verification manifest missing or too large")
    unwindless = {}
    if mapping is not None:
        candidates = mapping.get("unwindless_direct_call_candidates", [])
        if not isinstance(candidates, list) or len(candidates)>4000:
            raise ValueError("Untrusted original CALL entry manifest")
        for entry in candidates:
            rva = parsed_rva(entry.get("rva"))
            if rva in unwindless:
                raise ValueError("Duplicate original direct CALL target")
            if (entry.get("unwind_protected") is False and
                entry.get("static_first_block_verified") is True and
                isinstance(entry.get("direct_call_references"),int) and
                entry["direct_call_references"]>0):
                unwindless[rva]=entry
    starts=[]
    ends=[]
    if mapping is not None:
        for row in mapping.get("interval_map", []):
            starts.append(parsed_rva(row["rva"]))
            ends.append(parsed_rva(row["end_rva"]))
        if starts!=sorted(starts):
            raise ValueError("Invalid original interval ordering")
    checked = {}
    for item in manifest:
        if not isinstance(item, dict):
            raise ValueError("Malformed verification record")
        rva = parsed_rva(item.get("original_rva"))
        sym=item.get("native_symbol", "")
        is_unwindless=item.get("original_direct_CALL_entry_without_pdata") is True
        if is_unwindless:
            index=bisect_right(starts,rva)-1
            if (not UNWINDLESS_SYMBOL.fullmatch(sym) or
                sym!=f"mx_unwindless_native_{rva:08x}" or
                rva not in unwindless or
                index>=0 and rva<ends[index]):
                raise ValueError("Unverified original unwindless CALL entry")
        elif (item.get("original_direct_CALL_entry_without_pdata") is not None or
              not SYMBOL.fullmatch(sym) or
              sym!=f"mx_verified_{rva:08x}"):
            raise ValueError("Unverified native proof symbol")
        if (rva in checked or rva >= 1 << 32 or
            item.get("full_function_behavior_verified") is not True or
            item.get("win64_guest_call_abi_verified") is not True or
            item.get("code_presence") != "ephemeral_ci_elf_only" or
            not EVIDENCE.fullmatch(item.get("differential_test_run_url", ""))):
            raise ValueError("Unverified/duplicate native function registration")
        checked[rva] = sym
    return checked


def validate_bounded_proofs(proofs):
    """Curated proof pointers identify work to REUSE, not completed functions."""
    if proofs is None:
        return {}
    if (not isinstance(proofs, dict) or
        proofs.get("pinned_original_sha256") != SHA or
        not isinstance(proofs.get("entries"), list) or
        len(proofs["entries"]) > 128):
        raise ValueError("Invalid curated bounded-startup proof inventory")
    allowed = {
        "bounded_native_branch", "bounded_native_prefix",
        "bounded_original_initializer", "modeled_external_import",
        "nonreturning_import_boundary",
    }
    result = {}
    for entry in proofs["entries"]:
        if not isinstance(entry, dict):
            raise ValueError("Malformed bounded proof")
        rva = parsed_rva(entry.get("original_rva"))
        if (rva in result or entry.get("proof_kind") not in allowed or
            not isinstance(entry.get("scope"), str) or
            not 12 <= len(entry["scope"]) <= 256 or
            not EVIDENCE.fullmatch(entry.get("evidence_run",""))):
            raise ValueError("Unknown or unevidenced bounded startup proof")
        result[rva] = {
            "kind": entry["proof_kind"],
            "scope": entry["scope"],
            "evidence_run": entry["evidence_run"],
        }
    return result


def analyze(mapping, manifest, *, depth=MAX_DEPTH, known_proofs=None, import_graph=None):
    if (mapping.get("input_sha256") != SHA or
        mapping.get("original_file_verified") is not True or
        not 1 <= depth <= MAX_DEPTH):
        raise ValueError("Unknown original executable or unsafe search depth")
    verified = verify_manifest(manifest, mapping)
    known = validate_bounded_proofs(known_proofs)
    imports_by_thunk = {}
    named_imports = []
    if import_graph is not None:
        if (import_graph.get("original_sha256") != SHA or
            import_graph.get("input_kind") !=
                "SHA-pinned PE import table plus static original x64 instructions"):
            raise ValueError("Original import-thunk map is not from pinned executable")
        if len(import_graph.get("original_import_thunks", [])) > 4096 or (
            len(import_graph.get("direct_iat_callsites", [])) > 4096):
            raise ValueError("Import edge scan exceeds bounded startup budget")
        for thunk in import_graph["original_import_thunks"]:
            rva = parsed_rva(thunk["called_target_rva"])
            if rva in imports_by_thunk:
                raise ValueError("Duplicate original import thunk")
            if thunk.get("kind") == "import_thunk":
                imports_by_thunk[rva] = {
                    "dll": thunk["import_dll"],
                    "symbol": thunk["import_symbol"],
                    "iat_slot_rva": thunk["iat_slot_rva"],
                }
        named_imports = import_graph["direct_iat_callsites"]
    stats = mapping["statistics"]
    rows = mapping["interval_map"]
    starts, ends, lookup = [], [], {}
    for item in rows:
        lo = parsed_rva(item["rva"])
        hi = parsed_rva(item["end_rva"])
        if lo in lookup or hi <= lo:
            raise ValueError("Invalid original PE unwind interval")
        starts.append(lo)
        ends.append(hi)
        lookup[lo] = item
    if starts != sorted(starts):
        raise ValueError("Unwind interval map must be sorted")
    graph = {}
    for key, values in mapping.get("direct_call_graph", {}).items():
        src = parsed_rva(key)
        if not isinstance(values, list) or len(values) > 1024:
            raise ValueError("Malformed bounded direct-call edges")
        graph[src] = set(parsed_rva(x) for x in values)
    if not graph:
        raise ValueError("No original direct-call graph to traverse")
    def owner(addr):
        i = bisect_right(starts, addr) - 1
        return starts[i] if i >= 0 and addr < ends[i] else None
    # Mapping uses unwind intervals as parent nodes. Preserve raw, unwindless
    # function targets as separate nodes and NEVER pretend they are decoded.
    roots = {}
    for name, rva in ROOTS.items():
        parent = owner(rva)
        roots[name] = parent if parent is not None else rva

    traversals = {}
    overall = set()
    all_direct_targets = set()
    for name, root in roots.items():
        distances = {root: 0}
        pending = deque([root])
        while pending:
            src = pending.popleft()
            if len(distances) > MAX_NODES:
                raise ValueError("Original call graph exceeds audit budget")
            step = distances[src]
            if step >= depth:
                continue
            for direct in graph.get(src, ()):
                all_direct_targets.add(direct)
                target = owner(direct) or direct
                if target not in distances:
                    distances[target] = step + 1
                    pending.append(target)
        traversals[name] = distances
        overall.update(distances)

    # No unverified branch can become a native function just by being
    # statically decoded. Only exact VA matches from the audited manifest
    # count as fully verified native functions.
    union_dist = {node: min(
        distances.get(node, MAX_DEPTH + 1) for distances in traversals.values())
        for node in overall}
    referenced = Counter()
    missing_by_type = Counter()
    details = {}
    indirect = Counter()
    for src, src_depth in union_dist.items():
        row = lookup.get(src)
        if row:
            indirect["indirect_calls"] += int(row.get("indirect_calls", 0))
            indirect["import_thunk_calls"] += int(row.get("import_thunk_calls", 0))
            indirect["indirect_jumps"] += int(row.get("indirect_jumps", 0))
        if src_depth >= depth:
            continue
        for call in graph.get(src, ()):
            target = owner(call) or call
            if target not in overall:
                continue
            referenced[target] += 1
            if target in verified:
                kind = "verified_exact_native_leaf"
            elif target in lookup and lookup[target]["status"] == "decoded_linear":
                kind = "decoded_unverified_interval"
            elif target in lookup:
                kind = "unrecovered_unwind_interval"
            else:
                kind = "unwindless_or_unmapped_target"
            if kind != "verified_exact_native_leaf":
                missing_by_type[kind] += 1
            details[target] = kind
    verified_reachable = sorted(v for v in overall if v in verified)
    registered_outside = sorted(v for v in verified if v not in overall)
    queue = sorted(
        (v for v in referenced if v not in verified and v not in roots.values()),
        key=lambda v: (
            union_dist[v],
            v in known,  # promote genuinely new blockers over already studied prefixes
            -referenced[v],
            details.get(v, ""),
            v,
        ),
    )
    priorities = [
        {
            "target_rva": hex(v),
            "min_static_depth": union_dist[v],
            "inbound_mapped_sources": referenced[v],
            "category": details[v],
            "native_dispatch_ready": False,
            "already_bounded_tested": v in known,
            "existing_proof": known.get(v),
            "import_thunk": imports_by_thunk.get(v),
            "next_action": (
                "implement or connect authorized imported-service adapter; do not translate this thunk as a function"
                if v in imports_by_thunk else
                "extend or connect existing verified boundary; do not relift"
                if v in known else
                "inspect original call and group its missing dependencies"
            ),
        }
        for v in queue[:50]
    ]
    return {
        "schema": 1,
        "original_sha256": SHA,
        "analysis": "bounded conservative direct-call graph, not execution",
        "depth_limit": depth,
        "whole_image": {
            "unwind_described_intervals": int(stats["unique_unwind_intervals"]),
            "fully_decoded_unwind_intervals": int(stats["fully_linear_decoded_intervals"]),
            "unwindless_direct_call_targets": int(
                stats["direct_call_targets_without_unwind_records"]),
            "all_distinct_original_direct_call_targets": int(
                stats["direct_call_targets_found"]),
            "original_statical_direct_call_sources": int(
                stats["direct_call_graph_sources"]),
            "whole_game_function_total_known": False,
        },
        "roots": {
            name: {
                "requested_rva": hex(ROOTS[name]),
                "unwind_owner_or_entry": hex(roots[name]),
                "bounded_potentially_reachable_nodes": len(distances),
                "verified_exact_native_leaf_nodes": sum(
                    node in verified for node in distances),
            }
            for name, distances in traversals.items()
        },
        "combined": {
            "potentially_reachable_static_nodes": len(overall),
            "potentially_reachable_unwind_intervals": sum(
                v in lookup for v in overall),
            "potentially_reachable_unwindless_targets": sum(
                v not in lookup for v in overall),
            "verified_native_leaves_from_same_run": len(verified),
            "verified_leaves_potentially_reachable": len(verified_reachable),
            "known_bounded_startup_proofs_in_static_reach": sum(
                v in overall for v in known),
            "existing_bounded_proofs_are_complete_native_functions": False,
            "recognized_named_import_thunks_in_root_graph": sum(
                v in overall for v in imports_by_thunk),
            "recognized_direct_iat_callsites_in_root_graph": len(named_imports),
            "import_thunk_is_native_callable_function": False,
            "verified_native_leaves_outside_known_roots": len(registered_outside),
            "unverified_potentially_reachable_nodes": sum(
                v not in verified for v in overall),
            "unresolved_distinct_call_targets_in_traversal": len(queue),
            "unresolved_edges_by_category": dict(missing_by_type),
            "potential_indirect_call_sites_in_intervals": dict(indirect),
            "complete_native_game_startup_verified": False,
            "original_iOS_game_boot_verified": False,
        },
        "prioritized_next_static_dependencies": priorities,
        "verified_leaf_rvas_potentially_reachable": [
            hex(x) for x in verified_reachable[:128]],
        "method_limits": [
            "Only original statically decoded direct CALLs, not conditional dynamic coverage.",
            "Unwind records may describe chunks, omit leaf functions, or overlap; they are not a true total function count.",
            "Indirect CALLs, callbacks, imports, jump tables, and hand-written startup may be absent from the graph.",
            "The 12-level call depth is an intentional budget and not an exact reachable-function count.",
            "Verified native leaves are same-CI-run side-effect-limited auto-links; other separately proven original native startup bodies are not counted in that leaf manifest.",
            "Verified auto-linked leaves do not imply that an entire call chain is resolved.",
            "Win32, MSVCR90 and Steam functionality still require independent authorized runtime integration.",
        ],
    }


def render(result):
    w, r = result["whole_image"], result["combined"]
    lines = [
        "# MX Bikes startup-chain coverage — original SHA-pinned executable", "",
        f"- Original unwind intervals (NOT all game functions): **{w['unwind_described_intervals']:,}**",
        f"- Completely linearly decoded intervals: **{w['fully_decoded_unwind_intervals']:,}**",
        f"- Direct-call targets without unwind records: **{w['unwindless_direct_call_targets']:,}**",
        f"- Distinct original static direct-call targets: **{w['all_distinct_original_direct_call_targets']:,}**",
        f"- Bounded call-chain nodes near CRT/main/entry (depth {result['depth_limit']}): **{r['potentially_reachable_static_nodes']:,}**",
        f"- Same-run x64/host/AArch64-verified native leaf functions: **{r['verified_native_leaves_from_same_run']:,}**",
        f"- Such verified leaves within bounded startup graph: **{r['verified_leaves_potentially_reachable']:,}**",
        f"- Static reachable nodes without that leaf proof: **{r['unverified_potentially_reachable_nodes']:,}**",
        f"- Known bounded startup proofs inside this static graph: **{r['known_bounded_startup_proofs_in_static_reach']:,}** (not counted as complete callable functions)",
        f"- Matched external-import jump thunks: **{r['recognized_named_import_thunks_in_root_graph']:,}** (not native functions)",
        f"- Direct IAT import-call sites: **{r['recognized_direct_iat_callsites_in_root_graph']:,}** (not native functions)",
        "",
        "## Root-specific potential call reach", "",
        "| Original root | Bounded nodes | Auto-verified leaves |",
        "| --- | ---: | ---: |",
    ]
    for name, entry in result["roots"].items():
        lines.append(f"| {name} ({entry['requested_rva']}) | "
                     f"{entry['bounded_potentially_reachable_nodes']:,} | "
                     f"{entry['verified_exact_native_leaf_nodes']:,} |")
    lines += ["", "## Closest unresolved static direct-call targets", ""]
    for item in result["prioritized_next_static_dependencies"][:20]:
        lines.append(
            f"- {item['target_rva']} — depth {item['min_static_depth']}; "
            f"{item['inbound_mapped_sources']} mapped sources; "
            f"{item['category'].replace('_',' ')}"
            + ("; external "+item['import_thunk']['dll']+"::"+item['import_thunk']['symbol']
               if item['import_thunk'] else "")
            + ("; existing bounded proof available"
               if item['already_bounded_tested'] else "")
        )
    lines += [
        "",
        "**Do not turn these counts into a completion percentage.** "
        "Unwind intervals and static edges are not a complete game function "
        "inventory; the graph omits indirect calls, imports and dynamic "
        "callbacks. Verified leaves in this manifest do not include the "
        "larger original startup functions proved under separate CI gates. "
        "Native engine startup, Steam, first frame, menu and iOS are still unverified.",
        "",
    ]
    return "\n".join(lines)


def run(map_path, verified_path, output, known_path=None, import_path=None):
    mapping = json.loads(map_path.read_text())
    verified = json.loads(verified_path.read_text())
    curated = json.loads(known_path.read_text()) if known_path else None
    import_graph = json.loads(import_path.read_text()) if import_path else None
    result = analyze(mapping, verified, known_proofs=curated,
                     import_graph=import_graph)
    output.mkdir(parents=True, exist_ok=True)
    (output / "startup-chain-coverage.json").write_text(
        json.dumps(result, indent=2) + "\n")
    md = render(result)
    (output / "startup-chain-coverage.md").write_text(md)
    print(md)
    return result


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("whole_game_map", type=Path)
    p.add_argument("same_run_verified_leaf_manifest", type=Path)
    p.add_argument("metadata_output", type=Path)
    p.add_argument("--known-proofs", type=Path)
    p.add_argument("--import-graph", type=Path)
    args = p.parse_args()
    run(args.whole_game_map, args.same_run_verified_leaf_manifest,
        args.metadata_output, args.known_proofs, args.import_graph)
