#!/usr/bin/env python3
"""Large-batch first-original-CALL structural triage across PE parents.

Targets hundreds of original unwind parent entries with direct CALL
relationships, even when *none* of the children is currently native-verified.
Executes only bounded x64 caller entry->first-CALL under deterministic
Unicorn fixtures, stops before CALL, and never registers a native symbol.
This is a broad next-wave planning tool, not a recompiler or game boot.
All game bytes and transient register states remain private.
"""
from __future__ import annotations
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "arm64-lab"))
from tools.pe_probe import PE
from mxbikes_whole_game_map import INPUT_SHA
from mxbikes_win64_unwind_frame import pdata_index
from mxbikes_parent_batch_frontier import (
    run_fixture, preflight, decode_frontier_unwind,
    verified_targets,
)

MAX_BULK_PARENTS = 384
MAX_CASES_PER_PARENT = 4
MAX_REPORTED_TARGETS = 30
# The original main and CRT are important independently of generic call count.
STARTUP_ROOTS = (0x136710, 0x2ab02c, 0x133e80, 0x130580)

def select_parents(mapping, limit=MAX_BULK_PARENTS):
    if not 1 <= limit <= MAX_BULK_PARENTS:
        raise ValueError("Unbounded bulk parent selection")
    graph = mapping.get("direct_call_graph", {})
    incoming = Counter(int(child, 16) for children in graph.values() for child in children)
    rows = []
    for address, children in graph.items():
        parent = int(address, 16)
        if not children:
            continue
        unique_targets = {int(target, 16) for target in children}
        rows.append((parent, len(unique_targets), incoming[parent]))
    priority = set(STARTUP_ROOTS)
    rows.sort(key=lambda v: (
        0 if v[0] in priority else 1,
        -(v[2] * 4 + v[1]),
        -v[2], -v[1], v[0],
    ))
    selected = rows[:limit]
    if len({x[0] for x in selected}) != len(selected):
        raise RuntimeError("Duplicate original caller in bulk selection")
    return selected

def analyze(pe, mapping, verified, limit=MAX_BULK_PARENTS,
            cases_per_parent=MAX_CASES_PER_PARENT):
    if (mapping.get("input_sha256") != INPUT_SHA
        or mapping.get("original_file_verified") is not True):
        raise ValueError("Bulk scanner requires an exact original SHA-pinned graph")
    if not 1 <= cases_per_parent <= MAX_CASES_PER_PARENT:
        raise ValueError("Fixture batch cap exceeded")
    native_targets = verified_targets(verified)
    rows = select_parents(mapping, limit)
    all_original_direct_targets = {
        int(child, 16)
        for children in mapping["direct_call_graph"].values()
        for child in children
    }
    records = pdata_index(pe)
    rejected = Counter()
    outcomes = Counter()
    reachable = {}
    executed_fixtures = 0
    native_overlap = set()
    complete_prologues = 0
    for parent, out_degree, in_degree in rows:
        if parent not in records:
            rejected["no_original_pdata_entry"] += 1
            continue
        end, metadata = records[parent]
        unwind = decode_frontier_unwind(pe, metadata)
        if not unwind.get("eligible"):
            rejected[unwind["reason"]] += 1
            continue
        error = preflight(pe, parent, end, unwind)
        if error:
            rejected[error] += 1
            continue
        complete_prologues += 1
        hits = {}
        per_function = Counter()
        for fixture in range(cases_per_parent):
            result = run_fixture(
                pe, parent, end, unwind, all_original_direct_targets, fixture
            )
            executed_fixtures += 1
            outcome = result["outcome"]
            if outcome == "original_x64_first_verified_call_reached":
                # Naming comes from a shared low-level tracer; this result
                # has only a STATIC original direct-call destination.
                outcome = "original_x64_first_mapped_direct_call_reached"
                site = result["callsite_rva"]
                child = result["native_verified_target_rva"]
                if (site, child) not in hits:
                    hits[(site, child)] = {
                        "original_callsite_rva": site,
                        "original_target_rva": child,
                        "target_already_native_verified": int(child, 16) in native_targets,
                        "first_reached_fixture": fixture,
                        "original_x64_path_only": True,
                    }
                if int(child, 16) in native_targets:
                    native_overlap.add((parent, site, child))
            outcomes[outcome] += 1
            per_function[outcome] += 1
        if hits:
            reachable[parent] = {
                "parent_rva": hex(parent),
                "original_direct_call_targets_in_parent": out_degree,
                "other_original_calls_to_parent": in_degree,
                "first_calls_observed": list(hits.values()),
                "fixture_outcomes": dict(sorted(per_function.items())),
            }
        else:
            rejected["eligible_but_no_first_direct_call_reached"] += 1
    total_edges = {
        (parent, hit["original_callsite_rva"], hit["original_target_rva"])
        for parent, p in reachable.items() for hit in p["first_calls_observed"]
    }
    ranked = sorted(reachable.values(), key=lambda row: (
        -row["other_original_calls_to_parent"],
        -len(row["first_calls_observed"]),
        row["parent_rva"],
    ))
    return {
        "schema": 1,
        "original_sha256": INPUT_SHA,
        "scope": "broad_unverified_original_x64_first_direct_call_triage",
        "original_parent_call_graph_candidates": len(
            mapping.get("direct_call_graph", {})),
        "prioritized_parent_sampled": len(rows),
        "parents_with_verified_unwind_prologue": complete_prologues,
        "original_x64_fixtures_executed": executed_fixtures,
        "parent_entries_reaching_mapped_direct_first_call": len(reachable),
        "distinct_original_x64_first_direct_call_edges": len(total_edges),
        "first_direct_call_edges_to_previously_native_verified_leaves": len(native_overlap),
        "fixture_outcomes": dict(sorted(outcomes.items())),
        "parent_rejections": dict(sorted(rejected.items())),
        "highest_priority_first_call_parents": ranked[:MAX_REPORTED_TARGETS],
        "sample_truncated_to_bounded_topn": len(reachable) > MAX_REPORTED_TARGETS,
        "new_native_verified_functions": 0,
        "original_code_or_fixture_registers_exported": False,
        "startup_or_engine_boot_verified": False,
    }

def run(executable, mapping_json, verified_json, report_dir):
    pe = PE(executable)
    if hashlib.sha256(pe.b).hexdigest() != INPUT_SHA:
        raise RuntimeError("Owned original executable hash mismatch")
    result = analyze(pe, json.loads(mapping_json.read_text()),
                     json.loads(verified_json.read_text()))
    report_dir.mkdir(parents=True, exist_ok=True)
    (report_dir / "bulk-original-firstcall-triage.json").write_text(
        json.dumps(result, indent=2) + "\n"
    )
    lines = [
        "# MX Bikes broad original x64 direct-call first-frontier survey", "",
        "- Original graph parent candidates: **" +
        str(result["original_parent_call_graph_candidates"]) + "**",
        "- Prioritized parent functions sampled in one pass: **" +
        str(result["prioritized_parent_sampled"]) + "**",
        "- Original x64 function-entry fixtures run: **" +
        str(result["original_x64_fixtures_executed"]) + "**",
        "- Original parent entries reaching a direct first CALL: **" +
        str(result["parent_entries_reaching_mapped_direct_first_call"]) + "**",
        "- Distinct direct first-CALL edges seen: **" +
        str(result["distinct_original_x64_first_direct_call_edges"]) + "**",
        "- Native verified symbols added: **0**", "",
        "| Original x64 fixture outcome | Count |", "| --- | ---: |",
    ]
    lines.extend("| " + k + " | " + str(v) + " |"
                 for k, v in result["fixture_outcomes"].items())
    lines += ["", "| Blocked parent family | Count |", "| --- | ---: |"]
    lines.extend("| " + k + " | " + str(v) + " |"
                 for k, v in result["parent_rejections"].items())
    lines += [
        "", "**Targets are static original direct calls, NOT translated native functions.**",
        "**All execution stops before the CALL. Do not claim engine boot or iOS.**", ""
    ]
    report = "\n".join(lines)
    (report_dir / "bulk-original-firstcall-triage.md").write_text(report)
    print(report)
    return result

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("sha_pinned_original", type=Path)
    p.add_argument("same_run_whole_map", type=Path)
    p.add_argument("same_run_verified_leaf_registry", type=Path)
    p.add_argument("output", type=Path)
    a = p.parse_args()
    run(a.sha_pinned_original, a.same_run_whole_map,
        a.same_run_verified_leaf_registry, a.output)
