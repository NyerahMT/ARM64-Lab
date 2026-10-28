#!/usr/bin/env python3
"""Plan multi-root MX Bikes startup dependency batches from SHA-pinned metadata.

Static call edges are candidate work, not executed paths or translated native code.
Original import thunks are grouped with runtime services, never lifted as functions.
"""
from __future__ import annotations
import argparse
from bisect import bisect_right
from collections import defaultdict, deque
import json
from pathlib import Path

SHA = "4ae7de3854b4d0a18271679fb57a1f2fdf0b21804417b85dd82055078ea123b6"
ROOTS = [("game_main", 0x136710), ("crt_startup", 0x2ab02c), ("pe_entry", 0x2ab31c)]
MAX_DEPTH = 5
MAX_NODES = 4096
MAX_BATCH_SIZE = 64


def rva(value):
    if not isinstance(value, str) or not value.startswith("0x"):
        raise ValueError("Unrecognized original RVA")
    number = int(value, 16)
    if number < 0 or number >= (1 << 32):
        raise ValueError("Original RVA outside PE32+ range")
    return number


def plan(mapping, import_scan, service_matrix, native_plan, *, depth=4, batch_size=48):
    if not 1 <= depth <= MAX_DEPTH or not 1 <= batch_size <= MAX_BATCH_SIZE:
        raise ValueError("Unbounded startup batch settings")
    if (mapping.get("input_sha256") != SHA or
        mapping.get("original_file_verified") is not True or
        import_scan.get("original_sha256") != SHA or
        service_matrix.get("original_sha256") != SHA or
        native_plan.get("source_original_sha256") != SHA):
        raise ValueError("Cross-run original executable identity mismatch")
    if (import_scan.get("input_kind") !=
            "SHA-pinned PE import table plus static original x64 instructions"):
        raise ValueError("Unsupported import scanner provenance")
    if native_plan.get("source") != "SHA-verified original MX Bikes whole executable static PE map":
        raise ValueError("Unverified native link plan")
    rows = mapping.get("interval_map", [])
    if not isinstance(rows, list) or len(rows) > 600000:
        raise ValueError("Missing or excessive original unwind intervals")
    ranges = [(rva(row["rva"]), rva(row["end_rva"]), row) for row in rows]
    ranges.sort(key=lambda x: x[0])
    starts = [x[0] for x in ranges]
    if any(hi <= lo for lo, hi, _ in ranges):
        raise ValueError("Invalid unwind interval")

    def owner(address):
        at = bisect_right(starts, address) - 1
        return starts[at] if at >= 0 and address < ranges[at][1] else address

    by_node = {lo: item for lo, _, item in ranges}
    raw_graph = mapping.get("direct_call_graph")
    if not isinstance(raw_graph, dict) or not raw_graph:
        raise ValueError("No original call graph for batch planning")
    graph = defaultdict(set)
    for raw_src, targets in raw_graph.items():
        if not isinstance(targets, list) or len(targets) > 1024:
            raise ValueError("Unbounded original direct-call adjacency")
        graph[owner(rva(raw_src))].update(owner(rva(t)) for t in targets)

    services = {}
    for item in service_matrix.get("services", []):
        key = (item["dll"].lower(), item["symbol"].lower())
        if key in services:
            raise ValueError("Duplicate service metadata")
        services[key] = item
    thunks = {}
    for item in import_scan.get("original_import_thunks", []):
        if item.get("kind") == "import_thunk":
            target = rva(item["called_target_rva"])
            key = (item["import_dll"].lower(), item["import_symbol"].lower())
            if target in thunks or key not in services:
                raise ValueError("Unclassified or duplicate original import thunk")
            thunks[target] = key
    iat_by_owner = defaultdict(set)
    for item in import_scan.get("direct_iat_callsites", []):
        key = (item["import_dll"].lower(), item["import_symbol"].lower())
        if key not in services:
            raise ValueError("Unclassified direct IAT callsite")
        iat_by_owner[owner(rva(item["source_rva"]))].add(key)

    verified = {rva(x["original_rva"]) for x in native_plan.get("native_dispatch_table", [])}
    visited = {}
    pending = deque((owner(root), name, 0) for name, root in ROOTS)
    hit_budget = False
    while pending:
        node, lane, step = pending.popleft()
        if node in thunks:
            continue
        if node in visited:
            visited[node]["lanes"].add(lane)
            continue
        if len(visited) >= MAX_NODES:
            hit_budget = True
            break
        visited[node] = {"depth": step, "lanes": {lane}, "services": set(), "children": set()}
        if step >= depth:
            continue
        for target in sorted(graph.get(node, [])):
            if target in thunks:
                visited[node]["services"].add(thunks[target])
            else:
                visited[node]["children"].add(target)
                pending.append((target, lane, step + 1))
    for node, info in visited.items():
        info["services"].update(iat_by_owner.get(node, ()))
    grouping = defaultdict(list)
    for node, info in visited.items():
        if node in verified:
            continue
        row = by_node.get(node)
        status = ("decoded_candidate_not_native" if row and row.get("status") == "decoded_linear"
                  else "unwind_interval_needs_recovery" if row else "unwindless_or_unmapped_entry")
        lane = next((name for name, _ in ROOTS if name in info["lanes"]), "other")
        grouping[(lane, info["depth"], status)].append(node)

    batches = []
    for (lane, wave, kind), nodes in sorted(grouping.items(), key=lambda x:
                                           ([name for name, _ in ROOTS].index(x[0][0]), x[0][1], x[0][2])):
        nodes.sort()
        for offset in range(0, len(nodes), batch_size):
            chunk = nodes[offset:offset + batch_size]
            needs = sorted({key for n in chunk for key in visited[n]["services"]})
            deps = sorted({child for n in chunk for child in visited[n]["children"] if child not in chunk})
            batches.append({
                "batch_id": f"wave-{len(batches) + 1:03d}", "lane": lane,
                "static_depth": wave, "work_kind": kind,
                "original_entries": [hex(n) for n in chunk],
                "dependency_nodes_outside_batch": [hex(n) for n in deps[:128]],
                "dependency_list_truncated": len(deps) > 128,
                "service_families": sorted({services[key]["family"] for key in needs}),
                "imported_service_dependencies": [f"{a}::{b}" for a, b in needs],
                "required_gate": "full-body x64/ARM64 differential plus Win64 guest ABI",
                "native_dispatch_ready": False,
            })

    families = sorted(service_matrix.get("families", []),
                      key=lambda x: (-len(x.get("missing_symbols", [])), x["family"]))
    services_needed = sorted({key for info in visited.values() for key in info["services"]})
    unresolved = sorted({f"{a}::{b}" for a, b in services_needed
                         if services[(a, b)]["status"] == "missing"})
    return {
        "schema": 1, "original_sha256": SHA,
        "meaning": "static multi-root scheduling only; NOT native translation or boot",
        "configured_depth": depth, "batch_size_limit": batch_size,
        "static_nodes_examined": len(visited), "node_budget_exhausted": hit_budget,
        "native_verified_nodes_skipped": sum(node in verified for node in visited),
        "code_batches": batches, "code_batches_total": len(batches),
        "service_family_batches": [{
            "family": f["family"], "batch_name": f["batch_name"],
            "missing_symbols": f["missing_symbols"], "next_work": f["next_work"]
        } for f in families if f.get("missing_symbols")],
        "services_referenced_in_examined_nodes": len(services_needed),
        "missing_services_referenced_in_examined_nodes": unresolved,
        "limitations": [
            "Multi-root static direct-call potential reachability is not dynamic startup execution.",
            "Unwind intervals are not all functions; indirect calls, callbacks and jump tables can be absent.",
            "Services and import thunks are never counted as translated game functions.",
            "All code batches require full-body native differential validation before dispatch.",
            "Native graphics initialization, game boot and iOS app launch remain unverified."
        ],
    }


def run(map_path, scan_path, service_path, native_path, output):
    sources = [json.loads(p.read_text()) for p in (map_path, scan_path, service_path, native_path)]
    result = plan(*sources)
    output.mkdir(parents=True, exist_ok=True)
    (output / "startup-dependency-batches.json").write_text(json.dumps(result, indent=2) + "\n")
    lines = ["# MX Bikes multi-root dependency batches", "",
             f"- Nodes analyzed: **{result['static_nodes_examined']}**",
             f"- Code batches: **{result['code_batches_total']}**",
             f"- Native-verified nodes excluded: **{result['native_verified_nodes_skipped']}**",
             f"- Search budget exhausted: **{result['node_budget_exhausted']}**", "",
             "| Batch | Lane | Wave | Class | Nodes | Imported service families |",
             "| --- | --- | ---: | --- | ---: | --- |"]
    for item in result["code_batches"][:40]:
        lines.append(f"| {item['batch_id']} | {item['lane']} | {item['static_depth']} | "
                     f"{item['work_kind']} | {len(item['original_entries'])} | "
                     f"{', '.join(item['service_families']) or 'none identified'} |")
    lines += ["", "## Shared service-family work", ""]
    for item in result["service_family_batches"]:
        lines.append(f"- {item['batch_name']}: {', '.join(item['missing_symbols'])}")
    lines += ["", "**These are bounded candidate work packages, not converted ARM64 functions or boot progress.**", ""]
    (output / "startup-dependency-batches.md").write_text("\n".join(lines))
    print("\n".join(lines))
    return result


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("whole_game_map", type=Path)
    p.add_argument("startup_import_edges", type=Path)
    p.add_argument("startup_service_matrix", type=Path)
    p.add_argument("native_link_plan", type=Path)
    p.add_argument("output", type=Path)
    args = p.parse_args()
    run(args.whole_game_map, args.startup_import_edges,
        args.startup_service_matrix, args.native_link_plan, args.output)
