#!/usr/bin/env python3
"""Prioritize a bounded, metadata-only Ghidra startup call graph.

This models static direct calls, not actual runtime execution or dependencies
that must be implemented before boot. It never reads proprietary binaries.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict, deque
import json
from pathlib import Path

API_CATEGORIES = {
    "process_and_crt": {
        "getstartupinfoa", "getcurrentprocessid", "getcurrentthreadid",
        "getcurrentprocess", "_cexit", "exit", "_ismbblead",
        "isdebuggerpresent", "terminateprocess", "rtlcapturecontext",
        "setunhandledexceptionfilter", "unhandledexceptionfilter",
    },
    "time_and_scheduling": {
        "queryperformancecounter", "queryperformancefrequency",
        "gettickcount", "getsystemtimeasfiletime", "timegettime",
        "timebeginperiod", "timeendperiod", "sleep",
    },
    "filesystem_and_paths": {
        "setcurrentdirectorya", "getmodulefilenamea", "shgetpathfromidlista", "shgetspecialfolderlocation",
    },
    "window_and_messages": {
        "peekmessagea", "translatemessage", "dispatchmessagea",
        "setwindowtexta", "createwindowexa", "destroywindow", "registerclassexa",
        "unregisterclassa", "updatewindow", "showwindow", "messageboxa",
        "loadcursora", "loadimagea", "getclientrect",
        "getwindowlongptra", "setwindowlongptra", "changedisplaysettingsa",
        "enumdisplaymonitors",
    },
    "window_drawing": {
        "getdc", "releasedc", "getstockobject",
    },
    "rendering_wgl": {
        "wglcreatecontext", "wgldeletecontext", "wglmakecurrent",
        "choosepixelformat", "describepixelformat", "setpixelformat",
        "swapbuffers",
    },
    "dynamic_library_loading": {
        "freelibrary", "loadlibrarya", "getprocaddress",
    },
    "steam_startup": {
        "steamapi_init", "steamapi_restartappifnecessary", "steaminternal_contextinit",
    },
    "steam_lifecycle": {
        "steamapi_shutdown",
    },
    "com_memory": {
        "cotaskmemfree",
    },
}
PRIORITY = {
    "process_and_crt": "early runtime",
    "time_and_scheduling": "early runtime",
    "filesystem_and_paths": "early runtime",
    "window_and_messages": "window/event-loop",
    "window_drawing": "window/rendering",
    "rendering_wgl": "graphics context/Metal adaptation",
    "dynamic_library_loading": "dynamic imports/loader",
    "steam_startup": "Steam integration/initialization",
    "com_memory": "COM heap/lifetime",
    "steam_lifecycle": "lifecycle; not necessarily boot-critical",
    "uncategorized": "investigate",
}
def classify(api):
    name = str(api).rsplit("::", 1)[-1].lower()
    for category, names in API_CATEGORIES.items():
        if name in names:
            return category
    return "uncategorized"


def analyze_graph(data):
    if not data.get("entry_function_found") or not data.get("entry_function_rva"):
        raise ValueError("Ghidra did not recover a usable executable entry function")
    raw_nodes = data.get("graph_nodes", [])
    raw_edges = data.get("graph_edges", [])
    if not isinstance(raw_nodes, list) or not isinstance(raw_edges, list):
        raise ValueError("Expected Ghidra node and edge arrays")
    if len(raw_nodes) > 5000 or len(raw_edges) > 25000:
        raise ValueError("Graph exceeds safety limits")
    entry = data["entry_function_rva"]
    nodes = {node["rva"]: node for node in raw_nodes if not node.get("external")}
    children = defaultdict(list)
    api_edges = []
    for edge in raw_edges:
        source = edge["from"]
        target = edge["to"]
        if edge.get("external"):
            api_edges.append(edge)
        else:
            children[source].append(target)

    parent = {entry: None}
    queue = deque([entry])
    while queue:
        current = queue.popleft()
        for child in children[current]:
            if child not in parent:
                parent[child] = current
                queue.append(child)

    def ancestry(src):
        result = [src]
        while parent.get(src) is not None:
            src = parent[src]
            result.append(src)
        return list(reversed(result))

    grouped = defaultdict(Counter)
    api_paths = {}
    for edge in api_edges:
        api = edge.get("api", "unresolved")
        group = classify(api)
        grouped[group][api] += 1
        if api not in api_paths and edge["from"] in parent:
            api_paths[api] = ancestry(edge["from"]) + [api]
    depth_limit = int(data.get("graph_depth_limit", 0))
    frontier = [n for n in nodes.values() if int(n.get("depth", -1)) >= depth_limit]
    outgoing = Counter(e["from"] for e in raw_edges)
    incoming = Counter(e["to"] for e in raw_edges if not e.get("external"))
    graph_hotspots = [
        {
            "rva": rva,
            "depth": nodes[rva].get("depth"),
            "static_outgoing_calls": outgoing[rva],
            "static_incoming_calls": incoming[rva],
            "score": outgoing[rva] * 2 + incoming[rva],
        }
        for rva in nodes if outgoing[rva] > 0
    ]
    graph_hotspots.sort(key=lambda x:(-x["score"], x["depth"], x["rva"]))
    # Optional richer metrics from newer Ghidra snapshots. Small, shallow
    # candidates are inspection targets, not automatically liftable functions.
    translation_candidates = [
        {
            "rva": n["rva"],
            "depth": int(n.get("depth", 0)),
            "instructions": int(n["instruction_count"]),
            "call_instructions": int(n.get("call_instruction_count", 0)),
            "jump_instructions": int(n.get("jump_instruction_count", 0)),
            "outgoing_graph_edges": outgoing[n["rva"]],
        }
        for n in nodes.values()
        if int(n.get("instruction_count", 0)) > 0
        and not n.get("instruction_scan_truncated", False)
    ]
    translation_candidates.sort(key=lambda c: (
        c["jump_instructions"] > 0,
        c["call_instructions"] > 0,
        c["depth"], c["instructions"], c["rva"],
    ))
    # Explicitly avoid treating lifecycle/shutdown calls as mandatory boot blockers.
    plan = []
    for group, apis in sorted(grouped.items(), key=lambda item: (
        list(API_CATEGORIES).index(item[0]) if item[0] in API_CATEGORIES else 100
    )):
        plan.append({
            "category": group,
            "priority": PRIORITY[group],
            "unique_apis": len(apis),
            "call_edges": sum(apis.values()),
            "api_names": sorted(apis),
            "paths": {api: api_paths.get(api, []) for api in sorted(apis)},
        })
    return {
        "source": "Ghidra static call graph, not dynamic execution",
        "entry_rva": entry,
        "analyzed_depth_limit": depth_limit,
        "graph_node_count": len(raw_nodes),
        "graph_edge_count": len(raw_edges),
        "distinct_external_api_names": len({e.get("api") for e in api_edges}),
        "external_api_call_edges": len(api_edges),
        "internal_nodes_at_depth_limit": len(frontier),
        "internal_nodes_at_depth_limit_sample": sorted(n["rva"] for n in frontier)[:30],
        "graph_hotspots": graph_hotspots[:15],
        "sampled_startup_instructions": data.get("sampled_startup_instructions"),
        "unique_mnemonics": data.get("unique_mnemonics"),
        "top_mnemonics": data.get("top_mnemonics", [])[:30],
        "translation_inspection_candidates": translation_candidates[:25],
        "compatibility_groups": plan,
        "limitations": [
            "Direct-call reachability does not prove runtime reachability or call order.",
            "A startup-time dependency cannot be inferred solely from appearing in the graph.",
            "Shutdown and cleanup functions may appear without being needed to reach startup.",
            "Indirect calls and dynamically resolved imports may be absent.",
            "Nodes at the configured depth limit are an unexpanded frontier, not complete coverage.",
            "Short instruction sequences are not automatically safe or complete translation targets.",
        ],
    }


def make_summary(report):
    lines = [
        "# MX Bikes — bounded startup compatibility roadmap", "",
        f"- Entry function: {report['entry_rva']}",
        f"- Static graph: {report['graph_node_count']} nodes / {report['graph_edge_count']} edges",
        f"- External API call edges: {report['external_api_call_edges']}",
        f"- Distinct external API names: {report['distinct_external_api_names']}",
        f"- **Unexpanded depth-limit nodes: {report['internal_nodes_at_depth_limit']}**",
        "", "## API families seen in the static graph", "",
        "| API family | Unique APIs | Call edges | Interpretation |",
        "| --- | ---: | ---: | --- |",
    ]
    for item in report["compatibility_groups"]:
        lines.append(f"| {item['category']} | {item['unique_apis']} | {item['call_edges']} | {item['priority']} |")
    if report.get("sampled_startup_instructions") is not None:
        lines.extend([
            "", "## Instruction profile (bounded and static)", "",
            "- Instructions sampled: " + str(report["sampled_startup_instructions"]),
            "- Distinct decoded mnemonics: " + str(report["unique_mnemonics"]),
            "", "### Candidate functions for follow-up inspection", "",
            "| RVA | Graph depth | Instructions | Call instructions | Jump instructions |",
            "| --- | ---: | ---: | ---: | ---: |",
        ])
        for c in report["translation_inspection_candidates"][:12]:
            lines.append(
                f"| {c['rva']} | {c['depth']} | {c['instructions']} | "
                f"{c['call_instructions']} | {c['jump_instructions']} |"
            )
    lines.extend(["", "## Candidate internal call hotspots", "",
                  "| RVA | Depth | Outgoing direct calls | Incoming direct calls |",
                  "| --- | ---: | ---: | ---: |"])
    for item in report["graph_hotspots"][:10]:
        lines.append(f"| {item['rva']} | {item['depth']} | {item['static_outgoing_calls']} | {item['static_incoming_calls']} |")
    lines.extend(["", "## External calls identified", ""])
    for group in report["compatibility_groups"]:
        lines.append(f"**{group['category']}**: " + ", ".join(group["api_names"]))
        lines.append("")
    lines.extend(["## Engineering decision", "",
                  "Prioritize program/CRT entry, clock functions, and filesystem path semantics for controlled host tests; "
                  "investigate message-loop and rendering adapters before attempting a real window. "
                  "Do not classify a call as a boot blocker until it is observed in a runtime trace.",
                  "", "## Important limits", ""])
    for note in report["limitations"]:
        lines.append("- " + note)
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="Ghidra startup JSON metadata")
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    raw = json.loads(args.input.read_text(encoding="utf-8"))
    report = analyze_graph(raw)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "startup-roadmap.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    summary = make_summary(report)
    (args.output_dir / "startup-roadmap.md").write_text(summary, encoding="utf-8")
    print(summary)


if __name__ == "__main__":
    main()
